---
id: FOR-0023
title: "MFT MACB 시간 해석: 복사·이동·다운로드·압축해제 구분법"
slug: "mft-macb"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["MACB", "$STANDARD_INFORMATION", "$FILE_NAME", "FILETIME", "bodyfile", "Zone.Identifier"]
file_paths: ["C:\\$MFT", "C:\\Users\\<user>\\Downloads"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem"]
event_ids: []
protocols: []
tools: ["MFTECmd", "analyzeMFT", "mactime", "Sleuth Kit", "DCode", "Timeline Explorer", "PowerShell", "fsutil"]
commands: ["MFTECmd.exe -f \"C:\\case\\$MFT\" --body . --bodyf mft.body --bdl C", "mactime -b mft.body -d -z UTC 2026-03-14", "fsutil behavior query disablelastaccess", "[datetime]::FromFileTimeUtc(134179465610000000)"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Created0x10", "LastModified0x10", "LastRecordChange0x10", "LastAccess0x10", "Created0x30", "LastModified0x30", "LastRecordChange0x30", "LastAccess0x30"]
file_formats: ["ntfs", "bodyfile"]
primary_terms: ["MACB", "MFT MACB", "macb 시간"]
keywords: ["MACB", "MAC time", "타임스탬프", "Modified", "Accessed", "MFT entry changed", "Birth", "Created", "FILETIME", "NtfsDisableLastAccessUpdate", "복사 흔적", "압축해제 흔적", "KST 변환"]
aliases: ["macb", "mac time", "시간 왜 다름", "파일 복사 흔적", "생성시각이 수정시각보다 늦다", "last access 안 바뀜", "압축 풀었는지", "다운로드 시각"]
symptom_keywords: ["생성 시각이 수정 시각보다 늦다", "접근 시각이 안 바뀐다", "복사한 파일인지 알고 싶다", "언제 다운로드했는지", "압축을 풀었는지 만든 건지", "시간이 9시간 다르다"]
related: ["FOR-0021", "FOR-0024", "FOR-0038"]
source_ids: ["SRC-005", "SRC-014", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

MACB의 `C`는 Created가 아니라 **MFT entry Changed**이며, **`B`(생성)가 `M`(수정)보다 늦은 파일은 그 볼륨에서 만들어진 것이 아니라 복사·압축해제·이동으로 들어온 것**이다. 이 한 가지 역전만 봐도 "만들었나 가져왔나"가 갈린다.

## 어떤 문제에서 필요한가

- "이 파일을 사용자가 직접 만들었나, 어디서 가져왔나"
- "언제 복사했나 / 언제 압축을 풀었나 / 언제 다운로드했나"
- "같은 볼륨 안에서 옮긴 건가 USB에서 가져온 건가"
- "접근 시각이 전부 생성 시각과 같은데 정상인가"
- "왜 파일 시각이 문제 지문의 시각과 9시간 다른가"

`$MFT` 파싱과 CSV 필터는 [FOR-0022](./analyzemft-csv.html)에서, 두 타임스탬프 세트의 조작 탐지는 [FOR-0024](./si-vs-fn-timestamps.html)에서 다룬다. 이 글은 **행위 → 시각 변화 패턴**의 매핑이다.

## 문제에서 처음 볼 단서

1. `Created0x10` > `LastModified0x10` → **외부에서 들어온 파일**. 복사/압축해제/다른 볼륨 이동
2. 4개 시각이 초 단위까지 동일 → 그 자리에서 새로 만들어진 레코드
3. `LastAccess0x10`이 `Created0x10`과 항상 같다 → last access 갱신이 꺼진 시스템
4. 같은 `Created0x10`을 가진 파일이 수십~수백 개 → 설치 또는 대량 압축해제
5. `LastRecordChange0x10`만 최근이고 나머지는 과거 → 이름 변경·이동·권한 변경, 또는 timestomp
6. `LastModified0x10`의 초가 항상 짝수 → ZIP에서 복원된 시각일 가능성

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
```

```powershell
# B > M 역전 = 그 볼륨에서 만들어지지 않은 파일
Import-Csv C:\case\out\mft.csv |
  Where-Object {
    $_.IsDirectory -eq 'False' -and $_.Created0x10 -and $_.LastModified0x10 -and
    ([datetime]$_.Created0x10) -gt ([datetime]$_.LastModified0x10)
  } |
  Select-Object ParentPath, FileName, Created0x10, LastModified0x10, HasAds |
  Sort-Object Created0x10
```

`HasAds = True`가 함께 붙으면 다운로드(Zone.Identifier) 쪽, 안 붙으면 복사·압축해제 쪽이다.

## 상세 절차

### 1단계 — 네 글자의 정확한 의미

`$STANDARD_INFORMATION`(0x10) 속성 안의 네 값이다.

| 글자 | `$SI` 내 오프셋 | 정식 이름 | 무엇이 바뀔 때 갱신되나 |
| --- | --- | --- | --- |
| **M** | `0x08` | Modified / File Altered | `$DATA` 내용이 바뀔 때 |
| **A** | `0x18` | Accessed / Last Read | 파일을 읽을 때 (**기본 비활성**) |
| **C** | `0x10` | **MFT entry Changed** | 레코드 자체가 바뀔 때 — 이름·부모·크기·속성·권한·타임스탬프 |
| **B** | `0x00` | Birth / Created | 레코드가 만들어질 때 |

**`C`를 Created로 읽는 것이 이 주제 최대의 오답원이다.** `C`는 metadata change이고, `B`가 생성이다. 도구별 컬럼명 대응은 다음과 같다.

| 개념 | MFTECmd | analyzeMFT | TSK `istat` / bodyfile |
| --- | --- | --- | --- |
| M | `LastModified0x10` | `Std Info Modification date` | `File Modified` / `m` |
| A | `LastAccess0x10` | `Std Info Access date` | `Accessed` / `a` |
| C | `LastRecordChange0x10` | `Std Info Entry date` | `MFT Modified` / `c` |
| B | `Created0x10` | `Std Info Creation date` | `Created` / `b` |

bodyfile을 `mactime`으로 돌리면 각 행에 `macb` 플래그가 표시된다. 어느 시각이 그 순간에 찍혔는지 한눈에 보인다.

```bash
mactime -b mft.body -d -z UTC 2026-03-14 > timeline.csv
```

```text
Date,Size,Type,Mode,UID,GID,Meta,File Name
2026-03-14 07:29:40 (UTC),1184,.a.b,r/rrwxrwxrwx,0,0,128512,C:/Users/jhkim/Desktop/notes.txt
2026-03-14 07:29:40 (UTC),1184,..c.,r/rrwxrwxrwx,0,0,128512,C:/Users/jhkim/Desktop/notes.txt
2025-11-02 13:44:22 (UTC),1184,m...,r/rrwxrwxrwx,0,0,128512,C:/Users/jhkim/Desktop/notes.txt
```

`m`만 4개월 전에 따로 찍혀 있다 — 이것이 "가져온 파일"의 서명이다.

### 2단계 — 행위별 MACB 변화표

**이 표가 이 글의 본체다.** `유지`는 값이 그대로, `갱신`은 그 행위 시각으로 바뀐다는 뜻이다.

| 행위 | M | A | C | B | 결과 패턴 |
| --- | --- | --- | --- | --- | --- |
| 새 파일 생성 | 갱신 | 갱신 | 갱신 | 갱신 | 4개가 초 단위까지 동일 |
| 내용 수정 후 저장 | **갱신** | 갱신(활성 시) | **갱신** | 유지 | `B` < `M` ≈ `C` |
| 열어서 읽기만 | 유지 | 갱신(활성 시) | 유지 | 유지 | 기본 설정이면 **아무것도 안 바뀐다** |
| 이름 변경 | 유지 | 유지 | **갱신** | 유지 | `C`만 최근 |
| 같은 볼륨 내 이동 | 유지 | 유지 | **갱신** | 유지 | `C`만 최근. `B`는 원래 생성 시각 유지 |
| **다른 볼륨으로 이동** | 유지(계승) | 갱신 | 갱신 | **갱신** | **`B` > `M`** |
| **복사** | 유지(계승) | 갱신 | 갱신 | **갱신** | **`B` > `M`** |
| 웹 다운로드 | 갱신 | 갱신 | 갱신 | 갱신 | 4개 근접 + `Zone.Identifier` ADS |
| **압축 해제** | **아카이브의 원본 시각으로 복원** | 갱신 | 갱신 | **갱신** | **`B` > `M`**, `M`의 초가 짝수 |
| 설치(MSI/setup) | 패키지의 원본 시각이 흔하다 | 갱신 | 갱신 | 갱신 | 같은 `B`가 수백 건 군집 |
| 파일 삭제 | 유지 | 유지 | 유지 | 유지 | **MACB로는 삭제 시각을 알 수 없다** |
| API timestomp | 조작값 | 조작값 | **갱신(조작 시각)** | 조작값 | `C`만 진짜, `$FN`은 잔존 |

핵심 판정 로직 세 줄로 요약한다.

```text
B == M == C == A  (초 단위 동일)   -> 이 볼륨에서 새로 만들어졌다
B >  M                              -> 외부에서 들어왔다 (복사/압축해제/타 볼륨 이동)
B <  M ~= C, A는 유지               -> 이 볼륨에서 만들고 나중에 편집했다
C만 최근, M/B는 과거                -> 이름변경·이동·권한변경 또는 timestomp
```

### 3단계 — `B > M`을 세부 구분하기

`B > M`까지 왔으면 원인이 셋이다. 다음 표로 갈라낸다.

| 구분 신호 | 복사 | 압축 해제 | 다른 볼륨에서 이동 |
| --- | --- | --- | --- |
| 같은 시각에 생성된 형제 파일 수 | 1~수개 | **수십~수백 개, 폴더 구조까지** | 1~수개 |
| `M`의 초 단위 | 원본과 동일(홀·짝 무관) | **짝수만** (ZIP은 2초 해상도) | 원본과 동일 |
| `M`의 서브초(ms) | 원본 값 보존 | **0** (DOS 시각에 서브초가 없다) | 원본 값 보존 |
| 원본 파일의 존재 | **같은 볼륨에 남아 있을 수 있다** | 아카이브 파일이 남아 있다 | 원본 볼륨에서 삭제됨 |
| `$UsnJrnl` 패턴 | 대상에 `FileCreate`만 | 아카이브 접근 후 다수 `FileCreate` | `FileCreate`만 (원본 볼륨에는 `FileDelete`) |
| 보조 흔적 | — | 아카이브의 `Zone.Identifier`, 압축 도구 Prefetch | USB라면 `USBSTOR`, LNK의 볼륨 시리얼 |

ZIP의 로컬 파일 헤더는 **MS-DOS 형식(2초 해상도, 시간대 정보 없음, 로컬 시간)** 으로 시각을 저장한다. 그래서 압축을 풀면 `M`이 항상 짝수 초로 떨어지고 서브초가 0이 된다. `.7z`/`.tar`는 더 정밀한 시각을 저장할 수 있으므로 이 신호가 항상 나오는 것은 아니다.

```powershell
# M의 초가 짝수이고 서브초가 0인 항목 = 아카이브 유래 후보
Import-Csv out\mft.csv |
  Where-Object {
    $_.LastModified0x10 -and
    ([datetime]$_.LastModified0x10).Second % 2 -eq 0 -and
    ([datetime]$_.LastModified0x10).Millisecond -eq 0 -and
    ([datetime]$_.Created0x10) -gt ([datetime]$_.LastModified0x10)
  } |
  Select-Object ParentPath, FileName, Created0x10, LastModified0x10
```

### 4단계 — 같은 `B` 시각의 군집을 찾는다

설치·대량 압축해제·대량 복사는 **동일한 `B` 시각을 공유하는 무리**를 남긴다. 이 군집이 사건 시각을 특정한다.

```powershell
# 초 단위로 묶어 생성 건수가 몰린 시점 상위 20
Import-Csv out\mft.csv |
  Where-Object { $_.Created0x10 } |
  Group-Object { ([datetime]$_.Created0x10).ToString('yyyy-MM-dd HH:mm:ss') } |
  Sort-Object Count -Descending | Select-Object -First 20 Count, Name
```

```text
Count Name
----- ----
  418 2026-01-08 11:02:19      <- 설치 (Windows Temp 하위)
  137 2026-03-14 07:29:40      <- 압축 해제 (Desktop 하위)
   62 2026-03-14 07:31:04
```

군집의 `ParentPath`를 보면 성격이 바로 나온다. `Windows\Temp`·`Program Files`면 설치, 사용자 폴더면 압축해제나 복사다.

### 5단계 — last access 갱신 여부 확인

Windows 7 이후 `A`(last access) 갱신은 **기본적으로 꺼져 있다.** 그래서 `A`는 대개 "레코드가 만들어질 때 찍힌 값"에 멈춰 있고, "사용자가 이 파일을 열었다"의 근거로 쓸 수 없다.

| 확인 대상 | 값 |
| --- | --- |
| 레지스트리 키 | `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem` |
| 값 이름 | `NtfsDisableLastAccessUpdate` (DWORD) |
| 라이브 확인 | `fsutil behavior query disablelastaccess` |

| 값 | 의미 |
| --- | --- |
| `0` | User Managed, 갱신 **활성** |
| `1` | User Managed, 갱신 **비활성** |
| `2` | System Managed, 갱신 활성 |
| `3` | System Managed, 갱신 비활성 |

Windows 7 ~ 초기 Windows 10에서는 `1`(비활성)이 사실상의 기본값이었고, Windows 10 1803 이후로는 System Managed 모드가 기본이 되어 시스템이 조건에 따라 켜고 끈다. **어느 쪽인지 추측하지 말고 대상 시스템의 실제 값을 읽는다.** 이미지 분석이라면 SYSTEM 하이브에서 그 값을 확인한다.

`A`가 갱신되는 시스템이었다면 그 자체가 강력한 무기가 된다. 반대로 비활성이었다면 "A가 안 바뀌었으므로 열지 않았다"는 결론은 **성립하지 않는다.**

### 6단계 — FILETIME과 KST 변환

MFT의 네 시각은 모두 **FILETIME**이다.

| 항목 | 값 |
| --- | --- |
| 기준 시각(epoch) | 1601-01-01 00:00:00 **UTC** |
| 단위 | 100나노초 (1초 = 10,000,000) |
| 크기 | 8바이트 (little-endian) |
| Unix epoch와의 차이 | **11644473600초** |
| KST | UTC + 9시간 |

```text
Unix초  = FILETIME / 10000000 - 11644473600
FILETIME = (Unix초 + 11644473600) * 10000000
```

검산용 실제 값 하나를 외워 두면 편하다.

```text
FILETIME 134179465610000000
  = 2026-03-14 07:22:41 UTC
  = 2026-03-14 16:22:41 KST
  = little-endian 8바이트: 80 F6 D5 57 83 B3 DC 01
```

```powershell
# FILETIME(10진) -> UTC / 로컬
[datetime]::FromFileTimeUtc(134179465610000000)
[datetime]::FromFileTime(134179465610000000)

# UTC 문자열 -> KST
([datetime]'2026-03-14 07:22:41').AddHours(9)

# CSV 컬럼 전체를 KST로 바꿔 새 컬럼 추가
Import-Csv out\mft.csv |
  Select-Object FileName, Created0x10,
    @{n='Created_KST'; e={ if ($_.Created0x10) { ([datetime]$_.Created0x10).AddHours(9) } }}
```

```bash
# hex little-endian FILETIME -> UTC (HxD에서 읽은 바이트를 그대로 붙인다)
python3 -c "
import struct, datetime
b = bytes.fromhex('80F6D55783B3DC01')
ft = struct.unpack('<Q', b)[0]
print(ft, datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft//10))
"
```

```text
134179465610000000 2026-03-14 07:22:41
```

GUI로는 DCode에 FILETIME 값을 넣어도 같은 결과가 나온다. 파서 출력의 시간대 표기를 반드시 확인하고, **이미 로컬 시간이면 +9를 또 하지 않는다.**

## 출력 필드 해석

| 관찰 | 해석 | 단독으로 결론 내릴 수 있나 |
| --- | --- | --- |
| `B` = `M` = `C` = `A` (초까지) | 이 볼륨에서 새로 생성 | 예 |
| `B` > `M` | 외부 유입 | 예 — 원인 구분은 3단계 표로 |
| `B` < `M`, `C` ≈ `M` | 로컬 생성 후 편집 | 예 |
| `C` > `M`, `C` > `B` (큰 차이) | 이름변경·이동·권한변경 또는 timestomp | 아니오 — `$FN`과 `$J`로 확인 |
| `A` = `B`, 모든 파일이 동일 | last access 갱신 비활성 | 예 — 레지스트리로 확증 |
| `A` < `M` | 수정 후 한 번도 안 읽었다 (갱신 활성 환경) | 아니오 — 갱신 설정 확인 필수 |
| 서브초가 정확히 `.000` | 아카이브 유래 또는 조작 | 아니오 — 2차 신호와 함께 |
| 같은 `B`가 대량 | 설치/대량 복사/대량 해제 | 예 — `ParentPath`로 성격 판별 |
| `M`이 `B`보다 수년 전 | 오래된 문서를 가져왔다 | 예 |
| 모든 시각이 미래 | 시스템 시계 조작 또는 timestomp | 아니오 |

## pivot: 다음에 볼 artifact

| MACB에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `B` > `M` (복사 의심) | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | 대상에 `FileCreate`만 있는가 |
| `B` > `M` (해제 의심) | 같은 `B` 군집의 부모 폴더 | 아카이브 파일이 그 폴더/상위에 있는가 |
| 아카이브 파일 발견 | `Zone.Identifier` ADS, `ZoneIdContents` | 다운로드 URL |
| 다운로드 URL | 브라우저 History ([FOR-0191](./chrome-history.html)) | 어느 사이트, 어느 시각 |
| `C`만 최근 | `$SI` vs `$FN` 대조 ([FOR-0024](./si-vs-fn-timestamps.html)) | 조작인가 정상 rename인가 |
| 이름변경 의심 | `$LogFile` ([FOR-0025](./logfile-basics.html)) | 인덱스 항목 삭제/추가 기록 |
| 삭제 시각 필요 | `$J`의 `FileDelete`, `$Recycle.Bin` `$I` | MACB에는 삭제 시각이 없다 |
| 압축 해제 시각 | Prefetch (`7Z.EXE-*.pf`, `WINRAR.EXE-*.pf`) | 그 시각에 압축 도구가 실행됐나 |
| 설치 군집 시각 | Amcache / Shimcache / `4688` ([FOR-0083](./event-4624-logon.html)) | 어떤 설치 프로그램이었나 |
| 사용자 열람 여부 | LNK / Jump List / RecentDocs / UserAssist ([FOR-0061](./userassist.html)) | `A`를 못 믿을 때의 대체 근거 |
| 타 볼륨 이동 의심 | `USBSTOR`, LNK의 볼륨 시리얼 | 어느 매체에서 왔나 |

## 흔한 함정

- **`C`를 Created로 읽는 것.** `C`는 MFT **entry Changed**다. Created는 `B`다. MFTECmd 컬럼명(`LastRecordChange0x10` vs `Created0x10`)을 보면 헷갈리지 않는다.
- **`A`(last access)로 "열어 봤다"를 주장하는 것.** Windows 7 이후 기본 비활성이다. `fsutil behavior query disablelastaccess` 또는 SYSTEM 하이브의 `NtfsDisableLastAccessUpdate`를 먼저 확인하고, 비활성이면 LNK·Jump List·UserAssist로 대체 근거를 만든다.
- **삭제 시각을 MACB에서 찾는 것.** 삭제는 대상 파일의 `$SI` MACB를 갱신하지 않는다. 삭제 시각은 `$UsnJrnl`의 `FileDelete`, `$LogFile`, `$Recycle.Bin`의 `$I` 파일에서 온다.
- **`B` > `M`을 파서 버그나 조작으로 단정하는 것.** 복사·압축해제·타 볼륨 이동에서 **정상적으로** 발생하는 패턴이다. 조작 판정은 `$FN`과 대조한 뒤에 한다.
- **같은 볼륨 이동과 복사를 같게 보는 것.** 같은 볼륨 이동은 `B`가 **유지**되고 `C`만 갱신된다. 복사는 `B`가 새로 찍힌다. 이 차이로 "원본이 어디 있었나"가 갈린다.
- **다운로드 파일의 `M`을 서버의 파일 날짜로 착각하는 것.** 브라우저는 로컬에 새로 쓰므로 `M`도 다운로드 시각이다. 원래 작성 시각을 알고 싶으면 파일 내부 메타데이터(EXIF, Office `docProps`)를 본다.
- **압축해제 파일의 `M`을 "그 시각에 편집됨"으로 읽는 것.** 아카이브에 저장돼 있던 과거 시각이 복원된 것이다. 초가 짝수이고 서브초가 0이면 강한 신호다.
- **ZIP 시각의 시간대를 UTC로 가정하는 것.** MS-DOS 형식 시각에는 시간대 정보가 없고 **압축한 사람의 로컬 시간**이 들어간다. 그래서 해제된 파일의 `M`은 UTC로 보정되지 않은 값일 수 있다. 이 값끼리의 비교는 안전하지만 다른 UTC 시각과의 정밀 비교는 위험하다.
- **폴더의 MACB를 파일처럼 읽는 것.** 디렉터리의 `M`/`C`는 내부 색인이 바뀔 때(항목 추가·삭제) 갱신된다. "폴더를 수정했다"가 아니라 "그 안에서 뭔가 생기거나 사라졌다"로 읽는다.
- **시간대를 두 번 더하는 것.** analyzeMFT의 `-l`은 로컬 시간대로 출력한다. 이미 KST인 출력에 +9를 더하면 18시간이 틀어진다. EVTX 로그온 시각처럼 확실한 기준점 하나로 맞춘다.
- **초 단위까지 같은 것을 "동시"로만 보는 것.** 서브초(밀리초)까지 비교하면 순서가 드러난다. 파서가 서브초를 잘라 표시하는 경우가 있으니 원본 정밀도를 확인한다.
- **`FileSize`가 0인 파일의 시각을 신뢰하는 것.** 생성만 되고 내용이 안 쓰인 파일은 `M`이 `B`와 같다. 실제 작업 흔적이 아니다.

## 교차검증

```powershell
# 1) 같은 파일의 $SI 와 $FN 8개 시각을 한 화면에
Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq '128512' } |
  Select-Object Created0x10, Created0x30, LastModified0x10, LastModified0x30,
                LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30

# 2) last access 갱신 설정 (라이브)
fsutil behavior query disablelastaccess

# 3) 압축 도구가 그 시각에 실행됐는지 (Prefetch)
Get-ChildItem C:\Windows\Prefetch -Filter '*RAR*'
Get-ChildItem C:\Windows\Prefetch -Filter '*7Z*'
```

```bash
# 4) TSK로 같은 레코드의 시각을 재확인 — 속성별로 나온다
istat -o 2048 image.dd 128512

# 5) bodyfile + mactime 으로 그 날짜의 모든 시각 이벤트를 시간순 전개
mactime -b mft.body -d -z UTC 2026-03-14 | rg 'notes.txt'

# 6) $J 로 실제 행위 확인 (복사인지 해제인지)
rg -i 'notes.txt' usn.csv
```

`istat` 출력의 `$STANDARD_INFORMATION`과 `$FILE_NAME` 시각이 CSV와 다르면 **파서 시간대 설정을 의심**한다. 값 자체가 다른 경우는 거의 없다.

## mini walkthrough

```text
문제:
"2026-03-14 사건 당일 유출 문서를 특정하고, 그 파일이 이 PC에서 작성된 것인지
 외부에서 들어온 것인지 판정하세요. 첨부: $MFT"

1. 파싱
   MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv

2. 첫 시도 (실패한 판정):
   Import-Csv out\mft.csv |
     Where-Object { $_.Created0x10 -like '2026-03-14*' -and $_.Extension -eq '.txt' } |
     Select-Object ParentPath, FileName, Created0x10

   ParentPath                   FileName       Created0x10
   ----------                   --------       -----------
   .\Users\jhkim\Desktop        notes.txt      2026-03-14 07:29:40

   여기서 "07:29:40 에 사용자가 Desktop 에 notes.txt 를 작성했다" 고 답했다.
   -> 오답. 생성 시각만 봤다.

3. 왜 틀렸나 — 네 시각을 전부 펼친다
   Import-Csv out\mft.csv | Where-Object { $_.FileName -eq 'notes.txt' } |
     Select-Object EntryNumber, Created0x10, LastModified0x10,
                   LastRecordChange0x10, LastAccess0x10, HasAds

   EntryNumber          : 128512
   Created0x10   (B)    : 2026-03-14 07:29:40
   LastModified0x10 (M) : 2025-11-02 13:44:22     <-- 4개월 전
   LastRecordChange (C) : 2026-03-14 07:29:40
   LastAccess0x10   (A) : 2026-03-14 07:29:40
   HasAds               : False

   B > M 이다. 이 PC에서 07:29:40 에 "만들어진" 것이 아니라
   그 시각에 "들어온" 파일이다. M 은 원본이 마지막으로 편집된 시각이다.

4. 복사인가 압축해제인가 — 3단계 표를 적용
   4-1) M 의 초 = 22 (짝수), 서브초 = 0        -> ZIP 2초 해상도 신호
   4-2) 같은 B 시각의 형제 개수
        Import-Csv out\mft.csv |
          Where-Object { $_.Created0x10 -eq '2026-03-14 07:29:40' } |
          Measure-Object | Select-Object Count
        -> 137

   137개 파일이 같은 초에 생성됐다. 복사 한 건이 아니라 대량 전개다.
   -> 압축 해제로 판정

5. 아카이브를 찾는다
   Import-Csv out\mft.csv |
     Where-Object { $_.ParentPath -like '*jhkim*' -and
                    $_.Extension -in '.zip','.7z','.rar' } |
     Select-Object FileName, Created0x10, LastModified0x10, HasAds, ZoneIdContents

   FileName        Created0x10          LastModified0x10     HasAds ZoneIdContents
   --------        -----------          ----------------     ------ --------------
   evidence.zip    2026-03-14 07:28:11  2026-03-14 07:28:11  True   [ZoneTransfer]...ZoneId=3

   07:28:11 다운로드 -> 07:29:40 해제. 1분 29초 차이. 앞뒤가 맞는다.
   ZoneId=3 = 인터넷에서 받음.

6. 군집 성격 확증
   Import-Csv out\mft.csv |
     Where-Object { $_.Created0x10 -eq '2026-03-14 07:29:40' } |
     Group-Object ParentPath | Sort-Object Count -Descending |
     Select-Object -First 3 Count, Name

   Count Name
   ----- ----
      94 .\Users\jhkim\Desktop\evidence
      31 .\Users\jhkim\Desktop\evidence\docs
      12 .\Users\jhkim\Desktop\evidence\img

   폴더 구조까지 한 번에 만들어졌다 -> 압축 해제 확정.

7. 조작 가능성 배제
   Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq '128512' } |
     Select-Object 'SI<FN', uSecZeros, Created0x30, LastModified0x30
   -> SI<FN=False, uSecZeros=False, 0x30 값이 0x10 과 정합
      timestomp 아님. B > M 은 정상적인 압축해제 패턴.

8. KST 변환
   07:28:11 UTC = 16:28:11 KST (다운로드)
   07:29:40 UTC = 16:29:40 KST (압축 해제)

정답: notes.txt 는 이 PC에서 작성된 것이 아니다.
      evidence.zip 을 2026-03-14 16:28:11 KST 에 인터넷에서 받아
      16:29:40 KST 에 압축 해제한 결과물이며,
      원본은 2025-11-02 13:44:22 에 마지막으로 편집된 문서다.
```

2단계의 오답은 **생성 시각 하나만 본 것**에서 나왔다. 3단계에서 `M`을 함께 펼치자 `B > M` 역전이 드러나고, 4단계의 "짝수 초 + 137개 군집"이 압축해제로 확정했다. `Created0x10`만 보는 습관이 이 유형에서 가장 많은 오답을 만든다.

## 막혔을 때 다음 체크

1. `C`를 Created로 오해하지 않았는가 — `C`는 MFT entry Changed다
2. 네 시각을 **전부** 펼쳤는가 — `Created0x10` 단독 판정이 최다 오답
3. `B` > `M`인가 → 복사·압축해제·타 볼륨 이동. 3단계 표로 갈라낸다
4. `M`의 초가 짝수이고 서브초가 0인가 → ZIP 유래
5. 같은 `B` 시각의 형제 개수를 셌는가 → 1개면 복사, 수십 개면 해제/설치
6. `A`를 근거로 쓰기 전에 `NtfsDisableLastAccessUpdate`를 확인했는가
7. 삭제 시각을 MACB에서 찾고 있는가 → `$J`/`$LogFile`/`$Recycle.Bin`으로 이동
8. `C`만 최근이면 → `$SI` vs `$FN` 대조로 rename과 timestomp를 구분
9. 시간대를 두 번 변환하지 않았는가 → 파서의 UTC/로컬 설정 확인
10. 파일 내부 메타데이터(EXIF, Office `docProps`)를 봤는가 — 파일시스템 시각과 독립된 제3의 증거다

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$STANDARD_INFORMATION`과 `$FILE_NAME`이 각각 타임스탬프 세트를 갖는다는 구조적 근거
- SRC-014 — Microsoft Learn, File Times: FILETIME이 1601-01-01 UTC 기준 100ns 단위이며 Unix epoch와 11644473600초 차이라는 값의 출처
- SRC-004 — Eric Zimmerman 문서: MFTECmd의 `Created0x10`/`LastRecordChange0x10` 등 컬럼명과 bodyfile 출력 옵션
- `NtfsDisableLastAccessUpdate`의 **기본값은 Windows 버전과 볼륨 조건에 따라 다르다.** 추정하지 말고 대상 시스템의 `fsutil behavior query disablelastaccess` 또는 SYSTEM 하이브 값을 확인할 것
- 행위별 MACB 변화는 Windows 버전·복사에 사용한 도구(탐색기 / `robocopy` / `xcopy /d` / 압축 도구)에 따라 달라질 수 있다. 결론은 `$UsnJrnl`·`$LogFile`과 교차검증할 것
- MFTECmd / analyzeMFT의 컬럼명과 시간대 옵션은 버전에 따라 다르므로 실제 출력에서 확인할 것
