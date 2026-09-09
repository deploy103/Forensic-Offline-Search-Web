---
id: FOR-0038
title: "Timestomp 탐지: $SI/$FN 불일치부터 나노초 0까지 7가지 지표"
slug: "timestomp-detection"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$STANDARD_INFORMATION", "$FILE_NAME", "$MFT", "$UsnJrnl", "MACB", "EntryNumber", "Prefetch", "Amcache"]
file_paths: ["C:\\$MFT", "C:\\$Extend\\$UsnJrnl", "C:\\Windows\\Prefetch", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "C:\\Windows\\System32\\config\\SOFTWARE"]
registry_paths: ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"]
event_ids: []
protocols: []
tools: ["MFTECmd", "analyzeMFT", "Timeline Explorer", "NTFS Log Tracker", "RegistryExplorer", "WinPrefetchView", "Autopsy", "HxD"]
commands: ["MFTECmd.exe -f C:\\case\\$MFT --csv C:\\case\\out --csvf mft.csv", "MFTECmd.exe -f C:\\case\\$J --csv C:\\case\\out --csvf j.csv", "istat -o 2048 image.dd 84213", "analyzeMFT.py -f $MFT -o mft.csv"]
regex_patterns: ["\\.0000000$", "\\.000000$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastAccess0x10", "SI<FN", "uSecZeros", "EntryNumber", "SequenceNumber", "InstallDate", "InstallTime"]
file_formats: ["ntfs"]
primary_terms: ["timestomp", "타임스탬프 조작", "uSecZeros"]
keywords: ["timestomp", "타임스탬프 조작", "$SI", "$FN", "$STANDARD_INFORMATION", "$FILE_NAME", "MACB", "나노초 0", "uSecZeros", "BASIC_INFO_CHANGE", "안티포렌식", "T1070.006"]
aliases: ["타임스탬프 조작", "timestomp", "시간 조작 탐지", "시간이 이상하다", "생성시각이 수정시각보다 늦다", "si fn 불일치", "타임스톰프"]
symptom_keywords: ["생성 시각이 수정 시각보다 나중이다", "타임스탬프가 조작된 것 같다", "시간이 다른 파일과 너무 다르다", "실행 기록보다 파일이 늦게 생겼다", "어느 시각을 믿어야 하는지 모르겠다"]
related: ["FOR-0021", "FOR-0027", "FOR-0039"]
source_ids: ["SRC-005", "SRC-013", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

timestomp는 단일 증거로 판정하지 않는다. `$SI`와 `$FN`의 8개 타임스탬프 불일치를 1차 지표로 삼고, 초 이하 자리가 정확히 0인지·MFT 엔트리 번호 순서와 모순되는지·`$UsnJrnl`에 `BASIC_INFO_CHANGE`가 단독으로 남았는지를 겹쳐서 **지표 2개 이상이 같은 방향을 가리킬 때** 결론을 낸다.

## 어떤 문제에서 필요한가

- 지문이 "타임스탬프가 조작되었다", "진짜 생성 시각을 찾아라"라고 요구하는 경우
- 파일 생성 시각이 수정 시각보다 **나중**인 경우
- 사건 시각(로그·실행 기록)과 파일 시각이 앞뒤가 맞지 않는 경우
- 악성 파일의 시각이 시스템 파일과 똑같이 맞춰져 있는 경우 (Windows 설치 시각으로 위장하는 전형적 기법)
- 타임라인을 만들었는데 한 파일만 다른 시대에 있는 경우

MITRE ATT&CK에서 이 행위는 Indicator Removal 하위의 Timestomp(T1070.006)로 분류된다. 목적은 타임라인 분석 방해이므로, **탐지에 성공하면 그 파일이 곧 사건의 핵심**인 경우가 많다.

## 문제에서 처음 볼 단서

1. `$MFT` 파서 CSV에서 `Created0x10`과 `Created0x30`이 다른 행
2. 초 이하 자리가 `.0000000`인 타임스탬프 (`uSecZeros` 계열 컬럼이 있으면 그 컬럼)
3. `Created`(B)가 `LastModified`(M)보다 **나중**인 행
4. `LastRecordChange`(MFT 엔트리 변경 시각, C)만 최근이고 나머지가 과거인 행
5. 같은 폴더의 이웃 파일들과 시각이 수년 단위로 다른 파일
6. `$UsnJrnl`에서 `BASIC_INFO_CHANGE`가 `DATA_*` 없이 단독으로 찍힌 레코드

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
```

CSV가 나오면 세 줄로 후보를 좁힌다.

```powershell
# 1) $SI 와 $FN 의 생성 시각이 다른 항목
Import-Csv .\out\mft.csv |
  Where-Object { $_.Created0x10 -and $_.Created0x30 -and $_.Created0x10 -ne $_.Created0x30 } |
  Select-Object EntryNumber, ParentPath, FileName, Created0x10, Created0x30

# 2) 초 이하 자리가 전부 0 인 항목
Import-Csv .\out\mft.csv |
  Where-Object { $_.Created0x10 -match '\.0000000$' } |
  Select-Object EntryNumber, FileName, Created0x10, LastModified0x10

# 3) 생성이 수정보다 나중인 항목
Import-Csv .\out\mft.csv | Where-Object {
  $_.Created0x10 -and $_.LastModified0x10 -and
  [datetime]$_.Created0x10 -gt [datetime]$_.LastModified0x10
} | Select-Object EntryNumber, FileName, Created0x10, LastModified0x10
```

## 상세 절차

### 1단계 — 판정의 토대: 8개 타임스탬프

NTFS는 파일 하나에 타임스탬프를 **두 세트, 총 8개** 보관한다 ([FOR-0021](./mft-basics.html)).

| 속성 | 타입 | 담긴 시각 | 조작 난이도 |
| --- | --- | --- | --- |
| `$STANDARD_INFORMATION` | `0x10` | M / A / C / B 4개 | **쉽다.** Win32 API(`SetFileTime`)로 사용자 권한에서 변경 가능 |
| `$FILE_NAME` | `0x30` | M / A / C / B 4개 | **어렵다.** API로 직접 쓸 수 없고 파일시스템이 관리한다 |

MACB의 의미:

| 약자 | 이름 | 갱신 시점 |
| --- | --- | --- |
| M | Modified | 파일 **내용**이 바뀔 때 |
| A | Accessed | 파일을 읽을 때 (Win7+ 기본 갱신 비활성인 경우가 많다) |
| C | **MFT Changed** | **MFT 엔트리 자체가 바뀔 때** (이름·속성·시각 변경 포함) |
| B | Born (Created) | 파일이 생성될 때 |

여기서 결정적인 사실 두 가지다.

- 대부분의 timestomp 도구는 `SetFileTime`을 쓰므로 **`$SI`만 바꾸고 `$FN`은 그대로 남긴다**
- `SetFileTime`은 `$SI`의 **C(MFT Changed)를 지정할 수 없다.** 타임스탬프를 바꾸는 행위 자체가 MFT 엔트리를 변경하므로 C는 **조작 시점의 실제 시각**으로 갱신된다

즉 `$FN`의 4개와 `$SI`의 C가 "진짜에 가까운 시각"이고, `$SI`의 M/A/B가 "의심해야 하는 시각"이다.

### 2단계 — 지표 7가지 (강도 순)

이 표가 이 글의 핵심이다. **위쪽이 강하다.**

| # | 지표 | 무엇을 보면 되나 | 강도 | 주요 오탐 사유 |
| --- | --- | --- | --- | --- |
| ① | **`$SI` vs `$FN` 불일치** | `Created0x10` ≠ `Created0x30` (M/A/C도 같이) | 매우 강함 | 파일 이동·이름변경 시 `$FN`이 갱신되어 정상적으로 값이 달라질 수 있다. 하드링크가 여러 개인 파일 |
| ② | **초 이하 자리가 정확히 0** | `.0000000`으로 끝나는 시각 | 강함 | ZIP/tar 해제(DOS 시각은 2초 단위), FAT/exFAT 매체 경유 복사, 일부 정상 설치 프로그램 |
| ③ | **엔트리 번호와 생성 순서 모순** | `EntryNumber`가 큰데 `Created`가 이웃보다 훨씬 과거 | 중간~강함 | 레코드 슬롯 재사용(`SequenceNumber` > 1), 대량 복사, MFT 확장 구간 |
| ④ | **`$UsnJrnl`의 `BASIC_INFO_CHANGE` 단독** | `DATA_*` 없이 `BASIC_INFO_CHANGE`만(+`CLOSE`) 찍힌 레코드 | 강함 | 읽기전용/숨김 속성 변경, 백신·백업 도구의 속성 조작, 압축 속성 변경 |
| ⑤ | **파일 시각이 OS 설치 시각보다 이전** | `Created0x10` < `InstallDate` | 중간~강함 | 백업 복원, 다른 PC에서 복사(M은 보존됨), 압축 해제. **B(생성)로 판단해야 하고 M으로 판단하면 오탐** |
| ⑥ | **이웃 파일과의 극단적 괴리** | 같은 폴더 파일들의 시각 분포에서 혼자 떨어짐 | 중간 | 오래된 파일을 나중에 그 폴더로 이동, 설치 프로그램이 심은 배포 파일 |
| ⑦ | **실행 기록과 파일 생성 시각 모순** | Prefetch/Amcache/EVTX 4688의 실행 시각 < 파일 `Created` | 중간~강함 | 같은 이름의 다른 파일이 먼저 있었다, 파일 재설치·업데이트, Prefetch 이름 해시 충돌 |

보조 지표(위 7개를 보강한다):

| 지표 | 관찰 | 해석 |
| --- | --- | --- |
| `$SI`의 C만 최근 | M/A/B는 2019년, C는 어제 | **`$SI`가 어제 조작되었다**는 강한 신호 |
| B > M (생성이 수정보다 나중) | `Created0x10` > `LastModified0x10` | 복사로도 생길 수 있으나(복사는 B를 새로 찍고 M을 보존), 값 차이가 수년이면 조작 의심 |
| `$SI` M/A/B가 완전히 동일한 값 | 세 값이 초까지 같다 | 도구가 한 번에 같은 값을 써넣은 흔적 |
| 시스템 파일과 시각이 동일 | `kernel32.dll` 등과 초까지 일치 | 위장 목적으로 시스템 파일 시각을 복사한 전형적 패턴 |
| `$SI`의 USN 값 | `$SI` 안의 Update Sequence Number | `$UsnJrnl`의 마지막 레코드와 대조 가능 |
| `$FN`의 A/M이 B보다 이전 | `$FN` 내부의 논리적 모순 | `$FN`까지 조작한 도구 사용 의심 |

### 3단계 — ① $SI vs $FN 비교 (1차 지표)

`MFTECmd`의 컬럼 이름에 속성 타입이 붙어 있다.

| 컬럼 | 출처 | 의미 |
| --- | --- | --- |
| `Created0x10` | `$SI` | 조작 가능한 생성 시각 |
| `Created0x30` | `$FN` | 조작이 어려운 생성 시각 |
| `LastModified0x10` / `0x30` | `$SI` / `$FN` | 수정 시각 두 세트 |
| `LastRecordChange0x10` / `0x30` | `$SI` / `$FN` | MFT 엔트리 변경 시각 |
| `LastAccess0x10` / `0x30` | `$SI` / `$FN` | 접근 시각 |
| `SI<FN` | 계산값 | `$SI` 시각이 `$FN`보다 **이전**이면 참 — 과거로 되돌린 조작의 전형 |
| `uSecZeros` | 계산값 | 초 이하 자리가 0인 타임스탬프가 있으면 참 |

```powershell
# $SI 를 과거로 되돌린 후보 (파서가 계산 컬럼을 제공할 때)
Import-Csv .\out\mft.csv |
  Where-Object { $_.'SI<FN' -eq 'True' -or $_.uSecZeros -eq 'True' } |
  Select-Object EntryNumber, FileName, Created0x10, Created0x30, uSecZeros |
  Export-Csv .\candidates.csv -NoTypeInformation
```

Sleuth Kit으로 같은 것을 본다. `istat`은 두 속성을 나란히 보여준다.

```bash
istat -o 2048 image.dd 84213
```

```text
$STANDARD_INFORMATION Attribute Values:
Created:        2019-03-19 04:12:00.0000000 (UTC)
File Modified:  2019-03-19 04:12:00.0000000 (UTC)
MFT Modified:   2026-03-14 07:31:52.6641280 (UTC)
Accessed:       2019-03-19 04:12:00.0000000 (UTC)

$FILE_NAME Attribute Values:
Created:        2026-03-14 07:20:11.4820096 (UTC)
File Modified:  2026-03-14 07:20:11.4820096 (UTC)
MFT Modified:   2026-03-14 07:20:11.4820096 (UTC)
Accessed:       2026-03-14 07:20:11.4820096 (UTC)
```

이 출력 하나에 지표 3개가 동시에 들어 있다.

| 관찰 | 지표 |
| --- | --- |
| `$SI` Created 2019 vs `$FN` Created 2026 | ① 불일치 |
| `$SI`의 세 값이 `.0000000` | ② 초 이하 0 |
| `$SI` MFT Modified만 2026-03-14 07:31:52 | 보조 — **07:31:52가 조작 실행 시각** |

결론은 이렇게 쓴다: **"이 파일의 실제 생성 시각은 2026-03-14 07:20:11 UTC(=16:20:11 KST)이고, 2026-03-14 07:31:52 UTC에 `$SI` 타임스탬프가 2019-03-19로 조작되었다."**

### 4단계 — ② 초 이하 자리 확인

FILETIME은 1601-01-01 UTC 기준 **100나노초** 단위다. 정상적으로 파일시스템이 찍은 값은 초 이하 자리에 임의의 수가 들어간다(`.4820096`). 반면 사람이 지정한 시각을 초 단위로 변환해 `SetFileTime`에 넘기면 **초 이하가 정확히 0**이 된다.

```bash
# CSV 에서 초 이하 0 패턴 세기
rg -c '\.0000000' out/mft.csv
rg '\.0000000' out/mft.csv | rg -v 'True,True' | head -20
```

```powershell
Import-Csv .\out\mft.csv |
  Where-Object {
    $_.Created0x10      -match '\.0*$|\.0000000$' -and
    $_.LastModified0x10 -match '\.0*$|\.0000000$'
  } | Measure-Object | Select-Object Count
```

오탐 판별:

| 초 이하 0의 원인 | 구별 방법 |
| --- | --- |
| **timestomp 도구** | `$FN`은 0이 아니다. `$SI`만 0 |
| ZIP/tar 해제 | `$FN`도 함께 정상. **초 값이 짝수**인 경우가 많다(DOS 시각 2초 단위). 압축 파일 원본이 시스템에 있다 |
| FAT32/exFAT USB 경유 복사 | 여러 파일이 **한꺼번에** 0을 가진다. 같은 폴더 전체가 그렇다 |
| 정상 설치 프로그램 | 시스템 폴더의 배포 파일 다수가 동일 패턴 |

**한 파일만 0이고 `$FN`은 정상이면 조작, 폴더 전체가 0이면 매체/압축 경유**로 읽는 것이 실전 규칙이다.

### 5단계 — ③ MFT 엔트리 번호 순서

NTFS는 새 파일에 **가장 낮은 빈 MFT 슬롯**을 배정한다. 삭제가 적은 볼륨에서는 결과적으로 엔트리 번호가 생성 시각순으로 증가한다. 그래서 "엔트리 번호는 매우 큰데 생성 시각은 아주 과거"인 파일은 모순이다.

```powershell
# 엔트리 번호로 정렬해 생성 시각이 역행하는 지점 찾기
Import-Csv .\out\mft.csv |
  Where-Object { $_.IsDirectory -eq 'False' -and $_.InUse -eq 'True' } |
  Sort-Object { [int]$_.EntryNumber } |
  Select-Object EntryNumber, SequenceNumber, FileName, Created0x10 |
  Export-Csv .\by_entry.csv -NoTypeInformation
```

```text
EntryNumber  SequenceNumber  FileName        Created0x10
...
91000        1               setup_a.log     2026-03-14 07:19:41.2210048
91001        1               setup_b.log     2026-03-14 07:19:44.8830464
91002        1               svc.exe         2019-03-19 04:12:00.0000000   <- 모순
91003        1               setup_c.log     2026-03-14 07:20:33.1140096
```

앞뒤 엔트리는 2026년인데 91002만 2019년이다. **`SequenceNumber`가 1이므로 슬롯 재사용도 아니다** — 이 파일은 2026-03-14에 만들어졌다.

오탐 사유: `SequenceNumber`가 2 이상이면 그 슬롯은 재사용된 것이므로 순서 논리가 약해진다. 대량 복사·설치 시에는 짧은 시간에 수천 개가 만들어져 순서가 촘촘해지므로 판정에 쓸 여유가 없다.

### 6단계 — ④ $UsnJrnl의 BASIC_INFO_CHANGE

`$UsnJrnl`은 파일 변경 이유를 플래그로 남긴다. 타임스탬프 변경은 "기본 정보 변경"으로 기록된다.

| USN Reason | 값 | 의미 |
| --- | --- | --- |
| `USN_REASON_BASIC_INFO_CHANGE` | `0x00008000` | **타임스탬프/파일 속성 변경** |
| `USN_REASON_DATA_OVERWRITE` | `0x00000001` | 내용 덮어쓰기 |
| `USN_REASON_DATA_EXTEND` | `0x00000002` | 내용 추가 |
| `USN_REASON_FILE_CREATE` | `0x00000100` | 파일 생성 |
| `USN_REASON_RENAME_OLD_NAME` | `0x00001000` | 이름 변경 전 이름 |
| `USN_REASON_RENAME_NEW_NAME` | `0x00002000` | 이름 변경 후 이름 |
| `USN_REASON_CLOSE` | `0x80000000` | 핸들 닫힘 |

판독 규칙:

| 패턴 | 해석 |
| --- | --- |
| `FILE_CREATE` → `DATA_EXTEND` → `CLOSE` | 정상적인 파일 생성 |
| `DATA_OVERWRITE` + `BASIC_INFO_CHANGE` | 내용을 저장하면서 시각이 갱신됨 — 정상 |
| **`BASIC_INFO_CHANGE` + `CLOSE` 단독** | 내용은 그대로인데 시각/속성만 바뀌었다 — **timestomp 후보** |
| `BASIC_INFO_CHANGE`가 파일 생성 직후 수십 초 안에 | 만들자마자 시각을 덮어썼다 — 매우 강한 신호 |

```powershell
MFTECmd.exe -f 'C:\case\$J' --csv "C:\case\out" --csvf j.csv
```

```bash
# 대상 파일의 USN 이력을 시간순으로
rg -i 'svc\.exe' out/j.csv | head -20
```

```text
2026-03-14 07:19:58.1120000, svc.exe, 91002, FileCreate
2026-03-14 07:19:58.4410000, svc.exe, 91002, DataExtend
2026-03-14 07:20:11.4820096, svc.exe, 91002, DataExtend|Close
2026-03-14 07:31:52.6641280, svc.exe, 91002, BasicInfoChange
2026-03-14 07:31:52.6641280, svc.exe, 91002, BasicInfoChange|Close
```

마지막 두 줄의 시각이 3단계에서 본 `$SI`의 MFT Modified와 **정확히 일치한다.** 조작 시각이 두 출처로 확정된다.

`$UsnJrnl`의 중요한 성질: **`$UsnJrnl`의 레코드 시각 자체는 `SetFileTime`으로 바꿀 수 없다.** 조작자가 지우려면 저널 전체를 삭제해야 하므로, 저널이 남아 있으면 조작 시각의 강력한 증거가 된다 ([FOR-0027](./usnjrnl-basics.html)).

오탐 사유: 읽기전용·숨김·아카이브 속성 변경, 백신 검사 후 속성 복원, 백업 소프트웨어의 아카이브 비트 조작도 `BASIC_INFO_CHANGE`를 만든다. 따라서 이 지표는 **다른 지표와 시각이 일치할 때** 결정적이 된다.

### 7단계 — ⑤ OS 설치 시각과 비교

파일 생성 시각이 OS 설치보다 이전이면 그 볼륨에서 만들어진 파일이 아니다.

```text
레지스트리: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
  InstallDate  (REG_DWORD)  = Unix epoch 초, UTC
  InstallTime  (REG_QWORD)  = FILETIME (100ns, 1601 기준 UTC)
```

```powershell
# 라이브 시스템
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$d = (Get-ItemProperty $k).InstallDate
[datetimeoffset]::FromUnixTimeSeconds($d).UtcDateTime      # UTC
[datetime]::FromFileTimeUtc((Get-ItemProperty $k).InstallTime)
```

오프라인 이미지에서는 `SOFTWARE` 하이브를 꺼내 RegistryExplorer로 같은 키를 본다. 대안 지표:

| 대안 | 위치 |
| --- | --- |
| `$MFT` 자체의 생성 시각 | 엔트리 0의 `Created` = 볼륨 포맷 시각 |
| 루트 디렉터리 생성 시각 | 엔트리 5의 `Created` |
| `C:\Windows` 폴더의 `$FN` Created | 설치 시각의 근사값 |

**반드시 B(생성)로 비교한다.** M(수정)이 설치 시각보다 이전인 것은 정상이다 — 다른 PC에서 복사하거나 압축을 풀면 M은 보존되고 B만 새로 찍힌다. 여기서 지표를 잘못 고르는 실수가 가장 많다.

### 8단계 — ⑥ 이웃 파일과 비교, ⑦ 실행 기록과 비교

```powershell
# 같은 폴더 파일들의 시각 분포
Import-Csv .\out\mft.csv |
  Where-Object { $_.ParentPath -like '*\Windows\Temp*' } |
  Select-Object FileName, Created0x10, Created0x30 |
  Sort-Object Created0x10
```

혼자 수년 떨어진 파일이 후보다. 오탐: 오래된 파일을 나중에 그 폴더로 이동한 경우(이 경우 `$FN`이 이동 시각으로 갱신되어 `$SI`/`$FN` 불일치가 정상적으로 발생한다 — ①과 겹쳐 판단하면 오류가 난다).

실행 기록과의 대조는 강력하다.

| 대조 대상 | 무엇을 보나 | 모순의 의미 |
| --- | --- | --- |
| Prefetch (`C:\Windows\Prefetch\*.pf`) | 마지막 실행 시각, 실행 횟수 | 실행 시각이 파일 `Created`보다 이전이면 모순 |
| Amcache (`Amcache.hve`) | 파일 항목의 키 LastWrite, 파일 크기·해시 | 등록 시각이 생성 시각보다 이전이면 모순 |
| EVTX 4688 / Sysmon 1 | 프로세스 생성 시각과 이미지 경로 | 위와 동일 ([FOR-0083](./event-4624-logon.html)와 같은 EVTX 라인) |
| Shimcache / UserAssist | 실행 흔적과 순서 | 보강 증거 ([FOR-0061](./userassist.html)) |

오탐: 같은 경로에 같은 이름의 **다른 파일**이 먼저 있었고 나중에 교체된 경우, Prefetch 항목이 이전 파일의 것일 수 있다. Prefetch 안의 참조 파일 목록과 볼륨 시리얼로 확인한다.

### 9단계 — 판정 절차

```text
1. $MFT, $Extend\$UsnJrnl:$J, SOFTWARE 하이브를 추출한다.
2. MFTECmd 로 $MFT 와 $J 를 각각 CSV 로 변환한다.
3. 스크리닝 (넓게):
     - Created0x10 != Created0x30
     - .0000000 로 끝나는 시각
     - Created0x10 > LastModified0x10
     - LastRecordChange0x10 만 최근
4. 후보 파일마다 지표 ①~⑦을 표로 채운다. 몇 개가 성립하는가.
5. $J 에서 그 파일의 전체 USN 이력을 시간순으로 뽑는다.
6. 조작 시각을 확정한다:
     $SI 의 MFT Changed 시각  ==  $J 의 BASIC_INFO_CHANGE 시각
7. 실제 시각을 확정한다:
     $FN 의 Created           ==  $J 의 FILE_CREATE 시각
8. 결론을 서술한다 (아래 형식).
```

결론 서술 형식:

```text
[대상]      C:\Windows\Temp\svc.exe  (MFT EntryNumber 91002, SequenceNumber 1)

[표시된 시각]  $SI Created / Modified / Accessed = 2019-03-19 04:12:00.0000000 UTC
[실제 시각]    $FN Created                        = 2026-03-14 07:20:11.4820096 UTC
                                                  = 2026-03-14 16:20:11 KST
[조작 시각]    $SI MFT Changed                    = 2026-03-14 07:31:52.6641280 UTC
               $J  BasicInfoChange                = 2026-03-14 07:31:52.6641280 UTC (일치)

[성립 지표]  ① $SI/$FN 불일치     성립 (생성 7년 차이)
             ② 초 이하 0          성립 ($SI 3개 값 모두 .0000000, $FN 은 정상)
             ③ 엔트리 순서 모순   성립 (91001/91003 은 2026-03-14, SequenceNumber=1)
             ④ BASIC_INFO_CHANGE  성립 (DATA_* 없이 단독, 생성 후 11분 41초)
             ⑤ 설치 시각 이전     성립 (InstallTime = 2024-11-02)
             ⑥ 이웃 파일 괴리     성립 (같은 폴더 전 파일이 2026-03)
             ⑦ 실행 기록 모순     성립 (Prefetch 마지막 실행 2026-03-14 07:22)

[결론] 7개 지표가 모두 같은 방향을 가리킨다. svc.exe 는 2026-03-14 07:20:11 UTC 에
       생성되었고, 07:31:52 UTC 에 $SI 타임스탬프가 2019-03-19 로 소급 조작되었다.
       $FN 은 조작되지 않았으므로 실제 생성 시각의 근거로 사용한다.
```

**"조작되었다"만 쓰지 않는다.** ① 표시된 시각, ② 실제 시각, ③ 조작 시각, ④ 근거 지표를 함께 적어야 답으로 인정된다.

## 출력 필드 해석

| 필드 | 출처 | 신뢰도 | 비고 |
| --- | --- | --- | --- |
| `Created0x10` (B) | `$SI` | **낮다** | 조작의 1순위 대상 |
| `LastModified0x10` (M) | `$SI` | 낮다 | 조작 대상 |
| `LastAccess0x10` (A) | `$SI` | 낮다 | 그리고 Win7+에서 갱신 자체가 꺼진 경우가 많다 |
| `LastRecordChange0x10` (C) | `$SI` | **높다** | `SetFileTime`으로 지정 불가. 조작 시각을 알려준다 |
| `Created0x30` 등 | `$FN` | **높다** | API로 직접 쓸 수 없다 |
| `SequenceNumber` | MFT 헤더 | 높다 | 1이면 슬롯 첫 사용 — 지표 ③의 전제 |
| `$J`의 `UpdateTimestamp` | `$UsnJrnl` | **매우 높다** | 파일 API로 조작 불가 |
| Prefetch 마지막 실행 시각 | `.pf` 파일 | 높다 | 실행 사실의 독립 증거 |

시간대 처리:

- 8개 타임스탬프 전부 FILETIME이다. 1601-01-01 UTC 기준 100ns 단위 64비트 값
- `MFTECmd`/`istat`은 기본적으로 **UTC**로 출력한다. 문제가 KST를 요구하면 **+9시간**
- Unix epoch와의 차이는 **11644473600초**
- 레지스트리 `InstallDate`는 Unix epoch 초(UTC), `InstallTime`은 FILETIME이다. 둘을 섞어 비교하면 안 된다
- 조작자가 시각을 KST로 입력하고 도구가 로컬 시각으로 해석했다면, UTC 값이 9시간 어긋난 형태로 남는다. **조작값이 정확히 9시간 단위로 어긋나 있으면 시간대 처리 실수의 흔적**이다

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 조작 시각 (`$SI` C = `$J` BasicInfoChange) | 그 시각 ±5분의 EVTX 4688/Sysmon 1 — **무엇이 조작을 실행했나** |
| 실제 생성 시각 (`$FN` Created) | 그 시각의 브라우저 다운로드·`Zone.Identifier` ([FOR-0035](./alternate-data-streams.html)) |
| 조작된 파일 | 실행 여부 — Prefetch, Amcache, Shimcache |
| 같은 시각에 조작된 다른 파일 | `$J`에서 그 시각대의 `BASIC_INFO_CHANGE` 전수 조회 |
| 이름도 바뀌었는지 | `$J`의 `RENAME_OLD_NAME`/`RENAME_NEW_NAME` ([FOR-0039](./filename-change-traces.html)) |
| 조작 도구의 실행 흔적 | UserAssist, PowerShell 4104, Prefetch ([FOR-0061](./userassist.html)) |
| `$MFT` 파서가 못 읽는 값 | HxD로 레코드 직접 열람 ([FOR-0037](./hxd-header-check.html)) |
| `$J`가 잘려 있다 | `$LogFile` (NTFS Log Tracker), VSS 내부의 이전 `$MFT` |

## 흔한 함정

- **`$SI` 하나만 보고 결론 내리는 것.** 탐색기·`dir`·대부분의 GUI가 `$SI`만 보여준다. 왜 틀리는가: 조작 대상이 바로 그 값이다. 어떻게: `$FN`(`0x30` 컬럼)을 항상 나란히 본다.
- **`$SI`/`$FN` 불일치를 곧 조작으로 단정하는 것.** 파일을 이동하거나 이름을 바꾸면 `$FN`이 갱신되어 정상적으로 값이 달라진다. `$UsnJrnl`에서 그 시각에 `RENAME_*`/이동 기록이 있는지 확인해 배제한다.
- **초 이하 0을 단독 증거로 쓰는 것.** ZIP 해제와 FAT 매체 경유 복사가 같은 패턴을 만든다. **`$FN`도 0인가**와 **폴더 전체가 0인가**로 갈라 본다.
- **엔트리 번호 순서를 절대 규칙으로 믿는 것.** `SequenceNumber`가 2 이상인 슬롯은 재사용된 것이다. 삭제가 많은 볼륨에서는 이 지표가 거의 쓸 수 없다.
- **`BASIC_INFO_CHANGE`를 전부 timestomp로 세는 것.** 읽기전용/숨김/아카이브 속성 변경도 같은 플래그를 만든다. `DATA_*`가 함께 있는지, 다른 지표와 시각이 일치하는지로 좁힌다.
- **M(수정)이 설치 시각보다 이전인 것을 조작으로 보는 것.** 복사·압축 해제는 M을 보존한다. 지표 ⑤는 반드시 **B(생성)** 로 판정한다.
- **`$FN`이 정상이면 조작이 없었다고 결론 내리는 것.** `$MFT`를 직접 쓰는 도구는 `$FN`과 `$LogFile`까지 바꿀 수 있다. 이때는 `$UsnJrnl`·`$LogFile`·VSS·Prefetch 같은 **파일시스템 외부 증거**로 넘어간다.
- **시간대를 섞어 비교하는 것.** MFT는 UTC, EVTX 파서는 설정에 따라 로컬, 레지스트리 `InstallDate`는 Unix 초다. 전부 UTC로 정규화한 뒤 비교하고, 답만 KST로 바꾼다.
- **A(접근 시각)로 판단하는 것.** Win7 이후 기본 설정에서 접근 시각 갱신이 꺼져 있어 값이 오래된 채로 남는다. 조작 여부와 무관하게 이상해 보인다.
- **조작 시각을 "지금"으로 오해하는 것.** `$SI` C가 최근이라도 그것은 **마지막 MFT 엔트리 변경 시각**이다. 이름 변경·속성 변경으로도 갱신되므로 `$J`와 대조해 원인을 확정한다.
- **후보를 한 파일만 보고 끝내는 것.** 조작은 대개 여러 파일에 한꺼번에 이뤄진다. 조작 시각을 확정했으면 그 시각의 `BASIC_INFO_CHANGE`를 전수 조회해 나머지 파일도 찾는다.
- **결론에 "조작되었다"만 쓰는 것.** 표시된 시각·실제 시각·조작 시각·근거 지표 4개를 함께 적는다.

## 교차검증

```powershell
# 1) 파서 두 개의 결과가 같은가
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
python analyzeMFT.py -f 'C:\case\$MFT' -o mft_a.csv
```

```bash
# 2) $MFT 파서 vs Sleuth Kit 직접 조회
istat -o 2048 image.dd 91002

# 3) $MFT 레코드를 HxD/xxd 로 직접 확인 (파서 버그 배제)
#    레코드 오프셋 = EntryNumber * 1024
xxd -s $((91002 * 1024)) -l 512 '$MFT'

# 4) $UsnJrnl 의 조작 시각이 $SI 의 C 와 일치하는가
rg -i 'svc\.exe' out/j.csv | rg -i 'basicinfo'

# 5) $LogFile 로 3차 확인 (NTFS Log Tracker)
#    저널이 잘렸을 때의 대안

# 6) Prefetch 의 실행 시각과 모순 확인
#    WinPrefetchView 또는 PECmd 로 SVC.EXE-*.pf

# 7) VSS 안의 이전 $MFT 와 비교 — 조작 전 값이 남아 있을 수 있다
```

`$SI`의 C 시각과 `$J`의 `BASIC_INFO_CHANGE` 시각이 100ns 단위까지 일치하면 **같은 사건을 두 출처가 기록한 것**이므로 조작 시각이 확정된다. 이것이 이 글에서 얻을 수 있는 가장 강한 결론이다.

## mini walkthrough

```text
문제:
"침해 사고 PC 입니다. 악성 실행 파일이 실제로 언제 생성되었는지 답하세요."
첨부: pc01.E01, 지문에 'C:\Windows\Temp' 언급

1. $MFT 추출 -> MFTECmd -> CSV
   Import-Csv mft.csv |
     Where-Object { $_.ParentPath -like '*Windows\Temp*' -and $_.Extension -eq '.exe' } |
     Select-Object EntryNumber, FileName, Created0x10, LastModified0x10

   EntryNumber FileName   Created0x10                  LastModified0x10
   ----------- --------   -----------                  ----------------
   91002       svc.exe    2019-03-19 04:12:00.0000000  2019-03-19 04:12:00.0000000

2. 첫 시도 (실패한 접근):
   "생성 2019-03-19 04:12:00 UTC = 2019-03-19 13:12:00 KST" 로 제출.
   -> 오답.

   그 다음 시도도 실패:
   Created0x10 이 LastModified0x10 과 같다는 점만 근거로
   "조작됨"이라고만 답했다. -> 실제 시각을 요구한 문제라 역시 오답.

   무엇이 틀렸나: $SI(0x10) 만 봤다.
   문제는 '실제 생성 시각'을 물었고, 그 값은 조작되지 않은 곳에 있다.
   그리고 조작 여부만 말하고 실제 값을 제시하지 않았다.

3. 접근 변경 — $FN(0x30) 을 나란히 본다
   Import-Csv mft.csv | Where-Object { $_.EntryNumber -eq '91002' } |
     Select-Object Created0x10, Created0x30, LastRecordChange0x10, 'SI<FN', uSecZeros |
     Format-List

   Created0x10          : 2019-03-19 04:12:00.0000000
   Created0x30          : 2026-03-14 07:20:11.4820096      <- 여기가 진짜
   LastRecordChange0x10 : 2026-03-14 07:31:52.6641280      <- 조작 시각 후보
   SI<FN                : True
   uSecZeros            : True

   지표 ① 성립 ($SI/$FN 7년 차이)
   지표 ② 성립 ($SI 는 .0000000, $FN 은 .4820096)

4. 지표 ③ — 엔트리 번호 순서
   91000 setup_a.log  2026-03-14 07:19:41
   91001 setup_b.log  2026-03-14 07:19:44
   91002 svc.exe      2019-03-19 04:12:00   <- 모순
   91003 setup_c.log  2026-03-14 07:20:33
   SequenceNumber = 1 -> 슬롯 재사용 아님. 지표 성립.

5. 지표 ④ — $UsnJrnl
   MFTECmd.exe -f 'C:\case\$J' --csv out --csvf j.csv
   rg 'svc\.exe' out\j.csv

   2026-03-14 07:19:58.1120000  FileCreate
   2026-03-14 07:19:58.4410000  DataExtend
   2026-03-14 07:20:11.4820096  DataExtend|Close      <- $FN Created 와 일치
   2026-03-14 07:31:52.6641280  BasicInfoChange       <- $SI C 와 일치
   2026-03-14 07:31:52.6641280  BasicInfoChange|Close

   DATA_* 없이 BasicInfoChange 단독. 지표 성립.
   두 출처의 시각이 100ns 까지 같다.

6. 지표 ⑤ — 설치 시각
   SOFTWARE 하이브 -> Microsoft\Windows NT\CurrentVersion\InstallTime
   -> 2024-11-02 03:11:07 UTC
   2019-03-19 < 2024-11-02 -> 이 볼륨에서 만들어질 수 없는 값. 성립.

7. 지표 ⑦ — 실행 기록
   Prefetch: SVC.EXE-A1B2C3D4.pf, 마지막 실행 2026-03-14 07:22:03 UTC
   실행(07:22) 이 표시된 생성 시각(2019) 보다 7년 뒤라는 것 자체는 모순이
   아니지만, $FN Created(07:20:11) 직후 2 분에 실행됐다는 사실이
   $FN 값을 뒷받침한다. 성립.

8. 결론 정리
   표시된 시각: 2019-03-19 04:12:00 UTC ($SI, 조작됨)
   실제 시각  : 2026-03-14 07:20:11 UTC ($FN) = 2026-03-14 16:20:11 KST
   조작 시각  : 2026-03-14 07:31:52 UTC = 16:31:52 KST
   성립 지표  : ① ② ③ ④ ⑤ ⑦ (6개)

정답: 2026-03-14 16:20:11 KST (= 2026-03-14 07:20:11 UTC)
      근거: $FN Created, $UsnJrnl FileCreate/DataExtend.
      $SI 는 07:31:52 UTC 에 2019-03-19 로 소급 조작되었다.
```

2→3단계가 이 글의 요지다. **`$SI`만 보면 7년 틀린 답을 자신 있게 제출한다.** 그리고 "조작됨"이라는 판정만으로는 답이 되지 않는다 — 조작되지 않은 값(`$FN`, `$J`)에서 실제 시각을 복원해 제시해야 한다.

## 막혔을 때 다음 체크

1. `$FN`(`0x30`) 컬럼을 봤는가 — `$SI`(`0x10`)만 보고 있지 않은가
2. 초 이하 자리를 확인했는가 — `.0000000`인지, `$FN`은 어떤지
3. `$SI`의 `LastRecordChange`(C)가 나머지보다 최근인가 — 조작 시각 후보다
4. `$UsnJrnl`(`$J`)을 파싱했는가 — `BASIC_INFO_CHANGE` 단독 레코드 검색
5. `SequenceNumber`가 1인가 — 엔트리 순서 지표를 쓸 수 있는 조건
6. OS 설치 시각을 구했는가 (`InstallTime` 또는 MFT 엔트리 0/5의 Created)
7. **B(생성)로 비교했는가** — M(수정)으로 비교하면 오탐이다
8. 같은 폴더 이웃 파일의 시각 분포를 봤는가
9. Prefetch/Amcache/4688의 실행 시각과 대조했는가
10. 시간대를 전부 UTC로 정규화했는가 — 답만 KST로 변환
11. `$FN`도 조작된 흔적이 있는가 → `$LogFile`, VSS의 이전 `$MFT`, 외부 로그로 전환
12. 같은 시각에 조작된 **다른 파일**을 전수 조회했는가
13. 파서 결과가 의심스러운가 → `istat` 또는 HxD로 레코드를 직접 확인
14. 결론에 표시된 시각·실제 시각·조작 시각·근거 지표를 모두 적었는가

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$STANDARD_INFORMATION`(`0x10`)과 `$FILE_NAME`(`0x30`)이 각각 4개의 타임스탬프를 보관한다는 구조. `$FN`이 파일시스템 내부에서 관리되어 파일 API로 직접 쓸 수 없다는 근거
- SRC-013 — Microsoft Learn, Change Journals: `USN_REASON_BASIC_INFO_CHANGE`(`0x00008000`)의 의미와 값, `DATA_OVERWRITE`/`DATA_EXTEND`/`FILE_CREATE`/`RENAME_*`/`CLOSE` 플래그 값. USN 레코드가 파일 변경 사유를 남긴다는 동작
- SRC-086 — MITRE ATT&CK Enterprise Techniques: Timestomp(Indicator Removal 하위, T1070.006)의 기법 정의와 탐지 관점
- `MFTECmd` CSV의 계산 컬럼 이름(`SI<FN`, `uSecZeros`, `Created0x10`/`0x30` 등)은 버전에 따라 다를 수 있으므로 실제 CSV 헤더에서 확인할 것
- `istat`의 타임스탬프 표기와 시간대 출력 옵션은 Sleuth Kit 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
- 초 이하 자리가 0이 되는 이유는 도구의 구현에 따라 다르다. `SetFileTime`에 초 단위로 변환한 값을 넘기는 구현에서 나타나는 현상이며, 나노초까지 채우는 도구도 존재하므로 이 지표의 부재를 "조작 없음"의 근거로 쓰지 않을 것
- 예시로 든 타임스탬프·엔트리 번호·설치 시각은 설명을 위해 구성한 값이므로, 실제 사건에서는 대상 이미지에서 직접 확인할 것
- `MFTECmd`·`Timeline Explorer`는 `tools/manifest.json`에 등재되어 있지 않다. 등재된 `analyzeMFT`(`$MFT`)와 `NTFS Log Tracker`(`$LogFile`), Sleuth Kit `istat`으로 같은 판정을 할 수 있다
