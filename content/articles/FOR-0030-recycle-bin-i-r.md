---
id: FOR-0030
title: "$Recycle.Bin의 $I / $R 파일: 원래 경로·원본 크기·삭제 시각 복원"
slug: "recycle-bin-i-r"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["$Recycle.Bin", "$I", "$R", "INFO2", "RECYCLER", "SID"]
file_paths: ["C:\\$Recycle.Bin", "C:\\$Recycle.Bin\\S-1-5-21-...-1001", "C:\\RECYCLER", "C:\\RECYCLER\\INFO2", "D:\\$Recycle.Bin"]
registry_paths: ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"]
event_ids: []
protocols: []
tools: ["RBCmd", "FTK Imager", "HxD", "Autopsy", "Timeline Explorer", "DCode"]
commands: ["RBCmd.exe -d \"C:\\case\\$Recycle.Bin\" --csv \"C:\\case\\out\"", "RBCmd.exe -f \"$IQK41Z.pdf\"", "Get-ChildItem -Force -Recurse 'C:\\$Recycle.Bin'"]
regex_patterns: ["^\\$I[A-Z0-9]{6}\\.", "^\\$R[A-Z0-9]{6}\\.", "S-1-5-21-\\d+-\\d+-\\d+-\\d+"]
wireshark_filters: []
tshark_fields: []
log_fields: ["SourceName", "FileName", "FileSize", "DeletedOn", "Version"]
file_formats: ["ntfs"]
primary_terms: ["$Recycle.Bin", "$I", "$R", "휴지통", "INFO2"]
keywords: ["$Recycle.Bin", "$I 파일", "$R 파일", "휴지통", "삭제 시각", "원래 경로", "FILETIME", "SID", "INFO2", "RECYCLER", "휴지통 복원"]
aliases: ["휴지통 분석", "$I $R", "recycle bin 포렌식", "휴지통에서 복원", "지운 파일 원래 경로", "삭제 시각 구하기", "sid 사용자 찾기"]
symptom_keywords: ["삭제된 파일의 원래 경로를 알고 싶다", "누가 지웠는지 알고 싶다", "언제 지웠는지 알고 싶다", "$R 파일이 뭔지 모르겠다", "휴지통 파일을 열 수 없다", "이름이 $IABC12로 되어 있다"]
related: ["FOR-0031", "FOR-0032", "FOR-0027"]
source_ids: ["SRC-004", "SRC-014", "SRC-019"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

휴지통 삭제는 파일을 지우지 않고 **`$Recycle.Bin\<SID>\` 아래로 이름만 바꿔 옮긴다** — 같은 6문자를 공유하는 `$I`(메타데이터: 원래 전체 경로·원본 크기·삭제 시각)와 `$R`(내용 그대로) 한 쌍이 남으므로, `$I`를 읽고 `$R`을 복사해 이름만 되돌리면 복원이 끝난다.

## 어떤 문제에서 필요한가

- "삭제된 파일의 **원래 전체 경로**를 구하시오"
- "그 파일을 **언제** 삭제했는가"
- "**누가** 삭제했는가" (SID로 사용자 특정)
- "삭제된 파일의 내용을 복원하시오"
- "`$RQK41Z.pdf`라는 파일이 있는데 이게 뭡니까"
- 휴지통을 거쳤는지 완전삭제였는지 판정 ([FOR-0028](./usn-reason-flags.html)의 플래그 판정과 짝을 이룬다)

## 문제에서 처음 볼 단서

1. 파일 목록에 `$I`/`$R`로 시작하는 이름이 보인다 → 휴지통 경유 삭제 확정
2. 첨부에 `$Recycle.Bin` 폴더가 통째로 있다 → RBCmd 한 번으로 대부분 끝난다
3. 폴더 이름이 `S-1-5-21-...-1001` 형태다 → 그 숫자가 사용자를 특정한다
4. `$R` 파일만 있고 `$I`가 없다 → 메타데이터가 지워졌다. 내용은 살아 있다
5. `$I` 파일만 있고 `$R`이 없다 → 휴지통을 비웠거나 복원됐다. 경로·크기·시각만 답할 수 있다
6. `RECYCLER`(`$Recycle.Bin`이 아니라) → Windows XP 이미지다

## 30초 절차

```powershell
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out'
```

`-d`는 디렉터리를 재귀 탐색하므로 모든 SID 폴더의 `$I`를 한 번에 파싱한다. 사용법 상세는 [FOR-0031](./rbcmd.html).

폴더 목록만 먼저 눈으로 보려면(휴지통 항목은 숨김 + 시스템 속성이라 `-Force`가 없으면 안 보인다):

```powershell
Get-ChildItem -Force -Recurse 'C:\case\$Recycle.Bin' | Select-Object FullName, Length
```

```text
FullName                                                            Length
C:\case\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1001
C:\case\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1001\$IQK41Z.pdf     114
C:\case\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1001\$RQK41Z.pdf  268435
C:\case\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1002\$I8M2P0A.xlsx   102
C:\case\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1002\$R8M2P0A.xlsx 1204736
```

`$I`가 수백 바이트, `$R`이 원본 크기라는 대비가 바로 보인다.

## 상세 절차

### 1단계 — 경로 구조를 읽는다

```text
C:\$Recycle.Bin\<SID>\$I<6문자>.<원래확장자>     ← 메타데이터
C:\$Recycle.Bin\<SID>\$R<6문자>.<원래확장자>     ← 실제 내용
                        ^^^^^^^ 두 파일이 같은 6문자를 공유한다
```

| 구성 요소 | 의미 | 포렌식 활용 |
| --- | --- | --- |
| `$Recycle.Bin` | 볼륨 루트마다 하나. 숨김+시스템 속성 | `D:\$Recycle.Bin`도 별도로 확인한다 |
| `<SID>` | **삭제를 수행한 사용자의 SID** | 사용자 특정의 유일한 근거 |
| `$I` / `$R` | 메타데이터 / 내용 | `$I` 없이 `$R`만으로는 원래 이름을 알 수 없다 |
| 6문자 | 무작위 식별자 (영숫자) | `$I`와 `$R`을 **짝짓는 키** |
| `.<원래확장자>` | **원본 확장자가 그대로 보존된다** | 확장자만으로 문서/이미지/실행파일 분류 가능 |

원본 파일 **이름**은 파일명에 남지 않는다. 이름은 `$I` 내부의 전체 경로 문자열에서만 나온다.

디렉터리를 삭제한 경우 `$R<6문자>`가 **폴더**이며 그 아래에 원래 트리가 그대로 들어 있다. 이때 `$I` 하나가 폴더 전체를 가리킨다.

### 2단계 — SID로 사용자를 특정한다

`S-1-5-21-1004336348-1177238915-682003330-1001`의 구조:

| 부분 | 값 | 의미 |
| --- | --- | --- |
| `S-1-5-21-` | 고정 | 로컬/도메인 사용자 계정 도메인 식별자 |
| `1004336348-1177238915-682003330` | 가변 | **머신(또는 도메인) 고유 식별자.** 같은 값 = 같은 컴퓨터 |
| `-1001` | RID | **계정 식별자** |

자주 나오는 RID와 well-known SID:

| SID / RID | 계정 |
| --- | --- |
| `S-1-5-18` | LocalSystem (SYSTEM) |
| `S-1-5-19` | LocalService |
| `S-1-5-20` | NetworkService |
| `...-500` | 내장 Administrator |
| `...-501` | 내장 Guest |
| `...-503` | DefaultAccount |
| `...-1000` 이상 | **일반적으로 생성 순서대로 부여되는 사용자 계정** |

SID → 사용자 이름 매핑은 SOFTWARE 하이브에서 확정한다.

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
  └ ProfileImagePath = C:\Users\pshin
```

RegistryExplorer로 SOFTWARE 하이브를 열어 `ProfileList` 하위의 SID 키를 찾고 `ProfileImagePath` 값을 읽는다. 하이브가 없으면 `C:\Users\` 폴더 목록과 SID의 RID 순서로 추정하되, **추정임을 명시한다.**

**여러 SID 폴더가 있으면 각각이 다른 사용자의 삭제 행위다.** 문제에서 "누가"를 물으면 이 폴더 이름이 답의 근거다.

### 3단계 — `$I` 파일 구조

`$I`는 작은 고정 형식 바이너리다. 버전이 두 가지 있다.

| 버전 값 (선두 8바이트) | 대상 OS | 파일 크기 | 경로 저장 방식 |
| --- | --- | --- | --- |
| `1` | Windows Vista ~ 8.1 | **544바이트 고정** | UTF-16LE, **260문자(520바이트) 고정 영역**, 남는 공간은 널 패딩 |
| `2` | Windows 10 이후 | **가변** | 4바이트 경로 길이(문자 수, 종료 널 포함) + 그 길이만큼의 UTF-16LE |

공통 필드 배치:

| 오프셋 | 크기 | 필드 | 읽는 법 |
| --- | --- | --- | --- |
| `0x00` | 8바이트 | 헤더 버전 | 리틀엔디언. `1` 또는 `2` |
| `0x08` | 8바이트 | **원본 파일 크기 (바이트)** | 리틀엔디언 정수. `$R` 파일 크기와 일치해야 한다 |
| `0x10` | 8바이트 | **삭제 시각 (FILETIME, UTC)** | 1601-01-01 UTC 기준 100ns 단위 |
| `0x18` | — | 버전 1: 원래 전체 경로 (520바이트 고정) / 버전 2: 4바이트 경로 길이 이후 경로 | UTF-16LE |

버전 1의 총 크기 계산: `0x18`(24바이트 헤더) + 520바이트 경로 = **544바이트**. 파일 크기가 정확히 544라면 버전 1이라고 바로 알 수 있다.

버전 2 `$I` 파일의 실제 덤프 예시:

```text
00000000  02 00 00 00 00 00 00 00  93 18 04 00 00 00 00 00
00000010  80 c3 02 07 b2 c7 dc 01  2b 00 00 00 43 00 3a 00
00000020  5c 00 55 00 73 00 65 00  72 00 73 00 5c 00 70 00
00000030  73 00 68 00 69 00 6e 00  5c 00 44 00 6f 00 63 00
00000040  75 00 6d 00 65 00 6e 00  74 00 73 00 5c 00 63 00
00000050  6f 00 6e 00 74 00 72 00  61 00 63 00 74 00 5f 00
00000060  32 00 30 00 32 00 36 00  2e 00 70 00 64 00 66 00
00000070  00 00
```

| 읽은 값 | 해석 |
| --- | --- |
| `0x00`: `02 00 00 00 00 00 00 00` | 버전 2 → Windows 10 계열 |
| `0x08`: `93 18 04 00 ...` | `0x00041893` = **268,435 바이트** |
| `0x10`: `80 c3 02 07 b2 c7 dc 01` | FILETIME `0x01DCC7B20702C380` = **2026-04-08 23:47:15 UTC** |
| `0x18`: `2b 00 00 00` | 경로 길이 `0x2B` = **43문자** (경로 42문자 + 종료 널) |
| `0x1C`~`0x71` | `C:\Users\pshin\Documents\contract_2026.pdf` (42문자 × 2바이트 = 84바이트) |

파일 총 크기는 `0x1C`(28) + 84 + 2(종료 널) = **114바이트**다. 버전 2는 경로 길이에 따라 파일 크기가 달라진다.

HxD에서 확인할 때는 Data Inspector를 `Int64`(리틀엔디언)로 두고 `0x08`과 `0x10`을 각각 클릭하면 값이 바로 읽힌다. FILETIME은 DCode에 넣거나 다음으로 환산한다.

```powershell
# FILETIME hex -> UTC / KST
$ft = 0x01DCC7B20702C380
[datetime]::FromFileTimeUtc($ft)                      # UTC
[datetime]::FromFileTimeUtc($ft).AddHours(9)          # KST
```

```text
2026년 4월 8일 오후 11:47:15      (UTC)
2026년 4월 9일 오전 8:47:15       (KST)
```

Unix epoch로 환산하려면 `(FILETIME / 10000000) - 11644473600`.

**세부 오프셋을 손으로 읽는 것은 확인용이다. 실무 순서는 RBCmd로 먼저 파싱하고, 값이 의심스러울 때만 HxD로 원본을 확인하는 것이다.**

### 4단계 — `$R`로 내용을 복원한다

`$R` 파일은 **원본 바이트 그대로**다. 변환·압축·암호화가 없다. 복원은 복사 후 이름 변경으로 끝난다.

```powershell
# $I 에서 읽은 원래 이름으로 되돌린다
Copy-Item 'C:\case\$Recycle.Bin\S-1-5-21-...-1001\$RQK41Z.pdf' 'C:\case\restored\contract_2026.pdf'
```

확인 절차 두 가지.

```powershell
# 1) 크기 일치 — $I 의 원본 크기와 $R 의 실제 크기가 같아야 한다
(Get-Item 'C:\case\restored\contract_2026.pdf').Length     # 268435

# 2) 매직 바이트 — 확장자와 실제 형식이 맞는가
Format-Hex -Path 'C:\case\restored\contract_2026.pdf' -Count 16
```

크기가 다르면 `$R`이 잘렸거나 다른 `$I`와 잘못 짝지은 것이다. **6문자가 정확히 같은 짝인지 다시 확인한다.**

`$R`이 폴더인 경우:

```powershell
Copy-Item -Recurse 'C:\case\$Recycle.Bin\S-1-5-21-...-1001\$R8M2P0A' 'C:\case\restored\ProjectX'
```

### 5단계 — Windows XP의 `INFO2`와의 차이 (간단히)

| 항목 | XP 이전 | Vista 이후 |
| --- | --- | --- |
| 폴더 | `C:\RECYCLER\<SID>\` | `C:\$Recycle.Bin\<SID>\` |
| 메타데이터 | **`INFO2` 파일 하나에 모든 항목의 레코드가 누적** | **항목마다 `$I` 파일 하나** |
| 삭제된 파일 이름 | `D<드라이브문자><인덱스>.<원래확장자>` (예: `Dc1.doc`) | `$R<6문자>.<원래확장자>` |
| 인덱스 | `INFO2` 레코드에 순번이 있어 삭제 순서가 남는다 | `$I`에는 순번이 없다. 순서는 시각으로 판단 |
| 휴지통 비우기 후 | `INFO2` 레코드가 남아 **이미 사라진 파일 목록**을 볼 수 있는 경우가 있다 | `$I`도 함께 삭제된다 |

실전 요점은 두 가지다. **XP 이미지에서는 `$Recycle.Bin`을 찾지 말고 `RECYCLER`를 찾는다.** 그리고 RBCmd는 `INFO2`도 파싱하므로 도구를 바꿀 필요는 없다.

## 출력 필드 해석

RBCmd CSV의 컬럼이 곧 답변 항목이다.

| 컬럼 | 원본 필드 | 답변에 쓰는 방식 |
| --- | --- | --- |
| `SourceName` | 파싱한 `$I` 파일의 경로 | `$R` 짝을 찾는 키. 여기서 SID도 읽는다 |
| `FileName` | `$I` 내부의 **원래 전체 경로** | "원래 경로" 문항의 정답 |
| `FileSize` | `$I`의 원본 크기 | `$R` 실제 크기와 대조해 무결성 확인 |
| `DeletedOn` | `$I`의 FILETIME | **UTC로 출력된다.** KST 답이면 +9시간 |
| 버전 | `$I` 선두 8바이트 | 1 = Vista~8.1, 2 = Win10+. OS 추정 근거 |

`FileName`이 전체 경로라는 점이 중요하다. 파일 이름만이 아니라 `C:\Users\pshin\Documents\payroll.xlsx`처럼 드라이브 문자부터 들어 있으므로 **삭제 당시 그 파일이 어느 폴더에 있었는지**가 그대로 답이 된다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음에 열 것 | 확인할 것 |
| --- | --- | --- |
| SID | SOFTWARE 하이브 `ProfileList` | 사용자 이름 (`ProfileImagePath`) |
| SID | SAM 하이브 | 계정 생성 시각, 마지막 로그온 |
| 삭제 시각 | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | 같은 시각의 rename 짝, 전후 파일 활동 |
| 삭제 시각 | EVTX 4624 ([FOR-0083](./event-4624-logon.html)) | 그 시각에 로그온한 사용자가 SID와 일치하는가 |
| 원래 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 폴더의 다른 파일, 삭제 전 MACB |
| `$R` 파일 내용 | 파일 형식별 분석 (exiftool, ZIP 구조 등) | 내부 메타데이터, 작성자 |
| `$I`만 있고 `$R` 없음 | `$J`의 `FileDelete`, 카빙 | 휴지통 비우기 시각, 내용 회수 |
| `$R`만 있고 `$I` 없음 | `$J`의 `RenameNewName` | `$R` 6문자로 검색해 원래 이름 복원 |
| 여러 항목 일괄 처리 | RBCmd ([FOR-0031](./rbcmd.html)) | CSV 타임라인화 |
| 휴지통에 아무것도 없음 | 원인 분기 ([FOR-0032](./deleted-file-not-in-recycle-bin.html)) | Shift+Delete·이동식 매체·도구 삭제 |

## 흔한 함정

- **`$Recycle.Bin`이 안 보인다고 없다고 판단하는 것** → 숨김+시스템 속성이라 기본 탐색기와 `Get-ChildItem`에 나오지 않는다 → `Get-ChildItem -Force`, FTK Imager, Autopsy처럼 속성을 무시하는 도구로 본다.
- **`C:` 볼륨만 보는 것** → 휴지통은 **볼륨마다** 루트에 따로 생긴다 → `D:\$Recycle.Bin`, 다른 파티션까지 전부 확인한다.
- **`$R` 파일을 그대로 열어보고 "깨졌다"고 판단하는 것** → 파일 자체는 온전하고 이름과 확장자만 `$R` 형식이다 → `$I`에서 읽은 원래 이름으로 복사한 뒤 연다.
- **`$I`와 `$R`을 이름 순서로 짝짓는 것** → 6문자가 무작위이므로 정렬 순서는 짝과 무관하다 → **6문자 문자열이 정확히 일치하는 것**끼리만 짝짓는다. 확장자도 같아야 한다.
- **`FileSize`를 `$R`의 디스크 점유량과 비교하는 것** → 클러스터 단위 반올림 때문에 값이 다르다 → 논리 크기(바이트)끼리 비교한다.
- **삭제 시각을 로컬 시간으로 착각하는 것** → `$I`의 값은 FILETIME(1601-01-01 UTC 기준 100ns)이고 RBCmd CSV도 UTC로 출력한다 → KST 답이 필요하면 +9시간. Unix 환산은 `-11644473600`초.
- **`$I`의 삭제 시각을 "파일을 마지막으로 만진 시각"으로 읽는 것** → 이 값은 **휴지통으로 보낸 순간**이다. 수정 시각과 무관하다 → 수정 시각은 복원한 `$R`의 내부 메타데이터나 `$MFT`에서 얻는다.
- **`$I` 부재를 "휴지통 삭제가 아니었다"로 읽는 것** → 휴지통을 비우면 `$I`가 먼저 사라지고 `$R`이 카빙 가능한 상태로 남는 경우가 있다 → `$R` 형식 이름이 하나라도 있으면 휴지통 경유가 있었던 것이다.
- **SID를 사용자 이름 없이 그대로 답하는 것** → 채점 기준이 사용자 이름인 경우가 많다 → `ProfileList`로 매핑하거나, 매핑 불가면 "SID ...-1001 (프로필 미확인)"처럼 근거를 밝힌다.
- **버전 1의 경로 영역을 문자열 끝까지 읽는 것** → 520바이트 고정 영역이라 뒤에 이전 데이터의 잔여물이 남아 있을 수 있다 → 첫 널 종료 지점까지만 경로로 취급한다. 다만 그 뒤의 잔여 바이트 자체가 **이전 항목의 경로 조각**일 수 있어 별도 단서가 된다.
- **네트워크 드라이브·USB에서 휴지통을 찾는 것** → 이동식 매체와 네트워크 드라이브는 기본적으로 휴지통을 쓰지 않고 즉시 삭제된다 → [FOR-0032](./deleted-file-not-in-recycle-bin.html)로 간다.

## 교차검증

```powershell
# 1) RBCmd 로 $I 전부 파싱
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv

# 2) $I 의 원본 크기와 $R 의 실제 크기 대조
Import-Csv 'C:\case\out\rb.csv' | ForEach-Object {
  # $I 파일 경로에서 파일명 앞 2문자만 $R 로 바꾼다
  $r = Join-Path (Split-Path $_.SourceName -Parent) ('$R' + (Split-Path $_.SourceName -Leaf).Substring(2))
  [pscustomobject]@{
    OriginalPath = $_.FileName
    DeletedOn    = $_.DeletedOn
    SizeInI      = $_.FileSize
    SizeOfR      = (Get-Item -LiteralPath $r -ErrorAction SilentlyContinue).Length
  }
} | Format-Table -AutoSize
```

```text
OriginalPath                                DeletedOn             SizeInI  SizeOfR
C:\Users\pshin\Documents\contract_2026.pdf  2026-04-08 23:47:15Z   268435   268435
C:\Users\pshin\Desktop\ProjectX             2026-04-08 23:52:03Z        0   (폴더)
C:\Users\pshin\Downloads\installer.exe      2026-04-07 11:02:44Z  9822712   (없음)
```

| 관측 | 해석 |
| --- | --- |
| 크기 일치 | 정상. `$R` 복원 가능 |
| `SizeInI` = 0, `$R`이 폴더 | 디렉터리 삭제. `$R` 폴더를 재귀 복사 |
| `$R` 없음 | **휴지통이 비워졌거나 복원됐다.** `$I`만 남아 경로·시각만 답 가능 |

```powershell
# 3) $J 로 독립 확증 — 같은 6문자가 rename 대상으로 나타나는가
Import-Csv usn.csv | Where-Object { $_.FileName -match 'QK41Z' } |
  Sort-Object {[uint64]$_.Usn} | Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath
```

`$J`에 `RenameNewName`으로 `$RQK41Z.pdf`가, `FileCreate`로 `$IQK41Z.pdf`가 같은 시각에 나오면 `$I`의 삭제 시각이 독립적으로 확증된다.

## mini walkthrough

```text
문제:
"직원 PC 이미지입니다. 삭제된 계약서 파일의 원래 전체 경로, 삭제한 사용자,
 삭제 시각(KST)을 구하고 파일을 복원하세요."
첨부: disk.E01

1. FTK Imager 로 E01 열고 볼륨 루트 확인
   -> $Recycle.Bin 폴더 존재. Export 로 폴더 전체 추출.

2. 첫 시도 (실패):
   추출한 폴더에서 $R 파일을 바로 열어봤다.
   $RQK41Z.pdf 를 PDF 뷰어로 열기 -> "파일 형식을 인식할 수 없습니다"
   Format-Hex -Count 8 '$RQK41Z.pdf' -> 25 50 44 46 2d 31 2e 37   (%PDF-1.7)

   매직 바이트는 정상 PDF였다. 즉 파일이 깨진 게 아니라
   뷰어가 '$' 로 시작하는 이름/확장자 연결을 거부한 것이었다.  <-- 진단 오류

   그리고 더 큰 문제: $R 만 봐서는 원래 경로도 삭제 시각도 알 수 없다.
   문제가 요구한 세 값 중 어느 것도 $R 에는 없다.

3. 접근 변경 — $I 를 먼저 읽는다
   RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv

   SourceName                                        FileName                                    FileSize  DeletedOn
   ...\S-1-5-21-...-682003330-1001\$IQK41Z.pdf       C:\Users\pshin\Documents\contract_2026.pdf    268435   2026-04-08 23:47:15
   ...\S-1-5-21-...-682003330-1002\$I8M2P0A.xlsx     C:\Users\hjlee\Desktop\budget.xlsx           1204736   2026-04-05 02:11:09

   원래 전체 경로와 삭제 시각이 나왔다.

4. $I 원본으로 값 재확인 (RBCmd 결과를 믿기 전에 한 번)
   HxD 로 $IQK41Z.pdf 열기 (114바이트)
   0x00: 02 00 00 00 00 00 00 00   -> 버전 2 (Windows 10 계열)
   0x08: 93 18 04 00 00 00 00 00   -> 0x41893 = 268,435 바이트  (RBCmd 와 일치)
   0x10: 80 c3 02 07 b2 c7 dc 01   -> FILETIME 0x01DCC7B20702C380
   0x18: 2b 00 00 00               -> 경로 43문자 (42문자 + 종료 널)
   0x1C: C:\Users\pshin\Documents\contract_2026.pdf  (42문자, CSV 와 일치)

   세 값(크기 / 시각 / 경로)이 모두 RBCmd 출력과 일치. 파싱 신뢰 확보.
   경로 문자 수와 길이 필드가 어긋나면 다른 $I 를 열었거나 짝을 잘못 본 것이므로
   SourceName 을 다시 대조한다.

5. 시각 변환
   [datetime]::FromFileTimeUtc(0x01DCC7B20702C380)
   -> 2026-04-08 23:47:15 UTC
   [datetime]::FromFileTimeUtc(0x01DCC7B20702C380).AddHours(9)
   -> 2026-04-09 08:47:15 KST      <- 문제가 KST를 요구했다

6. SID -> 사용자
   RegistryExplorer 로 SOFTWARE 하이브 열기
   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-...-1001
     ProfileImagePath = C:\Users\pshin
   -> 삭제한 사용자 = pshin
      (-1002 는 hjlee. 다른 파일을 삭제한 별개 사용자다)

7. 복원
   Copy-Item '...\$RQK41Z.pdf' 'C:\case\restored\contract_2026.pdf'
   (Get-Item 'C:\case\restored\contract_2026.pdf').Length  -> 268435  (일치)
   -> 정상 오픈

8. 교차검증 — $J
   Import-Csv usn.csv | Where-Object { $_.FileName -match 'QK41Z' }
   -> 2026-04-08 23:47:15Z  RenameNewName|Close   $RQK41Z.pdf   .\$Recycle.Bin\S-1-5-21-...-1001
      2026-04-08 23:47:15Z  FileCreate|Close      $IQK41Z.pdf   .\$Recycle.Bin\S-1-5-21-...-1001
   -> 삭제 시각이 독립적으로 확증됨. 이후 FileDelete 없음 = 휴지통 미비움.

정답:
  원래 경로  C:\Users\pshin\Documents\contract_2026.pdf
  사용자     pshin (S-1-5-21-...-682003330-1001)
  삭제 시각  2026-04-09 08:47:15 KST (2026-04-08 23:47:15 UTC)
  복원       $RQK41Z.pdf 를 복사해 원래 이름으로 변경
```

2단계가 이 글의 핵심이다. **`$R`에는 원래 경로도 삭제 시각도 없다.** `$R`만 붙잡고 있으면 문제의 세 문항 중 하나도 답할 수 없고, `$I`로 먼저 가는 것이 순서다.

## 막혔을 때 다음 체크

1. `Get-ChildItem -Force`로 봤는가 — 숨김+시스템 속성 때문에 안 보이는 경우가 대부분이다
2. `C:` 외의 볼륨 루트도 확인했는가
3. `$I`와 `$R`의 **6문자와 확장자가 모두** 일치하는 짝인가
4. `$I` 파일 크기가 544바이트인가 — 그러면 버전 1(Vista~8.1)이다
5. `FileSize`와 `$R` 실제 크기가 같은가 — 다르면 짝 오류 또는 절단
6. SID를 `ProfileList`로 사용자 이름까지 매핑했는가
7. 시각을 UTC로 답해야 하는지 KST로 답해야 하는지 지문을 다시 읽었는가
8. `$R`이 없다면 → 휴지통 비우기 시점을 `$J`의 `FileDelete`로 찾고, 내용은 카빙으로
9. `$I`가 없다면 → `$R`의 6문자로 `$J`를 검색해 `RenameNewName` 짝에서 원래 이름을 복원
10. `$Recycle.Bin`이 아예 비어 있다면 → [FOR-0032](./deleted-file-not-in-recycle-bin.html)의 원인 분기로 이동
11. XP 이미지라면 → `C:\RECYCLER\<SID>\INFO2`를 찾는다

## 출처

- SRC-004 — Eric Zimmerman 문서: RBCmd의 `$I`/`INFO2` 파싱과 CSV 출력 컬럼(`SourceName`, `FileName`, `FileSize`, `DeletedOn`)
- SRC-014 — Microsoft Learn, File Times: `$I`의 삭제 시각이 FILETIME(1601-01-01 UTC 기준 100ns)이라는 근거와 Unix epoch 차이 `11644473600`초
- SRC-019 — Microsoft Learn, Well-known SIDs / Security Identifiers: `S-1-5-21-` 구조, RID `500`/`501`/`1000` 이상의 의미, `S-1-5-18`~`S-1-5-20`
- `$I` 버전 1의 544바이트 고정 크기와 버전 2의 경로 길이 필드는 실제 `$I` 파일을 HxD로 열어 파일 크기와 선두 8바이트로 먼저 확인할 것. 판정이 걸린 값은 RBCmd 출력과 원본 hex를 반드시 대조한다
- RBCmd의 컬럼명과 시간대 출력은 도구 버전에 따라 다를 수 있으므로 실제 CSV에서 확인할 것
- walkthrough의 SID·6문자 식별자·파일 이름은 설명을 위한 예시 값이다
