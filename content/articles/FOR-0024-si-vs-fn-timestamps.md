---
id: FOR-0024
title: "$STANDARD_INFORMATION vs $FILE_NAME: 8개 타임스탬프로 timestomp 잡기"
slug: "si-vs-fn-timestamps"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$STANDARD_INFORMATION", "$FILE_NAME", "0x10", "0x30", "timestomp", "$INDEX_ROOT", "$INDEX_ALLOCATION", "INDX"]
file_paths: ["C:\\$MFT"]
registry_paths: []
event_ids: []
protocols: []
tools: ["MFTECmd", "analyzeMFT", "Sleuth Kit", "Timeline Explorer", "PowerShell"]
commands: ["MFTECmd.exe -f \"C:\\case\\$MFT\" --csv . --csvf mft.csv", "MFTECmd.exe -f \"C:\\case\\$MFT\" --de 210044", "istat -o 2048 image.dd 210044", "Import-Csv mft.csv | Where-Object { $_.'SI<FN' -eq 'True' }"]
regex_patterns: ["\\.0000000$", "\\.000$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30", "SI<FN", "uSecZeros", "STF FN Shift", "uSec Zero"]
file_formats: ["ntfs"]
primary_terms: ["$STANDARD_INFORMATION", "$FILE_NAME", "si vs fn"]
keywords: ["timestomp", "$STANDARD_INFORMATION", "$FILE_NAME", "0x10", "0x30", "SI<FN", "uSecZeros", "타임스탬프 조작", "시간 조작 탐지", "SetFileTime", "anti-forensics"]
aliases: ["timestomp", "타임스탬프 조작", "시간 조작 탐지", "si fn 비교", "0x10 0x30", "si<fn", "시간 위조", "마이크로초 0"]
symptom_keywords: ["시각이 조작된 것 같다", "생성 시각이 너무 오래됐다", "두 시각이 다르다", "타임스탬프를 믿을 수 없다", "사건 시각에 파일이 없다", "서브초가 0이다"]
related: ["FOR-0021", "FOR-0023", "FOR-0038"]
source_ids: ["SRC-005", "SRC-014", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

NTFS 파일은 `$STANDARD_INFORMATION`(0x10)과 `$FILE_NAME`(0x30)에 각각 4개씩 **총 8개**의 시각을 갖는다. 사용자 API로는 `$SI`만 바꿀 수 있고 `$FN`은 파일시스템이 rename 시점에만 쓰므로, **두 세트가 어긋나면 조작이다** — 특히 `$SI` 값이 `$FN`보다 **과거**라면 시간을 뒤로 돌린 흔적이다.

## 어떤 문제에서 필요한가

- "이 파일의 생성 시각이 2009년인데 진짜인가"
- "사건 시각대에 만들어진 파일이 하나도 없다"
- "타임스탬프가 조작됐는지 판정하라"
- "악성 파일이 시스템 파일로 위장했다"
- "어느 시각을 답으로 써야 하는가"

MACB 각 글자의 의미와 행위별 변화 패턴은 [FOR-0023](./mft-macb.html)에서 다룬다. 이 글은 **같은 파일의 두 세트를 대조해 진짜 시각을 골라내는 절차**다.

## 문제에서 처음 볼 단서

1. `Created0x10`이 Windows 설치 시각·시스템 파일 시각과 똑같다 → 위장 대상 시각을 복사한 것
2. `Created0x10` ≠ `Created0x30` → **생성 시각은 정상적으로 두 세트가 같아야 한다.** 다르면 즉시 의심
3. 서브초가 정확히 `.0000000` → 문자열로 지정한 시각을 API로 써 넣은 흔적
4. `SI<FN` 컬럼이 `True` (MFTECmd) 또는 `STF FN Shift`가 채워짐 (analyzeMFT `-a`)
5. `LastRecordChange0x10`만 사건 시각대에 있고 나머지는 과거 → 조작 시점이 바로 그 `C` 값
6. 사건 시각대의 파일이 안 보이는데 `$UsnJrnl`에는 `BasicInfoChange`가 있다

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
```

```powershell
# 파서가 이미 계산해 준 두 플래그로 후보를 뽑는다
Import-Csv C:\case\out\mft.csv |
  Where-Object { $_.'SI<FN' -eq 'True' -or $_.uSecZeros -eq 'True' } |
  Select-Object EntryNumber, ParentPath, FileName,
                Created0x10, Created0x30, LastModified0x10, LastModified0x30
```

플래그 컬럼이 없거나 비어 있으면 직접 비교한다.

```powershell
# 생성 시각이 두 세트에서 다른 항목 = 가장 강한 단독 신호
Import-Csv C:\case\out\mft.csv |
  Where-Object { $_.Created0x30 -and $_.Created0x10 -ne $_.Created0x30 } |
  Select-Object ParentPath, FileName, Created0x10, Created0x30
```

## 상세 절차

### 1단계 — 왜 두 세트가 존재하는가

`$FILE_NAME` 속성은 **디렉터리 색인을 빠르게 만들기 위한 캐시**다. 폴더 내용을 나열할 때 파일마다 `$SI`를 읽으러 가지 않고, 이름·크기·시각을 `$FN`에 복제해 둔다.

```text
같은 파일에 대해 실제로는 세 벌의 시각이 존재한다

1) $STANDARD_INFORMATION (0x10)  <- 커널이 상시 갱신. 도구가 보는 "그 파일의 시각"
2) $FILE_NAME            (0x30)  <- rename/생성 시점에만 기록되는 스냅샷
3) 부모 디렉터리의 색인 항목      <- $INDEX_ROOT(0x90) / $INDEX_ALLOCATION(0xA0) 안의
                                    $FILE_NAME 사본. 세 번째 복제본
```

3번은 **삭제된 파일의 이름과 시각이 부모 폴더의 `INDX` 슬랙에 남는** 경로이기도 하다. `$MFT` 레코드가 재사용된 뒤에도 여기서 나오는 경우가 있다.

갱신 주체가 다르다는 점이 탐지의 근거다.

| | `$SI` (0x10) | `$FN` (0x30) |
| --- | --- | --- |
| 누가 쓰나 | 커널이 모든 변경마다 | 파일시스템이 **생성·rename·이동 시에만** |
| 사용자 API로 변경 | **가능** (`SetFileTime`) | **불가능** |
| 도구가 표시하는 값 | 이것 (`dir`, 탐색기 속성) | 표시되지 않음 |
| 조작 도구가 건드리는 곳 | 여기 | 대개 그대로 남는다 |

### 2단계 — 8개 타임스탬프 대조표

두 속성 내부의 오프셋과, 파서 컬럼 대응이다.

| 개념 | `$SI` 오프셋 | `$FN` 오프셋 | MFTECmd (0x10) | MFTECmd (0x30) | analyzeMFT (0x10) |
| --- | --- | --- | --- | --- | --- |
| B 생성 | `0x00` | `0x08` | `Created0x10` | `Created0x30` | `Std Info Creation date` |
| M 수정 | `0x08` | `0x10` | `LastModified0x10` | `LastModified0x30` | `Std Info Modification date` |
| C 엔트리 변경 | `0x10` | `0x18` | `LastRecordChange0x10` | `LastRecordChange0x30` | `Std Info Entry date` |
| A 접근 | `0x18` | `0x20` | `LastAccess0x10` | `LastAccess0x30` | `Std Info Access date` |

`$FN` 속성은 오프셋 `0x00`에 **부모 디렉터리 참조(8바이트: 하위 6바이트 레코드 번호 + 상위 2바이트 시퀀스)** 를 먼저 두기 때문에, 같은 네 시각이 `$SI`보다 8바이트씩 뒤에 온다.

analyzeMFT는 `$FN` 쪽을 `FN Info Creation date` 처럼 `FN Info *`로 낸다.

### 3단계 — 왜 조작 도구는 `$SI`만 바꾸는가

Windows가 제공하는 시각 설정 API는 하나뿐이고, 인자가 셋이다.

```text
SetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
             -> B                   -> A               -> M
```

| 항목 | API로 설정 가능한가 |
| --- | --- |
| `$SI` B / A / M | **가능** |
| `$SI` C (MFT entry changed) | **불가능.** 메타데이터가 바뀌었으므로 커널이 "지금"으로 갱신한다 |
| `$FN` B / M / C / A | **불가능.** 사용자 모드 API가 없다 |

결과적으로 API 기반 timestomp(MITRE ATT&CK의 Timestomp 기법, PowerShell의 `(Get-Item x).CreationTime = ...` 포함)는 다음 흔적을 반드시 남긴다.

```text
1) $SI 의 B/M/A 는 조작값
2) $SI 의 C 는 "조작을 실행한 시각"  <- 진짜 시각이 여기 남는다
3) $FN 의 4개는 원래 값 그대로       <- 대조 대상
4) $UsnJrnl 에 BasicInfoChange 레코드 <- 조작 행위 자체의 기록
```

**단, `$FN`까지 바꾸는 도구도 존재한다.** raw 디스크에 직접 쓰거나 커널 드라이버를 쓰는 방식이면 8개 전부를 맞출 수 있다. 그래서 `$SI` = `$FN`이 "조작 없음"의 증명은 아니다. 그때는 `$UsnJrnl`·`$LogFile`·`INDX` 슬랙의 세 번째 복제본으로 넘어간다.

### 4단계 — 판정 규칙

`$FN`은 rename 시점에 그 순간의 `$SI` 값으로 새로 기록된다. 따라서 **정상 파일에서 `$FN`은 `$SI`와 같거나 과거**다.

| 비교 | 정상 | 이상 신호 | 강도 |
| --- | --- | --- | --- |
| `Created0x10` vs `Created0x30` | **같다** | 다르다 | **매우 강함** |
| `Created0x10` < `Created0x30` | 없음 | 생성 시각을 과거로 돌렸다 | **매우 강함** |
| `LastModified0x10` vs `0x30` | `0x10` ≥ `0x30` | `0x10` < `0x30` | 강함 |
| `LastRecordChange0x10` vs `0x30` | `0x10` ≥ `0x30` | `0x10` < `0x30` | 강함 |
| `LastAccess0x10` vs `0x30` | `0x10` ≥ `0x30` | `0x10` < `0x30` | 중간 (갱신 비활성 영향) |
| `$SI` C만 최근, B/M은 과거 | rename·이동·권한변경 | 조작 | 중간 — 단독 판정 불가 |
| 서브초 `.0000000` | 아카이브·FAT 유래 가능 | 조작 | 중간 |

`Created`가 두 세트에서 다르면 사실상 확정이다. 파일 생성 시 두 속성이 동시에 만들어지고, rename 시에도 `$FN`이 `$SI`의 값을 복사해 가므로 **정상 경로로는 어긋날 수 없다.**

```powershell
# 규칙을 그대로 코드로 — 역전 항목만
Import-Csv out\mft.csv |
  Where-Object {
    $_.Created0x30 -and $_.Created0x10 -and
    ([datetime]$_.Created0x10) -lt ([datetime]$_.Created0x30)
  } |
  Select-Object EntryNumber, ParentPath, FileName,
                Created0x10, Created0x30, LastRecordChange0x10 |
  Sort-Object LastRecordChange0x10
```

```powershell
# 네 쌍 전부를 점수화 — 어긋난 쌍의 개수를 센다
Import-Csv out\mft.csv | ForEach-Object {
  $r = $_
  $score = 0
  foreach ($p in @(
      @('Created0x10','Created0x30'),
      @('LastModified0x10','LastModified0x30'),
      @('LastRecordChange0x10','LastRecordChange0x30'),
      @('LastAccess0x10','LastAccess0x30'))) {
    $si = $r.($p[0]); $fn = $r.($p[1])
    if ($si -and $fn -and ([datetime]$si) -lt ([datetime]$fn)) { $score++ }
  }
  if ($score -gt 0) {
    [pscustomobject]@{
      Entry = $r.EntryNumber; Path = $r.ParentPath; Name = $r.FileName
      Reversed = $score; SI_B = $r.Created0x10; FN_B = $r.Created0x30
      SI_C = $r.LastRecordChange0x10
    }
  }
} | Sort-Object Reversed -Descending | Format-Table -AutoSize
```

### 5단계 — 서브초(나노초) 절삭 신호

FILETIME은 100나노초 단위다. 파일시스템이 실제로 찍는 값은 하위 자릿수가 사실상 무작위다.

```text
정상적으로 생성된 파일
  Created: 2026-03-14 07:20:08.7412955     <- 7자리 서브초가 채워져 있다

문자열로 지정한 시각을 API로 써 넣은 파일
  Created: 2009-07-14 04:37:05.0000000     <- 정확히 0
```

조작 도구는 대개 `"2009-07-14 04:37:05"` 같은 문자열을 파싱해 FILETIME으로 변환하므로 **서브초가 정확히 0**이 된다. MFTECmd는 이 조건을 `uSecZeros` 컬럼으로, analyzeMFT는 `-a` 옵션의 `uSec Zero` 컬럼으로 표시한다.

```powershell
# 파서 플래그 없이 직접 판정
Import-Csv out\mft.csv |
  Where-Object {
    $_.Created0x10 -and ([datetime]$_.Created0x10).Ticks % 10000000 -eq 0
  } |
  Select-Object ParentPath, FileName, Created0x10, LastModified0x10
```

**서브초 0은 단독 증거가 아니다.** 다음 경우에 정상적으로 발생한다.

| 정상적으로 서브초가 0이 되는 경우 | 이유 |
| --- | --- |
| ZIP에서 압축 해제된 파일의 `M` | MS-DOS 시각은 2초 해상도, 서브초 없음 |
| FAT/exFAT 매체에서 복사된 파일 | FAT 시각 해상도가 낮다 |
| 일부 설치 프로그램이 배포한 파일 | 패키지에 저장된 시각을 복원 |
| 파서가 서브초를 표시하지 않는 경우 | 출력 형식 문제 — 데이터는 있다 |

그래서 실전 판정은 **"서브초 0" + "두 세트 불일치"** 를 함께 본다. 서브초가 안 보이면 파서의 시각 출력 형식 옵션을 확인해 `.fffffff`까지 나오게 한 뒤 다시 본다.

### 6단계 — 진짜 시각을 확정한다

조작이 확인되면 답으로 쓸 시각을 골라야 한다. 신뢰도 순서다.

| 순위 | 값 | 왜 신뢰하나 |
| --- | --- | --- |
| 1 | `$UsnJrnl`의 `FileCreate` 시각 | 별개 파일에 append-only로 기록됨 |
| 2 | `$LogFile`의 해당 트랜잭션 시각 | 트랜잭션 로그. 조작 대상이 아니다 |
| 3 | `$FN` (0x30)의 B | 사용자 API로 못 바꾼다 |
| 4 | `$SI`의 C (`LastRecordChange0x10`) | 조작을 실행한 시각 자체 |
| 5 | 부모 폴더 `INDX`의 `$FN` 사본 | 세 번째 복제본 |
| 6 | `$SI`의 B/M/A | **조작 대상. 마지막에 본다** |

즉 timestomp 문제의 정답은 보통 **`Created0x30`(원래 생성 시각)** 이거나 **`LastRecordChange0x10`(조작 시각)** 이다. 문제 지문이 "파일이 실제로 만들어진 시각"을 물으면 전자, "조작이 일어난 시각"을 물으면 후자다.

## 출력 필드 해석

| 컬럼 | 의미 | 읽는 법 |
| --- | --- | --- |
| `SI<FN` | `$SI` 시각 중 하나 이상이 `$FN`보다 과거 | `True` = **1순위 후보** |
| `uSecZeros` | 서브초가 0 | `True` = 2차 신호 |
| `Created0x10` / `Created0x30` | 생성 시각 두 벌 | **다르면 사실상 확정** |
| `LastModified0x10` / `0x30` | 수정 시각 | `0x10` < `0x30`이면 이상 |
| `LastRecordChange0x10` | `$SI` 엔트리 변경 | 조작 시각이 남는 자리 |
| `LastRecordChange0x30` | `$FN` 엔트리 변경 | 마지막 rename 시각 |
| `LastAccess0x10` / `0x30` | 접근 시각 | 갱신 비활성 환경에서는 판정력이 약하다 |
| `Copied` | 생성 > 수정 형태 | 조작이 아니라 복사일 수 있다 |
| `NameType` | `Win32` / `Dos` / `Win32&Dos` | `Dos`만 있는 8.3 이름 항목은 별도 `$FN`이다 |
| `UpdateSequenceNumber` | `$SI`의 USN | `$J`와 조인해 실제 행위 확인 |
| `STF FN Shift` (analyzeMFT) | `$SI`/`$FN` 시각 어긋남 | `-a` 옵션 필요 |
| `uSec Zero` (analyzeMFT) | 서브초 0 | `-a` 옵션 필요 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `SI<FN = True` | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | `BasicInfoChange` 레코드와 그 시각 |
| `LastRecordChange0x10` (조작 시각) | `$LogFile` ([FOR-0025](./logfile-basics.html)) | 그 순간의 `$SI` 속성 갱신 트랜잭션 |
| `Created0x30` (원래 시각) | `$J`의 `FileCreate` | 두 값이 일치하면 확정 |
| 조작 시각 | EVTX `4688`, PowerShell `4104` ([FOR-0083](./event-4624-logon.html)) | 어떤 프로세스가 시각을 바꿨나 |
| 조작 대상 파일 | Prefetch / Amcache / UserAssist ([FOR-0061](./userassist.html)) | 그 파일이 실행됐나 |
| 위장 대상 시각 | 같은 시각을 가진 정상 파일 목록 | 어느 시스템 파일을 베꼈나 |
| `EntryNumber` | `MFTECmd --de`, `istat` | 속성 원본에서 8개 값 직접 확인 |
| 부모 폴더 | 부모의 `$INDEX_ALLOCATION` (`INDX`) | 세 번째 복제본의 시각 |
| `HasAds`, `ZoneIdContents` | 다운로드 출처 ([FOR-0191](./chrome-history.html)) | 조작 전 원본이 어디서 왔나 |

## 흔한 함정

- **`Created0x30`이 비어 있는 것을 "값 없음"으로 읽는 것.** 파서가 **`0x10`과 동일할 때 `0x30` 컬럼을 비워 두는** 출력 방식을 쓸 수 있다. 빈 값을 곧바로 이상으로 판정하면 오탐이 쏟아진다. 확실한 항목 하나를 `MFTECmd --de`나 `istat`으로 열어 파서의 출력 규칙을 먼저 확인한다.
- **`$SI` > `$FN`을 조작으로 신고하는 것.** `$FN`은 rename 시점에 멈춘 스냅샷이므로 파일을 그 후에 편집하면 `$SI`의 M/C가 자연히 더 최근이다. **이상은 `$SI` < `$FN` 방향이다.** 단, `Created`만은 방향과 무관하게 불일치 자체가 신호다.
- **`uSecZeros`만으로 결론 내리는 것.** ZIP 해제·FAT 매체 복사·일부 설치 파일에서 정상적으로 0이 된다. 반드시 두 세트 불일치와 함께 본다.
- **`$SI` = `$FN`이면 조작이 없다고 결론 내리는 것.** raw 디스크에 직접 쓰는 도구는 8개를 모두 맞춘다. `$UsnJrnl`의 `BasicInfoChange`와 `$LogFile`을 봐야 한다.
- **8.3 이름 항목을 중복 파일로 세는 것.** 하나의 파일이 `Win32` 이름과 `Dos` 이름 두 개의 `$FN`을 가질 수 있고, 하드링크는 더 많다. `NameType`을 확인한다.
- **rename을 조작으로 오판하는 것.** 정상 rename도 `$FN`의 네 시각을 그 시점 값으로 갱신하고 `$SI`의 C를 올린다. `$J`의 `RenameOldName`/`RenameNewName` 짝이 있으면 정상 rename이다.
- **문자열로 시각을 비교하는 것.** `-lt`/`-gt`를 문자열에 쓰면 사전순 비교가 된다. ISO 형식이면 우연히 맞지만 파서가 `03/14/2026` 형식으로 내면 완전히 깨진다. `[datetime]` 캐스팅을 항상 한다.
- **조작 시각을 파일의 생성 시각으로 답하는 것.** `LastRecordChange0x10`은 "조작한 시각"이다. "파일이 만들어진 시각"을 물으면 `Created0x30` 또는 `$J`의 `FileCreate`가 답이다.
- **`LastAccess`의 불일치에 비중을 두는 것.** last access 갱신이 꺼진 시스템에서는 이 쌍의 판정력이 거의 없다 ([FOR-0023](./mft-macb.html)).
- **위장 대상 시각을 확인하지 않는 것.** 조작값이 `2009-07-14 04:37:05` 처럼 시스템 파일과 동일하면, 같은 시각을 가진 정상 파일 목록을 뽑아 "베낀 대상"을 특정할 수 있다. 이것이 조작의 추가 증거가 된다.
- **디렉터리를 제외하지 않는 것.** 폴더도 `$SI`/`$FN`을 갖고, 색인 변경으로 시각이 자주 움직여 오탐이 많다. 1차 스크리닝에서는 `IsDirectory=False`로 좁힌다.
- **시간대를 섞는 것.** 두 세트 모두 FILETIME(UTC)이다. 한쪽만 KST로 변환해 비교하면 9시간짜리 가짜 역전이 만들어진다.

## 교차검증

```powershell
# 1) 파서를 거치지 않고 속성 원본에서 8개 값 확인
MFTECmd.exe -f 'C:\case\$MFT' --de 210044

# 2) 조작값과 같은 시각을 가진 정상 파일 = 위장 대상
Import-Csv out\mft.csv |
  Where-Object { $_.Created0x10 -eq '2009-07-14 04:37:05' } |
  Select-Object -First 10 ParentPath, FileName

# 3) $J 에서 조작 행위 자체를 확인
Import-Csv out\usn.csv |
  Where-Object { $_.EntryNumber -eq '210044' } |
  Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName | Sort-Object Usn
```

```bash
# 4) TSK istat — $STANDARD_INFORMATION 과 $FILE_NAME 을 속성별로 따로 출력한다
istat -o 2048 image.dd 210044

# 5) 부모 폴더의 INDX 에 남은 세 번째 복제본
istat -o 2048 image.dd 9114
```

`istat`은 `$STANDARD_INFORMATION`과 `$FILE_NAME` 시각을 **별개 블록으로 보여준다.** CSV 컬럼 해석이 의심스러울 때 최종 근거로 쓴다.

## mini walkthrough

```text
문제:
"2026-03-14 07:00~08:00 사이에 침입이 있었습니다.
 공격자가 심어 둔 실행 파일을 찾고, 실제 생성 시각을 구하세요.
 첨부: $MFT, $J"

1. 파싱
   MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv
   MFTECmd.exe -f "$J" -m "$MFT" --csv out --csvf usn.csv

2. 첫 시도 (실패):
   Import-Csv out\mft.csv |
     Where-Object { $_.Extension -eq '.exe' -and
                    ([datetime]$_.Created0x10) -ge [datetime]'2026-03-14 07:00' -and
                    ([datetime]$_.Created0x10) -le [datetime]'2026-03-14 08:00' }

   -> 0건.

   "사건 시각대에 만들어진 실행 파일이 없다" 고 결론 냈다. 오답이다.
   Created0x10 은 조작 가능한 값이다. 조작된 파일은 이 필터에 걸리지 않는다.

3. 접근 변경 — 조작 플래그로 다시 찾는다
   Import-Csv out\mft.csv |
     Where-Object { $_.'SI<FN' -eq 'True' -or $_.uSecZeros -eq 'True' } |
     Where-Object { $_.IsDirectory -eq 'False' } |
     Select-Object EntryNumber, ParentPath, FileName, Created0x10, Created0x30

   EntryNumber ParentPath                       FileName      Created0x10           Created0x30
   ----------- ----------                       --------      -----------           -----------
   210044      .\Users\Public\Libraries         svchost.exe   2009-07-14 04:37:05   2026-03-14 07:20:08

   Users\Public\Libraries 에 svchost.exe 가 있다. 정상 위치가 아니다.

4. 8개 값 전개
   MFTECmd.exe -f "$MFT" --de 210044

   $STANDARD_INFORMATION (0x10)
     Created            : 2009-07-14 04:37:05.0000000
     Last Modified      : 2009-07-14 04:37:05.0000000
     Last Record Change : 2026-03-14 07:20:11.4180233   <-- 진짜 흔적
     Last Access        : 2009-07-14 04:37:05.0000000

   $FILE_NAME (0x30)
     Created            : 2026-03-14 07:20:08.7412955   <-- 원래 생성 시각
     Last Modified      : 2026-03-14 07:20:08.7412955
     Last Record Change : 2026-03-14 07:20:08.7412955
     Last Access        : 2026-03-14 07:20:08.7412955

   판정:
     - Created 가 두 세트에서 다르다                -> 조작 확정
     - $SI Created(2009) < $FN Created(2026)        -> 시간을 뒤로 돌렸다
     - $SI 의 B/M/A 서브초가 정확히 .0000000        -> 문자열 지정 API 호출
     - $SI C 만 2026-03-14 07:20:11 로 최근         -> 조작을 실행한 시각
     - $FN 4개가 모두 07:20:08.7412955 로 동일      -> 생성 후 rename 없음

5. 위장 대상 특정
   Import-Csv out\mft.csv |
     Where-Object { $_.Created0x10 -eq '2009-07-14 04:37:05' } |
     Select-Object -First 5 ParentPath, FileName

   .\Windows\System32    svchost.exe
   .\Windows\System32    services.exe
   ...
   -> Windows 설치 당시 시스템 파일의 시각을 그대로 베꼈다.

6. $J 로 확증 (독립 artifact)
   Import-Csv out\usn.csv | Where-Object { $_.EntryNumber -eq '210044' } |
     Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName | Sort-Object Usn

   Usn        UpdateTimestamp        UpdateReasons              FileName
   0x51a2100  2026-03-14 07:20:08Z   FileCreate                 svchost.exe
   0x51a2240  2026-03-14 07:20:08Z   FileCreate|DataExtend      svchost.exe
   0x51a2380  2026-03-14 07:20:09Z   DataExtend|Close           svchost.exe
   0x51a2b40  2026-03-14 07:20:11Z   BasicInfoChange|Close      svchost.exe   <-- timestomp

   $FN Created(07:20:08.74) 와 $J FileCreate(07:20:08) 가 일치한다. 확정.
   BasicInfoChange 시각(07:20:11) 이 $SI C 와 일치한다. 조작 시점도 확정.

7. 답 정리 (KST 변환)
   실제 생성 : 2026-03-14 07:20:08 UTC = 16:20:08 KST
   조작 시각 : 2026-03-14 07:20:11 UTC = 16:20:11 KST
   조작폭    : 약 16년 8개월 뒤로

정답: .\Users\Public\Libraries\svchost.exe (EntryNumber 210044)
      실제 생성 2026-03-14 16:20:08 KST
      2009-07-14 04:37:05 으로 timestomp 됨 (조작 시각 16:20:11 KST)
```

2단계의 실패가 이 유형의 핵심이다. **`Created0x10`으로 시간 구간을 필터하면 조작된 파일은 구조적으로 걸리지 않는다.** 3단계처럼 "시각으로 찾기"를 버리고 "불일치로 찾기"로 축을 바꾸는 것이 정답 경로였고, 6단계에서 `$J`라는 독립 artifact가 `$FN` 값을 뒷받침해 판정이 확정됐다.

## 막혔을 때 다음 체크

1. `Created0x10`과 `Created0x30`을 비교했는가 — 불일치 하나로 거의 끝난다
2. 비교 방향을 맞췄는가 — 이상은 `$SI` < `$FN`이다
3. `0x30` 컬럼이 비어 있다면 파서의 출력 규칙을 확인했는가
4. `[datetime]` 캐스팅 없이 문자열 비교를 하고 있지 않은가
5. `uSecZeros`가 `True`인데 ZIP 해제·FAT 복사 가능성을 배제했는가
6. `IsDirectory=False`로 좁혔는가
7. 사건 시각대에 아무것도 안 나오면 → **시각 필터를 버리고 불일치 필터로 전환**한다
8. `$SI` = `$FN`이라 조작이 없어 보이면 → `$J`의 `BasicInfoChange`, `$LogFile`, 부모 `INDX` 슬랙
9. 조작 대상 시각과 같은 시각을 가진 정상 파일을 뽑아 위장 대상을 특정했는가
10. 문제가 묻는 것이 "실제 생성 시각"인지 "조작 시각"인지 지문을 다시 읽었는가
11. 두 세트를 같은 시간대(UTC)로 비교했는가

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$STANDARD_INFORMATION`과 `$FILE_NAME`이 별개 속성으로 각각 타임스탬프 세트를 갖는 구조
- SRC-014 — Microsoft Learn, File Times: FILETIME이 100나노초 단위라는 점(서브초 절삭 판정의 근거)과 UTC 기준
- SRC-086 — MITRE ATT&CK Enterprise: Timestomp(Indicator Removal) 기법이 파일 시각을 변경해 탐지를 회피한다는 기법 정의
- MFTECmd의 `SI<FN`·`uSecZeros` 컬럼명과 `0x30` 컬럼이 비었을 때의 의미, analyzeMFT의 `STF FN Shift`·`uSec Zero` 컬럼은 **버전에 따라 다를 수 있으므로 실제 CSV 헤더와 `--de` 출력에서 확인할 것**
- `$FN` 시각이 rename 시점에 갱신된다는 동작은 Windows 버전·조작 도구에 따라 예외가 있을 수 있다. 판정은 `$UsnJrnl`/`$LogFile`과 교차검증할 것
