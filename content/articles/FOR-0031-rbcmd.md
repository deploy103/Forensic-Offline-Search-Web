---
id: FOR-0031
title: "RBCmd로 $Recycle.Bin 일괄 파싱: -f / -d / --csv 와 $R 복원"
slug: "rbcmd"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["$Recycle.Bin", "$I", "$R", "INFO2", "SID"]
file_paths: ["C:\\$Recycle.Bin", "C:\\RECYCLER\\INFO2", "C:\\case\\out\\rb.csv"]
registry_paths: ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"]
event_ids: []
protocols: []
tools: ["RBCmd", "Timeline Explorer", "PowerShell", "RegistryExplorer", "FTK Imager"]
commands: ["RBCmd.exe -d 'C:\\case\\$Recycle.Bin' --csv 'C:\\case\\out' --csvf rb.csv", "RBCmd.exe -f 'C:\\case\\$IQK41Z.pdf'", "RBCmd.exe -d 'C:\\case\\$Recycle.Bin' -q --csv 'C:\\case\\out'", "Import-Csv rb.csv | Sort-Object DeletedOn | Format-Table DeletedOn, FileSize, FileName"]
regex_patterns: ["\\$I[A-Za-z0-9]{6}\\.", "S-1-5-21-[\\d-]+", "\\.(xlsx|docx|pdf|7z|zip)$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["SourceName", "FileType", "FileName", "FileSize", "DeletedOn"]
file_formats: ["ntfs"]
primary_terms: ["RBCmd"]
keywords: ["RBCmd", "Eric Zimmerman", "$Recycle.Bin 파싱", "$I 파싱", "INFO2", "SourceName", "DeletedOn", "Timeline Explorer", "휴지통 CSV", "$R 복원"]
aliases: ["rbcmd", "rbcmd 사용법", "휴지통 파싱 도구", "$I 파서", "휴지통 csv", "삭제 목록 뽑기", "ez tools 휴지통"]
symptom_keywords: ["휴지통을 한 번에 파싱하고 싶다", "RBCmd 옵션을 모르겠다", "CSV 컬럼이 무슨 뜻인지 모르겠다", "삭제 목록을 시간순으로 보고 싶다", "$R 파일을 복원하고 싶다", "RBCmd가 아무것도 못 찾는다"]
related: ["FOR-0030", "FOR-0032", "FOR-0027"]
source_ids: ["SRC-004", "SRC-019", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`RBCmd.exe -d <휴지통 폴더> --csv <출력폴더>` 한 줄이면 모든 SID 폴더의 `$I`와 XP `INFO2`를 재귀로 훑어 "원래 전체 경로 + 원본 크기 + 삭제 시각" 표를 만든다 — 단 **RBCmd는 `$R`을 복원해 주지 않으므로 내용 회수는 별도의 복사 단계가 필요하다.**

## 어떤 문제에서 필요한가

- `$Recycle.Bin` 아래 SID 폴더가 여러 개이고 `$I`가 수십~수백 개일 때
- "삭제된 파일 **목록**을 시간순으로 제출하시오"
- "이 사용자가 삭제한 것만 골라내시오"
- 특정 확장자·경로·시간대의 삭제만 추려야 할 때
- `$I` 하나를 손으로 읽었는데 값이 맞는지 검증하고 싶을 때

`$I`/`$R`의 내부 구조와 필드 의미는 [FOR-0030](./recycle-bin-i-r.html)에 있다. 이 글은 **도구 조작과 결과 가공**만 다룬다.

## 문제에서 처음 볼 단서

1. 첨부/이미지에 `$Recycle.Bin` 폴더가 통째로 있다 → `-d`로 한 번에
2. `$I` 파일 하나만 주어졌다 → `-f`로 단일 파싱
3. 폴더 이름이 `RECYCLER`다 → XP. RBCmd가 `INFO2`도 처리하므로 같은 명령
4. SID 폴더가 여럿이다 → `SourceName` 컬럼으로 사용자별 분리
5. 삭제 시각이 답이다 → `DeletedOn`이 **UTC**임을 먼저 확정한 뒤 변환

## 30초 절차

```powershell
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv
```

**단일 인용부호를 쓴다.** PowerShell 이중 인용부호 안에서는 `$Recycle`이 변수로 해석되어 경로가 `.Bin`으로 망가진다 (아래 함정 참고).

결과를 바로 눈으로 보려면:

```powershell
Import-Csv 'C:\case\out\rb.csv' | Sort-Object DeletedOn |
  Format-Table DeletedOn, FileSize, FileName -AutoSize
```

```text
DeletedOn             FileSize  FileName
2026-04-05 02:11:09    1204736  C:\Users\hjlee\Desktop\budget.xlsx
2026-04-07 11:02:44    9822712  C:\Users\pshin\Downloads\installer.exe
2026-04-08 23:47:15     268435  C:\Users\pshin\Documents\contract_2026.pdf
2026-04-08 23:52:03          0  C:\Users\pshin\Desktop\ProjectX
```

## 상세 절차

### 1단계 — 옵션

| 옵션 | 의미 | 실전 사용 |
| --- | --- | --- |
| `-f <파일>` | `$I` 또는 `INFO2` **파일 하나** 파싱. 결과를 콘솔에 출력 | 값 검증, 단일 첨부 |
| `-d <디렉터리>` | 디렉터리를 **재귀** 탐색해 발견되는 모든 `$I`/`INFO2` 파싱 | 기본 작업 방식 |
| `--csv <디렉터리>` | CSV를 저장할 **디렉터리** (파일이 아니다) | 항상 붙인다 |
| `--csvf <파일명>` | CSV 파일 이름 지정 | 생략하면 타임스탬프가 붙은 이름이 자동 생성된다 |
| `-q` | 항목별 상세 출력을 억제하고 진행만 표시 | 항목이 수백 개일 때 속도 확보 |
| `--dt <형식>` | 타임스탬프 표시 형식 지정 | 기본 형식이 읽기 불편할 때 |

`-f`와 `-d`는 **둘 중 하나가 반드시 필요**하고 함께 쓸 수 없다.

```powershell
# 단일 $I 파싱 — 콘솔에 바로 값이 나온다
RBCmd.exe -f 'C:\case\$IQK41Z.pdf'
```

```text
Source name: C:\case\$IQK41Z.pdf
File name:   C:\Users\pshin\Documents\contract_2026.pdf
File size:   262.1 KB (268,435 bytes)
Deleted on:  2026-04-08 23:47:15
```

```powershell
# 휴지통 전체 — 모든 SID 폴더를 한 번에
RBCmd.exe -d 'C:\case\$Recycle.Bin' -q --csv 'C:\case\out' --csvf rb.csv
```

```text
Looking for files in C:\case\out ...
Found 47 files
Processed 47 files. 0 errors
CSV output will be saved to C:\case\out\rb.csv
```

### 2단계 — `$Recycle.Bin` 전체를 확보하는 순서

RBCmd는 파일이 있어야 동작한다. 이미지에서 폴더를 통째로 꺼내는 것이 먼저다.

| 상황 | 방법 |
| --- | --- |
| E01/RAW 이미지 | FTK Imager로 볼륨 열고 `[root]` → `$Recycle.Bin` 우클릭 → `Export Files` ([FOR-0016](./ftk-imager-open-image.html)) |
| 이미지 마운트 | Arsenal Image Mounter로 읽기 전용 마운트 후 복사 ([FOR-0017](./arsenal-image-mounter.html)) |
| 라이브 시스템 | 관리자 PowerShell에서 `Copy-Item -Force -Recurse` (숨김+시스템 속성 때문에 `-Force` 필수) |
| 볼륨이 여러 개 | **볼륨마다** 루트의 `$Recycle.Bin`을 따로 꺼낸다. `D:\$Recycle.Bin`도 별도 |

```powershell
# 라이브 수집 — 숨김/시스템 속성 무시
Copy-Item -Force -Recurse 'C:\$Recycle.Bin' 'E:\collect\C_RecycleBin'
Copy-Item -Force -Recurse 'D:\$Recycle.Bin' 'E:\collect\D_RecycleBin'
```

여러 볼륨을 모았으면 상위 폴더 하나를 `-d`로 주면 전부 처리된다.

```powershell
RBCmd.exe -d 'E:\collect' --csv 'E:\out' --csvf rb_all.csv
```

### 3단계 — 출력 컬럼 해석

| 컬럼 | 내용 | 해석 |
| --- | --- | --- |
| `SourceName` | 파싱한 `$I`/`INFO2` **파일 자체의 경로** | **SID와 6문자 식별자가 여기 들어 있다.** `$R` 짝을 찾는 키 |
| `FileType` | `$I` 또는 `INFO2` (버전에 따라 컬럼 유무·표기가 다를 수 있다) | Vista+ 인지 XP인지 |
| `FileName` | **삭제 당시의 원래 전체 경로** | "원래 경로" 문항의 정답. 드라이브 문자부터 들어 있다 |
| `FileSize` | `$I`에 기록된 원본 크기 (바이트) | `$R` 실제 크기와 대조. 폴더면 `0` |
| `DeletedOn` | 휴지통으로 보낸 시각 (FILETIME 원본 → **UTC**) | KST 답이면 +9시간 |

`SourceName`에서 두 가지를 뽑는다.

```powershell
Import-Csv rb.csv | ForEach-Object {
  [pscustomobject]@{
    Sid       = ([regex]::Match($_.SourceName, 'S-1-5-21-[\d-]+')).Value
    Id6       = ([regex]::Match($_.SourceName, '\$I([A-Za-z0-9]{6})')).Groups[1].Value
    DeletedOn = $_.DeletedOn
    Size      = $_.FileSize
    Original  = $_.FileName
  }
} | Format-Table -AutoSize
```

```text
Sid                                            Id6     DeletedOn             Size     Original
S-1-5-21-1004336348-1177238915-682003330-1001  QK41Z   2026-04-08 23:47:15   268435   C:\Users\pshin\Documents\contract_2026.pdf
S-1-5-21-1004336348-1177238915-682003330-1002  8M2P0A  2026-04-05 02:11:09   1204736  C:\Users\hjlee\Desktop\budget.xlsx
```

`Id6`은 `$R` 파일을 찾는 키이고, `Sid`는 삭제한 사용자다.

### 4단계 — SID를 사용자 이름으로 바꾼다

RBCmd는 SID를 이름으로 바꿔 주지 않는다. SOFTWARE 하이브로 직접 매핑한다.

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
  └ ProfileImagePath = C:\Users\pshin
```

RegistryExplorer로 SOFTWARE 하이브를 열어 `ProfileList` 하위 키를 확인하고, 매핑 표를 만들어 CSV에 붙인다.

```powershell
# ProfileList 에서 읽은 값을 손으로 표로 만들고 조인한다
$map = @{
  'S-1-5-21-1004336348-1177238915-682003330-1001' = 'pshin'
  'S-1-5-21-1004336348-1177238915-682003330-1002' = 'hjlee'
}

Import-Csv rb.csv | ForEach-Object {
  $sid = ([regex]::Match($_.SourceName, 'S-1-5-21-[\d-]+')).Value
  [pscustomobject]@{
    User      = if ($map.ContainsKey($sid)) { $map[$sid] } else { "$sid (미매핑)" }
    DeletedOn = $_.DeletedOn
    Original  = $_.FileName
    Size      = $_.FileSize
  }
} | Sort-Object DeletedOn | Format-Table -AutoSize
```

하이브가 없으면 RID(`-1001`, `-1002`)와 `C:\Users\` 폴더 목록으로 추정하되 **추정임을 답변에 명시한다.** SID 구조와 well-known 값은 [FOR-0030](./recycle-bin-i-r.html)에 정리되어 있다.

### 5단계 — PowerShell / Timeline Explorer로 좁히기

```powershell
# 특정 사용자만
Import-Csv rb.csv | Where-Object { $_.SourceName -match '682003330-1001' }

# 특정 확장자만 (원래 경로 기준)
Import-Csv rb.csv | Where-Object { $_.FileName -match '\.(xlsx|docx|pdf|7z|zip)$' }

# 시간대 한정 — DeletedOn 은 UTC 문자열이므로 datetime 으로 캐스팅해 비교
Import-Csv rb.csv |
  Where-Object { [datetime]$_.DeletedOn -ge '2026-04-08 00:00:00' -and
                 [datetime]$_.DeletedOn -le '2026-04-09 00:00:00' } |
  Sort-Object { [datetime]$_.DeletedOn }

# 큰 파일부터 (유출 후보)
Import-Csv rb.csv | Sort-Object { [int64]$_.FileSize } -Descending | Select-Object -First 10

# 삭제된 폴더만 (FileSize 0 + 확장자 없음)
Import-Csv rb.csv | Where-Object { $_.FileSize -eq '0' -and $_.FileName -notmatch '\.\w{1,5}$' }

# KST 컬럼을 붙여 제출용으로
Import-Csv rb.csv | Select-Object @{n='DeletedKST';e={([datetime]$_.DeletedOn).AddHours(9)}},
                                  FileSize, FileName | Sort-Object DeletedKST
```

`Sort-Object FileSize`를 그냥 쓰면 **문자열 정렬**이 되어 `9822712`가 `268435`보다 작게 나온다. 반드시 `[int64]`로 캐스팅한다. `DeletedOn`도 같은 이유로 `[datetime]` 캐스팅이 필요하다.

Timeline Explorer로는 `rb.csv`를 드래그해 열고 `DeletedOn` 컬럼을 클릭 정렬한 뒤 컬럼 필터에 확장자나 사용자 문자열을 입력한다. 다른 EZ 도구의 CSV(`usn.csv`, `mft.csv`, `sec.csv`)를 같은 창에 탭으로 열어 두면 시각 대조가 빠르다.

### 6단계 — `$R` 파일 복원

RBCmd는 메타데이터만 읽는다. 내용 회수는 `SourceName`의 `$I`를 `$R`로 바꿔 복사하는 작업이다.

```powershell
$out = 'C:\case\restored'
New-Item -ItemType Directory -Force -Path $out | Out-Null

Import-Csv 'C:\case\out\rb.csv' | ForEach-Object {
  # $I... -> $R...  파일명 앞 2문자만 바꾼다. 정규식 치환은 '$' 때문에 위험하므로 쓰지 않는다
  $dir  = Split-Path $_.SourceName -Parent
  $leaf = Split-Path $_.SourceName -Leaf
  $r    = Join-Path $dir ('$R' + $leaf.Substring(2))
  $name = Split-Path $_.FileName -Leaf
  if (Test-Path -LiteralPath $r) {
    $dest = Join-Path $out $name
    Copy-Item -LiteralPath $r -Destination $dest -Recurse -Force
    [pscustomobject]@{ Restored = $name
                       SizeInI  = $_.FileSize
                       SizeOnDisk = (Get-Item -LiteralPath $dest).Length
                       Match    = ($_.FileSize -eq (Get-Item -LiteralPath $dest).Length) }
  } else {
    [pscustomobject]@{ Restored = $name; SizeInI = $_.FileSize; SizeOnDisk = $null; Match = '$R 없음' }
  }
} | Format-Table -AutoSize
```

```text
Restored             SizeInI  SizeOnDisk  Match
contract_2026.pdf     268435      268435   True
budget.xlsx          1204736     1204736   True
installer.exe        9822712                $R 없음
ProjectX                   0                (폴더 - 재귀 복사됨)
```

| 결과 | 해석 | 다음 조치 |
| --- | --- | --- |
| `Match = True` | 온전한 복원 | 매직 바이트로 형식 한 번 더 확인 |
| 크기 불일치 | `$R` 절단 또는 짝 오류 | 6문자와 확장자가 정확히 같은지 재확인 |
| `$R 없음` | 휴지통이 비워졌거나 복원됨 | `$J`의 `FileDelete` 시각 확인 → 카빙 |
| 폴더 | 디렉터리 삭제 | `-Recurse`로 트리 전체 복사 |

**동일 이름의 파일이 여러 개 삭제되었으면 마지막 복사가 앞의 것을 덮는다.** 위 스크립트에서 `$name`에 `Id6`을 접두로 붙이면 충돌을 피할 수 있다.

## 출력 필드 해석

`-f` 단일 파싱의 콘솔 출력과 CSV 컬럼의 대응이다.

| 콘솔 출력 라벨 | CSV 컬럼 | 주의 |
| --- | --- | --- |
| `Source name` | `SourceName` | 여기에 SID와 6문자가 들어 있다 |
| `File name` | `FileName` | **원래 전체 경로**다. 파일 이름만이 아니다 |
| `File size` | `FileSize` | 콘솔은 `262.1 KB (268,435 bytes)` 처럼 두 형태, CSV는 바이트 정수 |
| `Deleted on` | `DeletedOn` | **UTC.** 콘솔은 `--dt` 형식을 따른다 |

CSV 컬럼명·컬럼 순서·`FileType` 컬럼의 존재 여부는 RBCmd 버전에 따라 다르다. **필터를 짜기 전에 `Import-Csv rb.csv | Get-Member -MemberType NoteProperty`로 실제 컬럼을 한 번 확인한다.**

```powershell
Import-Csv 'C:\case\out\rb.csv' | Get-Member -MemberType NoteProperty | Select-Object Name
```

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음에 열 것 | 확인할 것 |
| --- | --- | --- |
| `SourceName`의 SID | SOFTWARE 하이브 `ProfileList` | 사용자 이름 |
| `DeletedOn` | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | 같은 시각의 rename 짝, 전후 활동 |
| `DeletedOn` | EVTX 4624 ([FOR-0083](./event-4624-logon.html)) | 그 시각의 로그온 세션이 SID와 일치하는가 |
| `FileName`(원래 경로) | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 폴더의 다른 파일과 MACB |
| 복원한 `$R` 내용 | exiftool / 문서 메타데이터 | 작성자, 원본 생성 시각 |
| `$R` 없음 | `$J`의 `FileDelete` + 카빙 | 휴지통 비운 시각, 내용 회수 |
| 삭제 목록이 비어 있음 | 원인 분기 ([FOR-0032](./deleted-file-not-in-recycle-bin.html)) | Shift+Delete·이동식 매체·도구 삭제 |
| 구조를 직접 확인해야 할 때 | `$I` hex ([FOR-0030](./recycle-bin-i-r.html)) | 버전·크기·시각·경로 오프셋 |

## 흔한 함정

- **PowerShell 이중 인용부호로 `"$Recycle.Bin"`을 쓰는 것** → `$Recycle`이 변수로 확장되어(정의되지 않았으므로 빈 문자열) 경로가 `C:\case\.Bin`이 되고 RBCmd가 "찾을 수 없다"고 답한다 → **단일 인용부호** `'C:\case\$Recycle.Bin'`을 쓰거나 백틱으로 `` "C:\case\`$Recycle.Bin" `` 이스케이프한다. `$I`, `$R`, `$J`, `$MFT` 경로 전부 같은 문제다.
- **`--csv`에 파일 경로를 주는 것** → `--csv`는 **디렉터리**를 받는다. 파일명은 `--csvf`다 → `--csv 'C:\out' --csvf rb.csv`.
- **`-d` 없이 `-f`로 폴더를 지정하는 것** → 오류만 난다 → 폴더는 `-d`, 파일은 `-f`.
- **RBCmd가 `$R`을 복원해 줄 것으로 기대하는 것** → RBCmd는 `$I`/`INFO2` **파서**다. 내용은 손대지 않는다 → 복원은 `$R` 복사 단계를 직접 수행한다.
- **`$Recycle.Bin`을 `-Force` 없이 복사해 빈 폴더를 넘기는 것** → 숨김+시스템 속성 항목이 복사되지 않아 RBCmd가 0건을 보고한다 → `Copy-Item -Force -Recurse`, 또는 FTK Imager로 Export한다.
- **`C:` 볼륨만 파싱하는 것** → 휴지통은 볼륨마다 따로 있다 → 각 볼륨의 `$Recycle.Bin`을 모두 모아 상위 폴더를 `-d`로 준다.
- **`FileSize`/`DeletedOn`을 문자열로 정렬·비교하는 것** → `Import-Csv`는 모든 값을 문자열로 준다. `9822712`가 `268435`보다 작게 정렬된다 → `[int64]`, `[datetime]`으로 캐스팅한다.
- **`DeletedOn`을 로컬 시각으로 보고하는 것** → `$I`의 값은 FILETIME(1601-01-01 UTC 기준 100ns)이고 RBCmd도 UTC로 출력한다. `--dt`는 표시 **형식**만 바꾸고 시간대를 바꾸지 않는다 → KST 답이면 `+9시간`, Unix 환산은 `-11644473600`초.
- **`FileName`을 파일 이름으로만 읽는 것** → 이 컬럼은 전체 경로다. `Split-Path -Leaf`로 이름만 뽑아야 복원 파일명이 된다 → 반대로 "원래 경로" 문항에는 컬럼 값을 그대로 쓴다.
- **`FileSize = 0`을 빈 파일로 단정하는 것** → 삭제된 **폴더**의 `$I`도 0으로 나온다 → `$R`이 디렉터리인지 확인한다.
- **여러 SID를 한 사용자로 합쳐 보는 것** → `-d`로 한 번에 파싱하면 CSV에 모든 사용자가 섞인다 → 반드시 `SourceName`의 SID로 분리해 집계한다.
- **0건이 나왔을 때 "삭제가 없었다"로 결론 내는 것** → 경로 확장 오류, `-Force` 누락, 다른 볼륨, Shift+Delete 등 원인이 많다 → 먼저 `Get-ChildItem -Force -Recurse`로 `$I` 파일 자체가 있는지 확인하고, 없으면 [FOR-0032](./deleted-file-not-in-recycle-bin.html)로 간다.

## 교차검증

```powershell
# 1) RBCmd 결과
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv

# 2) 파일 시스템 실측 — $I 개수와 CSV 행 수가 맞는가
(Get-ChildItem -Force -Recurse 'C:\case\$Recycle.Bin' -Filter '$I*').Count
(Import-Csv 'C:\case\out\rb.csv').Count

# 3) 단일 파싱으로 값 하나를 재확인
RBCmd.exe -f 'C:\case\$Recycle.Bin\S-1-5-21-...-1001\$IQK41Z.pdf'

# 4) $J 와 시각 대조 — 독립 출처로 삭제 시각 확증
Import-Csv usn.csv | Where-Object { $_.FileName -match 'QK41Z' } |
  Sort-Object {[uint64]$_.Usn} | Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName
```

| 대조 항목 | 일치해야 하는 값 | 불일치 시 |
| --- | --- | --- |
| `$I` 파일 개수 vs CSV 행 수 | 같아야 한다 | 파싱 실패 항목이 있다. `-q` 빼고 다시 돌려 오류 메시지를 본다 |
| CSV `FileSize` vs `$R` 실제 크기 | 같아야 한다 | 짝 오류 또는 `$R` 절단 |
| CSV `DeletedOn` vs `$J`의 rename 시각 | 초 단위까지 같아야 한다 | 한쪽이 다른 시간대로 표시됐거나 다른 항목을 본 것 |
| CSV의 SID vs `$J`의 `ParentPath` | 같은 SID 폴더여야 한다 | 다른 사용자의 삭제를 보고 있다 |

## mini walkthrough

```text
문제:
"두 명이 쓰던 PC입니다. 2026-04-08(KST) 하루 동안 삭제된 파일 중
 가장 큰 것의 원래 경로와 삭제한 사용자를 구하세요."
첨부: $Recycle.Bin 폴더, SOFTWARE 하이브, $J

1. 첫 시도 (실패):
   RBCmd.exe -d "C:\case\$Recycle.Bin" --csv "C:\case\out" --csvf rb.csv
   -> "Directory 'C:\case\.Bin' not found"

   PowerShell 이중 인용부호 안의 $Recycle 이 변수로 확장되어
   경로가 C:\case\.Bin 으로 망가졌다.  <-- 도구 문제가 아니라 셸 문제

   수정: 단일 인용부호
   RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv
   -> Processed 47 files. 0 errors

2. 두 번째 시도 (실패):
   Import-Csv 'C:\case\out\rb.csv' | Sort-Object FileSize -Descending |
     Select-Object -First 1

   FileSize  FileName
   9822712   C:\Users\pshin\Downloads\installer.exe

   그런데 목록을 눈으로 보니 1204736 이 9822712 보다 위에 정렬돼 있었다.
   Import-Csv 가 모든 값을 문자열로 주기 때문에 사전순 정렬이 됐다.
   ("9822712" < "1204736" 이 아니라 "1" < "9" 로 비교된다)

   수정: [int64] 캐스팅
   Import-Csv 'C:\case\out\rb.csv' | Sort-Object {[int64]$_.FileSize} -Descending |
     Select-Object -First 5 FileSize, DeletedOn, FileName

   FileSize   DeletedOn             FileName
   9822712    2026-04-07 11:02:44   C:\Users\pshin\Downloads\installer.exe
   4118016    2026-04-08 14:30:22   C:\Users\hjlee\Documents\salary_2026.xlsx
   1204736    2026-04-05 02:11:09   C:\Users\hjlee\Desktop\budget.xlsx
   268435     2026-04-08 23:47:15   C:\Users\pshin\Documents\contract_2026.pdf

3. 세 번째 함정 — 날짜 범위
   문제는 "2026-04-08 KST 하루"를 요구했다. DeletedOn 은 UTC 다.
   KST 04-08 00:00 ~ 04-09 00:00  =  UTC 04-07 15:00 ~ 04-08 15:00

   Import-Csv 'C:\case\out\rb.csv' |
     Where-Object { [datetime]$_.DeletedOn -ge '2026-04-07 15:00:00' -and
                    [datetime]$_.DeletedOn -lt  '2026-04-08 15:00:00' } |
     Sort-Object {[int64]$_.FileSize} -Descending |
     Select-Object @{n='KST';e={([datetime]$_.DeletedOn).AddHours(9)}}, FileSize, FileName, SourceName

   KST                  FileSize  FileName                                     SourceName
   2026-04-08 23:30:22   4118016  C:\Users\hjlee\Documents\salary_2026.xlsx    ...\S-1-5-21-...-1002\$I3PB7QW.xlsx

   installer.exe(04-07 11:02 UTC = 04-07 20:02 KST)는 범위 밖이므로 탈락.
   contract_2026.pdf(04-08 23:47 UTC = 04-09 08:47 KST)도 범위 밖이다.
   -> UTC 로 그대로 필터했으면 두 건 다 오답이 됐다.

4. SID -> 사용자
   RegistryExplorer 로 SOFTWARE 하이브 열기
   ProfileList\S-1-5-21-...-1002 : ProfileImagePath = C:\Users\hjlee
   -> hjlee

5. 교차검증 — $J
   Import-Csv usn.csv | Where-Object { $_.FileName -match '3PB7QW' } | Sort-Object Usn
   -> 2026-04-08 14:30:22Z  RenameNewName|Close  $R3PB7QW.xlsx  .\$Recycle.Bin\S-1-5-21-...-1002
      2026-04-08 14:30:22Z  FileCreate|Close     $I3PB7QW.xlsx  .\$Recycle.Bin\S-1-5-21-...-1002
   -> RBCmd 의 DeletedOn 과 초 단위까지 일치. 사용자 폴더도 일치.

6. 복원
   Copy-Item -LiteralPath 'C:\case\$Recycle.Bin\S-1-5-21-...-1002\$R3PB7QW.xlsx' `
             -Destination 'C:\case\restored\salary_2026.xlsx'
   크기 4118016 일치, Format-Hex 선두 = 50 4b 03 04 (PK, xlsx 정상)

정답:
  원래 경로  C:\Users\hjlee\Documents\salary_2026.xlsx
  사용자     hjlee (S-1-5-21-...-682003330-1002)
  삭제 시각  2026-04-08 23:30:22 KST (2026-04-08 14:30:22 UTC)
```

이 문제의 실패는 전부 **도구가 아니라 셸과 자료형**에서 나왔다. 이중 인용부호의 `$` 확장, `Import-Csv`의 문자열 정렬, UTC/KST 경계 — 세 가지가 RBCmd 사용에서 가장 자주 답을 틀리게 만드는 지점이다.

## 막혔을 때 다음 체크

1. 경로를 **단일 인용부호**로 감쌌는가 (`$Recycle.Bin`, `$I...` 전부)
2. `--csv`에 디렉터리를, `--csvf`에 파일명을 줬는가
3. `Get-ChildItem -Force -Recurse ... -Filter '$I*'`로 `$I`가 실제로 존재하는지 확인했는가
4. `$I` 개수와 CSV 행 수가 일치하는가 — 다르면 `-q`를 빼고 오류를 읽는다
5. 모든 볼륨의 `$Recycle.Bin`을 모았는가
6. `FileSize`/`DeletedOn`을 캐스팅해 정렬·비교했는가
7. 문제가 요구하는 시간대(UTC/KST)로 필터 경계를 환산했는가
8. SID를 `ProfileList`로 사용자 이름까지 매핑했는가
9. `$R` 복사 후 크기와 매직 바이트를 확인했는가
10. 0건이라면 → [FOR-0032](./deleted-file-not-in-recycle-bin.html)의 원인 분기로 이동

## 출처

- SRC-004 — Eric Zimmerman 도구 문서: RBCmd의 `-f`/`-d`/`--csv`/`--csvf`/`-q`/`--dt` 옵션과 CSV 출력 컬럼(`SourceName`, `FileName`, `FileSize`, `DeletedOn`), `$I`와 XP `INFO2` 양쪽 지원, Timeline Explorer 연동
- SRC-019 — Microsoft Learn, Well-known SIDs / Security Identifiers: `SourceName`에서 추출한 `S-1-5-21-...` SID의 구조와 RID 의미
- SRC-014 — Microsoft Learn, File Times: `DeletedOn`이 FILETIME(1601-01-01 UTC 기준 100ns) 기반 UTC 값이라는 근거와 Unix epoch 차이 `11644473600`초
- RBCmd의 옵션 표기, CSV 컬럼명·순서, `FileType` 컬럼의 존재 여부, 콘솔 출력 문구는 버전에 따라 다르므로 `RBCmd.exe` 를 인자 없이 실행해 도움말을 확인하고 `Get-Member`로 실제 컬럼을 대조할 것
- walkthrough의 SID·6문자 식별자·파일 이름·크기는 설명을 위한 예시 값이다
