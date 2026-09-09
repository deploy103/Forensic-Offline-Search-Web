---
id: FOR-0022
title: "analyzeMFT / MFTECmd CSV로 $MFT 필터링하기"
slug: "analyzemft-csv"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["$MFT", "MFT CSV", "MFT record", "bodyfile"]
file_paths: ["C:\\$MFT", "C:\\case\\out\\mft.csv"]
registry_paths: []
event_ids: []
protocols: []
tools: ["analyzeMFT", "MFTECmd", "Timeline Explorer", "PowerShell", "ripgrep", "awk", "sqlite3", "FTK Imager"]
commands: ["MFTECmd.exe -f \"C:\\case\\$MFT\" --csv \"C:\\case\\out\" --csvf mft.csv", "analyzeMFT.py -f $MFT -o mft.csv -a", "Import-Csv mft.csv | Where-Object { $_.InUse -eq 'False' }", "rg -N ',False,' mft.csv", "sqlite3 mft.db \".import --csv mft.csv mft\""]
regex_patterns: ["\\.(zip|7z|rar|exe|ps1|docx|xlsx)$", "^2026-03-14"]
wireshark_filters: []
tshark_fields: []
log_fields: ["EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "ParentPath", "FileName", "Extension", "FileSize", "IsDirectory", "HasAds", "SI<FN", "uSecZeros", "Created0x10", "LastModified0x10", "Record Number", "Active", "Std Info Creation date", "STF FN Shift", "uSec Zero"]
file_formats: ["ntfs", "csv"]
primary_terms: ["analyzeMFT", "MFTECmd", "MFT CSV"]
keywords: ["analyzeMFT", "MFTECmd", "MFT CSV", "$MFT 파싱", "Import-Csv", "삭제 파일 필터", "ParentEntryNumber", "경로 복원", "Timeline Explorer", "대용량 CSV"]
aliases: ["analyzemft", "mftecmd", "mft csv", "mft 파싱", "mft 엑셀로 보기", "삭제 파일만 보기", "mft 필터링", "mft 경로 복원"]
symptom_keywords: ["CSV가 너무 커서 안 열린다", "삭제된 파일만 보고 싶다", "경로가 안 나온다", "특정 시간대 파일만 뽑고 싶다", "엑셀이 멈춘다", "확장자별로 세고 싶다"]
related: ["FOR-0021", "FOR-0023", "FOR-0024"]
source_ids: ["SRC-005", "SRC-004", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`$MFT`는 수십만 행 CSV로 변환한 뒤 **`InUse` + `Extension` + 시간 구간** 세 조건으로 좁혀야 쓸 수 있다. MFTECmd는 경로(`ParentPath`)까지 채워 주므로 기본값으로 쓰고, analyzeMFT는 `STF FN Shift`·`uSec Zero` 같은 이상 징후 컬럼이 필요할 때 쓴다.

## 어떤 문제에서 필요한가

- "삭제된 파일 중 `.zip`만 찾아라"
- "2026-03-14 07:00~08:00 사이에 생성된 파일 전체"
- "`C:\Users\jhkim\Documents` 아래에 뭐가 있었나"
- "확장자별 파일 개수" / "가장 큰 파일 10개"
- "이 파일의 전체 경로" (CSV에 이름만 있을 때)
- Excel로 열었더니 행이 잘리거나 응답이 없을 때

`$MFT` 구조 자체는 [FOR-0021](./mft-basics.html)에서 다룬다. 이 글은 **CSV가 나온 다음**을 다룬다.

## 문제에서 처음 볼 단서

1. 첨부가 `$MFT` 파일 하나 → 이 절차 그대로
2. 첨부가 이미 `mft.csv` → 헤더 한 줄부터 확인해 어느 파서 산출물인지 판별
3. 지문에 시각이 있다 → 그 시각 ±10분의 `Created0x10`
4. 지문에 폴더 경로가 있다 → `ParentPath` 부분일치
5. 지문에 "삭제" → `InUse = False`
6. 지문에 "숨겨진" → `HasAds = True` 또는 `IsAds = True`

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
```

```powershell
# 헤더 한 줄로 파서 판별 — 컬럼명이 다르면 필터도 달라진다
Get-Content C:\case\out\mft.csv -TotalCount 1

# 삭제된 항목만, 파일만
Import-Csv C:\case\out\mft.csv |
  Where-Object { $_.InUse -eq 'False' -and $_.IsDirectory -eq 'False' } |
  Select-Object EntryNumber, ParentPath, FileName, FileSize, Created0x10
```

CSV가 100MB를 넘으면 `Import-Csv`부터 쓰지 않는다. 아래 "대용량 CSV" 절로 바로 간다.

## 상세 절차

### 1단계 — 파서 선택

| | MFTECmd | analyzeMFT |
| --- | --- | --- |
| 언어/실행 | .NET 단일 실행 파일 | Python 스크립트 |
| 속도 | 수십만 레코드를 수십 초 | 상대적으로 느리다 |
| **경로 복원** | `ParentPath` 컬럼을 채워 준다 | 부모 레코드 번호만 준다 |
| 이상 징후 컬럼 | `SI<FN`, `uSecZeros`, `HasAds`, `Copied` | `STF FN Shift`, `uSec Zero` (`-a` 옵션) |
| 추가 입력 | `-m $MFT`로 `$J` 파싱 시 경로 결합 | — |
| bodyfile 출력 | `--body` / `--bodyf` | `-b` |
| 기타 지원 | `$J`, `$Boot`, `$SDS` | `$MFT` 전용 |

실전 결론: **경로가 필요하면 MFTECmd, Python만 있는 환경이거나 이상 징후 플래그를 원하면 analyzeMFT.** 둘 다 돌려서 교차검증하는 것이 가장 안전하다.

```powershell
# MFTECmd — 기본
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv

# JSON 으로 (jq 로 다루고 싶을 때)
MFTECmd.exe -f 'C:\case\$MFT' --json "C:\case\out" --jsonf mft.json

# bodyfile (mactime 타임라인용). --bdl 로 드라이브 문자를 붙인다
MFTECmd.exe -f 'C:\case\$MFT' --body "C:\case\out" --bodyf mft.body --bdl C

# 레코드 하나만 상세 덤프 — 속성 단위로 본다
MFTECmd.exe -f 'C:\case\$MFT' --de 84213
```

```bash
# analyzeMFT — -a 를 붙여야 이상 징후 컬럼이 채워진다
analyzeMFT.py -f '$MFT' -o mft.csv -a

# bodyfile 출력
analyzeMFT.py -f '$MFT' -b mft.body
```

### 2단계 — 헤더를 먼저 읽는다

필터를 짜기 전에 컬럼 이름을 확인한다. 컬럼명 하나 틀리면 `Where-Object`는 **에러 없이 0건**을 돌려주기 때문에, 필터가 잘못됐는지 데이터가 없는지 구분이 안 된다.

```bash
head -1 mft.csv | tr ',' '\n' | nl
```

```powershell
# PowerShell 로도 같은 확인
(Import-Csv mft.csv -TotalCount 1) | Get-Member -MemberType NoteProperty | Select-Object Name
```

### 3단계 — 레시피

아래는 MFTECmd 컬럼명 기준이다. analyzeMFT를 쓰면 `InUse`→`Active`, `FileName`→`Filename #1`, `Created0x10`→`Std Info Creation date`로 바꾼다.

**삭제된 파일만**

```powershell
Import-Csv out\mft.csv |
  Where-Object { $_.InUse -eq 'False' -and $_.IsDirectory -eq 'False' } |
  Sort-Object { [datetime]$_.Created0x10 } |
  Select-Object EntryNumber, SequenceNumber, ParentPath, FileName, FileSize, Created0x10
```

**확장자별 (삭제 여부 무시)**

```powershell
Import-Csv out\mft.csv |
  Where-Object { $_.Extension -in '.zip', '.7z', '.rar', '.exe', '.ps1' } |
  Select-Object ParentPath, FileName, FileSize, Created0x10, LastModified0x10
```

**시간 구간별** — 문자열 비교가 아니라 `[datetime]` 캐스팅으로 비교한다.

```powershell
$from = [datetime]'2026-03-14 07:00:00'
$to   = [datetime]'2026-03-14 08:00:00'

Import-Csv out\mft.csv |
  Where-Object {
    $_.Created0x10 -and
    ([datetime]$_.Created0x10) -ge $from -and ([datetime]$_.Created0x10) -le $to
  } |
  Sort-Object { [datetime]$_.Created0x10 } |
  Format-Table Created0x10, ParentPath, FileName, FileSize
```

**특정 폴더만**

```powershell
Import-Csv out\mft.csv |
  Where-Object { $_.ParentPath -like '*\Users\jhkim\Downloads*' } |
  Select-Object FileName, FileSize, Created0x10, InUse
```

`ParentPath`는 MFTECmd 버전에 따라 `.\Users\jhkim\Downloads` 처럼 `.\`로 시작한다. 그래서 앞뒤를 `*`로 감싼 부분일치를 쓴다.

**파일 개수 집계**

```powershell
# 확장자별 개수 상위 20
Import-Csv out\mft.csv |
  Where-Object { $_.IsDirectory -eq 'False' } |
  Group-Object Extension |
  Sort-Object Count -Descending | Select-Object -First 20 Count, Name

# 삭제 / 활성 비율
Import-Csv out\mft.csv | Group-Object InUse | Select-Object Name, Count

# 폴더별 파일 수
Import-Csv out\mft.csv | Group-Object ParentPath |
  Sort-Object Count -Descending | Select-Object -First 15 Count, Name
```

**가장 큰 파일**

```powershell
Import-Csv out\mft.csv |
  Where-Object { $_.IsDirectory -eq 'False' -and $_.FileSize -as [long] } |
  Sort-Object { [long]$_.FileSize } -Descending |
  Select-Object -First 10 FileName, ParentPath, @{n='MB';e={[math]::Round($_.FileSize/1MB,1)}}
```

### 4단계 — ripgrep / awk (PowerShell이 느릴 때)

```bash
# 삭제된 zip/7z/rar — 컬럼 위치를 몰라도 되는 거친 필터
rg -N -i '\.(zip|7z|rar)"?,' mft.csv | rg -N ',False,' | head -30

# 특정 날짜에 생성된 항목 (생성일 컬럼 번호를 head -1 로 미리 확인)
awk -F',' 'NR==1 || $20 ~ /^2026-03-14/' mft.csv | head

# 확장자별 개수 — Extension 컬럼 번호가 8일 때
awk -F',' 'NR>1 {print $8}' mft.csv | sort | uniq -c | sort -nr | head -20

# 특정 폴더
rg -N 'Users\\\\jhkim\\\\Downloads' mft.csv | wc -l
```

CSV 필드에 콤마가 들어간 파일명이 있으면 `awk -F','`는 컬럼이 밀린다. **집계는 awk, 최종 확인은 반드시 PowerShell `Import-Csv`나 Timeline Explorer로** 다시 본다.

### 5단계 — ParentEntryNumber로 경로 복원

analyzeMFT처럼 경로 컬럼이 없거나, MFTECmd의 `ParentPath`가 비어 있는(부모 레코드가 재사용된) 항목은 직접 올라간다.

```text
규칙: EntryNumber 5 = 루트 디렉터리 -> 여기서 멈춘다
      ParentEntryNumber 를 따라 이름을 앞에 붙여 나간다
      ParentSequenceNumber 가 부모의 SequenceNumber 와 다르면 -> 부모가 이미 재사용됨 (경로 불확실)
```

```powershell
$rows = Import-Csv out\mft.csv
$byEntry = @{}
foreach ($r in $rows) { $byEntry[$r.EntryNumber] = $r }

function Get-MftPath([string]$entry) {
  $parts = @()
  $cur = $byEntry[$entry]
  $guard = 0
  while ($cur -and $guard -lt 64) {
    if ($cur.EntryNumber -eq '5') { break }          # 루트 도달
    $parts = ,$cur.FileName + $parts
    $next = $byEntry[$cur.ParentEntryNumber]
    if (-not $next) { $parts = ,'<ORPHAN>' + $parts; break }
    if ($next.SequenceNumber -ne $cur.ParentSequenceNumber) {
      $parts = ,'<REUSED>' + $parts; break           # 부모 슬롯 재사용 = 경로 신뢰 불가
    }
    $cur = $next
    $guard++
  }
  '\' + ($parts -join '\')
}

Get-MftPath '84213'
```

```text
\Users\jhkim\Documents\secret.txt
```

`<ORPHAN>`이 나오면 부모 레코드가 CSV에 없다는 뜻이다. 삭제된 폴더의 자식일 때 흔하고, 이 경우 경로는 `$UsnJrnl`의 `ParentEntryNumber`나 `$LogFile`의 인덱스 조작 기록으로 보완한다 ([FOR-0027](./usnjrnl-basics.html)).

### 6단계 — Timeline Explorer

CSV를 GUI로 볼 때는 Excel이 아니라 Timeline Explorer를 쓴다. Excel은 행 한계(1,048,576)와 자동 형식 변환 때문에 타임스탬프를 망친다.

| 하려는 일 | Timeline Explorer에서 |
| --- | --- |
| 컬럼별 조건 필터 | 헤더 아래 필터 입력 행에 값을 입력한다 |
| 여러 조건 조합 | 필터 편집 창에서 컬럼 조건을 AND/OR로 조합한다 |
| 전체 문자열 검색 | 검색 상자에 키워드를 넣어 전체 컬럼을 훑는다 |
| 중요한 행 표시 | 행에 태그/체크를 달아 두고 태그된 행만 다시 본다 |
| 컬럼 고정 | 자주 보는 컬럼(시각·파일명)을 왼쪽에 고정한다 |
| 결과 내보내기 | 필터가 적용된 현재 화면을 CSV/Excel로 export |

메뉴 이름과 배치는 버전에 따라 다르다. 컬럼 필터 → 정렬 → export 라는 **순서**만 기억하면 된다.

### 7단계 — 대용량 CSV

`$MFT`가 큰 볼륨이면 CSV가 300MB~1GB까지 간다. `Import-Csv`는 전체를 객체로 올리므로 메모리에서 터진다.

**방법 A — SQLite로 밀어 넣는다 (가장 강력하다)**

```bash
sqlite3 mft.db <<'SQL'
.mode csv
.import --csv mft.csv mft
SQL

# 이제 SQL로 질의한다
sqlite3 -header -column mft.db "
  SELECT EntryNumber, ParentPath, FileName, FileSize, Created0x10
  FROM mft
  WHERE InUse='False' AND Extension IN ('.zip','.7z','.rar')
  ORDER BY Created0x10;
"

# 확장자별 집계
sqlite3 -header -column mft.db "
  SELECT Extension, COUNT(*) c FROM mft
  WHERE IsDirectory='False' GROUP BY Extension ORDER BY c DESC LIMIT 20;
"

# 시간 구간 — 문자열 비교로도 ISO 형식이면 정확하다
sqlite3 -header -column mft.db "
  SELECT Created0x10, ParentPath, FileName FROM mft
  WHERE Created0x10 >= '2026-03-14 07:00' AND Created0x10 < '2026-03-14 08:00'
  ORDER BY Created0x10;
"
```

`.import`로 넣으면 모든 컬럼이 TEXT다. 크기 비교가 필요하면 `CAST(FileSize AS INTEGER)`를 쓴다.

**방법 B — 스트리밍 필터로 CSV를 먼저 줄인다**

```bash
# 헤더 + 삭제 항목만 남긴 작은 CSV
{ head -1 mft.csv; rg -N ',False,' mft.csv; } > deleted.csv
wc -l deleted.csv
```

**방법 C — PowerShell 스트리밍**

```powershell
# 파이프 중간에서 바로 필터해 결과만 남긴다 (전체를 변수에 담지 않는다)
Import-Csv out\mft.csv |
  Where-Object { $_.InUse -eq 'False' } |
  Export-Csv out\deleted.csv -NoTypeInformation

# 그래도 느리면 파일을 텍스트로 흘려 읽는다
Get-Content out\mft.csv -ReadCount 5000 |
  ForEach-Object { $_ | Where-Object { $_ -match ',False,.*\.zip' } }
```

## 출력 필드 해석

### MFTECmd CSV

| 컬럼 | 의미 | 필터에서 쓰는 법 |
| --- | --- | --- |
| `EntryNumber` | MFT 레코드 번호 | `--de`, `icat`에 그대로 넣는다 |
| `SequenceNumber` | 슬롯 재사용 횟수 | 같은 `EntryNumber`라도 값이 다르면 다른 파일 |
| `InUse` | 사용 중 | `False` = **삭제** |
| `ParentEntryNumber` | 부모 레코드 번호 | 경로 복원 키 |
| `ParentSequenceNumber` | 부모 슬롯 재사용 횟수 | 불일치 = 경로 신뢰 불가 |
| `ParentPath` | 복원된 부모 경로 | 폴더 필터 |
| `FileName` | 파일 이름 | 검색 대상 |
| `Extension` | 확장자 (점 포함) | `.zip` 처럼 점까지 넣어 비교 |
| `FileSize` | 논리 크기 | 문자열이므로 `[long]` 캐스팅 후 비교 |
| `IsDirectory` | 디렉터리 여부 | 파일만 볼 때 `False` |
| `HasAds` / `IsAds` | ADS 보유 / 자기 자신이 ADS | 은닉 스트림 탐지 |
| `SI<FN` | `$SI` 시각이 `$FN`보다 빠름 | **timestomp 후보** ([FOR-0024](./si-vs-fn-timestamps.html)) |
| `uSecZeros` | 서브초가 0 | 위와 동일 신호 |
| `Copied` | 복사 흔적 판정 | 생성 > 수정 형태 |
| `NameType` | 이름 공간 | `Win32`, `Dos`, `Win32&Dos`, `Posix` |
| `Created0x10` / `Created0x30` | `$SI` / `$FN` 생성 시각 | 대조 → 조작 탐지 |
| `LastModified0x10` / `0x30` | 수정 시각 | 동일 |
| `LastRecordChange0x10` / `0x30` | MFT 엔트리 변경 시각 | 조작이 가장 어려운 값 |
| `LastAccess0x10` / `0x30` | 접근 시각 | Win7+ 갱신 비활성인 경우 많음 |
| `UpdateSequenceNumber` | `$SI`에 기록된 USN | `$UsnJrnl`과 조인 |
| `LogfileSequenceNumber` | 마지막 변경의 LSN | `$LogFile`과 조인 ([FOR-0025](./logfile-basics.html)) |
| `ZoneIdContents` | `Zone.Identifier` ADS 내용 | 다운로드 출처 URL |

### analyzeMFT CSV

| 컬럼 | MFTECmd 대응 | 비고 |
| --- | --- | --- |
| `Record Number` | `EntryNumber` | — |
| `Good` | — | 레코드 파싱 정상 여부 |
| `Active` | `InUse` | `Active`/`Inactive` 문자열 |
| `Record type` | `IsDirectory` 등 | `File`/`Folder` |
| `Sequence Number` | `SequenceNumber` | — |
| `Parent File Rec. #` | `ParentEntryNumber` | 경로는 직접 복원해야 한다 |
| `Filename #1` | `FileName` | 이름이 여러 개면 `#2`, `#3`로 이어진다 |
| `Std Info Creation date` | `Created0x10` | — |
| `Std Info Modification date` | `LastModified0x10` | — |
| `Std Info Access date` | `LastAccess0x10` | — |
| `Std Info Entry date` | `LastRecordChange0x10` | — |
| `FN Info *` | `*0x30` | `$FILE_NAME` 4개 |
| `STF FN Shift` | `SI<FN` 유사 | `-a`(anomaly) 옵션에서 채워진다 |
| `uSec Zero` | `uSecZeros` | 동일 개념 |
| `ADS` | `HasAds` | — |

**컬럼 이름에 공백과 점이 들어간다.** PowerShell에서는 반드시 백틱 인용을 쓴다.

```powershell
Import-Csv mft.csv | Where-Object { $_.Active -eq 'Inactive' } |
  Select-Object 'Record Number', 'Filename #1', 'Std Info Creation date'
```

두 파서 모두 타임스탬프를 **UTC**로 출력하는 것이 기본이다. FILETIME은 1601-01-01 UTC 기준 100ns 단위이며 Unix epoch와의 차이는 11644473600초다. 문제가 KST를 요구하면 **+9시간**한다. analyzeMFT는 로컬 시간대로 출력하는 옵션(`-l`)이 있어, 그 옵션이 켜졌는지 모른 채 +9를 또 하면 18시간이 틀린다.

## pivot: 다음에 볼 artifact

| CSV에서 얻은 값 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `EntryNumber` | `icat -o <off> image.dd <n>` | 파일 내용 직접 추출 |
| `EntryNumber` | `MFTECmd --de <n>` | 속성 단위 원본, resident 데이터 |
| `InUse=False` + 시각 | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | 삭제 시각과 원래 이름 |
| `LogfileSequenceNumber` | `$LogFile` ([FOR-0025](./logfile-basics.html)) | 그 변경의 redo/undo 상세 |
| `SI<FN=True` / `uSecZeros=True` | `$SI` vs `$FN` 대조 ([FOR-0024](./si-vs-fn-timestamps.html)) | timestomp 확정 |
| `Created0x10` 군집 | MACB 패턴 ([FOR-0023](./mft-macb.html)) | 복사·압축해제·설치 구분 |
| `HasAds=True` | `Get-Item -Stream *`, `ZoneIdContents` | 다운로드 출처 |
| `ZoneIdContents` URL | 브라우저 History ([FOR-0191](./chrome-history.html)) | 어느 사이트에서 받았나 |
| 실행 파일 이름 | Prefetch / Amcache / UserAssist ([FOR-0061](./userassist.html)) | 실제로 실행됐나 |
| 시각 | EVTX 4624/4688 ([FOR-0083](./event-4624-logon.html)) | 어느 세션이 만들었나 |

## 흔한 함정

- **컬럼명을 확인하지 않고 필터를 짜는 것.** `Where-Object { $_.Deleted -eq 'True' }`는 존재하지 않는 속성을 비교하므로 조용히 0건을 반환한다. 결과가 0이면 먼저 `Get-Content -TotalCount 1`로 헤더를 본다.
- **`InUse`를 boolean으로 비교하는 것.** CSV에서 온 값은 `'False'` **문자열**이다. `-eq $false`는 매치되지 않는다. 항상 문자열로 비교한다.
- **`FileSize`를 문자열로 정렬하는 것.** `Sort-Object FileSize`는 `"9"`를 `"1000000"`보다 크게 본다. `[long]`으로 캐스팅한다.
- **`Extension`을 점 없이 비교하는 것.** MFTECmd의 `Extension`은 `.zip` 형태다. `-eq 'zip'`은 안 맞는다.
- **Excel로 CSV를 여는 것.** 행 한계에서 잘리고, `Created0x10`을 로컬 시간대 서식으로 바꿔 버리며, 긴 숫자를 지수 표기로 망친다. Timeline Explorer 또는 SQLite를 쓴다.
- **`awk -F','`로 최종 결론을 내는 것.** 파일명에 콤마가 들어가면 컬럼이 밀린다. 집계 용도로만 쓰고 확인은 정식 CSV 파서로 한다.
- **`ParentPath`를 절대 경로로 믿는 것.** 파서는 `.\Users\...` 같은 상대 표기를 쓰고, 부모가 삭제·재사용된 항목은 비어 있거나 부정확하다. `ParentSequenceNumber` 일치를 함께 본다.
- **`EntryNumber`만으로 두 CSV를 조인하는 것.** `$J`나 다른 시점의 `$MFT`와 조인할 때는 `EntryNumber` + `SequenceNumber` **둘 다** 키로 써야 한다. 레코드 슬롯은 재사용된다.
- **`-l`(로컬 시간) 옵션 유무를 확인하지 않고 +9시간 하는 것.** 출력이 이미 KST면 두 번 더해 18시간이 틀어진다. 알려진 이벤트(예: EVTX 로그온 시각) 하나로 기준을 맞춘다.
- **`IsAds=True` 행을 파일로 세는 것.** ADS는 부모 파일과 같은 `EntryNumber`를 공유한다. 파일 개수 집계에서 중복이 된다.
- **디렉터리를 제외하지 않고 개수를 세는 것.** `IsDirectory=True`가 상당수라 확장자 집계가 왜곡된다.

## 교차검증

```powershell
# 1) 두 파서의 레코드 수가 맞는가
(Import-Csv out\mft.csv).Count
(Import-Csv analyzemft.csv).Count

# 2) 파일 크기 검산 — $MFT 크기 / 레코드 크기 = 레코드 수
(Get-Item 'C:\case\$MFT').Length / 1024

# 3) 특정 레코드를 속성 단위로 재확인
MFTECmd.exe -f 'C:\case\$MFT' --de 84213
```

```bash
# 4) Sleuth Kit 으로 같은 목록을 다시 뽑아 대조 (삭제 파일 포함)
fls -o 2048 -r -p image.dd | rg -i 'secret'

# 5) 레코드 상세를 istat 으로 재확인 — 속성별 크기와 data run 이 보인다
istat -o 2048 image.dd 84213
```

CSV에서 본 `FileSize`와 `istat`의 `init_size`/`actual_size`가 다르면 파서가 아니라 **속성 해석 차이**다. `istat` 쪽을 신뢰한다.

## mini walkthrough

```text
문제:
"유출 의심 압축파일을 특정하세요. 첨부: $MFT (1.2GB), image 없음"

1. 파싱
   MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv
   -> 1,241,880 레코드, CSV 612MB

2. 첫 시도 (실패):
   Import-Csv out\mft.csv | Where-Object { $_.Extension -eq '.zip' }

   -> 5분 넘게 응답 없음. 메모리 사용량이 6GB를 넘어가고 세션이 죽었다.

   왜 틀렸나: Import-Csv 는 612MB CSV의 모든 행을 PSObject 로 만들어
   메모리에 올린다. 1백만 행 × 30컬럼이면 감당이 안 된다.
   "필터를 나중에" 하는 파이프라인이 문제다.

3. 접근 변경 — 파일을 먼저 줄인다
   { head -1 mft.csv; rg -N ',False,' mft.csv; } > deleted.csv
   -> 18,442행, 9MB. 여기부터는 Import-Csv 로 충분하다.

4. 두 번째 시도도 빗나감:
   Import-Csv deleted.csv | Where-Object { $_.Extension -eq 'zip' }
   -> 0건.

   왜 틀렸나: MFTECmd 의 Extension 은 점을 포함한 '.zip' 이다.

5. 정정 후:
   Import-Csv deleted.csv |
     Where-Object { $_.Extension -in '.zip','.7z','.rar' -and
                    $_.IsDirectory -eq 'False' } |
     Sort-Object { [long]$_.FileSize } -Descending |
     Select-Object -First 5 EntryNumber, ParentPath, FileName, FileSize, Created0x10

   EntryNumber ParentPath                  FileName          FileSize   Created0x10
   ----------- ----------                  --------          --------   -----------
   128441      .\Users\jhkim\Documents     report_final.7z   284113920  2026-03-14 07:31:04
   96110       .\Windows\Temp              vc_redist.7z      1204224    2026-01-08 11:02:19
   ...

   271MB 짜리 삭제된 7z 가 사용자 Documents 에 있었다. 이것이 후보.

6. 경로 검증 — ParentPath 를 그대로 믿지 않는다
   Import-Csv deleted.csv | Where-Object { $_.EntryNumber -eq '128441' } |
     Select-Object ParentEntryNumber, ParentSequenceNumber

   ParentEntryNumber ParentSequenceNumber
   ----------------- --------------------
   9114              3

   Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq '9114' } |
     Select-Object FileName, SequenceNumber
   -> Documents, 3      (일치 -> 경로 신뢰 가능)

7. 조작 여부 확인
   Import-Csv deleted.csv | Where-Object { $_.EntryNumber -eq '128441' } |
     Select-Object 'SI<FN', uSecZeros, Created0x10, Created0x30, LastModified0x10
   -> SI<FN=False, uSecZeros=False  (조작 흔적 없음)

8. 집계로 사건 시각 좁히기
   Import-Csv deleted.csv |
     Where-Object { $_.Created0x10 -like '2026-03-14*' } |
     Group-Object { ([datetime]$_.Created0x10).ToString('HH') } |
     Select-Object Name, Count | Sort-Object Name

   Name Count
   ---- -----
   07     214      <- 이 시간대에 삭제 대상이 몰려 있다
   09       6

정답: .\Users\jhkim\Documents\report_final.7z (EntryNumber 128441),
      생성 2026-03-14 07:31:04 UTC = 16:31:04 KST
```

3단계가 이 문제의 분기점이다. **"CSV 전체를 파서에 넣고 필터"가 아니라 "텍스트로 먼저 줄이고 파서에 넣기"** 로 순서를 뒤집자 5분 걸리던 질의가 2초가 됐다. 4단계의 점 하나(`zip` vs `.zip`)도 0건 오판의 전형이다.

## 막혔을 때 다음 체크

1. `Get-Content -TotalCount 1`로 컬럼명을 확인했는가 — 0건의 절반은 컬럼명 오타다
2. `InUse`/`Active`를 **문자열**로 비교했는가
3. `Extension`에 점을 붙였는가
4. `FileSize`를 `[long]`으로 캐스팅했는가
5. CSV가 100MB를 넘는데 `Import-Csv`로 시작했는가 → `rg`로 먼저 줄이거나 SQLite로 옮긴다
6. 경로가 안 나오면 → `ParentEntryNumber` 재귀 복원, `ParentSequenceNumber` 일치 확인
7. `<ORPHAN>`이면 → `$UsnJrnl`의 `ParentEntryNumber`로 보완
8. 타임스탬프가 예상과 9시간 어긋나면 → 파서의 시간대 옵션과 KST 변환을 이중으로 했는지 확인
9. 파일 개수가 이상하면 → `IsDirectory=True`와 `IsAds=True`를 제외했는가
10. 찾는 파일이 아예 없으면 → 레코드 슬롯이 재사용된 것이다. `$UsnJrnl`/`$LogFile`로 넘어간다

## 출처

- SRC-005 — Microsoft Learn, Master File Table: MFT 레코드와 속성의 의미(각 CSV 컬럼이 무엇을 옮긴 것인지)
- SRC-004 — Eric Zimmerman 문서: MFTECmd의 `-f`/`-m`/`--csv`/`--csvf`/`--json`/`--body`/`--de` 옵션과 CSV 컬럼 정의, Timeline Explorer 사용법
- SRC-014 — Microsoft Learn, File Times: FILETIME이 1601-01-01 UTC 기준 100ns이며 Unix와 11644473600초 차이라는 근거
- MFTECmd와 analyzeMFT의 **컬럼 이름·개수·옵션 문자는 버전에 따라 다르다.** 필터를 짜기 전에 `--help`와 CSV 헤더 첫 줄을 실제로 확인할 것
- Timeline Explorer의 메뉴·버튼 이름도 버전에 따라 다르므로 실제 화면에서 확인할 것
