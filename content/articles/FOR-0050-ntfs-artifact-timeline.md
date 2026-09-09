---
id: FOR-0050
title: "NTFS artifact 종합 타임라인 만들기: $MFT·$J·EVTX·Prefetch를 한 축에"
slug: "ntfs-artifact-timeline"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$MFT", "$UsnJrnl", "$LogFile", "$Recycle.Bin", "LNK", "Prefetch", "EVTX", "MACB", "bodyfile"]
file_paths: ["C:\\$MFT", "C:\\$Extend\\$UsnJrnl", "C:\\$LogFile", "C:\\$Recycle.Bin", "C:\\Windows\\Prefetch", "C:\\Windows\\System32\\winevt\\Logs", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent"]
registry_paths: []
event_ids: ["1102", "104", "4616"]
protocols: []
tools: ["MFTECmd", "EvtxECmd", "PECmd", "RBCmd", "LECmd", "Timeline Explorer", "NTFS Log Tracker", "Sleuth Kit", "mactime"]
commands: ["MFTECmd.exe -f \"C:\\case\\$MFT\" --csv \"C:\\case\\out\" --csvf mft.csv", "EvtxECmd.exe -d \"C:\\case\\winevt\" --csv \"C:\\case\\out\" --csvf evtx.csv", "PECmd.exe -d \"C:\\case\\Prefetch\" --csv \"C:\\case\\out\"", "fls -o 2048 -m C:/ -r image.raw > body.txt", "mactime -b body.txt -d -z UTC > timeline.csv"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["UpdateTimestamp", "Usn", "EventRecordId", "TimeCreated", "LogfileSequenceNumber", "Created0x10", "Created0x30", "LastRun", "DeletedOn"]
file_formats: ["ntfs", "evtx", "csv"]
primary_terms: ["NTFS 타임라인", "mactime", "슈퍼 타임라인", "타임라인 만들기"]
keywords: ["타임라인", "timeline", "MACB", "$MFT", "$UsnJrnl", "Prefetch", "EVTX", "Timeline Explorer", "mactime", "bodyfile", "UTC", "KST", "슈퍼 타임라인"]
aliases: ["타임라인 만들기", "슈퍼 타임라인", "시간순 정리", "mactime", "timeline explorer", "사건 순서", "artifact 합치기", "csv 합치기"]
symptom_keywords: ["사건 순서를 모르겠다", "타임라인을 만들고 싶다", "같은 시각 이벤트 순서를 정하고 싶다", "시간이 안 맞는다", "로그가 지워진 것 같다", "여러 CSV를 합치고 싶다"]
related: ["FOR-0021", "FOR-0027", "FOR-0049"]
source_ids: ["SRC-005", "SRC-013", "SRC-004", "SRC-032"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

종합 타임라인은 **artifact마다 CSV를 만들고 → 전부 UTC로 통일해 하나의 CSV로 합치고 → Timeline Explorer에서 사건 시각 ±10분만 보는** 3단계이며, 같은 초에 몰린 이벤트의 순서는 시각이 아니라 `$J`의 `Usn`과 EVTX의 `EventRecordId` 같은 **단조 증가 순번**으로 판정한다.

## 어떤 문제에서 필요한가

- "무슨 일이 일어났는지 시간순으로 서술하세요" 유형 — 답이 값 하나가 아니라 사건 흐름인 문제
- artifact 하나로는 설명이 안 되는 문제 (파일은 있는데 누가 만들었는지, 실행은 됐는데 어디서 왔는지)
- 삭제·은폐 흔적을 찾아야 하는 문제 — 타임라인의 **공백**이 답인 경우
- 시각 조작(timestomp)이 의심되는 문제
- 여러 사용자·여러 세션이 섞여 있어 행위 주체를 가려야 하는 문제

## 문제에서 처음 볼 단서

1. 첨부에 무엇이 있는가 — `$MFT`만 있으면 MACB 타임라인, `$J`가 있으면 사건 순서, EVTX가 있으면 계정까지 확정된다
2. 지문에 시각이 하나라도 주어졌는가 — 있으면 그 시각 ±10분으로 범위를 먼저 좁힌다
3. 지문의 시각이 KST인가 UTC인가 — **여기서 틀리면 전부 틀린다**
4. 사용자 계정이 여럿인가 → `$Recycle.Bin`의 SID 폴더와 EVTX의 `UserName`으로 분리
5. Prefetch 폴더가 비어 있는가 → 은폐 의심. 그 자체가 단서

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
```

재료가 다 있으면 네 줄로 CSV를 전부 만든다.

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv "C:\case\out" --csvf usn.csv
EvtxECmd.exe -d "C:\case\winevt" --csv "C:\case\out" --csvf evtx.csv
PECmd.exe -d "C:\case\Prefetch" --csv "C:\case\out"
```

그다음 Timeline Explorer로 `C:\case\out`의 CSV를 열고, 각 탭에서 사건 시각으로 필터를 건다. 하나의 축으로 합치는 것은 아래 3단계다.

## 상세 절차

### 1단계 — 재료와 각 재료가 답하는 질문

| artifact | 답하는 질문 | 시각의 개수 | 보존 특성 |
| --- | --- | --- | --- |
| `$MFT` | 무엇이 존재했나 / 언제 만들어졌나 | **파일당 8개** (`$SI` 4 + `$FN` 4) | 삭제돼도 레코드가 남는다. 재사용되면 소실 |
| `$UsnJrnl:$J` | **무슨 일이 있었나** (생성·삭제·이름변경) | 변경마다 1개 | 순환. 며칠~몇 주 |
| `$LogFile` | 그 변경의 트랜잭션 상세 | 트랜잭션마다 | 가장 짧다. 보통 수 시간~며칠 |
| `$Recycle.Bin` (`$I`) | 누가 언제 무엇을 지웠나 | 삭제 시각 1개 | 휴지통을 비우면 사라진다 |
| LNK | 사용자가 무엇을 열었나 | 6개 (LNK 자신 3 + 대상 3) | 오래 남는다 |
| Prefetch (`.pf`) | 무엇이 **실행**되었나 | 최근 실행 시각 여러 개 + 실행 횟수 | 개수 제한으로 오래된 것이 밀려난다 |
| EVTX | **누가** 로그온했나 / 무엇이 실행됐나 | 이벤트마다 1개 | 로그 크기 제한으로 순환. 삭제 가능 |

MACB 8개의 의미:

| 약어 | `$SI`(0x10) | `$FN`(0x30) | 무엇이 갱신하나 |
| --- | --- | --- | --- |
| M (Modified) | `LastModified0x10` | `LastModified0x30` | 내용 변경 |
| A (Accessed) | `LastAccess0x10` | `LastAccess0x30` | 접근. Win7 이후 기본 갱신 비활성인 경우가 많다 |
| C (Changed) | `LastRecordChange0x10` | `LastRecordChange0x30` | **MFT 엔트리 변경.** 조작하기 가장 어렵다 |
| B (Born) | `Created0x10` | `Created0x30` | 생성 |

`$SI`는 API로 바꿀 수 있고 `$FN`은 그렇지 않다. **`0x10`과 `0x30`의 불일치가 timestomp의 근거**이며, 타임라인에서는 두 세트를 모두 축에 올려 놓고 어긋난 항목을 찾는다.

### 2단계 — 각각을 CSV로 만든다

```powershell
# $MFT
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv

# $J (경로 복원을 위해 $MFT를 함께 준다)
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv "C:\case\out" --csvf usn.csv

# EVTX 폴더 전체
EvtxECmd.exe -d "C:\case\winevt" --csv "C:\case\out" --csvf evtx.csv

# 특정 이벤트만 (용량이 클 때)
EvtxECmd.exe -f "C:\case\winevt\Security.evtx" --csv "C:\case\out" --csvf sec.csv --inc 4624,4625,4634,4688,1102

# Prefetch (메인 CSV와 함께 실행 시각을 펼친 Timeline CSV가 나온다)
PECmd.exe -d "C:\case\Prefetch" --csv "C:\case\out"

# 휴지통
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv "C:\case\out"

# LNK (최근 항목 폴더)
LECmd.exe -d "C:\case\Recent" --csv "C:\case\out"
```

| 도구 | 입력 | 타임라인에 쓰는 컬럼 |
| --- | --- | --- |
| MFTECmd (`$MFT`) | `$MFT` | `Created0x10` `LastModified0x10` `LastRecordChange0x10` `LastAccess0x10` + `0x30` 4개, `EntryNumber`, `FileSize`, `InUse` |
| MFTECmd (`$J`) | `$J` (+ `-m $MFT`) | `UpdateTimestamp`, `Usn`, `UpdateReasons`, `FileName`, `ParentPath` |
| EvtxECmd | `.evtx` | `TimeCreated`, `EventId`, `EventRecordId`, `Computer`, `UserName`, `MapDescription`, `PayloadData1~` |
| PECmd | `.pf` | 실행 시각들, `ExecutableName`, `RunCount`, 참조 파일 목록 |
| RBCmd | `$I` | `DeletedOn`, `FileName`(원래 전체 경로), `FileSize` |
| LECmd | `.lnk` | `SourceCreated/Modified/Accessed`, `TargetCreated/Modified/Accessed`, `LocalPath`, `VolumeSerialNumber` |
| NTFS Log Tracker | `$LogFile` + `$J` + `$MFT` | 트랜잭션 단위로 묶인 사건 CSV |

`$LogFile`은 표준 CSV 파서가 마땅치 않다. NTFS Log Tracker로 `$LogFile`·`$J`·`$MFT`를 함께 읽어 CSV로 내보내고, 그 결과를 같은 축에 얹는다.

### 3단계 — 하나의 축으로 합친다

Timeline Explorer는 CSV를 **탭별로** 열어 준다. 진짜 통합 타임라인이 필요하면 공통 스키마로 정규화한 CSV 하나를 만든다.

공통 스키마 6열로 고정한다.

```text
TimeUTC | Source | Actor | Action | Object | Detail
```

```powershell
$out = @()

# $J
$out += Import-Csv out\usn.csv | ForEach-Object {
  [pscustomobject]@{
    TimeUTC = $_.UpdateTimestamp
    Source  = '$J'
    Actor   = ''
    Action  = $_.UpdateReasons
    Object  = "$($_.ParentPath)\$($_.FileName)"
    Detail  = "Usn=$($_.Usn) Entry=$($_.EntryNumber)"
  }
}

# $MFT — 생성 시각($SI)만 축에 올린다 (4개를 다 올리면 4배로 늘어난다)
$out += Import-Csv out\mft.csv | Where-Object { $_.Created0x10 } | ForEach-Object {
  [pscustomobject]@{
    TimeUTC = $_.Created0x10
    Source  = '$MFT/B'
    Actor   = ''
    Action  = 'Created'
    Object  = "$($_.ParentPath)\$($_.FileName)"
    Detail  = "Entry=$($_.EntryNumber) InUse=$($_.InUse) Size=$($_.FileSize)"
  }
}

# EVTX
$out += Import-Csv out\evtx.csv | ForEach-Object {
  [pscustomobject]@{
    TimeUTC = $_.TimeCreated
    Source  = "EVTX/$($_.Channel)"
    Actor   = $_.UserName
    Action  = $_.EventId
    Object  = $_.MapDescription
    Detail  = "RecId=$($_.EventRecordId) $($_.PayloadData1)"
  }
}

# 휴지통
$out += Import-Csv out\*_RBCmd_Output.csv | ForEach-Object {
  [pscustomobject]@{
    TimeUTC = $_.DeletedOn
    Source  = '$Recycle.Bin'
    Actor   = ''
    Action  = 'Deleted'
    Object  = $_.FileName
    Detail  = "Size=$($_.FileSize)"
  }
}

$out | Sort-Object TimeUTC | Export-Csv -NoTypeInformation -Encoding UTF8 timeline_all.csv
```

- 컬럼명은 도구 버전에 따라 다르다. **먼저 `Import-Csv out\mft.csv | Get-Member`로 실제 컬럼명을 확인**하고 스크립트를 맞춘다
- `$MFT`의 타임스탬프 8개를 전부 올리면 행이 8배가 되어 읽을 수 없다. 1차에는 `Created0x10`과 `LastModified0x10`만, timestomp 검증이 필요할 때 `0x30`을 추가한다
- 완성된 `timeline_all.csv`를 Timeline Explorer로 열면 컬럼 필터·정렬·태깅·북마크를 그대로 쓸 수 있다

Timeline Explorer에서 실전에 쓰는 조작:

| 하고 싶은 것 | 방법 |
| --- | --- |
| 시간 범위 좁히기 | `TimeUTC` 컬럼 필터에 사건 시각 문자열(`2026-03-14 07:3`)을 넣는다 |
| 특정 파일의 생애 | `Object` 컬럼에 파일명 필터 |
| 출처별로 보기 | `Source` 컬럼 필터로 `$J`만, EVTX만 |
| 중요 행 표시 | 행 태깅/북마크 후 태그된 행만 보기 |
| 결과 저장 | 필터 적용 상태를 Excel/CSV로 내보내기 |

### 4단계 — 시각 기준 통일 (여기서 사고가 가장 많이 난다)

**원칙: 모든 값을 UTC로 모으고, 답을 낼 때만 KST로 바꾼다.**

| 값 | 기준 | 비고 |
| --- | --- | --- |
| `$MFT` MACB | FILETIME = 1601-01-01 UTC 기준 100ns | 파서가 UTC로 출력 |
| `$J` `UpdateTimestamp` | FILETIME (UTC) | 동일 |
| `$I` `DeletedOn` | FILETIME (UTC) | 동일 |
| EVTX `TimeCreated` | UTC | EVTX 자체가 UTC로 저장 |
| Prefetch 실행 시각 | FILETIME (UTC) | 동일 |
| LNK 대상 시각 | FILETIME (UTC) | 동일 |
| EXIF `DateTimeOriginal` | **기기 로컬 시각. 시간대 정보 없음** | 타임라인에 넣을 때 반드시 표시 |
| 파일시스템 mtime (추출물) | 추출 시각 | **타임라인에 넣지 않는다** |

```text
Unix epoch 와의 차이 = 11,644,473,600 초
KST = UTC + 9시간
```

```powershell
[datetime]::FromFileTimeUtc(133545600000000000).ToString('yyyy-MM-dd HH:mm:ss')      # UTC
[datetime]::FromFileTimeUtc(133545600000000000).AddHours(9).ToString('yyyy-MM-dd HH:mm:ss')   # KST

# 완성된 타임라인을 KST 컬럼과 함께 내보낸다
Import-Csv timeline_all.csv |
  Select-Object *, @{n='TimeKST';e={ ([datetime]$_.TimeUTC).AddHours(9) }} |
  Export-Csv -NoTypeInformation -Encoding UTF8 timeline_kst.csv
```

- **분석 대상 시스템의 시간대**는 별개 문제다. Windows의 시간대 설정은 `SYSTEM` hive에 있고, EVTX·`$MFT`는 그것과 무관하게 UTC로 저장된다. 로그 파일(텍스트 로그, 애플리케이션 로그)은 로컬 시각으로 쓰이는 경우가 많으므로 **텍스트 로그를 섞을 때만** 시간대 보정이 필요하다
- 도구 출력의 시각 표기 형식은 옵션으로 바꿀 수 있는 경우가 있다. 여러 CSV를 합칠 때는 **형식이 같아야 문자열 정렬이 정상 작동한다**. 형식이 섞였으면 `[datetime]`으로 캐스팅해 정렬한다

### 5단계 — 같은 초에 몰린 이벤트의 순서 판정

파일 복사·압축·삭제 같은 행위는 **1초 안에 수십 개의 레코드**를 만든다. 초 단위 시각으로는 순서를 알 수 없다. 각 artifact가 제공하는 단조 증가 순번을 쓴다.

| artifact | 순서 판정 필드 | 성질 |
| --- | --- | --- |
| `$UsnJrnl:$J` | **`Usn`** | 저널 내 오프셋 겸 순번. 작을수록 과거. 볼륨 전체에서 유일 |
| EVTX | **`EventRecordId`** | 채널(로그 파일)별 단조 증가. **다른 채널끼리는 비교 불가** |
| `$MFT` | `LogfileSequenceNumber` (LSN) | 그 레코드가 마지막으로 기록된 트랜잭션 번호. 클수록 나중 |
| `$LogFile` | LSN | 트랜잭션 순서의 원본 |
| Prefetch | 없음 | 시각만. 초 단위로 동률이면 순서 불가 |

```powershell
# $J 는 반드시 Usn 으로 정렬한다 (타임스탬프 정렬은 같은 초에서 뒤섞인다)
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateTimestamp -like '2026-03-14 07:39*' } |
  Sort-Object { [int64]("0x" + ($_.Usn -replace '^0x','')) } |
  Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName

# EVTX 는 같은 채널 안에서 EventRecordId 로 정렬한다
Import-Csv out\evtx.csv |
  Where-Object { $_.Channel -eq 'Security' -and $_.TimeCreated -like '*07:39:5*' } |
  Sort-Object { [int64]$_.EventRecordId } |
  Format-Table EventRecordId, TimeCreated, EventId, UserName, MapDescription
```

**서로 다른 artifact 사이의 순서**는 순번으로 비교할 수 없다. 이때는 인과 관계로 정한다.

| 관계 | 필연적 순서 |
| --- | --- |
| 프로세스 생성(EVTX 4688) ↔ 그 프로세스가 만든 파일(`$J FileCreate`) | 4688이 먼저 |
| `$J FileCreate` ↔ `$MFT Created0x10` | 사실상 동시. 어긋나면 timestomp |
| 실행(Prefetch 실행 시각) ↔ 그 실행이 남긴 파일 | 실행이 먼저 |
| `$J RenameOldName` ↔ `RenameNewName` | 항상 Old가 먼저 (같은 `Usn` 블록) |
| 로그온(4624) ↔ 그 세션의 모든 행위 | 로그온이 먼저. `Logon ID`로 묶는다 ([FOR-0083](./event-4624-logon.html)) |
| 삭제(`$J FileDelete`) ↔ 클러스터 재할당 | 삭제가 먼저 |

### 6단계 — 사건 서술로 바꾸기

타임라인 CSV는 답이 아니다. **누가 / 언제 / 무엇을 / 어떻게**로 정리된 문장이 답이다.

| 질문 | 어느 artifact에서 | 채우는 방법 |
| --- | --- | --- |
| **누가** | EVTX 4624의 `TargetUserName` + `Logon ID`, `$Recycle.Bin`의 SID 폴더, LNK가 있던 사용자 프로필 경로 | 세션 시간 범위와 행위 시각을 겹쳐 계정을 배정 |
| **언제** | 축으로 쓴 `TimeUTC` | UTC로 확정한 뒤 마지막에 KST 병기 |
| **무엇을** | `$J`의 `FileName`+`ParentPath`, `$MFT`의 경로, `$I`의 원래 전체 경로 | 파일 단위로 생애를 묶는다 |
| **어떻게** | Prefetch/4688의 실행 파일, `$J`의 `UpdateReasons` 패턴 | 도구를 특정한다 (압축 → 이름변경 → 삭제 등) |

서술 템플릿:

```text
2026-03-14 16:31:04 KST (07:31:04Z)
  jhkim (Logon ID 0x3E7A1, 4624 Type 10 = RDP)
  7z.exe 실행 (Prefetch RunCount 3)
  customer_db_2026.7z 생성 ($J FileCreate, Usn 0x4a11200)

2026-03-14 16:38:41 KST (07:38:41Z)
  같은 파일을 report_final.7z 로 이름 변경
  ($J RenameOldName -> RenameNewName, Usn 0x4a1a840/0x4a1a9c0)

2026-03-14 16:39:52 KST (07:39:52Z)
  삭제 ($J FileDelete|Close, Usn 0x4a1b8c0)
  휴지통 기록 없음 -> Shift+Delete
```

각 문장에 **근거 artifact와 순번을 함께 적는다.** 이것이 있으면 채점자가 검증할 수 있고, 자기 검산도 된다.

### 7단계 — Sleuth Kit 계열 대안 (bodyfile → mactime)

EZ 도구를 쓸 수 없는 환경(Linux만 있는 경우)이나 이미지에서 바로 타임라인을 만들 때 쓴다.

```bash
# 1) 이미지에서 bodyfile 생성 (-m 뒤에 붙일 경로 접두사)
fls -o 2048 -m C:/ -r image.raw > body.txt

# 2) 시간순으로 정렬된 타임라인으로 변환
mactime -b body.txt -d -z UTC > timeline.csv

# 3) 특정 날짜만
mactime -b body.txt -d -z UTC 03/14/2026 > timeline_0314.csv
```

bodyfile 한 줄의 형식(TSK 3.x):

```text
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
```

| `mactime` 옵션 | 의미 |
| --- | --- |
| `-b <파일>` | bodyfile 지정 |
| `-d` | 쉼표 구분 출력 (CSV) |
| `-z <TZ>` | **출력 시간대.** `UTC`로 고정한다 |
| `-y` | 날짜를 ISO 8601 형식으로 출력 |
| `-i day <파일>` | 일별 이벤트 개수 요약 — **공백 구간 찾기에 유용** |

`mactime` 출력의 활동 컬럼은 `m`/`a`/`c`/`b`가 조합되어 표시되므로, 어느 타임스탬프가 그 행을 만들었는지 바로 읽을 수 있다.

```bash
# 일별 활동량 요약 -> 급증/공백 구간을 눈으로 찾는다
mactime -b body.txt -d -z UTC -i day daily.txt > /dev/null && head -30 daily.txt
```

MFTECmd도 TSK 호환 bodyfile을 출력하는 옵션(`--body` 계열)을 제공하므로, `$MFT`만 있을 때 EZ 도구로 bodyfile을 만들어 `mactime`에 넣는 조합도 가능하다. 옵션 이름은 버전에 따라 다르므로 `MFTECmd.exe`를 인자 없이 실행해 확인한다.

**주의:** `fls -m`이 만드는 bodyfile은 `$SI` 타임스탬프 기반이다. `$FN` 4개는 들어가지 않으므로 **`mactime` 타임라인만으로는 timestomp를 탐지할 수 없다.** 그 검증은 MFTECmd CSV의 `0x10` vs `0x30` 비교로 따로 한다.

### 8단계 — 공백 구간 읽기 (로그 삭제·시각 조작)

타임라인에서 **아무 일도 없는 구간**은 종종 가장 중요한 증거다.

| 관찰 | 의미 | 확인 방법 |
| --- | --- | --- |
| EVTX에 특정 시각 이후 이벤트가 갑자기 없다 | 로그 삭제 또는 서비스 중단 | Security 로그의 **1102**(감사 로그 지움), 시스템 로그의 **104**(로그 파일 지움) |
| `$J`의 가장 오래된 레코드가 사건보다 나중 | 저널이 순환됐다(정상) 또는 잘렸다 | `$J` 첫 레코드의 `Usn`/시각을 확인. "없다"와 "지워졌다"를 구분 |
| `$MFT`에는 파일이 있는데 `$J`에 생성 기록이 없다 | 저널 보존 기간을 넘었다 | 파일 생성 시각과 `$J` 시작 시각 비교 |
| `EventRecordId`가 건너뛴다 | 같은 채널에서 레코드가 사라졌다 | 연속성 검사 (아래 명령) |
| 시각이 미래이거나 1601/1970년 | timestomp 또는 파서 오류 | `0x10` vs `0x30` 비교 |
| `Created0x10` > `LastModified0x10` | 생성이 수정보다 나중 = 논리적 모순 | timestomp 강한 신호 |
| `0x10`과 `0x30`이 어긋난다 | `$SI`만 조작됐다 | MFTECmd의 `SI<FN` 계열 컬럼 |
| 서브초가 전부 0 (`.0000000`) | 도구가 초 단위로만 써 넣었다 | MFTECmd의 `uSecZeros` 계열 컬럼 |
| 시스템 시각 변경 이벤트 **4616** | 시각 자체가 조작됐다 | 그 시각 전후의 모든 타임스탬프를 의심 |
| Prefetch 폴더가 비었는데 프로그램은 실행됐다 | 은폐 | `$J`에서 `.pf` 파일의 `FileDelete` 검색 |

```powershell
# EVTX 레코드 번호 연속성 검사 (같은 채널 안에서)
$ids = Import-Csv out\evtx.csv | Where-Object { $_.Channel -eq 'Security' } |
        ForEach-Object { [int64]$_.EventRecordId } | Sort-Object
Compare-Object $ids ($ids[0]..$ids[-1])

# 로그 삭제 이벤트 자체를 찾는다
Import-Csv out\evtx.csv | Where-Object { $_.EventId -in 1102,104 } |
  Select-Object TimeCreated, Channel, EventId, UserName

# timestomp 후보: $SI 와 $FN 생성 시각이 다른 항목
Import-Csv out\mft.csv |
  Where-Object { $_.Created0x30 -and $_.Created0x10 -ne $_.Created0x30 } |
  Select-Object EntryNumber, FileName, Created0x10, Created0x30 | Format-Table

# 삭제된 .pf (Prefetch 은폐 흔적)
Import-Csv out\usn.csv |
  Where-Object { $_.FileName -like '*.pf' -and $_.UpdateReasons -match 'FileDelete' }
```

Event ID 1102/104/4616의 정식 정의와 EventData 필드는 Microsoft의 감사 정책 문서에서 확인한다. 여기서는 **"타임라인의 공백을 설명하는 이벤트"** 로만 쓴다.

## 출력 필드 해석

정규화 스키마와 원본 컬럼의 대응이다. 이 표가 있으면 어떤 CSV가 와도 축에 올릴 수 있다.

| 스키마 | `$MFT` | `$J` | EVTX | Prefetch | `$I` | LNK |
| --- | --- | --- | --- | --- | --- | --- |
| `TimeUTC` | `Created0x10` 등 8개 | `UpdateTimestamp` | `TimeCreated` | 실행 시각 | `DeletedOn` | `Target*`/`Source*` |
| `Source` | `$MFT/B` `$MFT/M` … | `$J` | `EVTX/<채널>` | `Prefetch` | `$Recycle.Bin` | `LNK` |
| `Actor` | (없음) | (없음) | `UserName` | (없음) | SID 폴더 | 프로필 경로 |
| `Action` | `Created`/`Modified` | `UpdateReasons` | `EventId` | `Executed` | `Deleted` | `Opened` |
| `Object` | `ParentPath\FileName` | `ParentPath\FileName` | `MapDescription` | `ExecutableName` | 원래 전체 경로 | `LocalPath` |
| `Detail` | `Entry`/`InUse`/`FileSize` | `Usn`/`EntryNumber` | `EventRecordId`/payload | `RunCount` | `FileSize` | `VolumeSerialNumber` |

CSV 컬럼명은 도구 버전에 따라 달라진다. 스크립트를 쓰기 전에 실제 헤더를 확인한다.

```powershell
Import-Csv out\mft.csv  | Select-Object -First 1 | Get-Member -MemberType NoteProperty
Import-Csv out\evtx.csv | Select-Object -First 1 | Get-Member -MemberType NoteProperty
```

## pivot: 다음에 볼 artifact

| 타임라인에서 본 것 | 다음 목표 |
| --- | --- |
| 특정 시각의 파일 생성 폭발 | 그 시각의 4688/Prefetch — 어떤 프로세스가 만들었나 |
| 로그온 직후의 행위 묶음 | 4624의 `Logon ID`로 세션 전체 묶기 ([FOR-0083](./event-4624-logon.html)) |
| 실행 흔적 | UserAssist / RecentDocs ([FOR-0061](./userassist.html)) — 사용자가 직접 실행했나 |
| 삭제 사건 | 복구 시도 ([FOR-0049](./deleted-file-recovery-walkthrough.html)) |
| 원래 이름이 필요하다 | `$J`의 `RenameOldName` ([FOR-0027](./usnjrnl-basics.html)) |
| 다운로드 흔적 | 브라우저 History/Downloads ([FOR-0191](./chrome-history.html)) |
| timestomp 후보 | `$MFT`의 `0x10` vs `0x30`, `$LogFile` 트랜잭션 ([FOR-0021](./mft-basics.html)) |
| 외부 전송 의심 | 같은 시각의 pcap ([FOR-0146](./wireshark-30sec-triage.html)) |
| 로그 공백 | 1102/104 발생 시각과 계정 |

## 흔한 함정

- **시간대를 섞는 것.** 어떤 CSV는 UTC, 지문은 KST, 텍스트 로그는 로컬인 상태로 정렬하면 순서가 뒤집힌다. **전부 UTC로 모은 뒤 마지막에 KST로 바꾼다.** 이 글에서 가장 중요한 규칙이다.
- **같은 초 이벤트를 타임스탬프로 정렬하는 것.** 1초에 수십 개가 몰린다. `$J`는 `Usn`, EVTX는 `EventRecordId`로 정렬한다.
- **`EventRecordId`를 채널 간에 비교하는 것.** 로그 파일별로 독립적으로 증가한다. Security의 1000번과 System의 1000번은 아무 관계가 없다.
- **`$MFT` 타임스탬프 8개를 전부 축에 올리는 것.** 행이 8배가 되어 읽을 수 없다. 1차는 `Created0x10`/`LastModified0x10`만 올린다.
- **`$SI`만 보고 타임라인을 확정하는 것.** timestomp된 값이다. `0x30`과 비교하지 않으면 조작된 시간표를 그대로 믿는다.
- **`mactime` 타임라인으로 timestomp를 판정하려는 것.** `fls -m` bodyfile은 `$SI` 기반이다. `$FN` 비교는 MFTECmd CSV로 따로 한다.
- **추출물의 파일시스템 mtime을 타임라인에 넣는 것.** `icat`/카빙으로 뽑은 파일의 mtime은 추출 시각이다.
- **CSV 컬럼명을 문서 기억대로 쓰는 것.** 버전마다 다르다. `Get-Member`로 실제 헤더를 먼저 본다.
- **`$J`에 기록이 없다고 "일어나지 않았다"고 결론 내리는 것.** 저널은 순환한다. `$J` 첫 레코드의 시각을 확인해 관측 가능 구간을 먼저 정한다.
- **공백 구간을 "아무 일도 없었다"로 읽는 것.** 로그 삭제(1102/104), 저널 순환, 시각 변경(4616)일 수 있다.
- **artifact 하나로 서술을 완성하려는 것.** `$MFT`는 "무엇이 있었나", `$J`는 "무슨 일이 있었나", EVTX는 "누가"에만 답한다. 셋을 겹쳐야 문장이 된다.
- **필터 없이 전체 타임라인을 읽으려는 것.** 수십만 행이다. 사건 시각 ±10분으로 먼저 좁힌다.
- **Prefetch 실행 시각을 "그때만 실행됐다"로 읽는 것.** 최근 실행 기록만 유지되고 `RunCount`는 누적이다. 그 이전 실행은 타임라인에 나타나지 않는다.

## 교차검증

```powershell
# 1) 같은 사건이 세 artifact에서 같은 시각을 가리키는가
Import-Csv out\usn.csv | Where-Object { $_.FileName -eq 'budget_2026Q1.xlsx' } |
  Select-Object Usn, UpdateTimestamp, UpdateReasons
Import-Csv out\mft.csv | Where-Object { $_.FileName -eq 'budget_2026Q1.xlsx' } |
  Select-Object Created0x10, Created0x30, LastModified0x10, LastRecordChange0x10
Import-Csv out\*_RBCmd_Output.csv | Where-Object { $_.FileName -match 'budget' }

# 2) 실행 흔적 대조: Prefetch vs 4688 vs $J
Import-Csv out\*_PECmd_Output_Timeline.csv | Where-Object { $_.ExecutableName -match '7z' }
Import-Csv out\evtx.csv | Where-Object { $_.EventId -eq 4688 -and $_.PayloadData1 -match '7z' }

# 3) 시간 정렬 무결성: 순번과 시각이 함께 증가하는가
Import-Csv out\usn.csv | Sort-Object { [int64]("0x"+($_.Usn -replace '^0x','')) } |
  Select-Object -First 5 Usn, UpdateTimestamp
```

```bash
# 4) Sleuth Kit 으로 독립 타임라인을 만들어 대조한다
fls -o 2048 -m C:/ -r image.raw > body.txt
mactime -b body.txt -d -z UTC > tsk_timeline.csv
grep -i 'budget' tsk_timeline.csv

# 5) 일별 활동량으로 공백 구간 확인
mactime -b body.txt -d -z UTC -i day daily.txt > /dev/null && head -40 daily.txt
```

`$J`의 순번은 증가하는데 시각이 뒤로 가는 구간이 있으면 **시스템 시각이 변경된 것**이다(4616 확인). 이것은 순번 기반 정렬만이 잡아낼 수 있는 조작이다.

## mini walkthrough

```text
문제:
"2026-03-14 오후, 내부 자료가 외부로 나간 정황이 있습니다.
 누가 무엇을 어떻게 가져갔는지 시간순으로 서술하고 flag 를 제출하세요."
첨부: $MFT, $J, Security.evtx, System.evtx, Prefetch/ (12개), $Recycle.Bin/

1. CSV 생성
   MFTECmd.exe -f $MFT --csv out --csvf mft.csv          -> 412,880 행
   MFTECmd.exe -f $J -m $MFT --csv out --csvf usn.csv    -> 388,214 행
   EvtxECmd.exe -d . --csv out --csvf evtx.csv           ->  18,442 행
   PECmd.exe -d Prefetch --csv out                       ->      12 행
   RBCmd.exe -d $Recycle.Bin --csv out                   ->       0 행 (휴지통 비어 있음)

2. 첫 시도 (실패):
   지문의 "오후"를 그대로 믿고 KST 13:00~18:00 으로 필터를 걸었다.

   Import-Csv out\usn.csv |
     Where-Object { $_.UpdateTimestamp -ge '2026-03-14 13:00' -and
                    $_.UpdateTimestamp -le '2026-03-14 18:00' }
   -> 2,104 행. 그런데 정작 압축·삭제 흔적이 안 보인다.

   무엇이 틀렸나:
     MFTECmd 의 UpdateTimestamp 는 UTC 다.
     KST 오후(13~18시)는 UTC 04:00~09:00 이다.
     UTC 13~18시로 필터를 걸었으니 실제로는 KST 22시~다음날 03시를 본 것이다.
   => 5시간 이상 어긋난 구간을 뒤지고 있었다.

3. 접근 변경 — 축을 UTC로 고정하고 KST는 표시용으로만 쓴다
   KST 13:00~18:00  =  UTC 04:00~09:00

   Import-Csv out\usn.csv |
     Where-Object { $_.UpdateTimestamp -ge '2026-03-14 04:00' -and
                    $_.UpdateTimestamp -le '2026-03-14 09:00' -and
                    $_.UpdateReasons -match 'FileCreate|FileDelete|Rename' } |
     Sort-Object { [int64]("0x"+($_.Usn -replace '^0x','')) } |
     Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName

   Usn         UpdateTimestamp        UpdateReasons          FileName
   0x4a11200   2026-03-14 07:31:04Z   FileCreate             customer_db_2026.7z
   0x4a115a0   2026-03-14 07:33:18Z   DataExtend|Close       customer_db_2026.7z
   0x4a1a840   2026-03-14 07:38:41Z   RenameOldName          customer_db_2026.7z
   0x4a1a9c0   2026-03-14 07:38:41Z   RenameNewName|Close    report_final.7z
   0x4a1b8c0   2026-03-14 07:39:52Z   FileDelete|Close       report_final.7z

   07:31~07:39 UTC = 16:31~16:39 KST. 여기가 사건 구간이다.

4. 두 번째 문제 — 같은 초에 5개가 몰려 순서가 안 나온다
   07:38:41Z 에 Rename 두 개, 07:39:52Z 에 여러 레코드가 함께 있다.

   Sort-Object UpdateTimestamp 로 정렬했을 때
   RenameNewName 이 RenameOldName 보다 위에 오는 경우가 있었다.
   -> 타임스탬프는 초 단위라 동률이면 원래 순서를 보장하지 않는다.

   해결: Usn 으로 정렬한다 (위 3단계에서 이미 적용).
   0x4a1a840 < 0x4a1a9c0 이므로 Old -> New 가 확정된다.

   EVTX 도 같은 처리를 한다.
   Import-Csv out\evtx.csv |
     Where-Object { $_.Channel -eq 'Security' -and $_.TimeCreated -like '*07:3*' } |
     Sort-Object { [int64]$_.EventRecordId } |
     Format-Table EventRecordId, TimeCreated, EventId, UserName, MapDescription

   EventRecordId TimeCreated            EventId UserName  MapDescription
   1184402       2026-03-14 07:12:33Z   4624    jhkim     Logon Type 10 (RemoteInteractive)
   1184571       2026-03-14 07:30:58Z   4688    jhkim     7z.exe
   1184903       2026-03-14 07:41:02Z   4688    jhkim     rclone.exe
   1185004       2026-03-14 07:45:11Z   1102    jhkim     감사 로그 지움

5. 실행 흔적 확인
   Import-Csv out\*_PECmd_Output_Timeline.csv |
     Where-Object { $_.ExecutableName -match '7Z|RCLONE' }
   -> 7Z.EXE  RunCount 3
      RCLONE.EXE RunCount 1

   Prefetch 가 4688 과 같은 실행을 가리킨다. 교차검증 통과.

6. 공백 구간 판정
   Security 채널의 마지막 이벤트가 07:45:11Z 의 1102 이후 없다.
   Import-Csv out\evtx.csv | Where-Object { $_.Channel -eq 'Security' } |
     Sort-Object { [int64]$_.EventRecordId } | Select-Object -Last 3
   -> 1102 가 마지막. 그 뒤가 비어 있다.

   $J 는 07:45 이후에도 계속 기록되어 있다.
   => EVTX 만 끊겼다 = 로그를 지운 것이다. 시스템이 꺼진 것이 아니다.
   이 대비가 "공백의 원인"을 확정한다.

7. flag 위치
   삭제된 report_final.7z 를 복구한다 (FOR-0049 절차).
   $MFT: EntryNumber 128441, InUse=False, FileSize 284,113,920
   -> 레코드 생존. icat 으로 추출 -> 7z 정상 -> 내부에 flag

   flag{t1m3l1n3_1n_utc_0rd3r_by_usn}

8. 사건 서술 (제출 형태)
   16:12:33 KST (07:12:33Z)  jhkim RDP 로그온 (4624 Type 10, RecId 1184402)
   16:30:58 KST (07:30:58Z)  7z.exe 실행 (4688 RecId 1184571 / Prefetch RunCount 3)
   16:31:04 KST (07:31:04Z)  customer_db_2026.7z 생성 ($J Usn 0x4a11200)
   16:33:18 KST (07:33:18Z)  압축 완료 ($J Usn 0x4a115a0)
   16:38:41 KST (07:38:41Z)  report_final.7z 로 위장 개명 (Usn 0x4a1a840 -> 0x4a1a9c0)
   16:39:52 KST (07:39:52Z)  삭제 ($J Usn 0x4a1b8c0), 휴지통 기록 없음 = Shift+Delete
   16:41:02 KST (07:41:02Z)  rclone.exe 실행 (4688 RecId 1184903) = 외부 전송 수단
   16:45:11 KST (07:45:11Z)  감사 로그 지움 (1102 RecId 1185004) = 은폐

정답: flag{t1m3l1n3_1n_utc_0rd3r_by_usn}
```

두 번의 교정이 이 글의 전부다. **① 시간대를 섞으면 존재하지 않는 구간을 뒤지게 된다** — 축은 UTC 하나로 고정하고 KST는 출력 단계에서만 만든다. **② 같은 초의 순서는 시각이 아니라 순번이 정한다** — `Usn`과 `EventRecordId`가 없으면 "개명 후 삭제"인지 "삭제 후 개명"인지 구분할 수 없다. 그리고 6단계처럼 **한 artifact의 공백을 다른 artifact의 연속성과 대비**시키면 공백의 원인까지 확정할 수 있다.

## 막혔을 때 다음 체크

1. 모든 CSV의 시각이 **UTC**인지 확인했는가, 지문의 시각이 KST인가
2. 필터 구간을 UTC로 환산했는가 (KST − 9시간)
3. `$J`를 `Usn`으로, EVTX를 `EventRecordId`로 정렬했는가
4. `EventRecordId`를 **같은 채널 안에서만** 비교했는가
5. `Get-Member`로 실제 CSV 컬럼명을 확인했는가
6. `$MFT`의 `0x10`과 `0x30`을 비교했는가 (timestomp)
7. 사건 시각 ±10분으로 범위를 좁혔는가
8. `$J`의 **첫 레코드 시각**을 확인했는가 — 관측 가능한 구간의 하한이다
9. EVTX가 특정 시각 이후 비었는가 → 1102/104 검색
10. `EventRecordId`의 연속성을 검사했는가
11. 4616(시스템 시각 변경)이 있는가 → 그 전후 타임스탬프 전부 의심
12. Prefetch 폴더가 비었는가 → `$J`에서 `.pf`의 `FileDelete` 검색
13. Prefetch/4688/`$J`가 같은 실행을 가리키는가 (교차검증)
14. 행위마다 **계정**을 배정했는가 (4624 `Logon ID`, `$Recycle.Bin` SID)
15. `$LogFile`을 NTFS Log Tracker로 읽어 트랜잭션 단위 상세를 봤는가
16. Sleuth Kit `fls -m` + `mactime`으로 독립 타임라인을 만들어 대조했는가
17. 서술 문장마다 근거 artifact와 순번을 붙였는가

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$STANDARD_INFORMATION`(0x10)과 `$FILE_NAME`(0x30)이 각각 4개의 타임스탬프를 갖는다는 근거, 레코드 구조
- SRC-013 — Microsoft Learn, Change Journals: `USN_RECORD`의 `Usn`이 저널 내 위치 겸 단조 증가 순번이라는 근거, `UpdateReasons` 플래그
- SRC-004 — Eric Zimmerman 문서: MFTECmd(`-f` `-m` `--csv` `--csvf`, bodyfile 출력), EvtxECmd(`-d` `-f` `--inc`), PECmd, RBCmd, LECmd의 CSV 출력과 Timeline Explorer 사용
- SRC-032 — The Sleuth Kit 도구 문서: `fls -m`의 bodyfile 출력 형식과 `mactime`의 `-b` `-d` `-z` `-y` `-i` 옵션
- CSV 컬럼명, 메뉴 경로, 출력 파일 이름 규칙(예: `*_PECmd_Output_Timeline.csv`)은 도구 버전에 따라 다르므로 실제 화면과 `Get-Member` 결과에서 확인할 것
- Event ID 1102(감사 로그 지움), 104(로그 파일 지움), 4616(시스템 시각 변경)의 정식 정의와 EventData 필드는 Microsoft의 감사 정책/이벤트 문서에서 확인할 것. 이 글은 타임라인 공백의 원인 판정 용도로만 사용한다
