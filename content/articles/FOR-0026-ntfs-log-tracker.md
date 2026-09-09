---
id: FOR-0026
title: "NTFS Log Tracker로 $LogFile·$UsnJrnl·$MFT 한 번에 묶어 보기"
slug: "ntfs-log-tracker"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$LogFile", "$UsnJrnl", "$J", "$MFT", "$I30", "INDX", "LSN", "USN"]
file_paths: ["C:\\$LogFile", "C:\\$MFT", "C:\\$Extend\\$UsnJrnl", "C:\\$Extend\\$UsnJrnl:$J"]
registry_paths: []
event_ids: []
protocols: []
tools: ["NTFS Log Tracker", "MFTECmd", "Timeline Explorer", "FTK Imager", "Arsenal Image Mounter", "sqlite3", "DB Browser for SQLite"]
commands: ["MFTECmd.exe -f \"C:\\case\\$J\" -m \"C:\\case\\$MFT\" --csv \"C:\\case\\out\" --csvf usn.csv", "sqlite3 tracker.db \".tables\"", "sqlite3 tracker.db \".schema\"", "icat -o 2048 image.dd 2 > '$LogFile'"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["LSN", "USN", "Transaction ID", "Redo Operation", "Undo Operation", "File Name", "Full Path", "MFT Entry", "Parent MFT Entry", "Event Time", "Event Type"]
file_formats: ["ntfs", "sqlite", "csv"]
primary_terms: ["NTFS Log Tracker"]
keywords: ["NTFS Log Tracker", "$LogFile 파싱", "$UsnJrnl 파싱", "사건 단위 묶기", "SQLite 출력", "CSV 출력", "파일 생성 삭제 판별", "이름변경 이동 구분", "Timeline Explorer"]
aliases: ["ntfs log tracker", "로그 트래커", "logfile 파서", "usnjrnl 파서", "ntfs 로그 도구", "logfile 분석 도구", "삭제 이력 도구"]
symptom_keywords: ["$LogFile을 어떻게 파싱하나", "경로가 안 나온다", "생성인지 삭제인지 모르겠다", "이름변경인지 이동인지 모르겠다", "결과가 너무 많다", "도구가 없다"]
related: ["FOR-0025", "FOR-0027", "FOR-0029"]
source_ids: ["SRC-005", "SRC-013", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

NTFS Log Tracker는 `$LogFile`·`$UsnJrnl:$J`·`$MFT` **세 개를 함께 입력해야** 제 값을 한다 — `$MFT` 없이 돌리면 파일 이름만 나오고 경로가 비어서 동명 파일을 구분할 수 없다. 결과는 SQLite DB와 CSV로 나오므로 SQL이나 Timeline Explorer로 재질의한다.

## 어떤 문제에서 필요한가

- "삭제된 파일의 전체 경로와 삭제 시각을 모두 확정하라"
- "`$LogFile`을 어떻게 파싱하나" (MFTECmd는 `$LogFile`을 지원하지 않는다)
- "이름 변경인가 다른 폴더로의 이동인가"
- "`$J`에는 잘려 나간 구간의 사건을 복원하라"
- "저수준 연산 수십 개를 사용자 행위 하나로 묶어 보고 싶다"

`$LogFile` 자체의 구조와 redo/undo 개념은 [FOR-0025](./logfile-basics.html), `$UsnJrnl`의 `USN_REASON` 플래그는 [FOR-0027](./usnjrnl-basics.html)에서 다룬다. 이 글은 **세 입력을 합쳐 사건 목록을 만들고 재질의하는 절차**다.

## 문제에서 처음 볼 단서

1. 첨부에 `$LogFile`이 있다 → 이 도구가 사실상 유일한 선택지다
2. 첨부에 `$LogFile` + `$J` + `$MFT` 세 개가 함께 있다 → 출제자가 이 도구를 전제했다
3. 파일 이름은 아는데 경로를 모른다 → `$MFT`를 반드시 함께 입력
4. `$J` 파싱 결과에 사건 시각대가 없다 → `$LogFile`로 내려간다
5. 동명 파일이 여러 개다 → 경로 없이는 답을 못 낸다
6. 지문이 "이동"을 묻는다 → 부모 레코드 번호 두 개를 비교해야 한다

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv "C:\case\out" --csvf usn.csv
```

먼저 `$J`만 MFTECmd로 빠르게 훑어 사건 시각대가 남아 있는지 확인한다. 남아 있으면 그것으로 끝나는 문제도 많다. 없거나 부족하면 NTFS Log Tracker로 넘어간다.

NTFS Log Tracker의 최소 절차는 세 단계다.

```text
1) $MFT 를 먼저 지정한다        -> 경로 복원용 참조
2) $LogFile 을 지정해 파싱한다  -> 저수준 연산이 사건으로 묶여 나온다
3) $UsnJrnl($J) 도 파싱해 같은 결과 집합에 더한다
그 뒤 SQLite DB / CSV 로 저장하고 Timeline Explorer 나 SQL 로 본다
```

버전에 따라 탭 구성과 버튼 이름이 다르다. **"세 파일을 준다 → 파싱한다 → DB/CSV로 저장한다"는 순서만 유지하고, 실제 라벨은 화면에서 확인한다.**

## 상세 절차

### 1단계 — 입력 3개를 준비한다

| 입력 | 왜 필요한가 | 없으면 |
| --- | --- | --- |
| `$LogFile` | 저수준 연산과 undo(변경 전 값) | 상세 근거가 사라진다. `$J` 수준의 요약만 남는다 |
| `$Extend\$UsnJrnl:$J` | 파일 단위 사건과 긴 보존 기간 | 오래된 사건을 놓친다 |
| `$MFT` | **부모 레코드 번호 → 경로 문자열 변환** | 이름만 나오고 경로가 빈다. 동명 파일 구분 불가 |
| (선택) `$I30` / `INDX` | 삭제된 색인 항목의 잔존 이름 | 재사용된 레코드의 이름을 놓칠 수 있다 |

추출은 이미지에서 한다.

```bash
# 파티션 오프셋 확인
mmls image.dd

# 볼륨 루트의 메타파일 — 레코드 번호로 바로 뽑는다
icat -o 2048 image.dd 0 > '$MFT'
icat -o 2048 image.dd 2 > '$LogFile'

# $J 는 $Extend 안의 ADS 다. fls 로 "레코드-타입-ID" 를 확인한 뒤 그대로 준다
fls -o 2048 image.dd 11
# -> r/r 27-128-3:  $UsnJrnl:$J
icat -o 2048 image.dd 27-128-3 > '$J'
```

GUI로 뽑을 때는 FTK Imager에서 볼륨 `[root]`의 `$MFT`·`$LogFile`, 그리고 `$Extend` 폴더를 펼쳐 `$UsnJrnl`의 `$J` 항목을 각각 Export한다 ([FOR-0016](./ftk-imager-open-image.html)). 실행 중인 시스템에서는 일반 복사가 안 되므로 이미지를 마운트해서 접근한다 ([FOR-0017](./arsenal-image-mounter.html)).

**추출 검산**을 반드시 한다.

```bash
xxd -l 4 '$MFT'      # 4649 4c45  -> "FILE"
xxd -l 4 '$LogFile'  # 5253 5452  -> "RSTR"
ls -l '$J'           # sparse 라서 논리 크기가 매우 클 수 있다 (정상)
```

시그니처가 다르면 잘못된 레코드를 뽑은 것이다. 파싱을 시도하기 전에 여기서 잡는다.

### 2단계 — 파싱 순서와 시간대 고정

개념적 순서는 이렇게 지킨다.

| 순서 | 하는 일 | 이유 |
| --- | --- | --- |
| 1 | 출력 시간대를 UTC나 KST 중 하나로 **고정**하고 메모 | 나중에 +9를 두 번 하는 사고를 막는다 |
| 2 | `$MFT`를 참조로 먼저 로드 | 이후 파싱 결과의 경로가 채워진다 |
| 3 | `$LogFile` 파싱 | 가장 상세. 최근 구간에 강하다 |
| 4 | `$J` 파싱 | 보존 기간이 길다. 과거 구간을 채운다 |
| 5 | SQLite DB로 저장 | 재질의의 기반 |
| 6 | 필요한 범위만 CSV로 export | Timeline Explorer로 볼 부분만 |

`$LogFile`과 `$J`를 **둘 다** 넣는 이유는 커버 구간이 다르기 때문이다.

```text
시간 -->  과거                                                    현재
$UsnJrnl:$J   |=======================================|
$LogFile                                     |========|
              ^ $J 만 있는 구간               ^ 둘 다 있는 구간 (교차검증 가능)
```

두 소스가 겹치는 구간이 **교차검증 구간**이다. 같은 사건이 양쪽에 나오면 판정 신뢰도가 크게 올라간다. 겹치지 않는 구간은 한쪽 소스만의 진술이므로 `$MFT`의 최종 상태와 반드시 대조한다.

### 3단계 — SQLite 출력 vs CSV 출력

| | SQLite DB | CSV |
| --- | --- | --- |
| 용도 | **재질의**, 조인, 집계 | 눈으로 훑기, Timeline Explorer |
| 대용량 | 강하다 (수백만 행) | 100MB 넘으면 도구가 버벅인다 |
| 필터 표현력 | SQL 전체 | 컬럼 필터 수준 |
| 두 소스 조인 | `$LogFile`↔`$J`를 SQL로 대조 가능 | 수동 대조 |
| 보고서용 | 질의 결과를 다시 CSV로 | 그대로 제출 |

실전은 **DB로 저장 → SQL로 좁힘 → 결과만 CSV로 export → Timeline Explorer로 확인**이 가장 빠르다.

### 4단계 — 사건 유형 판별 규칙

도구가 사건 유형을 붙여 주더라도 **근거를 직접 확인**해야 오답을 피한다. 판별 논리는 다음과 같다.

| 판정 | `$LogFile` 근거 | `$J` 근거 |
| --- | --- | --- |
| 파일 생성 | `InitializeFileRecordSegment` + `AddIndexEntry*` + `SetBitsInNonresidentBitMap` | `FileCreate` |
| 파일 쓰기 | `UpdateMappingPairs` + `SetNewAttributeSizes` | `DataExtend` / `DataOverwrite` |
| 파일 삭제 | `DeallocateFileRecordSegment` + `DeleteIndexEntry*` + `ClearBitsInNonresidentBitMap` | `FileDelete` |
| **이름 변경** | `DeleteIndexEntry*` + `AddIndexEntry*`, **부모 레코드 번호가 같다** | `RenameOldName` + `RenameNewName`, `ParentEntryNumber` 동일 |
| **이동(같은 볼륨)** | `DeleteIndexEntry*` + `AddIndexEntry*`, **부모 레코드 번호가 다르다** | `RenameOldName` + `RenameNewName`, `ParentEntryNumber` 변경 |
| 이동(다른 볼륨) | 이 볼륨에서는 삭제 조합만 보인다 | `FileDelete` (대상 볼륨에는 `FileCreate`) |
| 폴더 생성 | `InitializeFileRecordSegment` + `$INDEX_ROOT` `CreateAttribute` | `FileCreate` + `Directory` 속성 |
| ADS 생성 | 이름 있는 `$DATA`의 `CreateAttribute` | `StreamChange` / `NamedDataExtend` |
| 타임스탬프 조작 | `$STANDARD_INFORMATION` 대상 `UpdateResidentValue` | `BasicInfoChange` 단독 |

**이름 변경과 이동을 가르는 것은 부모 레코드 번호 하나뿐이다.** 이 한 컬럼을 확인하지 않고 도구의 라벨만 믿으면 틀린다.

정렬 기준도 지킨다.

| 소스 | 순서 기준 | 시각으로 정렬하면 |
| --- | --- | --- |
| `$LogFile` | **LSN** | 같은 초에 몰린 수십 건의 순서가 뒤섞인다 |
| `$UsnJrnl` | **USN** | 위와 동일 |

### 5단계 — Timeline Explorer로 좁히기

CSV를 열고 다음 순서로 줄인다.

| 순서 | 필터 | 남는 양의 감각 |
| --- | --- | --- |
| 1 | 시각 범위 (사건 시각 ±30분) | 수십만 → 수천 |
| 2 | 사건 유형 (`Delete`/`Rename`) | 수천 → 수백 |
| 3 | 경로 (사용자 폴더로 한정) | 수백 → 수십 |
| 4 | 확장자 | 수십 → 한 자리 |

컬럼 헤더 아래 필터 입력 행에 값을 넣고, 중요한 행에 태그를 달아 두고, 마지막에 필터가 걸린 상태를 그대로 export한다. 메뉴·버튼 이름은 버전마다 다르므로 화면에서 확인한다.

### 6단계 — SQLite 출력을 SQL로 재질의

**컬럼 이름을 추측하지 않는다.** 스키마를 먼저 읽는다.

```bash
# 1) 테이블 목록
sqlite3 tracker.db ".tables"

# 2) 각 테이블의 정의
sqlite3 tracker.db ".schema"

# 3) 특정 테이블의 컬럼과 타입
sqlite3 tracker.db "PRAGMA table_info('<테이블명>');"

# 4) 실제 값 3행을 보고 형식을 확인한다 (특히 시각 컬럼)
sqlite3 -header -line tracker.db "SELECT * FROM <테이블명> LIMIT 3;"
```

스키마를 확인한 뒤 아래 형태로 채운다. `<...>`는 3단계에서 읽은 실제 이름으로 바꾼다.

```sql
-- 사건 시각대의 삭제 사건만
SELECT <시각>, <사건유형>, <경로>, <파일명>, <MFT엔트리>
FROM <테이블>
WHERE <사건유형> LIKE '%Delete%'
  AND <시각> BETWEEN '2026-03-14 07:00:00' AND '2026-03-14 08:00:00'
ORDER BY <LSN 또는 USN>;
```

```sql
-- 특정 파일의 전체 생애 (MFT 엔트리 번호로 추적 — 이름이 바뀌어도 따라간다)
SELECT <LSN>, <시각>, <사건유형>, <파일명>, <부모엔트리>
FROM <테이블>
WHERE <MFT엔트리> = 128441
ORDER BY <LSN>;
```

```sql
-- 이름 변경 짝을 부모 엔트리까지 함께 — rename 인가 move 인가
SELECT <시각>, <사건유형>, <파일명>, <부모엔트리>
FROM <테이블>
WHERE <사건유형> LIKE '%Rename%' OR <사건유형> LIKE '%IndexEntry%'
ORDER BY <LSN>;
```

```sql
-- 시간대별 사건 밀도 = 사용자 활동이 몰린 구간 찾기
SELECT substr(<시각>, 1, 13) AS hour, COUNT(*) AS n
FROM <테이블>
GROUP BY hour ORDER BY n DESC LIMIT 20;
```

```sql
-- 결과를 CSV 로 빼기
.headers on
.mode csv
.output deleted.csv
SELECT ... ;
.output stdout
```

### 7단계 — 도구가 없을 때의 대안

| 대상 | 대안 | 얻는 것 / 잃는 것 |
| --- | --- | --- |
| `$J` | `MFTECmd.exe -f "$J" -m "$MFT" --csv . --csvf usn.csv` | **얻음**: 사건 목록 + 경로. **잃음**: `$LogFile`의 상세와 undo |
| `$LogFile` | `LogFileParser` (별도 도구) | 저수준 연산 CSV. 사건 묶기는 직접 |
| `$LogFile` | `strings -e l '$LogFile'` 결과를 `rg`로 필터 | 이름 조각만. 순서·대상 레코드 없음 |
| `$MFT` | `MFTECmd.exe -f "$MFT" --csv . --csvf mft.csv` | 경로 복원용 조인 테이블 확보 |
| 전체 | Autopsy 타임라인 | 파일시스템 시각 기반. `$LogFile` 연산은 안 나온다 |

`-m "$MFT"`가 핵심이다. 이것 없이 `$J`를 파싱하면 NTFS Log Tracker를 `$MFT` 없이 돌린 것과 같은 문제(경로 없음)가 생긴다.

```powershell
# 대안 경로 전체 — $J + $MFT 만으로 삭제 사건 목록 만들기
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv "C:\case\out" --csvf usn.csv

Import-Csv C:\case\out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'FileDelete' -and $_.ParentPath -match 'Users' } |
  Select-Object Usn, UpdateTimestamp, ParentPath, FileName, EntryNumber |
  Sort-Object Usn
```

## 출력 필드 해석

컬럼 이름은 버전에 따라 다르다. **의미 기준**으로 대응시켜 읽는다.

| 개념 | `$LogFile` 쪽에서 | `$UsnJrnl` 쪽에서 | 읽는 법 |
| --- | --- | --- | --- |
| 순서 | `LSN` | `USN` | **정렬은 항상 이 값으로** |
| 시각 | 트랜잭션/페이지 시각 | `UpdateTimestamp` | FILETIME(UTC). KST면 +9 |
| 사건 유형 | `Redo Operation` + `Undo Operation` | `UpdateReasons` 플래그 | 4단계 표로 판정 |
| 묶음 키 | `Transaction ID` | `Usn` 인접 + `CLOSE` 플래그 | 사용자 행위 1건의 경계 |
| 대상 파일 | `MFT Entry` (+ 시퀀스) | `EntryNumber` + `SequenceNumber` | **둘 다** 같아야 같은 파일 |
| 대상 이름 | undo/redo 데이터 안의 `$FILE_NAME` | `FileName` | 경로는 포함되지 않는다 |
| 부모 | 색인 대상 `MFT Entry` | `ParentEntryNumber` | **rename vs move 판정 키** |
| 경로 | `$MFT` 조인 결과 | `$MFT` 조인 결과 | `$MFT` 없으면 빈다 |
| 대상 속성 | `Target Attribute` | — | `$SI`면 timestomp 후보 |
| 클러스터 | `Target VCN` / `Target LCN` | — | 카빙 대상 위치 |

`Full Path` 계열 컬럼이 비어 있다면 **거의 항상 `$MFT`를 안 준 것**이다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 삭제 사건 + 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 레코드가 남았는가, MACB는 무엇인가 |
| `MFT Entry` 번호 | `icat -o <off> image.dd <n>` | 내용 복구 시도 |
| undo의 옛 타임스탬프 | `$SI` vs `$FN` ([FOR-0024](./si-vs-fn-timestamps.html)) | 조작 전 값 확정 |
| `BasicInfoChange` 시각 | `$SI`의 `LastRecordChange0x10` | 두 값 일치 → timestomp 확정 |
| 해제된 클러스터(LCN) | 미할당 영역 카빙 | 내용이 아직 남았는가 |
| 사건 시각 | EVTX `4688`/`4104` ([FOR-0083](./event-4624-logon.html)) | 어느 프로세스·세션이 유발했나 |
| 아카이브 생성/삭제 | Prefetch (압축 도구), 브라우저 History ([FOR-0191](./chrome-history.html)) | 유출 경로 |
| 실행 파일 생성 | Prefetch / Amcache / UserAssist ([FOR-0061](./userassist.html)) | 실행 여부와 횟수 |
| 이동 목적지 부모 | 그 폴더의 `$INDEX_ALLOCATION` | 다른 항목도 함께 옮겼나 |

## 흔한 함정

- **`$MFT`를 안 주고 돌리는 것.** 경로 컬럼이 비고 이름만 남는다. `report.docx`가 볼륨에 다섯 개 있으면 답을 특정할 수 없다. 이 도구를 쓰는 이유의 절반이 경로 복원이다.
- **`$LogFile`만 넣고 `$J`를 빼는 것.** `$LogFile`은 보존 기간이 짧다. 며칠 전 사건이면 비어 있다. 두 소스의 커버 구간이 다르므로 항상 함께 넣는다.
- **`$UsnJrnl`을 통째로 주고 `$J`를 안 주는 것.** 데이터는 ADS `:$J`에 있다. `$UsnJrnl` 본체만 export하면 사실상 빈 파일이다.
- **도구가 붙인 사건 라벨을 그대로 답으로 쓰는 것.** rename과 move는 **부모 레코드 번호**로만 갈린다. 라벨이 `Rename`이어도 부모가 바뀌었으면 이동이다.
- **시각으로 정렬하는 것.** 같은 초에 수십~수백 레코드가 몰린다. 순서는 `LSN`(`$LogFile`)과 `USN`(`$J`)이 정한다.
- **저수준 연산 1건을 사용자 행위 1건으로 세는 것.** 파일 하나 삭제에 레코드가 수십 개 나온다. `Transaction ID`로 묶어야 "삭제 1건"이 된다. 안 묶고 세면 건수가 수십 배로 부풀려진다.
- **`EntryNumber`만으로 파일을 동일시하는 것.** MFT 레코드 슬롯은 재사용된다. `SequenceNumber`까지 같아야 같은 파일이다. 특히 삭제가 잦은 폴더에서 오판이 생긴다.
- **시간대를 두 번 변환하는 것.** 도구의 시간대 설정을 KST로 두고 결과에 다시 +9를 하면 18시간이 틀어진다. 파싱 시작 전에 시간대를 고정하고 그 값을 적어 둔다. FILETIME은 1601-01-01 UTC 기준 100ns이고 Unix와 11644473600초 차이다.
- **SQLite 컬럼 이름을 추측해 SQL을 짜는 것.** `.tables`와 `.schema`를 먼저 읽는다. 없는 컬럼을 쓰면 에러가 나고, 있는데 의미가 다르면 조용히 틀린 답이 나온다.
- **결과가 많다고 CSV를 Excel로 여는 것.** 행 한계에서 잘리고 시각 컬럼 서식이 망가진다. SQLite로 좁히고 Timeline Explorer로 확인한다.
- **`$LogFile`에 기록이 없다는 것을 "그 일이 없었다"로 읽는 것.** 원형 버퍼라 이미 덮였을 수 있다 ([FOR-0025](./logfile-basics.html)).
- **추출 검산을 건너뛰는 것.** `$MFT`는 `FILE`, `$LogFile`은 `RSTR`로 시작해야 한다. 엉뚱한 레코드를 뽑아 놓고 "파서가 이상하다"고 시간을 버리는 경우가 많다.
- **`$I30`/`INDX`를 안 보는 것.** 레코드가 재사용돼 `$MFT`에서 사라진 파일의 이름이 부모 폴더 색인 슬랙에 남아 있을 수 있다.

## 교차검증

```powershell
# 1) 같은 사건이 $J 에도 있는가 (독립 소스 확인)
Import-Csv C:\case\out\usn.csv |
  Where-Object { $_.EntryNumber -eq '128441' } |
  Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName | Sort-Object Usn

# 2) $MFT 의 최종 상태와 맞는가
Import-Csv C:\case\out\mft.csv |
  Where-Object { $_.EntryNumber -eq '128441' } |
  Select-Object InUse, FileName, ParentPath, FileSize, Created0x10, LastRecordChange0x10

# 3) 휴지통 경유였는지
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv "C:\case\out"
```

```bash
# 4) 레코드 원본에서 속성 확인
istat -o 2048 image.dd 128441

# 5) 파서를 못 믿을 때 이름 존재 여부만 raw 확인
strings -e l '$LogFile' | rg -i 'customer_db'
```

세 소스(`$LogFile`·`$J`·`$MFT`)의 시각이 서로 몇 초 이내로 정합하면 판정이 확정된다. 크게 어긋나면 **시간대 설정**을 먼저 의심한다.

## mini walkthrough

```text
문제:
"내부 문서가 외부로 나갔습니다. 유출된 파일의 전체 경로와 삭제 시각,
 그리고 그 파일이 이동된 것인지 이름만 바뀐 것인지 판정하세요.
 첨부: $LogFile, $J, $MFT"

1. 추출 검산
   xxd -l 4 '$MFT'      -> 4649 4c45   "FILE"  OK
   xxd -l 4 '$LogFile'  -> 5253 5452   "RSTR"  OK

2. 첫 시도 (실패):
   NTFS Log Tracker 에 $LogFile 만 지정해 파싱했다.
   결과에서 삭제 사건을 필터하니 이름은 나왔다.

   Event Type   File Name        Full Path
   ------------ ---------------- ---------
   Delete       report.docx      (빈칸)
   Delete       report.docx      (빈칸)
   Delete       report.docx      (빈칸)

   report.docx 3건이 전부 경로가 비어 있다. 어느 것이 유출본인지 알 수 없다.

   왜 틀렸나: $LogFile 에는 부모 "레코드 번호"만 들어 있다.
   경로 문자열로 바꾸려면 $MFT 가 있어야 한다.

3. 접근 변경 — $MFT 를 먼저 지정하고 다시 파싱, $J 도 함께 넣는다
   결과:

   Source    LSN/USN     Time(UTC)             Event    Full Path
   --------- ----------- --------------------- -------- -----------------------------------
   $LogFile  0x1a4b1200  2026-03-14 07:31:04   Create   \Users\jhkim\Documents\report.docx
   $LogFile  0x1a4b2c10  2026-03-14 07:38:41   IdxDel   \Users\jhkim\Documents\report.docx
   $LogFile  0x1a4b2c88  2026-03-14 07:38:41   IdxAdd   \Users\jhkim\Documents\quarter.docx
   $J        0x4a1b8c0   2026-03-14 07:39:52   Delete   \Users\jhkim\Documents\quarter.docx
   $LogFile  ...          (해당 구간 없음)
   $J        0x4a08110   2026-03-01 09:12:33   Delete   \Windows\Temp\report.docx
   $J        0x49f2200   2026-02-11 14:03:07   Delete   \Users\Public\report.docx

   -> 나머지 두 report.docx 는 사건과 무관한 과거 삭제였다.
      3월 1일과 2월 11일 건은 $LogFile 에 없다 (이미 덮였다).
      두 소스를 함께 넣어야 이 판단이 가능했다.

4. 두 번째 실수와 정정 — 도구 라벨을 믿었다
   IdxDel/IdxAdd 짝을 보고 "이동" 이라고 답했다.
   부모 레코드 번호를 확인하지 않은 판정이다.

   SELECT <LSN>, <사건유형>, <파일명>, <부모엔트리>
   FROM <테이블> WHERE <MFT엔트리> = 128441 ORDER BY <LSN>;

   LSN         사건유형                     파일명           부모엔트리
   ----------- ---------------------------- ---------------- ----------
   0x1a4b1200  InitializeFileRecordSegment  report.docx      9114
   0x1a4b2c10  DeleteIndexEntryAllocation   report.docx      9114
   0x1a4b2c88  AddIndexEntryAllocation      quarter.docx     9114     <-- 부모가 같다
   0x1a4b3a40  DeallocateFileRecordSegment  quarter.docx     9114

   부모 엔트리가 둘 다 9114 다. -> 이동이 아니라 이름 변경이다.

5. Transaction ID 로 묶어 사건 수를 바로잡는다
   원시 행은 41건이었지만 Transaction ID 로 묶으면 3건이다.
     T1 07:31:04  생성
     T2 07:38:41  이름 변경 (report.docx -> quarter.docx)
     T3 07:39:52  삭제

6. $J 로 독립 확증
   Import-Csv usn.csv | Where-Object { $_.EntryNumber -eq '128441' } |
     Sort-Object Usn | Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName

   0x4a1a840  2026-03-14 07:38:41Z  RenameOldName        report.docx
   0x4a1a9c0  2026-03-14 07:38:41Z  RenameNewName|Close  quarter.docx
   0x4a1b8c0  2026-03-14 07:39:52Z  FileDelete|Close     quarter.docx

   RenameOldName/RenameNewName 짝의 ParentEntryNumber 도 9114 로 동일.
   $LogFile 판정과 일치한다. 확정.

7. $MFT 최종 상태
   Import-Csv mft.csv | Where-Object { $_.EntryNumber -eq '128441' }
   -> InUse=False, FileName=quarter.docx, ParentPath=.\Users\jhkim\Documents
   $MFT 에는 최종 이름만 남아 있다. 원래 이름은 로그에서만 나온다.

8. 시간대
   07:39:52 UTC = 16:39:52 KST

정답: \Users\jhkim\Documents\report.docx (EntryNumber 128441)
      2026-03-14 16:38:41 KST 에 quarter.docx 로 이름 변경 (같은 폴더, 이동 아님)
      2026-03-14 16:39:52 KST 삭제
```

2단계와 4단계가 두 번의 실패다. **`$MFT`를 안 줘서 경로가 비었고, 부모 레코드 번호를 안 봐서 rename을 move로 오판했다.** 세 파일을 모두 넣고 부모 엔트리 컬럼을 확인하는 것 — 이 두 가지가 이 도구의 사용법 전부라고 봐도 된다.

## 막혔을 때 다음 체크

1. `$MFT`를 입력에 넣었는가 — 경로가 비면 100% 이것이다
2. `$UsnJrnl` 본체가 아니라 ADS `:$J`를 넣었는가
3. 추출 검산을 했는가 — `$MFT`는 `FILE`, `$LogFile`은 `RSTR`
4. `$LogFile`과 `$J`를 **둘 다** 넣었는가 — 커버 구간이 다르다
5. 정렬을 `LSN`/`USN`으로 했는가, 시각으로 하고 있지 않은가
6. rename인지 move인지 **부모 레코드 번호**로 확인했는가
7. `Transaction ID`로 묶어 사건 수를 셌는가
8. `EntryNumber` + `SequenceNumber` 둘 다로 파일을 특정했는가
9. 시간대를 파싱 전에 고정하고, 변환을 두 번 하지 않았는가
10. SQL을 짜기 전에 `.tables` / `.schema`를 읽었는가
11. `$LogFile`에 사건이 없으면 → 이미 덮였을 가능성. `$J`와 `$MFT`, `INDX` 슬랙으로 전환
12. 도구를 못 쓰는 상황이면 → `MFTECmd -f "$J" -m "$MFT"`로 최소한 사건 목록은 만든다

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$MFT`의 부모 레코드 참조 구조 — 경로 복원에 `$MFT`가 필요한 이유
- SRC-013 — Microsoft Learn, Change Journals: `$UsnJrnl`이 `$Extend\$UsnJrnl:$J` ADS에 있고 `USN_REASON` 플래그로 사건을 표현한다는 근거
- SRC-004 — Eric Zimmerman 문서: 대안 경로인 MFTECmd의 `-f`/`-m` 옵션과 `$J` 파싱 시 경로 복원, Timeline Explorer 사용법
- **NTFS Log Tracker의 화면 구성·탭 이름·버튼 라벨·출력 컬럼명·SQLite 테이블 스키마는 버전에 따라 다르므로 실제 화면에서 확인할 것.** 이 글의 절차는 "세 입력을 준다 → 파싱한다 → DB/CSV로 저장한다 → 재질의한다"는 개념 단계로 서술했다. 번들 버전은 `tools/manifest.json` 기준 v1.9다
- SQL 예시의 `<...>` 자리 이름은 반드시 `.tables` / `.schema` / `PRAGMA table_info()` 로 확인한 실제 이름으로 바꿔 쓸 것
- `$LogFile` 연산 이름의 표기는 파서·NTFS 버전에 따라 다르다. 판정은 `$UsnJrnl`·`$MFT`와 교차검증할 것
