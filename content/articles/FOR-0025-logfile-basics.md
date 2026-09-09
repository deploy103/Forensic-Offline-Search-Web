---
id: FOR-0025
title: "$LogFile 기본: NTFS 트랜잭션 로그의 RSTR/RCRD와 redo·undo"
slug: "logfile-basics"
category: "디스크/NTFS"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["$LogFile", "RSTR", "RCRD", "LSN", "redo", "undo", "restart area", "log record", "transaction"]
file_paths: ["C:\\$LogFile", "$LogFile"]
registry_paths: []
event_ids: []
protocols: []
tools: ["NTFS Log Tracker", "FTK Imager", "Sleuth Kit", "Arsenal Image Mounter", "HxD", "Timeline Explorer", "chkdsk"]
commands: ["icat -o 2048 image.dd 2 > '$LogFile'", "chkdsk /L", "strings -e l '$LogFile' | rg -i secret", "xxd -l 16 '$LogFile'", "fls -o 2048 image.dd"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["LSN", "Previous LSN", "Undo LSN", "Transaction ID", "Redo Operation", "Undo Operation", "Target Attribute", "Target VCN", "Target LCN", "MFT Entry"]
file_formats: ["ntfs"]
primary_terms: ["$LogFile", "LogFile", "RCRD", "RSTR"]
keywords: ["$LogFile", "NTFS 트랜잭션 로그", "RSTR", "RCRD", "LSN", "redo", "undo", "restart area", "log record", "저널", "메타데이터 변경 이력"]
aliases: ["logfile", "$logfile", "ntfs 로그", "트랜잭션 로그", "rcrd", "rstr", "lsn", "ntfs 저널 로그"]
symptom_keywords: ["$UsnJrnl에 기록이 없다", "삭제 흔적이 더 필요하다", "$LogFile을 어떻게 보나", "예전 파일 이름을 알고 싶다", "저널이 잘려 나갔다", "strings로 안 나온다"]
related: ["FOR-0021", "FOR-0026", "FOR-0029"]
source_ids: ["SRC-005", "SRC-013", "SRC-032"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`$LogFile`(MFT 레코드 2번)은 NTFS가 메타데이터 변경을 커밋하기 전에 남기는 트랜잭션 로그이며, **`$UsnJrnl`보다 보존 기간이 훨씬 짧은 대신 훨씬 상세하다** — undo 데이터에 "변경 직전의 값"이 그대로 들어 있어 예전 파일 이름, 예전 타임스탬프, 삭제된 색인 항목까지 복원된다.

## 개념

NTFS는 저널링 파일시스템이다. 파일 하나를 만들 때도 MFT 레코드 할당, 비트맵 갱신, 부모 디렉터리 색인 추가가 **하나의 트랜잭션**으로 묶여야 하고, 중간에 전원이 끊기면 되돌릴 수 있어야 한다. 그 목적으로 변경 **직전**에 로그를 먼저 쓴다(write-ahead logging).

```text
$LogFile 구조

[ restart area ]   RSTR 페이지. 복구 시작점, 마지막 체크포인트 정보
[ log record area ] RCRD 페이지가 순환(wrap)하며 채워진다
                    각 페이지 안에 여러 개의 log record
```

| 항목 | 값 |
| --- | --- |
| MFT 레코드 번호 | **2** |
| 파일 이름 | `$LogFile` (볼륨 루트) |
| 페이지 시그니처 | `RSTR` = `52 53 54 52`, `RCRD` = `52 43 52 44` |
| 페이지 크기 | 보통 4096바이트 |
| 기록 방식 | 원형 버퍼. 끝에 도달하면 앞을 덮어쓴다 |
| 순서 키 | **LSN** (Log Sequence Number). 단조 증가 |
| resident 여부 | 항상 non-resident |

`RCRD`/`RSTR` 페이지도 MFT 레코드와 동일한 **Update Sequence Array(fixup)** 를 쓴다. 512바이트 경계의 마지막 2바이트가 USN으로 덮여 있으므로 raw hex를 그대로 파싱하면 안 된다 ([FOR-0020](./ntfs-structure.html)).

### redo와 undo

각 log record는 같은 변경에 대해 두 벌의 데이터를 갖는다.

| | 내용 | 포렌식 가치 |
| --- | --- | --- |
| **redo** | 변경 **후** 값. 복구 시 다시 적용해 트랜잭션을 완료시킨다 | "무엇으로 바뀌었나" |
| **undo** | 변경 **전** 값. 복구 시 되돌려 트랜잭션을 취소한다 | **"무엇이었나" — 이쪽이 더 귀하다** |

`undo`가 이 artifact의 존재 이유다. 파일 이름을 `a.7z` → `b.7z`로 바꾸면 색인 항목 삭제 로그의 undo에 `a.7z`의 `$FILE_NAME` 전체(이름 + 4개 타임스탬프 + 크기)가 그대로 들어간다. `$MFT`에는 최종 상태만 남는데, `$LogFile`에는 **중간 상태들이 남는다.**

### `$UsnJrnl`과의 트레이드오프

| | `$LogFile` | `$UsnJrnl:$J` |
| --- | --- | --- |
| 목적 | 파일시스템 무결성 복구 | 애플리케이션용 변경 통지 |
| 기록 단위 | **속성·색인 단위의 저수준 연산** | 파일 단위의 사건 요약 |
| 상세도 | **매우 높음** (변경 전 값 포함) | 낮음 (플래그 + 이름) |
| 크기 | 기본 수십 MB 수준으로 **고정 상한** | 볼륨에 따라 수십~수백 MB |
| 쓰기량 | 파일 1개 생성에 로그 레코드 수십 개 | 파일 1개 생성에 레코드 2~3개 |
| **보존 기간** | **짧다.** 바쁜 시스템에서 수십 분~수 시간 | 길다. 수일~수 주 |
| 경로 정보 | 부모 레코드 번호 (조인 필요) | 부모 레코드 번호 (조인 필요) |
| 파서 난이도 | 높다 (전용 도구 필요) | 낮다 (MFTECmd로 충분) |

**실전 순서**: 사건이 오래됐으면 `$UsnJrnl`부터 ([FOR-0027](./usnjrnl-basics.html)), `$UsnJrnl`에서 이미 잘려 나갔거나 더 상세한 근거가 필요하면 `$LogFile`. 사건이 이미지 획득 직전이면 `$LogFile`이 가장 풍부하다.

## 파일 / 경로

| 상황 | 추출 방법 |
| --- | --- |
| 디스크 이미지 (E01/RAW) | FTK Imager로 열고 볼륨 `[root]` → `$LogFile` 선택 → Export Files ([FOR-0016](./ftk-imager-open-image.html)) |
| 이미지 마운트 | Arsenal Image Mounter로 읽기 전용 마운트 후 FTK Imager ([FOR-0017](./arsenal-image-mounter.html)) |
| Sleuth Kit | `icat -o <섹터오프셋> image.dd 2 > '$LogFile'` (레코드 번호 2) |
| 라이브 시스템 | KAPE의 트리아지 타깃에 포함된다. 일반 복사는 불가 |
| Autopsy | 파일 트리에서 볼륨 루트의 `$LogFile`을 Extract ([FOR-0018](./autopsy-ingest.html)) |

로그 크기는 라이브 시스템에서 확인할 수 있다.

```text
chkdsk /L
```

크기 상한이 곧 보존 기간이다. 볼륨 크기에 따라 자동 결정되며 큰 볼륨에서 대략 64MB 수준이지만, **정확한 값은 `chkdsk /L` 출력으로 확인한다.** 이 값이 작으면 몇 분치 기록만 남는다.

## 주요 필드

### log record의 핵심 필드

파서가 행 단위로 풀어 주는 값들이다.

| 필드 | 의미 | 실전 활용 |
| --- | --- | --- |
| `LSN` | 이 레코드의 순번 | **정확한 순서.** 같은 초에 몰린 사건의 전후 판정 |
| `Previous LSN` | 같은 클라이언트의 직전 레코드 | 로그 체인 추적 |
| `Undo LSN` | 되돌릴 대상 레코드 | 트랜잭션 복구 경로 |
| `Transaction ID` | 트랜잭션 식별자 | **같은 ID를 묶으면 하나의 사용자 행위**가 된다 |
| `Redo Operation` | 변경 후 연산 | 무슨 일을 했나 (아래 표) |
| `Undo Operation` | 되돌리기 연산 | 짝을 이룬다 |
| `Target Attribute` | 대상 속성 (열린 속성 테이블 인덱스) | `$DATA`인가 `$INDEX_ALLOCATION`인가 |
| `MFT Entry` / `Target VCN` / `Target LCN` | 대상 레코드·클러스터 | `$MFT`와 조인하는 키 |
| redo/undo 데이터 | 변경 후/전 원본 바이트 | **여기서 파일 이름·타임스탬프가 나온다** |

`Transaction ID`로 묶는 것이 핵심 기술이다. 파일 하나를 지우면 레코드 해제·색인 항목 삭제·비트맵 해제가 **같은 트랜잭션 ID**로 여러 행에 흩어져 나온다.

### 어떤 연산이 남는가

연산 이름은 파서 출력에 문자열로 나타난다. 실전에서 판정에 쓰는 것만 정리한다.

| 연산 이름 | 무슨 일 |
| --- | --- |
| `InitializeFileRecordSegment` | **MFT 레코드 초기화 = 파일/폴더 생성** |
| `DeallocateFileRecordSegment` | **MFT 레코드 해제 = 파일/폴더 삭제** |
| `CreateAttribute` / `DeleteAttribute` | 속성 추가/제거 (ADS 생성·제거 포함) |
| `UpdateResidentValue` | resident 속성 값 변경 (**`$SI` 타임스탬프 변경이 여기 온다**) |
| `UpdateNonresidentValue` | non-resident 데이터 변경 |
| `UpdateMappingPairs` | data run 목록 변경 (파일 크기 증감) |
| `SetNewAttributeSizes` | 속성 크기 갱신 |
| `AddIndexEntryRoot` / `AddIndexEntryAllocation` | **부모 폴더 색인에 항목 추가 = 이름이 그 폴더에 등장** |
| `DeleteIndexEntryRoot` / `DeleteIndexEntryAllocation` | **부모 폴더 색인에서 항목 제거 = 이름이 사라짐** |
| `UpdateFileNameRoot` / `UpdateFileNameAllocation` | 색인 안의 `$FILE_NAME` 갱신 |
| `WriteEndOfIndexBuffer` | 색인 버퍼 정리 |
| `SetBitsInNonresidentBitMap` | `$Bitmap` 비트 설정 = **클러스터 할당** |
| `ClearBitsInNonresidentBitMap` | `$Bitmap` 비트 해제 = **클러스터 해제** |
| `OpenNonresidentAttribute` | 속성 열기. 열린 속성 테이블에 등록 |
| `CommitTransaction` / `ForgetTransaction` | 트랜잭션 확정 / 폐기 |
| `CompensationLogRecord` | undo가 실제로 수행됨 (롤백 발생) |
| `Noop` | 채움용. 무시한다 |

연산에는 숫자 코드도 있지만 **버전·파서마다 표기가 다르므로 이름 문자열로 판단한다.**

### 사건 유형별 연산 조합

| 실제로 일어난 일 | `$LogFile`에 남는 조합 |
| --- | --- |
| 파일 생성 | `InitializeFileRecordSegment` + `AddIndexEntry*` + `SetBitsInNonresidentBitMap` |
| 파일 쓰기(크기 증가) | `UpdateMappingPairs` + `SetNewAttributeSizes` + `SetBitsInNonresidentBitMap` |
| 파일 삭제 | `DeallocateFileRecordSegment` + `DeleteIndexEntry*` + `ClearBitsInNonresidentBitMap` |
| 이름 변경 | 같은 부모에서 `DeleteIndexEntry*`(옛 이름) + `AddIndexEntry*`(새 이름) |
| 같은 볼륨 내 이동 | **부모 A**에서 `DeleteIndexEntry*` + **부모 B**에서 `AddIndexEntry*` |
| 폴더 생성 | `InitializeFileRecordSegment` + `$INDEX_ROOT` 관련 `CreateAttribute` |
| ADS 생성 | 이름 있는 `$DATA`에 대한 `CreateAttribute` |
| `$SI` 타임스탬프 변경 (timestomp) | `UpdateResidentValue` (대상 속성이 `$STANDARD_INFORMATION`) |
| 권한 변경 | `$SECURITY_DESCRIPTOR`/`$Secure` 관련 `UpdateResidentValue` |

이름 변경과 이동을 구분하는 지점은 **`DeleteIndexEntry`와 `AddIndexEntry`의 부모 레코드 번호가 같은가**다. 같으면 rename, 다르면 move다.

## 빠른 명령

```bash
icat -o 2048 image.dd 2 > '$LogFile'
```

```bash
# 추출 확인 — 첫 페이지가 RSTR 인지 본다
xxd -l 16 '$LogFile'
# 00000000: 5253 5452 2800 0900 0000 0000 0000 0000  RSTR(...........

# 로그 레코드 페이지 개수 대략 세기
rg -c --text 'RCRD' '$LogFile'

# 파일 이름은 UTF-16LE 다. 기본 strings 로는 안 나온다
strings -e l '$LogFile' | rg -i 'secret'

# 확장자로 훑기
strings -e l '$LogFile' | rg -i '\.(zip|7z|rar|exe|ps1|docx)$' | sort -u | head -40
```

```text
REM 라이브 시스템에서 로그 크기(=보존 기간 상한) 확인
chkdsk /L
```

정식 분석은 전용 파서로 한다.

| 파서 | 특징 | 출력 |
| --- | --- | --- |
| **NTFS Log Tracker** | `$LogFile` + `$UsnJrnl` + `$MFT`를 함께 입력해 사건 단위로 묶어 준다 | SQLite DB, CSV ([FOR-0026](./ntfs-log-tracker.html)) |
| **LogFileParser** | `$LogFile` 전용. 연산·트랜잭션 단위의 저수준 출력 | CSV |
| MFTECmd | **`$LogFile`은 지원하지 않는다.** `$MFT`/`$J`/`$Boot`/`$SDS` 전용 | CSV/JSON |
| `strings -e l` | 파서가 없을 때의 최후 수단. 이름 조각만 얻는다 | 텍스트 |

MFTECmd로 `$LogFile`을 열려는 시도가 흔한 실수다. 지원 대상이 아니다.

## 함께 보는 artifact

| `$LogFile`에서 얻은 것 | 함께 볼 것 | 확인할 것 |
| --- | --- | --- |
| 삭제 트랜잭션 시각 | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | 같은 삭제가 `FileDelete`로 남았는가 |
| undo의 옛 파일 이름 | `$MFT` ([FOR-0021](./mft-basics.html)) | 레코드가 남아 있는가, 최종 이름은 무엇인가 |
| `MFT Entry` 번호 | `MFTECmd --de <n>`, `istat` | 속성 원본 확인 |
| undo의 옛 타임스탬프 | `$SI` vs `$FN` ([FOR-0024](./si-vs-fn-timestamps.html)) | timestomp 전 값 복원 |
| `UpdateResidentValue` on `$SI` | `$J`의 `BasicInfoChange` | 시각 조작 확정 |
| 부모 레코드 번호 두 개 | 이동 경로 | 어디서 어디로 옮겼나 |
| 클러스터 해제 시각 | 미할당 영역 카빙 | 그 클러스터에 아직 내용이 남았나 |
| 트랜잭션 시각 | EVTX `4688` ([FOR-0083](./event-4624-logon.html)) | 어느 프로세스가 유발했나 |
| 파일 이름 | Prefetch / UserAssist ([FOR-0061](./userassist.html)) | 실행·열람 여부 |

## 흔한 실수

- **기본 `strings`로 파일 이름을 찾는 것.** NTFS 파일 이름은 **UTF-16LE**다. ASCII 모드 `strings`는 `s.e.c.r.e.t` 형태를 문자열로 인식하지 못해 놓친다. `strings -e l`(little-endian 16bit)을 쓴다.
- **MFTECmd에 `$LogFile`을 넣는 것.** 지원 대상이 아니다. NTFS Log Tracker 또는 LogFileParser를 쓴다.
- **`$UsnJrnl` 대신 `$LogFile`부터 여는 것.** 보존 기간이 훨씬 짧다. 며칠 전 사건이면 `$LogFile`에 아무것도 없을 가능성이 높다. `$J`를 먼저 보고, 부족하면 `$LogFile`로 내려온다.
- **`$LogFile`이 원형 버퍼임을 잊는 것.** 오래된 페이지는 새 로그로 덮인다. "기록이 없다"는 "그 일이 없었다"가 아니라 **"이미 덮였다"** 일 수 있다. `chkdsk /L`의 크기와 볼륨 활동량으로 보존 범위를 추정한다.
- **raw hex를 fixup 없이 파싱하는 것.** `RCRD`/`RSTR` 페이지도 512바이트 경계마다 마지막 2바이트가 USN으로 덮여 있다. 수동 파싱에서 오프셋이 밀리는 원인 1위다.
- **연산 하나를 사용자 행위 하나로 세는 것.** 파일 한 개 생성에도 레코드가 수십 개 나온다. **`Transaction ID`로 묶어야** 사용자 행위 단위가 된다.
- **rename과 move를 구분하지 않는 것.** 둘 다 `DeleteIndexEntry` + `AddIndexEntry` 조합이다. **부모 레코드 번호가 같으면 rename, 다르면 move**다.
- **redo만 읽는 것.** 옛 이름·옛 타임스탬프는 **undo** 쪽에 있다. `$LogFile`을 보는 이유의 절반이 undo다.
- **LSN 대신 시각으로 정렬하는 것.** 같은 초에 수십 개 레코드가 몰린다. 순서는 **LSN**이 정한다.
- **시각의 시간대를 확인하지 않는 것.** 로그에 실린 타임스탬프는 FILETIME(UTC 기준 100ns, 1601-01-01 epoch, Unix와 11644473600초 차이)이다. 파서 출력이 UTC인지 로컬인지 확인하고, KST 답이 필요하면 +9시간 한다.
- **`$LogFile`만으로 경로를 답하는 것.** 로그에는 부모 **레코드 번호**만 있다. 경로 문자열은 `$MFT`와 조인해야 나온다.
- **`Noop`·`CompensationLogRecord`를 사건으로 세는 것.** 전자는 채움, 후자는 롤백 수행 기록이다.

## mini example

```text
문제:
"사용자가 이미지 획득 30분 전에 파일 이름을 바꿔 위장했습니다.
 원래 이름을 구하세요.
 첨부: image.dd (파티션 오프셋 2048)"

1. $J 부터 시도 (정석 순서)
   fls -o 2048 image.dd | rg -i 'Extend'
   -> d/d 11-144-4:  $Extend
   fls -o 2048 image.dd 11
   -> r/r 27-128-3:  $UsnJrnl:$J      <- 이 "레코드-타입-ID" 를 그대로 icat 에 준다
   icat -o 2048 image.dd 27-128-3 > '$J'
   MFTECmd.exe -f '$J' -m '$MFT' --csv out --csvf usn.csv

   rg -i 'Rename' out\usn.csv | wc -l
   -> 0

   $J 가 이 볼륨에서 비활성이었다. 이름 변경 기록이 없다.
   -> $LogFile 로 내려간다.

2. 추출
   icat -o 2048 image.dd 2 > '$LogFile'
   xxd -l 16 '$LogFile'
   -> 00000000: 5253 5452 2800 0900 ...   "RSTR" 확인 (정상 추출)

   ls -l '$LogFile'
   -> 67,108,864 (64MB)

3. 첫 시도 (실패):
   strings '$LogFile' | rg -i '\.7z'
   -> 아무것도 안 나온다.

   왜 틀렸나: NTFS 파일 이름은 UTF-16LE 로 저장된다.
   ASCII 모드 strings 는 'r\0e\0p\0o\0r\0t\0' 를 문자열로 보지 않는다.

4. 정정 — 16bit little-endian 모드
   strings -e l '$LogFile' | rg -i '\.7z' | sort -u

   customer_db_2026.7z
   report_final.7z

   이름 두 개가 나왔다. 하지만 어느 쪽이 옛 이름인지, 같은 파일인지
   strings 로는 알 수 없다. 순서와 대상 레코드가 필요하다.

5. 파서로 정식 분석 — NTFS Log Tracker 에 $LogFile 과 $MFT 를 함께 입력
   ($MFT 를 함께 줘야 부모 레코드 번호가 경로로 풀린다)

   결과에서 두 이름이 등장하는 구간을 LSN 순으로 정렬하면:

   LSN         Redo Operation              Undo Operation              MFT Entry  이름
   ----------- --------------------------- --------------------------- ---------  ----
   0x1a4b2c10  DeleteIndexEntryAllocation  AddIndexEntryAllocation     9114       customer_db_2026.7z
   0x1a4b2c88  AddIndexEntryAllocation     DeleteIndexEntryAllocation  9114       report_final.7z
   0x1a4b2d00  UpdateFileNameAllocation    UpdateFileNameAllocation    128441     report_final.7z

   판정:
     - 대상 부모 레코드가 둘 다 9114 (같은 폴더) -> 이동이 아니라 rename
     - DeleteIndexEntry 가 먼저, AddIndexEntry 가 나중 -> 옛 이름은 삭제된 쪽
     - 옛 이름 = customer_db_2026.7z
     - 새 이름 = report_final.7z

6. undo 데이터에서 옛 $FILE_NAME 전체 복원
   DeleteIndexEntryAllocation 의 undo 에는 지워진 색인 항목,
   즉 옛 $FILE_NAME 속성 전체가 들어 있다.
   -> 이름 + 4개 타임스탬프 + 크기가 함께 나온다

   Created(FN) : 2026-03-14 07:31:04
   FileSize    : 284,113,920

7. 경로 확인 — $MFT 와 조인
   icat -o 2048 image.dd 0 > '$MFT'
   MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
   Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq '9114' } |
     Select-Object FileName, ParentPath
   -> Documents, .\Users\jhkim

   전체 경로: \Users\jhkim\Documents\customer_db_2026.7z

8. 시간대
   07:31:04 UTC = 16:31:04 KST

정답: 원래 이름 customer_db_2026.7z
      (\Users\jhkim\Documents, 생성 2026-03-14 16:31:04 KST)
```

3단계가 이 유형의 대표적 실패다. **`strings`를 ASCII 모드로 돌려 "아무것도 없다"고 결론 내리면 거기서 문제가 끝난다.** `-e l` 하나가 분기점이었고, 5단계에서 부모 레코드 번호가 같다는 점(9114)이 "이동이 아니라 rename"을 확정했다.

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$LogFile`이 MFT 레코드 2번의 예약 메타파일이라는 점과 레코드/속성 구조
- SRC-013 — Microsoft Learn, Change Journals: `$UsnJrnl`의 목적과 기록 단위 — `$LogFile`과의 역할·보존 기간 차이를 대조하는 근거
- SRC-032 — The Sleuth Kit 도구 문서: `icat`/`fls`로 메타파일을 레코드 번호로 추출하는 방법
- **연산 이름의 정확한 표기와 숫자 코드는 파서·NTFS 버전에 따라 다르다.** 표의 이름 문자열을 실제 파서 출력과 대조해 확인할 것
- `$LogFile`의 기본 크기와 페이지 크기는 볼륨·Windows 버전에 따라 다르다. `chkdsk /L`로 실제 값을 확인할 것
- `$LogFile` 내부 레코드 구조는 Microsoft가 공식 명세로 공개하지 않았다. 필드 해석은 파서 출력을 기준으로 하고, 오프셋 단위의 수동 파싱 결과는 반드시 `$MFT`/`$UsnJrnl`과 교차검증할 것
