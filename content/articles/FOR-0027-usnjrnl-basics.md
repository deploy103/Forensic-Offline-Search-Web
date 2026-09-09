---
id: FOR-0027
title: "$UsnJrnl($J)로 삭제·생성·이름변경 흔적 복원하기"
slug: "usnjrnl-basics"
category: "디스크/NTFS"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$UsnJrnl", "$J", "$Max", "USN_RECORD", "USN Journal", "$Extend"]
file_paths: ["C:\\$Extend\\$UsnJrnl", "C:\\$Extend\\$UsnJrnl:$J", "$Extend\\$UsnJrnl:$Max"]
registry_paths: []
event_ids: []
protocols: []
tools: ["MFTECmd", "NTFS Log Tracker", "FTK Imager", "Arsenal Image Mounter", "Timeline Explorer", "fsutil"]
commands: ["MFTECmd.exe -f \"C:\\case\\$J\" --csv .", "fsutil usn queryjournal C:", "fsutil usn readjournal C: csv", "Import-Csv j.csv | Where-Object { $_.UpdateReasons -match 'FileDelete' }"]
regex_patterns: ["FileDelete", "RenameOldName|RenameNewName", "\\.(zip|7z|rar|exe|ps1)$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Usn", "UpdateTimestamp", "UpdateReasons", "FileName", "EntryNumber", "ParentEntryNumber", "SequenceNumber", "FileAttributes"]
file_formats: ["ntfs"]
primary_terms: ["$UsnJrnl", "UsnJrnl", "$J", "USN Journal", "change journal", "usn 저널"]
keywords: ["UsnJrnl", "$J", "USN Journal", "USN_REASON", "FileDelete", "삭제 흔적", "이름 변경", "change journal", "파일 생성 기록"]
aliases: ["usnjrnl", "usn 저널", "$J", "삭제 파일", "삭제 흔적 찾기", "파일 지운 기록", "이름 바꾼 기록", "change journal"]
symptom_keywords: ["삭제된 파일 이름을 알고 싶다", "휴지통에 없다", "파일이 사라졌다", "이름을 바꿨는지", "언제 지웠는지", "MFT에 없는 파일", "$J 파일이 크다"]
related: ["FOR-0021", "FOR-0001"]
source_ids: ["SRC-013", "SRC-004", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`$Extend\$UsnJrnl`의 `$J` 스트림은 볼륨의 모든 파일 변경을 시간순으로 기록하므로, **MFT에서 이미 사라진 파일의 이름과 삭제 시각까지 남아 있는 유일한 artifact**다 — `USN_REASON`의 `FileDelete`/`RenameOldName`만 걸러도 사건 흐름이 나온다.

## 개념

NTFS의 Change Journal(변경 저널)은 파일이 생성·수정·삭제·이름변경될 때마다 레코드 하나를 추가하는 **append-only 로그**다.

```text
$Extend\$UsnJrnl
  ├─ :$J     ← 저널 레코드 본문 (분석 대상)
  └─ :$Max   ← 저널 최대 크기·할당 정보 (메타데이터)
```

`$J`와 `$Max`는 **ADS(대체 데이터 스트림)** 이다. 그래서 파일 목록에 `$UsnJrnl`만 보이고 실제 데이터는 `$UsnJrnl:$J`에 있다.

`$MFT`와의 결정적 차이:

| | `$MFT` | `$UsnJrnl:$J` |
| --- | --- | --- |
| 기록 방식 | 파일당 **현재 상태 1개** | 변경마다 **레코드 1개 추가** |
| 삭제된 파일 | 레코드가 남지만 **재사용되면 소실** | 삭제 사건 자체가 기록됨 |
| 이름 변경 | 최종 이름만 | **변경 전·후 이름 모두** |
| 시간 정보 | MACB 8개 | 변경 시각 1개 (변경마다) |
| 순서 | 없음 | **USN 번호로 완전한 순서** |

즉 `$MFT`는 "지금 무엇이 있나", `$J`는 "무슨 일이 있었나"에 답한다. 삭제 관련 문제에서는 `$J`가 우선이다.

`$J`는 **sparse 파일**이다. 논리 크기가 수십 GB로 보이더라도 실제 할당은 보통 수십~수백 MB다. 오래된 레코드는 앞쪽부터 잘려 나가므로 **보존 기간이 유한하다**(활동량에 따라 며칠~몇 주).

## 파일 / 경로

| 상황 | 추출 방법 |
| --- | --- |
| 디스크 이미지 (E01/RAW) | FTK Imager → 볼륨 → `[root]` → `$Extend` → `$UsnJrnl` 선택 → `Export Files`. `$J` 스트림이 별도 항목으로 보인다 |
| 이미지 마운트 | Arsenal Image Mounter로 마운트 후 FTK Imager |
| 라이브 시스템 | KAPE (`!SANS_Triage` 타깃에 포함), 또는 관리자 권한 `fsutil` |
| Sleuth Kit | `fls -o <offset> image.dd`로 `$Extend` 레코드 번호 확인 후 `icat -o <offset> image.dd <num>-128-<id>` |

CTF에서는 대개 `$J`(또는 `UsnJrnl_$J`) 파일 하나만 첨부된다.

라이브 시스템에서 저널 상태만 빠르게 보려면:

```powershell
# 관리자 권한 필요
fsutil usn queryjournal C:
```

```text
USN 저널 ID        : 0x01dc7f8e2a3b4c5d
첫 USN             : 0x0000000012340000
다음 USN           : 0x00000000567a1b20
최소 USN           : 0x0000000012340000
최대 USN           : 0x00000000ffffffff
최대 크기          : 0x0000000002000000    (32 MB)
할당 델타          : 0x0000000000400000
```

`최대 크기`가 작을수록 오래된 기록이 빨리 사라진다.

## 주요 필드

파서(MFTECmd / NTFS Log Tracker)가 내놓는 컬럼이다.

| 컬럼 | 의미 | 실전 활용 |
| --- | --- | --- |
| `Usn` | **저널 내 오프셋 겸 순번** | 값이 작을수록 과거. 시각이 같을 때 순서 판정의 기준 |
| `UpdateTimestamp` | 변경 시각 (FILETIME, **UTC**) | 타임라인의 축 |
| `UpdateReasons` | **무슨 일이 있었나** (비트 플래그, 아래 표) | 가장 중요한 필터 대상 |
| `FileName` | 대상 파일 이름 (**경로 없음**) | 검색 대상 |
| `EntryNumber` | 대상의 MFT 레코드 번호 | `$MFT`와 조인하는 키 |
| `SequenceNumber` | 레코드 재사용 횟수 | `EntryNumber`가 같아도 값이 다르면 다른 파일 |
| `ParentEntryNumber` | 부모 디렉터리의 MFT 레코드 번호 | **전체 경로 복원의 열쇠** |
| `ParentSequenceNumber` | 부모의 재사용 횟수 | 위와 동일 |
| `FileAttributes` | 파일 속성 | `Directory` 여부, `Hidden`, `Archive` |
| `SourceInfo` | 변경 유발 주체 | 백업·복제 소프트웨어가 유발한 변경 구분 |
| `SecurityId` | 보안 기술자 ID | 권한 변경 추적 |

`FileName`에 **경로가 없다**는 점이 중요하다. 경로가 필요하면 `ParentEntryNumber`를 `$MFT`의 `EntryNumber`와 조인해야 한다.

### USN_REASON 플래그

| 값 | 이름 | 의미 |
| --- | --- | --- |
| `0x00000001` | `DATA_OVERWRITE` | 기존 데이터 덮어쓰기 |
| `0x00000002` | `DATA_EXTEND` | 데이터 추가 (파일 커짐) |
| `0x00000004` | `DATA_TRUNCATION` | 데이터 잘림 |
| `0x00000010` | `NAMED_DATA_OVERWRITE` | **ADS** 데이터 덮어쓰기 |
| `0x00000020` | `NAMED_DATA_EXTEND` | ADS 데이터 추가 |
| `0x00000040` | `NAMED_DATA_TRUNCATION` | ADS 데이터 잘림 |
| `0x00000100` | **`FILE_CREATE`** | **파일/디렉터리 생성** |
| `0x00000200` | **`FILE_DELETE`** | **파일/디렉터리 삭제** |
| `0x00000400` | `EA_CHANGE` | 확장 속성 변경 |
| `0x00000800` | `SECURITY_CHANGE` | 권한/소유자 변경 |
| `0x00001000` | **`RENAME_OLD_NAME`** | **이름 변경 — 변경 전 이름** |
| `0x00002000` | **`RENAME_NEW_NAME`** | **이름 변경 — 변경 후 이름** |
| `0x00004000` | `INDEXABLE_CHANGE` | 색인 대상 여부 변경 |
| `0x00008000` | `BASIC_INFO_CHANGE` | **타임스탬프/속성 변경 (timestomp 신호)** |
| `0x00010000` | `HARD_LINK_CHANGE` | 하드링크 변경 |
| `0x00020000` | `COMPRESSION_CHANGE` | 압축 속성 변경 |
| `0x00040000` | `ENCRYPTION_CHANGE` | 암호화 속성 변경 |
| `0x00080000` | `OBJECT_ID_CHANGE` | 오브젝트 ID 변경 |
| `0x00100000` | `REPARSE_POINT_CHANGE` | 재분석 지점 변경 (심볼릭 링크 등) |
| `0x00200000` | `STREAM_CHANGE` | ADS 추가/삭제 |
| `0x00400000` | `TRANSACTED_CHANGE` | TxF 트랜잭션 변경 |
| `0x80000000` | `CLOSE` | **핸들 닫힘 — 그 변경 묶음의 종료 표시** |

플래그는 **OR로 합쳐진다.** 파서는 보통 `FileCreate|Close` 처럼 문자열로 풀어 준다.

### 사건 유형별 시그니처

| 실제로 일어난 일 | `$J`에 남는 패턴 |
| --- | --- |
| 파일 새로 만들고 씀 | `FileCreate` → `DataExtend` → `DataExtend\|Close` |
| 파일 삭제 | `FileDelete\|Close` (직전에 `DataTruncation` 등이 붙을 수 있음) |
| 이름 변경 | `RenameOldName` → `RenameNewName\|Close` (**두 레코드가 짝**) |
| 휴지통으로 이동 | `RenameOldName`/`RenameNewName` + `$Recycle.Bin` 하위의 `$I`/`$R` 생성 |
| 덮어쓰기(안티포렌식) | `DataOverwrite` 반복 → `FileDelete` |
| 파일 복사 | 원본 없음, 대상에 `FileCreate` + `DataExtend` |
| 파일 이동(같은 볼륨) | `RenameOldName`/`RenameNewName` (`ParentEntryNumber`가 바뀐다) |
| 파일 이동(다른 볼륨) | 원본 볼륨 `FileDelete` + 대상 볼륨 `FileCreate` |
| timestomp | `BasicInfoChange` 단독 |
| ADS로 숨김 | `StreamChange`, `NamedDataExtend` |

**이름 변경은 `RenameOldName`과 `RenameNewName`이 같은 `EntryNumber`로 연속해 나타난다.** 변경 전 이름을 찾을 때 이 짝을 본다.

## 빠른 명령

```powershell
# MFTECmd — $J 파싱 (가장 빠름)
MFTECmd.exe -f 'C:\case\$J' --csv "C:\case\out" --csvf usn.csv

# $MFT와 함께 주면 경로를 복원해 준다
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv "C:\case\out" --csvf usn.csv
```

`-m`으로 `$MFT`를 함께 넘기면 `ParentPath`가 채워진다. **경로가 필요하면 항상 함께 준다.**

```powershell
# 삭제된 항목만
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'FileDelete' } |
  Select-Object UpdateTimestamp, FileName, ParentPath, EntryNumber |
  Sort-Object UpdateTimestamp

# 특정 확장자의 삭제
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'FileDelete' -and $_.FileName -match '\.(zip|7z|rar|xlsx|docx)$' }

# 이름 변경 짝 찾기
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'Rename' } |
  Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName, EntryNumber |
  Sort-Object Usn

# 특정 시간대의 모든 변경
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateTimestamp -ge '2026-03-14 07:20:00' -and
                 $_.UpdateTimestamp -le '2026-03-14 07:30:00' } |
  Sort-Object Usn | Format-Table UpdateTimestamp, UpdateReasons, FileName

# timestomp 후보
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'BasicInfoChange' -and
                 $_.UpdateReasons -notmatch 'Data|Create|Delete' }
```

```bash
# Linux/CLI에서 CSV 처리
rg 'FileDelete' usn.csv | rg -i '\.(zip|exe|ps1)' | head -20

# 확장자별 삭제 개수
rg 'FileDelete' usn.csv | awk -F, '{print $NF}' | sort | uniq -c | sort -nr | head

# 특정 파일의 전체 생애
rg -i 'secret' usn.csv
```

GUI로는 **NTFS Log Tracker**가 `$LogFile`·`$J`·`$MFT`를 함께 읽어 사건 단위로 묶어 보여 준다. 결과 CSV는 Timeline Explorer로 열어 필터링한다.

## 함께 보는 artifact

| `$J`에서 얻은 것 | 함께 볼 것 | 확인할 것 |
| --- | --- | --- |
| 삭제된 파일 이름 | `$MFT` ([FOR-0021](./mft-basics.html)) | 레코드가 남아 있는가, MACB 시각 |
| 삭제 시각 | `$LogFile` | 같은 트랜잭션의 상세 (보존 기간은 더 짧다) |
| 삭제 시각 | `$Recycle.Bin`의 `$I`/`$R` | 휴지통 경유였는가, 원래 경로 |
| `ParentEntryNumber` | `$MFT`의 `EntryNumber` | 전체 경로 복원 |
| 파일 이름 | Prefetch / Amcache / UserAssist ([FOR-0061](./userassist.html)) | 그 파일이 실행되었는가 |
| 파일 이름 | LNK / Jump List / RecentDocs | 사용자가 열었는가 |
| 시각 | EVTX 4688 ([FOR-0083](./event-4624-logon.html)) | 어떤 프로세스가 그 변경을 유발했는가 |
| 압축 파일 생성 | 브라우저 Downloads ([FOR-0191](./chrome-history.html)) | 어디서 받았는가 / 어디로 보냈는가 |
| `BasicInfoChange` 단독 | `$MFT`의 `$SI` vs `$FN` 시각 | timestomp 확정 |

## 흔한 실수

- **`$UsnJrnl`만 추출하고 `$J`를 놓치는 것.** 데이터는 ADS인 `:$J`에 있다. FTK Imager에서 `$J` 항목을 따로 선택해야 한다.
- **`$J`의 논리 크기에 놀라는 것.** sparse 파일이라 수십 GB로 표시되지만 실제 데이터는 훨씬 작다. 그대로 export하면 앞쪽이 0으로 채워진 큰 파일이 나오는데, 파서는 이를 정상 처리한다.
- **경로를 기대하는 것.** `FileName`은 이름만이다. 경로는 `-m $MFT`로 조인해야 나온다.
- **`EntryNumber`만으로 파일을 동일시하는 것.** MFT 레코드는 재사용된다. `SequenceNumber`까지 같아야 같은 파일이다.
- **`FileDelete`만 보는 것.** 안티포렌식은 `DataOverwrite` 반복이나 `RenameOldName`(다른 이름으로 위장) 형태로 나타난다.
- **`RenameNewName`만 보고 원래 이름을 놓치는 것.** 직전 `RenameOldName` 레코드에 원래 이름이 있다.
- **시간대.** `UpdateTimestamp`는 FILETIME(UTC)다. MFTECmd CSV도 UTC로 출력한다. KST 답이 필요하면 +9시간.
- **저널 보존 한계를 무시하는 것.** `$J`에 없다면 정말 없었던 것이 아니라 **이미 잘려 나갔을** 수 있다. `fsutil usn queryjournal`의 `첫 USN`이 그 경계다.
- **`$J`가 비활성된 볼륨.** 저널은 볼륨별 설정이다. USB나 일부 서버 볼륨에서는 꺼져 있을 수 있다.
- **`CLOSE` 플래그를 별개 사건으로 세는 것.** 같은 변경의 종료 표시다. 사건 수를 셀 때 중복이 된다.
- **`Usn` 순서를 무시하고 타임스탬프만 정렬하는 것.** 같은 초에 여러 변경이 몰리면 타임스탬프로는 순서를 알 수 없다. `Usn`이 정확한 순서다.

## mini example

```text
문제:
"휴지통에는 없는데 유출된 압축파일이 있었다고 합니다.
 파일 이름과 삭제 시각, 그리고 원래 이름을 구하세요."
첨부: $J, $MFT

1. 파싱 (경로 복원을 위해 $MFT를 함께)
   MFTECmd.exe -f "$J" -m "$MFT" --csv out --csvf usn.csv
   -> 412,880 레코드

2. 첫 시도 (실패):
   Import-Csv out\usn.csv | Where-Object { $_.FileName -match '\.zip$' }
   -> 1,204건. 대부분 브라우저 캐시와 설치 파일. 특정이 안 된다.

3. 접근 변경 — 삭제 사건만, 사용자 폴더로 한정
   Import-Csv out\usn.csv |
     Where-Object { $_.UpdateReasons -match 'FileDelete' -and
                    $_.ParentPath -match 'Users\\jhkim' -and
                    $_.FileName -match '\.(zip|7z|rar)$' } |
     Select-Object Usn, UpdateTimestamp, FileName, ParentPath |
     Sort-Object Usn

   Usn        UpdateTimestamp           FileName            ParentPath
   0x4a1b8c0  2026-03-14 07:39:52Z      report_final.7z     .\Users\jhkim\Documents

   1건. 이것이 후보.

4. 이 파일의 전체 생애 추적 — EntryNumber로 검색
   먼저 EntryNumber 확인 -> 128441

   Import-Csv out\usn.csv |
     Where-Object { $_.EntryNumber -eq 128441 } |
     Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName |
     Sort-Object Usn

   Usn        UpdateTimestamp        UpdateReasons                FileName
   0x4a11200  2026-03-14 07:31:04Z   FileCreate                   customer_db_2026.7z
   0x4a11340  2026-03-14 07:31:04Z   FileCreate|DataExtend        customer_db_2026.7z
   0x4a115a0  2026-03-14 07:33:18Z   DataExtend|Close             customer_db_2026.7z
   0x4a1a840  2026-03-14 07:38:41Z   RenameOldName                customer_db_2026.7z   <-- 원래 이름
   0x4a1a9c0  2026-03-14 07:38:41Z   RenameNewName|Close          report_final.7z       <-- 위장 이름
   0x4a1b8c0  2026-03-14 07:39:52Z   FileDelete|Close             report_final.7z

   완전한 사건 흐름:
     07:31:04  customer_db_2026.7z 생성
     07:33:18  쓰기 완료 (2분 14초간 압축)
     07:38:41  report_final.7z 로 이름 변경 (위장)
     07:39:52  삭제

5. 교차검증 — $MFT
   Import-Csv mft.csv | Where-Object { $_.EntryNumber -eq 128441 }
   -> InUse=False, FileName=report_final.7z, FileSize=284,113,920

   $MFT에는 최종 이름(report_final.7z)만 남아 있다.
   원래 이름 customer_db_2026.7z 는 $J 에서만 나온다. <- $J를 봐야 하는 이유

6. 교차검증 — 휴지통
   RBCmd.exe -d "$Recycle.Bin" --csv .
   -> 해당 파일 없음. 즉 Shift+Delete(직접 삭제)였다.
      문제 지문의 "휴지통에는 없다"와 일치.

7. pivot — 어떻게 유출됐나
   같은 시간대(07:33~07:39) $J 전체를 훑는다
   Import-Csv out\usn.csv |
     Where-Object { $_.UpdateTimestamp -ge '2026-03-14 07:33:00' -and
                    $_.UpdateTimestamp -le '2026-03-14 07:40:00' } |
     Sort-Object Usn | Format-Table UpdateTimestamp, UpdateReasons, FileName

   07:35:12  FileCreate|Close   rclone.conf
   07:35:40  FileCreate|Close   rclone.exe
   -> 클라우드 업로드 도구가 같은 시간대에 생성됨

정답: report_final.7z (원래 이름 customer_db_2026.7z),
      삭제 시각 2026-03-14 07:39:52 UTC = 16:39:52 KST
```

4단계가 이 artifact의 존재 이유다. **`$MFT`만 봤다면 최종 이름만 알고 "원래 이름"에 답할 수 없었다.** `RenameOldName`/`RenameNewName` 짝이 위장을 드러냈다.

## 출처

- SRC-013 — Microsoft Learn, Change Journals: `USN_RECORD` 구조와 `USN_REASON_*` 플래그 값
- SRC-004 — Eric Zimmerman 문서: MFTECmd의 `$J` 파싱과 `-m` 옵션(경로 복원), CSV 컬럼
- SRC-014 — Microsoft Learn, File Times: `UpdateTimestamp`가 FILETIME(UTC)임의 근거
