---
id: FOR-0029
title: "$LogFile과 $UsnJrnl 교차검증: 한쪽에만 기록이 있을 때 무엇을 믿나"
slug: "logfile-usnjrnl-crosscheck"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$LogFile", "$UsnJrnl", "$J", "$MFT", "LSN", "LFS", "$Extend"]
file_paths: ["C:\\$LogFile", "C:\\$MFT", "C:\\$Extend\\$UsnJrnl:$J", "C:\\$Extend\\$UsnJrnl:$Max"]
registry_paths: []
event_ids: []
protocols: []
tools: ["NTFS Log Tracker", "MFTECmd", "FTK Imager", "Sleuth Kit", "Timeline Explorer", "fsutil"]
commands: ["icat -o 2048 image.dd 2 > LogFile", "icat -o 2048 image.dd 0 > MFT", "MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv", "fsutil usn queryjournal C:"]
regex_patterns: ["InitializeFileRecordSegment", "DeallocateFileRecordSegment", "AddIndexEntry(Root|Allocation)", "DeleteIndexEntry(Root|Allocation)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["LSN", "Usn", "UpdateTimestamp", "UpdateReasons", "EntryNumber", "SequenceNumber", "InUse", "RedoOperation", "UndoOperation", "TransactionId"]
file_formats: ["ntfs"]
primary_terms: ["$LogFile $UsnJrnl 교차검증"]
keywords: ["$LogFile", "$UsnJrnl", "교차검증", "LSN", "LFS", "저널 보존", "반포렌식", "저널 비활성", "3자 대조", "레코드 재사용", "InitializeFileRecordSegment"]
aliases: ["logfile usnjrnl 차이", "$LogFile 분석", "로그파일 저널 비교", "저널이 없다", "usn 저널 삭제", "ntfs log tracker", "삭제 증명"]
symptom_keywords: ["$J에는 있는데 $LogFile에 없다", "$MFT에 레코드가 없다", "저널이 비어 있다", "시각이 서로 다르다", "무엇을 신뢰해야 하나", "삭제를 증명해야 한다", "저널을 지운 것 같다"]
related: ["FOR-0027", "FOR-0028", "FOR-0032", "FOR-0025"]
source_ids: ["SRC-013", "SRC-005", "SRC-032"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`$LogFile`은 **짧고 상세**하고 `$UsnJrnl:$J`는 **길고 요약적**이다 — 두 로그의 보존 창이 다르기 때문에 "`$J`에는 있고 `$LogFile`에는 없다"는 정상이고, 그 **반대 방향의 불일치**와 `$MFT`까지의 3자 대조만이 삭제·조작을 결론으로 만든다.

## 어떤 문제에서 필요한가

- "이 파일이 삭제되었음을 증명하시오" — 한 artifact만으로는 반박 가능하다
- "`$J`에 기록이 없습니다. 정말 그 일이 없었던 겁니까"
- "저널을 지운 흔적이 있습니까" (반포렌식 판정)
- "`$MFT`에 레코드가 아예 없는 파일의 존재를 어떻게 주장합니까"
- "`$LogFile`의 시각과 `$J`의 시각이 다릅니다. 어느 쪽이 맞습니까"

플래그 시퀀스로 행위를 판정하는 단계는 [FOR-0028](./usn-reason-flags.html)에 있다. 이 글은 **판정이 끝난 뒤 그 판정을 반박 불가능하게 만드는 절차**다.

## 문제에서 처음 볼 단서

1. 첨부에 `$LogFile`이 **함께** 들어 있다 → 출제자가 교차검증을 요구한다는 신호다
2. 첨부에 `$MFT`가 있고 `$J`가 없다 → "언제 만들어졌나"만 답할 수 있고 "무슨 일이 있었나"는 못 답한다
3. 지문에 "증명", "확실히", "반증" → 3자 대조 서술이 정답 형식이다
4. `$J`의 첫 `Usn`이 사건 시각보다 뒤다 → 저널이 잘렸거나 삭제됐다
5. `$LogFile` 크기가 0 또는 극단적으로 작다 → 저널 초기화 의심
6. `fsutil usn queryjournal` 결과에서 `첫 USN`이 `0` 부근 → 저널이 최근에 새로 만들어졌다

## 30초 절차

```bash
icat -o 2048 image.dd 2 > LogFile
```

`$LogFile`은 **MFT 레코드 번호 2**로 고정되어 있다. 이미지에서 바로 뽑을 수 있다. `-o` 값은 `mmls`로 얻은 파티션 시작 섹터다.

세 개를 한 번에 확보한다.

```bash
mmls image.dd                          # 파티션 시작 섹터 확인
icat -o 2048 image.dd 0  > MFT         # 레코드 0 = $MFT
icat -o 2048 image.dd 2  > LogFile     # 레코드 2 = $LogFile
fls -o 2048 -r -p image.dd | grep '$Extend'   # $UsnJrnl 레코드 번호 확인
```

GUI라면 FTK Imager에서 볼륨 루트의 `$LogFile`·`$MFT`와 `$Extend\$UsnJrnl`의 `$J` 스트림을 Export한다 ([FOR-0016](./ftk-imager-open-image.html)).

세 파일이 모이면 **NTFS Log Tracker**에 `$LogFile`·`$J`·`$MFT`를 함께 로드한다. `$MFT`를 함께 주는 것이 핵심이다 — 경로 복원이 여기서 된다.

## 상세 절차

### 1단계 — 두 로그의 성질 차이를 먼저 고정한다

| 항목 | `$LogFile` | `$UsnJrnl:$J` |
| --- | --- | --- |
| 목적 | **파일시스템 정합성 복구** (트랜잭션 redo/undo) | 애플리케이션에 변경 알림 |
| MFT 레코드 | 2 (고정) | `$Extend\$UsnJrnl` 하위 ADS |
| 저장 방식 | **고정 크기 순환 버퍼** (LFS) | **sparse 파일**, 앞에서 잘려 나감 |
| 크기 | 볼륨 크기에 따라 결정. 현대 대용량 볼륨은 수십 MB 수준 | `$Max`로 설정. 기본은 볼륨에 따라 다름 |
| 보존 기간 | **매우 짧다. 활동량에 따라 수십 분~수 시간** | **며칠~수 주** |
| 기록 단위 | 메타데이터 **트랜잭션**(redo/undo 쌍) | 파일별 **변경 사건 요약** 1건 |
| 상세도 | **매우 높다.** 속성 이미지, 인덱스 엔트리, 이전 값까지 | 낮다. `Reason` 플래그 + 이름 |
| 순서 기준 | `LSN` (Log Sequence Number) | `Usn` |
| 레코드 자체의 시각 | **없다.** 시각은 redo/undo에 실린 `$SI`/`$FN` 속성 이미지에서 나온다 | **있다.** `UpdateTimestamp` (FILETIME, UTC) |
| 이전 파일 이름 | 인덱스 엔트리 삭제 기록에서 복원 가능 | `RenameOldName` 레코드 |
| 삭제된 파일의 내용 | 상주(resident) 작은 파일이면 **데이터 자체가 남을 수 있다** | 없음 |
| 저널 비활성 가능 | 사실상 불가 (NTFS 동작에 필수) | **가능** (`fsutil usn deletejournal`) |

핵심 비대칭: **`$LogFile`이 더 자세하지만 훨씬 빨리 사라진다.** 그래서 사건이 며칠 전이면 `$LogFile`에는 아무것도 없는 것이 정상이다.

### 2단계 — `$LogFile`에서 실제로 읽는 오퍼레이션

`$LogFile`은 플래그가 아니라 **오퍼레이션 이름**으로 사건을 말한다. 파서가 내놓는 redo/undo 오퍼레이션 중 포렌식적으로 의미 있는 것만 본다.

| 오퍼레이션 | 뜻 | 사건 해석 |
| --- | --- | --- |
| `InitializeFileRecordSegment` | MFT 레코드를 새로 초기화 | **파일 생성** (또는 레코드 재사용) |
| `DeallocateFileRecordSegment` | MFT 레코드를 해제 | **파일 삭제** |
| `AddIndexEntryRoot` / `AddIndexEntryAllocation` | 부모 디렉터리 인덱스에 이름 추가 | 그 폴더에 이름이 생겼다 |
| `DeleteIndexEntryRoot` / `DeleteIndexEntryAllocation` | 부모 디렉터리 인덱스에서 이름 제거 | **그 폴더에서 이름이 사라졌다.** 삭제·이동·이름변경 공통 |
| `CreateAttribute` / `DeleteAttribute` | 속성 추가/제거 | ADS 생성·제거, `$EFS` 부착 |
| `SetNewAttributeSizes` | 속성 크기 변경 | 파일 크기 변화 |
| `UpdateNonresidentValue` | 비상주 데이터 갱신 | 내용 변경 |
| `UpdateResidentValue` | 상주 데이터 갱신 | **작은 파일 내용이 로그에 실려 있을 수 있다** |
| `UpdateFileNameRoot` / `UpdateFileNameAllocation` | 인덱스의 `$FN` 갱신 | 이름·시각 변경 |
| `OpenNonresidentAttribute` | 비상주 속성 열기 | 접근 시점 단서 |
| `Open/Commit/ForgetTransaction` | 트랜잭션 경계 | 한 사용자 동작의 묶음 단위 |

**삭제의 `$LogFile` 시그니처**는 `DeleteIndexEntryAllocation`(부모에서 이름 제거) + `DeallocateFileRecordSegment`(레코드 해제)의 조합이다. 이름 변경은 `DeleteIndexEntry*` + `AddIndexEntry*`가 짝으로 나오되 `Deallocate*`가 **없다**.

`UpdateResidentValue`가 특히 값지다. 1KB 미만의 텍스트 파일이 삭제된 경우 **그 파일의 내용 전체가 `$LogFile`에 남아 있을 수 있다.** 다른 어떤 artifact도 이걸 주지 않는다.

### 3단계 — 불일치 패턴 판정표

두 로그에서 같은 사건을 찾은 결과는 네 가지 조합밖에 없다.

| `$J` | `$LogFile` | 가장 가능성 높은 해석 | 확인 방법 |
| --- | --- | --- | --- |
| 있음 | 있음 | **사건 확정.** 두 로그가 독립적으로 같은 것을 말한다 | 시각·순서가 일치하는지만 확인 |
| 있음 | 없음 | **정상.** `$LogFile`이 먼저 순환 소진됐다 (사건이 오래됨) | `$LogFile`에 남은 **가장 오래된** 사건 시각을 구한다. 그보다 앞이면 설명 완료 |
| 없음 | 있음 | **이상.** `$J`의 보존 창이 더 긴데 없다 → 저널 삭제/재생성, 또는 그 볼륨의 저널이 꺼져 있었다 | `fsutil usn queryjournal`의 저널 ID·첫 USN, `$Max` 스트림 확인 |
| 없음 | 없음 | 판단 불가. **"일어나지 않았다"가 아니다** | `$MFT`·카빙·다른 artifact로 이동 |

세 번째 줄이 반포렌식 판정 지점이다. **`$J`의 보존 기간이 `$LogFile`보다 훨씬 길다는 비대칭이 근거다.**

### 4단계 — `$J`가 비어 있을 때 세 원인을 가른다

| 원인 | 관측되는 것 | 결정적 증거 |
| --- | --- | --- |
| **보존 만료** (자연 소멸) | `$J`에 레코드는 많은데 **최소 `Usn`의 시각이 사건보다 뒤** | 저널 ID가 오래됐고, `$Max` 크기가 작아 회전이 빠르다 |
| **저널 삭제 후 재생성** (반포렌식) | `$J`가 거의 비었거나 **최소 `Usn`이 0 부근**, 저널 ID가 사건 시각 이후에 생성됨 | `fsutil usn deletejournal` 실행 흔적: Prefetch의 `FSUTIL.EXE-*.pf`, EVTX 4688의 명령행, 콘솔 히스토리 |
| **저널 비활성** (원래 꺼져 있었음) | `$Extend\$UsnJrnl` 자체가 없거나 `$J` 스트림이 없다 | 볼륨이 USB/외장이거나 저널을 쓰지 않는 구성. `$LogFile`은 여전히 존재한다 |

세 원인을 가르는 한 줄 기준: **`$J`가 "존재하지만 짧다"면 만료 또는 삭제, "존재하지 않는다"면 비활성.**

```powershell
# 라이브 시스템: 저널 ID와 첫 USN 이 사건 시각과 앞뒤가 맞는지
fsutil usn queryjournal C:
```

`첫 USN`이 `0x0` 또는 매우 작은 값이고 볼륨을 오래 써 왔다면 저널이 최근에 재생성됐다는 뜻이다.

### 5단계 — `$MFT`까지 3자 대조로 결론 세우기

목표 결론: **"이 파일은 존재했고, 삭제되었으며, MFT 레코드까지 재사용되어 메타데이터가 소실됐다"**처럼 각 단계마다 근거 artifact가 붙은 문장.

| 주장 | 근거 artifact | 확인할 값 |
| --- | --- | --- |
| ① 그 파일이 존재했다 | `$J`의 `FileCreate` 또는 `$LogFile`의 `InitializeFileRecordSegment` + `AddIndexEntry*` | `EntryNumber`, `SequenceNumber`, `FileName` |
| ② 어느 경로에 있었다 | `$J`의 `ParentEntryNumber` → `$MFT` 조인, 또는 `$LogFile`의 인덱스 엔트리 | `ParentPath` |
| ③ 그것이 삭제됐다 | `$J`의 `FileDelete` **또는** `$Recycle.Bin`으로의 rename | 삭제 시각 |
| ④ `$LogFile`도 같은 것을 말한다 | `DeleteIndexEntryAllocation` + `DeallocateFileRecordSegment` | 같은 `EntryNumber` |
| ⑤ 레코드가 재사용됐다 | `$MFT`의 같은 `EntryNumber`에 **다른** `FileName` + **증가한** `SequenceNumber` | `SequenceNumber` 비교 |
| ⑥ 그래서 메타데이터 복구 불가 | ⑤의 결과 | MACB 시각 없음 → 내용은 카빙으로만 |

`SequenceNumber` 비교가 ⑤⑥의 전부다. `$J`가 말하는 `(EntryNumber, SequenceNumber)`와 `$MFT`의 현재 `(EntryNumber, SequenceNumber)`가 다르면 **그 사이에 다른 파일이 그 자리를 차지했다**는 뜻이다.

```powershell
# $J 에서 관심 파일의 (EntryNumber, SequenceNumber)
Import-Csv usn.csv | Where-Object { $_.FileName -eq 'payroll.xlsx' } |
  Select-Object Usn, UpdateReasons, EntryNumber, SequenceNumber | Sort-Object Usn

# $MFT 의 현재 상태
Import-Csv mft.csv | Where-Object { $_.EntryNumber -eq 204118 } |
  Select-Object EntryNumber, SequenceNumber, InUse, FileName, ParentPath
```

```text
# $J
Usn        UpdateReasons        EntryNumber  SequenceNumber
0x81a0400  FileCreate|Close     204118       7
0x8244c80  FileDelete|Close     204118       7

# $MFT (현재)
EntryNumber  SequenceNumber  InUse   FileName            ParentPath
204118       9               True    Temp_a91f.tmp       .\Users\pshin\AppData\Local\Temp
```

`SequenceNumber` 7 → 9. 레코드가 두 번 재사용됐다. 결론: `payroll.xlsx`는 존재·삭제가 `$J`로 증명되지만 `$MFT` 기반 복구는 불가능하다.

### 6단계 — 시각이 어긋날 때 무엇을 믿나

**신뢰도 순위. 위에서부터 신뢰한다.**

| 순위 | 값 | 왜 신뢰하나 | 취약점 |
| --- | --- | --- | --- |
| 1 | `$J`의 `Usn` **순번** | 커널이 단조 증가로 부여. 사용자 도구로 조작 불가 | 절대 시각이 아니라 순서만 준다 |
| 2 | `$LogFile`의 `LSN` **순번** | 같은 이유 | 보존 창이 매우 짧다 |
| 3 | `$J`의 `UpdateTimestamp` | 사건 발생 순간에 커널이 기록. 사후 수정 불가 | **시스템 시계 자체가 조작되면 함께 틀린다** |
| 4 | `$MFT`의 `$FILE_NAME`(`$FN`) 시각 | 생성·이름변경 시에만 갱신. 일반 timestomp 도구가 손대지 않는 경우가 많다 | 정교한 도구는 이것도 바꾼다 |
| 5 | `$MFT`의 `$STANDARD_INFORMATION`(`$SI`) 시각 | 표준 필드 | **`SetFileTime` API로 누구나 변경 가능. timestomp의 주 표적** |

실전 규칙:

- **순서를 물으면 `Usn`/`LSN`으로 답한다.** 타임스탬프로 답하지 않는다.
- **절대 시각을 물으면 `$J`의 `UpdateTimestamp`로 답한다.** `$SI`가 이와 다르면 `$SI`가 틀린 것이다.
- `$SI` 시각이 `$J`의 `FileCreate` 시각보다 **앞서면** timestomp다. 파일이 만들어지기 전에 수정될 수는 없다.
- 시스템 시계 조작이 의심되면 `Usn`은 증가하는데 `UpdateTimestamp`가 역행하는 지점을 찾는다. 그 지점이 시계 변경 순간이다.
- `$J`·`$LogFile`·`$MFT`의 시각은 모두 **UTC** 기준 FILETIME(1601-01-01 UTC 기준 100ns 단위)이다. Unix epoch와의 차이는 `11644473600`초. KST 답이 필요하면 +9시간.

### 7단계 — 실전 판정 트리

```text
"이 파일에 무슨 일이 있었나"

[1] $J 에 그 이름이 있나?
     ├─ YES → 플래그 시퀀스를 Usn 순으로 읽는다 (FOR-0028)
     │         └─ [2] 로 진행 (확증 단계)
     └─ NO  → [4] 로 진행 (부재의 원인 규명)

[2] $LogFile 에 같은 EntryNumber 의 오퍼레이션이 있나?
     ├─ YES → Deallocate/DeleteIndexEntry 유무로 삭제 확정.
     │         상주 파일이면 UpdateResidentValue 에서 내용까지 회수 시도.
     └─ NO  → $LogFile 의 최소 LSN 시각을 구한다.
               ├─ 사건이 그보다 앞 → 정상 소진. $J 단독으로 결론.
               └─ 사건이 그보다 뒤 → 이상. $LogFile 만 잘렸을 이유가 없다.
                                     파서 오류 또는 부분 추출 의심. 재추출한다.

[3] $MFT 의 (EntryNumber, SequenceNumber) 가 $J 와 같나?
     ├─ 같고 InUse=False → 레코드 생존. MACB·데이터런 확보 가능. 복구 시도.
     ├─ 같고 InUse=True  → 아직 살아 있는 파일. 삭제가 아니었다(또는 복원됐다).
     └─ 다르다(Seq 증가) → 레코드 재사용. 메타데이터 소실. 카빙으로 전환.

[4] $J 에 없다 — 왜?
     ├─ $J 최소 Usn 의 시각 > 사건 시각 → 보존 만료. 판단 불가로 정직하게 남긴다.
     ├─ $J 최소 Usn ≈ 0 이고 볼륨 사용 이력이 길다 → 저널 재생성 = 반포렌식.
     │    └─ Prefetch/UserAssist/4688 로 fsutil 실행 흔적을 찾는다.
     ├─ $Extend\$UsnJrnl 자체가 없다 → 저널 비활성 볼륨. $LogFile 과 $MFT 만으로.
     └─ 이름이 애초에 달랐다 → RenameOldName 검색, 확장자 없이 부분 문자열로 재검색.
```

## 출력 필드 해석

NTFS Log Tracker 계열이 `$LogFile`을 파싱해 내놓는 컬럼의 의미다.

| 컬럼 | 의미 | 읽는 법 |
| --- | --- | --- |
| `LSN` | Log Sequence Number | **순서의 절대 기준.** 값이 클수록 최근 |
| `RedoOperation` | 트랜잭션 재적용 동작 | 실제로 무엇을 했나 (위 오퍼레이션 표) |
| `UndoOperation` | 되돌리기 동작 | redo와 짝. `Noop`이면 되돌릴 필요 없는 동작 |
| `TransactionId` / `Transaction LSN` | 같은 트랜잭션 묶음 | **한 사용자 동작을 묶는 키** |
| `TargetVCN` / `TargetAttribute` | 대상 속성과 클러스터 | 어느 속성이 바뀌었나 |
| `MFT EntryNumber` | 대상 MFT 레코드 | `$J`·`$MFT`와의 조인 키 |
| 파서가 복원한 `FileName` / `FullPath` | redo/undo의 `$FN` 이미지에서 추출 | `$MFT`를 함께 줬을 때만 경로가 채워진다 |
| 파서가 복원한 시각 | redo/undo에 실린 `$SI`/`$FN` 이미지의 시각 | **레코드 자체의 시각이 아니다.** 원리상 `$SI`와 같은 신뢰도다 |

마지막 줄이 중요하다. **`$LogFile`에서 나온 시각은 그 안에 실린 속성 이미지의 시각이므로, timestomp된 파일이면 `$LogFile`의 시각도 조작된 값을 보여준다.** 시각의 최종 심판은 `$J`의 `UpdateTimestamp`와 `Usn` 순서다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음에 열 것 | 확인할 것 |
| --- | --- | --- |
| `$J`에 rename → `$Recycle.Bin` | `$I` 파일 ([FOR-0030](./recycle-bin-i-r.html)) | 원래 전체 경로, 원본 크기, 삭제 시각 |
| 삭제 확정, 휴지통에 없음 | 원인 분기 ([FOR-0032](./deleted-file-not-in-recycle-bin.html)) | Shift+Delete인가 도구인가 |
| `SequenceNumber` 불일치 (레코드 재사용) | 카빙 (`photorec`, `foremost`) / `blkls` 비할당 영역 | 내용 회수 |
| `$LogFile`의 `UpdateResidentValue` | 그 redo 데이터의 hex | **작은 텍스트 파일 내용 원본** |
| `$MFT`의 `InUse=False` + 데이터런 생존 | `icat`로 직접 추출 | 삭제 파일 내용 복구 |
| 저널 재생성 의심 | Prefetch `FSUTIL.EXE-*.pf`, UserAssist ([FOR-0061](./userassist.html)) | 반포렌식 도구 실행 시각 |
| `$SI` vs `$J` 시각 불일치 | `$MFT`의 `$SI`/`$FN` 8개 시각 ([FOR-0021](./mft-basics.html)) | timestomp 확정 |
| 이미지 전체를 열어야 할 때 | Arsenal Image Mounter ([FOR-0017](./arsenal-image-mounter.html)) | 볼륨 마운트 후 원본 경로 확인 |

## 흔한 함정

- **`$LogFile`에 없는 것을 "일어나지 않았다"로 읽는 것** → `$LogFile`은 순환 버퍼라 활동량이 많으면 몇십 분 만에 덮인다 → `$LogFile`에 남은 **최소 `LSN`의 시각**을 먼저 구해 보존 창을 확정한 뒤 판단한다.
- **`$J`와 `$LogFile`의 보존 기간을 같다고 가정하는 것** → 두 로그의 불일치를 전부 반포렌식으로 오판한다 → 비대칭(`$J`가 훨씬 길다)을 전제로 방향을 본다. **`$J`에 없고 `$LogFile`에만 있는 경우**만 이상 신호다.
- **`$LogFile`의 시각을 `$J`보다 신뢰하는 것** → `$LogFile`의 시각은 redo/undo에 실린 `$SI` 이미지에서 나오므로 timestomp의 영향을 그대로 받는다 → 시각 판정은 `$J`의 `UpdateTimestamp`, 순서 판정은 `Usn`/`LSN`.
- **`EntryNumber`만으로 두 로그를 조인하는 것** → 레코드는 재사용되고 그때마다 `SequenceNumber`가 증가한다 → `(EntryNumber, SequenceNumber)` 쌍으로 조인한다.
- **`DeleteIndexEntryAllocation`을 삭제로 단정하는 것** → 이름 변경과 다른 폴더로의 이동에서도 부모 인덱스에서 이름이 제거된다 → `DeallocateFileRecordSegment`가 짝으로 있을 때만 삭제다.
- **`$J`가 없다는 이유로 저널이 꺼져 있었다고 결론 내는 것** → 만료·삭제·비활성의 세 원인이 전혀 다른 결론으로 이어진다 → `$Extend\$UsnJrnl` 파일 자체의 존재 여부와 최소 `Usn` 값으로 먼저 가른다.
- **볼륨을 쓰기 가능 상태로 마운트해 놓고 분석하는 것** → 분석 행위 자체가 `$LogFile`을 회전시켜 증거를 덮는다 → 항상 읽기 전용 마운트 또는 이미지에서 직접 추출한다.
- **한쪽 로그만 첨부된 문제에서 없는 쪽을 계속 찾는 것** → 시간만 잃는다 → 첨부 목록으로 답변 가능 범위를 먼저 확정한다. `$MFT`만 있으면 "무슨 일이 있었나"는 답할 수 없다.
- **시간대 혼동** → 세 로그 모두 UTC 기준 FILETIME이고 파서 CSV도 UTC로 출력한다. NTFS Log Tracker처럼 로컬 시간대 변환 옵션이 있는 도구는 설정에 따라 화면 값이 달라진다 → 출력 시간대 설정을 먼저 확인하고, KST 답이 필요하면 +9시간.
- **트랜잭션 경계를 무시하고 오퍼레이션을 개별 사건으로 세는 것** → 파일 하나 삭제가 오퍼레이션 10건으로 부풀어 통계가 무너진다 → `TransactionId`로 묶어서 센다.

## 교차검증

```bash
# 0) 세 artifact 를 같은 이미지에서, 같은 시점에 추출한다
mmls image.dd
icat -o 2048 image.dd 0 > MFT
icat -o 2048 image.dd 2 > LogFile
fls -o 2048 -r -p image.dd | grep -i 'UsnJrnl'

# 1) $MFT 파싱
MFTECmd.exe -f MFT --csv out --csvf mft.csv

# 2) $J 파싱 (경로 복원을 위해 -m 로 $MFT 함께)
MFTECmd.exe -f J -m MFT --csv out --csvf usn.csv

# 3) $LogFile 은 NTFS Log Tracker 에 $LogFile + $J + $MFT 를 함께 로드
```

```powershell
# 4) 세 결과에서 같은 EntryNumber 를 훑는다
$e = 204118
Import-Csv out\usn.csv | Where-Object {$_.EntryNumber -eq $e} | Sort-Object {[uint64]$_.Usn} |
  Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName
Import-Csv out\mft.csv | Where-Object {$_.EntryNumber -eq $e} |
  Format-Table EntryNumber, SequenceNumber, InUse, FileName, ParentPath
Import-Csv out\logfile.csv | Where-Object {$_.EntryNumber -eq $e} | Sort-Object LSN |
  Format-Table LSN, RedoOperation, UndoOperation, FileName
```

```powershell
# 5) 각 로그의 보존 창을 수치로 확정한다 — 이게 모든 "없음" 판정의 전제다
Import-Csv out\usn.csv     | Sort-Object {[uint64]$_.Usn} | Select-Object -First 1 UpdateTimestamp
Import-Csv out\usn.csv     | Sort-Object {[uint64]$_.Usn} | Select-Object -Last  1 UpdateTimestamp
Import-Csv out\logfile.csv | Sort-Object {[uint64]$_.LSN} | Select-Object -First 1
```

보존 창을 먼저 표로 적어 두면 이후 모든 "없음"에 대해 즉시 답할 수 있다.

| 로그 | 가장 오래된 기록 | 가장 최근 기록 | 이 창 밖의 사건 |
| --- | --- | --- | --- |
| `$J` | 2026-04-01 22:14Z | 2026-04-09 06:02Z | 판단 불가 |
| `$LogFile` | 2026-04-09 03:51Z | 2026-04-09 06:02Z | 부재가 정상 |

## mini walkthrough

```text
문제:
"직원이 급여 파일을 삭제했다고 주장하는 사건입니다. 직원은 '그런 파일은 없었다'고
 반박합니다. 파일의 존재와 삭제를 증명하고, 내용을 복구할 수 있는지 판정하세요."
첨부: $MFT, $LogFile, $J (같은 이미지에서 추출)

1. 첫 시도 (실패):
   $MFT 만 먼저 파싱했다.
   MFTECmd.exe -f MFT --csv out --csvf mft.csv
   Import-Csv out\mft.csv | Where-Object { $_.FileName -match 'payroll|급여' }
   -> 0건.

   여기서 "MFT에 없으니 그런 파일은 없었다"고 결론 낼 뻔했다.  <-- 틀린 결론
   왜 틀렸나: $MFT 는 '지금 무엇이 있나'만 답한다. 레코드가 재사용되면
   삭제된 파일의 흔적은 통째로 사라진다. 부재는 증거가 아니다.

2. 접근 변경 — $J 로 '무슨 일이 있었나'를 묻는다
   MFTECmd.exe -f J -m MFT --csv out --csvf usn.csv
   Import-Csv out\usn.csv | Where-Object { $_.FileName -match 'payroll' } |
     Sort-Object {[uint64]$_.Usn} |
     Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath, EntryNumber, SequenceNumber

   Usn        UpdateTimestamp        UpdateReasons          FileName        ParentPath                EntryNumber  Seq
   0x81a0400  2026-04-06 05:11:02Z   FileCreate             payroll.xlsx    .\Users\pshin\Documents   204118       7
   0x81a0490  2026-04-06 05:11:02Z   FileCreate|DataExtend  payroll.xlsx    .\Users\pshin\Documents   204118       7
   0x81a1c20  2026-04-06 05:13:44Z   DataExtend|Close       payroll.xlsx    .\Users\pshin\Documents   204118       7
   0x8244c80  2026-04-08 23:47:15Z   FileDelete|Close       payroll.xlsx    .\Users\pshin\Documents   204118       7

   존재(①②)와 삭제(③)가 나왔다. 휴지통으로의 rename 이 없으므로 완전삭제다.

3. $LogFile 로 독립 확증 시도
   NTFS Log Tracker 에 $LogFile + $J + $MFT 로드, EntryNumber = 204118 로 필터
   -> 0건.

   두 번째 함정. 여기서 "$LogFile 이 반박한다"고 읽으면 또 틀린다.
   $LogFile 의 최소 LSN 시각을 먼저 확인한다.
   -> $LogFile 의 가장 오래된 기록 = 2026-04-09 03:51Z
      삭제 시각 04-08 23:47Z 는 그보다 4시간 앞이다.
   => $LogFile 이 이미 순환 소진된 구간. 부재가 정상이다. 반박이 아니다.

4. $MFT 재확인 — 왜 1단계에서 0건이었나
   Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq 204118 } |
     Format-Table EntryNumber, SequenceNumber, InUse, FileName, ParentPath

   EntryNumber  SequenceNumber  InUse  FileName        ParentPath
   204118       9               True   Temp_a91f.tmp   .\Users\pshin\AppData\Local\Temp

   $J 는 Seq 7, $MFT 는 Seq 9. 레코드가 두 번 재사용됐다.
   -> 1단계에서 0건이었던 이유가 설명된다. 삭제 후 다른 파일이 그 자리를 차지했다.

5. 저널 조작 여부 확인 (직원 주장의 다른 가능성)
   Import-Csv out\usn.csv | Sort-Object {[uint64]$_.Usn} | Select-Object -First 1
   -> 최소 Usn 시각 = 2026-04-01 22:14Z. 값도 0 부근이 아니다.
   => 저널은 정상 회전 중이었고 재생성되지 않았다. 기록의 신뢰성에 문제 없다.

6. 복구 판정
   $MFT 레코드는 재사용됨 -> MACB·데이터런 소실 -> $MFT 기반 복구 불가.
   남은 경로: 비할당 영역 카빙 (xlsx = ZIP 컨테이너, PK 시그니처 + [Content_Types].xml)
   blkls -o 2048 image.dd > unalloc.raw ; photorec unalloc.raw

결론:
  ① 존재:   $J Usn 0x81a0400, 2026-04-06 05:11:02Z 생성
            (= 2026-04-06 14:11:02 KST), 경로 \Users\pshin\Documents\payroll.xlsx
  ② 삭제:   $J Usn 0x8244c80, 2026-04-08 23:47:15Z 완전삭제(휴지통 미경유)
            (= 2026-04-09 08:47:15 KST)
  ③ $LogFile 부재는 보존 창(04-09 03:51Z 이후) 밖이므로 반증이 아니다
  ④ $MFT SequenceNumber 7 -> 9, 레코드 재사용으로 메타데이터 소실
  => 존재와 삭제는 증명됨. 내용 복구는 카빙에 의존.
```

1단계와 3단계가 이 글의 핵심이다. **`$MFT`의 부재도 `$LogFile`의 부재도 그 자체로는 아무것도 증명하지 않는다.** 각 로그의 보존 창을 수치로 먼저 확정한 것이 두 번의 오판을 막았다.

## 막혔을 때 다음 체크

1. 세 파일(`$MFT`, `$LogFile`, `$J`)을 **같은 이미지·같은 시점**에서 뽑았는가 — 다른 시점이면 대조가 무의미하다
2. 각 로그의 **최소/최대 기록 시각**을 표로 적었는가 — 모든 "없음" 판정의 전제다
3. `$J` 파싱에 `-m $MFT`를 줬는가 — 안 주면 `ParentPath`가 비고 경로 대조를 못 한다
4. 조인 키에 `SequenceNumber`를 포함했는가
5. `$LogFile` 부재가 보존 창 밖인지 안인지 확인했는가 — 안이면 부분 추출/파서 오류를 의심해 재추출
6. `$J`가 비었다면 만료·삭제·비활성 세 원인 중 어느 것인지 가렸는가
7. 시각 불일치가 있으면 `Usn`/`LSN` 순서로 다시 세웠는가
8. `$SI` 시각이 `$J`의 `FileCreate`보다 앞서지 않는가 (앞서면 timestomp)
9. 작은 텍스트 파일이라면 `$LogFile`의 `UpdateResidentValue`에서 내용 자체를 찾아봤는가
10. 여기까지 왔는데도 안 되면 → 카빙(`blkls` + `photorec`)과 `$Recycle.Bin` ([FOR-0030](./recycle-bin-i-r.html))으로 전환

## 출처

- SRC-013 — Microsoft Learn, Change Journals: `$UsnJrnl`의 순환/sparse 동작, `$Max`, 저널 생성·삭제와 저널 ID 개념
- SRC-005 — Microsoft Learn, Master File Table: `$LogFile`이 MFT 레코드 2번이라는 점, 시스템 메타데이터 파일 배치, 레코드 재사용과 시퀀스 개념
- SRC-032 — The Sleuth Kit 도구 문서: `mmls`/`fls`/`icat`/`blkls`로 이미지에서 시스템 파일을 레코드 번호로 직접 추출하는 방법
- `$LogFile`의 기본 크기, redo/undo 오퍼레이션 이름 표기, NTFS Log Tracker의 컬럼명·시간대 옵션은 볼륨 구성과 도구 버전에 따라 다르므로 실제 화면에서 확인할 것
- `$LogFile` 레코드 자체에 타임스탬프 필드가 없다는 점은 파서가 보여주는 시각의 출처(redo/undo에 실린 속성 이미지)를 반드시 확인해야 하는 근거다
- walkthrough의 `Usn`·`LSN`·엔트리 번호·시각은 설명을 위한 예시 값이다
