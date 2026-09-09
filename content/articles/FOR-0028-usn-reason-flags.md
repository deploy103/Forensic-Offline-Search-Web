---
id: FOR-0028
title: "USN_REASON 플래그 조합으로 실제 행위 판정하기 (삭제·이동·복사·timestomp 구분)"
slug: "usn-reason-flags"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["USN_REASON", "UpdateReasons", "$J", "$UsnJrnl", "USN_RECORD", "Usn"]
file_paths: ["C:\\$Extend\\$UsnJrnl:$J", "C:\\$Recycle.Bin"]
registry_paths: []
event_ids: []
protocols: []
tools: ["MFTECmd", "NTFS Log Tracker", "Timeline Explorer", "PowerShell"]
commands: ["Import-Csv usn.csv | Where-Object {$_.EntryNumber -eq 128441} | Sort-Object Usn", "MFTECmd.exe -f '$J' -m '$MFT' --csv out --csvf usn.csv", "Import-Csv usn.csv | Group-Object UpdateReasons | Sort-Object Count -Descending"]
regex_patterns: ["RenameOldName\\|RenameNewName", "^BasicInfoChange(\\|Close)?$", "FileCreate.*DataExtend", "StreamChange"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Usn", "UpdateReasons", "UpdateTimestamp", "FileName", "EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentPath", "FileAttributes"]
file_formats: ["ntfs"]
primary_terms: ["USN_REASON", "UpdateReasons", "FileDelete", "RenameOldName", "RenameNewName", "BasicInfoChange"]
keywords: ["USN_REASON", "UpdateReasons", "플래그 조합", "FileDelete", "RenameOldName", "RenameNewName", "BasicInfoChange", "StreamChange", "DataOverwrite", "CLOSE", "timestomp", "Shift+Delete", "USN 순번"]
aliases: ["usn reason", "update reasons", "플래그 해석", "0x80000200", "basicinfochange 뭔가", "rename old name", "휴지통인지 shift delete인지", "복사한 흔적"]
symptom_keywords: ["플래그가 무슨 뜻인지 모르겠다", "휴지통으로 갔는지 완전삭제인지 모르겠다", "복사했는지 이동했는지 모르겠다", "BasicInfoChange만 있다", "타임스탬프를 조작했는지", "이름을 바꿨는지 새로 만들었는지", "같은 초에 여러 레코드가 있다"]
related: ["FOR-0027", "FOR-0029", "FOR-0030", "FOR-0024"]
source_ids: ["SRC-013", "SRC-004", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`UpdateReasons` 하나만 보면 답이 안 나온다 — 같은 `EntryNumber`의 레코드를 **`Usn` 순번으로 정렬해 플래그 시퀀스를 읽어야** "새로 만든 것 / 덮어쓴 것 / 휴지통으로 보낸 것 / 완전삭제한 것 / 복사한 것"이 갈린다.

## 어떤 문제에서 필요한가

- "이 파일을 휴지통에 버렸습니까, Shift+Delete 했습니까"
- "파일을 옮긴 겁니까 복사한 겁니까" (같은 볼륨 이동 vs 다른 볼륨 이동 vs 복사)
- "USB로 빼돌린 흔적이 원본 볼륨에 남습니까"
- "타임스탬프를 조작(timestomp)했습니까"
- "이 파일에 ADS를 붙였습니까"
- "다운로드한 파일의 원래 임시 이름이 무엇이었습니까"

`$J`의 구조·추출·필드 의미는 [FOR-0027](./usnjrnl-basics.html)에 있다. 이 글은 **파싱이 끝난 CSV를 손에 들고 플래그를 사건으로 번역하는 단계**만 다룬다.

## 문제에서 처음 볼 단서

1. 지문에 "완전 삭제", "휴지통을 비웠다" → `FileDelete` 단독 레코드와 `$Recycle.Bin` 하위 rename을 대조
2. 지문에 "옮겼다", "이동" → `RenameOldName`/`RenameNewName` 짝의 `ParentEntryNumber` 변화
3. 지문에 "복사", "USB" → **원본 쪽에는 레코드가 없다**는 전제로 대상 볼륨을 찾는다
4. 지문에 "시간이 이상하다", "수정 시각이 생성 시각보다 빠르다" → `BasicInfoChange` 단독
5. 지문에 "숨겼다" → `StreamChange`, `NamedDataExtend`
6. 같은 초에 레코드가 몰려 있다 → 타임스탬프 정렬을 버리고 `Usn` 정렬로 바꾼다

## 30초 절차

```powershell
Import-Csv usn.csv | Where-Object {$_.EntryNumber -eq 128441} | Sort-Object Usn
```

관심 파일의 `EntryNumber`를 먼저 확보하고(이름으로 검색), 그 번호로 전체 레코드를 뽑아 `Usn` 오름차순으로 늘어놓는다. **플래그 시퀀스가 그대로 행위 서술이 된다.**

볼륨 전체의 성향을 먼저 보고 싶으면:

```powershell
Import-Csv usn.csv | Group-Object UpdateReasons | Sort-Object Count -Descending | Select-Object -First 20
```

```text
Count  Name
81204  Close
44119  DataExtend|Close
39877  FileCreate|DataExtend|Close
12043  DataOverwrite|Close
 8810  FileDelete|Close
 4402  BasicInfoChange|Close
 1120  RenameOldName
 1120  RenameNewName|Close
   88  StreamChange|Close
```

`RenameOldName`과 `RenameNewName`의 건수가 같지 않으면 저널이 앞에서 잘려 짝이 끊긴 것이다.

## 상세 절차

### 1단계 — 전체 플래그 값 표

`USN_RECORD`의 `Reason` 필드는 비트 플래그이고, 한 레코드에 여러 비트가 OR로 들어간다.

| 값 | 이름 (`USN_REASON_` 접두 생략) | 트리거 | 해석 무게 |
| --- | --- | --- | --- |
| `0x00000001` | `DATA_OVERWRITE` | 기존 클러스터 범위에 다시 씀 (파일 크기 안 변함) | 중 |
| `0x00000002` | `DATA_EXTEND` | 파일 끝에 데이터 추가 (크기 증가) | 중 |
| `0x00000004` | `DATA_TRUNCATION` | 파일이 잘림. 0바이트로 만들 때도 포함 | 중 |
| `0x00000010` | `NAMED_DATA_OVERWRITE` | **ADS** 데이터 덮어쓰기 | 상 |
| `0x00000020` | `NAMED_DATA_EXTEND` | ADS 데이터 추가 | 상 |
| `0x00000040` | `NAMED_DATA_TRUNCATION` | ADS 데이터 잘림 | 중 |
| `0x00000100` | `FILE_CREATE` | 파일/디렉터리가 새로 만들어짐 | **최상** |
| `0x00000200` | `FILE_DELETE` | 파일/디렉터리가 실제로 지워짐 | **최상** |
| `0x00000400` | `EA_CHANGE` | 확장 속성(`$EA`) 변경 | 하 |
| `0x00000800` | `SECURITY_CHANGE` | ACL/소유자 변경 | 중 |
| `0x00001000` | `RENAME_OLD_NAME` | 이름 변경 **직전** 이름을 담은 레코드 | **최상** |
| `0x00002000` | `RENAME_NEW_NAME` | 이름 변경 **직후** 이름을 담은 레코드 | **최상** |
| `0x00004000` | `INDEXABLE_CHANGE` | 색인 대상 속성 변경 | 하 |
| `0x00008000` | `BASIC_INFO_CHANGE` | `$STANDARD_INFORMATION`의 시각·속성 변경 | **상 (timestomp)** |
| `0x00010000` | `HARD_LINK_CHANGE` | 하드링크 추가/삭제 | 중 |
| `0x00020000` | `COMPRESSION_CHANGE` | 압축 속성 변경 | 하 |
| `0x00040000` | `ENCRYPTION_CHANGE` | **EFS 암호화 속성 변경** | 상 |
| `0x00080000` | `OBJECT_ID_CHANGE` | 오브젝트 ID 변경 | 하 |
| `0x00100000` | `REPARSE_POINT_CHANGE` | 재분석 지점(심볼릭 링크/정션/OneDrive placeholder) | 중 |
| `0x00200000` | `STREAM_CHANGE` | **ADS 자체가 추가/삭제/이름변경됨** | 상 |
| `0x00400000` | `TRANSACTED_CHANGE` | TxF 트랜잭션 내 변경 | 하 |
| `0x80000000` | `CLOSE` | **핸들이 닫혔다 = 이 변경 묶음의 종료 표시** | 구조용 |

`0x00000008`, `0x00000080`처럼 표에 없는 비트는 정의되지 않았다. 파서가 raw 값을 보여줄 때 미정의 비트가 켜져 있으면 파싱 오정렬을 의심한다.

### 2단계 — 플래그를 3계층으로 나눠 읽는다

플래그를 22개 개별 항목으로 외우면 실전에서 못 쓴다. **세 계층**으로 접는다.

| 계층 | 포함 플래그 | 답하는 질문 |
| --- | --- | --- |
| **존재** | `FILE_CREATE`, `FILE_DELETE`, `RENAME_OLD_NAME`, `RENAME_NEW_NAME`, `HARD_LINK_CHANGE` | 이 이름/엔트리가 생겼나 없어졌나 옮겨졌나 |
| **내용** | `DATA_*`, `NAMED_DATA_*`, `STREAM_CHANGE` | 바이트가 바뀌었나, 어느 스트림이 |
| **메타** | `BASIC_INFO_CHANGE`, `SECURITY_CHANGE`, `EA_CHANGE`, `*_CHANGE` 계열 | 내용은 그대로인데 껍데기만 바뀌었나 |

**존재 계층 플래그가 하나도 없으면 그 파일은 그 시점에 이미 있었던 파일이다.** 이 한 줄이 "언제 만들어졌나"에 대한 오답을 막는다.

### 3단계 — 자주 나오는 조합의 raw 값

문제에서 hex 값 하나만 주는 경우가 있다. 자주 나오는 OR 결과를 외워 둔다.

| raw 값 | 풀어쓰기 | 뜻 |
| --- | --- | --- |
| `0x80000100` | `FILE_CREATE\|CLOSE` | 만들고 바로 닫음 (0바이트 또는 디렉터리) |
| `0x80000200` | `FILE_DELETE\|CLOSE` | **삭제 완료** |
| `0x80000102` | `FILE_CREATE\|DATA_EXTEND\|CLOSE` | 만들고 쓰고 닫음 (작은 파일 한 번에) |
| `0x80002000` | `RENAME_NEW_NAME\|CLOSE` | 이름 변경 완료 |
| `0x00001000` | `RENAME_OLD_NAME` | 이름 변경 시작 (`CLOSE` 없음이 정상) |
| `0x80008000` | `BASIC_INFO_CHANGE\|CLOSE` | **시각/속성만 변경** |
| `0x80200000` | `STREAM_CHANGE\|CLOSE` | ADS 붙임/떼어냄 |
| `0x80000001` | `DATA_OVERWRITE\|CLOSE` | 같은 크기로 덮어씀 |

### 4단계 — 시퀀스 → 행위 매핑 (이 글의 핵심)

표기 규칙: `→`는 `Usn` 오름차순, `+`는 같은 레코드 안의 OR, `[별 엔트리]`는 다른 `EntryNumber`에서 벌어지는 일.

| 실제 행위 | `Usn` 순 플래그 시퀀스 | 결정적 판별점 |
| --- | --- | --- |
| **새 파일 작성** (메모장 저장, 다운로드 완료) | `FileCreate` → `FileCreate+DataExtend` → `DataExtend` ×N → `DataExtend+Close` | `FileCreate`가 시퀀스 **맨 앞**에 있다 |
| **기존 파일 덮어쓰기** (같은 이름으로 저장) | `DataOverwrite` (또는 `DataTruncation` → `DataExtend`) → `...+Close` | `FileCreate`가 **없다**. 엔트리는 그대로 |
| **문서 편집기의 안전 저장** | 임시파일 `FileCreate`+`DataExtend` → 원본 `FileDelete` → 임시파일 `RenameOldName`/`RenameNewName` | 최종 이름이 살아 있는데 `FileDelete`가 있다. **삭제로 오독 금지** |
| **완전 삭제 (Shift+Delete)** | (`DataTruncation`) → `FileDelete+Close` | `$Recycle.Bin`으로의 rename이 **전혀 없다** |
| **휴지통으로 이동** | `RenameOldName`(원래 이름, 원래 부모) → `RenameNewName+Close`(`$R......ext`, 부모 = `$Recycle.Bin\<SID>`) + [별 엔트리] `$I......ext` `FileCreate`+`DataExtend`+`Close` | **`FileDelete`가 없다.** `$I` 생성이 짝으로 붙는다 |
| **휴지통 비우기** | `$I` 엔트리 `FileDelete+Close` + `$R` 엔트리 `FileDelete+Close` | `$I`/`$R` **두 개**가 같은 시각에 삭제 |
| **휴지통에서 복원** | `RenameOldName`(`$R...`) → `RenameNewName+Close`(원래 이름, 원래 부모) + `$I` `FileDelete` | 부모가 `$Recycle.Bin`에서 사용자 폴더로 되돌아온다 |
| **이름 변경 (제자리)** | `RenameOldName` → `RenameNewName+Close` | `ParentEntryNumber`가 **같다**. 두 레코드의 `EntryNumber`도 같다 |
| **같은 볼륨 내 이동** | `RenameOldName` → `RenameNewName+Close` | `FileName`은 같고 `ParentEntryNumber`가 **바뀐다** |
| **다른 볼륨으로 이동** | 원본 볼륨: `FileDelete+Close` / 대상 볼륨 `$J`: `FileCreate` → `DataExtend` ×N → `Close` | rename이 아니라 **복사 + 삭제**로 기록된다. 두 볼륨의 `$J`를 모두 봐야 완성 |
| **복사 (같은 볼륨)** | 원본: **레코드 없음** / 사본: `FileCreate` → `DataExtend` ×N → `BasicInfoChange`(시각 승계) → `Close` | 읽기는 저널되지 않는다. **원본 쪽 공백 자체가 "복사됨"의 근거가 아니다** |
| **USB로 복사** | 원본 볼륨: **레코드 없음** / USB가 NTFS이고 저널 활성: USB `$J`에 `FileCreate`+`DataExtend` / USB가 FAT32/exFAT: **저널 자체가 없음** | 원본 볼륨 `$J`만으로는 절대 증명 못 한다. LNK·Shellbag·`USBSTOR`로 우회 |
| **압축 해제 (unzip/7z)** | 각 항목마다 `FileCreate` → `DataExtend` ×N → `Close` → `BasicInfoChange+Close` | 마지막 `BasicInfoChange`는 **아카이브 안의 원본 시각 복원**이다. timestomp와 겉모습이 같다 |
| **압축 파일 생성** | 아카이브 엔트리 `FileCreate` → `DataExtend` 대량 반복 → `Close`, 원본들은 무기록 | `DataExtend` 반복 횟수가 큰 파일 = 오래 쓴 파일 |
| **브라우저 다운로드 (Chrome/Edge)** | `<name>.crdownload` `FileCreate` → `DataExtend` ×N → `RenameOldName`(`.crdownload`) → `RenameNewName+Close`(최종 이름) → `StreamChange`(`Zone.Identifier`) | **`.crdownload` → 최종 이름 rename 짝**이 "직접 받았다"의 증거. 사본에는 없다 |
| **timestomp** | `BasicInfoChange` 단독 (`+Close`) — 앞뒤에 `Data*`/`FileCreate`/`Rename*` 없음 | **내용은 안 바뀌고 시각만 바뀐 순간**이 저널에 그대로 남는다 |
| **ADS 생성** | `StreamChange` → `NamedDataExtend` → `NamedDataExtend+Close` (`FileName`은 주 파일 이름) | `FileName` 컬럼에 스트림 이름이 안 나온다. 주 파일 이름으로 잡힌다 |
| **ADS 제거** (`Zone.Identifier` 삭제 등) | `StreamChange+Close` 단독 | 다운로드 흔적 지우기 |
| **EFS 암호화** (`cipher /e`) | `EncryptionChange`(+`Close`), 초기 암호화 시 같은 폴더에 `EFS0.TMP` 계열 임시파일의 `FileCreate`/`FileDelete`가 함께 | `EncryptionChange`는 흔하지 않다. 나오면 반드시 파고든다 |
| **권한 변경** (`icacls`) | `SecurityChange+Close` | 내용 무변경. 접근 통제 우회 준비 |
| **정션/심볼릭 링크 생성** | `FileCreate` → `ReparsePointChange` → `Close` | 실제 데이터는 다른 경로에 있다 |
| **하드링크 추가** | `HardLinkChange+Close` | 같은 데이터가 두 이름으로 존재. 한쪽 삭제로는 데이터가 안 사라진다 |
| **와이핑 도구** | `DataOverwrite` 다수 반복 → `DataTruncation` → `FileDelete+Close`, 또는 무의미한 이름으로 `Rename` 후 `FileDelete` | 같은 엔트리에 `DataOverwrite`가 비정상적으로 많다 |

### 5단계 — `CLOSE`를 구두점으로 읽는다

`CLOSE`(`0x80000000`)는 별개 사건이 아니다. **핸들이 닫혔다는 종료 표시**이며, 같은 변경 묶음의 마지막 레코드에 OR로 붙는다.

```text
Usn        UpdateReasons                  FileName
0x1a2000   FileCreate                     note.txt      <- 묶음 시작
0x1a2088   FileCreate|DataExtend          note.txt
0x1a2110   DataExtend                     note.txt
0x1a2198   DataExtend|Close               note.txt      <- 묶음 종료
```

실전 규칙 세 가지.

1. **사건 수를 셀 때 `CLOSE`가 붙은 레코드만 센다.** 그렇지 않으면 파일 하나의 저장을 4건으로 센다.
2. `RenameOldName`에는 `CLOSE`가 붙지 않고 `RenameNewName`에 붙는 것이 정상이다. 짝의 종료가 뒤쪽이기 때문이다.
3. `CLOSE` 없이 시퀀스가 끝났다면 프로세스가 비정상 종료했거나 **저널이 그 지점에서 잘렸다**. 후자면 앞쪽 레코드도 소실됐다고 봐야 한다.

### 6단계 — `Usn`이 타임스탬프보다 정확한 순서 기준이다

`UpdateTimestamp`는 FILETIME(100ns, 1601-01-01 UTC 기준)이지만, **한 번의 저장에서 여러 레코드가 같은 값을 갖는 경우가 흔하다.** 시스템 시계가 변경되면 타임스탬프는 역행할 수도 있다.

`Usn`은 `$J` 스트림 안의 바이트 오프셋 겸 단조 증가 순번이다. 따라서:

| 정렬 기준 | 신뢰도 | 언제 쓰나 |
| --- | --- | --- |
| `Usn` 오름차순 | **최상.** 볼륨 내 절대 순서 | 인과 관계 판정, 플래그 시퀀스 읽기 |
| `UpdateTimestamp` | 중. 초 단위 동시 발생 다수 | "몇 시에 일어났나" 답변, 다른 artifact와 대조 |

**시계가 조작된 사건에서는 `Usn` 순서가 유일하게 살아남는 진실이다.** 타임스탬프가 뒤로 점프하는데 `Usn`이 계속 증가하면 그 지점이 시스템 시계 변경 시점이다.

```powershell
# 타임스탬프 역행 지점 찾기 = 시계 조작 후보
$r = Import-Csv usn.csv | Sort-Object {[uint64]$_.Usn}
for ($i=1; $i -lt $r.Count; $i++) {
  if ([datetime]$r[$i].UpdateTimestamp -lt [datetime]$r[$i-1].UpdateTimestamp) {
    "{0}  {1} -> {2}" -f $r[$i].Usn, $r[$i-1].UpdateTimestamp, $r[$i].UpdateTimestamp
  }
}
```

## 출력 필드 해석

파서마다 플래그를 다른 문자열로 풀어 준다. **필터 정규식을 쓰기 전에 실제 컬럼 값을 한 번 눈으로 확인한다.**

| 개념 | MFTECmd 계열 표기 | 다른 파서에서 볼 수 있는 표기 |
| --- | --- | --- |
| `FILE_CREATE` | `FileCreate` | `File_Create`, `USN_REASON_FILE_CREATE`, `0x100` |
| `FILE_DELETE` | `FileDelete` | `File_Delete`, `0x200` |
| `RENAME_OLD_NAME` | `RenameOldName` | `Rename_Old_Name` |
| `BASIC_INFO_CHANGE` | `BasicInfoChange` | `Basic_Info_Change` |
| 조합 구분자 | `\|` (파이프) | `,`, `+`, 공백 |

그래서 안전한 정규식은 밑줄과 구분자를 흡수하는 형태다.

```powershell
# 표기 차이에 안전한 삭제 필터
Import-Csv usn.csv | Where-Object { $_.UpdateReasons -match 'File_?Delete' }

# 순수 timestomp 후보 — 다른 존재/내용 플래그가 하나도 없어야 한다
Import-Csv usn.csv | Where-Object {
  $_.UpdateReasons -match 'Basic_?Info_?Change' -and
  $_.UpdateReasons -notmatch 'Data|Create|Delete|Rename|Stream'
} | Select-Object Usn, UpdateTimestamp, FileName, ParentPath
```

```powershell
# 휴지통 경유 판정 — $R 로의 rename 이 있는지
Import-Csv usn.csv |
  Where-Object { $_.UpdateReasons -match 'Rename' -and $_.FileName -match '^\$[IR]' } |
  Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath | Sort-Object Usn
```

```powershell
# 다운로드 원본 이름 복원 — .crdownload 짝
Import-Csv usn.csv |
  Where-Object { $_.FileName -match '\.crdownload$|^Unconfirmed ' } |
  Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName, EntryNumber | Sort-Object Usn
```

## pivot: 다음에 볼 artifact

| 이 글에서 확정한 것 | 다음에 열 것 | 확인할 것 |
| --- | --- | --- |
| `$R`/`$I` 로의 rename 발견 | `$Recycle.Bin`의 `$I` ([FOR-0030](./recycle-bin-i-r.html)) | 원래 전체 경로, 원본 크기, 삭제 시각 |
| `$I` 파일 이름 확보 | RBCmd ([FOR-0031](./rbcmd.html)) | `$I` 일괄 파싱, SID로 사용자 특정 |
| `FileDelete`만 있고 rename 없음 | `$LogFile` 교차검증 ([FOR-0029](./logfile-usnjrnl-crosscheck.html)) | 같은 트랜잭션의 상세, 저널 누락 여부 |
| `BasicInfoChange` 단독 | `$MFT`의 `$SI` vs `$FN` 시각 ([FOR-0021](./mft-basics.html)) | 두 시각 불일치 = timestomp 확정 |
| `EntryNumber` + `SequenceNumber` | `$MFT` 해당 레코드 | `InUse` 여부, 레코드 재사용 여부 |
| `.crdownload` rename 짝 | 브라우저 Downloads ([FOR-0191](./chrome-history.html)) | 다운로드 URL, 참조 페이지 |
| `StreamChange` | 해당 파일의 ADS 목록 | `Zone.Identifier`의 `HostUrl`, 은닉 데이터 |
| 원본 볼륨에 기록 없음 (복사 의심) | LNK / Shellbag / `USBSTOR` | 외부 매체 연결 시각과 대조 |
| 와이핑 패턴 (`DataOverwrite` 다수) | Prefetch / UserAssist ([FOR-0061](./userassist.html)) | 와이핑 도구 실행 흔적 |
| `Usn` 기준 시각 역행 지점 | EVTX 4616 / 시스템 로그 | 시스템 시계 변경 확인 |

## 흔한 함정

- **`FileDelete`를 "사용자가 지웠다"로 읽는 것** → 프로그램의 임시파일 정리, 편집기의 안전 저장, 캐시 만료도 전부 `FileDelete`다 → 같은 `EntryNumber`의 앞뒤 레코드와 `ParentPath`를 함께 봐야 한다.
- **휴지통 이동을 삭제로 세는 것** → 휴지통으로 보내면 `FileDelete`가 **아니라** `RenameOldName`/`RenameNewName`이 남는다 → `FileDelete`만 필터하면 휴지통 경유 삭제를 통째로 놓친다.
- **복사를 원본 쪽에서 찾는 것** → 읽기 작업은 저널에 기록되지 않는다 → 사본이 생긴 **대상** 볼륨의 `FileCreate`를 찾는다. 대상이 FAT32 USB면 저널이 없으므로 다른 artifact로 간다.
- **`BasicInfoChange`를 무조건 timestomp로 단정하는 것** → 압축 해제, 파일 복사, 백업 복원, 속성(읽기전용/숨김) 변경도 같은 플래그다 → **다른 플래그가 하나도 없는 단독 레코드**이고 `$MFT`의 `$SI`/`$FN` 불일치가 함께 있을 때만 확정한다.
- **`CLOSE`를 사건으로 세는 것** → 파일 하나의 저장이 3~5건으로 부풀어 통계가 무너진다 → 건수를 셀 때 `CLOSE` 포함 레코드만 센다.
- **`RenameNewName`만 보고 원래 이름을 못 찾는 것** → 원래 이름은 직전 `RenameOldName` 레코드에만 있다 → 항상 `Usn` 정렬로 짝을 함께 뽑는다.
- **`EntryNumber`만으로 같은 파일이라 단정하는 것** → MFT 레코드는 삭제 후 재사용되고 그때 `SequenceNumber`가 증가한다 → 두 값이 모두 같아야 동일 파일이다.
- **타임스탬프로만 정렬하는 것** → 같은 초에 수십 건이 몰려 인과가 뒤집힌다 → `Usn` 오름차순이 정답이다.
- **`FileName`에 ADS 이름이 나올 것이라 기대하는 것** → `StreamChange`/`NamedData*` 레코드의 `FileName`은 주 파일 이름이다 → 어떤 스트림인지는 `$MFT`나 대상 파일에서 직접 확인한다.
- **플래그가 없는 구간을 "아무 일 없었다"로 읽는 것** → 저널은 유한하다. 앞쪽이 잘려 나가면 시퀀스의 시작이 사라진다 → `Usn` 최솟값이 저널의 경계이며, 그보다 앞의 사건은 판단 불가다.
- **시간대 혼동** → `UpdateTimestamp`는 FILETIME(1601-01-01 UTC 기준 100ns)이고 MFTECmd CSV는 UTC로 출력한다 → KST 답이 필요하면 +9시간. Unix epoch와의 차이는 `11644473600`초다.

## 교차검증

같은 결론을 두 경로로 확인한다.

```powershell
# 1) $J — 플래그 시퀀스로 행위 판정
Import-Csv usn.csv | Where-Object {$_.EntryNumber -eq 128441} |
  Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath | Sort-Object Usn

# 2) $MFT — 그 엔트리가 지금 살아 있는가, SequenceNumber 가 맞는가
Import-Csv mft.csv | Where-Object {$_.EntryNumber -eq 128441} |
  Select-Object EntryNumber, SequenceNumber, InUse, FileName, ParentPath,
                Created0x10, LastModified0x10, Created0x30, LastModified0x30

# 3) 휴지통 — $I 기록이 있는가 (있으면 휴지통 경유가 확정)
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv
```

| `$J` 판정 | `$MFT`에서 기대되는 것 | 어긋나면 |
| --- | --- | --- |
| `FileDelete` 있음 | `InUse=False` 또는 엔트리 재사용(`SequenceNumber` 증가) | 저널만 남고 MFT가 이미 재사용됨 → 데이터 복구는 카빙으로 |
| `RenameNewName` 있음 | `$FN`의 이름 = 최종 이름 | `$MFT`가 옛 이름이면 저널이 더 최신 (마운트 시점 차이) |
| `BasicInfoChange` 단독 | `$SI` 시각 ≠ `$FN` 시각 | 두 시각이 같으면 timestomp가 아니라 정상 속성 변경 |
| `FileCreate` 없음 | `$SI` 생성 시각이 저널 최소 `Usn` 시각보다 앞 | 저널 절단 구간. "언제 생성됐나"는 `$MFT`로 답한다 |

## mini walkthrough

```text
문제:
"내부 문서 하나가 외부로 나갔습니다. 사용자가 그 파일을 어떻게 처리했는지
 순서대로 서술하고, 최종적으로 완전삭제였는지 휴지통 삭제였는지 판정하세요."
첨부: $J, $MFT

1. 파싱
   MFTECmd.exe -f '$J' -m '$MFT' --csv out --csvf usn.csv
   -> 528,441 레코드

2. 첫 시도 (실패):
   Import-Csv out\usn.csv | Where-Object { $_.UpdateReasons -match 'FileDelete' } |
     Where-Object { $_.FileName -match '\.pdf$' }
   -> 0건.
   "삭제 기록이 없으니 삭제 안 했다"고 결론 낼 뻔했다.  <-- 틀린 결론

   왜 틀렸나: 휴지통으로 보내는 동작은 FileDelete 가 아니라
   $Recycle.Bin 하위로의 Rename 으로 기록된다. FileDelete 필터로는 안 걸린다.

3. 접근 변경 — 이름으로 먼저 엔트리를 잡고, 플래그 필터를 버린다
   Import-Csv out\usn.csv | Where-Object { $_.FileName -match 'contract' } |
     Select-Object Usn, EntryNumber, FileName -Unique
   -> EntryNumber 204118 / FileName contract_2026.pdf

4. 그 엔트리의 전체 생애를 Usn 순으로
   Import-Csv out\usn.csv | Where-Object { $_.EntryNumber -eq 204118 } |
     Select-Object Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath |
     Sort-Object {[uint64]$_.Usn}

   Usn        UpdateTimestamp        UpdateReasons              FileName              ParentPath
   0x71a0400  2026-04-02 01:12:33Z   FileCreate                 contract.pdf.crdownload  .\Users\pshin\Downloads
   0x71a0480  2026-04-02 01:12:33Z   FileCreate|DataExtend      contract.pdf.crdownload  .\Users\pshin\Downloads
   0x71a0c10  2026-04-02 01:12:41Z   DataExtend|Close           contract.pdf.crdownload  .\Users\pshin\Downloads
   0x71a0d90  2026-04-02 01:12:41Z   RenameOldName              contract.pdf.crdownload  .\Users\pshin\Downloads
   0x71a0e20  2026-04-02 01:12:41Z   RenameNewName|Close        contract_2026.pdf        .\Users\pshin\Downloads
   0x71a0ea0  2026-04-02 01:12:41Z   StreamChange|Close         contract_2026.pdf        .\Users\pshin\Downloads
   0x7204880  2026-04-02 02:40:19Z   BasicInfoChange|Close      contract_2026.pdf        .\Users\pshin\Downloads
   0x7311a00  2026-04-02 03:05:52Z   RenameOldName              contract_2026.pdf        .\Users\pshin\Downloads
   0x7311a90  2026-04-02 03:05:52Z   RenameNewName|Close        $RQK41Z.pdf              .\$Recycle.Bin\S-1-5-21-...-1001

   여기서 전부 읽힌다.

5. 시퀀스 번역
   01:12:33  .crdownload 로 생성  -> 브라우저가 직접 받았다 (사본이 아니다)
   01:12:41  최종 이름으로 rename -> 다운로드 완료
   01:12:41  StreamChange         -> Zone.Identifier 부착 (인터넷 출처)
   02:40:19  BasicInfoChange 단독 -> 내용 무변경, 시각만 변경 = timestomp 후보
   03:05:52  $RQK41Z.pdf 로 rename, 부모가 $Recycle.Bin\<SID>
             -> 휴지통으로 이동. FileDelete 가 아니다. Shift+Delete 아님.

6. 짝 확인 — $I 생성 레코드
   Import-Csv out\usn.csv | Where-Object { $_.FileName -match 'QK41Z' } | Sort-Object Usn

   0x7311b20  2026-04-02 03:05:52Z   FileCreate|DataExtend|Close   $IQK41Z.pdf   .\$Recycle.Bin\S-1-5-21-...-1001
   -> $I 가 같은 시각에 생성됐다. 휴지통 삭제 확정.
      이후 $IQK41Z / $RQK41Z 에 FileDelete 가 없다 -> 휴지통은 비워지지 않았다.

7. timestomp 확증 — $MFT 대조
   Import-Csv out\mft.csv | Where-Object {$_.EntryNumber -eq 204118}
   -> Created0x10 = 2025-01-08 09:00:00 / Created0x30 = 2026-04-02 01:12:33
      $SI 생성 시각이 $FN 보다 15개월 앞선다 -> 02:40:19 의 BasicInfoChange 가 timestomp 확정

정답:
  01:12:33 다운로드 시작(contract.pdf.crdownload) -> 01:12:41 완료 및 contract_2026.pdf 로 확정
  -> 02:40:19 타임스탬프 조작 -> 03:05:52 휴지통으로 삭제(완전삭제 아님)
  $R 파일이 아직 살아 있으므로 $RQK41Z.pdf 를 그대로 복원할 수 있다.
```

2단계가 이 글의 존재 이유다. **`FileDelete` 필터로 0건이 나온 것을 "삭제 안 함"으로 읽으면 문제를 틀린다.** 휴지통 삭제는 rename으로 기록된다는 조합 지식이 방향을 바꿨다.

## 막혔을 때 다음 체크

1. `UpdateReasons`로 필터하기 전에 **`FileName`으로 엔트리를 먼저 특정**했는가
2. `Usn`으로 정렬했는가 — 타임스탬프 정렬이면 순서가 틀릴 수 있다
3. `EntryNumber`가 같은 레코드를 **전부** 뽑았는가 (필터를 좁혀 중간을 잘라내지 않았는가)
4. 휴지통 경유 가능성을 확인했는가 — `FileName`이 `$R`/`$I`로 시작하는 레코드 검색
5. `RenameOldName`의 짝(`RenameNewName`)을 함께 뽑았는가
6. `ParentEntryNumber`/`ParentPath` 변화를 봤는가 — 이름이 같아도 이동일 수 있다
7. 시퀀스에 `FileCreate`가 없는가 — 없으면 저널 절단 구간이거나 원래부터 있던 파일이다
8. `BasicInfoChange`가 단독인가, 아니면 압축 해제/복사의 부산물인가
9. 대상이 다른 볼륨/USB인 경우 **그 볼륨의 `$J`**를 별도로 확보했는가
10. 결론이 `$MFT`와 모순되지 않는가 — 모순되면 [FOR-0029](./logfile-usnjrnl-crosscheck.html)의 3자 대조로 간다

## 출처

- SRC-013 — Microsoft Learn, Change Journals: `USN_RECORD`의 `Reason` 비트 정의와 `USN_REASON_*` 상수 값 전체
- SRC-004 — Eric Zimmerman 문서: MFTECmd의 `$J` 파싱, `UpdateReasons` 문자열 표기와 CSV 컬럼
- SRC-086 — MITRE ATT&CK: Timestomp(T1070.006), Indicator Removal 계열 기법의 파일시스템 관측 지점
- 파서별 플래그 문자열 표기(`FileDelete` vs `File_Delete`)와 CSV 컬럼명은 도구 버전에 따라 다르므로 실제 CSV를 열어 확인할 것
- 위 walkthrough의 `Usn`·타임스탬프·엔트리 번호는 설명을 위한 예시 값이다
