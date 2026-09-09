---
id: FOR-0016
title: "FTK Imager로 디스크 이미지 열고 필요한 artifact만 꺼내기"
slug: "ftk-imager-open-image"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["E01", "RAW", "AD1", "$MFT", "$LogFile", "$UsnJrnl", "unallocated space", "$OrphanFiles"]
file_paths: ["C:\\$MFT", "C:\\$Extend\\$UsnJrnl", "C:\\Windows\\System32\\config", "C:\\Windows\\System32\\winevt\\Logs", "C:\\Windows\\Prefetch", "C:\\Users\\<user>\\NTUSER.DAT"]
registry_paths: []
event_ids: []
protocols: []
tools: ["FTK Imager", "Arsenal Image Mounter", "HxD", "HashCalc"]
commands: []
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["MD5", "SHA1", "Logical Size", "Physical Size", "Date Created", "Date Modified", "Date Accessed"]
file_formats: ["e01", "ex01", "s01", "aff", "raw", "dd", "ad1"]
primary_terms: ["FTK Imager", "ftk"]
keywords: ["FTK Imager", "이미지 열기", "Add Evidence Item", "Export Files", "Evidence Tree", "artifact 추출", "디스크 이미지", "E01 열기", "무결성 검증"]
aliases: ["ftk imager", "ftk", "이미지 열기", "E01 열기", "디스크 이미지 열기", "artifact 뽑기", "파일 추출하기", "ftk imager 사용법"]
symptom_keywords: ["이미지 파일을 열 수 없다", "$MFT를 못 꺼낸다", "삭제된 파일이 보이는데 복사가 안 된다", "어떤 파일을 꺼내야 하는지", "이미지가 여러 조각으로 나뉘어 있다", "E01이 뭔지 모르겠다"]
related: ["FOR-0017", "FOR-0021", "FOR-0027"]
source_ids: ["SRC-005", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`File > Add Evidence Item > Image File`로 이미지를 열고, Evidence Tree에서 `[root]`을 펼쳐 **`$MFT` / `$Extend\$UsnJrnl` / `Windows\System32\config` / `winevt\Logs` / 사용자 프로필**만 `Export Files`로 꺼내면 이후 분석에 필요한 재료가 전부 확보된다.

## 어떤 문제에서 필요한가

- 첨부가 `.E01`, `.001`, `.dd`, `.raw`, `.AD1` 같은 디스크 이미지인 모든 문제
- Autopsy ingest가 너무 느려서 **필요한 artifact만 빠르게 빼내야** 하는 상황
- 삭제 파일 목록을 눈으로 훑어야 하는 상황
- 이미지 해시를 검증해 무결성을 확인해야 하는 상황

CTF에서 FTK Imager의 가치는 "분석"이 아니라 **추출 속도**다. 이미지를 열고 30초 안에 필요한 파일을 꺼내 각자의 전용 파서로 넘기는 것이 정석이다.

## 문제에서 처음 볼 단서

1. 확장자 `.E01` / `.Ex01` / `.001`~`.00n` / `.dd` / `.raw` / `.img` / `.AD1`
2. 파일이 `image.E01`, `image.E02`, `image.E03`... 으로 **분할**되어 있다 → 첫 조각(`.E01`)만 지정하면 나머지는 자동으로 붙는다
3. `file`로 확인하면 E01은 `EVF`로 시작한다 ([FOR-0001](./30sec-triage.html))
4. 문제 지문의 명사가 어떤 artifact를 꺼낼지 결정한다 — "실행"→Prefetch, "로그인"→EVTX, "삭제"→`$UsnJrnl`

## 30초 절차

```text
1. File > Add Evidence Item...
2. Image File 선택 > Next
3. 이미지 경로 지정 (분할 이미지는 .E01 또는 .001 하나만)
4. Evidence Tree에서 파티션 > [root] 펼치기
5. 필요한 파일/폴더 우클릭 > Export Files...
6. 출력 폴더 지정
```

`Add Evidence Item` 화면의 4가지 소스 유형:

| 유형 | 대상 |
| --- | --- |
| **Physical Drive** | 물리 디스크 전체 (파티션 테이블 포함). 라이브 수집용 |
| **Logical Drive** | 마운트된 볼륨 하나 (`C:`). 파티션 테이블은 안 보인다 |
| **Image File** | **이미 만들어진 이미지 파일. CTF에서 거의 항상 이것** |
| **Contents of a Folder** | 폴더 트리 (논리 파일 집합) |

## 상세 절차

### 1단계 — 어떤 이미지 형식을 열 수 있나

| 형식 | 확장자 | 특징 |
| --- | --- | --- |
| EnCase | `.E01`, `.Ex01` | 압축 + 내부 CRC. 분할되면 `.E02`, `.E03`... |
| SMART | `.s01` | 압축 지원 |
| RAW (dd) | `.001`, `.dd`, `.raw`, `.img` | 압축 없음. 원본 크기 그대로 |
| AFF | `.aff` | 오픈 포맷 |
| AD1 | `.ad1` | **논리** 파일만 담은 커스텀 이미지 (파티션 구조 없음) |

`.VHD` / `.VHDX` / `.VMDK` / `.VDI` 는 [Arsenal Image Mounter](./arsenal-image-mounter.html)로 먼저 마운트한 뒤 `Logical Drive`로 여는 편이 확실하다.

### 2단계 — Evidence Tree 읽기

트리를 펼치면 이런 구조가 나온다.

```text
▼ image.E01
  ▼ Partition 1 [100MB]           <- EFI System Partition
  ▼ Partition 2 [237GB]           <- 본체
    ▼ NONAME [NTFS]
      ▼ [root]                    <- 여기가 C:\ 에 해당
        ├ $BadClus
        ├ $Extend                 <- $UsnJrnl 이 여기
        ├ $LogFile
        ├ $MFT                    <- 최우선 추출 대상
        ├ $MFTMirr
        ├ $Recycle.Bin
        ├ Users
        └ Windows
      ▶ [unallocated space]       <- 비할당 영역 (카빙 대상)
      ▶ [orphan]                  <- 부모를 잃은 파일 ($OrphanFiles)
  ▶ [unpartitioned space]
```

| 노드 | 의미 | 놓치면 안 되는 이유 |
| --- | --- | --- |
| `[root]` | 볼륨 루트 (= `C:\`) | 모든 artifact의 시작점 |
| `[unallocated space]` | 어떤 파일에도 속하지 않은 클러스터 | **삭제 파일 카빙 대상.** Export 후 foremost/photorec |
| `[orphan]` | MFT 레코드는 있으나 부모 디렉터리가 사라진 파일 | 삭제된 파일이 여기 모인다 |
| `[unpartitioned space]` | 파티션 밖 영역 | 숨긴 파티션·데이터 |

**File List 창의 빨간 X 아이콘이 삭제된 파일이다.** 아이콘만으로 즉시 식별할 수 있다.

### 3단계 — 꺼낼 파일 목록 (이 표가 핵심)

| 목표 | 경로 | 파서 |
| --- | --- | --- |
| 전체 파일 목록·타임라인 | `[root]\$MFT` | MFTECmd / analyzeMFT ([FOR-0021](./mft-basics.html)) |
| 삭제·이름변경 흔적 | `[root]\$Extend\$UsnJrnl` (**`$J` 스트림 포함**) | MFTECmd `-f $J` ([FOR-0027](./usnjrnl-basics.html)) |
| 파일시스템 트랜잭션 | `[root]\$LogFile` | NTFS Log Tracker |
| 휴지통 | `[root]\$Recycle.Bin` (SID 하위 전체) | RBCmd |
| 시스템 레지스트리 | `Windows\System32\config\` → `SAM`, `SYSTEM`, `SOFTWARE`, `SECURITY` **+ 각 `.LOG1`/`.LOG2`** | RegistryExplorer / RegRipper |
| 사용자 레지스트리 | `Users\<user>\NTUSER.DAT` **+ `.LOG1`/`.LOG2`** | RegRipper ([FOR-0061](./userassist.html)) |
| 탐색기 활동 | `Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | ShellBags 파서 |
| 이벤트 로그 | `Windows\System32\winevt\Logs\` (폴더 전체) | EvtxECmd ([FOR-0083](./event-4624-logon.html)) |
| 프로그램 실행 | `Windows\Prefetch\` (폴더 전체) | WinPrefetchView / PECmd |
| 실행 파일 이력 | `Windows\AppCompat\Programs\Amcache.hve` | AmcacheParser |
| 브라우저 | `Users\<user>\AppData\Local\Google\Chrome\User Data\Default\` (**`History*` 전부**) | sqlite3 ([FOR-0191](./chrome-history.html)) |
| 바로가기·최근문서 | `Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` | LECmd / JLECmd |
| 사용 통계 | `Windows\System32\sru\SRUDB.dat` | SrumECmd / ESEDatabaseView |
| 검색 색인 | `ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | WinSearchDBAnalyzer |
| 스케줄 작업 | `Windows\System32\Tasks\` | 텍스트(XML) |
| 사용자 문서 | `Users\<user>\Desktop`, `Documents`, `Downloads` | 상황에 따라 |

**트랜잭션 로그(`.LOG1`, `.LOG2`)를 함께 꺼내는 것을 잊지 않는다.** 없으면 가장 최근 레지스트리 변경이 누락된다 ([FOR-0061](./userassist.html)의 `rla` 절 참고).

### 4단계 — `$UsnJrnl:$J` 꺼내기 (자주 실패하는 지점)

`$UsnJrnl`은 파일 이름이고 데이터는 **ADS인 `$J`에 있다.** FTK Imager는 이를 별도 항목으로 보여준다.

```text
[root] > $Extend > $UsnJrnl 을 선택하면
File List 창에 다음이 나온다:

  Name              Type          Size
  $UsnJrnl          NTFS Alt Data Stream   0
  $UsnJrnl:$J       NTFS Alt Data Stream   35,651,584      <- 이것을 Export
  $UsnJrnl:$Max     NTFS Alt Data Stream   32
```

`$J`를 골라야 한다. `$UsnJrnl`만 꺼내면 0바이트 파일을 얻는다.

`$J`는 sparse 파일이라 **논리 크기가 수십 GB로 표시될 수 있다.** Export하면 앞쪽이 0으로 채워진 큰 파일이 나오지만 MFTECmd는 정상 처리한다.

### 5단계 — 무결성 검증과 해시

```text
File > Verify Drive/Image...
```

이미지 안에 저장된 해시와 실제 계산 해시를 비교한다. E01은 획득 당시 해시를 내부에 갖고 있어 자동 대조되고, RAW는 계산만 해준다.

```text
Verify Results
  Name              image.E01
  Sector count      500118192
  MD5 Hash
    Computed hash   3f1a...   Stored verification hash   3f1a...   Report Hash Verified
  SHA1 Hash
    Computed hash   9b2c...   Stored verification hash   9b2c...   Report Hash Verified
```

개별 파일 해시는 File List에서 파일들을 선택해 우클릭 → `Export File Hash List...` → CSV로 나온다. 추출물이 원본과 같은지 확인할 때 쓴다.

### 6단계 — 디렉터리 목록만 CSV로

전체 파일 목록을 텍스트로 확보하면 `rg`/PowerShell로 검색할 수 있어 GUI보다 훨씬 빠르다.

```text
[root] 우클릭 > Export Directory Listing...
```

```powershell
# 나온 CSV에서 특정 확장자 찾기
Import-Csv listing.csv | Where-Object { $_.Filename -match '\.(7z|zip|rar)$' } |
  Select-Object Filename, 'Full Path', Size, Created
```

`$MFT` 파싱과 목적이 겹치지만, **`$MFT` 파서가 없을 때의 대안**으로 유용하다.

### 7단계 — 부가 기능 (라이브 시스템에서)

| 메뉴 | 하는 일 |
| --- | --- |
| `File > Create Disk Image` | 이미지 생성 (RAW/E01/AFF/SMART). 분할 크기·압축·해시 설정 |
| `File > Capture Memory` | 물리 메모리 덤프 (`.mem`) + pagefile 옵션 |
| `File > Obtain Protected Files` | 잠긴 레지스트리 hive를 라이브에서 복사 |
| `File > Image Mounting` | 이미지를 드라이브 문자로 마운트 (읽기 전용) |
| `File > Export Logical Image (AD1)` | 선택한 파일만 담은 논리 이미지 생성 |

`Capture Memory`는 메모리 문제의 출발점이 된다 ([FOR-0214](./volatility-pslist.html)).

## 출력 필드 해석

File List 창의 컬럼이다.

| 컬럼 | 의미 | 함정 |
| --- | --- | --- |
| `Name` | 파일명 | ADS는 `파일명:스트림명`으로 표시 |
| `Size` | **논리 크기** (바이트) | 실제 디스크 점유(물리 크기)와 다르다 |
| `Type` | `Regular File` / `Directory` / `NTFS Alt Data Stream` / `Unallocated space` | ADS 식별 |
| `Date Modified` | 수정 시각 | **`$SI` 기준. 조작 가능** |
| `Date Created` | 생성 시각 | 위와 동일 |
| `Date Accessed` | 접근 시각 | Win7+ 기본 갱신 비활성인 경우 많음 |
| 빨간 X 아이콘 | **삭제된 파일** | 아이콘만으로 판별 |

**FTK Imager가 보여주는 시각은 `$STANDARD_INFORMATION`(`$SI`) 기준이다.** timestomp를 탐지하려면 `$MFT`를 꺼내 `$SI`와 `$FN`을 비교해야 한다 ([FOR-0021](./mft-basics.html)).

하단 Viewer 창은 세 모드로 전환된다.

| 모드 | 용도 |
| --- | --- |
| Hex | 매직 바이트 확인. 확장자 위조 즉시 판별 |
| Text | 텍스트 파일·설정·로그 미리보기 |
| Automatic | 이미지 파일 썸네일 표시 |

파일을 꺼내기 전에 Hex 모드로 헤더만 확인하는 습관이 시간을 아낀다.

## pivot: 다음에 볼 artifact

| FTK Imager에서 확인한 것 | 다음 목표 |
| --- | --- |
| 사용자 폴더 이름 | 그 사용자의 `NTUSER.DAT` → UserAssist ([FOR-0061](./userassist.html)) |
| 의심 파일 발견 | Hex 헤더 확인 → Export → `file`/`strings`/해시 |
| 삭제 파일(빨간 X) | `$MFT` + `$UsnJrnl` 로 삭제 시각·원래 이름 ([FOR-0027](./usnjrnl-basics.html)) |
| 파일이 안 보임 | `[unallocated space]` Export → foremost/photorec 카빙 |
| `[orphan]` 내용 | 삭제된 디렉터리 트리 복원 |
| 파티션이 하나만 보임 | `[unpartitioned space]` 확인 → 숨긴 파티션 |
| 시간대 확인 필요 | `SYSTEM` hive의 `TimeZoneInformation` |
| Prefetch 존재 | 실행 이력 → Amcache/UserAssist 교차검증 |

## 흔한 함정

- **`$UsnJrnl`만 꺼내고 `$J`를 놓치는 것.** 0바이트를 얻는다. `$UsnJrnl:$J`를 선택해야 한다.
- **레지스트리 hive만 꺼내고 `.LOG1`/`.LOG2`를 두고 오는 것.** 최신 변경이 누락된다.
- **Chrome `History`만 꺼내고 `History-wal`을 두고 오는 것.** 최근 방문이 사라진다 ([FOR-0191](./chrome-history.html)).
- **분할 이미지의 조각을 전부 지정하려 하는 것.** `.E01`(또는 `.001`) 하나만 지정하면 나머지는 자동으로 이어진다. 단 **모든 조각이 같은 폴더에 있어야 한다.**
- **삭제 파일을 Export하고 내용이 온전할 것으로 기대하는 것.** MFT 레코드는 남았지만 데이터 클러스터는 재할당되었을 수 있다. 크기가 맞는지, 헤더가 온전한지 확인한다.
- **`Logical Drive`로 열고 파티션 테이블을 찾는 것.** 논리 볼륨에는 MBR/GPT가 없다. `Physical Drive` 또는 `Image File`로 열어야 파티션이 보인다 ([FOR-0019](./mbr-gpt.html)).
- **마운트된 볼륨에서 Explorer로 `$MFT`를 복사하려는 것.** NTFS 드라이버가 잠근다. 마운트했더라도 **FTK Imager로 `Logical Drive`를 열어** 꺼내야 한다.
- **Export 대상 폴더를 이미지와 같은 드라이브로 잡는 것.** 대용량 Export 시 공간이 터진다.
- **`Size`를 물리 크기로 착각하는 것.** 논리 크기다. sparse/compressed 파일에서 크게 차이 난다.
- **시간대 설정을 안 보는 것.** FTK Imager는 시각을 어느 시간대로 표시하는지 명시하지 않는 경우가 있다. 결론은 반드시 `$MFT` 파서(UTC 출력)로 재확인한다.
- **AD1 이미지에서 `$MFT`를 찾는 것.** AD1은 논리 파일만 담아 파일시스템 메타파일이 없다.

## 교차검증

```text
1) FTK Imager 의 File List 시각        -> $SI 기준
2) 꺼낸 $MFT 를 MFTECmd 로 파싱        -> $SI 와 $FN 둘 다
3) 꺼낸 $J 를 MFTECmd 로 파싱          -> 실제 변경 사건과 시각
4) Export File Hash List 의 MD5        -> 추출물 해시와 일치 확인
5) Verify Drive/Image                  -> 이미지 자체 무결성
```

1)과 2)의 시각이 다르면 timestomp이거나 FTK Imager가 표시하는 시간대가 다른 것이다. **2)를 신뢰한다.**

Arsenal로 같은 이미지를 마운트해 파일 개수와 크기를 비교하면 FTK Imager의 파싱 오류를 걸러낼 수 있다 ([FOR-0017](./arsenal-image-mounter.html)).

## mini walkthrough

```text
문제:
"직원 PC 이미지입니다. 반출된 파일 이름과 반출 시각을 구하세요."
첨부: pc01.E01 (12 GB), pc01.E02, pc01.E03

1. file pc01.E01
   -> pc01.E01: EWF/Expert Witness/EnCase image file format

2. FTK Imager: File > Add Evidence Item > Image File > pc01.E01
   (E02/E03 는 지정하지 않는다. 같은 폴더에 있으면 자동으로 이어짐)

3. File > Verify Drive/Image
   -> MD5/SHA1 Verified. 이미지 손상 없음.

4. Evidence Tree 확인
   Partition 1 [100MB]  EFI
   Partition 2 [11GB]   NONAME [NTFS]  <- 본체
     [root]
     [unallocated space]

5. 첫 시도 (느렸던 접근):
   Users\jhkim\Documents 를 눈으로 훑었다.
   파일이 400개가 넘고 반출된 파일이 이미 삭제되어 보이지 않았다.

6. 접근 변경 — 메타파일부터 꺼낸다
   [root] 에서 Export Files:
     $MFT
     $Extend > $UsnJrnl:$J          <- $J 를 명시적으로 선택
     $Recycle.Bin (폴더 전체)
   Users\jhkim 에서:
     NTUSER.DAT, NTUSER.DAT.LOG1, NTUSER.DAT.LOG2
   Windows\System32\config 에서:
     SYSTEM, SOFTWARE + 각 .LOG1/.LOG2

   여기까지 40초.

7. $J 파싱
   MFTECmd.exe -f "$J" -m "$MFT" --csv out --csvf usn.csv

   Import-Csv out\usn.csv |
     Where-Object { $_.UpdateReasons -match 'FileDelete' -and
                    $_.FileName -match '\.(7z|zip|rar)$' }

   UpdateTimestamp        FileName          ParentPath
   2026-03-14 07:39:52Z   report_final.7z   .\Users\jhkim\Documents

8. 이름 변경 이력 확인 (같은 EntryNumber 추적)
   -> 원래 이름 customer_db_2026.7z 로 확인 (FOR-0027 참조)

9. 반출 수단 확인
   SYSTEM hive 의 USBSTOR + $J 의 같은 시간대 변경
   -> 07:35 경 rclone.exe 생성. 클라우드 업로드.

10. 시간대 보정
    SYSTEM\ControlSet001\Control\TimeZoneInformation -> Korea Standard Time
    07:39:52 UTC = 16:39:52 KST

정답: customer_db_2026.7z (report_final.7z 로 위장), 2026-03-14 16:39:52 KST 삭제
```

5→6단계의 전환이 핵심이다. **GUI로 폴더를 훑는 것이 아니라 메타파일을 꺼내 전용 파서에 넘기는 것**이 FTK Imager의 올바른 사용법이다.

## 막혔을 때 다음 체크

1. 이미지가 안 열리는가 → `file`로 형식 확인. VHD/VMDK면 Arsenal로 먼저 마운트
2. 분할 이미지의 모든 조각이 **같은 폴더**에 있는가
3. `Verify Drive/Image`로 이미지 손상 여부를 확인했는가
4. `$UsnJrnl:$J`를 선택했는가 (`$UsnJrnl`이 아니라)
5. 레지스트리 hive의 `.LOG1`/`.LOG2`를 함께 꺼냈는가
6. 파일이 안 보이는가 → `[unallocated space]`와 `[orphan]` 확인
7. 파티션이 하나만 보이는가 → `[unpartitioned space]` 확인
8. 사용자가 여러 명인가 → 모든 프로필 확인
9. 시각이 이상한가 → `SYSTEM` hive의 시간대 확인 후 `$MFT` 파서 값으로 재검증
10. 대용량 카빙이 필요한가 → `[unallocated space]` Export 후 foremost/photorec
11. Export가 느린가 → 목적 파일만 선별. 전체 Export는 이미지 크기만큼 시간이 든다

## 출처

- SRC-005 — Microsoft Learn, Master File Table: `$MFT` 및 NTFS 메타파일 목록
- SRC-004 — Eric Zimmerman 문서: 추출한 artifact를 넘길 파서(MFTECmd, RegistryExplorer, EvtxECmd, PECmd)의 입력 요구사항
- FTK Imager의 메뉴 경로와 컬럼명은 도구 버전에 따라 미세하게 다를 수 있으므로 실제 화면에서 확인할 것
