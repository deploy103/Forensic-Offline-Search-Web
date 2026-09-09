---
id: FOR-0020
title: "NTFS 핵심 구조: 부트섹터 오프셋부터 속성·data run까지"
slug: "ntfs-structure"
category: "디스크/NTFS"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["$Boot", "VBR", "Volume Boot Record", "cluster", "data run", "Update Sequence Array", "$Extend", "ADS", "$AttrDef", "$UpCase", "backup boot sector"]
file_paths: ["C:\\$Boot", "C:\\$MFT", "C:\\$MFTMirr", "C:\\$LogFile", "C:\\$Volume", "C:\\$AttrDef", "C:\\$Bitmap", "C:\\$BadClus", "C:\\$Secure", "C:\\$UpCase", "C:\\$Extend", "C:\\$Extend\\$UsnJrnl", "C:\\$Extend\\$Quota", "C:\\$Extend\\$ObjId", "C:\\$Extend\\$Reparse"]
registry_paths: []
event_ids: []
protocols: []
tools: ["HxD", "Sleuth Kit", "FTK Imager", "Arsenal Image Mounter", "Autopsy"]
commands: ["fsstat -o 2048 image.dd", "xxd -s 1048576 -l 128 image.dd", "mmls image.dd", "dir /r C:\\Users", "Get-Item -Path file.txt -Stream *"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Sector Size", "Cluster Size", "First Cluster of MFT", "Size of MFT Entries", "Total Cluster Range", "Volume Serial Number", "OEM Name"]
file_formats: ["ntfs"]
primary_terms: ["NTFS 구조", "부트섹터", "VBR", "Volume Boot Record", "data run", "클러스터 크기"]
keywords: ["NTFS", "부트섹터", "VBR", "Volume Boot Record", "클러스터", "cluster size", "attribute", "data run", "resident", "non-resident", "$Extend", "ADS", "fixup", "0x55AA"]
aliases: ["ntfs 구조", "부트섹터", "클러스터 크기 확인", "vbr", "ntfs 오프셋", "data run 해석", "ntfs 속성 타입", "볼륨 시리얼"]
symptom_keywords: ["파일시스템을 못 읽는다", "클러스터 크기를 모르겠다", "MFT가 어디 있는지 모르겠다", "부트섹터가 깨졌다", "NTFS인지 확인하고 싶다", "data run이 뭔지 모르겠다"]
related: ["FOR-0019", "FOR-0021", "FOR-0035"]
source_ids: ["SRC-005", "SRC-032", "SRC-081"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

NTFS 볼륨의 모든 분석은 **첫 섹터(VBR)의 세 값** — `0x0B` bytes-per-sector, `0x0D` sectors-per-cluster, `0x30` MFT 시작 클러스터 — 에서 출발한다. 이 셋을 곱하고 더하면 `$MFT`의 정확한 바이트 오프셋이 나오고, 그 뒤 모든 파일 정보는 속성(attribute) 타입 번호로 찾는다.

## 개념

NTFS는 **볼륨 자체를 파일들의 집합으로** 관리한다. 부트섹터, MFT, 비트맵, 로그까지 전부 MFT에 레코드를 가진 "파일"이다.

- 할당 단위는 **클러스터**다. `클러스터 크기 = bytes-per-sector × sectors-per-cluster` (기본 4096바이트)
- 볼륨 전체 클러스터에는 0부터 번호가 붙는다 → **LCN** (Logical Cluster Number)
- 파일 내부의 클러스터 순번은 **VCN** (Virtual Cluster Number)
- 파일 내용의 위치는 "VCN → LCN 매핑" 목록, 즉 **data run**으로 표현된다

핵심 계산식 두 개만 외운다.

```text
볼륨 시작 바이트 = 파티션 시작 섹터 × 512
$MFT 바이트 오프셋 = 볼륨 시작 바이트 + (0x30의 값 × 클러스터 크기)
레코드 N의 오프셋 = $MFT 오프셋 + (N × 레코드 크기)
```

파티션 시작 섹터는 `mmls`로 얻는다 ([FOR-0019](./mbr-gpt.html)).

### Volume Boot Record (부트섹터, `$Boot`)

파티션의 **첫 섹터 512바이트**다. MFT 레코드 7번(`$Boot`)이 이 영역을 가리킨다.

| 오프셋 | 크기 | 필드 | 실전 의미 |
| --- | --- | --- | --- |
| `0x00` | 3 | jump instruction | 보통 `EB 52 90` |
| `0x03` | 8 | **OEM ID** | `4E 54 46 53 20 20 20 20` = `"NTFS    "` (뒤 4칸은 공백). **NTFS 판정 근거** |
| `0x0B` | 2 | **bytes per sector** | 보통 `00 02` = 512. 4Kn 디스크는 4096 |
| `0x0D` | 1 | **sectors per cluster** | `08` = 8 → 클러스터 4096바이트 |
| `0x0E` | 2 | reserved sectors | NTFS에서는 0 |
| `0x15` | 1 | media descriptor | 고정 디스크는 `F8` |
| `0x18` | 2 | sectors per track | 지오메트리. 분석에 안 쓴다 |
| `0x1A` | 2 | number of heads | 위와 동일 |
| `0x1C` | 4 | hidden sectors | 파티션 시작 섹터(=`mmls` 값과 일치해야 한다) |
| `0x28` | 8 | **total sectors** | 볼륨 섹터 수 |
| `0x30` | 8 | **$MFT 시작 LCN** | MFT를 찾는 값 |
| `0x38` | 8 | **$MFTMirr 시작 LCN** | MFT 손상 시 백업 위치 |
| `0x40` | 1 | **clusters per MFT record** | **signed byte.** 아래 설명 |
| `0x44` | 1 | clusters per index buffer | 같은 signed 규칙. 보통 `01` = 1클러스터 |
| `0x48` | 8 | **volume serial number** | 64비트. 하위 4바이트(`0x48`~`0x4B`)가 `vol` 명령·LNK가 쓰는 32비트 시리얼 |
| `0x50` | 4 | checksum | 실제로 검증하지 않는 구현이 많다 |
| `0x1FE` | 2 | **부트 시그니처** | `55 AA` |

**`0x40`을 unsigned로 읽는 것이 가장 흔한 실수다.** 이 바이트는 부호 있는 값이고, 규칙이 두 가지다.

| `0x40` 값 | 해석 | 레코드 크기 |
| --- | --- | --- |
| `0x01` ~ `0x7F` (양수) | 레코드가 그 개수만큼의 **클러스터** | `값 × 클러스터 크기` |
| `0xF6` = -10 | 음수 → `2^10` **바이트** | 1024바이트 (가장 흔함) |
| `0xF7` = -9 | `2^9` | 512바이트 |
| `0xF5` = -11 | `2^11` | 2048바이트 |

즉 `F6`은 246이 아니라 -10이고, 답은 1024바이트다.

### 백업 부트섹터

NTFS는 **볼륨의 마지막 섹터에 부트섹터 사본**을 둔다. `0x28`의 total sectors 값이 실제 볼륨 섹터 수보다 1 작은 것이 일반적인 이유가 이것이다(마지막 섹터를 백업용으로 제외).

첫 섹터가 0으로 밀렸거나 부트킷에 덮인 경우, 마지막 섹터에서 `"NTFS    "`와 `55 AA`를 찾으면 클러스터 크기와 MFT 위치를 복원할 수 있다.

## 파일 / 경로

### 메타파일 (MFT 레코드 0~15)

| 레코드 | 파일 | 내용 | 포렌식 가치 |
| --- | --- | --- | --- |
| 0 | `$MFT` | MFT 자기 자신 | 전체 파일 목록 ([FOR-0021](./mft-basics.html)) |
| 1 | `$MFTMirr` | MFT 앞부분(보통 레코드 0~3) 사본 | MFT 헤더 손상 복구 |
| 2 | `$LogFile` | 트랜잭션 로그 | 상세 변경 이력 ([FOR-0025](./logfile-basics.html)) |
| 3 | `$Volume` | 볼륨 이름·NTFS 버전·dirty flag | 강제 종료 여부 |
| 4 | `$AttrDef` | 속성 타입 정의 테이블 | 속성 번호↔이름 대조 |
| 5 | `.` | **루트 디렉터리** | 경로 복원의 종착점 |
| 6 | `$Bitmap` | 클러스터 할당 비트맵 | 미할당 영역 판정 |
| 7 | `$Boot` | 부트섹터 + 부트스트랩 코드 | 위 VBR 표 |
| 8 | `$BadClus` | 불량 클러스터 목록 | 데이터 은닉에 악용되는 경우 |
| 9 | `$Secure` | 보안 기술자 저장소(`$SDS`/`$SDH`/`$SII`) | 권한·소유자 이력 |
| 10 | `$UpCase` | 대문자 변환 테이블 | 파일명 비교 규칙 |
| 11 | `$Extend` | 확장 메타파일 **디렉터리** | 아래 표 |
| 12~15 | — | 예약 | 보통 비어 있다 |

### `$Extend` 하위

| 파일 | 내용 | 왜 보나 |
| --- | --- | --- |
| `$UsnJrnl` | Change Journal. 데이터는 ADS `:$J`, 설정은 `:$Max` | 생성·삭제·이름변경 이력 ([FOR-0027](./usnjrnl-basics.html)) |
| `$Quota` | 사용자별 디스크 쿼터 | SID별 사용량 → 계정 존재 근거 |
| `$ObjId` | 파일별 Object ID(GUID) | LNK의 Droid GUID와 대조해 파일 동일성 판정 |
| `$Reparse` | 재분석 지점 인덱스 | 심볼릭 링크·마운트 지점·중복 제거 |
| `$RmMetadata` | TxF 트랜잭션 메타데이터(Vista+) | 하위에 `$Txf`, `$TxfLog` |

`$Extend`는 디렉터리이므로 FTK Imager에서 `[root]` 아래 폴더로 펼쳐야 보인다 ([FOR-0016](./ftk-imager-open-image.html)).

### 추출 방법

| 대상 | 방법 |
| --- | --- |
| VBR 512바이트 | `xxd -s <볼륨시작바이트> -l 512 image.dd`, 또는 HxD로 물리 디스크 열기 |
| 백업 VBR | `xxd -s $(( (파티션끝섹터) * 512 )) -l 512 image.dd` |
| 메타파일 전체 | FTK Imager로 볼륨 루트 → `$MFT`/`$LogFile`/`$Extend` 선택 → Export Files |
| Sleuth Kit | `icat -o <offset> image.dd 7 > \$Boot` (레코드 번호로 지정) |
| 마운트 후 | Arsenal Image Mounter로 읽기 전용 마운트 ([FOR-0017](./arsenal-image-mounter.html)) |

## 주요 필드

### 속성 타입 번호

MFT 레코드는 헤더 + 속성 목록이다. 속성은 **4바이트 타입 번호**로 구분한다.

| 타입 | 이름 | 내용 |
| --- | --- | --- |
| `0x10` | `$STANDARD_INFORMATION` | MACB 4개, 파일 속성 플래그, USN, SecurityId |
| `0x20` | `$ATTRIBUTE_LIST` | 속성이 레코드 하나에 안 들어갈 때 확장 레코드 목록 |
| `0x30` | `$FILE_NAME` | 파일 이름 + **두 번째 MACB 세트** + 부모 레코드 참조 |
| `0x40` | `$OBJECT_ID` | 파일 GUID |
| `0x50` | `$SECURITY_DESCRIPTOR` | (구형) 권한 정보 |
| `0x60` | `$VOLUME_NAME` | 볼륨 라벨 (레코드 3) |
| `0x70` | `$VOLUME_INFORMATION` | NTFS 버전, dirty flag (레코드 3) |
| `0x80` | `$DATA` | **실제 파일 내용** 또는 data run |
| `0x90` | `$INDEX_ROOT` | 디렉터리 색인 루트 (**항상 resident**) |
| `0xA0` | `$INDEX_ALLOCATION` | 색인이 커질 때의 `INDX` 레코드 (항상 non-resident) |
| `0xB0` | `$BITMAP` | 색인/MFT 할당 비트맵 |
| `0xC0` | `$REPARSE_POINT` | 심볼릭 링크·마운트 지점 대상 |
| `0xD0` / `0xE0` | `$EA_INFORMATION` / `$EA` | 확장 속성 (WSL 메타데이터가 여기 들어간다) |
| `0x100` | `$LOGGED_UTILITY_STREAM` | EFS 암호화 정보(`$EFS`), TxF 데이터 |

속성 헤더의 **`0x08` 바이트가 non-resident 플래그**다. `0x00`이면 resident, `0x01`이면 non-resident.

### resident vs non-resident

| | resident | non-resident |
| --- | --- | --- |
| 내용 위치 | MFT 레코드 **내부** | 볼륨의 클러스터 |
| 크기 한계 | 레코드 잔여 공간(1024바이트 레코드에서 대략 700바이트 이하) | 무제한 |
| `$MFT`만으로 내용 복구 | **가능** | 불가능 (볼륨 필요) |
| 어떤 속성이 | `$STANDARD_INFORMATION`, `$FILE_NAME`, `$INDEX_ROOT`, 작은 `$DATA` | 큰 `$DATA`, `$INDEX_ALLOCATION`, `$BITMAP` |

### data run 디코딩

non-resident `$DATA`는 클러스터 구간 목록으로 저장된다. 각 구간의 첫 바이트가 길이 정보다.

```text
헤더 바이트: 상위 니블 = 오프셋 필드 바이트 수
              하위 니블 = 길이 필드 바이트 수
그 다음: [길이 필드][오프셋 필드]
오프셋은 signed, 그리고 "직전 run의 LCN에 대한 상대값"
0x00 이 나오면 목록 종료
```

실제 예 (클러스터 4096바이트 가정):

```text
21 18 34 56   11 05 E0   00

1) 21 -> 길이 1바이트, 오프셋 2바이트
   길이 = 0x18 = 24 클러스터
   오프셋 = 0x5634 = 22068 (첫 run이므로 절대 LCN)
   => LCN 22068 부터 24 클러스터 = 바이트 오프셋 22068*4096 = 90,390,528

2) 11 -> 길이 1바이트, 오프셋 1바이트
   길이 = 0x05 = 5 클러스터
   오프셋 = 0xE0 = -32 (signed!)
   => LCN = 22068 - 32 = 22036 부터 5 클러스터

3) 00 -> 종료

총 29 클러스터 = 118,784바이트 할당
```

**오프셋 필드 바이트 수가 0인 run은 sparse(구멍)** 다. 예: `01 20` = 32 클러스터가 실제 할당 없이 0으로 읽힌다. `$UsnJrnl:$J`가 이 방식으로 앞부분을 비운다.

### ADS (Alternate Data Stream)

`$DATA` 속성은 이름을 가질 수 있고, 이름 있는 `$DATA`가 여러 개 붙는다. 기본 스트림은 이름이 없다.

```text
표기법:  파일명:스트림명
예:      report.docx:Zone.Identifier
         notes.txt:hidden
```

| 스트림 | 의미 |
| --- | --- |
| `:Zone.Identifier` | 다운로드 출처 표시. 내용의 `ZoneId=3` = 인터넷 |
| `:$DATA` | 기본 스트림의 정식 이름 (`file.txt::$DATA`) |
| `:SmartScreen`, `:$SmartScreen` | Windows의 평판 검사 결과 |
| 임의 이름 | CTF의 데이터 은닉 지점 |

ADS는 **일반 `dir`과 탐색기 크기 표시에 나타나지 않는다.** `dir /r` 또는 PowerShell로 확인한다.

### Update Sequence Array (fixup)

MFT 레코드와 `INDX`/`RCRD` 페이지는 **섹터 단위 쓰기 실패를 탐지하기 위해** 각 512바이트 섹터의 **마지막 2바이트를 USN 값으로 덮어쓴다.** 원본 2바이트는 레코드 헤더의 Update Sequence Array에 따로 보관된다.

- 레코드 헤더 `0x04`(2바이트) = Update Sequence Array **오프셋**
- 레코드 헤더 `0x06`(2바이트) = Array **크기(워드 단위)**

결과: **HxD로 MFT 레코드를 raw로 읽으면 512바이트 경계마다 2바이트가 엉뚱한 값이다.** 파서는 이를 원본으로 되돌려(fixup) 해석한다. 수동 분석 시 이 2바이트를 실제 데이터로 착각하면 오프셋이 전부 밀린다.

## 빠른 명령

```bash
fsstat -o 2048 image.dd
```

```bash
# 1) 파티션 오프셋 확인 (섹터 단위)
mmls image.dd

# 2) VBR 앞 128바이트 — 2048섹터 * 512 = 1048576
xxd -s 1048576 -l 128 image.dd

# 3) 파일시스템 요약 (오프셋은 섹터 단위로 준다)
fsstat -o 2048 image.dd

# 4) 메타파일 추출
icat -o 2048 image.dd 7  > '$Boot'
icat -o 2048 image.dd 0  > '$MFT'
icat -o 2048 image.dd 2  > '$LogFile'
```

`fsstat` 출력 해석:

```text
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 054F2C9D7E3B1A8C     <- VBR 0x48 (바이트 역순 표기)
OEM Name: NTFS                             <- VBR 0x03
Volume Name: EVIDENCE                      <- $Volume 의 $VOLUME_NAME
Version: Windows XP                        <- $VOLUME_INFORMATION

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 262144               <- VBR 0x30
First Cluster of MFT Mirror: 2             <- VBR 0x38
Size of MFT Entries: 1024 bytes            <- VBR 0x40 (0xF6 = -10 = 2^10)
Size of Index Records: 4096 bytes          <- VBR 0x44
Range: 0 - 90111                           <- 현재 MFT 레코드 번호 범위 (총 90,112개)
Root Directory: 5                          <- 루트는 항상 레코드 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512                           <- VBR 0x0B
Cluster Size: 4096                         <- 0x0B * 0x0D
Total Cluster Range: 0 - 1638398
Total Sector Range: 0 - 13107198           <- VBR 0x28
```

이 출력만으로 `$MFT` 오프셋이 나온다: `1048576 + 262144 × 4096 = 1,074,790,400`.

```powershell
# ADS 확인 (Windows)
Get-Item -Path C:\case\report.docx -Stream *

# Zone.Identifier 내용 읽기
Get-Content -Path C:\case\report.docx -Stream Zone.Identifier

# 하위 폴더 전체의 ADS 목록
Get-ChildItem C:\Users -Recurse -File | ForEach-Object { Get-Item $_.FullName -Stream * } |
  Where-Object { $_.Stream -ne ':$DATA' } | Select-Object FileName, Stream, Length
```

```text
REM cmd 한 줄로도 된다 — ADS가 있으면 파일명 아래 별도 행으로 표시된다
dir /r C:\Users\jhkim\Downloads
```

## 함께 보는 artifact

| VBR/구조에서 얻은 값 | 다음에 볼 것 | 확인할 것 |
| --- | --- | --- |
| 클러스터 크기 | 카빙·슬랙 분석 | 파일 슬랙 크기 = 클러스터 크기 − 실제 크기 |
| `$MFT` 오프셋 | `$MFT` ([FOR-0021](./mft-basics.html)) | 전체 파일 목록, MACB |
| `$Extend\$UsnJrnl:$J` | `$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html)) | 삭제·이름변경 이력 |
| `$LogFile` | `$LogFile` ([FOR-0025](./logfile-basics.html)) | 트랜잭션 단위 상세 |
| 볼륨 시리얼 하위 4바이트 | LNK, Jump List | 같은 볼륨에서 만들어진 바로가기 대조 |
| `$Bitmap` | 미할당 영역 카빙 | 어느 클러스터가 비었는가 |
| ADS 목록 | `Zone.Identifier`, 브라우저 History ([FOR-0191](./chrome-history.html)) | 다운로드 출처 |
| `$ObjId` | LNK의 Droid GUID | 이름이 바뀌어도 같은 파일인가 |
| 파티션 오프셋 | MBR/GPT ([FOR-0019](./mbr-gpt.html)) | 숨겨진 파티션 존재 |

## 흔한 실수

- **이미지의 0번 섹터를 VBR로 읽는 것.** 디스크 이미지의 첫 섹터는 MBR/GPT다. `mmls`로 파티션 시작 섹터를 먼저 구하고, `그 섹터 × 512`부터 읽어야 `"NTFS    "`가 보인다. 볼륨만 잘라낸 이미지라면 0번이 맞지만, 그것부터 확인한다.
- **`0x40`을 unsigned로 읽는 것.** `0xF6`을 246으로 읽으면 레코드 크기가 246클러스터(약 1MB)라는 말이 되고, 레코드 오프셋 계산이 전부 깨진다. 음수면 `2^절댓값` 바이트다.
- **클러스터 크기를 4096으로 가정하는 것.** SSD 이미지, USB, 서버 볼륨은 512·2048·8192·65536바이트도 흔하다. `fsstat`의 `Cluster Size`를 반드시 읽는다. 이 값이 틀리면 data run이 가리키는 바이트 오프셋이 전부 어긋난다.
- **`fsstat -o`에 바이트 오프셋을 넣는 것.** Sleuth Kit의 `-o`는 **섹터** 단위다. `-o 1048576`이 아니라 `-o 2048`이다. 잘못 주면 "Cannot determine file system type"이 뜬다.
- **Update Sequence Array fixup을 무시하는 것.** HxD로 MFT 레코드를 직접 읽을 때 512바이트 경계의 마지막 2바이트는 원본이 아니다. 그 2바이트를 속성 길이나 오프셋으로 해석하면 파싱이 산으로 간다.
- **`$Extend` 안을 안 보는 것.** `$UsnJrnl`은 볼륨 루트가 아니라 `$Extend` 디렉터리 안에 있고, 실제 데이터는 ADS `:$J`에 있다. 루트만 보고 "저널이 없다"고 결론 내리는 사고가 잦다.
- **ADS를 파일 목록에서 놓치는 것.** 일반 `dir`, 탐색기, 대부분의 백업 도구는 ADS를 표시하지 않는다. `dir /r` 또는 `Get-Item -Stream *`을 쓴다. 파일 크기 합이 볼륨 사용량과 안 맞으면 ADS를 의심한다.
- **부트섹터가 깨졌을 때 포기하는 것.** 볼륨 **마지막 섹터의 백업 부트섹터**에서 동일한 값을 읽을 수 있다.
- **`total sectors`를 볼륨 크기로 그대로 쓰는 것.** 백업 부트섹터가 놓인 마지막 섹터가 이 값에서 빠져 있는 것이 일반적이다. 정확한 볼륨 끝은 파티션 테이블 값과 함께 본다.
- **sparse run을 손상으로 오해하는 것.** 오프셋 필드 길이가 0인 run은 정상적인 sparse 구간이다. `$J`의 논리 크기가 수십 GB로 보이는 이유가 이것이다.

## mini example

```text
문제:
"disk.dd 에서 $MFT를 추출해 삭제된 파일 목록을 뽑으세요.
 단, FTK Imager 없이 CLI만 사용하세요."

1. 첫 시도 (실패):
   xxd -l 128 disk.dd
   -> 00000000: 33c0 8ed0 bc00 7c8e c08e d8be 007c bf00  3............|.
      0x03 위치가 "NTFS    " 가 아니다. 부트 코드처럼 보인다.

   왜 틀렸나: 읽은 것은 디스크 이미지의 0번 섹터, 즉 MBR이다.
   NTFS VBR은 "파티션의 첫 섹터"다.

2. 파티션 오프셋부터 구한다
   mmls disk.dd
   -> Slot  Start    End        Length     Description
      002:  2048     13109247   13107200   NTFS / exFAT (0x07)

   볼륨 시작 바이트 = 2048 * 512 = 1,048,576

3. 이제 VBR을 읽는다
   xxd -s 1048576 -l 80 disk.dd
   -> 00100000: eb52 904e 5446 5320 2020 2000 0208 0000  .R.NTFS    .....
      00100010: 0000 0000 00f8 0000 3f00 ff00 0008 0000  ........?.......
      00100020: 0000 0000 8000 8000 ffff c700 0000 0000  ................
      00100030: 0000 0400 0000 0000 0200 0000 0000 0000  ................
      00100040: f600 0000 0100 0000 8c1a 3b7e 9d2c 4f05  ..........;~.,O.

   0x03: 4e54 4653 2020 2020      -> "NTFS    "  확정
   0x0B: 00 02                    -> 512 bytes/sector
   0x0D: 08                       -> 8 sectors/cluster => 클러스터 4096
   0x28: ff ff c7 00 00 00 00 00  -> 13,107,199 sectors
   0x30: 00 00 04 00 00 00 00 00  -> $MFT LCN 262,144
   0x38: 02 00 ...                -> $MFTMirr LCN 2
   0x40: f6                       -> signed -10 => 2^10 = 1024 bytes/record
   0x48: 8c 1a 3b 7e 9d 2c 4f 05  -> serial 054F2C9D7E3B1A8C

4. $MFT 바이트 오프셋
   1,048,576 + 262,144 * 4096 = 1,074,790,400

   확인: 그 위치에 "FILE" 시그니처가 있어야 한다
   xxd -s 1074790400 -l 16 disk.dd
   -> 4649 4c45 3000 0300 ...     "FILE" 확인

5. 두 번째 실수와 정정:
   icat -o 1048576 disk.dd 0 > '$MFT'
   -> "Cannot determine file system type"

   Sleuth Kit의 -o 는 섹터 단위다. 바이트를 주면 안 된다.
   icat -o 2048 disk.dd 0 > '$MFT'
   -> 92,274,688 바이트 추출 성공 (= 90,112 레코드 * 1024)

6. 파싱
   MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
   Import-Csv out\mft.csv | Where-Object { $_.InUse -eq 'False' } |
     Select-Object EntryNumber, FileName, ParentPath, FileSize

정답 경로: 부트섹터 3개 값 -> $MFT 오프셋 -> 삭제 파일 목록
```

3단계에서 `0x40 = 0xF6`을 246으로 읽었다면 레코드 크기를 1,007,616바이트로 계산해 5단계의 검산(`92,274,688 / 1024 = 90,112`)이 성립하지 않았다. **signed 해석이 이 문제의 분기점이다.**

## 출처

- SRC-005 — Microsoft Learn, Master File Table: MFT 레코드와 속성 구조, 예약 메타파일의 역할
- SRC-032 — The Sleuth Kit 도구 문서: `fsstat`/`icat`/`mmls`의 `-o` 옵션이 섹터 단위라는 점과 NTFS 출력 항목
- SRC-081 — Microsoft Learn, File Streams: 이름 있는 `$DATA` 스트림(ADS) 표기법과 `::$DATA`
- `fsstat` 출력의 항목 이름과 순서는 Sleuth Kit 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
- 부트섹터 오프셋 값은 이미지에서 `xxd`로 직접 대조해 검산할 것. 특히 `0x0B`/`0x0D`/`0x40`은 볼륨마다 다르다
