---
id: FOR-0043
title: "fsstat 출력 필드 레퍼런스 (NTFS/FAT/ext)"
slug: "tsk-fsstat"
category: "디스크/NTFS"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["volume boot record", "$MFT", "$MFTMirr", "cluster", "sector", "$AttrDef", "superblock"]
file_paths: ["$MFTMirr", "$Boot"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "fsstat", "mmls", "fls", "icat", "istat", "HxD"]
commands: ["fsstat -o 2048 image.dd", "fsstat -t -o 2048 image.dd", "fsstat -o 0 image.dd", "fsstat -f list", "fsstat -f ntfs -o 2048 image.dd", "fsstat -o 2048 -b 4096 image.dd", "fsstat -i ewf -o 2048 image.E01"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["File System Type", "Volume Serial Number", "OEM Name", "Version", "First Cluster of MFT", "First Cluster of MFT Mirror", "Size of MFT Entries", "Size of Index Records", "Root Directory", "Sector Size", "Cluster Size", "Total Cluster Range", "Total Sector Range", "Block Size", "Inode Range"]
file_formats: ["ntfs", "fat", "exfat", "ext4", "raw", "dd", "e01"]
primary_terms: ["fsstat"]
keywords: ["fsstat", "Sleuth Kit", "Cluster Size", "Sector Size", "First Cluster of MFT", "Size of MFT Entries", "Volume Serial Number", "파일시스템 정보", "오프셋 검증", "Total Cluster Range"]
aliases: ["fsstat", "fsstat 사용법", "클러스터 크기 확인", "섹터 크기 확인", "mft 위치 계산", "파일시스템 종류 확인", "오프셋 맞는지 확인"]
symptom_keywords: ["클러스터 크기를 모르겠다", "MFT가 어디에 있는지 모르겠다", "오프셋이 맞았는지 확인하고 싶다", "파일시스템 종류를 모르겠다", "Cannot determine file system type가 뜬다", "볼륨 시리얼을 알고 싶다"]
related: ["FOR-0040", "FOR-0021", "FOR-0019"]
source_ids: ["SRC-032", "SRC-005"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`fsstat -o <오프셋> image.dd`가 정상 출력을 내면 그 오프셋이 맞았다는 증거이며, 출력의 `Sector Size` / `Cluster Size` / `First Cluster of MFT` / `Size of MFT Entries` 네 값만 적어 두면 이후의 모든 오프셋 계산과 카빙 정렬이 끝난다.

## 개념

`fsstat`은 파일시스템의 **슈퍼블록/부트섹터 수준 메타데이터**만 읽어 출력한다. 파일 목록도 내용도 보지 않으므로 수백 GB 이미지에서도 즉시 끝난다.

이 도구의 실전 역할은 두 가지다.

| 역할 | 근거 |
| --- | --- |
| **오프셋 판정기** | 오프셋이 틀리면 `Cannot determine file system type`이 나온다. 맞으면 표가 나온다. 이 이진 판정이 시행착오의 기준이 된다 |
| **상수 공급기** | `Cluster Size`, `Size of MFT Entries` 등은 이후 모든 손계산(레코드 오프셋, 클러스터→바이트 환산)의 재료다 |

출력은 파일시스템 종류에 따라 섹션 구성이 달라지지만, NTFS/FAT/exFAT은 공통으로 세 섹션을 가진다.

| 섹션 | 담는 것 |
| --- | --- |
| `FILE SYSTEM INFORMATION` | 종류, 볼륨 식별자, 생성 OS 정보 |
| `METADATA INFORMATION` | 메타데이터 구조(MFT/inode/루트 디렉터리)의 위치와 범위 |
| `CONTENT INFORMATION` | 섹터/클러스터(블록) 크기와 전체 범위 |

## 파일 / 경로

`fsstat`은 이미지 파일을 직접 읽으며, 실제로 참조하는 것은 볼륨 시작부의 구조다.

| 파일시스템 | 읽는 구조 | 볼륨 내 위치 |
| --- | --- | --- |
| NTFS | 볼륨 부트 레코드(VBR) + `$MFT` 앞부분 + `$AttrDef` | 볼륨 첫 섹터 |
| FAT12/16/32 | 부트섹터 + BPB + FSINFO | 볼륨 첫 섹터 |
| exFAT | 부트섹터 + 확장 BPB | 볼륨 첫 섹터 |
| ext2/3/4 | 슈퍼블록 | 볼륨 시작 + `0x400`(1024바이트) |

옵션은 다섯 개뿐이다.

| 옵션 | 의미 |
| --- | --- |
| `-o offset` | 파일시스템이 시작하는 **섹터** 오프셋 |
| `-t` | **파일시스템 타입만** 출력 (스크립트용) |
| `-f fstype` | 타입 강제. `-f list`로 지원 목록 |
| `-i imgtype` | 이미지 형식 강제. `-i list`로 지원 목록 |
| `-b size` | 하부 장치 섹터 크기(바이트). 미지정 시 이미지 형식의 값 또는 512 |
| `-v` / `-V` | 디버그 출력 / 버전 |

## 주요 필드

### NTFS 출력

```text
$ fsstat -o 206848 image.dd
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 8C3A1F2D9B4E7A65
OEM Name: NTFS
Version: Windows XP

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 2
Size of MFT Entries: 1024 bytes
Size of Index Records: 4096 bytes
Range: 0 - 262143
Root Directory: 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 5216766
Total Sector Range: 0 - 41734143

$AttrDef Attribute Values:
$STANDARD_INFORMATION (16)   Size: 48-72   Flags: Resident
$ATTRIBUTE_LIST (32)   Size: No Limit   Flags: Non-resident
$FILE_NAME (48)   Size: 68-578   Flags: Resident,Index
$DATA (128)   Size: No Limit   Flags:
...
```

| 필드 | 의미 | 어디에 쓰는가 |
| --- | --- | --- |
| `File System Type` | 파일시스템 종류 | **오프셋이 맞았다는 증거** |
| `Volume Serial Number` | 볼륨 시리얼(부트섹터의 8바이트) | LNK 파일의 볼륨 시리얼과 대조해 "어느 볼륨의 파일인지" 확정. 이미지 동일성 확인 |
| `OEM Name` | 부트섹터의 OEM ID 문자열 | 시그니처 스캔으로 볼륨을 찾을 때의 검색어(`NTFS    `) ([FOR-0019](./mbr-gpt.html)) |
| `Version` | NTFS 버전에서 유추한 생성 OS | 대략적 OS 세대 추정. 정밀한 근거는 아니다 |
| `First Cluster of MFT` | `$MFT`가 시작하는 **클러스터 번호** | **`$MFT` 물리 위치 계산의 시작점** |
| `First Cluster of MFT Mirror` | `$MFTMirr` 시작 클러스터 | `$MFT` 앞부분 손상 시 복구 출발점 |
| `Size of MFT Entries` | MFT 레코드 1개 크기 (보통 1024바이트) | **레코드 N의 오프셋 = N × 이 값** ([FOR-0021](./mft-basics.html)) |
| `Size of Index Records` | 디렉터리 색인 레코드 크기 | `$INDEX_ALLOCATION` 수동 파싱 시 |
| `Range` | 유효 MFT 엔트리 번호 범위 | `icat`/`istat`에 넣을 주소가 범위 안인지 확인 |
| `Root Directory` | 루트 디렉터리의 메타주소 (NTFS는 `5`) | `fls -o N image.dd 5` |
| `Sector Size` | 섹터 크기 | 섹터↔바이트 환산 |
| `Cluster Size` | **클러스터 크기** | 클러스터↔바이트 환산, **카빙 정렬 단위**, 슬랙 크기 계산 |
| `Total Cluster Range` | 클러스터 번호 범위 | data run 값의 유효성 검증 |
| `Total Sector Range` | 섹터 번호 범위 | 볼륨 크기 검증 |
| `$AttrDef Attribute Values` | 속성 타입 번호와 이름 대응표 | `icat`의 세 토막 주소에 넣을 속성 타입 번호 확인 ([FOR-0042](./tsk-icat.html)) |

### 오프셋 계산 공식

```text
볼륨 시작(바이트)   = 파티션 Start(섹터) × Sector Size
$MFT 시작(볼륨 상대) = First Cluster of MFT × Cluster Size
$MFT 시작(이미지 절대) = 볼륨 시작 + $MFT 시작(볼륨 상대)
레코드 N 오프셋       = $MFT 시작 + N × Size of MFT Entries
클러스터 C 오프셋     = 볼륨 시작 + C × Cluster Size
```

위 출력 값으로 실제 계산한 예다.

```text
볼륨 시작        = 206848 × 512  = 105,906,176    (0x6500000)
$MFT 볼륨 상대   = 786432 × 4096 = 3,221,225,472  (0xC0000000)
$MFT 절대        = 105,906,176 + 3,221,225,472 = 3,327,131,648
레코드 12345     = 3,327,131,648 + 12345 × 1024 = 3,339,772,928
```

HxD의 Goto에 `3339772928`(또는 `0xC7167000`)을 넣으면 그 레코드의 `FILE` 시그니처가 보인다. 안 보이면 계산이나 오프셋이 틀렸다.

### FAT / exFAT / ext 출력의 차이

| 항목 | NTFS | FAT32 | exFAT | ext4 |
| --- | --- | --- | --- | --- |
| 볼륨 식별자 필드 | `Volume Serial Number` | `Volume ID`, `Volume Label (Boot Sector)`, `Volume Label (Root Directory)` | `Volume Serial Number` | `Volume Name`, `Volume ID` |
| 메타데이터 구조 | `First Cluster of MFT`, `Size of MFT Entries` | 없음 (디렉터리 엔트리 방식) | 없음 | `Inode Range`, `Free Inodes` |
| 루트 디렉터리 주소 | `5` | `2` | 구현에 따라 다름 | `2` |
| 데이터 단위 명칭 | `Cluster Size` | `Cluster Size` | `Cluster Size` | **`Block Size`** |
| 범위 필드 | `Total Cluster Range` | `Total Cluster Range` | `Total Cluster Range` | **`Block Range`** |
| 고유 추가 섹션 | `$AttrDef Attribute Values` | `FAT CONTENTS (in sectors)` | — | `BLOCK GROUP INFORMATION` |
| 마운트/시각 정보 | 없음 | 없음 | 없음 | `Last Written at`, `Last Checked at`, `Last Mounted at`, `Last mounted on`, `Unmounted properly` |

ext4 출력의 실전 포인트다.

| 필드 | 의미 |
| --- | --- |
| `Last Written at` / `Last Mounted at` / `Last Checked at` | **볼륨 수준 타임스탬프.** 마지막 사용 시각 추정의 근거 |
| `Last mounted on` | 마지막 마운트 경로 문자열 (`/`, `/mnt/data` 등) |
| `Unmounted properly` | 정상 언마운트 여부. `No`면 강제 종료·전원 차단 흔적 |
| `Compat/InCompat/Read Only Compat Features` | `has_journal`, `extents`, `64bit` 등. ext3/ext4 구분 근거 |
| `Journal ID` / 저널 존재 | `journal`이 있으면 `$LogFile`에 해당하는 분석 여지 |
| `Free Inodes` / `Free Blocks` | 사용률. 비할당 영역의 규모 추정 |

FAT 계열은 `FAT CONTENTS (in sectors)` 섹션이 클러스터 체인의 할당 상태를 섹터 범위로 나열한다. 파일 하나의 조각 분포를 눈으로 보고 싶을 때 쓴다.

exFAT의 세부 필드 이름은 TSK 버전에 따라 차이가 있다. `Sector Size` / `Cluster Size` / `Total Cluster Range` 세 개를 우선 읽고 나머지는 실제 출력에서 확인한다.

## 빠른 명령

```bash
fsstat -o 2048 image.dd
```

```bash
fsstat -o 2048 image.dd | head -20              # 앞 세 섹션만 (긴 $AttrDef 를 자른다)
fsstat -t -o 2048 image.dd                      # 타입만: ntfs / fat32 / ext4 ...
fsstat -o 0 image.dd                            # 파티션 테이블 없는 단일 볼륨 이미지
fsstat -o 2048 -b 4096 image.dd                 # 4Kn 이미지
fsstat -i ewf -o 2048 image.E01                 # E01 직접
fsstat -f list                                  # 지원 파일시스템 목록
fsstat -f ntfs -o 2048 image.dd                 # 자동탐지 실패 시 타입 강제
```

필요한 값만 뽑아 변수에 담는다.

```bash
IMG=image.dd; OFF=206848
fsstat -o $OFF $IMG | grep -E 'File System Type|Sector Size|Cluster Size|First Cluster of MFT|Size of MFT Entries'
```

`-t`는 오프셋 후보를 무작위로 훑을 때 유용하다.

```bash
# 흔한 시작 섹터 후보를 순서대로 두드린다
for s in 0 63 64 128 2048 8192 32768 206848; do
  printf '%8s : %s\n' "$s" "$(fsstat -t -o $s image.dd 2>&1 | head -1)"
done
```

```text
       0 : Cannot determine file system type
      63 : Cannot determine file system type
    2048 : ntfs
  206848 : ntfs
```

시그니처 스캔으로 찾은 후보 섹터를 검증하는 것도 같은 방식이다 ([FOR-0019](./mbr-gpt.html)).

## 함께 보는 artifact

| fsstat에서 얻은 값 | 다음에 볼 것 |
| --- | --- |
| `File System Type` 확정 | `fls -o N -r -p`로 전체 파일 목록 ([FOR-0041](./tsk-fls.html)) |
| `Root Directory` | `fls -o N image.dd <그 주소>`로 루트만 나열 |
| `First Cluster of MFT` + `Cluster Size` | HxD로 `$MFT` 위치 직접 점프, 또는 `icat -o N image.dd 0`으로 추출 ([FOR-0042](./tsk-icat.html)) |
| `Size of MFT Entries` | MFT 레코드 N의 오프셋 계산 ([FOR-0021](./mft-basics.html)) |
| `First Cluster of MFT Mirror` | `$MFT` 손상 시 `$MFTMirr`(레코드 1)로 앞부분 복구 |
| `Cluster Size` | 카빙 시 헤더 정렬 단위, 슬랙 크기 계산 ([FOR-0045](./carving-strategy.html)) |
| `Total Cluster Range` | `istat`의 data run 값이 범위를 벗어나면 파싱 오류 신호 |
| `Volume Serial Number` | LNK/Jump List의 볼륨 시리얼, 레지스트리 `MountedDevices` 항목과 대조 |
| `$AttrDef` 속성 번호 | `icat`의 `<주소>-<타입>-<ID>` 지정 |
| ext의 `Last mounted on` | 리눅스 이미지의 원래 마운트 경로 |
| `Cannot determine file system type` | `mmls`로 오프셋 재확인 ([FOR-0040](./tsk-mmls.html)) |

`Volume Serial Number`를 레지스트리와 대조할 때는 주의한다. `MountedDevices`의 값 형태는 항목마다 다르며(디스크 서명 + 파티션 오프셋, 또는 볼륨 식별자) NTFS 볼륨의 부트섹터 시리얼과 항상 같은 형태가 아니다. **실제 바이트를 확인하고 판단한다.**

## 흔한 실수

- **`Cannot determine file system type`을 "이미지가 깨졌다"로 읽는 것.** 거의 항상 오프셋이 틀린 것이다. → `mmls`로 `Start`를 다시 받고, 그래도 안 되면 `-o 0`(파티션 없는 단일 볼륨)을 시도한다.
- **`-b`를 빼먹는 것.** 4Kn 이미지에서 `mmls`가 준 `Start`를 512바이트 섹터로 해석해 8배 틀린 위치를 읽는다. `mmls`와 `fsstat`의 `-b`는 항상 같아야 한다.
- **`Cluster Size`와 `Sector Size`를 혼동하는 것.** 클러스터 번호에 섹터 크기를 곱하면 위치가 8배 틀린다. **`First Cluster of MFT`는 클러스터 번호이므로 `Cluster Size`를 곱한다.**
- **볼륨 상대 오프셋을 이미지 절대 오프셋으로 쓰는 것.** `First Cluster of MFT × Cluster Size`는 **볼륨 기준**이다. HxD로 이미지를 열었다면 여기에 볼륨 시작 바이트를 더해야 한다.
- **`Size of MFT Entries`를 1024로 가정하는 것.** 4K 클러스터 환경에서 4096바이트인 볼륨도 있다. 출력 값을 그대로 쓴다.
- **`Version: Windows XP`를 OS 판정 근거로 쓰는 것.** NTFS 버전에서 유추한 값이며 실제 설치 OS와 다를 수 있다. OS는 레지스트리 `CurrentVersion`으로 확정한다.
- **`Range`를 무시하고 범위 밖 메타주소를 `icat`에 넣는 것.** 결과가 없거나 엉뚱한 데이터가 나온다.
- **`$AttrDef` 목록 때문에 출력이 길어 앞부분을 놓치는 것.** `head -20`으로 잘라 본다.
- **ext 이미지에서 `Cluster Size`를 찾는 것.** ext는 `Block Size`, `Block Range`라는 이름을 쓴다.
- **`fsstat` 성공을 "파일이 온전하다"로 확대 해석하는 것.** 부트섹터/슈퍼블록만 읽은 것이다. `$MFT`가 손상되었는지는 `fls`가 정상 목록을 내는지로 판단한다.

## mini example

```text
문제:
"이미지에서 MFT 레코드 12345 를 HxD로 직접 열어 파일 이름을 읽으세요."
첨부: disk.dd (20 GB)

1. 첫 시도 (실패):
   $ fsstat -o 2048 disk.dd
   Cannot determine file system type

   "2048은 관례적 시작 섹터"라고 알고 있어서 그대로 넣었다.
   -> 이 디스크는 파티션이 두 개이고 시스템 볼륨이 두 번째였다.

2. 접근 변경 — mmls 로 실제 값을 받는다
   $ mmls -a disk.dd
         Slot      Start        End          Length       Description
   002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
   003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)

   2048 볼륨도 목록에는 있었다. 왜 fsstat 이 실패했나?
   $ fsstat -t -o 2048 disk.dd
   Cannot determine file system type
   $ fsstat -t -o 206848 disk.dd
   ntfs

   -> 첫 볼륨(2048)은 100MB 복구 파티션인데 부트섹터가 비어 있었다.
      진짜 시스템 볼륨은 206848 이다.

3. 필요한 값만 뽑는다
   $ fsstat -o 206848 disk.dd | head -20
   File System Type: NTFS
   Volume Serial Number: 8C3A1F2D9B4E7A65
   OEM Name: NTFS
   First Cluster of MFT: 786432
   First Cluster of MFT Mirror: 2
   Size of MFT Entries: 1024 bytes
   Range: 0 - 262143
   Root Directory: 5
   Sector Size: 512
   Cluster Size: 4096

4. 두 번째 실패 — 계산에서 볼륨 시작을 빼먹었다
   $MFT 위치를 786432 × 4096 = 3,221,225,472 로 계산해
   HxD Goto 에 3221225472 를 넣었더니 0x00 만 보였다.

   빠진 것: 이 값은 '볼륨 기준' 오프셋이다.
   볼륨 시작 = 206848 × 512 = 105,906,176 을 더해야 한다.

5. 다시 계산
   $MFT 절대   = 105,906,176 + 3,221,225,472 = 3,327,131,648
   레코드 12345 = 3,327,131,648 + 12345 × 1024 = 3,339,772,928

   HxD Goto: 3339772928 (dec)
   -> 46 49 4C 45 ("FILE") 시그니처 확인. 위치가 맞다.
      $FILE_NAME 속성에서 UTF-16LE 이름을 읽는다.

6. 교차검증 — TSK 로 같은 레코드를 본다
   $ istat -o 206848 disk.dd 12345 | head
   MFT Entry Header Values:
   Entry: 12345      Sequence: 4
   $FILE_NAME Attribute Values:
   Name: quarterly_report.xlsx

   -> HxD 로 읽은 이름과 일치. 계산 검증 완료.

정답: quarterly_report.xlsx
```

두 번의 실패가 이 글의 요지다. **`fsstat`이 실패하면 오프셋을 의심하고, `fsstat`이 준 클러스터 값을 쓸 때는 볼륨 시작 바이트를 더한다.** 그리고 손계산은 항상 `istat`으로 대조한다.

## 출처

- SRC-032 — The Sleuth Kit 도구 문서(fsstat man page): `-t` "파일시스템 타입만 출력", `-f` / `-i` / `-b` / `-o`의 정의와 기본값(섹터 크기 미지정 시 512 가정)
- SRC-005 — Microsoft Learn, Master File Table: `$MFT` / `$MFTMirr`의 역할, MFT 레코드 크기와 예약 레코드 번호(루트 디렉터리 5), 클러스터 단위 저장 구조
- 출력 예시의 필드 이름은 TSK 버전과 파일시스템 종류에 따라 추가·변경될 수 있다. 특히 exFAT과 ext4의 세부 항목은 버전 차이가 크므로 실제 출력에서 확인할 것
- 예시의 볼륨 시리얼·클러스터 번호·범위 값은 설명을 위한 값이며 실제 이미지의 값은 다르다
