---
id: FOR-0019
title: "MBR과 GPT 파티션 테이블 직접 읽기"
slug: "mbr-gpt"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["MBR", "GPT", "protective MBR", "partition table", "LBA", "EFI PART"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["HxD", "Sleuth Kit", "FTK Imager", "Arsenal Image Mounter", "xxd", "fdisk", "gdisk"]
commands: ["mmls image.dd", "xxd -l 512 image.dd", "xxd -s 512 -l 512 image.dd", "fdisk -l image.dd", "gdisk -l image.dd", "fsstat -o 2048 image.dd"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Start", "End", "Length", "Description", "Slot"]
file_formats: ["raw", "dd", "e01"]
primary_terms: ["MBR", "GPT", "파티션 테이블", "EFI PART", "protective MBR"]
keywords: ["MBR", "GPT", "파티션 테이블", "55AA", "EFI PART", "LBA", "파티션 오프셋", "mmls", "protective MBR", "파티션 타입 GUID"]
aliases: ["mbr", "gpt", "파티션 테이블", "파티션 오프셋", "mmls", "55aa", "부트섹터", "파티션 구조", "디스크 앞 512바이트"]
symptom_keywords: ["파티션이 안 보인다", "오프셋을 모르겠다", "툴이 파일시스템을 못 찾는다", "파티션이 삭제된 것 같다", "숨긴 파티션이 있는지", "부트섹터가 깨졌다", "2TB가 넘는데 이상하다"]
related: ["FOR-0020", "FOR-0016", "FOR-0017"]
source_ids: ["SRC-005"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

디스크 첫 512바이트의 끝이 `55 AA`이고 파티션 타입이 `0xEE`이면 GPT(진짜 테이블은 LBA 1의 `EFI PART`)이고, 그렇지 않으면 MBR이다 — 파티션 시작 LBA에 섹터 크기(보통 512)를 곱한 값이 모든 도구에 넣을 **바이트 오프셋**이다.

## 어떤 문제에서 필요한가

- `mmls`나 Autopsy가 파티션을 못 찾아 파일시스템에 접근할 수 없는 경우
- 도구가 `-o <offset>` 같은 오프셋 인자를 요구하는 경우
- 파티션 테이블이 삭제·손상되어 복구해야 하는 경우
- **숨긴 파티션**이나 파티션 사이의 미할당 영역을 찾아야 하는 경우
- 문제 지문이 "MBR", "부트섹터", "파티션 구조"를 직접 언급하는 경우

## 문제에서 처음 볼 단서

1. `file`이 `data`라고 답하고 크기가 수 GB인 RAW 이미지 ([FOR-0001](./30sec-triage.html))
2. `mmls`가 `Cannot determine partition type` 오류
3. Autopsy/FTK Imager가 볼륨을 하나도 못 보여준다
4. 첫 512바이트 끝 2바이트가 `55 AA`인지 아닌지 — **여기서 모든 것이 갈린다**
5. `[unpartitioned space]`가 비정상적으로 크다 → 숨긴 데이터

## 30초 절차

```bash
# 1) 도구가 알아서 해 주는 경우 (대부분)
mmls image.dd

# 2) 실패하면 직접 본다
xxd -l 512 image.dd          # LBA 0 — MBR 또는 protective MBR
xxd -s 512 -l 512 image.dd   # LBA 1 — GPT 헤더 ("EFI PART")
```

Windows GUI라면 HxD로 이미지를 열고 오프셋 `0`과 `200`(=512)만 읽는다.

```powershell
Format-Hex -Path .\image.dd -Count 512
```

## 상세 절차

### 1단계 — `mmls` 출력 읽기 (정상 경로)

```bash
$ mmls image.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0500117503   0499910656   NTFS / exFAT (0x07)
004:  -------   0500117504   0500118191   0000000688   Unallocated
```

| 컬럼 | 의미 |
| --- | --- |
| `Slot` | `Meta` = 테이블 자체, `-------` = 미할당, `000:001` = 주 테이블의 2번째 항목 |
| `Start` | **시작 섹터(LBA).** 이 값이 오프셋 계산의 재료 |
| `End` / `Length` | 끝 섹터 / 섹터 개수 |
| `Description` | 파일시스템 추정과 파티션 타입 코드 |

**Sleuth Kit의 `-o`는 섹터 단위다.**

```bash
fsstat -o 2048 image.dd        # 파일시스템 정보
fls -o 206848 -r -p image.dd   # 파일 목록
icat -o 206848 image.dd 12345  # 파일 추출
```

반면 `dd`, HxD, 대부분의 hex 도구는 **바이트 단위**다.

```text
바이트 오프셋 = 시작 LBA × 섹터 크기
             = 206848 × 512
             = 105,906,176  (0x6500000)
```

**이 두 단위를 혼동하는 것이 이 분야에서 가장 흔한 실수다.**

`Unallocated` 항목의 크기를 반드시 확인한다. 위 예시의 003 앞 `Unallocated 2048 섹터`(1 MB)는 정상 정렬 여백이지만, 수 GB짜리 `Unallocated`가 있으면 **삭제되거나 숨겨진 파티션**이다.

### 2단계 — MBR 직접 읽기 (LBA 0, 512바이트)

```text
오프셋      크기   내용
0x000       446    부트스트랩 코드
0x1BE        16    파티션 엔트리 #1
0x1CE        16    파티션 엔트리 #2
0x1DE        16    파티션 엔트리 #3
0x1EE        16    파티션 엔트리 #4
0x1FE         2    시그니처 55 AA        <- 이것이 없으면 MBR 이 아니다
```

파티션 엔트리 16바이트의 구조:

| 오프셋 | 크기 | 필드 | 해석 |
| --- | --- | --- | --- |
| `0x00` | 1 | 부트 플래그 | `0x80` = 활성, `0x00` = 비활성 |
| `0x01` | 3 | CHS 시작 | 레거시. 무시해도 된다 |
| `0x04` | 1 | **파티션 타입** | 아래 표 |
| `0x05` | 3 | CHS 끝 | 레거시 |
| `0x08` | 4 | **시작 LBA** | **리틀엔디언 32비트** |
| `0x0C` | 4 | **섹터 개수** | 리틀엔디언 32비트 |

주요 파티션 타입 코드:

| 코드 | 의미 |
| --- | --- |
| `0x00` | 사용 안 함 (빈 슬롯) |
| `0x07` | **NTFS / exFAT / HPFS** |
| `0x0B` | FAT32 (CHS) |
| `0x0C` | FAT32 (LBA) |
| `0x0E` | FAT16 (LBA) |
| `0x05` | 확장 파티션 (CHS) |
| `0x0F` | **확장 파티션 (LBA)** — 안에 논리 파티션이 체인으로 들어 있다 |
| `0x82` | Linux swap |
| `0x83` | **Linux 파일시스템** |
| `0x8E` | Linux LVM |
| `0x27` | Windows 복구 파티션 |
| `0xEE` | **GPT protective MBR** — 실제 테이블은 GPT다 |
| `0xEF` | EFI 시스템 파티션 |
| `0xA5` | FreeBSD |
| `0xAF` | macOS HFS/HFS+ |

읽기 예시:

```text
$ xxd -s 0x1BE -l 16 image.dd
000001be: 0000 2100 0700 fe3f 0008 0000 0020 0300  ..!....?..... ..

0x00: 00              부트 플래그 = 비활성
0x01: 00 21 00        CHS 시작 (무시)
0x04: 07              타입 = NTFS
0x05: 00 fe 3f        CHS 끝 (무시)
0x08: 00 08 00 00     시작 LBA = 0x00000800 = 2048
0x0C: 00 20 03 00     섹터 개수 = 0x00032000 = 204800  (= 100 MB)
```

**리틀엔디언이므로 `00 08 00 00`을 `0x00000800`으로 뒤집어 읽는다.** 이 한 가지만 주의하면 손으로도 읽을 수 있다.

바이트 오프셋 = 2048 × 512 = **1,048,576** (`0x100000`).

### 3단계 — MBR의 한계와 확장 파티션

- **최대 4개의 주 파티션.** 더 필요하면 `0x05`/`0x0F` 확장 파티션 안에 논리 파티션을 체인으로 넣는다.
- **최대 2 TiB.** 시작 LBA와 섹터 개수가 32비트이므로 `2^32 × 512 = 2 TiB`가 한계다. 이보다 큰 디스크는 GPT를 쓴다.

확장 파티션이 있으면 `mmls`가 자동으로 펼쳐 준다.

```text
005:  Meta      0000206848   0500117503   0499910656   DOS Extended (0x0F)
006:  Meta      0000206848   0000206848   0000000001   Extended Table (#1)
007:  001:000   0000208896   0250216447   0250007552   Linux (0x83)
```

`Meta`로 표시된 항목은 파티션이 아니라 테이블이다. 실제 데이터는 `001:000` 같은 슬롯에 있다.

### 4단계 — GPT 직접 읽기

`0x1BE`의 타입이 `0xEE`이면 GPT다. LBA 0은 구형 도구를 위한 **protective MBR**이고 진짜 정보는 LBA 1에 있다.

```text
LBA 0        protective MBR (타입 0xEE 하나로 디스크 전체를 덮는다)
LBA 1        GPT 헤더
LBA 2 ~ 33   파티션 엔트리 배열 (128바이트 × 128개 = 16 KB = 32섹터)
...          데이터 영역
디스크 끝    백업 파티션 엔트리 + 백업 GPT 헤더 (마지막 LBA)
```

GPT 헤더(LBA 1, 오프셋 512부터) 주요 필드:

| 오프셋(헤더 내) | 크기 | 필드 | 값 |
| --- | --- | --- | --- |
| `0x00` | 8 | **시그니처** | `45 46 49 20 50 41 52 54` = `"EFI PART"` |
| `0x08` | 4 | 리비전 | `00 00 01 00` = 1.0 |
| `0x0C` | 4 | 헤더 크기 | 보통 92 (`0x5C`) |
| `0x10` | 4 | 헤더 CRC32 | 검증용 |
| `0x18` | 8 | 이 헤더의 LBA | 보통 1 |
| `0x20` | 8 | **백업 헤더 LBA** | 손상 시 복구 출발점 |
| `0x28` | 8 | 첫 사용 가능 LBA | 보통 34 |
| `0x30` | 8 | 마지막 사용 가능 LBA | — |
| `0x38` | 16 | 디스크 GUID | 디스크 식별자 |
| `0x48` | 8 | **파티션 엔트리 시작 LBA** | 보통 2 |
| `0x50` | 4 | 엔트리 개수 | 보통 128 |
| `0x54` | 4 | 엔트리 크기 | 보통 128 |
| `0x58` | 4 | 엔트리 배열 CRC32 | 검증용 |

```text
$ xxd -s 512 -l 32 image.dd
00000200: 4546 4920 5041 5254 0000 0100 5c00 0000  EFI PART....\...
00000210: 8b7c 9f2a 0000 0000 0100 0000 0000 0000  .|.*............
         ^^^^^^^^^ 헤더 CRC32   ^^^^^^^^^^^^^^^^^ MyLBA = 1
```

파티션 엔트리 128바이트:

| 오프셋 | 크기 | 필드 |
| --- | --- | --- |
| `0x00` | 16 | **파티션 타입 GUID** |
| `0x10` | 16 | 파티션 고유 GUID |
| `0x20` | 8 | **시작 LBA (64비트 리틀엔디언)** |
| `0x28` | 8 | **끝 LBA (포함)** |
| `0x30` | 8 | 속성 플래그 |
| `0x38` | 72 | 파티션 이름 (**UTF-16LE**, 최대 36자) |

주요 파티션 타입 GUID:

| GUID | 의미 |
| --- | --- |
| `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | EFI 시스템 파티션 |
| `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` | **Microsoft 기본 데이터 (NTFS/exFAT/FAT)** |
| `E3C9E316-0B5C-4DB8-817D-F92DF00215AE` | Microsoft 예약 (MSR) |
| `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC` | Windows 복구 환경 |
| `0FC63DAF-8483-4772-8E79-3D69D8477DE4` | Linux 파일시스템 |
| `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F` | Linux swap |
| `E6D6D379-F507-44C2-A23C-238F2A3DF928` | Linux LVM |
| `21686148-6449-6E6F-744E-656564454649` | BIOS 부트 파티션 |
| `00000000-0000-0000-0000-000000000000` | **빈 엔트리** |

> **GUID 바이트 순서 주의.** GUID의 앞 세 필드(4-2-2바이트)는 리틀엔디언으로 저장되고 뒤 두 필드(2-6바이트)는 빅엔디언이다. 디스크에서 `A2 A0 D0 EB E5 B9 33 44 87 C0 68 B6 B7 26 99 C7`로 보이는 것이 `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`다. **손으로 읽을 때 앞 8바이트만 뒤집는다.**

### 5단계 — 파티션 테이블이 손상되었을 때

| 상황 | 대응 |
| --- | --- |
| `55 AA` 시그니처가 없다 | 이미지가 파티션 없는 단일 볼륨일 수 있다. LBA 0에서 바로 `NTFS`/`EFI` OEM ID 확인 ([FOR-0020](./ntfs-structure.html)) |
| GPT 헤더가 깨졌다 | **백업 헤더**를 쓴다. 디스크 마지막 LBA. `gdisk -l`이 자동으로 시도한다 |
| MBR 엔트리가 지워졌다 | 파일시스템 시그니처를 전체 스캔해 파티션 시작을 찾는다 (아래) |
| 파티션이 하나 사라졌다 | `Unallocated` 구간에서 파일시스템 시그니처 검색 |

파일시스템 시그니처로 파티션 시작 찾기:

```bash
# NTFS 볼륨 부트섹터의 OEM ID "NTFS    " 위치를 전부 찾는다
grep -abo 'NTFS    ' image.dd | head

# 결과가 바이트 오프셋으로 나온다. 볼륨 시작은 그보다 3바이트 앞이다.
#   출력이 105906179 라면 볼륨 시작 = 105906176 = 섹터 206848
# 섹터 단위로 환산:
python3 -c "print((105906179 - 3) // 512)"
```

```bash
# 다른 파일시스템 시그니처
grep -abo 'EXFAT   ' image.dd | head      # exFAT (오프셋 3)
grep -abo 'MSDOS5.0' image.dd | head      # FAT (오프셋 3)
# ext4 는 슈퍼블록 오프셋 0x438 에 매직 53 EF
```

찾은 섹터 번호를 `-o`에 넣어 확인한다.

```bash
fsstat -o 206848 image.dd
```

`fsstat`이 정상 출력을 내면 오프셋이 맞다. `testdisk`는 이 과정을 자동화해 주며 파티션 테이블 재작성까지 지원한다.

### 6단계 — 도구별 오프셋 단위 정리

| 도구 | 인자 | 단위 |
| --- | --- | --- |
| `mmls` / `fls` / `icat` / `fsstat` / `istat` | `-o N` | **섹터** |
| `dd` | `skip=N bs=512` | 섹터(bs 지정 시) |
| `dd` | `skip=N bs=1` | 바이트 |
| `xxd` | `-s N` | **바이트** |
| HxD (Goto) | 값 | **바이트** (16진수 입력 가능) |
| `mount` (Linux) | `-o offset=N` | **바이트** |
| `losetup` | `-o N` | **바이트** |
| Volatility | 해당 없음 | — |

```bash
# 섹터 206848 부터의 볼륨만 별도 파일로 떼어내기
dd if=image.dd of=vol.dd bs=512 skip=206848

# Linux 에서 오프셋 지정 마운트 (바이트)
sudo mount -o ro,loop,offset=$((206848*512)) image.dd /mnt/case
```

## 출력 필드 해석

`fsstat`으로 오프셋이 맞는지 확인하는 것이 실전 검증법이다.

```text
$ fsstat -o 206848 image.dd
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 8C3A1F2D9B4E7A65
OEM Name: NTFS
Version: Windows XP
...
METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 2
Size of MFT Entries: 1024 bytes
...
CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 62488830
```

| 필드 | 쓰는 곳 |
| --- | --- |
| `File System Type` | 오프셋이 맞았다는 증거 |
| `Sector Size` / `Cluster Size` | 오프셋 환산과 카빙 정렬 |
| `Size of MFT Entries` | `$MFT` 레코드 오프셋 계산 ([FOR-0021](./mft-basics.html)) |
| `First Cluster of MFT` | `$MFT` 물리 위치 |
| `Volume Serial Number` | 레지스트리 `MountedDevices`와 대조해 드라이브 문자 확정 |

오프셋이 틀리면 `fsstat`이 `Cannot determine file system type`을 낸다. 이것이 시행착오의 판정 기준이다.

## pivot: 다음에 볼 artifact

| 확인한 것 | 다음 목표 |
| --- | --- |
| 파티션 오프셋 | `fls -o N -r -p` 로 전체 파일 목록 |
| NTFS 볼륨 확정 | `$MFT` 추출 → MFTECmd ([FOR-0021](./mft-basics.html)) |
| 볼륨 시리얼 번호 | `SYSTEM\MountedDevices` → 드라이브 문자 매핑 |
| 큰 `Unallocated` 구간 | 시그니처 스캔 → 숨긴/삭제된 파티션 |
| 여러 파티션 | 각각을 Arsenal로 마운트 ([FOR-0017](./arsenal-image-mounter.html)) |
| Linux 파티션(`0x83`) | `/var/log`, `/etc/passwd`, `~/.bash_history` |
| EFI 시스템 파티션 | 부트로더 변조 흔적 |
| 파티션 테이블 손상 | `testdisk`로 복구 시도 |

## 흔한 함정

- **섹터와 바이트를 혼동하는 것.** `mmls`/`fls`는 섹터, `xxd`/HxD/`mount`는 바이트다. **가장 흔한 실수이며, 오프셋 하나 틀리면 아무것도 안 보인다.**
- **섹터 크기를 512로 가정하는 것.** 4Kn 디스크는 4096바이트다. `mmls` 출력 첫 줄의 `Units are in N-byte sectors`를 확인한다.
- **리틀엔디언을 잊는 것.** `00 08 00 00`은 `0x800`(2048)이지 `0x08000000`이 아니다.
- **`0xEE`를 보고 MBR로 분석하는 것.** protective MBR이다. 진짜 테이블은 LBA 1의 GPT다.
- **GPT GUID를 바이트 순서 그대로 읽는 것.** 앞 8바이트가 뒤집혀 저장된다.
- **`Unallocated` 구간을 무시하는 것.** 1 MB 정렬 여백은 정상이지만 수 GB짜리는 숨긴 데이터다.
- **확장 파티션의 `Meta` 항목을 파티션으로 세는 것.** 실제 데이터는 논리 파티션 슬롯에 있다.
- **GPT 백업을 안 써 보는 것.** 주 헤더가 깨져도 디스크 끝의 백업으로 복구된다.
- **파티션 개수가 4개를 넘는데 MBR로 가정하는 것.** MBR 주 파티션은 최대 4개다. 그 이상이면 확장 파티션 또는 GPT다.
- **2 TiB 초과 디스크를 MBR로 읽는 것.** 32비트 LBA 한계 때문에 값이 잘리거나 순환한다.
- **`AD1`이나 논리 이미지에서 파티션 테이블을 찾는 것.** 논리 이미지에는 없다.

## 교차검증

```bash
# 1) Sleuth Kit
mmls image.dd

# 2) fdisk (MBR 중심)
fdisk -l image.dd

# 3) gdisk (GPT 중심 + 백업 헤더 자동 시도)
gdisk -l image.dd

# 4) 시그니처 직접 확인
xxd -s 0x1FE -l 2 image.dd            # 55 aa 인가
xxd -s 0x1BE -l 1 -ps image.dd        # 첫 엔트리 부트 플래그
xxd -s 0x1C2 -l 1 -ps image.dd        # 첫 엔트리 타입 코드
xxd -s 512 -l 8 image.dd              # "EFI PART" 인가

# 5) 오프셋이 맞는지 최종 확인
fsstat -o <섹터> image.dd

# 6) GUI 대조
#    FTK Imager 의 Evidence Tree 파티션 목록
#    Arsenal 마운트 후 diskmgmt.msc 의 파티션 배치
```

`mmls`와 `gdisk`의 파티션 개수가 다르면 GPT/MBR 판정이 갈린 것이다. `0x1BE + 4`의 타입 코드가 `0xEE`인지로 결론을 낸다.

## mini walkthrough

```text
문제:
"이 이미지에서 삭제된 파티션의 파일을 복구하세요."
첨부: usb.dd (16 GB)

1. mmls usb.dd
   DOS Partition Table
   Units are in 512-byte sectors

         Slot      Start        End          Length       Description
   000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
   001:  -------   0000000000   0000002047   0000002048   Unallocated
   002:  000:000   0000002048   0016777215   0016775168   Unallocated   <- 파티션이 없다!

   파티션 엔트리가 비어 있다. 테이블이 지워졌다.

2. MBR 직접 확인
   $ xxd -s 0x1BE -l 64 usb.dd
   000001be: 0000 0000 0000 0000 0000 0000 0000 0000  ................
   000001ce: 0000 0000 0000 0000 0000 0000 0000 0000  ................
   000001de: 0000 0000 0000 0000 0000 0000 0000 0000  ................
   000001ee: 0000 0000 0000 0000 0000 0000 0000 0000  ................

   $ xxd -s 0x1FE -l 2 usb.dd
   000001fe: 55aa                                     U.

   시그니처는 살아 있는데 엔트리 4개가 전부 0. 의도적으로 지운 것이다.

3. 첫 시도 (실패):
   fsstat -o 2048 usb.dd
   -> Cannot determine file system type
   2048 은 관례적 시작 위치일 뿐, 이 디스크는 달랐다.

4. 접근 변경 — 파일시스템 시그니처를 직접 스캔
   $ grep -abo 'NTFS    ' usb.dd | head
   1048579:NTFS

   OEM ID 는 볼륨 시작 + 3 바이트 위치에 있다.
   볼륨 시작 = 1048579 - 3 = 1048576 바이트
   섹터 환산 = 1048576 / 512 = 2048

   ... 결국 2048 이 맞았다. 그런데 왜 3단계가 실패했나?

5. 재확인 — 다른 시그니처도 스캔
   $ grep -abo 'EXFAT   ' usb.dd | head
   4194307:EXFAT

   볼륨 시작 = 4194304 바이트 = 섹터 8192
   NTFS 볼륨(2048)과 exFAT 볼륨(8192) 두 개가 있다!

   3단계가 실패한 이유: 2048 의 NTFS 부트섹터가 손상되어
   fsstat 이 인식하지 못했다. 두 번째 볼륨이 온전했다.

6. 두 번째 볼륨 확인
   $ fsstat -o 8192 usb.dd
   File System Type: exFAT
   Sector Size: 512
   Cluster Size: 32768
   -> 성공

7. 파일 목록과 추출
   $ fls -o 8192 -r -p usb.dd | head
   r/r 5:  secret/plan.docx
   r/r 7:  secret/flag.txt
   -/r * 9: deleted_note.txt          (* = 삭제됨)

   $ icat -o 8192 usb.dd 7 > flag.txt
   $ cat flag.txt
   flag{p4rt1t10n_t4bl3_w1p3d_n0t_d4t4}

8. 손상된 첫 볼륨도 처리
   $ dd if=usb.dd of=vol1.dd bs=512 skip=2048 count=6144
   $ xxd -l 16 vol1.dd
   -> 부트섹터 앞부분이 0으로 덮여 있었다.
      $MFTMirr 나 백업 부트섹터(볼륨 마지막 섹터)에서 복구 가능 (FOR-0020)

정답: flag{p4rt1t10n_t4bl3_w1p3d_n0t_d4t4}
```

교훈 두 가지다. **① 파티션 테이블이 지워져도 파일시스템 시그니처는 남는다.** **② 시그니처 스캔은 `head`로 끊지 말고 전부 봐야 한다** — 첫 결과만 보고 진행하면 5단계의 두 번째 볼륨을 놓쳤을 것이다.

## 막혔을 때 다음 체크

1. `mmls` 출력 첫 줄의 **섹터 크기**를 확인했는가 (512 vs 4096)
2. 넣는 오프셋의 단위가 **섹터인지 바이트인지** 확인했는가
3. `0x1FE`가 `55 AA`인가
4. `0x1C2`(첫 엔트리 타입)가 `0xEE`인가 → GPT
5. GPT라면 LBA 512에 `EFI PART`가 있는가
6. GPT 주 헤더가 깨졌다면 **백업 헤더**(`gdisk -l`)를 시도했는가
7. 큰 `Unallocated` 구간이 있는가 → 시그니처 스캔
8. `grep -abo 'NTFS    '` / `'EXFAT   '` / `'MSDOS5.0'` 를 **전부** 돌렸는가 (`head`로 끊지 말 것)
9. 찾은 오프셋에서 `fsstat`이 성공하는가 — 이것이 판정 기준
10. 부트섹터가 손상되었는가 → 볼륨 **마지막 섹터**의 백업 부트섹터 확인
11. 파티션이 4개를 넘는가 → 확장 파티션 또는 GPT
12. `testdisk`로 자동 복구를 시도했는가
13. 논리 이미지(AD1)인가 → 파티션 테이블은 애초에 없다

## 출처

- SRC-005 — Microsoft Learn, Master File Table 및 NTFS 관련 문서: 볼륨 부트섹터와 MFT 위치 관계
- MBR 구조, GPT 헤더/엔트리 레이아웃, 파티션 타입 코드/GUID는 UEFI 명세와 각 OS 문서에 정의된 값이다. 실제 이미지에서 `xxd`/HxD로 직접 확인해 재검증할 것
