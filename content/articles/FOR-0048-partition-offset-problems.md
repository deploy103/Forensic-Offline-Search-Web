---
id: FOR-0048
title: "파티션 오프셋이 안 맞을 때: 섹터/바이트, 4Kn, 볼륨 단독 이미지"
slug: "partition-offset-problems"
category: "디스크/NTFS"
type: "troubleshooting"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["partition offset", "sector size", "4Kn", "volume image", "EWF"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "mmls", "fsstat", "losetup", "kpartx", "mount", "xxd", "HxD", "ewfmount", "ewfinfo", "testdisk", "Arsenal Image Mounter", "FTK Imager"]
commands: ["fsstat -o 2048 image.dd", "mmls image.dd", "mmls -b 4096 image.dd", "losetup -P -f --show image.dd", "sudo mount -o ro,loop,offset=1048576 image.dd /mnt/case", "ewfmount image.E01 /mnt/ewf"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Units are in", "Sector Size", "Cluster Size", "File System Type"]
file_formats: ["raw", "dd", "e01", "ntfs"]
primary_terms: ["파티션 오프셋", "오프셋 안 맞음", "4Kn"]
keywords: ["파티션 오프셋", "offset", "섹터", "바이트", "4Kn", "4096 섹터", "mount 실패", "fsstat 실패", "볼륨 이미지", "E01", "손상된 파티션 테이블"]
aliases: ["오프셋 안 맞음", "mount 실패", "파일시스템을 못 찾는다", "오프셋 계산", "섹터 바이트 변환", "fsstat 실패", "offset 얼마", "wrong fs type"]
symptom_keywords: ["mount가 실패한다", "파일시스템을 못 찾는다", "파일 목록이 쓰레기로 나온다", "오프셋을 얼마로 줘야 하나", "Cannot determine file system type", "wrong fs type bad superblock", "이미지가 안 열린다"]
related: ["FOR-0019", "FOR-0049", "FOR-0017"]
source_ids: ["SRC-032", "SRC-034", "SRC-005"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

오프셋이 맞는지는 오직 `fsstat -o <섹터> image.dd`가 `File System Type`을 출력하는지로 판정하고, 그것이 실패하면 **원인을 추측하지 말고 아래 7가지 후보를 순서대로 배제**한다 — 1순위는 언제나 섹터/바이트 단위 혼동이다.

## 증상

| 증상 | 어디서 |
| --- | --- |
| `Cannot determine file system type` | `fsstat`, `fls`, `icat` |
| `Cannot determine partition type` | `mmls` |
| `mount: wrong fs type, bad option, bad superblock` | Linux `mount` |
| `NTFS signature is missing` | `ntfs-3g` |
| 파일 목록이 나오긴 하는데 **이름이 깨진 쓰레기** | `fls` |
| 도구가 볼륨을 하나도 못 보여준다 | Autopsy, FTK Imager |
| hex로 열었는데 원하는 구조가 안 보인다 | HxD, `xxd` |
| 마운트는 됐는데 폴더가 비어 있다 | `mount`, Arsenal |

**"파일 목록이 나오는데 쓰레기"가 가장 위험한 증상이다.** 오프셋이 조금 틀려도 도구는 에러 없이 무의미한 값을 해석해 보여 준다. 이름에 제어문자가 섞이거나 크기가 수 TB로 나오면 오프셋을 의심한다.

이 글은 "안 될 때 무엇을 하나"만 다룬다. MBR/GPT 바이트를 직접 읽는 법과 시그니처 스캔은 [FOR-0019](./mbr-gpt.html)에 있다.

## 가장 가능성 높은 원인

빈도 순서다. 위에서부터 배제한다.

| # | 원인 | 판정 신호 | 해결 |
| --- | --- | --- | --- |
| 1 | **섹터 단위 vs 바이트 단위 혼동** | `mmls`가 정상 출력되는데 `mount`/`xxd`만 실패, 또는 그 반대 | 아래 단위 표대로 환산 |
| 2 | **섹터 크기가 4096 (4Kn)** | `mmls` 첫 줄이 `Units are in 4096-byte sectors` | 바이트 = LBA × 4096 |
| 3 | **볼륨 단독 이미지에 오프셋을 준 경우** | `mmls` 실패 + `fsstat -o 0` 성공 | 오프셋을 **주지 않는다** |
| 4 | **물리 이미지인데 오프셋을 안 준 경우** | `mmls` 성공 + `fsstat`(오프셋 없이) 실패 | `mmls`의 `Start` 값을 `-o`에 |
| 5 | **파티션 테이블 손상** | `mmls` 실패 + `fsstat -o 0`도 실패 | 시그니처 스캔 / `testdisk` |
| 6 | **이미지가 잘렸다** | 파일 크기 < 파티션 끝 오프셋 | 뒤쪽 파티션 포기, 앞쪽만 분석 |
| 7 | **E01을 raw로 취급** | 첫 8바이트가 `45 56 46 09 0D 0A FF 00` | `ewfmount` / `-i ewf` |

## 1차 확인

세 명령으로 1~4번을 거의 다 가른다.

```bash
mmls image.dd
```

```bash
ls -l image.dd                    # 원인 6 판정용 실제 크기
xxd -l 16 image.dd                # 원인 7 판정용 매직 바이트
fsstat -o 0 image.dd              # 원인 3 판정용 (볼륨 단독인가)
```

### 판정 분기

```text
mmls 성공?
├─ 예 -> Units 줄의 섹터 크기 확인 (512 인가 4096 인가)
│        Start 값(섹터)을 fsstat -o 에 넣어 확인
│        성공 -> 오프셋 확정. 바이트가 필요한 도구는 Start × 섹터크기
│        실패 -> 원인 5(해당 파티션 부트섹터 손상) 또는 6(이미지 잘림)
└─ 아니오 -> fsstat -o 0 성공?
             ├─ 예   -> 원인 3. 볼륨 단독 이미지다. 오프셋을 주지 않는다
             └─ 아니오 -> xxd -l 16 으로 EWF(원인 7) 확인
                          아니면 원인 5. 시그니처 스캔으로 넘어간다
```

### 원인 1 — 섹터/바이트 혼동 (가장 흔함)

`mmls`가 `Start 206848`을 알려줬을 때 각 도구에 넣어야 하는 값이 다르다.

| 도구 / 인자 | 단위 | 넣을 값 | 잘못 넣으면 |
| --- | --- | --- | --- |
| `mmls -o` | 섹터 | `206848` | 엉뚱한 위치를 테이블로 해석 |
| `fls -o` / `icat -o` / `fsstat -o` / `istat -o` / `blkls -o` / `blkcalc -o` | **섹터** | `206848` | `Cannot determine file system type` |
| `xxd -s` | 바이트 | `105906176` | 전혀 다른 바이트가 보인다 |
| `dd bs=512 skip=` | 섹터(bs 기준) | `206848` | — |
| `dd bs=1 skip=` | 바이트 | `105906176` | 시작이 어긋난 잘린 볼륨 |
| `mount -o offset=` | **바이트** | `105906176` | `wrong fs type, bad superblock` |
| `losetup -o` | **바이트** | `105906176` | 마운트 단계에서 실패 |
| HxD Goto | 바이트 (16진 입력 가능) | `105906176` / `0x6500000` | 구조가 안 보인다 |
| `photorec` / `testdisk` | 오프셋 인자 없음 | 파티션을 골라 준다 | — |

```text
바이트 = 시작 LBA × 섹터 크기
       = 206848 × 512 = 105,906,176   (0x6500000)
섹터   = 바이트 ÷ 섹터 크기
```

```bash
# 계산을 손으로 하지 않는다
python3 -c "print(206848*512)"
sudo mount -o ro,loop,offset=$((206848*512)) image.dd /mnt/case
```

**증상으로 구분하는 법:** Sleuth Kit 계열은 되는데 `mount`만 실패하면 바이트로 환산하지 않은 것이다. 반대로 `mount`는 되는데 `fsstat`이 실패하면 섹터로 되돌리지 않은 것이다.

### 원인 2 — 섹터 크기 4096 (4Kn)

```text
$ mmls image.dd
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 4096-byte sectors        <- 여기를 읽지 않으면 8배 틀린다

      Slot      Start        End          Length       Description
002:  000       0000000256   0000131327   0000131072   Basic data partition
```

```text
바이트 오프셋 = 256 × 4096 = 1,048,576
512로 계산하면 256 × 512 = 131,072  -> 8배 작다. 아무것도 안 보인다
```

- `fsstat` 출력의 `Sector Size` 필드로 재확인한다
- 도구가 섹터 크기를 잘못 추정하면 `mmls -b 4096 image.dd`로 강제한다
- 4Kn은 대용량 디스크·일부 VM 이미지·SSD 이미지에서 나온다. **`mmls` 첫 줄을 읽는 습관 하나로 예방된다**

### 원인 3 — 볼륨 단독 이미지에 오프셋을 준 경우

파티션 테이블 없이 **볼륨(파일시스템)만** 담긴 이미지가 CTF에 흔하다.

```text
$ mmls vol.dd
Cannot determine partition type

$ xxd -l 16 vol.dd
00000000: eb52 904e 5446 5320 2020 2000 0208 0000  .R.NTFS    .....
              ^^^^^^^^^^^^^^^^^^ 오프셋 3에 OEM ID "NTFS    "

$ fsstat -o 0 vol.dd          (또는 fsstat vol.dd)
File System Type: NTFS
Sector Size: 512
Cluster Size: 4096
-> 성공. 이 이미지는 오프셋 0에서 파일시스템이 시작한다
```

| 볼륨 종류 | 오프셋 3부터의 OEM ID / 매직 | 위치 |
| --- | --- | --- |
| NTFS | `NTFS    ` (공백 4개 포함 8바이트) | 오프셋 `0x03` |
| exFAT | `EXFAT   ` | 오프셋 `0x03` |
| FAT | `MSDOS5.0`, `mkfs.fat` 등 | 오프셋 `0x03` |
| ext2/3/4 | 매직 `53 EF` | 오프셋 `0x438` |

이 경우 해결은 "오프셋을 안 주는 것"이다. `-o`를 붙이면 오히려 실패한다.

```bash
fsstat vol.dd
fls -r -p vol.dd | head
sudo mount -o ro,loop vol.dd /mnt/case          # offset 없이
```

### 원인 4 — 물리 이미지인데 오프셋을 안 준 경우

원인 3의 반대다. `mmls`는 잘 되는데 `fsstat image.dd`(오프셋 없이)가 실패한다. 이미지 첫 512바이트는 MBR/GPT이고 파일시스템이 아니므로 당연하다. `mmls`의 `Start`를 `-o`에 넣는다.

```bash
mmls image.dd                       # Start = 2048
fsstat -o 2048 image.dd             # 이제 성공
```

파티션이 여러 개면 **각각 시도**한다. `Description`이 `NTFS / exFAT (0x07)`인 것부터 본다.

## 2차 확인

1~4번을 배제했는데도 실패하면 5~7번이다.

### 원인 5 — 파티션 테이블 손상

`mmls`도 실패하고 `fsstat -o 0`도 실패하는 경우다. 파일시스템 시그니처를 직접 찾아 오프셋을 만든다.

```bash
grep -abo 'NTFS    ' image.dd | head
# 출력: 105906179  ->  볼륨 시작 = 105906179 - 3 = 105906176 바이트
python3 -c "print((105906179-3)//512)"     # -> 206848 (섹터)
fsstat -o 206848 image.dd                  # 성공하면 확정
```

시그니처 스캔의 상세 절차와 다른 파일시스템의 매직 값은 [FOR-0019](./mbr-gpt.html)에 정리되어 있다. 결과가 여러 개 나오면 **전부** 시도한다. `head`로 끊지 않는다.

### 원인 6 — 이미지가 잘렸다

```bash
ls -l image.dd
# 실제 크기 4,294,967,296 (4 GB)

mmls image.dd
# 003:  000:001   0000206848   0062521343   0062314496   NTFS / exFAT (0x07)
# 끝 섹터 62,521,343 -> 필요한 크기 = (62521343+1) × 512 = 32,011,208,192 (약 32 GB)
```

필요한 크기가 실제 파일 크기보다 크면 **이미지가 잘린 것**이다. 판정 공식:

```text
필요 크기 = (End 섹터 + 1) × 섹터 크기
필요 크기 > 실제 파일 크기  ->  잘림
```

| 잘렸을 때 어떻게 되나 | 대응 |
| --- | --- |
| 앞쪽 파티션은 정상 동작 | 앞쪽만 분석한다 |
| `$MFT`가 이미지 범위 안에 있으면 파일 목록은 나온다 | `fls`는 되지만 `icat`이 빈 파일/에러 |
| 뒤쪽 클러스터를 참조하는 파일 추출 실패 | 그 파일은 포기하거나 카빙으로 우회 ([FOR-0046](./foremost.html)) |
| E01이 `.E02`, `.E03`… 분할인데 일부만 받았다 | **모든 세그먼트를 같은 폴더에** 두고 `.E01`만 지정 |

### 원인 7 — E01을 raw로 취급

```bash
xxd -l 16 image.E01
# 00000000: 4556 4609 0d0a ff00 0100 ...   "EVF\x09\r\n\xff\x00"
```

첫 8바이트가 `45 56 46 09 0D 0A FF 00`이면 EWF(E01)다. raw가 아니므로 `xxd -s`로 오프셋을 계산해도 무의미하고, `mount -o offset=`도 통하지 않는다. 확장자가 `.dd`나 `.raw`로 위장돼 있어도 매직 바이트가 진실이다.

```bash
# FUSE 로 raw 처럼 노출한다 (권장)
ewfinfo image.E01                       # 획득 정보와 해시 확인
mkdir /mnt/ewf && ewfmount image.E01 /mnt/ewf     # /mnt/ewf/ewf1 이 raw 로 보인다
mmls /mnt/ewf/ewf1 && fsstat -o 2048 /mnt/ewf/ewf1

# Sleuth Kit 이 libewf 지원으로 빌드돼 있으면 직접 열린다
mmls -i ewf image.E01
```

Windows에서는 Arsenal Image Mounter([FOR-0017](./arsenal-image-mounter.html))나 FTK Imager([FOR-0016](./ftk-imager-open-image.html))가 E01을 그대로 읽으므로 오프셋 문제 자체가 사라진다.

## 다른 방법

오프셋을 손으로 계산하는 것을 아예 피하는 우회로들이다. **막히면 계산을 더 하지 말고 이쪽으로 넘어간다.**

```bash
# 커널이 파티션을 대신 잘라 준다 (-P). 오프셋 계산이 필요 없다
sudo losetup -P -f --show image.dd
# -> /dev/loop0 , 파티션은 /dev/loop0p1, /dev/loop0p2 로 생긴다
sudo mount -o ro /dev/loop0p2 /mnt/case
sudo umount /mnt/case && sudo losetup -d /dev/loop0
```

```bash
sudo kpartx -av image.dd && ls /dev/mapper/     # device-mapper 매핑 (해제는 -d)
dd if=image.dd of=vol.dd bs=512 skip=206848     # 파티션만 별도 파일로 분리
testdisk image.dd                               # Analyse -> Quick Search -> Deeper Search
```

| 방법 | 장점 | 주의 |
| --- | --- | --- |
| `losetup -P` | 오프셋 계산이 필요 없다 | 파티션 테이블이 온전해야 한다. root 권한 |
| `kpartx` | 같은 효과 | 사용 후 반드시 `-d`로 해제 |
| `dd`로 분리 | 이후 모든 도구를 오프셋 0으로 | 디스크 공간을 그만큼 더 쓴다 |
| `testdisk` | 손상된 테이블을 재구성 | **쓰기 기능이 있으므로 반드시 사본에** |
| Arsenal / FTK Imager | E01·VHD·VMDK를 그대로, GUI | Windows 전용 |
| Autopsy | 이미지를 넣으면 볼륨을 스스로 찾는다 ([FOR-0018](./autopsy-ingest.html)) | 느리다 |

**시각 관련 주의.** 오프셋 시행착오 중 이미지를 쓰기 가능 상태로 마운트하면 파일시스템의 접근/수정 시각과 저널이 갱신되어 증거가 오염된다. Linux는 항상 `-o ro`, Windows는 Arsenal의 읽기 전용 모드를 쓴다. `ntfs-3g`가 dirty 볼륨을 자동 복구하려 드는 경우가 있어 `-o ro` 없이는 저널이 재생될 수 있다.

## 실제 예시

```text
문제:
"이미지의 사용자 문서 폴더에서 flag.txt 를 찾으세요."
첨부: evidence.raw (2.1 GB)

1. 판을 읽는다
   $ ls -l evidence.raw
   -rw-r--r-- 1 user user 2147483648 evidence.raw

   $ mmls evidence.raw
   GUID Partition Table (EFI)
   Offset Sector: 0
   Units are in 4096-byte sectors

         Slot      Start        End          Length       Description
   000:  Meta      0000000000   0000000000   0000000001   Safety Table
   001:  -------   0000000000   0000000255   0000000256   Unallocated
   002:  Meta      0000000001   0000000001   0000000001   GPT Header
   003:  Meta      0000000002   0000000005   0000000004   Partition Table
   004:  000       0000000256   0000000511   0000000256   EFI system partition
   005:  001       0000000512   0000524287   0000523776   Basic data partition

   목표는 005 (Basic data partition), 시작 섹터 512.

2. 첫 시도 (실패):
   $ sudo mount -o ro,loop,offset=$((512*512)) evidence.raw /mnt/case
   mount: /mnt/case: wrong fs type, bad option, bad superblock on /dev/loop0

   습관적으로 512를 곱했다. 그런데 mmls 첫 줄은
   "Units are in 4096-byte sectors" 였다.
   512 × 512 = 262,144  -> 파일시스템이 없는 지점

3. 접근 변경 — 섹터 크기를 4096으로
   $ fsstat -o 512 evidence.raw | head -5
   FILE SYSTEM INFORMATION
   File System Type: NTFS
   Sector Size: 4096
   Cluster Size: 4096

   fsstat(섹터 단위)이 성공했다. 오프셋 확정.

   $ python3 -c "print(512*4096)"
   2097152
   $ sudo mount -o ro,loop,offset=2097152 evidence.raw /mnt/case
   $ ls /mnt/case
   '$Recycle.Bin'  Users  Windows

4. 두 번째 문제 — 파일이 안 보인다
   $ ls /mnt/case/Users/jhkim/Documents
   (비어 있다)

   $ fls -o 512 -r -p evidence.raw | grep -i 'flag.txt'
   -/r * 84213:  Users/jhkim/Documents/flag.txt        (* = 삭제됨)

   마운트로는 안 보이는 것이 정상이다. 삭제된 파일이었다.

5. 추출
   $ icat -o 512 -r evidence.raw 84213 > flag.txt
   $ cat flag.txt
   flag{s3ct0r_s1z3_1s_n0t_4lw4ys_512}

   (오프셋 인자가 여기서도 섹터 단위(512)임에 주의.
    바이트 2097152 를 넣었다면 조용히 실패했을 것이다)

정답: flag{s3ct0r_s1z3_1s_n0t_4lw4ys_512}
```

2단계의 실패가 이 글의 요지다. **`mmls` 출력 첫 줄의 `Units are in N-byte sectors`를 읽지 않고 512를 곱하는 것이 이 분야에서 가장 자주 일어나는 실수다.** 그리고 `mount`가 실패했을 때 오프셋을 이리저리 바꿔 보는 대신 **`fsstat -o <섹터>`로 판정을 먼저 확정**하는 것이 시간을 아끼는 순서다. `mount`는 성공/실패를 알려 주지만 왜 실패했는지는 알려 주지 않고, `fsstat`은 맞았을 때 `Sector Size`와 `Cluster Size`까지 준다.

## 막혔을 때 다음 체크

1. `mmls` 첫 줄의 **`Units are in N-byte sectors`** 를 읽었는가 (512 vs 4096)
2. 넣는 오프셋의 단위가 **섹터인지 바이트인지** 도구별로 확인했는가
3. `fsstat -o <섹터>`가 성공하는가 — **이것만이 판정 기준이다**
4. `mmls`가 실패하면 `fsstat -o 0`(오프셋 없이)을 시도했는가 → 볼륨 단독 이미지
5. `xxd -l 16`으로 매직 바이트를 봤는가 → `EVF` = E01, `NTFS`/`EXFAT` = 볼륨 단독
6. E01/Ex01이면 `ewfmount` 또는 `mmls -i ewf`로 열었는가
7. E01 분할 세그먼트(`.E02`, `.E03`…)가 **모두 같은 폴더에** 있는가
8. `ls -l` 크기가 `(End 섹터 + 1) × 섹터 크기`보다 작은가 → 이미지 잘림
9. 파티션이 여러 개면 **전부** `-o`에 넣어 봤는가
10. `mmls -b 4096`으로 섹터 크기를 강제해 봤는가
11. `losetup -P -f --show`로 커널이 파티션을 잘라 주게 했는가 (계산 불필요)
12. 파일 목록이 **쓰레기 이름**으로 나오는가 → 오프셋이 근접했지만 틀렸다
13. `grep -abo 'NTFS    '` 시그니처 스캔 결과를 **전부** 시도했는가 ([FOR-0019](./mbr-gpt.html))
14. `testdisk`로 파티션 테이블 복구를 시도했는가 (반드시 사본에)
15. 마운트가 `ro`인가 — 쓰기 마운트는 증거를 오염시킨다
16. BitLocker/암호화 볼륨인가 → 오프셋 문제가 아니다. 복호화가 먼저다

## 출처

- SRC-032 — The Sleuth Kit 도구 문서: `mmls`/`fsstat`/`fls`/`icat`/`istat`/`blkls`의 `-o`가 섹터 단위임, `-b`(장치 섹터 크기 강제), `-i`(이미지 타입) 옵션, `fsstat`의 `Sector Size`/`Cluster Size` 출력
- SRC-034 — UEFI 명세(GPT): 파티션 시작/끝을 LBA로 기술하므로 바이트 환산에 섹터 크기가 필요하다는 근거, 4Kn 디스크의 LBA 크기
- SRC-005 — Microsoft Learn(NTFS/MFT): 볼륨 부트섹터의 OEM ID(`NTFS    `) 위치와 볼륨 시작 지점의 관계
- 오류 메시지 문구는 배포판·도구 버전·로케일에 따라 다르다. 문구가 아니라 **어떤 명령이 성공하는가**로 판정할 것
