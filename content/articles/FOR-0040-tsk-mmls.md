---
id: FOR-0040
title: "Sleuth Kit mmls 옵션과 오프셋 파이프라인"
slug: "tsk-mmls"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["volume system", "partition table", "unallocated space", "metadata volume", "Safety Table"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "mmls", "fsstat", "fls", "icat", "ewfmount", "ewfinfo", "libewf", "Autopsy"]
commands: ["mmls image.dd", "mmls -t dos image.dd", "mmls -t gpt image.dd", "mmls -t list", "mmls -i list", "mmls -B image.dd", "mmls -b 4096 image.dd", "mmls -i ewf image.E01", "mmls -r image.dd", "mmls -a image.dd", "mmls -A image.dd", "mmls -o 2048 image.dd", "ewfmount image.E01 /mnt/ewf"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Slot", "Start", "End", "Length", "Description", "Offset Sector", "Units are in 512-byte sectors"]
file_formats: ["raw", "dd", "e01", "aff", "split"]
primary_terms: ["mmls"]
keywords: ["mmls", "Sleuth Kit", "파티션 오프셋", "volume system", "Cannot determine partition type", "-t gpt", "-i ewf", "4Kn", "섹터 크기", "unallocated", "metadata volume"]
aliases: ["mmls", "mmls 사용법", "파티션 오프셋 구하기", "mmls 안 됨", "e01 mmls", "-o 값 뭐 넣어야 하나", "mmls gpt", "mmls 4096"]
symptom_keywords: ["mmls가 파티션을 못 찾는다", "Cannot determine partition type가 뜬다", "E01을 mmls로 못 읽는다", "-o에 무엇을 넣어야 하는지 모르겠다", "파티션이 하나도 안 나온다", "섹터 크기가 4096인 것 같다", "fsstat이 오프셋을 거부한다"]
related: ["FOR-0019", "FOR-0041", "FOR-0043"]
source_ids: ["SRC-032", "SRC-034"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`mmls`는 이미지의 볼륨 시스템만 읽어 파티션 목록을 뽑는 도구이며, 출력의 `Start` 값이 그대로 뒤따르는 모든 Sleuth Kit 명령의 `-o` 인자가 된다 — 실패하면 `-t`로 타입을, `-b`로 섹터 크기를, `-i`로 이미지 형식을 강제하는 순서로 뚫는다.

파티션 테이블의 바이트 구조와 파티션 타입 코드/GUID는 [FOR-0019](./mbr-gpt.html)에서 다룬다. 이 글은 **도구를 어떻게 굴리는가**만 다룬다.

## 어떤 문제에서 필요한가

- `fls` / `icat` / `fsstat` / `istat` 가 요구하는 `-o` 값을 알아내야 하는 경우
- 이미지에 볼륨이 몇 개인지, 비할당 영역이 어디에 얼마나 있는지 먼저 재야 하는 경우
- Autopsy가 볼륨을 잘못 잡았거나 하나도 못 잡았을 때 CLI로 대조하는 경우
- E01/split RAW를 변환 없이 그대로 읽어야 하는 경우
- 카빙 대상 범위(비할당 구간의 시작·길이)를 정해야 하는 경우 ([FOR-0045](./carving-strategy.html))

## 문제에서 처음 볼 단서

1. `mmls image.dd`가 **파티션 표를 정상 출력**한다 → 바로 `Start` 값을 `-o`에 넣고 진행
2. `Cannot determine partition type` → 타입 자동탐지 실패. `-t` 강제 대상
3. 표는 나오는데 **전부 `-------` (Unallocated)** → 테이블은 있으나 엔트리가 비었거나 섹터 크기가 틀렸다
4. `Units are in 4096-byte sectors` → 4Kn 이미지. 이후 모든 명령에 `-b 4096`을 붙여야 한다
5. 파일명이 `.E01` / `.001` / `.aff` → 이미지 형식 지정(`-i`) 또는 분할 자동 인식 대상

## 30초 절차

```bash
mmls image.dd
```

```bash
mmls -B image.dd                 # 파티션 크기를 바이트 컬럼으로 함께 본다
mmls -t dos image.dd             # 자동탐지 실패 시 타입 강제 (dos / gpt / mac / bsd / sun)
mmls -b 4096 image.dd            # 4Kn 디스크
mmls -i ewf image.E01            # libewf 지원으로 빌드된 TSK 라면 E01 직접
fsstat -o <Start> image.dd       # 오프셋이 맞는지 즉시 검증
```

`mmls`가 성공하면 그 자리에서 `fsstat -o <Start>`로 검증까지 끝낸다. **검증 없이 `-o` 값을 다음 명령에 넘기면 빈 출력의 원인을 찾느라 시간을 잃는다.**

## 상세 절차

### 1단계 — 옵션 전체

| 옵션 | 의미 | 실전 용도 |
| --- | --- | --- |
| `-t mmtype` | 볼륨 시스템(미디어 관리) 타입 강제 | 자동탐지 실패 시. `dos` `gpt` `mac` `bsd` `sun` |
| `-t list` | 지원 타입 목록 출력 | 빌드가 무엇을 아는지 확인 |
| `-o offset` | **이미지 안에서 볼륨 시스템이 시작하는 오프셋(섹터)** | 이미지 안에 이미지가 들어 있는 경우, 중첩 볼륨 |
| `-b size` | 하부 장치의 섹터 크기(바이트) | 4Kn = `-b 4096`. 지정 없으면 이미지 형식의 값, 없으면 512 |
| `-B` | 파티션 크기를 **바이트로 표시하는 컬럼 추가** | 크기를 눈으로 환산하지 않아도 된다 |
| `-r` | DOS 파티션 안으로 **재귀**해 다른 파티션 테이블을 찾는다 | 확장 파티션, x86에 설치된 Unix 디스크 라벨 |
| `-a` | 할당된 볼륨만 표시 | 스크립트로 파티션만 뽑을 때 |
| `-A` | 비할당 볼륨만 표시 | 숨긴 영역·카빙 대상 찾기 |
| `-m` | 메타데이터 볼륨 표시 | GPT 헤더/파티션 테이블 행 |
| `-M` | 메타데이터 볼륨 숨김 | 출력 정리 |
| `-i imgtype` | 이미지 형식 강제 | `raw` `ewf` `aff` `split` 등. `-i list`로 확인 |
| `-i list` | 지원 이미지 형식 목록 | **E01 지원 여부 판정에 쓴다** |
| `-v` | 디버그 출력(stderr) | 왜 자동탐지가 실패했는지 |
| `-V` | 버전 표시 | 빌드 확인 |

`-a` `-A` `-m` `-M` 중 **아무것도 주지 않으면 전부 표시된다.** 하나라도 주면 그 종류만 표시된다. `mmls -a`는 파티션만 남기므로 파싱하기 편하다.

### 2단계 — DOS 파티션 테이블 출력

```text
$ mmls -B image.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Size    Description
000:  Meta      0000000000   0000000000   0000000001   512B    Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   1M      Unallocated
002:  000:000   0000002048   0000206847   0000204800   100M    NTFS / exFAT (0x07)
003:  000:001   0000206848   0500117503   0499910656   238G    NTFS / exFAT (0x07)
004:  -------   0500117504   0500118191   0000000688   344K    Unallocated
```

| 헤더 줄 | 의미 |
| --- | --- |
| `DOS Partition Table` | 판정된 볼륨 시스템 타입. `GUID Partition Table (EFI)`면 GPT |
| `Offset Sector: 0` | `-o`로 준 값이 반영된 기준점 |
| `Units are in 512-byte sectors` | **이 값이 `Start`/`End`/`Length`의 단위다. 반드시 읽는다** |

### 3단계 — GPT 출력의 차이

```text
$ mmls image_gpt.dd
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0001085439   0001083392   EFI system partition
005:  001       0001085440   0001118207   0000032768   Microsoft reserved partition
006:  002       0001118208   0499808255   0498690048   Basic data partition
```

| DOS와 다른 점 | 설명 |
| --- | --- |
| `Slot` 표기 | DOS는 `000:001`(테이블:엔트리), GPT는 `000` `001` 단일 번호 |
| `Description` | DOS는 파티션 타입 코드 추정, GPT는 **엔트리에 저장된 파티션 이름 문자열** |
| `Meta` 행 | GPT는 `Safety Table`(protective MBR), `GPT Header`, `Partition Table`이 별도 행으로 나온다 |

GPT의 `Description`은 사람이 쓴 이름이므로 **파일시스템 종류의 근거가 아니다.** `Basic data partition`이라고 적혀 있어도 안이 NTFS인지 exFAT인지 ext4인지는 `fsstat`으로 확인한다 ([FOR-0043](./tsk-fsstat.html)).

### 4단계 — E01 직접 읽기

두 가지 경로가 있다.

**경로 A — TSK가 libewf 지원으로 빌드된 경우**

```bash
mmls -i list                # 목록에 ewf 가 있는지 먼저 본다
mmls -i ewf image.E01
fls  -i ewf -o 206848 -r -p image.E01
icat -i ewf -o 206848 image.E01 9134 > out.bin
```

`-i ewf`를 쓰면 **뒤따르는 모든 TSK 명령에도 `-i ewf`를 붙여야 한다.** 하나라도 빠지면 그 명령만 raw로 해석해 실패한다.

**경로 B — 지원이 없거나 형식이 애매한 경우: ewfmount로 raw로 노출**

```bash
ewfinfo image.E01                     # 획득 정보·해시·분할 개수 확인
mkdir -p /mnt/ewf
ewfmount image.E01 /mnt/ewf           # /mnt/ewf/ewf1 이 raw 이미지처럼 보인다
mmls /mnt/ewf/ewf1
fls -o 206848 -r -p /mnt/ewf/ewf1
```

분할 이미지는 **첫 조각만 지정한다.** `image.001`을 주면 `.002` 이후를 자동으로 이어 붙인다. `image.E01`도 같다.

Windows GUI가 편하면 FTK Imager나 Arsenal Image Mounter로 마운트해 raw 볼륨을 만든 뒤 그 위에서 작업한다 ([FOR-0016](./ftk-imager-open-image.html), [FOR-0017](./arsenal-image-mounter.html)).

### 5단계 — 실패 진단 순서

증상별로 이 순서대로 뚫는다.

| 증상 | 원인 | 대응 |
| --- | --- | --- |
| `Cannot determine partition type` | 자동탐지 실패 | `mmls -t dos` → `-t gpt` → `-t mac` → `-t bsd` → `-t sun` 순으로 강제 |
| 위를 다 해도 실패 | **파티션 테이블이 없는 단일 볼륨 이미지** | `mmls`를 포기하고 `fsstat -o 0 image.dd` |
| 표는 나오는데 파티션이 없다 | 엔트리가 지워졌다 | 시그니처 스캔으로 볼륨 시작 찾기 ([FOR-0019](./mbr-gpt.html)) |
| 크기가 실제 디스크의 1/8 | 섹터 크기 오판 | `mmls -b 4096` |
| `Start` 값을 넣었는데 `fsstat` 실패 | `-b`를 downstream에 안 넘겼다 | 모든 명령에 동일한 `-b` 지정 |
| E01을 못 읽는다 | 빌드에 EWF 지원 없음 | `-i list` 확인 → `ewfmount` |
| 논리 이미지(AD1)·단일 파일 | 볼륨 시스템 자체가 없다 | `mmls` 대상이 아니다 |
| 큰 `Unallocated`가 하나뿐 | 삭제·숨긴 파티션 또는 암호화 볼륨 | 시그니처 스캔 / BitLocker 확인 |

```bash
# -t 를 순서대로 시도하는 한 줄
for t in dos gpt mac bsd sun; do echo "== $t"; mmls -t $t image.dd 2>&1 | head -5; done
```

### 6단계 — 오프셋을 다음 명령으로 이어 쓰는 파이프라인

`mmls`의 결론은 숫자 하나다. 그 숫자를 셸 변수에 넣고 끝까지 재사용한다.

```bash
IMG=image.dd
OFF=$(mmls -a "$IMG" | awk '/NTFS/ {print $3; exit}')
echo "offset=$OFF"

fsstat -o "$OFF" "$IMG" | head -20          # 검증
fls   -o "$OFF" -r -p "$IMG" > files.txt    # 전체 목록
fls   -o "$OFF" -r -p -d "$IMG" > del.txt   # 삭제 항목만
icat  -o "$OFF" "$IMG" 9134 > out.bin       # 특정 파일 추출
```

`mmls -a`로 **할당 볼륨만 남기면 컬럼 수가 고정되어** `awk '{print $3}'`가 안전하다. `-a` 없이 돌리면 `-------` 행과 `Meta` 행의 컬럼 수가 달라 파싱이 깨진다.

4Kn 이미지는 `-b`를 전부에 붙인다.

```bash
B=4096
OFF=$(mmls -a -b $B "$IMG" | awk '/NTFS/ {print $3; exit}')
fsstat -o "$OFF" -b $B "$IMG"
fls    -o "$OFF" -b $B -r -p "$IMG"
```

비할당 구간만 뽑아 카빙 범위를 정하는 것도 `mmls`의 역할이다.

```bash
mmls -A -B image.dd            # 비할당 볼륨만, 바이트 크기 포함
```

## 출력 필드 해석

| 컬럼 | 의미 | 어디에 쓰는가 |
| --- | --- | --- |
| 행 번호(`002:`) | 출력 줄 번호 | 사람이 지목하기 위한 번호. 파티션 번호가 아니다 |
| `Slot` | `Meta` / `-------` / 파티션 슬롯 | `Meta`=테이블 자체, `-------`=비할당 |
| `Start` | **시작 섹터** | 그대로 `-o` 값 |
| `End` | 끝 섹터(포함) | 범위 계산 |
| `Length` | 섹터 개수 | `Length × 섹터크기` = 볼륨 크기 |
| `Size`(`-B`) | 크기를 바이트/축약 단위로 | 눈으로 환산 생략 |
| `Description` | DOS는 타입 코드 추정, GPT는 파티션 이름 | **확정 근거가 아니다.** `fsstat`으로 확인 |

`Start`가 0인 볼륨과 `Offset Sector` 값은 다르다. `Offset Sector`는 `-o`로 준 기준점이고, `Start`는 그 기준점 기준의 상대 섹터다. **`-o`를 준 상태에서 나온 `Start`를 다시 `-o`에 넣으면 두 번 더해지지 않는다** — `mmls -o N`은 이미 절대 섹터로 환산해 출력한다. 헷갈리면 `-o` 없이 다시 돌려 대조한다.

## pivot: 다음에 볼 artifact

| mmls에서 얻은 것 | 다음 목표 |
| --- | --- |
| 파티션 `Start` | `fsstat -o N`으로 파일시스템 확정 ([FOR-0043](./tsk-fsstat.html)) |
| 파일시스템 확정 | `fls -o N -r -p`로 전체 파일 목록 ([FOR-0041](./tsk-fls.html)) |
| 파일의 메타주소 | `icat -o N`으로 내용 추출 ([FOR-0042](./tsk-icat.html)) |
| 큰 `Unallocated` 구간 | 비할당만 떼어 카빙 ([FOR-0045](./carving-strategy.html)) |
| 파티션 여러 개 | 각각 `fsstat`으로 종류 판정 후 우선순위 결정 |
| `Description`이 Linux | `/etc/passwd`, `/var/log`, `~/.bash_history` |
| 테이블이 깨졌다 | 파티션 테이블 바이트 직접 읽기 ([FOR-0019](./mbr-gpt.html)) |
| GUI로 교차확인 | FTK Imager Evidence Tree ([FOR-0016](./ftk-imager-open-image.html)) |

## 흔한 함정

- **`Units are in N-byte sectors` 줄을 읽지 않는 것.** 4Kn 이미지에서 512를 가정하면 오프셋이 8배 틀린다. → 첫 세 줄을 항상 읽고, 512가 아니면 이후 모든 명령에 `-b`를 붙인다.
- **`-b`를 `mmls`에만 주고 `fls`/`icat`/`fsstat`에는 빼먹는 것.** TSK의 `-o`는 "섹터 단위"이므로 섹터 크기가 다르면 같은 숫자가 다른 위치를 가리킨다. → 셸 변수로 묶어 전부에 넘긴다.
- **`-i ewf`를 첫 명령에만 주는 것.** 형식 지정은 명령마다 독립이다. 빠진 명령은 E01 헤더를 데이터로 읽고 실패한다.
- **`Description`을 파일시스템 확정으로 쓰는 것.** DOS는 타입 코드 기반 추정이고 GPT는 사용자가 쓴 이름이다. → `fsstat`이 유일한 판정 근거다.
- **`Meta` 행의 `Start`를 `-o`에 넣는 것.** `Primary Table`, `GPT Header`, `Partition Table`은 파티션이 아니다. `-M`으로 숨기면 실수하지 않는다.
- **`mmls` 실패를 "이미지가 깨졌다"로 결론 내는 것.** 파티션 테이블 없는 단일 볼륨 이미지가 CTF에서 매우 흔하다. → `fsstat -o 0`을 반드시 시도한다.
- **`-r`을 안 써서 확장 파티션 안쪽을 놓치는 것.** DOS 확장 파티션이나 x86 디스크에 얹힌 BSD 라벨은 재귀해야 보인다.
- **`awk '{print $3}'`을 `-a` 없이 쓰는 것.** `-------` 행은 `Slot` 컬럼이 한 토큰, 파티션 행은 `000:001`로 역시 한 토큰이지만 `Meta` 행과 헤더 줄이 섞이면 오탐이 난다. → `mmls -a`로 좁히고 `exit`으로 첫 결과만 받는다.
- **분할 이미지의 조각을 전부 나열하려다 순서를 틀리는 것.** 첫 조각만 주면 자동으로 이어진다.
- **`mmls` 결과를 Autopsy가 잡은 볼륨과 대조하지 않는 것.** 둘이 다르면 오프셋 지정이 다른 것이다. 개수부터 맞춰 본다 ([FOR-0018](./autopsy-ingest.html)).

## 교차검증

```bash
# 1) Sleuth Kit
mmls -B image.dd

# 2) 다른 구현으로 대조
fdisk -l image.dd            # MBR 중심
gdisk -l image.dd            # GPT 중심, 백업 헤더 자동 시도

# 3) 시그니처 직접 확인 (구조 해석은 FOR-0019)
xxd -s 0x1FE -l 2 image.dd   # 55 aa
xxd -s 512   -l 8 image.dd   # "EFI PART"

# 4) 최종 판정 — 오프셋이 맞으면 fsstat 이 성공한다
fsstat -o 206848 image.dd | head -5

# 5) 이미지 형식·해시 확인 (E01)
ewfinfo image.E01
```

`mmls`와 `fdisk`/`gdisk`의 파티션 개수가 다르면 볼륨 시스템 판정이 갈린 것이다. `mmls -t dos`와 `mmls -t gpt`를 각각 강제해 어느 쪽이 일관된 표를 내는지 본다.

## mini walkthrough

```text
문제:
"첨부한 이미지에서 사용자 문서를 찾아 플래그를 제출하세요."
첨부: case01.E01 (단일 파일, 4 GB)

1. 첫 시도 (실패):
   $ mmls case01.E01
   Cannot determine partition type

   E01 이니 형식을 강제해 본다.
   $ mmls -i ewf case01.E01
   mmls: image type "ewf" not supported

   -> 이 TSK 빌드에 libewf 지원이 없다.

2. 지원 목록을 먼저 확인한다 (처음부터 이걸 했어야 한다)
   $ mmls -i list
   Supported image format types:
       raw (Single or split raw file (dd))
       aff (Advanced Forensic Format)
       ...
   -> ewf 가 없다. 우회로가 필요하다.

3. 접근 변경 — ewfmount 로 raw 로 노출
   $ ewfinfo case01.E01 | head
   Acquiry information ...
   $ mkdir -p /mnt/ewf && ewfmount case01.E01 /mnt/ewf
   $ ls /mnt/ewf
   ewf1

   $ mmls /mnt/ewf/ewf1
   Cannot determine partition type      <- 또 실패

4. 두 번째 실패의 원인은 형식이 아니었다
   $ ls -l /mnt/ewf/ewf1
   -r--r--r-- 1 root root 4294967296 ...   (4 GiB)

   4 GiB 인데 512바이트 섹터로 보면 8388608 섹터.
   -t 를 전부 강제해 본다.
   $ for t in dos gpt mac bsd sun; do echo "== $t"; \
       mmls -t $t /mnt/ewf/ewf1 2>&1 | head -3; done
   == dos
   Cannot determine partition type
   == gpt
   Cannot determine partition type
   ...
   -> 타입 문제도 아니다. 남은 변수는 섹터 크기다.

5. 섹터 크기 강제
   $ mmls -b 4096 /mnt/ewf/ewf1
   DOS Partition Table
   Offset Sector: 0
   Units are in 4096-byte sectors

         Slot      Start        End          Length       Description
   000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
   001:  -------   0000000000   0000000255   0000000256   Unallocated
   002:  000:000   0000000256   0001048575   0001048320   NTFS / exFAT (0x07)

   -> 4Kn 이미지였다. Start = 256 (4096바이트 섹터 기준)

6. 검증 — -b 를 빼먹으면 여기서 또 실패한다
   $ fsstat -o 256 /mnt/ewf/ewf1
   Cannot determine file system type       <- -b 누락

   $ fsstat -o 256 -b 4096 /mnt/ewf/ewf1 | head -6
   FILE SYSTEM INFORMATION
   --------------------------------------------
   File System Type: NTFS
   Volume Serial Number: 4C2F9A1B7D3E5061
   OEM Name: NTFS
   Version: Windows XP
   -> 성공. 오프셋 확정.

7. 파이프라인으로 이어 쓴다
   $ fls -o 256 -b 4096 -r -p /mnt/ewf/ewf1 | grep -i 'documents/'
   r/r 9134-128-1:  Users/kim/Documents/report.docx
   -/r * 9188-128-1: Users/kim/Documents/passwords.txt

   $ icat -o 256 -b 4096 /mnt/ewf/ewf1 9188 > pw.txt
   $ cat pw.txt
   flag{4kn_s3ct0r_s1z3_m4tt3rs}

정답: flag{4kn_s3ct0r_s1z3_m4tt3rs}
```

두 번의 실패가 각각 다른 변수였다. **1단계는 이미지 형식, 4단계는 섹터 크기.** `mmls`가 실패하면 형식(`-i`) → 타입(`-t`) → 섹터 크기(`-b`) 순으로 하나씩 고정해 가며 좁힌다. 그리고 `-b`는 반드시 뒤따르는 모든 명령에 복사한다.

## 막혔을 때 다음 체크

1. 출력 셋째 줄의 `Units are in N-byte sectors`를 읽었는가
2. `-b`를 `fsstat`/`fls`/`icat`에도 전부 넘겼는가
3. `mmls -i list`로 이 빌드가 E01을 아는지 확인했는가
4. `-i ewf`를 모든 명령에 붙였는가, 아니면 `ewfmount`로 raw로 바꿨는가
5. `-t dos` `-t gpt` `-t mac` `-t bsd` `-t sun`을 전부 시도했는가
6. 그래도 안 되면 `fsstat -o 0`으로 **파티션 없는 단일 볼륨**을 시도했는가
7. `-r`로 확장 파티션 안쪽을 봤는가
8. `-A -B`로 비할당 구간의 크기를 확인했는가 (수 GB면 숨긴 파티션)
9. `Meta` 행의 `Start`를 오프셋으로 쓰지 않았는가 (`-M`으로 숨겨 확인)
10. `Description`을 파일시스템 확정 근거로 쓰지 않았는가
11. 분할 이미지에서 **첫 조각**을 지정했는가
12. `fdisk -l` / `gdisk -l` 결과와 파티션 개수가 일치하는가
13. 논리 이미지(AD1)라면 볼륨 시스템이 애초에 없다는 것을 알고 있는가

## 출처

- SRC-032 — The Sleuth Kit 도구 문서(mmls man page): `-t` `-o` `-b` `-B` `-r` `-a` `-A` `-m` `-M` `-i` `-v` `-V` 의 정의, "아무 선택 플래그도 없으면 전 종류 표시" 규칙, 분할 이미지 자동 인식
- SRC-034 — UEFI 명세: GPT의 protective MBR / GPT 헤더 / 파티션 엔트리 배열이 별도 `Meta` 볼륨으로 표시되는 근거, 파티션 이름 필드가 `Description`에 나오는 이유
- 지원되는 `-t` / `-i` 값 목록은 man page가 열거하지 않고 **빌드마다 다르다.** 반드시 `mmls -t list` / `mmls -i list`로 현장에서 확인할 것
- 출력 예시의 파티션 배치·시리얼·플래그 값은 설명을 위한 예시이며 실제 이미지의 값은 다르다
