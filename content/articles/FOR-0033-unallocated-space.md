---
id: FOR-0033
title: "비할당 영역(Unallocated Space) 추출과 카빙"
slug: "unallocated-space"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["unallocated space", "$Bitmap", "$Unalloc", "cluster", "deleted file"]
file_paths: ["C:\\$Bitmap", "$Bitmap", "$MFT"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "FTK Imager", "Autopsy", "foremost", "scalpel", "photorec", "bulk_extractor", "strings", "binwalk"]
commands: ["blkls -o 2048 image.dd > unalloc.dd", "blkcalc -o 2048 -u 1234 image.dd", "fsstat -o 2048 image.dd", "foremost -t jpg,pdf,zip -i unalloc.dd -o carved", "bulk_extractor -o be_out unalloc.dd", "strings -t d -n 8 unalloc.dd", "blkstat -o 2048 image.dd 1234"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Sector Size", "Cluster Size", "Total Cluster Range", "Allocation Status"]
file_formats: ["ntfs", "dd", "raw", "e01"]
primary_terms: ["비할당 영역", "unallocated space", "blkls", "blkcalc"]
keywords: ["비할당 영역", "unallocated space", "blkls", "blkcalc", "$Bitmap", "카빙", "carving", "TRIM", "삭제 데이터", "free space", "$Unalloc"]
aliases: ["비할당 영역", "언얼로케이티드", "빈 공간 추출", "blkls", "삭제된 데이터 어디", "free space 카빙", "unallocated 뽑기"]
symptom_keywords: ["삭제된 파일 내용을 찾고 싶다", "MFT에는 이름만 있고 내용이 없다", "카빙할 대상을 좁히고 싶다", "복구했는데 내용이 0으로 채워져 있다", "카빙 결과의 원래 위치를 모르겠다"]
related: ["FOR-0034", "FOR-0021", "FOR-0027"]
source_ids: ["SRC-032", "SRC-005", "SRC-035"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

비할당 영역은 "파일시스템이 지금 아무 파일에도 배정하지 않은 클러스터"의 집합이며, 이미지 전체를 카빙하지 말고 `blkls -o <오프셋> image.dd > unalloc.dd`로 비할당 클러스터만 뽑아 그 파일에만 카빙·`strings`를 돌리면 대상 크기와 오탐이 함께 줄어든다.

## 어떤 문제에서 필요한가

- `$MFT`에 삭제 파일의 **이름은 남았는데 내용이 필요한** 경우 ([FOR-0021](./mft-basics.html))
- 지문이 "삭제된 사진/문서를 복구하라"라고 요구하는 경우
- 파일시스템 트리에는 없는 문자열(flag, URL, 계정)을 이미지 어딘가에서 찾아야 하는 경우
- 이미지가 수십 GB라 전체 카빙이 시간 안에 끝나지 않는 경우
- 포맷 후 재설치된 볼륨에서 이전 사용 흔적을 찾아야 하는 경우

핵심은 **대상 축소**다. 100 GB 이미지에서 비할당이 12 GB면 카빙 시간이 8분의 1이 되고, 살아 있는 파일이 중복 검출되는 오탐도 사라진다.

## 문제에서 처음 볼 단서

1. `fsstat` 출력의 `Cluster Size` — 이후 모든 오프셋 계산의 단위다
2. `$MFT`에서 `InUse=False`인 항목의 `FileSize` — 0이 아니면 클러스터에 내용이 있었다
3. `$Bitmap`의 0 비트 비율 — 비할당이 전체의 몇 %인지가 카빙 소요 시간을 결정한다
4. 매체 종류 — **SSD면 TRIM 때문에 이 절차가 무력할 수 있다** (아래 참고)
5. 지문에 나온 파일 형식 — 카버의 `-t` 목록을 그것만으로 좁힌다

## 30초 절차

```bash
blkls -o 2048 image.dd > unalloc.dd
```

이어서 세 줄로 1차 회수를 끝낸다.

```bash
fsstat -o 2048 image.dd | head -30                 # 클러스터 크기 확인
strings -t d -n 8 unalloc.dd | grep -Ei 'flag|http|@|C:\\\\Users' | head -40
foremost -t jpg,png,pdf,zip,doc -i unalloc.dd -o carved
```

`-o 2048`은 `mmls image.dd`로 얻은 파티션 시작 섹터다 ([FOR-0019](./mbr-gpt.html)). 이 값을 틀리면 `blkls`가 파일시스템을 인식하지 못하거나 엉뚱한 블록을 뽑는다.

## 상세 절차

### 1단계 — 클러스터 할당 해제가 실제로 하는 일

파일을 삭제할 때 NTFS가 하는 일은 세 가지뿐이다.

| 대상 | 삭제 시 변화 | 데이터는? |
| --- | --- | --- |
| MFT 레코드 헤더 | `in use` 플래그 하강 | 레코드 내용(이름·시각·데이터런)은 **그대로 남는다** |
| `$Bitmap` | 해당 클러스터 비트 1 → 0 | 클러스터 내용은 **그대로 남는다** |
| 부모 디렉터리 인덱스 | 엔트리 제거 | — |

즉 **파일 내용은 지워지지 않는다.** 지워지는 것은 "여기에 데이터가 있다"는 표시뿐이다. 그래서 삭제 직후의 비할당 영역은 삭제된 파일의 바이트를 그대로 담고 있다.

### 2단계 — `$Bitmap`이 비할당의 정의다

`$Bitmap`은 MFT 6번 레코드에 있는 메타파일이고, **클러스터 1개당 1비트**를 쓴다.

| 비트 값 | 의미 |
| --- | --- |
| 1 | 할당됨 (어떤 파일의 `$DATA`가 점유) |
| 0 | 비할당 |

`blkls`가 "비할당 블록"을 판정하는 근거가 바로 이 비트맵이다. 개별 블록의 상태는 `blkstat`으로 직접 확인한다.

```bash
blkstat -o 2048 image.dd 1234
```

```text
Cluster: 1234
Not Allocated
```

`Not Allocated`인데 그 자리에 JPEG 헤더가 보이면 **삭제된 파일의 잔존 데이터**다.

### 3단계 — 데이터가 사라지는 조건

비할당에 남아 있을 것이라는 가정이 깨지는 경우를 먼저 알아야 헛수고를 피한다.

| 조건 | 결과 | 판별 방법 |
| --- | --- | --- |
| **재할당** — 다른 파일이 그 클러스터를 다시 씀 | 부분/전체 덮어써짐. 카빙 결과가 중간부터 깨진다 | 카빙된 파일이 앞부분만 정상 |
| **SSD + TRIM** | OS가 삭제를 컨트롤러에 통보하고, 컨트롤러가 해당 블록을 0(또는 쓰레기)으로 반환 | 비할당이 **거의 전부 0x00** |
| **wiping (sdelete, cipher /w, DBAN)** | 0x00 또는 난수로 덮어씀 | 비할당 엔트로피가 0에 가깝거나 0.99에 가깝다 |
| **볼륨 축소/조각모음** | 데이터가 이동하며 원래 자리가 덮어써짐 | 카빙 결과가 조각남 |
| **암호화 볼륨** | 복호화 전에는 전부 난수처럼 보인다 | 엔트로피 0.99, 매직 바이트 0건 |

TRIM은 특히 중요하다. **TRIM이 활성인 SSD에서는 삭제 직후 몇 초 안에 비할당 영역이 0으로 채워지므로, 이 글의 카빙 절차 자체가 성립하지 않는다.** 이때는 방향을 바꿔서 메타데이터 계열(`$MFT`, `$UsnJrnl`, `$LogFile`, Prefetch, 레지스트리)에서 "무엇이 있었는가"를 재구성한다 ([FOR-0027](./usnjrnl-basics.html)). CTF 문제 이미지는 대개 가상디스크이므로 TRIM이 적용되지 않지만, 비할당이 전부 0으로 나오면 이 가능성을 먼저 떠올린다.

빠른 판정:

```bash
# 비할당이 전부 0인지 30초 확인
xxd unalloc.dd | head -5
tr -d '\0' < unalloc.dd | wc -c     # 0 이 아닌 바이트 수. 매우 작으면 wipe/TRIM
```

### 4단계 — 추출 방법 세 가지

| 도구 | 방법 | 특징 |
| --- | --- | --- |
| **Sleuth Kit** | `blkls -o 2048 image.dd > unalloc.dd` | 가장 빠르고 정확. 기본 동작이 "비할당 블록만 출력" |
| **FTK Imager** | 볼륨 트리에서 `[unallocated space]` 노드 선택 → Export | GUI. 여러 조각으로 나뉘어 표시된다 ([FOR-0016](./ftk-imager-open-image.html)) |
| **Autopsy** | `Data Sources > vol > $Unalloc` 노드 | ingest 결과 트리에 이미 준비되어 있다 ([FOR-0018](./autopsy-ingest.html)) |

`blkls`의 주요 옵션:

| 옵션 | 동작 |
| --- | --- |
| (없음) | **비할당 블록만** 출력 (기본값) |
| `-e` | 모든 블록 출력 (할당 + 비할당) |
| `-a` | 할당된 블록만 |
| `-s` | **slack 공간만** ([FOR-0034](./file-slack.html)) |
| `-o <섹터>` | 파티션 시작 섹터 오프셋 |
| `-l` | 블록별 상태를 목록으로 |

FTK Imager의 `[unallocated space]`는 하나의 큰 파일이 아니라 연속 구간별로 쪼개진 여러 항목으로 보인다. 조각 이름과 개수는 버전마다 다르므로 **전부 선택해서 한 폴더로 Export**한 뒤 이어 붙이거나 각각 카빙한다.

### 5단계 — 추출 후 무엇을 돌리나

세 갈래를 순서대로 돌린다. 앞의 것이 더 싸고 빠르다.

```bash
# (1) 문자열 — 가장 싸다. 오프셋을 함께 받는 것이 핵심
strings -t d -n 8 unalloc.dd > unalloc_str.txt
grep -Ein 'flag\{|password|BEGIN .*PRIVATE KEY|https?://' unalloc_str.txt | head
strings -t d -el -n 8 unalloc.dd | grep -i flag        # UTF-16LE (한글/Windows 문자열)

# (2) 시그니처 카빙 — 형식을 좁힐 수 있으면 좁힌다
foremost -t jpg,png,pdf,zip,docx -i unalloc.dd -o carved
photorec unalloc.dd                                    # 대화형, 복원율이 높다
scalpel -c scalpel.conf -o carved_s unalloc.dd

# (3) 특징값 일괄 추출 — 이메일/URL/전화/카드번호를 한 번에
bulk_extractor -o be_out unalloc.dd
```

`foremost` 결과 폴더에는 형식별 하위 디렉터리와 `audit.txt`가 생긴다. `audit.txt`에는 **각 복원 파일이 `unalloc.dd` 안 몇 번째 바이트에서 시작했는지**가 적히므로 반드시 보관한다. 6단계에서 이 값이 필요하다.

```text
$ head -12 carved/audit.txt
Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
Audit File

Foremost started at Fri Sep 10 11:02:31 2026
Invocation: foremost -t jpg,png,pdf -i unalloc.dd -o carved
Output directory: /case/carved
Configuration file: /etc/foremost.conf

File: unalloc.dd
Start: Fri Sep 10 11:02:31 2026
Length: 12 GB (12884901888 bytes)

Num      Name (bs=512)         Size      File Offset     Comment
0:      00000112.jpg          148 KB           57344
1:      00004096.png          2 MB           2097152
```

`bulk_extractor`는 `email.txt`, `url.txt`, `domain.txt`, `telephone.txt`, `ccn.txt` 등을 오프셋과 함께 남긴다. "유출된 이메일 주소를 찾아라" 유형은 이 한 방으로 끝나는 경우가 많다.

### 6단계 — 오프셋을 원본 이미지 좌표로 되돌리기

**이 단계가 이 글에서 가장 자주 틀리는 부분이다.** `unalloc.dd`는 비할당 클러스터만 골라 이어 붙인 파일이므로, 그 안의 오프셋은 **원본 이미지의 오프셋이 아니다.** "flag가 오프셋 0x4A2C000에 있었다"라고 답하면 틀린다.

변환은 `blkcalc`가 한다.

```bash
# unalloc.dd 안의 바이트 오프셋 -> 블록 번호
#   블록 번호 = 바이트 오프셋 / 클러스터 크기
#   예: 오프셋 57344, 클러스터 4096  ->  57344 / 4096 = 14

# blkls 이미지의 14번 블록이 원본 이미지의 몇 번 블록인가
blkcalc -o 2048 -u 14 image.dd
```

```text
1892
```

이제 원본 좌표로 되돌린다.

| 값 | 계산 |
| --- | --- |
| 원본 파일시스템 블록 번호 | `blkcalc -u` 결과 (예: 1892) |
| 파일시스템 시작 바이트 | 파티션 시작 섹터 × 섹터 크기 = 2048 × 512 = 1048576 |
| 블록의 바이트 오프셋 | 1892 × 4096 = 7749632 |
| **원본 이미지 절대 오프셋** | 1048576 + 7749632 = **8798208** |

`blkcalc`의 방향 옵션:

| 옵션 | 입력 | 출력 |
| --- | --- | --- |
| `-u <addr>` | `blkls` 출력(비할당 이미지)의 블록 번호 | 원본 이미지의 블록 번호 |
| `-d <addr>` | 원본 이미지의 블록 번호 | `blkls` 출력의 블록 번호 |
| `-s <addr>` | slack 이미지(`blkls -s`)의 블록 번호 | 원본 이미지의 블록 번호 |

검산은 `blkcat`으로 한다. 같은 내용이 나오면 매핑이 맞다.

```bash
blkcat -o 2048 image.dd 1892 | xxd | head -2
```

## 출력 필드 해석

`fsstat`에서 이 절차에 필요한 값만 읽는다.

```text
$ fsstat -o 2048 image.dd
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 1A2B3C4D5E6F7A8B
...
CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 5242879
```

| 필드 | 의미 | 이 글에서의 용도 |
| --- | --- | --- |
| `Sector Size` | 섹터 크기 (보통 512, 4Kn 디스크는 4096) | `-o` 오프셋 → 바이트 변환 |
| `Cluster Size` | 클러스터 크기 (NTFS 기본 4096) | **블록 번호 ↔ 바이트 변환의 단위** |
| `Total Cluster Range` | 전체 클러스터 번호 범위 | `blkcalc` 결과가 이 범위 안인지 검산 |
| `MFT Entry Size` | MFT 레코드 크기 (보통 1024) | `$MFT` 오프셋 계산 |
| `blkstat` 의 `Allocated`/`Not Allocated` | 개별 블록 할당 상태 | 삭제 데이터 여부 판정 |

카빙 결과 파일에서 확인할 것:

| 관찰 | 의미 |
| --- | --- |
| 파일 크기가 카버 기본 상한과 정확히 같다 | 푸터를 못 찾아 잘린 것. 실제 크기가 아니다 |
| 앞부분만 정상 표시되고 뒤가 깨진다 | 중간 클러스터가 **재할당되어 덮어써졌다** |
| 파일이 열리지만 내용이 다른 파일과 섞였다 | 조각화(fragmentation). 시그니처 카빙의 구조적 한계 |
| 전부 0 바이트 | TRIM 또는 wiping |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 카빙된 파일 (이름 없음) | `$MFT`의 `InUse=False` 항목과 크기·타임스탬프 대조로 원래 이름 추정 ([FOR-0021](./mft-basics.html)) |
| 삭제 시각이 필요하다 | `$UsnJrnl`의 `FILE_DELETE` 레코드 ([FOR-0027](./usnjrnl-basics.html)) |
| 파일이 있었던 원래 경로 | `$Recycle.Bin`의 `$I` 파일, `$UsnJrnl`의 `ParentFileReferenceNumber` |
| `blkcalc`로 얻은 원본 오프셋 | HxD로 그 오프셋 점프해 구조 직접 확인 ([FOR-0037](./hxd-header-check.html)) |
| 비할당에서 나온 URL | 브라우저 History와 대조 ([FOR-0191](./chrome-history.html)) |
| 비할당이 전부 0 | 메타데이터 계열로 전환 (`$MFT` / `$J` / Prefetch / 레지스트리) |
| 카빙 파일 확장자가 내용과 안 맞는다 | 시그니처 대조 ([FOR-0036](./signature-extension-mismatch.html)) |
| slack에도 잔존이 있는지 | `blkls -s` ([FOR-0034](./file-slack.html)) |

## 흔한 함정

- **이미지 전체를 카빙하는 것.** 살아 있는 파일이 전부 다시 검출되어 결과가 수만 건이 된다. 왜 틀리는가: 카버는 할당 여부를 모른다. 어떻게: `blkls`로 비할당만 뽑아 그 파일에 카빙한다.
- **`-o` 오프셋을 빼먹는 것.** `blkls image.dd`는 이미지 선두를 파일시스템으로 해석하려 해서 실패하거나 엉뚱한 결과를 낸다. `mmls`로 파티션 시작 섹터를 먼저 확인한다.
- **`unalloc.dd` 안의 오프셋을 그대로 답으로 쓰는 것.** 좌표계가 다르다. `blkcalc -u`로 원본 블록 번호로 되돌리고, 파티션 시작 바이트를 더한다.
- **비할당이 0으로 가득한데 카버를 계속 돌리는 것.** TRIM/wiping이면 결과가 나올 수 없다. `xxd | head`와 `tr -d '\0' | wc -c`로 5초 안에 판정한 뒤 메타데이터 라인으로 전환한다.
- **카빙된 파일의 타임스탬프를 증거로 쓰는 것.** 비할당에는 메타데이터가 없다. 카빙 결과의 파일 시각은 **카빙을 실행한 시각**이다. 시각이 필요하면 `$MFT`/`$UsnJrnl`에서 가져온다.
- **`-t` 없이 모든 형식을 카빙하는 것.** 텍스트·`htm`·`dll` 같은 형식이 수만 건 오탐을 만든다. 지문이 요구하는 형식만 지정한다.
- **조각화된 파일을 시그니처 카빙으로 복구하려는 것.** 시그니처 카빙은 "헤더에서 푸터까지 연속"을 가정한다. 조각난 파일은 `$MFT`의 데이터런을 읽어 `icat`으로 복구하는 편이 맞다.
- **비할당 = 삭제 파일이라고 단정하는 것.** 한 번도 쓰이지 않은 공간, 포맷 전 이전 볼륨의 잔재, 이전 OS의 페이지파일 조각도 전부 비할당이다. 출처를 단정하려면 `$MFT`/`$UsnJrnl`과 묶어야 한다.
- **`blkls -e`를 기본값으로 착각하는 것.** `-e`는 할당 블록까지 전부 포함하므로 결과가 이미지 크기와 비슷해진다. 옵션 없이 실행한 것이 비할당만이다.
- **E01을 먼저 RAW로 변환하려고 시간을 쓰는 것.** Sleuth Kit은 libewf가 있으면 `blkls -i ewf` 또는 자동 인식으로 E01을 직접 읽는다. 변환은 디스크 용량만 두 배로 먹는다.

## 교차검증

같은 결론을 서로 다른 도구로 두 번 확인한다.

```bash
# 1) 비할당 크기가 상식적인가
ls -l image.dd unalloc.dd
fsstat -o 2048 image.dd | grep -i cluster

# 2) 특정 블록이 정말 비할당인가
blkstat -o 2048 image.dd 1892

# 3) blkcalc 매핑이 맞는가 — 두 좌표의 내용이 같아야 한다
blkcat -o 2048 image.dd 1892 | md5sum
dd if=unalloc.dd bs=4096 skip=14 count=1 2>/dev/null | md5sum

# 4) 카버 두 개의 결과 수 비교 (구조적 오탐/누락 확인)
foremost -t jpg -i unalloc.dd -o f_out  && ls f_out/jpg | wc -l
photorec /log /d p_out unalloc.dd       && ls p_out | wc -l

# 5) 카빙된 파일이 진짜 그 형식인가
file carved/jpg/*.jpg | sort | uniq -c
```

Autopsy의 `$Unalloc` 노드 크기와 `blkls` 출력 크기가 다르면 **대상 볼륨이 다른 것**이다. Autopsy가 인식한 볼륨과 `mmls` 출력을 대조한다.

## mini walkthrough

```text
문제:
"직원이 자료를 삭제한 뒤 반납한 노트북 이미지입니다.
 삭제된 문서에 적힌 계좌번호를 찾으세요."
첨부: laptop.E01 (60 GB, NTFS 단일 볼륨)

1. mmls laptop.E01
   -> 002: 000002048  0125829119  0125827072  NTFS / exFAT (0x07)

2. 첫 시도 (실패한 접근):
   photorec 을 laptop.E01 전체에 걸었다.
   -> 22분 뒤 진행률 18%, 복원 파일 47,000건.
      살아 있는 Windows 설치 파일까지 전부 복원되어 목록이 무의미했다.
   -> 중단.

   무엇이 틀렸나: 카버는 클러스터의 할당 여부를 모른다.
   대상이 60 GB 전체가 되어 시간과 오탐이 동시에 폭발했다.

3. 접근 변경 — 비할당만 분리
   fsstat -o 2048 laptop.E01 | grep -i "cluster size"
   -> Cluster Size: 4096

   blkls -o 2048 laptop.E01 > unalloc.dd
   ls -l unalloc.dd
   -> 9.1 GB   (60 GB -> 9.1 GB, 대상 1/6.6)

4. 비할당이 살아 있는지 먼저 확인 (TRIM/wipe 배제)
   xxd unalloc.dd | head -3
   -> 00000000: 2d2d 2d2d 2d20 4245 ...   (0 이 아니다. 잔존 데이터 있음)

5. 가장 싼 것부터 — 문자열
   strings -t d -n 6 unalloc.dd | grep -E '[0-9]{3}-[0-9]{2,3}-[0-9]{6}' | head
   -> 4102340928  110-234-567890

   strings -t d -el -n 6 unalloc.dd | grep -E '[0-9]{3}-[0-9]{2,3}-[0-9]{6}' | head
   -> (UTF-16LE 에서도 같은 값 1건)

6. 문맥 확보 — 이 값이 어떤 파일에 있었나
   4102340928 / 4096 = 1001548  (unalloc.dd 안 블록 번호)
   blkcalc -o 2048 -u 1001548 laptop.E01
   -> 4517392                      (원본 파일시스템 블록 번호)

   blkstat -o 2048 laptop.E01 4517392
   -> Not Allocated                (삭제 데이터 확인)

7. 그 구간을 형식 카빙으로 되살린다
   foremost -t doc,docx,pdf,xls -i unalloc.dd -o carved
   grep -n 4102 carved/audit.txt
   -> 12:  00001001536.doc   38 KB   4102324224

   strings carved/doc/00001001536.doc | grep -A3 -B3 110-234
   -> 계좌: 110-234-567890  예금주: ...

8. 원래 파일 이름 확인 ($MFT 대조)
   MFTECmd 로 뽑은 CSV 에서 InUse=False, 크기 38KB 근처, 확장자 .doc
   -> 정산자료_2026Q1.doc  (삭제 시각 2026-03-14 07:22:41 UTC = 16:22:41 KST)

정답: 110-234-567890 (출처: 삭제된 정산자료_2026Q1.doc)
```

2→3단계가 이 글의 요지다. **60 GB 전체 카빙 22분에 답이 안 나왔고, 비할당 9.1 GB만 분리한 뒤 `strings` 한 줄로 40초에 나왔다.** 그리고 6단계의 `blkcalc` 없이는 "이 값이 삭제 데이터에서 나왔다"를 증명할 수 없었다.

## 막혔을 때 다음 체크

1. `mmls`로 얻은 `-o` 값이 정확한가 — `fsstat -o N`이 NTFS를 인식하는지로 검증
2. `unalloc.dd`가 전부 0인가 — TRIM/wiping이면 즉시 메타데이터 라인으로 전환
3. `strings -el`(UTF-16LE)을 돌렸는가 — 한글 문서 내용은 ASCII `strings`에 안 걸린다
4. 카버 `-t` 목록에 지문의 형식이 들어 있는가
5. `foremost`가 실패하면 `photorec`을 시도했는가 — 내부 형식 지식이 더 많아 복원율이 높다
6. slack 영역도 봤는가 — `blkls -s image.dd > slack.dd` ([FOR-0034](./file-slack.html))
7. `$MFT`의 데이터런으로 `icat` 직접 복구를 시도했는가 — 조각난 파일은 이쪽이 정답이다
8. 페이지파일/최대절전 파일은 별도로 추출했는가 (`pagefile.sys`, `hiberfil.sys`는 **할당된 파일**이라 비할당에 없다)
9. `$LogFile`/`$UsnJrnl`을 봤는가 — 내용은 없어도 이름과 시각은 남는다
10. 볼륨 섀도 복사본(VSS)이 있는가 — 삭제 전 상태가 그대로 남아 있을 수 있다
11. 카빙 결과가 앞부분만 정상인가 → 재할당된 것. `$MFT` 데이터런으로 원래 클러스터를 확인한다
12. 이미지가 암호화 볼륨인가 — 엔트로피가 0.99 부근이고 매직 바이트가 0건이면 BitLocker 등을 먼저 해제한다

## 출처

- SRC-032 — The Sleuth Kit 도구 문서: `blkls`(기본값이 비할당 블록 출력, `-e`/`-a`/`-s` 옵션), `blkcalc`(비할당 이미지 ↔ 원본 이미지 블록 주소 변환), `blkstat`, `blkcat`, `fsstat`의 동작과 옵션
- SRC-005 — Microsoft Learn, Master File Table: NTFS가 클러스터 할당을 `$Bitmap`으로 관리하고 삭제 시 MFT 레코드와 데이터가 즉시 소거되지 않는다는 근거
- SRC-035 — foremost/scalpel 매뉴얼: 시그니처 기반 카빙의 `-t` 형식 지정, `audit.txt`의 File Offset 컬럼, 헤더/푸터 기반 복원의 한계
- FTK Imager의 `[unallocated space]` 표시 방식과 조각 이름, Autopsy의 `$Unalloc` 노드 명칭은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- `blkcalc`의 옵션 방향(`-u`/`-d`/`-s`)은 버전에 따라 표기가 다를 수 있으므로 `blkcalc -h`로 확인할 것
- 카빙 결과의 절대 오프셋은 반드시 `blkcat`으로 원본 이미지에서 재확인할 것
