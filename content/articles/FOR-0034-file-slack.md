---
id: FOR-0034
title: "File Slack(RAM slack / drive slack) 계산과 추출"
slug: "file-slack"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["file slack", "RAM slack", "drive slack", "cluster", "$DATA", "resident"]
file_paths: ["C:\\$MFT", "$MFT"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "HxD", "FTK Imager", "Autopsy", "strings", "MFTECmd"]
commands: ["blkls -s -o 2048 image.dd > slack.dd", "icat -s -o 2048 image.dd 84213 > with_slack.bin", "istat -o 2048 image.dd 84213", "blkcat -o 2048 image.dd 1892", "fsstat -o 2048 image.dd"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Sector Size", "Cluster Size", "Size", "init_size", "Allocated Size"]
file_formats: ["ntfs", "dd", "raw"]
primary_terms: ["file slack", "파일 슬랙", "RAM slack", "슬랙"]
keywords: ["file slack", "슬랙", "RAM slack", "drive slack", "cluster slack", "논리 크기", "물리 크기", "잔존 데이터", "blkls -s", "icat -s"]
aliases: ["슬랙 영역", "file slack", "램 슬랙", "클러스터 남는 공간", "슬랙에 숨긴 데이터", "논리크기 물리크기 차이"]
symptom_keywords: ["파일 크기와 점유 크기가 다르다", "파일 끝에 이상한 데이터가 붙어 있다", "슬랙에 뭐가 있는지 보고 싶다", "이전 파일 내용이 보인다", "숨겨진 데이터를 못 찾겠다"]
related: ["FOR-0033", "FOR-0021", "FOR-0037"]
source_ids: ["SRC-032", "SRC-005", "SRC-088"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

NTFS는 파일에 클러스터 단위로 공간을 주기 때문에 파일의 논리 크기와 물리 점유 크기 사이에 항상 빈 틈이 생기고, 이 틈(slack)에는 그 클러스터를 예전에 쓰던 파일의 바이트가 그대로 남아 있으므로 `icat -s`나 `blkls -s`로 반드시 함께 꺼내 본다.

## 어떤 문제에서 필요한가

- 파일을 정상적으로 열어봤는데 아무것도 없고, 지문은 "이 파일에 숨겨져 있다"라고 하는 경우
- `$MFT`의 논리 크기와 Autopsy의 점유 크기가 다른 이유를 설명해야 하는 경우
- "삭제된 파일의 일부"만 필요한데 비할당 카빙으로는 안 나오는 경우 ([FOR-0033](./unallocated-space.html))
- 지문에 "slack", "잔여 공간", "클러스터 나머지"가 등장하는 경우
- 작은 텍스트 조각(flag, 암호, 계좌번호)을 찾아야 하는 경우 — slack에 남는 전형적인 크기다

## 문제에서 처음 볼 단서

1. `fsstat`의 `Sector Size`와 `Cluster Size` — slack 계산의 두 단위다
2. 대상 파일의 논리 크기 — 클러스터 크기로 나눈 나머지가 slack의 크기를 결정한다
3. 파일 크기가 클러스터 배수와 아주 가까운가 — 그러면 slack이 거의 없어 볼 가치가 낮다
4. `strings`가 파일 본문에서 끝나지 않고 이어지는가 — HxD로 열었을 때 논리 끝 이후에 텍스트가 보이면 확정
5. 파일이 resident인가 — 클러스터가 없으면 클러스터 slack도 없다 (아래 참고)

## 30초 절차

```bash
icat -s -o 2048 image.dd 84213 > with_slack.bin
```

`-s`가 slack 포함이다. 그 다음:

```bash
fsstat -o 2048 image.dd | grep -iE 'sector size|cluster size'
istat -o 2048 image.dd 84213 | head -40      # 논리 크기와 클러스터 목록
ls -l with_slack.bin                          # 물리 점유 크기와 같아야 한다
strings -t d -n 6 with_slack.bin | tail -20   # 논리 끝 이후의 문자열
```

볼륨 전체의 slack만 모으려면:

```bash
blkls -s -o 2048 image.dd > slack.dd
strings -n 8 slack.dd | grep -Ei 'flag|password|http'
```

## 상세 절차

### 1단계 — 세 가지 크기를 구분한다

| 이름 | 정의 | 어디서 보나 |
| --- | --- | --- |
| **논리 크기 (logical size)** | 파일 내용의 실제 바이트 수 | 탐색기의 "크기", `$MFT`의 `FileSize`, `ls -l` |
| **물리 크기 (physical / allocated size)** | 파일에 배정된 클러스터의 총 바이트 = 클러스터 크기의 배수 | 탐색기의 "디스크 할당 크기", `istat`의 클러스터 개수 × 클러스터 크기 |
| **초기화 크기 (initialized size)** | 실제로 쓰기가 일어난 바이트 수 | `istat`의 `init_size` (버전에 따라 표기 다름) |

`slack = 물리 크기 - 논리 크기`. 이 정의만 잡아 두면 나머지는 산수다.

### 2단계 — 계산 예시 (이 글의 핵심)

클러스터 4096바이트, 섹터 512바이트, 파일 논리 크기 5000바이트를 가정한다.

| 단계 | 계산 | 값 |
| --- | --- | --- |
| 필요한 클러스터 수 | `ceil(5000 / 4096)` | 2개 |
| 물리 점유 크기 | `2 × 4096` | 8192 바이트 |
| **전체 slack** | `8192 - 5000` | **3192 바이트** |
| 데이터가 걸친 마지막 섹터 | `ceil(5000 / 512)` = 10번째 섹터 | 논리 끝은 그 섹터 중간 |
| 마지막 섹터의 끝까지 | `10 × 512` | 5120 바이트 |
| **RAM slack** (섹터 나머지) | `5120 - 5000` | **120 바이트** |
| **drive slack** (클러스터 나머지 = 남은 섹터들) | `8192 - 5120` | **3072 바이트** |
| 검산 | `120 + 3072` | 3192 = 전체 slack |

두 종류의 성격이 완전히 다르다.

| 구분 | 범위 | 무엇이 들어 있나 |
| --- | --- | --- |
| **RAM slack** | 논리 끝 → 그 섹터의 끝 | 과거 Win9x는 메모리 내용을 그대로 흘렸다. **NT 계열(현재 Windows)은 0x00으로 채운다** |
| **drive slack (file slack)** | 마지막 섹터 다음 → 클러스터의 끝 | **OS가 건드리지 않는다.** 그 섹터를 예전에 쓴 파일의 바이트가 그대로 남는다 |

즉 **실전 포렌식에서 값이 있는 쪽은 drive slack**이다. RAM slack이 0으로 채워져 있다고 실망하고 멈추면 안 된다. 0의 구간이 끝난 다음부터가 본론이다.

```text
클러스터 0                                클러스터 1
|<-------------- 4096 -------------->|<-------------- 4096 -------------->|
[  파일 데이터 5000 바이트           ][   904   |0x00×120|  이전 파일 3072  ]
                                       ^         ^        ^
                                   논리 끝   RAM slack   drive slack
                                   (5000)   (섹터 채움)  (건드리지 않음)
```

### 3단계 — Sleuth Kit으로 꺼내기

```bash
# (1) 파일 하나의 slack 포함 전체 (= 물리 점유 전체)
icat -s -o 2048 image.dd 84213 > with_slack.bin

# (2) slack 없는 원본
icat -o 2048 image.dd 84213 > logical.bin

# (3) 차이가 곧 slack
ls -l logical.bin with_slack.bin
#  -rw-r--r-- 5000 logical.bin
#  -rw-r--r-- 8192 with_slack.bin
dd if=with_slack.bin of=slack_only.bin bs=1 skip=5000
strings -n 4 slack_only.bin
```

```bash
# (4) 볼륨 전체의 slack 만 한 파일로
blkls -s -o 2048 image.dd > slack.dd
ls -lh slack.dd
strings -t d -n 8 slack.dd | grep -Ei 'flag|BEGIN |@'
```

`blkls -s` 결과 안의 오프셋은 원본 이미지 오프셋이 아니다. `blkcalc -s <addr>`로 원본 블록 번호로 되돌린다 ([FOR-0033](./unallocated-space.html)).

### 4단계 — 클러스터 번호를 직접 확인하고 blkcat으로 읽기

`icat -s`가 안 통하거나 구조를 눈으로 봐야 할 때는 `istat`으로 클러스터 목록을 얻어 마지막 클러스터를 `blkcat`으로 직접 읽는다.

```bash
istat -o 2048 image.dd 84213
```

```text
MFT Entry Header Values:
Entry: 84213        Sequence: 3
$LogFile Sequence Number: 118273940
Allocated File
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Archive
Owner ID: 0
Created:        2026-03-14 07:22:41.1284416 (UTC)
File Modified:  2026-03-14 07:24:03.9013120 (UTC)
MFT Modified:   2026-03-14 07:24:03.9013120 (UTC)
Accessed:       2026-03-14 07:22:41.1284416 (UTC)

Attributes:
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 84
Type: $DATA (128-1)   Name: N/A   Non-Resident   size: 5000  init_size: 5000
1892 1893
```

마지막 줄의 `1892 1893`이 이 파일이 점유한 클러스터 번호다. slack은 **1893 클러스터의 뒷부분**에 있다.

```bash
blkcat -o 2048 image.dd 1893 | xxd | tail -20
```

```text
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 5052 4f4a 4543 5420 4b45 593a 2073 6b32  PROJECT KEY: sk2
000000f0: 3961 6633 6231 640a 0000 0000 0000 0000  9af3b1d.........
```

`1893 - 1892 = 1`번째(0부터 두 번째) 클러스터이므로, 논리 데이터는 이 클러스터에서 `5000 - 4096 = 904`바이트만 차지한다. 그 이후 바이트가 slack이며, 위 출력의 `PROJECT KEY:` 문자열은 **이전 파일의 잔존 데이터**다.

### 5단계 — HxD로 직접 보기

HxD로 **파일을 열면 논리 크기까지만 보인다.** slack은 파일이 아니라 볼륨의 일부이므로, 볼륨(또는 이미지)을 열어 클러스터 오프셋으로 점프해야 한다 ([FOR-0037](./hxd-header-check.html)).

| 목표 | 방법 |
| --- | --- |
| slack을 보고 싶다 | 이미지 파일 또는 디스크를 열고 **클러스터의 절대 오프셋**으로 이동 |
| 오프셋 계산 | `파티션 시작 섹터 × 섹터 크기 + 클러스터 번호 × 클러스터 크기` |
| 위 예시 | `2048 × 512 + 1893 × 4096 = 1048576 + 7753728 = 8802304` |
| 편한 우회 | `icat -s`로 뽑은 `with_slack.bin`을 HxD로 열고 논리 크기 지점부터 본다 |

CTF에서는 후자가 훨씬 빠르다. `icat -s` 결과 파일에서 논리 크기(5000 = 0x1388) 오프셋으로 점프하면 그 지점부터가 slack이다.

### 6단계 — resident 파일에는 이 계산이 적용되지 않는다

`$DATA`가 MFT 레코드 안에 들어가는 resident 파일(대략 700바이트 이하)은 **클러스터를 하나도 배정받지 않는다** ([FOR-0021](./mft-basics.html)).

| 상황 | 클러스터 slack | 그럼 잔존 데이터는 어디에 |
| --- | --- | --- |
| non-resident (클러스터 배정) | 있다. 이 글의 계산대로 | 마지막 클러스터의 뒷부분 |
| **resident** (레코드 내부) | **없다.** 배정된 클러스터가 없다 | MFT 레코드(보통 1024바이트) 안에서 속성 뒤에 남은 여유 공간 |
| resident였다가 커져서 non-resident로 전환 | 있다 | 레코드 안의 옛 데이터 + 새 클러스터의 slack **양쪽** |

resident 파일의 레코드 여유 공간은 HxD로 MFT 레코드를 직접 보는 것이 가장 확실하다. 레코드 오프셋 = `EntryNumber × 1024`. 속성 목록이 끝나는 `FF FF FF FF` 종료 표식 이후의 바이트를 본다.

### 7단계 — slack에 데이터를 숨기는 기법과 탐지

| 기법 | 원리 | 탐지 |
| --- | --- | --- |
| 논리 크기를 줄여 뒷부분을 slack으로 만들기 | 파일 끝에 데이터를 붙인 뒤 크기 필드를 원래대로 되돌린다 | `init_size`와 `size` 불일치, slack에 고엔트로피 데이터 |
| 전용 slack 은닉 도구 사용 | 클러스터 나머지에 직접 쓴다 | slack 구간이 0이 아니고 **주변 파일과 무관한 내용** |
| slack에 암호문 분산 저장 | 여러 파일의 slack에 조각 저장 | `blkls -s` 결과 전체에 엔트로피/문자열 스캔 |

정상 slack과 은닉 slack을 구별하는 기준:

| 관찰 | 해석 |
| --- | --- |
| slack 전체가 0x00 | 새로 배정된 클러스터. 볼 것 없다 |
| slack에 다른 파일 형식의 조각(문서 XML, HTML 태그) | **정상적인 잔존 데이터.** 이전 파일의 흔적 |
| slack이 난수처럼 보인다 (엔트로피 높음) | 암호화된 은닉 데이터 후보 |
| slack에 완결된 매직 바이트가 있다 | 파일을 통째로 숨긴 것. `binwalk`로 확인 |
| 여러 파일의 slack에 동일한 패턴 | 도구로 분산 저장한 흔적 |

## 출력 필드 해석

`istat`의 `$DATA` 줄이 핵심이다.

| 필드 | 의미 | slack 판정에서의 역할 |
| --- | --- | --- |
| `Non-Resident` / `Resident` | 클러스터 배정 여부 | Resident면 클러스터 slack이 없다 |
| `size:` | **논리 크기** | slack 시작 지점 |
| `init_size:` | 초기화된 크기 | `size`보다 작으면 뒤쪽이 0으로 읽힌다. `size`보다 큰 값이 보이면 크기 조작 의심 |
| 마지막 줄의 숫자 목록 | 점유 클러스터 번호 (데이터런) | 마지막 번호가 slack이 있는 클러스터 |
| `Allocated File` / `Not Allocated` | 삭제 여부 | 삭제된 파일이면 slack 이전에 본문부터 재할당 위험 |

`fsstat`에서:

| 필드 | 값 예 | 쓰임 |
| --- | --- | --- |
| `Sector Size` | 512 | RAM slack 경계 계산 |
| `Cluster Size` | 4096 | drive slack 경계 계산 |

타임스탬프는 `istat` 출력에서 **UTC로 표시된다**(FILETIME은 1601-01-01 UTC 기준 100ns 단위). 문제가 KST를 요구하면 +9시간 한다. Unix epoch와의 차이는 11644473600초다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| slack에서 나온 문자열 | 그 문자열로 볼륨 전체 키워드 검색 ([FOR-0018](./autopsy-ingest.html)) |
| slack에 남은 이전 파일 조각 | `$MFT`의 `InUse=False` 항목과 대조해 이전 파일 이름 추정 ([FOR-0021](./mft-basics.html)) |
| 그 클러스터를 예전에 쓴 파일 | `$UsnJrnl`에서 같은 시기 `FILE_DELETE` 검색 ([FOR-0027](./usnjrnl-basics.html)) |
| slack이 전부 0 | 비할당 영역으로 전환 ([FOR-0033](./unallocated-space.html)) |
| 논리 크기 조작 의심 | HxD로 MFT 레코드의 `$DATA` 헤더 직접 확인 ([FOR-0037](./hxd-header-check.html)) |
| slack 안의 완결된 파일 | `binwalk`/`foremost`로 추출 후 형식 확인 ([FOR-0036](./signature-extension-mismatch.html)) |
| resident 파일 | MFT 레코드 여유 공간을 HxD로 확인 |

## 흔한 함정

- **탐색기나 HxD에서 파일을 열어 slack을 찾는 것.** 파일 핸들은 논리 크기까지만 읽게 되어 있으므로 slack은 애초에 보이지 않는다. 볼륨/이미지를 열거나 `icat -s`를 쓴다.
- **`icat`에 `-s`를 빼먹는 것.** `-s` 없는 `icat`은 논리 크기까지만 출력하므로 slack이 통째로 빠진다. 출력 파일 크기가 클러스터 배수인지로 즉시 검증한다.
- **RAM slack이 0이라서 slack 전체가 비었다고 결론 내리는 것.** NT 계열 Windows는 RAM slack을 0으로 채운다. **0 구간 뒤의 drive slack**부터가 본론이다.
- **`blkls -s`의 오프셋을 원본 이미지 오프셋으로 쓰는 것.** slack 이미지는 별도 좌표계다. `blkcalc -s`로 변환한다.
- **resident 파일에 클러스터 slack을 기대하는 것.** 700바이트짜리 텍스트 파일은 클러스터를 안 받는다. MFT 레코드 내부 여유 공간을 봐야 한다.
- **클러스터 크기를 4096으로 가정하는 것.** exFAT/큰 볼륨은 32 KB~128 KB인 경우도 있다. 클러스터가 크면 slack도 커진다(= 잔존 데이터가 많다). 반드시 `fsstat`으로 확인한다.
- **slack의 내용을 그 파일의 내용으로 보고하는 것.** slack은 **다른 파일**의 잔재다. "A.docx의 slack에서 발견"이라고 쓰되 "A.docx에 들어 있었다"라고 쓰지 않는다.
- **압축/암호화된 `$DATA`에 단순 계산을 적용하는 것.** NTFS 압축(sparse/compressed) 파일은 클러스터 배정 방식이 달라 `물리 - 논리` 산수가 성립하지 않는다. `istat`의 속성 플래그를 먼저 본다.
- **slack에서 찾은 타임스탬프를 신뢰하는 것.** 잔존 데이터의 시각 값은 이전 파일의 것이고, 그 파일이 언제 삭제됐는지는 slack만으로 알 수 없다.
- **`dd ... bs=1 skip=N`으로 큰 파일을 자르는 것.** `bs=1`은 매우 느리다. 큰 대상은 `bs=4096 skip=<클러스터수>`로 클러스터 단위로 자른 뒤 미세 조정한다.

## 교차검증

```bash
# 1) 물리 크기가 정말 클러스터 배수인가
ls -l with_slack.bin                      # 8192 = 4096 * 2  (OK)

# 2) 논리 부분이 원본과 동일한가 (앞부분 해시 비교)
head -c 5000 with_slack.bin | md5sum
icat -o 2048 image.dd 84213 | md5sum

# 3) istat 의 클러스터 번호로 직접 읽은 것과 icat -s 의 꼬리가 같은가
blkcat -o 2048 image.dd 1893 | md5sum
dd if=with_slack.bin bs=4096 skip=1 count=1 2>/dev/null | md5sum

# 4) 볼륨 전체 slack 에도 같은 문자열이 있는가
blkls -s -o 2048 image.dd | strings -n 6 | grep -c 'PROJECT KEY'

# 5) 그 클러스터가 지금 할당 상태인가
blkstat -o 2048 image.dd 1893
```

Autopsy에서 같은 파일을 열면 하단 `Hex` 탭이 **점유 클러스터 전체**를 보여주므로 CLI 결과와 육안 대조가 가능하다.

## mini walkthrough

```text
문제:
"보고서 파일 하나를 드립니다. 이 파일이 있던 자리에 남은
 이전 문서의 프로젝트 키를 찾으세요."
첨부: disk.dd (2 GB, NTFS), 지문에 report.docx 언급

1. mmls disk.dd
   -> 002: 000002048  0004194303  ...  NTFS

   fls -o 2048 -r -p disk.dd | grep -i report
   -> r/r 84213-128-1:  Users/jhkim/Documents/report.docx

2. 첫 시도 (실패한 접근):
   icat -o 2048 disk.dd 84213 > report.docx
   7z l report.docx  &&  strings report.docx | grep -i 'project\|key'
   -> 정상 docx. 내부에 프로젝트 키 없음.
      binwalk report.docx -> 붙어 있는 파일 없음.
      exiftool report.docx -> 특이사항 없음.

   무엇이 틀렸나: 문제는 "이 파일 안"이 아니라 "이 파일이 있던 자리"를
   물었다. -s 없는 icat 은 논리 크기까지만 뽑기 때문에
   slack 이 처음부터 출력에 포함되지 않았다.

3. 접근 변경 — slack 포함으로 다시 추출
   fsstat -o 2048 disk.dd | grep -iE 'sector size|cluster size'
   -> Sector Size: 512
      Cluster Size: 4096

   istat -o 2048 disk.dd 84213 | tail -5
   -> Type: $DATA (128-1) ... Non-Resident  size: 5000  init_size: 5000
      1892 1893

   icat -s -o 2048 disk.dd 84213 > with_slack.bin
   ls -l with_slack.bin
   -> 8192          (5000 -> 8192. slack 3192 바이트 확보)

4. slack 만 분리
   dd if=with_slack.bin of=slack_only.bin bs=1 skip=5000
   xxd slack_only.bin | head -12
   -> 00000000: 0000 0000 ... 0000                (RAM slack 120 바이트 = 0)
      00000078: 5052 4f4a 4543 5420 4b45 593a 2073  PROJECT KEY: s
      00000088: 6b32 3961 6633 6231 640a            k29af3b1d.

   0x78 = 120. RAM slack 이 끝나는 정확히 그 지점부터
   drive slack 이 시작되고, 거기에 이전 파일 내용이 있다.

5. 검산 — 계산과 실제가 맞는가
   ceil(5000/4096) = 2 클러스터 -> 8192 바이트 점유
   RAM slack  = ceil(5000/512)*512 - 5000 = 5120 - 5000 = 120   (0x78) OK
   drive slack = 8192 - 5120 = 3072                              OK
   전체 slack = 120 + 3072 = 3192                                OK

6. 이전 파일이 무엇이었나 (교차검증)
   MFTECmd 로 뽑은 CSV 에서 InUse=False 항목 중
   삭제 시각이 report.docx 생성 직전인 것:
   -> 프로젝트계획_v3.docx (삭제 2026-03-14 07:20:11 UTC = 16:20:11 KST)
      report.docx 생성 2026-03-14 07:22:41 UTC
   같은 클러스터를 재사용한 것이 시간순으로 일치한다.

정답: sk29af3b1d (삭제된 프로젝트계획_v3.docx 의 잔존 데이터, report.docx 의 drive slack)
```

2→3단계가 전부다. **`-s` 한 글자가 3192바이트를 보이게 만든다.** 그리고 4단계에서 0x78(=120)이 RAM slack 계산값과 정확히 일치한 것이 "우연히 붙은 쓰레기가 아니라 구조적인 slack"임을 증명한다.

## 막혔을 때 다음 체크

1. `icat`에 `-s`를 넣었는가 — 출력 크기가 클러스터 배수인지로 확인
2. `fsstat`으로 실제 `Cluster Size`/`Sector Size`를 확인했는가 (4096/512로 가정하지 않았는가)
3. `istat`에서 `Resident`인가 — 그렇다면 MFT 레코드 내부를 봐야 한다
4. `strings -el`(UTF-16LE)로도 slack을 훑었는가 — 한글 문서 잔재는 ASCII로 안 잡힌다
5. 볼륨 전체 slack을 봤는가 — `blkls -s -o N image.dd > slack.dd`
6. slack이 전부 0인가 → 새 클러스터다. 비할당 영역으로 전환 ([FOR-0033](./unallocated-space.html))
7. 파일이 NTFS 압축/sparse인가 — `istat`의 속성 플래그 확인. 단순 산수가 안 통한다
8. MFT 레코드 slack(속성 종료 표식 이후)을 봤는가
9. 디렉터리의 `$INDEX_ALLOCATION` slack도 있다 — 삭제된 파일 이름이 인덱스 slack에 남는다
10. `binwalk with_slack.bin`으로 slack 안의 완결된 파일을 확인했는가
11. 엔트로피가 높은가 — 암호화된 은닉 데이터일 수 있다. 암호를 찾는 문제로 방향 전환
12. 같은 폴더의 다른 파일 slack도 확인했는가 — 조각을 분산 저장한 경우

## 출처

- SRC-032 — The Sleuth Kit 도구 문서: `icat -s`(slack 포함 출력), `blkls -s`(slack만 추출), `istat`(속성별 resident/non-resident, `size`/`init_size`, 데이터런 클러스터 목록), `blkcat`, `fsstat`의 `Sector Size`/`Cluster Size`
- SRC-005 — Microsoft Learn, Master File Table: NTFS의 클러스터 단위 할당과 resident `$DATA`(레코드 내부 저장) 구조. 논리/물리 크기 차이의 근거
- SRC-088 — HxD 문서: 파일 열기와 디스크 열기의 차이, 오프셋 이동. 파일 핸들로는 논리 크기까지만 보이므로 slack 확인에는 볼륨 열기가 필요하다는 점
- `istat` 출력의 컬럼명(`init_size` 등)과 데이터런 표시 형식은 Sleuth Kit 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
- resident 전환 임계값(약 700바이트)은 레코드 크기와 속성 구성에 따라 달라지므로 개별 파일은 `istat`으로 확인할 것
