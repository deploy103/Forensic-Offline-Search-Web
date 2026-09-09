---
id: FOR-0041
title: "fls로 파일 목록·삭제 항목·bodyfile 뽑기"
slug: "tsk-fls"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["directory entry", "metadata address", "deleted file", "bodyfile", "$OrphanFiles", "MACB"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "fls", "mactime", "icat", "istat", "mmls", "grep", "awk", "Timeline Explorer"]
commands: ["fls -o 2048 -r -p image.dd", "fls -o 2048 -r -p -d image.dd", "fls -o 2048 -r -p -u image.dd", "fls -o 2048 -l image.dd", "fls -o 2048 -r -m / image.dd > body.txt", "fls -o 2048 -F -r -p image.dd", "fls -o 2048 -D -r -p image.dd", "fls -o 2048 -z Asia/Seoul -l image.dd", "fls -o 2048 -s -300 -l image.dd", "mactime -b body.txt -d -z UTC"]
regex_patterns: ["[0-9]+-[0-9]+-[0-9]+"]
wireshark_filters: []
tshark_fields: []
log_fields: ["file_type", "inode", "file_name", "mod_time", "acc_time", "chg_time", "cre_time", "size", "uid", "gid"]
file_formats: ["ntfs", "fat", "exfat", "ext4", "raw", "dd", "e01"]
primary_terms: ["fls", "bodyfile"]
keywords: ["fls", "Sleuth Kit", "삭제 파일 목록", "bodyfile", "mactime", "메타주소", "r/r", "realloc", "타임라인", "-m", "-d", "-p"]
aliases: ["fls", "fls 사용법", "삭제 파일 목록 뽑기", "bodyfile 만들기", "mactime 타임라인", "fls 출력 읽기", "fls -m", "이미지 파일 목록"]
symptom_keywords: ["삭제된 파일 이름을 알고 싶다", "이미지 전체 파일 목록이 필요하다", "fls 출력의 숫자가 무엇인지 모르겠다", "타임라인을 만들어야 한다", "fls 결과가 루트만 나온다", "별표가 붙은 항목이 뭔지 모르겠다"]
related: ["FOR-0040", "FOR-0042", "FOR-0021"]
source_ids: ["SRC-032", "SRC-005"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`fls -o <오프셋> -r -p image.dd`는 이미지 전체의 파일 목록을 삭제 항목까지 포함해 한 번에 쏟아내며, 각 줄의 `r/r 9134-128-1:` 부분이 **다음 명령(`icat`, `istat`)에 그대로 넣는 메타주소**다.

## 어떤 문제에서 필요한가

- 이미지에 무슨 파일이 있었는지 전체 목록이 필요한 경우
- **삭제된 파일의 이름·경로**를 찾아야 하는 경우 (`-d`)
- 추출할 파일의 메타주소를 알아내야 하는 경우 → `icat`로 이어진다 ([FOR-0042](./tsk-icat.html))
- `$MFT` 파서를 못 쓰는 환경(리눅스만 있음)에서 파일시스템 타임라인을 만들어야 하는 경우 (`-m` → `mactime`)
- Autopsy의 파일 개수·삭제 파일 개수를 CLI로 교차검증하는 경우

## 문제에서 처음 볼 단서

1. `mmls`로 오프셋이 확정되었다 → 바로 `fls`로 넘어간다 ([FOR-0040](./tsk-mmls.html))
2. 지문이 "삭제된 ~ 파일"을 언급 → `-d`
3. 지문이 "언제 무슨 일이 있었나"를 요구 → `-m`으로 bodyfile → `mactime`
4. 출력의 이름 앞에 `*`가 있다 → **삭제된 항목**
5. 출력 줄 끝에 `(realloc)` → 메타데이터가 다른 파일에 재할당되었다. 이름은 남았지만 내용은 신뢰할 수 없다

## 30초 절차

```bash
fls -o 2048 -r -p image.dd
```

```bash
fls -o 2048 -r -p -d image.dd        # 삭제 항목만
fls -o 2048 -r -p -u image.dd        # 살아 있는 항목만
fls -o 2048 -l image.dd              # 루트 디렉터리 상세(시각 포함)
fls -o 2048 -r -m / image.dd > body.txt   # bodyfile
mactime -b body.txt -d -z UTC > timeline.csv
```

목록이 크면 파일로 받고 `grep`으로 좁힌다. **화면에 흘려보내지 않는다.**

```bash
fls -o 2048 -r -p image.dd > files.txt
grep -iE '\.(docx|xlsx|pdf|zip|txt)$' files.txt
```

## 상세 절차

### 1단계 — 옵션 전체

| 옵션 | 의미 | 실전 용도 |
| --- | --- | --- |
| `-o offset` | 파일시스템이 시작하는 **섹터** 오프셋 | `mmls`의 `Start` 값 |
| `-r` | 디렉터리로 **재귀** | 없으면 지정 디렉터리 한 단계만 나온다 |
| `-p` | **전체 경로** 출력 | 없으면 재귀 깊이를 `+` 기호로만 표시해 경로를 알 수 없다 |
| `-d` | **삭제된 항목만** | 삭제 파일 사냥의 기본 |
| `-u` | 삭제되지 않은 항목만 | 정상 파일 목록만 필요할 때 |
| `-l` | **상세(long) 형식** — 시각·크기·UID/GID 포함 | 시각을 눈으로 확인할 때 |
| `-m mnt` | **bodyfile(mactime 입력) 형식**으로 출력, `mnt`를 경로 앞에 붙인다 | 타임라인 생성 |
| `-F` | 디렉터리가 아닌 항목(파일)만 | 목록 정리 |
| `-D` | 디렉터리만 | 구조 파악 |
| `-a` | `.` 과 `..` 항목도 표시 (기본은 숨김) | 디렉터리 색인 이상 확인 |
| `-z zone` | 원본 시스템의 시간대 문자열 | `-l` / `-m` 출력에만 영향 |
| `-s seconds` | 원본 시스템의 시간 스큐(초) | `-l` / `-m`이 주어진 경우에만 적용 |
| `-f fstype` | 파일시스템 타입 강제. `-f list`로 목록 | 자동탐지 실패 시 |
| `-i imgtype` | 이미지 형식 강제. `-i list`로 목록 | E01/split |
| `-b size` | 하부 장치 섹터 크기 | 4Kn = `4096` |
| `-v` / `-V` | 디버그 출력 / 버전 | 진단 |

마지막 인자로 **inode(메타주소)를 주면 그 디렉터리만** 나열한다.

```bash
fls -o 2048 image.dd 5        # NTFS 루트 (레코드 5)
fls -o 2048 image.dd 2        # ext 계열 루트 (inode 2)
fls -o 2048 -r -p image.dd 9134   # 특정 디렉터리 이하만 재귀
```

**목표 디렉터리를 알면 전체 재귀보다 이 방법이 몇 배 빠르다.**

### 2단계 — 기본 출력 형식 읽기

```text
$ fls -o 2048 -r -p image.dd
d/d 9101-144-5:  Users
d/d 9110-144-5:  Users/kim
r/r 9134-128-1:  Users/kim/Documents/report.docx
r/r 9134-128-5:  Users/kim/Documents/report.docx:hidden
-/r * 9188-128-1: Users/kim/Documents/passwords.txt
r/- * 9201-128-1: Users/kim/Desktop/tmp.bin (realloc)
d/d 11-144-5:    $OrphanFiles
```

한 줄의 구조는 이렇다.

```text
r/r  *  9134-128-1:  <탭>  Users/kim/Documents/report.docx
 |   |   |   |  |
 |   |   |   |  +--- 속성 ID
 |   |   |   +------ 속성 타입 (128 = 0x80 = $DATA, 144 = 0x90 = $INDEX_ROOT)
 |   |   +---------- 메타주소 (NTFS 라면 MFT 엔트리 번호)
 |   +-------------- '*' 가 있으면 삭제됨
 +------------------ 파일 타입: 디렉터리 엔트리 / 메타데이터
```

| 필드 | 의미 |
| --- | --- |
| 앞 문자(`r/`) | **디렉터리 엔트리**가 주장하는 타입 |
| 뒤 문자(`/r`) | **메타데이터(MFT 레코드/inode)** 가 주장하는 타입 |
| `*` | 삭제된 항목 |
| `9134` | 메타주소. `icat`/`istat`에 넣는 값 |
| `-128-1` | 속성 타입-ID. 같은 파일의 여러 스트림을 구분한다 |
| `(realloc)` | 그 메타데이터가 이미 다른 파일에 재할당되었다 |

파일 타입 문자:

| 문자 | 의미 |
| --- | --- |
| `r` | 일반 파일 |
| `d` | 디렉터리 |
| `l` | 심볼릭 링크 |
| `c` / `b` | 문자 / 블록 장치 |
| `p` | 이름 있는 파이프(FIFO) |
| `s` | 소켓 |
| `v` | TSK 가상 파일 (`$OrphanFiles` 등) |
| `-` | 알 수 없음 / 메타데이터가 비어 있음 |

**앞뒤 문자가 다르면(`-/r`, `r/-`, `d/r`) 그 자체가 신호다.**

| 형태 | 해석 |
| --- | --- |
| `r/r` | 정상 |
| `-/r` | 디렉터리 엔트리는 지워졌고 메타데이터만 남았다 → 삭제 파일 |
| `r/-` | 이름은 남았고 메타데이터가 비었거나 재할당되었다 → 내용 복구 기대치 낮음 |
| `d/r` | 엔트리는 디렉터리라 하는데 레코드는 파일 → **레코드가 재사용되었다** |

`9134-128-1`과 `9134-128-5`처럼 **메타주소가 같고 속성 ID만 다른 두 줄**은 같은 파일의 다른 데이터 스트림이다. 이름에 `:hidden`이 붙은 쪽이 ADS다 ([FOR-0042](./tsk-icat.html)).

### 3단계 — `-l` 상세 형식

`-l`을 주면 컬럼이 다음 순서로 나온다.

```text
file_type  inode  file_name  mod_time  acc_time  chg_time  cre_time  size  uid  gid
```

```text
$ fls -o 2048 -l -z Asia/Seoul image.dd 9110
r/r 9134-128-1: report.docx  2026-03-14 16:22:41 (KST) 2026-03-14 16:22:41 (KST) 2026-03-14 16:22:41 (KST) 2026-03-11 09:03:12 (KST) 24680  0  0
```

| 컬럼 | NTFS에서의 의미 |
| --- | --- |
| `mod_time` | 내용 수정 (M) |
| `acc_time` | 접근 (A) — Win7+ 기본 갱신 비활성이 많다 |
| `chg_time` | **MFT 엔트리 변경 (C)** — 조작하기 가장 어려운 값 |
| `cre_time` | 생성 (B) |
| `size` | 논리 크기 |
| `uid` / `gid` | NTFS에서는 대개 0 |

**`fls`가 보여주는 NTFS 시각은 TSK 메타데이터 시각($STANDARD_INFORMATION 계열)이다.** `$FILE_NAME` 세트와의 비교(timestomp 탐지)는 `$MFT`를 꺼내 전용 파서로 봐야 한다 ([FOR-0021](./mft-basics.html)).

### 4단계 — `-z` 시간대와 `-s` 스큐

```bash
fls -o 2048 -l -z UTC image.dd 9110          # UTC 로 표시 (기본 판단 기준)
fls -o 2048 -l -z Asia/Seoul image.dd 9110   # KST 로 표시
fls -o 2048 -l -s -300 image.dd 9110         # 원본 시계가 300초 느렸다면 -300
```

| 주의 | 내용 |
| --- | --- |
| `-z` 값의 문법 | 시스템(OS) 의존이다. `-z` 없이 돌려 기본값을 확인하고, 필요하면 `TZ` 환경변수로도 검증한다 |
| POSIX TZ 부호 | `GMT+9` 형태는 POSIX 문법에서 **UTC-9**를 뜻한다. KST는 `Asia/Seoul`을 쓴다 |
| `-s` 적용 조건 | `-l` 또는 `-m`이 있을 때만 반영된다 |
| 최종 답 | UTC로 뽑아 두고 필요할 때 `+9시간` 해서 KST로 바꾸는 편이 안전하다 |

NTFS 타임스탬프의 원본은 FILETIME(1601-01-01 UTC 기준 100ns)이고 Unix 시각과의 차이는 `11644473600`초다. bodyfile은 **Unix 초**로 저장된다.

### 5단계 — bodyfile과 mactime 타임라인

```bash
# 1) bodyfile 생성 — 마운트 지점 문자열을 경로 앞에 붙인다
fls -o 2048 -r -m /C: image.dd > body.txt

# 2) 시간순 타임라인
mactime -b body.txt -d -z UTC > timeline.csv

# 3) 기간을 좁힌다
mactime -b body.txt -d -z UTC 2026-03-14 > d0314.csv
mactime -b body.txt -d -z UTC 2026-03-01..2026-03-31 > mar.csv
mactime -b body.txt -d -z UTC 2026-03-14T09:00:00..2026-03-14T18:00:00 > win.csv
```

bodyfile(TSK 3.x 이후) 컬럼 순서:

```text
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
```

```text
0|/C:/Users/kim/Documents/passwords.txt|9188-128-1|r/rrwxrwxrwx|0|0|318|1773471761|1773471761|1773471761|1773212592
```

| 필드 | 비고 |
| --- | --- |
| `MD5` | `fls`는 해시를 계산하지 않으므로 `0` 또는 0 32개다 |
| `name` | `-m`에 준 마운트 문자열 + 전체 경로. NTFS에서는 `($FILE_NAME)` 접미가 붙은 줄이 별도로 나오는 구현이 있다 — 실제 출력에서 확인할 것 |
| `inode` | `9188-128-1` 형태의 TSK 메타주소가 그대로 들어간다 → **`icat`에 복붙할 수 있다** |
| `atime`~`crtime` | **Unix 초.** 0이면 해당 시각이 없다는 뜻 |

`mactime` 주요 옵션:

| 옵션 | 의미 |
| --- | --- |
| `-b body` | 입력 bodyfile. 생략하면 표준입력 |
| `-d` | **쉼표 구분(CSV) 출력** — 스프레드시트/Timeline Explorer 로 넘길 때 |
| `-z TIME_ZONE` | 수집 시스템의 시간대. `-z list`로 사용 가능한 값 확인 |
| `-y` | 날짜를 ISO 8601 형식으로 |
| `-m` | 월을 이름 대신 숫자로 (**매뉴얼에 `-y`와 함께 쓸 수 없다고 명시**) |
| `-i day\|hour <파일>` | 일별/시간별 활동 요약 색인 파일 생성 |
| `-h` | 시간 범위·입력 소스 등 세션 헤더 출력 |
| `-p` / `-g` | passwd / group 파일을 주면 UID/GID 대신 이름 출력 |

`DATE_RANGE`는 `yyyy-mm-dd`, `yyyy-mm-dd..yyyy-mm-dd`, `yyyy-mm-ddThh:mm:ss` 형태를 받는다. **날짜를 안 주면 전 기간이 나오므로 CTF에서는 반드시 좁힌다.**

`-i`로 만든 요약은 "언제 활동이 몰렸는가"를 한눈에 보여 준다.

```bash
mactime -b body.txt -d -z UTC -i day day_index.csv > timeline.csv
sort -t, -k2 -nr day_index.csv | head      # 활동이 가장 많은 날
```

### 6단계 — 삭제 항목만 뽑아 icat으로 넘기기

```bash
# 삭제 항목만
fls -o 2048 -r -p -d image.dd > del.txt
wc -l del.txt

# 확장자로 좁힌다
grep -iE '\.(txt|docx|jpg|zip)$' del.txt

# 메타주소만 뽑는다 (NTFS: 세 토막 주소)
grep -oE '[0-9]+-[0-9]+-[0-9]+' del.txt | sort -u > addrs.txt

# 하나 추출
icat -o 2048 image.dd 9188 > passwords.txt
```

**`awk '{print $2}'`로 주소를 뽑으면 삭제 항목에서 틀린다.** `*` 때문에 컬럼이 한 칸 밀린다.

```text
r/r 9134-128-1:  path        -> $1=r/r  $2=9134-128-1:  $3=path
-/r * 9188-128-1: path       -> $1=-/r  $2=*  $3=9188-128-1:  $4=path
```

그래서 위치 기반 대신 **패턴 기반**으로 뽑는다.

```bash
# NTFS (세 토막 주소)
grep -oE '[0-9]+-[0-9]+-[0-9]+' del.txt

# ext / FAT (주소가 숫자 하나인 경우까지 포함)
sed -n 's/^.*[[:space:]]\([0-9][0-9-]*\):[[:space:]].*$/\1/p' del.txt
```

이름과 주소를 함께 유지하려면 주소·이름 구분자(탭)를 이용한다. 구현에 따라 공백일 수 있으니 `cat -A`로 한 번 확인한다.

```bash
fls -o 2048 -r -p -d image.dd | head -3 | cat -A | head -3
```

## 출력 필드 해석

| 보이는 것 | 판단 |
| --- | --- |
| `r/r 9134-128-1:` | 정상 파일. 주소 `9134`로 `icat` 가능 |
| `-/r * 9188-128-1:` | 삭제 파일. 레코드는 살아 있어 이름·시각·크기 신뢰 가능 |
| `r/- * 9201-128-1: ... (realloc)` | 레코드가 재할당됨. **내용 복구는 카빙으로** ([FOR-0045](./carving-strategy.html)) |
| `9134-128-1` 과 `9134-128-5` | 같은 파일의 두 데이터 스트림(ADS) |
| 이름에 `:` 포함 | ADS. `파일명:스트림명` |
| `$OrphanFiles` 하위 항목 | 부모 디렉터리를 잃은 파일. 삭제 흔적의 보물창고 |
| 크기가 0인데 이름이 있다 | resident 이거나 파서가 `$DATA`를 못 읽었다. `istat`으로 확인 |
| `d/d 11-144-5` | 디렉터리. 속성 타입 `144`(0x90)는 `$INDEX_ROOT` |

`-r`은 **삭제된 디렉터리 안으로는 들어가지 못한다**(매뉴얼 명시). 그 안에 있던 파일들은 TSK가 `$OrphanFiles` 가상 디렉터리에 모아 주므로, 삭제 파일을 찾을 때 `$OrphanFiles`를 반드시 확인한다.

## pivot: 다음에 볼 artifact

| fls에서 얻은 것 | 다음 목표 |
| --- | --- |
| 메타주소 | `icat -o N image.dd <주소>`로 내용 추출 ([FOR-0042](./tsk-icat.html)) |
| 메타주소 | `istat -o N image.dd <주소>`로 속성·data run·전체 시각 |
| 삭제 파일 목록 | `$UsnJrnl`로 **삭제 시각과 원래 이름** ([FOR-0027](./usnjrnl-basics.html)) |
| 파일 크기가 작은 삭제 텍스트 | `$MFT` resident 데이터로 내용 복구 ([FOR-0021](./mft-basics.html)) |
| bodyfile | `mactime` → Timeline Explorer / 스프레드시트 |
| 활동이 몰린 시각 | EVTX 로그온 이벤트와 대조 ([FOR-0083](./event-4624-logon.html)) |
| `(realloc)` 항목 | 카빙으로 전환 ([FOR-0045](./carving-strategy.html)) |
| 오프셋이 의심된다 | `fsstat`으로 재확인 ([FOR-0043](./tsk-fsstat.html)) |

## 흔한 함정

- **`-r` 없이 돌려 "파일이 없다"고 결론 내는 것.** `fls`는 기본적으로 루트 한 단계만 나열한다. → 전체 목록은 항상 `-r -p`.
- **`-p` 없이 `-r`만 쓰는 것.** 경로 없이 깊이를 `+`로만 표시해 어느 디렉터리인지 알 수 없다. → `-r`과 `-p`는 항상 붙여 쓴다.
- **`awk '{print $2}'`로 메타주소를 뽑는 것.** 삭제 항목의 `*` 때문에 컬럼이 밀려 `*`가 출력된다. → `grep -oE '[0-9]+-[0-9]+-[0-9]+'` 같은 패턴 추출을 쓴다.
- **`*`가 붙은 항목을 "복구 가능"으로 단정하는 것.** 레코드가 남은 것과 데이터 클러스터가 남은 것은 다른 문제다. `(realloc)`이면 내용은 이미 덮였을 가능성이 높다.
- **같은 메타주소의 두 줄을 중복으로 보고 하나를 버리는 것.** 속성 ID가 다르면 **다른 스트림**이다. ADS를 놓치는 대표적 경로다.
- **`$OrphanFiles`를 무시하는 것.** 삭제된 디렉터리의 자식들이 여기에 모인다. 삭제 파일 문제의 정답이 자주 여기 있다.
- **`-z`에 `GMT+9`를 넣는 것.** POSIX TZ 문법에서는 부호가 반대로 해석된다. KST는 `Asia/Seoul`을 쓰고, 확신이 없으면 UTC로 뽑아 손으로 +9한다.
- **`-s` 스큐를 주고 `-l`/`-m`을 빼는 것.** 스큐는 `-l` 또는 `-m`이 있을 때만 반영된다(매뉴얼 명시). 기본 출력에는 영향이 없다.
- **bodyfile을 `mactime` 없이 시간순으로 보려 하는 것.** bodyfile은 파일 순서이고 시간순 정렬은 `mactime`이 한다.
- **`mactime`에 날짜 범위를 주지 않는 것.** 전 기간이 나와 수십만 줄이 된다. → `yyyy-mm-dd..yyyy-mm-dd`로 좁힌다.
- **`-b`(섹터 크기)를 `mmls`에만 주고 `fls`에 안 주는 것.** 4Kn 이미지에서 같은 `-o` 값이 다른 위치를 가리킨다 ([FOR-0040](./tsk-mmls.html)).
- **`fls`의 NTFS 시각으로 timestomp를 판정하는 것.** `$SI`/`$FN` 두 세트 비교가 필요하며 그것은 `$MFT` 파서의 일이다.

## 교차검증

```bash
# 1) 전체 항목 수 vs Autopsy 의 파일 수
fls -o 2048 -r -p image.dd | wc -l

# 2) 삭제 항목 수
fls -o 2048 -r -p -d image.dd | wc -l

# 3) 특정 파일의 상세를 istat 으로 재확인 (크기·속성·data run)
istat -o 2048 image.dd 9188

# 4) 시각을 두 시간대로 각각 뽑아 대조
fls -o 2048 -l -z UTC        image.dd 9110
fls -o 2048 -l -z Asia/Seoul image.dd 9110

# 5) bodyfile 기준 타임라인 vs $MFT 파서 CSV
fls -o 2048 -r -m /C: image.dd > body.txt
mactime -b body.txt -d -z UTC 2026-03-14 | head

# 6) 이름이 같은데 주소가 다른 항목이 있는지 (레코드 재사용 흔적)
fls -o 2048 -r -p image.dd | awk -F'\t' '{print $2}' | sort | uniq -d
```

`fls`의 삭제 항목 수와 `$MFT` 파서의 `InUse=False` 개수는 보통 일치하지 않는다. `fls`는 **디렉터리 엔트리 기준**이고 `$MFT` 파서는 **레코드 기준**이기 때문이다. 차이가 크면 `$OrphanFiles`와 재할당 항목을 확인한다.

## mini walkthrough

```text
문제:
"이미지에서 삭제된 자격증명 파일의 내용과 삭제 시각을 찾으세요."
첨부: host.dd (20 GB)

1. 오프셋 확정
   $ mmls -a host.dd
   002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
   003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)
   -> 큰 쪽(206848)이 시스템 볼륨이다.

2. 첫 시도 (실패):
   $ fls -o 206848 host.dd | grep -i pass
   (출력 없음)

   "삭제된 파일이 없다"고 판단하고 카빙으로 넘어가려 했다.
   -> 틀렸다. -r 을 주지 않아 루트 디렉터리만 봤을 뿐이다.

3. 접근 변경 — 재귀 + 전체 경로 + 삭제만
   $ fls -o 206848 -r -p -d host.dd > del.txt
   $ wc -l del.txt
   1842 del.txt
   $ grep -iE 'pass|cred|secret' del.txt
   -/r * 9188-128-1:  Users/kim/Documents/passwords.txt
   r/- * 9201-128-1:  Users/kim/Desktop/tmp.bin (realloc)

   -> 목표 확정. 9188 은 -/r 이므로 레코드가 살아 있다.

4. 두 번째 실패 — 주소 추출
   $ grep -i passwords del.txt | awk '{print $2}'
   *
   -> '*' 가 컬럼을 밀었다. 위치 기반 추출이 틀린 것이다.

   $ grep -i passwords del.txt | grep -oE '[0-9]+-[0-9]+-[0-9]+'
   9188-128-1
   -> 패턴 기반으로 교체하니 정상.

5. 상세 확인 후 추출
   $ istat -o 206848 host.dd 9188 | head -20
   MFT Entry Header Values:
   Entry: 9188        Sequence: 3
   $FILE_NAME Attribute Values:
   Name: passwords.txt
   ...
   Size: 318
   Attributes:
   Type: $DATA (128-1)   Resident   size: 318

   318바이트 = resident. 내용이 레코드 안에 있으므로 추출 성공 확률이 높다.

   $ icat -o 206848 host.dd 9188 > pw.txt
   $ file pw.txt
   pw.txt: ASCII text
   $ cat pw.txt
   ...
   flag{fls_r3curs3_0r_m1ss_1t}

6. 삭제 시각 — 타임라인으로 확정
   $ fls -o 206848 -r -m /C: host.dd > body.txt
   $ mactime -b body.txt -d -z UTC 2026-03-14 | grep -i passwords
   2026-03-14 07:22:41,318,m...,r/rrwxrwxrwx,0,0,9188-128-1,/C:/Users/kim/Documents/passwords.txt

   UTC 07:22:41 -> KST 16:22:41 (+9시간)

7. 교차검증 — $UsnJrnl 로 삭제 사유 확인
   -> FILE_DELETE 레코드의 시각이 위와 일치 (FOR-0027)

정답: flag{fls_r3curs3_0r_m1ss_1t}
      삭제 시각 2026-03-14 16:22:41 (KST)
```

실패가 두 번 있었고 원인이 서로 달랐다. **2단계는 `-r` 누락(도구 사용법), 4단계는 `*`로 인한 컬럼 밀림(출력 파싱).** 둘 다 "출력이 비었다"로 보이지만 대응은 완전히 다르다.

## 막혔을 때 다음 체크

1. `-r`과 `-p`를 함께 주었는가
2. `-o` 값이 `fsstat`으로 검증된 값인가 ([FOR-0043](./tsk-fsstat.html))
3. 4Kn 이미지라면 `-b 4096`을 주었는가
4. 삭제 항목만 보려면 `-d`, 정상만 보려면 `-u`를 썼는가
5. `$OrphanFiles` 하위를 확인했는가
6. 같은 메타주소에 속성 ID가 다른 줄(ADS)이 있는지 확인했는가
7. 이름에 `:`가 포함된 항목이 있는가 → ADS
8. `(realloc)` 항목인가 → 내용은 카빙으로 ([FOR-0045](./carving-strategy.html))
9. 주소를 `awk` 위치 기반으로 뽑고 있지 않은가
10. 목표 디렉터리를 안다면 마지막 인자로 그 inode만 주어 범위를 줄였는가
11. 시각이 필요하면 `-l` 또는 `-m`을 주었는가 (`-s`는 이 둘이 있을 때만 적용)
12. `mactime`에 날짜 범위를 주었는가
13. 시간대를 UTC로 고정해 두고 최종 답만 KST로 변환했는가
14. 파일시스템 자동탐지가 실패했다면 `-f list`로 타입을 강제했는가

## 출처

- SRC-032 — The Sleuth Kit 도구 문서(fls / mactime man page): 옵션 정의, `-l` 출력 컬럼 순서(`file_type inode file_name mod_time acc_time chg_time cre_time size uid gid`), `-r`이 삭제된 디렉터리를 따라가지 못한다는 명시, `-s`가 `-l`/`-m`에서만 적용된다는 명시, `mactime`의 `DATE_RANGE` 문법과 `-m`이 `-y`와 함께 동작하지 않는다는 명시
- SRC-005 — Microsoft Learn, Master File Table: NTFS 메타주소가 MFT 엔트리 번호라는 점, 속성 타입 `0x80`($DATA) / `0x90`($INDEX_ROOT)의 의미
- bodyfile 컬럼 순서(`MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`)는 TSK 3.x 형식이다. NTFS의 `inode`/`mode_as_string` 표기와 `($FILE_NAME)` 접미 여부는 구현·버전에 따라 다르므로 실제 출력에서 확인할 것
- `-z`에 넣을 수 있는 시간대 문자열은 OS 의존이다. `mactime -z list`로 현장에서 확인할 것
