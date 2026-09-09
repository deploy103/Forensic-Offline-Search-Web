---
id: FOR-0046
title: "foremost로 파일 카빙하기: 옵션, foremost.conf, audit.txt"
slug: "foremost"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [linux]
artifact: ["unallocated space", "file signature", "header", "footer", "audit.txt"]
file_paths: ["/etc/foremost.conf", "./output/audit.txt"]
registry_paths: []
event_ids: []
protocols: []
tools: ["foremost", "scalpel", "Sleuth Kit", "blkls", "blkcalc", "file", "binwalk"]
commands: ["foremost -t jpg,png,pdf,zip -i image.dd -o carved", "foremost -t all -v -i image.dd -o carved", "foremost -c my.conf -i unalloc.blkls -o carved", "blkls -o 2048 image.dd > unalloc.blkls"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Num", "Name", "Size", "File Offset", "Comment"]
file_formats: ["jpg", "png", "gif", "pdf", "zip", "ole", "raw", "dd"]
primary_terms: ["foremost", "audit.txt", "foremost.conf"]
keywords: ["foremost", "카빙", "carving", "파일 복구", "시그니처", "header", "footer", "audit.txt", "foremost.conf", "비할당 영역", "unallocated"]
aliases: ["foremost", "포모스트", "카빙 툴", "foremost 사용법", "시그니처 카빙", "삭제 파일 카빙", "foremost.conf", "audit.txt"]
symptom_keywords: ["삭제된 사진을 복구하고 싶다", "카빙이 안 된다", "출력 폴더가 비어 있어야 한다고 나온다", "카빙한 파일이 깨진다", "원하는 형식이 안 나온다", "파일 이름이 숫자로만 나온다"]
related: ["FOR-0047", "FOR-0049", "FOR-0019"]
source_ids: ["SRC-035", "SRC-032", "SRC-089"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

foremost는 헤더/푸터 시그니처만 보고 파일을 잘라내는 카빙 도구이므로 `-t`로 형식을 좁히고 `-i` 입력에 **비할당 영역만 뽑은 스트림**을 주는 것이 정답이며, 결과 판정은 출력 폴더의 `audit.txt`에 적힌 `File Offset`과 `Size`로 한다.

## 어떤 문제에서 필요한가

- 파일시스템 메타데이터(`$MFT` 레코드)가 이미 사라져 `icat`으로 꺼낼 수 없는 삭제 파일
- 파티션 테이블도 파일시스템도 인식되지 않는 raw 덤프에서 사진·문서만 건져야 하는 경우
- "이미지 안에 몇 개의 JPEG가 숨어 있는가" 류의 개수/개체 확인 문제
- USB 이미지, 메모리 카드 이미지처럼 포맷 후 재사용된 매체
- 특정 매직 바이트를 가진 **커스텀 형식**을 대량으로 뽑아야 하는 경우 (`foremost.conf`)

파일시스템이 살아 있고 레코드가 남아 있다면 카빙보다 `icat`/FTK Imager 추출이 항상 우선이다 ([FOR-0049](./deleted-file-recovery-walkthrough.html)). 카빙은 그 두 개가 실패한 뒤의 수단이다.

## 문제에서 처음 볼 단서

1. `mmls`/`fsstat`이 모두 실패하는 이미지 → 파일시스템 경로가 막혔으므로 카빙
2. 지문에 "복구", "지워진 사진", "몇 개인가"가 있으면 카빙 문제일 확률이 높다
3. `strings image.dd | grep -c JFIF` 같은 사전 정찰로 형식을 미리 좁힐 수 있다
4. 이미지 크기 — 수십 GB에 `-t all`을 걸면 대회 시간 내에 끝나지 않는다
5. `binwalk image.dd`의 시그니처 목록 — 어떤 `-t`를 줄지 결정하는 가장 빠른 근거

## 30초 절차

```bash
foremost -t jpg,png,pdf,zip -i image.dd -o carved
```

```bash
# 결과 요약은 audit.txt 한 파일에 다 있다
cat carved/audit.txt
ls -R carved/ | head -40
file carved/jpg/* | head
```

출력 폴더는 **없거나 비어 있어야 한다.** 이미 파일이 있으면 foremost는 실행을 거부하고 종료한다. 재실행할 때는 폴더 이름을 바꾸거나 `-T`를 쓴다.

```bash
foremost -T -t jpg -i image.dd -o carved     # carved 뒤에 타임스탬프를 붙인 새 폴더 생성
```

## 상세 절차

### 1단계 — 옵션 표

| 옵션 | 의미 | 실전 용도 |
| --- | --- | --- |
| `-t <타입>` | 카빙할 형식 목록. 쉼표로 여러 개 (`-t jpg,pdf,zip`) | **거의 항상 지정한다.** 좁히면 빨라지고 오탐이 줄어든다 |
| `-i <파일>` | 입력 파일. 생략하면 stdin | 이미지, 볼륨 덤프, `blkls` 출력, 메모리 덤프 |
| `-o <폴더>` | 출력 폴더 | **비어 있어야 한다.** 없으면 만들어 준다 |
| `-c <파일>` | 설정 파일 지정 | 커스텀 시그니처를 쓸 때 (5단계) |
| `-v` | verbose. 진행 상황과 찾은 파일을 화면에 출력 | 오래 걸리는 작업의 생존 확인용 |
| `-q` | quick 모드. 블록 경계에서만 헤더를 찾는다 | 속도 우선. **경계에 정렬되지 않은 파일을 놓친다** |
| `-b <숫자>` | 블록 크기(기본 512). 파일 이름 번호와 `-q`의 경계 기준 | 클러스터가 4096이면 `-b 4096` |
| `-a` | 헤더만 보고 무조건 쓴다. 오류 검사를 하지 않는다 | 푸터가 깨진 파일이라도 일단 건져야 할 때 |
| `-w` | audit 파일만 쓰고 파일은 추출하지 않는다 | "몇 개 있는가"만 세는 정찰용 |
| `-T` | 출력 폴더 이름에 타임스탬프를 붙인다 | 같은 이미지를 옵션 바꿔 여러 번 돌릴 때 |
| `-s <숫자>` | 입력의 앞쪽 n바이트를 건너뛰고 시작 | 파티션 시작 바이트 오프셋을 직접 줄 때 |
| `-d` | 간접 블록 탐지 (UNIX 계열 파일시스템용) | ext 이미지에서 시도해 볼 값 |
| `-Q` | quiet. 화면 출력 억제 | 스크립트에서 |
| `-V` | 버전/저작권 출력 | 버전 확인 |

가장 많이 쓰는 조합 세 개:

```bash
# 1) 개수만 먼저 센다 (파일을 쓰지 않으므로 빠르고 디스크를 안 먹는다)
foremost -w -t all -i image.dd -o count_only

# 2) 형식을 좁혀 실제 추출
foremost -v -t jpg,png,gif,pdf,doc,zip -i image.dd -o carved

# 3) 깨진 파일까지 강제로 건진다
foremost -a -t jpg -i image.dd -o carved_all
```

### 2단계 — 지원 타입과 `-t all`

`-t`에 넣을 수 있는 타입은 배포본에 내장된 목록과 설정 파일에 정의된 확장자다. 내장 목록은 대략 다음과 같다.

| 타입 | 포함되는 실제 형식 | 비고 |
| --- | --- | --- |
| `jpg` | JPEG/JFIF/EXIF | 헤더 `FF D8 FF`, 푸터 `FF D9` |
| `gif` | GIF87a / GIF89a | 푸터 `00 3B` |
| `png` | PNG | 푸터 `IEND` + CRC |
| `bmp` | BMP | 푸터 없음 → 크기 추정 |
| `pdf` | PDF | 푸터 `%%EOF`, 여러 개 있을 수 있다 |
| `ole` | `doc` `xls` `ppt` 등 구형 Office 복합 문서 | 헤더 `D0 CF 11 E0 A1 B1 1A E1` |
| `doc` | Word 문서 | `ole`와 중복 탐지될 수 있다 |
| `zip` | ZIP 및 그 파생(`docx` `xlsx` `pptx` `jar` `apk`) | **확장자가 `.zip`으로 나온다.** 내부를 봐야 진짜 형식을 안다 |
| `rar` | RAR | — |
| `htm` | HTML | 텍스트라 오탐이 많다 |
| `cpp` | C/C++ 소스 | 텍스트라 오탐이 매우 많다 |
| `avi` `mov` `mpg` `wmv` `wav` `riff` | 미디어 컨테이너 | 크기가 커서 최대 크기 제한에 걸리기 쉽다 |
| `exe` | PE 실행 파일 | 헤더 `MZ`. 오탐이 많다 |
| `all` | 위 전부 | **느리고 오탐 폭증.** 정찰 단계에서만 |

`-t all`은 "무엇이 있는지 모를 때 딱 한 번" 쓰는 옵션이다. 수 GB 이미지에서는 `-w`와 함께 써서 개수만 세고, 실제 추출은 형식을 좁혀 다시 돌린다.

```bash
foremost -w -t all -i image.dd -o probe
tail -20 probe/audit.txt        # 형식별 개수 요약이 맨 끝에 있다
```

### 3단계 — 출력 폴더 구조

```text
carved/
├── audit.txt          <- 전체 결과 요약 (가장 먼저 읽는다)
├── jpg/
│   ├── 00000123.jpg
│   ├── 00000456.jpg
│   └── ...
├── pdf/
│   └── 00028811.pdf
└── zip/
    └── 00031002.zip
```

- 타입별 하위 폴더가 만들어지고, **찾은 것이 없으면 폴더도 생기지 않는다**
- 파일 이름의 숫자는 **블록 번호**다. `블록 번호 × 블록 크기(-b, 기본 512) = 입력 파일 안의 바이트 오프셋`
  - `00000123.jpg` → `123 × 512 = 62,976` 바이트 지점에서 시작
- 원래 파일 이름·경로·타임스탬프는 **복구되지 않는다.** 카빙은 파일시스템 메타데이터를 보지 않기 때문이다

이름에서 오프셋을 되짚는 것이 실전에서 중요하다. HxD나 `xxd`로 그 지점을 직접 열어 헤더 앞에 무엇이 있는지 보면 어떤 파일 안에 박혀 있던 조각인지 알 수 있다.

```bash
xxd -s $((123*512)) -l 64 image.dd
```

### 4단계 — audit.txt 해석

```text
Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
Audit File

Foremost started at Thu Sep 10 09:12:44 2026
Invocation: foremost -v -t jpg,pdf,zip -i image.dd -o carved
Output directory: /cases/carved
Configuration file: /etc/foremost.conf
------------------------------------------------------------------
File: image.dd
Start: Thu Sep 10 09:12:44 2026
Length: 2 GB (2147483648 bytes)

Num      Name (bs=512)       Size      File Offset     Comment

0:      00000123.jpg        102 KB           62976
1:      00000456.pdf         45 KB          233472
2:      00031002.zip        1 MB          15873024
3:      00042110.jpg        200 MB       21560320      (JPEG at max size)

Finish: Thu Sep 10 09:19:02 2026

4 FILES EXTRACTED

jpg:= 2
pdf:= 1
zip:= 1
------------------------------------------------------------------

Foremost finished at Thu Sep 10 09:19:02 2026
```

| 항목 | 의미 | 판정에 쓰는 법 |
| --- | --- | --- |
| `Invocation` | 실제로 실행된 명령줄 | 재현성 확보. 어떤 `-t`로 뽑은 결과인지 증명 |
| `Configuration file` | 어느 conf가 적용됐나 | `-c`가 먹었는지 확인 |
| `Length` | 입력 크기 | 이미지가 잘렸는지 판단 |
| `Num` | 순번 | — |
| `Name (bs=512)` | 파일 이름과 **적용된 블록 크기** | `-b`가 반영됐는지 확인 |
| `Size` | 잘라낸 크기 | **최대 크기와 같으면 푸터를 못 찾고 잘린 것** |
| `File Offset` | 입력 파일 내 바이트 오프셋 | `블록 번호 × bs`와 일치해야 정상 |
| `Comment` | 경고 | `at max size` 등이 여기 붙는다 |
| 맨 끝 `jpg:= 2` | 형식별 개수 | 문제의 "몇 개" 답 |

`Size`가 `-t` 형식의 최대 크기와 정확히 같은 항목은 **거의 확실히 잘린 파일**이다. 위 예시의 `00042110.jpg` 200 MB는 정상 사진이 아니라 "푸터를 못 찾아 한계까지 긁어온 쓰레기"다.

**시간 주의.** `Foremost started at` / `Finish`는 **분석 호스트의 로컬 시각**이며 증거의 시각이 아니다. 카빙된 파일의 mtime도 추출 시각으로 찍히므로 타임라인에 절대 넣지 않는다. 증거 시각은 파일 내부 메타데이터(EXIF `DateTimeOriginal`, Office `core.xml`)에서만 얻는다. 그 값들이 UTC인지 로컬인지도 형식별로 다르므로 KST 환산 전에 확인한다.

### 5단계 — foremost.conf로 커스텀 시그니처 추가

설정 파일은 `-c`로 지정하고, 없으면 현재 폴더의 `foremost.conf`, 그다음 `/etc/foremost.conf`가 쓰인다. 한 줄이 시그니처 하나다.

```text
# extension   case   max_size    header                  footer
```

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| `extension` | 출력 파일의 확장자 겸 하위 폴더 이름 | 소문자 영숫자 |
| `case` | 헤더/푸터의 대소문자 구분 (`y`/`n`) | 바이너리 시그니처는 `y` |
| `max_size` | 최대 크기(바이트) | 푸터를 못 찾으면 여기까지 잘라온다 |
| `header` | 시작 시그니처 | `\x` 16진 이스케이프 사용 |
| `footer` | 끝 시그니처 (**생략 가능**) | 비우면 항상 `max_size`까지 |

필드 구분은 공백/탭이고, 주석은 `#`이다. 실제 예시:

```text
# EVTX (Windows Event Log)
	evtx	y	20971520	\x45\x6c\x66\x46\x69\x6c\x65\x00

# SQLite 3 데이터베이스
	sqlite	y	104857600	\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00

# Registry hive (regf)
	regf	y	104857600	\x72\x65\x67\x66

# 7-Zip
	7z	y	524288000	\x37\x7a\xbc\xaf\x27\x1c

# ZIP (헤더/푸터 모두 지정 — EOCD 를 푸터로)
	zip	y	104857600	\x50\x4b\x03\x04	\x50\x4b\x05\x06

# PDF
	pdf	y	20971520	\x25\x50\x44\x46	\x25\x25\x45\x4f\x46
```

시그니처 값 자체는 매직 바이트 대조표로 확정한다(SRC-089). 만들었으면 **반드시 자기 시그니처가 먹는지 먼저 검증한다.**

```bash
# 1) 알려진 정상 파일 하나로 conf를 시험한다
foremost -c my.conf -t evtx -i known.evtx -o /tmp/conftest
cat /tmp/conftest/audit.txt   # 1개가 잡히면 conf가 정상

# 2) 그다음 실제 이미지에 적용
foremost -c my.conf -t evtx,sqlite,regf -i image.dd -o carved
```

`-t`에 conf에서 정의한 확장자를 그대로 넣어야 그 규칙이 활성된다. conf에 줄만 추가하고 `-t jpg`로 돌리면 그 규칙은 무시된다.

푸터 탐색 방향이나 푸터 포함 여부를 바꾸는 추가 키워드가 배포본 `foremost.conf` 주석에 설명되어 있고, 헤더에 임의 1바이트를 뜻하는 와일드카드도 쓸 수 있다고 알려져 있다. 값을 쓰기 전에 **자기 배포본의 `/etc/foremost.conf` 주석을 직접 읽어 확인한다.**

### 6단계 — 비할당 영역만 카빙하기 (핵심 기법)

이미지 전체를 카빙하면 **살아 있는 파일까지 전부 다시 뽑혀** 결과가 수천 개가 된다. 삭제된 것만 원하면 `blkls`로 비할당 블록만 뽑아 그 스트림을 카빙한다.

```bash
# 1) 파티션 오프셋 확인 (섹터 단위)
mmls image.dd

# 2) 비할당 블록만 하나의 스트림으로 (blkls 기본 동작이 비할당만 출력)
blkls -o 2048 image.dd > unalloc.blkls

# 3) 그 스트림을 카빙
foremost -t jpg,png,pdf,zip -i unalloc.blkls -o carved_unalloc
```

| 명령 | 대상 |
| --- | --- |
| `blkls -o 2048 image.dd` | **비할당 블록만** (기본 동작) |
| `blkls -e -o 2048 image.dd` | 모든 블록 |
| `blkls -s -o 2048 image.dd` | **슬랙 공간만** — 파일 끝과 클러스터 끝 사이 |
| `blkls -a -o 2048 image.dd` | 할당된 블록만 |

`blkls -o`는 **섹터 단위**다. 바이트를 넣으면 조용히 엉뚱한 곳을 읽는다 ([FOR-0048](./partition-offset-problems.html)).

**중요한 함정:** `audit.txt`의 `File Offset`은 `unalloc.blkls` 안의 오프셋이고 **원본 이미지의 오프셋이 아니다.** 원본 위치가 필요하면 `blkcalc`로 되돌린다.

```bash
# blkls 스트림의 단위 번호 -> 원본 이미지의 블록 번호
blkcalc -o 2048 -u 12345 image.dd
```

단위 번호는 `File Offset ÷ 클러스터 크기`로 구한다(클러스터 크기는 `fsstat -o 2048 image.dd`의 `Cluster Size`). 단위 번호의 시작값(0 또는 1)이 버전에 따라 다를 수 있으므로 결과가 어긋나면 ±1을 시도한다.

슬랙만 노리는 문제도 실재한다.

```bash
blkls -s -o 2048 image.dd > slack.raw
strings -n 8 slack.raw | grep -i 'flag{'
```

### 7단계 — foremost의 한계 (반드시 알아야 할 것)

| 한계 | 왜 그런가 | 대안 |
| --- | --- | --- |
| **조각화(fragmented) 파일 복구 불가** | 헤더부터 연속된 바이트만 잘라낸다. 중간에 다른 파일이 끼면 그 데이터까지 포함된 깨진 파일이 나온다 | PhotoRec의 brute force 모드 ([FOR-0047](./photorec.html)), 또는 `$MFT` 런리스트로 `icat` |
| **푸터 없는 형식은 최대 크기까지 긁어온다** | conf에 푸터가 없으면 끝을 알 수 없다 | conf의 `max_size`를 현실적으로 줄인다. 뒤쪽 쓰레기는 수동 절단 |
| 원래 파일 이름/경로/타임스탬프 없음 | 파일시스템을 보지 않는다 | `$MFT`/`$UsnJrnl`과 이름을 대조 ([FOR-0027](./usnjrnl-basics.html)) |
| 헤더가 오프셋 0이 아닌 형식 지원 곤란 | 규칙이 "헤더로 시작"을 가정한다 (Prefetch는 `SCCA`가 오프셋 4) | 전용 파서, 또는 `grep -abo`로 위치를 찾아 `dd`로 직접 절단 |
| 압축/암호화된 영역 안의 파일 | 시그니처가 압축되어 사라진다 | 컨테이너를 먼저 풀고 다시 카빙 |
| 텍스트 형식 오탐 폭증 | `htm`/`cpp`는 시그니처가 사실상 없다 | 텍스트는 카빙 대신 `strings` + regex |
| 중복 결과 | `ole`와 `doc`, `zip`과 `docx`가 같은 바이트를 두 번 잡는다 | 해시로 중복 제거 |

```bash
# 중복 제거: 같은 내용이 여러 폴더에 뽑힌 경우
find carved -type f -exec md5sum {} + | sort | uniq -w32 -d
```

## 출력 필드 해석

카빙 직후 반드시 돌리는 3종 검증이다.

```bash
# 1) 진짜 그 형식인가 (확장자는 foremost가 붙인 추측이다)
file carved/*/* | sort | uniq -c | sort -nr

# 2) 크기 0 또는 최대 크기 = 실패 후보
find carved -type f -size 0
find carved -type f -size +100M -ls

# 3) 내용 확인
strings -n 8 carved/zip/00031002.zip | head
exiftool carved/jpg/*.jpg | grep -i 'date\|gps' | head
```

| 관찰 | 해석 | 조치 |
| --- | --- | --- |
| `file`이 `data`라고 답한다 | 헤더만 맞고 내용이 깨졌다 | 오프셋 지점을 hex로 직접 확인 |
| `Size`가 최대 크기와 동일 | 푸터 미발견 | conf의 `max_size` 조정, 또는 수동 절단 |
| `.zip`인데 `file`이 `Microsoft Word 2007+` | 정상. ZIP 기반 OOXML | 확장자를 `.docx`로 바꿔 열기 |
| JPEG인데 이미지 뷰어에서 위쪽만 보인다 | 조각화되어 뒷부분이 다른 파일 | PhotoRec brute force 또는 `$MFT` 경로 |
| 같은 사진이 수십 개 | 썸네일 캐시/브라우저 캐시가 함께 잡혔다 | 정상. 해시로 묶는다 |
| 개수가 0 | `-t` 지정이 잘못됐거나 conf가 안 먹었다 | `audit.txt`의 `Invocation`/`Configuration file` 확인 |

## pivot: 다음에 볼 artifact

| 카빙으로 얻은 것 | 다음 목표 |
| --- | --- |
| JPEG/PNG 다수 | `exiftool`로 EXIF·GPS·`DateTimeOriginal` |
| `File Offset` 값 | `blkcalc`로 원본 블록 → `ifind`/`$MFT`로 어떤 파일이었는지 |
| ZIP 계열 | 압축 해제 후 `docProps/core.xml`의 작성자·시각 |
| 실행 파일 | 해시 → Prefetch/Amcache 대조로 실행 여부 |
| 파일 이름이 필요할 때 | `$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html))에서 같은 시간대의 `FileDelete` |
| 카빙이 실패한 형식 | PhotoRec으로 재시도 ([FOR-0047](./photorec.html)) |
| 이미지 전체 정찰 | Autopsy의 카빙 모듈로 교차 ([FOR-0018](./autopsy-ingest.html)) |
| 파티션을 못 찾아 카빙했다 | 오프셋 문제였는지 재확인 ([FOR-0048](./partition-offset-problems.html)) |

## 흔한 함정

- **출력 폴더를 재사용하는 것.** 비어 있지 않으면 foremost는 아무 일도 하지 않고 끝난다. 실패를 성공으로 오해해 "결과가 0개"라고 결론 내리는 사고가 잦다. `-T`를 쓰거나 폴더를 새로 만든다.
- **`-t`를 생략하는 것.** 기본 동작이 원하는 형식을 커버한다고 가정하면 결과가 비어 나온다. 형식은 항상 명시한다.
- **`-t all`로 대용량 이미지를 도는 것.** 수십 GB에 `all`을 걸면 시간과 디스크를 모두 잃는다. `-w`로 개수만 먼저 센다.
- **이미지 전체를 카빙하는 것.** 살아 있는 파일까지 다시 뽑혀 결과가 수천 개가 된다. `blkls`로 비할당만 걸러서 넣는다.
- **`blkls`의 `-o`에 바이트를 넣는 것.** `-o`는 섹터다. 바이트를 넣으면 에러 없이 엉뚱한 데이터가 카빙된다.
- **`audit.txt`의 `File Offset`을 원본 이미지 오프셋으로 착각하는 것.** `blkls` 스트림을 입력으로 줬다면 그 스트림 내부 오프셋이다. `blkcalc`로 환산해야 원본 위치가 된다.
- **`Size`가 최대 크기인 파일을 정상으로 취급하는 것.** 푸터를 못 찾아 잘린 쓰레기다. 열어 보고 판단한다.
- **`-q`를 습관적으로 쓰는 것.** 블록 경계에 정렬되지 않은 파일(다른 파일 안에 박힌 이미지, 압축 스트림 내부)을 전부 놓친다. 결과가 적으면 `-q` 없이 다시 돌린다.
- **`-b`를 클러스터 크기와 맞추지 않는 것.** 클러스터가 4096인데 기본 512로 두면 `-q` 모드의 경계 판정과 파일 이름 번호가 어긋난다.
- **카빙 파일의 mtime을 증거 시각으로 쓰는 것.** 그것은 추출 시각이다. 시각은 파일 내부 메타데이터에서만 얻는다.
- **`.zip`으로 나온 파일을 ZIP으로만 보는 것.** `docx`/`xlsx`/`apk`/`jar`가 모두 ZIP 헤더다. 내부를 열어 확인한다.
- **conf에 줄을 추가하고 `-t`에 그 확장자를 안 넣는 것.** 규칙이 활성되지 않는다. `audit.txt`의 `Configuration file` 줄로 어느 conf가 적용됐는지 확인한다.

## 교차검증

```bash
# 1) 개수 정찰 (파일을 쓰지 않는다)
foremost -w -t all -i image.dd -o probe && tail -20 probe/audit.txt

# 2) 시그니처를 직접 세어 foremost 결과와 대조
grep -abo $'\xff\xd8\xff' image.dd | wc -l          # JPEG 헤더 개수
grep -abo '%PDF' image.dd | wc -l                   # PDF 헤더 개수
grep -abo 'PK'$'\x03\x04' image.dd | wc -l          # ZIP local file header

# 3) binwalk 로 같은 이미지를 스캔 (다른 시그니처 DB)
binwalk image.dd | head -40

# 4) 파일시스템 경로가 살아 있다면 그쪽이 정답
fls -o 2048 -r -d -p image.dd | head -40            # -d = 삭제된 항목만

# 5) 카빙물 형식 재판정
file carved/*/* | awk -F: '{print $2}' | sort | uniq -c | sort -nr
```

`grep -abo`로 센 헤더 개수보다 foremost 결과가 훨씬 적으면 `-q`가 켜져 있거나 `-t`가 그 형식을 포함하지 않은 것이다. 반대로 훨씬 많으면 오탐이다.

## mini walkthrough

```text
문제:
"포맷된 USB 이미지입니다. 삭제된 사진 중 flag가 적힌 것을 찾으세요."
첨부: usb.dd (4 GB)

1. 판을 읽는다
   $ mmls usb.dd
   DOS Partition Table / Units are in 512-byte sectors
   002:  000:000   0000002048   0008388607   0008386560   FAT32 (0x0C)

   $ fsstat -o 2048 usb.dd | grep -i 'cluster size\|file system type'
   File System Type: FAT32
   Cluster Size: 4096

2. 첫 시도 (실패):
   $ foremost -t all -i usb.dd -o carved
   ... 12분 후
   $ tail -8 carved/audit.txt
   4812 FILES EXTRACTED
   jpg:= 3944
   htm:= 611
   cpp:= 208
   ...

   4,812개. 사람이 볼 수 없는 양이다.
   원인 두 가지:
     (a) -t all 이 htm/cpp 같은 텍스트 오탐을 대량 생산했다
     (b) 이미지 전체를 돌려서 "살아 있는 파일"까지 다시 뽑았다
   지문은 "삭제된" 사진이다. 살아 있는 파일은 애초에 답이 아니다.

3. 접근 변경 — 비할당 영역만, 형식은 jpg/png 로 좁힌다
   $ blkls -o 2048 usb.dd > unalloc.blkls
   $ ls -l unalloc.blkls
   -rw-r--r-- 1 user user 2113929216 unalloc.blkls      (약 2 GB)

   $ foremost -v -t jpg,png -i unalloc.blkls -o carved2
   $ tail -6 carved2/audit.txt
   38 FILES EXTRACTED
   jpg:= 35
   png:= 3

   38개. 다룰 수 있는 양이다.

4. 두 번째 시도 (부분 실패):
   $ file carved2/jpg/* | grep -c JPEG
   35
   $ eog carved2/jpg/*.jpg
   -> 대부분 정상. 그런데 flag 문자열이 어디에도 없다.

   $ strings carved2/*/* | grep -i 'flag{'
   (출력 없음)

   막혔다. 여기서 audit.txt 를 다시 읽는다.

   $ grep 'max size' carved2/audit.txt
   12:     00204800.jpg     20 MB    104857600    (JPEG at max size)

   1개가 최대 크기까지 잘려 있다. 즉 푸터(FF D9)를 못 찾은 파일이다.
   조각화되었거나, 뒤에 다른 데이터가 붙어 있다는 뜻이다.

5. 그 오프셋을 직접 본다
   블록 번호 204800, bs=512 -> 오프셋 104,857,600

   $ xxd -s 104857600 -l 32 unalloc.blkls
   06400000: ffd8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
   06400010: 0001 0000 ffe1 1a2b 4578 6966 0000 4d4d  .......+Exif..MM

   헤더는 정상 JPEG. 그러면 푸터가 왜 없나.

   $ xxd -s 104857600 -l 4000 unalloc.blkls | grep -n 'ffd9' | head -3
   (없음)

   $ strings -n 6 carved2/jpg/00204800.jpg | head -20
   JFIF
   Exif
   MM
   flag{c4rv3d_fr0m_un4ll0c4t3d_sp4c3}      <- 여기 있다

   EXIF 코멘트 안에 flag 가 들어 있었다.
   4단계의 strings 가 실패한 이유: -n 기본값과 파이프 조합에서
   바이너리 파일 여러 개를 한 번에 넘겨 결과가 묻혔다.
   파일을 하나씩 봤어야 했다.

6. 검증
   $ exiftool carved2/jpg/00204800.jpg | grep -i comment
   Comment                         : flag{c4rv3d_fr0m_un4ll0c4t3d_sp4c3}

   $ md5sum carved2/jpg/00204800.jpg
   (문제에 기준 해시가 있으면 대조. 없으면 헤더/푸터와 열림 여부로 판정)

7. 원래 파일이 무엇이었는지 (보너스)
   블록 번호를 원본 이미지 좌표로 환산
   단위 번호 = 104857600 / 4096 = 25600
   $ blkcalc -o 2048 -u 25600 usb.dd
   -> 원본 블록 번호를 얻어 ifind/fls 로 이름을 역추적

정답: flag{c4rv3d_fr0m_un4ll0c4t3d_sp4c3}
```

교훈 세 가지다. **① `-t all` + 이미지 전체는 거의 항상 오답이다** — `blkls`로 비할당만, `-t`로 형식만 좁힌다. **② `audit.txt`의 `at max size`는 실패 표시가 아니라 단서다** — 잘린 파일이 오히려 답인 경우가 있다. **③ 카빙물은 하나씩 검증한다** — 여러 파일을 한 번에 `strings`로 넘기면 결과가 묻힌다.

## 막혔을 때 다음 체크

1. 출력 폴더가 **비어 있는가** — 아니면 foremost는 아무 일도 하지 않는다
2. `audit.txt`의 `Invocation`과 `Configuration file`이 의도한 것과 같은가
3. `-t`에 원하는 형식을 실제로 넣었는가 (conf 확장자도 `-t`에 넣어야 한다)
4. 이미지 전체가 아니라 `blkls` 비할당 스트림을 입력으로 줬는가
5. `blkls -o`에 **섹터**를 넣었는가 (바이트가 아니다)
6. `-q`를 켠 상태인가 → 끄고 다시 돌려 개수를 비교
7. `-b`를 `fsstat`의 `Cluster Size`와 맞췄는가
8. `Size`가 최대 크기인 항목이 있는가 → 그것이 조각화/푸터 미발견 후보
9. `-a`로 오류 검사를 끄고 다시 뽑아 봤는가
10. `grep -abo` 헤더 개수와 foremost 결과 개수가 비슷한가
11. `binwalk`가 foremost보다 많이 찾는가 → 시그니처 DB 차이
12. `blkls -s`로 **슬랙만** 따로 뽑아 `strings`를 돌려 봤는가
13. PhotoRec으로 같은 이미지를 돌려 봤는가 ([FOR-0047](./photorec.html)) — 조각화에 더 강하다
14. 파일시스템이 살아 있는데 카빙부터 한 것은 아닌가 → `fls -d`가 먼저다

## 출처

- SRC-035 — foremost/scalpel 매뉴얼: `-t` `-i` `-o` `-c` `-v` `-q` `-Q` `-a` `-w` `-b` `-s` `-d` `-T` 옵션 정의, 설정 파일 탐색 순서, 지원 타입 목록
- SRC-032 — The Sleuth Kit 도구 문서: `blkls`(비할당/슬랙/전체 블록 출력), `blkcalc`(blkls 단위 번호 ↔ 이미지 블록 번호 환산), `fsstat`의 `Cluster Size`
- SRC-089 — 파일 시그니처 대조표: 본문 conf 예시에 쓴 EVTX(`ElfFile\x00`), SQLite(`SQLite format 3\x00`), regf, 7z, ZIP, PDF 매직 바이트
- foremost 버전에 따라 내장 타입 목록과 `foremost.conf`의 주석·부가 키워드(푸터 탐색 방향, 와일드카드)가 다르다. 커스텀 시그니처를 쓰기 전에 자기 배포본의 `/etc/foremost.conf` 주석과 `foremost -V`를 확인할 것
- `audit.txt`의 컬럼 배치와 요약 문구는 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
