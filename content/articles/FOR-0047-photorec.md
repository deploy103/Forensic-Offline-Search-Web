---
id: FOR-0047
title: "PhotoRec 사용법: TUI 절차, File Opt, recup_dir 해석"
slug: "photorec"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["unallocated space", "recup_dir", "file signature", "photorec.log"]
file_paths: ["recup_dir.1", "photorec.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["PhotoRec", "QPhotoRec", "TestDisk", "foremost", "Sleuth Kit", "exiftool", "file"]
commands: ["photorec image.dd", "photorec /d out/recup image.dd", "photorec /log image.dd", "file recup_dir.1/* | sort | uniq -c"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["jpg", "png", "pdf", "zip", "sqlite", "raw", "dd", "e01"]
primary_terms: ["PhotoRec", "recup_dir"]
keywords: ["PhotoRec", "QPhotoRec", "TestDisk", "카빙", "carving", "파일 복구", "recup_dir", "File Opt", "Free", "Whole", "brute force"]
aliases: ["photorec", "포토렉", "photorec 사용법", "사진 복구", "삭제 사진 복구", "testdisk", "qphotorec", "recup_dir"]
symptom_keywords: ["삭제된 사진을 복구하고 싶다", "photorec이 너무 느리다", "복구된 파일 이름이 f로 시작한다", "파티션이 안 보인다", "어떤 메뉴를 골라야 하는지 모르겠다", "foremost로 안 나온 파일이 있다"]
related: ["FOR-0046", "FOR-0049", "FOR-0018"]
source_ids: ["SRC-036", "SRC-035", "SRC-032"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

PhotoRec은 대화형 TUI를 **미디어 → 파티션 테이블 타입 → 파티션 → 파일시스템 타입(ext2/3 vs Other) → Free/Whole → 출력 폴더** 순서로 통과시키는 것이 전부이며, 속도가 문제라면 `File Opt`에서 형식을 다 끄고 필요한 것만 켜고 범위는 반드시 `Free`(비할당만)를 고른다.

## 어떤 문제에서 필요한가

- foremost/scalpel로 뽑은 파일이 중간에서 잘리거나 깨져 나오는 경우 (**조각화**)
- 지원 형식이 넓어야 하는 문제 — SQLite, 문서, 압축, 동영상, 메일이 섞여 있는 이미지
- 파티션 테이블이 없거나 깨져서 파일시스템 경로가 막힌 이미지
- 카메라 SD카드/USB 이미지에서 사진·동영상을 대량으로 건져야 하는 경우
- 원본 파일 이름은 필요 없고 **내용만** 필요한 경우

원본 이름·경로·삭제 시각이 답이라면 PhotoRec은 답을 주지 못한다. 그때는 `$MFT`/`$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html))이 먼저다.

## 문제에서 처음 볼 단서

1. `mmls`가 파티션을 못 찾는다 → PhotoRec의 파티션 테이블 타입에서 `None`을 골라야 하는 신호
2. foremost 결과에 `at max size`가 많다 → 조각화. PhotoRec의 brute force 쪽이 유리하다
3. 이미지 크기와 남은 시간 — `Whole`은 `Free`보다 몇 배 느리다
4. 지문이 요구하는 형식이 한두 개인가 → `File Opt`로 나머지를 다 끈다
5. 출력 폴더를 둘 여유 공간 — 카빙 결과는 원본 이미지 크기에 육박할 수 있다

## 30초 절차

```bash
photorec image.dd
```

TUI에서 누를 순서만 외운다.

```text
1. 미디어 선택            -> image.dd (또는 /dev/sdb) 에서 [Proceed]
2. 파티션 테이블 타입     -> Intel (일반 MBR) / EFI GPT / None (파티션 없는 볼륨 단독)
3. 파티션 목록            -> 대상 파티션 선택
   (여기서 [File Opt] 로 형식 선택, [Options] 로 동작 변경)
4. [Search]
5. 파일시스템 타입        -> ext2/ext3 이면 첫 항목, 그 외 전부 [Other]
6. 범위                   -> [Free] 비할당만  /  [Whole] 파티션 전체
7. 출력 폴더 선택         -> 원본과 다른 디스크. 확인 키를 눌러 확정
8. 진행 화면에서 형식별 개수가 올라간다
```

Windows에서는 다운로드한 폴더의 `photorec_win.exe`를 **관리자 권한**으로 실행한다. 물리 디스크를 대상으로 하려면 관리자 권한이 필수다. GUI가 편하면 같은 폴더의 `qphotorec_win.exe`(QPhotoRec)를 쓴다.

```bash
# 출력 폴더를 미리 지정해 폴더 선택 단계를 건너뛴다
photorec /d /cases/recup image.dd

# 로그를 남긴다 (photorec.log)
photorec /log /d /cases/recup image.dd
```

## 상세 절차

### 1단계 — 실행 대상과 권한

| 대상 | 명령 | 주의 |
| --- | --- | --- |
| RAW/dd 이미지 | `photorec image.dd` | 가장 흔한 CTF 형태 |
| 물리 디스크 | `sudo photorec /dev/sdb` | 루트/관리자 권한 필요 |
| E01 | 직접 열 수 없다 | `ewfmount`로 마운트해 나온 `ewf1`을 주거나 `ewfexport`로 raw 변환 |
| 마운트된 이미지(Windows) | Arsenal로 마운트 후 물리 디스크로 선택 ([FOR-0017](./arsenal-image-mounter.html)) | 읽기 전용 모드로 마운트 |

**원본은 절대 쓰기 대상이 되지 않게 한다.** PhotoRec은 읽기만 하지만, 출력 폴더를 복구 대상과 같은 파티션에 두면 비할당 영역을 덮어써서 아직 못 찾은 파일을 파괴한다. TUI의 출력 폴더 선택 화면에도 같은 경고가 표시된다.

### 2단계 — 파티션 테이블 타입 선택 (첫 갈림길)

미디어를 고르고 `[Proceed]`를 누르면 파티션 테이블 타입을 묻는다.

| 선택 | 언제 |
| --- | --- |
| `Intel` | 일반적인 MBR 디스크 이미지 |
| `EFI GPT` | GPT 디스크 (`mmls`가 GPT라고 답한 경우, [FOR-0019](./mbr-gpt.html)) |
| `None` | **파티션 테이블이 없는 볼륨 단독 이미지**, 또는 테이블이 완전히 파괴된 경우 |
| `Mac` / `Sun` / `XBox` / `Humax` | 해당 플랫폼 디스크 |

PhotoRec은 보통 올바른 값을 미리 선택해 준다. 그 추천이 틀렸다고 판단할 근거는 `mmls`/`fsstat` 결과다. `mmls`가 실패하고 `fsstat -o 0`이 성공하는 이미지는 볼륨 단독이므로 `None`이다 ([FOR-0048](./partition-offset-problems.html)).

`None`을 고르면 파티션 목록에 `Whole disk` 하나만 나온다. 이것을 선택해 진행한다.

### 3단계 — 파티션 선택 화면의 하단 메뉴

파티션 목록 화면 하단에 다음 항목들이 있다.

| 메뉴 | 역할 |
| --- | --- |
| `Search` | 선택한 파티션에서 카빙 시작 |
| `Options` | 동작 옵션 변경 (5단계) |
| `File Opt` | **카빙할 파일 형식 선택/해제** (4단계) |
| `Quit` | 이전 화면 |

**`Search`를 누르기 전에 `File Opt`를 먼저 다녀오는 것이 실전 순서다.** 형식을 좁히는 것이 속도를 가장 크게 바꾼다.

### 4단계 — File Opt로 속도를 올린다

`File Opt` 화면은 수백 개의 확장자 목록이고, 각 줄 앞의 표시가 활성/비활성을 나타낸다.

```text
[X] 1cd  1CD file
[X] 3dm  Rhino 3D Model
[X] 7z   7zip archive
[ ] a    ar archive
[X] abr  Adobe Brush
...
```

권장 절차:

1. 전체 해제 키를 눌러 **모든 형식을 끈다** (화면 하단에 안내되는 키를 쓴다)
2. 필요한 형식만 스페이스로 켠다 — `jpg`, `png`, `gif`, `pdf`, `zip`, `doc`, `sqlite` 등
3. 저장 항목을 선택하면 설정이 파일로 저장되어 다음 실행에도 유지된다
4. `Quit`으로 파티션 화면으로 돌아가 `Search`

형식을 3~4개로 줄이면 검사할 시그니처 수가 줄어 검사 속도가 크게 올라가고, 무엇보다 **결과 파일 개수가 사람이 볼 수 있는 수준으로 떨어진다.** 형식 전부를 켠 채로 수십 GB를 돌리면 결과가 수만 개가 되어 그 자체가 새로운 문제가 된다.

키 배치와 전체 토글 키는 버전에 따라 다르므로 화면 하단 안내를 읽고 누른다.

### 5단계 — Options 화면

| 항목 | 값 | 의미 |
| --- | --- | --- |
| `Paranoid` | `Yes` (기본) | 카빙한 파일을 내부 검증해 깨진 것을 버린다 |
| `Paranoid` | `bf` | **brute force.** 조각화된 파일을 재조립 시도. 매우 느리다 |
| `Paranoid` | `No` | 검증 없이 전부 저장 |
| `Keep corrupted files` | `Yes` | 검증에 실패한 파일도 남긴다 — **부분 복구가 필요하면 켠다** |
| `Expert mode` | `Yes` | 파일시스템 블록 크기/시작 오프셋을 직접 지정 |
| `Low memory` | `Yes` | 메모리가 부족해 죽을 때 |

실전 조합:

- **1차: 기본값(`Paranoid Yes`)** 으로 빠르게 돌려 정상 파일을 확보
- **2차: `Paranoid bf` + `Keep corrupted files Yes`** 로 조각화·부분 파일을 노린다

옵션 이름과 기본값은 버전에 따라 다를 수 있으므로 실제 화면에서 확인한다.

### 6단계 — 파일시스템 타입과 범위

`Search`를 누르면 두 개를 연달아 묻는다.

첫 질문 — 파일이 저장돼 있던 파일시스템:

| 선택 | 대상 |
| --- | --- |
| `ext2/ext3/ext4` | Linux 파일시스템 |
| `Other` | **FAT / exFAT / NTFS / HFS+ 등 그 외 전부** |

NTFS 이미지에서 `ext2` 쪽을 고르면 블록 판정이 어긋나 결과가 급감한다. Windows 이미지는 예외 없이 `Other`다.

두 번째 질문 — 검사 범위:

| 선택 | 의미 | 언제 |
| --- | --- | --- |
| `Free` | **비할당 영역만** 검사 | 삭제 파일만 원할 때. 빠르다. **기본 선택지** |
| `Whole` | 파티션 전체 검사 | 파일시스템이 깨져서 할당 정보를 믿을 수 없을 때, `Free`가 아무것도 못 찾았을 때 |

`Free`는 파일시스템의 할당 비트맵을 읽어 빈 클러스터만 훑는다. 그래서 **파일시스템이 손상되면 `Free`가 아무것도 못 찾는다.** 그럴 때 `Whole`로 전환하는 것이 정석 대응이다.

### 7단계 — 출력 폴더와 진행 화면

출력 폴더 선택은 방향키로 디렉터리를 이동하고 확인 키로 확정하는 파일 브라우저다. 화면 하단에 확정 키가 안내된다.

진행 화면은 형식별로 찾은 개수를 실시간으로 보여 준다.

```text
Destination /cases/recup

Pass 1 - Reading sector 1245184/8388608, 128 files found
Elapsed time 0h02m14s - Estimated time to completion 0h11m40

jpg: 96 recovered
png: 12 recovered
pdf: 14 recovered
zip: 6 recovered
```

`Pass 1`이 끝나면 `Pass 2`로 넘어가며, 패스가 올라갈수록 정렬되지 않은 위치까지 훑는다. 중단하면 그 시점까지의 결과는 남는다.

### 8단계 — recup_dir 출력 구조와 파일명 규칙

```text
/cases/recup/
├── recup_dir.1/
│   ├── f0012345.jpg
│   ├── f0012800.jpg
│   ├── f0018220.pdf
│   └── ... (수백 개)
├── recup_dir.2/
│   └── ...
└── recup_dir.3/
```

| 규칙 | 내용 |
| --- | --- |
| 폴더 | `recup_dir.1`, `recup_dir.2` … 한 폴더에 수백 개(대략 500개)씩 채워지면 다음 폴더를 만든다 |
| 파일명 | `f` + 숫자 + 확장자. 숫자는 **파일이 발견된 위치(블록/섹터 번호)** 에서 유도된다 |
| 원본 이름 | **복구되지 않는다.** 단, 파일 내부 메타데이터에 이름이 들어 있는 일부 형식은 이름 일부가 덧붙는 경우가 있다 (실제 출력에서 확인) |
| 타임스탬프 | 복구되지 않는다. mtime은 추출 시각이다 |

폴더가 많아 다루기 힘들면 한 번에 정리한다.

```bash
# 형식별 개수
find /cases/recup -type f | sed 's/.*\.//' | sort | uniq -c | sort -nr

# 실제 형식 재판정 (확장자는 PhotoRec의 추측이다)
find /cases/recup -type f -exec file {} + | awk -F: '{print $2}' | sort | uniq -c | sort -nr

# 형식별로 한 폴더에 모으기
mkdir -p sorted/jpg && find /cases/recup -name '*.jpg' -exec cp {} sorted/jpg/ \;

# 중복 제거
find /cases/recup -type f -exec md5sum {} + | sort | uniq -w32 -d | head
```

**시간 주의.** 복구된 파일의 mtime/ctime은 전부 추출 시각이므로 타임라인에 넣으면 안 된다. 증거 시각은 파일 내부에서만 얻는다.

```bash
exiftool -DateTimeOriginal -CreateDate -GPSPosition sorted/jpg/*.jpg | head -30
```

EXIF `DateTimeOriginal`은 보통 촬영 기기의 **로컬 시각**이고 시간대 정보가 없다. Office 문서의 `docProps/core.xml`은 UTC(`Z`)로 기록된다. KST 답을 요구하면 어느 기준인지 확정한 뒤 +9시간을 적용한다.

### 9단계 — 비대화형 실행

PhotoRec에는 문서화된 명령줄 옵션이 있다.

| 옵션 | 의미 | 확신도 |
| --- | --- | --- |
| `/d <경로>` | 출력(recup) 경로 지정 | 문서화됨 |
| `/log` | `photorec.log`에 로그 기록 | 문서화됨 |
| `/debug` | 디버그 로그 | 문서화됨 |
| `/cmd <장치> <명령열>` | **완전 비대화형 배치 실행** | 존재하지만 서브명령 문법이 버전마다 다르다 |

```bash
photorec /log /d /cases/recup image.dd
```

`/cmd`로 파티션 선택·형식 선택·검색까지 한 줄에 지정하는 배치 실행이 가능하다고 문서에 나오지만, **서브명령 이름과 순서는 버전에 따라 달라진다.** 대회장에서 확실하지 않은 문법을 쓰다 시간을 잃지 말고, `photorec` 실행 시 표시되는 사용법(또는 `/help`)으로 지원 여부를 먼저 확인한 뒤 쓴다. 배치가 꼭 필요하면 QPhotoRec GUI나 foremost 쪽이 확실하다.

### 10단계 — foremost/scalpel과의 비교

| 항목 | PhotoRec | foremost / scalpel |
| --- | --- | --- |
| 지원 형식 수 | 수백 개 (사실상 최다) | 내장 십여 개 + conf 추가 |
| 조각화 대응 | `Paranoid bf`로 **재조립 시도** | 없음. 연속 바이트만 |
| 파일 검증 | 형식별 내부 검증으로 쓰레기를 버린다 | 헤더/푸터만 |
| 비할당 한정 | `Free` 선택 하나로 | `blkls`로 미리 잘라 넣어야 한다 |
| 속도 | 느리다 | 빠르다 |
| 실행 방식 | 대화형 TUI (배치는 제약) | 완전한 CLI. 스크립트에 강하다 |
| 커스텀 시그니처 | 코드 수준. 사용자가 쉽게 추가 못 한다 | **`foremost.conf` 한 줄로 추가** ([FOR-0046](./foremost.html)) |
| 결과 위치 추적 | 파일명 숫자로 유추 | `audit.txt`에 `File Offset` 명시 |
| 파일명 복구 | 안 됨 | 안 됨 |

정리하면 **커스텀 매직 바이트나 정확한 오프셋이 필요하면 foremost, 형식 폭과 깨지지 않은 결과가 필요하면 PhotoRec**이다. 둘 다 돌려서 개수를 비교하는 것이 가장 안전하다.

### 11단계 — TestDisk와의 관계

PhotoRec과 TestDisk는 같은 배포 패키지(CGSecurity)에 들어 있는 형제 도구이며 역할이 다르다.

| 도구 | 무엇을 하나 | 파일 이름 복구 |
| --- | --- | --- |
| **TestDisk** | 파티션 테이블 복구, 부트섹터 복구, 파일시스템 메타데이터를 이용한 삭제 파일 복사 | **가능** (메타데이터를 쓰므로) |
| **PhotoRec** | 파일시스템을 무시하고 시그니처로 카빙 | 불가 |

그래서 순서가 정해진다.

```text
1. 파티션이 안 보인다        -> TestDisk (Analyse -> Quick Search)
2. 파티션은 보이는데 파일이 지워졌다 -> TestDisk 의 Undelete, 또는 fls/icat
3. 위 둘이 실패한다          -> PhotoRec
```

원본 파일 이름이 답인 문제에서 PhotoRec부터 돌리는 것은 순서를 거꾸로 밟는 것이다.

## 출력 필드 해석

진행 화면과 결과에서 판정에 쓰는 값들이다.

| 관찰 | 해석 | 조치 |
| --- | --- | --- |
| `Free`로 0개 | 할당 비트맵을 못 읽었다 = 파일시스템 손상 | `Whole`로 재시도 |
| `Whole`에서만 나온다 | 파일시스템 메타데이터가 깨졌다 | 결과를 신뢰. 단 살아 있는 파일도 섞인다 |
| 개수가 수만 개 | `File Opt`에서 형식을 안 좁혔다 | 형식을 3~4개로 줄여 재실행 |
| 같은 사진 수십 장 | 썸네일·캐시가 함께 잡혔다 | 해시로 중복 제거 |
| 진행률이 멈춘 듯 느리다 | `Paranoid bf` 또는 `Whole` | 정상. 시간 없으면 `Free` + 기본값 |
| `file`이 `data`라고 답한다 | 헤더만 맞았다 | `Keep corrupted files`로 뽑힌 부분 파일일 수 있다 |
| 크기가 비정상적으로 큰 파일 | 뒤쪽에 다른 데이터가 붙었다 | 푸터까지 수동 절단 |

## pivot: 다음에 볼 artifact

| PhotoRec에서 얻은 것 | 다음 목표 |
| --- | --- |
| 사진 다수 | `exiftool`로 EXIF·GPS·기기 모델·`DateTimeOriginal` |
| SQLite 파일 | 브라우저 History/모바일 앱 DB로 식별 ([FOR-0191](./chrome-history.html)) |
| 파일명 숫자(위치) | 원본 이미지의 그 오프셋을 hex로 확인 → 어떤 파일 안이었나 |
| 문서(zip 계열) | 압축 해제 → `docProps/core.xml`의 작성자·시각 |
| 복구된 실행 파일 | 해시 → Prefetch/Amcache로 실행 여부 |
| 원래 이름이 필요하다 | `$UsnJrnl`의 `FileDelete` ([FOR-0027](./usnjrnl-basics.html)) |
| 결과가 부실하다 | foremost로 교차 카빙 ([FOR-0046](./foremost.html)) |
| 파티션 자체가 안 보였다 | TestDisk, 그리고 오프셋 점검 ([FOR-0048](./partition-offset-problems.html)) |

## 흔한 함정

- **출력 폴더를 복구 대상과 같은 파티션에 두는 것.** 아직 카빙하지 못한 비할당 영역을 자기 결과물로 덮어쓴다. 다른 디스크나 별도 볼륨을 쓴다.
- **`Whole`을 기본으로 고르는 것.** 살아 있는 파일까지 전부 다시 뽑혀 결과가 수만 개가 되고 시간도 몇 배로 든다. 삭제 파일이 목표라면 `Free`가 먼저다.
- **`File Opt`를 건너뛰는 것.** 수백 개 형식을 다 켠 상태가 기본이다. 이것이 "PhotoRec은 느리다"의 실제 원인이다.
- **NTFS/FAT 이미지에서 `ext2/ext3`를 고르는 것.** 블록 판정이 어긋나 결과가 급감한다. Windows 계열은 전부 `Other`다.
- **파티션 테이블 타입에서 추천을 무시하고 `Intel`을 고집하는 것.** 볼륨 단독 이미지는 `None`이어야 하고, GPT 디스크는 `EFI GPT`다. 잘못 고르면 파티션 목록 자체가 엉뚱하게 나온다.
- **`f0012345.jpg`의 숫자를 원본 파일 이름의 일부로 착각하는 것.** 발견 위치에서 만든 번호다. 원본 이름은 카빙으로 절대 나오지 않는다.
- **복구된 파일의 mtime을 증거 시각으로 쓰는 것.** 추출 시각이다. 시각은 EXIF/문서 메타데이터에서만 얻는다.
- **`Paranoid Yes` 상태에서 "그 파일은 없다"고 결론 내리는 것.** 검증에 실패한 파일이 조용히 버려진 것일 수 있다. `Keep corrupted files Yes`로 다시 돌린다.
- **`Paranoid bf`를 처음부터 켜는 것.** 대회 시간 안에 끝나지 않는다. 기본값으로 1차를 돌려 확보한 뒤 2차에서 켠다.
- **E01을 직접 넘기는 것.** PhotoRec은 raw를 기대한다. `ewfmount`나 `ewfexport`로 raw를 만들어 준다.
- **결과 개수만 보고 성공했다고 판단하는 것.** `file`로 실제 형식을 재판정하고 열어 봐야 복구다.
- **디스크 여유 공간을 확인하지 않는 것.** 카빙 결과는 쉽게 수 GB가 된다. 공간이 차면 중간에 멈춘다.

## 교차검증

```bash
# 1) PhotoRec 결과 개수
find /cases/recup -type f | wc -l
find /cases/recup -type f | sed 's/.*\.//' | sort | uniq -c | sort -nr

# 2) foremost 로 같은 이미지를 카빙해 개수 비교
blkls -o 2048 image.dd > unalloc.blkls
foremost -t jpg,png,pdf,zip -i unalloc.blkls -o carved
tail -10 carved/audit.txt

# 3) 시그니처를 직접 세어 상한을 구한다
grep -abo $'\xff\xd8\xff' image.dd | wc -l
grep -abo '%PDF' image.dd | wc -l

# 4) 파일시스템 경로가 살아 있는지 (있으면 그쪽이 정답)
mmls image.dd
fls -o 2048 -r -d -p image.dd | head -30

# 5) 형식 재판정
find /cases/recup -type f -exec file {} + | awk -F: '{print $2}' | sort | uniq -c | sort -nr
```

PhotoRec이 foremost보다 적게 찾았다면 `File Opt`에서 그 형식이 꺼져 있거나 `Paranoid`가 버린 것이다. 많이 찾았다면 조각화 재조립이나 넓은 형식 지원이 작동한 것이다.

## mini walkthrough

```text
문제:
"손상된 SD카드 이미지입니다. 삭제된 문서에서 flag를 찾으세요."
첨부: sd.dd (8 GB)

1. 정찰
   $ mmls sd.dd
   Cannot determine partition type
   $ fsstat -o 0 sd.dd
   File System Type: FAT32
   Cluster Size: 32768
   -> 파티션 테이블이 없는 볼륨 단독 이미지다.

2. 첫 시도 (실패):
   photorec sd.dd
     파티션 테이블 타입 -> Intel   (추천이 None 이었는데 습관적으로 Intel 을 골랐다)
     파티션 목록 -> "Unknown" 하나만 표시
     Search -> Other -> Free
   결과: 0 files found

   원인: 파티션 테이블이 없는데 Intel 로 지정해
        PhotoRec 이 존재하지 않는 파티션 구조를 기준으로 범위를 잡았다.
        Free 는 할당 비트맵을 읽어야 하는데 그 기준점이 틀렸다.

3. 접근 변경 — 파티션 테이블 타입을 None 으로
   photorec sd.dd
     파티션 테이블 타입 -> None
     파티션 목록 -> "Whole disk" 선택
     File Opt -> 전체 해제 후 pdf, doc, zip, xlsx 만 활성
     Search -> Other -> Free
     출력 -> /cases/recup   (원본과 다른 디스크)

   Pass 1 ... 41 files found
   결과: recup_dir.1 에 41개

4. 두 번째 시도의 부분 실패:
   $ find /cases/recup -type f -exec file {} + | awk -F: '{print $2}' | sort | uniq -c
        22  PDF document, version 1.7
        11  Microsoft Word 2007+
         8  Zip archive data

   $ grep -ril 'flag{' /cases/recup
   (출력 없음)

   $ for f in /cases/recup/recup_dir.1/*.pdf; do
   >   echo "== $f"; strings -n 6 "$f" | grep -i 'flag' ; done
   (없음)

   flag 가 있어야 할 문서가 아예 안 뽑힌 것으로 보인다.
   여기서 "손상된 SD카드"라는 지문을 다시 읽는다.
   파일시스템이 손상되었다면 Free 가 신뢰할 수 없다.

5. 세 번째 시도 — Whole + Keep corrupted files
   photorec sd.dd
     None -> Whole disk
     Options -> Keep corrupted files: Yes,  Paranoid: bf
     File Opt -> pdf, doc, zip 만
     Search -> Other -> Whole

   Pass 1 ... 화면상 개수가 계속 올라간다
   결과: 156개 (recup_dir.1 ~ recup_dir.2)

   $ grep -rl 'flag{' /cases/recup2
   /cases/recup2/recup_dir.1/f0421120.pdf

   $ strings -n 6 /cases/recup2/recup_dir.1/f0421120.pdf | grep -o 'flag{[^}]*}'
   flag{ph0t0r3c_wh0l3_n0t_fr33}

6. 검증
   $ file /cases/recup2/recup_dir.1/f0421120.pdf
   PDF document, version 1.5
   $ xxd -l 8 /cases/recup2/recup_dir.1/f0421120.pdf
   00000000: 2550 4446 2d31 2e35                      %PDF-1.5
   $ tail -c 16 /cases/recup2/recup_dir.1/f0421120.pdf | xxd
   -> %%EOF 확인 (푸터까지 온전하다)
   $ pdftotext f0421120.pdf - | head       # 실제로 열리는지

7. 원래 이름 확보 (PhotoRec 으로는 불가)
   블록 번호 421120 -> 원본 오프셋을 hex 로 확인하고,
   같은 시간대의 $UsnJrnl FileDelete 와 대조해 이름을 찾는다.

정답: flag{ph0t0r3c_wh0l3_n0t_fr33}
```

두 번의 실패가 각각 다른 교훈이다. **① 파티션 테이블 타입을 잘못 고르면 결과가 0개로 나온다** — PhotoRec의 추천을 무시하지 말고, `mmls` 실패 + `fsstat -o 0` 성공은 `None`이라는 신호다. **② `Free`가 비면 파일시스템 손상을 의심하고 `Whole`로 전환한다** — "없다"는 결론을 내리기 전에 범위를 바꿔 본다.

## 막혔을 때 다음 체크

1. 파티션 테이블 타입을 PhotoRec의 **추천대로** 골랐는가 (`None`이 필요한 이미지인가)
2. 파일시스템 질문에서 Windows 이미지에 `Other`를 골랐는가
3. `Free`가 0개인가 → **`Whole`로 재시도**
4. `File Opt`에서 필요한 형식이 실제로 켜져 있는가
5. `Options`의 `Keep corrupted files`를 `Yes`로 바꿔 봤는가
6. `Paranoid`를 `bf`로 올려 조각화 재조립을 시도했는가
7. 출력 폴더가 원본과 **다른 디스크**인가, 여유 공간이 충분한가
8. E01을 raw로 변환/마운트해서 넘겼는가
9. `find ... -exec file {} +`로 실제 형식을 재판정했는가
10. 결과 파일을 하나씩 열어 `strings`/`grep`을 돌렸는가 (한 번에 넘기면 묻힌다)
11. foremost로 같은 이미지를 돌려 개수를 비교했는가 ([FOR-0046](./foremost.html))
12. 파일 이름·경로·삭제 시각이 답인가 → TestDisk / `fls -d` / `$UsnJrnl`로 전환
13. 파티션 자체가 안 보이는가 → TestDisk의 파티션 복구, 그리고 오프셋 점검 ([FOR-0048](./partition-offset-problems.html))

## 출처

- SRC-036 — CGSecurity TestDisk/PhotoRec 문서: TUI 진행 단계(미디어 → 파티션 테이블 타입 → 파티션 → 파일시스템 타입 → Free/Whole → 출력 폴더), `File Opt`/`Options` 화면, `recup_dir.N` 출력 규칙, `/d` `/log` `/debug` 명령줄 옵션, TestDisk와의 역할 분담
- SRC-035 — foremost/scalpel 매뉴얼: 비교표의 foremost 쪽 동작(내장 타입, conf 기반 시그니처, `audit.txt`의 오프셋)
- SRC-032 — The Sleuth Kit 도구 문서: 교차검증에 쓴 `mmls`, `fsstat`, `fls -d`, `blkls`
- 메뉴 항목 이름, 키 배치, `Options` 기본값, `/cmd` 서브명령 문법은 버전에 따라 다르다. 실제 화면과 실행 시 표시되는 사용법에서 확인할 것
- 파일명에 원본 이름 일부가 덧붙는 경우가 있는지는 형식과 버전에 의존하므로 실제 출력에서 확인할 것
