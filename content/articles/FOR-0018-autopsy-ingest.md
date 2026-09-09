---
id: FOR-0018
title: "Autopsy로 이미지 ingest 시작하고 결과 트리 읽기"
slug: "autopsy-ingest"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["disk image", "Extracted Content", "Keyword Hits", "Deleted Files", "unallocated space", "Timeline"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["Autopsy", "Sleuth Kit", "PhotoRec", "FTK Imager", "Arsenal Image Mounter"]
commands: ["mmls image.dd", "fls -o 2048 -r -p image.dd"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Name", "Location", "Modified Time", "Created Time", "Size", "MD5 Hash", "Extension", "MIME Type"]
file_formats: ["e01", "raw", "dd", "vmdk", "vhd", "ad1"]
primary_terms: ["Autopsy", "autopsy ingest", "ingest", "ingest module"]
keywords: ["Autopsy", "ingest", "Ingest Modules", "Data Source", "Extracted Content", "Keyword Search", "Extension Mismatch", "PhotoRec Carver", "Timeline", "Deleted Files"]
aliases: ["autopsy", "오토프시", "autopsy 사용법", "이미지 통합 분석", "ingest 모듈", "키워드 검색", "카빙 자동", "autopsy 느림"]
symptom_keywords: ["ingest가 너무 느리다", "어떤 모듈을 켜야 하는지", "결과가 어디 있는지 모르겠다", "삭제 파일을 보고 싶다", "확장자가 위조된 파일을 찾고 싶다", "타임라인이 필요하다", "키워드로 찾고 싶다"]
related: ["FOR-0016", "FOR-0017", "FOR-0021"]
source_ids: ["SRC-005", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Autopsy는 강력하지만 전체 ingest가 느리므로, **처음에는 File Type Identification / Extension Mismatch Detector / Recent Activity / EXIF 만 켜서 5분 안에 1차 결과를 받고**, 키워드 검색과 PhotoRec 카버는 목표가 좁혀진 뒤 2차로 돌린다.

## 어떤 문제에서 필요한가

- 디스크 이미지 전체를 한 화면에서 훑어야 하는 경우
- **확장자가 위조된 파일**을 자동으로 찾아야 하는 경우
- 삭제 파일 목록과 비할당 영역 카빙을 한 번에 처리하고 싶은 경우
- 브라우저·레지스트리·최근문서 등 여러 artifact를 통합 타임라인으로 보고 싶은 경우
- 이미지 전체에 키워드(`flag{`, 사람 이름, 도메인)를 검색해야 하는 경우

FTK Imager가 "추출", Arsenal이 "마운트"라면 Autopsy는 **"자동 분석"** 이다. 다만 대회장에서는 시간이 곧 점수이므로 모듈 선택이 실력이 된다.

## 문제에서 처음 볼 단서

1. 이미지 크기가 수십~수백 GB이고 **어디를 봐야 할지 지문이 알려주지 않는다** → Autopsy 자동 분석이 유효
2. 지문이 "숨겨진 파일", "위조된 확장자", "삭제된 사진"을 언급 → Extension Mismatch / PhotoRec
3. 지문이 특정 문자열·계정·도메인을 준다 → Keyword Search
4. 지문이 "언제 무슨 일이 있었나"를 요구 → Timeline

반대로 **지문이 특정 artifact를 지목하면 Autopsy를 쓰지 않는다.** `$MFT`나 EVTX를 원하는 문제는 FTK Imager로 파일만 꺼내 전용 파서에 넘기는 편이 몇 배 빠르다 ([FOR-0016](./ftk-imager-open-image.html)).

## 30초 절차

```text
1. New Case  -> Case Name, Base Directory 지정 > Next > Finish
2. Add Data Source > Disk Image or VM File > 이미지 경로
3. Time zone 을 증거물의 시간대로 지정   <- 가장 중요한 한 줄
4. Configure Ingest Modules:
     [v] File Type Identification
     [v] Extension Mismatch Detector
     [v] Recent Activity
     [v] EXIF Parser
     [ ] Keyword Search        <- 1차에서는 끈다 (색인이 오래 걸린다)
     [ ] PhotoRec Carver       <- 1차에서는 끈다 (매우 오래 걸린다)
     [ ] Hash Lookup           <- 해시셋이 없으면 의미 없다
5. Finish -> 우하단 진행률 확인
```

Time zone 선택을 놓치면 이후 모든 화면의 시각이 어긋난다. **여기서 틀리면 나중에 전부 다시 봐야 한다.**

## 상세 절차

### 1단계 — Data Source 유형

| 유형 | 대상 |
| --- | --- |
| **Disk Image or VM File** | `.E01`, `.raw`, `.dd`, `.vmdk`, `.vhd`. **CTF에서 거의 항상 이것** |
| Local Disk | 물리 디스크 직접 (라이브 수집) |
| Logical Files | 파일/폴더 집합 (파일시스템 구조 없음) |
| Unallocated Space Image File | 비할당 영역만 담은 파일 (카빙 전용) |

분할 이미지는 첫 조각만 지정하면 나머지가 자동으로 이어진다.

### 2단계 — Ingest 모듈 선택: 무엇이 빠르고 무엇이 느린가

**이 표가 이 글의 핵심이다.**

| 모듈 | 속도 | 하는 일 | 1차에 켜나 |
| --- | --- | --- | --- |
| **File Type Identification** | 빠름 | 매직 바이트로 실제 MIME 판정 | **예 (다른 모듈의 전제)** |
| **Extension Mismatch Detector** | 빠름 | 확장자 ≠ 실제 형식인 파일 목록화 | **예** |
| **Recent Activity** | 보통 | 브라우저·최근문서·설치프로그램·USB 등 자동 추출 | **예** |
| **EXIF Parser** | 보통 | 이미지 메타데이터·GPS 추출 | **예** |
| Embedded File Extractor | 보통 | ZIP/문서 내부 파일 재귀 추출 | 상황에 따라 |
| Email Parser | 보통 | PST/MBOX 파싱 | 메일 문제면 예 |
| Encryption Detection | 빠름 | 엔트로피 기반 암호화 후보 탐지 | 저렴하므로 켜도 무방 |
| Interesting Files Identifier | 빠름 | 규칙 기반 관심 파일 표시 | 켜도 무방 |
| **Hash Lookup** | 빠름(해시셋 있을 때) | NSRL/알려진 악성 해시 대조 | 해시셋 없으면 아니오 |
| **Keyword Search** | **매우 느림** | 전체 텍스트 색인 생성 | **아니오 (2차)** |
| **PhotoRec Carver** | **매우 느림** | 비할당 영역 파일 카빙 | **아니오 (2차)** |
| Plaso | 매우 느림 | 초정밀 타임라인 | 아니오 |
| Virtual Machine Extractor | 느림 | 이미지 내부의 VM 디스크 추출 | 해당 시 |
| Android/iOS Analyzer | 보통 | 모바일 이미지 파싱 | 모바일 문제면 예 |
| YARA | 느림 | 규칙 기반 스캔 | 규칙이 있을 때 |
| Data Source Integrity | 빠름 | 이미지 해시 계산·검증 | 예 |

1차 조합(위 4~5개)은 수십 GB 이미지에서도 보통 몇 분 안에 끝난다. 여기서 방향이 잡히면 2차로 필요한 무거운 모듈만 추가한다.

**모듈은 나중에 다시 돌릴 수 있다.** 데이터 소스 우클릭 → `Run Ingest Modules`로 추가 실행하면 되므로 처음부터 다 켜야 한다는 부담을 가질 필요가 없다.

### 3단계 — 결과 트리 읽기 (어디에 무엇이 있나)

좌측 트리 구조와 각 노드의 용도다.

```text
▼ Data Sources
  ▼ pc01.E01
    ▼ vol2 (NTFS)
      ├ $Extend, Users, Windows ...          <- 실제 파일 트리
      ├ $CarvedFiles                          <- 카버가 복원한 파일
      ├ $Unalloc                              <- 비할당 영역 블록
      └ $OrphanFiles                          <- 부모를 잃은 파일 (삭제 흔적)
▼ Views
  ├ File Types
  │   ├ By Extension     (images, videos, archives, documents, executable)
  │   └ By MIME Type     <- 실제 형식 기준. 위조 파일 찾기에 유용
  ├ Deleted Files
  │   ├ File System      <- MFT 에 남은 삭제 파일
  │   └ All
  └ File Size
▼ Results
  ├ Extracted Content
  │   ├ Web History / Web Downloads / Web Cookies / Web Search
  │   ├ Recent Documents
  │   ├ Installed Programs
  │   ├ USB Device Attached           <- USB 흔적
  │   ├ Operating System Information
  │   ├ Run Programs
  │   ├ Shell Bags
  │   ├ Metadata / EXIF Metadata
  │   └ Encryption Detected
  ├ Keyword Hits           <- Keyword Search 모듈 결과
  ├ Hashset Hits
  ├ E-Mail Messages
  ├ Interesting Items
  │   └ Extension Mismatch Detected   <- 확장자 위조 파일
  └ Accounts
▼ Tags
▼ Reports
```

**실전에서 가장 먼저 보는 세 곳:**

1. `Results > Interesting Items > Extension Mismatch Detected` — 위조된 파일
2. `Results > Extracted Content` — 브라우저·USB·최근문서·실행프로그램이 이미 정리되어 있다
3. `Views > Deleted Files` — 삭제 파일 목록

### 4단계 — 확장자 위조 파일 찾기

```text
Results > Interesting Items > Extension Mismatch Detected
```

```text
Name              Location                           Extension  MIME Type
vacation.jpg      /Users/jhkim/Pictures/             jpg        application/zip
notes.txt         /Users/jhkim/Desktop/              txt        application/x-dosexec
logo.png          /Users/jhkim/Downloads/            png        application/x-7z-compressed
```

`MIME Type`이 진실이다. `vacation.jpg`는 실제로 ZIP이므로 이름을 바꿔 압축을 풀면 된다. **CTF에서 매우 흔한 패턴이며, Autopsy를 쓰는 가장 큰 이유 중 하나다.**

같은 목적으로 `Views > File Types > By MIME Type`을 열어 실제 형식별로 훑을 수도 있다.

### 5단계 — 키워드 검색 (2차)

방향이 잡힌 뒤 실행한다. 상단 우측 검색창 또는 `Tools > Keyword Search`.

| 검색 유형 | 예 | 용도 |
| --- | --- | --- |
| Exact Match | `flag{` | 정확한 문자열 |
| Substring Match | `secret` | 부분 문자열 |
| **Regular Expression** | `flag\{[^}]+\}` | 패턴 |

자주 쓰는 정규식:

```text
flag\{[^}]{1,64}\}
[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
(?:\d{1,3}\.){3}\d{1,3}
https?://[^\s"'<>]+
-----BEGIN [A-Z ]*PRIVATE KEY-----
[A-Za-z0-9+/]{40,}={0,2}
```

키워드 목록(Keyword List)을 미리 만들어 두면 ingest 시점에 함께 검색된다. **대회 전에 위 패턴들을 리스트로 저장해 두는 것이 준비의 핵심이다.**

키워드 검색은 색인 기반이라 최초 실행이 느리지만, 한 번 색인되면 이후 검색은 즉시 끝난다.

### 6단계 — 카빙 (2차)

```text
데이터 소스 우클릭 > Run Ingest Modules > PhotoRec Carver 만 체크
```

결과는 `$CarvedFiles` 노드에 쌓인다. 파일명은 복원되지 않고 오프셋 기반 이름(`f0012345.jpg`)이 붙는다.

카빙은 **비할당 영역**을 대상으로 하므로 파일 이름·경로·타임스탬프가 없다. 이름이 필요하면 `$MFT`/`$UsnJrnl`과 대조해야 한다 ([FOR-0027](./usnjrnl-basics.html)).

이미지가 크면 매우 오래 걸린다. 대안:

```text
FTK Imager 로 [unallocated space] 만 Export -> foremost/photorec 를 CLI로 직접
```

목표 파일 형식이 정해져 있다면 CLI 카빙이 훨씬 빠르다.

### 7단계 — 타임라인

```text
Tools > Timeline
```

파일시스템 시각 + 웹 활동 + 최근문서 등을 하나의 축에 올린다. 상단에서 기간을 좁히고, 좌측에서 이벤트 유형(File Modified / Accessed / Created / Changed, Web Activity 등)을 필터링한다.

정밀한 타임라인이 필요하면 Autopsy 타임라인보다 **`$MFT` + `$J` + EVTX CSV를 Timeline Explorer에 모아 보는 편**이 컬럼이 풍부하고 빠르다.

## 출력 필드 해석

파일 목록 창의 주요 컬럼이다.

| 컬럼 | 의미 | 함정 |
| --- | --- | --- |
| `Name` | 파일명 | 삭제 파일은 이름 앞에 표시가 붙는다 |
| `Location` | 볼륨 내 경로 | `/` 구분자를 쓴다 |
| `Modified/Accessed/Created/Changed Time` | MACB | **`Changed`가 MFT 엔트리 변경 시각** |
| `Size` | 논리 크기 | 물리 점유와 다르다 |
| `Flags(Dir)` / `Flags(Meta)` | `Allocated` / `Unallocated` | **`Unallocated` = 삭제됨** |
| `Known` | 해시셋 대조 결과 | `Unknown`이 기본 |
| `MD5 Hash` | 해시 | Hash Lookup 모듈 실행 시 채워진다 |
| `MIME Type` | **실제 형식** | 확장자 위조 판별의 근거 |
| `Extension` | 확장자 | `MIME Type`과 비교한다 |

`Flags(Meta) = Unallocated`가 삭제 파일 판별의 정확한 기준이다.

시각은 **Data Source 추가 시 지정한 시간대로 표시된다.** 이 값이 틀렸다면 `Case > Case Properties`에서 확인하고, 최종 답은 `$MFT` 파서의 UTC 값으로 검증한다.

## pivot: 다음에 볼 artifact

| Autopsy에서 얻은 것 | 다음 목표 |
| --- | --- |
| Extension Mismatch 파일 | Extract File → `file`/`binwalk`/7-Zip ([FOR-0001](./30sec-triage.html)) |
| `Extracted Content > Web History` | Chrome History DB 직접 질의 ([FOR-0191](./chrome-history.html)) |
| `Extracted Content > USB Device Attached` | `SYSTEM` hive의 USBSTOR / MountedDevices |
| `Extracted Content > Run Programs` | UserAssist / Prefetch 교차검증 ([FOR-0061](./userassist.html)) |
| `Views > Deleted Files` | `$UsnJrnl` 로 삭제 시각·원래 이름 ([FOR-0027](./usnjrnl-basics.html)) |
| Keyword Hit의 위치 | 해당 파일 Extract → 전체 문맥 확인 |
| `$CarvedFiles` 의 복원 파일 | 해시 → `$MFT` 대조로 원래 이름 추정 |
| 시각 하나 | Timeline에서 그 시각 ±5분 |
| 사용자 계정 목록 | 각 프로필의 `NTUSER.DAT` |

## 흔한 함정

- **Time zone을 기본값으로 두고 진행하는 것.** 이후 모든 시각이 어긋난다. Data Source 추가 화면에서 반드시 증거물 시간대로 설정한다.
- **모든 모듈을 켜고 기다리는 것.** 수십 GB 이미지에서 Keyword Search + PhotoRec을 함께 돌리면 수 시간이 간다. **1차는 가벼운 모듈만.**
- **Hash Lookup을 해시셋 없이 켜는 것.** NSRL 등을 등록하지 않으면 아무 결과가 없다.
- **ingest 완료 전에 결과를 결론으로 삼는 것.** 우하단 진행률이 100%가 되기 전에는 목록이 계속 늘어난다.
- **`$MFT` 수준의 상세 타임스탬프를 Autopsy에서 찾는 것.** `$SI`/`$FN` 구분이나 8개 타임스탬프 비교는 `$MFT` 파서가 필요하다 ([FOR-0021](./mft-basics.html)).
- **삭제 파일 판별을 이름 표시로 하는 것.** `Flags(Meta) = Unallocated`가 정확한 기준이다.
- **`$CarvedFiles`의 파일명을 원래 이름으로 착각하는 것.** 카빙 결과의 이름은 오프셋에서 생성된 것이다.
- **Case 폴더를 이미지와 같은 드라이브에 두는 것.** 색인·카빙 결과가 이미지 크기에 육박할 수 있다.
- **`Views > File Types > By Extension`만 보는 것.** 위조 파일은 여기서 잘못된 분류에 들어간다. `By MIME Type`을 본다.
- **Keyword Search 정규식을 grep 문법으로 쓰는 것.** Autopsy는 Java 정규식(Lucene 기반)이다. 문법 차이가 있으니 간단한 패턴으로 시작한다.
- **결과를 화면에서만 보는 것.** 목록을 우클릭 → `Export selected rows to CSV`로 뽑아 `rg`/PowerShell로 검색하는 편이 빠를 때가 많다.

## 교차검증

```bash
# 1) Autopsy 의 파일 목록  vs  Sleuth Kit 직접 실행
mmls image.dd                        # 파티션 오프셋 (예: 2048)
fls -o 2048 -r -p image.dd | wc -l   # 전체 항목 수
fls -o 2048 -r -p -d image.dd        # 삭제 항목만 (-d)

# 2) Autopsy 의 삭제 파일 수  vs  $MFT 의 InUse=False 수
#    (FTK Imager 로 $MFT 를 꺼내 MFTECmd 파싱)

# 3) Autopsy 의 Extension Mismatch  vs  직접 확인
#    해당 파일을 Extract 한 뒤
file extracted_vacation.jpg

# 4) Autopsy Web History  vs  Chrome History DB 직접 질의
sqlite3 History "SELECT count(*) FROM urls;"
```

Autopsy와 Sleuth Kit의 결과가 다르면 파티션 오프셋 지정이 다른 것이다 — Autopsy가 자동 탐지한 볼륨과 `mmls` 출력을 비교한다 ([FOR-0019](./mbr-gpt.html)).

## mini walkthrough

```text
문제:
"사진 폴더에 위조된 파일이 있습니다. 숨겨진 내용을 찾으세요."
첨부: photos.E01 (8 GB)

1. New Case > Add Data Source > Disk Image > photos.E01
   Time zone: (GMT+9:00) Asia/Seoul     <- 지문의 시각이 KST 였다

2. 첫 시도 (실패한 접근):
   모든 모듈을 켜고 Finish.
   Keyword Search 색인과 PhotoRec 이 돌기 시작해 12분이 지나도 30% 였다.
   -> Cancel 하고 다시 시작.

3. 접근 변경 — 가벼운 모듈만
   Run Ingest Modules 다시 실행:
     [v] File Type Identification
     [v] Extension Mismatch Detector
     [v] EXIF Parser
   -> 90초 만에 완료.

4. Results > Interesting Items > Extension Mismatch Detected

   Name             Location                  Extension  MIME Type
   IMG_2841.jpg     /Users/jhkim/Pictures/    jpg        application/zip
   IMG_2903.jpg     /Users/jhkim/Pictures/    jpg        application/x-7z-compressed

   2건. 목표 확정.

5. IMG_2841.jpg 우클릭 > Extract File(s) > C:\case\out\

   $ file IMG_2841.jpg
   IMG_2841.jpg: Zip archive data, at least v2.0 to extract

   $ 7z l IMG_2841.jpg
   secret/notes.txt
   secret/flag.txt

   $ 7z x IMG_2841.jpg -osecret_out
   $ cat secret_out/secret/flag.txt
   flag{3xt3ns10n_m1smatch_1s_a_g1ft}

6. 두 번째 파일도 확인
   IMG_2903.jpg -> 7z 아카이브, 암호 필요
   -> notes.txt 의 내용이 암호였다

7. 교차검증 — EXIF 로 진짜 사진과 구분
   Results > Extracted Content > EXIF Metadata
   -> 정상 사진 142장에는 EXIF 가 있고, 위조된 2건에는 없다.
      MIME Type 판정과 일치.

정답: flag{3xt3ns10n_m1smatch_1s_a_g1ft}
```

2→3단계가 이 글의 요지다. **모듈을 다 켜면 시간을 잃고, 필요한 세 개만 켜면 90초에 답이 나온다.**

## 막혔을 때 다음 체크

1. **Time zone**을 증거물 시간대로 설정했는가
2. 무거운 모듈(Keyword Search, PhotoRec, Plaso)을 1차에서 껐는가
3. ingest 진행률이 100%인가
4. `Results > Interesting Items > Extension Mismatch Detected`를 봤는가
5. `Views > File Types > **By MIME Type**`을 봤는가 (By Extension이 아니라)
6. `Results > Extracted Content` 하위 노드를 전부 펼쳐 봤는가 — 이미 정리된 정보가 많다
7. `Views > Deleted Files`와 `$OrphanFiles`를 봤는가
8. 파일이 없는가 → PhotoRec 카버 2차 실행 또는 CLI 카빙
9. 문자열을 찾는가 → Keyword Search 정규식 (Java 문법)
10. 시각 정밀도가 부족한가 → `$MFT`/`$J`를 꺼내 전용 파서로 ([FOR-0016](./ftk-imager-open-image.html))
11. 파티션이 예상과 다른가 → `mmls`로 대조 ([FOR-0019](./mbr-gpt.html))
12. 목록이 많은가 → CSV로 Export 후 `rg`/PowerShell로 검색

## 출처

- SRC-005 — Microsoft Learn, Master File Table: 할당/비할당 판정과 NTFS 메타데이터의 근거
- SRC-004 — Eric Zimmerman 문서: Autopsy 결과를 검증할 때 쓰는 전용 파서들의 입출력
- 모듈 이름과 트리 노드 명칭은 Autopsy 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
