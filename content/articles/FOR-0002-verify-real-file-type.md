---
id: FOR-0002
title: "확장자 대신 실제 파일 형식 확인하기: file·DIE·xxd 판정 근거와 우선순위"
slug: "verify-real-file-type"
category: "트리아지"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["file signature", "footer", "container format", "[Content_Types].xml", "AndroidManifest.xml", "EOCD"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["file", "Detect It Easy", "TrID", "xxd", "HxD", "binwalk", "7-Zip", "exiftool", "pngcheck"]
commands: ["file -b target.bin", "file -k target.bin", "file -b --mime-type target.bin", "xxd -l 32 target.bin", "tail -c 32 target.bin | xxd", "7z l target.bin", "binwalk -B target.bin", "Format-Hex -Path .\\target.bin -Count 32"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["MIME Type", "Extension"]
file_formats: ["zip", "docx", "xlsx", "pptx", "apk", "jar", "epub", "odt", "jpeg", "png", "pdf", "gzip", "mp4", "ole"]
primary_terms: ["실제 파일 형식 확인", "확장자 믿지 말기", "file 명령"]
keywords: ["실제 파일 형식", "확장자 믿지 말기", "file 명령", "libmagic", "Detect It Easy", "TrID", "Format-Hex", "푸터", "footer", "컨테이너 형식", "PK 헤더", "binwalk", "MIME type"]
aliases: ["파일 형식 확인", "확장자 믿지 마", "file 명령어", "실제 형식 판정", "libmagic 틀림", "docx가 zip으로 나온다", "헤더 푸터 확인"]
symptom_keywords: ["확장자와 내용이 다른 것 같다", "file 결과를 믿어도 되나", "docx가 zip으로 나온다", "file이 data라고만 한다", "도구마다 다른 형식이라고 한다", "파일이 열리지 않는다"]
related: ["FOR-0001", "FOR-0036", "FOR-0037", "FOR-0008"]
source_ids: ["SRC-089", "SRC-042", "SRC-037"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

확장자는 사용자가 정한 문자열일 뿐이므로 **확장자 믿지 말기**를 기본값으로 두고, `file` 판정 → 헤더 바이트 → 푸터 바이트 → (컨테이너면) 내부 파일 이름 순서로 확인한다. 도구들이 서로 다른 답을 내면 **오프셋과 바이트를 직접 말할 수 있는 쪽이 이긴다.**

## 어떤 문제에서 필요한가

- 파일 **하나**의 정체를 확정해야 하는데 확장자와 내용이 어긋나 보이는 경우
- `file`은 `Microsoft Excel 2007+`라고 하는데 실제로 열면 아무것도 없는 경우
- `docx`/`apk`/`jar`/`xlsx`가 전부 `Zip archive data`로 나와 구분이 안 되는 경우
- 도구 두 개(`file`과 DIE, DIE와 TrID)가 다른 답을 내서 어느 쪽을 믿어야 할지 모르는 경우
- 전용 파서가 "손상된 파일"이라고 거부하는 경우

파일 **수백~수천 개를 한 번에** 대조해 위조 파일만 골라내는 절차는 [FOR-0036](./signature-extension-mismatch.html)에 있다. 매직 바이트 대조표 자체와 "무엇부터 열까"의 판단은 [FOR-0001](./30sec-triage.html)이 담당한다. 이 글은 **파일 하나를 놓고 판정 근거를 따지는 방법**과 **판정이 충돌할 때의 우선순위**만 다룬다.

## 문제에서 처음 볼 단서

1. **크기와 형식의 궁합** — 시트 3개짜리 `.xlsx`가 40 MB, 사진 한 장이 12 KB면 내용이 이름과 다르다
2. **`file`이 `data`라고만 답한다** — 매직이 없거나, 앞에 패딩이 붙었거나, 암호화되었다
3. **`file`이 `ASCII text`류로 답한다** — 매직 바이트가 없는 형식이거나 hex 덤프·Base64 텍스트다
4. **확장자가 컨테이너 계열이다** (`.docx` `.xlsx` `.pptx` `.apk` `.jar` `.epub` `.odt` `.ipa`) — 헤더만으로는 절대 구분되지 않는다
5. **전용 도구가 열다가 멈춘다** — 헤더는 정상이고 뒤가 잘렸거나, 뒤에 다른 파일이 붙어 있다

## 30초 절차

```bash
file -b target.bin
```

이 한 줄로 시작해서, 아래 네 줄로 근거를 확보한다.

```bash
file -k -b target.bin              # 하나만 답하지 말고 매칭된 것을 전부 보여라
xxd -l 32 target.bin               # 헤더 32바이트 (판정의 최종 근거)
tail -c 32 target.bin | xxd        # 푸터 32바이트 (헤더가 위조된 경우 여기가 진실)
binwalk -B target.bin              # 파일 내부 전체의 시그니처 위치
```

Windows에서 `file`/`xxd`가 없을 때:

```powershell
# 헤더 32바이트
Format-Hex -Path .\target.bin -Count 32

# 푸터 32바이트 (PowerShell 7+)
Get-Content -Path .\target.bin -AsByteStream -Tail 32 | Format-Hex

# PowerShell 5.1 이라면
Get-Content -Path .\target.bin -Encoding Byte -Tail 32 | Format-Hex
```

GUI만 있으면 HxD로 열어 좌상단 16바이트와 `Ctrl+End`로 이동한 마지막 16바이트를 읽는다 ([FOR-0037](./hxd-header-check.html)). Detect It Easy(DIE)는 실행 파일·패커 판정에서 `file`보다 구체적인 답을 준다.

## 상세 절차

### 1단계 — 도구별 "무엇을 보고 답하는가"

같은 파일에 서로 다른 답이 나오는 이유는 도구들이 **보는 곳이 다르기** 때문이다. 판정 근거를 알면 어느 쪽이 틀렸는지 즉시 안다.

| 도구 | 판정 근거 | 강한 곳 | 속는 경우 |
| --- | --- | --- | --- |
| `file` (libmagic) | magic DB의 "오프셋 + 바이트 패턴" 규칙 + 텍스트 인코딩 휴리스틱 | 속도, MIME 문자열, 스크립트 연동 | 앞에 패딩, 헤더 덮어쓰기, 재압축된 OOXML |
| `file -k` | 위와 같으나 **매칭 전부** 출력 | 애매한 파일에서 후보 확인 | 후보가 많아 사람이 골라야 한다 |
| `file -z` | 압축을 풀어 **내용**까지 판정 | gzip/bzip2로 감싼 파일 | 암호가 걸린 압축 |
| Detect It Easy | 자체 시그니처 + 섹션/엔트로피 분석 | PE·ELF, 패커·컴파일러·설치 파일 | 실행 파일이 아닌 형식은 판정이 거칠다 |
| TrID | 시그니처 DB 대조 후 **확률(%) 후보 목록** | `file`이 포기한 파일의 후보 좁히기 | "확률"이지 확정이 아니다 |
| `xxd` / `Format-Hex` / HxD | **바이트 그 자체** | 최종 근거. 오프셋을 말할 수 있다 | 사람이 표를 알아야 한다 |
| `binwalk` | 파일 **전체**를 스캔해 오프셋별 시그니처 나열 | 앞 패딩, 뒤에 붙인 파일, 중첩 | 오탐이 많다. 구조 검증이 필수 |
| `7z l` / `unzip -l` | 컨테이너 **내부 파일 이름** | ZIP 계열 세부 형식 확정 | 압축이 깨지면 목록이 안 나온다 |
| `exiftool` | 형식별 전용 파서 | 메타데이터, 하위 형식(JFIF/Exif) 구분 | 파싱 실패 시 침묵하거나 일부만 출력 |
| 전용 검증기 (`pngcheck`, `sqlite3`) | 구조를 끝까지 읽어 본다 | "정상인가"까지 답한다 | 형식별로 도구가 따로다 |

`file`은 **파일 이름을 보지 않는다.** 이것이 확장자 위조에 강한 이유이면서, 동시에 `.jar`와 `.zip`처럼 **이름과 내부 규약으로만 구분되는 형식**을 구분하지 못하는 이유다.

### 2단계 — 판정이 충돌할 때의 우선순위

이 표가 이 글의 핵심이다. 위에서 아래로 내려가며, **위쪽 근거가 아래쪽을 항상 덮어쓴다.**

| 순위 | 근거 | 왜 강한가 | 확인 방법 |
| --- | --- | --- | --- |
| 1 | 헤더 바이트 + 푸터 바이트가 **같은 형식**을 가리킨다 | 위조하려면 양쪽을 다 고쳐야 한다. 실제로는 헤더만 고친다 | `xxd -l 32`, `tail -c 32 \| xxd` |
| 2 | 컨테이너 내부 구조가 해석된다 | 내부 이름·디렉터리는 형식의 정의 그 자체다 | `7z l`, `unzip -l` |
| 3 | 전용 파서가 **끝까지** 읽는다 | 구조 전체가 유효하다는 뜻 | `pngcheck -v`, `sqlite3 f .schema`, `exiftool` |
| 4 | `file` / DIE 판정 | 헤더 기반. 대체로 맞지만 앞부분에만 의존한다 | `file -k -b` |
| 5 | TrID의 최상위 후보 | 확률. 근거가 아니라 힌트다 | 후보 여러 개를 그대로 기록 |
| 6 | 확장자와 파일 이름 | 사용자가 정한 문자열 | 판정 근거로 쓰지 않는다 |

판정이 갈릴 때 던지는 질문은 하나다. **"몇 번째 오프셋의 어떤 바이트를 근거로 그렇게 말하는가?"** 대답할 수 있는 쪽이 이긴다.

두 도구가 다른 답을 내는 것 자체가 신호다. `file`은 `PNG`, 푸터는 `FF D9`라면 **헤더만 바꿔치기한 JPEG**이고, 그것이 문제의 정답인 경우가 많다.

### 3단계 — libmagic이 틀리는 경우

| 상황 | `file` 출력 | 실제 | 대응 |
| --- | --- | --- | --- |
| 앞에 패딩·다른 파일이 붙었다 | `data` | 오프셋 N에서 시작하는 정상 파일 | `binwalk -B` → `dd skip=N` |
| 헤더만 정상 시그니처로 덮어썼다 | 덮어쓴 형식 | 푸터가 가리키는 형식 | 푸터 확인 → 헤더 복구 |
| OOXML을 다른 도구로 재압축했다 | `Zip archive data` | `.docx` / `.xlsx` | 내부 이름 확인 (4단계) |
| 매직 바이트가 없는 형식 | `ASCII text`, `CSV text`, `JSON data` | 텍스트 기반 형식 전부 | 내용을 직접 읽는다 |
| 암호화·고엔트로피 | `data` | 암호 컨테이너 후보 | `binwalk -E`로 엔트로피 확인 |
| 0바이트 | `empty` | 껍데기 파일 | 다른 첨부·ADS·슬랙을 본다 |
| 시그니처가 오프셋 4에 있다 (`ftyp`) | 구형 magic DB에서 `data` | mp4/mov/heic | `xxd -l 16`으로 `ftyp` 직접 확인 |
| 블록 디바이스·디스크 이미지 | 장치는 `block special` | 파일시스템·파티션 | `file -s`로 내용을 읽게 한다 |
| 심볼릭 링크 | `symbolic link to ...` | 대상 파일 | `file -L` |
| magic DB 버전 차이 | `application/x-rar` vs `application/vnd.rar` | 같은 형식 | 문자열 정확 일치 비교를 하지 않는다 |

libmagic의 판정은 **규칙의 "강도(strength)"로 정렬된 첫 매칭**이다. 그래서 짧은 매직(`MZ`, `BM`, `PK`)을 가진 형식은 우연한 일치로 오답이 나오기 쉽고, `file -k`로 후보 전체를 봐야 그 사실이 드러난다.

```text
$ file -k -b suspicious.bin
Zip archive data, at least v2.0 to extract
- data
```

`file -b --mime-type`은 스크립트에서 쓰기 쉬운 대신 정보량이 적다. 사람이 볼 때는 MIME 없이 설명 문자열을 읽는 편이 낫다.

### 4단계 — 컨테이너 형식: 전부 `PK`로 나오는 문제

`.docx` `.xlsx` `.pptx` `.apk` `.jar` `.epub` `.odt` `.ipa` `.xpi` `.kmz`는 **모두 정상적으로 ZIP이다.** 헤더는 예외 없이 `50 4B 03 04`(`PK..`)다. 세부 형식은 **내부 파일 이름으로만** 결정된다. `file`도 내부적으로 같은 방법을 쓴다.

```bash
7z l target.bin | head -25          # 내부 목록
unzip -l target.bin | head -25      # 7-Zip 이 없을 때
unzip -p target.bin mimetype        # epub/odt 는 이 항목 하나로 끝난다
```

| 내부에 있는 것 | 실제 형식 |
| --- | --- |
| `[Content_Types].xml` + `word/document.xml` | `.docx` |
| `[Content_Types].xml` + `xl/workbook.xml` | `.xlsx` |
| `[Content_Types].xml` + `ppt/presentation.xml` | `.pptx` |
| `AndroidManifest.xml` + `classes.dex` + `resources.arsc` | `.apk` |
| `META-INF/MANIFEST.MF` (+ `.class`) | `.jar` |
| 첫 항목이 `mimetype` = `application/epub+zip` | `.epub` |
| 첫 항목이 `mimetype` = `application/vnd.oasis.opendocument.*` | `.odt` / `.ods` / `.odp` |
| `Payload/<앱>.app/Info.plist` | `.ipa` |
| `install.rdf` 또는 `manifest.json` | `.xpi` |
| `doc.kml` | `.kmz` |
| 규칙 없는 임의 목록 | 순수 `.zip` |

주의할 점 두 가지다.

- `mimetype` 항목은 **아카이브의 첫 항목이면서 무압축(Store)으로 저장**되어야 규격에 맞다. 그래서 `xxd -l 64`만으로도 `mimetypeapplication/epub+zip` 문자열이 보인다. 재압축되면 이 성질이 깨지고 `file`은 그냥 `Zip archive data`라고 답한다.
- ZIP은 **끝에서부터 읽는 형식**이다. End of Central Directory(`50 4B 05 06`)를 먼저 찾고 그 안의 오프셋으로 목록을 읽는다. 그래서 **파일 앞에 다른 데이터가 붙어 있어도 압축 프로그램은 정상적으로 열린다.** `file`은 `data`, `7z l`은 정상 — 이 조합이 나오면 앞에 패딩이 있다는 뜻이다.

EOCD의 마지막에는 **주석(comment) 필드**가 있다. 여기에 숨긴 문자열은 `unzip -z target.zip` 또는 EOCD 이후 바이트를 직접 읽어 확인한다.

### 5단계 — 헤더가 아니라 푸터를 본다

헤더 위조는 1바이트 편집이면 되지만, 푸터까지 맞추는 문제는 드물다. 그래서 푸터가 실질적인 판정 근거가 된다.

| 형식 | 푸터 | 의미 |
| --- | --- | --- |
| JPEG | `FF D9` (EOI) | 이후 바이트가 있으면 뒤에 붙인 데이터다 |
| PNG | `49 45 4E 44 AE 42 60 82` (`IEND` + CRC) | `IEND` 뒤는 규격상 아무것도 없다 |
| GIF | `3B` (trailer) | — |
| PDF | `25 25 45 4F 46` (`%%EOF`) | 없으면 잘린 PDF 또는 카빙 실패 |
| ZIP 계열 | `50 4B 05 06` (EOCD) + 주석 길이 | EOCD가 끝이 아니면 뒤에 데이터가 붙었다 |
| gzip | 마지막 8바이트 = CRC32 + 원본 크기(ISIZE) | 원본 크기를 압축 해제 없이 알 수 있다 |
| VHD (고정/동적) | `conectix` | 디스크 이미지 판정 근거 |

```bash
tail -c 16 target.jpg | xxd
xxd target.png | tail -3

# EOCD 위치가 파일 끝인지 확인 (마지막 매칭 오프셋 vs 파일 크기)
grep -aob $'\x50\x4b\x05\x06' target.bin | tail -1
stat -c %s target.bin
```

```text
$ tail -c 16 photo.png | xxd
00000000: 0000 0000 4945 4e44 ae42 6082 504b 0304  ....IEND.B`.PK..
```

`IEND` **뒤에 `PK 03 04`가 있다.** PNG 뒤에 ZIP을 이어 붙인 파일이다. `7z l photo.png`가 바로 열린다.

### 6단계 — 앞에 패딩이 붙은 파일

`file`이 `data`라고 답하는 가장 흔한 원인이다. libmagic 규칙은 대부분 **오프셋 0 기준**이므로 앞에 1바이트만 끼워 넣어도 판정이 무너진다.

```bash
binwalk -B target.bin
```

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
512           0x200           PNG image, 1920 x 1080, 8-bit/color RGBA
560           0x230           Zlib compressed data, default compression
1049088       0x100200        7-zip archive data, version 0.4
```

```bash
# 오프셋 512 부터 끝까지 잘라낸다
dd if=target.bin of=fixed.png bs=1 skip=512 status=none
file -b fixed.png

# 길이까지 지정해 특정 구간만 (bs=1 은 느리다. 큰 파일은 아래처럼)
dd if=target.bin of=part.7z bs=512 skip=2049 status=none
```

`skip`은 `bs` 단위다. `bs=1`이면 바이트 단위라 정확하지만 대용량에서 매우 느리고, `bs=512`면 512의 배수 오프셋만 가능하다. `binwalk -e`로 자동 추출할 수도 있으나, **자동 추출은 오탐까지 그대로 꺼내므로 오프셋을 직접 확인한 뒤 `dd`로 잘라내는 편이 확실하다.**

`binwalk`의 결과는 **후보 목록**이다. 각 후보마다 그 오프셋에서 `xxd -s <오프셋> -l 16`으로 바이트를 눈으로 확인하고, 잘라낸 파일이 전용 도구로 열리는지까지 봐야 진짜다.

## 출력 필드 해석

`file` 출력에서 자주 만나는 문자열의 의미다.

| 출력 | 의미 | 다음 행동 |
| --- | --- | --- |
| `data` | 어떤 규칙에도 매칭 안 됨 | 크기 확인 → `binwalk -B` → 엔트로피 |
| `empty` | 0바이트 | 다른 첨부·ADS·슬랙 확인 |
| `ASCII text` / `UTF-8 Unicode text` | 매직 없는 텍스트 | 직접 읽는다. hex 덤프·Base64 가능성 |
| `CSV text`, `JSON data` | 텍스트 휴리스틱 판정 | 내용으로 재확인 |
| `Zip archive data` | ZIP 컨테이너 | **내부 이름을 반드시 본다** |
| `Microsoft Word 2007+` 등 | 내부 이름까지 확인된 OOXML | 신뢰. 단 뒤에 붙은 데이터는 별개 |
| `Composite Document File V2 Document` | OLE CFB (구형 doc/xls/ppt, msi, Jump List) | oledump 계열 |
| `PE32 executable` / `ELF 64-bit` | 실행 파일 | DIE로 패커·컴파일러 확인 |
| `ISO Media` | `ftyp` 기반 mp4/mov/heic 계열 | `exiftool`로 하위 브랜드 확인 |
| `gzip compressed data, was "x.tar"` | gzip 헤더의 **원본 파일 이름 필드** | 원래 이름이 단서가 된다 |
| `... (Zip archive data)` 뒤에 `at least vX.Y` | ZIP 버전 정보 | 암호화 여부는 별도 확인 |

`gzip`의 원본 파일 이름과 mtime이 헤더에 남는 성질은 실전에서 자주 정답이 된다. `file`이 알려주지 않으면 `xxd -l 32`로 헤더 뒤 문자열을 직접 읽는다.

## pivot: 다음에 볼 artifact

| 여기서 확정한 것 | 다음 목표 |
| --- | --- |
| ZIP 계열로 확정 | `7z l` → 내부 이름 → 암호 필요 여부 → 다른 첨부에 암호가 있는지 |
| PNG/JPEG로 확정 | `exiftool` → `pngcheck -v` → LSB/부가 데이터 스테가노 라인 |
| PE/ELF로 확정 | DIE로 패커 확인 → `strings -n 8` → 실행 흔적(Prefetch/Amcache) |
| 푸터 뒤에 붙은 데이터 발견 | 오프셋 계산 → `dd`로 분리 → 분리된 파일 재판정 |
| 헤더만 위조된 것으로 확정 | 원래 시그니처로 헤더 복구 ([FOR-0037](./hxd-header-check.html)) |
| 매직 없는 대용량(`data`) | 디스크/메모리 이미지 판정 라인으로 전환 |
| 확장자 없는 시스템 파일 | artifact 식별 표로 이동 ([FOR-0001](./30sec-triage.html)) |
| 위조 파일이 여러 개일 가능성 | 대량 대조로 전환 ([FOR-0036](./signature-extension-mismatch.html)) |

## 흔한 함정

- **확장자를 근거로 도구를 고르는 것.** 왜 틀리는가: 확장자는 검증되지 않은 사용자 입력이다. 어떻게: `file -b`와 `xxd -l 32`를 먼저 돌리고 그 결과로 도구를 고른다.
- **`file` 한 줄만 보고 확정하는 것.** 왜 틀리는가: libmagic은 강도순 첫 매칭에서 멈추고 오프셋 0 근처만 본다. 어떻게: `file -k`로 후보 전체를 보고, 헤더와 푸터를 직접 읽어 교차 확인한다.
- **`docx`/`apk`/`jar`를 "ZIP 위조"로 보고하는 것.** 왜 틀리는가: 이들은 규격상 ZIP 컨테이너다. 어떻게: `7z l`의 내부 이름으로 세부 형식을 확정한다.
- **헤더만 확인하고 끝내는 것.** 왜 틀리는가: 헤더 위조는 몇 바이트 편집이면 끝난다. 어떻게: 푸터(`FF D9`, `IEND`, `%%EOF`, EOCD)를 항상 함께 본다.
- **첫 4바이트만 읽는 것.** 왜 틀리는가: `ftyp`는 오프셋 4에 있고, RIFF·TIFF 계열은 하위 타입이 뒤에서 갈린다. 어떻게: 최소 16~32바이트를 읽는다.
- **`file`이 `data`라고 하면 포기하는 것.** 왜 틀리는가: 앞 패딩 한 가지 이유로도 `data`가 나온다. 어떻게: `binwalk -B`로 내부 오프셋을 훑고 `dd`로 잘라 재판정한다.
- **`binwalk` 결과를 그대로 사실로 받는 것.** 왜 틀리는가: 짧은 시그니처의 우연 일치가 많다. 어떻게: 후보 오프셋을 `xxd -s`로 확인하고 잘라낸 파일이 실제로 열리는지 본다.
- **TrID의 최상위 후보를 확정으로 쓰는 것.** 왜 틀리는가: TrID는 확률 목록을 준다. 어떻게: 후보를 좁히는 용도로만 쓰고 결론은 바이트로 낸다.
- **`file`의 MIME 문자열을 정확 일치로 비교하는 것.** 왜 틀리는가: magic DB 버전마다 표기가 다르다. 어떻게: 부분 일치·정규식으로 비교한다.
- **텍스트 형식을 위조로 판정하는 것.** 왜 틀리는가: `.txt` `.csv` `.json` `.xml` `.log`는 애초에 매직이 없다. 어떻게: 비교 대상에서 빼거나 `text/`로 시작하는지만 본다.
- **원본을 직접 편집하는 것.** 왜 틀리는가: 헤더를 고쳐 보다가 증거가 훼손되면 되돌릴 수 없다. 어떻게: 사본을 만들고 원본 해시를 먼저 기록한다.
- **압축 파일 내부를 검사하지 않는 것.** 왜 틀리는가: `file`은 기본적으로 컨테이너 안을 들여다보지 않는다. 어떻게: `file -z`, `7z x` 후 재귀 검사한다.

## 교차검증

```bash
# 1) libmagic 판정 (후보 전체)
file -k -b target.bin

# 2) 헤더 바이트 — 판정의 최종 근거
xxd -l 32 target.bin

# 3) 푸터 바이트 — 헤더와 같은 형식을 가리키는가
tail -c 32 target.bin | xxd

# 4) 컨테이너면 내부 이름으로 세부 형식 확정
7z l target.bin | head -25

# 5) 파일 내부 전체 시그니처 (앞 패딩·뒤에 붙인 파일 탐지)
binwalk -B target.bin

# 6) 엔트로피 — 0.99 부근이면 암호화/압축 구간
binwalk -E target.bin

# 7) 전용 파서가 끝까지 읽는가
pngcheck -v target.png
exiftool target.bin | head -20
```

1)과 2)가 다르면 앞에 패딩이 있거나 헤더가 위조된 것이다. 2)와 3)이 다르면 **헤더만 바꿔치기한 파일**이다. GUI에서는 DIE로 같은 파일을 열어 `file`과 판정이 일치하는지 본다.

## mini walkthrough

```text
문제:
"협력사에서 받은 견적서입니다. 유출된 자료의 파일 이름을 찾으세요."
첨부: quote_2026.xlsx (41 MB)

1. 첫 시도 (실패):
   file -b quote_2026.xlsx
   -> Microsoft Excel 2007+

   판정을 그대로 믿고 Excel 로 열었다.
   시트 3개(견적, 단가, 비고)를 전부 훑고 숨긴 시트/행/열,
   수식, 이름 정의까지 확인했으나 아무것도 없었다. 6분 소모.

   무엇이 틀렸나:
   file 은 "이 파일의 시작이 무엇인가"에만 답한다.
   "파일 전체가 그것뿐인가"에는 답하지 않는다.
   시트 3개짜리 xlsx 가 41 MB 라는 크기 이상치를 무시한 것이 실수였다.

2. 크기 검산 — 압축 해제 후 크기와 비교
   7z l quote_2026.xlsx | tail -3
   ->  Size: 3 214 887   Compressed: 41 203 456
   압축 결과가 원본보다 12배 크다. 산술적으로 불가능하다.
   -> ZIP 이 설명하지 못하는 바이트가 파일 안에 있다.

3. 푸터 확인
   tail -c 16 quote_2026.xlsx | xxd
   -> 00000000: 0000 0000 0000 0000 0000 0000 0000 0000

   EOCD(50 4B 05 06)가 파일 끝에 없다.
   grep -aob $'\x50\x4b\x05\x06' quote_2026.xlsx | tail -1
   -> 3215104:PK...
   stat -c %s quote_2026.xlsx
   -> 41203456
   EOCD 뒤로 38 MB 가 더 있다. Excel 은 EOCD 기준으로 읽으므로
   정상 파일처럼 열렸던 것이다.

4. 붙은 데이터의 정체
   binwalk -B quote_2026.xlsx
   -> DECIMAL     HEX        DESCRIPTION
      0           0x0        Zip archive data
      3215104     0x310C00   End of Zip archive
      3215360     0x310D00   7-zip archive data, version 0.4

   xxd -s 3215360 -l 16 quote_2026.xlsx
   -> 377a bcaf 271c ...        (37 7A BC AF 27 1C = 7z. 확정)

5. 잘라내기
   dd if=quote_2026.xlsx of=hidden.7z bs=1 skip=3215360 status=none
   file -b hidden.7z
   -> 7-zip archive data, version 0.4

6. 내부 확인
   7z l hidden.7z
   -> 고객단가_2026.xlsx      (암호 필요 표시)
      개발로드맵.pdf

7. 암호는 어디에 — 같은 컨테이너의 주석을 본다
   unzip -z quote_2026.xlsx
   -> pw: Q1Nw!2026

8. 검산
   7z x -p'Q1Nw!2026' hidden.7z
   -> 정상 해제. 두 파일 모두 열림.

정답: 고객단가_2026.xlsx, 개발로드맵.pdf
      (정상 xlsx 뒤에 7z 를 이어 붙이고 암호는 ZIP 주석에 숨김)
```

1→2단계의 전환이 이 글의 요지다. **`file`의 답은 "파일의 시작"에 대한 것이고, "파일 전체"에 대한 것이 아니다.** 크기 이상치와 푸터를 확인하는 두 동작이 6분을 30초로 줄인다.

## 막혔을 때 다음 체크

1. `file -k`로 후보 전체를 봤는가 (한 줄만 보지 않았는가)
2. 헤더 32바이트를 눈으로 읽었는가
3. 푸터 32바이트를 눈으로 읽었는가 — 헤더와 같은 형식을 가리키는가
4. 컨테이너 계열이면 `7z l`로 내부 이름을 확인했는가
5. 압축 해제 크기와 파일 크기의 비율이 상식적인가
6. `binwalk -B`로 파일 내부 전체를 훑었는가
7. 오프셋 4의 `ftyp`처럼 0이 아닌 위치의 시그니처를 확인했는가
8. `file -z`로 압축 내부까지 판정했는가
9. `file`이 `data`인가 → 엔트로피(`binwalk -E`)로 암호화 여부를 갈랐는가
10. 디스크·장치라면 `file -s`를 썼는가
11. DIE 또는 TrID로 2차 판정을 받아 봤는가 (판정이 갈리면 2단계 우선순위표 적용)
12. 전용 검증기(`pngcheck -v`, `sqlite3 .schema`)가 끝까지 읽는가
13. 파일 이름·확장자를 판정 근거에서 완전히 배제했는가

## 출처

- SRC-089 — Wikipedia, List of file signatures: 헤더/푸터 매직 바이트 대조값(JPEG `FF D8 FF` / `FF D9`, PNG 시그니처와 `IEND`, ZIP `50 4B 03 04` / `50 4B 05 06`, 7z `37 7A BC AF 27 1C`, gzip, `ftyp` 오프셋)
- SRC-042 — ZIP File Format Specification (PKWARE APPNOTE): Local File Header와 End of Central Directory 구조, EOCD를 끝에서부터 찾는 읽기 순서, EOCD 주석 필드, docx/xlsx/apk/jar가 동일한 ZIP 컨테이너를 쓴다는 근거
- SRC-037 — binwalk 문서: 시그니처 스캔(`-B`), 엔트로피(`-E`), 추출(`-e`) 동작과 오프셋 출력 형식
- `file`/libmagic이 출력하는 설명·MIME 문자열은 버전과 magic DB에 따라 달라지므로 실제 환경에서 확인할 것
- `Format-Hex`의 `-Count` / `Get-Content`의 `-AsByteStream`·`-Encoding Byte`는 PowerShell 버전에 따라 지원 여부가 다르므로 실제 콘솔에서 확인할 것
- TrID는 `tools/manifest.json`의 확인된 도구 목록에 없다(권장 추가 목록에만 있음). 대회장에서는 `file`과 Detect It Easy로 대체한다
- epub/odt의 `mimetype` 항목 위치·무압축 저장 규칙은 각 형식 규격 문서로 재확인할 것 (`research/sources.json`에 ECMA-376은 SRC-043으로 있으나 이 글의 인용 범위에는 포함하지 않았다)
- 최종 판정은 항상 대상 파일의 헤더/푸터 바이트를 `xxd`/HxD로 직접 읽어 확인할 것
