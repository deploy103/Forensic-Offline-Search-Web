---
id: FOR-0231
title: "HxD 실전 레시피 8개: 시그니처 복구·푸터 붙이기·패딩 제거·구간 추출"
slug: "hxd-practice"
category: "파일/카빙"
type: "guide"
difficulty: "basic"
priority: "normal"
platform: [windows]
artifact: ["file header", "file footer", "padding", "byte pattern", "checksum"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["HxD", "xxd", "dd", "PowerShell", "pngcheck", "7-Zip"]
commands: ["Copy-Item .\\evidence.bin .\\work.bin", "dd if=work.bin of=fixed.bin bs=1 skip=4", "printf '\\x00\\x00\\x00\\x00IEND\\xae\\x42\\x60\\x82' >> work.png", "dd if=work.bin of=inner.zip bs=1 skip=1234 count=8192", "Get-FileHash .\\work.bin -Algorithm SHA256"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Offset", "Selection length", "File size", "Edit mode"]
file_formats: ["png", "jpeg", "zip", "gif", "pdf"]
primary_terms: ["HxD 실전", "hex 편집 실습", "바이트 직접 수정"]
keywords: ["HxD 실전", "hex 편집 실습", "바이트 직접 수정", "시그니처 복구", "푸터 붙이기", "패딩 제거", "파일 비교", "선택 영역 저장", "체크섬 계산", "IEND", "FFD9", "Overwrite", "dd skip"]
aliases: ["hxd 실습", "hxd 연습 문제", "헥스로 파일 고치기", "png 푸터 붙이기", "파일 앞 쓰레기 지우기", "hxd 파일 비교", "선택한 부분만 저장"]
symptom_keywords: ["헤더를 고쳤는데 여전히 안 열린다", "파일 끝이 잘려 있다", "파일 앞에 이상한 바이트가 붙어 있다", "정상 파일과 어디가 다른지 모르겠다", "파일 안의 특정 부분만 빼내고 싶다"]
related: ["FOR-0037", "FOR-0001", "FOR-0240", "FOR-0241"]
source_ids: ["SRC-088", "SRC-089", "SRC-040"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

헥스 편집은 여덟 가지 작업으로 끝난다. 시그니처 교체, 푸터 추가, 앞 패딩 제거, 두 파일 비교, 패턴 일괄 검색, 오프셋 계산, 구간 추출, 체크섬 확인. 각 작업은 **사본 만들기 → Overwrite 모드 확인 → 편집 → 형식 검사기로 검증**이라는 같은 네 단계를 따르며, 검증을 건너뛴 편집은 편집하지 않은 것과 같다.

## 어떤 문제에서 필요한가

기능 설명이 아니라 손이 기억해야 하는 작업 순서가 필요한 상황이다. HxD의 화면 구성, Goto/검색 대화상자, Data Inspector, Insert/Overwrite 모드의 의미는 [FOR-0037](./hxd-header-check.html)에 있고, 매직 바이트 → 도구 대응표는 [FOR-0001](./30sec-triage.html)에 있다. 이 글은 그 두 글을 이미 읽었다고 가정하고 **레시피만** 다룬다.

| 증상 | 레시피 |
| --- | --- |
| `file`이 `data`라고 하는데 내부에 IHDR/IDAT가 보인다 | 레시피 1 — 시그니처 복구 |
| 이미지가 절반만 렌더링되고 아래가 회색이다 | 레시피 2 — 푸터 붙이기 |
| `binwalk`가 오프셋 4나 0x200에서 시작한다고 한다 | 레시피 3 — 앞 패딩 제거 |
| 정상 파일이 함께 주어졌는데 어디가 다른지 모른다 | 레시피 4 — 두 파일 비교 |
| 파일 안에 같은 시그니처가 몇 개 있는지 세야 한다 | 레시피 5 — 패턴 일괄 검색 |
| CSV에서 얻은 MFT Entry Number 위치를 봐야 한다 | 레시피 6 — 오프셋 계산 |
| 파일 안에 박힌 ZIP만 따로 빼야 한다 | 레시피 7 — 구간 추출 |
| 편집 후 원본이 오염되지 않았는지 증명해야 한다 | 레시피 8 — 체크섬 |

## 문제에서 처음 볼 단서

1. **파일 크기** — 512/4096의 배수인가, 잘린 흔적처럼 어중간한가
2. **앞 32바이트** — 무엇이 0으로 덮였는가, 무엇이 남아 있는가
3. **끝 32바이트** — 푸터가 있어야 할 형식인데 없는가
4. **정상 참조 파일 유무** — 있으면 비교(레시피 4)가 가장 빠른 길이다
5. **`binwalk` 출력의 오프셋** — 0이 아니면 앞에 뭔가 붙어 있다는 뜻이다

## 30초 절차

```powershell
Copy-Item .\evidence.bin .\work.bin; Get-FileHash .\evidence.bin,.\work.bin -Algorithm SHA256
```

증거물을 직접 열지 않는다. 사본을 만들고, 두 해시가 같은지 확인하고, `work.bin`만 HxD로 연다. 작업이 끝난 뒤 원본 해시를 한 번 더 확인한다. 이 한 줄을 생략해서 문제 파일을 다시 받는 사고가 가장 흔하다.

편집 창을 열었으면 하단 상태 표시줄에서 **편집 모드가 Overwrite**인지 본다. Insert면 `Insert` 키로 전환한다.

## 상세 절차

### 레시피 1 — PNG / JPEG / ZIP 시그니처 복구

앞 몇 바이트가 0이나 엉뚱한 값으로 덮였고 내부 구조는 살아 있는 경우다. **먼저 형식을 확정하고 그다음에 쓴다.** 순서를 바꾸면 다른 형식을 PNG로 위조하게 된다.

| 형식 | 오프셋 0에 쓸 바이트 | 형식 확정 근거 (파일 안에서 먼저 확인) |
| --- | --- | --- |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 오프셋 8~11 = `00 00 00 0D`, 오프셋 12~15 = `IHDR` |
| JPEG | `FF D8 FF E0` 또는 `FF D8 FF DB` | `JFIF` 또는 `Exif` 문자열, 끝의 `FF D9` |
| GIF | `47 49 46 38 39 61` (`GIF89a`) | 끝의 `3B`, `NETSCAPE2.0` 문자열 |
| ZIP | `50 4B 03 04` | 끝 근처의 `50 4B 05 06`, 내부 파일 이름 문자열 |
| PDF | `25 50 44 46 2D 31 2E` (`%PDF-1.`) | `obj` / `endobj`, `%%EOF` |

절차:

```text
1. Ctrl+G -> hex 모드 -> 0 -> Enter
2. 오프셋 8~15 를 읽어 형식을 확정한다 (위 표의 3열)
3. Ctrl+F -> hex 검색으로 푸터를 찾아 한 번 더 확인한다
4. 오프셋 0 에 커서를 놓고 표의 2열 바이트를 입력한다 (Overwrite)
5. 저장 -> 하단 상태 표시줄의 파일 크기가 변하지 않았는지 확인
6. file / pngcheck / 7z t 로 검증
```

**PNG는 시그니처 8바이트만 고쳐도 되는 경우가 많다.** 청크 구조(길이 4바이트 + 타입 4바이트 + 데이터 + CRC 4바이트)는 시그니처와 독립이므로 시그니처만 복원하면 디코더가 IHDR부터 정상적으로 읽는다.

같은 작업을 CLI로 하면 원본을 건드리지 않아 더 안전하다.

```bash
printf '\x89PNG\r\n\x1a\n' > fixed.png
tail -c +9 broken.png >> fixed.png
file fixed.png && pngcheck fixed.png
```

### 레시피 2 — 잘린 파일 뒤에 푸터 붙이기

이미지가 위쪽만 보이거나 뷰어가 "예상치 못한 파일 끝"을 말하는 경우다. 데이터 자체가 잘려 나갔으므로 **푸터를 붙여도 잘린 부분은 돌아오지 않는다.** 목표는 디코더가 "여기까지"라고 판단하고 남은 부분을 그려 주게 만드는 것이다.

| 형식 | 붙일 바이트 | 의미 |
| --- | --- | --- |
| PNG | `00 00 00 00 49 45 4E 44 AE 42 60 82` | 길이 0 + `IEND` + 고정 CRC32 `AE426082` |
| JPEG | `FF D9` | EOI 마커 |
| GIF | `3B` | trailer |
| PDF | `%%EOF` | 다만 xref가 깨져 있으면 이것만으로는 부족하다 |

HxD 절차:

```text
1. Ctrl+End 로 파일 끝으로 이동
2. Insert 키로 Insert 모드로 전환  (이 레시피는 예외적으로 Insert 를 쓴다)
3. 표의 바이트를 입력
4. 저장 -> 파일 크기가 정확히 붙인 바이트 수만큼 늘었는지 확인
5. Insert 키로 다시 Overwrite 로 돌려놓는다
```

CLI가 훨씬 안전하다.

```bash
cp broken.png work.png
printf '\x00\x00\x00\x00IEND\xae\x42\x60\x82' >> work.png
pngcheck -v work.png
```

```text
File: work.png (204812 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1920 x 1080 image, 32-bit RGB+alpha, non-interlaced
  chunk IDAT at offset 0x00025, length 65536
  chunk IDAT at offset 0x10031, length 65536
  chunk IEND at offset 0x3200d, length 0
ERROR: zlib: inflate error = -5 (buffer error)
```

`IEND` 청크가 인식되고 이미지 크기가 읽히지만 IDAT 스트림이 부족하다는 에러다. 이 상태에서도 대부분의 뷰어는 **잘린 지점까지의 이미지를 그려 준다.** 답이 그림 위쪽에 있으면 여기서 문제가 풀린다.

ZIP은 이 방식이 통하지 않는다. 파일 목록의 진실은 Central Directory에 있고 EOCD는 그 위치를 가리키는 포인터일 뿐이므로, 22바이트짜리 빈 EOCD를 붙이면 "항목 0개인 정상 ZIP"이 된다. ZIP이 잘린 경우는 Local File Header를 스캔해 재구성하거나 `zip -FF`를 쓴다.

### 레시피 3 — 파일 앞 패딩 제거

`binwalk`가 오프셋 0이 아닌 곳에서 시그니처를 찾았을 때다. 앞에 붙은 바이트를 잘라내면 정상 파일이 된다.

```bash
binwalk suspicious.bin
```

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
512           0x200           PNG image, 1024 x 768, 8-bit/color RGBA, non-interlaced
549           0x225           Zlib compressed data, default compression
```

시작 오프셋이 512다.

```bash
dd if=suspicious.bin of=fixed.png bs=1 skip=512
file fixed.png
```

```text
206336+0 records in
206336+0 records out
fixed.png: PNG image data, 1024 x 768, 8-bit/color RGBA, non-interlaced
```

| dd 인자 | 뜻 | 주의 |
| --- | --- | --- |
| `bs=1` | 블록 크기 1바이트 | 느리지만 오프셋이 정확하다. 큰 파일은 `bs=512 skip=1` 처럼 블록 단위로 |
| `skip=N` | 입력에서 앞 N블록을 버린다 | `bs=1`이면 N바이트 |
| `count=N` | N블록만 읽는다 | 뒤쪽을 잘라낼 때 |
| `of=` | 출력 파일 | 원본과 다른 이름을 쓴다 |

HxD로 같은 일을 하려면 오프셋 0부터 511까지를 블록 선택하고 삭제한 뒤 저장한다. 선택 길이가 하단 상태 표시줄에 **512**로 보이는지 반드시 확인한다. 한 바이트 어긋나면 전체 구조가 밀린다.

### 레시피 4 — 두 파일 비교로 차이 찾기

정상 파일과 조작된 파일이 함께 주어지는 문제에서 가장 빠른 길이다. HxD에는 파일 비교 기능이 있고, CLI에서는 `cmp -l`이 바이트 단위 차이를 전부 뱉는다.

```bash
cmp -l normal.png tampered.png | head -20
```

```text
    9   0  15
   10   0  61
   11   0 101
   12  15  15
```

`cmp -l`의 출력은 **1부터 세는 바이트 위치 + 왼쪽 파일의 값(8진수) + 오른쪽 파일의 값(8진수)** 이다. 8진수라는 점이 함정이다.

| cmp 출력 | 10진 위치(0-based) | 왼쪽 hex | 오른쪽 hex |
| --- | --- | --- | --- |
| `9 0 15` | 8 | `00` | `0D` |
| `10 0 61` | 9 | `00` | `31` |
| `11 0 101` | 10 | `00` | `41` |

차이 개수만 먼저 세는 것이 요령이다.

```bash
cmp -l normal.png tampered.png | wc -l
```

```text
17
```

17바이트만 다르다면 은닉된 메시지 길이일 가능성이 높다. 다른 값들만 모아 ASCII로 붙여 본다.

```bash
cmp -l normal.png tampered.png | awk '{printf "%c", strtonum("0"$3)}'
```

```text
flag{byte_diff_17}
```

Windows에서는 `fc /b`로 같은 비교를 한다.

```powershell
fc.exe /b .\normal.png .\tampered.png | Select-Object -First 20
```

`fc /b`는 오프셋과 값을 **16진수**로 보여주므로 변환이 필요 없다. 다만 차이가 많으면 출력이 길어져 `Select-Object`로 잘라야 한다.

### 레시피 5 — 특정 바이트 패턴 일괄 검색

"파일 안에 PNG가 몇 개 있나", "JPEG 시그니처가 어디에 또 있나"를 답해야 할 때다. HxD의 "모두 찾기"는 결과 목록과 개수를 주므로, 하나씩 `F3`으로 넘기는 것보다 먼저 개수를 본다.

CLI에서는 `grep -aob`가 hex 패턴의 **바이트 오프셋**을 준다.

```bash
grep -aob $'\x89PNG' dump.bin
```

```text
0:.PNG
1048576:.PNG
3145728:.PNG
```

| 옵션 | 뜻 |
| --- | --- |
| `-a` | 바이너리를 텍스트로 취급 (없으면 "Binary file matches"만 나온다) |
| `-o` | 매칭된 부분만 출력 |
| `-b` | 매칭의 바이트 오프셋을 앞에 붙인다 |

세 개의 PNG가 오프셋 0, 1048576, 3145728에 있다. 이 값들이 곧 레시피 7의 `skip=` 인자가 된다.

`binwalk`는 같은 일을 형식 인식까지 붙여서 해 준다. 목적이 다르다.

| 도구 | 강점 | 언제 |
| --- | --- | --- |
| HxD 검색 | 특정 구조의 정확한 위치를 눈으로 확인 | 오프셋을 하나 확정할 때 |
| `grep -aob` | 오프셋 목록을 스크립트로 넘길 수 있다 | 개수를 세고 일괄 추출할 때 |
| `binwalk` | 시그니처를 형식 이름으로 해석 | 무엇이 들었는지 모를 때 ([FOR-0045](./carving-strategy.html)) |

### 레시피 6 — 오프셋 계산

CSV나 도구 출력에서 얻은 번호를 HxD가 이해하는 오프셋으로 바꾸는 계산이다. **곱셈 결과를 10진수로 얻었으면 Goto 대화상자를 dec 모드로, hex로 변환했으면 hex 모드로 맞춘다.**

| 목표 | 계산식 | 예 |
| --- | --- | --- |
| MFT 레코드 위치 (`$MFT` 파일 내부) | `EntryNumber × 1024` | 12345 × 1024 = 12641280 = `0xC0F400` |
| MFT 레코드 위치 (이미지 전체 기준) | `파티션시작바이트 + $MFT클러스터 × 클러스터크기 + EntryNumber × 1024` | 세 항을 모두 더한다 |
| 클러스터의 절대 오프셋 | `파티션시작섹터 × 섹터크기 + 클러스터번호 × 클러스터크기` | 2048 × 512 + 500 × 4096 = 3096576 |
| 섹터의 절대 오프셋 | `LBA × 512` | LBA 63 → 32256 = `0x7E00` |
| slack 시작 지점 | 논리 파일 크기 | 3500 = `0xDAC` |

MFT 레코드 크기가 1024인지는 부트섹터에서 확인해야 하는 값이다. 대부분 1024지만 `fsstat` 출력의 레코드 크기를 보고 쓴다 ([FOR-0021](./mft-basics.html)).

계산이 맞았는지 확인하는 방법은 하나다. **이동한 자리에 그 구조의 시그니처가 있는가.**

```text
Ctrl+G -> hex -> C0F400 -> Enter

00C0F400  46 49 4C 45 30 00 03 00  ...
          ^^^^^^^^^^^ "FILE" -> MFT 레코드 맞다
```

`FILE`이 아니면 계산이 틀렸거나 레코드 크기가 1024가 아니다. 512로 다시 계산해 본다.

```bash
xxd -s 0xC0F400 -l 16 mft.bin
```

```text
00c0f400: 4649 4c45 3000 0300 0000 0000 0000 0000  FILE0...........
```

### 레시피 7 — 선택 영역만 별도 파일로 저장

파일 안에 박힌 다른 파일을 빼낼 때다. 필요한 값은 **시작 오프셋과 길이** 두 개다.

```text
1. Ctrl+G 로 시작 오프셋으로 이동
2. 블록 선택 대화상자에서 시작/길이를 입력  (또는 끝 오프셋에서 Shift+클릭)
3. 하단 상태 표시줄의 선택 길이가 의도한 값인지 확인
4. "선택 영역 저장" 계열 기능으로 새 파일에 쓴다
5. 새 파일을 file 로 검증
```

길이를 모를 때의 판단:

| 상황 | 길이 결정법 |
| --- | --- |
| 푸터가 있는 형식(PNG, JPEG, GIF) | 푸터 끝 오프셋 − 시작 오프셋 + 푸터 길이 |
| 헤더에 크기 필드가 있는 형식(ZIP 항목, PE) | 그 필드를 읽어서 계산 |
| 다음 시그니처가 보이는 경우 | 다음 시그니처 오프셋 − 시작 오프셋 |
| 아무 근거도 없을 때 | 넉넉하게 자르고 형식 도구가 뒤쪽 쓰레기를 무시하는지 본다 |

마지막 줄이 실전에서 가장 많이 쓰인다. PNG·JPEG·ZIP 디코더는 대체로 **뒤에 붙은 여분 바이트를 무시**하므로, 길이를 정확히 모르면 크게 잘라도 열린다.

```bash
dd if=dump.bin of=inner1.png bs=1 skip=1048576 count=1048576
file inner1.png
```

```text
inner1.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced
```

여러 개를 한 번에 뽑을 때는 오프셋 목록을 루프로 돌린다.

```bash
for off in 0 1048576 3145728; do
  dd if=dump.bin of=png_$off.png bs=1 skip=$off count=1048576 status=none
done
file png_*.png
```

### 레시피 8 — 체크섬·해시 계산

두 가지 목적이 있고, 섞으면 안 된다.

| 목적 | 무엇을 계산 | 성공 기준 |
| --- | --- | --- |
| 증거 무결성 | 원본 파일 전체의 SHA-256 | 작업 전후 값이 같다 |
| 산출물 동일성 판정 | 추출한 파일과 참조 파일의 MD5/SHA-256 | 두 값이 같다 |

HxD에는 체크섬·해시 계산 기능이 있어 **선택 구간만**의 값도 낼 수 있다. 파일 전체가 아니라 특정 청크만의 CRC를 검산할 때 유용하다. 지원 알고리즘 목록과 메뉴 위치는 버전에 따라 다르므로 화면에서 확인한다.

```powershell
Get-FileHash .\evidence.bin -Algorithm SHA256
Get-FileHash .\work.bin -Algorithm SHA256
```

```text
Algorithm  Hash                                                              Path
---------  ----                                                              ----
SHA256     9F2C...A17B                                                       ...\evidence.bin
SHA256     9F2C...A17B                                                       ...\work.bin
```

```bash
sha256sum evidence.bin work.bin
md5sum extracted.png reference.png
```

PNG 청크의 CRC32는 별도로 검산할 수 있다. **CRC 계산 범위는 청크 타입 4바이트 + 데이터이며, 길이 필드는 포함하지 않는다.** `pngcheck -v`가 청크별로 CRC 오류를 지적하므로 손으로 계산할 일은 거의 없다.

## 출력 필드 해석

편집 작업에서 판정 근거가 되는 표시는 네 개다.

| 표시 | 어디서 | 무엇을 판정 |
| --- | --- | --- |
| 파일 크기 | 하단 상태 표시줄 | Overwrite 편집 후 **변하지 않아야 한다**. 변했으면 Insert 모드였다 |
| 선택 길이 | 하단 상태 표시줄 | 잘라낼 바이트 수, 구조 크기 검산 |
| 현재 오프셋 | 하단 상태 표시줄 | Goto 계산이 맞았는지 |
| 편집 모드 | 하단 상태 표시줄 | Overwrite / Insert |

검증 도구의 출력 해석:

| 출력 | 뜻 | 다음 |
| --- | --- | --- |
| `file` → 구체적 형식명 + 해상도 | 헤더가 정상적으로 파싱됨 | 열어서 내용 확인 |
| `file` → `data` | 아직 시그니처가 안 맞는다 | 오프셋 0을 다시 본다 |
| `pngcheck` → `OK` | 모든 청크와 CRC가 정상 | 끝 |
| `pngcheck` → `CRC error in chunk IHDR` | 시그니처는 맞지만 뒤가 밀렸다 | Insert 사고. 사본에서 다시 |
| `pngcheck` → `inflate error` | 구조는 맞고 IDAT가 부족하다 | 잘린 파일. 뷰어로 부분 렌더링 |
| `7z t` → `Everything is Ok` | ZIP 무결성 통과 | 압축 해제 |
| `7z t` → `Data Error` | CRC 불일치 | 내용은 나올 수 있다. 강제 추출 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 복구한 이미지 | exiftool로 메타데이터, zsteg/steghide로 스테가노 |
| 복구한 ZIP | 내부 파일 목록 → 중첩 압축 여부 |
| 추출한 내부 파일의 오프셋 목록 | `binwalk -e`로 나머지도 일괄 추출 |
| 두 파일 비교로 얻은 차이 바이트 | ASCII 변환 → 은닉 메시지 |
| 확인한 매직 바이트 | 형식별 전용 도구 ([FOR-0001](./30sec-triage.html)) |
| 확장자와 다른 헤더 | 대량 위조 스캔 ([FOR-0036](./signature-extension-mismatch.html)) |
| MFT 레코드 오프셋에서 읽은 값 | `$SI`/`$FN` 시각 비교 ([FOR-0038](./timestomp-detection.html)) |
| 논리 크기 이후 구간 | slack 추출 ([FOR-0034](./file-slack.html)) |

## 흔한 함정

- **증거물 원본을 열어 편집하는 것.** HxD는 뷰어가 아니라 에디터이고, 저장까지 되면 복구 수단이 없다. 사본을 만들고 원본 해시를 기록한 뒤 사본만 연다.
- **형식을 확정하지 않고 시그니처를 써넣는 것.** 오프셋 8~15의 내부 구조를 보지 않고 PNG 시그니처를 쓰면 JPEG를 PNG로 위조한 파일이 된다. 디코더는 열지 못하고, 왜 안 열리는지도 알 수 없게 된다. 항상 내부 구조로 형식을 확정하고 쓴다.
- **레시피 2에서 Insert 모드를 다시 Overwrite로 돌려놓지 않는 것.** 푸터 추가는 Insert가 맞지만, 그 상태로 다음 편집을 하면 파일이 밀린다. 붙인 ���후 모드를 되돌린다.
- **`cmp -l`의 값을 16진수로 읽는 것.** `cmp -l`은 **8진수**를 출력하고 위치는 **1부터** 센다. `61`은 0x61이 아니라 0x31이다. 변환하지 않으면 엉뚱한 문자열이 나온다. Windows `fc /b`는 16진수라 헷갈리지 않는다.
- **`dd bs=1`을 큰 파일에 쓰는 것.** 1바이트씩 읽어 수 GB에서 수십 분이 걸린다. 오프셋이 블록 크기의 배수면 `bs=4096 skip=N`으로 바꾸고, 아니면 `skip`을 `bs=1`로 하되 `count`를 크게 줘서 호출 횟수를 줄인다.
- **잘린 파일에 푸터를 붙여 놓고 "복구했다"고 결론 내리는 것.** 없어진 데이터는 돌아오지 않는다. 푸터 추가는 디코더가 부분 렌더링하도록 유도하는 것뿐이다. 답이 잘린 뒤쪽에 있으면 카빙이나 slack에서 나머지 조각을 찾아야 한다 ([FOR-0047](./photorec.html)).
- **`grep`에 `-a`를 빼는 것.** 바이너리 파일이면 `Binary file dump.bin matches` 한 줄만 나오고 오프셋을 못 본다. `-aob` 세 개를 세트로 기억한다.
- **선택 길이를 확인하지 않고 삭제하는 것.** 512바이트를 지우려다 511이나 513을 지우면 뒤쪽 전체가 어긋난다. 상태 표시줄의 숫자를 눈으로 읽고 삭제한다.
- **Goto의 hex/dec 모드를 계산 결과의 진법과 맞추지 않는 것.** 12641280(dec)과 12641280(hex)은 완전히 다른 위치다. 이동 직후 그 자리에 시그니처가 있는지로 검산한다.
- **편집 후 검증을 생략하는 것.** 헤더만 맞고 내부가 손상된 경우가 흔하다. 형식별 검사기(`pngcheck`, `7z t`, `exiftool`) 중 하나는 반드시 돌린다.

## 교차검증

```powershell
# 1) 원본이 오염되지 않았음을 증명
Get-FileHash .\evidence.bin -Algorithm SHA256
```

```bash
# 2) HxD 로 본 값과 CLI 값이 같은가
xxd -s 0xC0F400 -l 32 work.bin

# 3) 편집 전후 어디가 달라졌는지 확정
cmp -l original_copy.bin work.bin

# 4) 복구 결과를 두 도구로
file work.png && pngcheck -v work.png

# 5) 추출한 파일이 참조 파일과 동일한가
sha256sum extracted.png reference.png

# 6) 앞에 붙은 바이트 수가 맞았는가 (잘라낸 파일의 오프셋 0)
xxd -l 16 fixed.png
```

같은 오프셋에서 HxD와 `xxd`가 다른 값을 보이면 기준점이 다른 것이다. 파일로 열었는지 디스크/이미지로 열었는지, 파티션 시작 오프셋을 더했는지 확인한다.

## mini walkthrough

```text
문제:
"사진 파일이 손상되었습니다. 사진에 적힌 문자열을 제출하세요."
첨부: photo_broken (확장자 없음, 512,000 바이트)

1. 트리아지
   file photo_broken
   -> photo_broken: data

   xxd -l 32 photo_broken
   00000000: 0000 0000 0000 0000 0000 000d 4948 4452  ............IHDR
   00000010: 0000 0400 0000 0300 0806 0000 0027 4c8e  .............'L.

   오프셋 8~11 = 00 00 00 0D (13), 오프셋 12~15 = "IHDR"
   -> PNG 확정. 앞 8바이트 시그니처만 0으로 덮였다.

2. 첫 시도 (실패):
   사본을 만들지 않고 HxD 로 photo_broken 을 바로 열었다.
   오프셋 0 에 89 50 4E 47 0D 0A 1A 0A 를 입력하고 저장.

   file photo_broken
   -> PNG image data, 1024 x 768, 8-bit/color RGBA, non-interlaced

   뷰어로 열었더니 위쪽 1/3 만 보이고 아래는 회색.
   pngcheck -v photo_broken
   -> chunk IHDR / IDAT ... 
      ERROR: unexpected end of file

   왜 틀렸나 (두 가지):
   (a) 파일 끝을 확인하지 않았다. 시그니처만 문제라고 단정했다.
   (b) 원본을 직접 편집했다. 되돌릴 사본이 없어 원래 상태를 잃었다.

3. 접근 변경 — 사본부터, 그리고 파일 "끝"도 본다
   Copy-Item .\photo_broken .\work.png     (문제 파일 재다운로드 후)
   Get-FileHash .\photo_broken,.\work.png -Algorithm SHA256   -> 동일

   tail -c 16 work.png | xxd
   00000000: 3f2a 91cc 1b7e 4402 aa38 0f19 c5d1 7b60  ?*...~D..8....{`

   IEND (49 45 4E 44 AE 42 60 82) 가 없다. 파일이 뒤에서 잘렸다.

   grep -aob 'IEND' work.png
   -> (출력 없음)  IEND 청크 자체가 존재하지 않는다.

4. 레시피 1 + 레시피 2 를 함께 적용
   # 시그니처 복구 (CLI 로, 원본 보존)
   printf '\x89PNG\r\n\x1a\n' > fixed.png
   tail -c +9 work.png >> fixed.png

   # 푸터 추가
   printf '\x00\x00\x00\x00IEND\xae\x42\x60\x82' >> fixed.png

   ls -l fixed.png
   -> 512012   (512000 + 12 바이트)

5. 검증
   file fixed.png
   -> PNG image data, 1024 x 768, 8-bit/color RGBA, non-interlaced

   pngcheck -v fixed.png
   -> chunk IHDR at offset 0x0000c, length 13
        1024 x 768 image, 32-bit RGB+alpha, non-interlaced
      chunk IDAT at offset 0x00025, length 65536
      ...
      chunk IEND at offset 0x7d00c, length 0
      ERROR: zlib: inflate error = -5 (buffer error)

   여전히 에러지만 IEND 가 인식되고 IHDR 이 완전하다.
   이제 뷰어가 잘린 지점까지 그려 준다.

6. 열어서 확인
   위에서 약 2/3 지점까지 렌더링. 그 안에 문자열이 보인다:
   flag{tru7ca73d_png_r3nd3rs_p4r7ial}

7. 잘린 나머지를 찾아 보완 (선택)
   binwalk photo_broken
   -> 다른 시그니처 없음. 조각이 다른 파일에 있는 문제는 아니다.

정답: flag{tru7ca73d_png_r3nd3rs_p4r7ial}
```

2→3단계가 이 글의 요지다. **시그니처를 고쳐 `file`이 정상 답을 준 순간 "복구 완료"라고 판단한 것이 실패의 원인이었다.** 헤더는 파일의 앞 8바이트일 뿐이고, 손상은 앞과 뒤에 동시에 있을 수 있다. 레시피 1을 적용하기 전에 항상 **끝 16바이트도 함께 읽는 습관**이 이 문제를 한 번에 풀게 한다. 그리고 사본을 만들지 않아 문제 파일을 다시 받은 것은 순수한 시간 손실이었다.

## 막혔을 때 다음 체크

1. 사본에서 작업하고 있는가 — 원본 해시가 기록되어 있는가
2. 하단 상태 표시줄의 편집 모드가 의도한 모드인가 (편집=Overwrite, 푸터 추가=Insert)
3. 편집 후 파일 크기가 예상대로인가 (Overwrite는 불변, Insert는 정확히 붙인 만큼 증가)
4. 파일 **끝** 16바이트를 확인했는가 — 앞만 고치고 끝나는 경우는 절반뿐이다
5. 오프셋 8~15로 형식을 확정했는가, 아니면 확장자를 믿었는가
6. `binwalk`로 앞 패딩과 내부 임베디드 파일을 확인했는가
7. `grep -aob`에 `-a`를 넣었는가
8. `cmp -l` 출력을 8진수로 읽었는가
9. Goto의 진법이 계산 결과와 맞는가 — 이동한 자리에 시그니처가 있는가
10. 추출 길이를 넉넉하게 잡아 봤는가 — 대부분의 디코더는 뒤쪽 여분을 무시한다
11. `pngcheck`/`7z t`/`exiftool` 중 하나로 검증했는가
12. 잘린 파일이면 뷰어로 **부분 렌더링**을 시도했는가

## 출처

- SRC-088 — HxD 문서(mh-nexus): 파일 열기, 오프셋 이동(Goto), 검색과 "모두 찾기", 블록 선택과 선택 영역 저장, 삽입/덮어쓰기 모드, 상태 표시줄 정보, 체크섬·해시 계산 기능의 존재
- SRC-089 — Wikipedia, List of file signatures: 레시피 1·2 표의 형식별 헤더/푸터 바이트값 (PNG 시그니처, JPEG `FF D8 FF`/`FF D9`, GIF `GIF89a`/`3B`, ZIP `PK\x03\x04`/`PK\x05\x06`, PDF `%PDF-`)
- SRC-040 — PNG Specification (W3C): 청크 구조(길이 4바이트 + 타입 4바이트 + 데이터 + CRC 4바이트), `IEND` 청크가 길이 0이라는 점, CRC32 계산 범위가 청크 타입과 데이터라는 점
- **HxD의 메뉴 라벨·대화상자 항목 이름은 버전과 언어 설정에 따라 다르다.** 블록 선택, 선택 영역 저장, 파일 비교, 체크섬 계산의 메뉴 위치와 지원 알고리즘 목록은 실제 화면에서 확인할 것
- `IEND` 청크의 고정 CRC32 값 `AE 42 60 82`는 정상 PNG 파일의 마지막 4바이트를 `xxd`로 직접 확인해 검산할 수 있다
- MFT 레코드 크기가 1024바이트라는 전제는 `fsstat` 출력의 레코드 크기로 확인할 것. 볼륨 설정에 따라 다를 수 있다
- `awk`의 `strtonum`은 GNU awk 확장이다. 다른 awk에서는 동작하지 않으므로 Python 등으로 대체할 것
</content>
