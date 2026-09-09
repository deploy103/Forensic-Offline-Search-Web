---
id: FOR-0036
title: "확장자 위조 파일 대량 스캔: 시그니처와 확장자 불일치 찾기"
slug: "signature-extension-mismatch"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["file signature", "magic byte", "MIME type", "Extension Mismatch Detected", "footer"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["file", "Autopsy", "Detect It Easy", "TrID", "binwalk", "7-Zip", "PowerShell", "Python", "Sleuth Kit", "MFTECmd"]
commands: ["find . -type f -exec file --mime-type {} + > types.txt", "file -b --mime-type target.jpg", "file -k -z target.bin", "binwalk -B target.bin", "7z l target.jpg"]
regex_patterns: ["\\.(jpg|png|gif)$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Extension", "MIME Type", "Name", "Location"]
file_formats: ["jpeg", "png", "gif", "pdf", "zip", "docx", "apk", "jar", "7z", "gzip", "pe"]
primary_terms: ["확장자 위조", "extension mismatch", "시그니처 불일치"]
keywords: ["확장자 위조", "extension mismatch", "file signature", "magic byte", "MIME Type", "시그니처 불일치", "푸터", "EOCD", "IEND", "EOI", "TrID", "Detect It Easy"]
aliases: ["확장자 위조 찾기", "시그니처 불일치", "extension mismatch", "가짜 jpg", "확장자 바꾼 파일", "대량 스캔 file", "mime 비교"]
symptom_keywords: ["확장자가 거짓인 파일을 전부 찾고 싶다", "jpg인데 열리지 않는다", "docx가 zip으로 나온다", "오탐이 너무 많다", "어떤 파일이 위조인지 모르겠다"]
related: ["FOR-0001", "FOR-0037", "FOR-0018"]
source_ids: ["SRC-089", "SRC-033", "SRC-042"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

파일 하나가 아니라 **수천 개를 한 번에** 검사해야 할 때는 "확장자에서 기대되는 형식"과 "실제 헤더가 말하는 형식"을 표로 만들어 기계적으로 비교한다. Autopsy의 Extension Mismatch Detector가 가장 빠르고, CLI에서는 `find . -type f -exec file --mime-type {} +` 결과를 확장자와 대조하는 스크립트가 정답이다.

## 어떤 문제에서 필요한가

- 이미지/폴더에 파일이 수백~수만 개 있고 그중 **위조된 것만** 골라내야 하는 경우
- 지문이 "숨겨진 파일", "확장자를 바꾼 파일", "위장된 실행 파일"을 언급하는 경우
- 사진 폴더 안에 압축 파일이나 PE가 섞여 있는지 확인해야 하는 경우
- `$MFT` 목록만 있고 실제 파일은 이미지 안에 있는 경우
- 반대로, 정상인데 위조로 잡히는 오탐을 줄여야 하는 경우

단일 파일 한 개를 판정하는 절차는 [FOR-0001](./30sec-triage.html)에 있다. 이 글은 그 판정을 **대량으로 자동화**하고, 자동화가 만들어내는 **오탐을 걷어내는 방법**을 다룬다.

## 문제에서 처음 볼 단서

1. 파일 개수 — 수십 개면 손으로, 수백 개 이상이면 스크립트/Autopsy
2. 확장자 분포 — `.jpg`만 300개인 폴더에서 1~2개가 튄다면 그것이 답이다
3. **파일 크기 이상치** — 다른 사진은 2~4 MB인데 하나가 180 KB거나 40 MB인 경우
4. `file` 판정이 `data`인 파일 — 헤더가 없거나 잘렸거나 암호화됐다
5. 확장자가 아예 없는 파일 — 비교 대상이 없으므로 별도 처리한다

## 30초 절차

```bash
find . -type f -exec file --mime-type {} + > types.txt
```

이 파일 하나로 대조를 끝낸다.

```bash
# 확장자별 MIME 분포 — 한 확장자에 여러 MIME 이 섞이면 그 안에 위조가 있다
awk -F': ' '{print $2}' types.txt | sort | uniq -c | sort -nr | head -20

# .jpg 인데 image/jpeg 가 아닌 것
grep -i '\.jpg:' types.txt | grep -v 'image/jpeg'

# .png 인데 image/png 가 아닌 것
grep -i '\.png:' types.txt | grep -v 'image/png'
```

```powershell
# Windows 한 줄 — 확장자별 실제 헤더 4바이트 분포
Get-ChildItem -Recurse -Filter *.jpg | ForEach-Object {
  ($_.Name), (( Get-Content $_.FullName -Encoding Byte -TotalCount 4 |
    ForEach-Object { $_.ToString('X2') }) -join '') -join '  '
} | Group-Object { $_.Split('  ')[-1] } | Select-Object Count, Name
```

## 상세 절차

### 1단계 — 확장자에서 기대되는 값 표를 먼저 고정한다

대량 비교는 이 표가 있어야 성립한다. **헤더만이 아니라 푸터도 함께 적어 둔다** (5단계에서 쓴다).

| 확장자 | `file --mime-type` 기대값 | 헤더 (hex) | 푸터 (hex / ASCII) |
| --- | --- | --- | --- |
| `.jpg` `.jpeg` | `image/jpeg` | `FF D8 FF` | `FF D9` (EOI) |
| `.png` | `image/png` | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` (IEND+CRC) |
| `.gif` | `image/gif` | `47 49 46 38` (`GIF8`) | `00 3B` |
| `.bmp` | `image/bmp` | `42 4D` (`BM`) | — |
| `.pdf` | `application/pdf` | `25 50 44 46` (`%PDF`) | `25 25 45 4F 46` (`%%EOF`) |
| `.zip` | `application/zip` | `50 4B 03 04` | `50 4B 05 06` (EOCD) |
| `.docx` `.xlsx` `.pptx` | OOXML MIME (또는 `application/zip`) | `50 4B 03 04` | `50 4B 05 06` |
| `.apk` `.jar` | `application/java-archive` / `application/zip` | `50 4B 03 04` | `50 4B 05 06` |
| `.7z` | `application/x-7z-compressed` | `37 7A BC AF 27 1C` | — |
| `.gz` `.tgz` | `application/gzip` | `1F 8B` | — |
| `.rar` | `application/x-rar` | `52 61 72 21 1A 07` | — |
| `.exe` `.dll` `.sys` | `application/x-dosexec` | `4D 5A` (`MZ`) | — |
| `.txt` `.log` `.csv` | `text/plain` 계열 | (없음) | — |
| `.sqlite` `.db` | `application/x-sqlite3` | `53 51 4C 69 74 65 20 66` | — |
| `.evtx` | `application/octet-stream` | `45 6C 66 46 69 6C 65 00` | — |

`file`의 MIME 문자열은 libmagic 버전에 따라 표기가 다르다(`application/x-rar` vs `application/vnd.rar`, `application/gzip` vs `application/x-gzip`). 그래서 **스크립트에는 "정확히 같음"이 아니라 "기대 집합에 포함"으로 비교 조건을 만든다.**

### 2단계 — Autopsy: 가장 적은 노동으로 가장 넓게

```text
Add Data Source 시 Ingest Modules:
  [v] File Type Identification        <- 전제 모듈. 반드시 함께 켠다
  [v] Extension Mismatch Detector
결과: Results > Interesting Items > Extension Mismatch Detected
```

```text
Name              Location                           Extension  MIME Type
vacation.jpg      /Users/jhkim/Pictures/             jpg        application/zip
notes.txt         /Users/jhkim/Desktop/              txt        application/x-dosexec
logo.png          /Users/jhkim/Downloads/            png        application/x-7z-compressed
```

`Views > File Types > By MIME Type`도 같은 목적에 쓴다. **`By Extension`이 아니라 `By MIME Type`을 봐야 한다** — 위조 파일은 `By Extension`에서 잘못된 분류에 들어가 있다 ([FOR-0018](./autopsy-ingest.html)).

Autopsy의 장점은 삭제 파일과 카빙 결과까지 함께 검사한다는 점이고, 단점은 오탐 규칙을 사용자가 조정하기 번거롭다는 점이다. 그래서 **Autopsy로 후보를 얻고, CLI로 검산한다.**

### 3단계 — bash: 확장자 대 MIME 비교 스크립트

```bash
#!/usr/bin/env bash
# ext_vs_type.sh — 확장자와 실제 형식이 어긋나는 파일만 출력
declare -A EXPECT=(
  [jpg]="image/jpeg"            [jpeg]="image/jpeg"
  [png]="image/png"             [gif]="image/gif"
  [bmp]="image/bmp"             [pdf]="application/pdf"
  [zip]="application/zip"       [7z]="application/x-7z-compressed"
  [gz]="application/gzip|application/x-gzip"
  [rar]="application/x-rar|application/vnd.rar"
  [exe]="application/x-dosexec" [dll]="application/x-dosexec"
  [txt]="text/"                 [csv]="text/"
  [docx]="application/zip|officedocument"
  [xlsx]="application/zip|officedocument"
  [apk]="application/zip|java-archive|android"
  [mp3]="audio/mpeg"            [mp4]="video/mp4"
  [sqlite]="application/x-sqlite3"
)

find "${1:-.}" -type f -print0 | while IFS= read -r -d '' f; do
  base="${f##*/}"
  [[ "$base" != *.* ]] && continue          # 확장자 없음 -> 비교 불가
  ext="${base##*.}"
  ext="${ext,,}"
  exp="${EXPECT[$ext]}"
  [[ -z "$exp" ]] && continue               # 표에 없는 확장자는 건너뛴다
  act="$(file -b --mime-type "$f" 2>/dev/null)"
  if ! grep -qE "$exp" <<<"$act"; then
    printf 'MISMATCH\t%s\text=%s\tactual=%s\n' "$f" "$ext" "$act"
  fi
done
```

```text
$ ./ext_vs_type.sh /mnt/evidence/Users
MISMATCH  /mnt/evidence/Users/jhkim/Pictures/IMG_2841.jpg  ext=jpg  actual=application/zip
MISMATCH  /mnt/evidence/Users/jhkim/Desktop/notes.txt      ext=txt  actual=application/x-dosexec
MISMATCH  /mnt/evidence/Users/jhkim/Music/song.mp3         ext=mp3  actual=application/octet-stream
```

`grep -qE`로 비교하기 때문에 `EXPECT` 값에 `|`로 여러 후보를 넣을 수 있고, libmagic 표기 차이에 견딘다.

### 4단계 — PowerShell / Python: 헤더 바이트로 직접 비교

`file`이 없는 Windows에서는 헤더 바이트를 직접 읽는다. libmagic에 의존하지 않으므로 판정 기준이 명확한 대신, 표에 없는 형식은 잡지 못한다.

```powershell
# ExtVsHeader.ps1
$Sig = @{
  '.jpg'  = @('FFD8FF');            '.jpeg' = @('FFD8FF')
  '.png'  = @('89504E470D0A1A0A');  '.gif'  = @('47494638')
  '.bmp'  = @('424D');              '.pdf'  = @('25504446')
  '.zip'  = @('504B0304','504B0506','504B0708')
  '.docx' = @('504B0304');          '.xlsx' = @('504B0304')
  '.apk'  = @('504B0304');          '.jar'  = @('504B0304')
  '.7z'   = @('377ABCAF271C');      '.gz'   = @('1F8B')
  '.rar'  = @('526172211A07');      '.exe'  = @('4D5A')
  '.dll'  = @('4D5A');              '.sqlite'= @('53514C69746520')
  '.evtx' = @('456C6646696C6500')
}

Get-ChildItem -Path . -Recurse -File | ForEach-Object {
  $ext = $_.Extension.ToLower()
  if (-not $Sig.ContainsKey($ext)) { return }
  # PowerShell 5.1: -Encoding Byte / PowerShell 7+: -AsByteStream
  $bytes = Get-Content -Path $_.FullName -Encoding Byte -TotalCount 8 -ErrorAction SilentlyContinue
  if (-not $bytes) { return }
  $hex = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
  $ok = $false
  foreach ($s in $Sig[$ext]) { if ($hex.StartsWith($s)) { $ok = $true } }
  if (-not $ok) {
    [pscustomobject]@{
      Path = $_.FullName; Ext = $ext; Size = $_.Length; Head = $hex
    }
  }
} | Format-Table -AutoSize
```

```text
Path                                        Ext  Size    Head
----                                        ---  ----    ----
C:\case\Pictures\IMG_2841.jpg               .jpg 184320  504B03040A0000
C:\case\Desktop\notes.txt                   .txt 451584  4D5A900003000000
```

```python
#!/usr/bin/env python3
# ext_vs_header.py — 헤더 기반 대량 대조 (오프셋 있는 형식도 처리)
import os, sys

SIG = [
    (b"\xFF\xD8\xFF",                 {"jpg", "jpeg"}),
    (b"\x89PNG\r\n\x1a\n",            {"png"}),
    (b"GIF8",                         {"gif"}),
    (b"BM",                           {"bmp"}),
    (b"%PDF",                         {"pdf"}),
    (b"PK\x03\x04",                   {"zip", "docx", "xlsx", "pptx",
                                       "apk", "jar", "odt", "epub"}),
    (b"7z\xBC\xAF\x27\x1C",           {"7z"}),
    (b"\x1F\x8B",                     {"gz", "tgz"}),
    (b"Rar!\x1A\x07",                 {"rar"}),
    (b"MZ",                           {"exe", "dll", "sys", "ocx", "scr"}),
    (b"SQLite format 3\x00",          {"sqlite", "db", "sqlite3"}),
    (b"ElfFile\x00",                  {"evtx"}),
    (b"regf",                         {"dat", "hiv"}),
    (b"\x7FELF",                      {"so", "elf", "o"}),
    (b"ID3",                          {"mp3"}),
    (b"\xFF\xFB",                     {"mp3"}),
    (b"RIFF",                         {"wav", "avi", "webp"}),
]
# 오프셋 4에 나타나는 시그니처
SIG_AT4 = [(b"ftyp", {"mp4", "m4a", "mov", "3gp", "heic"})]


def identify(head: bytes):
    for magic, exts in SIG:
        if head.startswith(magic):
            return magic, exts
    for magic, exts in SIG_AT4:
        if head[4:4 + len(magic)] == magic:
            return magic, exts
    return None, None


def main(root):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            if "." not in name:
                continue
            ext = name.rsplit(".", 1)[1].lower()
            try:
                with open(path, "rb") as fh:
                    head = fh.read(32)
            except OSError:
                continue
            magic, exts = identify(head)
            if magic is None:
                if ext not in {"txt", "log", "csv", "xml", "json", "html",
                               "ini", "md", "bin", "dat"}:
                    print(f"UNKNOWN\t{path}\text={ext}\thead={head[:8].hex()}")
                continue
            if ext not in exts:
                print(f"MISMATCH\t{path}\text={ext}\t"
                      f"actual={sorted(exts)}\thead={head[:8].hex()}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
```

```text
$ python3 ext_vs_header.py /mnt/evidence/Users
MISMATCH  .../Pictures/IMG_2841.jpg  ext=jpg  actual=['apk','docx',...,'zip']  head=504b03040a000000
MISMATCH  .../Desktop/notes.txt      ext=txt  actual=['dll','exe',...]         head=4d5a900003000000
UNKNOWN   .../Music/song.mp3         ext=mp3  head=00000000deadbeef
```

Python 판은 `PK 03 04`를 여러 확장자에 **동시에 허용**하므로 `docx`를 `zip`이라고 오탐하지 않는다. 이것이 6단계에서 말하는 오탐 억제의 핵심 설계다.

### 5단계 — 헤더만으로 부족한 경우: 푸터와 내부 이름

헤더가 정상인데도 파일이 위조·조작된 경우가 있다. 이때는 끝을 본다.

```bash
# 푸터 확인 — 마지막 16바이트
tail -c 16 target.jpg | xxd

# JPEG: FF D9 로 끝나야 한다. 뒤에 데이터가 더 붙어 있으면 은닉
xxd target.jpg | tail -3

# PNG: IEND(49 45 4E 44) + CRC(AE 42 60 82) 이후에 바이트가 있으면 붙인 것
xxd target.png | tail -3

# ZIP: EOCD(50 4B 05 06) 위치 확인
grep -aob $'\x50\x4b\x05\x06' target.zip | tail -1

# 내부에 다른 파일이 있는가
binwalk target.jpg
binwalk -B target.bin        # 시그니처 스캔만
```

| 관찰 | 해석 | 다음 |
| --- | --- | --- |
| JPEG가 `FF D9` 뒤에 수백 KB 더 있다 | 파일 뒤에 다른 파일을 이어 붙였다 | `binwalk -e`, `7z x` 시도 |
| PNG IEND 뒤에 데이터가 있다 | 동일 | `dd`로 잘라내 별도 파일로 |
| ZIP EOCD가 파일 끝이 아니다 | 앞에 다른 파일이 붙어 있거나 EOCD가 여러 개 | 오프셋 계산 후 분리 |
| 헤더는 PNG, 푸터는 `FF D9` | **헤더만 바꿔치기한 JPEG** | 헤더를 원래대로 복구 ([FOR-0037](./hxd-header-check.html)) |
| `%PDF`로 시작하는데 `%%EOF` 없음 | 잘린 PDF 또는 카빙 실패 | 크기와 원본 대조 |

ZIP 기반 형식은 **내부 파일 이름으로만 구별된다.** `file`도 이 방법을 쓴다.

```bash
7z l target.zip | head -20
```

| 내부에 있는 항목 | 실제 형식 |
| --- | --- |
| `[Content_Types].xml` + `word/document.xml` | `.docx` |
| `[Content_Types].xml` + `xl/workbook.xml` | `.xlsx` |
| `[Content_Types].xml` + `ppt/presentation.xml` | `.pptx` |
| `AndroidManifest.xml` + `classes.dex` | `.apk` |
| `META-INF/MANIFEST.MF` (+ `.class`) | `.jar` |
| 첫 항목이 `mimetype` = `application/epub+zip` | `.epub` |
| 첫 항목이 `mimetype` = `application/vnd.oasis...` | `.odt`/`.ods` |
| 그 외 임의 파일 목록 | 순수 `.zip` |

### 6단계 — 도구 교차: TrID / Detect It Easy

`file`이 `data`나 `application/octet-stream`을 반환할 때 2차 판정에 쓴다.

| 도구 | 특징 | 출력 |
| --- | --- | --- |
| **`file`** (libmagic) | 가장 빠르고 스크립트 친화적 | `image/jpeg` 같은 MIME 또는 설명 문자열 |
| **Detect It Easy (DIE)** | 실행 파일/패커/컴파일러 판정이 강하다 | 형식 + 패커/컴파일러 이름 |
| **TrID** | 시그니처 DB 기반. 후보를 **확률(%)로 여러 개** 제시한다 | 후보 목록 + 매칭 비율 |
| **`binwalk`** | 파일 **내부 전체**를 스캔해 오프셋별 시그니처 나열 | 오프셋 + 형식 |
| **`7z l`** | 컨테이너 내부 목록 | 내부 파일 이름 |

여러 후보를 확률로 보여주는 도구는 "확실히 무엇이다"보다 "무엇일 가능성이 높다"를 준다. **최종 판정은 헤더 바이트를 직접 본 결과로 한다.**

```bash
file -b --mime-type target.bin      # 1차
file -k target.bin                  # 여러 매칭을 모두 표시
file -z target.gz                   # 압축 내부까지 판정
binwalk -B target.bin               # 내부 시그니처 전체
```

### 7단계 — `$MFT` 목록과 실제 헤더 대조

이미지를 마운트하지 않고 `$MFT` 파서 CSV만으로도 후보를 좁힐 수 있다.

```powershell
# 1) 확장자별 개수와 크기 분포 — 이상치를 먼저 본다
Import-Csv .\mft.csv | Where-Object { $_.IsDirectory -eq 'False' } |
  Group-Object Extension | Sort-Object Count -Descending |
  Select-Object Count, Name -First 20

# 2) .jpg 인데 크기가 비정상적으로 작거나 큰 것
Import-Csv .\mft.csv |
  Where-Object { $_.Extension -eq '.jpg' -and [int64]$_.FileSize -lt 40000 } |
  Select-Object EntryNumber, ParentPath, FileName, FileSize
```

```bash
# 3) 후보의 EntryNumber 로 헤더만 뽑아 확인 (이미지 마운트 불필요)
for e in 84213 84590 91002; do
  printf '%s\t' "$e"
  icat -o 2048 image.dd "$e" 2>/dev/null | head -c 8 | xxd -p
done
```

```text
84213   504b03040a000000
84590   ffd8ffe000104a46
91002   4d5a900003000000
```

`84213`은 `.jpg`인데 ZIP, `91002`는 `.txt`인데 PE다. `$MFT`의 `Extension` 컬럼은 **파일 이름에서 잘라낸 문자열일 뿐 내용과 무관하다** ([FOR-0021](./mft-basics.html)).

## 출력 필드 해석

| 출처 | 필드 | 진실 여부 |
| --- | --- | --- |
| `$MFT` / 탐색기 | `Extension`, 파일 이름 | **거짓일 수 있다.** 사용자가 정한 문자열 |
| `file --mime-type` | MIME 문자열 | 헤더 기반. 대체로 진실이지만 앞부분이 조작되면 속는다 |
| Autopsy | `MIME Type` | 위와 동일 기반 |
| 직접 읽은 헤더 바이트 | hex | **가장 신뢰할 수 있다** |
| 푸터 바이트 | hex | 헤더가 조작된 경우 진짜 형식을 알려준다 |
| 컨테이너 내부 이름 | `7z l` 목록 | ZIP 계열 세부 형식의 유일한 근거 |

`file` 출력에서 특히 주의할 값:

| 출력 | 의미 |
| --- | --- |
| `application/octet-stream` | libmagic이 판정 실패. 헤더 없음/암호화/잘림 |
| `text/plain` | 헤더가 없는 텍스트. 확장자 비교가 거의 무의미하다 |
| `application/zip` (확장자가 `docx`) | **오탐일 가능성이 높다.** 내부 이름을 확인한다 |
| `data` (설명 모드) | 위 `octet-stream`과 같은 상황 |
| `empty` | 0바이트 파일 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| ZIP으로 판정된 `.jpg` | `7z l` → `7z x`로 내부 확인 ([FOR-0001](./30sec-triage.html)) |
| PE로 판정된 `.txt` | DIE/`strings`, 실행 흔적(Prefetch/Amcache/4688) |
| 헤더 손상으로 안 열리는 파일 | HxD로 시그니처 수동 복구 ([FOR-0037](./hxd-header-check.html)) |
| 위조 파일의 생성 시각 | `$MFT` `$SI`/`$FN` 비교, timestomp 여부 ([FOR-0038](./timestomp-detection.html)) |
| 이름을 바꾼 시점 | `$UsnJrnl`의 `RENAME_OLD_NAME`/`RENAME_NEW_NAME` ([FOR-0039](./filename-change-traces.html)) |
| 다운로드 출처 | `Zone.Identifier` ADS ([FOR-0035](./alternate-data-streams.html)) |
| 푸터 뒤에 붙은 데이터 | `binwalk -e`로 분리 후 재판정 |
| 후보가 너무 많다 | Autopsy로 삭제 파일·카빙 결과까지 일괄 검사 ([FOR-0018](./autopsy-ingest.html)) |

## 흔한 함정

- **`docx`/`xlsx`/`apk`/`jar`를 ZIP 오탐으로 대량 보고하는 것.** 이들은 **정상적으로** `PK 03 04`로 시작한다. 왜 틀리는가: ZIP은 컨테이너이고 이들은 그 컨테이너를 쓰는 포맷이다. 어떻게: 확장자 하나에 기대 시그니처를 **집합**으로 허용하고, 세부 구분은 `7z l`의 내부 이름으로 한다.
- **텍스트 파일을 위조로 판정하는 것.** `.txt`/`.csv`/`.log`/`.json`은 매직 바이트가 없다. 비교 대상에서 제외하거나 `text/`로 시작하는지만 본다.
- **`file` MIME 문자열을 정확히 일치로 비교하는 것.** libmagic 버전마다 `application/gzip` vs `application/x-gzip`처럼 표기가 다르다. 정규식/부분 일치로 비교한다.
- **첫 4바이트만 읽는 것.** `ftyp`(mp4/mov/heic)는 **오프셋 4**에 있고, TIFF/RIFF 계열은 하위 타입을 뒤에서 구분한다. 최소 16~32바이트를 읽는다.
- **헤더만 확인하고 끝내는 것.** 헤더를 정상 시그니처로 덮어써 위장하는 문제가 많다. 푸터(`FF D9`, `IEND`, `%%EOF`, EOCD)와 파일 크기까지 본다.
- **확장자가 없는 파일을 건너뛰는 것.** 스크립트에서 조용히 제외되므로 놓친다. `UNKNOWN`으로 별도 목록화해 반드시 눈으로 훑는다.
- **Autopsy에서 File Type Identification을 끄고 Extension Mismatch Detector만 켜는 것.** 실제 형식을 판정하는 모듈이 없으면 결과가 비거나 부정확하다. 두 모듈은 함께 켠다.
- **대문자 확장자(`.JPG`)를 다른 확장자로 취급하는 것.** Windows는 대소문자를 구분하지 않는다. 비교 전에 소문자로 정규화한다.
- **모든 불일치를 악의적 은닉으로 결론 내리는 것.** 이름을 잘못 저장한 사용자 실수, 웹서버가 잘못 준 파일, 임시 파일 등 정상 원인이 많다. 위치(`Pictures`에 PE)와 시각으로 맥락을 보강한다.
- **압축 파일 안의 파일을 검사하지 않는 것.** ZIP/7z 내부는 `file`이 기본적으로 들여다보지 않는다. `7z x`로 풀어 재귀 검사하거나 Autopsy의 Embedded File Extractor를 쓴다.
- **네트워크/이미지 마운트 없이 `$MFT`의 `Extension`만으로 위조를 판정하는 것.** `$MFT`는 이름만 안다. 헤더는 `icat`으로 직접 뽑아 봐야 한다.

## 교차검증

```bash
# 1) file 판정 vs 직접 읽은 헤더
file -b --mime-type IMG_2841.jpg
xxd -l 16 IMG_2841.jpg

# 2) 헤더 vs 푸터 (둘이 다른 형식을 가리키면 조작)
xxd -l 8 IMG_2841.jpg
tail -c 8 IMG_2841.jpg | xxd

# 3) 컨테이너면 내부 이름으로 세부 형식 확정
7z l IMG_2841.jpg | head -20

# 4) 내부 시그니처 전수 스캔 (앞부분 위조에 견딘다)
binwalk IMG_2841.jpg

# 5) 도구 2개의 판정이 같은가
file -k IMG_2841.jpg
# GUI: Detect It Easy 로 같은 파일을 열어 판정 비교

# 6) Autopsy 목록과 CLI 스크립트 결과 건수 비교
./ext_vs_type.sh /mnt/evidence | wc -l
```

Autopsy가 잡은 건수와 스크립트 건수가 크게 다르면 대개 **범위 차이**다. Autopsy는 삭제 파일·카빙 결과·압축 내부까지 포함하고, 마운트한 파일시스템을 훑는 스크립트는 살아 있는 파일만 본다.

## mini walkthrough

```text
문제:
"직원 PC의 사진 폴더에 회사 자료가 숨겨져 있습니다. 파일 이름을 찾으세요."
첨부: pc.E01 (사진 1,284개가 있는 Pictures 폴더 포함)

1. 마운트 후 목록
   ls /mnt/evidence/Users/jhkim/Pictures | wc -l
   -> 1284      (손으로 볼 수 있는 수가 아니다)

2. 첫 시도 (실패한 접근):
   for f in *; do file "$f"; done | grep -v JPEG
   -> 출력 0건. "위조 파일이 없다"고 결론.

   그 다음 시도도 실패:
   find . -name '*.jpg' -exec file {} \; | grep -i zip
   -> 0건.

   무엇이 틀렸나: 두 가지가 겹쳤다.
   (a) 첫 명령은 현재 디렉터리만 봤고 하위 폴더(Pictures/2026/03/)를
       보지 않았다.
   (b) 위조 파일의 확장자가 .jpg 가 아니라 .png 였는데
       'grep -v JPEG' 와 '-name *.jpg' 로 대상을 미리 좁혀 버렸다.
   대량 스캔에서는 대상을 좁히기 전에 '전수 분포'를 먼저 본다.

3. 접근 변경 — 전수 스캔 후 분포로 이상치 찾기
   find /mnt/evidence/Users/jhkim/Pictures -type f \
        -exec file --mime-type {} + > types.txt
   awk -F': ' '{print $2}' types.txt | sort | uniq -c | sort -nr

   ->  1279 image/jpeg
          3 image/png
          1 application/x-7z-compressed        <- 1건이 튄다
          1 application/zip                    <- 1건이 튄다

   grep -E '7z-compressed|application/zip' types.txt
   -> /mnt/.../Pictures/2026/03/DSC_0417.png: application/x-7z-compressed
      /mnt/.../Pictures/2026/03/DSC_0418.png: application/zip

4. 헤더 직접 확인
   xxd -l 16 DSC_0417.png
   -> 00000000: 377a bcaf 271c 0004 ...    (37 7A BC AF 27 1C = 7z)
   xxd -l 16 DSC_0418.png
   -> 00000000: 504b 0304 1400 ...          (PK 03 04 = ZIP)

5. ZIP 쪽은 docx 오탐이 아닌지 내부 이름 확인
   7z l DSC_0418.png | head
   -> 고객명단_2026.xlsx
      단가표.xlsx
   [Content_Types].xml 이 없고 임의 파일 목록 -> 순수 ZIP. 오탐 아님.

6. 7z 쪽 열기
   7z l DSC_0417.png
   -> 개발계획서.pdf  (암호 필요 표시)
   -> DSC_0418.png 안의 파일에 암호가 적혀 있었다

7. 검산 — 푸터로도 확인
   tail -c 4 DSC_0418.png | xxd
   -> 504b 0506 ... 형태의 EOCD 계열 (ZIP 이 정상 종료됨)
   정상 PNG 라면 49 45 4E 44 AE 42 60 82 로 끝나야 한다. 아니다.

8. 부가 확인 — 이름을 언제 바꿨나
   $UsnJrnl 에 DSC_0417.png 의 RENAME_OLD_NAME/RENAME_NEW_NAME 쌍 존재
   -> 원래 이름: backup_0417.7z

정답: 고객명단_2026.xlsx, 단가표.xlsx, 개발계획서.pdf
      (DSC_0417.png = 7z, DSC_0418.png = ZIP 으로 위장)
```

2→3단계가 이 글의 요지다. **대상을 미리 좁히는 `grep -v JPEG`와 `-name '*.jpg'`가 정답을 걸러 버렸다.** 전수 스캔 후 `uniq -c` 분포로 이상치를 찾는 방식은 위조가 어느 확장자에 숨어 있든 잡아낸다.

## 막혔을 때 다음 체크

1. `find`가 하위 디렉터리까지 훑었는가 (`-type f`, 경로 지정 확인)
2. 대상을 확장자로 미리 좁히지 않았는가 — 전수 스캔 후 분포로 본다
3. 확장자를 소문자로 정규화했는가 (`.JPG`)
4. 확장자가 없는 파일을 별도 목록으로 확인했는가
5. 푸터를 확인했는가 (`tail -c 16 | xxd`)
6. ZIP 계열이면 `7z l`로 내부 이름을 봤는가 (docx/apk 오탐 배제)
7. `binwalk`로 파일 **내부**의 시그니처를 스캔했는가
8. `file -z`로 압축 내부까지 판정했는가
9. Autopsy에서 File Type Identification을 함께 켰는가
10. 삭제 파일과 카빙 결과도 검사 대상에 넣었는가
11. `file`이 `octet-stream`인 파일은 DIE/TrID로 2차 판정했는가
12. 크기 이상치(같은 폴더 평균 대비 1/10 또는 10배)를 따로 뽑아 봤는가

## 출처

- SRC-089 — Wikipedia, List of file signatures: 확장자별 헤더/푸터 매직 바이트 대조값(JPEG `FF D8 FF`/`FF D9`, PNG 시그니처와 `IEND`, ZIP `50 4B 03 04`, 7z, gzip, RAR, PE `MZ` 등)
- SRC-033 — Autopsy User Documentation: File Type Identification과 Extension Mismatch Detector 모듈의 관계, `Results > Interesting Items` 및 `Views > File Types > By MIME Type` 위치
- SRC-042 — ZIP File Format Specification (PKWARE APPNOTE): Local File Header(`50 4B 03 04`)와 End of Central Directory(`50 4B 05 06`) 구조. docx/xlsx/apk/jar가 모두 동일한 ZIP 컨테이너를 쓰므로 헤더만으로 구별할 수 없다는 근거
- `file`/libmagic이 출력하는 MIME 문자열은 버전과 magic DB에 따라 표기가 다르므로 스크립트에서는 부분 일치로 비교할 것
- Autopsy 모듈 이름과 결과 트리 노드 명칭은 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- TrID는 `tools/manifest.json`에 등재되어 있지 않다. 대회장에서는 `file`과 Detect It Easy(등재됨)로 대체한다
- 최종 판정은 항상 대상 파일의 헤더/푸터 바이트를 `xxd`/HxD로 직접 읽어 확인할 것
