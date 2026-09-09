---
id: FOR-0035
title: "ADS(Alternate Data Stream)와 Zone.Identifier로 다운로드 출처 찾기"
slug: "alternate-data-streams"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["ADS", "Alternate Data Stream", "Zone.Identifier", "$DATA", "MOTW", "HasAds"]
file_paths: ["C:\\Users\\<user>\\Downloads", "report.docx:Zone.Identifier:$DATA", "C:\\$MFT", "C:\\$Extend\\$UsnJrnl"]
registry_paths: []
event_ids: []
protocols: []
tools: ["PowerShell", "Sleuth Kit", "MFTECmd", "FTK Imager", "Autopsy", "HxD", "streams.exe"]
commands: ["dir /r", "Get-Item -Path .\\report.docx -Stream *", "Get-Content -Path .\\report.docx -Stream Zone.Identifier", "fls -o 2048 -r -p image.dd", "icat -o 2048 image.dd 84213-128-5", "more < report.docx:Zone.Identifier"]
regex_patterns: ["HostUrl=(.*)", "ZoneId=([0-4])"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ZoneId", "ReferrerUrl", "HostUrl", "Stream", "Length", "HasAds"]
file_formats: ["ntfs"]
primary_terms: ["ADS", "Alternate Data Stream", "Zone.Identifier", "대체 데이터 스트림"]
keywords: ["ADS", "Alternate Data Stream", "Zone.Identifier", "ZoneId", "MOTW", "Mark of the Web", "HostUrl", "ReferrerUrl", "dir /r", "Get-Item -Stream", "$DATA", "NTFS 스트림"]
aliases: ["ads", "대체 데이터 스트림", "zone identifier", "다운로드 출처", "어디서 받았나", "숨겨진 스트림", "dir /r", "motw"]
symptom_keywords: ["이 파일을 어디서 다운로드했는지 알고 싶다", "파일에 숨겨진 데이터가 있다", "파일 크기와 디스크 사용량이 다르다", "스트림을 어떻게 보는지 모르겠다", "다운로드 경고창이 뜬다"]
related: ["FOR-0021", "FOR-0027", "FOR-0034"]
source_ids: ["SRC-081", "SRC-005", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

NTFS 파일은 `파일명:스트림명:$DATA` 문법으로 본문과 별개의 데이터 스트림을 여러 개 가질 수 있고, 실전에서 가장 값이 큰 스트림은 다운로드 출처 URL이 그대로 적혀 있는 `Zone.Identifier`이므로 `Get-Content -Path <파일> -Stream Zone.Identifier`를 먼저 돌린다.

## 어떤 문제에서 필요한가

- **"이 파일을 어디서 받았는가"**를 답해야 하는 경우 — 브라우저 기록이 지워졌어도 `Zone.Identifier`가 남아 있다
- 파일 크기는 작은데 디스크 점유가 크거나, `$MFT` 파서의 `HasAds`가 `True`인 경우
- 지문이 "숨겨진 데이터", "스트림", "보이지 않는 파일"을 언급하는 경우
- 악성 실행 파일이 정상 문서 뒤에 붙어 있는지 확인해야 하는 경우
- `$UsnJrnl`에 `STREAM_CHANGE`나 `NAMED_DATA_*` 플래그가 보이는 경우 ([FOR-0027](./usnjrnl-basics.html))

## 문제에서 처음 볼 단서

1. `$MFT` 파서 CSV의 `HasAds` 컬럼이 `True`인 항목 — 여기서 후보가 좁혀진다
2. `Downloads` 폴더의 파일 — 브라우저가 저장한 파일은 대부분 `Zone.Identifier`를 가진다
3. `dir /r` 출력에서 파일명 아래에 들여쓰여 나오는 줄
4. `fls` 출력에서 `파일명:스트림명` 형태로 **별도 항목으로 등장하는 줄**
5. 파일을 열 때 Windows가 "차단 해제" 경고나 Office 보호된 보기를 띄웠는가 — MOTW가 붙어 있다는 뜻이다

## 30초 절차

```powershell
Get-Content -Path .\report.docx -Stream Zone.Identifier
```

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://drive.example.com/share/9f2a
HostUrl=https://cdn.example.com/files/report.docx
```

폴더 전체를 훑을 때:

```powershell
# 스트림을 가진 파일만, 기본 스트림 제외
Get-ChildItem -Recurse -File | ForEach-Object {
  Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
} | Where-Object { $_.Stream -ne ':$DATA' } |
  Select-Object FileName, Stream, Length
```

```cmd
dir /r /s C:\Users\jhkim\Downloads
```

## 상세 절차

### 1단계 — 문법과 구조

NTFS의 파일 내용은 `$DATA` 속성에 들어간다. 이 속성은 **이름을 가질 수 있고, 여러 개 존재할 수 있다.** 이름 있는 `$DATA`가 곧 ADS다.

| 표기 | 의미 |
| --- | --- |
| `report.docx` | 기본(이름 없는) 스트림 |
| `report.docx::$DATA` | 위와 동일. 명시적 표기 |
| `report.docx:Zone.Identifier` | `Zone.Identifier` 라는 이름의 ADS |
| `report.docx:Zone.Identifier:$DATA` | 완전 표기 (`파일명:스트림명:속성타입`) |
| `folder:hidden.txt` | **디렉터리에도 ADS를 붙일 수 있다** |
| `C:\dir:$I30:$INDEX_ALLOCATION` | 디렉터리 인덱스 (참고용. ADS가 아니라 다른 속성 타입) |

핵심 성질:

- **`dir`의 기본 출력과 탐색기의 "크기"에 ADS 크기가 포함되지 않는다.** 5 KB 문서에 50 MB ADS가 붙어도 목록에서는 5 KB로 보인다
- ADS는 NTFS 기능이다. **FAT32/exFAT/USB로 복사하거나 ZIP으로 압축하면 조용히 사라진다**
- 본문을 지우지 않고 ADS만 삭제할 수 있다
- 파일 해시(본문 기준)는 ADS 유무에 영향받지 않는다

### 2단계 — Zone.Identifier가 실전에서 가장 중요하다

Windows는 인터넷에서 받은 파일에 `Zone.Identifier` ADS를 붙인다(Mark of the Web, MOTW). 내용은 INI 형식이다.

| 키 | 내용 | 포렌식 가치 |
| --- | --- | --- |
| `[ZoneTransfer]` | 섹션 헤더 | — |
| `ZoneId` | 보안 영역 번호 | 어디서 왔는지의 대분류 |
| `ReferrerUrl` | **파일 링크가 있던 페이지 URL** | 사용자가 어느 페이지를 보고 있었는지 |
| `HostUrl` | **파일 자체의 실제 다운로드 URL** | 가장 결정적인 값 |
| `LastWriterPackageFamilyName` | 파일을 쓴 앱의 패키지 이름 | 어느 앱이 저장했는지 (있는 버전에서만) |
| `AppZoneId` | 앱 기준 영역 값 | 있는 버전에서만 |

`ZoneId` 값:

| 값 | 영역 | 해석 |
| --- | --- | --- |
| 0 | Local machine | 로컬에서 만들어짐 |
| 1 | Local intranet | 사내망/UNC 공유 |
| 2 | Trusted sites | 신뢰 사이트 |
| **3** | **Internet** | **인터넷에서 다운로드. 실전에서 거의 항상 이 값** |
| 4 | Restricted sites | 제한된 사이트 |

`ZoneId=3`이면 "이 파일은 인터넷에서 왔다"가 확정된다. `HostUrl`이 함께 있으면 **URL 자체가 답인 문제**가 많다.

브라우저에 따라 채워지는 필드가 다르다.

| 저장 경로 | 보통 채워지는 필드 |
| --- | --- |
| Chrome/Edge 다운로드 | `ZoneId`, `ReferrerUrl`, `HostUrl` |
| 메일 첨부 저장 | `ZoneId`만 있는 경우가 많다 |
| UNC/네트워크 공유 복사 | `ZoneId=1` 또는 없음 |
| 압축 파일 내부에서 압축 해제 | 압축 프로그램에 따라 전파되거나 사라진다 |

`Zone.Identifier`의 시각 정보는 스트림 자체에 없다. **파일의 생성 시각과 브라우저 다운로드 기록으로 시각을 보강한다** ([FOR-0191](./chrome-history.html)).

### 3단계 — 탐지: 라이브 시스템

```cmd
REM 스트림을 포함해 목록 표시
dir /r
```

```text
 2026-03-14  16:22             5,120 report.docx
                                  26 report.docx:Zone.Identifier:$DATA
 2026-03-14  16:31           184,320 notes.txt
                             451,584 notes.txt:payload.exe:$DATA
               2 File(s)        189,440 bytes
```

두 번째 항목이 결정적이다. `notes.txt`는 목록상 184 KB인데 그 안에 451 KB짜리 실행 파일이 숨어 있다.

```powershell
# 특정 파일의 모든 스트림
Get-Item -Path .\notes.txt -Stream *

# 특정 스트림 읽기 (텍스트)
Get-Content -Path .\report.docx -Stream Zone.Identifier

# 바이너리 스트림 추출 (PowerShell 7+)
Get-Content -Path .\notes.txt -Stream payload.exe -AsByteStream -Raw |
  Set-Content -Path .\payload.exe -AsByteStream

# PowerShell 5.1 에서는
Get-Content -Path .\notes.txt -Stream payload.exe -Encoding Byte -Raw |
  Set-Content -Path .\payload.exe -Encoding Byte

# 스트림 삭제 (분석 중에는 쓰지 않는다)
Remove-Item -Path .\report.docx -Stream Zone.Identifier
Unblock-File -Path .\report.docx      # Zone.Identifier 제거의 표준 방법
```

```cmd
REM cmd 에서 텍스트 스트림 읽기
more < report.docx:Zone.Identifier
notepad report.docx:Zone.Identifier
```

Sysinternals `streams.exe`는 재귀 목록화에 편하다.

```text
streams -s C:\Users\jhkim\Downloads
```

### 4단계 — 탐지: 이미지/오프라인

라이브 접근이 불가능한 CTF 이미지에서는 이쪽이 본류다.

| 방법 | 명령/위치 | 특징 |
| --- | --- | --- |
| **Sleuth Kit `fls`** | `fls -o 2048 -r -p image.dd` | ADS가 **별도 항목**으로 나온다 |
| **Sleuth Kit `istat`** | `istat -o 2048 image.dd 84213` | 속성 목록에 이름 있는 `$DATA`가 보인다 |
| **`icat`** | `icat -o 2048 image.dd 84213-128-5` | 속성 ID까지 지정해 스트림만 추출 |
| **`$MFT` 파서** | MFTECmd CSV의 `HasAds` 컬럼 | 볼륨 전체를 한 번에 스크리닝 |
| **FTK Imager** | 파일 트리에서 스트림이 별도 항목으로 표시 | Export로 꺼낸다 ([FOR-0016](./ftk-imager-open-image.html)) |
| **Autopsy** | 파일 목록에 스트림 항목이 함께 나온다 | ([FOR-0018](./autopsy-ingest.html)) |

`fls` 출력이 핵심이다.

```text
$ fls -o 2048 -r -p image.dd | grep -i notes
r/r 84213-128-1:   Users/jhkim/Desktop/notes.txt
r/r 84213-128-5:   Users/jhkim/Desktop/notes.txt:payload.exe
```

같은 MFT 엔트리(`84213`)에 `$DATA`(타입 `128`)가 **속성 ID만 다르게 두 개** 존재한다. 두 번째가 ADS다.

```bash
# ADS 만 골라 보기
fls -o 2048 -r -p image.dd | grep ':' | grep -E ':[^/:]+$' | grep -v '^d'

# 스트림 추출 — 엔트리-타입-ID 를 그대로 넣는다
icat -o 2048 image.dd 84213-128-5 > payload.exe
file payload.exe
```

```text
payload.exe: PE32+ executable (console) x86-64, for MS Windows
```

`$MFT`만 주어진 문제라면:

```powershell
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
Import-Csv .\out\mft.csv | Where-Object { $_.HasAds -eq 'True' } |
  Select-Object EntryNumber, ParentPath, FileName, FileSize
```

### 5단계 — ADS로 숨기는 기법

| 기법 | 명령 예 | 흔적 |
| --- | --- | --- |
| 파일을 ADS로 복사 | `type payload.exe > notes.txt:p.exe` | `dir /r`에 스트림 크기가 노출된다 |
| 디렉터리에 ADS | `echo secret > C:\temp:hidden.txt` | 폴더 항목에 스트림이 붙는다. 탐색기로는 안 보인다 |
| 텍스트/키를 ADS에 보관 | `echo flag{...} > a.txt:s` | `more < a.txt:s`로 읽힌다 |
| 실행 파일을 ADS에서 실행 | 경로에 `호스트:스트림`을 지정해 프로세스 생성 | 프로세스 이미지 경로에 `:`이 들어간다 |
| MOTW 제거로 경고 회피 | `Unblock-File`, ADS 삭제, ZIP 경유 복사 | `Zone.Identifier`의 **부재** 자체가 단서 |

ADS에 놓인 실행 파일을 직접 실행하는 것은 Windows 버전과 보안 제품에 따라 차단되는 경우가 있으므로, "가능하다/불가능하다"를 단정하기보다 **흔적**으로 판단한다. 프로세스 경로나 명령줄에 `파일명:스트림명` 형태의 콜론이 포함된 기록(EVTX 4688, Sysmon 1)이 있으면 결정적이다.

반대 방향의 단서도 중요하다. **`Downloads` 폴더의 파일에 `Zone.Identifier`가 없다면** 다음 중 하나다.

| 원인 | 확인 방법 |
| --- | --- |
| 사용자가 `Unblock-File`/우클릭 차단 해제를 실행 | PowerShell 기록, `$UsnJrnl`의 `STREAM_CHANGE` |
| ZIP/USB(FAT32) 경유로 복사되어 소실 | 압축 파일 원본과 `$UsnJrnl` 대조 |
| 로컬에서 직접 만든 파일 | 브라우저 다운로드 기록에 없다 |
| 브라우저가 MOTW를 안 붙임(구버전/특정 클라이언트) | 다른 다운로드 파일에는 있는지 비교 |

### 6단계 — $UsnJrnl과 연결하기

ADS 조작은 `$UsnJrnl`에 고유한 플래그를 남긴다. `$Extend\$UsnJrnl:$J`를 파싱해 이 플래그를 검색하면 **"언제 어떤 파일에 스트림이 붙었는가"**를 시각과 함께 얻을 수 있다.

| USN Reason | 값 | 의미 |
| --- | --- | --- |
| `USN_REASON_STREAM_CHANGE` | `0x00200000` | **이름 있는 스트림이 추가/삭제/이름변경됨** |
| `USN_REASON_NAMED_DATA_OVERWRITE` | `0x00000010` | 이름 있는 스트림의 데이터를 덮어씀 |
| `USN_REASON_NAMED_DATA_EXTEND` | `0x00000020` | 이름 있는 스트림에 데이터를 추가 |
| `USN_REASON_NAMED_DATA_TRUNCATION` | `0x00000040` | 이름 있는 스트림을 잘라냄 |
| `USN_REASON_DATA_OVERWRITE` | `0x00000001` | (비교용) **기본** 스트림 덮어쓰기 |
| `USN_REASON_DATA_EXTEND` | `0x00000002` | (비교용) 기본 스트림에 추가 |
| `USN_REASON_CLOSE` | `0x80000000` | 마지막 레코드에 함께 표시된다 |

판독 규칙:

- `NAMED_DATA_EXTEND` + `STREAM_CHANGE`가 붙어 있으면 **그 시각에 ADS를 만들어 데이터를 넣었다**
- `STREAM_CHANGE`만 단독으로 있으면 스트림 추가 또는 **삭제**다. 어느 쪽인지는 현재 상태와 대조한다
- `Downloads` 폴더 파일에 다운로드 직후가 아닌 시각의 `STREAM_CHANGE`가 있으면 **MOTW 제거 의심**

## 출력 필드 해석

`Get-Item -Stream *` 출력:

```text
   PSPath        : ...\notes.txt::$DATA
   PSChildName   : notes.txt::$DATA
   FileName      : C:\Users\jhkim\Desktop\notes.txt
   Stream        : :$DATA
   Length        : 184320

   FileName      : C:\Users\jhkim\Desktop\notes.txt
   Stream        : payload.exe
   Length        : 451584
```

| 필드 | 의미 | 판정 |
| --- | --- | --- |
| `Stream` | 스트림 이름. `:$DATA`가 기본 스트림 | `:$DATA` 외의 값이 ADS |
| `Length` | 그 스트림의 바이트 수 | 기본 스트림보다 크면 강한 은닉 신호 |
| `FileName` | 호스트 파일 경로 | — |

`fls`의 `r/r 84213-128-5` 표기:

| 조각 | 의미 |
| --- | --- |
| `r/r` | 파일 타입 (디렉터리는 `d/d`) |
| `84213` | MFT 엔트리 번호 |
| `128` | 속성 타입 (`0x80` = `$DATA`) |
| `5` | 속성 ID. **같은 엔트리에서 ID가 다른 `$DATA`가 ADS** |
| 뒤의 `*` 표시 | 삭제된 항목 |

`Zone.Identifier` 판독:

| 관찰 | 결론 |
| --- | --- |
| `ZoneId=3` + `HostUrl` 존재 | 인터넷 다운로드. URL이 확정 증거 |
| `ZoneId=3`인데 URL 필드 없음 | 인터넷 유래는 맞으나 출처 URL은 브라우저 기록에서 찾아야 한다 |
| `ZoneId=1` | 사내망/UNC. 내부 이동 |
| 스트림 자체가 없음 | 로컬 생성, 또는 MOTW가 제거/소실됨 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| `HostUrl` / `ReferrerUrl` | 브라우저 History·Downloads에서 같은 URL 검색 ([FOR-0191](./chrome-history.html)) |
| 다운로드 URL의 호스트 | pcap에서 같은 호스트로의 요청 확인 ([FOR-0158](./http-post-find.html)) |
| ADS에서 추출한 실행 파일 | 형식 확인 → `strings`/DIE ([FOR-0036](./signature-extension-mismatch.html)) |
| ADS 생성 시각 | `$UsnJrnl`의 `STREAM_CHANGE` 레코드 ([FOR-0027](./usnjrnl-basics.html)) |
| ADS에 실행 파일이 있었다 | Prefetch·Amcache·EVTX 4688에서 실행 여부 |
| `HasAds=True` 목록 | 각 항목을 `icat`으로 스트림 추출 ([FOR-0021](./mft-basics.html)) |
| `Zone.Identifier`가 사라진 파일 | PowerShell 로그의 `Unblock-File`, 4104 스크립트 블록 |
| 스트림에 아무것도 없다 | slack/비할당으로 은닉 위치 전환 ([FOR-0034](./file-slack.html)) |

## 흔한 함정

- **`dir`만 보고 스트림이 없다고 결론 내리는 것.** 기본 `dir`은 ADS를 표시하지 않는다. 반드시 `dir /r` 또는 `Get-Item -Stream *`을 쓴다.
- **파일 크기로 은닉을 판단하는 것.** ADS 크기는 파일 크기에 포함되지 않는다. 184 KB로 보이는 파일에 451 KB가 들어 있을 수 있다.
- **증거 파일을 FAT32 USB나 ZIP으로 옮긴 뒤 분석하는 것.** ADS가 조용히 사라진다. **이 과정 자체가 증거를 파괴한다.** 원본 이미지에서 `fls`/`icat`으로 다룬다.
- **`Zone.Identifier`가 없는 것을 "다운로드하지 않았다"로 읽는 것.** 제거되었거나 전송 과정에서 소실된 경우가 흔하다. 부재는 부재의 이유를 함께 조사해야 한다.
- **`ZoneId`만 읽고 끝내는 것.** 값 있는 정보는 `HostUrl`/`ReferrerUrl`이다. 필드가 잘려 보이지 않는지 스트림 전체를 출력해 확인한다.
- **`icat`에 엔트리 번호만 넣는 것.** `icat image.dd 84213`은 기본 스트림을 뽑는다. ADS는 `84213-128-5`처럼 **타입과 속성 ID까지** 지정해야 한다.
- **PowerShell 5.1에서 `-AsByteStream`을 쓰는 것.** 5.1에는 없는 파라미터다. 5.1은 `-Encoding Byte`, 7+는 `-AsByteStream`이다.
- **`Unblock-File`이나 `Remove-Item -Stream`을 분석 중에 실행하는 것.** 증거를 지운다. 읽기만 한다.
- **`$MFT`의 `HasAds=True`를 모두 은닉으로 보는 것.** 정상 시스템에도 `Zone.Identifier`, `SmartScreen`, macOS 경유 파일의 `com.apple.*` 스트림이 대량으로 존재한다. 스트림 **이름**으로 걸러낸다.
- **스트림 이름의 콜론을 경로 구분자로 착각해 셸에서 잘못 인용하는 것.** `bash`에서는 문제없지만 PowerShell/`cmd`에서는 경로에 콜론이 들어가면 파싱이 달라진다. PowerShell은 `-Stream` 파라미터를 쓰고, `cmd`는 `more <`로 리다이렉트한다.
- **디렉터리 ADS를 잊는 것.** `C:\temp:hidden.txt`처럼 폴더에도 붙는다. `dir /r`을 폴더 자체에 대해서도 확인한다.

## 교차검증

```powershell
# 1) 스트림 목록을 두 도구로
dir /r .\notes.txt
Get-Item .\notes.txt -Stream * | Select-Object Stream, Length

# 2) 스트림 내용의 해시가 추출본과 같은가
Get-FileHash -Path '.\notes.txt:payload.exe' -Algorithm MD5
Get-FileHash -Path .\payload_extracted.exe -Algorithm MD5
```

```bash
# 3) 이미지에서 본 것과 라이브에서 본 것이 같은가
fls -o 2048 -r -p image.dd | grep -c ':'
icat -o 2048 image.dd 84213-128-5 | md5sum

# 4) Zone.Identifier 의 URL 을 브라우저 DB 와 대조
sqlite3 History "SELECT target_path, tab_url FROM downloads
                 JOIN downloads_url_chains USING(id) LIMIT 20;"

# 5) $UsnJrnl 에 그 시각의 STREAM_CHANGE 가 있는가
#    (MFTECmd -f \$J 로 CSV 변환 후)
rg -i 'STREAM_CHANGE|NAMED_DATA' usnjrnl.csv | rg 'notes.txt'
```

`Zone.Identifier`의 `HostUrl`과 브라우저 `downloads` 테이블의 URL이 일치하면 다운로드 경로가 두 출처로 확정된다. 불일치하면 파일이 다른 경로로 들어왔거나 스트림이 조작된 것이다.

## mini walkthrough

```text
문제:
"사내 PC에서 유출 도구가 발견되었습니다.
 이 파일을 내려받은 URL을 답하세요."
첨부: pc01.E01, 지문에 'Downloads 폴더의 update.txt' 언급

1. FTK Imager 로 열고 Users/jhkim/Downloads 확인
   update.txt   (184 KB)   -> Export 후
   file update.txt
   -> ASCII text
   strings update.txt | head
   -> 그냥 설치 안내 텍스트. URL 없음.

2. 첫 시도 (실패한 접근):
   strings -a update.txt | grep -Ei 'http|://'
   binwalk update.txt
   exiftool update.txt
   -> 전부 무소득. "파일 안에 없다"고 판단하고
      브라우저 History 로 넘어갔으나 History 가 삭제되어 있었다.

   무엇이 틀렸나: update.txt 를 파일로만 다뤘다.
   ADS 는 파일을 읽는 어떤 방법으로도 보이지 않는다.
   본문이 아니라 '같은 MFT 엔트리의 다른 $DATA 속성'을 봐야 했다.

3. 접근 변경 — 스트림을 본다
   fls -o 2048 -r -p pc01.E01 | grep -i update.txt
   -> r/r 91002-128-1:   Users/jhkim/Downloads/update.txt
      r/r 91002-128-4:   Users/jhkim/Downloads/update.txt:Zone.Identifier
      r/r 91002-128-6:   Users/jhkim/Downloads/update.txt:svc.exe

   같은 엔트리 91002 에 $DATA 가 3 개. ADS 2 개 확정.

4. Zone.Identifier 추출
   icat -o 2048 pc01.E01 91002-128-4
   -> [ZoneTransfer]
      ZoneId=3
      ReferrerUrl=http://files.badhost.example/dl/index.php?id=77
      HostUrl=http://files.badhost.example/dl/svc_pack.bin

   ZoneId=3 = 인터넷. HostUrl 이 실제 다운로드 URL.

5. 두 번째 ADS 도 확인
   icat -o 2048 pc01.E01 91002-128-6 > svc.exe
   file svc.exe
   -> PE32+ executable (console) x86-64, for MS Windows
   184 KB 텍스트 파일에 451 KB 실행 파일이 숨어 있었다.

6. 교차검증 — 언제 붙었나
   (FTK Imager 로 C:\$Extend\$UsnJrnl 의 $J 스트림을 C:\case\$J 로 Export)
   MFTECmd.exe -f 'C:\case\$J' --csv out --csvf j.csv
   rg 'update.txt' out\j.csv
   -> 2026-03-14 07:19:58 UTC  FileCreate|Close
      2026-03-14 07:20:02 UTC  NamedDataExtend|StreamChange
      2026-03-14 07:20:02 UTC  NamedDataExtend|StreamChange|Close

   07:19:58 에 파일이 생기고 4 초 뒤 ADS 두 개가 붙었다.
   UTC 07:20:02 = KST 16:20:02.

7. 실행 여부
   Prefetch 에 SVC.EXE-xxxxxxxx.pf 존재 -> 실행됨

정답: http://files.badhost.example/dl/svc_pack.bin
      (Zone.Identifier 의 HostUrl. ADS 로 svc.exe 가 함께 은닉되어 있었다)
```

2→3단계가 이 글의 요지다. **`strings`/`binwalk`/`exiftool`은 모두 "파일 본문"만 읽으므로 ADS를 절대 못 본다.** 스트림은 스트림을 보는 명령(`fls`, `dir /r`, `Get-Item -Stream *`)으로만 드러난다.

## 막혔을 때 다음 체크

1. `dir /r` 또는 `Get-Item -Stream *`을 실행했는가 (`dir`만으로는 안 보인다)
2. `$MFT` 파서 CSV의 `HasAds` 컬럼으로 볼륨 전체를 스크리닝했는가
3. `fls -r -p`에서 `파일명:스트림명` 형태의 줄을 찾았는가
4. `icat`에 `엔트리-128-속성ID` 형식으로 스트림을 지정했는가
5. **디렉터리**에도 ADS가 있는지 확인했는가
6. `Zone.Identifier`의 전체 내용을 봤는가 — `HostUrl`이 잘리지 않았는지
7. 스트림이 없다면 왜 없는지 조사했는가 — `Unblock-File` 실행 흔적, ZIP/USB 경유
8. `$UsnJrnl`에서 `STREAM_CHANGE`/`NAMED_DATA_*`를 검색했는가
9. 증거를 FAT32/ZIP 경유로 복사한 적이 있는가 — 그렇다면 원본 이미지로 되돌아간다
10. ADS에서 나온 바이너리를 `file`/DIE로 판정했는가
11. 다운로드 URL을 브라우저 DB·pcap과 대조했는가
12. 스트림 이름이 정상 시스템 스트림(`SmartScreen`, `com.apple.*`)인지 확인했는가 — 전부 은닉은 아니다

## 출처

- SRC-081 — Microsoft Learn, File Streams: `파일명:스트림명:$DATA` 명명 규칙, 이름 있는 `$DATA` 스트림의 존재와 기본 스트림(`::$DATA`)과의 관계, 파일 크기에 스트림이 포함되지 않는 동작
- SRC-005 — Microsoft Learn, Master File Table: `$DATA`(속성 타입 `0x80`)가 한 MFT 레코드에 여러 개 존재할 수 있다는 구조적 근거. `fls`의 `엔트리-128-ID` 표기 해석의 기반
- SRC-004 — Eric Zimmerman 문서: MFTECmd의 `HasAds` 컬럼과 `$J`(USN 저널) 파싱 출력 형식
- `Zone.Identifier`의 필드 구성(`ReferrerUrl`, `HostUrl`, `LastWriterPackageFamilyName` 등)은 Windows 버전과 저장한 애플리케이션에 따라 다르므로 실제 스트림 내용을 그대로 확인할 것
- `streams.exe`(Sysinternals)는 `tools/manifest.json`에 등재되어 있지 않다. 대회장에서는 `dir /r`/`Get-Item -Stream *`/`fls`로 대체할 수 있다
- ADS에 놓인 실행 파일의 직접 실행 가능 여부는 Windows 버전·보안 제품 설정에 따라 다르므로 단정하지 말고 실행 흔적(Prefetch, 4688, Sysmon 1)으로 판정할 것
