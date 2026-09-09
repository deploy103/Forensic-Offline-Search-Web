---
id: FOR-0120
title: "PowerShell Get-Content 실전: -Tail, -Wait, -Raw, -ReadCount"
slug: "powershell-get-content"
category: "로그/Regex"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["access.log", "app.log", "text log", "Zone.Identifier"]
file_paths: ["C:\\inetpub\\logs\\LogFiles", "C:\\Windows\\System32\\LogFiles", "C:\\Windows\\Logs"]
registry_paths: []
event_ids: []
protocols: []
tools: ["PowerShell", "Get-Content", "Measure-Object", "Select-String"]
commands: ["Get-Content .\\access.log -TotalCount 3", "Get-Content .\\app.log -Tail 50 -Wait", "Get-Content .\\access.log -Raw", "Get-Content .\\huge.log -ReadCount 2000", "Get-Content .\\app.log | Measure-Object -Line", "Get-Content .\\file.txt -Stream Zone.Identifier"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Lines", "Words", "Characters", "Length"]
file_formats: ["log", "txt", "csv", "json", "jsonl"]
primary_terms: ["Get-Content", "gc", "파워쉘 파일 읽기", "Tail Wait"]
keywords: ["Get-Content", "gc", "cat", "type", "Tail", "Wait", "Raw", "ReadCount", "TotalCount", "Encoding", "Delimiter", "파일 읽기", "실시간 로그", "한글 깨짐", "Measure-Object"]
aliases: ["파워쉘 파일 읽기", "파워쉘 cat", "파워쉘 tail", "tail -f 파워쉘", "get-content", "윈도우에서 tail", "파워쉘 로그 실시간", "파워쉘 줄 수"]
symptom_keywords: ["파일이 너무 커서 안 열린다", "실시간으로 로그를 보고 싶다", "한글이 깨져서 나온다", "줄 수를 세고 싶다", "메모리가 부족하다", "마지막 줄만 보고 싶다"]
related: ["FOR-0121", "FOR-0118", "FOR-0035"]
source_ids: ["SRC-007"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Get-Content`는 기본적으로 **줄 단위 문자열 배열**을 돌려주고 `-Raw`를 주면 **파일 전체를 문자열 하나**로 돌려준다. 이 차이가 성능과 정규식 동작을 모두 바꾸므로, 로그를 만나면 `-TotalCount`로 앞을 보고 `-Tail`로 끝을 보고 큰 파일은 `-ReadCount`로 흘려보내는 것이 순서다.

## 어떤 문제에서 필요한가

- 첨부된 로그의 **형식을 먼저 확인**해야 하는 상황 — 형식을 모르면 정규식을 못 만든다
- 수백 MB 로그를 메모장/VS Code로 열 수 없는 상황
- 문제 지문이 "마지막 로그", "최초 기록"을 묻는 상황
- 실행 중인 프로세스가 로그를 계속 쓰고 있어 **실시간 관찰**이 필요한 상황
- 한글이 포함된 로그가 물음표나 깨진 글자로 나오는 상황
- 파일 앞부분 몇 바이트만 보고 **매직 바이트**를 확인해야 하는 상황

## 문제에서 처음 볼 단서

1. 확장자가 `.log` `.txt` `.csv` `.json` 이면 텍스트로 읽는다
2. 파일 크기가 수십 MB 이상이면 `-Raw`나 `(Get-Content ...)` 괄호 감싸기를 쓰면 안 된다
3. 첫 줄이 헤더인지 데이터인지 (CSV는 헤더, syslog는 바로 데이터)
4. 한글이 깨지면 인코딩 문제이고, 물음표가 나오면 콘솔 폰트 문제일 수도 있다
5. 파일 크기가 계속 커지고 있으면 아직 쓰이는 중인 활성 로그다

크기를 먼저 본다.

```powershell
Get-ChildItem .\access.log | Select-Object Name, Length, LastWriteTime
```

```text
Name       Length LastWriteTime
----       ------ -------------
access.log 8412775 2026-03-14 07:41:09
```

## 30초 절차

```powershell
Get-Content .\access.log -TotalCount 3
```

앞·뒤·줄 수를 한 번에 확인하는 세 줄이 실제 시작점이다.

```powershell
Get-Content .\access.log -TotalCount 3       # 앞 3줄 = 형식 판별
Get-Content .\access.log -Tail 3             # 뒤 3줄 = 마지막 기록 시각
Get-Content .\access.log | Measure-Object -Line
```

```text
203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199
192.168.10.24 - - [14/Mar/2026:07:19:05 +0900] "GET /index.html HTTP/1.1" 200 5120
198.51.100.5 - - [14/Mar/2026:07:19:07 +0900] "GET /favicon.ico HTTP/1.1" 404 209

Lines      : 41882
Words      :
Characters :
Property   :
```

`+0900`이 보이므로 이 로그의 시각은 KST다. UTC 기준 artifact와 비교할 때는 9시간을 빼야 한다.

## 상세 절차

### 1단계 — 파라미터 8개만 외운다

| 파라미터 | 하는 일 | 반환 형태 | Linux 대응 |
| --- | --- | --- | --- |
| `-Path` | 대상 파일. 와일드카드 허용 | — | 파일 인자 |
| `-LiteralPath` | 경로를 **문자 그대로**. `[` `]` `*` 포함 경로에 필수 | — | — |
| `-TotalCount N` | 앞에서 N개만 읽고 멈춘다. 별칭 `-First`, `-Head` | 줄 배열 | `head -n N` |
| `-Tail N` | 뒤에서 N개. 별칭 `-Last` | 줄 배열 | `tail -n N` |
| `-Wait` | 파일을 열어 둔 채 새 내용이 붙으면 계속 출력 | 줄 스트림 | `tail -f` |
| `-Raw` | 파일 전체를 **문자열 하나**로 | 문자열 1개 | — |
| `-ReadCount N` | 파이프라인으로 한 번에 N줄씩 넘긴다 | N개짜리 배열 묶음 | — |
| `-Delimiter S` | 줄 구분자를 `S`로 바꾼다 | S 기준 조각 | `awk RS=S` |
| `-Encoding E` | 읽을 때 적용할 인코딩 | 줄 배열 | `iconv` |

별칭은 `gc`, `cat`, `type` 세 개다. 대회장에서는 `gc`가 가장 빠르다.

`-ReadCount` 기본값은 1이고, 0을 주면 전부 한 번에 보낸다.

### 2단계 — `-Raw` vs 기본 동작의 차이를 몸으로 익힌다

```powershell
$lines = Get-Content .\access.log        # String[] — 줄마다 원소 1개
$raw   = Get-Content .\access.log -Raw   # String   — 원소 1개

$lines.Count      # 41882
$raw.Count        # 1
$raw.Length       # 8412775  (문자 수)
$lines[0].Length  # 76       (첫 줄 문자 수)
```

| 비교 항목 | 기본 (줄 배열) | `-Raw` (문자열 하나) |
| --- | --- | --- |
| 반환 타입 | `String[]` | `String` |
| `.Count` | 줄 수 | 항상 1 |
| 여러 줄에 걸친 정규식 | 불가 (줄마다 따로 본다) | 가능 |
| 메모리 | 줄마다 객체 → 오버헤드 큼 | 파일 크기만큼 한 덩어리 |
| 큰 파일 속도 | 느리다 | 훨씬 빠르다 |
| 인덱싱 | `$lines[100]` | 불가 |

정규식이 줄바꿈을 넘어야 하는 경우(멀티라인 XML, 스택 트레이스, JSON 들여쓰기)는 `-Raw`가 유일한 답이다.

```powershell
# 여러 줄에 걸친 <Data> 블록 추출 — -Raw 없으면 절대 안 걸린다
$raw = Get-Content .\report.xml -Raw
[regex]::Matches($raw, '(?s)<Data Name="CommandLine">(.*?)</Data>') |
  ForEach-Object { $_.Groups[1].Value }
```

`(?s)`는 `.`이 줄바꿈까지 매칭하게 하는 인라인 옵션이다.

### 3단계 — 큰 파일은 `-ReadCount`로 흘려보낸다

`(Get-Content huge.log)`처럼 괄호로 감싸면 **파일 전체가 배열로 메모리에 올라간다.** 수 GB 파일에서는 이것만으로 세션이 죽는다.

```powershell
# 나쁜 예 — 전체를 배열로 만든다
$all = Get-Content .\huge.log
$all | Where-Object { $_ -match 'ERROR' }

# 좋은 예 — 2000줄씩 파이프로 흘린다
Get-Content .\huge.log -ReadCount 2000 | Select-String -Pattern 'ERROR'
```

`-ReadCount`를 1보다 크게 주면 **파이프라인에 배열이 흐른다.** 이것이 최대 함정이다.

```powershell
# 의도대로 안 되는 코드 — $_ 가 문자열이 아니라 배열이다
Get-Content .\huge.log -ReadCount 1000 | ForEach-Object { $_.Substring(0,10) }
# -> Method invocation failed ... [System.Object[]] 에 Substring 없음

# 고친 코드 — 배열을 한 겹 더 풀어 준다
Get-Content .\huge.log -ReadCount 1000 | ForEach-Object { $_ } |
  ForEach-Object { $_.Substring(0,10) }
```

`Select-String`은 배열 입력을 알아서 줄 단위로 처리하므로 `-ReadCount`와 그대로 조합된다. 검색은 [FOR-0121](./powershell-select-string.html)로 넘긴다.

가장 빠른 방법은 .NET을 직접 부르는 것이다.

```powershell
# 스트리밍 열거자 — 메모리에 한 줄씩만 올린다
[System.IO.File]::ReadLines((Resolve-Path .\huge.log)) |
  Where-Object { $_ -like '*ERROR*' } | Select-Object -First 20
```

`Resolve-Path`로 감싸는 이유가 중요하다. .NET 메서드는 PowerShell의 현재 위치가 아니라 **프로세스의 작업 디렉터리**를 기준으로 상대 경로를 푼다. 상대 경로를 그대로 넘기면 엉뚱한 폴더를 보거나 `FileNotFoundException`이 난다.

### 4단계 — `-Wait`로 실시간 관찰

```powershell
# tail -f 와 같다. 마지막 20줄을 보여준 뒤 새 줄을 계속 붙인다
Get-Content .\app.log -Tail 20 -Wait
```

`-Wait`는 파일을 열어 둔 채 주기적으로(약 1초 간격) 크기 변화를 확인해 새 내용을 출력한다. 종료는 Ctrl+C다.

실전에서는 필터와 함께 쓴다.

```powershell
# 실시간으로 실패 로그온만 흘려보기
Get-Content .\auth.log -Tail 0 -Wait | Select-String -Pattern 'Failed password'

# 악성 프로세스가 만들 파일을 감시하며 로그를 본다
Get-Content .\app.log -Wait | Where-Object { $_ -match 'exec|cmd|powershell' }
```

주의: `-Wait`는 프로세스가 살아 있는 **라이브 시스템 대응**용이다. 정지된 이미지에서 뜬 파일에 쓰면 아무것도 나오지 않고 그냥 멈춘 것처럼 보인다.

### 5단계 — 인코딩과 한글 깨짐

기본 인코딩이 **PowerShell 버전마다 다르다.** 이것이 한글 깨짐의 대부분이다.

| 환경 | 기본 인코딩 | UTF-8 로그를 그냥 읽으면 |
| --- | --- | --- |
| Windows PowerShell 5.1 | 시스템 ANSI 코드페이지 (한국어 Windows는 CP949) | 한글이 `ìƒ‰` 같은 깨진 글자 |
| PowerShell 7.x | UTF-8 (BOM 없음) | 정상 |
| PowerShell 7.x + CP949 로그 | UTF-8로 가정 | 한글이 `ìƒ‰` 또는 대체 문자 |

해결은 명시하는 것뿐이다.

```powershell
Get-Content .\korean.log -Encoding utf8      # UTF-8 로그
Get-Content .\korean.log -Encoding oem       # 콘솔/CP949 로 저장된 로그
Get-Content .\korean.log -Encoding unicode   # UTF-16LE (Windows 툴 출력이 흔히 이것)
```

BOM으로 먼저 판정하면 추측이 필요 없다.

```powershell
# PowerShell 7
Get-Content .\korean.log -AsByteStream -TotalCount 4 | ForEach-Object { $_.ToString('X2') }

# Windows PowerShell 5.1
Get-Content .\korean.log -Encoding Byte -TotalCount 4 | ForEach-Object { $_.ToString('X2') }
```

```text
EF
BB
BF
7B
```

| 첫 바이트 | 인코딩 | `-Encoding` 값 |
| --- | --- | --- |
| `EF BB BF` | UTF-8 with BOM | `utf8` |
| `FF FE` | UTF-16 LE | `unicode` |
| `FE FF` | UTF-16 BE | `bigendianunicode` |
| BOM 없음 + `7B`(`{`) 같은 ASCII | UTF-8 또는 ANSI | 한글 확인 후 `utf8` / `oem` |

같은 바이트 읽기로 **매직 바이트 확인**도 끝난다. `50 4B 03 04`면 ZIP, `89 50 4E 47`면 PNG다.

`-Encoding Byte`는 Windows PowerShell 5.1 전용이고 PowerShell 6 이상에서는 `-AsByteStream`으로 바뀌었다. 둘을 섞으면 파라미터 오류가 난다.

### 6단계 — `-Delimiter`와 ADS

줄바꿈이 아닌 구분자로 잘라야 할 때가 있다. NUL 구분 리스트, 레코드 구분자가 `;`인 덤프 등이다.

```powershell
# ; 를 레코드 구분자로 사용
Get-Content .\records.txt -Delimiter ';' | ForEach-Object { $_.Trim() }
```

`-Delimiter`로 자르면 구분자 자체가 각 조각의 끝에 남는다. 그래서 위처럼 `Trim()`이나 `TrimEnd(';')`이 필요하다.

Windows에서는 대체 데이터 스트림도 `Get-Content`로 읽는다.

```powershell
Get-Item .\suspicious.exe -Stream *
Get-Content .\suspicious.exe -Stream Zone.Identifier
```

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=http://203.0.113.77/payload
HostUrl=http://203.0.113.77/payload/suspicious.exe
```

`ZoneId=3`은 인터넷에서 내려온 파일이라는 증거다. 스트림 자체는 [FOR-0035](./alternate-data-streams.html)에서 다룬다.

## 출력 필드 해석

`Get-Content`가 무엇을 돌려주는지 알면 뒤에 붙일 커맨드릿이 정해진다.

| 호출 | 반환 타입 | `.Count` | 그다음 붙일 것 |
| --- | --- | --- | --- |
| `Get-Content f` | `String[]` | 줄 수 | `Where-Object`, `Select-String`, `[int]` 인덱싱 |
| `Get-Content f -Raw` | `String` | 1 | `[regex]::Matches`, `-split`, `-match` |
| `Get-Content f -TotalCount 5` | `String[]` | 5 이하 | 형식 판별 |
| `Get-Content f -Tail 5` | `String[]` | 5 이하 | 마지막 시각 확인 |
| `Get-Content f -ReadCount 500` | `String[]` 묶음 스트림 | 묶음 개수 | `Select-String`, `ForEach-Object { $_ }` |
| `Get-Content f -AsByteStream` | `Byte[]` | 바이트 수 | `ToString('X2')` |
| `Get-Content f -Delimiter ';'` | `String[]` | 조각 수 | `Trim()` |

줄 수를 세는 방법도 반환 타입에 따라 다르다.

```powershell
Get-Content .\access.log | Measure-Object -Line   # 스트리밍. 큰 파일에도 안전
(Get-Content .\access.log).Count                  # 전체를 배열로 올린다. 작은 파일만
((Get-Content .\access.log -Raw) -split "\r?\n").Count   # -Raw 로 읽었을 때
```

`-Raw` 결과에 `.Count`를 쓰면 무조건 1이 나온다. 줄 수를 센 줄 알고 오답을 쓰는 대표적인 사고다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 로그 형식 (Apache / syslog / CSV / JSON) | 그 형식 전용 파서 또는 정규식 |
| 로그의 마지막 시각 | 그 시각 전후의 EVTX·$MFT 활동 |
| `+0900` 같은 오프셋 표기 | 로그 시각의 시간대 확정. UTC artifact와 맞추기 |
| 첫 4바이트 매직 | 텍스트가 아니면 헥스 편집기·카빙으로 전환 |
| `Zone.Identifier`의 `HostUrl` | 다운로드 출처 IP·도메인 → pcap, 브라우저 히스토리 |
| 파일 크기가 계속 증가 | 라이브 프로세스 존재 → `-Wait`로 관찰 |
| 파일 크기가 0 | 로그 삭제·초기화 의심 → $MFT ([FOR-0021](./mft-basics.html)) |

## 흔한 함정

- **`(Get-Content huge.log)`로 감싸는 것.** 괄호는 파이프라인을 끝내고 전체를 배열로 만들라는 뜻이다. 수 GB에서 메모리가 폭발한다. `-ReadCount`나 `[System.IO.File]::ReadLines`로 흘려보낸다.
- **`-Raw` 결과에 `.Count`를 쓰는 것.** `-Raw`는 원소 1개인 문자열이라 항상 1이 나온다. 줄 수는 `Measure-Object -Line`으로 센다.
- **`-Raw` 없이 여러 줄 정규식을 시도하는 것.** 기본 모드는 줄마다 따로 매칭하므로 줄바꿈을 넘는 패턴은 절대 안 걸린다. `-Raw` + `(?s)`가 정답이다.
- **`-ReadCount`를 켜고 `$_`를 문자열로 취급하는 것.** 파이프라인에 흐르는 것은 N개짜리 배열이다. `$_.Substring()`이 죽는다. `ForEach-Object { $_ }`로 한 겹 풀거나 `Select-String`에 그대로 넘긴다.
- **기본 인코딩을 믿는 것.** PowerShell 5.1은 ANSI(CP949), PowerShell 7은 UTF-8이 기본이다. 같은 명령이 두 환경에서 다른 결과를 낸다. 한글이 섞이면 `-Encoding`을 항상 명시한다.
- **`-Encoding Byte`와 `-AsByteStream`을 섞는 것.** 앞은 5.1 전용, 뒤는 6 이상 전용이다. `$PSVersionTable.PSVersion`을 먼저 확인한다.
- **증거 파일에 `Set-Content` / `Add-Content` / `Out-File`을 쓰는 것.** 쓰기는 $STANDARD_INFORMATION 시각을 바꾸고 $UsnJrnl 레코드를 남긴다. 증거의 시간선을 조사자가 오염시키는 것이다. 결과는 항상 **다른 드라이브의 작업 폴더**에 저장하고, 원본은 해시로 고정한다.
- **`-Path`에 대괄호가 든 경로를 주는 것.** `-Path`는 `[` `]` `*` `?`를 와일드카드로 해석한다. `C:\case\log[1].txt`는 매칭 실패한다. `-LiteralPath`를 쓴다.
- **.NET 메서드에 상대 경로를 주는 것.** `[System.IO.File]` 계열은 PowerShell의 현재 위치를 모른다. `Resolve-Path`로 절대 경로를 만들어 넘긴다.
- **정지된 이미지에서 `-Wait`를 쓰는 것.** 새 내용이 붙을 일이 없으므로 영원히 대기한다. 멈춘 것으로 오해해 시간을 버린다.
- **`-Tail`을 앞에서 세는 것으로 착각하는 것.** `-Tail`은 끝에서, `-TotalCount`는 앞에서다. 별칭 `-Last` / `-First`로 외우면 헷갈리지 않는다.

## 교차검증

같은 값을 다른 경로로 확인한다. 줄 수는 특히 자주 틀린다.

```powershell
Get-Content .\access.log | Measure-Object -Line | Select-Object Lines
((Get-Content .\access.log -Raw) -split "\r?\n" | Where-Object { $_ -ne '' }).Count
```

```bash
wc -l access.log
awk 'END{print NR}' access.log
```

네 숫자가 어긋나는 원인은 정해져 있다.

| 증상 | 원인 |
| --- | --- |
| `wc -l`이 1 적다 | 마지막 줄에 줄바꿈이 없다. `wc -l`은 줄바꿈 개수를 센다 |
| `-split`이 1 많다 | 파일 끝 줄바꿈 뒤의 빈 문자열이 원소로 남는다 |
| PowerShell이 훨씬 적다 | 파일에 CR만 있는 구형 Mac 개행이거나 NUL 바이트가 섞였다 |
| 전부 다르다 | 텍스트 파일이 아니다. 매직 바이트를 다시 확인한다 |

## mini walkthrough

```text
문제:
"첨부된 서버 로그에서 마지막으로 기록된 요청 시각과 전체 요청 수를 구하고,
 로그에 포함된 한글 오류 메시지를 원문 그대로 제출하세요."
첨부: server.log (약 240MB)

1. 크기 확인
   Get-ChildItem .\server.log | Select-Object Length
   -> 251658240
      => 편집기로 열면 안 된다.

2. 첫 시도 (실패):
   $log = Get-Content .\server.log
   $log.Count
   -> 몇 분간 응답 없음. 세션 메모리가 3GB 를 넘고 콘솔이 멈춘다.
      원인: 240MB 파일의 모든 줄이 PSObject 래핑된 문자열로 메모리에 올라간다.

3. 접근 변경 — 앞뒤만 보고 줄 수는 스트리밍으로 센다
   Get-Content .\server.log -TotalCount 2
   -> 2026-03-14T07:19:02Z INFO  GET /index.html 200
      2026-03-14T07:19:03Z INFO  GET /style.css 200

   Get-Content .\server.log -Tail 2
   -> 2026-03-14T09:58:41Z ERROR POST /upload 500
      2026-03-14T09:58:44Z ERROR ??? ?? ??

   Get-Content .\server.log | Measure-Object -Line
   -> Lines : 1204471

   시각 표기가 Z 로 끝난다 => 이 로그는 UTC 다.
   마지막 요청 09:58:44 UTC = 2026-03-14 18:58:44 KST.

4. 두 번째 실패 — 한글이 물음표로 나온다
   Get-Content .\server.log -Tail 1
   -> 2026-03-14T09:58:44Z ERROR ??? ?? ??
      Windows PowerShell 5.1 이 CP949 로 읽었고, 로그는 UTF-8 이었다.

5. 인코딩 명시
   Get-Content .\server.log -Tail 1 -Encoding utf8
   -> 2026-03-14T09:58:44Z ERROR 인증 서버 응답 없음

   BOM 으로 확증
   Get-Content .\server.log -Encoding Byte -TotalCount 3 |
     ForEach-Object { $_.ToString('X2') }
   -> 32 30 32   (BOM 없는 UTF-8. 그래도 본문은 UTF-8 이다)

6. 교차검증
   wc -l server.log
   -> 1204471 server.log      (Measure-Object 와 일치)

정답: 마지막 요청 2026-03-14 09:58:44 UTC (18:58:44 KST) /
      전체 1204471건 / 오류 메시지 "인증 서버 응답 없음"
```

2단계와 4단계가 이 글의 핵심이다. **큰 파일은 변수에 담지 않는다. 한글이 보이면 인코딩을 명시한다.**

## 막혔을 때 다음 체크

1. `Get-ChildItem`으로 **크기**를 봤는가 — 크기가 전략을 결정한다
2. `-TotalCount 3`으로 형식을 확인했는가
3. `$PSVersionTable.PSVersion`을 확인했는가 — 인코딩 기본값이 다르다
4. 한글이 깨지면 `-Encoding utf8` / `-Encoding oem`을 둘 다 시도했는가
5. 여러 줄 정규식이 필요한데 `-Raw`를 빠뜨리지 않았는가
6. `-ReadCount`를 켠 상태에서 `$_`를 문자열로 다루고 있지 않은가
7. 줄 수를 `-Raw` 결과의 `.Count`로 세고 있지 않은가
8. 경로에 `[` `]`가 있는데 `-Path`를 쓰고 있지 않은가
9. `-Wait`가 멈춘 것처럼 보이면, 그 파일이 지금도 쓰이는 파일인가
10. 결과를 원본과 같은 볼륨에 쓰고 있지 않은가 — 증거 오염
11. 텍스트가 아닐 가능성 — 첫 4바이트 매직을 확인했는가
12. 검색·집계가 목적이면 `Select-String`으로 넘어갈 시점인가 ([FOR-0121](./powershell-select-string.html))

## 출처

- SRC-007 — Microsoft Learn, Select-String: `Get-Content` 출력을 파이프로 넘길 때의 동작과 `-Encoding` 파라미터 대응 확인
- `Get-Content` 자체의 파라미터 전체 목록(`-ReadCount`, `-Delimiter`, `-Wait`, `-AsByteStream`)은 Microsoft Learn의 `Get-Content` (Microsoft.PowerShell.Management) 문서가 1차 출처다. 이 SRC는 `research/sources.json`에 아직 없으므로 추가가 필요하다
- `-Wait`의 폴링 간격, `-Delimiter`의 구분자 잔류 동작은 PowerShell 버전에 따라 세부가 다를 수 있으므로 실제 환경에서 확인할 것
- 기본 인코딩(5.1 = ANSI, 7.x = UTF-8)은 버전 의존이다. `$PSVersionTable`로 먼저 확인할 것
