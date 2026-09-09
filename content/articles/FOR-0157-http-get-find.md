---
id: FOR-0157
title: "pcap에서 HTTP GET 요청 분석: 쿼리 명령·다운로드 파일·User-Agent 도구 식별"
slug: "http-get-find"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP request line", "User-Agent"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r c.pcapng -Y 'http.request.method == \"GET\"' -T fields -e http.host -e http.request.uri", "tshark -r c.pcapng -Y http.request -T fields -e http.user_agent | sort | uniq -c | sort -nr", "tshark -r c.pcapng -Y 'http.request.uri contains \"cmd=\"' -T fields -e frame.number -e http.request.full_uri"]
regex_patterns: ["(?i)[?&](cmd|exec|command|shell|c)=([^&\\s]+)", "(?i)(\\.\\./|%2e%2e%2f|%252e%252e%252f)", "(?i)(union(\\s|%20|/\\*)+select|information_schema|or(\\s|%20)+1=1|sleep\\()"]
wireshark_filters: ["http.request.method == \"GET\"", "http.request.uri contains \"cmd=\"", "http.request.uri contains \".php?\"", "http.request.uri matches \"\\\\.(zip|exe|dll|ps1|7z|rar)($|\\\\?)\"", "http.user_agent contains \"curl\"", "http.user_agent contains \"sqlmap\"", "http.referer", "!http.referer && http.request.method == \"GET\"", "http.response.code == 200 && http.content_length > 100000"]
tshark_fields: ["http.request.method", "http.request.uri", "http.request.full_uri", "http.host", "http.user_agent", "http.referer", "http.response.code", "http.content_length", "http.content_type", "http.request_in", "http.response_for.uri", "tcp.stream"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["HTTP GET 찾기", "GET 요청 분석", "다운로드 URI 찾기"]
keywords: ["HTTP GET", "GET 요청", "쿼리 문자열", "웹셸 cmd", "경로 순회", "User-Agent", "다운로드 파일", "Referer", "sqlmap", "certutil"]
aliases: ["http get 찾기", "get 요청 보기", "다운로드한 파일 찾기", "웹셸 명령 찾기", "user-agent 확인", "쿼리스트링 보기", "url 파라미터 찾기"]
symptom_keywords: ["다운로드한 파일 이름을 찾아야 한다", "어떤 명령을 보냈는지 알고 싶다", "스캐너인지 브라우저인지 구분해야 한다", "GET 요청이 너무 많다", "쿼리 문자열에 뭐가 있는지"]
related: ["FOR-0156", "FOR-0158", "FOR-0159"]
source_ids: ["SRC-002", "SRC-064", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

GET은 **모든 정보가 요청 라인에 노출된 메서드**다. `http.request.method == "GET"`으로 좁힌 뒤 URI의 쿼리 문자열(명령·경로순회·SQL), 확장자(다운로드 파일), `http.user_agent`(도구 정체), 응답 코드·크기(성공 여부) 네 축으로 읽으면 본문을 볼 필요가 없다.

## 어떤 문제에서 필요한가

- "공격자가 다운로드한 파일 이름을 구하라"
- "웹셸에 어떤 명령을 실행했는가" — 웹셸 명령은 대부분 GET 쿼리로 온다
- "스캐닝에 사용된 도구는 무엇인가"
- "어떤 경로를 탐색했는가 / 어떤 파일 목록을 시도했는가"
- "사용자가 어느 페이지를 거쳐 이 페이지에 도달했는가" (Referer)
- "SQL Injection 시도 문자열을 구하라"

POST는 본문을 꺼내는 단계가 필요하지만([FOR-0158](./http-post-find.html)), **GET은 필터 한 줄과 컬럼 설정만으로 끝난다.** 그래서 항상 GET을 먼저 본다.

## 문제에서 처음 볼 단서

1. `Info` 컬럼에 `GET /uploads/x.php?cmd=id HTTP/1.1` 형태로 **명령이 그대로 보인다**
2. Protocol Hierarchy에 HTTP가 있고 `Media Type` 또는 `JPEG File Interchange Format` 같은 하위 항목 = 파일 다운로드가 있었다
3. 지문의 "다운로드", "실행", "조회", "탐색", "스캔", "접속" 같은 표현
4. Conversations에서 **서버→클라이언트 방향** 바이트가 큰 대화 = GET 다운로드
5. 같은 IP에서 짧은 시간에 수백 개의 다른 URI 요청 = 디렉터리 브루트포스

## 30초 절차

```text
http.request.method == "GET"
```

컬럼 네 개를 올리면 그 자리에서 답이 보인다. 필드 우클릭 → `Apply as Column`:

```text
http.host  /  http.request.uri  /  http.user_agent  /  http.response.code
```

의심스러운 쿼리만 즉시 훑기:

```text
http.request.uri contains "cmd=" || http.request.uri contains "../" || http.request.uri contains "%2e%2e"
```

CLI 한 줄:

```bash
tshark -r capture.pcapng -Y 'http.request.method == "GET"' \
  -T fields -e frame.number -e http.host -e http.request.uri -e http.user_agent -E header=y
```

## 상세 절차

### 1단계 — GET 전체를 표로 확보

눈으로 훑는 것보다 표로 뽑아 정렬하는 것이 항상 빠르다.

```bash
tshark -r capture.pcapng -Y 'http.request.method == "GET"' \
  -T fields -e frame.number -e tcp.stream -e ip.src -e http.host \
            -e http.request.uri -e http.user_agent -e http.referer \
  -E header=y -E separator='|'
```

```text
frame.number|tcp.stream|ip.src|http.host|http.request.uri|http.user_agent|http.referer
221|3|10.0.0.15|shop.example.com|/|Mozilla/5.0 (Windows NT 10.0; Win64; x64)|
238|3|10.0.0.15|shop.example.com|/css/main.css|Mozilla/5.0 (Windows NT 10.0; Win64; x64)|http://shop.example.com/
1902|17|198.51.100.9|shop.example.com|/.git/config|Mozilla/5.00 (Nikto/2.1.6)|
2211|21|198.51.100.9|shop.example.com|/uploads/av4tar.php?cmd=id|curl/8.4.0|
2455|21|198.51.100.9|shop.example.com|/backup/db_2026.zip|curl/8.4.0|
```

**정적 리소스가 목록을 채운다.** `.css` `.js` `.png` `.woff`를 걸러내야 본질이 보인다.

```text
http.request.method == "GET" && !(http.request.uri matches "\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)($|\\?)")
```

`matches`는 정규식이며 **기본적으로 대소문자를 구분하지 않는다.** `.PNG`도 함께 걸러진다.

### 2단계 — 쿼리 문자열: 명령과 공격 문자열이 여기 있다

GET 쿼리는 URL 인코딩된 상태로 그대로 보인다. 유형별 필터:

| 유형 | 필터 | 실제로 보게 되는 값 |
| --- | --- | --- |
| 웹셸 명령 실행 | `http.request.uri matches "[?&](cmd\|exec\|command\|shell\|c)="` | `?cmd=whoami`, `?c=cat%20/etc/passwd` |
| 파일 읽기(LFI) | `http.request.uri matches "[?&](file\|page\|path\|include\|template\|doc)="` | `?file=../../etc/passwd` |
| 경로 순회 | `http.request.uri contains "../" \|\| http.request.uri contains "%2e%2e"` | `/download?f=..%2f..%2fetc%2fshadow` |
| SQL Injection | `http.request.uri matches "(union.{0,10}select\|information_schema\|or.{0,5}1=1\|sleep\\()"` | `?id=1%27%20UNION%20SELECT%201,2,3--` |
| 자격증명 노출 | `http.request.uri matches "[?&](user\|username\|pass\|passwd\|password\|pw\|token\|key\|api_key)="` | `?username=admin&password=1234` |
| 원격 파일 포함(RFI) | `http.request.uri matches "[?&][a-z]+=https?%3a"` | `?page=http%3a%2f%2fevil.tld%2fs.txt` |
| 명령 연결 문자 | `http.request.uri matches "(%3b\|%7c\|%26%26\|`)"` | `?ip=127.0.0.1%3bid` |

**GET에 자격증명이 실렸다면 그 자체가 취약점이고, 동시에 문제의 정답인 경우가 많다.** POST를 뒤지기 전에 GET 쿼리를 먼저 훑는다.

쿼리 부분만 따로 보는 필드가 버전에 따라 존재한다.

```bash
# http.request.uri.query 가 있는 버전이라면 쿼리만 뽑을 수 있다
tshark -r capture.pcapng -Y 'http.request.method == "GET" && http.request.uri contains "?"' \
  -T fields -e frame.number -e http.request.uri.query
```

없으면 `http.request.uri`를 그대로 받아 `?` 뒤를 자른다.

```bash
tshark -r capture.pcapng -Y 'http.request.method == "GET"' -T fields -e http.request.uri |
  grep '?' | sed 's/^[^?]*?//' | tr '&' '\n' | sort | uniq -c | sort -nr | head -30
```

파라미터 이름과 값의 빈도표가 나온다. **한 번만 등장한 파라미터가 공격 문자열이다.**

URL 디코딩을 잊지 않는다.

```bash
python3 -c "import urllib.parse,sys; print(urllib.parse.unquote_plus(sys.argv[1]))" \
  'cat%20/etc/passwd'
```

```powershell
[System.Uri]::UnescapeDataString('cat%20/etc/passwd')
```

### 3단계 — 다운로드 파일: 확장자로 찾는다

```text
http.request.uri matches "\\.(zip|rar|7z|tar|gz|exe|dll|msi|ps1|bat|vbs|jar|apk|pdf|docx?|xlsx?|sql|bak|db|pcap|txt|key|pem)($|\\?)"
```

한 줄로 후보를 모두 잡는다. 표로 뽑을 때는 응답까지 같이 본다.

```bash
tshark -r capture.pcapng \
  -Y 'http.request.method == "GET" && http.request.uri matches "\\.(zip|exe|dll|ps1|7z|rar|sql|bak)($|\\?)"' \
  -T fields -e frame.number -e http.host -e http.request.uri -e http.user_agent -E header=y
```

응답 측에서 파일 다운로드를 잡는 방법도 있다. 요청 확장자가 위장되어 있을 때 이쪽이 더 정확하다.

```text
http.response.code == 200 && http.content_type contains "application/octet-stream"
http.response.code == 200 && http.content_length > 100000
http.response.code == 200 && http.header contains "attachment"
```

마지막 필터의 `http.header`는 버전에 따라 없을 수 있다. 대신 `http.file_data contains "attachment"`가 아니라 **Follow HTTP Stream으로 `Content-Disposition` 헤더를 눈으로 확인**하는 것이 확실하다.

실제 파일을 얻는 것은 Export Objects의 몫이다 ([FOR-0165](./export-objects-http.html)).

### 4단계 — User-Agent: 도구를 특정한다

`http.user_agent` 하나로 "사람이 브라우저로 했는가 / 스크립트가 했는가"가 갈린다.

```bash
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.user_agent |
  sort | uniq -c | sort -nr
```

```text
    412 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
     88 Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)
     31 curl/8.4.0
     14 sqlmap/1.7#stable (https://sqlmap.org)
      6 Microsoft-CryptoAPI/10.0
      3 
```

식별표 — 문자열의 **고정 부분**만 신뢰한다. 버전 숫자는 환경마다 다르다.

| User-Agent에 들어 있는 문자열 | 클라이언트 | 포렌식 해석 |
| --- | --- | --- |
| `curl/` | curl | 스크립트/수동 CLI. 다운로드·웹셸 호출 |
| `Wget/` | wget | 리눅스 측 다운로드 |
| `python-requests/` | Python requests | 자동화 스크립트, C2 비컨 |
| `python-urllib` / `Python-urllib/` | Python 표준 라이브러리 | 같음 |
| `Go-http-client/` | Go 프로그램 | 최근 멀웨어/툴에서 흔하다 |
| `sqlmap/` | sqlmap | **SQL Injection 자동화. 그 자체가 공격 증거** |
| `Nikto/` | Nikto | 웹 취약점 스캐너. 404 급증과 함께 나타난다 |
| `Nmap Scripting Engine` | Nmap NSE (`http-*` 스크립트) | 포트/웹 스캔 |
| `WindowsPowerShell/` 또는 `PowerShell/` | `Invoke-WebRequest` / `Invoke-RestMethod` | **Windows 측 파일 다운로드.** EVTX 4104와 대조 |
| `Microsoft-CryptoAPI/` | `certutil -urlcache -f <url>` 계열 | LOLBin 다운로드 |
| `Microsoft BITS/` | BITS 전송(`bitsadmin`, `Start-BitsTransfer`) | 백그라운드 다운로드. 은닉 목적 |
| `Java/` | Java 런타임 | 취약 앱/익스플로잇 페이로드 |
| `libwww-perl` / `LWP::` | Perl 스크립트 | 오래된 자동화 |
| (빈 값) | UA 헤더 없음 | 직접 소켓으로 만든 요청. **거의 항상 도구다** |
| `Mozilla/5.0 ... Chrome/... Safari/...` | 실제 브라우저 | 정상 사용자 후보 |

UA가 비어 있는 요청은 이렇게 잡는다.

```text
http.request && !http.user_agent
```

**UA는 위조 가능하다.** `curl -A "Mozilla/5.0"`이면 브라우저처럼 보인다. 그래서 UA만으로 결론짓지 않고 아래 두 가지와 교차한다.

| 위조 판정 근거 | 왜 |
| --- | --- |
| 정적 리소스를 안 가져간다 | 브라우저는 HTML을 받으면 `.css`/`.js`/이미지를 반드시 뒤따라 요청한다. HTML만 받고 끝나면 스크립트다 |
| `Referer`가 전혀 없다 | 브라우저 내 링크 이동에는 Referer가 붙는다 |
| 요청 간격이 기계적으로 일정하다 | `http.time`이나 프레임 시각의 간격이 초 단위로 균일하면 스크립트 |
| `Accept-Language`/`Accept-Encoding` 헤더가 없다 | 브라우저는 항상 보낸다 |

### 5단계 — Referer: 유입 경로를 잇는다

```bash
tshark -r capture.pcapng -Y 'http.request.method == "GET" && http.referer' \
  -T fields -e http.referer -e http.request.uri -E header=y | sort -u | head -30
```

| 관찰 | 해석 |
| --- | --- |
| `Referer`가 같은 사이트 페이지 | 정상 내부 링크 이동 |
| `Referer`가 검색엔진 | 외부 유입 |
| `Referer`가 외부 낯선 도메인 | 피싱/악성 리다이렉트 유입 지점 |
| **`Referer`가 아예 없다** | 주소창 직접 입력, 북마크, 또는 **스크립트** |
| `Referer`에 세션 토큰/비밀번호 | 토큰 유출 취약점. 그 값이 답인 문제가 있다 |

Referer가 없는 GET만 보는 필터:

```text
http.request.method == "GET" && !http.referer && !(http.request.uri matches "\\.(css|js|png|ico)$")
```

### 6단계 — 응답과 짝지어 성공 판정

GET을 찾았어도 **그 요청이 성공했는지는 응답이 말한다.** 요청만 보고 답을 제출하는 것이 가장 흔한 실수다.

```bash
tshark -r capture.pcapng -Y 'http.response' \
  -T fields -e frame.number -e http.request_in -e http.response.code \
            -e http.content_length -e http.response_for.uri -E header=y
```

```text
frame.number  http.request_in  http.response.code  http.content_length  http.response_for.uri
1908          1902             404                 291                  http://shop.example.com/.git/config
2218          2211             200                 34                   http://shop.example.com/uploads/av4tar.php?cmd=id
2470          2455             200                 4194304              http://shop.example.com/backup/db_2026.zip
```

- `404 / 291바이트` = 실패. 존재하지 않는 경로
- `200 / 34바이트` = 웹셸이 명령 출력을 돌려줬다. **실행 성공**
- `200 / 4194304바이트` = 4 MB 파일이 실제로 나갔다. **유출 확정**

`http.response_for.uri` 컬럼이 요청/응답을 손으로 맞추는 수고를 없앤다. 자세한 코드 해석은 [FOR-0161](./http-status-analysis.html).

## 출력 필드 해석

| 필드 | 의미 | GET 분석에서의 쓸모 |
| --- | --- | --- |
| `http.request.method` | `GET` | 문자열. 큰따옴표와 대문자 필수 |
| `http.request.uri` | 경로+쿼리 | **본문 없는 GET에서는 이것이 전부다** |
| `http.request.full_uri` | 스킴+호스트+경로+쿼리 | 보고서에 그대로 붙일 값 |
| `http.host` | Host 헤더 | 가상 호스트 구분 ([FOR-0160](./http-host-filter.html)) |
| `http.user_agent` | 클라이언트 문자열 | 도구 식별. **위조 가능** |
| `http.referer` | 유입 경로 | 없으면 스크립트 의심 |
| `http.request.version` | `HTTP/1.1` / `HTTP/1.0` | `HTTP/1.0` 단독은 구식 스크립트 신호 |
| `http.response.code` | 응답 코드 | 성공/실패 판정 |
| `http.content_length` | 응답 본문 크기 | **유출량. 0이면 출력 없음** |
| `http.content_type` | 응답 MIME | `application/octet-stream` = 파일 |
| `http.request_in` | 응답에 붙는 요청 프레임 번호 | 짝짓기 |
| `http.response_for.uri` | 응답에 붙는 요청 URI | 짝짓기 |
| `tcp.stream` | 연결 인덱스 | Follow로 직행 ([FOR-0164](./tcp-stream-filter.html)) |

## pivot: 다음에 볼 artifact

| GET에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 다운로드 파일명 | Export Objects ([FOR-0165](./export-objects-http.html)) | 실제 바이트와 해시 |
| 다운로드 파일명 | `$MFT` ([FOR-0021](./mft-basics.html)) | 디스크에 저장된 시각과 경로 |
| 다운로드 파일명 | 브라우저 다운로드 기록 ([FOR-0191](./chrome-history.html)) | 사용자가 직접 받았는가 |
| `?cmd=` 명령 문자열 | EVTX 4688 ([FOR-0088](./event-4688-process-creation.html)), PowerShell 4104 ([FOR-0097](./powershell-4104-scriptblock.html)) | 서버에서 실제 실행됐는가 |
| 웹셸 URI | 그 URI로의 POST ([FOR-0158](./http-post-find.html)) | 업로드 시점 |
| User-Agent | 같은 UA의 모든 요청 | 그 도구의 활동 전체 |
| 공격자 IP | `ip.addr == <IP>` | 스캔→침입→유출 흐름 |
| 404가 몰린 URI 목록 | 스캐너 지문 | 사용한 도구/워드리스트 |
| Referer 도메인 | DNS 질의, 접속 도메인 목록 ([FOR-0160](./http-host-filter.html)) | 유입 경로 재구성 |
| 응답 크기 | `Statistics > Conversations` | 총 유출량 |

## 흔한 함정

- **`http.request.method == GET` 처럼 따옴표를 빼는 것.** 문법 오류로 필터가 빨갛게 되거나 엉뚱하게 해석된다. `"GET"`으로, 대문자로 쓴다.
- **`http.request.uri contains "../"` 만 믿는 것.** 실제 공격은 `..%2f`, `%2e%2e/`, `..%252f`(이중 인코딩)로 온다. URI 필드에는 **인코딩된 원문이 들어 있어** 디코딩된 문자열로는 안 걸린다. `matches "(\\.\\./|%2e%2e|%252e)"`로 함께 잡는다.
- **정적 리소스를 걸러내지 않는 것.** `.css`/`.js`/이미지가 요청의 80%를 차지해 실제 공격 요청이 묻힌다. 1단계의 제외 필터를 먼저 적용한다.
- **요청만 보고 성공했다고 판단하는 것.** `?cmd=` 요청이 있어도 응답이 404/403이면 실행되지 않았다. 응답 코드와 `http.content_length`를 반드시 확인한다.
- **User-Agent를 신원으로 믿는 것.** 위조가 자유롭다. 정적 리소스 후속 요청 유무, Referer 유무, 요청 간격으로 교차검증한다.
- **`http.user_agent contains "Mozilla"`로 브라우저를 판정하는 것.** Nikto·Nmap NSE 등 다수 스캐너의 UA도 `Mozilla`로 시작한다. 문자열 전체를 봐야 한다.
- **HEAD/OPTIONS를 놓치는 것.** 스캐너는 `HEAD`로 존재만 확인하고 `OPTIONS`로 허용 메서드를 캐낸다. `http.request.method in {"HEAD" "OPTIONS" "PUT" "DELETE" "TRACE"}`도 한 번 돌린다.
- **GET에 자격증명이 없다고 가정하는 것.** 잘못 만든 앱은 `?password=`를 GET으로 보낸다. POST만 뒤지면 놓친다.
- **캐시된 요청을 성공으로 세는 것.** `304 Not Modified`는 본문이 전송되지 않았다. 다운로드 성공이 아니다.
- **HTTPS 요청을 GET 필터로 찾는 것.** TLS 안의 GET은 `http` 필터에 안 걸린다. SNI(`tls.handshake.extensions_server_name`)까지가 한계다.
- **URL 디코딩을 건너뛰고 답을 제출하는 것.** `cat%20/etc/passwd`는 `cat /etc/passwd`다. `%20`은 공백, 쿼리 문맥의 `+`도 공백이다.
- **시간을 상대 초로 두고 다른 로그와 대조하는 것.** `View > Time Display Format > UTC Date and Time of Day`로 먼저 바꾼다. KST는 UTC+9이므로 `07:22:41 UTC` = `16:22:41 KST`다.

## 교차검증

```bash
# 1) GET 요청 개수
tshark -r capture.pcapng -Y 'http.request.method == "GET"' | wc -l

# 2) 요청된 URI 빈도표 — 반복 = 정상, 1회 = 특이
tshark -r capture.pcapng -Y 'http.request.method == "GET"' -T fields -e http.request.uri |
  sort | uniq -c | sort -nr | head -30

# 3) User-Agent 빈도표 — 종류가 곧 클라이언트 수
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.user_agent |
  sort | uniq -c | sort -nr

# 4) 응답 코드 분포 — 404 급증 = 스캔
tshark -r capture.pcapng -Y 'http.response' -T fields -e http.response.code |
  sort | uniq -c | sort -nr

# 5) 파서를 우회한 확인 — Wireshark가 놓친 GET 라인까지
strings -n 8 capture.pcapng | grep -E '^GET /' | sort -u | head -30

# 6) 서버 로그와 대조 (있다면) — URI·UA·상태 코드가 동일하게 남는다
grep -E '"GET /(uploads|backup)' access.log
```

2)와 5)의 결과가 다르면 Wireshark가 일부 요청을 HTTP로 인식하지 못한 것이다. 비표준 포트(`Decode As`)나 잘린 캡처를 의심한다. 서버 로그가 함께 주어졌다면 6)이 최종 근거다 ([FOR-0121](./powershell-select-string.html)).

## mini walkthrough

```text
문제:
"침해된 웹서버에서 공격자가 유출한 파일 이름과, 유출에 사용한 도구를 구하세요."
첨부: exfil.pcapng (12,904 packets, 9 MB)

1. 첫 시도 (실패):
   File > Export Objects > HTTP 를 열어 큰 파일을 찾으려 했다.
   목록에 .zip 이 없고 .css/.js/.png 만 수백 개 나왔다.
   원인: 유출 응답이 Transfer-Encoding: chunked 로 왔고,
        Wireshark 가 이 응답을 객체 목록에 올리지 못한 상태였다.
   -> Export Objects 를 근거로 "파일 전송이 없다"고 결론내면 오답이다.

2. 접근 변경 — 요청 측에서 확장자로 찾는다
   필터:
     http.request.method == "GET" &&
     http.request.uri matches "\\.(zip|rar|7z|tar|gz|sql|bak|db)($|\\?)"

   frame  host              uri                        user_agent
   2455   shop.example.com  /backup/db_2026.zip        curl/8.4.0
   2601   shop.example.com  /backup/db_2026.zip.md5    curl/8.4.0

   -> 후보 확보. 하지만 요청이 있었다는 사실만으로는 유출 확정이 아니다.

3. 응답을 짝지어 성공 판정
   tshark -r exfil.pcapng -Y 'http.response' \
     -T fields -e http.request_in -e http.response.code \
               -e http.content_length -e http.transfer_encoding \
               -e http.response_for.uri -E header=y | grep db_2026

   2455  200  (빈칸)  chunked  http://shop.example.com/backup/db_2026.zip
   2601  200  32              http://shop.example.com/backup/db_2026.zip.md5

   -> content_length 가 비어 있는 이유가 1단계 실패의 원인이었다(chunked).
      크기는 Statistics > Conversations 에서 확인한다.

4. 실제 전송량 확인
   필터: tcp.stream eq 21   (frame 2455 의 스트림)
   Statistics > Conversations > TCP -> 그 행의 Bytes = 4,201,880

   -> 4 MB 가 실제로 나갔다. 유출 확정.

5. 도구 식별 — User-Agent 전수 조사
   tshark -r exfil.pcapng -Y 'http.request' -T fields -e http.user_agent |
     sort | uniq -c | sort -nr

      412 Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/122.0.0.0 ...
       88 Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)
       31 curl/8.4.0
       14 sqlmap/1.7#stable (https://sqlmap.org)

   -> 유출 요청(frame 2455)의 UA 는 curl/8.4.0.
      Nikto 는 정찰, sqlmap 은 침입 단계의 도구였다.

6. 공격 흐름 재구성 — 같은 IP 로 전체를 본다
   필터: ip.addr == 198.51.100.9 && http.request

   시각(UTC)      uri                              ua
   07:11:03~07:14  /.git/config, /admin, /phpmyadmin ...  Nikto/2.1.6   (404 88건)
   07:19:22~07:21  /product.php?id=1'+UNION+SELECT... sqlmap/1.7        (200)
   07:22:41        /uploads/av4tar.php?cmd=id         curl/8.4.0        (200, 34B)
   07:24:10        /backup/db_2026.zip                curl/8.4.0        (200, 4 MB)

   KST 로는 16:11 ~ 16:24.

7. 교차검증 — 파서 우회
   strings -n 8 exfil.pcapng | grep -E '^GET /backup'
   GET /backup/db_2026.zip HTTP/1.1
   -> 요청 라인이 원문에도 존재. Wireshark 파싱 결과와 일치.

정답: db_2026.zip / curl (정찰 Nikto, SQLi sqlmap)
```

1단계의 실패가 핵심이다. **Export Objects의 부재는 파일 부재의 증거가 아니다.** chunked 응답은 목록에서 빠질 수 있고, 그때는 요청 측 URI 확장자와 `Statistics > Conversations`의 실제 바이트가 진실을 말한다. 그리고 `curl` 하나로 끝내지 않고 UA 빈도표를 전수 조사한 덕분에 정찰-침입-유출 3단 흐름이 드러났다.

## 막혔을 때 다음 체크

1. `http.request.method == "GET"` 에 **따옴표와 대문자**를 썼는가
2. `.css`/`.js`/이미지를 제외 필터로 걸러냈는가 — 안 하면 노이즈에 묻힌다
3. `http.host` `http.request.uri` `http.user_agent` `http.response.code`를 **컬럼으로 올렸는가**
4. 쿼리 문자열을 URL 디코딩했는가 — `%20`, `+`, `%2f`, 이중 인코딩(`%252e`)
5. `contains "../"` 가 0건이면 `matches "(%2e%2e|%252e)"` 로 다시 시도했는가
6. 확장자 필터(`matches "\\.(zip|exe|ps1)($|\\?)"`)를 돌렸는가
7. **응답 코드와 `http.content_length`로 성공 판정**을 했는가
8. `http.user_agent` 빈도표를 전수로 뽑았는가 — UA 종류 수 = 클라이언트 종류 수
9. UA가 **빈 요청**(`http.request && !http.user_agent`)을 확인했는가
10. `HEAD` / `OPTIONS` / `PUT` 도 확인했는가
11. Referer가 없는 GET을 따로 봤는가 — 스크립트 신호
12. Export Objects가 비었다면 chunked·비표준 포트·잘린 캡처를 확인했는가 ([FOR-0165](./export-objects-http.html))
13. 시간을 UTC 절대시각으로 바꿨는가 (KST = UTC+9)
14. TLS뿐이면 SNI로 전환했는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `http.request.method`, `http.request.uri`, `http.user_agent`, `http.referer`, `http.request_in`, `http.response_for.uri` 필드 이름과 자료형, `contains` / `matches` 연산자 동작
- SRC-064 — RFC 9110 HTTP Semantics: GET/HEAD/OPTIONS 메서드 정의, `Referer` / `User-Agent` / `Content-Disposition` 헤더, `304 Not Modified` 의미
- SRC-010 — tshark man page: `-Y`, `-T fields`, `-e`, `-E header=y`, `-E separator=`
- User-Agent 문자열의 버전 숫자(`curl/8.4.0`, `Nikto/2.1.6`, `Microsoft-CryptoAPI/10.0` 등)는 환경마다 다르다. **고정 부분(도구 이름)만 판정 근거로 쓸 것**
- `http.request.uri.query`, `http.header` 처럼 버전에 따라 없을 수 있는 필드는 필터 입력창 색으로 존재를 확인할 것
- 메뉴 경로(`Apply as Column`, `View > Time Display Format`)는 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
