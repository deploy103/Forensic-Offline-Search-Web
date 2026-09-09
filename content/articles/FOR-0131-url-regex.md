---
id: FOR-0131
title: "URL regex: 어디서 URL이 끝나는지 정하는 문제"
slug: "url-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["access.log", "proxy log", "memory strings", "eml 본문", "History", "Sysmon 22"]
file_paths: ["/var/log/nginx/access.log", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "HTTPS", "FTP", "WebSocket"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "strings", "tshark"]
commands: ["grep -Eoi 'https?://[^ \"<>]+' access.log", "grep -Poi '\\bhttps?://[^\\s\"<>]*[^\\s\"<>.,;:!?)\\]}]' strings.txt", "strings -a -el mem.raw | grep -Eoi 'https?://[^ \"<>]+' | sort -u", "tshark -r c.pcapng -T fields -e http.request.full_uri -Y http.request"]
regex_patterns: ["https?://[^\"'<> ]+", "[a-zA-Z][a-zA-Z0-9+.-]*://[^\\s\"'<>]+", "\\bhttps?://[^\\s\"'<>]*[^\\s\"'<>.,;:!?)\\]}]", "\\bhttps?://(?:[^\\s()<>\"']+|\\([^\\s()<>\"']*\\))+(?<![.,;:!?'\"])", "%[0-9A-Fa-f]{2}", "%25(?:2e|2f|5c|00)", "\\.\\.(?:%2[fF]|%5[cC]|/|\\\\)", "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?"]
wireshark_filters: ["http.request.full_uri contains \"cmd=\"", "http.request.method == \"GET\""]
tshark_fields: ["http.request.full_uri", "http.host", "http.request.uri"]
log_fields: ["cs-uri-stem", "cs-uri-query", "request", "Referer"]
file_formats: ["log", "txt", "eml", "csv"]
primary_terms: ["URL regex", "url 정규식", "링크 추출"]
keywords: ["URL regex", "url 정규식", "링크 추출", "URI 파싱", "scheme", "쿼리스트링", "프래그먼트", "퍼센트 인코딩", "percent encoding", "urlencode", "urllib.parse", "System.Uri", "url 경계"]
aliases: ["url 정규식", "url 추출", "링크 정규식", "url 뽑기", "grep url", "http 링크 찾기", "url 파싱 정규식"]
symptom_keywords: ["URL만 뽑고 싶다", "URL 끝에 괄호가 붙어 나온다", "URL이 중간에서 잘린다", "메모리에서 C2 URL을 찾고 싶다", "쿼리스트링만 분리하고 싶다", "퍼센트 인코딩된 URL을 못 읽는다"]
related: ["FOR-0130", "FOR-0158", "FOR-0128"]
source_ids: ["SRC-064", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

URL 정규식의 난점은 "URL이 어떻게 생겼는가"가 아니라 **"어디서 끝나는가"** 다. 구두점·괄호·따옴표가 URL의 일부일 수도 있고 문장의 일부일 수도 있기 때문에, `https?://[^\s"'<>]+`로 넉넉히 잡은 뒤 후행 구두점을 코드에서 잘라내고 `urllib.parse.urlsplit` / `System.Uri`로 파싱해 확정한다.

## 개념

URL은 정해진 순서의 조각으로 이루어진다.

```text
https://user:pass@www.example.com:8443/a/b.php?id=3&x=%2Fetc%2Fpasswd#frag
\___/   \_______/ \_____________/ \__/\_______/ \______________________/ \__/
scheme  userinfo       host       port   path            query           frag
```

| 조각 | 구분자 | 허용 문자(대략) | 포렌식에서 보는 이유 |
| --- | --- | --- | --- |
| scheme | 뒤에 `://` 또는 `:` | 첫 글자는 문자, 이후 문자·숫자·`+`·`-`·`.` | `file://`, `ws://`, `data:` 는 그 자체가 단서 |
| userinfo | 뒤에 `@` | `@`·`/`·`?`·`#` 을 뺀 나머지 | URL 에 박힌 평문 자격증명 |
| host | `@` 뒤 `:` `/` `?` `#` 앞 | 도메인, IPv4, `[IPv6]` | 목적지 판정의 핵심 |
| port | 앞에 `:` | 숫자 | 비표준 포트가 C2 지표 |
| path | `/` 로 시작 | 슬래시 구분 세그먼트 | 웹셸 파일명, 다운로드 대상 |
| query | 앞에 `?` | `key=value&...` | 명령·유출 데이터가 실린다 |
| fragment | 앞에 `#` | 나머지 전부 | 서버로 전송되지 않는다 |

### 왜 "끝"이 어려운가

문서·로그·메모리에는 URL이 문장 속에, 따옴표 속에, 괄호 속에 들어 있다. 그런데 **그 구두점들이 URL에 합법적으로 들어갈 수도 있다.**

| 원문 | 사람이 읽는 URL | 순진한 `\S+` 결과 |
| --- | --- | --- |
| `자세히는 http://a.com/x.` | `http://a.com/x` | `http://a.com/x.` |
| `(http://a.com/x)` | `http://a.com/x` | `http://a.com/x)` |
| `"http://a.com/x",` | `http://a.com/x` | `http://a.com/x",` |
| `http://a.com/w/Foo_(bar)` | `http://a.com/w/Foo_(bar)` | 맞다 |
| `<a href="http://a.com/x">` | `http://a.com/x` | `http://a.com/x">` |
| `http://a.com/a?b=1&c=2.` | `http://a.com/a?b=1&c=2` | 끝의 `.` 이 붙는다 |

4번째 줄과 2번째 줄이 **서로 모순된다.** 닫는 괄호를 버리면 위키 스타일 URL이 잘리고, 살리면 문장 속 URL에 괄호가 붙는다. **정규식만으로는 둘을 동시에 만족시킬 수 없다.** 그래서 순서는 정해져 있다.

1. 넉넉히 잡는다 (재현율 우선)
2. 후행 구두점을 잘라낸다 (코드에서, 규칙을 명시적으로)
3. 파서에 넘겨 host·path·query를 분해한다 (판정)

## 파일 / 경로

| 대상 | 경로/필드 | URL 이 나오는 형태 |
| --- | --- | --- |
| nginx/Apache | `access.log` | `"GET /a/b.php?id=3 HTTP/1.1"` — 스킴과 호스트가 없다 |
| IIS | `C:\inetpub\logs\LogFiles\W3SVC*\*.log` | `cs-uri-stem` + `cs-uri-query` 로 분리되어 있다 |
| 프록시 로그 | 벤더별 | 전체 URL 이 한 필드에 들어간다 |
| pcap | `*.pcapng` | `http.request.full_uri` (Wireshark 가 합성해 준다) |
| 메모리 덤프 | `*.raw`, `*.mem` | `strings` 결과. C2 URL이 그대로 남는다 |
| 브라우저 히스토리 | `History` (SQLite) | `urls.url` |
| 메일 | `*.eml` | 본문(HTML/quoted-printable/base64 안쪽) |
| Sysmon | 이벤트 22 `QueryName` | 호스트만. URL 전체는 없다 |
| 문서 | `*.docx`, `*.pdf` | 하이퍼링크 대상 |

**access.log 에는 스킴과 호스트가 없다.** 요청 라인은 `GET /path HTTP/1.1` 이고 호스트는 `Host:` 헤더에 있다. 로그 포맷에 `%{Host}i`가 없으면 전체 URL을 만들 수 없다. `http://`를 찾는 패턴을 access.log 에 돌려서 아무것도 안 나오면 이것 때문이다.

## 주요 필드

### 패턴 1 — 느슨한 후보 수집 (가장 많이 쓴다)

```text
https?://[^"'<> ]+
```

`grep -E`에서도 그대로 돌아간다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `http://a.com/x`, `https://a.com:8443/b?c=1#d`, `http://[2001:db8::1]/x` |
| 매칭 안 됨 | `ftp://a.com/x`, `www.a.com/x` (스킴 없음), `a.com/x` |
| **오탐** | 후행 구두점이 붙은 `http://a.com/x.`, `http://a.com/x),`, `http://a.com/x">` |

### 패턴 2 — 스킴을 넓힌 버전

```text
[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `ftp://a.com/f`, `file:///C:/x`, `ws://a.com/s`, `smb://srv/share` |
| 매칭 안 됨 | `mailto:a@b.com`, `data:text/plain;base64,...` (`//` 가 없다) |
| 오탐 | 코드의 `C://`, 주석 속 `example://`, 로그의 `proto://` 자리표시자 |

`mailto:`·`data:`·`javascript:` 는 `//`가 없으므로 별도 패턴이 필요하다.

```text
(?i)\b(?:mailto|data|javascript|vbscript|tel):[^\s"'<>]+
```

`javascript:` / `data:text/html;base64,` 는 그 자체가 악성 지표다. 반드시 함께 검색한다.

### 패턴 3 — 후행 구두점을 정규식에서 잘라내기 (PCRE / .NET / Python)

```text
\bhttps?://[^\s"'<>]*[^\s"'<>.,;:!?)\]}]
```

마지막 문자만 "구두점이 아닌 것"으로 강제한다. 탐욕적으로 먹은 뒤 backtracking 으로 구두점을 되돌린다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `자세히는 http://a.com/x.` → `http://a.com/x` |
| 매칭됨 | `("http://a.com/a?b=1"),` → `http://a.com/a?b=1` |
| 매칭 안 됨 | 스킴 없는 `www.a.com` |
| **오탐** | `http://a.com/w/Foo_(bar)` → `http://a.com/w/Foo_(bar` 로 잘린다 |

### 패턴 4 — 괄호 균형을 맞춘 heuristic

```text
\bhttps?://(?:[^\s()<>"']+|\([^\s()<>"']*\))+(?<![.,;:!?'"])
```

`(...)` 한 겹은 URL의 일부로 인정하고, 마지막 문자가 구두점이면 lookbehind로 거부한다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `http://a.com/w/Foo_(bar)`, `http://a.com/x` |
| 매칭됨 | `(http://a.com/x)` → `http://a.com/x` |
| 매칭 안 됨 | 중첩 괄호 `http://a.com/((x))` 는 완전히 처리하지 못한다 |
| 오탐 | `http://a.com/x)` 처럼 닫는 괄호만 있으면 붙여서 잡는다 |

**중첩 괄호 균형은 정규식의 능력 밖이다.** 여기서 멈추고 파서로 넘긴다.

### 패턴 5 — 스킴 없는 URL / 호스트+경로

```text
(?i)\b(?:www\.|[a-z0-9-]+\.)+[a-z]{2,63}(?::\d{1,5})?(?:/[^\s"'<>]*)?
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `www.example.com/a/b`, `example.com:8080/x` |
| 매칭 안 됨 | `/a/b.php?id=3` (호스트 없음) |
| **오탐** | `report.pdf`, `System.Net.Http`, `nginx/1.20.1` — 도메인 오탐이 그대로 온다 |

스킴이 없으면 도메인 오탐 문제(FOR-0130)를 전부 물려받는다. 스킴이 있는 URL을 먼저 처리하고, 이 패턴은 마지막에 따로 돌린다.

### 패턴 6 — 경로만 (access.log 용)

```text
"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ([^ "]+) HTTP/[0-9.]+"
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `"GET /a/b.php?id=3 HTTP/1.1"` → 2번 그룹 `/a/b.php?id=3` |
| 매칭 안 됨 | 잘린 요청 라인, `"-"` 로 찍힌 줄 |
| 오탐 | User-Agent 안에 `HTTP/1.1` 문자열이 들어 있는 조작된 요청 |

### 패턴 7 — URL 을 조각으로 분해

```text
^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
```

| 그룹 | 의미 | `http://a.com:8443/x?y=1#z` 에서 |
| --- | --- | --- |
| 2 | scheme | `http` |
| 4 | authority (userinfo+host+port) | `a.com:8443` |
| 5 | path | `/x` |
| 7 | query | `y=1` |
| 9 | fragment | `z` |

authority 를 다시 쪼갠다.

```text
^(?:([^@]*)@)?(\[[^\]]+\]|[^:]*)(?::(\d+))?$
```

| 그룹 | 의미 |
| --- | --- |
| 1 | userinfo (`user:pass`) |
| 2 | host (`[IPv6]` 포함) |
| 3 | port |

**이 분해 정규식은 "검증"이 아니라 "분해"용이다.** 잘못된 URL 도 조각으로 나눠 준다. 검증은 파서가 한다.

### 패턴 8 — 퍼센트 인코딩

| 목적 | 패턴 | 무엇을 잡나 |
| --- | --- | --- |
| 인코딩 바이트 | `%[0-9A-Fa-f]{2}` | 정상 퍼센트 인코딩 |
| 잘못된 퍼센트 | `%(?![0-9A-Fa-f]{2})` | `%` 뒤에 hex 2자리가 없는 것 |
| 이중 인코딩 | `%25(?:2[eEfF]\|5[cC]\|00)` | `%252e` = `%2e` = `.` |
| 경로 탈출 | `\.\.(?:%2[fF]\|%5[cC]\|/\|\\)` | `../`, `..%2f`, `..%5c` |
| 널 바이트 주입 | `%00` | 확장자 우회 |
| UTF-8 다바이트 | `(?:%[cCdD][0-9A-Fa-f]%[89aAbB][0-9A-Fa-f])` | 한글 등 |
| 공백 | `%20\|\+` | 쿼리에서 `+` 는 공백이다 |

**쿼리스트링에서 `+`는 공백이고, 경로에서 `+`는 리터럴 `+`다.** `unquote`만 쓰면 쿼리의 `+`가 그대로 남는다. 쿼리는 `unquote_plus`(또는 `parse_qsl`)로 푼다.

## 빠른 명령

### grep / ripgrep

셸 인용을 단순하게 유지하려고 문자 클래스에서 작은따옴표를 뺐다. 필요하면 패턴을 파일에 넣고 `grep -f` 로 쓴다.

```bash
# 1) 후보 전부 (ERE)
grep -Eoi 'https?://[^ "<>]+' access.log | sort -u

# 2) 후행 구두점을 잘라낸 실전 패턴 (PCRE 전용)
grep -Poi '\bhttps?://[^\s"<>]*[^\s"<>.,;:!?)\]}]' strings.txt | sort -u

# 3) 스킴 전체 + mailto/data/javascript 까지
grep -Eoi '[a-z][a-z0-9+.-]*://[^ "<>]+|(mailto|data|javascript):[^ "<>]+' strings.txt

# 4) 메모리 strings 에서 URL — 두 인코딩을 모두 훑는다
strings -a -n 8 mem.raw     | grep -Eoi 'https?://[^ "<>]+' | sort -u > url_ascii.txt
strings -a -n 8 -el mem.raw | grep -Eoi 'https?://[^ "<>]+' | sort -u > url_utf16.txt
cat url_ascii.txt url_utf16.txt | sort -u | wc -l

# 5) 호스트만 뽑아 빈도 (외부 통신 대상 목록화)
grep -Eoi 'https?://[^/ "<>]+' access.log |
  sed -E 's#^https?://##; s#^[^@]*@##; s#:[0-9]+$##' |
  tr 'A-Z' 'a-z' | sort | uniq -c | sort -nr | head -20

# 6) 쿼리스트링이 있는 요청만 + 파라미터 이름 집계
grep -Eo '\?[^ "]+' access.log | tr '?&' '\n\n' |
  grep -Eo '^[A-Za-z0-9_%.-]+=' | sort | uniq -c | sort -nr | head

# 7) 경로 탈출 / 이중 인코딩 / 널 바이트 — 공격 흔적
grep -Ein '\.\.(%2[fF]|%5[cC]|/|\\)|%25(2[eEfF]|5[cC]|00)|%00' access.log

# 8) 비표준 포트로 나가는 URL
grep -Eoi 'https?://[^/ ]+:[0-9]{1,5}' proxy.log |
  grep -Ev ':(80|443)$' | sort | uniq -c | sort -nr

# 9) access.log 의 요청 라인에서 경로만 (필드가 확실하면 awk 가 정확하다)
awk -F'"' '{split($2,a," "); print a[2]}' access.log | sort | uniq -c | sort -nr | head

# 10) pcap 은 정규식 대신 필드를 쓴다
tshark -r c.pcapng -T fields -e http.request.full_uri -Y 'http.request' | sort -u | head

# 11) ripgrep
rg -oiP '(?<![\w-])https?://[^\s"<>]*[^\s"<>.,;:!?)\]}]' .
```

출력 예:

```text
$ grep -Poi '\bhttps?://[^\s"<>]*[^\s"<>.,;:!?)\]}]' strings.txt | sort -u | head -4
http://203.0.113.77:8443/gate.php
http://cdn.example.com/jquery.min.js
https://update.example.com/v2/manifest.json
https://www.microsoft.com/pki/crl
```

### PowerShell

```powershell
# 정규식은 항상 작은따옴표. 큰따옴표 안의 $ 는 변수로 확장된다
$re = '(?i)\bhttps?://[^\s"''<>]*[^\s"''<>.,;:!?)\]}]'
$cand = Select-String -Path .\strings.txt -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# 정규식이 아니라 .NET 파서로 확정한다
$uri = [System.Uri]$null
$parsed = $cand | ForEach-Object {
  $ok = [System.Uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$uri)
  if ($ok) {
    [pscustomobject]@{
      Url      = $_
      Scheme   = $uri.Scheme
      Host     = $uri.Host
      Port     = $uri.Port
      Path     = $uri.AbsolutePath
      Query    = $uri.Query
      UserInfo = $uri.UserInfo
      Decoded  = [System.Net.WebUtility]::UrlDecode($uri.Query)
    }
  }
}

# 외부 통신 대상 목록
$parsed | Group-Object Host | Sort-Object Count -Descending |
  Select-Object -First 20 Count, Name

# 비표준 포트 = C2 후보
$parsed | Where-Object { $_.Port -notin 80,443 } | Format-Table Url, Host, Port

# URL 에 박힌 평문 자격증명
$parsed | Where-Object { $_.UserInfo } | Format-Table Url, UserInfo

# 경로 탈출 / 이중 인코딩
$parsed | Where-Object { $_.Url -match '\.\.(%2[fF]|%5[cC]|/|\\)|%25(2[eEfF]|5[cC]|00)|%00' }

# 퍼센트 인코딩 풀기 — 쿼리의 + 는 공백이다
[System.Net.WebUtility]::UrlDecode('a=%2Fetc%2Fpasswd&b=hello+world')
# a=/etc/passwd&b=hello world
```

### Python

```python
import re, collections
from urllib.parse import urlsplit, unquote, unquote_plus, parse_qsl

URL = re.compile(r'''
    \b
    (?:https?|ftp|ftps|file|ws|wss)://
    (?:[^\s()<>"']+ | \([^\s()<>"']*\))+      # 괄호 한 겹은 URL 의 일부로 인정
    (?<![.,;:!?'"])                            # 마지막 문자가 구두점이면 거부
''', re.IGNORECASE | re.VERBOSE)

TRAILING = '.,;:!?\'")]}>'

text = open('strings.txt', encoding='utf-8', errors='replace').read()

rows = []
for m in URL.finditer(text):
    raw = m.group().rstrip(TRAILING)      # 정규식이 놓친 구두점은 여기서 자른다
    p = urlsplit(raw)                     # 판정은 파서가 한다
    if not p.scheme or not p.netloc:
        continue                          # 스킴/호스트가 없으면 URL 이 아니다
    rows.append({
        'url'   : raw,
        'scheme': p.scheme.lower(),
        'host'  : (p.hostname or '').lower(),
        'port'  : p.port,                 # 없으면 None
        'path'  : p.path,
        'query' : dict(parse_qsl(p.query, keep_blank_values=True)),  # + 를 공백으로 푼다
        'user'  : p.username,
        'pw'    : p.password,
    })

# 1) 외부 통신 대상
for host, n in collections.Counter(r['host'] for r in rows).most_common(20):
    print(f'{n:6d}  {host}')

# 2) 비표준 포트
for r in rows:
    if r['port'] not in (None, 80, 443):
        print(r['port'], r['url'])

# 3) URL 에 박힌 자격증명
print([ (r['user'], r['pw'], r['url']) for r in rows if r['user'] ])

# 4) 쿼리 파라미터 이름 집계 — cmd=, id=, data= 같은 것이 튀어나온다
print(collections.Counter(k for r in rows for k in r['query']).most_common(15))

# 5) 퍼센트 인코딩 이상 징후
SUSPECT = re.compile(r'\.\.(?:%2[fF]|%5[cC]|/|\\)|%25(?:2[eEfF]|5[cC]|00)|%00')
print([r['url'] for r in rows if SUSPECT.search(r['url'])])

# 6) 경로와 쿼리는 디코딩 함수가 다르다
print(unquote('/a%2Fb+c'))        # /a/b+c      (경로: + 는 리터럴)
print(unquote_plus('a%2Fb+c'))    # a/b c       (쿼리: + 는 공백)

# 7) 이중 인코딩은 두 번 풀어야 보인다
s = '%252e%252e%252fetc%252fpasswd'
print(unquote(s))                 # %2e%2e%2fetc%2fpasswd
print(unquote(unquote(s)))        # ../etc/passwd
```

**정규식으로 URL 의 유효성을 검증하려 하지 말고, 느슨하게 뽑아 후행 구두점을 자르고 `urlsplit` / `System.Uri.TryCreate`에 넘긴다.** 스킴·호스트가 없으면 URL 이 아니라는 판정은 파서가 한 줄로 해 준다.

## 함께 보는 artifact

| URL 을 얻은 뒤 | 다음에 볼 것 |
| --- | --- |
| 호스트 확정 | 도메인 규칙과 DNS 조회 흔적 (FOR-0130) |
| 응답 IP 확보 | IPv4/IPv6 로 전 로그 재검색 ([FOR-0128](./ipv4-regex.html)) |
| 경로에 웹셸 후보 | pcap 에서 그 경로의 POST 본문 ([FOR-0158](./http-post-find.html)) |
| 쿼리에 base64 값 | 디코딩해 명령/유출 데이터 확인 (FOR-0135) |
| 비표준 포트 | 방화벽 로그에서 같은 포트 세션 전수 조사 |
| 브라우저에서 방문했나 | `History` 의 `urls.url` ([FOR-0191](./chrome-history.html)) |
| 메모리에서만 발견 | 그 프로세스의 명령행과 로드 모듈 ([FOR-0214](./volatility-pslist.html)) |

## 흔한 실수

- **`https?://\S+`로 뽑고 끝내는 것.** 결과의 상당수에 후행 `.`·`)`·`"`·`,`가 붙는다. 그 상태로 `sort -u`하면 같은 URL이 여러 항목으로 갈라져 빈도 순위가 무너진다. 마지막 문자를 제한하거나 코드에서 `rstrip`한다.
- **닫는 괄호를 무조건 버리는 것.** `http://a.com/w/Foo_(bar)` 같은 URL이 잘린다. 반대로 무조건 살리면 문장 속 URL에 `)`가 붙는다. 어느 쪽을 택했는지 알고 쓰고, 최종 목록은 눈으로 훑는다.
- **access.log 에서 `http://`를 찾는 것.** 요청 라인에는 스킴과 호스트가 없다. `GET /path HTTP/1.1`뿐이다. 호스트는 `Host:` 헤더에 있고 기본 로그 포맷에는 기록되지 않는다. 경로 패턴을 따로 쓴다.
- **메모리 덤프에서 ASCII strings 만 돌리는 것.** 윈도우 프로세스의 문자열은 대부분 UTF-16LE 다. `strings -el`(또는 `-e l`)로 한 번 더 훑지 않으면 C2 URL 을 통째로 놓친다.
- **퍼센트 인코딩을 풀지 않고 판단하는 것.** `%2e%2e%2f`는 `../`다. 디코딩 전에는 경로 탈출로 보이지 않는다. 반대로 **이중 인코딩(`%252e`)은 한 번 풀어도 안 보인다** — 두 번 풀어 본다.
- **경로와 쿼리에 같은 디코딩 함수를 쓰는 것.** 쿼리에서 `+`는 공백이고 경로에서는 리터럴 `+`다. `unquote`로 쿼리를 풀면 `hello+world`가 그대로 남아 값 비교가 어긋난다. 쿼리는 `parse_qsl` 또는 `unquote_plus`를 쓴다.
- **`//`가 없는 스킴을 빼먹는 것.** `mailto:`, `data:text/html;base64,`, `javascript:` 는 `[a-z]+://` 패턴에 걸리지 않는다. 그런데 이 세 개가 악성 지표로서 가치가 가장 높다. 별도 패턴으로 반드시 함께 돌린다.
- **IPv6 호스트를 처리하지 않는 것.** `http://[2001:db8::1]:8443/x` 에서 `[...]` 를 인식하지 못하면 호스트가 `[2001`로 잘린다. 대괄호를 host 클래스에 포함하거나 파서에 맡긴다.
- **대소문자와 후행 슬래시를 정규화하지 않는 것.** `http://A.com/x`와 `http://a.com/x/`는 같은 대상일 수 있다. 호스트는 소문자로, 경로 끝 슬래시는 규칙을 정해 통일한 뒤 센다.
- **URL 목록을 그대로 열어 보는 것.** 조사 대상 URL 을 실수로 클릭하거나 자동 미리보기가 요청을 보내면 공격자에게 조사 사실이 노출된다. 목록화 단계에서는 `hxxp://`처럼 무해화(defang)해 저장한다.
- **fragment 가 서버 로그에 있을 것으로 기대하는 것.** `#` 뒤는 브라우저가 서버로 보내지 않는다. 서버 로그에 fragment 가 보이면 로그가 아니라 클라이언트 측 기록(히스토리, 메모리)에서 온 것이다.

## mini example

```text
문제:
"감염 호스트의 메모리 덤프에서 악성코드가 사용한 C2 URL 을 구하세요."
첨부: mem.raw (4 GiB)

1. 첫 시도 (실패) — ASCII strings + \S+
   $ strings -a mem.raw | grep -Eo 'https?://\S+' | sort -u | wc -l
   18442
   $ strings -a mem.raw | grep -Eo 'https?://\S+' | sort -u | head -5
   http://a.com/x",
   http://crl.microsoft.com/pki/crl/products/CSPCA.crl
   http://ocsp.digicert.com
   http://schemas.microsoft.com/office/2006/metadata/contentType>
   http://www.w3.org/2000/svg"/>

   -> 18,442건 대부분이 XML 네임스페이스·인증서 URL 같은 노이즈다.
      게다가 끝에 ", > /> 같은 쓰레기가 붙어 같은 URL 이 여러 줄로 갈라진다.

2. 두 번째 시도 (실패) — 구두점을 자르고 노이즈 도메인을 제외
   $ strings -a mem.raw |
       grep -Poi '\bhttps?://[^\s"<>]*[^\s"<>.,;:!?)\]}]' |
       grep -Evi '(microsoft|w3\.org|digicert|verisign|adobe|schemas)' |
       sort -u | wc -l
   214
   $ ... | sort -u | head -3
   http://cdn.example.com/jquery.min.js
   http://update.example.com/v2/manifest.json
   https://www.example.co.kr/

   -> 214건으로 줄었지만 C2 로 보이는 것이 없다. 전부 평범한 웹 URL 이다.
      악성코드 문자열은 UTF-16LE 라서 ASCII strings 에 잡히지 않았다.

3. UTF-16LE 도 훑는다 (이것이 결정적이었다)
   $ strings -a -el mem.raw |
       grep -Poi '\bhttps?://[^\s"<>]*[^\s"<>.,;:!?)\]}]' |
       grep -Evi '(microsoft|w3\.org|digicert|schemas)' | sort -u
   http://203.0.113.77:8443/gate.php
   http://203.0.113.77:8443/panel/upload.php
   https://svc-update.example-cdn.top/api/v1/beacon

4. 파서로 분해해 지표를 뽑는다
   >>> from urllib.parse import urlsplit
   >>> for u in open('urls_utf16.txt').read().split():
   ...     p = urlsplit(u)
   ...     print(p.hostname, p.port, p.path)
   203.0.113.77 8443 /gate.php
   203.0.113.77 8443 /panel/upload.php
   svc-update.example-cdn.top None /api/v1/beacon

   -> 비표준 포트 8443 + IP 직접 접속 + .top TLD. 세 지표가 모두 C2 를 가리킨다.

5. 쿼리스트링이 붙은 변형이 있는지 재검색
   $ strings -a -el mem.raw | grep -Po '203\.0\.113\.77:8443/[^\s"]*' | sort -u
   /gate.php
   /gate.php?id=%s&hn=%s&os=%s
   /panel/upload.php

   -> %s 포맷 문자열이 남아 있다. 실행 중 채워지는 템플릿이었다.

6. 교차검증 — 프록시 로그에 실제 요청이 있는지
   $ grep -F '203.0.113.77:8443' proxy.log | head -2
   2026-03-14T07:22:11+09:00 10.10.20.5 GET http://203.0.113.77:8443/gate.php?id=WS01&hn=WS01&os=10.0 200
   2026-03-14T07:27:11+09:00 10.10.20.5 GET http://203.0.113.77:8443/gate.php?id=WS01&hn=WS01&os=10.0 200
   -> 5분 간격 비콘. 확정.

정답: http://203.0.113.77:8443/gate.php?id=%s&hn=%s&os=%s (5분 주기 비콘)
```

2단계가 이 글의 핵심이다. **윈도우 메모리에서 URL 을 찾을 때 ASCII strings 만 돌리면 절반을 못 본다.** `strings -el`을 반드시 함께 돌리고, 노이즈 도메인 제외는 패턴이 아니라 화이트리스트로 관리한다.

## 출처

- SRC-064 — RFC 9110 (HTTP Semantics): 요청 대상(request target)이 절대 URI 가 아니라 경로 형태로 전송된다는 점, `Host` 헤더가 호스트 정보를 담는다는 점의 근거
- SRC-057 — Python 문서 `re`: `re.VERBOSE`, lookbehind, `finditer`. `urllib.parse`(`urlsplit`, `unquote`, `unquote_plus`, `parse_qsl`)의 동작 근거는 같은 표준 라이브러리 문서
- URI 일반 문법(scheme/authority/path/query/fragment 구분, 퍼센트 인코딩 규칙, IPv6 대괄호 표기, 부록의 분해용 정규식)의 1차 규격은 `research/sources.json`에 등록되어 있지 않다. 이 글의 조각 구분은 `urlsplit`·`System.Uri`가 실제로 내놓는 결과를 기준으로 서술했고, 문자별 허용 범위는 단정하지 않았다
- `System.Net.WebUtility`, `System.Uri.TryCreate`의 동작은 .NET 버전에 따라 다를 수 있으므로 실제 환경에서 확인할 것
