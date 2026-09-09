---
id: FOR-0159
title: "http.request.uri 필터 실전: == / contains / matches 와 퍼센트 인코딩 함정"
slug: "http-request-uri-filter"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP request line"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r c.pcapng -Y http.request -T fields -e http.request.uri | sort | uniq -c | sort -nr", "tshark -r c.pcapng -Y 'http.request.uri matches \"\\\\.php($|\\\\?)\"' -T fields -e http.request.full_uri", "tshark -r c.pcapng -Y 'http.request.uri contains \"%2e%2e\"' -T fields -e frame.number -e http.request.uri"]
regex_patterns: ["\\.(php|asp|aspx|jsp|cgi|pl|sh)($|\\?)", "(\\.\\./|%2e%2e|%252e%252e|\\.\\.%2f|%2e%2e%2f)", "[?&][a-zA-Z_][a-zA-Z0-9_]*="]
wireshark_filters: ["http.request.uri == \"/login\"", "http.request.uri contains \"login\"", "http.request.uri matches \"login\"", "http.request.uri matches \"(?-i)Login\"", "http.request.uri matches \"\\\\.(zip|exe|dll|ps1)($|\\\\?)\"", "http.request.uri contains \"%2e%2e\"", "http.request.full_uri contains \"evil.tld\"", "!(http.request.uri matches \"\\\\.(css|js|png|jpe?g|gif|svg|ico|woff2?)($|\\\\?)\")", "http.request.uri matches \"[?&](cmd|file|page|id)=\""]
tshark_fields: ["http.request.uri", "http.request.full_uri", "http.host", "http.request.method", "frame.number", "http.response.code", "tcp.stream"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["http.request.uri", "URI 필터", "경로로 찾기"]
keywords: ["http.request.uri", "URI 필터", "contains", "matches", "full_uri", "퍼센트 인코딩", "URL 인코딩", "정규식 필터", "경로 필터", "확장자 필터"]
aliases: ["uri 필터", "url로 필터", "경로로 찾기", "contains 안 걸린다", "matches 대소문자", "full_uri 차이", "uri 목록 뽑기"]
symptom_keywords: ["contains가 아무것도 못 찾는다", "URI 필터가 안 걸린다", "대소문자 때문에 안 잡힌다", "full_uri와 uri 차이를 모르겠다", "URI 목록을 전부 보고 싶다"]
related: ["FOR-0156", "FOR-0157", "FOR-0164"]
source_ids: ["SRC-002", "SRC-064", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`http.request.uri`에는 **클라이언트가 보낸 원문 바이트가 그대로** 들어 있다. 그래서 `contains "../"`는 `..%2f`를 못 잡고, `contains`는 대소문자를 구분하며, 정답은 대부분 **대소문자를 무시하는 `matches` 정규식**이다.

## 어떤 문제에서 필요한가

- "특정 경로에 접근한 요청을 모두 찾아라"
- "다운로드된 파일 확장자로 요청을 좁혀라"
- `contains`로 검색했는데 0건이 나와 막힌 상황
- 요청 URI 전체 목록을 빈도순으로 정리해야 하는 상황
- 정적 리소스가 화면을 채워 실제 요청이 안 보이는 상황
- 파라미터 이름(`?file=`, `?cmd=`)으로 취약점 시도를 찾는 상황

## 문제에서 처음 볼 단서

1. `Info` 컬럼의 요청 라인에 경로가 보이는데 필터로는 안 걸린다 → **인코딩 또는 대소문자 문제**
2. 필터 입력창이 **빨강**이면 문법 오류, **노랑**이면 의도와 다르게 해석될 수 있다는 경고, **초록**이면 유효
3. URI에 `%`가 보인다 → 퍼센트 인코딩된 구간이 있다
4. URI가 `http://`로 시작한다 → **프록시 경유 요청**(절대 형식 request-target)
5. URI가 `host:443` 형태다 → `CONNECT` 요청(HTTPS 터널)

## 30초 절차

```text
http.request.uri contains "login"
```

0건이면 즉시 정규식으로 바꾼다. `matches`는 대소문자를 무시한다.

```text
http.request.uri matches "login"
```

그래도 0건이면 인코딩을 의심한다.

```text
http.request.uri matches "(login|l%6fgin|%6c%6f%67%69%6e)"
```

URI 전체 목록을 빈도순으로 뽑는 한 줄:

```bash
tshark -r capture.pcapng -Y http.request -T fields -e http.request.uri |
  sort | uniq -c | sort -nr | head -40
```

## 상세 절차

### 1단계 — 세 연산자의 차이를 정확히 안다

| 연산자 | 매칭 방식 | 대소문자 | `/Admin/Login.php?id=1` 에 대해 |
| --- | --- | --- | --- |
| `==` | **값 전체가 완전히 동일** | 구분 | `== "/Admin/Login.php?id=1"` 만 참. `== "/Admin/Login.php"` 는 거짓 |
| `contains` | 바이트 부분 문자열 | **구분** | `contains "Login"` 참 / `contains "login"` **거짓** |
| `matches` (`~`) | 정규식(PCRE) 부분 매칭 | **무시(기본)** | `matches "login"` 참 / `matches "(?-i)login"` 거짓 |

세 줄로 요약한다.

- **`==` 는 URI를 이미 정확히 알 때만** 쓴다. 쿼리 문자열이 붙으면 실패하므로 실전에서는 잘 안 맞는다.
- **`contains` 는 빠르지만 대소문자에 발목이 잡힌다.** 확실한 소문자 경로에만 쓴다.
- **`matches` 는 기본이 대소문자 무시라서 사실상 가장 안전하다.** 구분이 필요하면 패턴 앞에 `(?-i)`를 붙인다.

```text
http.request.uri == "/login"
http.request.uri contains "login"
http.request.uri matches "login"
http.request.uri matches "(?-i)Login"
```

`==` 는 집합 멤버십으로 확장할 수 있다.

```text
http.request.uri in {"/login" "/logout" "/admin"}
```

### 2단계 — 성능과 정확도의 실제 균형

| 관점 | `==` | `contains` | `matches` |
| --- | --- | --- | --- |
| 비교 비용 | 가장 낮음 | 낮음 | 가장 높음(정규식 엔진) |
| 대소문자 실수 위험 | 높음 | **높음** | 낮음 |
| 인코딩 변형 대응 | 불가 | 불가 | **가능(대안 패턴)** |
| 여러 조건 한 번에 | 불가 | `\|\|` 로 나열 | **하나의 패턴에 통합** |

비교 연산 자체의 비용 차이는 **패킷을 해체(dissection)하는 비용에 대부분 묻힌다.** 수천~수만 패킷 규모에서는 체감 차이가 없다. 다만 수십만 패킷에 `matches`를 여러 개 `||`로 묶으면 눈에 보이게 느려지므로, 그때는 **1차로 `http.request`로 좁혀 파일을 잘라낸 뒤** 정규식을 적용한다.

```bash
# 큰 캡처를 먼저 HTTP 요청만으로 잘라낸다
tshark -r huge.pcapng -Y 'http.request' -w http_only.pcapng

# 잘라낸 파일에 정규식을 마음껏 쓴다
tshark -r http_only.pcapng -Y 'http.request.uri matches "[?&](cmd|file|page|id|include)="' \
  -T fields -e frame.number -e http.request.full_uri
```

**정확도가 언제나 성능보다 중요하다.** 대회장에서 느린 필터는 커피 한 잔이지만, 안 걸리는 필터는 오답이다.

### 3단계 — `http.request.uri` 와 `http.request.full_uri` 의 차이

| 필드 | 값 | 언제 쓰나 |
| --- | --- | --- |
| `http.request.uri` | `/admin/upload.php?id=3` | 경로·쿼리로 필터할 때. **호스트가 없다** |
| `http.request.full_uri` | `http://shop.example.com/admin/upload.php?id=3` | **도메인을 조건에 넣을 때**, 보고서에 URL을 적을 때 |

`full_uri`는 Wireshark가 **`Host` 헤더 + request-target을 합성해 만든 값**이다. 따라서:

- 도메인과 경로를 함께 조건에 넣으려면 `full_uri` 하나로 끝난다
  ```text
  http.request.full_uri matches "evil\\.tld/.*\\.(exe|ps1)"
  ```
- 같은 조건을 `uri`로 하려면 두 필드를 `&&`로 묶어야 한다
  ```text
  http.host contains "evil.tld" && http.request.uri matches "\\.(exe|ps1)"
  ```

두 가지 예외가 있다. **둘 다 실전에서 사람을 헷갈리게 만든다.**

| 상황 | 요청 라인 | `http.request.uri` 의 값 |
| --- | --- | --- |
| 일반 요청(origin-form) | `GET /a.php HTTP/1.1` | `/a.php` |
| **프록시 경유(absolute-form)** | `GET http://site/a.php HTTP/1.1` | `http://site/a.php` — **호스트가 들어 있다** |
| **`CONNECT` (HTTPS 터널)** | `CONNECT site:443 HTTP/1.1` | `site:443` — 경로가 아니다 |

프록시 캡처에서 `http.request.uri matches "^/"` 로 좁히면 **모든 요청이 사라진다.** `^/`를 조건에 넣기 전에 `Info` 컬럼에서 요청 라인의 형태를 먼저 확인한다.

### 4단계 — 퍼센트 인코딩: `contains` 가 실패하는 진짜 이유

`http.request.uri`는 **전송된 바이트를 그대로 담는다.** Wireshark는 이 필드를 URL 디코딩해서 넣지 않는다. 그래서 다음이 성립한다.

| 실제로 전송된 URI | `contains "../"` | `contains "%2e%2e"` | `matches "(\\.\\./\|%2e%2e)"` |
| --- | --- | --- | --- |
| `/dl?f=../../etc/passwd` | **참** | 거짓 | 참 |
| `/dl?f=..%2f..%2fetc%2fpasswd` | 거짓 | 거짓 | 참 |
| `/dl?f=%2e%2e%2f%2e%2e%2fetc` | 거짓 | **참** | 참 |
| `/dl?f=%2E%2E%2Fetc` (대문자 hex) | 거짓 | 거짓(대소문자) | **참**(matches는 무시) |
| `/dl?f=..%252f..%252fetc` (이중) | 거짓 | 거짓 | 거짓 → `%252e\|%252f` 추가 필요 |

**디코딩된 문자열로는 검색할 수 없다.** 방법은 두 가지뿐이다.

1. **인코딩된 형태로 검색한다** — 어떤 변형이 왔는지 알아야 하므로 실전성이 낮다
2. **`matches`로 변형을 모두 열거한다** — 이것이 정답이다

경로 순회 만능 패턴:

```text
http.request.uri matches "(\\.\\./|\\.\\.%2f|%2e%2e%2f|%2e%2e/|%252e%252e|\\.\\.%5c|%2e%2e%5c)"
```

`%5c`는 백슬래시(`\`)다. Windows 서버 대상 공격에서 `..\`로 오는 경우를 잡는다.

**대소문자와 인코딩을 동시에 무력화하는 일반 전략**은 "핵심 글자 하나만 리터럴로 두지 않는 것"이다.

```text
# "passwd" 를 찾되 p 가 %70 으로 왔을 가능성까지
http.request.uri matches "(passwd|%70asswd|pass%77d)"

# 더 실전적인 접근 — 짧고 인코딩되기 어려운 조각을 쓴다
http.request.uri matches "(etc.{0,6}passwd|shadow)"
```

**가장 확실한 최후 수단은 필드 대신 프레임 전체를 뒤지는 것이다.**

```text
frame matches "(?i)(\\.\\.%2f|%2e%2e|passwd)"
```

`frame matches`는 파싱된 필드가 아니라 프레임 바이트를 본다. HTTP로 인식되지 않은 요청까지 잡힌다.

### 5단계 — 좁히는 패턴 모음

확장자로:

```text
http.request.uri matches "\\.(zip|rar|7z|tar|gz|exe|dll|msi|ps1|bat|vbs|jar|apk)($|\\?)"
http.request.uri matches "\\.(php|asp|aspx|jsp|cgi|pl|sh)($|\\?)"
http.request.uri matches "\\.(sql|bak|old|swp|conf|ini|env|log|pem|key)($|\\?)"
```

`($|\\?)`가 중요하다. 이것이 없으면 `/report.zipx`나 `/exe_help.html`처럼 확장자가 아닌 위치의 문자열도 걸린다.

경로로:

```text
http.request.uri matches "^/(admin|manage|console|wp-admin|phpmyadmin)"
http.request.uri matches "/(uploads?|files?|tmp|temp|images)/.*\\.(php|jsp|asp)"
http.request.uri matches "/\\.(git|svn|env|htaccess|DS_Store)"
```

세 번째는 설정 파일 노출 정찰의 표준 지문이다. `.git/config`, `.env`가 여기 걸린다.

파라미터 이름으로:

```text
http.request.uri matches "[?&](cmd|exec|command|shell|c)="
http.request.uri matches "[?&](file|page|path|include|template|dir|folder|doc)="
http.request.uri matches "[?&](id|uid|pid|no|num|idx)=[^&]*['%27]"
http.request.uri matches "[?&](user(name)?|pass(word)?|pw|token|key|api_?key)="
http.request.uri matches "[?&](url|uri|next|redirect|return|dest|target)=https?%3a"
```

노이즈 제거(**항상 먼저 적용한다**):

```text
http.request && !(http.request.uri matches "\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp)($|\\?)")
```

조합 예 — 도메인 + 확장자 + 성공한 응답까지:

```text
http.request.full_uri matches "shop\\.example\\.com/backup/.*\\.(zip|sql)"
```

### 6단계 — URI 전체 목록을 빈도순으로

**목록화가 URI 분석의 핵심 작업이다.** 무엇을 찾을지 모를 때 빈도표가 방향을 정해준다.

```bash
# 빈도순 (많이 호출된 것부터)
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.request.uri |
  sort | uniq -c | sort -nr | head -40

# 정적 리소스를 뺀 빈도순
tshark -r capture.pcapng \
  -Y 'http.request && !(http.request.uri matches "\\.(css|js|png|jpe?g|gif|svg|ico|woff2?)($|\\?)")' \
  -T fields -e http.request.uri | sort | uniq -c | sort -nr | head -40

# 쿼리를 떼고 경로만 집계 (같은 엔드포인트를 묶어 본다)
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.request.uri |
  cut -d'?' -f1 | sort | uniq -c | sort -nr | head -30

# 호스트별 URI (여러 사이트가 섞인 캡처)
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -e http.host -e http.request.uri | sort | uniq -c | sort -nr | head -40
```

```text
    118 /
     97 /css/main.css
     88 /product.php
     31 /api/v1/items
      2 /uploads/av4tar.php
      1 /backup/db_2026.zip
      1 /.git/config
```

읽는 법:

| 관찰 | 해석 |
| --- | --- |
| 상위 = 정적 리소스와 인덱스 | 정상 브라우징 배경 |
| **1회만 등장한 URI** | 특이 행위. **여기에 답이 있다** |
| 같은 경로 + 서로 다른 쿼리 수백 개 | 파라미터 퍼징 / SQLi 자동화 |
| 서로 다른 경로 수백 개 + 대부분 404 | 디렉터리 브루트포스 / 스캐너 |
| 경로가 `/`로 끝나는 것이 많다 | 디렉터리 목록 탐색 |

빈도표는 `sort -nr`이 아니라 `sort -n`으로도 한 번 본다. **꼬리(1회)가 본문이다.**

PowerShell에서 같은 집계:

```powershell
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.request.uri |
  Group-Object | Sort-Object Count -Descending |
  Select-Object -First 40 Count, Name
```

## 출력 필드 해석

| 필드 | 값의 예 | 주의 |
| --- | --- | --- |
| `http.request.uri` | `/a.php?id=1` | **원문 바이트.** 디코딩 안 됨. 프록시 요청에서는 전체 URL |
| `http.request.full_uri` | `http://h/a.php?id=1` | Host + request-target 합성값 |
| `http.request.uri.path` | `/a.php` | 버전에 따라 존재. 쿼리 제외 경로 |
| `http.request.uri.query` | `id=1` | 버전에 따라 존재. `?` 뒤 전체 |
| `http.host` | `h` | Host 헤더 단독 ([FOR-0160](./http-host-filter.html)) |
| `http.request.method` | `GET` | `CONNECT` 인지 먼저 확인 |
| `http.response_for.uri` | `http://h/a.php?id=1` | **응답 패킷**에서 URI를 보는 필드 |

필터 입력창의 색이 알려주는 것:

| 색 | 의미 | 대응 |
| --- | --- | --- |
| 초록 | 유효 | 그대로 실행 |
| 빨강 | 문법 오류 | 오타·따옴표·필드명 확인 |
| 노랑 | 유효하지만 의도와 다를 수 있음 | `!=` 를 쓴 경우가 대표적. `!(...)`로 바꾼다 |

`http.request.uri != "/login"` 은 노랑이 뜬다. 다중 값 필드에서 `!=` 는 "어느 하나라도 다르면 참"으로 동작해 직관과 어긋난다. **부정은 항상 `!(http.request.uri == "/login")` 로 쓴다.**

## pivot: 다음에 볼 artifact

| URI에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 특이 URI 하나 | 그 요청의 `tcp.stream` ([FOR-0164](./tcp-stream-filter.html)) | 요청·응답 전문 |
| 특이 URI 하나 | `http.response_for.uri` 로 응답 ([FOR-0161](./http-status-analysis.html)) | 성공했는가 |
| 확장자 매칭 URI | Export Objects ([FOR-0165](./export-objects-http.html)) | 실제 파일 바이트 |
| `?cmd=` 쿼리 | GET 전용 분석 ([FOR-0157](./http-get-find.html)) | 명령 전체 목록 |
| 업로드 엔드포인트 | 같은 URI로의 POST ([FOR-0158](./http-post-find.html)) | 본문·파일명 |
| `full_uri` 의 도메인 | 접속 도메인 목록 ([FOR-0160](./http-host-filter.html)) | DNS·SNI 대조 |
| 404가 몰린 URI 집합 | 스캐너 워드리스트 지문 | 사용 도구 |
| 다운로드 파일명 | `$MFT` ([FOR-0021](./mft-basics.html)) | 디스크 생성 시각 |

## 흔한 함정

- **`contains`를 대소문자 무시로 착각하는 것.** `contains "login"`은 `/Login`을 못 잡는다. 원인 불명의 0건은 거의 항상 이것이다. `matches`로 바꾼다.
- **`matches`가 대소문자를 구분한다고 착각하는 것.** 반대다. **기본이 무시**이므로 `matches "ADMIN"`이 `/admin`을 잡는다. 구분이 필요하면 `(?-i)`를 앞에 붙인다.
- **`contains "../"` 로 경로 순회를 판정하는 것.** 실제 공격은 `..%2f`, `%2e%2e%2f`, `..%252f`로 온다. URI 필드는 디코딩되지 않으므로 **`matches`로 변형을 열거**해야 한다.
- **`==` 로 쿼리 있는 URI를 찾는 것.** `http.request.uri == "/a.php"` 는 `/a.php?id=1`을 잡지 못한다. `matches "^/a\\.php"` 를 쓴다.
- **`http.request.uri`에 도메인이 있다고 가정하는 것.** 일반 요청에는 경로만 있다. 도메인 조건은 `http.host` 또는 `http.request.full_uri`로.
- **프록시 캡처에서 `^/` 를 쓰는 것.** absolute-form 요청은 `http://`로 시작하므로 `^/` 조건에 하나도 안 걸린다. `Info` 컬럼에서 요청 라인 형태를 먼저 본다.
- **`CONNECT` 요청의 URI를 경로로 읽는 것.** `example.com:443`은 경로가 아니라 터널 목적지다. 이 요청 뒤의 내용은 TLS라서 `http`로는 볼 수 없다.
- **확장자 정규식에 `($|\\?)` 를 빼는 것.** `matches "\\.zip"` 은 `/report.zipx`, `/a.zip.html`도 잡는다. 경계를 명시한다.
- **정규식의 백슬래시를 한 번만 쓰는 것.** Wireshark 필터 문자열 안에서 `\.` 는 `\\.` 로 써야 정규식에 `\.`로 전달된다. 점을 리터럴로 만들지 못하면 아무 문자에 매칭되어 오탐이 늘어난다.
- **정적 리소스를 걸러내지 않는 것.** URI 목록의 80%가 `.css`/`.js`/이미지다. 노이즈 제외 필터를 항상 먼저 적용한다.
- **`!=` 를 쓰는 것.** 입력창이 노랑으로 경고한다. `!(field == value)` 형태로 바꾼다.
- **빈도표의 머리만 보는 것.** 답은 **1회만 등장한 URI**에 있다. `sort -n`으로 꼬리를 반드시 확인한다.
- **URL 디코딩 없이 답을 제출하는 것.** `%2e%2e%2fetc%2fpasswd`는 `../etc/passwd`다. 필터는 인코딩 형태로 쓰고, **제출은 디코딩한 값으로** 한다.

## 교차검증

```bash
# 1) URI 총 개수와 고유 개수
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.request.uri | wc -l
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.request.uri | sort -u | wc -l

# 2) 같은 조건을 세 연산자로 각각 세어 본다 — 개수가 다르면 인코딩/대소문자 문제
tshark -r capture.pcapng -Y 'http.request.uri contains "admin"'  | wc -l
tshark -r capture.pcapng -Y 'http.request.uri matches "admin"'   | wc -l
tshark -r capture.pcapng -Y 'frame matches "(?i)admin"'          | wc -l

# 3) 파서를 우회한 요청 라인 원문 — Wireshark가 놓친 것까지
strings -n 8 capture.pcapng | grep -E '^(GET|POST|HEAD|PUT) ' | sort -u | head -40

# 4) % 인코딩이 들어간 URI만 골라 눈으로 확인
tshark -r capture.pcapng -Y 'http.request.uri contains "%"' \
  -T fields -e frame.number -e http.request.uri

# 5) 4)의 결과를 일괄 디코딩
tshark -r capture.pcapng -Y 'http.request.uri contains "%"' -T fields -e http.request.uri |
  python3 -c "import sys,urllib.parse; [print(urllib.parse.unquote_plus(l.strip())) for l in sys.stdin]"

# 6) 서버 로그와 대조 — URI가 동일하게 남는다
awk '{print $7}' access.log | sort | uniq -c | sort -nr | head -30
```

2)에서 `contains` < `matches` < `frame matches` 순으로 개수가 늘어나면 **대소문자 → 인코딩 → 미파싱** 순서로 원인이 누적된 것이다. 3)과 1)의 고유 개수가 다르면 HTTP로 인식되지 않은 요청이 있다.

## mini walkthrough

```text
문제:
"공격자가 읽어낸 시스템 파일의 경로를 URL 디코딩된 형태로 제출하세요."
첨부: lfi.pcapng (7,320 packets)

1. 첫 시도 (실패):
   필터: http.request.uri contains "../"
   -> 0건.
   "경로 순회가 없다"고 판단하고 다음 문제로 넘어갈 뻔했다.

2. 두 번째 시도 (여전히 실패):
   필터: http.request.uri contains "%2e%2e"
   -> 0건.
   인코딩 형태를 하나만 찍어 본 것이 실수였다.
   URI 필드는 원문 바이트이므로 "어떤 변형으로 왔는지"를 먼저 봐야 한다.

3. 관측으로 전환 — % 가 들어간 URI 를 전부 눈으로 본다
   필터: http.request.uri contains "%"

   tshark -r lfi.pcapng -Y 'http.request.uri contains "%"' \
     -T fields -e frame.number -e http.request.uri

   1841  /view.php?doc=index.html
   2903  /view.php?doc=..%252f..%252f..%252fetc%252fpasswd
   2951  /view.php?doc=..%252f..%252f..%252fetc%252fshadow
   3010  /view.php?doc=..%252f..%252f..%252fvar%252fwww%252fhtml%252fconfig.php

   -> 이중 인코딩(%252f = %2f 의 % 가 다시 %25 로 인코딩됨)이었다.
      그래서 %2e%2e 도, ../ 도 걸리지 않았다.

4. 올바른 필터로 재확인
   필터:
     http.request.uri matches "(\\.\\./|\\.\\.%2f|%2e%2e|%252e|%252f)"
   -> 3건. 3단계의 관측과 일치.

5. 성공한 것만 골라낸다 — 응답 코드
   tshark -r lfi.pcapng -Y 'http.response' \
     -T fields -e http.request_in -e http.response.code \
               -e http.content_length -e http.response_for.uri -E header=y |
     grep view.php

   2903  200  1893  http://web.example.com/view.php?doc=..%252f...%252fetc%252fpasswd
   2951  403  289   http://web.example.com/view.php?doc=..%252f...%252fetc%252fshadow
   3010  200  742   http://web.example.com/view.php?doc=..%252f...config.php

   -> shadow 는 403 으로 실패. passwd 와 config.php 는 200 + 본문 있음 = 성공.

6. 디코딩 — 이중 인코딩이므로 두 번 돌린다
   $ python3 -c "import urllib.parse as u,sys; s=sys.argv[1]; \
       print(u.unquote_plus(s)); print(u.unquote_plus(u.unquote_plus(s)))" \
       '..%252f..%252f..%252fetc%252fpasswd'
   ..%2f..%2f..%2fetc%2fpasswd
   ../../../etc/passwd

7. 교차검증 — 응답 본문에 실제로 passwd 내용이 있는가
   필터: tcp.stream eq <2903의 스트림> && http.response
   Follow > HTTP Stream
   root:x:0:0:root:/root:/bin/bash
   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   -> 유출 확정.

정답: ../../../etc/passwd  (그리고 성공한 두 번째 대상은 /var/www/html/config.php)
```

1·2단계의 실패가 이 글의 존재 이유다. **`contains` 0건은 "없다"가 아니라 "내 문자열 형태가 틀렸다"는 뜻이다.** 해결 순서는 항상 같다. ① `matches`로 대소문자를 무력화 ② `contains "%"` 로 인코딩된 URI를 눈으로 관측 ③ 관측한 실제 형태로 정규식 작성 ④ 제출은 디코딩한 값으로.

## 막혔을 때 다음 체크

1. `contains` 를 `matches` 로 바꿔 봤는가 — 대소문자 무시로 즉시 해결되는 경우가 가장 많다
2. `http.request.uri contains "%"` 로 **인코딩된 URI를 눈으로 관측**했는가
3. 이중 인코딩(`%252e`, `%252f`)을 후보에 넣었는가
4. `%5c`(백슬래시) 변형을 확인했는가 — Windows 서버 대상
5. 정규식의 점을 `\\.` 로 이스케이프했는가
6. 확장자 패턴에 `($|\\?)` 경계를 넣었는가
7. 도메인 조건이 필요하면 `http.host` 나 `http.request.full_uri` 로 바꿨는가
8. `Info` 컬럼에서 요청 라인이 origin-form(`/path`)인지 absolute-form(`http://...`)인지 확인했는가
9. `CONNECT` 요청이 섞여 있는가 — URI가 `host:port` 다
10. 정적 리소스 제외 필터를 먼저 적용했는가
11. 필터 입력창이 **노랑**이면 `!=` 를 `!(... == ...)` 로 바꿨는가
12. 빈도표의 **꼬리(1회 등장)** 를 확인했는가
13. 그래도 0건이면 `frame matches "(?i)..."` 로 프레임 전체를 뒤졌는가
14. `strings capture.pcapng | grep -E '^GET '` 로 파서를 우회했는가
15. 제출 값을 **디코딩**했는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `http.request.uri` / `http.request.full_uri` 필드 정의, `==` / `contains` / `matches` 연산자 의미와 `matches`의 기본 대소문자 무시 동작, `in {}` 멤버십, `!=` 가 다중 값 필드에서 갖는 함정
- SRC-064 — RFC 9110 HTTP Semantics: request-target의 네 가지 형식(origin-form, absolute-form, authority-form, asterisk-form)과 `CONNECT` 메서드, 퍼센트 인코딩 규칙
- SRC-010 — tshark man page: `-Y`, `-w`, `-T fields`, `-e`
- `http.request.uri.path` / `http.request.uri.query` 는 Wireshark 버전에 따라 없을 수 있다. 필터 입력창이 초록으로 바뀌는지로 존재를 확인할 것
- Wireshark가 이 필드를 URL 디코딩하지 않는다는 점은 실제 캡처에서 `contains "%"` 로 직접 확인 가능하다. 버전에 따라 표시 방식이 달라질 수 있으므로 화면에서 확인할 것
