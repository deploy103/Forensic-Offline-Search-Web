---
id: FOR-0161
title: "HTTP 상태 코드로 성공·실패 판정: http.response.code와 401→200 전환 읽기"
slug: "http-status-analysis"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP response header", "HTTP status line"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r c.pcapng -Y http.response -T fields -e http.response.code | sort | uniq -c | sort -nr", "tshark -r c.pcapng -Y 'http.response.code >= 400' -T fields -e http.request_in -e http.response.code -e http.response_for.uri", "tshark -r c.pcapng -Y 'http.response.code == 401 || http.response.code == 200' -T fields -e tcp.stream -e http.response.code"]
regex_patterns: []
wireshark_filters: ["http.response", "http.response.code == 200", "http.response.code == 401", "http.response.code == 206", "http.response.code >= 400", "http.response.code >= 400 && http.response.code < 500", "http.response.code >= 500", "http.response.code == 302 && http.location", "http.response.code == 200 && http.content_length > 100000", "http.response.code == 101"]
tshark_fields: ["http.response.code", "http.response.phrase", "http.request_in", "http.response_for.uri", "http.content_length", "http.content_type", "http.server", "http.location", "http.set_cookie", "http.time", "http.transfer_encoding", "tcp.stream"]
log_fields: ["sc-status", "status"]
file_formats: ["pcap", "pcapng"]
primary_terms: ["http.response.code", "응답 코드 분석", "패킷 상태코드"]
keywords: ["HTTP 상태 코드", "http.response.code", "401", "403", "404", "206 Partial Content", "302 리다이렉트", "500 에러", "성공 판정", "스캔 탐지"]
aliases: ["응답 코드 필터", "상태코드 분석", "401 200 전환", "로그인 성공 판정", "404 많이 나온다", "206 부분전송", "500 에러 패킷"]
symptom_keywords: ["요청이 성공했는지 모르겠다", "로그인 성공 지점을 찾아야 한다", "404가 너무 많다", "응답 코드로 스캔을 판정해야 한다", "어느 응답이 어느 요청의 것인지 모르겠다"]
related: ["FOR-0156", "FOR-0157", "FOR-0164"]
source_ids: ["SRC-002", "SRC-064"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

요청을 찾는 것은 절반이고, **성공·실패는 응답 코드가 결정한다.** `http.response.code`로 분포를 먼저 보고(404 급증=스캔, 500 존재=주입 성공 흔적), `http.request_in`·`http.response_for.uri`로 요청과 짝지은 뒤, **`http.content_length`를 함께 봐야** "200인데 빈 응답"과 "200에 4 MB"를 구분할 수 있다.

## 어떤 문제에서 필요한가

- "로그인에 성공한 시각을 구하라" — 성공 지점은 코드 전환에 있다
- "공격자의 시도 중 실제로 통한 것은 무엇인가"
- "스캐닝이 있었는가, 어느 도구가 무엇을 훑었는가"
- "파일이 실제로 전송됐는가" — 요청만으로는 알 수 없다
- "서버가 무엇으로 만들어졌는가" (`Server` 헤더)
- "대용량 데이터가 나눠서 빠져나갔는가" (206)

**응답을 안 보고 답을 제출하는 것이 pcap 문제의 최다 오답 원인이다.** 실패한 로그인 시도를 정답으로 적는 실수가 대표적이다.

## 문제에서 처음 볼 단서

1. `Info` 컬럼에 `HTTP/1.1 404 Not Found`가 화면을 가득 채운다 → 스캔
2. `HTTP/1.1 401 Unauthorized`가 보인다 → 인증 구간이 있다. **그 뒤의 200을 찾는다**
3. `HTTP/1.1 302 Found` + `Location:` → 로그인/리다이렉트 성공 지점
4. `HTTP/1.1 500 Internal Server Error` → 주입 시도가 서버 로직을 깨뜨렸다
5. `HTTP/1.1 206 Partial Content` → 이어받기/분할 전송. 대용량 이동
6. `HTTP/1.1 101 Switching Protocols` → WebSocket 업그레이드. 이후는 `http`로 안 보인다

## 30초 절차

```bash
tshark -r capture.pcapng -Y http.response -T fields -e http.response.code | sort | uniq -c | sort -nr
```

```text
    502 200
     88 404
     31 302
     14 500
      6 401
      3 206
      1 101
```

**이 표 하나로 사건의 성격이 정해진다.** 404가 많으면 스캔, 500이 있으면 주입, 401이 있으면 인증 구간, 206이 있으면 대용량 전송.

GUI에서 실패만 즉시 보기:

```text
http.response.code >= 400
```

`http.response.code`와 `http.response_for.uri`를 컬럼으로 올리면(필드 우클릭 → `Apply as Column`) 어느 경로가 실패했는지 한 화면에 나온다.

## 상세 절차

### 1단계 — 코드별 의미와 포렌식 해석

#### 1xx — 정보

| 코드 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| 100 Continue | 본문을 보내도 좋다 | 클라이언트가 `Expect: 100-continue`를 보냈다. **대용량 업로드 직전 신호** |
| 101 Switching Protocols | 프로토콜 전환 | **WebSocket 업그레이드.** 이후 통신은 `http` 필터에 안 걸린다. `websocket` 필터로 전환. C2 채널로 쓰인다 |

#### 2xx — 성공

| 코드 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| 200 OK | 성공 | **본문 크기를 함께 봐야 한다.** 0바이트 200과 4 MB 200은 완전히 다른 사건 |
| 201 Created | 리소스 생성됨 | **업로드/등록 성공.** REST API 업로드의 성공 신호 |
| 204 No Content | 성공했고 본문 없음 | 비컨 응답에서 흔하다. **"할 일 없음" 신호로 쓰이는 C2 패턴** |
| 206 Partial Content | 요청한 범위만 전송 | **이어받기/분할 다운로드.** 대용량 유출을 조각내 보낸 흔적. 여러 206을 합쳐야 원본 크기가 나온다 |

#### 3xx — 리다이렉션

| 코드 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| 301 Moved Permanently | 영구 이동 | HTTP→HTTPS 강제 전환에서 흔하다 |
| 302 Found / 303 See Other | 임시 이동 | **로그인 성공의 표준 신호.** `Location`이 대시보드면 인증 통과 |
| 304 Not Modified | 변경 없음 | **본문이 전송되지 않았다.** 다운로드 성공으로 세면 안 된다 |
| 307 / 308 | 메서드 보존 리다이렉트 | POST가 다른 URL로 재전송된다. 자격증명이 두 곳에 남을 수 있다 |

#### 4xx — 클라이언트 오류

| 코드 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| 400 Bad Request | 요청 형식 오류 | 손으로 조립한 요청, 퍼징, 프로토콜 혼선 |
| 401 Unauthorized | 인증 필요 | **`WWW-Authenticate` 헤더가 함께 온다.** 다음 요청의 `Authorization`과 짝 |
| 403 Forbidden | 권한 없음 | 파일은 존재하나 접근 차단. **404와 구분되는 정보** — 경로가 실재한다는 뜻 |
| 404 Not Found | 없음 | **급증하면 스캔.** 어떤 경로를 시도했는지가 도구 지문 |
| 405 Method Not Allowed | 메서드 불허 | `PUT`/`DELETE` 시도가 막혔다 |
| 407 Proxy Authentication Required | 프록시 인증 필요 | 프록시 경유 환경 |
| 413 Content Too Large | 본문이 너무 큼 | **업로드가 크기 제한에 막혔다.** 공격 실패 근거 |
| 414 URI Too Long | URI 과다 | 긴 SQLi/셸코드를 GET 쿼리로 밀어넣은 흔적 |
| 416 Range Not Satisfiable | 범위 불가 | 206 이어받기 시도가 실패 |
| 429 Too Many Requests | 요청 과다 | **스캐너가 레이트 리밋에 걸렸다.** 스캔의 강한 증거 |

#### 5xx — 서버 오류

| 코드 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| 500 Internal Server Error | 서버 내부 오류 | **주입이 서버 코드를 깨뜨렸다.** SQLi·LFI·역직렬화 시도의 핵심 증거. 응답 본문에 스택 트레이스·DB 오류가 실려 정보가 유출되는 경우가 많다 |
| 501 Not Implemented | 미구현 메서드 | 이상한 메서드 시도 |
| 502 / 503 / 504 | 게이트웨이·과부하·타임아웃 | DoS, 백엔드 다운, 또는 리버스 프록시 뒤의 서버 문제 |

**403과 404의 차이가 실전에서 큰 정보다.** 스캐너가 100개 경로를 훑어 99개가 404, 1개가 403이면 **그 1개는 실제로 존재하는 경로**다.

### 2단계 — 필터: 단일 값과 범위

`http.response.code`는 **숫자 필드**이므로 부등호가 그대로 통한다.

```text
http.response.code == 200
http.response.code == 404
http.response.code >= 400
http.response.code >= 400 && http.response.code < 500
http.response.code >= 500
http.response.code in {401 403 407}
http.response.code in {301 302 303 307 308}
!(http.response.code == 200) && http.response
```

**성공한 것만 / 실패한 것만** 두 축으로 나누는 것이 첫 작업이다.

```text
http.response.code < 400
http.response.code >= 400
```

크기 조건과 결합하면 훨씬 강해진다.

| 목적 | 필터 |
| --- | --- |
| 실제로 데이터가 나간 응답 | `http.response.code == 200 && http.content_length > 100000` |
| 성공했지만 본문이 빈 응답 | `http.response.code == 200 && http.content_length == 0` |
| 파일 다운로드 성공 | `http.response.code == 200 && http.content_type contains "octet-stream"` |
| 로그인 성공 후보 | `http.response.code == 302 && http.set_cookie` |
| 인증 도전 | `http.response.code == 401` |
| 분할 전송 | `http.response.code == 206` |
| 오류 본문에 정보 유출 | `http.response.code >= 500 && http.content_length > 500` |

`http.response.phrase`로도 필터할 수 있지만 **판정 근거로 쓰지 않는다.** 사유구는 서버가 임의 문자열로 바꿀 수 있어 `200 Not Found` 같은 응답도 만들 수 있다. 판정은 항상 숫자로 한다.

### 3단계 — 요청과 응답을 짝짓는 절차

응답 패킷에는 `http.request.uri`가 없다. 짝짓는 방법이 세 가지다.

| 방법 | 필드/절차 | 정확도 | 언제 쓰나 |
| --- | --- | --- | --- |
| `http.request_in` | 응답 패킷에 붙는 **요청 프레임 번호** | **가장 높음** | 항상 1순위. Keep-Alive에서도 정확 |
| `http.response_for.uri` | 응답 패킷에 붙는 요청 URI | 높음 | 표로 뽑을 때. URI만 필요할 때 |
| `tcp.stream` | 같은 연결로 묶기 | 보통 | 한 연결에 요청이 하나뿐일 때만 안전 |

한 번에 뽑는 표:

```bash
tshark -r capture.pcapng -Y 'http.response' \
  -T fields -e frame.number -e http.request_in -e tcp.stream \
            -e http.response.code -e http.content_length -e http.content_type \
            -e http.time -e http.response_for.uri \
  -E header=y -E separator='|'
```

```text
frame.number|http.request_in|tcp.stream|http.response.code|http.content_length|http.content_type|http.time|http.response_for.uri
908|902|7|401|294|text/html|0.008|http://portal.example.com/admin/
918|912|7|200|8214|text/html|0.021|http://portal.example.com/admin/
1908|1902|17|404|291|text/html|0.006|http://portal.example.com/.git/config
2470|2455|21|200|4194304|application/octet-stream|3.912|http://portal.example.com/backup/db.zip
```

역방향으로 요청에서 응답을 찾는 필드는 `http.response_in`이다.

```bash
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -e frame.number -e http.request.uri -e http.response_in -E header=y
```

**응답이 없는 요청**(`http.request && !http.response_in`)은 서버가 답하지 않았거나 캡처가 잘린 것이다. 둘을 구분하려면 `Analyze > Expert Information`에서 재전송·누락을 확인한다.

GUI에서 한 요청의 짝을 즉시 보려면 요청 패킷 상세 트리의 `Response in frame: 918` 항목을 **더블클릭**하면 그 프레임으로 점프한다. 응답 쪽에서는 `Request in frame: 912`가 같은 역할을 한다.

### 4단계 — 401→200 전환이 인증 성공 지점

HTTP 기본/다이제스트 인증의 표준 흐름은 세 단계다.

```text
1) 클라이언트: GET /admin/  (Authorization 없음)
2) 서버:      401 Unauthorized  + WWW-Authenticate: Basic realm="Admin"
3) 클라이언트: GET /admin/  + Authorization: Basic YWRtaW46UzNjcjN0
4) 서버:      200 OK        <-- 인증 성공 지점
```

**따라서 "401 다음에 온 200"이 성공 시각이고, 그 사이 요청의 `Authorization` 헤더가 통한 자격증명이다.**

```text
http.response.code in {401 200} && tcp.stream eq 7
```

전체 캡처에서 401이 등장한 스트림만 골라 그 안의 코드 흐름을 보는 절차:

```bash
# 1) 401 이 난 스트림 목록
tshark -r capture.pcapng -Y 'http.response.code == 401' -T fields -e tcp.stream | sort -un
# 예: 7 13 19

# 2) 그 스트림들의 코드 흐름을 시간순으로
tshark -r capture.pcapng -Y 'tcp.stream in {7 13 19} && http' \
  -T fields -e frame.number -e tcp.stream -e http.request.method \
            -e http.request.uri -e http.authorization -e http.response.code \
  -E header=y
```

```text
frame.number  tcp.stream  method  uri        authorization                    code
902           7           GET     /admin/
908           7                                                               401
912           7           GET     /admin/    Basic YWRtaW46UzNjcjN0UGFzcw==
918           7                                                               200
1520          13          GET     /admin/    Basic YWRtaW46MTIzNA==
1526          13                                                              401
1602          13          GET     /admin/    Basic YWRtaW46YWRtaW4=
1608          13                                                              401
```

스트림 7은 성공, 스트림 13은 두 번 실패다. **`Authorization: Basic`은 Base64이므로 디코딩하면 `사용자:비밀번호`가 나온다.**

```bash
echo 'YWRtaW46UzNjcjN0UGFzcw==' | base64 -d
# admin:S3cr3tPass
```

```powershell
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('YWRtaW46UzNjcjN0UGFzcw=='))
```

폼 로그인은 401을 쓰지 않는다. 그때의 성공 신호는 다르다.

| 인증 방식 | 실패 시 | **성공 시** |
| --- | --- | --- |
| HTTP Basic/Digest | 401 반복 | **401 → 200** |
| 폼 로그인 (세션 쿠키) | 200 (로그인 화면 재표시) | **302 + `Location: /dashboard` + `Set-Cookie`** |
| REST API 토큰 | 401 / 403 + JSON 오류 | 200 + 토큰이 담긴 JSON 본문 |
| 리다이렉트 없는 SPA | 200 + `{"ok":false}` | 200 + `{"ok":true}` — **코드가 같으므로 본문을 봐야 한다** |

**폼 로그인에서 "200이니까 성공"으로 읽는 것이 가장 흔한 오답이다.** 200은 "로그인 페이지를 다시 그려줬다"는 뜻일 수 있다. 판정 근거는 `302` + `Set-Cookie` + `Location`이다.

### 5단계 — 206 Partial Content: 대용량 전송 신호

클라이언트가 `Range:` 헤더로 바이트 범위를 요청하면 서버는 206으로 그 범위만 보낸다. 정상 용도는 동영상 시킹과 다운로드 이어받기다. 포렌식에서는:

| 관찰 | 해석 |
| --- | --- |
| 하나의 큰 파일에 206이 여러 개 | 이어받기 또는 **분할 유출**(작은 조각으로 나눠 탐지 회피) |
| 동영상/오디오 URI에 206 | 정상 스트리밍 |
| 206 개수가 수십~수백 | **총량을 합산해야 실제 유출량이 나온다** |
| 416 Range Not Satisfiable | 범위 요청 실패. 파일이 바뀌었거나 없다 |

```text
http.response.code == 206
```

범위 정보는 헤더 라인에 들어 있다. 개별 헤더 라인을 담는 필드로 조건을 걸 수 있다.

```text
http.response.line contains "Content-Range"
http.request.line contains "Range:"
```

가장 확실한 확인은 Follow HTTP Stream으로 헤더를 눈으로 읽는 것이다 ([FOR-0162](./follow-tcp-stream.html)).

```text
GET /backup/db.zip HTTP/1.1
Range: bytes=2097152-4194303

HTTP/1.1 206 Partial Content
Content-Range: bytes 2097152-4194303/8388608
Content-Length: 2097152
```

마지막 값 `8388608`이 **원본 전체 크기**다. 206 조각들의 `Content-Length`를 다 합쳐 이 값과 비교하면 전송이 완결됐는지 알 수 있다.

```bash
# 206 응답의 본문 크기 합계
tshark -r capture.pcapng -Y 'http.response.code == 206' \
  -T fields -e http.content_length |
  awk '{s+=$1} END {print "총 " s " bytes (" s/1048576 " MB)"}'
```

### 6단계 — 404 급증 = 스캔, 그리고 무엇을 훑었는지

```bash
# 시간대별 404 개수 — 급증 구간을 찾는다
tshark -r capture.pcapng -Y 'http.response.code == 404' \
  -T fields -e frame.time_epoch |
  awk '{printf "%d\n", $1/60}' | uniq -c
```

```text
      2 29557875
     71 29557876      <-- 1분 사이 71건
     17 29557877
      1 29557890
```

사람의 브라우징으로는 1분에 71개의 404가 나오지 않는다. 무엇을 시도했는지가 도구의 지문이다.

```bash
tshark -r capture.pcapng -Y 'http.response.code == 404' \
  -T fields -e http.response_for.uri | sed 's|.*://[^/]*||' | sort -u | head -30
```

```text
/.env
/.git/config
/admin
/backup.zip
/phpmyadmin/
/wp-admin/
/wp-login.php
```

| 시도한 경로 집합 | 추정 도구/워드리스트 |
| --- | --- |
| `/wp-admin`, `/wp-login.php`, `/wp-content` | WordPress 대상 스캔 |
| `/.git/config`, `/.env`, `/.svn/entries` | 설정 파일 노출 정찰 |
| `/phpmyadmin/`, `/adminer.php` | DB 관리 도구 탐색 |
| 무작위 확장자 조합이 방대함 | dirb/gobuster/ffuf 계열 |
| `/nikto-test-*` 같은 특유 경로 | Nikto |

**404 사이에 섞인 200과 403이 진짜 소득이다.** 스캔 구간 안에서 성공만 골라낸다.

```text
http.response.code in {200 301 302 403} && tcp.stream in {17 18 19 20}
```

응답 코드와 함께 User-Agent를 보면 도구가 특정된다 ([FOR-0157](./http-get-find.html)).

### 7단계 — `Server` 헤더로 기술 스택 파악

```bash
tshark -r capture.pcapng -Y 'http.response' -T fields -e http.server |
  grep . | sort | uniq -c | sort -nr
```

```text
    502 Apache/2.4.52 (Ubuntu)
     31 nginx/1.18.0
      8 Microsoft-IIS/10.0
```

| `Server` 값 | 함의 | 다음에 볼 것 |
| --- | --- | --- |
| `Apache/...` | Linux/Unix 계열이 많다 | `access.log`, `error_log`, `.htaccess` |
| `nginx/...` | 리버스 프록시일 수 있다 → 뒤에 다른 서버 | `access.log`, `X-Forwarded-For` |
| `Microsoft-IIS/...` | Windows 서버 | W3C Extended 로그(`u_ex*.log`), EVTX |
| 헤더가 없다 | 헤더를 지우도록 설정됨 | 다른 지문(`X-Powered-By`, 쿠키 이름)으로 추정 |
| `Server`가 요청마다 다르다 | 로드밸런서 뒤에 여러 서버 | 어느 노드가 응답했는지 |

쿠키 이름도 스택 지문이다. `PHPSESSID`=PHP, `JSESSIONID`=Java, `ASP.NET_SessionId`=ASP.NET, `csrftoken`+`sessionid`=Django.

**서버 종류를 알면 다음에 어떤 로그 파일을 요구해야 하는지가 정해진다.** 이것이 상태 코드 분석의 마지막 소득이다.

## 출력 필드 해석

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| `http.response.code` | 상태 코드 | **숫자 필드.** 부등호·범위 비교 가능 |
| `http.response.phrase` | 사유구(`OK`, `Not Found`) | 서버가 임의로 바꿀 수 있다. **판정 근거 아님** |
| `http.request_in` | 대응 요청 프레임 번호 | **짝짓기 1순위.** 더블클릭으로 점프 |
| `http.response_in` | (요청 측) 대응 응답 프레임 번호 | 없으면 서버 무응답 또는 캡처 잘림 |
| `http.response_for.uri` | 이 응답이 답한 요청 URI | 표로 뽑을 때 필수 |
| `http.content_length` | 본문 길이 | **chunked면 비어 있다.** 실제 크기는 Conversations에서 |
| `http.content_type` | 본문 MIME | `octet-stream`=파일, `text/html`=페이지 |
| `http.content_encoding` | `gzip` 등 | 압축된 크기 기준임을 유의 |
| `http.transfer_encoding` | `chunked` | `Content-Length` 부재의 원인 |
| `http.server` | 서버 소프트웨어 | 기술 스택 |
| `http.location` | 리다이렉트 대상 | **로그인 성공 판정** |
| `http.set_cookie` | 발급된 쿠키 | 세션 생성 = 인증 성공 시점 |
| `http.time` | 요청→응답 경과 초 | 큰 값 = 대용량 전송 또는 서버 지연. blind SQLi의 `sleep()`도 여기 드러난다 |
| `tcp.stream` | 연결 인덱스 | Follow로 직행 ([FOR-0164](./tcp-stream-filter.html)) |

`http.time`이 의외로 강력하다. Time-based blind SQL Injection은 응답이 정확히 5초·10초씩 지연되므로 코드는 200이어도 `http.time`으로 잡힌다.

```text
http.time > 4
```

## pivot: 다음에 볼 artifact

| 응답에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 401 → 200 전환 프레임 | 그 사이 요청의 `http.authorization` | Base64 디코딩한 자격증명 |
| 302 + `Set-Cookie` | 그 요청의 POST 본문 ([FOR-0158](./http-post-find.html)) | 아이디/비밀번호 |
| 자격증명 | EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) | 실제 로그온 성공 여부 |
| 200 + 큰 `content_length` | Export Objects ([FOR-0165](./export-objects-http.html)) | 나간 파일 실물 |
| 206 여러 건 | `Content-Range` 합산 | 총 유출량과 완결 여부 |
| 500 응답 | 그 응답 본문(Follow Stream) | 스택 트레이스·DB 오류·경로 노출 |
| 404 급증 구간 | 그 구간의 `http.user_agent` ([FOR-0157](./http-get-find.html)) | 스캐너 특정 |
| 404 사이의 403 | 그 경로 ([FOR-0159](./http-request-uri-filter.html)) | **실재하는 경로** |
| 101 Switching Protocols | `websocket` 필터 | 업그레이드 이후의 채널 |
| `http.server` 값 | 서버 접근 로그 ([FOR-0121](./powershell-select-string.html)) | 서버 측 상태 코드와 대조 |
| `http.time` 이 큰 응답 | 그 요청의 쿼리 | time-based blind SQLi |

## 흔한 함정

- **요청만 보고 성공으로 판정하는 것.** `?cmd=whoami` 요청이 있어도 응답이 404/403이면 실행되지 않았다. 이것이 pcap 문제 최다 오답이다.
- **폼 로그인에서 200을 성공으로 읽는 것.** 200은 로그인 페이지 재표시일 수 있다. 성공은 **302 + `Location` + `Set-Cookie`** 로 판정한다.
- **`http.response.phrase`로 판정하는 것.** 사유구는 서버가 바꿀 수 있다. 숫자만 신뢰한다.
- **`http.content_length`가 없으면 본문이 없다고 판단하는 것.** `Transfer-Encoding: chunked`면 헤더가 아예 없다. 실제 크기는 `Statistics > Conversations`의 Bytes로 본다.
- **`304 Not Modified`를 다운로드 성공으로 세는 것.** 본문이 전송되지 않았다. 캐시 적중이다.
- **`tcp.stream`만으로 요청과 응답을 짝짓는 것.** Keep-Alive 연결에는 요청/응답이 여러 쌍 들어 있다. 짝짓기는 `http.request_in`으로 한다.
- **404와 403을 같은 실패로 묶는 것.** 403은 **경로가 실재한다**는 정보다. 스캔 결과에서 403은 성공에 가깝다.
- **500을 서버 문제로 넘기는 것.** 공격 맥락의 500은 **주입이 서버 코드에 도달했다는 증거**다. 응답 본문에 DB 오류·파일 경로가 유출된다.
- **206을 무시하는 것.** 조각난 전송의 총량을 합산하지 않으면 유출량을 과소평가한다. `Content-Range`의 마지막 값이 원본 크기다.
- **101 이후를 `http`로 찾는 것.** WebSocket으로 전환된 뒤의 트래픽은 `websocket` 필터의 몫이다. `http`로는 0건이다.
- **응답이 없는 요청을 놓치는 것.** `http.request && !http.response_in` 을 확인한다. 서버 무응답과 캡처 잘림을 `Expert Information`으로 구분한다.
- **`http.response.code >= 400` 을 문자열 비교로 착각하는 것.** 숫자 필드이므로 부등호가 정상 동작한다. 반대로 `http.request.method`에는 부등호를 쓸 수 없다.
- **시간을 상대 초로 두고 판정하는 것.** `View > Time Display Format > UTC Date and Time of Day`가 먼저다. KST = UTC+9이므로 `07:22:41 UTC` = `16:22:41 KST`다.

## 교차검증

```bash
# 1) 코드 분포 — 사건 성격 판정
tshark -r capture.pcapng -Y 'http.response' -T fields -e http.response.code |
  sort | uniq -c | sort -nr

# 2) 요청 수 vs 응답 수 — 차이가 크면 캡처가 잘렸다
tshark -r capture.pcapng -Y 'http.request'  | wc -l
tshark -r capture.pcapng -Y 'http.response' | wc -l

# 3) 응답 없는 요청
tshark -r capture.pcapng -Y 'http.request && !http.response_in' \
  -T fields -e frame.number -e http.request.uri

# 4) 실패한 요청의 경로 집합
tshark -r capture.pcapng -Y 'http.response.code >= 400' \
  -T fields -e http.response.code -e http.response_for.uri | sort -u | head -40

# 5) 성공하고 데이터가 실제로 나간 응답
tshark -r capture.pcapng -Y 'http.response.code == 200 && http.content_length > 10000' \
  -T fields -e http.content_length -e http.content_type -e http.response_for.uri |
  sort -nr | head -20

# 6) 파서를 우회한 상태 라인 원문
strings -n 8 capture.pcapng | grep -E '^HTTP/1\.[01] [0-9]{3}' | sort | uniq -c | sort -nr

# 7) 서버 로그와 대조 (있다면) — 상태 코드가 같은 값으로 남는다
awk '{print $9}' access.log | sort | uniq -c | sort -nr
```

1)과 6)의 개수가 다르면 HTTP로 파싱되지 않은 응답이 있다(비표준 포트·잘린 캡처). 2)에서 요청 수가 응답 수보다 크게 많으면 캡처 구간이 응답을 담지 못한 것이다. 서버 로그가 함께 주어졌다면 7)이 최종 근거다.

## mini walkthrough

```text
문제:
"관리자 페이지 인증에 성공한 계정과 비밀번호, 그리고 성공 시각(UTC)을 구하세요."
첨부: bruteforce.pcapng (9,880 packets)

1. 첫 시도 (실패):
   "성공은 200 일 것"이라고 보고
   필터: http.response.code == 200

   -> 502건. 이미지·CSS·정상 페이지가 전부 200 이라 판정이 불가능했다.
      게다가 이 사이트의 관리자 페이지는 HTTP Basic 인증을 쓰고 있어
      "실패한 시도"도 화면상으로는 401 이었는데, 200 만 보다가
      /admin/ 관련 응답이 어느 것인지 특정하지 못했다.

2. 접근 변경 — 코드 분포부터 본다
   tshark -r bruteforce.pcapng -Y 'http.response' \
     -T fields -e http.response.code | sort | uniq -c | sort -nr

      502 200
       47 401     <-- 인증 구간이 있다
       12 404
        1 206

   -> 401 이 47건. 브루트포스다. 성공은 "401 다음의 200".

3. 401 이 난 스트림 목록
   tshark -r bruteforce.pcapng -Y 'http.response.code == 401' \
     -T fields -e tcp.stream | sort -un | tr '\n' ' '
   7 9 11 13 15 17 19 21 23 25 ... 51

   -> 시도마다 새 연결. 스트림이 23개.

4. 그 스트림들의 코드 흐름과 Authorization 을 한 표로
   tshark -r bruteforce.pcapng -Y 'http && tcp.stream >= 7 && tcp.stream <= 51' \
     -T fields -e frame.number -e tcp.stream -e http.authorization \
               -e http.response.code -e http.response_for.uri -E header=y |
     grep -E 'admin|Basic|40[13]|200'

   frame  stream  authorization                    code  uri
   902    7                                        401   http://portal.example.com/admin/
   912    7       Basic YWRtaW46MTIzNDU2
   918    7                                        401
   1020   9       Basic YWRtaW46cGFzc3dvcmQ=
   1026   9                                        401
   ...
   4402   49      Basic YWRtaW46UzNjcjN0UGFzcw==
   4408   49                                       200   http://portal.example.com/admin/

   -> 스트림 49 에서만 200. 여기가 성공 지점.

5. 자격증명 디코딩
   $ echo 'YWRtaW46UzNjcjN0UGFzcw==' | base64 -d
   admin:S3cr3tPass

6. 성공 시각 — 응답이 아니라 요청 프레임 기준으로 본다
   tshark -r bruteforce.pcapng -Y 'frame.number == 4408' \
     -T fields -e http.request_in -e http.time
   4402   0.019

   tshark -r bruteforce.pcapng -Y 'frame.number == 4402' \
     -T fields -e frame.time -e frame.time_epoch
   2026-03-14 07:31:08.442000000 UTC   1773473468.442

   KST = 16:31:08

7. 교차검증 — 성공 후 실제로 뭘 했는가
   필터: http.authorization == "Basic YWRtaW46UzNjcjN0UGFzcw=="
   -> 이후 12건의 요청이 같은 자격증명으로 200 을 받았다.
      그중 하나가 206 Partial Content (파일 이어받기).

   tshark -r bruteforce.pcapng -Y 'http.response.code == 206' \
     -T fields -e http.content_length -e http.response_for.uri
   2097152   http://portal.example.com/admin/export/users.csv

   -> 인증 성공 후 users.csv 를 부분 전송으로 가져갔다.

8. 실패 횟수 확인 — 브루트포스 규모
   tshark -r bruteforce.pcapng -Y 'http.response.code == 401' | wc -l
   47

정답: admin / S3cr3tPass / 2026-03-14 07:31:08 UTC (16:31:08 KST)
      (부수 소득: 47회 실패 후 성공, 이후 users.csv 2 MB 유출)
```

1단계의 실패가 이 글의 요점이다. **`http.response.code == 200` 단독은 판정 도구가 아니다.** 200은 캡처의 절반을 차지한다. 쓸모 있는 것은 **코드 분포(어떤 코드가 존재하는가) → 전환 지점(401 다음의 200) → 짝짓기(`http.request_in`)** 순서다. 그리고 성공 시각은 응답이 아니라 **요청 프레임의 시각**으로 적는 것이 맞다.

## 막혔을 때 다음 체크

1. `http.response.code` **분포표**를 먼저 뽑았는가 — 사건 성격이 여기서 정해진다
2. `http.response.code >= 400` 으로 실패만 따로 봤는가
3. 401이 있는가 → **401 다음의 200**을 찾았는가
4. 폼 로그인인가 → **302 + `Location` + `Set-Cookie`** 로 성공을 판정했는가
5. 요청과 응답을 `http.request_in` 으로 짝지었는가 — `tcp.stream` 만으로는 부정확하다
6. `http.response_for.uri` 를 컬럼으로 올렸는가
7. `http.content_length` 를 함께 봤는가 — 200이라도 0바이트면 아무것도 안 나갔다
8. `content_length`가 비었으면 `http.transfer_encoding == "chunked"` 를 확인했는가
9. 404가 급증한 구간이 있는가 → 그 구간의 URI 집합과 User-Agent를 봤는가
10. 404 사이에 **403·200·301** 이 섞여 있는가 — 그것이 소득이다
11. 500이 있는가 → 그 응답 본문에서 스택 트레이스·DB 오류를 읽었는가
12. 206이 있는가 → `Content-Range` 를 합산해 총량과 원본 크기를 냈는가
13. 101이 있는가 → `websocket` 필터로 전환했는가
14. `http.time > 4` 로 지연 응답(blind SQLi)을 확인했는가
15. `http.request && !http.response_in` 으로 무응답 요청을 봤는가
16. `http.server` 로 기술 스택을 파악해 다음에 볼 로그를 정했는가
17. 시간을 UTC 절대시각으로 바꿨는가 (KST = UTC+9)

## 출처

- SRC-064 — RFC 9110 HTTP Semantics: 상태 코드 클래스와 개별 코드(100, 101, 200, 201, 204, 206, 301~308, 400, 401, 403, 404, 405, 413, 414, 416, 429, 500~504)의 정의, `WWW-Authenticate` / `Authorization` / `Location` / `Range` / `Content-Range` / `Transfer-Encoding` 헤더 의미
- SRC-002 — Wireshark Display Filter Reference: `http.response.code`(숫자 필드), `http.response.phrase`, `http.request_in`, `http.response_in`, `http.response_for.uri`, `http.time`, `http.server`, `http.location`, `http.set_cookie` 필드 정의
- `http.request.line` / `http.response.line`(개별 헤더 라인) 과 `http.response.code.desc` 는 Wireshark 버전에 따라 이름·존재가 다를 수 있다. 필터 입력창이 초록으로 바뀌는지로 확인하고, 확실하지 않으면 Follow HTTP Stream 으로 헤더를 직접 읽을 것
- `Server` 헤더 값과 세션 쿠키 이름으로 하는 스택 추정은 **정황 근거**다. 서버가 헤더를 위조·삭제할 수 있으므로 단정하지 말 것
- 메뉴 경로(`Analyze > Expert Information`, `Statistics > Conversations`, `View > Time Display Format`)는 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
