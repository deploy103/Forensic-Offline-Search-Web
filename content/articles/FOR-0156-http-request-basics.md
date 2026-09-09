---
id: FOR-0156
title: "Wireshark HTTP 필터 필드 레퍼런스: http.request부터 http.request_in까지"
slug: "http-request-basics"
category: "Network/PCAP"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP request header", "HTTP response header"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r c.pcapng -Y http.request -T fields -e http.host -e http.request.uri", "tshark -r c.pcapng -Y http.response -T fields -e http.response.code -e http.response_for.uri", "tshark -r c.pcapng -Y http -T fields -e http.request_in -e http.time"]
regex_patterns: []
wireshark_filters: ["http", "http.request", "http.response", "http.request.method", "http.request.uri", "http.request.full_uri", "http.request.version", "http.host", "http.user_agent", "http.referer", "http.cookie", "http.authorization", "http.content_type", "http.content_length", "http.content_encoding", "http.transfer_encoding", "http.file_data", "http.response.code", "http.response.phrase", "http.server", "http.location", "http.set_cookie", "http.time", "http.request_in", "http.response_for.uri"]
tshark_fields: ["http.request.method", "http.request.uri", "http.request.full_uri", "http.request.version", "http.host", "http.user_agent", "http.referer", "http.cookie", "http.authorization", "http.content_type", "http.content_length", "http.content_encoding", "http.transfer_encoding", "http.file_data", "http.response.code", "http.response.phrase", "http.server", "http.location", "http.set_cookie", "http.time", "http.request_in", "http.response_for.uri", "tcp.stream"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["http.request", "HTTP 필터 기본", "http 필드 목록"]
keywords: ["HTTP 필터", "http.request", "http.response", "Wireshark 필드", "display filter", "http.host", "http.request.uri", "http.request_in", "http.time", "필드 목록"]
aliases: ["http 필터", "와이어샤크 http 필터", "http 필드 목록", "http.request 뭐냐", "http 필터 정리", "패킷 http 필터"]
symptom_keywords: ["어떤 HTTP 필터를 써야 하는지 모르겠다", "필드 이름이 기억나지 않는다", "요청과 응답을 짝지어야 한다", "http 필터가 아무것도 안 걸린다", "응답이 어느 요청의 것인지 모르겠다"]
related: ["FOR-0157", "FOR-0159", "FOR-0161"]
source_ids: ["SRC-002", "SRC-064"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

HTTP 분석의 필터는 세 층으로 나뉜다. **존재 판정(`http`, `http.request`, `http.response`) → 요청 식별(`http.request.method`, `http.request.uri`, `http.host`) → 응답 판정(`http.response.code`, `http.content_length`)** 이고, 요청과 응답을 잇는 열쇠는 `http.request_in`과 `tcp.stream`이다.

## 개념

Wireshark의 HTTP 필드는 **패킷 하나에 요청 필드와 응답 필드가 동시에 존재하지 않는다.** 요청 패킷에는 `http.request.*`가, 응답 패킷에는 `http.response.*`가 붙는다. 이 사실이 필터 설계를 지배한다.

| 층 | 필터 | 무엇을 얻는가 |
| --- | --- | --- |
| 존재 | `http` | HTTP로 해석된 모든 패킷(요청+응답+이어붙은 본문) |
| 요청만 | `http.request` | 요청 라인이 있는 패킷. **URI 목록을 뽑는 출발점** |
| 응답만 | `http.response` | 상태 라인이 있는 패킷. 성공/실패 판정 |
| 특정 요청 | `http.request.method == "GET"` | 메서드별 분리 |
| 특정 대상 | `http.host`, `http.request.uri` | 누구에게 무엇을 요청했는가 |
| 결과 | `http.response.code` | 그 요청이 통했는가 |
| 내용 | `http.file_data` | 실제로 전송된 바이트 |

`http`와 `http.request`의 차이가 초보자를 가장 많이 잡는다. `http`는 응답 패킷과 재조립된 본문 패킷까지 포함하므로 **개수가 요청 개수보다 훨씬 많다.** "요청이 몇 건인가"를 세려면 반드시 `http.request`를 쓴다.

HTTP는 평문 프로토콜이므로 캡처에 다 남는다. 반대로 **HTTPS(TLS 안의 HTTP)는 `http` 필터에 걸리지 않는다.** `tls` 필터와 SNI로 넘어가야 한다.

## 파일 / 경로

이 글은 디스크 artifact가 아니라 캡처 파일을 다룬다.

| 대상 | 형식 | 비고 |
| --- | --- | --- |
| 캡처 파일 | `.pcap` / `.pcapng` | pcapng는 주석·인터페이스 정보를 함께 담는다 |
| Wireshark 기본 HTTP 포트 | TCP 80, 8080, 8008, 3128 등 | `Preferences > Protocols > HTTP > TCP port(s)` 에 목록이 있다 |
| 비표준 포트 | 예: 8888, 9001 | 패킷 우클릭 `Decode As...` 로 HTTP 지정 |
| 서버 측 대조 로그 | `access.log`, `u_ex*.log` | 요청 URI·상태 코드·User-Agent가 같은 값으로 남는다 |

```text
Preferences > Protocols > HTTP > TCP port(s)
Analyze > Decode As...   (Field=TCP port, Current=HTTP)
Preferences > Protocols > TCP > Allow subdissector to reassemble TCP streams
```

세 번째 설정이 꺼져 있으면 `http.file_data`가 비고, 여러 세그먼트에 걸친 본문 검색이 실패한다.

## 주요 필드

### 요청 측

| 필드 | 값의 예 | 용도 | 컬럼으로 둘 가치 |
| --- | --- | --- | --- |
| `http.request` | (존재 여부) | 요청 패킷만 남긴다 | - |
| `http.request.method` | `GET` `POST` `PUT` `HEAD` `OPTIONS` | 메서드 분리. **문자열이므로 큰따옴표 필수** | 있음 |
| `http.request.uri` | `/admin/upload.php?id=3` | 경로+쿼리. **호스트는 없다** | 필수 |
| `http.request.full_uri` | `http://shop.example.com/admin/upload.php?id=3` | Host 헤더와 합성한 전체 URL | 있음 |
| `http.request.version` | `HTTP/1.1` `HTTP/1.0` | `HTTP/1.0` 단독 사용은 스크립트/도구 신호 | 낮음 |
| `http.host` | `shop.example.com` | Host 헤더. 가상 호스트를 구분한다 | 필수 |
| `http.user_agent` | `curl/8.4.0` | 클라이언트 도구 식별 | 있음 |
| `http.referer` | `http://shop.example.com/index.php` | 유입 경로. **철자가 `referer`(r 하나)** | 있음 |
| `http.cookie` | `PHPSESSID=9f2a...` | 세션 추적, 하이재킹 판정 | 있음 |
| `http.authorization` | `Basic YWRtaW46cGFzcw==` | `Basic`은 Base64, `Bearer`는 JWT | 있음 |
| `http.content_type` | `application/x-www-form-urlencoded` | **요청 본문 처리 방법을 결정** | 있음 |
| `http.content_length` | `8421` | 선언된 본문 길이 | 있음 |

### 응답 측

| 필드 | 값의 예 | 용도 |
| --- | --- | --- |
| `http.response` | (존재 여부) | 응답 패킷만 남긴다 |
| `http.response.code` | `200` `302` `401` `404` `500` | **숫자 필드. 범위 비교가 된다** (`>= 400`) |
| `http.response.phrase` | `OK` `Not Found` `Forbidden` | 코드와 짝인 사유구. 서버가 임의로 바꿀 수 있다 |
| `http.server` | `Apache/2.4.52 (Ubuntu)` | 서버 기술 스택 파악 |
| `http.location` | `/dashboard.php` | 3xx 리다이렉트 목적지. **로그인 성공 판정에 쓰인다** |
| `http.set_cookie` | `PHPSESSID=...; HttpOnly` | 세션 발급 시점 = 인증 성공 시점 |
| `http.content_type` | `application/octet-stream` | 응답 본문 종류. 파일 다운로드 판정 |
| `http.content_length` | `1048576` | 응답 크기. 유출량 추정 |
| `http.content_encoding` | `gzip` `br` `deflate` | 압축됨. 원문을 보려면 해제 필요 |
| `http.transfer_encoding` | `chunked` | **`Content-Length`가 없다.** 크기 판정과 추출이 까다로워진다 |
| `http.file_data` | (바이트) | **재조립된 본문 바이트.** 요청·응답 모두에 붙는다 |

### 요청과 응답을 잇는 필드

| 필드 | 붙는 곳 | 의미 |
| --- | --- | --- |
| `http.request_in` | **응답 패킷** | 이 응답에 대응하는 요청의 프레임 번호 |
| `http.response_in` | **요청 패킷** | 이 요청에 대응하는 응답의 프레임 번호 |
| `http.response_for.uri` | **응답 패킷** | 이 응답이 어떤 URI에 대한 것인지 (full URI) |
| `http.time` | **응답 패킷** | 요청부터 응답까지 초 단위 경과 시간 |
| `tcp.stream` | 모든 패킷 | 같은 TCP 연결의 요청/응답을 묶는 인덱스 |

**`http.response_for.uri`가 실무에서 가장 강력하다.** 응답만 필터한 상태에서도 "이 404가 어떤 경로에 대한 것인가"를 한 컬럼으로 볼 수 있어, 요청과 응답을 따로 뽑아 손으로 맞추는 작업이 사라진다.

Keep-Alive 연결에서는 한 `tcp.stream`에 요청/응답이 여러 쌍 들어 있다. 이때 **`tcp.stream`만으로는 짝을 확정할 수 없고 `http.request_in`이 정답이다.** 반대로 파이프라이닝이 없는 일반 브라우징이라면 `tcp.stream`으로도 충분하다.

### 비교 연산자별 동작

| 표현 | 의미 | 주의 |
| --- | --- | --- |
| `http.host == "a.com"` | 값 전체가 정확히 일치 | 부분 일치 안 됨 |
| `http.host contains "a.com"` | 부분 문자열. **대소문자 구분** | 바이트 단위 비교 |
| `http.host matches "a\\.(com\|net)"` | 정규식. **기본이 대소문자 무시** | `(?-i)`로 구분 강제 |
| `http.response.code >= 400` | 숫자 비교 | 문자열 필드에는 못 쓴다 |
| `http.request.method in {"GET" "POST"}` | 집합 멤버십 | 값마다 따옴표 필요 |
| `http.host` | 필드 존재 여부 | 값을 몰라도 "헤더가 있는가"를 판정 |

## 빠른 명령

```bash
tshark -r c.pcapng -Y http.request -T fields -e http.host -e http.request.uri
```

요청을 한눈에 보는 표:

```bash
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -e frame.number -e tcp.stream -e ip.src -e http.request.method \
            -e http.host -e http.request.uri -e http.user_agent \
  -E header=y -E separator=,
```

응답을 URI와 함께:

```bash
tshark -r capture.pcapng -Y 'http.response' \
  -T fields -e frame.number -e http.request_in -e http.response.code \
            -e http.content_length -e http.content_type -e http.response_for.uri \
  -E header=y
```

```text
frame.number  http.request_in  http.response.code  http.content_length  http.content_type  http.response_for.uri
918           842              302                 0                    text/html          http://shop.example.com/login
1310          1204             200                 44                   application/json   http://shop.example.com/admin/upload.php
2402          2377             404                 291                  text/html          http://shop.example.com/.git/config
```

GUI에서 같은 것을 보려면 필드 우클릭 → `Apply as Column`으로 `http.host`, `http.request.uri`, `http.response.code`, `tcp.stream` 네 개를 컬럼으로 올린다.

## 함께 보는 artifact

| 이 글의 필드 | 다음에 볼 것 |
| --- | --- |
| `http.request.method == "GET"` | GET 전용 분석 ([FOR-0157](./http-get-find.html)) |
| `http.request.method == "POST"` | 본문·자격증명 ([FOR-0158](./http-post-find.html)) |
| `http.request.uri` | URI 필터 정밀 사용 ([FOR-0159](./http-request-uri-filter.html)) |
| `http.host` | 접속 도메인 목록화 ([FOR-0160](./http-host-filter.html)) |
| `http.response.code` | 상태 코드 판정 ([FOR-0161](./http-status-analysis.html)) |
| `http.file_data` | Export Objects로 파일 추출 ([FOR-0165](./export-objects-http.html)) |
| `tcp.stream` | 스트림 번호 필터 ([FOR-0164](./tcp-stream-filter.html)) |
| 전체 흐름 | 트리아지 순서 ([FOR-0146](./wireshark-30sec-triage.html)) |

## 흔한 실수

- **`http.request.method == GET` (따옴표 없음).** Wireshark는 문자열 값에 큰따옴표를 요구한다. 게다가 값은 **대문자**다. `"get"`은 매칭되지 않는다.
- **`http.referrer`로 쓰는 것.** HTTP 헤더 자체가 `Referer`(r 하나)이고 Wireshark 필드도 `http.referer`다. `http.referrer`는 존재하지 않는 필드라 문법 오류가 난다.
- **`http` 개수를 요청 개수로 세는 것.** `http`는 응답과 이어붙은 본문 패킷까지 포함한다. 요청 개수는 `http.request`로 센다.
- **`http.request.uri`에 호스트가 들어 있다고 가정하는 것.** `/login`만 들어 있다. 도메인까지 필요하면 `http.request.full_uri`나 `http.host`를 쓴다.
- **응답 패킷에 `http.request.uri`를 기대하는 것.** 응답에는 그 필드가 없다. `http.response_for.uri`가 응답 측 대응 필드다.
- **`http.content_length`를 실제 전송량으로 믿는 것.** `Transfer-Encoding: chunked`면 `Content-Length` 헤더가 아예 없고, 값이 있어도 압축 전/후 기준이 헷갈린다. 실제 크기는 `Statistics > Conversations`의 Bytes로 확인한다.
- **HTTPS를 `http` 필터로 찾는 것.** TLS로 감싼 HTTP는 `http`에 안 걸린다. 키가 없으면 `tls.handshake.extensions_server_name`(SNI)으로 목적지만 확보한다.
- **비표준 포트를 놓치는 것.** 9001 포트 HTTP는 Protocol 컬럼에 `TCP`로만 보인다. `Decode As...`로 HTTP를 강제하기 전까지 `http` 필터는 0건이다.
- **`http.file_data`가 비었다고 본문이 없다고 판단하는 것.** TCP 재조립 설정, chunked 전송, 미인식 포트 중 하나가 원인이다.
- **`http.response.phrase`로 성공/실패를 판정하는 것.** 사유구는 서버가 임의 문자열로 바꿀 수 있다. 판정은 항상 숫자 `http.response.code`로 한다.

## mini example

```text
문제:
"관리자가 로그인에 성공한 시각과 그때 발급된 세션 쿠키 값을 구하세요."
첨부: portal.pcapng (4,180 packets)

1. 첫 시도 (실패):
   필터: http && http.cookie
   -> 1,204개가 걸렸다. 브라우징 내내 모든 요청이 쿠키를 실어 보내므로
      "발급 시점"을 여기서 찾을 수 없다.
      http.cookie 는 "요청이 들고 간 쿠키"이고, 발급은 응답 측 사건이다.

2. 필드를 바꾼다 — 발급은 Set-Cookie 다.
   필터: http.set_cookie

   frame  code  set_cookie
   918    302   PHPSESSID=b71c3ad9f0e24; path=/; HttpOnly
   3355   200   PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:00 GMT

   -> 918 이 발급, 3355 는 로그아웃(값이 deleted).

3. 그 응답이 어느 요청의 것인지 — http.request_in
   tshark -r portal.pcapng -Y 'frame.number == 918' \
     -T fields -e http.request_in -e http.response.code -e http.location -e http.time

   842   302   /dashboard.php   0.043

   -> 요청은 frame 842. 302 + Location: /dashboard.php = 로그인 성공 리다이렉트.

4. 요청 쪽을 확인
   필터: frame.number == 842
   POST /login  Host: portal.example.com
   http.content_type = application/x-www-form-urlencoded

   본문 파싱은 POST 전용 절차로 넘긴다 -> FOR-0158

5. 시각 확정
   View > Time Display Format > UTC Date and Time of Day
   frame 842: 2026-03-14 07:22:41.108 UTC  = KST 16:22:41 (UTC+9)

정답: 2026-03-14 07:22:41 UTC (16:22:41 KST) / PHPSESSID=b71c3ad9f0e24
```

1단계의 실패가 이 글의 요점이다. **`http.cookie`(요청)와 `http.set_cookie`(응답)는 방향이 반대인 서로 다른 필드다.** 요청 측 필드로 응답 측 사건을 찾으려 하면 건수만 폭발한다. 그리고 응답에서 요청으로 되돌아가는 다리가 `http.request_in`이다.

## 출처

- SRC-002 — Wireshark Display Filter Reference: `http.*` 필드 이름과 자료형(문자열/숫자/프레임 번호), 비교 연산자와 `matches`의 대소문자 동작
- SRC-064 — RFC 9110 HTTP Semantics: 메서드, 상태 코드, `Host` / `Referer` / `Authorization` / `Content-Length` / `Transfer-Encoding` 헤더의 정의
- `http.request.uri.path`, `http.request.uri.query`, `http.response.code.desc` 처럼 비교적 최근에 추가된 필드는 Wireshark 버전에 따라 없을 수 있다. 필터 입력창이 초록색으로 바뀌는지로 존재를 확인할 것
- `Preferences` 하위 항목명과 `Decode As...` 메뉴 경로는 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
