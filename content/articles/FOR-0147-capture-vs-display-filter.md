---
id: FOR-0147
title: "Capture Filter와 Display Filter 차이: 필터가 안 먹을 때"
slug: "capture-vs-display-filter"
category: "Network/PCAP"
type: "troubleshooting"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP", "UDP", "HTTP", "DNS", "ICMP"]
tools: ["Wireshark", "tshark", "tcpdump", "dumpcap"]
commands: ["tshark -r capture.pcapng -Y 'tcp.port == 80'", "tcpdump -i eth0 -w out.pcap 'tcp port 80'", "tshark -i eth0 -f 'host 10.0.0.1' -w out.pcapng"]
regex_patterns: []
wireshark_filters: ["tcp.port == 80", "ip.addr == 10.0.0.1", "ip.src == 10.0.0.1", "tcp.dstport == 443", "eth.addr == 00:11:22:33:44:55", "ip.proto == 47", "frame.len >= 100", "tcp.flags.syn == 1", "!(ip.addr == 10.0.0.1)", "http.host contains \"example\"", "http.host matches \"(?i)example\"", "tcp.port in {80, 443, 8080}"]
tshark_fields: ["ip.addr", "tcp.port", "frame.len", "eth.addr", "ip.proto"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["Capture Filter", "Display Filter", "필터 문법 차이", "필터가 안 먹는다"]
keywords: ["Capture Filter", "Display Filter", "BPF", "pcap-filter", "필터 문법", "필터 오류", "빨간 배경", "Decode As", "tcp port 80", "tcp.port == 80", "Wireshark 필터", "필터 결과 0건"]
aliases: ["와이어샤크 필터 오류", "필터가 빨갛다", "tcp port 80 안된다", "필터 문법 틀림", "캡처필터 표시필터", "필터 결과가 없다", "필터 안먹힘"]
symptom_keywords: ["필터를 넣었는데 빨간색이 된다", "필터 결과가 0건이다", "필터 문법 오류가 난다", "tcp port 80이 안 먹는다", "http 필터에 아무것도 안 나온다", "필터를 넣어도 패킷이 그대로다"]
related: ["FOR-0146", "FOR-0151", "FOR-0148"]
source_ids: ["SRC-003", "SRC-002"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

이미 저장된 pcap 에는 **Display Filter 문법만** 유효하다. `tcp port 80` 같은 Capture Filter(BPF)를 상단 필터 입력창에 넣으면 배경이 빨개지고 아무것도 적용되지 않는다. 올바른 형태는 `tcp.port == 80` 이며, 문법이 맞는데 결과가 0건이면 원인은 문법이 아니라 **비표준 포트·대소문자·재조립 설정** 쪽이다.

## 증상

| 증상 | 무슨 일이 벌어진 것인가 |
| --- | --- |
| 필터 입력창 배경이 **빨강**이고 Enter 를 눌러도 반응이 없다 | 문법 오류. 필터가 아예 적용되지 않았다 |
| `Filter "..." isn't a valid display filter` 류의 오류 메시지 | Capture Filter 문법 또는 존재하지 않는 필드명 |
| 배경이 **초록**인데 패킷 목록이 텅 비었다 | 문법은 맞다. 조건에 맞는 패킷이 정말 없거나, 파서가 프로토콜을 인식하지 못했다 |
| 배경이 **노랑**이고 결과가 이상하다 | 유효하지만 의도와 다르게 동작할 수 있는 필터. 대표는 `ip.addr != 10.0.0.1` |
| 필터를 쳤는데 패킷 목록이 그대로다 | Enter 또는 오른쪽 화살표(Apply) 를 누르지 않았다 |
| `tshark -r file -f '...'` 가 오류로 죽는다 | `-f` 는 라이브 캡처 전용이다. 파일 읽기에는 `-Y` 를 쓴다 |

## 가장 가능성 높은 원인

### 원인 1 — 두 필터 언어를 혼동했다 (압도적 1위)

Wireshark 는 **완전히 다른 두 개의 필터 언어**를 쓴다.

| | Capture Filter | Display Filter |
| --- | --- | --- |
| 정식 이름 | BPF / pcap-filter 문법 | Wireshark Display Filter |
| 언제 쓰나 | **캡처하는 순간** 저장할 패킷을 고를 때 | **이미 있는 패킷**에서 볼 것을 고를 때 |
| 저장된 pcap 분석에 | **쓸 수 없다** | 이것만 쓴다 |
| 입력 위치 | `Capture > Options` 의 Capture filter 칸 | 메인 창 상단 필터 입력창 |
| 표기 방식 | 키워드 나열 (`tcp port 80`) | 필드 = 값 (`tcp.port == 80`) |
| 문자열 검색 | 불가 | `frame contains "flag"` |
| 애플리케이션 프로토콜 | 불가 (포트로 근사) | `http`, `dns`, `smb2` 직접 지정 |
| tshark 옵션 | `-f` | `-Y` (또는 `-R`) |
| tcpdump | 그대로 동일 문법 | 없음 |

**핵심 오해 정정**: 논리 연산자가 다르다는 설명은 정확하지 않다. pcap-filter 는 `and` `or` `not` 과 `&&` `||` `!` 를 **둘 다** 받고, Display Filter 도 `and`/`&&`, `or`/`||`, `not`/`!` 를 **둘 다** 받는다. 진짜 차이는 **연산자가 아니라 좌변의 표기법**이다. `port` 는 BPF 키워드고 `tcp.port` 는 Display Filter 필드다. 이 둘은 서로의 언어에서 존재하지 않는다.

### 두 문법 대조표 (이 표가 이 글의 본체다)

| 하고 싶은 것 | Capture Filter (BPF) | Display Filter |
| --- | --- | --- |
| 특정 포트 (양방향) | `tcp port 80` | `tcp.port == 80` |
| 목적지 포트만 | `dst port 443` | `tcp.dstport == 443` |
| 출발지 포트만 | `src port 1337` | `tcp.srcport == 1337` |
| 특정 IP (양방향) | `host 10.0.0.1` | `ip.addr == 10.0.0.1` |
| 출발지 IP | `src host 10.0.0.1` | `ip.src == 10.0.0.1` |
| 목적지 IP | `dst host 10.0.0.1` | `ip.dst == 10.0.0.1` |
| 네트워크 대역 | `net 10.0.0.0/24` | `ip.addr == 10.0.0.0/24` |
| 포트 범위 | `portrange 1-1024` | `tcp.port <= 1024` 또는 `tcp.port in {1..1024}` |
| 여러 포트 | `tcp port 80 or tcp port 443` | `tcp.port in {80, 443, 8080}` |
| 프로토콜 | `tcp` / `udp` / `icmp` / `arp` | `tcp` / `udp` / `icmp` / `arp` (동일) |
| IP 프로토콜 번호 | `ip proto 47` | `ip.proto == 47` |
| MAC 주소 | `ether host 00:11:22:33:44:55` | `eth.addr == 00:11:22:33:44:55` |
| 프레임 길이 | `greater 100` / `less 60` | `frame.len >= 100` / `frame.len < 60` |
| SYN 만 | `tcp[tcpflags] & tcp-syn != 0` | `tcp.flags.syn == 1` |
| VLAN | `vlan 100` | `vlan.id == 100` |
| HTTP | **불가** — `tcp port 80` 으로 근사 | `http` |
| DNS 질의 도메인 | **불가** | `dns.qry.name contains "evil"` |
| 문자열 사냥 | **불가** | `frame contains "flag"` |
| 정규식 | **불가** | `http.host matches "acme\\.(org\|com)"` |
| 부정 | `not host 10.0.0.1` | `!(ip.addr == 10.0.0.1)` |

마지막 줄이 중요하다. 아래 원인 3을 보라.

### 원인 2 — `=` 를 썼다

Display Filter 의 등호는 `==` (또는 `eq`) 다. `ip.addr = 10.0.0.1` 은 오류다.
BPF 의 바이트 슬라이스에서는 `=` 가 `==` 와 같게 동작하므로(`ip[0] & 0xf = 5`), BPF 습관이 있으면 실수하기 쉽다.

### 원인 3 — `!=` 의 함정

| Wireshark 버전 | `!=` 의 의미 | `ip.addr != 10.0.0.1` 결과 |
| --- | --- | --- |
| 3.6 이전 | `any_ne` (하나라도 다르면 참) | `ip.addr` 는 src/dst 두 번 나오므로 **거의 항상 참** = 필터가 무의미 |
| 3.6 이후 | `all_ne` (전부 달라야 참) | 의도대로 동작 |

버전을 따지지 않으려면 항상 이렇게 쓴다.

```text
!(ip.addr == 10.0.0.1)
```

`==` 는 `any_eq` 이므로 "src 든 dst 든 하나라도 그 IP" 를 잡고, 그 전체를 부정하면 정확히 "그 IP 와 무관한 패킷" 이 된다. 값 기준을 강제하려면 `===`(`all_eq`) / `!==`(`any_ne`) 도 쓸 수 있다.

### 원인 4 — 필드명 오타

필드명은 **전부 소문자**이고, 짐작으로 쓰면 거의 틀린다. 자주 틀리는 것들.

| 틀린 표기 | 올바른 표기 |
| --- | --- |
| `dns.query.name` | `dns.qry.name` |
| `dns.response` | `dns.flags.response` |
| `http.method` | `http.request.method` |
| `http.uri` | `http.request.uri` |
| `tcp.sport` / `tcp.dport` | `tcp.srcport` / `tcp.dstport` |
| `ip.source` | `ip.src` |
| `tcp.flag.syn` | `tcp.flags.syn` |
| `TCP.PORT` | `tcp.port` |

확인 방법: 패킷 상세 창에서 그 필드를 클릭하면 **좌하단 상태 바에 정식 필드명이 표시된다.** 또는 우클릭 → `Apply as Filter > Selected` 로 Wireshark 가 직접 필터를 만들게 한다. 이것이 오타를 없애는 가장 빠른 길이다.

### 원인 5 — 문자열 따옴표와 대소문자

```text
http.host == "example.com"        <- 문자열은 큰따옴표
http.host contains "Example"      <- contains 는 대소문자를 구분한다
http.host matches "example"       <- matches 는 대소문자를 무시한다
lower(http.host) contains "example"   <- contains 로 대소문자를 무시하고 싶을 때
```

`contains` 로 `"Password"` 를 찾는데 실제 페이로드가 `password` 면 0건이 나온다. 이때 `matches` 로 바꾸면 즉시 잡힌다.

### 원인 6 — 비표준 포트라 프로토콜이 인식되지 않았다

`http` 필터가 0건인데 `Protocol` 컬럼에 `TCP` 만 보이면, 서버가 8080/8888/9001 등에서 HTTP 를 서비스한 것이다. Wireshark 는 포트로 dissector 를 고르므로 HTTP 로 해석하지 않는다.

```text
패킷 우클릭 > Decode As...
  Field = "TCP port",  Value = 8080,  Current = HTTP
확인 후 OK -> 이제 http 필터가 동작한다
```

`Analyze > Decode As...` 로도 같은 창을 연다.

### 원인 7 — TCP 재조립이 꺼져 있다

`frame contains "flag"` 는 **한 프레임 안**만 본다. 문자열이 두 세그먼트에 걸쳐 쪼개졌으면 걸리지 않는다.

```text
Edit > Preferences > Protocols > TCP
  [v] Allow subdissector to reassemble TCP streams
```

이것을 켜야 `http.file_data`, `tcp.reassembled.data` 계열이 채워진다. 그리고 재조립 자체가 불가능한 캡처(중간부터 시작, snaplen 으로 잘림)라면 필터를 아무리 고쳐도 답이 안 나온다 — 먼저 [FOR-0151](./expert-information.html) 로 캡처 신뢰도를 판정한다.

## 1차 확인

순서대로 30초 안에 끝낸다.

```text
1. 필터 입력창 배경색을 본다
   빨강 -> 문법 문제 (아래 2~4)
   초록 -> 문법은 정상. 대상이 없는 것 (아래 5~7)

2. 입력한 문자열에 점(.)이 있는가
   "tcp port 80" 처럼 점이 없으면 BPF 다. "tcp.port == 80" 으로 바꾼다

3. 등호가 == 인가. = 하나면 오류다

4. 필드명을 직접 타이핑했는가
   -> 지우고, 패킷 상세에서 해당 필드 우클릭 > Apply as Filter > Selected

5. Protocol 컬럼에 그 프로토콜이 보이는가
   보이지 않으면 Decode As 로 강제한다

6. contains 를 matches 로 바꿔 본다 (대소문자)

7. Statistics > Protocol Hierarchy 로 그 프로토콜이 캡처에 있는지 먼저 확인한다
   ([FOR-0148](./protocol-hierarchy.html))
```

## 2차 확인

### 필터를 손으로 쓰지 않는 세 가지 방법

| 방법 | 경로 | 결과 |
| --- | --- | --- |
| 필드에서 만들기 | 패킷 상세 트리 → 우클릭 → `Apply as Filter > Selected` | 필드명·값·따옴표가 자동으로 정확하다 |
| 대화에서 만들기 | `Statistics > Conversations` → 행 우클릭 → `Apply as Filter > Selected > A ↔ B` | `ip.addr == A && ip.addr == B && tcp.port == ...` |
| 표현식 빌더 | 필터창 오른쪽 `+` 또는 `Analyze > Display Filter Expression...` | 프로토콜 트리에서 필드를 골라 넣는다 |

`Prepare as Filter` 를 쓰면 적용하지 않고 입력창에만 넣어 준다. 조건을 여러 개 조합할 때 이쪽이 편하다.

### 두 언어를 각자의 자리에서 쓰기

```text
Capture Filter 입력 위치
  Capture > Options > 인터페이스 선택 > 하단 "Capture filter for selected interfaces"
  Capture > Capture Filters...        (저장된 BPF 관리)

Display Filter 입력 위치
  메인 창 상단 필터 입력창
  Analyze > Display Filters...        (저장된 Display Filter 관리)
```

두 메뉴 이름이 각각 `Capture` / `Analyze` 아래에 있다는 것만 기억하면 헷갈리지 않는다.

### tshark 에서의 대응

```bash
# 라이브 캡처 — Capture Filter (BPF)
tshark -i eth0 -f 'host 10.0.0.1 and tcp port 80' -w out.pcapng

# 저장 파일 분석 — Display Filter
tshark -r capture.pcapng -Y 'tcp.port == 80'

# 저장 파일에 -f 를 쓰면 오류다. 이것이 가장 흔한 tshark 실수다
tshark -r capture.pcapng -f 'tcp port 80'      # 잘못됨

# BPF 로 저장 파일을 다시 걸러야 한다면 tcpdump 를 쓴다
tcpdump -r capture.pcapng -w filtered.pcap 'tcp port 80'
```

`-Y` 로 걸러 새 파일을 만들 수도 있다.

```bash
tshark -r capture.pcapng -Y 'http.request' -w http_only.pcapng
```

## 다른 방법

문법이 계속 말썽이면 필터를 우회한다.

| 상황 | 우회 |
| --- | --- |
| 필드명을 모른다 | 우클릭 `Apply as Filter` 로 Wireshark 가 쓰게 한다 |
| 프로토콜이 인식되지 않는다 | `Decode As`, 아니면 `tcp.port == 8080` 으로 포트만 걸고 Follow Stream |
| 문자열이 안 걸린다 | `Edit > Find Packet` (Packet bytes / String / Case sensitive 체크 해제) |
| 그래도 안 걸린다 | 파서를 완전히 우회한다: `strings -n 6 capture.pcapng \| grep -Ei 'flag\{\|password'` |
| 필터 결과를 표로 뽑고 싶다 | `tshark -Y ... -T fields -e ... -E header=y` |

`Edit > Find Packet` 의 `Packet bytes` + `String` 조합은 필터 문법 없이 페이로드 전체를 훑는다. 대소문자 체크박스를 반드시 확인한다.

## 흔한 함정

- **저장된 pcap 에 BPF 를 넣는 것.** `tcp port 80` 은 캡처 시점 문법이다. 분석 창에서는 `tcp.port == 80` 이다. 빨간 배경이 보이면 반사적으로 점(`.`)과 `==` 를 찾는다.
- **`ip.addr != x` 로 특정 IP 를 제외했다고 믿는 것.** 3.6 이전에서는 거의 항상 참이 되어 아무것도 걸러지지 않는다. `!(ip.addr == x)` 로 쓴다.
- **필드명을 짐작해서 타이핑하는 것.** `dns.query.name` 은 없다. `dns.qry.name` 이다. 상태 바 표기를 보거나 `Apply as Filter` 로 만든다.
- **`contains` 가 대소문자를 무시한다고 착각하는 것.** 구분한다. `matches` 가 무시한다. 또는 `lower()` 로 감싼다.
- **`http` 가 0건이면 HTTP 가 없다고 결론 내리는 것.** 비표준 포트에서는 `TCP` 로만 보인다. `Decode As > HTTP` 로 강제한다.
- **Enter 를 안 누르는 것.** 초록 배경만 확인하고 넘어가면 필터는 적용되지 않은 상태다. Enter 또는 오른쪽 화살표 버튼.
- **`frame contains` 로 재조립된 데이터를 찾으려는 것.** 프레임 단위 검색이다. 스트림 전체를 보려면 Follow Stream 이나 `http.file_data` 를 쓴다.
- **캡처 자체가 잘린 것을 필터 문제로 오진하는 것.** `Expert Information` 에 "packet size limited during capture" 가 있으면 페이로드가 아예 저장되지 않았다. 필터를 고쳐도 나오지 않는다.
- **tshark 에서 `-r` 과 `-f` 를 같이 쓰는 것.** 파일 읽기에는 `-Y` 다.
- **대화형 필터 히스토리를 재사용하다 문법이 섞이는 것.** 필터창 드롭다운에 BPF 와 Display Filter 가 함께 남아 있으면 실수한다. `Clear` 로 비우고 다시 쓴다.

## 실제 예시

```text
문제:
"내부 호스트가 외부 웹 서버에 업로드한 파일 이름을 찾으세요."
첨부: upload.pcapng (4,211 packets)

1. 첫 시도 (실패)
   필터창에 입력: tcp port 8080 and host 203.0.113.20
   -> 입력창 배경이 빨강. Enter 를 눌러도 패킷 목록이 그대로다.
   원인: BPF 문법을 Display Filter 창에 넣었다.

2. 두 번째 시도 (또 실패)
   필터창에 입력: tcp.port == 8080 && ip.addr == 203.0.113.20
   -> 배경은 초록. 패킷 1,102개가 걸린다. 여기까지는 맞다.
   이어서 입력: http.request.method == "POST"
   -> 0건.
   Protocol 컬럼을 보니 전부 "TCP" 다. HTTP 로 해석되지 않았다.

3. 접근 변경 — Decode As
   패킷 하나 우클릭 > Decode As...
     Field = TCP port, Value = 8080, Current = HTTP
   OK -> Protocol 컬럼이 HTTP 로 바뀐다.

   다시: http.request.method == "POST"
   -> 3건.

4. 세 번째 시도 (실패)
   본문에서 파일명을 찾으려고: http.file_data contains "Filename"
   -> 0건.
   원인 둘. (a) multipart 헤더의 실제 표기는 "filename" 소문자다.
            (b) contains 는 대소문자를 구분한다.

5. 수정
   http.file_data matches "filename"
   -> 3건. matches 는 대소문자를 무시한다.

   패킷 하나 선택 > Follow > HTTP Stream
     Content-Disposition: form-data; name="file"; filename="payroll_2026Q1.xlsx"

6. tshark 로 재확인
   $ tshark -r upload.pcapng -d tcp.port==8080,http \
       -Y 'http.request.method == "POST"' \
       -T fields -e frame.number -e http.host -e http.request.uri
   412   203.0.113.20:8080   /upload.php
   1877  203.0.113.20:8080   /upload.php
   2903  203.0.113.20:8080   /upload.php

   ("-d tcp.port==8080,http" 가 GUI 의 Decode As 에 해당한다)

정답: payroll_2026Q1.xlsx

교훈 세 개:
  - 빨간 배경 = 문법. 점과 == 를 확인한다.
  - 초록인데 0건 = 대상이 없거나 파서가 모른다. Decode As 를 떠올린다.
  - 문자열이 0건 = 대소문자. contains 를 matches 로 바꾼다.
```

## 막혔을 때 다음 체크

1. 배경색이 빨강인가 초록인가 — 이 하나로 원인 절반이 갈린다
2. 입력한 문자열에 점(`.`)이 있는가 — 없으면 BPF 를 잘못 넣었다
3. `=` 가 아니라 `==` 인가
4. 필드명을 상태 바나 `Apply as Filter` 로 확인했는가
5. 문자열에 큰따옴표를 씌웠는가
6. `contains` 를 `matches` 로 바꿔 봤는가
7. `!=` 를 `!( ... == ... )` 로 바꿔 봤는가
8. `Protocol` 컬럼에 그 프로토콜이 보이는가 → 아니면 `Decode As`
9. `Statistics > Protocol Hierarchy` 에 그 프로토콜이 존재하는가 ([FOR-0148](./protocol-hierarchy.html))
10. `Analyze > Expert Information` 에 "packet size limited during capture" 가 있는가 ([FOR-0151](./expert-information.html))
11. TCP 재조립 옵션이 켜져 있는가
12. Enter 또는 Apply 를 눌렀는가
13. tshark 라면 `-f` 가 아니라 `-Y` 를 썼는가
14. 마지막 수단으로 `strings` + `grep` 을 돌렸는가 ([FOR-0146](./wireshark-30sec-triage.html))

## 출처

- SRC-003 — Wireshark User's Guide: "The Filter Toolbar" 절의 필터 입력창 배경색 설명(유효=초록, 불완전·무효=빨강), Capture Filters / Display Filters 메뉴 위치, Decode As
- SRC-002 — Wireshark Display Filter Reference 및 사용자 가이드의 필터 문법 절: 비교 연산자(`eq`/`==`, `ne`/`!=`, `all_eq`/`===`, `any_ne`/`!==`, `contains`, `matches`/`~`), 논리 연산자(`and`/`&&`, `or`/`||`, `not`/`!`, `xor`/`^^`), `in {}` 집합 표기, `matches` 가 대소문자를 무시한다는 점, `lower()`/`upper()` 함수, `!=` 의 의미가 3.6 에서 all_ne 로 변경된 사실, 본문에 등장한 모든 필드명(`ip.addr`, `ip.src`, `ip.dst`, `ip.proto`, `tcp.port`, `tcp.srcport`, `tcp.dstport`, `tcp.flags.syn`, `eth.addr`, `frame.len`, `vlan.id`, `dns.qry.name`, `dns.flags.response`, `http.request.method`, `http.request.uri`, `http.host`, `http.file_data`)
- Capture Filter(BPF) 문법의 primitive 와 연산자 — pcap-filter(7) 명세 기준으로 작성했다. `and`/`&&`, `or`/`||`, `not`/`!` 가 양쪽 모두에서 동등하게 허용된다는 점, `portrange`, `greater`/`less`, `ether host`, `ip proto`, `vlan`, `tcp[tcpflags] & tcp-syn` 표기가 이에 해당한다. 이 명세는 `research/sources.json` 에 등재되어 있지 않아 SRC 로 인용하지 못했다 (최종 보고에 추가 요청)
- 필터 입력창의 **노랑** 배경(유효하지만 의도와 다른 결과가 나올 수 있음)은 현행 Wireshark GUI 에서 관찰되지만 User's Guide 의 Filter Toolbar 절에는 초록·빨강만 문서화되어 있다. 버전에 따라 표시 여부가 다를 수 있으므로 실제 화면에서 확인할 것
- 메뉴 경로(`Capture > Options`, `Analyze > Decode As...`, `Edit > Preferences > Protocols > TCP`)와 Preferences 항목명은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
