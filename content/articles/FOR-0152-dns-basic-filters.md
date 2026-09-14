---
id: FOR-0152
title: "DNS 트래픽 기본 필터 모음"
slug: "dns-basic-filters"
category: "Network/PCAP"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "DNS query", "DNS response"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["DNS", "UDP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.a", "tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort | uniq -c | sort -nr", "tshark -r capture.pcapng -Y 'dns.flags.rcode != 0'"]
regex_patterns: []
wireshark_filters: ["dns", "dns.flags.response == 0", "dns.flags.response == 1", "dns.qry.name", "dns.qry.name contains \"flag\"", "dns.qry.type == 1", "dns.qry.type == 28", "dns.qry.type == 16", "dns.qry.type == 5", "dns.flags.rcode == 3", "dns.flags.rcode != 0", "dns.a", "dns.aaaa", "dns.cname", "dns.txt", "dns.count.answers > 0", "udp.port == 53", "tcp.port == 53"]
tshark_fields: ["dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.cname", "dns.txt", "dns.count.answers", "dns.id"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["dns 필터", "dns 기본 필터"]
keywords: ["DNS 필터", "dns 기본 필터", "dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.flags.rcode", "dns.a", "dns.txt", "NXDOMAIN", "DNS 레코드 타입"]
aliases: ["dns 필터 정리", "와이어샤크 dns 필터", "dns 질의 응답 필터", "dns 필터 모음", "dns rcode", "dns 레코드 타입 필터"]
symptom_keywords: ["dns 필터가 뭐가 있는지 모르겠다", "dns 질의와 응답을 구분하고 싶다", "레코드 타입별로 필터하고 싶다", "nxdomain만 보고 싶다", "dns 필터 문법을 모르겠다"]
related: ["FOR-0153", "FOR-0154", "FOR-0155", "FOR-0148"]
source_ids: ["SRC-002", "SRC-065", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

DNS 필터는 세 층으로 정리한다. **존재 판정(`dns`) → 질의/응답 구분(`dns.flags.response`) → 이름·타입·결과 확인(`dns.qry.name`, `dns.qry.type`, `dns.a`, `dns.flags.rcode`)**. 이 순서만 지키면 DNS 트래픽에서 필요한 값은 대부분 한두 줄 필터로 뽑힌다.

## 개념

DNS는 UDP 53(대용량 응답이나 Zone Transfer는 TCP 53)으로 오가는 요청-응답 프로토콜이다. 한 트랜잭션은 **질의(Query, `dns.flags.response == 0`) 패킷 하나와 응답(Response, `dns.flags.response == 1`) 패킷 하나**로 구성되며, 같은 `dns.id`(트랜잭션 ID)로 짝지어진다.

Wireshark의 DNS 필드는 질의 패킷과 응답 패킷 모두에서 `dns.qry.name`(질의한 이름)을 공유하지만, **답을 담은 필드(`dns.a`, `dns.cname` 등)는 응답 패킷에만 존재한다.** 이 차이가 필터 설계를 지배한다 — "누가 무엇을 물었나"는 질의에서, "결과가 무엇인가"는 응답에서 봐야 한다.

CTF에서 DNS가 등장하는 대표 시나리오.

| 시나리오 | 확인할 필터 |
| --- | --- |
| 어떤 도메인에 접속했는지 | `dns.qry.name` |
| 그 도메인이 실제로 가리킨 IP | `dns.a` (응답에서) |
| 이상하게 많은 질의(터널링 의심) | `dns.flags.response == 0`으로 개수 집계 |
| 존재하지 않는 도메인 조회 | `dns.flags.rcode == 3` (NXDOMAIN) |
| 특정 레코드 타입만 | `dns.qry.type` |
| Zone Transfer 시도 | `dns.qry.type == 252` 또는 `tcp.port == 53` |

## 파일 / 경로

DNS는 별도 저장 파일이 없고 pcap/pcapng 캡처 안의 패킷으로만 존재한다. 연관된 다른 위치는 다음과 같다.

| 대상 | 위치 | 관련성 |
| --- | --- | --- |
| pcap/pcapng | 캡처 파일 자체 | DNS 패킷의 유일한 출처 |
| Windows DNS 클라이언트 캐시 | `ipconfig /displaydns` (라이브 시스템) | 캡처가 없을 때 과거 조회 이력 |
| 브라우저 History | Chrome/Firefox 프로필 (`History`, `places.sqlite`) | DNS 조회 시점과 브라우저 방문 시점 대조 |
| `hosts` 파일 | `C:\Windows\System32\drivers\etc\hosts` | DNS를 우회한 강제 매핑 여부 확인 |

## 주요 필드

### 존재/방향 판정

| 필터 | 의미 |
| --- | --- |
| `dns` | DNS 패킷 전체(UDP/TCP 53 무관, 실제 DNS로 해석된 것만) |
| `udp.port == 53` | 포트 기준. 비표준 파싱이라 DNS로 안 잡힌 패킷까지 포함 |
| `tcp.port == 53` | TCP DNS(대용량 응답, Zone Transfer) |
| `dns.flags.response == 0` | 질의(클라이언트 → 서버) |
| `dns.flags.response == 1` | 응답(서버 → 클라이언트) |
| `dns.flags.recdesired == 1` | 재귀 질의 요청 |

### 이름과 타입

| 필터 | 의미 |
| --- | --- |
| `dns.qry.name` | 질의한 이름이 존재하는 모든 패킷 (질의+응답) |
| `dns.qry.name == "example.com"` | 정확히 일치 |
| `dns.qry.name contains "flag"` | 부분 문자열 포함 (대소문자 구분) |
| `dns.qry.name matches "(?i)flag"` | 대소문자 무시 정규식 |
| `dns.qry.type == 1` | A 레코드 (IPv4 주소) 질의 |
| `dns.qry.type == 28` | AAAA 레코드 (IPv6 주소) 질의 |
| `dns.qry.type == 5` | CNAME 질의 |
| `dns.qry.type == 15` | MX 질의 |
| `dns.qry.type == 16` | TXT 질의 |
| `dns.qry.type == 2` | NS 질의 |
| `dns.qry.type == 12` | PTR 질의 (역방향 조회) |
| `dns.qry.type == 252` | AXFR (전체 Zone Transfer 요청) |

### 응답 값과 결과 코드

| 필터 | 의미 |
| --- | --- |
| `dns.a` | 응답에 포함된 A 레코드 IPv4 주소 |
| `dns.aaaa` | 응답에 포함된 AAAA 레코드 IPv6 주소 |
| `dns.cname` | 응답에 포함된 CNAME 별칭 |
| `dns.txt` | 응답에 포함된 TXT 레코드 텍스트 |
| `dns.count.answers > 0` | 응답에 Answer 레코드가 1개 이상 |
| `dns.count.answers == 0 && dns.flags.response == 1` | 응답은 왔지만 답이 없음 (NXDOMAIN 등) |
| `dns.flags.rcode == 0` | 정상(NOERROR) |
| `dns.flags.rcode == 1` | 형식 오류(FORMERR) |
| `dns.flags.rcode == 2` | 서버 오류(SERVFAIL) |
| `dns.flags.rcode == 3` | 존재하지 않는 도메인(NXDOMAIN) |
| `dns.flags.rcode != 0` | 실패한 응답 전체 |

### 트랜잭션 짝짓기

| 필터 | 의미 |
| --- | --- |
| `dns.id == 0x1a2b` | 특정 트랜잭션 ID의 질의/응답 쌍 |
| `dns.time` | 질의부터 응답까지 걸린 시간(응답 패킷에만 존재) |
| `dns.time > 1` | 응답이 1초 이상 걸린 느린 DNS (터널링/부하 의심) |

## 빠른 명령

```bash
# 1) 질의-응답 한 줄 표로 정리 (가장 많이 쓴다)
tshark -r capture.pcapng -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.a

# 2) 고유 질의 이름 빈도 (터널링/이상 탐지 기본기)
tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name |
  sort | uniq -c | sort -nr | head -20

# 3) 실패한 응답만 (NXDOMAIN 등)
tshark -r capture.pcapng -Y 'dns.flags.rcode != 0' \
  -T fields -e dns.qry.name -e dns.flags.rcode

# 4) TXT 레코드만 (은닉 채널 후보)
tshark -r capture.pcapng -Y 'dns.txt' -T fields -e dns.qry.name -e dns.txt

# 5) 응답 지연 상위 (부하/터널링 의심)
tshark -r capture.pcapng -Y 'dns.time > 0.5' \
  -T fields -e dns.qry.name -e dns.time | sort -k2 -nr | head

# 6) TCP DNS (Zone Transfer 등 비정상 대용량)
tshark -r capture.pcapng -Y 'tcp.port == 53'
```

GUI에서는 `dns` 필터를 건 뒤 `Statistics > DNS`(있으면) 또는 컬럼에 `dns.qry.name`, `dns.a`를 추가해 나란히 본다.

## 함께 보는 artifact

| DNS에서 얻은 것 | 다음 목표 |
| --- | --- |
| 조회한 도메인 이름 | [FOR-0153](./dns-qry-name-filter.html)으로 그 이름만 필터 |
| 응답 IP | [FOR-0154](./dns-response-ip-tracking.html)로 그 IP와의 실제 통신 세션 추적 |
| 질의 개수가 비정상적으로 많음 | [FOR-0155](./dns-tunneling.html)로 터널링 여부 판정 |
| 특정 IP의 전체 프로토콜 구성 확인 | [FOR-0148](./protocol-hierarchy.html) |
| 세션/바이트 총량 | [FOR-0150](./endpoints.html) UDP 탭 |
| 브라우저 방문 시각과 대조 | Chrome History ([FOR-0191](./chrome-history.html)) |

## 흔한 실수

- **`dns.qry.name`만 걸고 IP를 찾으려는 것.** `dns.qry.name`은 질의/응답 양쪽에 다 있지만 IP(`dns.a`)는 **응답 패킷에만** 있다. 질의 패킷을 눌러서는 IP가 안 보인다.
- **`udp.port == 53`와 `dns`를 같은 것으로 쓰는 것.** `udp.port == 53`은 파서가 DNS로 인식하지 못한 비표준 트래픽(다른 프로토콜이 53번 포트를 도용한 경우)까지 잡는다. 정상 DNS만 원하면 `dns`를 쓴다.
- **`dns.a`가 없다고 응답이 없다고 판단하는 것.** CNAME 체인만 있고 최종 A 레코드가 다른 응답 패킷에 나뉘어 있거나, AAAA만 응답한 경우 `dns.a`는 비어 있다. `dns.count.answers`와 `dns.aaaa`도 함께 확인한다.
- **TCP DNS를 놓치는 것.** 기본 필터 `dns`는 TCP 53도 포함하지만, 캡처 시 TCP 스트림 재조립이 안 된 상태면 개별 세그먼트로 쪼개져 안 보일 수 있다. `tcp.port == 53`으로 존재 여부를 먼저 확인한다.
- **`rcode`값을 숫자로 외워 헷갈리는 것.** `dns.flags.rcode == 3`이 NXDOMAIN이라는 것을 매번 표로 확인하지 않으려면 `dns.flags.rcode != 0`으로 "실패 전체"부터 걸고 개별 코드는 나중에 좁힌다.
- **대소문자를 구분하는 `contains`로 못 찾는 것.** 도메인은 대소문자를 섞어 보낼 수 있다. 정확히 안 걸리면 `matches "(?i)..."`로 바꾼다.
- **질의만 세고 응답을 안 보는 것.** 질의 개수와 실제로 성공한 응답(`dns.flags.rcode == 0 && dns.count.answers > 0`) 개수가 다르면 그 차이 자체가 단서(서버 다운, 캐시 미스, 터널링 서버의 선택적 응답)다.

## mini example

```text
문제:
"이 캡처에서 접속한 외부 도메인과 그 도메인이 가리킨 IP를 구하세요."
첨부: browse.pcapng (2,204 packets)

1. 존재 확인
   필터: dns
   -> 88개 패킷. 질의 44 / 응답 44로 짝이 맞는다.

2. 질의만 추출해 빈도 확인
   $ tshark -r browse.pcapng -Y 'dns.flags.response == 0' \
       -T fields -e dns.qry.name | sort | uniq -c | sort -nr
      12 example-shop.com
       8 cdn.example-shop.com
       6 fonts.googleapis.com
       ...
       1 c2-relay.duckdns.org        <- 낯선 이름

3. 낯선 도메인만 좁혀서 응답 확인
   $ tshark -r browse.pcapng -Y 'dns.qry.name == "c2-relay.duckdns.org"' \
       -T fields -e dns.flags.response -e dns.a
      0
      1   198.51.100.230

4. 그 IP와의 실제 통신이 있었는지 확인
   필터: ip.addr == 198.51.100.230
   -> TCP 4444 포트로 세션 존재. 정상 CDN/폰트 도메인과는 확실히 다른 패턴.

정답: 도메인 c2-relay.duckdns.org / IP 198.51.100.230
```

3~4단계처럼 "빈도가 낮고 이름이 낯선 것"을 먼저 걸러낸 뒤 그 도메인의 응답 IP로 pivot하는 흐름이 DNS 필터의 기본 사용법이다.

## 출처

- SRC-002 — Wireshark Display Filter Reference: `dns.*` 필드 전체 목록(`dns.qry.name`, `dns.qry.type`, `dns.flags.response`, `dns.flags.rcode`, `dns.a`, `dns.aaaa`, `dns.cname`, `dns.txt`, `dns.count.answers`, `dns.id`, `dns.time`)
- SRC-065 — RFC 1035: DNS 메시지 구조, QTYPE 코드값(A=1, NS=2, CNAME=5, MX=15, TXT=16, AAAA는 RFC 3596에서 28), RCODE 정의(NOERROR=0, FORMERR=1, SERVFAIL=2, NXDOMAIN=3)
- SRC-010 — tshark man page: `-Y`, `-T fields`, `-e` 필드 추출 문법
