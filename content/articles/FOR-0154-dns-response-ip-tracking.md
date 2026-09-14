---
id: FOR-0154
title: "DNS 응답에서 실제 접속 IP 추적하기"
slug: "dns-response-ip-tracking"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "DNS response"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["DNS", "UDP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y 'dns.flags.response == 1' -T fields -e dns.qry.name -e dns.a -e dns.cname", "tshark -r capture.pcapng -Y 'dns.a == 198.51.100.230'", "tshark -r capture.pcapng -Y 'ip.addr == 198.51.100.230 && !dns'"]
regex_patterns: []
wireshark_filters: ["dns.flags.response == 1", "dns.a", "dns.a == 198.51.100.230", "dns.cname", "dns.resp.name", "dns.count.answers > 1", "ip.addr == 198.51.100.230 && !dns"]
tshark_fields: ["dns.qry.name", "dns.a", "dns.aaaa", "dns.cname", "dns.resp.name", "dns.resp.ttl", "dns.count.answers", "ip.addr"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["dns.a", "dns 응답 ip 추적"]
keywords: ["dns.a", "dns 응답 ip 추적", "도메인 실제 접속 ip", "dns cname 체인", "dns 응답 매핑", "도메인 ip 매핑", "dns resp ttl", "cdn ip 여러개"]
aliases: ["dns 응답 ip 추적", "도메인이 가리킨 ip 찾기", "dns.a 사용법", "cname 체인 따라가기", "도메인 ip 매핑 찾기", "dns로 접속 ip 찾기"]
symptom_keywords: ["도메인은 아는데 실제 ip를 모르겠다", "dns 응답에 ip가 여러 개다", "cname만 있고 a레코드가 안 보인다", "dns 응답과 실제 접속 ip가 다른 것 같다", "그 도메인으로 실제 통신했는지 확인하고 싶다"]
related: ["FOR-0152", "FOR-0153", "FOR-0150", "FOR-0149"]
source_ids: ["SRC-002", "SRC-065", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

도메인이 가리키는 실제 IP는 **응답 패킷의 `dns.a`/`dns.aaaa` 필드**에 있다. CNAME 체인이 끼면 여러 Answer 레코드를 순서대로 따라가야 하고, 그 IP를 알아낸 뒤에는 반드시 **같은 IP로의 실제 TCP/UDP 세션이 캡처에 존재하는지**까지 확인해야 "접속했다"고 결론 낼 수 있다.

## 어떤 문제에서 필요한가

- "이 도메인이 실제로 가리킨 IP를 구하세요" 류의 지문
- DNS 질의는 있는데 그 뒤로 실제 접속이 이루어졌는지(캐시된 조회 vs 실접속) 확인해야 할 때
- CDN이나 로드밸런서를 쓰는 도메인이라 응답 IP가 여러 개일 때 실제로 접속한 IP 하나를 특정해야 할 때
- CNAME으로 여러 단계 우회된 도메인의 최종 IP를 추적해야 할 때
- DNS 응답이 위조(스푸핑)되었는지 의심되는 문제

## 문제에서 처음 볼 단서

1. **지문에 도메인만 주어지고 IP를 물어본다** — DNS 응답을 먼저 찾아야 한다는 신호다.
2. **캡처에 같은 도메인에 대한 응답이 여러 개, IP가 다르다** — CDN/로드밸런서 또는 DNS 라운드로빈.
3. **질의는 있는데 그 이후 해당 IP로의 세션이 안 보인다** — 캐시된 조회이거나 접속이 차단됨.
4. **응답에 A 레코드가 없고 CNAME만 있다** — 체인을 한 단계 더 따라가야 한다.
5. **같은 질의에 응답이 두 번, IP가 서로 다르다** — DNS 스푸핑/캐시 포이즈닝 의심.

## 30초 절차

```bash
tshark -r capture.pcapng -Y 'dns.flags.response == 1' -T fields -e dns.qry.name -e dns.a -e dns.cname
```

GUI는 세 단계다.

```text
1. 필터: dns.qry.name == "example.com" and dns.flags.response == 1
2. 결과 패킷 펼치기 -> Answers 섹션에서 A/CNAME 레코드 확인
3. 얻은 IP로 필터: ip.addr == <IP> -> 실제 세션 존재 여부 확인
```

## 상세 절차

### 1단계 — 응답 패킷으로 좁히기

`dns.qry.name`은 질의와 응답 모두에 있지만, 실제 IP를 담은 `dns.a`/`dns.aaaa`는 **응답 패킷에만** 있다. 먼저 응답만 남긴다.

```text
dns.qry.name == "example.com" and dns.flags.response == 1
```

이름을 모르고 이미 얻은 서브도메인만 있다면 [FOR-0153](./dns-qry-name-filter.html)의 `contains`/`matches`로 먼저 좁힌 뒤 여기에 `and dns.flags.response == 1`을 추가한다.

### 2단계 — Answers 섹션 펼쳐 읽기

패킷 상세 창에서 `Domain Name System (response)` → `Answers` 를 펼친다.

```text
Answers
  example.com: type A, class IN, addr 203.0.113.10
  example.com: type A, class IN, addr 203.0.113.11
```

Answer가 여러 개면 **같은 이름에 IP가 여러 개 응답된 것**이다(로드밸런싱/CDN). 어느 것이 실제로 쓰였는지는 3단계에서 확인한다.

컬럼으로 뽑으면 한 줄에 여러 값이 온다.

```bash
tshark -r capture.pcapng -Y 'dns.qry.name == "example.com" and dns.flags.response == 1' \
  -T fields -e dns.a
```

```text
203.0.113.10,203.0.113.11
```

tshark는 같은 필드가 여러 번 나오면 기본적으로 쉼표로 이어붙인다.

### 3단계 — CNAME 체인 따라가기

응답에 A 레코드 없이 CNAME만 있으면 체인이다.

```text
Answers
  cdn.example.com: type CNAME, class IN, cname edge-1.cdnvendor.net
  edge-1.cdnvendor.net: type A, class IN, addr 203.0.113.55
```

같은 응답 패킷 안에 전체 체인이 다 들어있는 경우가 많으므로, `dns.cname`과 `dns.a`를 함께 뽑으면 한 번에 확인된다.

```bash
tshark -r capture.pcapng -Y 'dns.qry.name == "cdn.example.com" and dns.flags.response == 1' \
  -T fields -e dns.qry.name -e dns.cname -e dns.a
```

```text
cdn.example.com    edge-1.cdnvendor.net    203.0.113.55
```

체인이 여러 응답 패킷에 걸쳐 나뉘어 있으면(드묾) `dns.id`가 같은 패킷들을 순서대로 이어서 읽는다.

### 4단계 — 여러 IP 중 실제로 쓰인 것 특정하기

응답에 IP가 여러 개 있어도 클라이언트가 실제로 접속한 것은 보통 하나(또는 순서대로 재시도)다. 응답으로 얻은 각 IP에 대해 실제 세션 유무를 확인한다.

```bash
for ip in 203.0.113.10 203.0.113.11; do
  echo "== $ip =="
  tshark -r capture.pcapng -Y "ip.addr == $ip && !dns" | wc -l
done
```

```text
== 203.0.113.10 ==
0
== 203.0.113.11 ==
214
```

DNS가 아닌(`!dns`) 패킷이 존재하는 쪽(`203.0.113.11`)이 실제로 접속한 IP다.

### 5단계 — DNS 응답과 실제 목적지 IP가 다른 경우

`http.host`나 TLS SNI에 담긴 도메인과 그 세션의 목적지 IP가 이 단계에서 찾은 `dns.a`와 일치하는지 대조한다. **불일치하면 다음 중 하나다.**

| 불일치 상황 | 가능한 원인 |
| --- | --- |
| DNS 응답 IP와 실제 접속 IP가 다름 | DNS 캐시(다른 시점 조회 사용), `hosts` 파일 우회, DNS 스푸핑 |
| 같은 이름에 응답이 두 번, IP가 다름 | DNS 캐시 포이즈닝/스푸핑 의심 — `dns.id`와 응답 시각을 비교 |
| 응답 자체가 없는데 그 IP로 접속함 | 캡처 시작 전에 조회됨(캡처 범위 밖), 또는 `hosts` 파일 하드코딩 |

### 6단계 — TTL로 캐시 여부 추정

응답에는 `dns.resp.ttl`(레코드 유효 시간, 초)이 있다. 값이 아주 작으면(수 초~수십 초) 이 조회가 최근에 새로 이루어졌을 가능성이 높고, 값이 크고(수 시간) 캡처 내내 재조회가 없다면 클라이언트가 로컬 캐시를 계속 썼다고 볼 수 있다.

```bash
tshark -r capture.pcapng -Y 'dns.qry.name == "example.com" and dns.flags.response == 1' \
  -T fields -e dns.resp.ttl -e dns.a
```

## 출력 필드 해석

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| `dns.a` | 응답에 담긴 IPv4 주소(들) | 여러 개면 로드밸런싱/CDN. 실제 접속 IP는 별도 확인 필요 |
| `dns.aaaa` | 응답에 담긴 IPv6 주소 | IPv4/IPv6 이중 스택 환경에서는 둘 다 응답될 수 있다 |
| `dns.cname` | 별칭이 가리키는 다음 이름 | 체인의 중간 단계. 최종 IP가 아니다 |
| `dns.resp.name` | 이 Answer 레코드가 응답하는 이름 | CNAME 체인에서 각 단계의 이름 확인용 |
| `dns.resp.ttl` | 레코드 캐시 유효시간(초) | 캐시 재사용 여부 추정에 사용, 절대적 증거는 아니다 |
| `dns.count.answers` | Answer 레코드 개수 | 1보다 크면 체인 또는 다중 IP 응답 |

## pivot: 다음에 볼 artifact

| DNS 응답에서 얻은 것 | 다음에 할 일 |
| --- | --- |
| 실제 접속에 쓰인 IP | `ip.addr == <IP>`로 [FOR-0149](./conversations.html) 열어 세션 상세 확인 |
| 여러 응답 IP 중 미사용 IP | 정상 CDN 대역인지 대조. 다른 목적이면 별도 조사 |
| CNAME 체인의 벤더 도메인 | 그 벤더가 알려진 C2 호스팅/다이나믹 DNS(duckdns 등)인지 확인 |
| DNS 응답과 실제 접속 IP 불일치 | `hosts` 파일, 브라우저 DNS 캐시, ARP 스푸핑 여부 조사 |
| 짧은 TTL의 반복 조회 | [FOR-0155](./dns-tunneling.html)로 비콘/터널링 여부 재확인 |
| 응답 IP 전체 목록 | [FOR-0150](./endpoints.html)로 그 IP들의 총 트래픽 비교 |

## 흔한 함정

- **질의 패킷에서 `dns.a`를 찾는 것.** `dns.a`는 응답 패킷에만 존재한다. 반드시 `dns.flags.response == 1`을 함께 건다.
- **여러 IP 중 첫 번째를 무조건 "그 IP"로 답하는 것.** CDN/로드밸런서는 IP를 여러 개 응답한다. 실제 세션이 존재하는 IP인지 `ip.addr == <IP> && !dns`로 확인한다.
- **CNAME만 보고 그 이름을 최종 답으로 제출하는 것.** CNAME은 별칭이지 IP가 아니다. 체인을 끝까지 따라가 A/AAAA 레코드를 찾는다.
- **DNS 응답 IP와 실제 목적지 IP가 항상 같다고 가정하는 것.** `hosts` 파일 우회, 캐시, 스푸핑으로 다를 수 있다. 문제가 "실제 접속 IP"를 요구하면 반드시 세션 데이터로 재확인한다.
- **TTL을 절대적인 캐시 증거로 쓰는 것.** TTL은 서버가 권고하는 값일 뿐, 클라이언트/리졸버가 실제로 그만큼 캐시했다는 보장은 없다. 보조 지표로만 쓴다.
- **응답이 두 번 이상 다른 IP로 온 것을 정상 재시도로 넘기는 것.** 같은 `dns.id`, 같은 이름에 짧은 시간 간격으로 다른 IP가 응답되면 스푸핑 가능성을 반드시 검토한다.
- **AAAA(IPv6) 응답을 놓치는 것.** `dns.a`만 확인하고 IPv6로 실제 접속이 이루어진 경우를 놓친다. 실제 세션에 IPv4 흔적이 없으면 `dns.aaaa`와 IPv6 세션을 함께 본다.
- **응답 자체가 캡처 밖에서 이루어진 경우를 놓치는 것.** 캡처 시작 이전에 조회되고 캐시된 상태로 세션만 캡처에 포함되면 DNS 응답 패킷 자체가 없다. 이 경우 `hosts`/캐시 데이터가 별도로 필요하다.

## 교차검증

```bash
# 1) 응답 전체를 한 표로 (이름/CNAME/A/TTL)
tshark -r capture.pcapng -Y 'dns.flags.response == 1' \
  -T fields -e dns.qry.name -e dns.cname -e dns.a -e dns.resp.ttl

# 2) 특정 IP가 어느 도메인의 응답이었는지 역방향 확인
tshark -r capture.pcapng -Y 'dns.a == 198.51.100.230'

# 3) 그 IP로의 실제 통신이 있었는지 (DNS 패킷 제외)
tshark -r capture.pcapng -Y 'ip.addr == 198.51.100.230 && !dns'

# 4) 같은 이름에 대한 응답이 여러 번, IP가 다른지 확인 (스푸핑 의심)
tshark -r capture.pcapng -Y 'dns.qry.name == "example.com" and dns.flags.response == 1' \
  -T fields -e frame.time -e ip.src -e dns.a

# 5) HTTP Host/TLS SNI와 DNS 응답 도메인이 일치하는지 대조
tshark -r capture.pcapng -Y 'http.host or tls.handshake.extensions_server_name' \
  -T fields -e ip.dst -e http.host -e tls.handshake.extensions_server_name
```

`(4)`에서 `ip.src`(응답한 DNS 서버)가 바뀌거나 짧은 시간 내 IP가 달라지면 스푸핑을 의심한다. `(5)`는 DNS로 얻은 이름과 실제 세션에서 쓰인 이름이 같은지 최종 대조하는 단계다.

## mini walkthrough

```text
문제:
"악성코드가 조회한 도메인 update-service.example-cdn.net이
 실제로 가리킨 IP와, 그 IP로 실제 접속이 이루어졌는지 확인하세요."
첨부: cdn.pcapng (8,904 packets)

1. 첫 시도 (실패)
   필터: dns.qry.name == "update-service.example-cdn.net"
   -> 4개 패킷(질의 2, 응답 2). Answers를 펼쳐 첫 번째 IP
      203.0.113.40 을 그대로 답으로 제출했다.

2. 검토 요청으로 재확인 — 응답만 다시 본다
   필터: dns.qry.name == "update-service.example-cdn.net" and dns.flags.response == 1
   -T fields -e dns.a
     203.0.113.40,203.0.113.41
   -> 응답에 IP가 2개였다. 1단계는 그중 하나만 우연히 맞춘 것이었다.

3. 두 IP 각각 실제 세션이 있는지 확인
   $ tshark -r cdn.pcapng -Y 'ip.addr == 203.0.113.40 && !dns' | wc -l
   0
   $ tshark -r cdn.pcapng -Y 'ip.addr == 203.0.113.41 && !dns' | wc -l
   187

   -> 203.0.113.41 로만 실제 TCP 세션(187 패킷)이 있다.
      203.0.113.40 은 응답만 되고 쓰이지 않았다.

4. 그 세션 상세 확인
   필터: ip.addr == 203.0.113.41
   Statistics > Conversations, TCP 탭
     10.0.0.62:51900 <-> 203.0.113.41:443   187 packets   214,880 bytes

5. TLS SNI로 재확인 (도메인 이름이 실제로 이 세션에서도 쓰였는가)
   필터: tcp.stream eq (해당 스트림) && tls.handshake.type == 1
   -T fields -e tls.handshake.extensions_server_name
     update-service.example-cdn.net
   -> DNS로 조회한 이름과 실제 세션의 SNI가 일치. 확정.

정답: 실제 접속 IP = 203.0.113.41 (203.0.113.40 은 응답만 되고 미사용) /
      해당 IP로 실제 TLS 세션(443, 187 패킷) 존재 확인됨
```

1단계의 실패가 핵심이다. **응답 IP가 여러 개일 때 그중 하나만 보고 답하면 절반의 확률로 틀린다.** 반드시 실제 세션 유무로 검증해야 한다.

## 막혔을 때 다음 체크

1. `dns.flags.response == 1`을 걸었는가 — 질의 패킷에는 `dns.a`가 없다
2. Answer가 여러 개인가 — 각 IP에 대해 실제 세션이 있는지 개별 확인했는가
3. CNAME만 있고 A 레코드가 안 보이는가 — 체인을 끝까지 따라갔는가
4. 얻은 IP로 `ip.addr == <IP> && !dns` 결과가 0인가 — 그 IP는 미사용 후보다
5. DNS 응답 IP와 실제 세션의 목적지 IP가 다른가 — `hosts`/스푸핑/캐시를 의심했는가
6. TLS SNI나 `http.host`로 도메인-IP 매핑을 교차 확인했는가
7. 같은 질의에 응답이 여러 번, IP가 다른가 — 스푸핑 가능성을 검토했는가
8. IPv6(`dns.aaaa`)로 실제 접속이 이루어진 것은 아닌가
9. 캡처 범위 밖에서 조회되어 응답 패킷 자체가 없는 것은 아닌가
10. 이름 자체가 불확실하면 [FOR-0153](./dns-qry-name-filter.html)으로 먼저 정확히 특정했는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `dns.a`, `dns.aaaa`, `dns.cname`, `dns.resp.name`, `dns.resp.ttl`, `dns.count.answers` 필드
- SRC-065 — RFC 1035: Answer 섹션 구조, CNAME 처리 규칙(리졸버가 체인을 따라간다는 점), TTL의 정의
- SRC-010 — tshark man page: `-T fields`에서 반복 필드가 쉼표로 결합되는 기본 동작(`-E occurrence`로 변경 가능), `-Y`, `-e`
