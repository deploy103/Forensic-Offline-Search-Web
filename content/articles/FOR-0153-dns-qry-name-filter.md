---
id: FOR-0153
title: "dns.qry.name 필터로 특정 도메인 질의 찾기"
slug: "dns-qry-name-filter"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "DNS query"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["DNS", "UDP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y 'dns.qry.name contains \"flag\"' -T fields -e frame.number -e ip.src -e dns.qry.name", "tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u", "tshark -r capture.pcapng -Y 'dns.qry.name.len > 30'"]
regex_patterns: []
wireshark_filters: ["dns.qry.name", "dns.qry.name == \"example.com\"", "dns.qry.name contains \"flag\"", "dns.qry.name matches \"(?i)admin\"", "dns.qry.name.len > 20", "dns.qry.name and dns.flags.response == 0"]
tshark_fields: ["dns.qry.name", "dns.qry.name.len", "dns.flags.response", "ip.src"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["dns.qry.name", "dns 쿼리 이름 필터"]
keywords: ["dns.qry.name", "dns 쿼리 이름 필터", "특정 도메인 찾기", "dns contains", "dns matches", "dns 질의 이름", "dns.qry.name.len", "도메인 검색 와이어샤크"]
aliases: ["dns 쿼리 이름 필터", "특정 도메인 dns 찾기", "dns.qry.name 사용법", "dns 이름으로 필터", "dns contains flag", "도메인 필터 와이어샤크"]
symptom_keywords: ["특정 도메인을 조회했는지 확인하고 싶다", "dns.qry.name 필터가 안 걸린다", "부분 일치로 도메인을 찾고 싶다", "긴 서브도메인만 찾고 싶다", "누가 그 도메인을 조회했는지 모르겠다"]
related: ["FOR-0152", "FOR-0154", "FOR-0155", "FOR-0150"]
source_ids: ["SRC-002", "SRC-065", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`dns.qry.name`은 DNS 질의에 담긴 도메인 이름 필드다. 정확한 이름을 알면 `==`, 일부만 알면 `contains`, 대소문자를 모르면 `matches "(?i)..."`로 좁히고, **누가(`ip.src`) 언제(`frame.time`) 그 이름을 물었는지**까지 뽑아야 문제가 완성된다.

## 어떤 문제에서 필요한가

- "이 캡처에서 `flag`가 포함된 도메인을 조회한 적이 있는지 확인하세요" 류의 지문
- 특정 C2 도메인 하나가 주어지고 그 도메인에 대한 통신 이력을 캡처에서 찾아야 할 때
- 어떤 내부 호스트가 그 도메인을 조회했는지(감염 호스트 특정)를 알아야 할 때
- 서브도메인이 유난히 길거나 이상한 문자로 구성된 질의를 찾아야 할 때(터널링/인코딩 데이터 후보)

## 문제에서 처음 볼 단서

1. **지문에 도메인 전체 또는 일부 문자열이 적혀 있다** — `example.com`처럼 완전한 형태거나 `flag`, `admin`처럼 조각만 주어질 수 있다.
2. **지문에 "누가 접속했는지"가 함께 묻힌다** — 이름만이 아니라 출발지 IP까지 필요하다는 신호다.
3. **서브도메인이 유난히 길게 캡처에 등장한다** — Base32/Base64로 인코딩된 데이터를 담은 터널링 질의일 수 있다 ([FOR-0155](./dns-tunneling.html)).
4. **대소문자가 섞여 있거나 지문에 명시되지 않았다** — `contains`가 대소문자를 구분한다는 점을 염두에 둔다.

## 30초 절차

```bash
tshark -r capture.pcapng -Y 'dns.qry.name contains "flag"' -T fields -e frame.number -e ip.src -e dns.qry.name
```

GUI는 필터창에 한 줄이면 끝난다.

```text
1. 필터창: dns.qry.name contains "flag"
2. 결과 행 클릭 -> Source(질의한 IP) 확인
3. 같은 dns.id의 응답 패킷으로 이동해 dns.a 확인
```

## 상세 절차

### 1단계 — 정확히 알 때: 완전 일치

지문에 도메인 전체가 주어지면 `==`를 쓴다. 가장 빠르고 오탐이 없다.

```text
dns.qry.name == "example.com"
```

FQDN의 끝에 점(`.`)이 붙어 캡처되는 경우가 있다(`example.com.`). `==`가 안 걸리면 `contains`로 바꿔 확인한다.

### 2단계 — 일부만 알 때: contains

```text
dns.qry.name contains "flag"
```

| 상황 | 결과 |
| --- | --- |
| `flag.example.com` | 걸림 |
| `FLAG.example.com` | **안 걸림** (대소문자 구분) |
| `example.com/flag` | 해당 없음 (도메인 이름 필드에는 경로가 없다) |

`contains`는 바이트 단위 부분 문자열 매칭이라 도메인의 어느 위치에 있어도(서브도메인, 2단계 도메인, TLD) 잡힌다.

### 3단계 — 대소문자를 모를 때: matches

```text
dns.qry.name matches "(?i)flag"
```

`matches`는 Wireshark 내장 정규식(PCRE 기반)을 쓰므로 `(?i)`로 대소문자 무시가 가능하다. 정규식 특수문자(`.`, `-` 등)가 포함된 도메인을 검색할 때는 이스케이프에 주의한다.

```text
dns.qry.name matches "(?i)c2\\-relay"
```

### 4단계 — 여러 후보를 한 번에: OR 결합

지문에 후보 도메인이 여러 개 나열되거나, 알려진 악성 도메인 목록과 대조해야 할 때는 `or`로 묶는다.

```text
dns.qry.name == "bad1.example.net" or dns.qry.name == "bad2.example.net" or dns.qry.name contains "duckdns.org"
```

목록이 길면 GUI보다 CLI가 편하다.

```bash
tshark -r capture.pcapng -Y 'dns.qry.name' -T fields -e dns.qry.name |
  grep -iFf known_bad_domains.txt
```

### 5단계 — 질의와 응답을 함께 걸기

`dns.qry.name`만 걸면 **질의와 응답 패킷이 모두** 걸린다(둘 다 이 필드를 갖고 있기 때문). 질의만 보고 싶으면 `dns.flags.response == 0`을 더한다.

```text
dns.qry.name contains "flag" and dns.flags.response == 0   -- 질의만
dns.qry.name contains "flag" and dns.flags.response == 1   -- 응답만 (dns.a 확인용)
```

### 6단계 — 누가 물었는지: ip.src와 함께 컬럼으로

값 하나만 보고 끝내지 않는다. 감염 호스트를 특정해야 하는 문제가 훨씬 많다.

```bash
tshark -r capture.pcapng -Y 'dns.qry.name contains "flag" and dns.flags.response == 0' \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

```text
Mar 14, 2026 07:22:11.204 UTC   10.0.0.31   flag-c2.duckdns.org
```

GUI에서는 `ip.src` 필드를 우클릭해 `Apply as Column`으로 추가해 두면 스크롤하면서 바로 보인다.

### 7단계 — 길이·패턴으로 이상 서브도메인 찾기

터널링이나 인코딩된 데이터를 담은 질의는 이름이 비정상적으로 길다. 특정 문자열을 모를 때는 길이로 좁힌다.

```text
dns.qry.name.len > 30
```

```bash
tshark -r capture.pcapng -Y 'dns.flags.response == 0' \
  -T fields -e dns.qry.name.len -e dns.qry.name | sort -rn | head -10
```

## 출력 필드 해석

```text
frame.number  ip.src        dns.qry.name
1841          10.0.0.31     flag-c2.duckdns.org
1842          10.0.0.31     flag-c2.duckdns.org
2210          10.0.0.44     cdn.flags-static.net
```

| 컬럼 | 해석 |
| --- | --- |
| `frame.number` | 같은 질의가 여러 번 나오면 재시도(응답 지연/실패)이거나 반복 접속 |
| `ip.src` | 질의 패킷에서는 **클라이언트**(질의자), 응답 패킷에서는 **DNS 서버** — 방향에 따라 의미가 뒤바뀐다 |
| `dns.qry.name` | 매칭된 전체 이름. 우연히 문자열이 겹친 다른 도메인(`cdn.flags-static.net`)이 섞였는지 반드시 눈으로 확인 |

`dns.flags.response == 0` 없이 `ip.src`만 보면, 응답 패킷의 `ip.src`는 DNS 서버 IP라서 **질의자를 서버로 착각**하는 실수가 생긴다.

## pivot: 다음에 볼 artifact

| dns.qry.name에서 얻은 것 | 다음에 할 일 |
| --- | --- |
| 질의한 도메인 이름 | 같은 `dns.id`의 응답에서 `dns.a`로 실제 IP 확인 ([FOR-0154](./dns-response-ip-tracking.html)) |
| 질의한 내부 호스트 IP | [FOR-0150](./endpoints.html)로 그 호스트의 전체 트래픽 확인 |
| 비정상적으로 긴 서브도메인 | [FOR-0155](./dns-tunneling.html)로 터널링 여부 판정 |
| 질의 시각 | EVTX 4688 프로세스 생성, 브라우저 History의 같은 시각 대조 |
| 반복된 동일 질의 | 주기 계산 → 비콘 여부 판단 |

## 흔한 함정

- **`contains`가 대소문자를 구분한다는 것을 잊는 것.** `FLAG.example.com`은 `contains "flag"`에 걸리지 않는다. 확신이 없으면 `matches "(?i)..."`를 쓴다.
- **질의와 응답을 구분하지 않고 `ip.src`를 읽는 것.** 응답 패킷의 `ip.src`는 DNS 서버다. 질의자를 찾으려면 반드시 `dns.flags.response == 0`을 같이 건다.
- **`==`로 완전 일치를 시도했는데 끝에 점(`.`)이 붙어 안 걸리는 것.** `example.com.`처럼 FQDN 표기가 캡처될 수 있다. 안 걸리면 `contains`로 전환한다.
- **도메인에 포함된 정규식 특수문자를 이스케이프하지 않는 것.** `c2-relay.duckdns.org`에서 `-`나 `.`은 `matches`에서 특별한 의미를 가지지 않지만, `+`, `*` 등이 포함된 이름을 `matches`로 검색할 때는 이스케이프가 필요하다.
- **`dns.qry.name`이 없는 응답도 있다는 것을 놓치는 것.** 일부 malformed 응답이나 비표준 레코드는 이 필드가 비어 있을 수 있다. 그런 패킷은 [FOR-0151](./expert-information.html)로 먼저 이상 여부를 확인한다.
- **부분 문자열이 우연히 다른 도메인과 겹치는 것을 못 보는 것.** `contains "flag"`가 `flags-static.net`처럼 무관한 정상 도메인도 잡을 수 있다. 결과를 눈으로 한 번 훑는다.
- **캐시된 재질의를 실제 접속 횟수로 세는 것.** 같은 이름이 짧은 간격으로 반복되는 것은 DNS 캐시 만료·재시도 때문일 수 있다. `frame.time` 간격을 봐야 실제 이벤트 횟수를 안다.

## 교차검증

```bash
# 1) 필터 결과와 전체 고유 이름 목록 대조
tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u

# 2) 이름 + 질의자 + 응답 IP를 한 번에 (dns.id로 짝짓기는 tshark가 자동 처리하지 않으므로 응답만 별도 추출)
tshark -r capture.pcapng -Y 'dns.qry.name contains "flag" and dns.flags.response == 1' \
  -T fields -e dns.qry.name -e dns.a

# 3) grep으로 우회 확인 (파서를 거치지 않는 최후 수단)
tshark -r capture.pcapng -Y dns -T fields -e dns.qry.name | grep -i flag

# 4) 길이 기준 이상 탐지와 문자열 기준 결과 비교
tshark -r capture.pcapng -Y 'dns.qry.name.len > 30' -T fields -e dns.qry.name
```

`(1)`과 필터 결과를 비교하면 우연히 겹친 도메인이 섞였는지 바로 확인된다. `(3)`은 Wireshark 필터 문법 실수를 배제하는 용도다.

## mini walkthrough

```text
문제:
"악성코드가 감염 직후 조회한 C2 도메인과 감염된 내부 호스트의
 IP를 구하세요. 힌트: 도메인에 'c2'가 들어간다."
첨부: infect.pcapng (6,204 packets)

1. 첫 시도 (실패)
   필터: dns.qry.name contains "c2"
   -> 결과가 0건.
   원인: 실제 도메인은 대문자가 섞인 "C2-Relay.duckdns.org" 로
        캡처되어 있었다. contains 는 대소문자를 구분한다.

2. 접근 변경 — 대소문자 무시
   필터: dns.qry.name matches "(?i)c2"
   -> 3개 패킷.

     frame.number  dns.qry.name
     4021          C2-Relay.duckdns.org   (질의)
     4022          C2-Relay.duckdns.org   (응답)
     4023          C2-Relay.duckdns.org   (재시도 질의)

3. 질의자 확인 (질의 패킷만)
   필터: dns.qry.name matches "(?i)c2" and dns.flags.response == 0
   Source 컬럼: 10.0.0.57

4. 응답 IP 확인
   필터: dns.qry.name matches "(?i)c2" and dns.flags.response == 1
   -T fields -e dns.a
   -> 198.51.100.230

5. 교차검증 — 그 IP와 10.0.0.57 사이에 실제 통신이 있는지
   필터: ip.addr == 10.0.0.57 && ip.addr == 198.51.100.230
   -> TCP 4444로 세션 존재. DNS 응답과 실제 접속이 일치한다.

정답: 도메인 C2-Relay.duckdns.org / 감염 호스트 10.0.0.57
```

1단계의 실패가 핵심이다. **`contains`의 대소문자 구분을 잊으면 결과가 통째로 0건이 되어 "그 도메인이 없다"고 오판하기 쉽다.** 결과가 0건이면 먼저 `matches "(?i)..."`로 바꿔 재확인한다.

## 막혔을 때 다음 체크

1. `contains` 결과가 0건인가 → `matches "(?i)..."`로 대소문자 무시 재시도
2. `==`가 안 걸리는가 → 끝에 점(`.`)이 붙었을 수 있다, `contains`로 전환
3. 결과에 `ip.src`가 이상한가 → `dns.flags.response`로 질의/응답을 구분했는가
4. 결과가 너무 많은가 → 부분 문자열이 무관한 도메인과 겹쳤는지 눈으로 확인
5. 도메인은 찾았는데 IP가 안 보이는가 → 응답 패킷(`dns.flags.response == 1`)에서 `dns.a`/`dns.aaaa` 확인
6. 서브도메인이 비정상적으로 긴가 → `dns.qry.name.len`으로 정렬해 터널링 의심 목록 뽑기 ([FOR-0155](./dns-tunneling.html))
7. 캡처에 DNS 자체가 없는가 → `dns` 필터로 존재부터 재확인 ([FOR-0152](./dns-basic-filters.html))
8. 반복 질의의 실제 발생 횟수가 필요한가 → `frame.time` 간격을 계산했는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `dns.qry.name`, `dns.qry.name.len`, `contains`/`matches` 연산자 문법
- SRC-065 — RFC 1035: DNS 질의 이름(QNAME)의 인코딩과 FQDN 표기(끝 점 포함 가능)
- SRC-010 — tshark man page: `-Y`, `-T fields`, `-e` 옵션
