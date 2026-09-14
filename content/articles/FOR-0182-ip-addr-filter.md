---
id: FOR-0182
title: "ip.addr 필터로 특정 IP 트래픽만 골라내기"
slug: "ip-addr-filter"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["IP", "IPv4", "IPv6", "TCP", "UDP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y 'ip.addr == 10.0.0.5' -c 5", "tshark -r capture.pcapng -Y 'ip.addr==10.0.0.5 && ip.addr==203.0.113.77'", "tshark -r capture.pcapng -Y 'ip.addr == 10.0.0.0/24'"]
regex_patterns: []
wireshark_filters: ["ip.addr == 10.0.0.5", "ip.src == 10.0.0.5", "ip.dst == 10.0.0.5", "ip.addr == 10.0.0.5 && ip.addr == 203.0.113.77", "ip.addr == 10.0.0.0/24", "ip.addr in {10.0.0.5, 10.0.0.6}", "!(ip.addr == 10.0.0.5)", "ipv6.addr == fe80::1"]
tshark_fields: ["ip.addr", "ip.src", "ip.dst", "ipv6.addr", "ip.src_host", "ip.dst_host"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["ip.addr", "ip 주소 필터"]
keywords: ["ip.addr", "ip.src", "ip.dst", "ip 필터", "특정 ip 트래픽", "conversation 필터", "CIDR 필터", "ipv6.addr", "host 필터", "wireshark ip 검색", "ip 주소로 좁히기"]
aliases: ["ip 주소로 필터링", "특정 ip만 보기", "ip.addr 안됨", "아이피 필터", "두 ip 사이 트래픽", "ip 주소 검색"]
symptom_keywords: ["특정 ip의 트래픽만 보고 싶다", "ip.addr != 가 이상하게 동작한다", "ipv6 주소가 필터에 안 걸린다", "두 ip 사이 대화만 보고 싶다", "host 필터가 display filter에서 안 먹는다"]
related: ["FOR-0183", "FOR-0147", "FOR-0149", "FOR-0146"]
source_ids: ["SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`ip.addr == x`는 그 IP가 **출발지든 목적지든 상관없이** 걸리는 양방향 필터다. 한쪽 방향만 보려면 `ip.src`/`ip.dst`를, 두 IP 사이의 대화만 보려면 `ip.addr==A && ip.addr==B`를 쓴다.

## 어떤 문제에서 필요한가

- 공격자 IP나 피해자 IP를 지문/로그에서 알아낸 뒤 그 IP가 관련된 패킷만 걸러야 할 때
- 수만 개 패킷 중 특정 두 호스트 사이의 대화만 봐야 할 때
- 서브넷 전체(예: 내부망 10.0.0.0/24) 트래픽을 한 번에 제외하거나 남길 때
- IPv6 환경에서 필터가 안 먹혀 원인을 못 찾을 때

## 문제에서 처음 볼 단서

1. 지문이나 다른 로그(EVTX 4624의 `IpAddress`, access.log의 클라이언트 IP)에서 확보한 IP 하나
2. `Statistics > Endpoints`에서 외부 IP가 하나뿐이면 그것이 공격자/서버일 확률이 높다
3. IP가 `fe80::` `2001:` 같은 콜론 표기 → IPv4용 `ip.addr`가 아니라 `ipv6.addr`가 필요한 신호
4. "두 사람 사이의 대화만"이라는 지문 → `ip.addr==A && ip.addr==B` 패턴이 필요하다는 신호

## 30초 절차

```bash
tshark -r capture.pcapng -Y 'ip.addr == 10.0.0.5' -c 10
```

이 IP가 나온 패킷 수를 먼저 확인한다. 너무 많으면 `&& ip.addr==<상대IP>`로 대화를 좁힌다. 너무 적거나 0이면 IPv4/IPv6를 헷갈렸는지, 오타인지 확인한다.

## 상세 절차

### 1단계 — `ip.addr`은 두 필드를 동시에 검사한다

패킷 하나의 IP 헤더에는 `ip.src`와 `ip.dst`가 각각 하나씩 있다. `ip.addr`은 **이 둘을 합쳐 부르는 이름**이며, `ip.addr == x`는 사실상 `ip.src == x || ip.dst == x`와 같다.

| 필터 | 의미 |
| --- | --- |
| `ip.addr == 10.0.0.5` | 10.0.0.5가 출발지이거나 목적지인 모든 패킷 |
| `ip.src == 10.0.0.5` | 10.0.0.5가 **출발지인** 패킷만 (나가는 트래픽) |
| `ip.dst == 10.0.0.5` | 10.0.0.5가 **목적지인** 패킷만 (들어오는 트래픽) |

방향을 구분해야 하는 대표 상황: "10.0.0.5가 보낸 데이터양"과 "10.0.0.5가 받은 데이터양"을 따로 봐야 할 때, 또는 스캔 탐지에서 "누가 먼저 SYN을 보냈는가"를 확정할 때.

### 2단계 — 두 IP 사이의 대화만 보기

```text
ip.addr == 10.0.0.5 && ip.addr == 203.0.113.77
```

`&&`(AND)인데도 "두 IP 사이의 대화"가 되는 이유는 `ip.addr`이 한 패킷 안에서 **두 값(src, dst)을 갖는 필드**이기 때문이다. 왼쪽 조건은 그 중 하나가 10.0.0.5인지, 오른쪽 조건은 다른 하나(또는 같은 값)가 203.0.113.77인지를 각각 독립적으로 검사하므로, 두 조건이 동시에 참이려면 src/dst 자리에 두 IP가 각각 들어 있어야 한다.

```text
ip.addr == 10.0.0.5 || ip.addr == 203.0.113.77
```

이건 완전히 다른 필터다. **둘 중 하나라도 나오면** 걸리므로, 10.0.0.5가 다른 제3의 서버와 통신한 패킷까지 전부 포함된다. "두 호스트 사이"를 원하면 반드시 `&&`다.

### 3단계 — 서브넷/CIDR

```text
ip.addr == 10.0.0.0/24
ip.addr != 10.0.0.0/24
```

CIDR 표기를 슬래시 없이 공백을 넣으면(`10.0.0.0 /24`) 문법 오류가 난다. **슬래시는 IP 바로 뒤에 붙인다.**

내부망을 통째로 빼고 외부만 보고 싶을 때 흔히 쓰는 조합:

```text
!(ip.addr == 10.0.0.0/8 || ip.addr == 192.168.0.0/16 || ip.addr == 172.16.0.0/12)
```

사설 IP 대역(RFC 1918) 세 개를 한 번에 제외하는 관용구다.

### 4단계 — 목록(`in`)과 부정

```text
ip.addr in {10.0.0.5, 10.0.0.6, 203.0.113.77}
!(ip.addr == 10.0.0.5)
```

여러 IP를 OR로 나열하는 대신 `in {...}`을 쓰면 가독성이 좋다. **부정은 `!=`가 아니라 `!(...)`로 감싸는 것을 기본값으로 삼는다** — 이유는 5단계.

### 5단계 — `!=`의 함정과 버전 차이

`ip.addr`처럼 한 패킷에 값이 여러 개(src, dst) 있는 필드에서 `!=`의 의미는 Wireshark 버전에 따라 달랐다.

| 버전 | `ip.addr != x`의 실제 의미 |
| --- | --- |
| 3.6 이전 | `any_ne` — src/dst 중 **하나라도** x와 다르면 참. 사실상 거의 모든 패킷이 걸린다(이 IP가 관련된 패킷도 포함되는 유명한 함정) |
| 3.6 이후 | `all_ne` — src와 dst **모두** x와 달라야 참. "이 IP가 전혀 안 나온 패킷"이라는 직관과 일치 |

버전을 확신할 수 없는 대회장에서는 처음부터 의미가 명확한 형태를 쓴다.

```text
!(ip.addr == 10.0.0.5)
```

이 표현은 버전에 관계없이 "10.0.0.5가 src에도 dst에도 없는 패킷"을 정확히 의미한다.

### 6단계 — IPv4와 IPv6는 다른 필드

`ip.addr`은 **IPv4 전용**이다. IPv6 주소는 `ipv6.addr`을 쓴다.

| 프로토콜 | 필드 |
| --- | --- |
| IPv4 | `ip.addr`, `ip.src`, `ip.dst` |
| IPv6 | `ipv6.addr`, `ipv6.src`, `ipv6.dst` |

```text
ipv6.addr == fe80::1
ipv6.addr == 2001:db8::/32
```

혼합 환경(듀얼스택)에서 IPv4/IPv6를 한 필터로 같이 보고 싶으면 `||`로 연결한다.

```text
ip.addr == 10.0.0.5 || ipv6.addr == fe80::1
```

### 7단계 — 캡처 필터(BPF)와 혼동하지 않는다

이미 저장된 pcap을 열 때 화면 상단 필터 입력창은 **디스플레이 필터**다. BPF 문법인 `host`를 그대로 쓰면 오류가 난다.

| 상황 | 문법 | 예시 |
| --- | --- | --- |
| 캡처 필터 (`-f`, 라이브 캡처 전용) | BPF | `host 10.0.0.5`, `net 10.0.0.0/24` |
| 디스플레이 필터 (`-Y`, 저장 파일 분석) | 디스플레이 필터 | `ip.addr == 10.0.0.5` |

저장 파일에는 `-f`가 아예 적용되지 않는다는 점은 [FOR-0147](./capture-vs-display-filter.html)에서 자세히 다룬다.

### 8단계 — tshark로 필드 추출까지

```bash
tshark -r capture.pcapng -n -Y 'ip.addr == 10.0.0.5' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream -E header=y
```

```powershell
tshark -r capture.pcapng -n -Y 'ip.addr == 10.0.0.5' `
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream -E header=y
```

```text
frame.number  frame.time_epoch    ip.src        ip.dst        tcp.stream
842           1773645302.418221   10.0.0.5      203.0.113.77  4
845           1773645302.601884   203.0.113.77  10.0.0.5      4
```

`1773645302` → UTC `2026-03-16 09:55:02` → KST `2026-03-16 18:55:02`. 다른 artifact(EVTX, access.log)와 시각을 맞출 때는 UTC 기준으로 먼저 정렬하고 KST는 +9시간으로 병기한다.

## 출력 필드 해석

| 컬럼 | 의미 | 함정 |
| --- | --- | --- |
| `ip.src` / `ip.dst` | 그 패킷의 실제 방향 | `ip.addr`로 걸렀어도 각 패킷의 방향은 다시 `ip.src`/`ip.dst`로 확인해야 한다 |
| `tcp.stream` | 그 대화의 스트림 번호 | `ip.addr==A && ip.addr==B`로 걸러도 스트림이 여러 개일 수 있다(포트가 다르면 별개 스트림) |
| Source/Destination 컬럼(GUI) | 이름 변환이 켜져 있으면 도메인/호스트명으로 표시 | `View > Name Resolution` 해제 또는 `-n` 옵션으로 순수 IP 확인 |

## pivot: 다음에 볼 artifact

| ip.addr로 확정한 것 | 다음 목표 |
| --- | --- |
| 관심 IP 사이의 `tcp.stream` 번호 | Follow TCP Stream ([FOR-0162](./follow-tcp-stream.html)) |
| 그 IP가 쓴 포트 | [FOR-0183](./port-filters.html)로 포트 기준 추가 필터링 |
| 그 IP의 전체 대화량 | Conversations/Endpoints ([FOR-0149](./conversations.html)) |
| 그 IP가 관련된 시각 | EVTX 4624/4625의 `IpAddress` 필드와 대조 ([FOR-0083](./event-4624-logon.html)) |
| 그 IP가 다운로드한 파일 | Export Objects, `http.host`/`http.request.uri` |

## 흔한 함정

- **`host 10.0.0.5`를 디스플레이 필터 창에 그대로 입력.** BPF 문법이라 저장 파일 분석 화면에서는 문법 오류다. `ip.addr == 10.0.0.5`로 바꾼다.
- **`ip.addr == A || ip.addr == B`를 "두 IP 사이의 대화"로 착각.** OR은 둘 중 하나만 나오면 걸리므로 A가 제3자와 통신한 것까지 포함된다. "사이의 대화"는 반드시 `&&`.
- **CIDR 표기에 공백을 넣음.** `10.0.0.0 /24`는 오류다. `10.0.0.0/24`처럼 붙여 쓴다.
- **`ip.addr != x`가 그 IP를 완전히 제외한다고 가정.** 3.6 이전 버전에서는 오히려 대부분의 패킷이 걸리는 함정이 있었다. `!(ip.addr == x)`로 쓰면 버전과 무관하게 의도한 대로 동작한다.
- **IPv6 주소에 `ip.addr`을 사용.** `ip.addr`은 IPv4 전용이라 IPv6에는 0줄이 나온다. `ipv6.addr`을 쓴다.
- **이름 변환이 켜진 채로 필터를 작성.** 화면에는 도메인이 보이는데 필터에는 IP를 써야 하는 경우 혼란이 생긴다. `-n` 또는 `View > Name Resolution` 해제로 순수 IP를 기준으로 통일한다.
- **`ip.src`만으로 왕복 트래픽을 다 봤다고 착각.** `ip.src == x`는 나가는 방향만 잡는다. 응답까지 보려면 `ip.addr == x`가 필요하다.
- **NAT 뒤의 사설 IP를 공인 IP로 착각.** 사설망 캡처 지점(예: 게이트웨이 안쪽)에서 뜬 IP는 NAT 이후 바뀔 수 있다. 캡처 위치를 지문에서 확인한다.

## 교차검증

```bash
# 1) 양방향 vs 출발지만 — 개수 차이로 응답 존재 여부 확인
tshark -r capture.pcapng -Y 'ip.addr == 10.0.0.5' | wc -l
tshark -r capture.pcapng -Y 'ip.src == 10.0.0.5' | wc -l

# 2) AND vs OR 차이 직접 확인
tshark -r capture.pcapng -Y 'ip.addr==10.0.0.5 && ip.addr==203.0.113.77' | wc -l
tshark -r capture.pcapng -Y 'ip.addr==10.0.0.5 || ip.addr==203.0.113.77' | wc -l

# 3) Endpoints 통계와 대조 — 그 IP의 총 패킷/바이트 수가 필터 결과와 맞는지
tshark -r capture.pcapng -q -z endpoints,ip | grep 10.0.0.5

# 4) GUI Conversations에서 A<->B 행의 Packets 수와 tshark 필터 결과 수 비교
tshark -r capture.pcapng -q -z conv,ip | grep -E '10.0.0.5.*203.0.113.77'
```

Endpoints/Conversations 통계는 필터 없이 전체를 집계하므로, `ip.addr` 필터 결과 개수와 통계 수치가 어긋나면 필터 조건(AND/OR, 버전별 `!=`)을 다시 의심한다.

## mini walkthrough

```text
문제:
"공격자 IP 203.0.113.77과 내부 피해 호스트 사이에서만 오간 트래픽을 분석하세요."
첨부: incident.pcapng (32,004 packets), 내부 대역은 10.0.0.0/24

1. 첫 시도 (실패)
   $ tshark -r incident.pcapng -Y 'ip.addr == 203.0.113.77 || ip.addr == 10.0.0.15' -q -z io,phs
   Packets: 8,214

   생각보다 너무 많다. Protocol Hierarchy를 보니 203.0.113.77이 관련 없는
   다른 내부 호스트(10.0.0.20 등)와 주고받은 DNS 응답까지 섞여 있었다.
   OR로 걸렀기 때문에 "203.0.113.77이 낀 모든 트래픽"이 다 나온 것이다.

2. 접근 변경 — AND로 두 호스트 사이만
   $ tshark -r incident.pcapng -Y 'ip.addr == 203.0.113.77 && ip.addr == 10.0.0.15' -q -z io,phs
   Packets: 1,340

   -> 훨씬 줄었다. 이제 이 둘 사이의 대화만 남았다.

3. 대화 안에서 프로토콜 확인
   $ tshark -r incident.pcapng -Y 'ip.addr == 203.0.113.77 && ip.addr == 10.0.0.15' -q -z io,phs
     Transmission Control Protocol   96%   1287   1,204,880
       Hypertext Transfer Protocol   40%    536     892,010

4. 시각까지 추출해 EVTX와 대조
   $ tshark -r incident.pcapng -n -Y 'ip.addr==203.0.113.77 && ip.addr==10.0.0.15 && http.request' \
       -T fields -e frame.time_epoch -e http.request.uri | head -3
   1773645302.418221   /login
   1773645305.101100   /admin/upload

   1773645302 -> UTC 2026-03-16 09:55:02 -> KST 18:55:02.
   같은 시각 대의 EVTX 4624(10.0.0.15, IpAddress=203.0.113.77)와 대조해
   실제 로그온 성공 여부를 확인한다.

정답: AND로 좁힌 1,340개 패킷 중 HTTP 536개, /admin/upload 요청이 침해의 핵심 증거
```

1번의 실패는 OR과 AND를 혼동한 전형적인 사례다. **"두 호스트 사이"라는 말은 거의 항상 `&&`를 의미한다.**

## 막혔을 때 다음 체크

1. `ip.addr`(양방향)과 `ip.src`/`ip.dst`(단방향) 중 무엇이 필요한지 다시 확인했는가
2. "사이의 대화"를 OR이 아니라 AND로 썼는가
3. CIDR 표기에 공백이 없는가 (`x.x.x.x/nn`)
4. `!=`를 쓰는 대신 `!(ip.addr == x)`로 명확하게 썼는가
5. 대상이 IPv6인데 `ip.addr`을 쓰고 있지 않은가 — `ipv6.addr`로 교체
6. 캡처 필터 문법(`host`, `net`)을 디스플레이 필터 창에 넣지 않았는가
7. 이름 변환이 꺼져 있어 필터에 쓴 IP와 화면에 보이는 값이 일치하는가
8. Endpoints/Conversations 통계와 필터 결과 개수를 대조했는가
9. 시각을 UTC로 맞추고 KST를 별도로 계산했는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `ip.addr`, `ip.src`, `ip.dst`, `ipv6.addr` 필드 정의, CIDR 표기법, `in {}` 목록 문법
- SRC-003 — Wireshark User's Guide: "Building Display Filter Expressions"의 다중 occurrence 필드 비교 규칙, Wireshark 3.6에서 `!=` 의미가 `all_ne`로 변경된 사실
- `!=`의 버전별 동작 차이는 실제 대회장 Wireshark 버전에 따라 다를 수 있으므로, 애매하면 `!(field == value)` 형태로 통일해 쓸 것
