---
id: FOR-0150
title: "Endpoints: IP·포트별 트래픽 총량으로 용의선상 좁히기"
slug: "endpoints"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["Ethernet", "IPv4", "IPv6", "TCP", "UDP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z endpoints,ip", "tshark -r capture.pcapng -q -z endpoints,tcp", "tshark -r capture.pcapng -q -z endpoints,ip,ip.addr==10.0.0.15"]
regex_patterns: []
wireshark_filters: ["ip.addr == 203.0.113.77", "!(ip.addr == 10.0.0.0/8)", "eth.addr == aa:bb:cc:dd:ee:ff"]
tshark_fields: ["ip.addr", "tcp.port", "udp.port", "eth.addr"]
log_fields: ["Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes"]
file_formats: ["pcap", "pcapng"]
primary_terms: ["Endpoints", "엔드포인트 통계"]
keywords: ["Endpoints", "엔드포인트 통계", "IP별 트래픽 총량", "Tx Bytes", "Rx Bytes", "endpoints ip", "endpoints tcp", "누가 가장 많이 통신했나", "외부 IP 목록화", "Limit to display filter"]
aliases: ["엔드포인트 통계", "ip별 트래픽 보기", "누가 제일 많이 보냈나", "endpoints 창", "와이어샤크 endpoints", "ip 목록 뽑기", "외부 ip 찾기"]
symptom_keywords: ["어떤 ip가 가장 많이 통신했는지 모르겠다", "외부 ip 목록만 뽑고 싶다", "conversations랑 뭐가 다른지 모르겠다", "특정 호스트의 총 트래픽을 구해야 한다", "ip가 너무 많아 못 보겠다"]
related: ["FOR-0148", "FOR-0149", "FOR-0146", "FOR-0182"]
source_ids: ["SRC-003", "SRC-010", "SRC-002"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Statistics > Endpoints` 는 **개별 호스트(IP/MAC/포트) 하나가 주고받은 트래픽 총량**을 보여준다. `Conversations`가 "누구와 누가" 를 묻는다면 `Endpoints`는 "누가 가장 많이" 를 묻는다. `Bytes` 내림차순으로 정렬하면 그 캡처의 핵심 플레이어가 상위 몇 줄에 다 모인다.

## 어떤 문제에서 필요한가

- "이 캡처에 등장하는 외부 IP를 모두 나열하세요" 류의 지문
- 어떤 호스트가 여러 세션(TCP 여러 개, UDP 포함)에 걸쳐 총 얼마나 통신했는지 합산이 필요할 때
- [FOR-0149](./conversations.html)에서 세션 단위로 봤는데 특정 호스트가 여러 상대와 나눈 세션이 흩어져 있어 합산 값이 필요할 때
- 캡처에 존재하는 MAC 주소로 물리적 장비 수를 세야 할 때
- 사설 대역을 걷어내고 외부와 통신한 IP만 추려야 할 때

## 문제에서 처음 볼 단서

1. **행 개수** — IPv4 탭에 IP가 3개뿐이면 캡처가 이미 좁혀진 상태다. 수백 개면 스캔이거나 정상 브라우징의 CDN/광고 트래픽이다.
2. **`Bytes` 1위와 나머지의 격차** — 1위가 압도적이면 그 IP가 핵심이다.
3. **`Packets`는 많은데 `Bytes`는 작은 행** — 비콘, DNS, keep-alive 후보.
4. **탭 종류** — 문제가 "IP" 를 묻는지 "MAC" 을 묻는지에 따라 IPv4 탭과 Ethernet 탭 중 고른다.
5. **컬럼에 보이는 IP 대역** — 10.x/172.16-31.x/192.168.x가 아닌 것이 외부 IP다.

## 30초 절차

```bash
tshark -r capture.pcapng -q -z endpoints,ip
```

GUI는 다섯 클릭이다.

```text
1. Statistics > Endpoints
2. IPv4 탭 선택
3. Bytes 컬럼 헤더 클릭 (내림차순)
4. 상위 행이 이 캡처의 핵심 호스트
5. 행 우클릭 > Apply as Filter > Selected > A
```

사설 대역을 빼고 외부만 보고 싶으면 필터를 먼저 걸고 `Limit to display filter`를 켠다.

```text
!(ip.addr == 10.0.0.0/8 || ip.addr == 172.16.0.0/12 || ip.addr == 192.168.0.0/16)
```

## 상세 절차

### 1단계 — 탭 선택과 Conversations와의 차이

`Statistics > Endpoints`를 열면 하단(또는 우측)에 프로토콜별 탭이 있다.

| 탭 | "엔드포인트"의 정의 | 언제 쓰나 |
| --- | --- | --- |
| `Ethernet` | MAC 주소 1개 | 세그먼트 내 장비 수, ARP 스푸핑 시 중복 MAC 확인 |
| `IPv4` / `IPv6` | IP 주소 1개 | **가장 많이 쓴다.** 호스트별 총 트래픽 |
| `TCP` | IP:포트 조합 1개 | 어떤 포트로 얼마나 받았는지 (서버 측 관점) |
| `UDP` | IP:포트 조합 1개 | DNS 서버, UDP 서비스 식별 |

`Endpoints`와 `Conversations`([FOR-0149](./conversations.html))는 자주 헷갈린다.

| | Endpoints | Conversations |
| --- | --- | --- |
| 단위 | 호스트 하나 | 호스트 쌍(세션) |
| "10.0.0.15가 총 몇 바이트 보냈나" | 한 줄로 바로 나온다 | 상대별로 쪼개져 있어 직접 합산해야 한다 |
| "이 세션이 언제 시작했나" | 없음 | `Rel Start`/`Duration` 있음 |
| "이 호스트가 상대한 대상 목록" | 없음 | 있음 |

10.0.0.15가 서버 3곳과 통신했다면, Conversations에는 3개 행으로 나뉘지만 Endpoints의 IPv4 탭에는 10.0.0.15 한 줄에 세 세션의 합계가 그대로 나온다. **"이 IP가 총 얼마나 썼는가"를 물으면 Endpoints, "누구와 얼마나"를 물으면 Conversations다.**

### 2단계 — 컬럼 의미

| 컬럼 | 의미 | 판정에 쓰는 방법 |
| --- | --- | --- |
| `Address` | IP/MAC/포트 조합 | 정렬·필터 대상 |
| `Packets` | 이 엔드포인트가 관여한 총 패킷(양방향) | 비콘 탐지 |
| `Bytes` | 총 바이트(양방향) | **핵심 플레이어 판정 1순위** |
| `Tx Packets` | 이 엔드포인트가 **보낸** 패킷 수 | 발신 활동량 |
| `Tx Bytes` | 이 엔드포인트가 **보낸** 바이트 | **업로드/유출 판정** |
| `Rx Packets` | 이 엔드포인트가 **받은** 패킷 수 | 수신 활동량 |
| `Rx Bytes` | 이 엔드포인트가 **받은** 바이트 | **다운로드 판정** |
| `Latitude`/`Longitude` | GeoIP 데이터베이스가 설정된 경우만 | 오프라인 환경에서는 대개 비어 있다 |

`Tx`/`Rx`는 **그 행의 주체 기준**이다. Conversations의 `A → B`처럼 상대를 명시하지 않아도 되므로 "이 IP가 보낸 바이트"를 바로 읽을 수 있다.

```text
10.0.0.15    Packets 1621   Bytes 8104332   Tx Packets 1309   Tx Bytes 8084218   Rx Packets 312   Rx Bytes 20114
```

Tx가 Rx보다 압도적으로 크면 이 호스트는 데이터를 **내보내는** 쪽이다.

### 3단계 — GeoIP/Map 기능은 오프라인에서 기대하지 않는다

Endpoints 창에는 `Map` 버튼과 국가/좌표 컬럼이 있으나, 이는 로컬에 GeoIP 데이터베이스(MaxMind 등)를 미리 설치해 둔 경우에만 채워진다. **완전 오프라인 대회 환경에서는 이 데이터베이스가 없을 가능성이 높고, 지도 표시는 온라인 타일 서버가 필요하므로 동작하지 않는다.** 국가 판정이 필요하면 IP 대역을 손으로 대조하거나 사전에 받아 둔 오프라인 GeoIP DB가 있는지 확인한다.

### 4단계 — 정렬 두 번 규칙

```text
(1) Bytes 내림차순      -> 데이터를 가장 많이 주고받은 호스트
(2) Packets 내림차순    -> 빈도가 이상한 호스트 (비콘, 스캔 대상)
```

`Bytes`로는 안 잡히는 것이 있다. C2 비콘은 `Packets`은 많고 `Bytes`는 작다. 두 정렬을 항상 함께 확인한다.

### 5단계 — Limit to display filter로 외부 IP만 추리기

`Conversations`와 동일하게 하단에 `Limit to display filter` 체크박스가 있다.

```text
(1) 메인 필터창: !(ip.addr == 10.0.0.0/8 || ip.addr == 172.16.0.0/12 || ip.addr == 192.168.0.0/16)
(2) Statistics > Endpoints, IPv4 탭
(3) Limit to display filter 체크
    -> 외부 IP만 나열된다
```

캡처 시작 전에 이미 필터를 걸어 두었다면 이 체크박스가 자동으로 켜진 채로 열린다. `Total Packets`/`Percent Filtered` 컬럼이 추가로 보이면 필터가 걸린 상태라는 신호다.

### 6단계 — Resolve name 옵션

`Name resolution` 체크박스를 켜면 IP 대신 호스트명이 보이려 시도한다. 단, DNS 역질의를 인터넷으로 보내려 하므로 **오프라인 환경에서는 응답이 오지 않아 그대로 IP로 남거나 지연만 발생한다.** 오프라인에서는 끈 채로 두고, 도메인이 필요하면 [dns.qry.name 필터](./dns-qry-name-filter.html)로 같은 캡처 안의 DNS 트래픽에서 직접 찾는다.

## 출력 필드 해석

`tshark -q -z endpoints,ip`의 출력.

```text
================================================================================
IPv4 Endpoints
Filter:<No Filter>
                             |       Total        |     Tx      |      Rx      |
                             | Frames    Bytes     | Frames Bytes | Frames Bytes |
10.0.0.15                        2044   8135650        1683   8112544        361    23106
203.0.113.77                     1621   8104332         312     20114       1309   8084218
93.184.216.34                     631   1892044         402   1801322        229    90722
10.0.0.2                            88     12004          44      5880         44     6124
================================================================================
```

| 출력 항목 | GUI 대응 | 비고 |
| --- | --- | --- |
| `Total Frames/Bytes` | `Packets` / `Bytes` | 양방향 합계 |
| `Tx Frames/Bytes` | `Tx Packets` / `Tx Bytes` | 이 IP가 보낸 양 |
| `Rx Frames/Bytes` | `Rx Packets` / `Rx Bytes` | 이 IP가 받은 양 |

CLI 출력에는 GeoIP 컬럼이 없다. 국가 판정이 필요 없는 CTF 환경에서는 오히려 CLI가 더 깔끔하다.

## pivot: 다음에 볼 artifact

| Endpoints에서 얻은 것 | 다음에 할 일 |
| --- | --- |
| `Bytes` 1위 IP | `ip.addr == <IP>`로 필터 → [FOR-0149](./conversations.html)로 세션 단위 확인 |
| `Tx Bytes`가 큰 내부 IP | 유출 시나리오. 해당 IP의 세션에서 Follow Stream |
| 외부 IP 전체 목록 | [FOR-0154](./dns-response-ip-tracking.html)로 그 IP가 어느 도메인의 응답이었는지 역추적 |
| 특이한 포트를 쓴 TCP 엔드포인트 | [FOR-0148](./protocol-hierarchy.html)로 그 포트의 프로토콜 구성 재확인 |
| MAC 주소 목록 | ARP 테이블·DHCP 로그와 대조해 물리 장비 특정 |
| DNS 서버로 보이는 UDP:53 엔드포인트 | [FOR-0152](./dns-basic-filters.html)의 필터로 질의/응답 상세 확인 |
| 사설 IP만 남았는데 외부 유출이 의심됨 | NAT/프록시를 의심하고 프록시 로그·방화벽 로그로 pivot |

## 흔한 함정

- **Endpoints와 Conversations를 같은 것으로 착각하는 것.** Endpoints는 호스트 하나의 합계, Conversations는 호스트 쌍의 값이다. "총 얼마나"를 물으면 Endpoints, "누구와"를 물으면 Conversations다.
- **`Limit to display filter`가 켜진 줄 모르고 "IP가 몇 개 없다"고 판단하는 것.** 창을 열기 전 필터가 있었으면 자동으로 켜진다. `Total Packets`/`Percent Filtered` 컬럼이 그 신호다.
- **오프라인 환경에서 `Map` 버튼이나 국가 컬럼이 채워지길 기대하는 것.** GeoIP DB와 지도 타일 모두 인터넷/사전 설치가 필요하다. 대회장에서는 대개 비어 있다.
- **`Name resolution`을 켜고 응답을 기다리는 것.** 오프라인에서는 DNS 역질의가 실패하거나 지연만 생긴다. 도메인은 DNS 트래픽에서 직접 찾는다.
- **`Bytes`만 보고 비콘을 놓치는 것.** 주기적으로 소량씩 보내는 C2는 `Bytes`로는 하위권이다. `Packets`로 한 번 더 정렬한다.
- **`Tx`/`Rx`를 Conversations의 `A→B`/`B→A`와 같은 방향으로 착각하는 것.** Endpoints의 Tx/Rx는 그 행 주체 기준이라 상대가 누구인지는 알려주지 않는다. 상대까지 필요하면 Conversations로 넘어간다.
- **Ethernet 탭을 건너뛰는 것.** IP가 여러 개라도 MAC이 하나면 물리 장비는 한 대다. IP 스푸핑이나 DHCP 재할당 판별에 MAC이 필요하다.
- **UDP 탭을 무시하는 것.** DNS 서버, NTP, 터널링에 쓰인 UDP 엔드포인트는 TCP 탭에 나타나지 않는다.
- **사설 대역 제외 필터의 대역을 하나 빠뜨리는 것.** `169.254.0.0/16`(링크 로컬)을 빼먹으면 DHCP 실패 흔적이 "외부 IP"로 잘못 집계된다.

## 교차검증

```bash
# 1) GUI Endpoints IPv4 탭과 같은 표
tshark -r capture.pcapng -q -z endpoints,ip

# 2) TCP 포트 단위 엔드포인트
tshark -r capture.pcapng -q -z endpoints,tcp

# 3) 특정 호스트만 낀 엔드포인트 (Limit to display filter 상당물)
tshark -r capture.pcapng -q -z endpoints,ip,ip.addr==10.0.0.15

# 4) Endpoints 값을 Conversations로 재검산 (합산이 맞는지 확인)
tshark -r capture.pcapng -Y 'ip.addr==203.0.113.77' -T fields -e ip.src -e frame.len |
  awk '{s[$1]+=$2} END {for (k in s) print k, s[k]}'

# 5) 사설 대역 제외 후 외부 IP만
tshark -r capture.pcapng -q -z 'endpoints,ip,!(ip.addr==10.0.0.0/8||ip.addr==172.16.0.0/12||ip.addr==192.168.0.0/16)'
```

`(4)`의 합이 GUI/CLI `Total Bytes`와 다르면 필터 조건이나 프레임 길이 계산 기준(헤더 포함 여부)이 다른 것이다. `frame.len`은 프레임 전체 길이이므로 Endpoints의 `Bytes`와 같은 기준이다.

## mini walkthrough

```text
문제:
"이 캡처에서 외부와 통신한 IP를 모두 나열하고, 그중 가장 많은
 데이터를 내보낸(Tx) IP를 구하세요."
첨부: office2.pcapng (9,442 packets)

1. 첫 시도 (실패)
   Statistics > Conversations, IPv4 탭에서 Bytes 내림차순 정렬 후
   상위 5개 행의 Address A/B를 손으로 모아 "외부 IP 목록"이라 적었다.
   -> 문제가 요구하는 "IP별 총 트래픽"과 맞지 않았다.
   원인: 같은 외부 IP가 여러 세션(포트가 다른 TCP, 그리고 DNS UDP)에
        걸쳐 등장해 Conversations에서는 값이 여러 행으로 쪼개져 있었다.
        합산 없이 상위 몇 개만 본 것이 오답의 원인이었다.

2. 접근 변경 — Statistics > Endpoints, IPv4 탭
   먼저 필터 없이 전체를 본다.

   Address          Packets  Bytes     Tx Packets  Tx Bytes  Rx Packets  Rx Bytes
   10.0.0.31        7912     9021004   3102        612004    4810        8409000
   198.51.100.44    6204     8712004   264         43892     5940        8668112
   93.184.216.34    631      1892044   229         90722     402        1801322
   10.0.0.2         88       12004     44          6124      44          5880

3. 사설 대역 제외
   필터: !(ip.addr == 10.0.0.0/8)
   Limit to display filter 체크
   -> 198.51.100.44, 93.184.216.34 두 개만 남는다. 이것이 외부 IP 목록.

4. Tx Bytes 비교
   198.51.100.44: Tx Bytes 43,892 (적게 보냄, 많이 받음 8,668,112)
   93.184.216.34: Tx Bytes 90,722

   -> 둘 다 "많이 내보낸" 쪽이 아니다. 10.0.0.31(내부)이 Tx Bytes 612,004로
      가장 많이 보냈지만 이것은 외부가 아니라 내부 호스트다.

5. 두 번째 시도 (실패)
   "외부 IP 중 Tx Bytes 최대" 를 93.184.216.34로 답했다. 오답.
   원인: 문제의 "내보낸"은 **내부에서 외부로 나간 방향**을 뜻했는데,
        Endpoints의 Tx는 그 IP 자신이 보낸 절대량이라
        93.184.216.34의 Tx 90,722는 "서버가 클라이언트에 보낸 응답"이었다.
        방향의 주체를 착각했다.

6. 수정 — Conversations로 방향을 재확인
   Statistics > Conversations, TCP 탭, 93.184.216.34가 낀 행:
     10.0.0.31:52120 <-> 93.184.216.34:80
     Bytes A→B(내부→외부) 90,722   Bytes B→A(외부→내부) 1,801,322
   -> 실제로는 내부가 90,722바이트만 보내고 외부에서 1.8MB를 받은 것.
      "내보낸" 이 아니라 "받은" 상황이었다.

   198.51.100.44가 낀 행:
     10.0.0.31:51442 <-> 198.51.100.44:443
     Bytes A→B(내부→외부) 8,668,112   Bytes B→A(외부→내부) 43,892
   -> 내부에서 외부로 8.6MB. 이것이 진짜 "내보낸" 트래픽이다.

정답: 외부 IP = 198.51.100.44, 93.184.216.34 / 가장 많이 내보낸 IP(내부→외부 방향) = 198.51.100.44 (8,668,112 bytes)
```

두 번의 실패가 이 글의 핵심이다. Endpoints의 `Tx`/`Rx`는 **그 IP 자신 기준**일 뿐, "누구를 향해"는 알려주지 않는다. 방향이 문제의 핵심이면 Endpoints로 후보를 추리고 Conversations로 방향을 확정하는 두 단계를 반드시 거친다.

## 막혔을 때 다음 체크

1. `Statistics > Endpoints`의 IPv4 탭을 열었는가, TCP/UDP 탭이 필요한 문제는 아닌가
2. `Limit to display filter`가 의도치 않게 켜져 있지 않은가
3. `Bytes`와 `Packets` 두 기준으로 각각 정렬해 봤는가
4. 사설 대역(10/8, 172.16/12, 192.168/16, 169.254/16, 127/8) 제외 필터를 정확히 걸었는가
5. `Tx`/`Rx`가 "그 IP 자신 기준"임을 헷갈리지 않았는가 — 방향이 중요하면 Conversations로
6. `Name resolution`을 켰다가 오프라인이라 멈춘 것은 아닌가
7. `Map`/GeoIP 컬럼이 비어 있는 것을 오류로 오해하지 않았는가
8. Ethernet 탭에서 MAC 개수를 확인했는가
9. UDP 탭에서 DNS 서버·터널링 후보를 확인했는가
10. CLI `-z endpoints,ip`와 GUI 값이 일치하는가
11. 값이 안 맞으면 [FOR-0149](./conversations.html)로 세션 단위로 내려가 재확인했는가

## 출처

- SRC-003 — Wireshark User's Guide, "The Endpoints Window": 탭 구성(Ethernet/IPv4/IPv6/TCP/UDP 등), `Packets`/`Bytes`/`Tx Packets`/`Tx Bytes`/`Rx Packets`/`Rx Bytes` 컬럼 정의, `Limit to display filter` 체크박스, `Name resolution` 체크박스, GeoIP 데이터베이스가 설정되어야 지도/좌표 컬럼이 채워진다는 점
- SRC-010 — tshark man page: `-z endpoints,type[,filter]`의 문법과 출력 구성(Total/Tx/Rx Frames·Bytes)
- SRC-002 — Wireshark Display Filter Reference: `ip.addr`, `eth.addr` 필드
- 메뉴 경로, 컬럼 구성, GeoIP 관련 버튼(`Map`)의 동작은 도구 버전과 로컬 데이터베이스 설치 여부에 따라 다르므로 실제 화면에서 확인할 것
