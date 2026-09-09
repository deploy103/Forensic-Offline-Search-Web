---
id: FOR-0176
title: "UDP 흐름 분석: udp.stream 과 포트로 연결 없는 대화를 세는 방법"
slug: "udp-flow-analysis"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "UDP conversation"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["UDP", "DNS", "DHCP", "TFTP", "NTP", "SNMP", "syslog", "SSDP", "mDNS", "QUIC", "IKE"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z conv,udp", "tshark -r capture.pcapng -q -z endpoints,udp", "tshark -r capture.pcapng -Y udp -T fields -e udp.stream -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e udp.length"]
regex_patterns: []
wireshark_filters: ["udp", "udp.port == 53", "udp.stream eq 0", "udp.length > 100", "udp.dstport > 1024 && !dns && !quic", "udp && data.len > 64", "udp.srcport", "udp.dstport"]
tshark_fields: ["udp.srcport", "udp.dstport", "udp.length", "udp.stream", "udp.port", "udp.payload", "data.len", "ip.src", "ip.dst"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["UDP 분석", "udp 필터", "udp 흐름"]
keywords: ["UDP", "udp.stream", "udp.length", "udp.srcport", "udp.dstport", "Follow UDP Stream", "UDP Conversations", "connectionless", "UDP 포트", "data.len", "UDP 터널링", "비표준 포트"]
aliases: ["udp 필터", "udp 대화", "udp 스트림", "udp 포트 번호", "udp 어떻게 추적", "udp follow", "udp 페이로드 크기", "udp 목록"]
symptom_keywords: ["UDP 는 연결이 없어서 추적을 못 하겠다", "udp 대화를 어떻게 묶는지 모르겠다", "모르는 UDP 포트가 계속 통신한다", "UDP 트래픽이 너무 많다", "UDP 로 뭘 보냈는지 알고 싶다"]
related: ["FOR-0146", "FOR-0163", "FOR-0183", "FOR-0155"]
source_ids: ["SRC-002", "SRC-003", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

UDP 는 핸드셰이크가 없으므로 **`(src IP, src port, dst IP, dst port)` 네 값을 하나의 대화로 묶어 보는 것**이 유일한 추적 방법이고, Wireshark 는 그 묶음에 `udp.stream` 번호를 붙여준다. `Statistics > Conversations > UDP` 를 Bytes 로 정렬해 가장 큰 대화부터 열고, 표준 포트가 아닌 고포트 UDP 대화가 지속되면 터널링·C2 후보로 격상한다.

## 어떤 문제에서 필요한가

- Protocol Hierarchy 에서 UDP 비중이 크지만 그 아래에 `Data` 만 붙어 있는 pcap
- DNS·DHCP 도 아닌 **모르는 UDP 포트**로 트래픽이 계속 오가는 상황
- "어떤 프로토콜로 데이터를 빼냈는가"를 묻는데 TCP 에는 아무것도 없는 문제
- QUIC(UDP 443) 만 보여 HTTP 필터가 통하지 않는 최신 캡처
- TFTP·SNMP·syslog 같은 평문 UDP 프로토콜에서 파일·설정·로그를 꺼내야 하는 상황

**TCP 만 보고 "아무것도 없다"고 판단하는 것이 가장 흔한 오답이다.** 트리아지([FOR-0146](./wireshark-30sec-triage.html))에서 UDP 비중이 20% 를 넘으면 반드시 이 절차로 들어온다.

## 문제에서 처음 볼 단서

1. **Protocol Hierarchy 의 `User Datagram Protocol` 하위 항목** — `Domain Name System` 만 있는가, `Data` 가 붙어 있는가
2. **`Data` 의 존재** — Wireshark 가 프로토콜을 판정하지 못한 UDP 페이로드다. 커스텀 프로토콜·C2 후보
3. **Conversations > UDP 의 Bytes 1위** — 파일이나 대량 데이터가 실린 대화
4. **포트 번호가 양쪽 모두 1024 이상** — 표준 서비스가 아니다
5. **패킷 크기가 전부 동일** — 고정 길이 프로토콜(NTP 등)이거나 비콘
6. **한 대화의 지속 시간** — UDP 인데 수십 분 이상 이어지면 세션형 사용(터널·VPN·C2)

## 30초 절차

```text
udp && !dns && !mdns && !nbns && !dhcp && !ssdp && !ntp && !quic
```

**"설명되는 UDP"를 전부 지운 뒤 남는 것**이 이 pcap 의 UDP 이상 신호다. 0건이면 UDP 라인은 끝이다.

이어서 GUI 3단계:

```text
1. Statistics > Protocol Hierarchy   -> UDP 하위에 Data 가 있는가
2. Statistics > Conversations > UDP  -> Bytes 내림차순. 1위 대화 확인
3. 그 행 우클릭 > Apply as Filter > Selected -> Follow > UDP Stream
```

CLI 로 한 번에:

```bash
tshark -r capture.pcapng -q -z conv,udp
```

## 상세 절차

### 1단계 — "흐름"을 정의한다: UDP 에 스트림 번호가 붙는 원리

TCP 는 SYN 으로 시작하고 FIN/RST 로 끝나므로 세션 경계가 패킷에 적혀 있다. UDP 에는 그런 것이 없다. 그래서 Wireshark 는 **네 값이 같은 데이터그램들을 하나의 대화로 간주**하고 등장 순서대로 0부터 번호를 매긴다.

| 묶는 기준 | 값 |
| --- | --- |
| 출발지 IP | `ip.src` |
| 출발지 포트 | `udp.srcport` |
| 목적지 IP | `ip.dst` |
| 목적지 포트 | `udp.dstport` |
| 부여되는 번호 | `udp.stream` (0부터, 방향 무관하게 왕복 한 쌍이 같은 번호) |

즉 `udp.stream eq 3` 은 "3번째로 등장한 (IP,포트) 쌍의 왕복 트래픽 전부"다.

```text
udp.stream eq 3
```

주의할 점 두 개:

- **클라이언트가 소스 포트를 바꾸면 다른 스트림이 된다.** DNS 처럼 질의마다 임시 포트를 새로 여는 프로토콜은 스트림이 수백 개로 쪼개진다. 이때는 `udp.stream` 이 아니라 `udp.port == 53` 처럼 포트 기준으로 봐야 한다.
- **오래된 캡처에서 같은 포트가 재사용되면 서로 다른 세션이 한 스트림으로 합쳐진다.** 시간 축을 함께 봐야 한다.

### 2단계 — 필드 6개로 전부 처리한다

| 필드 | 타입 | 의미 | 실전 용도 |
| --- | --- | --- | --- |
| `udp` | 프로토콜 | UDP 데이터그램 전체 | 존재 여부 확인 |
| `udp.srcport` | 16비트 정수 | 출발지 포트 | 방향을 가려 서버/클라이언트 판별 |
| `udp.dstport` | 16비트 정수 | 목적지 포트 | 어떤 서비스로 보냈는가 |
| `udp.port` | 16비트 정수 | 출발지 **또는** 목적지 | 양방향 한 번에 |
| `udp.length` | 16비트 정수 | **UDP 헤더 8바이트를 포함한** 길이 | 페이로드 크기 = `udp.length - 8` |
| `udp.stream` | 32비트 정수 | 대화 번호 | Follow 대상 지정 |
| `data.len` | 정수 | 파서가 인식하지 못한 페이로드의 바이트 수 | 커스텀 프로토콜 크기 판정 |

`udp.length` 가 헤더를 포함한다는 점이 계속 실수를 만든다.

```text
udp.length == 56        -> 페이로드 48바이트 (NTP 표준 패킷)
udp.length > 512        -> DNS 로는 이례적인 크기
data.len > 64           -> 파서가 못 읽은 64바이트 초과 페이로드
```

Wireshark 3.4 이상에서는 `udp.payload` 로 페이로드 바이트열 자체를 필터·추출할 수 있다.

```text
udp.payload[0:4] == 4d:5a:90:00
```

`udp.time_delta` / `udp.time_relative`(3.0 이상)는 UDP 프로토콜 preference 의 대화 타임스탬프 계산이 켜져 있어야 값이 채워진다. 비콘 간격을 재려면 이 설정을 확인한다.

### 3단계 — 주요 UDP 포트표로 1차 분류한다

| 포트 | 프로토콜 | Wireshark 필터 | 포렌식에서 보는 것 |
| --- | --- | --- | --- |
| 53 | DNS | `dns` | 질의 도메인, 터널링(`dns.qry.name` 길이) |
| 67 / 68 | DHCP (BOOTP) | `dhcp` | 호스트명, MAC, 임대 IP — 자산 식별 |
| 69 | TFTP | `tftp` | **평문 파일 전송.** Export Objects > TFTP |
| 123 | NTP | `ntp` | 시각 동기화. 타임라인 기준점, `udp.length == 56` |
| 137 / 138 | NetBIOS (NBNS/NBDS) | `nbns \|\| nbdgm` | 호스트명, 워크그룹 |
| 161 / 162 | SNMP | `snmp` | **community string 평문**, 장비 정보 |
| 389 | CLDAP | `cldap` | 도메인 컨트롤러 탐지 |
| 443 | QUIC (HTTP/3) | `quic` | 암호화. SNI 만 단서 |
| 500 | IKE (IPsec) | `isakmp` | VPN 협상 시작 |
| 514 | syslog | `syslog` | **평문 로그 원문** |
| 1900 | SSDP (UPnP) | `ssdp` | 내부 장치 목록. 노이즈 |
| 3478 | STUN | `stun` | NAT 통과. WebRTC/P2P |
| 4500 | IPsec NAT-T | `isakmp \|\| esp` | NAT 뒤 VPN 터널 |
| 5060 | SIP | `sip` | VoIP 시그널링, 통화 상대 |
| 5353 | mDNS | `mdns` | 로컬 장치 이름. 노이즈 |
| 1024 이상 고포트 | 미지정 | `udp.dstport > 1024` | **터널·C2 후보** |

노이즈 제거용으로 자주 쓰는 조합:

```text
udp && !(udp.port == 53 || udp.port == 5353 || udp.port == 1900 || udp.port == 137 || udp.port == 138)
```

### 4단계 — 큰 대화와 지속 대화를 찾는다

`Statistics > Conversations` → **UDP 탭** → `Bytes` 헤더 클릭으로 내림차순.

```text
Address A      Port A   Address B        Port B   Packets  Bytes     Duration
10.0.0.24      51420    198.51.100.9     8443     14208    18442110  1382.4    <-- 18 MB, 23분
10.0.0.24      55311    10.0.0.1         53         912       84210    1401.2
10.0.0.24      68       10.0.0.1         67           4        1368       0.8
10.0.0.24      51877    239.255.255.250  1900       211       48920     600.1
```

읽는 순서:

1. **Bytes 1위** — 데이터가 실려 있다. 18 MB UDP 대화는 파일 유출이나 터널이다
2. **Duration 이 긴 대화** — 23분 지속되는 UDP 는 세션형 사용이다. 정상 UDP 서비스는 대개 짧다
3. **Packets 대비 Bytes** — 평균 데이터그램 크기를 계산한다. `18442110 / 14208 = 약 1298바이트` → MTU 에 가까운 큰 데이터그램 = 대량 전송
4. **포트가 양쪽 다 비표준** — 위 예의 `8443` 은 UDP 표준 서비스가 아니다

CLI 동등물:

```bash
tshark -r capture.pcapng -q -z conv,udp
tshark -r capture.pcapng -q -z endpoints,udp
```

### 5단계 — 페이로드 크기 분포로 프로토콜을 추정한다

파서가 프로토콜을 못 잡았을 때, **크기 분포가 정체를 알려준다.**

```bash
tshark -r capture.pcapng -Y 'udp.stream eq 0' -T fields -e udp.length |
  sort -n | uniq -c | sort -nr | head -15
```

| 관측된 분포 | 추정 |
| --- | --- |
| 전부 동일한 한 값 | 고정 길이 프로토콜 또는 비콘. `udp.length == 56` 이면 NTP |
| 두세 개 값에 집중 (예: 148, 92) | 핸드셰이크 2~3종 + 데이터인 VPN/암호 프로토콜 |
| 1200바이트 이상이 다수 + UDP 443 | QUIC. Initial 패킷은 1200바이트 이상으로 패딩된다 |
| 40~90바이트에 몰림 + 포트 53 | 평범한 DNS |
| 300~600바이트 + 포트 67/68 | DHCP |
| MTU 근처(1400~1472)가 연속 | 파일 전송 또는 터널링 |
| 크기가 완전히 무작위 | 암호화된 커스텀 프로토콜 |

크기가 일정하고 **시간 간격도 일정하면 비콘**이다. 간격을 직접 재본다.

```bash
tshark -r capture.pcapng -Y 'udp.stream eq 0' -T fields -e frame.time_relative -e udp.length | head -20
```

### 6단계 — 내용을 본다

```text
1. udp.stream eq 0 필터 적용
2. 패킷 우클릭 > Follow > UDP Stream
3. Show data as = ASCII / Hex Dump 로 전환
```

Follow UDP Stream 은 데이터그램들을 순서대로 이어 붙여 보여준다. **TCP 와 달리 순서 보장이 없으므로 이어 붙인 결과가 원래 바이트열과 다를 수 있다** — 파일을 꺼낼 때는 Hex Dump 로 경계를 확인한다.

CLI:

```bash
tshark -r capture.pcapng -q -z follow,udp,ascii,0
```

평문이 보이면 그대로 답이다. 알아볼 수 없는 바이트열이면 Base64/hex 인코딩 여부를 확인하고, 그래도 안 되면 암호화로 판정하고 **메타데이터(포트, 크기, 간격, 목적지 IP)만으로 결론을 낸다.**

## 출력 필드 해석

`tshark` 로 UDP 대화 표를 직접 만들면 정렬·집계가 쉽다.

```bash
tshark -r capture.pcapng -Y 'udp' -T fields \
  -e udp.stream -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e udp.length \
  -E header=y -E separator=, | head
```

```text
udp.stream,ip.src,udp.srcport,ip.dst,udp.dstport,udp.length
0,10.0.0.24,51420,198.51.100.9,8443,1306
0,198.51.100.9,8443,10.0.0.24,51420,84
1,10.0.0.24,55311,10.0.0.1,53,44
1,10.0.0.1,53,10.0.0.24,55311,60
```

| 읽는 값 | 판정 |
| --- | --- |
| 같은 `udp.stream` 에 두 방향이 모두 있는가 | 없으면 단방향 = 응답 없는 전송(유출/스캔) |
| `udp.length` 가 한쪽만 큰가 | 큰 쪽이 데이터를 보낸 쪽. 업로드/다운로드 방향 판정 |
| 서버 포트가 고정, 클라이언트 포트가 매번 다른가 | 정상 클라이언트-서버 패턴 |
| 양쪽 포트가 모두 고정된 고포트 | **터널링·P2P·C2 의 전형** |

포트별 데이터그램 개수 집계 — 어느 서비스가 지배적인지 즉시 나온다.

```bash
tshark -r capture.pcapng -Y 'udp' -T fields -e udp.dstport |
  sort -n | uniq -c | sort -nr | head -20
```

스트림별 총 바이트 집계:

```bash
tshark -r capture.pcapng -Y 'udp' -T fields -e udp.stream -e udp.length |
  awk -F'\t' '{s[$1]+=$2} END {for (k in s) print s[k], k}' | sort -nr | head
```

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| DNS 질의 도메인 목록 | 브라우저 History ([FOR-0191](./chrome-history.html)), hosts 파일, DNS 캐시 |
| DHCP 의 호스트명 + MAC | 자산 식별 → 컴퓨터 이름 확인 ([FOR-0073](./computer-name.html)) |
| TFTP 로 전송된 파일 | `File > Export Objects > TFTP` → `file` / `strings` ([FOR-0001](./30sec-triage.html)) |
| syslog 원문 | 서버 로그 라인 분석 ([FOR-0111](./log-triage.html)) |
| SNMP community string | 자격증명 후보 → 로그온 이벤트 대조 ([FOR-0083](./event-4624-logon.html)) |
| 비표준 고포트 대화의 상대 IP | 그 IP 의 전 트래픽 ([FOR-0182](./ip-addr-filter.html)) |
| UDP 443 뿐 | QUIC 의 SNI 로 목적지 도메인 ([FOR-0177](./tls-sni.html)) |
| 일정 간격의 고정 크기 데이터그램 | 비콘 판정 → 엔드포인트의 프로세스 확인 ([FOR-0100](./sysmon-event-3-network-connect.html)) |
| NTP 서버와 동기화 시각 | 타임라인 기준점, 시스템 시각 조작 여부 ([FOR-0054](./system-timezone.html)) |

## 흔한 함정

- **UDP 를 "연결이 없으니 추적 불가"로 포기하는 것.** `udp.stream` 이 (IP,포트) 튜플로 대화를 이미 묶어 놓았다. `Statistics > Conversations > UDP` 가 항상 첫 화면이다.
- **`udp.length` 를 페이로드 길이로 쓰는 것.** `udp.length` 는 **헤더 8바이트를 포함**한다. 페이로드는 `udp.length - 8` 이다. 48바이트 NTP 패킷은 `udp.length == 56` 으로 잡힌다.
- **`udp.port == 53` 을 `dns` 와 같다고 보는 것.** 53 번을 쓰지 않는 DNS(비표준 포트)도, DNS 가 아닌 53번 트래픽(위장 터널)도 있다. 두 필터를 각각 돌려 개수가 다르면 그 차이가 단서다.
- **DNS 스트림을 `udp.stream` 으로 묶으려 하는 것.** 질의마다 소스 포트가 바뀌어 스트림이 수백 개로 쪼개진다. DNS 는 `udp.port == 53` 또는 `dns.qry.name` 기준으로 집계한다.
- **`Data` 로 표시된 UDP 를 노이즈로 넘기는 것.** `Data` 는 **Wireshark 가 못 읽은 페이로드**이며, 커스텀 C2 가 정확히 이렇게 보인다. `data.len` 으로 크기를 먼저 재고 Follow 로 내용을 본다.
- **mDNS(5353) / SSDP(1900) / NBNS(137) 를 이상 신호로 보고하는 것.** 이들은 일반 LAN 에 항상 존재하는 배경 잡음이다. 제외 목록에 넣고 시작한다.
- **Follow UDP Stream 결과를 바이트 단위로 신뢰하는 것.** UDP 는 순서와 도착을 보장하지 않으므로 이어 붙인 결과가 원본과 다를 수 있다. 파일을 꺼낼 때는 Hex Dump 로 데이터그램 경계를 확인한다.
- **UDP 443 을 보고 "HTTPS 니까 볼 것 없다"고 넘기는 것.** UDP 443 은 QUIC 이며 `quic` 필터로 파싱된다. Initial 패킷 안의 SNI 로 목적지 도메인을 얻을 수 있다.
- **단방향 대화를 정상으로 보는 것.** 응답이 전혀 없는 UDP 전송은 스캔이거나 **응답을 기대하지 않는 데이터 유출**이다. `Statistics > Conversations` 에서 한 방향 패킷 수가 0 인 행을 찾는다.
- **체크섬 오류(`udp.checksum.status`)를 조작 증거로 읽는 것.** 송신 호스트에서 캡처하면 checksum offload 때문에 정상 트래픽도 오류로 표시된다. `udp.checksum.partial` 이 붙어 있으면 offload 다.
- **시간 간격을 상대 초로만 보고 비콘 판정을 내리는 것.** 절대시각(UTC)으로 바꿔 다른 artifact 와 맞춘 뒤 판정한다.

## 교차검증

```bash
# 1) UDP 대화 목록 — GUI Conversations > UDP 와 동일
tshark -r capture.pcapng -q -z conv,udp

# 2) UDP 엔드포인트 — 누가 등장하는가
tshark -r capture.pcapng -q -z endpoints,udp

# 3) 목적지 포트 빈도 — 어떤 서비스가 지배적인가
tshark -r capture.pcapng -Y 'udp' -T fields -e udp.dstport |
  sort -n | uniq -c | sort -nr | head -20

# 4) 설명되지 않는 UDP 만 남기기
tshark -r capture.pcapng \
  -Y 'udp && !dns && !mdns && !nbns && !dhcp && !ssdp && !ntp && !quic' \
  -T fields -e frame.number -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e udp.length

# 5) 특정 스트림의 크기 분포 — 프로토콜 추정
tshark -r capture.pcapng -Y 'udp.stream eq 0' -T fields -e udp.length |
  sort -n | uniq -c | sort -nr | head -15

# 6) 스트림 내용 — GUI Follow UDP Stream 과 동일
tshark -r capture.pcapng -q -z follow,udp,ascii,0

# 7) 파서를 우회한 최후 수단
tshark -r capture.pcapng -Y 'udp' -T fields -e data.data |
  tr -d ':\n' | xxd -r -p | strings -n 6 | head -30
```

GUI 의 Conversations 개수와 `-z conv,udp` 개수가 다르면 GUI 에 display filter 가 걸려 있는지 확인한다. `-z` 통계는 `-Y` 를 함께 주지 않으면 항상 전체 파일을 대상으로 한다.

## mini walkthrough

```text
문제:
"내부 호스트가 외부로 데이터를 유출했다. 사용한 프로토콜과 유출된 파일 이름을 구하세요."
첨부: exfil_udp.pcapng (21,344 packets, 22 MB)

1. 첫 시도 (실패) — TCP 만 봤다
   Statistics > Conversations > TCP  -> Bytes 최대가 82 KB (평범한 HTTP)
   필터: http.request  -> GET 요청 몇 개, 전부 정상 사이트
   File > Export Objects > HTTP -> 이미지 3개뿐

   "유출 흔적 없음" 이라 판단했다 -> 오답.
   원인: Protocol Hierarchy 를 보지 않고 TCP 탭만 열었다.

2. 접근 변경 — Protocol Hierarchy 를 먼저 본다
   Statistics > Protocol Hierarchy

     Transmission Control Protocol   9.1%    1942    418220
     User Datagram Protocol         90.2%   19256  21884410
       Domain Name System            2.1%     455     41120
       Data                         87.9%   18790  21830100    <-- 21 MB, 파서가 못 읽음
       QUIC                          0.0%       0         0

   -> 전체 바이트의 대부분이 "이름 없는 UDP" 다. 여기가 본체다.

3. 어느 대화인가
   Statistics > Conversations > UDP, Bytes 내림차순

     Address A   Port A   Address B        Port B   Packets   Bytes      Duration
     10.0.0.24   49188    198.51.100.9     8443     18790     21830100   264.7
     10.0.0.24   55102    10.0.0.1         53         455        41120   301.2

   -> udp.stream 0 하나에 21 MB. 264초 동안 지속.
      양쪽 포트가 모두 고정된 고포트 = 세션형 사용.

4. 페이로드 크기 분포로 정체를 좁힌다
   tshark -r exfil_udp.pcapng -Y 'udp.stream eq 0' -T fields -e udp.length |
     sort -n | uniq -c | sort -nr | head

      18102 1170
        680 84
          8 56

   -> 1170바이트가 절대다수. MTU 에 맞춰 잘린 대량 전송이다.
      84바이트는 응답(ACK 성격), 56바이트는 제어용.

5. 내용을 본다
   필터: udp.stream eq 0
   우클릭 > Follow > UDP Stream, Show data as = ASCII

     TFTP? 아니다. 첫 바이트가 매번 다르다.
     Hex Dump 로 전환 -> 각 데이터그램 앞 8바이트가 순번처럼 증가한다.
     ASCII 구간에 반복되는 문자열이 보인다:
       ...customer_db_2026.sql...

6. 문자열로 확정
   필터: udp contains "customer_db"
     No.   Src         Dst              Info
     104   10.0.0.24   198.51.100.9     53994 -> 8443  Len=1128

   상세창 Data 항목:
     0000  00 00 00 01 00 00 04 68  63 75 73 74 6f 6d 65 72
     0010  5f 64 62 5f 32 30 32 36  2e 73 71 6c 00 ...
     -> 8바이트 커스텀 헤더 + 파일명 + 데이터

   확정: 커스텀 UDP 프로토콜(포트 8443)로 customer_db_2026.sql 유출.

7. DNS 도 확인 (다른 유출 경로 배제)
   tshark -r exfil_udp.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name |
     sort -u | head
     ocsp.example-ca.net
     update.example.com
   -> 정상. DNS 터널링은 아니다.

정답: UDP 8443 커스텀 프로토콜 / customer_db_2026.sql
```

1단계의 실패가 이 글의 이유다. **`Statistics > Conversations` 의 TCP 탭만 여는 습관이 UDP 유출을 통째로 놓치게 만든다.** Protocol Hierarchy 를 먼저 보면 21 MB 짜리 `Data` 가 한눈에 들어온다.

## 막혔을 때 다음 체크

1. `Statistics > Protocol Hierarchy` 에서 UDP 하위 항목을 확인했는가 — `Data` 가 있으면 그것이 목표다
2. `Statistics > Conversations` 의 **UDP 탭**을 Bytes 로 정렬했는가
3. 노이즈 제거 필터(`udp && !dns && !mdns && !nbns && !dhcp && !ssdp && !ntp && !quic`)를 돌렸는가
4. 남은 대화의 양쪽 포트가 모두 1024 이상인가 — 터널 후보다
5. `udp.length` 분포를 집계했는가 — 고정 크기면 비콘, MTU 근처면 대량 전송
6. Duration 이 긴 대화가 있는가 — UDP 세션형 사용은 그 자체가 이상 신호다
7. 단방향 대화(응답 0)가 있는가 — 스캔 또는 응답 없는 유출
8. `Follow > UDP Stream` 을 ASCII 와 Hex Dump 로 모두 봤는가
9. `udp contains "..."` 로 파일명·확장자 문자열을 찾아봤는가
10. UDP 443 이 있으면 `quic` 필터로 파싱되는가 — SNI 확인으로 전환
11. TFTP·syslog·SNMP 가 있으면 Export Objects 와 평문 원문을 확인했는가
12. `udp.length` 를 페이로드 길이로 착각하지 않았는가 (8바이트 헤더 포함)

## 출처

- SRC-002 — Wireshark Display Filter Reference: `udp`, `udp.srcport`, `udp.dstport`, `udp.port`, `udp.length`, `udp.stream`, `udp.payload`(3.4.0 이상), `udp.time_delta` / `udp.time_relative`(3.0.0 이상), `udp.checksum.status`, `udp.checksum.partial`, `data.len`, `data.data` 의 정확한 필드명과 도입 버전 확인
- SRC-003 — Wireshark User's Guide: `Statistics > Conversations` / `Endpoints` 의 UDP 탭, `Statistics > Protocol Hierarchy`, `Follow > UDP Stream`, `File > Export Objects > TFTP`
- SRC-010 — tshark man page: `-z conv,udp`, `-z endpoints,udp`, `-z follow,udp,ascii,<stream>`, `-T fields -e`, `-Y`
- UDP 포트표의 서비스 대응은 IANA 등록 포트 관례를 따른 것이며, **포트 번호만으로 프로토콜을 단정할 수는 없다.** 실제 페이로드로 확인한다 ([FOR-0183](./port-filters.html))
- `udp.time_delta` / `udp.time_relative` 는 UDP 프로토콜 preference 의 대화 타임스탬프 계산이 켜져 있어야 값이 채워진다. preference 이름과 기본값은 버전에 따라 다를 수 있으므로 `Edit > Preferences > Protocols > UDP` 에서 실제 화면으로 확인할 것
- QUIC Initial 패킷의 최소 크기(1200바이트 이상 패딩)는 QUIC 명세의 요구사항이며, 실제 캡처에서 `quic.long.packet_type` 으로 패킷 종류를 확인해 검증할 것
- `dhcp` 필터명은 Wireshark 3.0 에서 `bootp` 를 대체한 것이다. 구버전 Wireshark 나 오래된 문서에서는 `bootp` 를 써야 하므로, 필터가 문법 오류로 뜨면 버전을 확인할 것
- `-e data.data` 출력은 콜론으로 구분된 hex 이므로 바이너리로 되돌릴 때 콜론을 먼저 제거해야 한다. 출력 구분 문자는 버전에 따라 다를 수 있으니 실제 출력을 한 줄 찍어 확인할 것
