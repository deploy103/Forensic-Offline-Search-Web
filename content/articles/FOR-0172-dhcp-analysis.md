---
id: FOR-0172
title: "DHCP 임대 기록으로 IP 할당 흐름 분석하기"
slug: "dhcp-analysis"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "DHCP lease", "DORA"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["DHCP", "BOOTP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y dhcp -T fields -e bootp.option.dhcp -e bootp.hw.mac_addr -e bootp.ip.your", "tshark -r capture.pcapng -Y 'bootp.option.dhcp == 2' -T fields -e ip.src -e bootp.ip.your", "tshark -r capture.pcapng -Y dhcp -T fields -e bootp.option.hostname -e bootp.hw.mac_addr"]
regex_patterns: []
wireshark_filters: ["dhcp", "bootp.option.dhcp == 1", "bootp.option.dhcp == 2", "bootp.option.dhcp == 3", "bootp.option.dhcp == 5", "bootp.option.hostname contains \"WIN\"", "bootp.option.dhcp_server_id != 10.0.0.1"]
tshark_fields: ["bootp.option.dhcp", "bootp.hw.mac_addr", "bootp.ip.your", "bootp.ip.client", "bootp.ip.server", "bootp.option.hostname", "bootp.option.requested_ip_address", "bootp.option.dhcp_server_id", "bootp.option.ip_address_lease_time"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["dhcp 분석", "DHCP 임대 확인"]
keywords: ["DHCP", "DORA", "Discover Offer Request Ack", "DHCP lease", "bootp", "IP 임대", "rogue DHCP", "DHCP 서버 스푸핑", "hostname 옵션", "lease time", "chaddr", "yiaddr"]
aliases: ["dhcp 임대", "ip 할당 기록", "dhcp 로그", "누가 이 ip 썼나", "가짜 dhcp 서버", "dhcp 호스트명"]
symptom_keywords: ["이 시간에 이 ip를 누가 썼는지 알고 싶다", "dhcp 서버가 두 개인 것 같다", "ip 할당 순서를 모르겠다", "호스트명을 확인하고 싶다", "임대 시간이 궁금하다"]
related: ["FOR-0171", "FOR-0146", "FOR-0073", "FOR-0182"]
source_ids: ["SRC-068", "SRC-002", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

DHCP 는 Discover → Offer → Request → Ack(DORA) 네 단계로 IP 를 할당하며, `bootp.option.dhcp`(메시지 타입), `bootp.hw.mac_addr`(클라이언트 MAC), `bootp.ip.your`(할당된 IP), `bootp.option.hostname`(클라이언트가 밝힌 이름) 네 필드만 뽑으면 "언제 누가 어떤 IP 를 받았는가"가 전부 나온다.

## 어떤 문제에서 필요한가

- "이 시각에 이 IP 를 쓴 호스트는 무엇인가" 를 묻는 문제
- pcap 안의 여러 IP 를 실제 장비(MAC, 호스트명)와 연결해야 하는 상황
- DHCP 서버가 두 개 이상 응답하는, **rogue DHCP 서버 삽입 공격**이 의심되는 캡처
- 특정 호스트의 네트워크 참여/이탈 시점을 확인해야 하는 상황(임대 시작·갱신·해제)

pcap 안의 IP 는 그 자체로는 "누구"인지 알려주지 않는다. **DHCP 가 IP 와 MAC/호스트명을 이어주는 유일한 다리**다.

## 문제에서 처음 볼 단서

1. **`Info` 컬럼의 `DHCP Discover`, `DHCP Offer`, `DHCP Request`, `DHCP ACK`** — 4단계가 온전히 있는지, 일부만 있는지
2. **서버 IP(`ip.src`)가 두 개 이상 등장하는지** — 정상 네트워크는 DHCP 서버가 보통 1대다
3. **`Option (12) Host Name`** — 클라이언트가 자기 이름을 밝히는 옵션. 있으면 바로 장비 식별
4. **`bootp.ip.your` 값의 변화** — 같은 MAC 이 다른 시점에 다른 IP 를 받았는지
5. **임대 시간(Option 51)** — 짧으면(수 분) 테스트/공격 환경, 길면(수 일) 일반 사무 환경

## 30초 절차

```bash
tshark -r capture.pcapng -Y dhcp -T fields -e bootp.option.dhcp -e bootp.hw.mac_addr -e bootp.ip.your
```

이 한 줄로 메시지 타입, MAC, 할당 IP 가 나란히 나온다. 타입 값 5(ACK) 행만 봐도 "누가 어떤 IP 를 최종적으로 받았는지"가 다 나온다.

GUI 3단계:

```text
1. 필터: dhcp                              -> DORA 4단계가 온전한지 확인
2. 필터: bootp.option.dhcp == 5 (ACK)      -> 실제로 확정된 임대만 남긴다
3. 컬럼에 bootp.hw.mac_addr, bootp.ip.your, bootp.option.hostname 추가
```

## 상세 절차

### 1단계 — DORA 4단계와 메시지 타입 코드

`Option 53 (DHCP Message Type)`, Wireshark 필드 `bootp.option.dhcp` 값:

| 값 | 메시지 | 방향 | 의미 |
| --- | --- | --- | --- |
| 1 | DHCPDISCOVER | 클라이언트 → 브로드캐스트 | "IP 를 줄 서버 있나?" |
| 2 | DHCPOFFER | 서버 → 클라이언트 | "이 IP 를 제안한다" |
| 3 | DHCPREQUEST | 클라이언트 → 브로드캐스트(또는 유니캐스트 갱신) | "이 IP 를 쓰겠다" |
| 4 | DHCPDECLINE | 클라이언트 → 서버 | "그 IP 는 이미 쓰이고 있다" |
| 5 | DHCPACK | 서버 → 클라이언트 | "확정. 이 IP 를 써라" |
| 6 | DHCPNAK | 서버 → 클라이언트 | "거부. 다시 Discover 부터" |
| 7 | DHCPRELEASE | 클라이언트 → 서버 | "IP 반납" |
| 8 | DHCPINFORM | 클라이언트 → 서버 | IP 는 이미 있고 다른 설정만 요청 |

정상적인 최초 임대는 1→2→3→5 네 패킷이 짧은 시간(수백 ms) 안에 오간다. **임대 갱신(renew)** 은 임대 기간의 절반 시점에 클라이언트가 서버로 직접(유니캐스트) Request 를 보내고 Ack 만 받는 2단계로 끝난다 — Discover/Offer 가 없다고 비정상은 아니다.

### 2단계 — MAC-IP-호스트명 매핑 표를 만든다

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 5' \
  -T fields -e frame.time -e bootp.hw.mac_addr -e bootp.ip.your -e bootp.option.hostname \
  -E header=y
```

```text
frame.time                    bootp.hw.mac_addr    bootp.ip.your   bootp.option.hostname
2026-03-14 08:01:12.310000    aa:bb:cc:00:11:22     10.0.0.101      DESKTOP-K7QX2M
2026-03-14 08:01:44.902000    aa:bb:cc:00:33:44     10.0.0.102      IOT-CAM-03
2026-03-14 09:15:02.117000    aa:bb:cc:00:11:22     10.0.0.101      DESKTOP-K7QX2M
```

이 표 한 장이 "이 시각, 이 IP 는 이 MAC/호스트명이었다"의 전체 근거가 된다. 문제에서 IP 만 주어졌다면 이 표에서 **그 IP 를, 그 시각에 가진 행**을 찾으면 된다.

### 3단계 — Discover 단계에서 이미 힌트를 얻는다

DHCPDISCOVER 에도 `bootp.option.hostname` 과 `bootp.hw.mac_addr` 이 실려 있다. ACK 을 못 받은(실패한) 클라이언트라도 Discover 패킷만으로 존재를 확인할 수 있다.

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 1' \
  -T fields -e bootp.hw.mac_addr -e bootp.option.hostname
```

### 4단계 — Request 의 `requested_ip_address` 로 재접속을 확인한다

클라이언트가 이전에 받았던 IP 를 기억하고 재요청하는 경우, Discover 대신 바로 Request 를 보내며 `Option 50 (Requested IP Address)` 에 그 IP 를 담는다.

```text
bootp.option.dhcp == 3
```

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 3' \
  -T fields -e bootp.hw.mac_addr -e bootp.option.requested_ip_address -e bootp.option.dhcp_server_id
```

`bootp.option.dhcp_server_id` (Option 54) 는 이 Request 가 **어느 서버를 향한 것인지** 명시한다. 서버가 여러 대인 네트워크에서 어느 서버로 요청이 갔는지 이 필드로 가른다.

### 5단계 — rogue DHCP 서버를 찾는다

같은 Discover 에 대해 서로 다른 IP 를 가진 서버가 응답하면 그중 하나는 비인가 서버일 수 있다.

```text
bootp.option.dhcp == 2
```

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 2' -T fields -e ip.src | sort -u
```

결과에 서버 IP 가 2개 이상이면 즉시 의심한다. 두 서버가 **같은 클라이언트에게** 응답했는지도 확인한다.

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 2' \
  -T fields -e ip.src -e bootp.hw.mac_addr -e bootp.ip.your
```

정상 서버가 아닌 IP 에서 Offer 가 왔다면, 그 서버가 제안한 IP 를 클라이언트가 실제로 채택(ACK)했는지도 이어서 확인한다. 채택됐다면 **DNS 서버(Option 6)나 게이트웨이(Option 3)를 공격자가 지정한 값으로 바꿔 트래픽을 가로챌 수 있는 상태**다.

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 5' \
  -T fields -e ip.src -e bootp.ip.your -e bootp.hw.mac_addr
```

### 6단계 — 임대 시간과 갱신 패턴을 본다

```text
bootp.option.ip_address_lease_time
```

```bash
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 5' \
  -T fields -e frame.time -e bootp.ip.your -e bootp.option.ip_address_lease_time
```

같은 IP 에 대해 ACK 이 임대 시간의 절반 간격으로 반복되면 정상 갱신이다. 갱신 없이 짧은 간격으로 새 Discover 부터 다시 시작하면 클라이언트가 재부팅했거나 네트워크를 재연결한 것이다.

## 출력 필드 해석

| 필드 | 의미 | 확인 포인트 |
| --- | --- | --- |
| `bootp.option.dhcp` | 메시지 타입(1~8) | DORA 흐름 판정 |
| `bootp.hw.mac_addr` | 클라이언트 하드웨어 주소(chaddr) | 장비 식별의 핵심 키 |
| `bootp.ip.your` | 서버가 할당한 IP(yiaddr) | "이 IP = 이 MAC" 매핑 |
| `bootp.ip.client` | 클라이언트가 이미 갖고 있던 IP(ciaddr) | 갱신/재확인 시에만 채워짐 |
| `bootp.ip.server` | 서버 IP(siaddr) | 부팅 서버 지정 시 사용, 보통 0 |
| `bootp.option.hostname` | 클라이언트가 밝힌 컴퓨터 이름 | 사람이 읽을 수 있는 장비 식별자 |
| `bootp.option.requested_ip_address` | Request 에서 요청한 IP | 재접속/특정 IP 고집 여부 |
| `bootp.option.dhcp_server_id` | 이 트랜잭션의 서버 IP | 다중 서버 환경에서 대상 구분 |
| `bootp.option.ip_address_lease_time` | 임대 시간(초) | 갱신 주기 계산 |

## pivot: 다음에 볼 artifact

| DHCP에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| IP-MAC-호스트명 매핑 표 | pcap 내 다른 모든 IP 기반 필터에 이름 붙이기 → [FOR-0182](./ip-addr-filter.html) |
| 의심되는 rogue DHCP 서버 IP | 그 IP 의 다른 트래픽(ARP 스푸핑 동반 여부) → [FOR-0171](./arp-analysis.html) |
| 호스트명 | 디스크/레지스트리의 ComputerName 과 대조 → [FOR-0073](./computer-name.html) |
| 특정 MAC 의 최초 등장 시각 | 그 시각 전후 다른 artifact(USB 삽입, 로그온)와 시간 대조 |
| 클라이언트가 받은 DNS 서버 옵션 값 | 이후 DNS 질의가 그 서버로 갔는지 확인 |

## 흔한 함정

- **`ip.src`/`ip.dst` 만 보고 DHCP 를 놓치는 것.** DHCPDISCOVER/REQUEST 는 출발 IP 가 `0.0.0.0`, 목적지가 `255.255.255.255`(브로드캐스트)다. IP 필터보다 `dhcp` 프로토콜 필터가 먼저다.
- **필터 이름 `dhcp` 가 안 먹는다고 포기하는 것.** Wireshark 3.0 미만에서는 `bootp` 를 써야 한다. 필드 이름 자체는 버전과 무관하게 `bootp.` 접두사를 유지한다.
- **Offer 단계의 IP 를 최종 할당 IP 로 오인하는 것.** 서버가 제안(Offer)한 IP 를 클라이언트가 거부할 수도 있다. 최종 확정은 반드시 ACK(`bootp.option.dhcp == 5`)에서 확인한다.
- **DHCP 서버가 1대뿐이라고 가정하는 것.** `ip.src` 를 Offer 기준으로 집계해 서버가 실제로 몇 대인지 세어본다.
- **갱신(renew) 패킷에 Discover/Offer 가 없다고 비정상으로 보는 것.** 유니캐스트 Request→Ack 두 단계만으로 끝나는 것이 정상 갱신이다.
- **호스트명 옵션이 없다고 장비를 특정할 수 없다고 포기하는 것.** MAC 주소 자체도 고유 식별자다. OUI 로 제조사만이라도 좁힌다.
- **임대 시간을 무시하고 IP 재사용을 놓치는 것.** DHCP 는 IP 를 회수해 다른 장비에 재할당한다. 같은 IP 라도 시간이 다르면 다른 장비일 수 있다. 반드시 시각까지 함께 본다.
- **시간을 상대 초로 두고 "몇 시에 누가 있었는가"를 판단하는 것.** UTC 절대시각으로 바꾸고, 필요하면 KST(UTC+9)로 환산해 문제 지문과 맞춘다.

## 교차검증

```bash
# 1) 전체 DORA 흐름 개요
tshark -r capture.pcapng -Y dhcp -T fields -e frame.time -e bootp.option.dhcp -e bootp.hw.mac_addr -e bootp.ip.your

# 2) 확정된 임대만 (ACK)
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 5' \
  -T fields -e frame.time -e bootp.hw.mac_addr -e bootp.ip.your -e bootp.option.hostname

# 3) DHCP 서버 IP 목록 - rogue 서버 존재 확인
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 2' -T fields -e ip.src | sort -u

# 4) 특정 MAC 의 임대 이력 전체
tshark -r capture.pcapng -Y 'bootp.hw.mac_addr == aa:bb:cc:00:11:22' \
  -T fields -e frame.time -e bootp.option.dhcp -e bootp.ip.your

# 5) 특정 IP 를 가졌던 모든 MAC (IP 재사용 이력)
tshark -r capture.pcapng -Y 'bootp.ip.your == 10.0.0.101' \
  -T fields -e frame.time -e bootp.hw.mac_addr

# 6) NAK(거부)만 모아 이상 신호 확인
tshark -r capture.pcapng -Y 'bootp.option.dhcp == 6' -T fields -e frame.time -e bootp.hw.mac_addr
```

## mini walkthrough

```text
문제:
"10.0.0.105 를 2026-03-14 09:20 KST 에 사용한 장비의 호스트명은?"
첨부: office_dhcp.pcapng (3,340 packets)

1. 첫 시도 (실패) - IP 필터로 바로 찾았다
   필터: ip.addr == 10.0.0.105
   -> HTTP, DNS 트래픽만 잔뜩 나왔고, 어떤 패킷에도 호스트명이 없었다.
      IP 트래픽 자체에는 장비 이름이 실려 있지 않다는 것을 뒤늦게 깨달음.

2. 접근 변경 - DHCP 로 IP-MAC-호스트명 매핑을 먼저 만든다
   필터: bootp.option.dhcp == 5
   tshark -r office_dhcp.pcapng -Y 'bootp.option.dhcp == 5' \
     -T fields -e frame.time -e bootp.hw.mac_addr -e bootp.ip.your -e bootp.option.hostname

   frame.time (UTC)              mac                    ip           hostname
   2026-03-14 00:02:11.000000    aa:11:22:33:44:55      10.0.0.105   ACCT-PC-07
   2026-03-14 00:45:03.000000    aa:66:77:88:99:00      10.0.0.108   HR-LAPTOP-02

   -> 09:20 KST = 00:20 UTC (KST 는 UTC+9). 00:02 에 발급된 임대가
      00:20 시점에도 유효할 가능성이 높다. 임대 시간을 확인한다.

3. 임대 시간 확인
   tshark -r office_dhcp.pcapng -Y 'bootp.option.dhcp == 5 && bootp.ip.your == 10.0.0.105' \
     -T fields -e bootp.option.ip_address_lease_time
   43200   (12시간)

   -> 00:02 부터 12시간짜리 임대이므로 00:20 시점에 10.0.0.105 는
      여전히 ACCT-PC-07 (aa:11:22:33:44:55) 소유가 맞다.

4. 이 시간대에 다른 REQUEST/재할당이 없었는지 재확인
   필터: bootp.ip.your == 10.0.0.105
   -> 00:02 이후 다음 임대 이벤트는 08:15 UTC(다음 날). 그 사이 재할당 없음. 확정.

정답: ACCT-PC-07 (aa:11:22:33:44:55)
```

1단계의 실패가 핵심이다. **IP 트래픽 자체에는 호스트명이 없다.** DHCP 로 매핑을 먼저 만들고, 시간대를 UTC 로 정확히 환산한 뒤 임대 시간까지 확인해야 오답을 피한다.

## 막혔을 때 다음 체크

1. `dhcp`(구버전은 `bootp`) 필터로 트래픽이 실제로 존재하는가
2. `bootp.option.dhcp == 5`(ACK)로 확정된 임대만 추렸는가
3. 문제의 시각을 UTC 로 정확히 환산했는가 (KST = UTC+9)
4. 해당 시각 직전의 ACK 이 어떤 MAC/호스트명이었는지 확인했는가
5. 임대 시간(`ip_address_lease_time`)을 확인해 그 시각까지 유효했는지 검증했는가
6. 그 사이에 다른 재할당/갱신 이벤트가 없었는지 재확인했는가
7. DHCP 서버가 여러 대인가 — rogue DHCP 가능성
8. 호스트명이 없으면 MAC OUI 로라도 장비 종류를 좁혔는가
9. Discover 단계만 있고 ACK 이 없는 실패한 임대 시도가 있는가

## 출처

- SRC-068 — RFC 826 / RFC 2131 계열: DHCP의 DORA(Discover-Offer-Request-Ack) 절차와 메시지 타입 정의
- SRC-002 — Wireshark Display Filter Reference: `bootp.option.dhcp`, `bootp.hw.mac_addr`, `bootp.ip.your`, `bootp.option.hostname`, `bootp.option.requested_ip_address`, `bootp.option.dhcp_server_id`, `bootp.option.ip_address_lease_time` 필드명 확인
- SRC-010 — tshark man page: `-T fields -e`, `-Y` 필터 문법
- Wireshark 의 DHCP 디스플레이 필터 이름은 3.0 부터 `bootp` 에서 `dhcp` 로 바뀌었으나 내부 필드 접두사는 `bootp.` 를 유지한다. 구버전 캡처 파일이나 오래된 Wireshark 에서는 `bootp` 필터를 써야 하므로 실제 화면에서 먼저 확인할 것
