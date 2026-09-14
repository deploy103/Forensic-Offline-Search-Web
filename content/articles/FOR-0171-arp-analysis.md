---
id: FOR-0171
title: "ARP 패킷으로 스푸핑·장비 흔적 분석하기"
slug: "arp-analysis"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "ARP cache", "gratuitous ARP"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["ARP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y arp -T fields -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4", "tshark -r capture.pcapng -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u", "tshark -r capture.pcapng -q -z endpoints,eth"]
regex_patterns: []
wireshark_filters: ["arp", "arp.opcode == 1", "arp.opcode == 2", "arp.isgratuitous == 1", "arp.duplicate-address-detected", "arp.src.proto_ipv4 == 192.168.0.1"]
tshark_fields: ["arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4", "arp.isgratuitous", "eth.src"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["arp 분석", "ARP 스푸핑 탐지"]
keywords: ["ARP", "ARP spoofing", "ARP 스푸핑", "gratuitous ARP", "arp.opcode", "MAC 주소", "ARP cache poisoning", "arp.isgratuitous", "중간자 공격", "MITM", "arp table", "ARP 요청 응답"]
aliases: ["arp 스푸핑", "arp 중독", "arp poisoning", "맥주소 위조", "mitm 흔적", "arp 요청 응답 확인", "누가 arp 보냈나"]
symptom_keywords: ["같은 ip에 mac이 두 개다", "arp가 이상하다", "중간자 공격이 의심된다", "게이트웨이 mac이 바뀌었다", "arp 요청이 너무 많다"]
related: ["FOR-0172", "FOR-0146", "FOR-0182", "FOR-0183"]
source_ids: ["SRC-068", "SRC-002", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

ARP 는 (IP, MAC) 매핑을 요청/응답으로 광고하는 브로드캐스트 프로토콜이므로, **같은 IP 에 서로 다른 MAC 이 매핑되는 패킷이 존재하면 그것이 ARP 스푸핑의 직접 증거**다. `arp.src.proto_ipv4` 와 `arp.src.hw_mac` 두 필드를 IP 기준으로 집계해 MAC 이 두 개 이상 나오는 IP 를 찾는다.

## 어떤 문제에서 필요한가

- "중간자 공격(MITM)이 있었다", "ARP 스푸핑을 탐지하라" 지문
- 게이트웨이 IP 의 MAC 주소가 캡처 도중 바뀌는 상황
- 네트워크에 연결된 장비 목록(MAC-IP 매핑)을 파악해야 하는 문제
- ARP 요청이 비정상적으로 많아 스캔이나 중독 공격이 의심되는 캡처

**ARP 에는 인증이 없다.** 누구나 "나는 이 IP 다"라고 광고할 수 있고, 수신측은 그 말을 그대로 캐시에 저장한다. 이 취약점이 스푸핑의 근거이자 탐지의 근거다.

## 문제에서 처음 볼 단서

1. **Protocol Hierarchy 에서 ARP 패킷 수** — 정상 LAN 에서도 어느 정도 있지만, 짧은 시간에 수백 개면 스캔/중독 공격
2. **`Info` 컬럼에 반복되는 "who has X? Tell Y" 메시지** — 같은 IP 를 반복 질의하면 캐시가 갱신되지 않는 상황(공격 진행 중)
3. **`Info` 컬럼의 "X is at MAC-A" 와 "X is at MAC-B" 가 같은 IP 에 대해 번갈아 등장** — 스푸핑 확정 신호
4. **캡처 시작 직후 몰려 있는 ARP 트래픽** — 정상적인 네트워크 참여(부팅/연결) 과정
5. **Gratuitous ARP(요청 없이 스스로 보내는 응답)의 빈도** — 정상 장비도 보내지만, 짧은 간격으로 반복되면 캐시 중독 시도

## 30초 절차

```bash
tshark -r capture.pcapng -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u
```

같은 IP 가 두 줄 이상, 서로 다른 MAC 과 함께 나오면 스푸핑 확정이다. 한 줄씩만 나오면 정상 매핑이다.

GUI 3단계:

```text
1. 필터: arp                                -> 전체 ARP 트래픽 개요
2. Statistics > Endpoints > Ethernet 탭      -> MAC 목록과 개수
3. 컬럼에 arp.src.proto_ipv4, arp.src.hw_mac 추가 -> IP-MAC 매핑을 눈으로 정렬
```

## 상세 절차

### 1단계 — ARP 헤더 필드를 정확히 이해한다

| 필드 | Wireshark 필드명 | 의미 |
| --- | --- | --- |
| Opcode | `arp.opcode` | 1=Request(누가 이 IP 를 갖고 있나), 2=Reply(내가 이 IP 다) |
| Sender MAC | `arp.src.hw_mac` | 보낸 쪽의 실제 MAC |
| Sender IP | `arp.src.proto_ipv4` | 보낸 쪽이 주장하는 IP |
| Target MAC | `arp.dst.hw_mac` | Request 에서는 보통 `00:00:00:00:00:00`, Reply 에서는 수신자 MAC |
| Target IP | `arp.dst.proto_ipv4` | 질의 대상 IP |

Request 는 이더넷 목적지가 브로드캐스트(`ff:ff:ff:ff:ff:ff`)이고, Reply 는 질의한 상대에게 유니캐스트로 간다.

```text
arp.opcode == 1   -> "who has 192.168.0.1? tell 192.168.0.20"
arp.opcode == 2   -> "192.168.0.1 is at aa:bb:cc:dd:ee:ff"
```

### 2단계 — IP-MAC 매핑을 전부 뽑아 충돌을 찾는다

```bash
tshark -r capture.pcapng -Y 'arp.opcode == 2' \
  -T fields -e frame.number -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac
```

```text
frame.number  frame.time                     arp.src.proto_ipv4  arp.src.hw_mac
102           2026-03-14 09:12:01.221000     192.168.0.1          00:1a:2b:3c:4d:5e
340           2026-03-14 09:14:33.552000     192.168.0.1          de:ad:be:ef:00:01
588           2026-03-14 09:17:02.109000     192.168.0.1          00:1a:2b:3c:4d:5e
```

같은 IP(`192.168.0.1`, 보통 게이트웨이)가 시간에 따라 서로 다른 MAC 으로 응답하고 있다. 이것이 **ARP 스푸핑의 전형적 패턴**이며, 원래 MAC 과 공격자 MAC 이 번갈아 나타나는 것은 공격자가 주기적으로 위조 응답을 재전송하고 있다는 뜻이다.

집계로 한 번에 확인:

```bash
tshark -r capture.pcapng -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort -u | awk '{print $1}' | sort | uniq -c | sort -nr | awk '$1 > 1'
```

이 명령 결과에 나오는 IP 가 곧 **두 개 이상의 MAC 을 주장한 IP**, 즉 스푸핑 대상이다.

### 3단계 — Gratuitous ARP 를 확인한다

Gratuitous ARP 는 sender IP 와 target IP 가 같은 ARP 패킷이다. 요청받지 않았는데도 스스로 "나는 이 IP 다"라고 광고하며, IP 충돌 감지나 장애조치(failover) 같은 정상적인 용도로도 쓰이지만 **캐시 중독 공격의 핵심 수단**이기도 하다.

```text
arp.opcode == 2 && arp.src.proto_ipv4 == arp.dst.proto_ipv4
```

Wireshark 버전에 따라 이를 직접 표시하는 필드도 있다.

```text
arp.isgratuitous == 1
```

정상적인 Gratuitous ARP 는 장비 부팅 시 한두 번만 나온다. **짧은 간격으로 반복되는 Gratuitous ARP** 는 캐시를 지속적으로 덮어쓰려는 공격 패턴이다.

```bash
tshark -r capture.pcapng -Y 'arp.opcode == 2 && arp.src.proto_ipv4 == arp.dst.proto_ipv4' \
  -T fields -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac
```

### 4단계 — ARP 요청 폭주(scan)를 확인한다

공격자가 네트워크의 살아있는 호스트를 찾을 때도 ARP 를 대량으로 사용한다.

```text
arp.opcode == 1
```

```bash
tshark -r capture.pcapng -Y 'arp.opcode == 1' -T fields -e arp.dst.proto_ipv4 \
  | sort | uniq -c | sort -nr | head -20
```

짧은 시간에 연속된 IP 대역(`192.168.0.1`, `.2`, `.3`, ...)을 순서대로 질의하면 ARP 스캔(네트워크 디스커버리)이다.

### 5단계 — MAC 주소로 장비 종류를 추정한다

MAC 주소 앞 3바이트(OUI)는 제조사를 나타낸다. 흔히 보이는 것들:

| OUI 예시 | 특징 |
| --- | --- |
| `00:0c:29`, `00:50:56`, `08:00:27` | 가상머신(VMware, VirtualBox) — 캡처 환경 자체가 VM |
| `b8:27:eb`, `dc:a6:32` | Raspberry Pi 계열 — IoT/공격 장비로 흔히 쓰임 |
| 무작위로 보이는 MAC (로컬 관리 비트 설정) | 스푸핑 도구가 임의 생성한 MAC일 가능성 |

MAC 의 두 번째 바이트 최하위 비트에서 두 번째 비트(0x02)가 켜져 있으면 "locally administered address", 즉 제조사가 부여한 것이 아니라 소프트웨어가 임의로 설정한 주소다. 공격 도구가 자체 MAC 을 생성할 때 이 패턴이 흔히 나타난다.

## 출력 필드 해석

| 필드 | 의미 | 확인 포인트 |
| --- | --- | --- |
| `arp.opcode` | 1=Request, 2=Reply | 요청 폭주=스캔, 응답 충돌=스푸핑 |
| `arp.src.hw_mac` / `arp.src.proto_ipv4` | 보낸 쪽 MAC/IP | IP 당 MAC 이 여러 개인지 |
| `arp.dst.hw_mac` / `arp.dst.proto_ipv4` | 질의 대상 MAC/IP | Request 의 target MAC 은 보통 0 |
| `arp.isgratuitous` | Gratuitous 여부 | 반복 빈도로 정상/공격 구분 |
| `eth.src` | 이더넷 계층 실제 발신 MAC | `arp.src.hw_mac` 과 다르면 프록시/터널 의심 |

## pivot: 다음에 볼 artifact

| ARP에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| 스푸핑 확정된 게이트웨이 IP/MAC | 그 시각 전후 트래픽이 실제로 공격자 MAC 을 거쳤는지 → [FOR-0182](./ip-addr-filter.html) |
| 공격자로 추정되는 MAC/IP | 그 IP 의 TCP/UDP 세션 전체 확인 |
| DHCP 로 할당된 IP-MAC 매핑 | 정상 매핑과 대조 → [FOR-0172](./dhcp-analysis.html) |
| 네트워크 내 전체 장비 목록 | 자산 식별, 호스트명 대조 → [FOR-0073](./computer-name.html) |
| ARP 스캔 시각 | 그 직후의 TCP SYN 스캔 여부 확인 |

## 흔한 함정

- **ARP 요청이 많다고 바로 스캔으로 단정하는 것.** 정상 LAN 에서도 DHCP 갱신, 장비 재접속 시 ARP 가 몰릴 수 있다. 대상 IP 가 연속적인 대역을 순서대로 훑는지 확인해야 스캔이라 확정한다.
- **IP 하나에 MAC 하나만 나온 짧은 구간만 보고 스푸핑이 없다고 단정하는 것.** 공격이 캡처의 특정 구간에만 있을 수 있다. 전체 시간대를 집계한다.
- **Gratuitous ARP 를 전부 공격으로 보는 것.** 로드밸런서/failover, DHCP 갱신 등 정상적으로도 발생한다. 빈도와 반복 간격을 함께 본다.
- **`arp.src.hw_mac` 만 보고 `eth.src` 를 확인하지 않는 것.** 두 값이 다르면 캡처 경로에 프록시나 터널이 있다는 뜻이며 분석이 복잡해진다.
- **MAC OUI 만으로 장비를 단정하는 것.** OUI 는 제조사 힌트일 뿐이며, 가상 MAC 이나 랜덤 MAC 기능(모바일 기기의 프라이버시 MAC 등)으로 쉽게 우회된다.
- **ARP 트래픽의 타임스탬프를 상대 시각으로 두고 다른 로그와 대조하는 것.** UTC 절대시각으로 바꿔야 DHCP 로그나 EVTX 와 시간 순서를 맞출 수 있다.
- **응답(Reply)만 보고 요청(Request)의 패턴을 확인하지 않는 것.** 스푸핑 공격자는 종종 요청 없이 Reply 만(Gratuitous) 반복 전송한다. Request 유무 자체가 단서다.
- **VLAN/서브넷이 여러 개 섞인 캡처에서 IP 를 전역으로 비교하는 것.** 서로 다른 네트워크의 사설 IP(예: 두 지점 모두 `192.168.0.1`)가 같은 값으로 보여 오판할 수 있다. 캡처 인터페이스/시간대별로 구간을 나눠 본다.

## 교차검증

```bash
# 1) 전체 ARP 개요
tshark -r capture.pcapng -Y arp -T fields -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4

# 2) IP 당 MAC 이 2개 이상인 경우 - 스푸핑 후보
tshark -r capture.pcapng -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort -u | awk '{print $1}' | sort | uniq -c | sort -nr | awk '$1 > 1'

# 3) Gratuitous ARP 목록
tshark -r capture.pcapng -Y 'arp.opcode == 2 && arp.src.proto_ipv4 == arp.dst.proto_ipv4' \
  -T fields -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac

# 4) 요청 대상 IP 빈도 - 스캔 판정
tshark -r capture.pcapng -Y 'arp.opcode == 1' -T fields -e arp.dst.proto_ipv4 \
  | sort | uniq -c | sort -nr | head -20

# 5) 이더넷 엔드포인트 - 등장하는 MAC 전체 목록
tshark -r capture.pcapng -q -z endpoints,eth

# 6) 특정 IP 의 시간에 따른 MAC 변화 (게이트웨이 예시)
tshark -r capture.pcapng -Y 'arp.src.proto_ipv4 == 192.168.0.1' \
  -T fields -e frame.time -e arp.src.hw_mac
```

## mini walkthrough

```text
문제:
"공격자가 ARP 스푸핑으로 중간자 공격을 수행했다. 공격자의 MAC 주소는?"
첨부: mitm.pcapng (2,204 packets)

1. 첫 시도 (실패) - Conversations만 봤다
   Statistics > Conversations > Ethernet
   -> MAC 주소가 3개 나열되어 있었지만 어느 것이 공격자인지 알 수 없었다.
      단순 목록만으로는 판단 근거가 없다.

2. 접근 변경 - IP-MAC 매핑 충돌 확인
   tshark -r mitm.pcapng -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac \
     | sort -u | awk '{print $1}' | sort | uniq -c | sort -nr | awk '$1 > 1'

        2 192.168.0.1

   -> 게이트웨이 IP(192.168.0.1)가 두 개의 MAC 을 주장했다.

3. 두 MAC 을 시간순으로 나열
   tshark -r mitm.pcapng -Y 'arp.src.proto_ipv4 == 192.168.0.1' \
     -T fields -e frame.time -e arp.src.hw_mac

     09:00:01.100   00:1a:2b:3c:4d:5e   <- 정상 게이트웨이 (캡처 시작부터 있던 값)
     09:02:15.400   02:11:22:33:44:55   <- 새로 등장, 로컬 관리 비트(0x02) 켜짐
     09:02:16.902   02:11:22:33:44:55   <- 반복 (Gratuitous)
     09:02:18.310   02:11:22:33:44:55
     09:05:40.221   00:1a:2b:3c:4d:5e   <- 정상 값도 계속 섞여 나옴

   -> 02:11:22:33:44:55 는 두 번째 바이트 최하위에서 2비트가 켜져 있어
      제조사가 부여한 정식 MAC 이 아니라 소프트웨어로 생성된 값으로 보인다.
      Gratuitous ARP 로 짧은 간격에 반복 전송된 것도 공격 패턴과 일치한다.

4. Gratuitous 여부 확인
   필터: arp.opcode == 2 && arp.src.proto_ipv4 == arp.dst.proto_ipv4 && arp.src.hw_mac == 02:11:22:33:44:55
   -> 09:02:15 이후 15초 간격으로 총 40회 반복. 정상 장비의 1회성 광고와 다르다.

5. 실제 트래픽이 이 MAC 을 거쳤는지 확인
   필터: eth.dst == 02:11:22:33:44:55 && !arp
   -> 클라이언트가 보낸 HTTP/DNS 트래픽의 이더넷 목적지가 이 MAC 으로 향하고 있었다.
      정상이라면 게이트웨이(00:1a:2b:3c:4d:5e)로 가야 한다.

정답: 공격자 MAC 02:11:22:33:44:55 (게이트웨이 192.168.0.1을 스푸핑, Gratuitous ARP로 캐시 중독)
```

1단계의 실패가 교훈이다. **Conversations 목록만으로는 "누가 공격자인가"를 알 수 없다.** IP-MAC 매핑을 시간순으로 나열해 충돌을 직접 확인해야 한다.

## 막혔을 때 다음 체크

1. `arp.src.proto_ipv4` 기준으로 MAC 이 2개 이상인 IP 를 찾았는가
2. 그 IP 가 게이트웨이(디폴트 라우트)인지 확인했는가
3. Gratuitous ARP(`arp.src.proto_ipv4 == arp.dst.proto_ipv4`)가 반복되는가
4. 의심 MAC 이 로컬 관리 비트(두 번째 바이트 0x02)를 갖는가
5. `eth.dst`/`eth.src` 가 실제로 그 MAC 을 거쳐 트래픽이 흘렀는지 확인했는가
6. ARP 요청 대상 IP 가 연속된 대역을 순서대로 훑는가(스캔 여부)
7. 시간을 UTC 절대시각으로 바꿔 DHCP/EVTX 와 대조했는가
8. 캡처에 서로 다른 서브넷/VLAN 이 섞여 있어 IP 가 겹치지 않는가

## 출처

- SRC-068 — RFC 826 (ARP): Request/Reply 동작, sender/target 하드웨어·프로토콜 주소 필드 정의
- SRC-002 — Wireshark Display Filter Reference: `arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.hw_mac`, `arp.dst.proto_ipv4`, `arp.isgratuitous` 필드명 확인
- SRC-010 — tshark man page: `-z endpoints,eth`, `-T fields -e`, `-Y` 필터 문법
- `arp.isgratuitous` 필드명과 Gratuitous ARP 관련 필드는 Wireshark 버전에 따라 존재 여부와 이름이 다를 수 있으므로, 필터가 인식되지 않으면 `arp.src.proto_ipv4 == arp.dst.proto_ipv4` 조합 필터로 대체할 것
- 로컬 관리 MAC 주소(0x02 비트) 판정은 IEEE 802 MAC 주소 체계의 일반 규칙이며, 개별 도구가 이를 지키지 않을 수 있으므로 단독 근거로 쓰지 않는다
