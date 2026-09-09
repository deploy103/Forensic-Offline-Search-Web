---
id: FOR-0148
title: "Protocol Hierarchy: 프로토콜 비중과 End Packets 읽는 법"
slug: "protocol-hierarchy"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP", "UDP", "HTTP", "DNS", "ICMP", "TLS", "ARP", "SMB2", "FTP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z io,phs", "tshark -r capture.pcapng -q -z io,phs,ip.addr==10.0.0.15", "tshark -r capture.pcapng -T fields -e frame.protocols | sort | uniq -c | sort -nr"]
regex_patterns: []
wireshark_filters: ["data", "data.len > 32", "icmp", "dns", "tls", "!(arp || icmp || dns || tls)", "frame contains \"flag\""]
tshark_fields: ["frame.protocols", "frame.len", "data.len"]
log_fields: ["Percent Packets", "Percent Bytes", "End Packets", "End Bytes", "End Bits/s", "PDUs"]
file_formats: ["pcap", "pcapng"]
primary_terms: ["Protocol Hierarchy", "프로토콜 계층 통계", "프로토콜 비중", "End Packets"]
keywords: ["Protocol Hierarchy", "프로토콜 계층", "End Packets", "End Bytes", "Percent Packets", "io,phs", "프로토콜 비중", "Line-based text data", "frame.protocols", "프로토콜 통계"]
aliases: ["프로토콜 계층", "프로토콜 비중 보기", "어떤 프로토콜이 있나", "io phs", "protocol hierarchy 읽기", "프로토콜 통계 와이어샤크"]
symptom_keywords: ["어떤 프로토콜이 들어있는지 모르겠다", "패킷이 너무 많아 못 본다", "이상한 프로토콜을 찾고 싶다", "End Packets가 무슨 뜻인가", "퍼센트 합이 100이 넘는다"]
related: ["FOR-0146", "FOR-0149", "FOR-0150", "FOR-0155"]
source_ids: ["SRC-003", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Statistics > Protocol Hierarchy` 는 pcap 에 **어떤 프로토콜이 얼마나** 실려 있는지 한 화면으로 알려주는 유일한 창이다. `Bytes` 가 큰 행은 파일 전송, `Packets` 가 과다한 행은 터널링·스캔, **`End Packets`/`End Bytes` 가 큰 행은 그 계층에서 해석이 끝났다는 뜻**이므로 `data` 나 `Line-based text data` 에 몰려 있으면 파서가 못 읽은 커스텀 페이로드가 있다는 신호다.

## 어떤 문제에서 필요한가

- pcap 을 열었는데 패킷이 수만 개라 어디를 볼지 정하지 못하는 모든 상황
- "정상 트래픽 중에 숨겨진 통신을 찾으세요" 류의 지문
- 특정 프로토콜(`http`, `ftp`, `smtp`)로 필터를 걸었는데 0건이라 그 프로토콜이 실제로 있는지 확인해야 할 때
- Export Objects 나 Follow Stream 을 시도하기 **전에** 목표를 하나로 좁혀야 할 때

전체 트리아지 순서는 [FOR-0146](./wireshark-30sec-triage.html) 에 있다. 이 글은 그 2단계 한 칸을 끝까지 파는 글이다.

## 문제에서 처음 볼 단서

1. **트리의 깊이** — `Frame > Ethernet > IPv4 > TCP` 까지만 있고 그 아래가 없으면 애플리케이션 페이로드가 없거나 파서가 못 읽었다는 뜻이다.
2. **`Bytes` 최댓값** — 전체 바이트의 절반 이상을 차지하는 행이 있으면 그것이 파일 전송이다.
3. **`Packets` 최댓값** — 바이트는 작은데 패킷 수가 많으면 스캔, 플러딩, 터널링, keep-alive 중 하나다.
4. **없어야 할 프로토콜** — Telnet, FTP 평문, TFTP, IRC, SMB1, LLMNR/NBNS 는 존재 자체가 단서다.
5. **`data` 또는 `Line-based text data`** — 파서가 포기한 바이트. C2 나 커스텀 프로토콜 후보.

## 30초 절차

```bash
tshark -r capture.pcapng -q -z io,phs
```

GUI 로는 이렇게 한다.

```text
1. Statistics > Protocol Hierarchy
2. 상단 필터 입력창을 먼저 비운다 (통계가 표시 중인 패킷 기준으로 계산된다)
3. Bytes 컬럼을 본다      -> 가장 큰 행 = 파일/데이터 전송
4. Packets 컬럼을 본다    -> 비정상적으로 많은 행 = 터널링/스캔
5. End Bytes 컬럼을 본다  -> data / Line-based text data 에 몰렸는가
6. 목표 행 우클릭 > Apply as Filter > Selected
```

읽은 결과를 한 줄 필터로 옮긴 뒤 [FOR-0149](./conversations.html) 로 "누가 얼마나" 를 확정한다.

## 상세 절차

### 1단계 — 창을 여는 세 가지 경로

```text
Statistics > Protocol Hierarchy
```

이 창에는 진행 중 캡처의 실시간 갱신 개념이 없고, **현재 표시 중인 패킷**을 기준으로 계산된다. 표시 필터가 걸려 있으면 창 하단에 그 필터 문자열이 표시되므로, 전체 파일의 그림을 보려면 먼저 필터를 지운다.

### 2단계 — 컬럼 의미

| 컬럼 | 정의 | 실전에서 쓰는 방법 |
| --- | --- | --- |
| `Protocol` | 프로토콜 이름. 들여쓰기가 계층 관계다 | 트리의 깊이로 해석 성공 여부를 판단 |
| `Percent Packets` | 전체 패킷 대비 이 프로토콜을 **포함한** 패킷 비율 | 상대 비중. 합계는 100%를 넘는다 |
| `Packets` | 이 프로토콜을 포함한 패킷의 총 개수 | 과다 프로토콜 탐지 |
| `Percent Bytes` | 전체 바이트 대비 비율 | 데이터가 어디 실렸는지 |
| `Bytes` | 이 프로토콜의 총 바이트 | **파일 전송 판정의 1순위 지표** |
| `Bits/s` | 캡처 시간 기준 이 프로토콜의 대역폭 | 지속적 대량 전송 여부 |
| `End Packets` | 이 프로토콜이 **스택의 최상위였던**(마지막으로 해석된) 패킷의 절대 개수 | 여기서 해석이 끝난 양 |
| `End Bytes` | 같은 조건의 절대 바이트 수 | **해석되지 못한 페이로드의 크기** |
| `End Bits/s` | 같은 조건의 대역폭 | 위와 동일 |
| `PDUs` | 이 프로토콜의 PDU 총 개수 | 한 패킷에 여러 PDU 가 들어가면 Packets 보다 커진다 |

### 3단계 — End Packets / End Bytes 가 이 창의 핵심이다

`Packets` 와 `End Packets` 의 차이를 이해하면 이 창의 절반을 얻는다.

```text
    Transmission Control Protocol   Packets 15125   End Packets 12761
      Hypertext Transfer Protocol   Packets   631   End Packets   512
        Line-based text data        Packets    78   End Packets    78
        Media Type                  Packets    41   End Packets    41
```

- `TCP` 의 `Packets` 15,125 는 "TCP 헤더를 가진 모든 패킷" 이다. ACK, SYN, 재전송, 상위 프로토콜 패킷이 전부 포함된다.
- `TCP` 의 `End Packets` 12,761 은 "TCP 까지만 해석되고 그 위가 없던 패킷" 이다. **순수 ACK 와 미해석 페이로드가 여기 모인다.**
- `Line-based text data` 는 항상 `Packets == End Packets` 다. 그 아래에 아무것도 없으므로.

판정 규칙 두 개.

| 관찰 | 해석 |
| --- | --- |
| `TCP` 의 `End Bytes` 가 전체 바이트의 큰 비중 | 상위 파서가 읽지 못한 페이로드가 크다. 비표준 포트 HTTP, 커스텀 C2, 암호화 페이로드 후보 → `Decode As` 또는 Follow Stream |
| `TCP` 의 `End Packets` 는 많은데 `End Bytes` 는 작다 | 그냥 ACK 다. 정상 |

`End Bytes` 가 큰 `TCP` 행을 보고 필터를 만드는 방법.

```text
data
data.len > 32
tcp.len > 0 && !http && !tls
```

`data` 필터는 "Wireshark 가 최종적으로 미해석 바이트로 처리한 부분" 을 잡는다. `data.len` 으로 크기 하한을 주면 잡음이 사라진다.

### 4단계 — 읽는 순서

```text
(1) 트리 최상단 Frame / Ethernet / IPv4 의 Packets 로 전체 규모를 잡는다
(2) Bytes 내림차순으로 머릿속 정렬 -> 1위가 "데이터가 있는 곳"
(3) Packets 로 다시 훑는다        -> 1위가 "빈도가 이상한 곳"
(4) (2)와 (3)이 다른 프로토콜이면 문제는 대개 두 개다
(5) End Bytes 가 data / Line-based text data 에 몰려 있으면 파서 우회 라인
(6) 리스트에 있으면 안 되는 프로토콜을 눈으로 스캔한다
```

`(4)` 가 실전에서 가장 자주 나온다. 큰 파일 전송(FTP/HTTP)과 은닉 채널(DNS/ICMP)이 같은 캡처에 함께 들어 있는 문제 구성이 흔하다.

### 5단계 — 이상 판정 기준

정상 브라우징 캡처의 대략적인 모습과 비교한다. (환경마다 다르므로 절대 기준이 아니라 **비율 감각**으로 쓴다.)

| 프로토콜 | 정상 브라우징에서 | 이상하다고 볼 만한 상태 | 의심 |
| --- | --- | --- | --- |
| TLS | 패킷·바이트 모두 최대 비중 | 아예 없다 | 평문 통신만 하는 환경 = 조작된 캡처 또는 내부망 |
| HTTP | 소수. 대부분 TLS 로 감 | 바이트 비중 1위 | 파일 다운로드/업로드 |
| DNS | 전체 패킷의 수 % 이내 | **10% 이상, 또는 수천 패킷** | DNS 터널링 ([FOR-0155](./dns-tunneling.html)) |
| ICMP | 거의 0 | 수백~수천 패킷, `data` 동반 | ICMP 터널링, ping sweep |
| ARP | 소수 | 폭증 | ARP 스캔/스푸핑 |
| TCP `End Bytes` | 작다 (ACK 뿐) | 전체 바이트의 상당 부분 | 미해석 페이로드 = 커스텀 프로토콜 |
| `data` | 없거나 극소 | 존재하고 `End Bytes` 가 크다 | 파서가 못 읽는 채널 |
| `Line-based text data` | HTTP 응답 본문 정도 | 비중이 크다 | 평문 텍스트 대량 전송 (스크립트, 명령 결과) |
| Telnet / FTP / TFTP / IRC | 없다 | 존재한다 | 존재 자체가 답에 가깝다 |
| NBNS / LLMNR / MDNS | 내부망이면 정상 | 외부로 나간다 | 정보 유출/열거 |
| SMB2 | 내부망이면 정상 | 외부 IP 와 445 | 유출 경로 |

`data` 와 `Line-based text data` 의 정확한 의미를 구분한다.

| 행 이름 | 의미 |
| --- | --- |
| `Data` (`data`) | 어떤 dissector 도 해석하지 못한 바이트 덩어리. 필터는 `data`, 길이는 `data.len` |
| `Line-based text data` | 텍스트로는 보이지만 구조를 모르는 본문. 주로 HTTP 응답 본문(HTML, JS, 텍스트) |
| `Media Type` | Content-Type 은 알지만 전용 파서가 없는 본문. 이미지·바이너리 첨부 |
| `Malformed Packet` | 파서가 중간에 실패. 조작된 패킷 또는 잘린 캡처 ([FOR-0151](./expert-information.html)) |

### 6단계 — 행 우클릭으로 필터 만들기

행에서 우클릭하면 그 프로토콜에 대한 필터를 바로 만들 수 있다.

```text
행 우클릭
  Apply as Filter   > Selected / Not Selected / ... and Selected / ... or Selected
  Prepare as Filter > (적용하지 않고 입력창에만 넣는다)
  Copy              > 창 내용을 CSV / YAML 로
```

손으로 프로토콜 필터 이름을 타이핑하지 않는다. `Line-based text data` 의 필터 이름이 `data-text-lines` 라는 것을 외울 필요가 없어진다.

### 7단계 — 필터를 적용한 상태의 계층 통계

이 창의 진짜 힘은 **필터와 조합할 때** 나온다.

```text
(1) 메인 필터창:  ip.addr == 10.0.0.15
(2) Statistics > Protocol Hierarchy 를 다시 연다
    -> 그 호스트 하나가 쓴 프로토콜만 보인다
```

용도.

| 필터 | 무엇을 알 수 있나 |
| --- | --- |
| `ip.addr == <의심 호스트>` | 그 호스트가 어떤 프로토콜을 썼는가 = 행위 프로파일 |
| `ip.addr == <외부 IP>` | 외부와의 통신이 무엇으로 이루어졌는가 |
| `tcp.stream eq 7` | 한 세션이 어떤 계층까지 해석되는가 |
| `frame.time >= "2026-03-14 07:30:00"` | 특정 구간의 프로토콜 구성 변화 |
| `!(ip.addr == 10.0.0.0/8)` | 외부로 나간 트래픽만의 구성 |

CLI 에서는 `-z io,phs` 에 필터를 붙인다.

```bash
tshark -r capture.pcapng -q -z io,phs,ip.addr==10.0.0.15
tshark -r capture.pcapng -q -z 'io,phs,!(arp || icmp)'
```

`-z io,phs` 의 필터는 메인 `-Y` 필터와 **독립적으로** 계산된다. 두 개를 동시에 써도 서로 영향을 주지 않으므로, 의도한 대로 나오지 않으면 필터를 `-z` 쪽에 붙였는지 확인한다.

## 출력 필드 해석

`tshark -q -z io,phs` 의 출력은 GUI 와 같은 트리다.

```text
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:18422 bytes:12894011
  ip                                     frames:18311 bytes:12851233
    tcp                                  frames:15125 bytes:11204418
      http                               frames:631   bytes:1892044
        data-text-lines                  frames:78    bytes:412009
        media                            frames:41    bytes:983221
      ftp-data                           frames:1621  bytes:8104332
      ftp                                frames:112   bytes:11204
      data                               frames:96    bytes:271882
    udp                                  frames:3186  bytes:264880
      dns                                frames:3112  bytes:258110
    icmp                                 frames:171   bytes:28442
  arp                                    frames:111   bytes:42778
===================================================================
```

CLI 출력에서 유의할 점.

| 항목 | 설명 |
| --- | --- |
| 표시 이름 | GUI 는 `Hypertext Transfer Protocol`, CLI 는 **필터 이름** `http` 를 쓴다. 필터를 만들 때는 CLI 이름이 그대로 쓰인다 |
| `Line-based text data` | CLI 에서는 `data-text-lines` |
| `Media Type` | CLI 에서는 `media` |
| `Data` | CLI 에서도 `data` |
| `Filter:` 줄 | `-z io,phs,<filter>` 로 준 필터가 여기 표시된다. 비어 있으면 전체 파일 기준 |
| End 컬럼 | CLI 기본 출력에는 End Packets/End Bytes 컬럼이 없다. 필요하면 GUI 를 쓰거나 `frame.protocols` 집계로 대체한다 |

End 정보에 해당하는 CLI 대체 수단은 `frame.protocols` 집계다. 이것은 각 프레임의 **프로토콜 스택 전체**를 콜론으로 이어 준다.

```bash
tshark -r capture.pcapng -T fields -e frame.protocols | sort | uniq -c | sort -nr | head -15
```

```text
  10842 eth:ethertype:ip:tcp
   3112 eth:ethertype:ip:udp:dns
   1621 eth:ethertype:ip:tcp:ftp-data
    512 eth:ethertype:ip:tcp:http
    171 eth:ethertype:ip:icmp:data
    111 eth:ethertype:arp
     96 eth:ethertype:ip:tcp:data
     78 eth:ethertype:ip:tcp:http:data-text-lines
```

각 줄의 **마지막 토큰이 그 프레임의 최상위 프로토콜**이므로, 이 집계가 곧 End Packets 다. `eth:ethertype:ip:tcp` 10,842건이 TCP 에서 끝난 패킷(대부분 ACK)이고, `...:tcp:data` 96건이 미해석 페이로드다.

## pivot: 다음에 볼 artifact

| Protocol Hierarchy 에서 본 것 | 다음에 할 일 |
| --- | --- |
| `Bytes` 1위가 `ftp-data` / `http` | [FOR-0149](./conversations.html) 로 그 대화를 찾고 Follow Stream / Export Objects |
| `dns` 패킷이 수천 개 | `dns.qry.name` 을 빈도순으로 뽑는다 ([FOR-0153](./dns-qry-name-filter.html)) |
| `dns` 서브도메인이 길다 | DNS 터널링 판정 ([FOR-0155](./dns-tunneling.html)) |
| `icmp` 과다 + `data` | `icmp && data.len > 32` 로 페이로드 확인 |
| `data` / `data-text-lines` 의 `End Bytes` 가 크다 | `data` 필터 → Follow TCP Stream → `Decode As` 시도 |
| `Malformed Packet` 존재 | [FOR-0151](./expert-information.html) 로 캡처 신뢰도 먼저 판정 |
| `http` 존재 | `http.request` → Export Objects, POST 는 [FOR-0158](./http-post-find.html) |
| `arp` 폭증 | `arp.opcode == 1` 로 스캔 범위 확인 |
| Telnet / FTP 평문 | Follow TCP Stream 이 곧 자격증명 |
| 프로토콜 목록에 외부 IP 가 낀 내부 프로토콜 | [FOR-0150](./endpoints.html) 로 IP 를 뽑아 다른 artifact 로 pivot |

## 흔한 함정

- **퍼센트 합이 100%를 넘는다고 버그로 오해하는 것.** 한 패킷은 여러 프로토콜을 동시에 포함하므로 `Percent Packets` 의 합은 당연히 100%를 넘는다. IPv4 100% + TCP 82% + HTTP 3% 는 정상이다.
- **상위 프로토콜 `Packets` 합이 부모와 안 맞는다고 놓친 패킷을 찾는 것.** 재조립 때문에 상위 PDU 가 다른 프레임에서 완성되고, TCP 헤더 오버헤드와 미해석 데이터가 따로 계산된다. 합이 안 맞는 것이 정상이다.
- **`End Packets` 를 그냥 `Packets` 의 다른 표현으로 읽는 것.** "그 계층에서 끝난" 양이다. TCP 의 `End Bytes` 가 크면 반드시 미해석 페이로드를 열어 봐야 한다.
- **필터가 걸린 상태로 창을 열고 전체 통계라고 믿는 것.** 통계는 표시 중인 패킷 기준이다. 창 하단의 `Filter` 표시를 확인하고, 전체를 보려면 필터를 지운다.
- **비중이 작은 프로토콜을 무시하는 것.** 18,000개 중 12개뿐인 Telnet 이 정답인 문제가 흔하다. **비중이 아니라 존재 여부**로 판단해야 하는 프로토콜 목록(Telnet/FTP/TFTP/IRC)을 따로 본다.
- **`http` 행이 없으면 HTTP 가 없다고 결론 내리는 것.** 비표준 포트의 HTTP 는 `tcp` 에서 끝나 `data` 로 잡힌다. `End Bytes` 가 큰 `tcp` 를 보면 `Decode As` 를 떠올린다 ([FOR-0147](./capture-vs-display-filter.html)).
- **GUI 표시 이름을 그대로 필터에 넣는 것.** `Line-based text data` 는 필터 이름이 아니다. `data-text-lines` 다. 행 우클릭 `Apply as Filter` 를 쓴다.
- **`Bytes` 만 보고 끝내는 것.** 은닉 채널은 바이트가 작다. `Packets` 기준으로 한 번 더 훑어야 DNS/ICMP 터널링이 보인다.
- **TLS 가 대부분이라 포기하는 것.** TLS 비중이 정상적으로 높은 것과, TLS 안에 숨은 비정상 세션이 있는 것은 다르다. Conversations 로 목적지별 바이트를 봐야 판단된다.
- **`icmp` 아래 `data` 를 못 보는 것.** 트리를 접어 두면 하위 행이 숨는다. 창을 열면 모든 노드를 펼치고 본다.

## 교차검증

```bash
# 1) GUI Protocol Hierarchy 와 같은 값
tshark -r capture.pcapng -q -z io,phs

# 2) End Packets 상당물 — 각 프레임의 최상위 프로토콜 집계
tshark -r capture.pcapng -T fields -e frame.protocols | sort | uniq -c | sort -nr

# 3) 특정 호스트만의 프로토콜 구성
tshark -r capture.pcapng -q -z io,phs,ip.addr==10.0.0.15

# 4) 미해석 페이로드가 실제로 얼마나 되는가
tshark -r capture.pcapng -Y 'data.len > 32' -T fields -e frame.number -e ip.src -e ip.dst -e data.len | head

# 5) 시간 구간별 프로토콜 변화 (60초 버킷, 프로토콜별 프레임 수)
tshark -r capture.pcapng -q -z io,stat,60,'FRAMES()dns','FRAMES()http','FRAMES()icmp'

# 6) 파서를 완전히 우회한 확인
strings -n 8 capture.pcapng | grep -Ei 'HTTP/1\.|USER |PASS |flag\{' | head
```

`(2)` 와 GUI 의 `End Packets` 가 크게 다르면 재조립 설정이나 `Decode As` 상태가 GUI 쪽에만 적용되어 있는 것이다. `(5)` 는 "정상 구간과 이상 구간이 시간으로 나뉘는" 문제에서 결정적이다.

## mini walkthrough

```text
문제:
"이 캡처에는 정상 업무 트래픽과 공격자의 C2 통신이 섞여 있다.
 C2 서버의 IP 와 사용된 포트를 구하세요."
첨부: office.pcapng (24,908 packets, 31 MB)

1. 첫 시도 (실패)
   패킷 목록에서 Protocol 컬럼을 정렬해 눈으로 훑었다.
   TLS 가 대부분이고 HTTP 몇 개, DNS 몇 개.
   "TLS 뿐이니 내용은 못 본다" 고 판단하고 SNI 를 전부 뽑았다.
   -> 전부 microsoft.com, google.com, 사내 도메인. 수상한 것이 없다.
   원인: 눈으로 본 Protocol 컬럼은 "그 패킷의 최종 프로토콜" 이라
        비중을 보여주지 않는다. 그리고 C2 는 TLS 가 아니었다.

2. 접근 변경 — Statistics > Protocol Hierarchy (필터 비운 상태)

   Protocol                     Percent Packets  Packets  Percent Bytes  Bytes      End Packets  End Bytes
   Frame                        100.0            24908    100.0          31402118   0            0
    Ethernet                    100.0            24908      1.1           348712    0            0
     Internet Protocol Ver 4     99.6            24801      1.6           496020    0            0
      Transmission Control Prot  96.2            23962     92.3         28983664   19884        4127554
       Transport Layer Security  58.1            14471     78.0         24493651   14471       24493651
       Hypertext Transfer Proto   1.4              349      2.1           659444      302         88112
        Line-based text data      0.2               61      0.4           125611       61        125611
       Data                       0.9              228      8.9          2795880      228      2795880   <-- 여기
      User Datagram Protocol      3.4              839      0.9           282640    0            0
       Domain Name System         3.3              812      0.8           251200      812        251200
      Internet Control Message    0.0                4      0.0              392        4          392

   눈에 걸리는 것:
     - Data 행이 존재한다. 228 패킷 / 2.79 MB.
       End Bytes 2,795,880 = 전체 바이트의 8.9%.
       Wireshark 가 전혀 해석하지 못한 데이터가 2.8 MB 있다.
     - TCP 의 End Bytes 4,127,554 도 크다.
       순수 ACK 이라면 이만큼 크지 않다.

3. Data 행 우클릭 > Apply as Filter > Selected
   필터창: data
   -> 228 패킷. 목적지가 한 곳으로 수렴한다.

4. 필터를 좁힌다
   data.len > 64
   Source/Destination 컬럼:
     10.0.0.42 <-> 198.51.100.77   포트 8443

5. Statistics > Conversations 로 확정
   10.0.0.42:51442  <-> 198.51.100.77:8443   228 packets  2,795,880 bytes  stream 61

6. 왜 TLS 로 잡히지 않았는가
   8443 은 Wireshark 기본 TLS 포트가 아니다. 그리고 페이로드가
   TLS 핸드셰이크로 시작하지도 않았다 -> data 로 떨어졌다.

   패킷 우클릭 > Follow > TCP Stream (Show data as = Hex Dump)
   -> 앞부분이 고정 8바이트 헤더 + Base64 로 보이는 본문.
      TLS 가 아닌 커스텀 프로토콜. C2 확정.

7. 필터를 걸고 계층 통계를 다시 본다 (구간 검증)
   메인 필터: ip.addr == 198.51.100.77
   Statistics > Protocol Hierarchy
   -> tcp 228 / data 228. 이 IP 와의 통신은 100% 미해석 데이터다.
      정상 서비스라면 이런 구성이 나오지 않는다.

8. CLI 재확인
   $ tshark -r office.pcapng -T fields -e frame.protocols | sort | uniq -c | sort -nr | head -5
     19884 eth:ethertype:ip:tcp
     14471 eth:ethertype:ip:tcp:tls
       812 eth:ethertype:ip:udp:dns
       302 eth:ethertype:ip:tcp:http
       228 eth:ethertype:ip:tcp:data     <- End Packets 와 일치

정답: 198.51.100.77 / TCP 8443

핵심은 1단계의 실패다. Protocol 컬럼을 눈으로 훑으면 0.9% 짜리 Data 행은
절대 보이지 않는다. 반면 End Bytes 8.9% 는 Protocol Hierarchy 에서 즉시 눈에 띈다.
```

## 막혔을 때 다음 체크

1. 필터 입력창을 비운 상태로 창을 열었는가 — 통계는 표시 중인 패킷 기준이다
2. 모든 트리 노드를 펼쳤는가 — 접힌 하위 행에 답이 있다
3. `Bytes` 기준과 `Packets` 기준을 **둘 다** 훑었는가
4. `End Bytes` 가 `data` / `data-text-lines` / `tcp` 에 몰려 있는가
5. 목록에 Telnet, FTP, TFTP, IRC, SMB1 같은 "있으면 안 되는" 프로토콜이 있는가
6. `dns` 나 `icmp` 의 패킷 수가 트래픽 성격에 비해 과다한가
7. `http` 행이 없는데 웹 트래픽이 있어야 할 상황인가 → `Decode As`
8. `Malformed Packet` 행이 있는가 → [FOR-0151](./expert-information.html)
9. 의심 호스트 하나로 필터를 걸고 계층 통계를 다시 봤는가
10. `frame.protocols` 집계와 GUI 값이 일치하는가
11. 시간 구간을 나눠(`-z io,stat,60,...`) 프로토콜 구성이 변하는 지점을 찾았는가
12. 목표 프로토콜을 정했으면 [FOR-0149](./conversations.html) 로 넘어갔는가

## 출처

- SRC-003 — Wireshark User's Guide, "The Protocol Hierarchy Window": 컬럼 정의 원문(`Protocol`, `Percent Packets`, `Packets`, `Percent Bytes`, `Bytes`, `Bits/s`, `End Packets`, `End Bytes`, `End Bits/s`, `PDUs`)과 "the highest protocol in the stack (last dissected)" 라는 End 컬럼의 정의, 퍼센트 합이 100%를 넘을 수 있는 이유, 재조립·TCP 오버헤드로 상위 계층 합이 부모와 어긋난다는 주의사항, 표시 필터가 설정되면 창 하단에 표시된다는 점, Copy 버튼의 CSV/YAML 출력
- SRC-010 — tshark man page: `-z io,phs[,filter]`, `-z io,stat,interval[,filter]` 및 `FRAMES()`/`BYTES()` 형식, `-q`, `-T fields`, `-e frame.protocols`
- `PDUs` 컬럼과 행 우클릭 컨텍스트 메뉴(`Apply as Filter` / `Prepare as Filter`)는 최근 버전에서 제공되며 버전에 따라 항목 구성이 다를 수 있으므로 실제 화면에서 확인할 것
- "정상 브라우징에서의 프로토콜 비중" 표는 절대 기준이 아니라 판단용 비율 감각이다. 환경(내부망/외부망, OS, 보안 제품)에 따라 크게 달라진다
