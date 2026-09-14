---
id: FOR-0174
title: "SYN scan 포트 스캔 흔적 찾기: tcp.flags.syn == 1 && tcp.flags.ack == 0"
slug: "syn-scan-traces"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "SYN scan", "port scan"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y \"tcp.flags.syn==1 && tcp.flags.ack==0\" -T fields -e ip.src -e tcp.dstport", "tshark -r capture.pcapng -q -z conv,tcp"]
regex_patterns: []
wireshark_filters: ["tcp.flags.syn == 1 && tcp.flags.ack == 0", "tcp.flags.syn == 1 && tcp.flags.ack == 1", "tcp.flags.reset == 1", "tcp.flags.reset == 1 && tcp.flags.ack == 1", "tcp.analysis.retransmission"]
tshark_fields: ["tcp.flags", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.srcport", "tcp.dstport", "ip.src", "ip.dst", "ip.id"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["syn scan", "SYN 스캔 흔적"]
keywords: ["SYN scan", "포트 스캔", "half-open scan", "nmap -sS", "TCP flags", "SYN-ACK", "RST", "three-way handshake", "port scanning", "recon", "스캔 탐지", "tcp.flags.syn"]
aliases: ["syn 스캔", "포트 스캔 흔적", "nmap 스캔 탐지", "누가 포트 스캔했는지", "half open scan", "스캔 로그 pcap"]
symptom_keywords: ["같은 IP가 여러 포트로 SYN만 보낸다", "핸드셰이크가 완료 안 된 연결이 많다", "열린 포트 목록을 찾아야 한다", "누가 포트 스캔했는지 알아야 한다"]
related: ["FOR-0173", "FOR-0175", "FOR-0146", "FOR-0149"]
source_ids: ["SRC-066", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

SYN scan(half-open scan)은 완결된 3-way handshake 없이 짧은 시간에 한 소스가 여러 목적지 포트로 **SYN만** 보내는 패턴이다. `tcp.flags.syn == 1 && tcp.flags.ack == 0` 으로 SYN만 골라낸 뒤, 응답이 `SYN-ACK`인지 `RST-ACK`인지로 열린/닫힌 포트를 가른다.

## 어떤 문제에서 필요한가

- "공격자가 어떤 포트를 스캔했는가", "열린 포트 목록을 구하라" 유형의 문제
- pcap 안에 정상 트래픽과 스캔 트래픽이 섞여 있어 스캔 시작 시각과 스캐너 IP를 특정해야 하는 문제
- 스캔 도구(nmap 등)의 흔적을 다른 정상 접속과 구분해야 하는 문제

## 문제에서 처음 볼 단서

1. **Protocol Hierarchy에서 TCP 비중이 매우 높은데 HTTP/FTP 등 상위 프로토콜이 거의 없음** — 페이로드 없는 SYN/RST뿐이라는 뜻
2. **Conversations에서 한 소스 IP가 같은 목적지 IP의 수십~수천 개 포트에 각각 1~2개 패킷만 주고받음** — 정상 접속은 보통 한 포트에 수십 개 이상의 패킷이 오간다
3. **짧은 시간 범위에 패킷 수가 몰림** — 스캔은 보통 수 초~수십 초 안에 끝난다
4. **`Info` 컬럼에 `[SYN]`만 있고 그 뒤로 데이터 전송 패킷이 없음**

## 30초 절차

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

이 한 줄로 나온 프레임의 `ip.src`가 동일하고 `tcp.dstport`가 여러 개면 스캔이다. 이어서 GUI 3단계.

```text
1. Statistics > Conversations > TCP, Bytes 오름차순 정렬
   -> 패킷 수 1~3개짜리 대화가 대량으로 보이면 스캔 후보
2. 필터: tcp.flags.syn == 1 && tcp.flags.ack == 0
   -> ip.src가 하나로 고정되고 tcp.dstport가 흩어져 있는지 확인
3. 필터: tcp.flags.syn == 1 && tcp.flags.ack == 1
   -> 여기 나온 tcp.srcport(서버 관점 목적지 포트였던 값)가 열린 포트
```

## 상세 절차

### 1단계 — TCP 플래그 값과 필터 매핑

| 상태 | 플래그 조합 | Wireshark 필터 | Info 컬럼 |
| --- | --- | --- | --- |
| SYN 전송(스캔/접속 시도) | SYN=1, ACK=0 | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | `[SYN]` |
| 열린 포트 응답 | SYN=1, ACK=1 | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | `[SYN, ACK]` |
| 닫힌 포트 응답 | RST=1, ACK=1 | `tcp.flags.reset == 1 && tcp.flags.ack == 1` | `[RST, ACK]` |
| 필터링(방화벽 드롭) | 응답 없음 | 해당 SYN에 대응하는 RST/SYN-ACK가 전혀 없음 | 응답 자체가 없다 |
| half-open scan 정리 | RST=1 (클라이언트가 보냄) | `tcp.flags.reset == 1 && ip.src == <스캐너>` | `[RST]` |

RFC 9293이 정의하는 3-way handshake는 `SYN` → `SYN,ACK` → `ACK` 순서다. SYN scan은 마지막 `ACK`를 보내지 않고 대신 `RST`로 연결을 끊는다. 이것이 "half-open"이라는 이름의 유래이며, 애플리케이션 로그에 접속 기록이 남지 않는 이유이기도 하다.

### 2단계 — 열린 포트와 닫힌 포트를 실제로 나눈다

```bash
# 스캐너가 보낸 SYN의 목적지 포트 전체
tshark -r capture.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e ip.src -e ip.dst -e tcp.dstport

# 대상이 SYN-ACK로 응답한 포트 = 열린 포트
tshark -r capture.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==1' \
  -T fields -e ip.src -e tcp.srcport | sort -t$'\t' -k2 -n -u

# 대상이 RST-ACK로 응답한 포트 = 닫힌 포트
tshark -r capture.pcapng -Y 'tcp.flags.reset==1 && tcp.flags.ack==1' \
  -T fields -e ip.src -e tcp.srcport | sort -t$'\t' -k2 -n -u
```

출력 예시:

```text
203.0.113.10    22
203.0.113.10    80
203.0.113.10    443
```

여기서 `tcp.srcport`는 응답 패킷 기준이므로 **대상 서버 입장의 포트 번호**다. 즉 SYN-ACK 목록에 22/80/443이 있으면 그 서버는 이 세 포트가 열려 있다.

### 3단계 — 스캔 소스와 스캔 범위를 확정한다

```text
Statistics > Endpoints > IPv4
```

한 IP가 유독 많은 고유 목적지 포트와 대화한 것으로 나오면 그것이 스캐너다. 포트 범위(1~1024, 1~65535 전체 등)는 아래로 확인한다.

```bash
tshark -r capture.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e tcp.dstport | sort -n | uniq | tail -1
```

가장 큰 목적지 포트 번호가 65535에 가까우면 전체 포트 스캔, 1024 근처면 well-known 포트 스캔이다.

### 4단계 — connect scan(-sT)과 구분한다

| 구분 | SYN scan (half-open, `-sS`) | Connect scan (`-sT`) |
| --- | --- | --- |
| 핸드셰이크 완료 여부 | 미완료 (ACK 안 보냄) | 완료 (정상 3-way handshake) |
| 스캐너 쪽 마지막 패킷 | `RST` | `ACK` 후 곧바로 `FIN`/`RST` |
| 애플리케이션 레벨 접속 기록 | 남지 않음 | 서버 애플리케이션 로그에 남을 수 있음 |
| 필터로 구분 | 위 필터로 잡힘 | `tcp.flags.syn==1 && tcp.flags.ack==0` 뒤에 `tcp.flags.ack==1`(순수 ACK)도 이어짐 |

connect scan은 실제 연결이 맺어지므로 이 글의 필터만으로는 "스캔인지 정상 접속인지" 구분이 안 되고, 포트 수와 세션당 패킷 수(1~4개로 극히 적음)로 판단해야 한다.

## 출력 필드 해석

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| `tcp.flags.syn` | SYN 비트 (1 bit) | SYN-ACK에서도 1이므로 단독으로 스캔 판정에 쓰면 안 된다 |
| `tcp.flags.ack` | ACK 비트 | `syn==1 && ack==0`이어야 순수 SYN(연결 시작) |
| `tcp.flags.reset` | RST 비트 | 닫힌 포트 응답 또는 스캐너의 연결 정리 |
| `tcp.dstport` | 목적지 포트 | SYN 패킷 기준으로 보면 스캔 대상 포트 목록 |
| `tcp.srcport` | 출발지 포트 | SYN-ACK/RST-ACK 응답 패킷 기준으로 보면 서버의 실제 포트 |
| `ip.id` | IP 식별자 | 스캐너에 따라 순차 증가/랜덤. 여러 스캐너 IP를 하나의 도구로 묶을 때 보조 근거 |

## pivot: 다음에 볼 artifact

| SYN scan에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| 열린 포트 목록 | 그 포트로 이어지는 이후 트래픽([FOR-0175](./tcp-retransmission.html) 재조립 신뢰도 확인 후 Follow Stream) |
| 스캐너 IP | 방화벽/IDS 로그, 다른 pcap에서의 동일 IP 활동 |
| 스캔 시각(UTC) | 서버 access.log·EVTX 4625 등 같은 시각대 로그 |
| 스캔 후 즉시 이어지는 접속 | 그 포트의 서비스 트래픽이 공격의 본 목적일 가능성 |

## 흔한 함정

- **`tcp.flags.syn == 1` 만 쓰는 것.** SYN-ACK도 SYN 비트가 1이라 같이 걸린다. 반드시 `&& tcp.flags.ack == 0`을 붙인다.
- **재전송된 SYN을 별도 스캔 시도로 세는 것.** 네트워크 손실로 SYN이 재전송될 수 있다. `tcp.analysis.retransmission`이 붙은 프레임은 계수에서 제외한다([FOR-0175](./tcp-retransmission.html)).
- **connect scan을 SYN scan과 같은 필터로 확정 짓는 것.** connect scan도 첫 패킷은 SYN이다. 이어서 스캐너가 `ACK`(순수 ACK, 데이터 없음)을 보냈는지까지 확인해야 half-open인지 판단할 수 있다.
- **분산 스캔(여러 소스 IP)을 놓치는 것.** Conversations를 소스 IP 기준으로만 보면 각 IP가 소량이라 눈에 안 띈다. 목적지 포트 기준으로 그룹핑해 "같은 포트 집합을 여러 IP가 반복 조회"하는 패턴도 확인한다.
- **UDP 스캔을 이 필터로 찾으려는 것.** 이 필터는 TCP 전용이다. UDP 스캔은 ICMP Port Unreachable 응답으로 판별해야 하며 이 글의 범위 밖이다.
- **캡처가 서버 쪽에서만 떠져 클라이언트의 RST를 못 보는 경우.** 이때는 SYN-ACK만 보이고 그 뒤가 없는 패턴(응답 없음)으로 스캔을 판단해야 한다. 캡처 위치를 먼저 확인한다.
- **허니팟/모든 포트가 열린 것처럼 응답하는 서버를 정상 서버로 오인하는 것.** 모든 SYN에 SYN-ACK가 오면 실제 서비스보다 허니팟일 가능성을 의심한다.

## 교차검증

```bash
# 1) 소스 IP별 고유 목적지 포트 개수 — 스캐너 후보를 한 번에
tshark -r capture.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e ip.src -e tcp.dstport | sort -u | cut -f1 | sort | uniq -c | sort -nr

# 2) GUI Conversations와 동일한 대화 통계
tshark -r capture.pcapng -q -z conv,tcp

# 3) 열린 포트만 추출
tshark -r capture.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==1' \
  -T fields -e tcp.srcport | sort -n | uniq

# 4) 재전송 오염 여부 확인 후 재계산
tshark -r capture.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && !tcp.analysis.retransmission' \
  -T fields -e tcp.dstport | sort -n | uniq | wc -l
```

## mini walkthrough

```text
문제:
"공격자 IP와 대상 서버에서 열려 있던 포트를 모두 구하시오."
첨부: scan.pcapng (4,210 packets, 3초 구간에 집중)

1. 첫 시도 (실패)
   필터: tcp.flags.syn == 1
   결과: 2,050개 프레임 — SYN과 SYN-ACK가 섞여서 나왔다.
   목적지 포트가 1~65535에 걸쳐 흩어져 있어 열린 포트를 구분할 수 없었다.

2. 원인 파악
   Info 컬럼을 보니 결과에 [SYN] 과 [SYN, ACK] 이 함께 있었다.
   ACK 비트를 걸지 않은 것이 문제였다.

3. 필터 수정
   tcp.flags.syn == 1 && tcp.flags.ack == 0
   결과: 2,048개, 전부 ip.src == 198.51.100.23 로 동일.
   -> 198.51.100.23 이 스캐너.

4. 열린 포트 확인
   tcp.flags.syn == 1 && tcp.flags.ack == 1
   결과 3건:
     ip.src=203.0.113.5  tcp.srcport=22
     ip.src=203.0.113.5  tcp.srcport=80
     ip.src=203.0.113.5  tcp.srcport=443

5. 닫힌 포트도 확인해 전체 스캔 범위 검증
   tcp.flags.reset == 1 && tcp.flags.ack == 1
   결과: 2,045건, tcp.srcport 값이 1~2048 범위에 분포
   -> 1~2048 포트 스캔이었고 그중 3개만 열려 있었다.

정답: 스캐너 198.51.100.23 / 열린 포트 22, 80, 443
```

1단계의 실패는 `ACK` 비트를 걸지 않아 SYN-ACK까지 섞인 것이다. TCP 플래그는 항상 조합으로 확인한다.

## 막혔을 때 다음 체크

1. `tcp.flags.syn == 1 && tcp.flags.ack == 0`로 스캐너 IP가 하나로 고정되는가
2. `tcp.flags.syn == 1 && tcp.flags.ack == 1`로 열린 포트를 뽑았는가
3. `tcp.analysis.retransmission`을 제외하고 다시 세었는가
4. 캡처 위치가 서버/클라이언트 어느 쪽인지 — 한쪽 방향만 있으면 판정이 왜곡된다
5. connect scan 가능성을 배제했는가 — 스캐너의 순수 ACK 여부 확인
6. `Statistics > Endpoints`에서 목적지 포트 개수가 비정상적으로 많은 IP가 또 있는가(분산 스캔)
7. 스캔 시작/종료 시각을 UTC 절대시각으로 기록했는가 — 다른 로그와 대조할 때 필요

## 출처

- SRC-066 — RFC 9293 (TCP): 3-way handshake 순서, SYN/ACK/RST 플래그 의미와 half-open 연결 종료 동작
- SRC-002 — Wireshark Display Filter Reference: `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.reset` 필드명 확인
- SRC-003 — Wireshark User's Guide: Statistics > Conversations / Endpoints 사용법
