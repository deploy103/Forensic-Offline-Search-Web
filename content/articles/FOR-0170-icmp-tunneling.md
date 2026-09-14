---
id: FOR-0170
title: "ICMP tunneling 탐지하기"
slug: "icmp-tunneling"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "ICMP Echo", "covert channel"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["ICMP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y icmp -T fields -e frame.time_relative -e icmp.type -e data.len", "tshark -r capture.pcapng -q -z io,stat,10,icmp", "tshark -r capture.pcapng -Y icmp -T fields -e icmp.ident | sort | uniq -c | sort -nr"]
regex_patterns: []
wireshark_filters: ["icmp", "icmp.type == 8", "icmp.type == 0", "icmp && data.len > 64", "icmp && !(data.len == 32)", "icmp.ident == 0x0001"]
tshark_fields: ["icmp.type", "icmp.code", "icmp.ident", "icmp.seq_le", "data.len", "data.data", "frame.time_relative", "ip.ttl"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["icmp tunneling", "icmp 터널링"]
keywords: ["ICMP tunneling", "ICMP 터널링", "covert channel", "ping tunnel", "ptunnel", "icmpsh", "C2", "은닉 채널", "data.len 분포", "beacon", "icmp.ident"]
aliases: ["핑 터널링", "icmp로 데이터 빼내기", "ping tunnel 탐지", "icmp c2", "icmp 은닉 채널", "핑 안에 명령어"]
symptom_keywords: ["icmp 개수가 비정상적으로 많다", "ping이 계속 오간다", "icmp로 우회한 것 같다", "방화벽을 icmp로 우회했다", "icmp 트래픽이 지속적이다"]
related: ["FOR-0169", "FOR-0176", "FOR-0155", "FOR-0146"]
source_ids: ["SRC-067", "SRC-002", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

ICMP tunneling 은 방화벽이 흔히 허용하는 ping 트래픽 안에 임의 데이터를 실어 나르는 은닉 채널이며, **정상 ping 대비 비정상적으로 많은 패킷 수, 표준을 벗어난 `data.len`, 불규칙한 `icmp.ident`, 그리고 요청·응답이 짝을 이루지 않는 패턴**으로 식별한다.

## 어떤 문제에서 필요한가

- Protocol Hierarchy 에서 ICMP 패킷 수가 수백~수천 개로 비정상적으로 많은 pcap
- "방화벽을 우회해서 데이터를 빼냈다", "C2 채널을 찾아라" 류의 지문
- ptunnel, icmpsh, icmp-backdoor 같은 도구의 흔적이 의심되는 상황
- ICMP 요청은 많은데 정상적인 응답 비율이 맞지 않는 캡처

**정상적인 ping 은 요청 하나에 응답 하나, 사람이 몇 번 실행하고 끝난다.** 자동화된 지속적 ICMP 트래픽은 그 자체로 의심 대상이다.

## 문제에서 처음 볼 단서

1. **ICMP 패킷 절대 개수** — 수백 개를 넘으면 사람이 수동으로 ping 한 것이 아니다
2. **캡처 전체 시간 대비 ICMP 지속성** — 캡처 시작부터 끝까지 일정한 간격으로 이어지면 자동화된 채널
3. **Echo Request 대 Echo Reply 비율** — 1:1 이 아니면 비정상 (터널링 도구는 응답에도 데이터를 실어 반대 방향 채널로 쓴다)
4. **`data.len` 값의 다양성** — 표준 ping 은 크기가 고정이다. 여러 값이 섞이면 가변 길이 메시지 전송
5. **패킷 간 시간 간격의 규칙성** — 정확히 일정한 간격(비콘)이거나, 반대로 사람이 만든 것보다 훨씬 촘촘하면 스크립트

## 30초 절차

```bash
tshark -r capture.pcapng -q -z io,stat,10,icmp
```

10초 구간별 ICMP 개수를 본다. 캡처 전 구간에 걸쳐 꾸준히 나오면 자동화된 채널이다. 특정 구간에만 몰려 있으면 일회성 전송이다.

GUI 3단계:

```text
1. Statistics > Protocol Hierarchy      -> ICMP Packets 절대 개수 확인
2. Statistics > IO Graph, Y축을 icmp 로 설정 -> 시간대별 분포 확인
3. 필터: icmp.type == 8 그리고 icmp.type == 0 개수 비교 -> 짝이 맞는지
```

## 상세 절차

### 1단계 — "정상 ping 사용"과 "터널링"을 개수로 가른다

| 관측 | 정상 ping (사람이 수동 실행) | ICMP 터널링 |
| --- | --- | --- |
| 총 패킷 수 | 수 개 ~ 수십 개 (기본 4회 등) | 수백 ~ 수만 개 |
| 지속 시간 | 캡처의 일부 구간에만 짧게 | 캡처 전체 또는 긴 구간에 걸쳐 지속 |
| `data.len` | 고정값 하나 | 여러 값이 섞이거나 표준과 다른 고정값 |
| Request:Reply 비율 | 1:1 | 1:1 이 아니거나, 양쪽 모두 큰 payload |
| TTL(`ip.ttl`) | 홉 수만큼 일정 | 터널 클라이언트/서버가 고정이면 일정하지만, 프록시를 거치면 변동 |

이 표의 "정상"과 "터널링" 값은 절대 기준이 아니라 **상대 비교용**이다. 캡처 안에서 다른 정상 ICMP 트래픽이 있다면 그것과 대조하는 것이 가장 정확하다.

### 2단계 — 요청/응답 비대칭을 확인한다

```text
icmp.type == 8
```

```text
icmp.type == 0
```

각각의 개수를 세어 비교한다.

```bash
tshark -r capture.pcapng -Y 'icmp.type == 8' -T fields -e frame.number | wc -l
tshark -r capture.pcapng -Y 'icmp.type == 0' -T fields -e frame.number | wc -l
```

정상 ping 은 요청과 응답 수가 거의 같다. 터널링 도구는 종종 **양방향 모두에 데이터를 실어**(질의는 Request, 응답은 Reply 페이로드에 명령 실행 결과) 두 방향 모두 payload 가 크고 다양하다. 반대로 응답이 거의 없는데 요청만 계속 나가면 일방적 유출(exfiltration) 채널일 수 있다.

### 3단계 — payload 크기 분포로 프로토콜성을 판단한다

```bash
tshark -r capture.pcapng -Y icmp -T fields -e data.len | sort -n | uniq -c | sort -nr
```

| 분포 | 해석 |
| --- | --- |
| 값 하나에 100% 집중, 표준값(32/48/56)과 일치 | 정상 ping |
| 값 하나에 집중하지만 표준값과 다름(예: 전부 100바이트) | 커스텀 고정 프레임 프로토콜. 터널링 도구가 프레임 크기를 고정한 경우 |
| 여러 값에 분산 | 가변 길이 명령/데이터 전송 |
| 최댓값이 MTU 근처(1400바이트 이상) | 대량 데이터 전송 구간. 파일 유출 의심 |

### 4단계 — 시간 간격으로 비콘/스크립트 여부를 확인한다

```bash
tshark -r capture.pcapng -Y 'icmp.type == 8' -T fields -e frame.time_relative | \
  awk 'NR>1{print $1-prev} {prev=$1}'
```

간격이 거의 균일한 값(예: 항상 1.000초 근처)으로 반복되면 스크립트/비콘이다. 사람이 직접 `ping` 명령을 반복 실행했다면 간격이 들쭉날쭉하다.

### 5단계 — ident 로 세션을 분리하고 내용을 재조립한다

```bash
tshark -r capture.pcapng -Y icmp -T fields -e icmp.ident | sort | uniq -c | sort -nr
```

하나의 `icmp.ident` 에 수백 개 패킷이 몰려 있으면 그것이 하나의 지속 세션이다. 그 ident 로 좁혀 [FOR-0169](./icmp-payload.html) 의 방법으로 payload 를 이어 붙인다.

```bash
tshark -r capture.pcapng -Y 'icmp.ident == 0x0001' \
  -T fields -e icmp.seq_le -e data.data | sort -n | awk '{print $2}' | tr -d '\n' | xxd -r -p
```

명령 실행 결과나 셸 프롬프트 문자열(`$`, `#`, `C:\>`)이 나오면 ICMP 기반 리버스 셸/C2 확정이다.

### 6단계 — TTL 이상으로 프록시/중계 여부를 본다

```bash
tshark -r capture.pcapng -Y icmp -T fields -e ip.src -e ip.ttl | sort | uniq -c
```

같은 출발지 IP 인데 TTL 값이 여러 개 섞여 있으면, 홉 수가 다른 경로로 온 패킷이 섞였거나 **IP 스푸핑**을 의심할 수 있다. 단, 운영체제 재부팅이나 경로 변경만으로도 TTL 이 바뀔 수 있으므로 단독 근거로는 약하다.

## 출력 필드 해석

| 필드 | 의미 | 확인 포인트 |
| --- | --- | --- |
| `icmp.type` | 8/0 요청·응답 | 비율 비대칭 확인 |
| `icmp.ident` | 세션 식별자 | 값 하나에 대량 집중 = 지속 채널 |
| `icmp.seq_le` | 순서 | 재조립 순서 |
| `data.len` | payload 크기 | 분포로 프로토콜성 판단 |
| `frame.time_relative` | 캡처 시작 기준 상대 시각 | 간격 계산, 비콘 판정 |
| `ip.ttl` | 홉 수 관련 값 | 경로 일관성, 스푸핑 의심 |

## pivot: 다음에 볼 artifact

| ICMP 터널링에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| 재조립된 명령/데이터 | flag 확인 또는 실행된 명령 목록 확보 |
| 터널 서버로 추정되는 외부 IP | 그 IP 로의 다른 프로토콜 트래픽 → [FOR-0182](./ip-addr-filter.html) |
| 지속적 채널 확인됨 | 같은 시간대 다른 은닉 채널(DNS)도 확인 → [FOR-0155](./dns-tunneling.html) |
| 비콘 간격 값 | 엔드포인트 프로세스/스케줄 작업 확인 → [FOR-0100](./sysmon-event-3-network-connect.html) |
| 유출된 데이터 조각 | 원본 파일 복원 시도, 크기 대조 |

## 흔한 함정

- **ICMP 패킷 몇 개를 보고 "정상 ping" 이라 단정하는 것.** 반드시 전체 개수와 지속 시간을 함께 본다. 짧게 보면 정상처럼 보여도 전체 캡처에서는 수천 개일 수 있다.
- **요청과 응답 비율을 확인하지 않는 것.** 정상 ping 은 1:1 이다. 크게 벗어나면 데이터가 실려 있다는 신호다.
- **`data.len` 이 고정이라고 정상으로 판단하는 것.** 표준값(32/48/56)과 다른 고정 크기는 오히려 **커스텀 프로토콜이 고정 프레임을 쓰는 것**일 수 있다. 값 자체를 표준과 비교해야 한다.
- **TTL 변동만으로 스푸핑을 단정하는 것.** 경로 변경이나 재부팅으로도 TTL 은 바뀐다. 다른 근거와 함께 판단한다.
- **ICMP 만 보고 DNS 등 다른 은닉 채널을 확인하지 않는 것.** 한 캡처에 여러 은닉 채널이 동시에 있을 수 있다. Protocol Hierarchy 를 다시 훑는다.
- **재조립한 데이터가 평문이 아니라고 포기하는 것.** base64, hex, XOR 인코딩이 흔하다. 몇 가지 인코딩을 시도한 뒤에 판단한다.
- **캡처 중간 구간만 잘라 보고 지속성을 놓치는 것.** IO Graph 로 전체 캡처 구간의 ICMP 분포를 먼저 확인한다.
- **`icmp.ident` 를 무시하고 전체 캡처의 payload 를 한 번에 이어 붙이는 것.** 여러 세션이 섞이면 재조립 결과가 깨진다. ident 로 먼저 분리한다.

## 교차검증

```bash
# 1) 시간대별 ICMP 분포 - 지속성 확인
tshark -r capture.pcapng -q -z io,stat,10,icmp

# 2) 요청/응답 개수 비교
tshark -r capture.pcapng -Y 'icmp.type == 8' -T fields -e frame.number | wc -l
tshark -r capture.pcapng -Y 'icmp.type == 0' -T fields -e frame.number | wc -l

# 3) payload 크기 분포
tshark -r capture.pcapng -Y icmp -T fields -e data.len | sort -n | uniq -c | sort -nr

# 4) ident 별 패킷 집중도
tshark -r capture.pcapng -Y icmp -T fields -e icmp.ident | sort | uniq -c | sort -nr

# 5) 패킷 간격 - 비콘 판정
tshark -r capture.pcapng -Y 'icmp.type == 8' -T fields -e frame.time_relative | \
  awk 'NR>1{print $1-prev} {prev=$1}' | sort -n | uniq -c | sort -nr | head

# 6) TTL 일관성
tshark -r capture.pcapng -Y icmp -T fields -e ip.src -e ip.ttl | sort | uniq -c

# 7) 재조립
tshark -r capture.pcapng -Y 'icmp.ident == 0x0001' -T fields -e icmp.seq_le -e data.data \
  | sort -n | awk '{print $2}' | tr -d '\n' | xxd -r -p
```

## mini walkthrough

```text
문제:
"내부 호스트가 외부와 은닉 채널로 통신했다. 실행된 명령을 구하세요."
첨부: covert.pcapng (4,120 packets, 캡처 시간 20분)

1. 첫 시도 (실패) - ICMP 개수만 보고 넘어갔다
   Statistics > Protocol Hierarchy
     ICMP   38.2%   1573 packets
   "ping 이 좀 많지만 트러블슈팅이겠지" 라고 넘기고 TCP/HTTP 만 팠다.
   HTTP 에서는 이미지 몇 개, 정상 브라우징 뿐이었다.
   -> 진전 없음. 다시 ICMP 로 돌아왔다.

2. 접근 변경 - ICMP 지속성 확인
   tshark -r covert.pcapng -q -z io,stat,10,icmp
   -> 20분 캡처 내내 10초마다 거의 균일하게 ICMP 가 발생.
      사람이 수동으로 ping 한 것이라면 이렇게 고르게 나올 수 없다.

3. 요청/응답 비교
   Request(type 8): 787개, Reply(type 0): 786개 -> 거의 1:1.
   그러나 정상 ping 치고는 총량(1573개)이 너무 많다.

4. payload 크기 분포
   tshark -r covert.pcapng -Y icmp -T fields -e data.len | sort -n | uniq -c | sort -nr
        1420 40
         153 8

   -> 대부분 40바이트, 일부 8바이트. Windows 표준(32)도 Linux 표준(48/56)도 아니다.
      고정 프레임 40바이트 커스텀 프로토콜로 판단.

5. ident 분리 및 재조립
   tshark -r covert.pcapng -Y icmp -T fields -e icmp.ident | sort | uniq -c | sort -nr
        1573 0x0002
   -> 전부 같은 ident. 하나의 지속 세션이다.

   tshark -r covert.pcapng -Y 'icmp.type == 8 && icmp.ident == 0x0002' \
     -T fields -e icmp.seq_le -e data.data | sort -n | head -5
     1   77686f61 6d690000
     2   77686f61 6d690000
     3   6c730000 00000000

   -> "whoami" 명령이 여러 패킷에 반복되어 보인다. 요청 방향이 명령 전송,
      응답 방향(type 0)이 실행 결과일 가능성이 높다.

6. 응답 payload 확인
   tshark -r covert.pcapng -Y 'icmp.type == 0 && icmp.ident == 0x0002' \
     -T fields -e icmp.seq_le -e data.data | sort -n | awk '{print $2}' \
     | tr -d '\n' | xxd -r -p
   corp\backupsvc

정답: 실행된 명령 whoami, 결과 corp\backupsvc — ICMP 기반 리버스 셸(icmpsh 계열)로 판정
```

1단계의 실패가 핵심이다. **ICMP 비중을 "그냥 좀 많다"로 넘기면 은닉 채널을 놓친다.** `-z io,stat` 으로 지속성을 확인하는 습관이 이를 막아준다.

## 막혔을 때 다음 체크

1. `Statistics > Protocol Hierarchy` 에서 ICMP 절대 패킷 수를 확인했는가
2. `-z io,stat,10,icmp` 로 시간대별 지속성을 봤는가
3. Request:Reply 비율이 1:1 에서 크게 벗어나는가
4. `data.len` 분포가 표준값(32/48/56)과 다른가
5. `icmp.ident` 로 세션이 몇 개로 나뉘는지 확인했는가
6. 패킷 간격이 지나치게 균일한가 (비콘 판정)
7. 재조립한 payload 에 명령/셸 프롬프트 문자열이 있는가
8. TTL 값이 같은 출발지 IP 에서 흔들리는가
9. 다른 은닉 채널(DNS 터널링 등)도 같은 시간대에 있는가
10. 재조립 결과가 인코딩(base64/hex/XOR)되어 있는가

## 출처

- SRC-067 — RFC 792 (ICMP): Echo Request/Reply의 정상 용도(진단)와 페이로드 규정. 터널링은 이 규정을 벗어난 오용
- SRC-002 — Wireshark Display Filter Reference: `icmp.type`, `icmp.ident`, `icmp.seq_le`, `data.len`, `ip.ttl` 필드명 확인
- SRC-010 — tshark man page: `-z io,stat`, `-T fields -e`, `-Y` 필터 문법
- "정상 ping" 대비 패킷 수·간격의 구체적 임계값은 환경마다 다르다. 절대적 기준이 아니라 같은 캡처 내 다른 트래픽과의 상대 비교로 판단할 것
