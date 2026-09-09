---
id: FOR-0175
title: "TCP 재전송 해석: tcp.analysis.retransmission 과 재조립 신뢰도"
slug: "tcp-retransmission"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "TCP stream", "Expert Information"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP"]
tools: ["Wireshark", "tshark", "editcap"]
commands: ["tshark -r capture.pcapng -Y \"tcp.analysis.flags\" -T fields -e frame.number -e tcp.stream -e ip.src -e ip.dst -e tcp.seq -e tcp.len", "tshark -r capture.pcapng -q -z expert", "editcap -d capture.pcapng dedup.pcapng"]
regex_patterns: []
wireshark_filters: ["tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission", "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order", "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment", "tcp.analysis.zero_window", "tcp.analysis.window_full", "tcp.analysis.keep_alive", "tcp.analysis.flags", "tcp.analysis.duplicate_ack_num"]
tshark_fields: ["tcp.analysis.retransmission", "tcp.analysis.flags", "tcp.seq", "tcp.len", "tcp.nxtseq", "tcp.stream", "tcp.time_delta", "tcp.window_size_value", "ip.id", "ip.ttl"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["TCP retransmission", "재전송", "tcp.analysis.retransmission"]
keywords: ["TCP retransmission", "재전송", "spurious retransmission", "fast retransmission", "duplicate ACK", "out-of-order", "lost segment", "zero window", "window full", "keep alive", "Expert Information", "TCP 재조립", "중복 패킷", "Bad TCP"]
aliases: ["재전송", "retransmission 많음", "패킷 중복", "같은 패킷 두 번", "follow stream 이상함", "zero window 무슨 뜻", "빨간 패킷 검은 배경", "bad tcp"]
symptom_keywords: ["Follow Stream 내용이 두 번 나온다", "재전송이 너무 많다", "패킷이 중복으로 보인다", "스트림 내용을 믿을 수 없다", "zero window 가 뜬다", "명령이 두 번 실행된 것처럼 보인다"]
related: ["FOR-0146", "FOR-0173", "FOR-0162", "FOR-0181"]
source_ids: ["SRC-066", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`tcp.analysis.flags` 로 재전송·중복 ACK·누락 세그먼트를 먼저 세고, 재전송이 섞인 스트림은 **Follow Stream 결과를 그대로 증거로 쓰지 않는다.** 같은 데이터가 두 번 보이면 자격증명·명령을 두 번 계수하게 되므로, `!tcp.analysis.retransmission` 으로 중복을 걷어내고 남은 세그먼트만으로 전송 내용을 판정한다.

## 어떤 문제에서 필요한가

- Follow TCP Stream 을 열었는데 같은 명령이나 같은 POST 본문이 두 번 이상 보이는 상황
- 패킷 목록이 검은 배경 + 빨간 글씨(`Bad TCP` 컬러링 룰)로 뒤덮인 pcap
- 추출한 파일이 깨졌고 원인이 캡처 누락인지 실제 전송 오류인지 판단해야 하는 상황
- "공격자가 명령을 몇 번 보냈는가", "비밀번호를 몇 번 입력했는가" 같은 **횟수를 묻는 문제**
- 캡처가 스위치 미러링으로 떠졌고 모든 프레임이 두 개씩 보이는 상황

**재전송 판정을 건너뛰면 그 뒤의 모든 계수와 재조립이 틀린다.** 트리아지([FOR-0146](./wireshark-30sec-triage.html))의 다음 단계로 항상 여기를 지난다.

## 문제에서 처음 볼 단서

1. **패킷 목록의 색** — `Bad TCP` 컬러링 룰(검은 배경 + 빨간 글씨)이 재전송·중복 ACK·누락을 한꺼번에 표시한다
2. **`Info` 컬럼의 대괄호 태그** — `[TCP Retransmission]`, `[TCP Dup ACK 512#3]`, `[TCP Previous segment not captured]`, `[TCP ZeroWindow]`
3. **`Analyze > Expert Information` 의 Note/Warning 개수** — 여기 숫자가 곧 신뢰도다
4. **전체 패킷 대비 재전송 비율** — 1% 미만은 정상 네트워크, 10% 이상은 캡처 환경이나 경로 자체에 문제가 있다
5. **똑같은 프레임이 연속 두 개** — 시간 간격이 0.00x초면 재전송이 아니라 **캡처 중복**이다

## 30초 절차

```text
tcp.analysis.flags && !tcp.analysis.window_update
```

이 한 줄이 "이 pcap의 TCP 이상 신호 전체"다. 결과가 0건이면 재조립을 신뢰해도 된다.

이어서 GUI 3단계:

```text
1. Analyze > Expert Information        -> Note/Warning 그룹별 개수
2. 위 필터 결과의 Statistics > Conversations -> 어느 스트림에 몰려 있는가
3. tcp.stream eq N && !tcp.analysis.retransmission -> 중복 제거 후 Follow
```

CLI 로 한 번에:

```bash
tshark -r capture.pcapng -q -z expert
```

## 상세 절차

### 1단계 — 전제 확인: 분석 기능이 켜져 있어야 한다

`tcp.analysis.*` 필드는 파일에 저장된 값이 아니라 **Wireshark 가 스트림을 추적해 붙이는 판정**이다. 다음 preference 가 꺼져 있으면 필터가 전부 0건이 된다.

```text
Edit > Preferences > Protocols > TCP
  [v] Analyze TCP sequence numbers      <- 이것이 꺼지면 tcp.analysis.* 가 사라진다
  [v] Relative sequence numbers
  [v] Allow subdissector to reassemble TCP streams
  [v] Reassemble out-of-order segments  <- 순서 뒤바뀐 스트림 재조립에 필요
```

`Analyze TCP sequence numbers` 는 기본값이 켜져 있다. 남의 프로필을 받아 쓰거나 성능 때문에 끈 상태로 분석하면 "이상 없음"이라는 잘못된 결론이 나온다.

### 2단계 — 9개 판정 플래그의 정확한 의미

| 필터 | Info 컬럼 표시 | 무엇을 뜻하는가 | 포렌식 함의 |
| --- | --- | --- | --- |
| `tcp.analysis.retransmission` | `[TCP Retransmission]` | 이미 본 시퀀스 구간의 데이터가 다시 왔다 | 같은 페이로드 중복. 계수 주의 |
| `tcp.analysis.fast_retransmission` | `[TCP Fast Retransmission]` | 중복 ACK 직후의 재전송 | 정상적인 손실 복구. 경로 손실 |
| `tcp.analysis.spurious_retransmission` | `[TCP Spurious Retransmission]` | **수신측이 이미 ACK 한 데이터**를 또 보냈다 | ACK 유실 또는 캡처 지점이 송신측에 가까움 |
| `tcp.analysis.out_of_order` | `[TCP Out-Of-Order]` | 기대 시퀀스보다 낮은 세그먼트가 곧바로 도착 | 손실이 아니라 경로 재배열. 재조립은 정상 |
| `tcp.analysis.lost_segment` | `[TCP Previous segment not captured]` | 시퀀스에 구멍이 있다 | **캡처 누락.** 추출 파일이 깨지는 1순위 원인 |
| `tcp.analysis.ack_lost_segment` | `[TCP ACKed unseen segment]` | 캡처에 없는 데이터를 ACK 했다 | 캡처가 중간부터 시작됐거나 한쪽만 떴다 |
| `tcp.analysis.duplicate_ack` | `[TCP Dup ACK n#k]` | 같은 ACK 번호를 반복 전송 | 수신측이 구멍을 알리는 중. 3회면 fast retransmit 유발 |
| `tcp.analysis.zero_window` | `[TCP ZeroWindow]` | 광고 window 가 0 | **수신측 버퍼 포화 = 과부하.** 서버가 죽어가는 중 |
| `tcp.analysis.window_full` | `[TCP Window Full]` | 이 세그먼트가 상대의 광고 window 를 꽉 채웠다 | 더 못 보낸다. 전송 정지 직전 |
| `tcp.analysis.keep_alive` | `[TCP Keep-Alive]` | 새 데이터 없이 연결 유지용 세그먼트 | **장시간 유지되는 유휴 연결 = C2 후보** |

세 가지 파생 필드도 실전에서 쓴다.

| 필드 | 용도 |
| --- | --- |
| `tcp.analysis.flags` | 위 이상 신호 **전부**를 한 번에. 트리아지 첫 줄 |
| `tcp.analysis.duplicate_ack_num` | 중복 ACK 가 몇 번째인가. `>= 3` 이면 손실 확정 |
| `tcp.analysis.rto` | 재전송까지 걸린 시간(초). 캡처 중복과 실제 재전송을 가른다 |

`tcp.analysis.flags` 는 `window_update` 처럼 정상 동작도 포함하므로, 이상 신호만 보려면 제외한다.

```text
tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive
```

### 3단계 — retransmission / out_of_order / spurious 를 구분한다

Wireshark 는 세 가지를 **도착 시각과 ACK 상태**로 갈라놓는다.

| 관측 | Wireshark 판정 | 근거 |
| --- | --- | --- |
| 낮은 seq 가 직전 프레임 **직후**(수 ms 이내) 도착 | out-of-order | 경로가 순서를 바꿨을 뿐 |
| 낮은 seq 가 **RTO 수준의 지연 뒤**(수백 ms) 도착 | retransmission | 송신측이 타이머 만료로 다시 보냄 |
| 이미 ACK 된 구간의 데이터가 도착 | spurious retransmission | 보낼 필요가 없었다 |
| 중복 ACK 3회 직후 즉시 재전송 | fast retransmission | 타이머 대기 없이 즉시 복구 |

RTO 는 RFC 9293 이 참조하는 재전송 타이머 규칙에 따라 **재전송이 실패할 때마다 두 배로 늘어난다.** 그래서 같은 세그먼트가 0.2s → 0.4s → 0.8s → 1.6s 간격으로 반복되는 패턴이 보이면 상대가 응답을 아예 못 하고 있다는 뜻이다.

```text
tcp.stream eq 7 && tcp.analysis.retransmission
```

`tcp.time_delta` 를 컬럼으로 올려두면 이 배수 패턴이 눈으로 보인다.

### 4단계 — 캡처 지점 문제인지 판별한다 (가장 자주 틀리는 곳)

**재전송처럼 보이는 것의 상당수는 캡처 중복이다.** 스위치 미러링이 같은 프레임을 두 방향에서 복사하거나, 탭과 SPAN 을 동시에 걸면 완전히 동일한 프레임이 두 번 저장된다.

두 경우는 다음 세 값으로 확실히 갈린다.

| 비교 항목 | 진짜 재전송 | 캡처 중복 |
| --- | --- | --- |
| `ip.id` | 다르다 (송신 OS 가 새로 발급) | **완전히 같다** |
| `ip.ttl` | 같거나 같다 | 같다 (또는 1 차이 = 다른 홉에서 캡처) |
| `tcp.time_delta` | 0.2초 이상 (RTO 단위) | 0.000x 초 |
| IP 체크섬·전체 바이트 | 동일할 수 있음 | 바이트 단위로 동일 |

판별 필터:

```text
tcp.analysis.retransmission && tcp.time_delta < 0.001
```

여기 걸린 것들은 **재전송이 아니라 중복 캡처**다. `ip.id` 를 컬럼으로 올려 앞 프레임과 같은지 확인하면 확정된다.

중복이 확인되면 Wireshark 동봉 CLI 로 걷어낸다.

```bash
editcap -d capture.pcapng dedup.pcapng
```

`-d` 는 인접 프레임 창 안에서 동일한 프레임을 제거한다. 창 크기·시간 기준 옵션은 버전마다 이름이 다를 수 있으므로 `editcap -h` 로 확인한 뒤 쓴다. 중복 제거 후 다시 `tcp.analysis.flags` 를 세어 숫자가 크게 줄면 원인이 캡처 환경이었던 것이 증명된다.

### 5단계 — 중복을 제거하고 실제 전송 내용을 판정한다

목표는 "이 스트림으로 실제로 오간 바이트열"을 한 번만 얻는 것이다.

```text
1. tcp.analysis.flags 로 이상 신호가 어느 스트림에 있는지 확인
2. tcp.stream eq N && tcp.analysis.lost_segment  -> 0건이어야 재조립 신뢰 가능
3. tcp.stream eq N && (tcp.analysis.retransmission || tcp.analysis.spurious_retransmission)
   -> 중복된 프레임 번호를 적어 둔다
4. tcp.stream eq N && tcp.len > 0 && !tcp.analysis.retransmission
   && !tcp.analysis.spurious_retransmission && !tcp.analysis.fast_retransmission
   -> 남은 세그먼트가 "한 번씩만" 전송된 실제 데이터
5. 이 상태에서 Follow > TCP Stream
```

핵심 원칙 두 개:

- **`lost_segment` 가 있으면 재조립 결과는 불완전하다.** 구멍만큼 바이트가 없는 파일이 나온다. 이때는 파일 추출을 포기하고 문자열 단위 증거(명령, URI, 자격증명)로 전환한다.
- **Follow Stream 은 시퀀스 번호로 재조립하므로 단순 재전송은 대개 한 번만 표시한다.** 그러나 **패킷 목록에서 눈으로 세거나 `tcp contains` 로 필터링해 개수를 세면 재전송이 그대로 중복 계수된다.** 횟수를 묻는 문제에서 이것이 오답의 원인이다.

그래서 계수는 항상 이렇게 한다.

```bash
# 잘못된 계수 — 재전송이 섞여 실제보다 많다
tshark -r capture.pcapng -Y 'tcp contains "PASS "' | wc -l

# 올바른 계수 — 재전송 제외
tshark -r capture.pcapng \
  -Y 'tcp contains "PASS " && !tcp.analysis.retransmission && !tcp.analysis.spurious_retransmission' \
  -T fields -e frame.number -e tcp.stream -e tcp.seq
```

`tcp.seq` 를 함께 뽑으면 **같은 시퀀스 번호가 반복되는 것이 곧 중복**이므로 눈으로도 검증된다.

### 6단계 — zero window 와 window full 은 사건의 증거다

`tcp.analysis.zero_window` 는 성능 문제가 아니라 **수신측이 버퍼를 비울 수 없는 상태**, 즉 과부하다.

| 관측 | 해석 | 어떤 문제인가 |
| --- | --- | --- |
| 서버 → 클라이언트 ZeroWindow 가 다수 | 서버가 처리 불능 | DoS, 대량 업로드, 애플리케이션 hang |
| 클라이언트 → 서버 ZeroWindow | 클라이언트가 못 받고 있음 | 대용량 다운로드 중 디스크/CPU 포화 |
| `window_full` → `zero_window` → `zero_window_probe` 순서 | 정상적인 흐름 제어 정지 | 전송 중단 시각이 곧 사건 시각 |
| ZeroWindow 직후 RST | 연결 강제 종료 | 서비스 중단 확정 |

```text
tcp.analysis.zero_window || tcp.analysis.window_full || tcp.analysis.zero_window_probe
```

이 필터의 **첫 프레임 시각**이 서비스가 무너지기 시작한 시점이다. 절대시각(UTC)으로 바꿔 서버 로그와 대조한다.

## 출력 필드 해석

`Analyze > Expert Information` 은 위 플래그를 그룹으로 묶어 보여준다.

| 그룹 | 대표 항목 | 읽는 법 |
| --- | --- | --- |
| Warning | Previous segment not captured / ACKed unseen segment / Out-of-Order | **재조립 신뢰도를 깎는 항목.** 여기 숫자가 0 이 아니면 추출 파일을 의심한다 |
| Warning | ZeroWindow | 수신측 과부하. 시각을 기록한다 |
| Note | Retransmission / Fast Retransmission / Spurious Retransmission | 중복 계수 위험. 개수를 적어 둔다 |
| Note | Duplicate ACK | 손실 발생 지점 |
| Note | Window Full / Keep-Alive | 흐름 제어와 유휴 연결 |
| Chat | Connection establish (SYN) / reset (RST) | 세션 경계. 스트림 분할 지점 |

심각도(Severity) 분류는 Wireshark 버전에 따라 항목이 오가므로, **필터로 개수를 확인하는 것이 더 정확하다.**

```bash
tshark -r capture.pcapng -q -z expert
tshark -r capture.pcapng -Y 'tcp.analysis.retransmission' -T fields -e frame.number | wc -l
tshark -r capture.pcapng -Y 'tcp.analysis.lost_segment'   -T fields -e frame.number | wc -l
```

스트림별 이상 신호 집계 — 어느 대화를 파야 하는지 바로 나온다.

```bash
tshark -r capture.pcapng -Y 'tcp.analysis.flags' -T fields -e tcp.stream |
  sort -n | uniq -c | sort -nr | head
```

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| `lost_segment` 가 있는 스트림 | 파일 추출 포기 → `strings` / 문자열 증거로 전환 ([FOR-0001](./30sec-triage.html)) |
| 재전송 없는 깨끗한 스트림 번호 | `tcp.stream eq N` → Follow Stream → Export |
| 중복 제거 후 확정된 자격증명 1건 | 실제 로그온 성공 여부 = EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) |
| ZeroWindow 시작 시각(UTC) | 그 시각 ±5분의 서버 로그·이벤트 로그 ([FOR-0111](./log-triage.html)) |
| Keep-Alive 만 오가는 장시간 연결 | 대상 IP 의 전 활동 → 프로세스 단위 확인 ([FOR-0100](./sysmon-event-3-network-connect.html)) |
| `ip.id` 가 같은 완전 중복 프레임 | 캡처 환경 문제 → `editcap -d` 후 전체 재분석 |
| 재전송이 특정 IP 에만 몰림 | 그 IP 의 경로/방화벽 드롭. 스캔이나 필터링 흔적 |

## 흔한 함정

- **재전송을 세어 "명령을 3번 실행했다"고 답하는 것.** 재전송은 애플리케이션이 다시 보낸 것이 아니라 TCP 계층이 같은 바이트를 다시 보낸 것이다. 시퀀스 번호가 같으면 **애플리케이션 관점에서는 1회**다. `tcp.seq` 를 확인하고, `!tcp.analysis.retransmission` 으로 걸러 계수한다.
- **`Analyze TCP sequence numbers` 가 꺼진 프로필로 "이상 없음"이라 판단하는 것.** 이 preference 가 꺼지면 `tcp.analysis.*` 가 전부 0건이 된다. 필터가 0건일 때는 먼저 preference 를 확인한다.
- **out-of-order 를 손실로 오해하는 것.** out-of-order 는 순서만 뒤바뀐 것이라 데이터가 다 있다. 재조립은 정상이므로 아무것도 할 필요가 없다. 진짜 문제는 `lost_segment` 다.
- **`tcp.time_delta` 가 0.000x 초인 "재전송"을 실제 재전송으로 믿는 것.** 그것은 캡처 중복이다. `ip.id` 가 같은지 보면 즉시 갈린다. 미러링 환경의 pcap 에서는 전체 프레임이 두 배로 잡히기도 한다.
- **Export Objects 로 나온 파일이 깨졌는데 원본이 손상됐다고 결론 내리는 것.** `tcp.analysis.lost_segment` 를 먼저 확인한다. 캡처 누락이면 파일은 애초에 온전하게 존재하지 않는다. 해시 대조를 시도해도 절대 맞지 않는다.
- **spurious retransmission 을 공격 신호로 읽는 것.** 대개는 ACK 유실이거나 캡처 지점이 송신측에 가까워 ACK 을 못 본 것이다. 단독으로는 악성 근거가 되지 않는다.
- **ZeroWindow 를 네트워크 성능 이슈로 넘기는 것.** ZeroWindow 는 **수신측 애플리케이션이 소켓 버퍼를 비우지 못하는 상태**다. 서버 과부하·행·DoS 의 직접 증거이며 시각이 중요하다.
- **Keep-Alive 를 노이즈로 보고 제외하는 것.** 데이터 없이 수십 분~수시간 유지되는 연결은 정상 웹 브라우징에서 흔하지 않다. 비콘 간격이 일정하면 C2 후보다.
- **시간을 상대 초로 두고 서버 로그와 대조하는 것.** `View > Time Display Format > UTC Date and Time of Day` 로 먼저 바꾼다. KST 로그와 맞출 때는 UTC + 9시간이다 ([FOR-0054](./system-timezone.html)).
- **한쪽 방향만 캡처된 pcap 에서 재전송 통계를 신뢰하는 것.** ACK 을 못 보면 Wireshark 가 `ack_lost_segment` 와 spurious 판정을 남발한다. `Statistics > Conversations` 에서 양방향 패킷 수가 모두 0 이 아닌지 먼저 본다.

## 교차검증

```bash
# 1) 전체 이상 신호 요약 — GUI Expert Information 과 동일
tshark -r capture.pcapng -q -z expert

# 2) 재전송 프레임 목록 + 시퀀스 번호 (같은 seq 반복 = 중복 확정)
tshark -r capture.pcapng -Y 'tcp.analysis.retransmission' \
  -T fields -e frame.number -e tcp.stream -e ip.src -e ip.dst -e tcp.seq -e tcp.len -E header=y

# 3) 캡처 누락이 있는 스트림 — 여기 나오는 스트림은 재조립 불가
tshark -r capture.pcapng -Y 'tcp.analysis.lost_segment' -T fields -e tcp.stream | sort -nu

# 4) 캡처 중복 판별 — ip.id 가 앞 프레임과 같으면 중복
tshark -r capture.pcapng -Y 'tcp.analysis.retransmission && tcp.time_delta < 0.001' \
  -T fields -e frame.number -e ip.id -e ip.ttl -e tcp.seq -e tcp.time_delta

# 5) 스트림별 이상 신호 집계
tshark -r capture.pcapng -Y 'tcp.analysis.flags' -T fields -e tcp.stream |
  sort -n | uniq -c | sort -nr | head

# 6) ZeroWindow 시각 (UTC 절대시각)
tshark -r capture.pcapng -Y 'tcp.analysis.zero_window' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst

# 7) 중복 제거 후 재계산 — 숫자가 급감하면 캡처 환경 문제였다
editcap -d capture.pcapng dedup.pcapng
tshark -r dedup.pcapng -q -z expert
```

`-z expert` 요약과 개별 필터 개수가 크게 다르면 preference(`Analyze TCP sequence numbers`)나 프로필 차이를 의심한다. tshark 는 기본 설정을 쓰므로 GUI 에서 preference 를 꺼둔 상태와 결과가 달라질 수 있다.

## mini walkthrough

```text
문제:
"관리자가 FTP 서버에 로그인을 몇 번 시도했고, 최종적으로 사용한 비밀번호는 무엇인가?"
첨부: ftp_case.pcapng (9,880 packets)

1. 첫 시도 (실패) — 바로 문자열을 세어 버렸다
   필터: tcp contains "PASS "
   결과: 7개 프레임
     No.  Time      Src            Info
     412  1.2044    10.0.0.24      Request: PASS Summer2026!
     418  1.4051    10.0.0.24      [TCP Retransmission] Request: PASS Summer2026!
     423  1.8062    10.0.0.24      [TCP Retransmission] Request: PASS Summer2026!
     501  6.7710    10.0.0.24      Request: PASS Summer2026!!
     640 12.3388    10.0.0.24      Request: PASS Pa55w0rd_2026
     645 12.5401    10.0.0.24      [TCP Retransmission] Request: PASS Pa55w0rd_2026
     648 12.9412    10.0.0.24      [TCP Retransmission] Request: PASS Pa55w0rd_2026

   "7번 시도" 라고 답했다 -> 오답.
   Info 컬럼의 [TCP Retransmission] 을 읽지 않은 것이 원인이다.

2. 왜 틀렸는가 — 시퀀스 번호를 본다
   tshark -r ftp_case.pcapng -Y 'tcp contains "PASS "' \
     -T fields -e frame.number -e tcp.seq -e tcp.time_delta

     412  1401  0.201
     418  1401  0.200     <- seq 동일. RTO 배수 간격
     423  1401  0.401     <- seq 동일. 0.2 -> 0.4 로 두 배
     501  1421  0.113
     640  1442  0.198
     645  1442  0.202     <- seq 동일
     648  1442  0.401     <- seq 동일

   seq 가 1401 / 1421 / 1442 세 개뿐이다.
   -> 애플리케이션이 보낸 PASS 는 3회. 나머지 4개는 TCP 재전송.

3. 캡처 중복인지도 확인한다
   필터: tcp.analysis.retransmission && tcp.time_delta < 0.001
   결과: 0건
   -> time_delta 가 0.2초 이상이므로 캡처 중복이 아니라 실제 RTO 재전송.
      즉 서버 ACK 이 지연되는 경로 문제였다. 프레임은 지우지 않는다.

4. 올바른 계수
   필터:
     tcp contains "PASS " && !tcp.analysis.retransmission
       && !tcp.analysis.spurious_retransmission && !tcp.analysis.fast_retransmission
   결과: 3개 프레임 (412, 501, 640)

5. 어느 것이 성공했는가 — 응답 코드로 판정
   필터: ftp.response.code == 230 || ftp.response.code == 530
     No.  Info
     430  Response: 530 Login incorrect.      <- 412 (Summer2026!) 실패
     520  Response: 530 Login incorrect.      <- 501 (Summer2026!!) 실패
     660  Response: 230 Login successful.     <- 640 (Pa55w0rd_2026) 성공

6. 재조립 신뢰도 확인
   필터: tcp.analysis.lost_segment
   결과: 0건 -> Follow TCP Stream 결과를 그대로 믿을 수 있다.
   우클릭 > Follow > TCP Stream 으로 전체 세션 확인, 3회 시도가 그대로 확인된다.

정답: 3회 시도 / Pa55w0rd_2026
```

1단계의 실패가 핵심이다. **`tcp contains` 로 센 개수는 언제나 상한값이다.** 시퀀스 번호가 같은 프레임을 하나로 접기 전에는 어떤 계수도 확정하지 않는다. 문자열 검색으로 자격증명을 사냥할 때의 필터 작성법은 [FOR-0181](./tcp-contains.html) 을 함께 본다.

## 막혔을 때 다음 체크

1. `Edit > Preferences > Protocols > TCP` 에서 `Analyze TCP sequence numbers` 가 켜져 있는가
2. `tcp.analysis.flags` 가 0건인가 — 그렇다면 재조립을 신뢰하고 다음 단계로 간다
3. `tcp.analysis.lost_segment` 가 있는가 — 있으면 파일 추출은 실패한다. 문자열 증거로 전환
4. `tcp.analysis.retransmission && tcp.time_delta < 0.001` 이 잡히는가 — 캡처 중복이다
5. `ip.id` 를 컬럼으로 올려 앞 프레임과 같은 값인지 봤는가
6. 계수할 때 `tcp.seq` 를 함께 뽑아 중복을 확인했는가
7. `Statistics > Conversations` 에서 양방향 패킷이 모두 존재하는가 — 단방향 캡처는 통계가 왜곡된다
8. ZeroWindow 의 첫 시각을 UTC 절대시각으로 기록했는가
9. Keep-Alive 만 오가는 장시간 연결이 있는가 — 비콘 간격을 재본다
10. `editcap -d` 로 중복을 제거한 뒤 개수가 줄었는가
11. 재전송이 특정 스트림 하나에만 몰려 있는가 — 그 스트림이 문제의 핵심일 가능성이 높다
12. Expert Information 의 Chat 그룹에서 RST 위치를 확인했는가 — 세션이 끊긴 지점이 사건 시각이다

## 출처

- SRC-066 — RFC 9293 (TCP): 시퀀스 번호와 ACK 규칙, 재전송 타이머와 지수적 backoff, 흐름 제어(window)와 zero window 동작
- SRC-002 — Wireshark Display Filter Reference: `tcp.analysis.retransmission`, `tcp.analysis.fast_retransmission`, `tcp.analysis.spurious_retransmission`, `tcp.analysis.duplicate_ack`, `tcp.analysis.duplicate_ack_num`, `tcp.analysis.out_of_order`, `tcp.analysis.lost_segment`, `tcp.analysis.ack_lost_segment`, `tcp.analysis.zero_window`, `tcp.analysis.zero_window_probe`, `tcp.analysis.window_full`, `tcp.analysis.window_update`, `tcp.analysis.keep_alive`, `tcp.analysis.flags`, `tcp.analysis.rto`, `tcp.seq`, `tcp.len`, `tcp.nxtseq`, `tcp.time_delta`, `tcp.window_size_value` 의 정확한 필드명 확인
- SRC-003 — Wireshark User's Guide: `Analyze > Expert Information`, TCP preference(`Analyze TCP sequence numbers`), Follow TCP Stream 의 재조립 동작, `Bad TCP` 컬러링 룰
- Expert Information 의 severity 분류(Note/Warning/Chat)와 항목 배치는 Wireshark 버전에 따라 달라진다. 개수를 근거로 쓸 때는 severity 가 아니라 개별 `tcp.analysis.*` 필터 결과로 세는 것이 안전하다
- `editcap` 은 Wireshark 에 동봉된 CLI 이지만 `tools/manifest.json` 에 등록되어 있지 않다. `-d` 이외의 중복 제거 옵션(창 크기·시간 기준)은 버전마다 이름이 다를 수 있으므로 `editcap -h` 로 확인한 뒤 사용할 것
- Info 컬럼의 대괄호 표기(`[TCP Retransmission]` 등)는 Wireshark 가 붙이는 표시이며 문구가 버전에 따라 미세하게 다를 수 있다. 필터 이름은 위 SRC-002 로 확인한 값이 정확하다
