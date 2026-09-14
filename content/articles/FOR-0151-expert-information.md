---
id: FOR-0151
title: "Wireshark Expert Information으로 이상 패킷 빠르게 찾기"
slug: "expert-information"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP", "IPv4", "IPv6"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z expert", "tshark -r capture.pcapng -Y 'tcp.analysis.flags' -T fields -e frame.number -e tcp.stream -e _ws.expert.message", "tshark -r capture.pcapng -Y 'expert.severity == 2'"]
regex_patterns: []
wireshark_filters: ["tcp.analysis.flags", "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment", "tcp.analysis.zero_window", "expert.severity == 2", "expert.severity == 1", "_ws.malformed"]
tshark_fields: ["_ws.expert.message", "_ws.expert.severity", "_ws.expert.group", "tcp.analysis.flags"]
log_fields: ["Severity", "Summary", "Group", "Protocol", "Count"]
file_formats: ["pcap", "pcapng"]
primary_terms: ["Expert Information", "익스퍼트 인포메이션"]
keywords: ["Expert Information", "익스퍼트 인포메이션", "tcp.analysis.flags", "Malformed Packet", "Bad Checksum", "Previous segment not captured", "Retransmission", "expert.severity", "Analyze 메뉴", "패킷 이상 자동 탐지"]
aliases: ["익스퍼트 인포메이션", "expert information 보는법", "이상 패킷 찾기", "빨간 패킷 이유", "와이어샤크 경고", "tcp.analysis.flags 필터", "재전송 왜 뜨는지"]
symptom_keywords: ["패킷 목록에 빨간 줄이 있다", "이 캡처를 믿어도 되는지 모르겠다", "재전송이 왜 표시되는지 모르겠다", "follow stream이 이상하게 나온다", "이상한 패킷만 골라내고 싶다"]
related: ["FOR-0146", "FOR-0148", "FOR-0149", "FOR-0175"]
source_ids: ["SRC-003", "SRC-010", "SRC-002"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Analyze > Expert Information`은 Wireshark가 각 패킷을 해석하면서 스스로 발견한 이상 징후(재전송, 손상된 체크섬, 파싱 실패, 순서 오류)를 한 창에 심각도별로 모아 보여준다. **Follow TCP Stream을 신뢰해도 되는지, 이 캡처가 온전한지를 결과 해석 전에 먼저 확인하는 용도**로 쓴다.

## 어떤 문제에서 필요한가

- Follow TCP Stream으로 연 내용이 중간에 끊기거나 순서가 이상할 때, 원인이 캡처 자체의 문제인지 먼저 확인해야 할 때
- "이 캡처는 조작되었다/일부가 누락되었다"를 증명해야 하는 문제
- 재전송·중복 ACK가 많은 트래픽에서 실제 통신 실패와 정상 재전송을 구분해야 할 때
- 패킷이 너무 많아 어디부터 봐야 할지 모를 때 Wireshark의 판단을 빌려 후보를 줄이는 용도
- `Malformed Packet`처럼 파서가 포기한 패킷을 콕 집어 찾아야 할 때

## 문제에서 처음 볼 단서

1. **패킷 목록의 배경색** — 검은 배경에 빨간 글씨(Malformed), 검은 텍스트(재전송류 코멘트)가 보이면 Expert Information에 항목이 있다는 뜻이다.
2. **하단 상태 표시줄의 원형 아이콘** — 빨강(Error)/노랑(Warning)/파랑(Note)/초록(Chat) 중 가장 심각한 색이 표시된다.
3. **캡처 파일 크기 대비 패킷 수가 적다** — 캡처가 중간에 끊겼거나 필터링되어 저장된 경우 `Previous segment not captured`가 대량 발생한다.
4. **Follow Stream 내용이 뒤죽박죽** — 재조립 실패의 신호. Expert Information에서 원인을 먼저 본다.

## 30초 절차

```bash
tshark -r capture.pcapng -q -z expert
```

GUI는 세 클릭이다.

```text
1. Analyze > Expert Information
2. 상단 탭에서 Errors > Warnings > Notes > Chats 순으로 확인 (심각도 내림차순)
3. 항목 더블클릭 -> 해당 패킷으로 바로 이동
```

## 상세 절차

### 1단계 — 창을 여는 두 가지 경로

```text
Analyze > Expert Information
```

또는 하단 상태 표시줄 왼쪽의 원형 아이콘을 클릭해도 같은 창이 열린다. 이 아이콘은 **캡처 전체에서 가장 심각한 등급의 색**으로 항상 표시되므로, 캡처를 열자마자 이 아이콘 색부터 확인하는 습관을 들인다.

### 2단계 — 심각도(Severity) 네 등급

| 등급 | 색 | 의미 | 실전에서 |
| --- | --- | --- | --- |
| `Error` | 빨강 | 파서가 패킷 해석에 실패했다 (`Malformed Packet` 등) | 캡처 손상, 조작, 또는 지원하지 않는 프로토콜 확장 |
| `Warning` | 노랑 | 프로토콜 규칙 위반이 의심된다 (체크섬 오류, 재전송, 순서 오류) | **TCP 문제의 대부분이 여기 모인다** |
| `Note` | 파랑 | 정상 범위지만 주목할 만하다 (윈도우 갱신, ACK만 있는 패킷 등) | 대개 무시해도 되지만 패턴 확인용 |
| `Chat` | 초록 | 정보성 (연결 시작/종료 등) | 흐름 파악용, 이상 징후 아님 |

**심각도는 배타적이지 않다.** 한 패킷이 여러 항목을 동시에 가질 수 있고, 이 창에는 그중 가장 심각한 등급으로 집계된다.

### 3단계 — 탭 구성

Expert Information 창은 보통 두 가지 보기를 제공한다.

| 탭 | 보여주는 것 |
| --- | --- |
| Errors / Warnings / Notes / Chats (그룹별) | 같은 메시지를 가진 패킷들을 묶어서 개수와 함께 표시 |
| Group / Protocol 열 | 어떤 프로토콜 계층에서 발생한 문제인지 (Sequence, Checksum, Malformed 등) |

각 행을 펼치면 그 메시지에 해당하는 **모든 패킷 번호**가 나열된다. 더블클릭하면 패킷 목록에서 그 패킷으로 바로 이동한다.

### 4단계 — 자주 보는 메시지와 의미

| 메시지 | 등급 | 의미 | 대응 |
| --- | --- | --- | --- |
| `Malformed Packet` | Error | 파서가 구조를 해석하지 못했다 | 캡처 손상, 지원 안 하는 확장, 또는 의도적 조작(문제의 단서일 수 있다) |
| `Previous segment not captured` | Warning | 이 세그먼트보다 앞선 데이터가 캡처에 없다 | 캡처가 세션 중간부터 시작됨. Follow Stream 앞부분 신뢰 불가 |
| `Retransmission (suspected)` | Warning | 이전에 보낸 것과 같은 시퀀스 번호가 다시 나타났다 | 네트워크 손실 또는 응답 지연. 대량이면 회선 문제 |
| `Fast Retransmission (suspected)` | Warning | 중복 ACK 3개 이상 후 재전송 | 손실 구간이 명확히 특정된다 |
| `Spurious Retransmission (suspected)` | Warning | ACK가 이미 왔는데도 재전송함 | 타이머 오작동. 데이터 손실은 아님 |
| `Duplicate ACK (#n)` | Warning/Note | 같은 ACK 번호가 반복 | 손실 세그먼트 대기 중 |
| `Out-Of-Order segment` | Warning | 시퀀스 번호가 이전 것보다 낮은 세그먼트 도착 | 경로 상 재정렬. 재조립에 영향 |
| `Window is full` | Warning | 송신 윈도우가 가득 참 | 수신 측 처리 지연 |
| `Zero window` | Warning | 수신 윈도우 크기가 0 | 수신 측 버퍼 고갈. 통신 일시 정지 |
| `TCP port numbers reused` | Note | 같은 4-튜플을 다른 세션이 재사용 | `tcp.stream` 번호가 세션을 정확히 구분해 준다 |
| `Checksum Error` | Warning/Error(설정에 따라) | 체크섬 불일치 | 오프로드(NIC checksum offload) 캡처의 정상적 오탐일 수 있다 |
| `Connection reset (RST)` | Chat/Note | RST로 연결 종료 | 강제 종료 이력 |

### 5단계 — 해당 필터로 직접 뽑기

Expert Information의 각 항목은 `tcp.analysis.flags` 계열 필터에 대응한다. 창을 거치지 않고 바로 필터를 걸 수도 있다.

```text
tcp.analysis.flags                    -- TCP 분석 관련 이상 전체
tcp.analysis.retransmission           -- 재전송(일반)
tcp.analysis.fast_retransmission      -- 빠른 재전송
tcp.analysis.spurious_retransmission  -- 불필요한 재전송
tcp.analysis.duplicate_ack            -- 중복 ACK
tcp.analysis.lost_segment             -- 손실 세그먼트 (Previous segment not captured)
tcp.analysis.out_of_order             -- 순서 뒤바뀜
tcp.analysis.zero_window              -- 윈도우 0
tcp.analysis.window_full              -- 윈도우 가득 참
```

일반화된 심각도 필터도 있다.

```text
expert.severity == 2   -- Error
expert.severity == 1   -- Warning
```

> 심각도 값(Error=2, Warning=1 등)은 Wireshark 내부 열거값이며 버전에 따라 표현이 다를 수 있다. 확실하지 않으면 Expert Information 창에서 항목을 우클릭해 `Apply as Filter`로 정확한 필터 문자열을 얻는 편이 안전하다.

### 6단계 — 재전송이 "정상"인지 "증거"인지 구분하기

재전송 자체는 TCP의 정상 복구 메커니즘이다. CTF에서 중요한 것은 **재전송의 존재가 아니라 재전송이 몰린 지점과 이유**다.

| 관찰 | 해석 |
| --- | --- |
| 캡처 전체에 재전송이 드문드문 소수 | 일반적인 네트워크 지연. 무시 가능 |
| 특정 스트림에만 재전송이 집중 | 그 세션에서 문제가 있었다. 해당 스트림을 우선 조사 |
| 캡처 시작부터 `Previous segment not captured`가 반복 | 캡처가 세션 중간에 시작됐다. Follow Stream 앞부분은 신뢰하지 말 것 |
| 재전송 직후 RST | 연결이 실패로 종료됨. 공격/차단 시도의 흔적일 수 있다 |
| 짧은 시간에 동일 목적지로 재전송 폭증 | 대상이 응답을 못 하는 상태(다운, 필터링, DoS 대상) |

## 출력 필드 해석

`tshark -q -z expert`의 출력.

```text
========================================================================
    Errors (1)
        Frame     Group     Protocol   Summary
        4821      Malformed TCP        Malformed Packet (Exception occurred)

    Warnings (3)
        Group     Protocol   Summary                                          Count
        Sequence  TCP        Previous segment not captured (common at capture start)  12
        Sequence  TCP        Retransmission (suspected)                              47
        Sequence  TCP        Duplicate ACK (#1)                                     203

    Notes (1)
        Group     Protocol   Summary                          Count
        Sequence  TCP        This frame is a (suspected) ACK to the segment...  312
========================================================================
```

| 컬럼 | 의미 |
| --- | --- |
| `Group` | 문제의 범주. `Sequence`(순서/재전송), `Checksum`, `Malformed`, `Reassembly` 등 |
| `Protocol` | 어느 프로토콜 계층에서 발생했는가 |
| `Summary` | 사람이 읽는 설명 |
| `Count` | 같은 메시지의 발생 횟수 |
| `Frame` | (Errors 등 단건 표시 시) 패킷 번호 |

`Count`가 큰 항목일수록 캡처 전반의 경향을, 작은 항목(특히 `Errors`의 단건)은 **개별 이상 패킷**을 가리킨다. CTF에서는 단건 `Malformed Packet`이 오히려 정답 패킷인 경우가 많다.

## pivot: 다음에 볼 artifact

| Expert Information에서 본 것 | 다음에 할 일 |
| --- | --- |
| `Malformed Packet` 단건 | 해당 프레임 번호로 이동해 hex 덤프 직접 확인. 의도적 조작 의심 |
| `Previous segment not captured` 다수 | 캡처가 세션 중간 시작. Follow Stream 결과를 전적으로 신뢰하지 말 것 |
| 특정 `tcp.stream`에 재전송 집중 | 그 스트림만 필터해 [FOR-0149](./conversations.html)에서 재검토 |
| 재전송 후 RST | EVTX/방화벽 로그에서 같은 시각의 차단 이벤트 |
| `Checksum Error` 다수 | NIC 오프로드로 인한 정상 오탐인지 먼저 확인 (실제 손상이 아닐 수 있다) |
| `Zero window` | 수신 측 애플리케이션 로그(서버 과부하 등) |
| 이상 없음(Chat/Note만) | Follow Stream 결과를 신뢰하고 [FOR-0148](./protocol-hierarchy.html) 단계로 진행 |

## 흔한 함정

- **재전송이 있으면 무조건 공격이라고 판단하는 것.** 정상 네트워크에도 소량의 재전송은 항상 있다. 집중도와 패턴을 봐야 한다.
- **Expert Information을 트리아지 맨 마지막에 보는 것.** Follow Stream이나 Export Objects를 먼저 시도했다가 결과가 이상해서 뒤늦게 여는 경우가 많다. **재구성 결과를 해석하기 전에** 먼저 확인하는 순서로 바꾼다.
- **`Malformed Packet`을 그냥 캡처 손상으로 치부하고 넘어가는 것.** CTF에서는 의도적으로 조작된 필드가 파서를 깨뜨려 `Malformed`로 뜨는 것 자체가 단서인 경우가 있다.
- **`Count`가 큰 항목에만 집중하고 단건 `Errors`를 놓치는 것.** 정렬 기준을 `Count`가 아니라 `Group`(Errors 우선)으로 먼저 본다.
- **체크섬 오류를 실제 데이터 손상으로 오해하는 것.** 캡처 지점이 송신 NIC 앞단이면 체크섬 오프로드로 인해 정상 패킷도 체크섬이 채워지지 않은 채 캡처되어 대량의 `Checksum Error`가 뜬다. `Edit > Preferences > Protocols > TCP > Validate checksum`을 꺼서 재확인한다.
- **재전송 필터와 원본 필터를 혼동하는 것.** `tcp.analysis.retransmission`은 재전송된 패킷만 잡는다. 원본 세그먼트를 함께 보려면 `tcp.analysis.flags`로 넓혀야 한다.
- **심각도 필터(`expert.severity`)의 숫자값을 외워서 쓰다 버전 차이로 틀리는 것.** 항목을 우클릭해 `Apply as Filter`로 만든 필터 문자열을 그대로 쓰는 것이 안전하다.
- **CLI `-z expert`를 GUI와 다른 결과라고 의심하는 것.** 표시 형식만 다를 뿐 같은 판정 엔진을 쓴다. 필터(`-Y`)를 걸고 돌렸다면 그 필터 범위 내 결과라는 점을 확인한다.

## 교차검증

```bash
# 1) GUI Expert Information과 같은 요약
tshark -r capture.pcapng -q -z expert

# 2) 이상이 있는 패킷 번호와 메시지를 표로
tshark -r capture.pcapng -Y 'tcp.analysis.flags' \
  -T fields -e frame.number -e frame.time_relative -e tcp.stream -e _ws.expert.message

# 3) 특정 스트림에 재전송이 몇 건인지
tshark -r capture.pcapng -Y 'tcp.stream eq 4 && tcp.analysis.retransmission' | wc -l

# 4) Error 등급만
tshark -r capture.pcapng -Y 'expert.severity == 2' \
  -T fields -e frame.number -e _ws.expert.message

# 5) 체크섬 검증을 끈 상태로 재확인 (오탐 여부 판단)
tshark -o tcp.check_checksum:FALSE -r capture.pcapng -q -z expert
```

`(5)`에서 `Checksum Error` 항목이 사라지면 오프로드로 인한 정상 오탐이었다는 뜻이다. 그래도 남는 오류가 진짜 이상 신호다.

## mini walkthrough

```text
문제:
"제공된 pcap에서 공격자가 응답을 조작해 삽입한 패킷 하나를 찾아
 그 패킷 번호와 이유를 설명하세요."
첨부: tampered.pcapng (4,102 packets)

1. 첫 시도 (실패)
   바로 http.request 필터를 걸어 요청/응답을 훑었다.
   200개 넘는 HTTP 트랜잭션을 하나씩 보는 것은 비현실적이었고,
   눈으로는 이상한 것을 찾지 못했다.
   원인: 어떤 패킷이 이상한지 힌트 없이 전수조사를 시도했다.

2. 접근 변경 — Analyze > Expert Information
   하단 상태 표시줄 아이콘이 빨간색(Error)이었다.

   Errors (1)
     Frame 2981   Malformed   TCP   Malformed Packet (Exception occurred)
   Warnings (2)
     Sequence  TCP  Previous segment not captured   3
     Sequence  TCP  Retransmission (suspected)       9

3. Errors 탭의 프레임 2981 더블클릭
   -> 패킷 목록에서 2981번으로 이동. 빨간 배경.
   Frame 2981: TCP 세그먼트 길이가 IP Total Length와 불일치.
   Info 컬럼: "Malformed Packet"

4. hex 덤프로 직접 확인 (우클릭 > Show Packet Bytes)
   IP 헤더의 Total Length 필드가 실제 캡처된 바이트 수보다
   훨씬 크게 설정되어 있었다. 정상적인 재조립이라면 나올 수 없는 값.

5. 같은 스트림의 앞뒤 패킷 확인
   tcp.stream eq 2981번 패킷의 스트림 번호로 필터
   -> 정상적인 HTTP 응답 시퀀스 사이에 이 패킷 하나만 시퀀스 번호가
      살짝 어긋나 있었다. 정상 서버라면 만들 수 없는 길이 불일치.

6. 두 번째 확인 — 체크섬 오탐이 아닌지
   $ tshark -o tcp.check_checksum:FALSE -r tampered.pcapng -q -z expert
   -> Malformed Packet 항목은 여전히 남는다. 체크섬 설정과 무관한
      구조적 손상임을 확인.

정답: Frame 2981 / IP Total Length 필드가 조작되어 파서가 TCP 세그먼트를
      해석하지 못한 것이 삽입 흔적이다.
```

1단계의 실패가 핵심이다. 전수조사 대신 Wireshark가 이미 계산해 둔 이상 판정을 먼저 확인했다면 즉시 후보 하나로 좁힐 수 있었다.

## 막혔을 때 다음 체크

1. 하단 상태 표시줄의 아이콘 색을 확인했는가 (Errors 존재 여부의 1차 신호)
2. `Analyze > Expert Information`을 Follow Stream/Export Objects **이전에** 열었는가
3. Errors 탭에 단건 항목이 있는가 — Count가 작을수록 개별 이상 패킷일 가능성이 높다
4. `Previous segment not captured`가 캡처 초반에 몰려 있어 세션 시작을 놓친 것은 아닌가
5. 재전송이 특정 `tcp.stream`에 집중되어 있는가
6. 체크섬 오류가 오프로드로 인한 오탐인지 `tcp.check_checksum:FALSE`로 재확인했는가
7. `Malformed Packet`을 hex 덤프로 직접 열어 어느 필드가 깨졌는지 확인했는가
8. CLI `-z expert` 결과와 GUI가 일치하는가
9. 이상이 전혀 없다면 Follow Stream 결과를 신뢰하고 다음 단계([FOR-0148](./protocol-hierarchy.html))로 진행했는가

## 출처

- SRC-003 — Wireshark User's Guide, "Expert Information": Errors/Warnings/Notes/Chats 4단계 심각도 체계, 상태 표시줄 아이콘, Group/Protocol/Summary/Count 컬럼 구성
- SRC-010 — tshark man page: `-z expert[,severity]` 옵션과 출력 형식
- SRC-002 — Wireshark Display Filter Reference: `tcp.analysis.*`, `expert.severity`, `expert.group` 필드
- 심각도 필터의 정수값(`expert.severity == 2` 등)과 컨텍스트 메뉴 항목 구성은 버전에 따라 달라질 수 있으므로, 정확한 필터 문자열이 필요하면 항목을 우클릭해 `Apply as Filter`로 생성한 값을 실제 화면에서 확인할 것
