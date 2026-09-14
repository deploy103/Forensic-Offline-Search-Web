---
id: FOR-0179
title: "WebSocket 프레임 분석하기: 마스킹, opcode, payload 복원"
slug: "websocket-analysis"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "WebSocket frame", "HTTP Upgrade"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["WebSocket", "HTTP", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y websocket -T fields -e frame.number -e websocket.opcode -e websocket.payload", "tshark -r capture.pcapng -Y \"http.upgrade\" -T fields -e frame.number -e http.request.method"]
regex_patterns: []
wireshark_filters: ["websocket", "http.upgrade == \"websocket\"", "websocket.opcode == 1", "websocket.opcode == 2", "websocket.opcode == 8", "websocket.mask == 1", "websocket.payload"]
tshark_fields: ["websocket.opcode", "websocket.payload", "websocket.mask", "websocket.masking_key", "websocket.payload_length", "http.upgrade"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["websocket 분석", "WebSocket 프레임"]
keywords: ["WebSocket", "websocket 분석", "opcode", "masking key", "Sec-WebSocket-Key", "HTTP Upgrade", "실시간 통신 pcap", "RFC 6455", "websocket.payload", "채팅 pcap"]
aliases: ["웹소켓 분석", "websocket 패킷", "실시간 채팅 pcap", "웹소켓 마스킹", "websocket flag 찾기", "101 switching protocols"]
symptom_keywords: ["Follow TCP Stream이 깨져 보인다", "websocket 트래픽에서 메시지를 못 읽겠다", "채팅 앱 pcap에서 대화 내용을 찾아야 한다", "마스킹된 데이터를 풀어야 한다"]
related: ["FOR-0146", "FOR-0162", "FOR-0180"]
source_ids: ["SRC-072", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

WebSocket은 `http.upgrade == "websocket"`으로 시작된 핸드셰이크 이후 `websocket` 필터로 잡히며, 클라이언트→서버 프레임은 RFC 6455에 따라 4바이트 마스킹 키로 XOR 마스킹되어 있다. Follow TCP Stream으로는 마스킹된 바이트만 보이므로 **`websocket.payload` 필드**로 Wireshark가 이미 언마스킹한 평문을 확인한다.

## 어떤 문제에서 필요한가

- 채팅/실시간 알림/게임 통신처럼 WebSocket을 쓰는 애플리케이션의 pcap에서 메시지 내용을 찾아야 하는 문제
- Follow TCP Stream을 열었는데 사람이 읽을 수 없는 바이트가 나오는 상황
- 특정 WebSocket 메시지 하나에 flag가 들어 있는 CTF형 문제

## 문제에서 처음 볼 단서

1. **HTTP 요청에 `Upgrade: websocket`, `Connection: Upgrade`, 응답이 `101 Switching Protocols`**
2. 그 이후 패킷들이 `Protocol` 컬럼에 `WebSocket`으로 표시됨
3. Follow TCP Stream을 열면 사람이 읽을 수 없는 바이트가 섞여 나옴(클라이언트→서버 방향이 마스킹돼서)
4. Info 컬럼에 `Text`, `Binary`, `Ping`, `Pong`, `Connection Close` 같은 표시

## 30초 절차

```text
websocket
```

이 한 줄로 핸드셰이크 이후의 모든 프레임을 잡는다. 이어서 각 프레임의 `websocket.payload` 필드를 확인한다.

```text
1. 필터: http.upgrade == "websocket"   -> 핸드셰이크 요청/응답 확인
2. 필터: websocket                     -> 프레임 전체
3. 각 프레임 펼치기 > WebSocket > Payload  -> 언마스킹된 실제 데이터
4. 텍스트 메시지만: websocket.opcode == 1
```

## 상세 절차

### 1단계 — 핸드셰이크 확인

WebSocket은 일반 HTTP 요청으로 시작해 `101 Switching Protocols` 응답을 받으면 그 TCP 연결이 WebSocket 프레임 형식으로 전환된다.

```text
필터: http.upgrade == "websocket"
```

핸드셰이크 요청/응답의 핵심 헤더:

| 헤더 | 방향 | 의미 |
| --- | --- | --- |
| `Upgrade: websocket` | 요청/응답 | 프로토콜 전환 요청/승인 |
| `Connection: Upgrade` | 요청/응답 | HTTP 연결을 그대로 재사용 |
| `Sec-WebSocket-Key` | 요청 | 클라이언트가 생성한 임의 base64 값 |
| `Sec-WebSocket-Accept` | 응답 | `Sec-WebSocket-Key` + 고정 GUID를 SHA-1 해시한 값(연결 확인용) |
| `Sec-WebSocket-Version` | 요청 | 보통 `13` |
| 응답 상태 코드 `101` | 응답 | 성공적으로 WebSocket으로 전환됨 |

이 헤더들이 없으면 이후 데이터가 WebSocket이 아니라 일반 TCP 페이로드일 수 있으므로 먼저 확인한다.

### 2단계 — 프레임 구조와 opcode

RFC 6455가 정의하는 WebSocket 프레임 헤더의 핵심 필드:

| 필드 | 크기 | 의미 |
| --- | --- | --- |
| FIN | 1 bit | 이 프레임이 메시지의 마지막 조각인지 |
| opcode | 4 bit | 프레임 종류 |
| MASK | 1 bit | 마스킹 여부. **클라이언트→서버는 반드시 1** |
| Payload length | 7/7+16/7+64 bit | 페이로드 길이(가변 인코딩) |
| Masking-key | 32 bit (MASK=1일 때만) | XOR 마스킹 키 |
| Payload data | 가변 | 실제 데이터(마스킹된 상태로 전송) |

opcode 값과 의미:

| opcode | 이름 | 설명 |
| --- | --- | --- |
| `0x0` | Continuation | 이전 프레임의 이어지는 조각 |
| `0x1` | Text | UTF-8 텍스트 메시지 |
| `0x2` | Binary | 바이너리 메시지 |
| `0x8` | Close | 연결 종료 |
| `0x9` | Ping | 연결 유지 확인 |
| `0xA` | Pong | Ping에 대한 응답 |

```text
websocket.opcode == 1     -> 텍스트 메시지만
websocket.opcode == 2     -> 바이너리 메시지만
websocket.opcode == 8     -> 종료 프레임(메시지 아님, 제외 대상)
```

### 3단계 — 마스킹 동작 이해

RFC 6455는 **클라이언트가 서버로 보내는 모든 프레임을 반드시 마스킹**하도록 강제한다. 서버가 클라이언트로 보내는 프레임은 마스킹하지 않는다. 마스킹은 단순 XOR이다.

```text
원본 바이트[i] = 마스킹된 바이트[i] XOR 마스킹키[i mod 4]
```

Wireshark는 `websocket.mask == 1`인 프레임을 자동으로 언마스킹해서 `websocket.payload` 필드에 평문을 채워 보여준다. **수동으로 XOR을 계산할 필요가 없다** — Follow TCP Stream이 이 자동 언마스킹을 거치지 않고 raw 바이트를 그대로 보여주기 때문에 깨져 보이는 것뿐이다.

### 4단계 — payload 추출

```bash
tshark -r capture.pcapng -Y 'websocket.opcode==1' \
  -T fields -e frame.number -e ip.src -e ip.dst -e websocket.payload
```

출력 예시:

```text
frame.number  ip.src      ip.dst        websocket.payload
55            10.0.0.15   203.0.113.9   {"type":"join","room":"lobby"}
61            203.0.113.9 10.0.0.15     {"type":"msg","user":"alice","text":"hi"}
102           10.0.0.15   203.0.113.9   {"type":"msg","user":"bob","text":"flag is in the pinned message"}
```

`websocket.payload`가 hex로만 보이면 텍스트가 아니라 바이너리 프레임(`opcode==2`)일 가능성이 높다. 이 경우 그 값을 별도로 디코딩(base64, protobuf, 커스텀 포맷 등)해야 한다.

### 5단계 — 연속 프레임(fragmentation) 처리

FIN=0인 프레임은 메시지가 아직 끝나지 않았다는 뜻이며, 뒤이어 opcode `0x0`(continuation) 프레임들이 이어지다가 FIN=1인 프레임에서 메시지가 끝난다. 하나의 논리적 메시지가 여러 프레임으로 나뉘어 있으면 순서대로 payload를 이어붙여야 완전한 메시지가 된다.

```text
websocket.fin == 0    -> 아직 끝나지 않은 메시지의 시작/중간 조각
```

## 출력 필드 해석

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| `websocket.opcode` | 프레임 종류(0~0xA) | Close/Ping/Pong은 메시지 내용이 아니다 |
| `websocket.mask` | 마스킹 여부(1/0) | 서버→클라이언트는 항상 0이어야 정상(RFC 위반이면 이상 신호) |
| `websocket.masking_key` | 4바이트 마스킹 키 | 프레임마다 랜덤. 재사용되면 비정상 구현 |
| `websocket.payload_length` | 페이로드 길이 | 126/127 이상이면 확장 길이 필드 사용 |
| `websocket.payload` | 언마스킹된 실제 데이터 | Wireshark가 이미 XOR을 풀어 보여준 값 |
| `websocket.fin` | 마지막 조각 여부 | 0이면 다음 continuation 프레임과 이어 붙여야 함 |

## pivot: 다음에 볼 artifact

| WebSocket에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| JSON/텍스트 메시지 payload | 애플리케이션 로직에 따른 flag 위치 파악 |
| 반복되는 Ping/Pong만 있는 구간 | 유휴 연결. 실제 데이터 구간을 앞뒤로 좁혀 찾기 |
| 바이너리 payload | base64/hex/커스텀 인코딩 여부 확인 후 추가 디코딩 |
| 핸드셰이크의 `Sec-WebSocket-Key`/`Accept` | 정상 핸드셰이크인지, 스푸핑된 응답인지 확인 |
| 클라이언트/서버 방향 구분 | `websocket.mask` 값으로 방향 재확인(마스킹=클라이언트발) |

## 흔한 함정

- **Follow TCP Stream 결과를 그대로 읽으려는 것.** 클라이언트→서버 프레임은 마스킹되어 있어 사람이 읽을 수 없는 바이트로 보인다. `websocket.payload` 필드나 패킷 상세 창을 사용한다.
- **Close/Ping/Pong 프레임을 실제 메시지로 세는 것.** `websocket.opcode`가 `0x1`(Text) 또는 `0x2`(Binary)인 것만 애플리케이션 메시지다.
- **연속(continuation) 프레임을 개별 메시지로 착각하는 것.** `FIN=0`으로 시작해 `opcode=0x0`인 프레임들이 이어지면 전부 합쳐야 하나의 메시지다.
- **서버→클라이언트 프레임에 마스킹 키가 있다고 가정하고 수동 XOR을 시도하는 것.** RFC 6455는 서버발 프레임에 마스킹을 금지한다. `websocket.mask == 0`이면 이미 평문이다.
- **비표준 포트(80/443이 아닌 포트)에서 Wireshark가 WebSocket으로 인식하지 못하는 것.** 이 경우 `Decode As > WebSocket`을 수동으로 지정해야 한다.
- **바이너리(`opcode==2`) 프레임의 hex 값을 그대로 flag로 제출하는 것.** 바이너리는 대개 추가 인코딩(protobuf, msgpack, 커스텀 프로토콜)이 들어 있어 한 번 더 디코딩해야 한다.
- **permessage-deflate 확장이 협상된 세션에서 payload가 압축되어 있는 것을 놓치는 것.** 핸드셰이크 응답에 `Sec-WebSocket-Extensions: permessage-deflate`가 있으면 `websocket.payload`가 압축된 바이트일 수 있다. 이 경우 별도로 inflate가 필요할 수 있다.

## 교차검증

```bash
# 1) 핸드셰이크 확인 — GUI에서 http.upgrade 필터와 동일
tshark -r capture.pcapng -Y 'http.upgrade' -T fields -e frame.number -e http.response.code

# 2) 텍스트 메시지 전체를 방향과 함께 뽑기
tshark -r capture.pcapng -Y 'websocket.opcode==1' \
  -T fields -e frame.number -e ip.src -e ip.dst -e websocket.payload -E header=y

# 3) opcode별 프레임 개수 집계 — Ping/Pong 노이즈 비율 확인
tshark -r capture.pcapng -Y 'websocket' -T fields -e websocket.opcode | sort | uniq -c

# 4) 마스킹 여부로 방향 재확인
tshark -r capture.pcapng -Y 'websocket' -T fields -e frame.number -e websocket.mask -e ip.src
```

## mini walkthrough

```text
문제:
"채팅 앱 pcap에서 flag가 포함된 메시지를 찾아라."
첨부: chat.pcapng (WebSocket, 512 packets)

1. 첫 시도 (실패)
   우클릭 > Follow > TCP Stream
   결과: 절반은 읽을 수 있는 JSON, 절반은 깨진 바이트(...\x81\x94\x3f\x7a...)
   클라이언트가 보낸 메시지 쪽이 전부 읽을 수 없는 상태였다.

2. 원인 파악
   Protocol 컬럼 확인 -> WebSocket으로 인식되어 있음.
   깨진 바이트가 나온 프레임은 ip.src가 클라이언트(10.0.0.20)였다.
   -> RFC 6455 마스킹 규칙: 클라이언트발 프레임은 항상 마스킹된다.

3. 필터 전환
   websocket.opcode == 1
   각 프레임의 websocket.payload 필드 확인 (Wireshark가 이미 언마스킹함)

4. tshark로 전체 텍스트 메시지 추출
   tshark -r chat.pcapng -Y 'websocket.opcode==1' \
     -T fields -e ip.src -e websocket.payload

     10.0.0.20   {"type":"join","user":"guest1"}
     203.0.113.9 {"type":"msg","user":"admin","text":"welcome"}
     10.0.0.20   {"type":"msg","user":"guest1","text":"flag{w3bs0ck3t_unm4sk3d}"}

정답: flag{w3bs0ck3t_unm4sk3d}
```

1단계에서 Follow TCP Stream만 믿고 "메시지 절반이 깨졌다"고 결론 냈다면 마스킹을 몰랐던 것이다. WebSocket 프레임은 항상 전용 필터로 다시 봐야 한다.

## 막혔을 때 다음 체크

1. `http.upgrade == "websocket"`으로 핸드셰이크가 정상적으로 `101`을 받았는지 확인했는가
2. 비표준 포트라 Wireshark가 자동 인식 못했다면 `Decode As`를 지정했는가
3. `websocket.opcode`로 Text/Binary만 남기고 Ping/Pong/Close를 제외했는가
4. `websocket.payload` 필드를 확인했는가, Follow Stream만 보지 않았는가
5. `FIN=0` 연속 프레임을 이어붙였는가
6. 바이너리 payload에 추가 인코딩(base64/protobuf)이 있는지 확인했는가
7. `permessage-deflate` 확장이 협상됐는지 핸드셰이크 응답 헤더를 확인했는가

## 출처

- SRC-072 — RFC 6455 (The WebSocket Protocol): 프레임 헤더 구조, opcode 정의, 마스킹 규칙(클라이언트→서버 필수), fragmentation 규칙
- SRC-002 — Wireshark Display Filter Reference: `websocket.opcode`, `websocket.mask`, `websocket.payload`, `http.upgrade` 필드명 확인
- SRC-003 — Wireshark User's Guide: Decode As, Follow TCP Stream 동작
