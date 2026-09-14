---
id: FOR-0169
title: "ICMP payload에 숨겨진 데이터 확인하기"
slug: "icmp-payload"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "ICMP Echo"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["ICMP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y icmp -T fields -e icmp.type -e data.len", "tshark -r capture.pcapng -Y icmp -T fields -e icmp.seq -e data.data", "tshark -r capture.pcapng -Y icmp -T fields -e data.data | tr -d '\\n:' | xxd -r -p"]
regex_patterns: []
wireshark_filters: ["icmp", "icmp.type == 8", "icmp.type == 0", "data.len > 32", "data.len != 32 && icmp.type == 8", "icmp && data contains \"flag\"", "icmp.ident == 1"]
tshark_fields: ["icmp.type", "icmp.code", "icmp.ident", "icmp.seq", "icmp.seq_le", "data.data", "data.len"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["icmp payload", "ICMP 데이터 확인"]
keywords: ["ICMP", "ICMP payload", "Echo Request", "Echo Reply", "data.len", "ping 페이로드", "icmp.seq", "icmp.ident", "ping 기본 패턴", "숨겨진 데이터", "hex 디코딩", "base64", "핑 데이터"]
aliases: ["핑 페이로드", "ping 데이터", "icmp 데이터 확인", "핑 안에 뭐가 있나", "icmp data 필드", "ping payload 크기"]
symptom_keywords: ["ping 패킷만 잔뜩 있다", "icmp 안에 뭔가 숨어있는 것 같다", "핑 데이터가 이상하다", "icmp 페이로드 크기가 다르다", "여러 핑 패킷에 flag가 나뉘어 있다"]
related: ["FOR-0170", "FOR-0146", "FOR-0181", "FOR-0001"]
source_ids: ["SRC-067", "SRC-002", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

ICMP Echo 패킷의 페이로드는 운영체제/도구마다 정해진 고정 크기와 패턴을 따른다. 그 표준에서 벗어난 `data.len` 이나 알파벳 반복이 아닌 `data` 내용이 보이면 그 자리가 숨긴 데이터이며, `icmp.seq` 순서로 여러 패킷을 이어 붙이면 조각난 메시지를 복원할 수 있다.

## 어떤 문제에서 필요한가

- pcap 안에 ICMP(ping) 패킷만 대량으로 있고 다른 프로토콜은 평범한 문제
- "핑으로 뭔가를 주고받았다", "ICMP로 파일을 옮겼다" 같은 지문
- flag 문자열이 하나의 패킷이 아니라 **여러 ICMP 패킷에 걸쳐 나뉜** 상황
- Echo Request 는 많은데 Echo Reply 가 없거나, 반대로 Reply 만 있는 비정상 흐름

**ICMP는 원래 데이터 전달용이 아니라 진단용 프로토콜이다.** 페이로드가 표준을 벗어났다는 것 자체가 이미 이상 신호다.

## 문제에서 처음 볼 단서

1. **Protocol Hierarchy 에서 ICMP 비중** — 정상 트래픽에서 ICMP 는 소량이다. 비중이 크면 우선 조사 대상
2. **패킷 목록의 `Length` 컬럼이 들쭉날쭉한지** — 표준 ping 은 매 패킷 크기가 동일하다
3. **`icmp.type` 이 8(Echo Request) 만 있는지** — 응답(Type 0)이 없으면 이 트래픽은 실제 핑이 아니라 **일방적 데이터 전송**일 가능성이 높다
4. **상세 패널 `Internet Control Message Protocol > Data` 의 첫 바이트** — `abcdefghijklmnop...` 로 시작하지 않으면 커스텀 데이터다
5. **`icmp.seq` 값이 연속적인지** — 순서대로 이어 붙이면 문자열이 완성되는 패턴인지 확인

## 30초 절차

```bash
tshark -r capture.pcapng -Y icmp -T fields -e icmp.type -e data.len
```

이 한 줄로 나온 `data.len` 값이 전부 32(Windows)나 48(Linux 계열)로 균일하면 표준 ping 이다. 값이 뒤섞여 있거나 표준값과 다르면 바로 페이로드를 본다.

GUI 3단계:

```text
1. Statistics > Protocol Hierarchy         -> ICMP Bytes/Packets 비중 확인
2. 필터: icmp                              -> Type 컬럼과 Length 컬럼을 나란히 본다
3. 패킷 클릭 > Internet Control Message Protocol > Data  -> 페이로드 직접 확인
```

## 상세 절차

### 1단계 — 표준 payload 크기와 패턴을 기준선으로 잡는다

| 도구/환경 | ICMP 데이터부 기본 크기 | 전형적 패턴 |
| --- | --- | --- |
| Windows `ping.exe` | 32바이트 | 알파벳 반복: `abcdefghijklmnopqrstuvwabcdefghi` |
| Linux `iputils ping` | 48바이트(옵션에 따라 56바이트까지) | 앞부분 타임스탬프 구조체 + 이후 증가하는 바이트 시퀀스 |
| macOS `ping` | 56바이트 | Linux 계열과 유사한 증가 패턴 |
| 사용자 지정(`ping -l N`, `ping -s N`) | 임의 | 임의(0으로 채우거나 반복 패턴) |

이 표는 **일반적으로 관찰되는 값**이다. ping 유틸리티 버전과 옵션에 따라 달라질 수 있으므로, 실제 캡처에서 정상 패킷 하나를 먼저 열어 그 환경의 "기준 패턴"을 확인한 뒤 벗어난 패킷을 찾는 순서가 안전하다.

### 2단계 — 기준을 벗어난 패킷만 남긴다

```text
data.len != 32
```

Windows 기준 ping 이 섞인 캡처라면 이 필터로 비표준 크기 패킷만 남는다. 크기가 다양하면 값 자체를 집계한다.

```bash
tshark -r capture.pcapng -Y icmp -T fields -e data.len | sort -n | uniq -c | sort -nr
```

한 값에 몰려 있지 않고 값이 들쭉날쭉하면, **패킷마다 다른 길이의 데이터를 실어 나르고 있다는 뜻**이다. 이는 곧 가변 길이 메시지 전송이다.

### 3단계 — 페이로드를 순서대로 꺼낸다

핵심은 `icmp.seq` 순서로 정렬해서 이어 붙이는 것이다. Wireshark 는 두 필드를 제공한다.

| 필드 | 의미 |
| --- | --- |
| `icmp.seq` | 네트워크 바이트 순서(빅 엔디안)로 해석한 sequence 번호 |
| `icmp.seq_le` | 리틀 엔디안으로 해석한 sequence 번호 |

Windows `ping.exe` 는 이 필드를 리틀 엔디안으로 채우는 경우가 있어 `icmp.seq` 만 보면 순서가 뒤죽박죽으로 보일 수 있다. 정렬이 이상하면 `icmp.seq_le` 로 바꿔본다.

```bash
tshark -r capture.pcapng -Y 'icmp.type == 8' \
  -T fields -e icmp.seq_le -e data.data -E header=y | sort -n
```

출력 예시:

```text
icmp.seq_le  data.data
1            666c6167 7b696333 6d705f68
2            34645f70 3477306c 6f34647d
```

`data.data` 는 콜론 없는 hex 문자열로 나온다. 순서대로 이어 붙여 hex → ASCII 로 바꾼다.

```bash
tshark -r capture.pcapng -Y 'icmp.type == 8' -T fields -e icmp.seq_le -e data.data \
  | sort -n | awk '{print $2}' | tr -d '\n' | xxd -r -p
```

```text
flag{ic3mp_h4d_p4yl0ad}
```

### 4단계 — GUI 에서 손으로 확인하는 방법

```text
1. 필터: icmp.type == 8
2. 컬럼 우클릭 > Column Preferences > 필드 추가 (icmp.seq_le, data.len)
3. 패킷 하나 클릭 > 상세 패널 하단 Data (X bytes) 펼치기
4. Data 바이트를 우클릭 > Copy > ...as Hex Stream
```

패킷 수가 적으면(수십 개 이내) GUI 로 하나씩 복사해 이어 붙이는 것이 오히려 빠르다. 수백 개 이상이면 tshark 일괄 처리로 넘어간다.

### 5단계 — base64 / 인코딩 여부를 의심한다

ICMP 페이로드에 출력 가능한 ASCII 가 보이지만 알아볼 수 없는 문자열이면 base64 를 의심한다.

```bash
tshark -r capture.pcapng -Y icmp -T fields -e data.data \
  | tr -d '\n:' | xxd -r -p | base64 -d 2>/dev/null
```

디코딩이 실패하면 hex 로 남겨두고 각 패킷 조각이 base64 문자열 하나를 나눠 실은 것은 아닌지, 즉 **패킷 경계와 인코딩 경계가 일치하는지**를 먼저 확인한다.

## 출력 필드 해석

| 필드 | 의미 | 확인 포인트 |
| --- | --- | --- |
| `icmp.type` | 8=Echo Request, 0=Echo Reply | 한쪽만 있으면 비정상 |
| `icmp.code` | Echo 계열은 항상 0 | 0이 아니면 다른 종류의 ICMP 메시지 |
| `icmp.ident` | 세션/프로세스 식별자 | 한 파일에 여러 값이 섞이면 여러 스트림이 겹쳐 있다는 뜻 |
| `icmp.seq` / `icmp.seq_le` | 순서 번호 | 재조립 순서. 엔디안을 바꿔가며 확인 |
| `data.len` | 페이로드 바이트 수 | 표준값과 다르면 1차 단서 |
| `data.data` | 페이로드 원본(hex) | 최종 디코딩 대상 |

## pivot: 다음에 볼 artifact

| ICMP payload에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| 짧은 flag 문자열 하나 | 그대로 제출. 추가 조사 불필요 |
| 반복적으로 오가는 대량 ICMP | 지속적 채널 여부 확인 → [FOR-0170](./icmp-tunneling.html) |
| ICMP 소스/목적지 IP | 그 IP 의 다른 프로토콜 트래픽 → [FOR-0182](./ip-addr-filter.html) |
| base64/hex 로 인코딩된 조각 | 전체 pcap 트리아지로 복귀해 다른 채널과 대조 → [FOR-0146](./wireshark-30sec-triage.html) |
| 특정 `icmp.ident` 값 | 그 값으로만 필터링해 다른 세션과 분리 |

## 흔한 함정

- **`icmp.seq` 만 보고 순서가 뒤섞였다고 포기하는 것.** Windows 환경은 리틀 엔디안으로 값을 채우는 경우가 있다. `icmp.seq_le` 로 바꿔본다.
- **표준 ping 패턴(`abcdefg...`)을 숨긴 데이터로 오인하는 것.** 32바이트 알파벳 반복은 Windows 기본값이다. 먼저 정상 패킷 하나로 기준선을 잡는다.
- **Echo Reply 를 무시하는 것.** 요청뿐 아니라 응답 페이로드에도 데이터가 실릴 수 있다. `icmp.type == 0` 도 함께 확인한다.
- **`data.len` 이 전부 같다고 안심하는 것.** 크기가 균일해도 내용이 표준 패턴과 다르면 여전히 숨긴 데이터다. 크기만이 아니라 내용도 반드시 확인한다.
- **hex 문자열의 구분자(콜론)를 제거하지 않고 바로 `xxd -r -p` 에 넣는 것.** `data.data` 출력은 버전에 따라 콜론 구분 hex 로 나올 수 있다. `tr -d ':'` 로 먼저 제거한다.
- **패킷 하나만 보고 결론 내리는 것.** flag 가 여러 패킷에 나뉜 경우가 흔하다. 반드시 같은 `icmp.ident` 를 가진 패킷 전체를 순서대로 모은다.
- **다른 `icmp.ident` 값이 섞인 것을 한 메시지로 이어 붙이는 것.** 여러 ping 세션이 겹쳐 있으면 ident 로 먼저 분리해야 한다.
- **ICMP 자체를 노이즈로 넘기는 것.** 정상 네트워크 트러블슈팅에도 ICMP 는 존재하지만, **payload 내용까지 확인하지 않고 넘기면** 숨긴 데이터를 통째로 놓친다.

## 교차검증

```bash
# 1) 타입별 개수와 payload 크기 분포
tshark -r capture.pcapng -Y icmp -T fields -e icmp.type -e data.len

# 2) seq 순서대로 payload 나열 (빅 엔디안 기준)
tshark -r capture.pcapng -Y icmp -T fields -e icmp.seq -e data.data | sort -n

# 3) seq 순서대로 payload 나열 (리틀 엔디안 기준, Windows 대응)
tshark -r capture.pcapng -Y icmp -T fields -e icmp.seq_le -e data.data | sort -n

# 4) ident 별로 그룹화해 세션 분리
tshark -r capture.pcapng -Y icmp -T fields -e icmp.ident -e icmp.seq_le -e data.data | sort -k1,1n -k2,2n

# 5) 이어 붙여 hex -> 텍스트 변환까지 한 번에
tshark -r capture.pcapng -Y 'icmp.type == 8' -T fields -e icmp.seq_le -e data.data \
  | sort -n | awk '{print $2}' | tr -d '\n' | xxd -r -p

# 6) GUI 와 대조 - Follow 는 ICMP 를 지원하지 않으므로 data.data 추출이 사실상 유일한 방법
```

GUI 에는 ICMP 전용 Follow Stream 기능이 없다. tshark 로 `data.data` 를 뽑는 것이 GUI 로 패킷 하나씩 열어보는 것을 대체하는 유일한 일괄 처리 방법이다.

## mini walkthrough

```text
문제:
"공격자가 ping을 이용해 짧은 메시지를 전송했다. 무엇을 보냈는가?"
첨부: ping_hidden.pcapng (64 packets)

1. 첫 시도 (실패) - Follow 기능을 찾았다
   패킷 우클릭 > Follow 메뉴를 열었으나 TCP/UDP/HTTP/TLS 만 있고
   ICMP 항목이 없었다. Follow Stream 으로 바로 못 본다는 것을 확인.

2. 접근 변경 - Protocol Hierarchy 먼저 확인
   Statistics > Protocol Hierarchy
     Internet Control Message Protocol   100%   64   6208 bytes
   -> 파일 전체가 ICMP 뿐이다. 표준 ping 인지부터 확인한다.

3. 표준 패턴인지 확인
   필터: icmp.type == 8
   패킷 1의 Data 필드: 61 62 63 64 65 66 67 (a b c d e f g ...)
   -> Windows 표준 32바이트 패턴처럼 보인다. 그러나 data.len 을 집계해보니:

   tshark -r ping_hidden.pcapng -Y icmp -T fields -e data.len | sort | uniq -c
        32 32     <- 절반은 표준 32바이트
        32 8      <- 나머지 절반은 8바이트뿐

   -> 8바이트짜리 패킷들이 이상 신호다. 표준 ping 에 8바이트는 없다.

4. 8바이트 패킷만 순서대로 추출
   tshark -r ping_hidden.pcapng -Y 'icmp.type == 8 && data.len == 8' \
     -T fields -e icmp.seq_le -e data.data | sort -n

     1   666c6167
     2   7b706e67
     3   5f68316e
     4   745f3472
     5   65616c7d

5. 이어 붙여 디코딩
   $ echo -n "666c61677b706e675f68316e745f347265616c7d" | xxd -r -p
   flag{png_h1nt_4real}

정답: flag{png_h1nt_4real}
```

1단계의 실패가 교훈이다. **ICMP 는 Follow Stream 대상이 아니다.** `data.data` 필드를 tshark 로 직접 뽑아 순서대로 이어 붙이는 것이 유일하게 확실한 방법이다.

## 막혔을 때 다음 체크

1. `Statistics > Protocol Hierarchy` 에서 ICMP 비중을 확인했는가
2. `data.len` 값을 집계해 표준값(32/48/56)과 다른 것을 찾았는가
3. `icmp.type == 8` 과 `== 0` 을 둘 다 확인했는가
4. `icmp.seq` 로 정렬이 이상하면 `icmp.seq_le` 로 바꿔봤는가
5. 여러 `icmp.ident` 가 섞여 있어 세션을 분리해야 하는가
6. `data.data` 를 hex → ASCII 로 이어 붙였는가
7. 이어 붙인 결과가 base64 로 보이는가 → `base64 -d` 시도
8. 첫 몇 바이트가 `flag{` 나 알아볼 수 있는 헤더로 시작하는가
9. 표준 ping 패턴(`abcdefg...`)과 혼동하지 않았는가
10. 지속적인 ICMP 트래픽이라면 터널링([FOR-0170](./icmp-tunneling.html))으로 관점을 넓혔는가

## 출처

- SRC-067 — RFC 792 (ICMP): Echo Request/Reply(Type 8/0)의 헤더 구조와 데이터부가 임의 길이를 가질 수 있다는 규정
- SRC-002 — Wireshark Display Filter Reference: `icmp.type`, `icmp.code`, `icmp.ident`, `icmp.seq`, `icmp.seq_le`, `data.data`, `data.len` 필드명 확인
- SRC-010 — tshark man page: `-T fields -e`, `-Y` 필터 문법
- Windows/Linux ping 의 기본 payload 크기와 패턴(32바이트 알파벳 반복, 48~56바이트 증가 시퀀스)은 RFC 792 에 규정된 값이 아니라 각 ping 구현체의 관례적 동작이다. 버전에 따라 달라질 수 있으므로 실제 캡처의 정상 패킷 하나로 기준선을 먼저 확인할 것
