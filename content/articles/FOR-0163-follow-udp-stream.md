---
id: FOR-0163
title: "Follow UDP Stream 사용법"
slug: "follow-udp-stream"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "UDP conversation"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["UDP", "TFTP", "syslog", "SNMP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z follow,udp,ascii,0", "tshark -r capture.pcapng -q -z follow,udp,hex,0", "tshark -r capture.pcapng -Y \"udp.stream==0\" -T fields -e frame.number -e frame.time_relative -e udp.length"]
regex_patterns: []
wireshark_filters: ["udp.stream eq 0", "udp.stream eq 0 && data.len > 0"]
tshark_fields: ["udp.stream", "udp.length", "frame.time_relative", "data.len"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["Follow UDP Stream", "UDP 스트림 재조합"]
keywords: ["Follow UDP Stream", "UDP 스트림 재조합", "udp.stream", "TFTP 복원", "syslog 원문", "UDP 순서 보장 없음", "데이터그램 이어붙이기", "Show data as", "Raw 저장"]
aliases: ["udp follow stream", "udp 스트림 내용 보기", "udp 대화 내용 확인", "udp 통째로 보기", "udp 텍스트로 복원"]
symptom_keywords: ["UDP 패킷을 하나씩 봐서는 전체 내용을 모르겠다", "TFTP로 전송된 내용을 통째로 읽고 싶다", "syslog 원문을 한 번에 보고 싶다", "udp 대화 내용이 순서대로 안 보인다"]
related: ["FOR-0176", "FOR-0162", "FOR-0155", "FOR-0169"]
source_ids: ["SRC-002", "SRC-003", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Follow > UDP Stream` 은 같은 (출발지 IP·포트, 목적지 IP·포트) 조합의 데이터그램을 **캡처에 도착한 순서 그대로** 이어 붙여 보여준다. TCP 와 달리 시퀀스 번호로 재정렬하지 않으므로, 평문 프로토콜(TFTP, syslog, SNMP)의 내용을 빠르게 읽을 때는 유용하지만 **바이트 순서가 절대적으로 정확해야 하는 파일 복원에는 Hex Dump 로 데이터그램 경계를 직접 확인한 뒤 신뢰한다.**

## 어떤 문제에서 필요한가

- TFTP·syslog·SNMP·커스텀 UDP 프로토콜처럼 평문 데이터가 여러 데이터그램에 걸쳐 있을 때
- `udp.stream` 하나를 지정해 그 대화의 전체 내용을 한 화면에서 읽어야 할 때
- Protocol Hierarchy 에서 UDP 트래픽에 사람이 읽을 수 있는 문자열이 섞여 있는 것을 확인했을 때
- UDP 로 전송된 명령/응답 시퀀스를 순서대로 훑어야 할 때

UDP 관련 통계·필터 전반(`udp.stream` 필터링, Conversations, 포트 분류)은 [FOR-0176](./udp-flow-analysis.html) 을 먼저 본다. 이 글은 **Follow 기능 자체**의 사용법과 한계에 집중한다.

## 문제에서 처음 볼 단서

1. **UDP 패킷 우클릭 메뉴에 `Follow > UDP Stream` 항목이 존재** — TCP 전용 기능이 아니다
2. **Info 컬럼에 평문 명령/응답** (`RRQ`, `WRQ`, syslog 메시지, SNMP OID) — Follow 로 한 번에 읽을 가치가 있다는 신호
3. **같은 4-tuple 로 여러 패킷이 짧은 시간 내 반복** — 하나의 논리적 전송이 여러 데이터그램으로 쪼개져 있다
4. **Protocol Hierarchy 의 UDP 하위 `Data`** — 파서가 못 읽은 페이로드. Follow 로 열어 사람이 읽을 수 있는 부분이 있는지 먼저 확인한다

## 30초 절차

```bash
tshark -r capture.pcapng -q -z follow,udp,ascii,0
```

GUI 3단계:

```text
1. 대상 UDP 패킷 하나 우클릭
2. Follow > UDP Stream 클릭
3. Show data as 를 ASCII / Hex Dump 로 전환하며 내용 확인
```

## 상세 절차

### 1단계 — 메뉴 위치와 필터 자동 생성

UDP 패킷 우클릭 → `Follow > UDP Stream`. 클릭하면 메인 창 필터에 `udp.stream eq N` 이 자동으로 걸리고, 새 창에 그 스트림의 데이터그램들이 도착 순서대로 표시된다.

TCP 의 Follow 와 마찬가지로 색상은 방향만 구분한다(빨강/파랑). 창 상단 드롭다운으로 `Entire conversation` 또는 한쪽 방향만 선택할 수 있는 것도 동일하다.

### 2단계 — UDP 는 "이어붙이기"이지 "재조립"이 아니다

TCP Follow 는 시퀀스 번호로 순서를 **보장**해 재조립한다. UDP 에는 그런 번호가 없으므로 Wireshark 는 **그 스트림에 속한 데이터그램을 프레임 번호(캡처 도착 순서) 그대로 이어 붙일 뿐**이다.

| | TCP Follow | UDP Follow |
| --- | --- | --- |
| 순서 기준 | `tcp.seq` (재정렬 가능) | 프레임 도착 순서 (재정렬 없음) |
| 네트워크가 순서를 바꿔 배달했을 때 | 원래 순서로 복원됨 | **뒤바뀐 순서 그대로 보임** |
| 손실된 데이터그램 | 손실 여부를 `tcp.analysis.lost_segment` 로 알 수 있음 | UDP 에는 이런 판정 필드가 없다. 애플리케이션 계층 번호(TFTP block 번호 등)로 직접 확인해야 한다 |

그래서 순서에 민감한 바이너리를 복원할 때는, Follow 창만 믿지 말고 **애플리케이션 프로토콜 자체에 내장된 순번**(TFTP 의 block 번호, 커스텀 프로토콜의 시퀀스 필드)을 별도로 확인한다.

### 3단계 — Show data as 옵션은 TCP 와 동일하다

| 옵션 | 용도 |
| --- | --- |
| ASCII | syslog 원문, TFTP 옵션 협상, SNMP community string 읽기 |
| Hex Dump | 데이터그램 경계와 헤더 바이트를 눈으로 구분 |
| Raw | 바이너리 파일 복원 시 저장용 |
| UTF-8 | 멀티바이트 문자가 깨질 때 |

**Hex Dump 로 전환하면 각 데이터그램이 시작하는 지점을 눈으로 짐작할 수 있다.** ASCII 뷰만으로는 데이터그램 경계가 보이지 않아, 두 데이터그램이 이어진 지점에서 헤더 바이트가 텍스트 중간에 섞여 들어간 것을 놓치기 쉽다.

### 4단계 — 대표 평문 UDP 프로토콜에서 바로 쓰는 법

| 프로토콜 | 포트 | Follow 로 보이는 것 |
| --- | --- | --- |
| TFTP | 69 | `RRQ`/`WRQ` 파일명, `DATA`/`ACK` 블록 번호, 전송된 바이트 |
| syslog | 514 | 로그 메시지 원문 (PRI, 타임스탬프, 호스트, 메시지) |
| SNMP | 161/162 | community string 평문, OID, 값 (SNMPv1/v2c 한정) |
| 커스텀 프로토콜 | 임의 | 파서가 없어 `Data` 로만 보이지만 Follow 의 ASCII/Hex 뷰에서 내용은 그대로 확인 가능 |

TFTP 는 파일 하나가 여러 `DATA` 데이터그램(기본 블록 크기 512바이트)으로 나뉜다. Follow 창에서 이어 붙여 보이는 내용이 파일 전체가 맞는지는, 마지막 데이터그램이 512바이트 미만인지(TFTP 종료 조건)로 확인한다.

### 5단계 — 신뢰할 수 없는 상황을 먼저 판별한다

Follow 결과를 그대로 파일로 저장하기 전에 다음을 확인한다.

```text
1. udp.stream eq N 필터로 이 스트림의 패킷 수를 센다
2. frame.time_relative 를 컬럼으로 올려 시간 간격이 균일한지 본다
   -> 간격이 들쭉날쭉하거나 순서가 이상하면 재정렬 없이 이어붙인 결과를 의심한다
3. 짧은 시간(수 ms) 안에 같은 내용으로 보이는 데이터그램이 중복되는지 확인한다
   -> UDP 에는 재전송 개념이 없으므로, 중복은 애플리케이션이 응답을 못 받아
      스스로 재전송한 것이다. Follow 결과에 같은 내용이 두 번 나타난다
```

### 6단계 — 파일 복원: 방향을 분리하고 Raw 로 저장

```text
1. 드롭다운에서 파일이 실려 있는 방향 하나만 선택
2. Show data as = Raw
3. Save as... 로 저장
4. file / strings 로 확인
```

큰 스트림은 GUI 표시가 잘릴 수 있으므로 tshark 로 대체한다.

```bash
tshark -r capture.pcapng -q -z follow,udp,hex,0
```

## 출력 필드 해석

Follow 창 자체에는 필드가 없지만, 판정에 쓰는 패킷 목록 필드는 다음과 같다.

| 필드 | 의미 | 실전 용도 |
| --- | --- | --- |
| `udp.stream` | Wireshark 가 부여한 대화 번호 | Follow 창과 필터를 연결하는 키 |
| `udp.length` | UDP 헤더 8바이트를 포함한 길이 | 페이로드 크기 = `udp.length - 8` |
| `data.len` | 파서가 못 읽은 페이로드 바이트 수 | 커스텀 프로토콜 데이터그램 크기 판정 |
| `frame.time_relative` | 캡처 시작 기준 상대 시각 | 데이터그램 간 간격으로 비콘/재전송 여부 판정 |

## pivot: 다음에 볼 artifact

| Follow UDP Stream 에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| TFTP 로 전송된 파일 | `file`/`strings` 로 종류 확인 ([FOR-0001](./30sec-triage.html)) |
| syslog 원문의 호스트명/IP | 그 호스트의 EVTX/auth.log 대조 |
| SNMP community string | 자격증명 후보로 다른 로그온 시도와 대조 |
| 반복되는 짧은 데이터그램(비콘 의심) | 전체 UDP 흐름 통계로 확장 ([FOR-0176](./udp-flow-analysis.html)) |
| Base32/64 처럼 보이는 페이로드 | DNS 가 아닌 UDP 채널의 터널링 여부 확인 ([FOR-0155](./dns-tunneling.html)) |
| 같은 스트림에서 확인한 커스텀 헤더 구조 | ICMP 등 다른 프로토콜에도 같은 패턴이 있는지 확인 ([FOR-0169](./icmp-payload.html)) |

## 흔한 함정

- **UDP Follow 결과가 TCP 처럼 순서를 보장한다고 믿는 것.** 시퀀스 번호가 없으므로 캡처 도착 순서일 뿐이다. 네트워크 경로에서 순서가 바뀌었다면 Follow 결과도 뒤섞인다.
- **클라이언트가 매 요청마다 포트를 바꾸는 프로토콜(DNS 등)에 Follow UDP Stream 을 걸어 "전체"라고 믿는 것.** 그 포트 조합의 왕복 하나만 보인다. 여러 스트림을 따로 열어야 한다.
- **`Entire conversation` 상태로 바이너리를 Raw 저장하는 것.** 양방향이 섞여 파일이 깨진다. 방향을 하나만 선택한다.
- **큰 스트림에서 GUI 표시가 잘렸는데 전체라고 판단하는 것.** `tshark -z follow,udp,...` 로 전체를 뽑아 길이를 비교한다.
- **애플리케이션 계층 재전송(중복 데이터그램)을 놓치는 것.** UDP 에는 `tcp.analysis.retransmission` 같은 판정이 없다. 같은 내용이 반복되면 수동으로 프레임 번호와 시간 간격을 비교해 중복을 골라낸다.
- **ASCII 뷰만 보고 데이터그램 경계를 무시하는 것.** 헤더 바이트가 텍스트 중간에 섞여 들어가도 ASCII 로는 깨진 문자 몇 개로만 보인다. Hex Dump 로 각 데이터그램의 시작을 확인한다.
- **`Follow > UDP Stream` 메뉴가 안 보이면 캡처에 문제가 있다고 판단하는 것.** UDP 계층이 있는 패킷이면 항상 메뉴가 뜬다. 안 보이면 해당 패킷이 UDP 가 아니라 다른 프로토콜(ICMP 등)일 가능성을 먼저 확인한다.
- **한글/멀티바이트 로그가 깨진 채로 포기하는 것.** `Show data as = UTF-8` 또는 `Hex Dump` 로 바이트를 직접 확인해 인코딩을 판단한다.

## 교차검증

```bash
# 1) GUI Follow UDP Stream 과 동일한 텍스트
tshark -r capture.pcapng -q -z follow,udp,ascii,0

# 2) hex 로 데이터그램 경계 확인
tshark -r capture.pcapng -q -z follow,udp,hex,0

# 3) 이 스트림의 패킷별 크기/시간 — 중복·간격 확인
tshark -r capture.pcapng -Y "udp.stream==0" -T fields \
  -e frame.number -e frame.time_relative -e udp.length

# 4) 양방향 데이터그램 개수 — 한쪽이 0이면 응답 없는 전송(단방향)
tshark -r capture.pcapng -Y "udp.stream==0" -T fields -e ip.src | sort | uniq -c
```

GUI 창의 바이트 수와 `-z follow,udp,ascii,N` 출력 길이가 다르면 GUI 가 잘렸을 가능성이 높다. tshark 결과를 정답으로 쓴다.

## mini walkthrough

```text
문제:
"TFTP로 전송된 설정 파일 안의 관리자 비밀번호를 찾으세요."
첨부: tftp_case.pcapng (612 packets)

1. Statistics > Protocol Hierarchy
   UDP 96%  TFTP 71% (Data)  -> TFTP 전송이 대부분

2. 필터: tftp
   RRQ config.bin 요청 확인, 이어서 DATA 블록들이 이어진다.

3. 첫 시도 (실패) — DATA 패킷 하나에 Follow UDP Stream 사용
   특정 DATA 패킷(블록 15번) 우클릭 > Follow > UDP Stream
   -> 데이터 채널의 포트가 전송 시작 시 매번 새로 협상되므로,
      이 스트림에는 RRQ 요청(69번 포트)이 빠져 있고 오직 데이터 채널만 보였다.
      파일 시작 부분이 없어 헤더가 깨진 것처럼 보였다.
   원인: TFTP 는 제어(69번 포트)와 데이터(임의 포트)가 서로 다른
        udp.stream 으로 분리된다.

4. 접근 변경 — 데이터 채널의 첫 DATA 패킷(블록 1)에서 다시 연다
   필터: tftp.opcode == 3 && tftp.block == 1
   해당 패킷 우클릭 > Follow > UDP Stream
   Show data as = Hex Dump

     0000  00 03 00 01 23 4d 5a 90 00 03 00 00 00 04 00 00
     0010  00 ff ff 00 00 b8 00 00 00 00 00 00 40 00 00 00
     ...
   -> 앞 4바이트(00 03 00 01)는 TFTP DATA 헤더(opcode + block 번호).
      그 다음부터 실제 파일 바이트(MZ 헤더!)가 시작된다.

5. Raw 로 저장 후 헤더 4바이트씩 제거
   Show data as = Raw, 방향은 서버->클라이언트만 선택, Save as raw_stream.bin

   $ python3 -c "
   data = open('raw_stream.bin','rb').read()
   # 블록마다 4바이트 TFTP 헤더가 섞여 있어 512+4 단위로 헤더를 제거
   out = b''
   for i in range(0, len(data), 516):
       out += data[i+4:i+516]
   open('config.bin','wb').write(out)
   "
   $ file config.bin
   config.bin: PE32 executable

   $ strings config.bin | grep -i admin
   admin_password=Str0ngP@ss2026

정답: Str0ngP@ss2026
```

3단계의 실패가 핵심이다. **TFTP 는 제어 채널과 데이터 채널이 서로 다른 `udp.stream` 이므로, 임의의 DATA 패킷에서 연 Follow 창에는 처음 몇 바이트가 빠질 수 있다는 것을 항상 의심해야 한다.** block 번호가 1인 첫 데이터그램에서 다시 열어야 파일 시작 부분을 놓치지 않는다.

## 막혔을 때 다음 체크

1. `Follow > UDP Stream` 메뉴가 보이는가 — UDP 패킷이 맞는지 확인
2. 이 스트림이 정말 전체 전송을 담고 있는가 — TFTP 처럼 제어/데이터 채널이 분리되는 프로토콜인지 확인
3. `frame.time_relative` 간격이 고르지 않은가 — 순서 뒤바뀜 의심
4. 같은 내용이 반복되는가 — 애플리케이션 레벨 재전송 의심
5. `Show data as` 를 Hex Dump 로 바꿔 데이터그램 경계를 확인했는가
6. 바이너리 복원 시 방향을 하나만 선택했는가
7. GUI 표시가 잘렸는가 — tshark `follow,udp,hex` 로 전체 길이 비교
8. 여러 `udp.stream` 중 맞는 것을 골랐는가 ([FOR-0176](./udp-flow-analysis.html))
9. 페이로드가 Base32/64 처럼 보이는가 — 터널링 라인으로 전환 ([FOR-0155](./dns-tunneling.html))
10. 프로토콜 전용 헤더(블록 번호, 시퀀스 필드)를 고려해 페이로드를 잘라냈는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `udp.stream`, `udp.length`, `data.len`, `frame.time_relative` 필드명 확인
- SRC-003 — Wireshark User's Guide: `Follow > UDP Stream`, Show and save data as 옵션, 방향 선택 드롭다운
- SRC-010 — tshark man page: `-z follow,udp,ascii,<stream>`, `-z follow,udp,hex,<stream>`
- TFTP 의 DATA 패킷 헤더 구조(2바이트 opcode + 2바이트 block 번호)와 블록 크기(기본 512바이트)는 일반적인 TFTP 구현 관례이며, 실제 옵션 협상(blksize 등)에 따라 달라질 수 있으므로 캡처에서 `tftp.blksize` 옵션을 직접 확인할 것
- Follow Stream 창의 정확한 배색과 드롭다운 문구는 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
