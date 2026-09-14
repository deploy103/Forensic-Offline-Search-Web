---
id: FOR-0162
title: "Follow TCP Stream으로 세션 전체 대화 복원하기"
slug: "follow-tcp-stream"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "TCP stream"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z follow,tcp,ascii,0", "tshark -r capture.pcapng -q -z follow,tcp,raw,0 > stream0.raw", "tshark -r capture.pcapng -Y \"tcp.stream==0\" -T fields -e frame.number -e tcp.seq -e tcp.len"]
regex_patterns: []
wireshark_filters: ["tcp.stream eq 0", "tcp.stream eq 0 && tcp.analysis.retransmission"]
tshark_fields: ["tcp.stream", "tcp.seq", "tcp.len", "tcp.nxtseq"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["Follow TCP Stream", "TCP 스트림 재조합"]
keywords: ["Follow TCP Stream", "TCP 스트림 재조합", "Show data as", "Raw 저장", "tcp.stream", "스트림 재구성", "패킷 재조립", "전체 대화 복원", "Follow Stream 창", "ASCII Hex Dump"]
aliases: ["follow stream 사용법", "tcp 대화 전체 보기", "패킷 재조립해서 읽기", "follow tcp stream 저장", "스트림 내용 저장", "tcp 스트림 텍스트로 보기"]
symptom_keywords: ["패킷을 하나씩 봐서는 전체 내용을 알 수 없다", "대화 내용을 통째로 읽고 싶다", "전송된 파일을 바이트 그대로 꺼내고 싶다", "따로따로 보이는 패킷을 이어붙이고 싶다"]
related: ["FOR-0164", "FOR-0175", "FOR-0165", "FOR-0181"]
source_ids: ["SRC-003", "SRC-002", "SRC-066"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

패킷 하나를 우클릭해 `Follow > TCP Stream` 을 열면 시퀀스 번호로 재조립된 **그 연결 전체의 클라이언트-서버 대화**가 한 화면에 나온다. 텍스트 프로토콜(HTTP, FTP, SMTP, Telnet)은 그대로 읽고, 바이너리를 복원할 때는 `Show data as`를 `Raw`로 바꾼 뒤 **한쪽 방향만** 골라 저장한다.

## 어떤 문제에서 필요한가

- HTTP/FTP/SMTP/Telnet 처럼 평문으로 오간 로그인·명령·데이터를 한 번에 읽어야 할 때
- 여러 패킷에 걸쳐 전송된 파일을 바이트 단위로 그대로 복원해야 할 때 (Export Objects 가 인식하지 못하는 프로토콜)
- 패킷 목록에서 조각조각 보이는 요청/응답을 시간 순서대로 이어 읽어야 할 때
- "몇 번째 명령이 성공했는가", "어떤 순서로 대화가 오갔는가"를 판정해야 할 때

패킷 목록의 `Info` 컬럼만 보고 내용을 짐작하는 것은 대부분 틀린다. Follow TCP Stream 이 첫 번째로 열어야 할 창이다.

## 문제에서 처음 볼 단서

1. **패킷 목록에 같은 IP 쌍이 반복** — 하나의 TCP 대화가 여러 패킷으로 쪼개져 있다는 뜻
2. **Info 컬럼에 `[TCP segment of a reassembled PDU]`** — 애플리케이션 데이터가 여러 세그먼트에 걸쳐 있다. Follow 로만 전체를 볼 수 있다
3. **평문 프로토콜(FTP/SMTP/Telnet/HTTP)** — 암호화되지 않았다면 Follow 로 100% 사람이 읽는 텍스트가 나온다
4. **Protocol Hierarchy 에서 바이트가 큰 TCP 대화** — Follow 로 열어 안에 무엇이 들었는지 직접 확인해야 한다

## 30초 절차

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,0
```

GUI 3단계:

```text
1. 대상 TCP 패킷 하나 우클릭
2. Follow > TCP Stream 클릭
3. 새 창에서 전체 대화 확인. 필요하면 Show data as 를 Raw 로 변경 후 Save as
```

## 상세 절차

### 1단계 — 메뉴 위치와 즉시 벌어지는 일

패킷 목록에서 TCP 패킷 우클릭 → `Follow > TCP Stream` (또는 `Analyze > Follow > TCP Stream`).

클릭 즉시 두 가지가 일어난다.

- 새 창이 뜨고, 그 패킷이 속한 TCP 연결의 **전체 대화**가 시퀀스 번호 순서로 재조립되어 표시된다
- 메인 창의 필터 입력창에 `tcp.stream eq N` 이 자동으로 걸린다 ([FOR-0164](./tcp-stream-filter.html))

**Follow 창은 현재 걸려 있던 Display Filter 를 무시한다.** `http.request` 로 걸러놓고 그중 한 패킷에서 Follow 를 열어도, 창에는 그 스트림의 요청·응답 전부(이미지, 헤더, 본문 전부)가 나온다. 요청만 보고 싶었다면 착각이다.

### 2단계 — 색으로 방향을 읽는다

기본 배색은 다음과 같다.

| 색 | 방향 |
| --- | --- |
| 빨강 | 이 스트림에서 먼저 데이터를 보낸 쪽 (대개 클라이언트 → 서버) |
| 파랑 | 그 반대쪽 (대개 서버 → 클라이언트) |

색은 **누가 공격자인지**를 알려주지 않는다. 순전히 방향 구분이다. 배색은 `Edit > Preferences > Appearance > Colors` 에서 바꿀 수 있다.

### 3단계 — 창 상단 드롭다운으로 방향을 분리한다

Follow Stream 창 위쪽에는 다음을 고르는 드롭다운이 있다.

```text
Entire conversation (48213 bytes)
10.0.0.15:49812 -> 203.0.113.77:80 (612 bytes)
203.0.113.77:80 -> 10.0.0.15:49812 (47601 bytes)
```

- **Entire conversation** — 두 방향을 시간 순서로 섞어서 함께 표시한다. 사람이 대화 흐름을 읽을 때 쓴다
- **한쪽 방향만** — 요청만, 또는 응답 본문만 순수하게 뽑고 싶을 때 쓴다. **바이너리 파일을 복원할 때는 반드시 이 옵션으로 한쪽만 고른다.**

### 4단계 — Show data as: 어떤 형식으로 볼 것인가

| 옵션 | 용도 |
| --- | --- |
| ASCII | 평문 프로토콜(HTTP 헤더, FTP 명령, SMTP) 읽기 |
| Hex Dump | 바이너리와 텍스트가 섞였을 때 오프셋 확인, 경계 판단 |
| UTF-8 | 한글 등 멀티바이트 문자가 깨질 때 |
| Raw | **바이트를 있는 그대로.** 파일 복원은 이것만 신뢰한다 |
| C Arrays | 코드에 바로 붙여 쓸 바이트 배열이 필요할 때 |
| EBCDIC | 메인프레임 트래픽 등 특수 인코딩 (CTF 에서는 드묾) |

ASCII 로 보면서 "깨끗해 보인다"고 그대로 텍스트를 복사해 파일로 저장하면 **줄바꿈 변환, 널바이트 손실**로 바이너리가 손상된다. 파일 추출은 항상 `Raw`.

### 5단계 — 저장(Save as)으로 바이트를 꺼낸다

```text
1. 드롭다운에서 복원할 방향 하나만 선택 (Entire conversation 아님)
2. Show data as = Raw
3. 우측 하단 Save as... 클릭 -> 파일로 저장
4. 저장된 파일에 file / strings 를 돌려 확인
```

```bash
file extracted.bin
strings extracted.bin | grep -i flag
```

### 6단계 — 큰 스트림에서 잘림(truncation)을 의심한다

스트림이 매우 크면(수십 MB 이상) GUI 창이 전체를 표시하지 못하고 잘릴 수 있다. 이때는 tshark 로 전체를 파일로 뽑는다.

```bash
tshark -r capture.pcapng -q -z follow,tcp,raw,0 > stream0_raw.txt
tshark -r capture.pcapng -q -z follow,tcp,ascii,0 > stream0_ascii.txt
```

`follow,tcp,raw,N` 출력은 hex 문자열이므로 바이너리로 되돌리려면 변환이 필요하다.

```bash
tshark -r capture.pcapng -q -z follow,tcp,raw,0 | tail -n +2 | xxd -r -p > stream0.bin
```

첫 줄은 헤더 정보이므로 `tail -n +2` 로 제외한다. 실제 출력 형식은 버전에 따라 다를 수 있으니 파일 앞부분을 직접 확인한 뒤 변환한다.

## 출력 필드 해석

Follow Stream 창 자체에는 컬럼이 없지만, 재조립 신뢰도를 판단하려면 패킷 목록의 필드를 함께 본다.

| 확인 항목 | 어디서 | 의미 |
| --- | --- | --- |
| `tcp.stream` | 상세 트리 "Transmission Control Protocol" 하단 `[Stream index: N]` | 이 스트림의 고유 번호. 자동으로 필터에 걸린다 |
| `tcp.analysis.lost_segment` | Expert Information / 필터 | 구멍이 있으면 재조립이 불완전하다 |
| `tcp.analysis.retransmission` | 필터 | 같은 데이터가 중복 표시될 수 있다 |
| `[TCP segment of a reassembled PDU]` | Info 컬럼 | 이 패킷은 애플리케이션 계층에서 조각이며 재조립 대상이다 |

재조립 신뢰도가 의심되면 [FOR-0175](./tcp-retransmission.html) 로 먼저 검증한 뒤 Follow 결과를 증거로 쓴다.

## pivot: 다음에 볼 artifact

| Follow Stream 에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| 로그인 자격증명(평문 FTP/Telnet) | EVTX 4624/4625 로 실제 로그온 성공 여부 확인 |
| 실행된 명령 문자열 | Sysmon Event 1 / EVTX 4688 로 실행 여부 대조 |
| 복원한 파일 바이트 | `file`/`strings`/해시 → Amcache, Prefetch 대조 |
| HTTP 헤더의 User-Agent, Host | 브라우저 History 대조 |
| 스트림 번호(`tcp.stream`) | 같은 번호로 다른 필터 적용 ([FOR-0164](./tcp-stream-filter.html)) |
| 재전송이 섞인 흔적 | 재조립 신뢰도 재검증 ([FOR-0175](./tcp-retransmission.html)) |

## 흔한 함정

- **Follow 창이 현재 Display Filter 를 반영한다고 착각하는 것.** `http.request` 필터를 걸어놓고 Follow 를 열어도 창에는 응답 본문까지 전부 나온다. 특정 요청만 보고 싶으면 필터로 패킷 목록을 좁힌 뒤 상세 트리에서 직접 읽는다.
- **바이너리를 ASCII 로 복사-붙여넣기 해서 저장하는 것.** 줄바꿈 변환과 null 바이트 손실로 파일이 깨진다. 항상 `Raw` + `Save as`.
- **`Entire conversation` 상태로 바이너리를 저장하는 것.** 요청과 응답이 시간 순으로 섞여 저장되어 파일 구조가 깨진다. 방향을 하나만 선택한다.
- **재전송이 섞인 스트림을 그대로 신뢰하는 것.** 같은 데이터가 두 번 나타나 명령 횟수를 두 번 세게 된다. `tcp.analysis.retransmission` 을 먼저 확인한다 ([FOR-0175](./tcp-retransmission.html)).
- **같은 4-tuple 이 재연결되면 같은 스트림이라고 가정하는 것.** 새 SYN 핸드셰이크는 새 `tcp.stream` 번호를 받는다. 연결이 끊겼다 다시 맺어지면 Follow 를 다시 열어야 한다.
- **한글/UTF-16 텍스트가 깨진 채로 포기하는 것.** `Show data as` 를 `UTF-8` 로 바꾸거나, 그래도 깨지면 `Hex Dump` 로 실제 바이트를 확인해 인코딩을 직접 판단한다.
- **큰 스트림에서 GUI 표시가 잘렸는데 그것을 전체라고 믿는 것.** tshark 의 `follow,tcp,raw` 로 전체를 파일로 뽑아 비교한다.
- **UDP 패킷에 Follow TCP Stream 을 시도하는 것.** 메뉴 자체가 다르다. UDP 는 `Follow > UDP Stream` 을 쓴다 ([FOR-0163](./follow-udp-stream.html)).

## 교차검증

```bash
# 1) GUI Follow Stream 과 동일한 텍스트
tshark -r capture.pcapng -q -z follow,tcp,ascii,0

# 2) 원본 바이트 (hex) — 파일 복원 검증용
tshark -r capture.pcapng -q -z follow,tcp,raw,0

# 3) 이 스트림의 패킷별 시퀀스/길이 — 재조립이 빈틈없는지 확인
tshark -r capture.pcapng -Y "tcp.stream==0" -T fields \
  -e frame.number -e tcp.seq -e tcp.len -e tcp.nxtseq

# 4) 재전송/누락 여부
tshark -r capture.pcapng -Y "tcp.stream==0 && tcp.analysis.flags" -T fields -e frame.number
```

`tcp.seq` 와 `tcp.nxtseq` 를 나열했을 때 다음 패킷의 `tcp.seq` 가 이전 패킷의 `tcp.nxtseq` 와 정확히 이어지면 구멍 없이 재조립된 것이다.

## mini walkthrough

```text
문제:
"내부 직원이 Telnet 으로 원격 서버에 접속해 실행한 명령과, 그 결과로 얻은
비밀번호를 찾으세요."
첨부: telnet_session.pcapng (2,140 packets)

1. Statistics > Protocol Hierarchy
   TCP 92%  Telnet 8%  -> Telnet 트래픽이 존재

2. 필터: telnet
   Info 컬럼에 한 글자씩 나뉘어 표시된다 (Telnet 은 키 입력 단위로 패킷을 보낸다)
   패킷 하나하나로는 명령을 읽을 수 없다.

3. 첫 시도 (실패)
   Info 컬럼을 위에서 아래로 읽어 글자를 손으로 이어붙이려 했다.
   -> 수백 개 패킷을 손으로 조합하는 것은 비현실적이고 순서를 놓치기 쉽다.

4. 접근 변경 — Follow TCP Stream
   Telnet 패킷 아무거나 우클릭 > Follow > TCP Stream

   빨강(클라이언트 입력)과 파랑(서버 에코+출력)이 섞여 나타난다.

     login: admin
     Password: [입력은 에코 없음, 서버 프롬프트만 보임]
     $ cat /etc/shadow | grep root
     root:$6$xyz...:19000:0:99999:7:::
     $ export SECRET_KEY=flag{t3ln3t_1s_pl41nt3xt}
     $ exit

5. 자격증명 확인
   Password 입력 자체는 로컬 에코가 꺼져 있어 화면에 안 보였지만,
   빨강(클라이언트->서버) 방향만 따로 선택하면 서버로 실제 전송된
   바이트가 그대로 보인다.

   드롭다운: "10.0.0.20:52344 -> 10.0.0.5:23" 선택
   -> P a s s 1 2 3 ! (한 글자씩 전송된 것이 이어져 보인다)

6. 결과 저장
   Show data as = Raw, 서버->클라이언트 방향만 선택, Save as session_out.bin
   $ strings session_out.bin | grep flag
   flag{t3ln3t_1s_pl41nt3xt}

정답: 실행 명령 "export SECRET_KEY=flag{t3ln3t_1s_pl41nt3xt}" / 비밀번호 Pass123!
```

3단계의 실패가 핵심이다. **Telnet 처럼 문자 단위로 패킷이 쪼개지는 프로토콜은 Follow Stream 없이는 사실상 읽을 수 없다.** 방향 드롭다운으로 클라이언트 입력만 분리하면 화면에 안 보이던 비밀번호까지 확인할 수 있다.

## 막혔을 때 다음 체크

1. `Follow > TCP Stream` 메뉴가 회색으로 비활성화되어 있는가 — UDP 패킷을 우클릭한 것은 아닌가
2. 현재 걸려 있던 Display Filter 때문에 원하는 요청만 보인다고 착각하지 않았는가
3. 방향 드롭다운에서 `Entire conversation` 과 개별 방향의 차이를 확인했는가
4. 바이너리를 복원할 때 `Show data as = Raw` 로 바꿨는가
5. 저장 전에 한쪽 방향만 선택했는가
6. `tcp.analysis.retransmission` 이 섞여 있어 내용이 중복되지는 않는가 ([FOR-0175](./tcp-retransmission.html))
7. 한글/멀티바이트 문자가 깨지면 `UTF-8` 또는 `Hex Dump` 로 바꿔봤는가
8. 스트림이 너무 커서 GUI 가 잘렸는가 — tshark `follow,tcp,raw` 로 재확인
9. 저장한 파일에 `file`/`strings`/해시를 돌려 확인했는가
10. 여러 스트림 중 맞는 것을 골랐는가 — `tcp.stream` 번호를 컬럼으로 켜 확인 ([FOR-0164](./tcp-stream-filter.html))

## 출처

- SRC-003 — Wireshark User's Guide: "Follow TCP Stream" 절, Show and save data as 옵션(ASCII/EBCDIC/Hex Dump/C Arrays/UTF-8/Raw), 방향 선택 드롭다운, 색상 코딩
- SRC-002 — Wireshark Display Filter Reference: `tcp.stream`, `tcp.analysis.retransmission`, `tcp.analysis.lost_segment` 필드명 확인
- SRC-066 — RFC 9293 (TCP): 시퀀스 번호 기반 재조립의 근거, 새 연결(SYN)마다 별개의 시퀀스 공간을 갖는다는 원리
- Follow Stream 창의 정확한 배색과 드롭다운 문구는 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
