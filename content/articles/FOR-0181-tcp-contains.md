---
id: FOR-0181
title: "tcp contains로 TCP 페이로드 안 문자열/바이트 검색하기"
slug: "tcp-contains"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "TCP payload"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP", "HTTP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y 'tcp contains \"flag\"' -c 5", "tshark -r capture.pcapng -q -z follow,tcp,ascii,4", "tshark -r capture.pcapng -Y 'tcp.payload contains \"flag\"' -T fields -e tcp.stream"]
regex_patterns: ["flag\\{[^}]+\\}"]
wireshark_filters: ["tcp contains \"flag\"", "tcp contains 66:6c:61:67", "frame contains \"flag\"", "tcp.payload contains \"flag\"", "http.file_data contains \"flag\"", "tcp matches r\"flag\\{.*\\}\""]
tshark_fields: ["tcp.stream", "tcp.payload", "tcp.reassembled.data", "frame.number"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["tcp contains", "TCP 페이로드 문자열 검색"]
keywords: ["tcp contains", "TCP 페이로드 검색", "바이트 문자열 검색", "wireshark contains", "hex 바이트 검색", "패킷 안 문자열 찾기", "tcp.payload", "Follow TCP Stream", "패킷 분할 문자열", "flag 검색 필터", "세그먼트 경계"]
aliases: ["tcp contains 필터", "패킷에서 문자열 찾기", "와이어샤크 문자열 검색", "tcp 안에 flag 찾기", "패킷 페이로드 검색", "wireshark grep"]
symptom_keywords: ["flag 문자열이 필터에 안 걸린다", "tcp contains가 0줄이다", "한 패킷에는 없는데 스트림엔 있다고 한다", "한글이나 유니코드 문자열 검색이 안 된다", "패킷 어디에 문자열이 있는지 모르겠다"]
related: ["FOR-0180", "FOR-0162", "FOR-0146", "FOR-0187"]
source_ids: ["SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`tcp contains "문자열"` 은 **그 패킷 한 개 안의 TCP 헤더+페이로드 바이트**만 뒤진다. 문자열이 TCP 세그먼트 경계에서 두 패킷에 걸쳐 잘리면 0줄이 나온다 — 이때는 필터를 더 손보는 대신 Follow TCP Stream으로 재조립해야 한다.

## 어떤 문제에서 필요한가

- pcap에 있는 문자열(플래그, 비밀번호, 실행된 커맨드)의 위치를 프로토콜 파서 없이 바로 찾아야 할 때
- Wireshark가 프로토콜을 못 알아채 `Data`로만 표시되는 raw TCP 트래픽(커스텀 프로토콜)에서 문자열을 찾아야 할 때
- `frame contains`로 너무 많이 걸려서(이더넷/IP 헤더까지 포함) 검색 범위를 TCP로 좁히고 싶을 때
- 한글/유니코드 문자열이나 특정 hex 시퀀스를 검색해야 할 때
- Protocol Hierarchy에서 알려진 상위 프로토콜이 하나도 안 잡히는데 문자열은 분명히 오간 것으로 보일 때

## 문제에서 처음 볼 단서

1. 지문에 "패킷 안에 문자열이 숨어 있다", "평문으로 전송된 값을 찾아라" 같은 표현
2. Protocol Hierarchy에 HTTP/FTP/SMTP 같은 알려진 프로토콜이 안 잡히고 `Data`로만 표시됨 → 커스텀 프로토콜, `tcp contains`가 사실상 유일한 진입점
3. `frame contains "flag"`는 걸리는데 그 패킷을 열어보면 정작 페이로드가 아니라 우연히 일치한 것처럼 보이는 경우 — hex pane에서 실제 강조 위치 확인 필요
4. 검색어가 짧고 흔한 값(`ok`, `no`, `id`)이면 오탐 가능성이 높다는 신호

## 30초 절차

```bash
tshark -r capture.pcapng -Y 'tcp contains "flag"' -c 5
```

걸리면 그 패킷의 `tcp.stream` 번호를 확인하고 바로 Follow TCP Stream으로 넘어간다. 안 걸리면 `frame contains`로 범위를 넓히고, 그래도 안 걸리면 스트림 재조립 문제(3단계)를 의심한다.

```bash
tshark -r capture.pcapng -Y 'frame contains "flag"' -c 5
```

## 상세 절차

### 1단계 — 검색 범위: `frame` vs `tcp` vs `tcp.payload`

`contains`는 프로토콜 이름이나 필드 이름 뒤에 붙어 **그 노드가 차지하는 바이트 범위 안**에서 문자열/바이트열을 찾는다. 어디에 붙이느냐로 검색 범위가 완전히 달라진다.

| 필터 | 검색 범위 | 특징 |
| --- | --- | --- |
| `frame contains "x"` | 프레임 전체 (Ethernet+IP+TCP+데이터) | 가장 넓다. IP/TCP 헤더의 숫자가 우연히 매칭될 수 있다 |
| `tcp contains "x"` | 그 패킷의 TCP 헤더+데이터 | Ethernet/IP 헤더는 제외. 실무 기본값 |
| `tcp.payload contains "x"` | TCP 헤더를 뺀 **데이터 부분만** | 가장 정밀. 헤더 바이트 오탐이 없다 |
| `udp contains "x"` / `udp.payload contains "x"` | UDP 버전 | DNS 터널링 등에서 사용 |
| `http.file_data contains "x"` | HTTP 재조립·압축 해제된 본문 | 청크/gzip 해제 이후 값 |
| `data contains "x"` | 파서가 인식 못한 잔여 바이트(`Data` 레이어) | 커스텀 프로토콜에서 `tcp`보다 좁게 잡힐 수 있음 |

`tcp.payload`는 셋 중 오탐이 가장 적다. 검색어가 3~4바이트로 짧을 때는 `tcp contains` 대신 `tcp.payload contains`를 쓴다. 검색어가 8바이트 이상이면 셋의 결과 차이는 실무적으로 거의 없다.

### 2단계 — 문자열 vs hex 바이트

```text
tcp contains "flag"
tcp contains 66:6c:61:67
```

두 표현은 ASCII 기준으로 동일한 바이트열을 찾는다. hex 표기가 필요한 대표 상황:

| 상황 | 이유 |
| --- | --- |
| UTF-16LE로 전송된 문자열(Windows 클라이언트) | 문자마다 `00`이 끼어 `contains "문자열"`이 그대로는 안 걸린다 |
| 셸이 따옴표를 삼켜 문자열 리터럴을 못 쓸 때 | hex는 따옴표가 필요 없다 ([FOR-0185](./tshark-display-filter.html)) |
| 널바이트를 포함한 바이너리 매직 값 | 문자열로 표현이 안 된다 |
| 대소문자가 섞인 값을 바이트 그대로 고정하고 싶을 때 | `matches "(?i)..."` 보다 명확하다 |

```text
tcp contains 66:00:6c:00:61:00:67:00
```

문자열을 콜론 구분 hex로 바꾸는 방법은 [FOR-0185](./tshark-display-filter.html)의 hex 변환 절 참고.

### 3단계 — 스트림 경계에서 잘린 문자열

`contains`는 **패킷(프레임) 하나** 단위로 평가된다. TCP가 문자열을 두 세그먼트로 나눠 보내면 어느 프레임에도 전체 문자열이 존재하지 않으므로 `tcp contains`도 `frame contains`도 0줄이다.

```text
패킷 210: ...GET /secret?token=fl
패킷 211: ag{real_token} HTTP/1.1...
```

`tcp contains "flag{"` → 0줄. 문자열이 없는 게 아니라 **잘려 있을 뿐**이다.

재조립된 바이트를 보는 방법:

| 방법 | 명령/경로 |
| --- | --- |
| GUI Follow TCP Stream | 패킷 우클릭 > Follow > TCP Stream, 전체 텍스트에서 검색 |
| tshark 스트림 재조립 출력 | `tshark -r capture.pcapng -q -z follow,tcp,ascii,<stream>` |
| 알려진 상위 프로토콜이면 그 재조립 필드 | `http.file_data contains "flag"` (재조립 preference 활성 시) |
| `tcp.reassembled.data` | 재조립이 실제로 일어난 **마지막 프레임**에서만 값이 채워진다 |

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,3 | grep -o 'flag{[^}]*}'
```

`-z follow,tcp,ascii,<n>`는 GUI의 Follow TCP Stream과 동일한 재조립 결과를 stdout으로 준다. 스트림 번호를 모르면 먼저 아무 필터로나 그 대화의 프레임 하나를 찾아 `tcp.stream` 값을 확인한다.

```bash
tshark -r capture.pcapng -Y 'ip.addr == 203.0.113.77' -T fields -e tcp.stream | sort -u
```

### 4단계 — 대소문자와 정규식

`contains`는 대소문자를 구분한다. 대소문자를 모르면 `matches`(PCRE2, 대소문자 무시)로 바꾼다.

```text
tcp contains "Flag"        (대소문자 정확히 일치해야 함)
tcp matches "(?i)flag"     (대소문자 무시, 상대적으로 느리다)
```

정규식으로 패턴만 알고 값을 모를 때(`flag{...}` 형태) 유용하다.

```text
tcp matches r"flag\{[a-zA-Z0-9_]+\}"
```

셸에서 백슬래시가 두 번 파싱되는 문제는 [FOR-0185](./tshark-display-filter.html)에서 다뤘다 — raw string 접두 `r`을 붙여야 필터 엔진과 PCRE2가 이중으로 이스케이프를 먹지 않는다.

### 5단계 — 여러 스트림에서 한 번에 찾기

```bash
tshark -r capture.pcapng -n -Y 'tcp contains "flag"' \
  -T fields -e frame.number -e tcp.stream -e ip.src -e ip.dst -E header=y
```

```powershell
tshark -r capture.pcapng -n -Y 'tcp contains \"flag\"' `
  -T fields -e frame.number -e tcp.stream -e ip.src -e ip.dst -E header=y
```

```text
frame.number  tcp.stream  ip.src        ip.dst
3391          2           203.0.113.77  10.0.0.15
5820          2           203.0.113.77  10.0.0.15
```

같은 `tcp.stream` 값이 여러 번 나오면 한 대화 안에서 문자열이 여러 번 등장한 것이다 — 스트림 하나만 재조립해서 확인하면 된다.

### 6단계 — Wireshark 없이 오프라인으로 재현

Wireshark/tshark가 없는 환경에서도 같은 결론에 도달할 수 있어야 한다. `tcp contains`가 결국 하는 일은 "이 바이트 범위 안에서 이 바이트열을 찾는다"이므로, 원시 pcap 파일을 그대로 grep해도 근사한 결과를 얻는다.

| 도구 | 명령 | 차이 |
| --- | --- | --- |
| `grep -a` | `grep -a 'flag{' capture.pcapng` | 패킷 구조를 모르고 파일 전체를 훑는다. `frame contains`와 비슷하지만 패킷 경계·스트림 정보가 없다 |
| `strings` | `strings -n 4 capture.pcapng \| grep flag` | 인쇄 가능 문자만 남긴 뒤 검색. 바이너리 잡음이 줄어든다 |
| `xxd` + 수작업 | `xxd capture.pcapng \| grep '66 6c 61 67'` | hex 패턴을 눈으로 확인할 때 |
| HxD | `Ctrl+F` → Hex-values 모드로 `66 6C 61 67` 검색 | GUI에서 오프셋을 직접 확인하고 싶을 때 |

이 방법들은 **스트림 재조립을 하지 않으므로**, `tcp contains`처럼 세그먼트 경계에서 잘린 문자열은 여기서도 안 잡힌다. 잘린 문자열을 오프라인에서 재현하려면 Follow Stream으로 미리 저장해 둔 텍스트 파일을 대상으로 검색해야 한다.

시각 확인이 필요하면 매칭된 프레임의 `frame.time_epoch`를 함께 뽑는다.

```bash
tshark -r capture.pcapng -n -Y 'tcp contains "flag"' -T fields -e frame.time_epoch -e tcp.stream
```

```text
1773645302.418221	2
```

`1773645302` → UTC `2026-03-16 09:55:02` → KST `2026-03-16 18:55:02`(+9시간). pcap의 타임스탬프는 파일 안에 UTC(epoch)로 저장되므로, EVTX나 access.log의 시각과 대조할 때는 반드시 UTC 기준으로 맞춘 뒤 KST를 별도로 병기한다.

## 출력 필드 해석

| 출력 | 의미 | 함정 |
| --- | --- | --- |
| 걸린 패킷 수 | `tcp contains`가 매칭된 **프레임** 수 | 스트림 수가 아니다. 한 스트림에서 여러 프레임이 걸릴 수 있다 |
| `tcp.stream` | 그 패킷이 속한 TCP 대화 번호 | Follow Stream/재조립의 다음 입력값 |
| Info 컬럼 | 요약 문자열 | 매칭된 문자열이 요약에 안 보일 수 있다. 반드시 패킷을 열어 hex pane에서 실제 위치 확인 |
| hex pane 강조 | 매칭 바이트가 노란색으로 표시됨 | 강조가 없으면 상위 레이어에서 **디코딩된 값**과 매칭된 것(예: URL 디코딩 후 값) |

## pivot: 다음에 볼 artifact

| tcp contains로 찾은 것 | 다음 목표 |
| --- | --- |
| 짧은 매칭(패킷 하나에 다 있음) | 그 패킷 상세(`-V -O <proto>`)로 전체 맥락 확인 |
| 매칭 없음, 프로토콜이 안 잡힘 | [FOR-0180](./frame-contains.html)으로 검색 범위를 넓혀 확인 |
| 스트림 경계에서 잘린 것으로 의심 | [FOR-0162](./follow-tcp-stream.html)로 전체 재조�� |
| 매칭된 스트림이 로그인/인증 관련 | [FOR-0187](./pcap-credentials.html) 절차로 자격증명 형식 확인 |
| 매칭 시각 확보 | [FOR-0146](./wireshark-30sec-triage.html)의 UTC 절대시각 설정으로 EVTX/access.log와 대조 |

## 흔한 함정

- **`frame contains`로만 찾다가 IP/TCP 헤더의 숫자를 문자열로 오인.** 짧은 검색어(2~3바이트)는 시퀀스 번호나 체크섬과 우연히 일치할 수 있다. `tcp.payload contains`로 좁히면 사라진다.
- **문자열이 스트림 경계에서 잘린 것을 "존재하지 않는다"로 결론.** `tcp contains`와 `frame contains` 둘 다 프레임 단위다. 0줄이면 Follow Stream을 반드시 시도한다.
- **대소문자를 안 맞추고 0줄로 포기.** `contains`는 대소문자를 구분한다. `matches "(?i)..."`로 바꿔본다.
- **UTF-16LE 문자열을 ASCII 그대로 검색.** Windows 클라이언트가 보내는 문자열은 UTF-16LE인 경우가 많다. 문자 사이 `00`을 넣은 hex 검색으로 바꾼다.
- **hex 검색에서 콜론을 빠뜨림.** `tcp contains 666c6167`은 오류다. `66:6c:61:67`처럼 콜론으로 구분해야 한다.
- **재조립 preference가 꺼져 있는데 `http.file_data`를 검색.** `tcp.desegment_tcp_streams`, `http.decompress_body`가 꺼져 있으면 재조립 필드 자체가 비어 있다 ([FOR-0184](./tshark-basics.html)).
- **`tcp contains`가 걸린 스트림 번호를 착각.** 매칭된 패킷이 여러 스트림에 흩어져 있을 수 있다. `-e tcp.stream`으로 각 매칭의 스트림 번호를 반드시 따로 확인한다.
- **`{`, `}` 같은 특수문자가 있는 고정 문자열을 굳이 `matches` 정규식으로 검색.** `contains`는 리터럴 매칭이라 이스케이프가 필요 없다. `flag{`처럼 값이 정확히 정해져 있으면 `contains`가 더 간단하고 실수도 적다.

## 교차검증

```bash
# 1) tcp vs tcp.payload — 결과 수가 다르면 헤더 우연 매칭 의심
tshark -r capture.pcapng -Y 'tcp contains "ok"' | wc -l
tshark -r capture.pcapng -Y 'tcp.payload contains "ok"' | wc -l

# 2) frame vs tcp — 범위 차이 확인
tshark -r capture.pcapng -Y 'frame contains "flag"' | wc -l
tshark -r capture.pcapng -Y 'tcp contains "flag"' | wc -l

# 3) 파서를 거치지 않는 strings로 최종 확인 (Wireshark가 놓친 것도 잡는다)
strings -n 4 capture.pcapng | grep -i flag

# 4) 걸린 스트림을 재조립해서 실제로 문자열이 완전한지 확인
tshark -r capture.pcapng -q -z follow,tcp,ascii,2 | grep -i flag
```

`strings`는 프로토콜 파서와 무관하게 파일 전체의 인쇄 가능 바이트를 뽑으므로, `tcp contains`가 놓친 것(비표준 인코딩, 재조립 전 상태 등)을 잡아낼 최후 수단이다. 단 `strings`는 패킷 경계·스트림 정보를 알려주지 않으므로 위치 확정에는 다시 tshark가 필요하다.

## mini walkthrough

```text
문제:
"서버가 클라이언트에게 내려준 플래그를 pcap에서 찾으세요."
첨부: leak.pcapng (6,204 packets)

1. 첫 시도 (실패)
   $ tshark -r leak.pcapng -Y 'tcp contains "flag{"'
   (0줄)

   지문에 분명 "플래그를 내려줬다"고 되어 있어 당황.
   frame contains로도 시도했지만 역시 0줄.
   $ tshark -r leak.pcapng -Y 'frame contains "flag{"'
   (0줄)

2. 원인 분석 — 프로토콜부터 확인
   $ tshark -r leak.pcapng -q -z io,phs
   ...
     Transmission Control Protocol   71.2%   4416   3,204,880
       Data                          71.2%   4416   3,190,102   <- 파서가 못 알아본 raw TCP

   알려진 상위 프로토콜이 없다. 커스텀 프로토콜이라 페이로드가
   여러 세그먼트에 나뉘어 전송되고 있을 가능성이 높다.

3. 접근 변경 — 짧은 조각으로 존재만 확인
   $ tshark -r leak.pcapng -Y 'tcp contains "flag"'
   프레임 3391: 매칭 (1개)

   -> "flag"는 있는데 "flag{"는 없다. 여는 중괄호 앞에서 잘렸다는 뜻이다.

4. 스트림 번호 확인 후 재조립
   $ tshark -r leak.pcapng -Y 'frame.number == 3391' -T fields -e tcp.stream
   2
   $ tshark -r leak.pcapng -q -z follow,tcp,ascii,2 | grep -o 'flag{[^}]*}'
   flag{tcp_segment_boundary_is_not_your_enemy}

정답: flag{tcp_segment_boundary_is_not_your_enemy}
```

1번의 실패에서 "플래그가 없다"로 결론짓지 않고 "flag"만으로 다시 검색해 부분 매칭을 확인한 것이 핵심이다. **부분 문자열은 걸리는데 전체가 안 걸리면 세그먼트 경계를 의심한다.**

## 막혔을 때 다음 체크

1. `tcp contains`가 0줄인가 → `frame contains`로 범위를 넓혀 봤는가
2. 검색어를 짧게 잘라서(`"flag"`만) 부분 매칭이 있는지 확인했는가
3. 부분 매칭이 있다면 그 스트림을 Follow/재조립했는가
4. 대소문자를 바꿔서 `matches "(?i)..."`로 시도했는가
5. UTF-16LE(문자 사이 `00`) 가능성을 hex 검색으로 확인했는가
6. `tcp.payload contains`로 좁혀서 헤더 우연 매칭이 아닌지 확인했는가
7. Protocol Hierarchy에서 알려진 상위 프로토콜(HTTP 등)이 있는지 봤는가 — 있으면 그 재조립 필드를 우선 사용한다
8. `strings capture.pcapng | grep -i flag`로 파서와 무관하게 확인했는가
9. `-2`(2-pass) 옵션이 필요한 상황인지 확인했는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `contains` 연산자, `tcp.payload`, `http.file_data` 필드 정의
- SRC-003 — Wireshark User's Guide: Follow TCP Stream의 재조립 동작, "Building Display Filter Expressions"의 문자열/바이트열 검색 문법
- `contains`가 프레임 단위로만 평가되어 다중 세그먼트에 걸친 문자열을 자동으로 찾지 못하는 동작은 여러 버전에서 공통으로 확인되나, TCP 재조립 preference(`tcp.desegment_tcp_streams`) 설정과 상위 프로토콜 dissector 유무에 따라 세부 동작이 달라질 수 있으므로 실제 환경에서 확인할 것
