---
id: FOR-0149
title: "Conversations: 가장 큰 대화를 찾아 tcp.stream으로 직행하기"
slug: "conversations"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "TCP stream"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TCP", "UDP", "IPv4", "IPv6", "Ethernet"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -q -z conv,tcp", "tshark -r capture.pcapng -q -z conv,ip", "tshark -r capture.pcapng -q -z conv,udp", "tshark -r capture.pcapng -q -z conv,tcp,ip.addr==10.0.0.15"]
regex_patterns: []
wireshark_filters: ["tcp.stream eq 4", "udp.stream eq 2", "ip.addr == 10.0.0.15 && ip.addr == 203.0.113.77", "tcp.len > 0", "tcp.time_delta > 30"]
tshark_fields: ["tcp.stream", "udp.stream", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.len", "frame.time_relative"]
log_fields: ["Address A", "Address B", "Port A", "Port B", "Packets A → B", "Bytes A → B", "Rel Start", "Duration", "Bits/s A → B", "Stream ID", "Total Packets", "Percent Filtered"]
file_formats: ["pcap", "pcapng"]
primary_terms: ["Conversations", "대화 통계", "가장 큰 대화", "Stream ID 컬럼"]
keywords: ["Conversations", "대화 통계", "Bytes 정렬", "Stream ID", "tcp.stream", "conv,tcp", "Rel Start", "Duration", "업로드 다운로드 판정", "방향별 바이트", "Limit to display filter"]
aliases: ["대화 통계", "가장 큰 대화 찾기", "conversations 창", "누가 제일 많이 보냈나", "conv tcp", "세션 목록 보기", "스트림 번호 찾기"]
symptom_keywords: ["어느 세션이 중요한지 모르겠다", "가장 큰 전송을 찾아야 한다", "업로드인지 다운로드인지 모르겠다", "tcp.stream 번호를 모른다", "세션이 언제 시작됐는지"]
related: ["FOR-0146", "FOR-0148", "FOR-0150", "FOR-0151"]
source_ids: ["SRC-003", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Statistics > Conversations` 의 TCP 탭에서 **`Bytes` 컬럼을 내림차순 정렬**하면 그 pcap 에서 가장 많은 데이터가 흐른 세션이 1행에 온다. 그 행의 `Stream ID` 를 그대로 `tcp.stream eq <N>` 필터로 옮기고, `Bytes A → B` 와 `Bytes B → A` 를 비교해 업로드인지 다운로드인지 한 번에 판정한다.

## 어떤 문제에서 필요한가

- "전송된 파일" / "유출된 데이터" / "가장 많이 통신한 상대" 를 찾아야 할 때
- Protocol Hierarchy 에서 `Bytes` 가 큰 프로토콜을 확인한 직후 ([FOR-0148](./protocol-hierarchy.html))
- Export Objects 가 비어 있어 세션을 직접 찾아 `Follow Stream > Raw` 로 꺼내야 할 때
- 세션의 **시작 시각과 지속 시간**이 필요한 타임라인 문제
- 업로드(유출)와 다운로드(투입)를 구분해야 하는 문제

## 문제에서 처음 볼 단서

1. **행 개수** — TCP 대화가 3개면 수동으로 다 본다. 3,000개면 스캔이다.
2. **`Bytes` 1위와 2위의 차이** — 1위가 압도적이면 그것이 목표다.
3. **`Port B` 의 값** — 80/443/21/22/445 는 서비스, 40000 이상은 클라이언트 임시 포트 또는 커스텀 서버
4. **`Duration` 이 0 에 가까운 대화가 수백 개** — SYN 스캔이다.
5. **`Packets` 는 많은데 `Bytes` 는 작은 대화** — keep-alive, beacon, 스캔
6. **`Bytes A → B` 와 `Bytes B → A` 의 비대칭** — 방향이 곧 시나리오다.

## 30초 절차

```bash
tshark -r capture.pcapng -q -z conv,tcp
```

GUI 는 여섯 클릭이다.

```text
1. Statistics > Conversations
2. 하단 Protocol 목록에서 TCP 탭을 선택
3. Bytes 컬럼 헤더를 클릭 (한 번 더 클릭하면 내림차순)
4. 1행의 Stream ID 를 확인
5. 그 행 우클릭 > Apply as Filter > Selected > A <-> B
6. 패킷 우클릭 > Follow > TCP Stream
```

`Stream ID` 를 알았으면 필터를 손으로 써도 된다.

```text
tcp.stream eq 4
```

## 상세 절차

### 1단계 — 탭 선택

`Statistics > Conversations` 를 열면 하단(또는 우측)의 Protocol 목록으로 탭을 고른다. 어떤 탭이 보이는지는 이 목록이 결정하고, 캡처에 해당 대화가 없는 탭은 회색으로 표시된다.

| 탭 | "대화" 의 정의 | 언제 쓰나 |
| --- | --- | --- |
| `Ethernet` | MAC 주소 쌍 | 같은 세그먼트의 장비 수, 게이트웨이 식별, ARP 스푸핑 |
| `IPv4` | IP 주소 쌍 (포트 무시) | 호스트 간 총 통신량. 여러 세션이 합산된다 |
| `IPv6` | IPv6 주소 쌍 | 위와 동일 |
| `TCP` | IP:포트 4-튜플 = **세션 하나** | **가장 자주 쓰는 탭.** 파일 전송·C2 세션 특정 |
| `UDP` | IP:포트 4-튜플 | DNS, 터널링, 스트리밍 |

세션 단위로 봐야 하면 TCP/UDP, 호스트 단위로 봐야 하면 IPv4 를 본다. IPv4 탭에서 500 KB 인 쌍이 TCP 탭에서 100 KB 짜리 5개로 쪼개져 보이는 것이 정상이다.

### 2단계 — 컬럼 의미

| 컬럼 | 의미 | 판정에 쓰는 방법 |
| --- | --- | --- |
| `Address A` / `Address B` | 대화 양단. **A 는 첫 패킷을 보낸 쪽**이다 | A 가 클라이언트, B 가 서버인 경우가 대부분 |
| `Port A` / `Port B` | 각각의 포트 | `Port B` 가 서비스 포트면 B 가 서버 |
| `Packets` | 양방향 합계 패킷 수 | 비콘·스캔 탐지 |
| `Bytes` | 양방향 합계 바이트 | **파일 전송 판정 1순위** |
| `Packets A → B` | A 가 B 로 보낸 패킷 수 | 방향 판정 |
| `Bytes A → B` | A 가 B 로 보낸 바이트 | **업로드/유출 판정** |
| `Packets B → A` | B 가 A 로 보낸 패킷 수 | 방향 판정 |
| `Bytes B → A` | B 가 A 로 보낸 바이트 | **다운로드 판정** |
| `Rel Start` | 캡처 첫 패킷 기준 이 대화의 시작 시각(초) | 세션 순서·인과관계 |
| `Abs Start` | 절대 시각 (체크박스로 전환) | EVTX·로그와 대조할 때 필수 |
| `Duration` | 대화 지속 시간(초) | 짧으면 스캔/실패, 길면 세션/터널 |
| `Bits/s A → B` | A→B 평균 대역폭 | 지속 전송 여부 |
| `Bits/s B → A` | B→A 평균 대역폭 | 위와 동일 |
| `Stream ID` | 그 대화의 `tcp.stream` / `udp.stream` 번호 | **필터로 직행하는 열쇠** |
| `Total Packets` | 필터 적용 시에만 나타남. 필터 무시한 전체 패킷 수 | 필터가 얼마나 잘라냈는지 |
| `Percent Filtered` | 필터 적용 시에만 나타남. 표시된 비율 | 위와 동일 |

`Total Packets` 와 `Percent Filtered` 는 표시 필터가 걸려 있을 때만 추가된다. 이 두 컬럼이 보이면 **지금 보고 있는 숫자가 전체가 아니라는 경고**로 읽는다.

### 3단계 — Bytes 정렬이 첫 수순인 이유

`Bytes` 컬럼 헤더를 클릭해 내림차순으로 만든다. 이유는 단순하다.

| 목표 | `Bytes` 상위에 나타나는가 |
| --- | --- |
| 전송된 파일 (문제의 flag 가 든 파일) | 거의 항상 1~3위 |
| 유출된 데이터 아카이브 | 1~3위 |
| Follow Stream 으로 읽을 만한 세션 | 상위권 (바이트가 없으면 읽을 것도 없다) |
| C2 비콘 | 아니다. `Packets` 는 많고 `Bytes` 는 작다 |
| 포트 스캔 | 아니다. `Duration` 이 0 에 가깝고 `Bytes` 가 극소 |

즉 `Bytes` 정렬은 "읽을 내용이 있는 세션" 을 위로 올린다. 비콘과 스캔은 `Bytes` 로는 안 잡히므로 **`Packets` 정렬과 `Duration` 정렬을 각각 한 번 더** 해 본다.

정렬 3회 규칙.

```text
(1) Bytes  내림차순  -> 파일 전송 / 읽을 세션
(2) Packets 내림차순 -> 비콘 / keep-alive / 재전송 폭주
(3) Duration 내림차순 -> 장시간 유지된 세션 (터널, 원격 셸)
    Duration 오름차순 -> 0초짜리 수백 개 = 스캔
```

### 4단계 — 방향별 바이트로 업로드/다운로드 판정

`Bytes A → B` 와 `Bytes B → A` 의 비율이 시나리오를 그대로 알려 준다.

| 패턴 | 해석 |
| --- | --- |
| `A → B` 가 압도적 (A=내부, B=외부) | **내부에서 외부로 데이터 유출.** 업로드 |
| `B → A` 가 압도적 (A=내부, B=외부) | 외부에서 내부로 다운로드. 악성코드 투입 또는 정상 다운로드 |
| 양방향이 비슷하고 둘 다 크다 | 대화형 세션. 원격 셸, 터널, 데이터베이스 |
| `A → B` 작고 `B → A` 도 작은데 패킷이 많다 | 비콘 또는 keep-alive |
| `A → B` 만 있고 `B → A` 가 0 | 응답 없음. 스캔, 차단, 또는 단방향 UDP |

주의: `Bytes` 에는 헤더가 포함된다. 순수 페이로드 크기가 필요하면 `tcp.len` 을 따로 합산한다.

```bash
# 스트림 4 의 방향별 페이로드 바이트만 합산
tshark -r capture.pcapng -Y 'tcp.stream eq 4 && tcp.len > 0' \
  -T fields -e ip.src -e tcp.len |
  awk '{s[$1]+=$2} END {for (k in s) print k, s[k]}'
```

```text
10.0.0.15 8083712
203.0.113.77 412
```

내부 호스트가 8 MB 를 보냈고 서버는 412바이트만 응답했다. 업로드 = 유출 확정이다.

### 5단계 — Rel Start 와 Duration 으로 세션 구간을 잡는다

`Rel Start` + `Duration` = 그 세션이 존재한 구간이다. 이것으로 세 가지를 한다.

| 용도 | 방법 |
| --- | --- |
| 세션 순서 확인 | `Rel Start` 오름차순 정렬. 정찰 → 침투 → 유출 순서가 드러난다 |
| 다른 artifact 와 대조 | `Absolute start time` 체크 → 절대 시각으로 전환 → EVTX/로그 시각과 비교 |
| 구간 필터 만들기 | `Rel Start` 가 132.4, `Duration` 이 45.2 라면 `frame.time_relative >= 132.4 && frame.time_relative <= 177.6` |

절대 시각 전환은 체크박스 하나다.

```text
Conversations 창 하단
  [ ] Limit to display filter
  [ ] Absolute start time      <- 체크하면 Rel Start 가 Abs Start 로 바뀐다
  [ ] Name resolution
```

**타임존**: `Absolute start time` 은 Wireshark 의 시간 표시 설정을 따른다. 기본은 로컬 시간(한국이면 KST, UTC+9)이다. 로그·EVTX 와 대조하기 전에 반드시 표시 형식을 통일한다.

```text
View > Time Display Format > UTC Date and Time of Day
View > Time Display Format > Milliseconds
```

UTC 로 맞춘 뒤 KST 가 필요하면 9시간을 더한다. `2026-03-14 07:15:02 UTC` = `2026-03-14 16:15:02 KST`.

### 6단계 — Stream ID 컬럼을 켜서 필터로 직행

TCP/UDP 탭에는 `Stream ID` 컬럼이 있다. 보이지 않으면 컬럼 헤더에서 우클릭해 표시할 컬럼 목록에서 켠다.

```text
tcp.stream eq 4
udp.stream eq 2
```

`Stream ID` 를 쓰는 이유는 필터가 짧고 정확하기 때문이다. 대안인 4-튜플 필터는 길고, 포트가 재사용되면 두 세션이 섞인다.

| 방법 | 필터 | 문제 |
| --- | --- | --- |
| Stream ID | `tcp.stream eq 4` | 없다. 세션 하나를 정확히 지목한다 |
| 4-튜플 | `ip.addr==10.0.0.15 && tcp.port==49813 && ip.addr==203.0.113.77 && tcp.port==20` | 길다. 포트 재사용 시 두 세션이 함께 걸린다 |
| IP 쌍 | `ip.addr==10.0.0.15 && ip.addr==203.0.113.77` | 그 두 호스트의 모든 세션이 걸린다 |

행 우클릭 메뉴로도 같은 것을 만들 수 있다.

```text
행 우클릭
  Apply as Filter   > Selected > A <-> B  /  A -> B  /  A  /  B  /  Any <-> B ...
  Prepare as Filter > (적용 없이 입력창에만)
```

`A -> B` 를 고르면 단방향만 걸린다. 유출 방향만 보고 싶을 때 유용하다.

### 7단계 — Limit to display filter

이 체크박스가 이 창의 두 번째 무기다.

| 체크 | 결과 |
| --- | --- |
| 해제 | 캡처 전체의 모든 대화 |
| 체크 | **현재 표시 필터에 맞는 대화만** |

창을 열기 **전에** 이미 필터를 적용해 두었으면 이 체크박스는 자동으로 켜진 상태로 열린다. 그래서 "대화가 몇 개 없다" 고 당황하는 일이 생긴다. 전체를 보려면 체크를 해제하거나 필터를 지운다.

활용 예.

```text
(1) 메인 필터: http.request.method == "POST"
(2) Statistics > Conversations, Limit to display filter 체크
    -> POST 를 포함한 세션만 나열된다. 업로드 세션을 즉시 특정
```

```text
(1) 메인 필터: tcp.flags.syn == 1 && tcp.flags.ack == 0
(2) Limit to display filter 체크, TCP 탭
    -> SYN 만 보낸 대화 = 스캔 대상 포트 목록
```

```text
(1) 메인 필터: !(ip.addr == 10.0.0.0/8)
(2) IPv4 탭
    -> 외부와의 통신만 남는다
```

### 8단계 — Copy 로 표를 꺼낸다

`Copy` 버튼은 창 내용을 클립보드로 내보낸다. 형식은 CSV, YAML, JSON 중에서 고른다. 숫자는 기본적으로 서식 없이(천 단위 구분 없이) 나가므로 스프레드시트나 스크립트로 바로 넘길 수 있다.

```text
Copy > as CSV     -> 엑셀/스프레드시트로 붙여 정렬·필터
Copy > as JSON    -> jq 로 가공
Copy > as YAML    -> 보고서에 붙이기
```

수십~수백 개 대화를 정리해야 하는 문제에서는 GUI 정렬보다 CSV 로 빼서 처리하는 편이 빠르다. CLI 로 같은 표를 만들려면 아래 교차검증의 `-z conv,tcp` 를 쓴다.

## 출력 필드 해석

`tshark -q -z conv,tcp` 의 출력.

```text
================================================================================
TCP Conversations
Filter:<No Filter>
                                                       |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                       | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.0.0.15:49813      <-> 203.0.113.77:20                  312     20114    1309   8084218    1621   8104332     132.401230       45.2119
10.0.0.15:49820      <-> 93.184.216.34:80                 402   1801322     229     90722     631   1892044      12.008411      301.7742
10.0.0.15:49812      <-> 203.0.113.77:21                   58      6902      54      4302     112     11204     130.882001       48.9930
10.0.0.42:51442      <-> 198.51.100.77:8443               114     11288     114   2784592     228   2795880      35.112900     1804.6621
================================================================================
```

| 출력 항목 | GUI 대응 | 비고 |
| --- | --- | --- |
| 좌측 `IP:port <-> IP:port` | `Address A:Port A` / `Address B:Port B` | 좌측이 A |
| `Total Frames/Bytes` | `Packets` / `Bytes` | 기본 정렬은 총 프레임 수 기준 |
| `Relative Start` | `Rel Start` | 초 단위 |
| `Duration` | `Duration` | 초 단위 |
| `<-` / `->` 열 | `Bytes B → A` / `Bytes A → B` | **방향 라벨을 눈으로 믿지 말고 아래 방법으로 확정한다** |

`<-` 와 `->` 중 어느 쪽이 A→B 인지는 헷갈리기 쉽다. 방향을 확실히 해야 하는 판정(유출 vs 다운로드)에서는 CLI 라벨에 의존하지 않고 다음 중 하나로 확정한다.

```bash
# 방법 1: ip.src 로 직접 합산 (가장 확실하다)
tshark -r capture.pcapng -Y 'tcp.stream eq 4' -T fields -e ip.src -e tcp.len |
  awk '{s[$1]+=$2} END {for (k in s) print k, s[k]}'

# 방법 2: Endpoints 의 Tx/Rx 로 교차 확인
tshark -r capture.pcapng -q -z endpoints,tcp
```

GUI 의 `Bytes A → B` 컬럼은 라벨이 명시적이므로 혼동이 없다. 방향이 결론에 직결되는 문제라면 GUI 컬럼이나 위 `awk` 합산을 쓴다.

`Stream ID` 는 이 CLI 출력에 없다. 필요하면 이렇게 뽑는다.

```bash
# 대화별 스트림 번호와 총 페이로드 바이트
tshark -r capture.pcapng -Y 'tcp.len > 0' \
  -T fields -e tcp.stream -e ip.src -e ip.dst -e tcp.len |
  awk '{p[$1]=$2" -> "$3; s[$1]+=$4} END {for (k in s) printf "%s\t%s\t%d\n", k, p[k], s[k]}' |
  sort -k3 -nr | head -10
```

## pivot: 다음에 볼 artifact

| Conversations 에서 얻은 것 | 다음에 할 일 |
| --- | --- |
| `Stream ID` | `tcp.stream eq N` → `Follow > TCP Stream` → `Show data as = Raw` → 파일 저장 |
| `Bytes A → B` 가 큰 내부→외부 세션 | 유출 시나리오. 유출된 파일명·내용 확보 |
| 외부 `Address B` | [FOR-0150](./endpoints.html) 로 전체 IP 목록화 → 방화벽/프록시 로그 대조 |
| `Abs Start` 절대 시각 | EVTX 4624/4688 ([FOR-0083](./event-4624-logon.html)), Sysmon 3 ([FOR-0100](./sysmon-event-3-network-connect.html)) 의 같은 시각 |
| `Port B` = 21/20 | FTP 명령·데이터 채널. 파일명은 명령 채널에 있다 |
| `Port B` = 445 | SMB. Export Objects > SMB |
| `Port B` 가 비표준 + 큰 바이트 | `Decode As` 또는 커스텀 C2 ([FOR-0148](./protocol-hierarchy.html)) |
| `Duration` 0 인 대화 수백 개 | 스캔. `tcp.flags.syn == 1 && tcp.flags.ack == 0` 로 대상 포트 열거 |
| `Packets` 많고 `Bytes` 작은 주기적 대화 | 비콘. `Rel Start` 간격을 계산해 주기 확인 |
| 재전송이 많아 보이는 대화 | [FOR-0151](./expert-information.html) 로 캡처 신뢰도 확인 |

## 흔한 함정

- **IPv4 탭과 TCP 탭을 같은 것으로 보는 것.** IPv4 탭은 포트를 무시하고 호스트 쌍으로 합산한다. 세션 하나를 특정하려면 반드시 TCP/UDP 탭이다.
- **`Limit to display filter` 가 켜진 것을 모르고 "대화가 몇 개 없다" 고 판단하는 것.** 창을 열기 전에 필터가 걸려 있었으면 자동으로 켜진다. `Total Packets` / `Percent Filtered` 컬럼이 보이면 필터 상태라는 신호다.
- **`Bytes` 만 정렬하고 끝내는 것.** 비콘과 스캔은 `Bytes` 하위에 있다. `Packets` 와 `Duration` 으로 각각 한 번 더 정렬한다.
- **`Bytes` 를 페이로드 크기로 착각하는 것.** 이더넷·IP·TCP 헤더가 포함된 값이다. 실제 전송 파일 크기는 `tcp.len` 합산으로 구한다.
- **A 가 항상 내부 호스트라고 가정하는 것.** A 는 "먼저 패킷을 보낸 쪽" 일 뿐이다. 캡처가 세션 중간부터 시작되면 서버가 A 가 될 수 있다.
- **`Rel Start` 를 절대 시각으로 읽는 것.** 기본은 캡처 첫 패킷 기준 상대 초다. 다른 artifact 와 대조하려면 `Absolute start time` 을 체크하고 표시 형식을 UTC 로 맞춘다.
- **4-튜플 필터를 손으로 쓰는 것.** 길고, 포트 재사용 시 두 세션이 섞인다. `Stream ID` → `tcp.stream eq N` 이 항상 낫다.
- **`Duration` 이 0 인 행을 무의미하다고 지우는 것.** 0초짜리가 수백 개면 그것이 곧 스캔 증거다.
- **UDP 탭을 건너뛰는 것.** DNS 터널링과 UDP 기반 C2 는 TCP 탭에 나타나지 않는다 ([FOR-0155](./dns-tunneling.html)).
- **Ethernet 탭을 무시하는 것.** MAC 쌍의 개수가 곧 세그먼트의 장비 수다. IP 가 바뀌어도 MAC 은 남는다.
- **CLI `-z conv,tcp` 의 `<-` / `->` 라벨로 유출 방향을 단정하는 것.** 방향이 결론이 되는 문제에서는 `ip.src` 기준 합산이나 GUI 의 `Bytes A → B` 컬럼으로 확정한다.

## 교차검증

```bash
# 1) GUI Conversations TCP 탭과 같은 표
tshark -r capture.pcapng -q -z conv,tcp

# 2) 호스트 쌍 단위 (IPv4 탭 상당물)
tshark -r capture.pcapng -q -z conv,ip

# 3) UDP 대화
tshark -r capture.pcapng -q -z conv,udp

# 4) 특정 호스트가 낀 대화만
tshark -r capture.pcapng -q -z conv,tcp,ip.addr==10.0.0.15

# 5) 외부와의 대화만
tshark -r capture.pcapng -q -z 'conv,ip,!(ip.addr==10.0.0.0/8)'

# 6) 스트림별 페이로드 바이트 상위 10개 (Stream ID 포함)
tshark -r capture.pcapng -Y 'tcp.len > 0' -T fields -e tcp.stream -e tcp.len |
  awk '{s[$1]+=$2} END {for (k in s) print s[k], "stream", k}' | sort -nr | head -10

# 7) 대화 목록을 CSV 로 (GUI Copy > as CSV 대체)
tshark -r capture.pcapng -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -E header=y -E separator=, \
  -e frame.time -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
```

`(1)` 의 총 바이트와 `(6)` 의 페이로드 바이트 차이가 헤더 오버헤드다. 8 MB 대화에서 둘의 차이가 100 KB 수준이면 정상, 차이가 절반이면 작은 패킷이 많다는 뜻이므로 비콘·터널을 의심한다.

## mini walkthrough

```text
문제:
"내부 직원이 외부로 유출한 압축 파일의 크기(바이트)와 그 세션의
 시작 시각(UTC)을 구하세요."
첨부: leak.pcapng (12,340 packets, 9.4 MB)

1. 첫 시도 (실패)
   Statistics > Conversations 를 열었더니 TCP 탭에 대화가 2개뿐이었다.
   둘 다 수십 KB. 9.4 MB 파일에 이럴 수가 없다.

   원인: 이 창을 열기 직전에 메인 필터창에 http.request 를 적용해 둔 상태였다.
        그래서 "Limit to display filter" 가 자동으로 켜져 있었고,
        Total Packets / Percent Filtered 컬럼이 추가되어 있었다.
        (이 두 컬럼이 보인다 = 필터가 걸려 있다는 신호였는데 지나쳤다)

2. 수정
   Limit to display filter 체크 해제.
   -> TCP 대화 41개가 나타난다.

3. Bytes 내림차순 정렬

   Address A    Port A   Address B        Port B   Packets   Bytes      Packets A→B  Bytes A→B  Packets B→A  Bytes B→A  Rel Start   Duration   Stream ID
   10.0.0.31    52118    198.51.100.44    443      6204      8,712,004   5940        8,668,112    264          43,892     41.882      92.104     17
   10.0.0.31    52101    10.0.0.2         53       88         12,004      44           5,880       44           6,124      0.412      120.331    -
   10.0.0.31    52120    93.184.216.34    80       402        88,220      112          9,102       290          79,118     18.220      60.442     22

4. 1행을 읽는다
   Bytes A→B 8,668,112  vs  Bytes B→A 43,892
   -> A(10.0.0.31, 내부)가 B(198.51.100.44, 외부)로 8.6 MB 를 보냈다.
      업로드 = 유출. 443 포트지만 방향이 완전히 비대칭이다.
      (정상 HTTPS 브라우징이라면 B→A 가 훨씬 커야 한다)

5. 두 번째 시도 (실패)
   Bytes 값 8,712,004 을 그대로 "파일 크기" 로 답했다. 오답.
   원인: Bytes 는 이더넷/IP/TCP 헤더를 포함한 총량이다.
        그리고 A→B 에는 TLS 레코드 헤더와 ACK 도 섞여 있다.

6. 수정 — 페이로드만 합산
   $ tshark -r leak.pcapng -Y 'tcp.stream eq 17 && tcp.len > 0' \
       -T fields -e ip.src -e tcp.len |
       awk '{s[$1]+=$2} END {for (k in s) print k, s[k]}'
     10.0.0.31      8578944
     198.51.100.44  21160

   업로드 페이로드 8,578,944 바이트.

7. 실제 파일 크기 확정
   필터: tcp.stream eq 17
   우클릭 > Follow > TCP Stream
   -> TLS 라 내용은 안 보인다. 파일 자체는 못 꺼낸다.
   그러나 지문이 "유출한 압축 파일의 크기" 이므로
   전송 페이로드에서 TLS 레코드 오버헤드를 뺀 값이 필요하다.

   다시 확인: 이 문제의 세션은 실제로 TLS 가 아니었다.
   Statistics > Protocol Hierarchy (Limit: tcp.stream eq 17)
     tcp -> data   (tls 행이 없다)
   -> 443 포트를 쓰지만 TLS 가 아닌 평문 커스텀 전송이다.

   Follow > TCP Stream, Show data as = Raw, Save as -> upload.bin
   $ ls -l upload.bin
     -rw-r--r-- 1 user user 8578944 upload.bin
   $ file upload.bin
     upload.bin: Zip archive data, at least v2.0 to extract
   -> 8,578,944 바이트. 페이로드 합산과 정확히 일치한다.

8. 시작 시각 — Rel Start 를 절대 시각으로
   Conversations 창에서 "Absolute start time" 체크
   그 전에: View > Time Display Format > UTC Date and Time of Day
   -> Abs Start = 2026-03-14 07:15:43 UTC
      (KST 로는 2026-03-14 16:15:43)

   교차 확인:
   $ tshark -r leak.pcapng -Y 'tcp.stream eq 17 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
       -T fields -e frame.time_epoch -e frame.time_utc
     1773472543.882000   Mar 14, 2026 07:15:43.882000000 UTC

정답: 8,578,944 바이트 / 2026-03-14 07:15:43 UTC

두 번의 실패가 이 글의 요점이다.
  - 1단계: Limit to display filter 가 켜져 있으면 세상이 좁아 보인다.
           Total Packets / Percent Filtered 컬럼이 그 경고 신호다.
  - 5단계: Bytes 는 헤더 포함 총량이다. 파일 크기는 tcp.len 합산이다.
```

## 막혔을 때 다음 체크

1. `Limit to display filter` 체크가 해제되어 있는가 — `Total Packets` 컬럼이 보이면 켜진 상태다
2. TCP 탭인가 IPv4 탭인가 — 세션 단위가 필요하면 TCP 탭
3. `Bytes` / `Packets` / `Duration` 세 기준으로 각각 정렬해 봤는가
4. UDP 탭도 봤는가 — DNS 터널링은 여기 있다
5. Ethernet 탭의 MAC 쌍 개수를 확인했는가
6. `Bytes A → B` 와 `Bytes B → A` 를 비교해 방향을 정했는가
7. `Bytes` 대신 `tcp.len` 합산으로 실제 페이로드 크기를 구했는가
8. `Stream ID` 컬럼을 켰는가 — 없으면 컬럼 헤더 우클릭
9. `Absolute start time` 을 체크하고 `View > Time Display Format` 을 UTC 로 맞췄는가
10. `Rel Start` 오름차순으로 세션 순서를 확인했는가
11. 목표 세션에 `Follow > TCP Stream > Raw > Save as` 를 해 봤는가
12. `Copy > as CSV` 로 표를 꺼내 정리했는가
13. 프로토콜 구성이 예상과 다르면 스트림 하나만 필터한 상태로 [FOR-0148](./protocol-hierarchy.html) 을 다시 봤는가
14. 재전송·누락 때문에 스트림이 깨진 것은 아닌가 ([FOR-0151](./expert-information.html))

## 출처

- SRC-003 — Wireshark User's Guide, "The Conversations Window": `Rel Start` / `Abs Start` 컬럼과 대화 지속 시간·방향별 평균 bits/s 컬럼의 존재, 표시 필터 적용 시 추가되는 `Total Packets` 와 `Percent Filtered` 컬럼, `Limit to display filter` 가 창을 열기 전 필터가 있으면 자동으로 켜진다는 동작, `Absolute start time` 체크박스가 상대/절대 시각을 전환한다는 점, `Name resolution` 체크박스, Copy 버튼이 CSV·YAML·JSON 으로 내보내며 숫자에 서식을 적용하지 않는다는 점, `Follow Stream…` / `Graph…` / `I/O Graphs…` 버튼, Protocol 컨트롤이 표시할 탭을 결정한다는 점
- SRC-010 — tshark man page: `-z conv,type[,filter]` 의 문법과 출력 구성(방향별 프레임/바이트, 총계, 시작 시각, 지속 시간, 기본 정렬은 총 프레임 수), 유효한 type 값 목록(`eth`, `ip`, `ipv6`, `tcp`, `udp` 등), `-z endpoints,type[,filter]`, `-Y`, `-T fields`, `-e`, `-E header=y`, `-E separator=,`
- `Stream ID` 컬럼은 TCP/UDP 탭에서 제공되며 표시 여부와 컬럼 선택 방법이 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- CLI `-z conv,tcp` 출력의 `<-` / `->` 열이 각각 어느 방향인지는 man page 에 명시적으로 대응되어 있지 않다. 방향 판정이 결론에 직결되는 경우 GUI 의 `Bytes A → B` 컬럼이나 `ip.src` 기준 합산으로 확정할 것
- 메뉴 경로와 컨텍스트 메뉴 항목 구성은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
