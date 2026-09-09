---
id: FOR-0146
title: "Wireshark 30초 트리아지: pcap을 받고 처음 할 다섯 가지"
slug: "wireshark-30sec-triage"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "DNS", "TCP", "UDP", "FTP", "SMTP", "SMB", "TLS", "ICMP", "ARP", "DHCP"]
tools: ["Wireshark", "tshark", "NetworkMiner", "HxD"]
commands: ["tshark -r capture.pcapng -q -z io,phs", "tshark -r capture.pcapng -q -z conv,tcp", "tshark -r capture.pcapng -q -z endpoints,ip", "tshark -r capture.pcapng --export-objects http,out/"]
regex_patterns: []
wireshark_filters: ["http.request", "dns", "ftp || ftp-data", "smtp", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "frame contains \"flag\"", "tcp contains \"password\"", "tcp.stream eq 0", "!(arp || icmp || dns)"]
tshark_fields: ["ip.src", "ip.dst", "tcp.stream", "http.host", "http.request.uri", "dns.qry.name"]
log_fields: []
file_formats: ["pcap", "pcapng"]
keywords: ["Wireshark", "pcap 트리아지", "Protocol Hierarchy", "Conversations", "Endpoints", "Export Objects", "Follow TCP Stream", "네트워크 문제 시작", "패킷 분석 순서"]
aliases: ["와이어샤크 시작", "pcap 처음", "pcap 뭐부터", "패킷 분석 순서", "와이어샤크 트리아지", "wireshark 처음", "pcap 열었는데 뭘 봐야하나"]
symptom_keywords: ["패킷이 너무 많다", "pcap을 받았는데 뭘 봐야 할지 모르겠다", "어디서 시작할지", "필터를 모르겠다", "파일을 추출하고 싶다", "flag가 어디 있는지"]
related: ["FOR-0001", "FOR-0158"]
source_ids: ["SRC-003", "SRC-002", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

pcap을 열면 패킷 목록을 스크롤하지 말고 **Statistics > Protocol Hierarchy → Conversations → 관심 프로토콜 필터 → Follow TCP Stream → Export Objects** 순서로 30초 안에 "어떤 프로토콜에 무엇이 실려 있는가"를 확정한다.

## 어떤 문제에서 필요한가

- 첨부가 `.pcap` / `.pcapng` 하나뿐이고 지문이 짧은 모든 문제
- 패킷이 수만~수십만 개라 눈으로 볼 수 없는 상황
- "다운로드한 파일 이름", "전송된 자격증명", "명령 실행 흔적"을 찾아야 하는 상황

**패킷 목록을 위에서 아래로 읽는 것은 거의 항상 오답이다.** 통계 화면이 먼저다.

## 문제에서 처음 볼 단서

1. **파일 크기** — 수백 KB면 프로토콜이 몇 개 안 된다. 수십 MB면 파일 전송이나 스캔이 들어 있다.
2. **지문의 명사** — "다운로드"→HTTP/FTP, "메일"→SMTP/IMF, "조회"→DNS, "접속"→TCP/RDP, "숨겨진"→ICMP/DNS 터널링
3. **Protocol Hierarchy에서 비중이 이상한 프로토콜** — 정상 트래픽에 ICMP가 40%면 그것이 답이다
4. **패킷 개수 대비 시간 범위** — 1초에 수천 패킷이면 스캔이나 플러딩

## 30초 절차

GUI 5단계:

```text
1. Statistics > Capture File Properties   -> 패킷 수, 시간 범위, 캡처 환경
2. Statistics > Protocol Hierarchy        -> 어떤 프로토콜이 있는가  (가장 중요)
3. Statistics > Conversations > TCP       -> Bytes로 정렬. 가장 큰 대화가 목표
4. 해당 행 우클릭 > Apply as Filter > Selected
5. 패킷 우클릭 > Follow > TCP Stream      -> 내용을 눈으로 읽는다
```

CLI로 같은 것을 한 번에:

```bash
tshark -r capture.pcapng -q -z io,phs
```

전문 없이 문자열만 먼저 확인하고 싶으면:

```bash
strings capture.pcapng | grep -Ei 'flag\{|password|user=|\.zip|\.exe|Authorization'
```

## 상세 절차

### 1단계 — Capture File Properties: 판을 읽는다

`Statistics > Capture File Properties`

| 보는 항목 | 왜 |
| --- | --- |
| Packets | 총 개수. 1,000개 이하면 수동으로도 볼 수 있다 |
| First / Last packet | 시간 범위. 문제 지문의 시각과 대조 |
| Capture file comments | **pcapng는 주석을 담을 수 있다. 힌트가 들어 있는 경우가 있다** |
| Interfaces / Encapsulation | Ethernet인지 Wi-Fi(802.11)인지 Linux cooked인지 |
| Average packets/s | 급증 구간이 있는지 판단 |

pcapng 주석 확인은 CTF에서 실제로 정답인 경우가 있다. 놓치지 않는다.

### 2단계 — Protocol Hierarchy: 전체 그림

`Statistics > Protocol Hierarchy`

```text
Protocol                          Percent Packets  Packets  Bytes
Frame                             100.0            18422    12894011
  Ethernet                        100.0            18422    257908
    Internet Protocol Version 4    99.4            18311    366220
      Transmission Control Protocol 82.1           15125    11204418
        Hypertext Transfer Protocol  3.4             631     1892044
          Line-based text data       0.4              78      412009
          Media Type                 0.2              41      983221
        FTP Data                     8.8            1621     8104332   <-- 큰 파일 전송
        File Transfer Protocol       0.6             112       11204
      User Datagram Protocol        17.3            3186      264880
        Domain Name System          16.9            3112      258110   <-- DNS가 비정상적으로 많다
      Internet Control Message Protocol 0.9          171       28442
```

읽는 법:

- **`Bytes`가 큰 프로토콜** = 파일이나 데이터가 실려 있다 → FTP Data 8 MB는 파일 전송 확정
- **`Packets`가 비정상적으로 많은 프로토콜** = DNS 3,112개는 정상 브라우징으로 나오지 않는다 → **DNS 터널링 의심**
- **없어야 할 프로토콜의 존재** = Telnet, FTP 평문, SMB, IRC
- **`data` / `Line-based text data`** = 파서가 인식 못한 페이로드. 커스텀 프로토콜/C2 후보

여기서 결정한 프로토콜 하나만 파는 것이 30초 트리아지의 목적이다.

### 3단계 — Conversations / Endpoints: 누가 얼마나

`Statistics > Conversations` → **TCP 탭** → `Bytes` 컬럼 헤더 클릭해 내림차순 정렬

```text
Address A       Port A   Address B        Port B   Packets   Bytes     Stream ID
10.0.0.15       49812    203.0.113.77     21       112       11204     3
10.0.0.15       49813    203.0.113.77     20       1621      8104332   4     <-- 8 MB
10.0.0.15       49820    93.184.216.34    80       631       1892044   7
```

- `Bytes` 1위 대화가 대개 문제의 핵심이다
- `Stream ID` 컬럼을 켜두면 그 값으로 바로 `tcp.stream eq 4` 필터를 만들 수 있다
- 행 우클릭 → `Apply as Filter > Selected > A ↔ B`

`Statistics > Endpoints` → **IPv4 탭**은 "누가 등장하는가"를 본다. 외부 IP가 1개뿐이면 그것이 공격자/서버다.

```bash
# CLI 동등물
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -q -z endpoints,ip
```

### 4단계 — 프로토콜별 첫 필터

2단계에서 고른 프로토콜에 따라 다음 한 줄만 입력한다.

| Protocol Hierarchy에서 본 것 | 첫 필터 | 다음 행동 |
| --- | --- | --- |
| HTTP | `http.request` | URI/Host 확인 → Export Objects |
| HTTP POST 존재 | `http.request.method == "POST"` | Follow TCP Stream으로 본문 ([FOR-0158](./http-post-find.html)) |
| DNS가 과다 | `dns` → `dns.qry.name` 길이 확인 | 서브도메인 길이/개수 → 터널링 판정 |
| FTP | `ftp.request.command == "STOR" \|\| ftp.request.command == "RETR"` | 파일명 확보 → `ftp-data` Follow |
| SMTP | `smtp.data.fragment \|\| imf` | File > Export Objects > IMF (메일 원문) |
| SMB | `smb2.cmd == 5` (Create) | 접근한 파일 경로 |
| Telnet | `telnet` | Follow TCP Stream = 입력한 명령 전체 |
| TLS만 있음 | `tls.handshake.type == 1` | SNI(`tls.handshake.extensions_server_name`)로 목적지 도메인 |
| ICMP 과다 | `icmp && data.len > 32` | 페이로드에 데이터 은닉 |
| 무엇도 모를 때 | `frame contains "flag"` | 문자열 직접 사냥 |

만능 첫 필터 세 개:

```text
frame contains "flag"
tcp contains "password"
!(arp || icmp || dns || tls)
```

세 번째는 "잡음 제거"용이다. 남은 것이 본질이다.

### 5단계 — Follow Stream과 Export Objects

**Follow TCP Stream** — 패킷 하나 우클릭 → `Follow > TCP Stream`

- 클라이언트→서버는 빨강, 서버→클라이언트는 파랑으로 표시된다
- 우하단 `Show data as`를 `ASCII` / `Hex Dump` / `Raw`로 바꿀 수 있다
- **`Raw`로 바꿔 저장하면 전송된 파일 바이너리를 그대로 얻는다**
- 좌하단의 스트림 번호 스핀박스로 다음 스트림을 훑을 수 있다

**Export Objects** — `File > Export Objects >`

| 메뉴 | 추출 대상 |
| --- | --- |
| HTTP | HTTP로 전송된 모든 파일/응답 본문 |
| IMF | SMTP 메일 원문 (`.eml`) |
| SMB / SMB2 | 공유를 통해 전송된 파일 |
| FTP-DATA | FTP 데이터 채널의 파일 |
| TFTP | TFTP 전송 파일 |
| DICOM | 의료 영상 |

```bash
# CLI로 일괄 추출
tshark -r capture.pcapng --export-objects http,out_http/
tshark -r capture.pcapng --export-objects smb,out_smb/
ls -la out_http/ && file out_http/*
```

추출 후 반드시 `file`과 `strings`를 돌린다 ([FOR-0001](./30sec-triage.html)). 확장자가 거짓인 경우가 흔하다.

## 출력 필드 해석

트리아지 단계에서 컬럼을 아래처럼 바꿔두면 이후가 편하다.

| 설정 | 경로 | 이유 |
| --- | --- | --- |
| 시간을 절대 UTC로 | `View > Time Display Format > UTC Date and Time of Day` | 로그·EVTX와 대조하려면 UTC 절대시각이 필요하다 |
| 초 단위 정밀도 | 같은 메뉴 > `Milliseconds` | 순서 판정 |
| 컬럼 추가 | 필드 우클릭 > `Apply as Column` | `http.host`, `dns.qry.name`, `tcp.stream`을 컬럼으로 |
| 이름 변환 끄기 | `View > Name Resolution` 해제 | 포트 번호가 `http` 대신 `80`으로 보여 필터 작성이 정확해진다 |

기본 컬럼의 의미:

| 컬럼 | 내용 | 함정 |
| --- | --- | --- |
| `No.` | 패킷 번호 | 필터를 걸어도 번호는 원본 유지 |
| `Time` | 기본은 **캡처 시작 기준 상대 초** | 절대시각으로 바꾸지 않으면 로그와 대조 불가 |
| `Source`/`Destination` | IP (또는 MAC) | 이름 변환이 켜져 있으면 도메인으로 보인다 |
| `Protocol` | Wireshark가 **최종 판정한** 프로토콜 | 8080 포트 HTTP는 `TCP`로 보일 수 있다 → `Decode As` |
| `Length` | 프레임 전체 길이 | 페이로드 길이가 아니다 |
| `Info` | 요약 | 여기서 URI/쿼리/명령이 보이면 바로 답 |

## pivot: 다음에 볼 artifact

| pcap에서 얻은 것 | 다음 목표 |
| --- | --- |
| 다운로드한 파일명 | 디스크의 `$MFT` ([FOR-0021](./mft-basics.html)), 브라우저 Downloads ([FOR-0191](./chrome-history.html)) |
| 접속한 도메인 | 브라우저 History, DNS 캐시, `hosts` 파일 |
| 자격증명 | EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) — 실제 로그온 성공 여부 |
| 공격자 IP | 웹 서버 `access.log` ([FOR-0121](./powershell-select-string.html)) |
| 실행된 명령 문자열 | EVTX 4688, PowerShell 4104 |
| 추출한 실행 파일 | 해시 → Amcache/Prefetch 대조 |
| 전송 시각 | 그 시각 ±5분의 모든 artifact |

## 흔한 함정

- **패킷 목록을 스크롤하는 것.** 18,000개를 눈으로 보는 것은 불가능하다. 통계 → 필터 순서를 지킨다.
- **Display Filter와 Capture Filter를 혼동하는 것.** 이미 저장된 pcap에는 **Display Filter만** 쓴다. Capture Filter(BPF, `tcp port 80`)는 캡처 시점 문법이며 분석 창에 넣으면 문법 오류가 난다.
- **`Time`을 상대 초로 두고 로그와 대조하는 것.** `View > Time Display Format`을 UTC 절대시각으로 먼저 바꾼다.
- **`Protocol` 컬럼을 신뢰하는 것.** 비표준 포트의 HTTP는 `TCP`로만 표시된다. 우클릭 `Decode As > HTTP`로 강제한다.
- **TCP 재조립 실패를 놓치는 것.** 캡처가 중간부터 시작되면 Follow Stream이 깨진다. `Analyze > Expert Information`에서 재전송/누락을 먼저 확인한다.
- **Export Objects에 안 나온다고 파일이 없다고 판단하는 것.** 청크 전송·gzip·비표준 포트에서는 안 나올 수 있다. Follow Stream → `Raw` 저장으로 직접 꺼낸다.
- **TLS를 보고 포기하는 것.** 내용은 못 봐도 SNI(`tls.handshake.extensions_server_name`), 인증서 CN, 패킷 크기 패턴, JA3는 여전히 단서다.
- **`frame contains`의 대소문자.** 대소문자를 구분한다. 대소문자 무시가 필요하면 `frame matches "(?i)flag"`.
- **한글/UTF-16 문자열.** `frame contains "플래그"`는 인코딩이 맞아야 걸린다. UTF-16으로 전송됐다면 hex 검색(`frame contains 66:00:6c:00`)이 필요하다.
- **pcapng 주석을 안 보는 것.** `Statistics > Capture File Properties` 하단에 답이 적혀 있는 문제가 있다.

## 교차검증

```bash
# 1) 프로토콜 구성 — GUI Protocol Hierarchy와 동일
tshark -r capture.pcapng -q -z io,phs

# 2) 대화 목록 — GUI Conversations와 동일
tshark -r capture.pcapng -q -z conv,tcp

# 3) HTTP 요청 전체를 표로
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -e frame.number -e frame.time -e ip.src -e http.host -e http.request.uri -E header=y

# 4) DNS 질의 이름만 (터널링 판정)
tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name |
  sort | uniq -c | sort -nr | head -20

# 5) 파일 추출 — GUI Export Objects와 동일
tshark -r capture.pcapng --export-objects http,out/

# 6) 문자열 직접 사냥 — Wireshark가 파싱 못한 것도 잡힌다
strings -n 6 capture.pcapng | grep -Ei 'flag\{|BEGIN .*PRIVATE KEY|Authorization: Basic'
```

GUI와 tshark 결과가 다르면 필터 문법이나 재조립 설정을 다시 본다. `strings`는 파서를 거치지 않으므로 **Wireshark가 놓친 것을 잡는 최후 수단**이다.

## mini walkthrough

```text
문제:
"공격자가 서버에서 가져간 파일 이름과 그 안의 flag를 구하세요."
첨부: capture.pcapng (18,422 packets, 12 MB)

1. Statistics > Capture File Properties
   Packets 18,422 / 2026-03-14 07:15:02 ~ 07:41:55 UTC / 주석 없음

2. Statistics > Protocol Hierarchy
   TCP 82%  |  FTP Data 8.8% (8.1 MB)  |  DNS 16.9% (3,112 packets)
   -> 큰 것 하나(FTP Data)와 이상한 것 하나(DNS 과다)가 동시에 보인다.
      먼저 파일 전송(FTP)을 판다.

3. 필터: ftp
   응답 목록에서 명령 흐름이 보인다.
     USER anonymous / PASS ftp@example.com
     ... 
     STOR customer_list_2026.zip      <- 업로드(서버로 올림)
     RETR internal_report.pdf         <- 다운로드(가져감)

   지문은 "가져간" 이므로 RETR.

4. 첫 시도 (실패):
   File > Export Objects > FTP-DATA -> 목록이 비어 있었다.
   원인: 데이터 채널이 다른 포트(passive mode)로 열려 Wireshark가
        FTP-DATA로 연결하지 못한 상태였다.

5. 접근 변경 — Conversations에서 8 MB 대화를 직접 찾는다
   Statistics > Conversations > TCP, Bytes 내림차순
     10.0.0.15:49813 <-> 203.0.113.77:20   1621 packets  8,104,332 bytes  stream 4

   필터: tcp.stream eq 4
   우클릭 > Follow > TCP Stream
   Show data as = Raw -> Save as -> extracted.bin

6. 추출물 확인
   $ file extracted.bin
   extracted.bin: PDF document, version 1.7
   $ strings extracted.bin | grep -i flag
   flag{ftp_p4ssive_m0de_str1kes_back}

7. 남은 이상 신호(DNS 3,112개)도 확인
   tshark -r capture.pcapng -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | head -3
     aGVsbG8gZnJvbSBk.tunnel.example.com
     b3RoZXIgZGF0YSBo.tunnel.example.com
   -> Base64 서브도메인. DNS 터널링. 이 문제의 답은 아니지만 별도 플래그일 수 있다.

정답: internal_report.pdf / flag{ftp_p4ssive_m0de_str1kes_back}
```

4단계의 실패가 핵심 교훈이다. **Export Objects가 비어도 파일이 없는 것이 아니다.** Conversations의 바이트 크기가 진실을 알려주고, `Follow Stream > Raw`가 언제나 통한다.

## 막혔을 때 다음 체크

1. `Statistics > Protocol Hierarchy`를 실제로 봤는가 — 대부분의 답이 여기서 갈린다
2. `Statistics > Capture File Properties`의 **주석**을 확인했는가
3. `Statistics > Conversations`를 Bytes로 정렬했는가 — 가장 큰 대화가 목표
4. `frame contains "flag"` / `tcp contains "flag"`를 시도했는가
5. `strings capture.pcapng | grep flag`를 시도했는가 — 파서를 우회한다
6. `Analyze > Expert Information`에 재전송·누락이 있는가 — Follow Stream 신뢰도 판단
7. `Protocol` 컬럼이 `TCP`뿐인가 → `Decode As`로 프로토콜 강제
8. Export Objects가 비었는가 → `Follow Stream > Raw > Save as`
9. TLS뿐인가 → SNI, 인증서 CN, 패킷 크기 패턴으로 전환
10. DNS/ICMP 개수가 비정상인가 → 터널링 라인으로 전환
11. 시간을 UTC 절대시각으로 바꿨는가 — 다른 artifact와 대조하려면 필수
12. 추출한 파일에 `file`/`strings`/`binwalk`를 돌렸는가

## 출처

- SRC-003 — Wireshark User's Guide: Statistics 메뉴(Protocol Hierarchy, Conversations, Endpoints), Follow Stream, Export Objects
- SRC-002 — Wireshark Display Filter Reference: 본문에 등장한 필터 필드 이름
- SRC-010 — tshark man page: `-z io,phs`, `-z conv,tcp`, `--export-objects`, `-T fields`
