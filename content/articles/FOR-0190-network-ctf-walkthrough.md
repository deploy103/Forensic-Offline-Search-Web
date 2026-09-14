---
id: FOR-0190
title: "Network/PCAP 종합 CTF 문제 풀이"
slug: "network-ctf-walkthrough"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP", "DNS", "FTP", "TLS", "ICMP"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "DNS", "FTP", "TCP", "TLS", "ICMP"]
tools: ["Wireshark", "tshark", "HxD"]
commands: ["tshark -r case.pcapng -q -z io,phs", "tshark -r case.pcapng -q -z conv,tcp", "tshark -r case.pcapng -Y \"dns.flags.response==0\" -T fields -e dns.qry.name", "tshark -r case.pcapng --export-objects http,out"]
regex_patterns: ["[A-Za-z0-9+/]{20,}={0,2}"]
wireshark_filters: ["http.request", "dns.qry.name.len > 30", "ftp || ftp-data", "tls.handshake.type == 1", "tcp.stream eq 5", "frame contains \"flag\""]
tshark_fields: ["ip.src", "ip.dst", "http.host", "http.request.uri", "dns.qry.name", "tls.handshake.extensions_server_name"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["Network 종합 풀이", "pcap CTF 종합"]
keywords: ["Network CTF", "pcap 종합 분석", "DNS 터널링", "FTP 파일 전송", "Base64 페이로드", "TLS SNI", "Protocol Hierarchy", "Conversations", "tshark 파이프라인", "타임라인 재구성"]
aliases: ["pcap 문제 풀이", "네트워크 문제 종합", "wireshark ctf", "pcap 종합", "네트워크 포렌식 풀이", "pcap 여러 단계"]
symptom_keywords: ["소문항이 여러 개인 네트워크 문제를 어디서부터 풀지 모르겠다", "여러 프로토콜이 섞여 있다", "flag가 여러 개인 것 같다", "시간순으로 정리해야 한다", "어느 필터부터 걸어야 할지 모르겠다"]
related: ["FOR-0146", "FOR-0155", "FOR-0188", "FOR-0189"]
source_ids: ["SRC-002", "SRC-003", "SRC-010", "SRC-065", "SRC-074"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

네트워크 종합 문제는 **Protocol Hierarchy로 프로토콜 비중을 먼저 확정하고, 비중이 큰 순서대로 하나씩 파서 소문항을 채운 뒤, 마지막에 시간순 표로 전체 침해 흐름을 재구성**하면 풀린다 — 한 프로토콜에 매몰되어 다른 단서를 놓치는 것이 최대 실패 요인이다.

## 어떤 문제에서 필요한가

- 하나의 pcap에 소문항이 3개 이상 딸린 시나리오형 문제("공격자의 IP는?", "탈취한 계정은?", "유출한 파일은?", "숨긴 통신 채널은?")
- 여러 프로토콜(DNS, HTTP, FTP, TLS 등)이 한 캡처에 섞여 있다
- 답을 시간순 서술로 요구한다
- 개별 필터는 아는데 "무엇부터 볼지" 순서가 안 잡힌다

## 문제에서 처음 볼 단서

1. 파일 크기와 패킷 수 — 수 MB 이상이면 여러 단계가 있다고 가정한다
2. 지문의 동사 개수 — "접속", "다운로드", "업로드", "숨김" 각각 다른 artifact다
3. Protocol Hierarchy에서 비중이 큰 프로토콜 2~3개가 각각 다른 소문항의 답일 가능성이 높다
4. DNS 패킷 수가 비정상적으로 많다 → 터널링 소문항이 따로 있다는 신호
5. TLS만 있고 평문이 없다 → SNI/인증서/패킷 크기 패턴으로 풀어야 하는 소문항

## 30초 절차

```bash
tshark -r case.pcapng -q -z io,phs
```

1. Protocol Hierarchy → 비중 순으로 프로토콜 목록을 적는다
2. Conversations(TCP/UDP) → Bytes로 정렬해 각 프로토콜의 "가장 큰 대화"를 찾는다
3. 비중이 큰 프로토콜부터 전용 필터로 진입해 소문항을 하나씩 채운다
4. 확보한 값(IP, 시각, 파일명, 계정)을 표에 쌓는다
5. 마지막에 시간순으로 정렬해 전체 흐름 문장을 완성한다

## 상세 절차

### 시나리오

```text
"사내망에서 다음 사건이 발생했다.
 아래 pcap 하나로 다음을 답하시오.
  ① 공격자의 IP와 최초 접근 방식
  ② 탈취된 웹 로그인 계정
  ③ 반출된 파일명과 내용
  ④ 숨겨진 명령 통신 채널의 종류
  ⑤ 전체 사건을 시각순으로 서술
 첨부: case.pcapng (52,140 packets, 31 MB)"
```

### 0단계 — 전체 그림: Protocol Hierarchy와 Conversations

```bash
tshark -r case.pcapng -q -z io,phs
```

```text
Protocol                         Percent Packets  Packets  Bytes
Frame                             100.0            52140   34881200
  IPv4                             99.8            52036     521004
    TCP                            71.2            37124   22104880
      HTTP                          2.1            1104     3980210
      FTP-DATA                      9.4            4908    12604112   <- 크다
      TLS                          14.7            7664     4108330
    UDP                            28.6           14902     388820
      DNS                          28.1           14655     372004     <- 비정상적으로 많다
```

여기서 이미 두 개의 큰 흐름이 보인다. **FTP-DATA(파일 전송)와 DNS(과다, 터널링 후보).** HTTP는 상대적으로 작지만 초기 침투 단계일 가능성이 있다.

```bash
tshark -r case.pcapng -q -z conv,tcp | sort -t/ -k1 -nr | head -5
```

```text
10.0.0.15:49930  <->  203.0.113.9:80     1104 pkts   3,980,210 bytes
10.0.0.15:49955  <->  203.0.113.9:20     4908 pkts  12,604,112 bytes
10.0.0.15:49980  <->  198.51.100.44:443  7664 pkts   4,108,330 bytes
```

내부 IP는 `10.0.0.15` 하나로 고정. 외부는 세 개(`203.0.113.9` 두 포트, `198.51.100.44`). **HTTP와 FTP 상대가 같은 IP(`203.0.113.9`)라는 점이 핵심 단서다** — 하나의 공격 인프라일 가능성이 높다.

### 1단계 — HTTP: 최초 접근과 계정 탈취 (① ②)

```text
필터: http.request
```

```text
No.  Time            Info
812  07:02:11.104    GET /login HTTP/1.1
900  07:02:44.310    POST /login.php HTTP/1.1
1050 07:03:02.882    GET /admin/dashboard HTTP/1.1
```

`POST /login.php`를 Follow TCP Stream으로 확인한다.

```text
POST /login.php HTTP/1.1
Host: 203.0.113.9
Content-Type: application/x-www-form-urlencoded
Content-Length: 41

username=jhkim&password=Summer2026!
```

```text
HTTP/1.1 302 Found
Set-Cookie: PHPSESSID=a1b2c3d4e5; path=/
Location: /admin/dashboard
```

**302 응답 + 세션 쿠키 발급 = 로그인 성공.** ① 공격자는 `203.0.113.9:80`에 로그인 폼으로 접근했고, ② 탈취(또는 사용)된 계정은 `jhkim / Summer2026!`이다.

```bash
tshark -r case.pcapng -Y 'http.request.method=="POST"' \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

```text
2026-05-02 07:02:44.310  10.0.0.15  203.0.113.9  /login.php
```

내부 IP `10.0.0.15`가 요청 **주체**라는 점에 주의한다. 시나리오에 따라 이 IP가 "탈취당한 내부 직원"일 수도 있고 "공격자가 내부망을 이미 장악한 상태"일 수도 있다 — 문항 ①의 "공격자 IP"가 반드시 외부 IP는 아니다. 여기서는 로그인 대상 서버(`203.0.113.9`)를 공격 인프라로 지목한다.

### 2단계 — FTP: 반출된 파일 (③)

```text
필터: ftp
```

```text
USER anonymous
PASS -
PASV
STOR employee_records.zip
```

`STOR`이므로 **업로드**다. 반출 방향이 맞는지는 IP 순서로 재확인한다 — `10.0.0.15`가 명령을 보냈고 `203.0.113.9`가 목적지이므로 내부에서 외부로 업로드, 즉 유출 흐름과 일치한다.

```text
첫 시도 (실패):
File > Export Objects > FTP-DATA 를 열었더니 메뉴 자체가 없다.
(FTP-DATA 는 Export Objects 대상이 아니다. FOR-0189 참고)
```

Conversations에서 확보한 `203.0.113.9:20` 스트림을 Follow TCP Stream, `Show data as: Raw`로 저장한다.

```bash
$ file extracted.zip
extracted.zip: Zip archive data
$ unzip -l extracted.zip
  Length  Name
--------  ----
  184320  employee_records.csv
     412  note.txt
$ unzip -p extracted.zip note.txt
flag{ftp_upload_via_pasv_mode}
```

③ 반출 파일은 `employee_records.zip`(내부에 `employee_records.csv`, `note.txt`)이며 `note.txt`에 첫 flag가 있다.

### 3단계 — DNS 과다: 숨겨진 채널 (④)

```bash
tshark -r case.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name |
  awk -F'.' '{print length($1), $1}' | sort -rn | head -5
```

```text
57 aGVsbG8gZnJvbSBjMmJlYWNvbg
55 ZmxhZ3tkbnNfdHVubmVsX2RldGVjdGVkfQ
52 ZXhmaWx0cmF0ZWRfZGF0YV9jaHVuazAwMQ
```

```text
필터: dns.qry.name.len > 30
```

서브도메인이 `A-Za-z0-9`로만 구성되고 길이가 40~60자 — Base64 패턴과 일치한다([FOR-0188](./pcap-base64-hex-payload.html)). 도메인 접미사(`.tunnel.example.com` 등)를 제외한 첫 라벨만 이어 붙여 디코딩한다.

```bash
tshark -r case.pcapng -Y 'dns.flags.response==0' -T fields -e frame.number -e dns.qry.name |
  sort -k1 -n | awk '{print $2}' | cut -d'.' -f1 > labels.txt

while read -r l; do
  pad=$(( (4 - ${#l} % 4) % 4 ))
  printf '%s%s' "$l" "$(printf '=%.0s' $(seq 1 $pad) 2>/dev/null)" | base64 -d 2>/dev/null
  echo
done < labels.txt
```

```text
hello from c2beacon
flag{dns_tunnel_detected}
exfiltrated_data_chunk001
...
```

④ 숨겨진 채널은 **DNS 쿼리 이름을 이용한 Base64 인코딩 터널링**이며 두 번째 flag가 여기서 나온다.

### 4단계 — TLS: 세 번째 대화의 정체

`198.51.100.44:443` 대화는 암호화되어 내용을 볼 수 없다. SNI로 목적지만 확인한다.

```text
필터: tls.handshake.type == 1
```

```text
Server Name: cdn-assets.example-cdn.net
```

정상적인 CDN 도메인이면 이 대화는 배경 트래픽(노이즈)이다. **모든 대화가 공격과 관련된 것은 아니다** — TLS 대화는 이번 사건의 답에서 제외한다는 판단을 명시적으로 적는다.

### 5단계 — 시간순 통합

```bash
tshark -r case.pcapng -Y 'http.request or ftp.request.command or dns.flags.response==0' \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri -e ftp.request.command -e dns.qry.name |
  sort
```

이 출력을 표로 옮긴다.

| 시각(UTC) | 시각(KST) | 이벤트 | 근거 |
| --- | --- | --- | --- |
| 07:02:11.104 | 16:02:11.104 | `GET /login` 요청 | HTTP |
| 07:02:44.310 | 16:02:44.310 | `POST /login.php`, 계정 `jhkim` 시도 | HTTP Follow Stream |
| 07:02:44.512 | 16:02:44.512 | `302 Found` + 세션 쿠키 발급 (로그인 성공) | HTTP 응답 |
| 07:03:02.882 | 16:03:02.882 | `/admin/dashboard` 접근 | HTTP |
| 07:05:18.220 | 16:05:18.220 | FTP `PASV` + `STOR employee_records.zip` | FTP 제어 채널 |
| 07:05:19.001 ~ 07:06:40.882 | 16:05:19 ~ 16:06:40 | 12.6 MB 데이터 채널 전송 | FTP-DATA (Follow Stream) |
| 07:07:02.010 ~ 07:41:55.660 | 16:07:02 ~ 16:41:55 | DNS 서브도메인 14,655건, Base64 인코딩 확인 | DNS 터널링 |

캡처의 타임존이 기록되어 있지 않으면 **UTC로 가정하고 명시**한다. KST 변환은 +9시간이다.

## 출력 필드 해석

| 소문항 | 답 | 근거 artifact | 강도 |
| --- | --- | --- | --- |
| ① 공격 인프라 IP | `203.0.113.9` | HTTP/FTP 상대 IP 동일 | 강 |
| ② 탈취 계정 | `jhkim` / `Summer2026!` | POST 본문 평문 | 강 (평문 캡처에 한함) |
| ③ 반출 파일 | `employee_records.zip` | FTP-DATA Follow Stream | 강 |
| ④ 은닉 채널 | DNS 터널링(Base64) | 서브도메인 길이/문자 집합 + 디코딩 성공 | 강 |
| (제외) TLS 대화 | 관련 없음 | 정상 CDN SNI | 판단 근거 명시 필요 |

## pivot: 다음에 볼 artifact

| pcap에서 얻은 것 | 다음 목표 |
| --- | --- |
| 탈취 계정(`jhkim`) | 해당 계정의 EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) |
| 반출 파일명 | 디스크 `$MFT`/`$UsnJrnl`에서 생성·삭제 이력 |
| 공격 인프라 IP | 방화벽/프록시 로그, `access.log`에서 같은 IP 재검색 |
| DNS 터널링 도메인 | 다른 세션에도 같은 도메인이 있는지 재검색 |
| 전송 시각 | 서버 로그·EVTX와 초 단위로 대조 |

## 흔한 함정

- **한 프로토콜만 파고 나머지를 놓치는 것** → HTTP만 보고 DNS 터널링 소문항을 놓친다 → Protocol Hierarchy에서 비중 있는 프로토콜을 전부 목록화하고 하나씩 소거한다.
- **HTTP에서 계정이 나왔다고 즉시 최종 답으로 쓰는 것** → 세션 쿠키가 실제로 로그인 성공을 의미하는지 응답 코드(302)와 함께 확인해야 한다 → 요청과 응답을 짝지어 본다.
- **FTP-DATA를 Export Objects에서 찾으려다 시간을 버리는 것** → 그 프로토콜은 지원 목록에 없다 → 처음부터 Follow Stream을 쓴다.
- **DNS 패킷 수만 보고 바로 터널링이라 단정하는 것** → 정상 환경에도 DNS가 많을 수 있다 → 서브도메인 문자 집합과 길이 분포를 반드시 확인한다.
- **TLS 대화를 무시하지 않고 억지로 답에 끼워 맞추는 것** → SNI가 정상 도메인이면 배경 트래픽이다 → "관련 없음"이라고 판단 근거와 함께 명시하는 것도 정답의 일부다.
- **시간대를 확정하지 않고 여러 프로토콜의 시각을 섞는 것** → Wireshark 기본은 상대 시간이다 → `View > Time Display Format`을 UTC 절대시각으로 통일한 뒤 비교한다.
- **소문항마다 필터를 처음부터 다시 만드는 것** → 비효율적이고 실수가 늘어난다 → Conversations에서 얻은 IP:포트를 각 프로토콜 필터에 재사용한다.
- **디코딩된 데이터가 최종 flag라고 확인 없이 제출하는 것** → 다중 인코딩이나 중간 노이즈가 섞일 수 있다 → `flag{...}` 형식이 실제로 나올 때까지 반복 디코딩한다.

## 교차검증

```bash
# 1) 전체 흐름 요약이 GUI와 일치하는지
tshark -r case.pcapng -q -z io,phs
tshark -r case.pcapng -q -z conv,tcp

# 2) 계정 정보가 다른 스트림에도 등장하는지 (재사용 여부)
tshark -r case.pcapng -Y 'http.request.method=="POST"' \
  -T fields -e frame.time -e http.file_data | grep -i jhkim

# 3) DNS 터널링 데이터 총량 추정
tshark -r case.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name | wc -l

# 4) FTP 로 전송된 바이트와 저장 파일 크기 일치 확인
ls -l extracted.zip
tshark -r case.pcapng -q -z conv,tcp | grep '203.0.113.9:20'
```

GUI 통계와 tshark 수치가 다르면 필터 조건이나 재조립 설정을 재확인한다. 저장한 파일 크기가 Conversations의 Bytes와 크게 다르면 헤더 포함 여부를 의심한다.

## mini walkthrough

```text
이어지는 예시(위 시나리오와 동일 pcap)로 실제 작업 순서를 그대로 기록한다.

[단계 A] 트리아지
  tshark -r case.pcapng -q -z io,phs
  -> FTP-DATA 9.4%(12.6MB), DNS 28.1%(14,655건), HTTP 2.1%, TLS 14.7%
  -> 파일 전송 + DNS 이상 + 로그인 흔적, 세 갈래로 나눠 조사하기로 결정

[단계 B] HTTP 를 먼저 판다 (비중은 작지만 "최초 접근"이 걸려 있어서)
  필터: http.request.method=="POST"
  Follow TCP Stream -> username=jhkim&password=Summer2026!
  다음 패킷 302 Found + Set-Cookie 확인 -> 로그인 성공 확정

[단계 C] FTP 로 이동
  필터: ftp
  STOR employee_records.zip 확인

  첫 시도 (실패): File > Export Objects > FTP-DATA
  -> 메뉴가 아예 없음. "왜 안 보이지" 하며 몇 분 허비.

  수정: Statistics > Conversations > TCP, Bytes 정렬
  -> 203.0.113.9:20 스트림 확인, Follow > TCP Stream > Raw 저장
  -> extracted.zip 확보, 안에서 note.txt 의 flag 1 확보

[단계 D] DNS 로 이동
  필터: dns.qry.name.len > 30
  라벨 문자 집합이 A-Za-z0-9 뿐 -> Base64 후보
  프레임 순서대로 라벨을 이어 붙여 디코딩 -> flag 2 확보
  ("도메인 알파벳 순 정렬"로 먼저 시도했다가 문장이 뒤섞여 나왔음.
   frame.number 기준 정렬로 바꾸자 정상 복원됨 — 이것도 실패 후 수정 사례)

[단계 E] TLS 대화 처리
  필터: tls.handshake.type == 1
  SNI = cdn-assets.example-cdn.net -> 정상 CDN. 사건과 무관 판단.
  (관련 없다는 판단도 답안에 근거와 함께 명시)

[단계 F] 시간순 통합
  세 갈래에서 얻은 시각을 표로 정리 -> 로그인(07:02) -> 업로드(07:05) ->
  DNS 터널링(07:07~07:41) 순서로 사건이 진행됐음을 확인

최종 답:
  ① 203.0.113.9 (로그인 폼 + FTP 목적지)
  ② jhkim / Summer2026!
  ③ employee_records.zip (flag{ftp_upload_via_pasv_mode})
  ④ DNS 터널링, Base64 인코딩 (flag{dns_tunnel_detected})
  ⑤ 07:02 로그인 -> 07:05 FTP 업로드 -> 07:07~07:41 DNS 터널링 (모두 KST 16시대)
```

단계 D의 "알파벳 순 정렬 실패 → 프레임 순서로 수정"이 이 문제의 핵심 함정이다. DNS 응답/요청은 도착 순서가 알파벳과 무관하므로 반드시 캡처 순서(프레임 번호)로 재조립해야 한다.

## 막혔을 때 다음 체크

1. Protocol Hierarchy에서 비중 있는 프로토콜을 전부 나열했는가 — 하나만 파지 않았는가
2. 각 프로토콜의 "가장 큰/많은 대화"를 Conversations로 찾았는가
3. HTTP 요청-응답을 짝지어 성공/실패를 판정했는가 (상태 코드 확인)
4. Export Objects가 안 되는 프로토콜(FTP-DATA)을 Follow Stream으로 전환했는가
5. DNS 서브도메인의 문자 집합과 길이로 인코딩 여부를 판단했는가
6. 디코딩 시 프레임 순서로 재조립했는가
7. TLS 등 볼 수 없는 트래픽을 "관련 없음"으로 판단할 근거(SNI 등)를 확보했는가
8. 모든 시각을 같은 기준(UTC 절대시각)으로 통일했는가
9. 각 소문항의 답에 근거 필터/artifact를 함께 적었는가
10. 최종 flag 형식(`flag{...}`)이 실제로 나왔는가, 중간 결과를 최종 답으로 오인하지 않았는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `http.request`, `dns.qry.name`, `ftp`, `tls.handshake.type` 등 필터 필드
- SRC-003 — Wireshark User's Guide: Protocol Hierarchy, Conversations, Follow Stream, Export Objects 사용법
- SRC-010 — tshark man page: `-z io,phs`, `-z conv,tcp`, `-T fields`, `--export-objects`
- SRC-065 — RFC 1035: DNS 쿼리 이름의 라벨 구조 (터널링 판정의 기반)
- SRC-074 — RFC 4648: Base64 인코딩 규칙 (서브도메인 디코딩)
- 시나리오의 IP·계정·파일명·도메인·시각은 설명을 위한 예시 값이다. 실제 문제의 프로토콜 조합과 순서는 다를 수 있으므로 본 글의 "순서를 정하는 방법"을 재사용할 것
