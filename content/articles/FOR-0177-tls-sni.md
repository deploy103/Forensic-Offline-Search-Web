---
id: FOR-0177
title: "TLS SNI로 암호화 트래픽에서도 접속 도메인 확인하기"
slug: "tls-sni"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "TLS ClientHello", "SNI"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TLS", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y \"tls.handshake.type==1\" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name", "tshark -r capture.pcapng -Y tls.handshake.type==1 -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -nr"]
regex_patterns: []
wireshark_filters: ["tls.handshake.type == 1", "tls.handshake.extensions_server_name", "tls.handshake.extensions_server_name contains \"example\"", "tls.handshake.type == 2", "tls.handshake.type == 11"]
tshark_fields: ["tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.version", "ip.src", "ip.dst", "frame.time"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["tls.handshake.extensions_server_name", "TLS SNI"]
keywords: ["TLS SNI", "Server Name Indication", "ClientHello", "tls.handshake.extensions_server_name", "암호화 트래픽 도메인", "HTTPS 목적지", "TLS handshake", "RFC 6066", "encrypted traffic domain"]
aliases: ["sni 확인", "https 도메인 확인", "암호화된 트래픽 도메인", "tls 목적지 도메인", "clienthello 도메인", "https인데 도메인 알아내기"]
symptom_keywords: ["HTTPS 트래픽뿐이라 http.host가 안 보인다", "암호화라 접속 도메인을 모르겠다", "TLS 트래픽에서 도메인을 찾아야 한다", "C2 도메인을 pcap에서 찾아야 한다"]
related: ["FOR-0178", "FOR-0152", "FOR-0146"]
source_ids: ["SRC-069", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

TLS 핸드셰이크의 첫 메시지인 ClientHello는 SNI(Server Name Indication) 확장을 **평문**으로 전송한다. 내용은 암호화되어 못 봐도 `tls.handshake.extensions_server_name` 필터 하나로 접속하려던 도메인을 확인할 수 있다.

## 어떤 문제에서 필요한가

- pcap이 전부 HTTPS(TLS)뿐이고 `http.host`, `http.request.uri`가 하나도 안 잡히는 문제
- "이 pcap에서 접속한 C2 서버 도메인을 구하라" 같은 문제
- 여러 도메인이 같은 서버 IP로 서비스되는 환경(CDN, 가상호스팅)에서 IP만으로는 목적지를 특정할 수 없는 상황
- DNS 질의는 안 남았는데(캐시된 DNS, hosts 파일 사용 등) 실제 접속 도메인을 확인해야 하는 상황

## 문제에서 처음 볼 단서

1. **Protocol Hierarchy에 HTTP는 없고 TLS만 있다**
2. **`http`로 필터링하면 0건**이면서 지문에 "접속한 사이트", "다운로드 출처" 같은 단어가 있다
3. **같은 IP로 여러 포트 443 연결이 있는데 목적지가 다른 서비스로 추정되는 상황**
4. 패킷 Info 컬럼에 `Client Hello`가 보인다

## 30초 절차

```text
tls.handshake.type == 1
```

이 필터로 나온 각 패킷을 펼쳐 `Handshake Protocol > Extension: server_name`을 확인한다. 컬럼으로 올려두면 한 번에 보인다.

```text
1. 필터: tls.handshake.type == 1              -> ClientHello만
2. 아무 패킷이나 우클릭 > Expand Subtrees
   Handshake Protocol: Client Hello > Extension: server_name
   > Server Name Indication extension > Server Name: <도메인>
3. Server Name 필드 우클릭 > Apply as Column
4. 컬럼으로 전체 목록을 한 번에 확인
```

## 상세 절차

### 1단계 — SNI가 평문인 이유

TLS 핸드셰이크는 서버 인증서를 받기 전에는 어떤 암호화 키도 아직 협상되지 않은 상태다. 클라이언트가 "어떤 도메인에 접속하려는지"를 서버에 알려줘야 서버가 그 도메인에 맞는 인증서를 골라 응답할 수 있다(가상 호스팅 환경 필수 기능). 그래서 SNI 확장은 ClientHello 안에 **암호화되지 않은 상태**로 들어간다. 이는 TLS 1.2와 TLS 1.3 모두 동일하다 — TLS 1.3이 핸드셰이크의 상당 부분(Certificate, EncryptedExtensions 등)을 암호화하지만, ClientHello 자체와 그 안의 SNI 확장은 여전히 평문이다.

### 2단계 — 필터로 전체 접속 도메인 목록 뽑기

```bash
tshark -r capture.pcapng -Y 'tls.handshake.type==1' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name \
  -E header=y
```

출력 예시:

```text
frame.number  frame.time                     ip.src        ip.dst          tls.handshake.extensions_server_name
41            2026-03-14 09:12:03.114201     10.0.0.15     93.184.216.34   www.example.com
88            2026-03-14 09:12:07.552310     10.0.0.15     198.51.100.9    login.suspicious-c2.net
203           2026-03-14 09:13:41.009821     10.0.0.15     198.51.100.9    cdn.suspicious-c2.net
```

빈도순으로 보고 싶으면:

```bash
tshark -r capture.pcapng -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -nr
```

### 3단계 — GUI에서 SNI를 컬럼으로 고정한다

패킷 상세 창에서 `Transport Layer Security > TLSv1.2/1.3 Record Layer: Handshake Protocol: Client Hello > Extension: server_name > Server Name Indication extension > Server Name` 을 찾아 우클릭 → `Apply as Column`. 이후 `tls.handshake.type == 1` 필터만 걸어두면 목록 화면에서 도메인이 바로 보인다.

### 4단계 — IP당 여러 도메인이 나오면 SNI가 실제 서비스를 구분해준다

같은 목적지 IP로 여러 SNI 값이 보이면 그 서버가 여러 도메인을 호스팅하는 것이다(CDN, 리버스 프록시, 가상 호스팅). 이 경우 **IP만으로 "무엇에 접속했다"고 결론 내리면 안 되고 SNI 값이 실제 답**이다.

### 5단계 — DNS 질의와 대조한다

SNI로 얻은 도메인은 반드시 DNS 질의 기록과 대조한다. 일치하면 신뢰도가 올라가고, DNS 질의 없이 SNI만 존재하면 hosts 파일 조작이나 DNS 캐시/DoH 사용을 의심한다.

```bash
tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u
```

## 출력 필드 해석

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| `tls.handshake.type` | 핸드셰이크 메시지 종류. `1`=ClientHello, `2`=ServerHello, `11`=Certificate | SNI는 반드시 `type==1`에서만 찾는다 |
| `tls.handshake.extensions_server_name` | ClientHello의 SNI 확장 값(도메인 문자열) | 이전 Wireshark 버전에서는 `ssl.handshake.extensions_server_name`으로 표시될 수 있다 |
| `tls.handshake.version` | ClientHello 안에 명시된 TLS 버전 | TLS 1.3 협상 시에도 호환성을 위해 이 필드가 1.2로 보일 수 있다(supported_versions 확장을 별도로 봐야 정확) |
| `ip.dst` | ClientHello의 목적지 IP | SNI 도메인과 IP가 1:1이 아닐 수 있다(가상 호스팅) |

## pivot: 다음에 볼 artifact

| SNI에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| 접속 도메인 | 같은 pcap의 DNS 질의(`dns.qry.name`)와 대조 |
| 도메인 + IP | TLS Certificate의 CN/SAN과 SNI 일치 여부 확인 ([FOR-0178](./tls-certificate-metadata.html)) |
| 접속 시각(UTC) | 브라우저 History, DNS 캐시, 프록시 로그의 같은 시각대 항목 |
| 반복 접속되는 도메인 | 접속 간격이 일정하면 비콘/C2 후보 — Conversations에서 해당 스트림의 패킷 크기 패턴 확인 |
| 못 보던 도메인 | 위협 인텔리전스 대조는 오프라인 환경 특성상 생략하고, 지문의 다른 단서와 교차 확인 |

## 흔한 함정

- **`http.host`로 먼저 찾으려다 0건에서 포기하는 것.** HTTPS는 HTTP 계층이 암호화되어 있어 `http.host`가 아예 나오지 않는다. TLS 계층의 SNI로 전환해야 한다.
- **SNI가 없는 ClientHello를 못 찾는다고 오류로 판단하는 것.** IP 주소로 직접 접속하거나 구형 클라이언트는 SNI를 안 보낼 수 있다. 이 경우 필터 결과가 애초에 없는 것이 정상이다.
- **Encrypted Client Hello(ECH)/구식 ESNI로 SNI 자체가 암호화된 최신 트래픽을 이 필터로 찾으려는 것.** 이런 캡처에서는 `tls.handshake.extensions_server_name`이 아예 나오지 않는다. 이 경우 목적지 IP·인증서(가능하면)·JA3 핑거프린트 등 다른 단서로 전환해야 한다.
- **같은 IP에 여러 도메인이 있다는 것을 놓치고 IP만으로 "접속 사이트"를 확정하는 것.** CDN/가상 호스팅 환경에서는 SNI가 실제 목적지다.
- **필드명을 `ssl.handshake.extensions_server_name`으로만 찾다가 안 나온다고 포기하는 것.** 최신 Wireshark는 `tls.*` 접두사를 쓴다. 버전에 따라 둘 다 시도한다.
- **세션 재개(Session Resumption/0-RTT)로 ClientHello 자체가 캡처에 없는 스트림을 놓치는 것.** 캡처가 세션 중간부터 시작됐다면 SNI를 볼 기회 자체가 없다. `tcp.stream`의 시작 프레임이 실제 handshake인지 먼저 확인한다.
- **SNI 도메인 문자열의 대소문자나 트레일링 문자를 무시하고 단순 비교하는 것.** DNS 질의 기록과 대조할 때 대소문자 차이나 말단 마침표(`example.com.`)로 문자열이 불일치할 수 있다.

## 교차검증

```bash
# 1) SNI 전체 목록
tshark -r capture.pcapng -Y 'tls.handshake.type==1' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name -E header=y

# 2) DNS 질의와 교차 대조
tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u

# 3) SNI 도메인이 DNS에 없는 것만 골라내기 (수동 비교용 목록 생성)
tshark -r capture.pcapng -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u > sni.txt
tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u > dns.txt
comm -23 sni.txt dns.txt

# 4) GUI 결과와 동일한지 protocol hierarchy로 재확인
tshark -r capture.pcapng -q -z io,phs
```

## mini walkthrough

```text
문제:
"악성코드가 통신한 C2 도메인을 구하라."
첨부: infected.pcapng (HTTPS만 존재, 6,004 packets)

1. 첫 시도 (실패)
   필터: http.request
   결과: 0건. Protocol Hierarchy를 보니 TLS만 82% 차지.
   HTTP 계층으로는 아무 것도 안 보였다.

2. 필터 전환
   tls.handshake.type == 1
   결과: 14건의 ClientHello.

3. SNI 컬럼 확인
   tshark -r infected.pcapng -Y 'tls.handshake.type==1' \
     -T fields -e ip.dst -e tls.handshake.extensions_server_name

     104.21.9.5      cdn.jsdelivr.net
     104.21.9.5      fonts.googleapis.com
     198.51.100.44   update.securehealthcheck-cdn.com
     198.51.100.44   update.securehealthcheck-cdn.com
     198.51.100.44   update.securehealthcheck-cdn.com

4. 판단
   정상 CDN/폰트 도메인은 1회씩만 등장.
   update.securehealthcheck-cdn.com 은 3회 반복, 목적지 IP가 하나로 고정.
   -> 반복 접속 패턴이 비콘과 일치한다.

5. DNS로 교차검증
   dns.qry.name 결과에도 동일 도메인이 존재 확인. 조작된 hosts가 아니라
   실제 DNS 질의를 거쳐 접속했음을 확인.

정답: update.securehealthcheck-cdn.com
```

1단계에서 `http.request`로 시작한 것 자체가 흔한 실수다. 프로토콜이 암호화되어 있으면 HTTP 계층 필터는 항상 실패한다는 것을 Protocol Hierarchy로 먼저 확인해야 한다.

## 막혔을 때 다음 체크

1. `tls.handshake.type == 1`이 0건인가 — TLS 자체가 없거나 캡처가 handshake 이후부터 시작됐을 수 있다
2. SNI 필드가 비어 있는가 — IP 직접 접속이거나 ECH/ESNI 사용 가능성
3. `ssl.handshake.extensions_server_name`으로도 시도했는가 — 구버전 필드명
4. DNS 질의 기록과 대조했는가 — 불일치 시 hosts 조작이나 DoH 의심
5. 같은 IP에 여러 SNI가 있는가 — CDN/가상 호스팅이면 SNI가 진짜 목적지
6. 반복 접속 간격이 일정한가 — 비콘/C2 판정
7. 인증서 메타데이터까지 확인했는가 — SNI 위조 여부는 인증서로 최종 확인([FOR-0178](./tls-certificate-metadata.html))

## 출처

- SRC-069 — RFC 8446 (TLS 1.3): ClientHello 구조와 확장 처리, Certificate 등 이후 메시지의 암호화 범위 / RFC 6066 SNI 확장 정의
- SRC-002 — Wireshark Display Filter Reference: `tls.handshake.type`, `tls.handshake.extensions_server_name` 필드명 확인
- SRC-003 — Wireshark User's Guide: 패킷 상세 창에서 필드를 컬럼으로 추가하는 절차
- Encrypted Client Hello(ECH)는 비교적 최신 확장이며 지원 브라우저/버전에 따라 동작이 다르므로, 실제 대회 캡처에서 SNI가 안 보이면 클라이언트 버전을 먼저 의심할 것
