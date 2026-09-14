---
id: FOR-0155
title: "DNS tunneling 의심 패턴 판별하기"
slug: "dns-tunneling"
category: "Network/PCAP"
type: "troubleshooting"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "DNS query"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["DNS"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name", "tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -20", "tshark -r capture.pcapng -Y dns -T fields -e dns.qry.name -e dns.qry.type", "tshark -r capture.pcapng -q -z conv,udp"]
regex_patterns: []
wireshark_filters: ["dns", "dns.flags.response == 0", "dns.qry.name", "dns.qry.type == 16", "dns.qry.type == 10", "dns.qry.name.len > 50", "dns.flags.rcode == 3", "dns.resp.ttl < 60"]
tshark_fields: ["dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.flags.rcode", "dns.resp.ttl", "dns.qry.name.len"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["dns tunneling", "dns 터널링"]
keywords: ["DNS tunneling", "dns 터널링", "iodine", "dnscat2", "dns.qry.name", "TXT 레코드", "NULL 레코드", "base32 서브도메인", "NXDOMAIN", "DNS exfiltration", "긴 서브도메인", "DNS 쿼리 폭주"]
aliases: ["dns 터널링 찾기", "dns가 이상하다", "dns 쿼리가 너무 많다", "서브도메인이 랜덤해 보인다", "dns로 데이터 유출", "dns c2"]
symptom_keywords: ["DNS 쿼리 개수가 비정상적으로 많다", "서브도메인이 길고 랜덤해 보인다", "TXT 쿼리가 계속 나온다", "같은 도메인으로 반복 조회한다", "NXDOMAIN이 반복된다"]
related: ["FOR-0152", "FOR-0153", "FOR-0154", "FOR-0170"]
source_ids: ["SRC-065", "SRC-002", "SRC-003", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

DNS tunneling 은 정상 조회로 위장한 서브도메인 라벨에 데이터를 인코딩해 실어 나르는 기법이다. `dns.qry.name` 을 길이·문자 구성·반복 빈도 세 축으로 집계했을 때 하나라도 비정상이면 의심하고, 목적지 도메인(등록 도메인) 하나로 수백~수천 건의 서로 다른 서브도메인이 몰리는지를 최종 확인 지표로 삼는다.

## 증상

| 증상 | 무슨 일이 벌어진 것인가 |
| --- | --- |
| Protocol Hierarchy 에서 DNS 가 전체 패킷의 10~90%를 차지한다 | 정상 브라우징에서는 DNS 가 이 정도 비율을 차지하지 않는다 |
| `dns.qry.name` 이 40~63자에 가까운 무작위 문자열이다 | base32/base36/hex 로 데이터를 인코딩한 라벨일 가능성 |
| 같은 등록 도메인(`something.example.com`)으로 질의가 수백 건 반복된다 | 정상 서비스는 같은 이름을 이렇게 자주 재조회하지 않는다 |
| TXT(`dns.qry.type == 16`) 또는 NULL(`dns.qry.type == 10`) 쿼리가 다수 존재한다 | 두 타입 모두 응답에 임의 바이트를 담기 좋아 터널링 도구가 선호한다 |
| 같은 질의에 대해 NXDOMAIN(`dns.flags.rcode == 3`) 응답이 반복된다 | 클라이언트가 존재하지 않는 이름을 계속 만들어 보내는 중이다(업로드 방향 인코딩) |
| 응답의 TTL(`dns.resp.ttl`)이 0에 가깝다 | 캐싱을 막아 매 요청이 실제 서버까지 도달하게 하려는 터널링 인프라의 특징 |

## 가장 가능성 높은 원인

### 원인 1 — 데이터를 서브도메인 라벨에 인코딩해 올리는 중 (업로드 방향)

DNS 질의 이름은 RFC 1035 기준 라벨 하나가 최대 63바이트, 전체 이름이 최대 253바이트다. 공격자는 유출할 데이터를 base32/base36/hex 로 인코딩해 이 한도에 최대한 채워 넣는다.

```text
aGVsbG8gZnJvbSBk.tunnel.example.com
b3RoZXIgZGF0YSBo.tunnel.example.com
c2VjcmV0X2ZpbGUu.tunnel.example.com
```

세 질의 모두 등록 도메인(`tunnel.example.com`)은 같고, 맨 앞 라벨만 매번 바뀐다. 이 패턴이 원인 1의 확정 근거다.

### 원인 2 — 응답에 데이터를 담아 내려받는 중 (다운로드 방향)

TXT/NULL/CNAME 레코드는 응답 페이로드에 임의 바이트를 넣기 쉽다. `iodine`, `dnscat2` 같은 도구가 실제로 이 방식을 쓴다.

```text
dns.qry.type == 16 && dns.qry.name contains "tunnel.example.com"
```

같은 이름을 반복 조회하면서 매번 다른 TXT 응답을 받는다면, 응답 쪽으로 명령이나 파일 조각을 전달하는 C2 채널이다.

### 원인 3 — 서브도메인이 정상적으로 길거나 무작위인 경우 (오탐)

CDN·트래킹·안티봇 서비스도 긴 무작위 서브도메인을 쓴다(`a1b2c3.cdn.example.net` 류). 다음 세 가지가 함께 있어야 진짜 터널링으로 격상한다.

| 판정 축 | 정상 CDN/트래킹 | DNS tunneling |
| --- | --- | --- |
| 등록 도메인 다양성 | 여러 도메인에 분산 | **동일 도메인에 집중** |
| 요청 빈도 | 페이지 로드 시 1회성 | **지속적, 주기적** |
| 응답 크기/타입 | A/AAAA, 표준 크기 | TXT/NULL 다수, 크기가 큼 |

셋 중 하나만 맞으면 오탐 가능성이 높다. 세 가지가 겹칠 때만 확정한다.

## 1차 확인

```bash
tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name |
  sort | uniq -c | sort -nr | head -20
```

이 한 줄로 "어떤 이름이 몇 번 조회됐는가"가 나온다. 상위 몇 개가 전부 같은 등록 도메인이고 앞부분만 랜덤이면 1차 확인 통과다.

```text
   1  aGVsbG8gZnJvbSBk.tunnel.example.com
   1  b3RoZXIgZGF0YSBo.tunnel.example.com
   1  c2VjcmV0X2ZpbGUu.tunnel.example.com
 987  (정상 브라우징 도메인들, 각 1~5회)
```

**빈도수가 전부 1인데도 의심스러운 이유**는, 매 질의의 라벨이 전부 다르기 때문이다 — 데이터를 실어 나르므로 같은 문자열이 반복될 이유가 없다. 이때는 빈도가 아니라 **등록 도메인으로 groupby** 해야 패턴이 드러난다.

```bash
tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name |
  awk -F'.' '{n=NF; print $(n-1)"."$n}' | sort | uniq -c | sort -nr | head
```

```text
 3112  example.com          <- 이 중 몇 개가 tunnel. 서브도메인인지 다시 확인
   45  google.com
   12  msftconnecttest.com
```

`example.com` 하나로 3,112건이 몰려 있으면 등록 도메인 집중도 확인이 끝난 것이다.

## 2차 확인

### 길이와 문자 구성으로 인코딩 여부를 확정한다

```bash
tshark -r capture.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name |
  awk '{print length, $0}' | sort -nr | head -10
```

63자에 가까운 이름이 다수이고, 알파벳+숫자만으로 구성되어 있으며 사람이 읽을 수 없는 문자열이면 base32/base36/hex 인코딩이다.

```text
wireshark 필터: dns.qry.name.len > 50
```

`dns.qry.name.len` 은 정확한 옥텟 길이를 준다. 일반적인 서비스 도메인은 20~30자를 넘기지 않는다.

### 쿼리 타입 분포를 본다

```bash
tshark -r capture.pcapng -Y dns -T fields -e dns.qry.type | sort | uniq -c | sort -nr
```

| 코드 | 타입 | 정상 비율 | 터널링에서 |
| --- | --- | --- | --- |
| 1 | A | 대다수 | 낮음 |
| 28 | AAAA | 다수 | 낮음 |
| 16 | TXT | 소수 (SPF/DKIM 조회) | **다수, 반복적** |
| 10 | NULL | 거의 없음 | **다수면 강한 신호** |
| 5 | CNAME | 소수 | 응답 데이터 운반용으로 다수 가능 |
| 255 | ANY | 거의 없음 | 대역폭을 늘리려는 시도 |

TXT/NULL 비중이 전체 DNS 쿼리의 10%를 넘으면 정상 인프라로 보기 어렵다.

### 응답 코드와 TTL 로 방향을 구분한다

```text
dns.flags.rcode == 3          -> NXDOMAIN 반복 = 업로드 방향(존재하지 않는 이름으로 데이터 전송)
dns.resp.ttl < 60             -> 캐싱 회피. 매 요청이 실서버까지 도달해야 하는 터널 인프라
```

NXDOMAIN 이 반복되는데도 클라이언트가 계속 같은 서버로 새 이름을 질의한다면, 서버 응답 자체가 필요 없고 **전송이 목적**인 업로드 채널이다.

## 다른 방법

| 상황 | 우회 |
| --- | --- |
| 필터로는 판단이 애매하다 | `tshark -q -z conv,udp` 로 해당 DNS 서버와의 대화 하나가 얼마나 오래·많이 지속되는지 본다 |
| 등록 도메인을 눈으로 찾기 번거롭다 | `awk -F'.' '{print $(NF-1)"."$NF}'` 로 항상 마지막 두 라벨만 뽑아 집계한다 |
| Base32/Base64 디코딩을 직접 확인하고 싶다 | 라벨을 이어붙여 CyberChef 없이 `python3 -c "import base64;print(base64.b32decode('...'.upper()+'===='))"` 로 검증 |
| 파일 하나가 여러 질의에 조각나 있다고 의심된다 | 시간 순으로 정렬한 라벨을 순서대로 이어 붙여 디코딩 시도 |
| DNS 자체가 아니라 다른 프로토콜 터널이 의심된다 | ICMP 페이로드도 함께 확인한다 ([FOR-0170](./icmp-tunneling.html)) |

## 실제 예시

```text
문제:
"내부 PC에서 외부로 파일이 유출된 것으로 의심된다. 어떤 방식으로, 무슨 파일이
유출됐는지 확인하시오."
첨부: leak.pcapng (24,910 packets)

1. 첫 시도 (실패) — HTTP/FTP만 확인했다
   Statistics > Protocol Hierarchy
     TCP 18%  UDP 81% (DNS 79.8%)
   http.request  -> 3건, 전부 정상 사이트 접속
   ftp           -> 0건
   "유출 흔적 없음" 이라 판단했다 -> 오답.
   원인: DNS 가 79.8%라는 압도적 비중을 그냥 넘겼다.

2. 접근 변경 — DNS 질의 이름을 집계한다
   tshark -r leak.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name |
     awk -F'.' '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -nr | head
     19832  cdn-relay.net       <- 압도적 1위, 등록 도메인 하나에 집중
       120  google.com
        45  msftconnecttest.com

3. 라벨 확인
   tshark -r leak.pcapng -Y 'dns.qry.name contains "cdn-relay.net"' \
     -T fields -e dns.qry.name | head -5
     nv2gk4rammfsyylhmvzhs4tjm5wgk5a=.chunk0.cdn-relay.net
     nv2wo3tfmzsxi2lhmvzhs4tjm5wgk5a=.chunk1.cdn-relay.net
     ojwgk4rammfsyylhmvzhs4tjm5wgk5a=.chunk2.cdn-relay.net

   순번(chunk0, chunk1, chunk2 ...)이 명시적으로 붙어 있다. base32 로 보인다.

4. 디코딩
   python3 -c "
   import base64
   labels = ['NV2GK4RAMMFSYYLHMVZHS4TJM5WGK5A=','NV2WO3TFMZSXI2LHMVZHS4TJM5WGK5A=','OJWGK4RAMMFSYYLHMVZHS4TJM5WGK5A=']
   for l in labels:
       print(base64.b32decode(l))
   "
   b'confidential_' b'report_2026_Q' b'1.docx......'

5. 전체 청크를 chunk 번호 순으로 정렬해 이어붙이면 파일명이 복원된다.

정답: DNS tunneling(TXT 없이 A 쿼리 이름 자체로 인코딩) / confidential_report_2026_Q1.docx
```

1단계의 실패가 핵심이다. **Protocol Hierarchy 의 비율을 확인하고도 "DNS 니까 정상"이라고 넘기면 안 된다.** 비정상적으로 높은 비중 자체가 1차 신호다.

## 막혔을 때 다음 체크

1. `Statistics > Protocol Hierarchy` 에서 DNS 비중이 비정상적으로 높은가
2. 등록 도메인 기준으로 groupby 했을 때 하나에 집중되는가
3. `dns.qry.name.len` 이 40자 이상으로 몰려 있는가
4. `dns.qry.type == 16`(TXT) 또는 `== 10`(NULL) 비중이 높은가
5. `dns.flags.rcode == 3`(NXDOMAIN) 이 반복되는가 — 업로드 방향 신호
6. `dns.resp.ttl` 이 비정상적으로 낮은가
7. 라벨에 순번(`chunk0`, `part1`, 일련번호)이 보이는가
8. base32/base64/hex 로 디코딩을 시도했는가
9. 같은 시각대의 다른 UDP 트래픽도 확인했는가 ([FOR-0176](./udp-flow-analysis.html))
10. ICMP 에도 유사한 반복 패턴이 있는가 ([FOR-0170](./icmp-tunneling.html))
11. 도메인 자체를 검색해 알려진 터널링 도구(`iodine`, `dnscat2`) 서명과 일치하는지 확인했는가

## 출처

- SRC-065 — RFC 1035 (DNS): 라벨 최대 63바이트, 전체 이름 최대 253바이트 제한, QTYPE 코드(A=1, CNAME=5, NULL=10, TXT=16, AAAA=28), RCODE 값(NXDOMAIN=3)
- SRC-002 — Wireshark Display Filter Reference: `dns.qry.name`, `dns.qry.type`, `dns.qry.name.len`, `dns.flags.response`, `dns.flags.rcode`, `dns.resp.ttl` 필드명 확인
- SRC-003 — Wireshark User's Guide: Protocol Hierarchy, Statistics 메뉴 사용법
- SRC-010 — tshark man page: `-Y`, `-T fields -e`, `-z conv,udp`
- 실제 터널링 도구(iodine, dnscat2)의 인코딩 방식은 도구/버전마다 다르며, 본문의 예시는 일반화된 패턴이다. 실제 사건에서는 캡처된 라벨을 직접 디코딩해 검증할 것
