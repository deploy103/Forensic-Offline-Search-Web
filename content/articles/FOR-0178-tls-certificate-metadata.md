---
id: FOR-0178
title: "TLS 인증서 메타데이터에서 단서 찾기: Subject, Issuer, 유효기간"
slug: "tls-certificate-metadata"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "TLS Certificate", "X.509"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["TLS", "TCP"]
tools: ["Wireshark", "tshark"]
commands: ["tshark -r capture.pcapng -Y \"tls.handshake.type==11\" -T fields -e ip.src -e ip.dst", "tshark -r capture.pcapng -Y \"tls.handshake.type==11\" -V"]
regex_patterns: []
wireshark_filters: ["tls.handshake.type == 11", "tls.handshake.type == 1", "tls.handshake.version"]
tshark_fields: ["tls.handshake.type", "tls.handshake.certificate", "tls.handshake.version", "ip.src", "ip.dst"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["tls 인증서 메타데이터", "TLS Certificate 필드"]
keywords: ["TLS Certificate", "X.509", "Subject CN", "Issuer", "self-signed certificate", "인증서 유효기간", "notBefore", "notAfter", "SAN", "인증서 위조", "TLS 1.3 암호화 인증서"]
aliases: ["tls 인증서 확인", "인증서 발급자", "자체서명 인증서", "cert cn 확인", "인증서 유효기간 확인", "https 인증서 정보"]
symptom_keywords: ["TLS 트래픽에서 인증서 정보를 확인해야 한다", "자체 서명 인증서인지 알아야 한다", "인증서 CN이 SNI와 다른지 확인해야 한다", "TLS 1.3 캡처에서 인증서가 안 보인다"]
related: ["FOR-0177", "FOR-0146", "FOR-0175"]
source_ids: ["SRC-069", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "draft"
---

## 한 줄 결론

TLS Certificate 메시지(`tls.handshake.type == 11`)를 펼치면 Subject CN, Issuer, 유효기간(notBefore/notAfter), SAN을 평문으로 확인할 수 있다. 단 **TLS 1.3에서는 이 메시지가 핸드셰이크 키로 암호화**되어 있어 세션 키 없이는 Wireshark가 열지 못한다 — 이 경우 SNI([FOR-0177](./tls-sni.html))까지만 보고 멈춰야 한다.

## 어떤 문제에서 필요한가

- SNI 도메인이 실제로 그 서버가 발급받은 인증서와 일치하는지 확인해야 하는 문제(도메인 위장/피싱 판정)
- 자체 서명(self-signed) 인증서인지 확인해 C2 서버 여부를 판단해야 하는 문제
- 인증서 유효기간으로 서버가 언제쯤 구축됐는지 추정해야 하는 문제
- 여러 pcap에서 같은 인증서(같은 Subject/Issuer)가 반복 등장해 동일 인프라임을 증명해야 하는 문제

## 문제에서 처음 볼 단서

1. **TLS 1.2 트래픽**이면서 `Certificate` 메시지가 파싱되어 보인다
2. 지문에 "이 사이트가 진짜인가", "인증서 발급자", "자체 서명" 같은 단어
3. SNI 도메인과 실제로 접속한 서버가 다를 수 있다는 의심(피싱 시나리오)

## 30초 절차

```text
tls.handshake.type == 11
```

패킷을 펼쳐 `Certificate > Certificates > Certificate > signedCertificate > subject` 와 `issuer`, `validity`를 확인한다.

```text
1. 필터: tls.handshake.type == 11        -> Certificate 메시지만
2. 0건이면 tls.handshake.version 확인    -> TLS 1.3이면 암호화되어 있어 못 본다
3. 패킷 상세창에서 subject/issuer/validity 확장
4. Subject CN(또는 SAN)을 SNI 값과 비교
```

## 상세 절차

### 1단계 — TLS 버전부터 확인한다 (가장 먼저, 가장 중요)

TLS 1.2에서는 서버가 `ServerHello` 직후 `Certificate` 메시지를 **평문**으로 보낸다. 반면 TLS 1.3에서는 키 교환 직후부터 `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`가 모두 핸드셰이크 트래픽 키로 암호화되어 전송된다. 즉 **TLS 1.3 캡처에서는 세션 키(`SSLKEYLOGFILE`) 없이는 Wireshark가 인증서 내용을 복호화하지 못한다.**

```bash
tshark -r capture.pcapng -Y 'tls.handshake.type==1' -T fields -e tls.handshake.version
```

이 값이 TLS 1.2(`0x0303`)면 인증서를 그대로 볼 수 있고, TLS 1.3 협상(ClientHello의 `supported_versions` 확장에 1.3이 있음)이면 `tls.handshake.type == 11` 필터가 대개 0건이거나 암호화된 바이트만 보인다.

### 2단계 — TLS 1.2에서 인증서 필드를 편다

```text
Certificate 패킷 클릭
> Handshake Protocol: Certificate
  > Certificates (n items)
    > Certificate
      > signedCertificate
        > subject: rdnSequence
            commonName: <Subject CN>
        > issuer: rdnSequence
            commonName: <Issuer CN>
            organizationName: <Issuer O>
        > validity
            notBefore: <시작 시각>
            notAfter: <만료 시각>
        > extensions
            subjectAltName
              dNSName: <SAN 도메인들>
```

**주의:** X.509 ASN.1 디코딩 트리의 정확한 필드 경로와 표시 방식은 Wireshark 버전에 따라 다를 수 있다. 여기서는 개념적인 위치만 제시하며, 대회장에서는 실제 캡처를 펼쳐 눈으로 확인하는 것이 가장 확실하다.

CLI에서 상세 덤프로 같은 정보를 텍스트로 뽑을 수 있다.

```bash
tshark -r capture.pcapng -Y 'tls.handshake.type==11' -V | grep -iE 'commonName|notBefore|notAfter|dNSName|organizationName'
```

### 3단계 — Self-signed 여부 판단

Subject의 CN/O와 Issuer의 CN/O가 완전히 같으면 자체 서명 인증서다.

| 관측 | 판정 |
| --- | --- |
| Subject CN == Issuer CN, Subject O == Issuer O | 자체 서명 |
| Issuer가 알려진 CA(Let's Encrypt, DigiCert 등) | 공인 CA 발급 |
| Issuer CN이 비어 있거나 임의 문자열 | 급조된 자체 서명 도구로 생성됐을 가능성 |

자체 서명 자체는 악성의 증거가 아니다. 내부 테스트 서버, 사설 IoT 장비도 흔히 자체 서명을 쓴다. **SNI/접속 맥락과 함께 봐야** 의미가 있다.

### 4단계 — 유효기간으로 서버 생성 시점 추정

`notBefore`는 인증서가 발급된 시각에 가깝다. 공인 CA(예: 90일 주기 자동 갱신)와 자체 서명(발급자 임의 설정, 종종 1~10년)의 패턴 차이도 참고 단서가 된다. 캡처 시각과 `notAfter`를 비교하면 "캡처 당시 이미 만료된 인증서를 쓰고 있었는가"도 확인할 수 있다 — 이는 클라이언트가 경고를 무시하고 접속했다는 뜻이므로 피싱/사용자 기만 시나리오에서 중요하다.

시간 비교는 반드시 UTC 기준으로 한다. X.509 `notBefore`/`notAfter`는 UTCTime 또는 GeneralizedTime으로 인코딩되며 표시값 자체가 UTC다. KST로 볼 때는 +9시간을 더한다.

### 5단계 — SNI와 인증서 도메인 일치 여부 확인

```text
1. tls.handshake.type == 1  에서 SNI 값 확보
2. tls.handshake.type == 11 에서 Subject CN 또는 SAN dNSName 값 확보
3. 두 값을 비교
```

일치하지 않으면 다음 중 하나다.

- 와일드카드 인증서(`*.example.com`)라 SNI(`sub.example.com`)와 문자열은 다르지만 유효한 경우
- SNI 위조(클라이언트가 실제 다른 서버에 접속하며 SNI만 위장) — 흔치 않지만 의심 시나리오에서 등장
- 인증서 자체가 해당 서비스와 무관(피싱 서버가 엉뚱한 인증서를 재사용)

## 출력 필드 해석

| 항목 | 의미 | 함정 |
| --- | --- | --- |
| Subject CN | 인증서가 보증하는 도메인/개체명 | SAN이 있으면 CN보다 SAN이 우선 적용 대상일 수 있다 |
| Issuer CN/O | 발급 기관 | 자체 서명이면 Subject와 동일 |
| notBefore/notAfter | 유효기간(UTC) | 캡처 시각과 비교할 때 시간대 변환 필수 |
| SAN(dNSName) | 인증서가 커버하는 모든 도메인 목록 | 여러 개일 수 있다. CN 하나만 보고 판단하면 놓친다 |
| Serial Number | 인증서 고유 식별자 | 여러 pcap에서 동일 값이면 같은 인증서(같은 서버) |

## pivot: 다음에 볼 artifact

| 인증서에서 얻은 것 | 다음에 볼 것 |
| --- | --- |
| Subject/SAN 도메인 | SNI 값([FOR-0177](./tls-sni.html))과 대조, DNS 질의 대조 |
| Issuer 정보(자체 서명 여부) | 다른 접속 시도와 함께 종합 판단(단독 근거로 쓰지 않는다) |
| notBefore(발급 시각) | 서버/인프라 구축 시점 추정, 사건 타임라인에 반영 |
| Serial Number/지문 | 다른 pcap이나 캡처 구간에서 동일 인증서 재사용 여부 확인 |
| Certificate 메시지가 안 보임(TLS 1.3) | SNI만으로 결론짓고, 필요하면 지문에 `SSLKEYLOGFILE` 제공 여부 확인 |

## 흔한 함정

- **TLS 1.3 캡처에서 Certificate가 안 보이는 것을 캡처 손상으로 오해하는 것.** 정상 동작이다. TLS 1.3은 Certificate 메시지 자체를 암호화한다. `tls.handshake.version`/ClientHello의 `supported_versions`로 먼저 버전을 확인한다.
- **자체 서명 인증서를 곧바로 "악성"으로 결론짓는 것.** 내부망 테스트 서버, IoT 장비도 흔히 자체 서명을 쓴다. 접속 맥락(반복 비콘, 의심스러운 SNI)과 함께 판단한다.
- **Subject CN만 보고 SAN을 안 보는 것.** 최신 인증서는 SAN이 실제 유효 범위이고 CN은 참고용으로만 남는 경우가 많다.
- **인증서가 여러 TCP 세그먼트에 걸쳐 재조립돼야 하는데 재조립 실패를 놓치는 것.** `tcp.analysis.lost_segment`가 있으면 Certificate 메시지가 불완전하게 보일 수 있다([FOR-0175](./tcp-retransmission.html)).
- **notBefore/notAfter를 로컬 시각으로 오인해 비교하는 것.** X.509 시각은 UTC다. KST 로그와 비교할 때 +9시간을 잊지 않는다.
- **leaf 인증서와 체인의 중간 CA 인증서를 혼동하는 것.** `Certificates (n items)`의 첫 번째가 서버(leaf) 인증서이고, 나머지는 대개 중간 CA다. 순서를 무시하고 아무 항목이나 보면 엉뚱한 Issuer를 보게 된다.
- **필드 경로 이름을 그대로 필터에 넣어 검색하려는 것.** X.509 ASN.1 트리의 서브필드는 패킷마다 펼쳐서 눈으로 읽는 것이 안전하다. 정확한 dissector 필드명은 Wireshark 버전에 따라 달라질 수 있으므로 실제 캡처에서 확인 후 `-T fields`에 사용한다.

## 교차검증

```bash
# 1) TLS 버전 먼저 확인 — 1.3이면 이 글의 대부분이 적용되지 않는다
tshark -r capture.pcapng -Y 'tls.handshake.type==1' -T fields -e tls.handshake.version

# 2) Certificate 메시지 존재 여부
tshark -r capture.pcapng -Y 'tls.handshake.type==11' -T fields -e frame.number

# 3) 상세 덤프에서 텍스트로 추출 (버전에 따라 필드명은 다를 수 있음)
tshark -r capture.pcapng -Y 'tls.handshake.type==11' -V | grep -iE 'commonName|notBefore|notAfter|dNSName'

# 4) SNI와 나란히 비교
tshark -r capture.pcapng -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name
```

GUI에서 패킷을 직접 펼쳐 눈으로 확인하는 것이 tshark 필드 경로를 추측하는 것보다 이 항목에서는 더 신뢰도가 높다.

## mini walkthrough

```text
문제:
"피싱 사이트로 의심되는 서버의 인증서 발급자와 자체 서명 여부를 확인하라."
첨부: phishing.pcapng

1. 첫 시도 (실패)
   필터: tls.handshake.type == 11
   결과: 0건.
   지문만 보고 "인증서가 없다"고 결론 내릴 뻔했다.

2. 원인 확인
   tshark -r phishing.pcapng -Y 'tls.handshake.type==1' -T fields -e tls.handshake.version
   결과: ClientHello의 supported_versions 확장에 TLS 1.3 존재.
   -> Certificate 메시지가 암호화되어 있어 애초에 파싱될 수 없는 상태였다.

3. 접근 변경 — SNI로 대체
   tls.handshake.type == 1
   Server Name: login-bank-verify.example-phish.net

4. 다른 캡처(TLS 1.2로 재현된 세션)에서 인증서 확인
   tls.handshake.type == 11 확장
     subject.commonName = login-bank-verify.example-phish.net
     issuer.commonName  = login-bank-verify.example-phish.net   <- Subject와 동일
     notBefore = 2026-03-10 00:00:00 UTC
     notAfter  = 2027-03-10 00:00:00 UTC

5. 판정
   Subject == Issuer -> 자체 서명.
   발급일이 캡처 시각(2026-03-14) 며칠 전 -> 공격 직전에 급조된 서버로 추정.

정답: 자체 서명 인증서, 발급 4일 전, Subject/Issuer CN 모두
login-bank-verify.example-phish.net
```

1단계처럼 TLS 1.3에서 Certificate 필터가 0건인 것은 실패가 아니라 정상이다. 버전을 먼저 확인하지 않으면 "인증서가 없는 서버"라는 잘못된 결론에 이른다.

## 막혔을 때 다음 체크

1. TLS 버전을 확인했는가 — 1.3이면 인증서를 못 보는 것이 정상이다
2. `tls.handshake.type == 11`이 0건인가 — 재조립 실패도 함께 의심(`tcp.analysis.lost_segment`)
3. Subject와 Issuer를 비교했는가 — 자체 서명 여부
4. SAN(dNSName) 전체 목록을 확인했는가 — CN 하나만 보지 않는다
5. notBefore/notAfter를 UTC로 캡처 시각과 비교했는가
6. SNI 값과 Subject/SAN이 일치하는가
7. 같은 인증서(Serial Number 등)가 다른 pcap/세션에도 나오는가 — 동일 인프라 증거

## 출처

- SRC-069 — RFC 8446 (TLS 1.3): Certificate 메시지가 핸드셰이크 트래픽 키로 암호화되는 범위, TLS 1.2와의 차이
- SRC-002 — Wireshark Display Filter Reference: `tls.handshake.type`, `tls.handshake.version` 필드명 확인
- SRC-003 — Wireshark User's Guide: 패킷 상세 창 탐색, Expand Subtrees 사용법
- X.509 ASN.1 서브필드(예: `x509sat.*`, `x509ce.dNSName` 등)의 정확한 tshark 필드 경로는 이 글에서 단정하지 않는다. Wireshark 버전에 따라 트리 구조와 필드명이 달라질 수 있으므로 실제 캡처에서 `-V` 상세 출력이나 GUI로 직접 확인할 것 — 이 이유로 이 글은 `status: draft`로 유지한다
