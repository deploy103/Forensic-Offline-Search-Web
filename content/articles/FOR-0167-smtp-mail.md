---
id: FOR-0167
title: "SMTP 메일 복원: imf로 .eml 추출하고 AUTH LOGIN 자격증명 디코딩"
slug: "smtp-mail"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "eml", "IMF"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["SMTP", "IMF", "POP3", "IMAP", "MIME"]
tools: ["Wireshark", "tshark", "Base64encoder", "strings", "file"]
commands: ["tshark -r capture.pcapng --export-objects imf,out_mail/", "tshark -r capture.pcapng -Y 'smtp.req.command' -T fields -e frame.number -e smtp.req.command -e smtp.req.parameter", "echo 'YmFja3VwX3N2Yw==' | base64 -d"]
regex_patterns: []
wireshark_filters: ["smtp", "smtp.data.fragment || imf", "smtp.req.command == \"AUTH\"", "smtp.req.command == \"MAIL\" || smtp.req.command == \"RCPT\"", "smtp.response.code == 235", "smtp.response.code == 535", "imf.subject contains \"invoice\"", "smtp.auth.username", "pop || imap"]
tshark_fields: ["smtp.req.command", "smtp.req.parameter", "smtp.response.code", "smtp.data.fragment", "smtp.auth.username", "smtp.auth.password", "imf.from", "imf.to", "imf.subject", "imf.date", "imf.message_id", "imf.return_path", "imf.received", "imf.ext.mailer", "imf.content.type", "imf.content.transfer_encoding"]
log_fields: ["Received", "Message-ID", "Return-Path", "X-Mailer"]
file_formats: ["eml", "pcap", "pcapng"]
primary_terms: ["SMTP 분석", "메일 내용 추출", "imf", "smtp 필터"]
keywords: ["SMTP", "imf", "Export Objects IMF", "eml 추출", "AUTH LOGIN", "Base64 자격증명", "MAIL FROM", "RCPT TO", "Received 헤더", "Message-ID", "MIME 첨부", "메일 헤더 분석", "POP3", "IMAP"]
aliases: ["smtp 필터", "메일 내용 보기", "eml 뽑기", "메일 첨부 파일 추출", "메일 비밀번호", "메일 보낸 사람 추적", "received 헤더 읽기"]
symptom_keywords: ["메일 본문을 보고 싶다", "첨부 파일을 꺼내고 싶다", "메일 계정과 비밀번호를 찾고 싶다", "메일을 실제로 누가 보냈는지 모르겠다", "Export Objects에 IMF가 없다", "base64 덩어리가 뭔지 모르겠다"]
related: ["FOR-0146", "FOR-0187", "FOR-0188"]
source_ids: ["SRC-070", "SRC-071", "SRC-002"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

메일 문제는 `smtp` 필터로 봉투(`MAIL FROM`/`RCPT TO`)와 인증(`AUTH LOGIN`의 Base64)을 읽고, `File > Export Objects > IMF`로 **본문 전체를 `.eml`로 통째로 꺼낸 뒤** `Received` 체인을 아래에서 위로 읽어 실제 발신 경로를 되짚는다.

## 어떤 문제에서 필요한가

- "메일 본문", "첨부 파일", "보낸 사람"을 답하라는 문제
- Protocol Hierarchy에 `Simple Mail Transfer Protocol` 또는 `Internet Message Format`이 보이는 pcap
- 피싱/사칭 메일의 **진짜** 발신 IP를 찾는 문제 — `From`은 위조되고 `Received`는 어렵다
- 메일 계정 자격증명 문제 — `AUTH LOGIN`은 암호화가 아니라 **Base64 인코딩**일 뿐이다
- 첨부로 반출된 자료(`.zip`, `.xlsx`, `.exe`)를 복원하는 문제

## 문제에서 처음 볼 단서

1. **포트 25 / 587 / 465** — 25는 서버 간 릴레이, 587은 제출(submission), 465는 암시적 TLS(내용 못 봄)
2. **`Info` 컬럼의 `C: MAIL FROM` / `C: RCPT TO` / `C: DATA`** — 봉투 정보가 바로 보인다
3. **`334`로 시작하는 서버 응답 두 개** — `AUTH LOGIN` 진행 중이라는 뜻. 다음 두 패킷이 계정과 비밀번호다
4. **`Internet Message Format` 프로토콜 행** — Wireshark가 메일 본문을 재조립했다는 확실한 신호
5. **`STARTTLS` 명령의 존재** — `220` 응답 이후는 암호화된다. 그 전까지가 전부다

## 30초 절차

```text
smtp.data.fragment || imf
```

이 한 줄로 본문이 실린 패킷만 남는다. 이어서:

```text
smtp.req.command == "MAIL" || smtp.req.command == "RCPT"
smtp.req.command == "AUTH"
imf.subject
```

메일 원문을 파일로 꺼낸다.

```text
File > Export Objects > IMF...   ->  Save All  ->  *.eml
```

CLI 동등물:

```bash
tshark -r capture.pcapng --export-objects imf,out_mail/ && ls -l out_mail/
```

## 상세 절차

### 1단계 — 명령 흐름 읽기

`smtp` 필터를 걸고 아무 패킷에서 `Follow > TCP Stream`을 한다. 세션 전체가 한 화면에 나온다.

```text
220 mail.corp.example smtp ready
EHLO attacker-pc
250-mail.corp.example
250-AUTH LOGIN PLAIN
250-STARTTLS
250 8BITMIME
AUTH LOGIN
334 VXNlcm5hbWU6
YmFja3VwX3N2Yw==
334 UGFzc3dvcmQ6
V2ludDNyITIwMjY=
235 2.7.0 Authentication successful
MAIL FROM:<ceo@corp.example>
250 2.1.0 Ok
RCPT TO:<external@mail.attacker.test>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
... (헤더 + 본문 + 첨부) ...
.
250 2.0.0 Ok: queued as 4A9C21E3F
QUIT
221 2.0.0 Bye
```

| 명령 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| `HELO` / `EHLO` | 클라이언트 자기소개 | **인자가 공격자 호스트명/도메인.** 위조 가능하지만 실수로 실제 PC 이름이 남는다 |
| `AUTH LOGIN` | 2단계 Base64 인증 | 다음 두 클라이언트 패킷이 계정, 비밀번호 |
| `AUTH PLAIN` | 1단계 Base64 인증 | 한 덩어리에 `\0user\0pass`가 들어 있다 |
| `MAIL FROM` | **봉투 발신자** (envelope sender) | 헤더 `From`과 다르면 사칭 신호. 반송 주소로 쓰인다 |
| `RCPT TO` | **봉투 수신자** | 여러 번 반복된다. 실제 배달 대상. `Bcc`는 여기에만 나타난다 |
| `DATA` | 본문 전송 시작 | `354` 응답 이후부터 `.` 한 줄까지가 메일 원문 |
| `RSET` | 세션 초기화 | 스팸 봇이 한 연결로 여러 메일 보낼 때 반복 |
| `VRFY` / `EXPN` | 계정 존재 확인 / 목록 확장 | **계정 열거(정찰).** 연속 `VRFY`는 스캔이다 |
| `STARTTLS` | 평문 세션을 TLS로 승격 | 이 뒤는 복호화 없이는 못 본다 |
| `QUIT` | 종료 | 세션 경계 |

### 2단계 — 응답 코드

| 코드 | 의미 | 판정 |
| --- | --- | --- |
| `220` | Service ready / STARTTLS 수락 | 세션 시작 또는 암호화 전환 |
| `250` | Requested action okay | 각 명령의 정상 처리 |
| `251` | User not local; will forward | 릴레이. 최종 목적지가 다른 곳 |
| `354` | Start mail input | 본문 전송 개시 신호 |
| `334` | Server challenge (Base64) | **AUTH 진행 중.** 다음 클라이언트 패킷을 디코딩한다 |
| `235` | Authentication successful | **인증 성공** |
| `535` | Authentication credentials invalid | **인증 실패.** 연속 535 = 무차별 대입 |
| `421` | Service not available, closing | 서버가 끊음. 전송 제한 또는 차단 |
| `450` / `451` | 임시 실패 | 재시도가 이어진다 |
| `550` | No such user / 정책 거부 | **주소 열거의 결과.** 550과 250이 섞이면 유효 계정을 걸러낸 것 |
| `552` | 용량 초과 | 대용량 첨부 반출 실패 |
| `554` | Transaction failed | 스팸 필터 차단 |

`RCPT TO`에 대해 `250`과 `550`이 번갈아 나오면, 공격자가 **유효한 사내 메일 주소 목록을 만들어낸 것**이다. `250`을 받은 주소가 그 결과물이다.

### 3단계 — AUTH의 Base64를 디코딩한다

`AUTH LOGIN`은 암호화가 아니다. 서버가 `334`로 프롬프트를 Base64로 보내고, 클라이언트가 값을 Base64로 답한다.

| 와이어 상의 값 | 디코딩 결과 |
| --- | --- |
| `334 VXNlcm5hbWU6` | `Username:` (서버 프롬프트) |
| `YmFja3VwX3N2Yw==` | `backup_svc` (계정) |
| `334 UGFzc3dvcmQ6` | `Password:` (서버 프롬프트) |
| `V2ludDNyITIwMjY=` | `Wint3r!2026` (비밀번호) |

```bash
echo 'YmFja3VwX3N2Yw==' | base64 -d ; echo
echo 'V2ludDNyITIwMjY=' | base64 -d ; echo
```

`334 VXNlcm5hbWU6` 와 `334 UGFzc3dvcmQ6` 는 고정 문자열이다. **이 두 값을 보면 그 뒤 두 줄이 자격증명이라는 것을 즉시 안다.**

`AUTH PLAIN`은 한 줄에 몰아넣는다. 구분자가 널 바이트(`0x00`)이므로 그대로 출력하면 붙어 보인다.

```bash
echo 'AGJhY2t1cF9zdmMAV2ludDNyITIwMjY=' | base64 -d | tr '\0' '\n'
```

```text
(빈 줄 = authzid)
backup_svc
Wint3r!2026
```

Wireshark는 이 값을 미리 파싱해 별도 필드로도 제공한다. 손으로 디코딩하기 전에 먼저 이것을 시도한다.

```bash
tshark -r capture.pcapng -Y 'smtp.auth.username || smtp.auth.password' \
  -T fields -e frame.number -e smtp.auth.username -e smtp.auth.password
```

### 4단계 — Export Objects > IMF로 메일 원문 확보

`DATA` 이후 본문은 여러 TCP 세그먼트에 쪼개져 있다. 손으로 이어붙이지 않는다.

```text
File > Export Objects > IMF...
  Packet   Hostname             Content Type       Size      Filename
  418      mail.corp.example    message/rfc822     284 kB    (no subject).eml
```

`Save All`로 `.eml`을 꺼내면 헤더·본문·첨부가 원본 그대로 들어 있다. `.eml`은 텍스트 파일이므로 어떤 편집기로도 열린다.

```bash
tshark -r capture.pcapng --export-objects imf,out_mail/
ls -l out_mail/
file out_mail/*
head -40 out_mail/*.eml
```

### 5단계 — 메일 헤더 해부: 진짜 발신 경로

`.eml`의 헤더가 이 문제의 핵심이다. **`From`은 누구나 아무 값으로 쓸 수 있다. `Received`는 각 서버가 자기가 받은 사실을 위에 덧붙인 것이므로 위조가 어렵다.**

```text
Received: from mail.corp.example (mail.corp.example [198.51.100.20])
        by mx.external.test with ESMTP id 7F2A1
        for <external@mail.attacker.test>; Sat, 14 Mar 2026 07:15:09 +0000
Received: from attacker-pc (unknown [203.0.113.77])
        by mail.corp.example with ESMTPA id 4A9C21E3F
        for <external@mail.attacker.test>; Sat, 14 Mar 2026 07:15:02 +0000
Return-Path: <backup_svc@corp.example>
From: "CEO" <ceo@corp.example>
To: external@mail.attacker.test
Subject: Q1 salary table
Date: Sat, 14 Mar 2026 07:15:01 +0000
Message-ID: <20260314071501.4A9C21E3F@mail.corp.example>
X-Mailer: swaks v20240103.0
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_b0undary_9911"
```

| 헤더 | 무엇을 알려주는가 | 함정 |
| --- | --- | --- |
| `Received` | 경유한 서버와 시각. **아래에서 위로 = 오래된 것에서 새것으로** | 가장 아래 항목이 최초 투입 지점. 그 괄호 안 IP가 실제 발신 IP |
| `From` | 표시용 발신자 | **완전히 위조 가능.** 이것만 보고 답하면 틀린다 |
| `Return-Path` | 봉투 발신자(`MAIL FROM`)를 기록 | `From`과 다르면 사칭 확정 신호 |
| `To` / `Cc` | 표시용 수신자 | `Bcc`는 헤더에 없다. `RCPT TO`에만 나온다 |
| `Message-ID` | 발신 서버가 부여한 유일 ID | 도메인 부분이 실제 발신 서버. 큐 ID(`4A9C21E3F`)가 서버 로그와 연결된다 |
| `Date` | 작성 시각과 오프셋 | `+0000`은 UTC. KST는 `+0900`. 오프셋을 무시하면 9시간 틀린다 |
| `X-Mailer` / `User-Agent` | 발신 클라이언트 | Outlook이 아니라 스크립트 도구 이름이면 자동 발송 |
| `Authentication-Results` | SPF/DKIM/DMARC 판정 | `spf=fail`, `dmarc=fail`이 사칭의 기계적 증거 |
| `Content-Type` | 본문 구조와 `boundary` | `multipart/mixed`면 첨부가 있다 |

위 예시의 결론: `From`은 `ceo@corp.example`이지만, `Return-Path`는 `backup_svc@corp.example`이고 가장 아래 `Received`의 실제 접속 IP는 `203.0.113.77`이다. **탈취된 `backup_svc` 계정으로 CEO를 사칭한 메일이다.**

`Received` 시각 차이(`07:15:02` → `07:15:09`)는 릴레이 지연이다. 수 시간 차이가 나면 큐에 머문 것이고, 순서가 역전되어 있으면 헤더가 조작된 것이다.

```bash
# 헤더만 필드로 추출해 한 표로
tshark -r capture.pcapng -Y 'imf' \
  -T fields -e frame.number -e imf.from -e imf.to -e imf.subject \
  -e imf.date -e imf.message_id -e imf.return_path -E header=y

# Received 체인만 (한 메일에 여러 개가 나오므로 -E occurrence=a)
tshark -r capture.pcapng -Y 'imf' -T fields -e imf.received -E occurrence=a
```

### 6단계 — MIME 첨부 복원

`Content-Type: multipart/mixed; boundary="=_b0undary_9911"` 이면, 본문은 `--=_b0undary_9911` 로 구분된 파트들이다.

```text
--=_b0undary_9911
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

Attached is the file you requested.

--=_b0undary_9911
Content-Type: application/zip; name="salary_2026Q1.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="salary_2026Q1.zip"

UEsDBBQAAAAIAJZ1c1ihWlV3TgAAAG0AAAAQAAAAc2FsYXJ5X3ExLnhsc3g=
...
--=_b0undary_9911--
```

`Content-Transfer-Encoding: base64` 파트를 잘라 디코딩하면 원본 파일이 된다.

```bash
# .eml 에서 base64 파트만 잘라 디코딩
sed -n '/^Content-Transfer-Encoding: base64/,/^--=_b0undary_9911--/p' out_mail/mail.eml \
  | sed '1,/^$/d' | sed '/^--/d' | tr -d '\r\n' | base64 -d > attach.zip
file attach.zip
```

Wireshark GUI에서는 더 쉽다. 패킷 상세창의 `MIME Multipart Media Encapsulation` 아래 각 파트에서 **`Media Type` 노드 우클릭 > `Export Packet Bytes...`** 로 디코딩된 바이트를 그대로 저장할 수 있다. `Content-Transfer-Encoding: base64`인 파트는 Wireshark가 이미 디코딩해 보여준다.

추출한 파일은 `file`과 `strings`로 검증한다 ([FOR-0001](./30sec-triage.html)). 확장자가 `.zip`인데 실제로는 PE 실행 파일인 경우가 흔하다.

### 7단계 — POP3 / IMAP: 받는 쪽도 평문이다

메일 수신 프로토콜도 TLS 없이 쓰면 전부 평문이다.

| 프로토콜 | 표시 필터 | 포트 | 자격증명 위치 |
| --- | --- | --- | --- |
| POP3 | **`pop`** (`pop3`이 아니다) | 110 (995=TLS) | `USER` / `PASS` 명령의 인자 |
| IMAP | `imap` | 143 (993=TLS) | `LOGIN` 명령의 인자 |

```text
pop
pop.request.command == "RETR"
imap.request.username || imap.request.password
```

POP3 세션 예시:

```text
+OK POP3 server ready
USER backup_svc
+OK
PASS Wint3r!2026
+OK Logged in.
LIST
+OK 2 messages
RETR 1
+OK 284310 octets
... (메일 원문) ...
QUIT
```

| 필드 | 내용 |
| --- | --- |
| `pop.request.command` | `USER` `PASS` `STAT` `LIST` `UIDL` `RETR` `DELE` `TOP` `QUIT` |
| `pop.request.parameter` | 명령 인자. `PASS`의 인자가 **평문 비밀번호** |
| `pop.response.indicator` | `+OK` 또는 `-ERR`. 인증 성공/실패 판정 |
| `pop.response.description` | 응답 설명 텍스트 |
| `imap.request.command` | `LOGIN` `SELECT` `FETCH` `SEARCH` `STORE` |
| `imap.request.username` / `imap.request.password` | Wireshark가 `LOGIN`에서 파싱한 값 |
| `imap.request.folder` | 접근한 메일함 이름 |

`RETR`로 내려온 메일 본문은 SMTP와 같은 RFC 5322 형식이므로, `Follow > TCP Stream`으로 그대로 읽거나 `Raw` 저장 후 `.eml`로 이름을 바꿔 열면 된다.

## 출력 필드 해석

| 필드 | 타입 | 주의 |
| --- | --- | --- |
| `smtp.req.command` | 문자열 | `req`다. `smtp.request.command`는 없다 |
| `smtp.req.parameter` | 문자열 | `MAIL FROM:<...>`의 `<...>` 부분 |
| `smtp.response.code` | 정수 | 여기는 `response`다. 요청은 `req`, 응답은 `response`로 비대칭이니 외운다 |
| `smtp.data.fragment` | 프레임 참조 | 본문이 실린 세그먼트. 재조립 전 조각 |
| `smtp.command_line` | 문자열 | 명령 한 줄 전체(명령+인자) |
| `smtp.auth.username` / `smtp.auth.password` | 문자열 | Wireshark가 Base64를 **이미 디코딩한** 값 |
| `imf` | 프로토콜 | 재조립 완료된 메일 원문이 있는 프레임 |
| `imf.from` / `imf.to` / `imf.subject` / `imf.date` | 문자열 | 헤더 원문 그대로 |
| `imf.message_id` | 문자열 | 서버 큐 ID 추출용 |
| `imf.return_path` | 문자열 | `From`과 비교해 사칭 판정 |
| `imf.received` | 문자열 | 한 메일에 여러 개. `-E occurrence=a`로 전부 뽑는다 |
| `imf.ext.mailer` | 문자열 | `X-Mailer` 헤더 |
| `imf.content.type` / `imf.content.transfer_encoding` | 문자열 | 첨부 존재와 인코딩 방식 |

## pivot: 다음에 볼 artifact

| SMTP/IMF에서 얻은 값 | 다음에 볼 것 |
| --- | --- |
| `AUTH` 계정/비밀번호 | EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) — 같은 계정의 OS 로그온 |
| 가장 아래 `Received`의 IP | 방화벽/웹 로그, 그 IP의 다른 트래픽 (`ip.addr == ...`) |
| `Message-ID`의 큐 ID | 메일 서버 로그(Postfix/Exchange) — 배달 결과 확인 |
| 첨부 파일명 | 수신 측 디스크 `$MFT` ([FOR-0021](./mft-basics.html)), 첨부 임시 폴더 |
| 추출한 실행 파일 해시 | Amcache/Prefetch, 실행 이벤트 4688 ([FOR-0088](./event-4688-process-creation.html)) |
| `RCPT TO`의 250 응답 목록 | 조직 계정 목록. 후속 피싱 대상 예측 |
| `EHLO` 인자의 호스트명 | 레지스트리 ComputerName, DHCP `option 12` |
| `Date` / `Received` 시각 | 그 시각 ±5분의 전체 타임라인. `+0000` → KST +9 |

## 흔한 함정

- **`smtp.request.command`라고 쓰는 것.** 존재하지 않는 필드다. 요청은 `smtp.req.command`, 응답은 `smtp.response.code`로 접두어가 비대칭이다. 필터 오타는 조용히 0건을 반환하므로 "SMTP가 없다"고 오판하게 만든다.
- **`pop3`로 필터를 거는 것.** POP3의 Wireshark 프로토콜 약칭은 **`pop`**이다. `pop3`는 유효한 필드가 아니다.
- **`From` 헤더를 발신자로 답하는 것.** 완전히 위조 가능하다. `Return-Path`(= `MAIL FROM`)와 가장 아래 `Received`의 IP가 실제 출처다.
- **`Received` 체인을 위에서 아래로 읽는 것.** 각 서버가 자기 항목을 **맨 위에 추가**한다. 최초 투입 지점은 **가장 아래**다. 순서를 뒤집으면 최종 수신 서버를 공격자로 지목하게 된다.
- **`AUTH LOGIN`을 암호화로 착각하는 것.** Base64는 인코딩일 뿐이다. `334` 응답 뒤의 두 줄을 `base64 -d`하면 끝난다. 반대로 `AUTH PLAIN`의 널 구분자를 모르면 계정과 비밀번호가 붙어 보인다.
- **`Bcc`를 헤더에서 찾는 것.** `Bcc` 수신자는 헤더에 남지 않는다. `smtp.req.command == "RCPT"`의 인자 목록에만 나타난다. 헤더 `To`/`Cc`에 없는 `RCPT TO`가 숨은 수신자다.
- **`Date` 헤더의 오프셋을 무시하는 것.** `+0000`은 UTC이고 KST는 `+0900`이다. 또한 `Date`는 클라이언트가 쓰는 값이라 조작 가능하다. 신뢰도는 `Received` 시각이 더 높다.
- **Export Objects > IMF에 항목이 없다고 본문을 포기하는 것.** `DATA` 재조립이 실패했거나(`Analyze > Expert Information`의 재전송/누락), 캡처가 중간부터 시작된 경우다. `Follow > TCP Stream` → `Raw` 저장 → 확장자를 `.eml`로 바꾼다.
- **`STARTTLS` 이후를 보려고 시간 낭비하는 것.** `220` 응답 뒤부터 암호화된다. 그 이전의 `EHLO` 응답, 서버 배너, IP만 남는다. 465 포트(암시적 TLS)는 처음부터 아무것도 안 보인다.
- **첨부의 Base64를 줄바꿈째로 디코딩하는 것.** MIME base64는 76자마다 줄바꿈이 들어간다. `tr -d '\r\n'`으로 제거하고 디코딩해야 한다. `boundary` 종료선(`--boundary--`)까지 포함하면 뒤가 깨진다.
- **`multipart` 경계 문자열을 하드코딩하는 것.** `boundary` 값은 메일마다 다르다. `Content-Type` 헤더에서 실제 값을 읽어서 쓴다.
- **여러 메일을 한 세션으로 뭉쳐 읽는 것.** 한 TCP 연결에 `RSET` 후 여러 통이 흐를 수 있다. `MAIL FROM` 개수만큼 메일이 있다.

## 교차검증

```bash
# 1) 명령 흐름 전체
tshark -r capture.pcapng -Y 'smtp.req' \
  -T fields -e frame.number -e ip.src -e smtp.req.command -e smtp.req.parameter -E header=y

# 2) 봉투 정보만 — 실제 발신/수신
tshark -r capture.pcapng -Y 'smtp.req.command in {"MAIL","RCPT"}' \
  -T fields -e tcp.stream -e smtp.req.command -e smtp.req.parameter

# 3) 인증 결과 집계 — 535 다수면 무차별 대입
tshark -r capture.pcapng -Y 'smtp.response.code in {235,535}' \
  -T fields -e smtp.response.code | sort | uniq -c

# 4) Wireshark가 디코딩한 자격증명
tshark -r capture.pcapng -Y 'smtp.auth.username || smtp.auth.password' \
  -T fields -e smtp.auth.username -e smtp.auth.password

# 5) 메일 헤더 요약표
tshark -r capture.pcapng -Y 'imf' \
  -T fields -e imf.from -e imf.return_path -e imf.to -e imf.subject -e imf.date \
  -e imf.message_id -e imf.ext.mailer -E header=y

# 6) Received 체인 전부
tshark -r capture.pcapng -Y 'imf' -T fields -e imf.received -E occurrence=a

# 7) 메일 원문 파일로
tshark -r capture.pcapng --export-objects imf,out_mail/ && file out_mail/*

# 8) POP3/IMAP 자격증명
tshark -r capture.pcapng -Y 'pop.request.command in {"USER","PASS"}' \
  -T fields -e pop.request.command -e pop.request.parameter
tshark -r capture.pcapng -Y 'imap.request.username || imap.request.password' \
  -T fields -e imap.request.username -e imap.request.password

# 9) 파서 우회
strings -n 8 capture.pcapng | grep -Ei 'MAIL FROM|RCPT TO|X-Mailer|Message-ID'
```

## mini walkthrough

```text
문제:
"사내 계정이 탈취되어 급여 자료가 외부로 메일 발송되었다.
 (1) 첨부 파일 안의 flag, (2) 실제 발송에 사용된 계정과 비밀번호,
 (3) 메일을 보낸 실제 IP 를 답하시오."
첨부: mail_case.pcapng (2,104 packets, 640 KB)

1. Protocol Hierarchy
   TCP 98.7%  |  Simple Mail Transfer Protocol 12.4%
   |  Internet Message Format 0.1% (1 packet, 284 kB)
   -> IMF 가 재조립되어 있다. 본문 확보는 확정.

2. 첫 시도 (실패):
   필터: smtp.request.command == "MAIL"
   -> Wireshark 필터 입력줄이 빨갛게 변하며
      "smtp.request.command" is not a valid protocol or field name

   원인: SMTP 요청 필드의 접두어는 request 가 아니라 req 다.
        (응답은 smtp.response.code 로 request 계열인데 요청만 req 라
         비대칭이다.)

   교훈: 필터가 빨간색이면 문법 오류다. 빨간 줄을 무시하고 엔터를 치면
        직전 필터 결과가 그대로 남아 "결과 0건"으로 오해한다.

3. 필터 수정: smtp.req.command == "MAIL" || smtp.req.command == "RCPT"
     MAIL   FROM:<ceo@corp.example>
     RCPT   TO:<external@mail.attacker.test>
     RCPT   TO:<archive@mail.attacker.test>     <- 헤더 To 에 없다 = Bcc

4. 인증 구간
   필터: smtp.req.command == "AUTH" || smtp.response.code == 334
   Follow > TCP Stream:
     AUTH LOGIN
     334 VXNlcm5hbWU6          -> base64 "Username:"
     YmFja3VwX3N2Yw==
     334 UGFzc3dvcmQ6          -> base64 "Password:"
     V2ludDNyITIwMjY=
     235 2.7.0 Authentication successful

   $ echo 'YmFja3VwX3N2Yw==' | base64 -d ; echo
   backup_svc
   $ echo 'V2ludDNyITIwMjY=' | base64 -d ; echo
   Wint3r!2026

   -> (2) 해결: backup_svc / Wint3r!2026
      From 은 ceo@corp.example 인데 인증 계정은 backup_svc.
      즉 CEO 사칭이다.

5. 메일 원문
   File > Export Objects > IMF... > Save All  ->  out_mail/
   $ head -20 out_mail/*.eml
     Received: from mail.corp.example (mail.corp.example [198.51.100.20])
             by mx.external.test ...; Sat, 14 Mar 2026 07:15:09 +0000
     Received: from attacker-pc (unknown [203.0.113.77])
             by mail.corp.example with ESMTPA ...; Sat, 14 Mar 2026 07:15:02 +0000
     Return-Path: <backup_svc@corp.example>
     From: "CEO" <ceo@corp.example>
     X-Mailer: swaks v20240103.0
     Content-Type: multipart/mixed; boundary="=_b0undary_9911"

   Received 를 아래에서 위로: attacker-pc [203.0.113.77]
     -> mail.corp.example -> mx.external.test
   -> (3) 해결: 203.0.113.77
      X-Mailer 가 Outlook 이 아니라 커맨드라인 메일 발송 도구다 = 자동 발송.

6. 첨부 복원
   Content-Disposition: attachment; filename="salary_2026Q1.zip"
   Content-Transfer-Encoding: base64

   패킷 상세창 > MIME Multipart Media Encapsulation > 두 번째 파트 >
   Media Type 우클릭 > Export Packet Bytes... > salary.zip

   $ file salary.zip
   salary.zip: Zip archive data, at least v2.0 to extract
   $ unzip -o salary.zip && strings salary_q1.xlsx | grep -i 'flag{'
   flag{r3c31v3d_ch41n_b0tt0m_up}

7. 시간 정리
   최초 투입 07:15:02 +0000 (UTC) = 2026-03-14 16:15:02 KST
   릴레이 지연 7초. 헤더 순서 역전 없음 = 조작 흔적 없음.

정답:
 (1) flag{r3c31v3d_ch41n_b0tt0m_up}
 (2) backup_svc / Wint3r!2026
 (3) 203.0.113.77
```

2단계의 실패가 이 글의 이유다. **`smtp.req`와 `smtp.response`의 비대칭을 모르면 SMTP 문제를 열고도 "데이터가 없다"고 결론낸다.** 필터 입력줄이 초록이 아니면 결과를 믿지 않는다.

## 막혔을 때 다음 체크

1. 필터 입력줄이 **초록색**인가 — 빨간색이면 문법 오류이고 결과는 직전 것이다
2. `smtp.req.command`인가 `smtp.request.command`인가 — 후자는 없다
3. `smtp.data.fragment || imf`로 본문 패킷을 찾았는가
4. `File > Export Objects > IMF`를 시도했는가 — 없으면 `Follow > Raw` → `.eml`
5. `smtp.response.code == 334`가 있는가 — 있으면 다음 두 줄이 자격증명
6. `smtp.auth.username` / `smtp.auth.password`를 먼저 시도했는가 — 손 디코딩 전에
7. `Return-Path`와 `From`이 다른가 — 사칭 판정
8. `Received`를 **아래에서 위로** 읽었는가
9. `RCPT TO` 목록과 헤더 `To`/`Cc`를 비교했는가 — 차이가 `Bcc`
10. `Content-Type`에 `multipart`가 있는가 — 있으면 첨부 존재
11. 첨부 Base64에서 줄바꿈과 종료 경계선을 제거했는가
12. `STARTTLS`/`465`인가 — 그러면 본문은 없다. 봉투와 IP로 승부
13. 추출한 `.eml`과 첨부에 `file`/`strings`를 돌렸는가
14. `pop` / `imap`도 확인했는가 — 수신 쪽에도 평문 자격증명이 있다

## 출처

- SRC-070 — RFC 959 / RFC 5321 (SMTP): `EHLO` `MAIL FROM` `RCPT TO` `DATA` `RSET` `VRFY` `QUIT` 명령 정의, 3자리 응답 코드 체계(`220` `250` `354` `421` `450` `550` `554`), 봉투(envelope)와 헤더의 구분
- SRC-071 — RFC 5322 (Internet Message Format) / RFC 2045 (MIME): 헤더 필드 정의(`From` `To` `Cc` `Bcc` `Return-Path` `Received` `Message-ID` `Date`), `Received` 체인이 위로 누적된다는 규칙, `Content-Type: multipart` 의 `boundary` 문법, `Content-Transfer-Encoding: base64`, `Content-Disposition: attachment; filename=`
- SRC-002 — Wireshark Display Filter Reference: `smtp` 항목에서 `smtp.req.command` `smtp.req.parameter` `smtp.response.code` `smtp.data.fragment` `smtp.command_line` `smtp.auth.username` `smtp.auth.password` 확인, `imf` 항목에서 `imf.from` `imf.to` `imf.subject` `imf.date` `imf.message_id` `imf.return_path` `imf.received` `imf.ext.mailer` `imf.content.type` `imf.content.transfer_encoding` 확인, POP3의 프로토콜 약칭이 `pop`이며 `pop.request.command` `pop.request.parameter` `pop.response.indicator` `pop.response.description` 임을 확인, IMAP의 `imap.request.command` `imap.request.username` `imap.request.password` `imap.request.folder` 확인
- `AUTH LOGIN` 의 `334 VXNlcm5hbWU6` / `334 UGFzc3dvcmQ6` 는 널리 쓰이는 서버 프롬프트이지만 문자열 자체는 서버 구현이 정하는 값이므로, 실제 캡처에서 `334` 응답 본문을 직접 디코딩해 확인할 것
- `Export Objects` 의 `IMF` 항목명과 `Export Packet Bytes` 메뉴 위치는 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
