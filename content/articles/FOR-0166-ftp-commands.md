---
id: FOR-0166
title: "FTP 명령과 파일 전송 추적: ftp.request.command로 STOR/RETR 잡기"
slug: "ftp-commands"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "ftp-data"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["FTP", "FTP-DATA", "TCP"]
tools: ["Wireshark", "tshark", "HxD", "file", "strings"]
commands: ["tshark -r capture.pcapng -Y 'ftp.request' -T fields -e frame.number -e ip.src -e ftp.request.command -e ftp.request.arg", "tshark -r capture.pcapng --export-objects ftp-data,out_ftp/", "tshark -r capture.pcapng -q -z conv,tcp"]
regex_patterns: []
wireshark_filters: ["ftp || ftp-data", "ftp.request.command == \"STOR\" || ftp.request.command == \"RETR\"", "ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"", "ftp.response.code == 230", "ftp.response.code == 530", "ftp.response.code == 227", "ftp.response.code == 226", "ftp-data", "ftp.request.command == \"DELE\""]
tshark_fields: ["ftp.request.command", "ftp.request.arg", "ftp.response.code", "ftp.response.arg", "ftp.passive.ip", "ftp.passive.port", "ftp.active.cip", "ftp.active.port", "ftp-data.setup-frame", "ftp-data.command", "ftp.command-response.bytes"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["FTP 분석", "ftp.request.command", "STOR RETR", "ftp 파일 전송"]
keywords: ["FTP", "ftp.request.command", "STOR", "RETR", "ftp-data", "PASV", "PORT", "평문 자격증명", "FTP 응답 코드", "파일 전송 추적", "Export Objects FTP-DATA", "액티브 패시브 모드"]
aliases: ["ftp 필터", "ftp 파일 전송", "ftp 아이디 비밀번호", "ftp 업로드 찾기", "ftp 다운로드 찾기", "패시브 모드 포트", "ftp-data 안 잡힘"]
symptom_keywords: ["FTP로 어떤 파일이 전송됐는지 모르겠다", "Export Objects FTP-DATA가 비어 있다", "ftp 계정과 비밀번호를 찾고 싶다", "업로드인지 다운로드인지 헷갈린다", "데이터 채널 포트를 모르겠다", "전송이 완료됐는지 알고 싶다"]
related: ["FOR-0146", "FOR-0187", "FOR-0189"]
source_ids: ["SRC-070", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

FTP는 **제어 채널(`ftp`, 21번)과 데이터 채널(`ftp-data`)이 분리된 프로토콜**이므로, 먼저 `ftp` 필터로 `ftp.request.command`의 `USER`/`PASS`/`STOR`/`RETR` 흐름을 읽어 "누가 무엇을 주고받았는가"를 확정하고, 그 다음에 데이터 채널을 찾아 파일 본문을 꺼낸다.

## 어떤 문제에서 필요한가

- "유출된 파일 이름", "업로드된 웹셸", "가져간 자료"를 찾아야 하는 문제
- Protocol Hierarchy에 `File Transfer Protocol` 또는 `FTP Data`가 보이는 pcap
- "계정과 비밀번호를 구하라"는 자격증명 문제 — FTP는 **전부 평문**이다
- 증거 인멸(`DELE`)이나 파일명 위장(`RNFR`/`RNTO`) 흔적을 찾는 문제

FTP 문제는 대개 두 단계다. **제어 채널에서 파일명을 얻고, 데이터 채널에서 파일을 얻는다.** 한쪽만 보면 반쪽이다.

## 문제에서 처음 볼 단서

1. **`Info` 컬럼에 대문자 4글자 명령** — `USER`, `RETR`, `STOR`가 그냥 보인다
2. **포트 21과 포트 20** — 21은 제어, 20은 액티브 모드의 서버측 데이터 포트
3. **Protocol Hierarchy의 `FTP Data` 바이트 수** — 여기가 크면 실제 파일이 흘렀다
4. **`Protocol` 컬럼이 `TCP`뿐인 큰 대화** — 패시브 모드 데이터 채널이 미인식된 상태다
5. **220 배너 문자열** — `220 (vsFTPd 3.0.3)` 처럼 서버 소프트웨어와 버전이 노출된다

## 30초 절차

```text
ftp.request.command == "STOR" || ftp.request.command == "RETR"
```

이 한 줄이 "무슨 파일이 오갔는가"를 즉시 답한다. 이어서 세 줄만 더 본다.

```text
ftp.request.command == "USER" || ftp.request.command == "PASS"
ftp.response.code == 227 || ftp.response.code == 200
ftp.response.code == 226
```

순서대로 **자격증명 → 데이터 채널 포트 → 전송 완료 여부**다.

CLI로 제어 채널 전체를 한 표에:

```bash
tshark -r capture.pcapng -Y 'ftp.request' \
  -T fields -e frame.number -e ip.src -e ftp.request.command -e ftp.request.arg -E header=y
```

파일 추출:

```bash
tshark -r capture.pcapng --export-objects ftp-data,out_ftp/ && file out_ftp/*
```

## 상세 절차

### 1단계 — 제어 채널 전문 읽기

`ftp` 필터를 걸고 아무 패킷에서 `Follow > TCP Stream`을 하면 세션 전체가 대화 형태로 보인다.

```text
220 (vsFTPd 3.0.3)
USER backup_svc
331 Please specify the password.
PASS Wint3r!2026
230 Login successful.
SYST
215 UNIX Type: L8
PWD
257 "/home/backup_svc" is the current directory
TYPE I
200 Switching to Binary mode.
PASV
227 Entering Passive Mode (203,0,113,77,195,80).
LIST
150 Here comes the directory listing.
226 Directory send OK.
CWD /home/backup_svc/reports
250 Directory successfully changed.
SIZE internal_report.pdf
213 2317540
MDTM internal_report.pdf
213 20260314071502
PASV
227 Entering Passive Mode (203,0,113,77,195,81).
RETR internal_report.pdf
150 Opening BINARY mode data connection for internal_report.pdf (2317540 bytes).
226 Transfer complete.
STOR notes.txt
150 Ok to send data.
226 Transfer complete.
DELE audit_trail.log
250 Delete operation successful.
QUIT
221 Goodbye.
```

이 한 화면에 계정, 비밀번호, 작업 디렉터리, 전송 모드, 데이터 포트, 가져간 파일, 올린 파일, 지운 파일이 전부 있다.

### 2단계 — 명령별 포렌식 의미

| 명령 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| `USER` | 로그인 계정 | **평문 계정명.** 다른 로그의 사용자와 대조 |
| `PASS` | 비밀번호 | **평문 비밀번호.** 재사용 여부가 다음 단서 |
| `PWD` | 현재 디렉터리 조회 | 257 응답에 절대 경로 → 서버 디렉터리 구조 |
| `CWD` | 디렉터리 이동 | 공격자가 관심 있던 경로. 이동 순서가 정찰 동선 |
| `LIST` | 상세 목록 (`ls -l` 형식) | 데이터 채널로 전송된다. 파일명+크기+시각 전체를 얻는다 |
| `NLST` | 이름만 목록 | 스크립트가 쓰는 형태. 자동화 도구 신호 |
| `TYPE A` / `TYPE I` | ASCII / Binary 모드 | **`TYPE I`는 실행 파일·압축·이미지 전송 신호** |
| `PASV` | 패시브 모드 요청 | 227 응답이 데이터 채널 IP/포트를 알려준다 |
| `PORT` | 액티브 모드 통보 | 클라이언트가 자기 수신 포트를 서버에 알린다 |
| `EPSV` / `EPRT` | 확장 패시브/액티브 | 229 응답 형식이 `(\|\|\|50001\|)`. IPv6 대응 |
| `STOR` | **업로드** (클라이언트 → 서버) | 웹셸·백도어 심기, 도구 반입 |
| `RETR` | **다운로드** (서버 → 클라이언트) | 자료 반출. 유출 문제의 정답이 여기 |
| `APPE` | 이어붙이기 | 분할 업로드. 파일을 여러 번 쪼개 올린 흔적 |
| `DELE` | 파일 삭제 | **증거 인멸.** 지운 파일명이 그대로 남는다 |
| `RNFR` / `RNTO` | 이름 변경 전 / 후 | 위장. `shell.php` → `image.jpg` 같은 쌍 |
| `MKD` / `RMD` | 디렉터리 생성 / 삭제 | 작업 디렉터리 준비·정리 |
| `SIZE` | 파일 크기 조회 | 213 응답의 바이트 수. 추출물 크기 검증에 쓴다 |
| `MDTM` | 수정 시각 조회 | 213 응답이 `YYYYMMDDhhmmss` **UTC**. KST는 +9시간 |
| `SITE` | 서버별 확장 | `SITE CHMOD 755` = 업로드한 파일에 실행권한 부여 |
| `QUIT` | 세션 종료 | 세션 경계. 여러 세션을 구분하는 기준 |

`STOR`과 `RETR`의 방향을 헷갈리면 문제를 반대로 답한다. **`STOR` = store to server = 올림, `RETR` = retrieve = 가져감.**

### 3단계 — 응답 코드로 성공/실패 판정

| 코드 | 텍스트 | 판정 |
| --- | --- | --- |
| `220` | Service ready | 세션 시작. 배너에 서버 SW/버전 |
| `331` | Need password | `USER`는 접수됨. 계정이 존재할 가능성 |
| `230` | User logged in | **인증 성공** |
| `530` | Not logged in | **인증 실패.** 연속 530 = 무차별 대입 |
| `200` | Command okay | `TYPE`/`PORT` 수락 |
| `227` | Entering Passive Mode | 괄호 안 6개 숫자 = 데이터 채널 IP+포트 |
| `229` | Extended Passive Mode | 괄호 안 포트만 |
| `150` | About to open data connection | 전송 시작 |
| `125` | Data connection already open | 전송 시작(채널 재사용) |
| `226` | Transfer complete | **전송 완료.** 추출물이 온전하다 |
| `425` | Can't open data connection | 데이터 채널 실패 → 파일이 없다 |
| `426` | Transfer aborted | **중단.** 추출물이 잘려 있다 |
| `213` | File status | `SIZE`/`MDTM` 응답값 |
| `250` | File action okay | `CWD`/`DELE`/`RNTO` 성공 |
| `257` | Pathname created | `PWD`/`MKD` 응답의 경로 |
| `550` | Action not taken | 파일 없음 또는 권한 없음. 정찰 실패 흔적 |
| `553` | Filename not allowed | 업로드 차단. 확장자 필터 우회 시도의 증거 |

`RETR` 뒤에 `226`이 없고 `426`만 있으면 **추출한 파일은 잘린 파일이다.** `file`이 형식을 못 알아보는 원인이 대개 여기다.

### 4단계 — 데이터 채널 포트를 직접 계산한다

FTP는 데이터 채널 포트를 제어 채널 안에서 텍스트로 협상한다. 그 숫자를 손으로 계산할 수 있어야 한다.

| 모드 | 누가 연다 | 협상 메시지 | 포트 계산 |
| --- | --- | --- | --- |
| Active | **서버 → 클라이언트** | `PORT h1,h2,h3,h4,p1,p2` | 클라이언트 포트 = `p1 * 256 + p2`. 서버측 출발 포트는 보통 20 |
| Passive | **클라이언트 → 서버** | `227 ... (h1,h2,h3,h4,p1,p2)` | 서버 포트 = `p1 * 256 + p2` |
| Extended Passive | 클라이언트 → 서버 | `229 ... (\|\|\|port\|)` | 괄호 안 값이 그대로 포트 |

계산 예시:

```text
227 Entering Passive Mode (203,0,113,77,195,80)
  IP   = 203.0.113.77
  Port = 195 * 256 + 80 = 49920 + 80 = 50000
  -> 데이터 채널 필터: tcp.port == 50000

PORT 10,0,0,15,194,208
  IP   = 10.0.0.15
  Port = 194 * 256 + 208 = 49664 + 208 = 49872
  -> 데이터 채널 필터: tcp.port == 49872
```

Wireshark가 이 숫자를 대신 파싱해 준 필드가 있다. 계산이 귀찮으면 이것을 쓴다.

```bash
tshark -r capture.pcapng -Y 'ftp.response.code == 227' \
  -T fields -e frame.number -e ftp.passive.ip -e ftp.passive.port
tshark -r capture.pcapng -Y 'ftp.request.command == "PORT"' \
  -T fields -e frame.number -e ftp.active.cip -e ftp.active.port
```

**왜 이것이 중요한가**: 액티브 모드는 서버가 20번에서 나가므로 포트가 고정되어 Wireshark가 쉽게 `FTP-DATA`로 인식한다. 패시브 모드는 매 전송마다 임의의 고포트가 쓰이므로, Wireshark가 `227` 응답을 **실제로 캡처에서 봤을 때만** 그 TCP 연결을 `ftp-data`로 승격한다.

### 5단계 — Export Objects가 비었을 때의 우회

`File > Export Objects > FTP-DATA`가 비는 조건과 대응:

| 원인 | 확인 방법 | 대응 |
| --- | --- | --- |
| `227`/`PORT` 응답이 캡처에 없다 (세션 중간부터 캡처) | `ftp.response.code == 227` 결과가 0건 | Conversations에서 바이트 큰 대화 → Follow > Raw |
| NAT/프록시가 `227`의 IP를 다시 써서 실제 연결과 불일치 | `ftp.passive.ip`와 실제 `ip.dst`가 다르다 | 같음. Decode As로 강제 |
| 데이터 채널만 필터링되어 빠졌다 | Conversations에 해당 포트 대화가 없다 | 파일 본문이 캡처에 없다. 파일명까지가 답이다 |
| `FTPS`(FTP over TLS) | `AUTH TLS` 명령과 `234` 응답이 보인다 | 본문 복원 불가. 파일명·크기만 확보 |
| `226`이 아니라 `426`으로 끝났다 | 응답 코드 확인 | 잘린 파일. 그대로 제출하지 않는다 |

우회 절차 (항상 통한다):

```text
1. Statistics > Conversations > TCP, Bytes 내림차순
2. 21번이 아닌 포트의 큰 대화를 고른다 (Stream ID 확인)
3. 그 행 우클릭 > Apply as Filter > Selected > A <-> B
4. 패킷 우클릭 > Follow > TCP Stream
5. Show data as = Raw > Save as > extracted.bin
```

Decode As로 강제하는 방법도 있다.

```text
데이터 채널 패킷 우클릭 > Decode As...
  Field = TCP port, Value = 50000, Current = FTP-DATA
-> 이후 Export Objects > FTP-DATA 에 나타난다
```

추출 뒤에는 반드시 헤더를 확인한다 ([FOR-0001](./30sec-triage.html)).

```bash
file extracted.bin
ls -l extracted.bin        # 213 SIZE 응답의 바이트 수와 일치하는지
strings -n 6 extracted.bin | head -30
```

## 출력 필드 해석

| 필드 | 내용 | 활용 |
| --- | --- | --- |
| `ftp.request.command` | 4글자 명령 (`USER`, `RETR` …) | 대문자 문자열로 정확히 비교한다 |
| `ftp.request.arg` | 명령의 인자 | 파일명, 계정명, **비밀번호**가 여기 |
| `ftp.response.code` | 3자리 정수 | 정수 비교 (`== 226`). 따옴표를 붙이지 않는다 |
| `ftp.response.arg` | 응답 텍스트 | 배너, 경로, 바이트 수, 패시브 포트 원문 |
| `ftp.passive.ip` / `ftp.passive.port` | `227`을 파싱한 값 | 데이터 채널 필터를 자동 생성 |
| `ftp.active.cip` / `ftp.active.port` | `PORT`를 파싱한 값 | 액티브 모드 클라이언트 수신 포트 |
| `ftp.current-working-directory` | 추적된 CWD | `CWD` 누적 결과. 파일의 절대 경로 복원 |
| `ftp-data.setup-frame` | 이 데이터 채널을 만든 제어 프레임 번호 | **데이터 ↔ 명령 연결의 핵심** |
| `ftp-data.command` | 이 데이터 채널에 대응하는 명령 | 어느 `RETR`의 본문인지 확정 |
| `ftp.command-response.bytes` | 명령-응답 사이 전송 바이트 | 실제 전송량 검증 |

`ftp-data.setup-frame`이 채워져 있으면 Wireshark가 채널 연결에 성공했다는 뜻이고, 비어 있으면 4단계의 수동 계산으로 가야 한다.

```bash
# 데이터 채널과 원본 명령을 한 줄로 묶어 본다
tshark -r capture.pcapng -Y 'ftp-data' \
  -T fields -e tcp.stream -e ftp-data.setup-frame -e ftp-data.command | sort -u
```

## pivot: 다음에 볼 artifact

| FTP에서 얻은 값 | 다음에 볼 것 |
| --- | --- |
| `USER` 계정명 | EVTX 4624/4625의 `TargetUserName` ([FOR-0083](./event-4624-logon.html)) — 같은 계정이 OS 로그온에도 쓰였나 |
| `PASS` 비밀번호 | 다른 프로토콜(SMTP AUTH, HTTP Basic)에서 재사용됐는지 검색 |
| `RETR` 파일명 | 클라이언트 디스크의 `$MFT` ([FOR-0021](./mft-basics.html)) — 실제로 저장됐는지 |
| `STOR` 파일명 | 서버 웹루트, 그 파일을 실행한 프로세스 ([FOR-0088](./event-4688-process-creation.html)) |
| `DELE` 파일명 | 서버측 `$UsnJrnl`, 백업본 — 지워진 원본 복구 |
| 데이터 채널 포트 | Sysmon Event 3 ([FOR-0100](./sysmon-event-3-network-connect.html)) — 어느 프로세스가 열었나 |
| `MDTM` 시각 (UTC) | 그 시각 ±5분의 전체 artifact. KST 변환 후 대조 |
| 추출한 바이너리 | 해시 → Amcache/Prefetch, `file`/`binwalk` |

## 흔한 함정

- **`STOR`과 `RETR`을 반대로 읽는 것.** 지문의 "유출"은 `RETR`(서버에서 가져감), "심었다"는 `STOR`(서버로 올림)이다. 방향을 뒤집으면 답이 정반대가 된다. 명령의 어원(store / retrieve)으로 외운다.
- **`ftp` 필터만 걸고 파일이 없다고 결론내는 것.** `ftp`는 제어 채널 21번만 잡는다. 파일 본문은 `ftp-data`에 있다. 항상 `ftp || ftp-data`로 본다.
- **`ftp.response.code`에 따옴표를 붙이는 것.** 정수 필드다. `ftp.response.code == "226"`은 원하는 대로 동작하지 않는다. `== 226`으로 쓴다.
- **`ftp.request.command`를 소문자로 비교하는 것.** 와이어에는 대문자로 흐른다. `== "retr"`은 매칭되지 않는다. 대소문자를 모르면 `ftp.request.command contains "ETR"` 같은 부분 매칭을 쓰지 않고, 우선 전체 목록을 뽑아 실제 값을 확인한다.
- **`226`을 확인하지 않고 추출물을 제출하는 것.** `426`으로 끝난 전송은 잘린 파일이다. `SIZE`의 213 응답 바이트 수와 추출 파일 크기를 비교하면 즉시 드러난다.
- **패시브 포트를 `p1 * 256 + p2`로 계산하지 않는 것.** `(203,0,113,77,195,80)`의 포트는 195나 80이 아니라 50000이다. 앞 4개는 IP, 뒤 2개가 포트의 상위/하위 바이트다.
- **Export Objects > FTP-DATA가 비면 파일이 없다고 판단하는 것.** 패시브 모드에서 `227` 응답이 캡처에 없으면 Wireshark는 그 연결을 일반 TCP로 둔다. Conversations의 바이트 크기가 진실이다.
- **`TYPE A`로 전송된 바이너리를 그대로 쓰는 것.** ASCII 모드는 줄바꿈을 변환하므로 바이너리가 손상된다. `TYPE I`가 아닌 전송에서 나온 실행 파일은 해시가 원본과 다를 수 있다.
- **`MDTM` 응답 시각을 로컬 시각으로 읽는 것.** `213 20260314071502`는 **UTC**다. KST 표기는 `2026-03-14 16:15:02`다.
- **여러 세션을 하나로 뭉쳐 읽는 것.** `QUIT`/`221` 이후에 다시 `USER`가 나오면 별개 세션이다. `tcp.stream` 값으로 나눠서 읽는다.
- **21번 포트만 FTP라고 가정하는 것.** 2121, 8021 등에서 돌리면 `Protocol` 컬럼이 `TCP`로만 보인다. `Decode As > FTP`로 강제한다.

## 교차검증

```bash
# 1) 제어 채널 전체를 시간순 표로
tshark -r capture.pcapng -Y 'ftp' \
  -T fields -e frame.number -e frame.time -e ip.src -e ip.dst \
  -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg -E header=y

# 2) 자격증명만
tshark -r capture.pcapng -Y 'ftp.request.command in {"USER","PASS"}' \
  -T fields -e tcp.stream -e ip.src -e ftp.request.command -e ftp.request.arg

# 3) 전송된 파일명만 (업로드/다운로드 구분)
tshark -r capture.pcapng -Y 'ftp.request.command in {"STOR","RETR","APPE","DELE"}' \
  -T fields -e frame.number -e ftp.request.command -e ftp.request.arg

# 4) 인증 결과 집계 — 530이 많으면 무차별 대입
tshark -r capture.pcapng -Y 'ftp.response.code in {230,530}' \
  -T fields -e ftp.response.code | sort | uniq -c

# 5) 데이터 채널 후보 찾기 (21번 제외한 큰 대화)
tshark -r capture.pcapng -q -z conv,tcp | sort -k5 -n -r | head -10

# 6) 파일 일괄 추출 후 형식 확인
tshark -r capture.pcapng --export-objects ftp-data,out_ftp/
ls -l out_ftp/ && file out_ftp/*

# 7) 파서를 우회한 최후 확인
strings -n 6 capture.pcapng | grep -Ei '^(USER|PASS|RETR|STOR|DELE|CWD) '
```

`ftp.request.command in {"USER","PASS"}` 의 집합 문법은 `==` 를 여러 번 쓰는 것보다 짧고 오타가 적다.

## mini walkthrough

```text
문제:
"공격자가 FTP 서버에 접속해 자료를 가져가고 흔적을 지웠다.
 가져간 파일 안의 flag 와, 공격자가 삭제한 파일 이름을 답하시오."
첨부: ftp_case.pcapng (4,912 packets, 3.1 MB)

1. Protocol Hierarchy
   TCP 99.1%  |  File Transfer Protocol 1.2% (58 packets)  |  FTP Data 0%
   -> FTP Data 가 0%. 하지만 TCP 바이트는 3 MB. 뭔가 미인식 상태다.

2. 필터: ftp
   Follow > TCP Stream 으로 제어 채널 전문 확인
     USER backup_svc / PASS Wint3r!2026 / 230 Login successful.
     TYPE I / PASV / 227 Entering Passive Mode (203,0,113,77,195,81)
     RETR internal_report.pdf
     150 Opening BINARY mode data connection ... (2317540 bytes)
     226 Transfer complete.
     DELE audit_trail.log
     250 Delete operation successful.

   삭제된 파일 = audit_trail.log  (두 번째 질문 해결)
   가져간 파일 = internal_report.pdf, 2,317,540 bytes

3. 첫 시도 (실패):
   File > Export Objects > FTP-DATA
   -> 목록이 완전히 비어 있다.

   원인 진단:
     tshark -r ftp_case.pcapng -Y 'ftp-data' | wc -l
       0
     tshark -r ftp_case.pcapng -Y 'ftp.response.code == 227' \
       -T fields -e ftp.passive.ip -e ftp.passive.port
       203.0.113.77   50001

   227 은 캡처에 있는데 ftp-data 로는 승격되지 않았다. 데이터 연결의
   SYN 이 캡처 범위를 벗어나 시작되어 Wireshark 가 setup frame 을
   연결하지 못한 상태다. ftp-data.setup-frame 도 비어 있다.

   교훈: Export Objects 는 Wireshark 의 채널 연결이 성공했을 때만 채워진다.
        비어 있다는 것은 "파일이 없다"가 아니라 "연결에 실패했다"다.

4. 접근 변경 — 협상된 포트를 직접 쓴다
   포트 계산 검산: 195 * 256 + 81 = 49920 + 81 = 50001  (필드값과 일치)

   필터: tcp.port == 50001
   Statistics > Conversations > TCP 에서 해당 대화 확인
     10.0.0.15:51344 <-> 203.0.113.77:50001   1,712 packets  2,317,540 bytes

   바이트 수가 150 응답의 2,317,540 과 정확히 일치한다. 이것이 그 파일이다.

5. 추출
   해당 패킷 우클릭 > Follow > TCP Stream
   Show data as = Raw > Save as > report.bin

   (또는 Decode As 로 FTP-DATA 를 강제한 뒤 Export Objects 재시도)

6. 검증과 답
   $ ls -l report.bin
   -rw-r--r-- 1 user user 2317540 report.bin        <- SIZE/150 응답과 일치
   $ file report.bin
   report.bin: PDF document, version 1.7
   $ strings report.bin | grep -i 'flag{'
   flag{p4ssiv3_p0rt_195x256plus81}

7. 시간 정리
   MDTM 응답 213 20260314071502 = 2026-03-14 07:15:02 UTC
                                = 2026-03-14 16:15:02 KST

정답: flag{p4ssiv3_p0rt_195x256plus81} / 삭제된 파일 audit_trail.log
```

3단계의 실패가 핵심이다. **Export Objects의 공백은 파일의 부재가 아니라 채널 연결의 실패를 뜻한다.** `ftp.passive.port`로 포트를 확정하고 그 대화의 바이트 수를 `150`/`SIZE` 응답과 맞춰보면 언제나 정답 스트림을 찾을 수 있다.

## 막혔을 때 다음 체크

1. `ftp || ftp-data`로 봤는가 — `ftp`만으로는 파일 본문이 안 보인다
2. `ftp` 아무 패킷에서 `Follow > TCP Stream`을 했는가 — 세션 전문이 가장 빠르다
3. `ftp.request.command` 전체 목록을 뽑았는가 — `DELE`/`RNTO` 같은 조용한 명령을 놓치기 쉽다
4. `ftp.response.code == 226`인가 `426`인가 — 추출물의 온전성
5. `SIZE`의 `213` 응답 바이트 수와 추출 파일 크기가 같은가
6. `ftp.passive.port` / `ftp.active.port`를 확인했는가 — 없으면 `227` 원문에서 손계산
7. Export Objects가 비었는가 → `Decode As > FTP-DATA` 또는 `Follow > Raw`
8. Conversations를 Bytes로 정렬해 21번 아닌 큰 대화를 찾았는가
9. `tcp.stream` 별로 세션을 나눠 봤는가 — `QUIT` 이후는 별개 세션
10. `AUTH TLS` / `234`가 있는가 — FTPS면 본문 복원은 포기하고 메타데이터로 승부
11. `Protocol` 컬럼이 `TCP`뿐인가 → 비표준 포트 FTP. `Decode As > FTP`
12. `strings capture.pcapng | grep -E '^(USER|RETR|STOR) '`를 돌렸는가 — 파서 우회

## 출처

- SRC-070 — RFC 959 (FTP): 명령어 정의(`USER` `PASS` `STOR` `RETR` `DELE` `RNFR` `RNTO` `TYPE` `PORT` `PASV`), 응답 코드 3자리 체계, `PORT`/`227`의 `h1,h2,h3,h4,p1,p2` 표기와 포트 계산 규칙, 액티브/패시브 데이터 채널 개설 주체
- SRC-002 — Wireshark Display Filter Reference: 본문에 쓴 필드 이름 전체(`ftp.request.command`, `ftp.request.arg`, `ftp.response.code`, `ftp.response.arg`, `ftp.passive.ip`, `ftp.passive.port`, `ftp.active.cip`, `ftp.active.port`, `ftp.current-working-directory`, `ftp-data.setup-frame`, `ftp-data.command`, `ftp.command-response.bytes`)를 dfref의 `ftp` 항목에서 확인
- SRC-003 — Wireshark User's Guide: `File > Export Objects > FTP-DATA`, `Follow > TCP Stream`의 `Show data as: Raw`, `Analyze > Decode As`, `Statistics > Conversations`
- `MDTM` 응답의 `YYYYMMDDhhmmss` UTC 표기는 RFC 3659(FTP 확장)에서 정의된 것으로, 서버 구현에 따라 지원되지 않을 수 있다. 실제 캡처에서 응답 코드 213이 오는지 확인할 것
- 메뉴 경로(`Export Objects`의 `FTP-DATA` 항목 명칭 등)는 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
