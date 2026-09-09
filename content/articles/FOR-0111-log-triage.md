---
id: FOR-0111
title: "로그 파일 30초 트리아지: 형식·줄수·시간범위부터 확인한다"
slug: "log-triage"
category: "로그/Regex"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "error.log", "auth.log", "syslog", "messages", "secure", "IIS W3C log", "JSONL log"]
file_paths: ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/apache2/access.log", "/var/log/nginx/access.log", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "syslog"]
tools: ["head", "tail", "wc", "file", "less", "split", "sed", "iconv", "xxd"]
commands: ["head -3 access.log", "wc -l access.log", "file access.log", "tail -3 access.log", "sed -n '1000,1010p' access.log", "split -l 500000 huge.log part_"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["remote_addr", "time_local", "request", "status", "body_bytes_sent", "date", "time", "c-ip", "cs-uri-stem", "sc-status"]
file_formats: ["log", "txt", "csv", "json", "jsonl", "gz"]
primary_terms: ["로그 트리아지", "로그 파일 처음", "로그 뭐부터", "로그가 너무 크다"]
keywords: ["로그 트리아지", "log triage", "로그 형식 판별", "Apache combined", "nginx log_format", "syslog RFC3164", "RFC5424", "IIS W3C", "JSONL", "wc -l", "인코딩", "CRLF", "시간대"]
aliases: ["로그 뭐부터 봐야", "로그 파일 처음", "로그 형식 확인", "로그 몇 줄", "로그 트리아지", "로그 파일 너무 큼", "로그 어떻게 열어"]
symptom_keywords: ["로그가 너무 크다", "로그 형식을 모르겠다", "편집기로 열면 멈춘다", "한글이 깨진다", "시간대가 뭔지 모르겠다", "무엇을 세야 할지 모르겠다", "줄 수가 안 맞는다"]
related: ["FOR-0112", "FOR-0117", "FOR-0118", "FOR-0121"]
source_ids: ["SRC-058", "SRC-059", "SRC-060"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

로그를 받으면 정규식을 짜기 전에 `head -3`·`tail -3`·`wc -l`·`file` 네 명령으로 **형식·줄수·시간범위·인코딩**을 먼저 확정한다 — 이 30초를 건너뛰면 잘못된 필드 번호로 잘못된 답을 세게 된다.

## 어떤 문제에서 필요한가

- 첨부가 수십 MB~수 GB `.log` / `.txt` / `.gz` 이고 GUI 편집기가 멈추는 상황
- "가장 많이 요청한 IP", "최초 접속 시각", "몇 번 실패했나" 같은 집계형 문제
- 여러 로그(웹 + 인증 + 시스템)를 시간축으로 합쳐야 하는 상황
- 로그의 시간대가 문제 지문의 시간대와 다른지 판단해야 하는 상황

## 문제에서 처음 볼 단서

| 단서 | 의미 |
| --- | --- |
| 파일명이 `access.log` / `error.log` | 웹 서버 로그. 1번 필드가 IP |
| 파일명이 `auth.log` / `secure` | SSH·sudo 인증 로그. `Failed password` / `Accepted password` |
| 파일명이 `syslog` / `messages` | 시스템 전반. 태그(`sshd[2841]:`)로 좁힌다 |
| 파일명이 `u_ex260314.log` | IIS W3C. `#Fields:` 헤더에 필드 순서가 있다 |
| 확장자가 `.jsonl` / `.ndjson` | 한 줄 = JSON 객체 하나. `jq -c` 대상 |
| 확장자가 `.gz` / `.bz2` / `.xz` | 압축. 풀지 말고 `zcat`·`rg -z`로 바로 읽는다 |
| 확장자가 `.evtx` | 텍스트 도구로 못 읽는다. 별도 파서 필요 |

**`.evtx`는 이 글의 대상이 아니다.** 바이너리 XML 컨테이너이므로 `grep`이 아니라 전용 파서를 쓴다 ([FOR-0081](./evtx-analysis-order.html)).

## 30초 절차

```bash
head -3 access.log; echo ---; tail -3 access.log; echo ---; wc -l access.log; file access.log
```

네 개를 한 줄로 붙인 것이다. 출력 예시:

```text
203.0.113.77 - - [14/Mar/2026:07:11:02 +0900] "GET / HTTP/1.1" 200 4021 "-" "curl/8.4.0"
203.0.113.77 - - [14/Mar/2026:07:11:04 +0900] "GET /admin/ HTTP/1.1" 403 199 "-" "curl/8.4.0"
192.168.10.24 - - [14/Mar/2026:07:11:09 +0900] "GET /index.html HTTP/1.1" 200 4021 "-" "Mozilla/5.0 ..."
---
198.51.100.5 - - [14/Mar/2026:23:58:41 +0900] "GET /favicon.ico HTTP/1.1" 404 209 "-" "Mozilla/5.0 ..."
203.0.113.77 - - [14/Mar/2026:23:59:12 +0900] "POST /upload.php HTTP/1.1" 200 87 "-" "python-requests/2.31"
192.168.10.24 - - [14/Mar/2026:23:59:58 +0900] "GET /health HTTP/1.1" 200 2 "-" "kube-probe/1.28"
---
   41882 access.log
access.log: ASCII text
```

이 한 화면에서 다음 5개가 전부 확정된다.

| 확정되는 것 | 위 예시의 값 |
| --- | --- |
| 형식 | Apache/nginx **combined** (필드 9개, Referer·User-Agent 있음) |
| 줄 수 | 41,882 |
| 시간 범위 | 2026-03-14 07:11:02 ~ 23:59:58 |
| 시간대 | `+0900` = KST |
| 인코딩·줄바꿈 | ASCII, LF (CRLF면 `file`이 명시한다) |

## 상세 절차

### 1단계 — 형식 판별표

첫 줄의 **첫 글자와 구분자**만 보면 형식이 나온다.

| 첫 줄 모양 | 형식 | 필드 구분 | 필드 수 |
| --- | --- | --- | --- |
| `1.2.3.4 - - [.../...] "GET / HTTP/1.1" 200 4021` | Apache/nginx **common (CLF)** | 공백 (따옴표 내부 제외) | 7 |
| 위 + `"-" "Mozilla/5.0..."` | Apache/nginx **combined** | 같음 | 9 |
| `Mar 14 07:11:02 web01 sshd[2841]: ...` | syslog **RFC3164** | 공백 | 고정 5 + 메시지 |
| `<34>1 2026-03-14T07:11:02.123+09:00 web01 sshd 2841 - - ...` | syslog **RFC5424** | 공백 | 고정 7 + 메시지 |
| `#Software: Microsoft Internet Information Services` | **IIS W3C Extended** | 공백, `#Fields:`가 순서 정의 | 가변 |
| `{"ts":"2026-03-14T07:11:02Z","ip":"1.2.3.4",...}` | **JSON Lines** | 없음 (구조화) | 키 기반 |
| `[` 로 시작하고 파일 끝이 `]` | **JSON 배열 1개** | 없음 | 키 기반 |
| `"time","ip","uri","status"` | **CSV** (헤더 있음) | 쉼표, 인용 필드 주의 | 헤더 개수 |
| 사람이 못 읽는 바이트 | EVTX·SQLite·압축 등 **바이너리** | — | — |

세부 확인 명령이다.

```bash
# 필드 수를 세어 common(7) / combined(9) 를 구분한다
head -1 access.log | awk '{print NF}'

# IIS 는 헤더가 필드 순서를 알려준다 (이걸 안 읽으면 필드 번호를 틀린다)
grep -m1 '^#Fields:' u_ex260314.log

# JSONL 은 첫 객체의 키만 본다
head -1 app.jsonl | jq -r 'keys | join(",")'

# CSV 헤더
head -1 export.csv
```

`#Fields:` 출력 예시:

```text
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
```

여기서 `c-ip`가 **9번째**다. Apache 습관대로 `$1`을 IP로 쓰면 IIS에서는 날짜를 세게 된다.

### 2단계 — 줄 수와 실제 크기

```bash
wc -l access.log          # 줄 수 (개행 문자 개수)
wc -c access.log          # 바이트
du -h access.log          # 디스크 사용량
awk 'END{print NR}' access.log   # 마지막 개행이 없어도 정확한 줄 수
```

| 상황 | `wc -l` | `awk 'END{print NR}'` |
| --- | --- | --- |
| 마지막 줄이 개행으로 끝남 | 정확 | 정확 |
| 마지막 줄에 개행 없음 | **1 적게 나온다** | 정확 |

줄 수를 알면 전략이 갈린다.

| 줄 수 | 전략 |
| --- | --- |
| ~10만 | 무엇을 해도 된다. `grep`·`awk` 그대로 |
| 10만~500만 | `grep`으로 먼저 좁히고 `awk`로 집계. `LC_ALL=C` 붙이면 빨라진다 |
| 500만 이상 | `rg`로 좁히거나 `split`으로 쪼갠다. 파이프 앞단에서 최대한 버린다 |

### 3단계 — 인코딩과 줄바꿈

```bash
file access.log
file -i access.log            # MIME + charset 추정
head -c 16 access.log | xxd   # BOM 확인
```

| `xxd` 앞 3바이트 | 의미 | 대응 |
| --- | --- | --- |
| `efbbbf` | UTF-8 BOM | 첫 필드 앞에 3바이트가 붙는다. `sed '1s/^\xef\xbb\xbf//'` |
| `fffe` / `feff` | UTF-16 LE / BE | `iconv -f UTF-16 -t UTF-8` 후 처리 |
| 그 외 | BOM 없음 | 그대로 |

`file` 출력에 `with CRLF line terminators`가 있으면 줄 끝에 `\r`(0x0D)이 남아 있다.

```bash
# CR 이 붙은 줄 수 (0이 아니면 CRLF)
grep -c $'\r' access.log

# 제거 (원본은 건드리지 않고 새 파일로)
tr -d '\r' < access.log > access.lf.log
```

CRLF를 방치하면 **마지막 필드에 `\r`이 붙어** `$9 == "200"` 같은 비교가 조용히 실패한다. `awk`에서만 고치려면 `awk 'BEGIN{RS="\r?\n"}'`로 레코드 구분자를 바꾼다.

한글이 깨지면 CP949(EUC-KR) 로그일 가능성이 높다.

```bash
iconv -f CP949 -t UTF-8 app.log > app.utf8.log
```

Windows 쪽에서 같은 일을 할 때다.

```powershell
# 앞 3줄 / 뒤 3줄 / 총 줄 수
Get-Content .\access.log -TotalCount 3
Get-Content .\access.log -Tail 3
(Get-Content .\access.log | Measure-Object -Line).Lines

# 인코딩 지정해서 읽기
Get-Content .\app.log -Encoding utf8 -TotalCount 5
```

### 4단계 — 시간대 표기 확인

**로그의 시간대를 확정하지 않으면 타임라인이 전부 어긋난다.**

| 형식 | 시간 표기 예 | 시간대 정보 | 판정 |
| --- | --- | --- | --- |
| Apache/nginx | `[14/Mar/2026:07:11:02 +0900]` | 오프셋 **있음** | KST. 그대로 신뢰 |
| Apache/nginx | `[14/Mar/2026:07:11:02 +0000]` | 오프셋 있음 | UTC. KST는 +9시간 |
| syslog RFC3164 | `Mar 14 07:11:02` | **없음. 연도도 없음** | 서버 로컬 시간으로 가정하고 별도 확인 |
| syslog RFC5424 | `2026-03-14T07:11:02.123+09:00` | 있음 | 그대로 신뢰 |
| IIS W3C | `2026-03-14 07:11:02` | 없음 | 기본이 **UTC**. KST는 +9시간 |
| JSONL | `"ts":"2026-03-14T07:11:02Z"` | `Z` = UTC | KST는 +9시간 |
| Unix epoch | `1773... ` (10자리) | UTC 기준 초 | `date -d @<초>` |

```bash
# epoch -> 사람이 읽는 시간 (UTC 와 KST 둘 다 본다)
date -u -d @1773450662 '+%F %T UTC'
TZ=Asia/Seoul date -d @1773450662 '+%F %T KST'
```

RFC3164 syslog는 **연도가 없다.** 파일 mtime, 로테이션 파일명(`syslog.1`), 또는 같은 사건이 찍힌 다른 로그에서 연도를 확정한다. 연도를 추측해서 적으면 오답이 된다.

### 5단계 — 대용량 전략

```bash
# 1) 구간만 보기 — 12,000~12,050 줄
sed -n '12000,12050p' huge.log

# sed 는 필요한 범위 뒤를 읽지 않게 끊어 주면 훨씬 빠르다
sed -n '12000,12050p;12051q' huge.log

# 2) 실시간 추적
tail -f app.log
less +F app.log        # less 안에서 Ctrl-C 로 탐색, Shift-F 로 다시 추적

# 3) 파일 쪼개기 — 50만 줄씩
split -l 500000 huge.log part_
ls part_*              # part_aa part_ab ...

# 4) 압축 로그는 풀지 않고 바로
zcat access.log.1.gz | head -3
zgrep -c 'POST' access.log.*.gz
rg -z 'POST /upload' access.log.*.gz

# 5) 파이프 앞단에서 최대한 버린다 (grep 먼저, awk 나중)
LC_ALL=C grep 'POST' huge.log | awk '{print $1}' | sort | uniq -c | sort -nr | head
```

`LC_ALL=C`는 로케일 기반 문자 분류를 끄기 때문에 ASCII 로그에서 `grep`·`sort` 속도가 크게 오른다. 다만 **한글이 든 로그에서 정렬 순서가 바뀌므로** 집계 결과를 사람이 읽는 목록으로 낼 때는 주의한다.

### 6단계 — 무엇을 세는지 결정한다

여기가 트리아지의 마지막 단계다. **문제 지문의 명사가 곧 세야 할 필드다.**

| 지문의 표현 | 세야 할 것 | 형식별 필드 |
| --- | --- | --- |
| "가장 많이 접속한", "공격자" | 출처 IP | combined `$1` / IIS `c-ip` / auth.log `from <IP>` |
| "어떤 페이지를", "무엇을 요청" | URI | combined `$7` / IIS `cs-uri-stem` |
| "성공했나", "실패했나" | 상태 코드 | combined `$9` / IIS `sc-status` |
| "누가", "어떤 계정" | 사용자명 | auth.log 메시지 / IIS `cs-username` |
| "몇 번" | 위 중 하나의 빈도 | `sort \| uniq -c \| sort -nr` |
| "최초", "언제" | 시각 | combined `$4` / IIS `date`+`time` |
| "얼마나 유출" | 응답 크기 합 | combined `$10` |
| "무슨 도구로" | User-Agent | combined `$12` 이후 |

세는 방법은 하나로 고정한다.

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -10
```

이 관용구가 왜 정답인지는 [FOR-0117](./sort-uniq.html)에서 다룬다.

## 출력 필드 해석

Apache/nginx **combined** 필드 번호다. 공백으로 자른 기준이며, 대괄호와 따옴표가 필드를 쪼개는 것이 함정이다.

| `awk` 필드 | 내용 | 예 |
| --- | --- | --- |
| `$1` | 클라이언트 IP (`%h`) | `203.0.113.77` |
| `$2` | identd (`%l`) | `-` |
| `$3` | HTTP 인증 사용자 (`%u`) | `-` |
| `$4` | `[`+날짜시각 | `[14/Mar/2026:07:11:02` |
| `$5` | 시간대 오프셋+`]` | `+0900]` |
| `$6` | `"`+메서드 | `"GET` |
| `$7` | URI (쿼리 포함) | `/upload.php?id=1` |
| `$8` | 프로토콜+`"` | `HTTP/1.1"` |
| `$9` | 상태 코드 | `200` |
| `$10` | 응답 바이트 (`%b`) | `4021` 또는 `-` |
| `$11` | Referer (따옴표 포함) | `"-"` |
| `$12` 이후 | User-Agent (**공백 때문에 여러 필드로 쪼개진다**) | `"Mozilla/5.0` `(Windows` ... |

`$4`와 `$5`가 시각 하나로 쪼개지고, User-Agent가 여러 필드로 쪼개진다는 점이 실전에서 가장 자주 사고를 낸다. 대응은 두 가지다.

```bash
# 1) 대괄호/따옴표를 구분자로 삼는다
awk -F'[][]' '{print $2}' access.log          # 시각만
awk -F'"' '{print $6}' access.log             # User-Agent 만

# 2) 시각은 $4 에서 대괄호만 떼고 쓴다
awk '{gsub(/^\[/,"",$4); print $4}' access.log
```

## pivot: 다음에 볼 artifact

| 트리아지에서 얻은 것 | 다음 목표 |
| --- | --- |
| 형식 = combined | 필드 번호 확정 → `awk` 집계 ([FOR-0115](./awk-fields.html)) |
| 형식 = IIS W3C | `#Fields:` 순서로 필드 번호 재계산 |
| 형식 = JSONL | `jq` 로 키 기준 추출 |
| 시간 범위 | 다른 로그·artifact를 같은 구간으로 자른다 |
| 시간대 오프셋 | 전체 타임라인을 UTC 또는 KST 하나로 통일 |
| 상위 IP | pcap `ip.addr == <IP>`, EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) |
| 상위 URI | 웹셸·업로드 경로 후보 |
| 파일 시그니처가 텍스트가 아님 | 매직 바이트 판정 ([FOR-0001](./30sec-triage.html)) |

## 흔한 함정

- **형식 확인 없이 정규식을 짜는 것.** IIS 로그에 `$1`을 IP로 쓰면 날짜를 센다. `head -1`과 `#Fields:`가 30초를 아껴 준다.
- **`tail`을 안 보는 것.** 로그가 시간순이 아닌 경우(여러 서버 병합, 로테이션 재조립)가 있다. 첫 줄과 마지막 줄의 시각을 둘 다 봐야 범위를 안다.
- **시간대를 가정하는 것.** IIS는 기본 UTC, Apache는 서버 로컬이다. 오프셋 표기가 없으면 "없다"는 사실을 기록하고 다른 근거로 확정한다.
- **RFC3164 syslog에 연도를 추측해 넣는 것.** 원본에 연도가 없다. 파일 mtime이나 다른 로그로 확정하지 않으면 적지 않는다.
- **CRLF를 무시하는 것.** 마지막 필드에 `\r`이 붙어 `$NF=="200"` 비교가 실패한다. `file` 출력에 `CRLF`가 보이면 먼저 `tr -d '\r'`.
- **`wc -l`을 절대 신뢰하는 것.** 마지막 줄에 개행이 없으면 1이 모자란다. 정확한 값이 답인 문제에서는 `awk 'END{print NR}'`로 교차 확인한다.
- **GUI 편집기로 대용량을 여는 것.** 수백 MB 파일을 메모장·VS Code로 열면 시간을 다 잃는다. `head`/`sed -n`/`less`로만 접근한다.
- **압축을 먼저 푸는 것.** 디스크와 시간을 낭비한다. `zcat`·`zgrep`·`rg -z`로 바로 읽는다.
- **`grep` 없이 `awk`로 전체를 훑는 것.** 파이프 앞단에서 줄을 버려야 빠르다. `grep 'POST' | awk ...` 순서가 `awk '/POST/{...}'`보다 대개 빠르다.
- **`.evtx`·`.pcapng`를 텍스트 도구로 여는 것.** 바이너리 컨테이너다. `strings`로 몇 조각이 보이더라도 그것으로 집계하면 누락이 생긴다.

## 교차검증

같은 값을 두 방법으로 세서 일치하는지 본다.

```bash
# 줄 수
wc -l access.log
awk 'END{print NR}' access.log
grep -c '' access.log

# 상위 IP — 필드 기준(정확) vs 정규식 기준(오탐 가능)
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -3
grep -Eo '^[0-9]{1,3}(\.[0-9]{1,3}){3}' access.log | sort | uniq -c | sort -nr | head -3

# 시간 범위 — 첫/마지막 줄 vs 정렬 결과
head -1 access.log | awk -F'[][]' '{print $2}'
tail -1 access.log | awk -F'[][]' '{print $2}'
```

세 줄 수가 다르면 개행이 없는 마지막 줄이나 `\r`이 원인이다. 상위 IP가 다르면 정규식이 본문 안의 IP까지 잡은 것이다. **필드 기준(`awk '{print $1}'`)이 기준값**이다 — 정규식 오탐은 [FOR-0128](./ipv4-regex.html)에 정리돼 있다.

## mini walkthrough

```text
문제:
"웹 서버 로그에서 공격자 IP와 최초 공격 시각(KST)을 구하세요."
첨부: u_ex260314.log (2,910,447줄, 412MB)

1. 첫 시도 (실패):
   $ awk '{print $1}' u_ex260314.log | sort | uniq -c | sort -nr | head -3
   2910441 2026-03-14
         3 #Software:
         1 #Fields:

   -> IP 가 아니라 날짜가 나왔다. Apache 습관으로 $1 을 IP 라고 가정한 것이 원인.

2. 접근 변경 — 형식을 먼저 확인한다
   $ head -4 u_ex260314.log
   #Software: Microsoft Internet Information Services 10.0
   #Version: 1.0
   #Date: 2026-03-14 00:00:00
   #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken

   -> IIS W3C Extended. c-ip 는 9번째 필드다.
      s-ip($3)는 서버 IP, c-ip($9)가 클라이언트 IP.

3. 줄수·범위·시간대
   $ wc -l u_ex260314.log
   2910447 u_ex260314.log
   $ head -5 u_ex260314.log | tail -1
   2026-03-14 00:00:01 10.0.0.11 GET /health - 443 - 10.0.0.50 kube-probe/1.28 200 0 0 1
   $ tail -1 u_ex260314.log
   2026-03-14 23:59:57 10.0.0.11 GET /favicon.ico - 443 - 198.51.100.5 Mozilla/5.0 404 0 2 3

   -> 00:00:01 ~ 23:59:57. 오프셋 표기가 없고 IIS 기본은 UTC.
      즉 이 로그의 시각은 UTC 이며 KST 는 +9시간이다. 이걸 놓치면 9시간 틀린다.

4. 헤더 줄을 버리고 c-ip 집계
   $ grep -v '^#' u_ex260314.log | awk '{print $9}' | sort | uniq -c | sort -nr | head -5
   1402118 10.0.0.50          <- 내부 헬스체크 봇
    880219 10.0.0.51
    412998 198.51.100.5
     84402 203.0.113.77
      2311 192.0.2.9

   -> 1,2위는 사설 IP(10.0.0.0/8) 헬스체크. 상위 1위를 공격자로 쓰면 오답.

5. 사설 IP 를 빼고 다시
   $ grep -v '^#' u_ex260314.log | awk '$9 !~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {print $9}' |
       sort | uniq -c | sort -nr | head -3
    412998 198.51.100.5
     84402 203.0.113.77
      2311 192.0.2.9

6. 빈도 1위가 공격자인지 확인 — 상태 코드 분포를 본다
   $ grep -v '^#' u_ex260314.log | awk '$9=="198.51.100.5"{print $11}' | sort | uniq -c
    412996 200
         2 304
   $ grep -v '^#' u_ex260314.log | awk '$9=="203.0.113.77"{print $11}' | sort | uniq -c
     79214 404
      5102 403
        84 500
         2 200

   -> 198.51.100.5 는 전부 200. 정상 크롤러다.
      203.0.113.77 은 404/403 이 압도적. 이것이 스캔·탐색 흔적이다.

7. 최초 시각
   $ grep -v '^#' u_ex260314.log | awk '$9=="203.0.113.77"{print $1, $2; exit}'
   2026-03-14 06:11:02
   -> UTC 06:11:02 = KST 15:11:02

정답: 공격자 203.0.113.77 / 최초 공격 2026-03-14 15:11:02 KST (로그 표기 06:11:02 UTC)
```

1단계와 4단계가 이 문제의 핵심이다. **형식을 확인하지 않으면 필드 번호를 틀리고, 빈도 1위를 그대로 믿으면 헬스체크 봇을 공격자로 지목한다.**

## 막혔을 때 다음 체크

1. `head -1`로 형식을 확정했는가 — 필드 번호는 형식에서 나온다
2. IIS라면 `#Fields:`를 읽었는가 — 필드 순서는 서버 설정마다 다르다
3. `head -1 | awk '{print NF}'`로 필드 수를 셌는가 (common 7 / combined 9)
4. `tail -1`로 마지막 시각을 봤는가 — 시간 범위를 알아야 다른 로그와 맞춘다
5. 시간대 오프셋이 로그에 있는가, 없으면 무엇으로 확정했는가
6. `file`이 `CRLF`나 `UTF-16`을 말하지 않았는가
7. `wc -l`과 `awk 'END{print NR}'`가 일치하는가
8. 헤더 줄(`#`)이나 주석을 `grep -v '^#'`로 걸렀는가
9. 사설 IP·헬스체크·정상 봇을 상위 목록에서 제외했는가
10. 압축 파일을 풀지 않고 `zcat`/`rg -z`로 읽었는가
11. 로테이션된 형제 파일(`access.log.1`, `.2.gz`)이 함께 있는가 — 사건이 그쪽에 있을 수 있다

## 출처

- SRC-058 — Apache HTTP Server, Log Files: Common Log Format과 Combined Log Format의 필드 구성(`%h %l %u %t \"%r\" %>s %b`)
- SRC-059 — nginx `ngx_http_log_module`: `combined` `log_format` 정의와 변수 이름(`$remote_addr`, `$time_local`, `$status`, `$body_bytes_sent`)
- SRC-060 — RFC 5424: syslog 헤더 구조와 타임스탬프(RFC3339) 표기, RFC3164 대비 차이
- IIS W3C 로그의 `#Fields:` 항목 구성과 기본 UTC 기록은 서버 설정에 따라 달라질 수 있으므로 실제 파일의 헤더 줄에서 확인할 것
- `LC_ALL=C`의 속도 이득과 `sed -n '...;Nq'`의 조기 종료 효과는 환경·구현에 따라 차이가 있다
