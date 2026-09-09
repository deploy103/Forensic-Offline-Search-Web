---
id: FOR-0140
title: "Apache/nginx/syslog timestamp regex: 10/Oct/2000 형식과 연도 없는 syslog"
slug: "apache-nginx-timestamp-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "error.log", "auth.log", "syslog", "IIS log"]
file_paths: ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/auth.log", "/var/log/secure", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: ["HTTP"]
tools: ["grep", "awk", "Python", "PowerShell", "goaccess", "date"]
commands: ["grep -Eo '\\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}(:[0-9]{2}){3} [+-][0-9]{4}\\]' access.log", "awk -F'[][]' '{print $2}' access.log | head", "python3 -c \"from datetime import datetime;print(datetime.strptime('10/Oct/2000:13:55:36 -0700','%d/%b/%Y:%H:%M:%S %z'))\""]
regex_patterns: ["\\[(\\d{2})/([A-Za-z]{3})/(\\d{4}):(\\d{2}):(\\d{2}):(\\d{2}) ([+-]\\d{4})\\]", "\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2}", "^[A-Z][a-z]{2}\\s{1,2}\\d{1,2} \\d{2}:\\d{2}:\\d{2}", "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)", "^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} "]
wireshark_filters: []
tshark_fields: []
log_fields: ["time_local", "time_iso8601", "date", "time", "TimeGenerated"]
file_formats: ["log", "txt"]
primary_terms: ["Apache timestamp regex", "nginx 시각 정규식", "10/Oct/2000 형식"]
keywords: ["Apache timestamp", "nginx timestamp", "CLF", "combined log format", "time_local", "strptime", "%d/%b/%Y", "syslog RFC3164", "연도 없는 로그", "IIS W3C", "월 약어", "시간대 오프셋"]
aliases: ["아파치 시간 정규식", "10/oct/2000", "nginx 시간 형식", "syslog 시간 정규식", "연도가 없다", "mar 14 시간", "웹로그 시간 파싱", "strptime 포맷"]
symptom_keywords: ["웹 로그 시각을 파싱하는 방법을 모르겠다", "syslog 에 연도가 없다", "로그 시각을 정렬할 수 없다", "월이 영어 약어로 나온다", "nginx error 로그 시각 형식이 다르다", "IIS 로그 시간이 9시간 다르다"]
related: ["FOR-0139", "FOR-0141", "FOR-0145", "FOR-0054"]
source_ids: ["SRC-058", "SRC-059", "SRC-060"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Apache/nginx access 로그의 `[10/Oct/2000:13:55:36 -0700]`은 `%d/%b/%Y:%H:%M:%S %z`로 파싱하면 끝나지만, nginx `error.log`(`2026/03/14 07:19:02`)와 syslog RFC 3164(`Mar 14 07:11:02`)는 형식이 다르고 **syslog에는 연도도 시간대도 없다** — 연도는 파일 mtime·회전 파일 이름·앞뒤 문맥으로 추정해야 한다.

## 개념

한 사건을 조사할 때 열게 되는 로그 네 종류가 시각 형식이 전부 다르다. 이 표가 이 글의 전부다.

| 로그 | 예 | strptime 포맷 | 연도 | 시간대 |
| --- | --- | --- | --- | --- |
| Apache/nginx access (CLF·combined) | `[14/Mar/2026:07:19:02 +0900]` | `%d/%b/%Y:%H:%M:%S %z` | 있음 | **오프셋 있음** |
| nginx `$time_iso8601` | `2026-03-14T07:19:02+09:00` | `%Y-%m-%dT%H:%M:%S%z` | 있음 | 오프셋 있음 |
| nginx `error.log` | `2026/03/14 07:19:02 [error] 1234#0: ...` | `%Y/%m/%d %H:%M:%S` | 있음 | **없음** (서버 로컬) |
| Apache `error.log` | `[Sat Mar 14 07:19:02.123456 2026] [php:error] ...` | `%a %b %d %H:%M:%S.%f %Y` | 있음 | **없음** (서버 로컬) |
| syslog RFC 3164 (BSD) | `Mar 14 07:11:02 web01 sshd[2841]: ...` | `%b %d %H:%M:%S` | **없음** | **없음** |
| syslog RFC 5424 | `<34>1 2026-03-14T07:11:02.003+09:00 web01 sshd 2841 - - ...` | `%Y-%m-%dT%H:%M:%S.%f%z` | 있음 | 오프셋 있음 |
| rsyslog `RSYSLOG_FileFormat` | `2026-03-14T07:11:02.123456+09:00 web01 sshd[2841]: ...` | `%Y-%m-%dT%H:%M:%S.%f%z` | 있음 | 오프셋 있음 |
| IIS W3C 확장 | `2026-03-13 22:19:02 GET /admin/ ...` | `%Y-%m-%d %H:%M:%S` | 있음 | **UTC 고정** |

**형식을 확정하지 않고 정규식을 짜기 시작하면 반드시 틀린다.** 로그를 만나면 무조건 첫 줄과 마지막 줄을 먼저 본다.

```bash
head -1 access.log; tail -1 access.log
head -1 error.log
head -1 /var/log/auth.log
```

### CLF 시각 필드 해부

```text
[14/Mar/2026:07:19:02 +0900]
 ^  ^    ^    ^  ^  ^   ^
 |  |    |    |  |  |   +-- 시간대 오프셋 (±HHMM, 콜론 없음)
 |  |    |    |  |  +------ 초   (2자리)
 |  |    |    |  +--------- 분   (2자리)
 |  |    |    +------------ 시   (2자리, 24시간제)
 |  |    +----------------- 연도 (4자리)
 |  +---------------------- 월   (영어 3글자 약어)
 +------------------------- 일   (2자리, 0으로 채움)
```

구분자에 주의한다. **날짜는 `/`, 날짜와 시각 사이도 `/`가 아니라 `:`, 시각 내부도 `:`, 오프셋 앞만 공백**이다. 이 `:`가 날짜와 시각을 잇는 것이 CLF의 특징이고, ISO 형식(`T` 또는 공백)과 다른 지점이다. 전체가 대괄호로 감싸여 있으므로 대괄호를 기준으로 잘라내는 것이 정규식보다 확실하다.

```bash
awk -F'[][]' '{print $2}' access.log | head -3
# 14/Mar/2026:07:19:02 +0900
```

### 월 약어 표

Apache와 nginx는 **C 로케일 영어 약어를 고정으로** 출력한다. 서버 로케일이 한국어여도 `Mar`이지 `3월`이 아니다.

| 약어 | 월 | 약어 | 월 |
| --- | --- | --- | --- |
| `Jan` | 1 | `Jul` | 7 |
| `Feb` | 2 | `Aug` | 8 |
| `Mar` | 3 | `Sep` | 9 |
| `Apr` | 4 | `Oct` | 10 |
| `May` | 5 | `Nov` | 11 |
| `Jun` | 6 | `Dec` | 12 |

```text
(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
```

`Sep`은 `Sept`가 아니다. `%b`로 파싱할 때 **파이썬의 `%b`는 실행 환경의 로케일을 따르므로**, 로케일이 한국어인 머신에서 `Mar`을 파싱하면 실패할 수 있다. 로그 파싱 스크립트에서는 로케일에 의존하지 않는 직접 매핑을 쓴다.

```python
MON = {m: i + 1 for i, m in enumerate(
    'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}
```

### syslog RFC 3164 — 연도가 없다

```text
Mar 14 07:11:02 web01 sshd[2841]: Failed password for root from 203.0.113.77 port 51240 ssh2
^^^^^^ ^^^^^^^^ ^^^^^ ^^^^^^^^^^  ^
|      |        |     |           +-- 메시지
|      |        |     +-------------- 태그[PID]
|      |        +-------------------- 호스트명
|      +----------------------------- 시:분:초 (서버 로컬, 오프셋 없음)
+------------------------------------ 월 약어 + 일 (연도 없음)
```

**연도가 없다는 것이 이 형식의 치명적 함정이다.** 다음 문제가 생긴다.

| 문제 | 결과 |
| --- | --- |
| 연도를 현재 연도로 가정한다 | 1년 이상 회전된 로그를 잘못된 해로 배치한다 |
| 12월/1월 경계 | `Dec 31 23:59` 다음 줄이 `Jan 01 00:00`이면 **연도가 넘어간다.** 같은 해로 두면 정렬이 역순이 된다 |
| 윤년 판정 | `Feb 29`가 있으면 그 해는 윤년이다. 연도 후보를 좁히는 근거가 된다 |
| 시간대가 없다 | 서버 로컬. `/etc/timezone`으로 확정해야 한다 |

일자 필드는 **한 자리 날짜일 때 공백으로 채운다.** `Mar  4 07:11:02`처럼 공백이 두 개다. `cut -c`로 열 위치를 고정하면 이 줄에서 틀어진다. 정규식은 `\s{1,2}` 또는 `\s+`로 받는다.

```text
^([A-Z][a-z]{2})\s{1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^:\[]+)(?:\[(\d+)\])?:
```

연도를 추정하는 근거를 신뢰도 순으로 정리한다.

| 근거 | 방법 | 신뢰도 |
| --- | --- | --- |
| 같은 사건이 다른 로그에도 있다 | ISO 형식 로그·EVTX·웹 로그의 그 줄과 대조 | 최고 |
| 로그 회전 파일 이름 | `auth.log-20260315`, `secure-20260401` | 높음 |
| 파일 mtime/ctime | `stat auth.log` → 마지막 줄의 연도 | 높음 |
| 파일 안의 연도 표기 줄 | `rsyslogd startup`, 커널 부트 메시지, `systemd` 버전 줄 | 중간 |
| `wtmp`/`last` 출력 | 연도가 들어 있다 | 높음 |
| 요일이 함께 있는 다른 로그 | `Sat Mar 14`면 요일-날짜 조합으로 연도 후보가 좁혀진다 | 중간 |
| 문제 지문 | CTF에서는 지문이 곧 근거 | 높음 |

**파일 마지막 줄의 시각이 그 파일의 mtime과 같다**는 성질이 가장 실용적이다. mtime의 연도를 마지막 줄에 부여하고, 뒤에서 앞으로 거꾸로 읽으며 월이 감소하다가 증가로 뒤집히는 지점에서 연도를 1 감소시킨다.

### IIS W3C는 UTC 고정

IIS의 W3C 확장 로그 형식은 `date`와 `time`을 **별도 필드**로, 그리고 **UTC(GMT)로** 기록한다. IIS 관리 콘솔의 "Use local time for file naming and rollover" 옵션은 **파일 이름과 회전 시점만** 로컬로 바꾸며, 로그 안의 `time` 값은 UTC로 남는다.

```text
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2026-03-13 22:19:02 10.0.0.5 GET /admin/ - 80 - 203.0.113.77 Mozilla/5.0 - 403 0 0 15
```

따라서 KST ��경에서 `07:19`에 일어난 일은 IIS 로그에 `22:19`(전날)로 남는다. **웹 로그와 IIS 로그를 나란히 놓고 벽시계 숫자만 비교하면 9시간 어긋난다.**

## 파일 / 경로

| 로그 | 경로 |
| --- | --- |
| Apache access (Debian) | `/var/log/apache2/access.log`, `other_vhosts_access.log` |
| Apache access (RHEL) | `/var/log/httpd/access_log` |
| Apache error | `/var/log/apache2/error.log`, `/var/log/httpd/error_log` |
| nginx access | `/var/log/nginx/access.log` |
| nginx error | `/var/log/nginx/error.log` |
| 로그 형식 정의 | `/etc/nginx/nginx.conf`의 `log_format`, Apache `LogFormat`/`CustomLog` |
| syslog | `/var/log/syslog`(Debian), `/var/log/messages`(RHEL) |
| 인증 | `/var/log/auth.log`(Debian), `/var/log/secure`(RHEL) |
| IIS | `C:\inetpub\logs\LogFiles\W3SVC<사이트ID>\u_exYYMMDD.log` |
| 회전 파일 | `*.1`, `*.2.gz`, `*-20260314`, `*.log.20260314.gz` |

로그 형식이 낯설면 **설정 파일에서 형식 정의를 먼저 읽는다.** `log_format`의 변수 이름이 각 필드의 정체를 알려준다.

```bash
grep -rn 'log_format\|access_log' /etc/nginx/ 2>/dev/null
grep -rn 'LogFormat\|CustomLog' /etc/apache2/ /etc/httpd/ 2>/dev/null
head -5 /path/to/iis.log      # #Fields: 줄이 스키마다
```

## 주요 필드

### 패턴 1 — CLF 시각 (대괄호 포함)

```text
\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `[14/Mar/2026:07:19:02 +0900]`, `[10/Oct/2000:13:55:36 -0700]` |
| 매칭 안 됨 | `[14/Mar/2026:07:19:02]`(오프셋 없는 커스텀 형식), `[2026-03-14T07:19:02+09:00]` |
| 캡처 | 1=일 2=월약어 3=연 4=시 5=분 6=초 7=오프셋 |

명명 그룹 버전이다.

```text
\[(?P<d>\d{2})/(?P<b>[A-Za-z]{3})/(?P<Y>\d{4}):(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2}) (?P<z>[+-]\d{4})\]
```

시간 창을 좁히는 데는 캡처 없이 문자열로 쓰는 편이 빠르다.

```text
\[14/Mar/2026:07:(1[5-9]|2[0-9]):
```

### 패턴 2 — 한 줄 전체 (combined format)

Apache `combined` 형식 한 줄을 통째로 분해한다. Apache 문서의 정의는 다음과 같다.

```text
%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
```

| 기호 | 의미 | 값이 없을 때 |
| --- | --- | --- |
| `%h` | 클라이언트 호스트/IP | |
| `%l` | identd 사용자 (거의 안 씀) | `-` |
| `%u` | HTTP 인증 사용자 | `-` |
| `%t` | 시각 `[...]` | |
| `%r` | 요청 첫 줄 `"GET /x HTTP/1.1"` | |
| `%>s` | 최종 상태 코드 | |
| `%b` | 응답 바이트 (헤더 제외) | `-` (0바이트) |
| `%{Referer}i` | Referer 헤더 | `-` |
| `%{User-Agent}i` | User-Agent 헤더 | `-` |

```text
^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?
```

nginx의 기본 `combined`는 Apache combined와 동일한 필드 순서를 쓰므로 **같은 정규식이 그대로 통한다.**

### 패턴 3 — nginx error.log

```text
^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}) \[(\w+)\] (\d+)#(\d+): (?:\*(\d+) )?(.*)$
```

```text
2026/03/14 07:19:02 [error] 1234#0: *5 open() "/var/www/html/x.php" failed (2: No such file or directory), client: 203.0.113.77, server: _, request: "GET /x.php HTTP/1.1", host: "example.com"
```

| 조각 | 의미 |
| --- | --- |
| `2026/03/14 07:19:02` | **서버 로컬 시각, 오프셋 없음** |
| `[error]` | 로그 레벨 (`debug` `info` `notice` `warn` `error` `crit` `alert` `emerg`) |
| `1234#0` | 워커 PID#TID |
| `*5` | 커넥션 번호. **같은 커넥션의 여러 줄을 묶는 키** |
| `client:`, `request:`, `host:` | 뒤쪽 key-value |

`error.log`의 `client:`와 `request:`를 뽑으면 access 로그와 대조할 수 있다.

```bash
grep -Eo 'client: [0-9.]+' error.log | sort | uniq -c | sort -nr | head
```

### 패턴 4 — Apache error.log

```text
^\[([A-Z][a-z]{2}) ([A-Z][a-z]{2}) (\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d+) (\d{4})\] \[([^\]]+)\](?: \[pid (\d+)(?::tid (\d+))?\])?(?: \[client ([^\]]+)\])? (.*)$
```

```text
[Sat Mar 14 07:19:02.123456 2026] [php:error] [pid 2841] [client 203.0.113.77:51234] PHP Fatal error: ...
```

**요일이 앞에, 연도가 맨 뒤에** 온다. CLF와 순서가 완전히 다르므로 같은 정규식을 쓸 수 없다. 마이크로초가 있다.

### 패턴 5 — syslog RFC 3164

```text
^([A-Z][a-z]{2})\s{1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^:\[]+)(?:\[(\d+)\])?: (.*)$
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `Mar 14 07:11:02 web01 sshd[2841]: ...`, `Mar  4 07:11:02 web01 CRON: ...` |
| 매칭 안 됨 | `2026-03-14T07:11:02.123456+09:00 web01 sshd[2841]: ...` (rsyslog ISO 형식) |
| 캡처 | 1=월약어 2=일 3=시 4=분 5=초 6=호스트 7=태그 8=PID 9=메시지 |

두 형식을 한 패턴으로 받으려면 앞부분을 선택으로 묶는다.

```text
^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))|(?P<bsd>[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?:
```

### strptime 포맷 문자열 표

| 형식 | 예 | 포맷 문자열 | 결과 |
| --- | --- | --- | --- |
| Apache/nginx CLF | `14/Mar/2026:07:19:02 +0900` | `%d/%b/%Y:%H:%M:%S %z` | aware |
| CLF (대괄호 포함) | `[14/Mar/2026:07:19:02 +0900]` | `[%d/%b/%Y:%H:%M:%S %z]` | aware |
| nginx `$time_iso8601` | `2026-03-14T07:19:02+09:00` | `%Y-%m-%dT%H:%M:%S%z` | aware |
| nginx error | `2026/03/14 07:19:02` | `%Y/%m/%d %H:%M:%S` | **naive** |
| Apache error | `Sat Mar 14 07:19:02.123456 2026` | `%a %b %d %H:%M:%S.%f %Y` | **naive** |
| syslog RFC 3164 | `Mar 14 07:11:02` | `%b %d %H:%M:%S` | **naive + 연도 1900** |
| syslog + 연도 주입 | `2026 Mar 14 07:11:02` | `%Y %b %d %H:%M:%S` | naive |
| rsyslog ISO | `2026-03-14T07:11:02.123456+09:00` | `%Y-%m-%dT%H:%M:%S.%f%z` | aware |
| IIS W3C | `2026-03-13 22:19:02` | `%Y-%m-%d %H:%M:%S` | naive (실제 UTC) |

`%z`는 `+0900`·`+09:00`·`Z`를 모두 받는다(Python 3.7+). `%b`는 로케일 의존이므로 스크립트 앞에서 로케일을 고정하거나 직접 매핑을 쓴다. **`%b %d %H:%M:%S`만으로 파싱하면 연도가 1900이 되어 모든 계산이 무의미해진다.**

## 빠른 명령

```bash
awk -F'[][]' '{print $2}' access.log | head -3
```

```bash
# 1) 형식 확정 -- 무조건 먼저
head -1 access.log; head -1 error.log; head -1 /var/log/auth.log

# 2) CLF 시각만 뽑기 (정규식)
grep -Eo '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}(:[0-9]{2}){3} [+-][0-9]{4}\]' access.log | head

# 3) CLF 시각만 뽑기 (대괄호 기준 -- 오탐 0, 더 빠르다)
awk -F'[][]' '{print $2}' access.log | sort -u | head

# 4) 오프셋 종류 확인 (여러 개면 서버가 여러 대이거나 DST 가 걸쳐 있다)
awk -F'[][]' '{print $2}' access.log | awk '{print $2}' | sort | uniq -c

# 5) 분 단위 요청 추이 -- 공격 시간 창 찾기
awk -F'[][]' '{print substr($2,1,17)}' access.log | sort | uniq -c | sort -k2 | tail -30
# 14/Mar/2026:07:19 형태로 잘라 분당 건수를 센다

# 6) 시간 창으로 좁히기 (문자열 매칭으로 충분하다)
grep -E '\[14/Mar/2026:07:(1[5-9]|2[0-9]):' access.log

# 7) 시간순 정렬 -- CLF 는 사전순 정렬이 시간순이 아니다 (일/월/년 순서)
awk -F'[][]' '{print $2"\t"$0}' access.log |
  while IFS=$'\t' read -r t rest; do printf '%s\t%s\n' "$(date -d "$(echo "$t" | sed 's|:| |;s|/|-|g')" +%s 2>/dev/null)" "$rest"; done |
  sort -n | cut -f2-
# 실전에서는 아래 Python 으로 처리하는 편이 빠르고 정확하다

# 8) syslog 연도 추정 근거 수집
stat -c '%y %n' /var/log/auth.log*
ls -l /var/log/auth.log*
last -F -f /var/log/wtmp | head -5        # 연도가 들어 있다
grep -m1 -i 'rsyslogd.*start' /var/log/syslog

# 9) syslog 를 시간순으로 -- 월 약어를 숫자로 바꿔야 sort 가 된다
awk 'BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",m," ");
          for(i=1;i<=12;i++) M[m[i]]=sprintf("%02d",i)}
     {printf "%s-%02d %s\t%s\n", M[$1], $2, $3, $0}' /var/log/auth.log | sort | cut -f2-

# 10) nginx error.log 에서 클라이언트별 오류 수
grep -Eo 'client: [0-9.]+' /var/log/nginx/error.log | sort | uniq -c | sort -nr | head

# 11) 회전 파일 포함 전수 검색
zgrep -h 'Failed password' /var/log/auth.log* | wc -l
```

**CLF는 사전순 정렬이 시간순이 아니다.** `01/Apr/2026`이 `31/Mar/2026`보다 앞에 온다. ISO 형식과 정반대이므로 `sort`로 병합하려면 반드시 변환한다.

```python
import re, os
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))
MON = {m: i + 1 for i, m in enumerate(
    'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}

CLF = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<d>\d{2})/(?P<b>[A-Za-z]{3})/(?P<Y>\d{4}):'
    r'(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2}) (?P<z>[+-]\d{4})\] '
    r'"(?P<method>\S+) (?P<uri>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\d+|-)'
)
NGX_ERR = re.compile(r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<lvl>\w+)\] ')
BSD     = re.compile(
    r'^(?P<b>[A-Z][a-z]{2})\s{1,2}(?P<d>\d{1,2}) (?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2}) '
    r'(?P<host>\S+) (?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$'
)

def clf_dt(m):
    off = m['z']
    tz = timezone(timedelta(hours=int(off[:3]), minutes=int(off[0] + off[3:])))
    return datetime(int(m['Y']), MON[m['b']], int(m['d']),
                    int(m['H']), int(m['M']), int(m['S']), tzinfo=tz)

def bsd_rows(path, tz=KST):
    """연도가 없는 syslog: 파일 mtime 의 연도를 마지막 줄에 주고 거꾸로 올라간다."""
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    year = datetime.fromtimestamp(os.path.getmtime(path), tz).year
    out, prev_mon = [], None
    for line in reversed(lines):
        m = BSD.match(line)
        if not m:
            continue
        mon = MON[m['b']]
        if prev_mon is not None and mon > prev_mon:   # 뒤로 갈수록 월이 커지면
            year -= 1                                  # 연도 경계를 넘었다
        prev_mon = mon
        out.append((datetime(year, mon, int(m['d']), int(m['H']), int(m['M']),
                             int(m['S']), tzinfo=tz), m['tag'].strip(), m['msg']))
    return list(reversed(out))

# 병합: 전부 UTC aware 로 정규화한 뒤 정렬
rows = []
for line in open('access.log', encoding='utf-8', errors='replace'):
    m = CLF.match(line)
    if m:
        rows.append((clf_dt(m).astimezone(timezone.utc), 'web',
                     f"{m['ip']} {m['method']} {m['uri']} {m['status']} {m['size']}"))
for dt, tag, msg in bsd_rows('/var/log/auth.log'):
    rows.append((dt.astimezone(timezone.utc), 'auth', f'{tag}: {msg}'))

for dt, src, msg in sorted(rows):
    print(dt.astimezone(KST).strftime('%Y-%m-%d %H:%M:%S'), f'{src:5s}', msg[:100])
```

```powershell
# CLF 시각 파싱 -- ParseExact 로 형식을 고정한다 (정규식은 작은따옴표)
$re = '^(?<ip>\S+) \S+ (?<user>\S+) \[(?<t>[^\]]+)\] "(?<m>\S+) (?<u>\S+)[^"]*" (?<st>\d{3}) (?<sz>\d+|-)'
$fmt = 'dd/MMM/yyyy:HH:mm:ss zzz'
$inv = [System.Globalization.CultureInfo]::InvariantCulture   # 월 약어는 영어 고정

Select-String -Path .\access.log -Pattern $re | ForEach-Object {
  $g = $_.Matches[0].Groups
  # +0900 -> +09:00 (zzz 는 콜론을 요구한다)
  $t = $g['t'].Value -replace '([+-]\d{2})(\d{2})$', '$1:$2'
  [pscustomobject]@{
    UtcTime = [datetimeoffset]::ParseExact($t, $fmt, $inv).UtcDateTime
    KstTime = [datetimeoffset]::ParseExact($t, $fmt, $inv).ToOffset('09:00').ToString('yyyy-MM-dd HH:mm:ss')
    Ip      = $g['ip'].Value
    Method  = $g['m'].Value
    Uri     = $g['u'].Value
    Status  = [int]$g['st'].Value
  }
} | Sort-Object UtcTime | Format-Table -AutoSize

# IIS 로그는 UTC 이므로 KST 컬럼을 만들어 둔다
Import-Csv .\iis.csv -Delimiter ' ' | Select-Object *,
  @{n='KST'; e={ ([datetime]::ParseExact("$($_.date) $($_.time)", 'yyyy-MM-dd HH:mm:ss', $inv)).AddHours(9) }}
```

## 함께 보는 artifact

| 시각을 확정한 뒤 | 다음 목표 |
| --- | --- |
| 웹 요청 시각 (KST) | 같은 순간의 `auth.log`·EVTX를 UTC 기준으로 재검색 |
| 오프셋이 없는 로그 | 시스템 시간대 확정 ([FOR-0054](./system-timezone.html)) |
| 상태 코드와 크기 | 성공/실패 판정 |
| 공격 IP | IPv4 추출·빈도 집계 ([FOR-0128](./ipv4-regex.html)) |
| `error.log`의 `client:` | access 로그의 같은 IP 요청 흐름 |
| nginx `*N` 커넥션 번호 | 같은 커넥션의 error 로그 줄 전체 |
| 업로드 파일 경로 | 디스크상 생성 시각 (`$MFT` / `stat`) |
| Windows 쪽 로그 | EVTX `SystemTime`은 UTC. 변환 후 대조 ([FOR-0083](./event-4624-logon.html)) |

## 흔한 실수

- **syslog에 연도가 있다고 가정하는 것.** `%b %d %H:%M:%S`로 파싱하면 연도가 **1900**이 된다. 정렬은 되지만 다른 로그와의 상관분석이 전부 깨진다. 연도를 명시적으로 주입한다.
- **12월/1월 경계를 무시하는 것.** `Dec 31` 다음 `Jan 01`은 연도가 바뀐 것이다. 파일 전체에 같은 연도를 주면 1월 줄들이 12월 줄들보다 앞으로 정렬되어 타임라인이 역전된다.
- **CLF를 사전순으로 정렬하는 것.** `일/월/년` 순서라서 `01/Apr` < `31/Mar`가 된다. ISO와 정반대다. 반드시 datetime으로 변환한 뒤 정렬한다.
- **`cut -c`로 syslog 시각을 자르는 것.** 한 자리 날짜(`Mar  4`)에서 공백이 하나 더 들어가 한 칸씩 틀어진다. `awk`의 필드나 `\s{1,2}` 정규식을 쓴다.
- **`%b`의 로케일 의존을 잊는 것.** 한국어 로케일 환경에서 `datetime.strptime('Mar', '%b')`가 실패할 수 있다. 로그의 월 약어는 서버 로케일과 무관하게 영어이므로 파서 쪽을 `InvariantCulture`/직접 매핑으로 고정한다.
- **`+0900`을 `zzz`(콜론 필요) 포맷에 그대로 넣는 것.** .NET `ParseExact`의 `zzz`는 `+09:00`을 요구한다. 콜론을 삽입하거나 `K`/`DateTimeOffset.Parse`를 쓴다.
- **nginx `error.log`와 `access.log`의 시각 형식이 같다고 가정하는 것.** `access.log`는 `14/Mar/2026:07:19:02 +0900`, `error.log`는 `2026/03/14 07:19:02`이다. 오프셋 유무까지 다르다.
- **IIS 로그를 로컬 시간으로 읽는 것.** UTC 고정이다. KST 사건 시각과 9시간 어긋난다. "Use local time for file naming and rollover"는 파일 이름만 바꾼다.
- **`%b`를 4글자로 쓰는 것.** `Sept`가 아니라 `Sep`이다. 3글자 고정이다.
- **회전 로그를 빼놓는 것.** `access.log`만 보면 사고 당일이 이미 `access.log.1`이나 `.2.gz`로 넘어간 경우 아무것도 안 나온다. `zgrep -h ... access.log*`.
- **커스텀 `log_format`을 표준으로 가정하는 것.** `log_format`에 `$http_x_forwarded_for`나 응답 시간이 추가되면 필드 번호가 밀린다. `awk $9`가 상태 코드가 아니게 된다. 설정 파일을 먼저 읽는다.
- **DST 전환을 무시하는 것.** 미국·유럽 서버는 3월/11월에 오프셋이 바뀐다. 같은 로그 안에 `-0700`과 `-0800`이 섞여 있으면 UTC로 정규화하지 않는 한 정렬이 틀린다.

## mini example

```text
문제:
"웹 서버 access.log 와 auth.log 를 대조해
 웹셸 요청 이후 SSH 로 접속한 시각(KST)을 구하세요."
첨부: access.log (41,882줄), auth.log (128,441줄)

1. 형식 확정
   $ head -1 access.log
   203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199
   $ head -1 auth.log
   Mar 14 07:11:02 web01 sshd[2841]: Failed password for invalid user admin from 203.0.113.77 port 51234 ssh2

   access.log = CLF + +0900, auth.log = RFC 3164 (연도 없음, 오프셋 없음).

2. 첫 시도 (실패):
   $ grep '2026-03-14' auth.log
   (0건)

   이유: RFC 3164 형식에는 `2026-03-14` 같은 표기가 아예 없다.
        `Mar 14` 로 찾아야 하고, 연도는 파일 어디에도 없다.

   $ grep -c '^Mar 14 ' auth.log
   9834

3. 두 번째 시도 (실패) -- 연도를 붙이지 않고 파싱했다
   >>> from datetime import datetime
   >>> datetime.strptime('Mar 14 07:11:02', '%b %d %H:%M:%S')
   datetime.datetime(1900, 3, 14, 7, 11, 2)

   연도가 1900 이 되어 access.log(2026) 와 병합하면
   auth.log 전체가 126년 전으로 밀려 상관분석이 불가능하다.

4. 연도 확정
   $ stat -c '%y %n' auth.log auth.log.1
   2026-03-15 06:25:11 auth.log
   2026-03-08 06:25:09 auth.log.1
   $ last -F -f /var/log/wtmp | head -2
   svc_backup pts/0  203.0.113.77  Sat Mar 14 07:18:39 2026 - Sat Mar 14 09:02:11 2026

   mtime 과 wtmp 가 모두 2026 년을 가리킨다. 연도 = 2026 확정.
   `Dec`/`Jan` 이 섞여 있지 않으므로 연도 경계 보정도 필요 없다.

5. 세 번째 시도 (실패) -- 시간대를 확인하지 않고 벽시계로 비교했다
   웹셸 요청 07:20:15 (+0900), SSH 성공 07:18:39.
   "SSH 접속이 웹셸보다 96초 먼저? 그럼 웹셸과 무관하다" 라고 결론.

   $ cat /etc/timezone
   Asia/Seoul

   auth.log 도 KST 였다. 즉 순서 자체는 맞게 읽었지만
   결론이 틀렸다 -- SSH 무차별 대입이 웹셸보다 먼저 성공한 것이고,
   두 침투 경로가 별개였다. 시간대를 확인하지 않았다면
   "auth.log 는 UTC 겠지" 라고 가정해 09:00 대로 밀어 놓고
   완전히 다른 시나리오를 썼을 것이다.

6. 두 로그를 UTC 로 정규화해 병합
   $ awk -F'[][]' '{print $2}' access.log | awk '{print $2}' | sort -u
   +0900
   -> access.log 오프셋 단일. auth.log 는 /etc/timezone 근거로 +0900.

   병합 결과(발췌, KST 표시):
   07:11:02  auth  sshd  Failed password for invalid user admin from 203.0.113.77
   07:18:39  auth  sshd  Accepted password for svc_backup from 203.0.113.77
   07:19:02  web   203.0.113.77 GET /admin/ 403 199
   07:19:44  web   203.0.113.77 POST /upload.php 200 87
   07:20:15  web   203.0.113.77 GET /uploads/av4tar.php?cmd=id 200 42

7. 교차검증
   $ TZ=UTC date -d '14 Mar 2026 07:18:39 +0900' --iso-8601=seconds
   2026-03-13T22:18:39+00:00
   $ TZ=UTC date -d '14 Mar 2026 07:20:15 +0900' --iso-8601=seconds
   2026-03-13T22:20:15+00:00
   UTC 로도 순서가 같다.

정답: SSH 접속 성공 2026-03-14 07:18:39 KST (2026-03-13 22:18:39 UTC),
      svc_backup 계정, 203.0.113.77
      -- 웹셸 실행(07:20:15)보다 96초 먼저이며 별개의 침투 경로다
```

3단계와 5단계가 핵심이다. **연도 없는 로그를 파싱하면 조용히 1900년이 되고, 시간대를 확인하지 않으면 순서가 맞아도 결론이 틀린다.**

## 출처

- SRC-058 — Apache HTTP Server, Log Files: Common/Combined Log Format의 `%h %l %u %t "%r" %>s %b` 정의, `%t`의 기본 표기가 `[day/month/year:hour:minute:second zone]`이라는 규정, `%b`가 값이 없을 때 `-`로 기록된다는 점
- SRC-059 — nginx `ngx_http_log_module`: 기본 `combined` `log_format` 정의, `$time_local`·`$time_iso8601` 변수의 형식
- SRC-060 — RFC 5424, The Syslog Protocol: 구조화된 syslog의 `TIMESTAMP`가 RFC 3339 형식이라는 규정, 그리고 이전 BSD 형식과의 차이(연도·시간대 부재)에 관한 서술
- BSD syslog 형식(`Mmm dd hh:mm:ss`, 한 자리 날짜의 공백 패딩)의 원 규격은 RFC 3164이며 `research/sources.json`에 등재되어 있지 않다. 본문의 형식 서술은 RFC 5424의 대비 서술과 실물 로그를 근거로 했으므로 RFC 3164 원문 확인을 권한다
- nginx `error.log` 형식과 Apache `error.log`의 `ErrorLogFormat` 기본값은 공식 문서에 완전한 문법이 명시되어 있지 않아 실물 로그를 근거로 정리했다. 버전에 따라 필드가 추가될 수 있으므로 대상 서버의 실제 로그로 확인할 것
- IIS W3C 로그가 UTC로 기록된다는 점과 "Use local time for file naming and rollover" 옵션의 범위는 Microsoft 문서에서 재확인할 것 (해당 문서는 `sources.json`에 미등재)
