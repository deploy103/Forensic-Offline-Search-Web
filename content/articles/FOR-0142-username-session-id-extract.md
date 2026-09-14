---
id: FOR-0142
title: "로그에서 username과 session id 추출하기: 계정과 세션을 엮는 정규식"
slug: "username-session-id-extract"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["auth.log", "sudo 로그", "Apache access log", "IIS W3C 로그", "EVTX TargetUserName", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "Logon ID"]
file_paths: ["/var/log/auth.log", "/var/log/secure", "/var/log/apache2/access.log", "/var/log/nginx/access.log", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: ["SSH", "HTTP", "HTTPS"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "awk", "EvtxECmd"]
commands: ["grep -oE 'Accepted \\S+ for \\S+ from [0-9.]+ port [0-9]+' auth.log", "Select-String -Path access.log -Pattern 'user(?:name)?=([A-Za-z0-9_.-]+)'", "python3 -c \"import re; print(re.findall(r'PHPSESSID=([a-z0-9]{26,32})', open('access.log').read()))\""]
regex_patterns: ["Accepted \\S+ for (\\S+) from ([\\d.]+) port (\\d+)", "Failed password for (invalid user )?(\\S+) from ([\\d.]+)", "sudo:\\s*(\\S+)\\s*:\\s*TTY=", "user(?:name)?[=:]\\s*\"?([A-Za-z0-9_.@-]+)\"?", "PHPSESSID=([a-z0-9]{26,32})", "JSESSIONID=([A-Z0-9]{32})", "ASP\\.NET_SessionId=([a-z0-9]{24})", "session[_-]?id[=:]\\s*\"?([A-Za-z0-9._-]{16,64})\"?", "Logon ID:\\s*(0x[0-9a-fA-F]+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["TargetUserName", "SubjectUserName", "TargetLogonId", "cs-username", "%u", "user", "sessionid"]
file_formats: ["log", "csv", "evtx", "txt"]
primary_terms: ["username 정규식", "session id 추출"]
keywords: ["username 정규식", "session id 추출", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "Logon ID", "TargetUserName", "sudo 로그", "auth.log 사용자", "세션 아이디", "로그 계정 추출", "cs-username"]
aliases: ["로그에서 아이디 뽑기", "누가 로그인했는지", "세션 아이디 정규식", "session id 정규식", "사용자 이름 정규식", "로그인 계정 추출", "쿠키 세션값 찾기"]
symptom_keywords: ["로그에서 계정 이름만 뽑고 싶다", "세션 아이디 형식을 모르겠다", "여러 로그의 사용자를 하나로 묶고 싶다", "익명 사용자와 실사용자를 구분하고 싶다", "세션 아이디로 같은 사람인지 확인하고 싶다"]
related: ["FOR-0104", "FOR-0121", "FOR-0083", "FOR-0193"]
source_ids: ["SRC-062", "SRC-001", "SRC-058", "SRC-060"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

username과 session id는 로그마다 표기 위치와 형식이 다르지만, **"이 계정이 이 세션으로 무엇을 했는가"를 재구성하려면 결국 둘을 정규식으로 뽑아 같은 표에 올려야** 한다 — SSH/sudo는 라인 안 고정 위치, 웹 로그는 쿼리스트링/쿠키, EVTX는 필드, 이 세 갈래를 구분해서 접근한다.

## 어떤 문제에서 필요한가

- "이 로그에서 로그인에 성공한 계정을 모두 나열하라"
- "특정 세션 ID로 이루어진 행위를 전부 찾아라"
- 웹 로그에 IP는 있는데 계정이 안 보이고, 세션 쿠키로만 사용자를 구분해야 하는 문제
- 여러 서버의 로그를 계정 하나로 엮어 침해 범위를 판단해야 하는 문제
- `auth.log`의 `Failed password`가 수천 줄이라 유효 계정만 추려야 하는 문제

계정 이름이 나온 뒤 그 계정의 Windows 로그온 세션 활동을 계속 추적하려면 [FOR-0104](./logon-id-session-linking.html)로 넘어간다. 이 글은 **여러 형식의 로그에서 계정/세션 값을 정규식으로 뽑아내는 단계**까지다.

## 문제에서 처음 볼 단서

1. 로그 첫 줄의 형식을 본다 — `Mon DD HH:MM:SS host sshd[pid]:` 형태면 syslog 계열, `IP - - [날짜] "GET ..."` 형태면 웹 access log
2. `Accepted`/`Failed password`/`session opened`가 보이면 SSH 인증 로그
3. `sudo:` 로 시작하는 줄이 있으면 권한 상승 로그
4. URL에 `PHPSESSID=`, `JSESSIONID=`, `sid=`, `token=` 이 보이면 세션이 쿠키가 아니라 URL로 전달되고 있다는 뜻 — 이건 그 자체로 취약점 정황이다
5. EVTX가 첨부되어 있으면 `TargetUserName`/`SubjectUserName`이 있는 4624/4625/4672를 본다

## 30초 절차

```bash
grep -oE 'Accepted \S+ for \S+ from [0-9.]+ port [0-9]+' auth.log
```

성공/실패를 한 번에 계정별로 세면 그 다음이 빨라진다.

```bash
grep -E 'Accepted|Failed password' auth.log |
  grep -oE '(Accepted|Failed password) \S+ for (invalid user )?[A-Za-z0-9_.-]+ from [0-9.]+' |
  sort | uniq -c | sort -nr
```

## 상세 절차

### 1단계 — 로그 종류별 username 위치

username이 **어디에 박혀 있는지**가 형식마다 다르다. 먼저 표로 정리한다.

| 로그 종류 | username이 있는 형태 | 정규식 |
| --- | --- | --- |
| SSH 인증 성공 | `Accepted password for jhkim from 203.0.113.5 port 51422 ssh2` | `Accepted \S+ for (\S+) from ([\d.]+) port (\d+)` |
| SSH 인증 실패 | `Failed password for invalid user admin from 203.0.113.5 port 51423` | `Failed password for (invalid user )?(\S+) from ([\d.]+)` |
| sudo | `sudo: jhkim : TTY=pts/0 ; PWD=/home/jhkim ; USER=root ; COMMAND=/bin/cat /etc/shadow` | `sudo:\s*(\S+)\s*:\s*TTY=` |
| su | `su: pam_unix(su:session): session opened for user root by jhkim(uid=1000)` | `session opened for user (\S+) by (\S+)` |
| Apache/nginx combined | 세 번째 필드(`%u`, 대부분 `-`) | `^\S+ \S+ (\S+) \[` |
| 애플리케이션 로그(JSON/텍스트) | `user=jhkim`, `"username":"jhkim"` | `user(?:name)?[=:]\s*"?([A-Za-z0-9_.@-]+)"?` |
| IIS W3C | `cs-username` 컬럼 (필드 순서는 로그 헤더 `#Fields:` 로 확인) | 컬럼 인덱스로 추출 |
| EVTX | `TargetUserName`/`SubjectUserName` 필드 | XML/CSV 필드 매칭 |

**Apache/nginx의 `%u`는 거의 항상 `-`다.** HTTP Basic 인증을 쓰는 사이트가 아니면 이 필드로 계정을 못 얻는다. 웹앱 로그인은 대개 애플리케이션 자체 로그(JSON/텍스트)나 세션 쿠키로만 계정을 알 수 있다.

### 2단계 — 세션 ID 형식 식별

세션 ID는 프레임워크마다 길이와 문자 집합이 정해져 있다. 형식만 보고도 어떤 스택인지 추정할 수 있다.

| 이름 | 형식 | 예시 | 프레임워크 |
| --- | --- | --- | --- |
| `PHPSESSID` | 소문자 영숫자 26~32자 | `8f3ha2m9c1x0k5p7q2r4s6t8u0v1` | PHP |
| `JSESSIONID` | 대문자 영숫자 32자(뒤에 `.node1` 등 라우팅 접미사) | `A1B2C3D4E5F6...32자` | Java(Servlet) |
| `ASP.NET_SessionId` | 소문자 영숫자 24자 | `abcd1234efgh5678ijkl9012` | ASP.NET |
| `connect.sid` | `s%3A` + base64 유사 문자열 + 서명 | `s%3Axxxxx.yyyyy` | Node.js Express |
| `laravel_session` | base64 유사 긴 문자열 | - | Laravel |
| Windows Logon ID | `0x` + 16진수 | `0x1a2b3c` | Windows 로그온 세션(EVTX) |
| 커스텀 토큰 | 대개 UUID/GUID 또는 32~64자 hex | `3fa85f64-5717-...` | 자체 구현 |

```text
PHPSESSID=([a-z0-9]{26,32})
JSESSIONID=([A-Z0-9]{32})
ASP\.NET_SessionId=([a-z0-9]{24})
session[_-]?id[=:]\s*"?([A-Za-z0-9._-]{16,64})"?
[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
```

**세션 ID 자체는 계정을 담고 있지 않다.** 세션 ID로 사용자를 알려면 그 세션이 **로그인에 성공한 순간의 로그 행**과 짝지어야 한다. 이것이 이 글의 핵심 작업이다.

### 3단계 — grep / ripgrep

```bash
# SSH 성공 계정 + IP + 포트를 캡처 그룹으로
grep -oP 'Accepted \S+ for \K\S+(?= from ([\d.]+) port)' auth.log

# 캡처 그룹 3개를 한 번에 표로 (rg -o 는 그룹 전체 매치만 출력하므로 -r 로 치환)
rg -oP 'Accepted \S+ for (\S+) from ([\d.]+) port (\d+)' auth.log \
  --replace '$1 $2 $3'

# sudo 사용자만
grep -oP 'sudo:\s*\K\S+(?=\s*:\s*TTY=)' auth.log | sort | uniq -c | sort -nr

# 웹 로그의 PHPSESSID 전체 (URL, Set-Cookie, Cookie 헤더 모두)
grep -oE 'PHPSESSID=[a-z0-9]{26,32}' access.log | sort -u
```

`-P`(PCRE)가 없으면 `\K`와 lookahead를 못 쓴다. macOS의 기본 `grep`은 PCRE가 안 되므로 `ripgrep`이 더 안전하다([FOR-0114](./ripgrep.html)).

### 4단계 — PowerShell

```powershell
# SSH 로그 파일(WSL/Linux 이미지에서 추출한 것)에서 성공 계정
Select-String -Path .\auth.log -Pattern 'Accepted \S+ for (\S+) from ([\d.]+) port (\d+)' |
  ForEach-Object { $_.Matches } |
  Select-Object @{n='User';e={$_.Groups[1].Value}}, @{n='Ip';e={$_.Groups[2].Value}}

# 애플리케이션 로그의 세션 아이디 수집
Select-String -Path .\app.log -Pattern 'session[_-]?id[=:]\s*"?([A-Za-z0-9._-]{16,64})"?' -AllMatches |
  ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique

# EVTX 에서 TargetUserName 뽑기 (4624/4625)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx'; Id=4624,4625} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; Id=$_.Id; User=$d['TargetUserName']; LogonId=$d['TargetLogonId'] }
  }
```

정규식은 항상 작은따옴표로 쓴다. 큰따옴표 안의 `$1`, `$(...)` 는 PowerShell 변수/서브표현식으로 해석되어 조용히 깨진다.

### 5단계 — Python

```python
import re, collections

pat_ssh_ok  = re.compile(r'Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)')
pat_ssh_bad = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)')
pat_sess    = re.compile(r'(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=([A-Za-z0-9._%-]{16,64})')

text = open('auth.log', encoding='utf-8', errors='replace').read()

ok = [m.groupdict() for m in pat_ssh_ok.finditer(text)]
bad_users = collections.Counter(m.group('user') for m in pat_ssh_bad.finditer(text))

print('성공 로그인:', ok[:5])
print('실패 시도 상위 계정:', bad_users.most_common(5))

# 로그인 성공 라인의 계정 <-> 세션 아이디를 시간 순서로 이어 붙이는 것은
# 정규식만으로는 안 된다 - 두 이벤트를 시간 창으로 묶어야 한다 (아래 상세 절차 6단계)
```

`named group`(`?P<user>`)을 쓰면 이후 여러 패턴을 합쳐도 열 이름이 안 흔들린다([FOR-0124](./python-named-group.html)).

### 6단계 — username과 session id를 시간으로 묶는다 (이 글의 핵심)

로그인 성공 이벤트에는 보통 세션 ID가 **같은 줄에 없다.** 세션 ID는 그 다음 응답의 `Set-Cookie` 헤더나 애플리케이션 로그의 별도 줄에 있다. 그래서 정규식 두 번을 각각 돌린 뒤 **시간 창으로 조인**해야 한다.

```python
import re
from datetime import datetime, timedelta

logins = []   # (시각, 계정, ip)
for line in open('app.log'):
    m = re.search(r'\[(?P<ts>[\d\-T:]+)\].*login success.*user=(?P<user>\S+).*ip=(?P<ip>[\d.]+)', line)
    if m:
        logins.append((datetime.fromisoformat(m['ts']), m['user'], m['ip']))

sessions = []  # (시각, session_id, ip)
for line in open('app.log'):
    m = re.search(r'\[(?P<ts>[\d\-T:]+)\].*Set-Cookie.*PHPSESSID=(?P<sid>[a-z0-9]{26,32}).*ip=(?P<ip>[\d.]+)', line)
    if m:
        sessions.append((datetime.fromisoformat(m['ts']), m['sid'], m['ip']))

# 같은 ip, 로그인 시각 ±2초 이내의 세션 발급을 그 계정 것으로 판정
window = timedelta(seconds=2)
for lt, user, ip in logins:
    match = [s for (st, sid, sip) in sessions if sip == ip and abs((st - lt).total_seconds()) <= window.total_seconds()]
```

핵심은 **정규식으로는 값만 뽑고, 조인은 시각+IP(또는 계정)로 한다**는 것이다. 정규식 하나로 "누가 이 세션인가"까지 답이 나온다고 기대하면 안 된다.

## 출력 필드 해석

| 값 | 주의할 점 |
| --- | --- |
| `Failed password for invalid user X` | `invalid user`가 붙으면 시스템에 **존재하지 않는 계정**에 대한 시도다. 존재하는 계정에 대한 실패와 구분해야 무차별 대입 대상 계정을 좁힐 수 있다 |
| `Accepted publickey for X` | 비밀번호가 아니라 SSH 키로 인증했다. `Accepted password`와 공격 시나리오가 다르다 |
| `sudo: X : ... USER=root` | `X`가 실행자, `USER=`가 **전환 대상**이다. 둘을 바꿔 읽으면 권한 상승 방향이 반대로 해석된다 |
| `%u`가 `-` | 인증 없는 요청이거나 애플리케이션 레벨 인증(쿠키/세션)이라 웹서버가 계정을 모른다 |
| `JSESSIONID`에 `.node1` 접미사 | 로드밸런서 라우팅 정보다. 세션을 비교할 때 접미사를 떼고 비교해야 같은 세션이 매칭된다 |
| `session_id`가 로그인 실패 직후에도 발급됨 | 세션 고정(session fixation) 취약점 정황 — 로그인 전후로 세션 ID가 안 바뀌는지 확인 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| 성공 계정 + 시각 | EVTX 4624 (Windows면) ([FOR-0083](./event-4624-logon.html)) | `TargetLogonId`로 그 세션의 이후 행위 전체 |
| `TargetLogonId` | [FOR-0104](./logon-id-session-linking.html) | 같은 세션의 4688/4672/5145 |
| 세션 쿠키 값 | pcap의 `http.cookie` | 그 세션으로 실제 오간 요청 전부 |
| 세션 쿠키 값 | 브라우저 `Cookies` DB ([FOR-0193](./chrome-cookies.html)) | 그 값이 실제 저장돼 있었는지 |
| 계정 이름 | SAM/`ProfileList`, `Login Data`의 `username_value` | 로컬 계정 존재 여부·비밀번호 저장 여부 |
| 유효 계정 목록(무차별 대입 통과) | 그 계정의 이후 4688/명령 실행 | 침투 성공 여부 |

## 흔한 함정

- **`%u`(Apache/nginx)를 보고 계정이 없다고 단정하는 것** → HTTP Basic 인증이 아니면 원래 `-`다. 웹앱 로그인은 애플리케이션 로그나 세션 쿠키로 찾아야 한다.
- **`Failed password`만 세고 `invalid user`를 구분하지 않는 것** → 존재하지 않는 계정에 대한 시도와 존재하는 계정에 대한 시도는 공격의 의미가 다르다. `(invalid user )?` 캡처 그룹으로 분리한다.
- **`sudo:`의 실행자와 `USER=` 전환 대상을 바꿔 읽는 것** → 방향이 반대로 서술되면 "권한 상승한 계정"이 틀린다.
- **세션 ID 정규식 하나로 계정까지 나온다고 기대하는 것** → 세션 ID에는 계정 정보가 없다. 로그인 성공 이벤트와 시간/IP로 조인해야 한다.
- **`JSESSIONID`의 라우팅 접미사(`.node1`)를 포함한 채로 비교하는 것** → 같은 세션인데 다른 값으로 보여 매칭이 깨진다. 접미사를 잘라내고 비교한다.
- **대소문자를 무시하고 계정을 집계하는 것** → Linux 계정명은 대소문자를 구분한다. `Admin`과 `admin`을 합치면 별개의 시도 횟수가 왜곡된다.
- **로그 회전(`auth.log.1`, `auth.log.2.gz`)을 빼먹는 것** → 공격이 자정을 넘기면 최신 파일에 처음 몇 분이 없다. 회전된 파일도 함께 `zgrep`으로 훑는다.
- **웹 로그의 세션 쿠키가 URL 쿼리스트링에도 나올 수 있음을 놓치는 것** → `Cookie:` 헤더만 찾으면 URL 파라미터로 전달된 세션(`;jsessionid=`)을 놓친다.

## 교차검증

```bash
# 1) SSH 성공 계정과 그 직후 sudo 사용 여부
grep -oP 'Accepted \S+ for \K\S+(?= from)' auth.log | sort -u > ok_users.txt
grep -oP 'sudo:\s*\K\S+(?=\s*:)' auth.log | sort -u > sudo_users.txt
comm -12 ok_users.txt sudo_users.txt

# 2) 같은 IP가 여러 계정 이름을 시도했는가 (계정 스프레이 정황)
grep -oP 'Failed password for (invalid user )?\K\S+(?= from ([\d.]+))' auth.log | sort -u | wc -l

# 3) 웹 로그의 세션 아이디가 로그인 성공 전후로 바뀌었는가 (세션 고정 확인)
grep -oE 'PHPSESSID=[a-z0-9]{26,32}' access.log | sort -u | wc -l
```

동일 계정이 SSH 로그의 성공 목록과 EVTX 4624의 `TargetUserName`, 웹앱 로그의 로그인 성공 계정 세 군데 모두에 나오면 그 계정의 활동을 확정적으로 좁힐 수 있다.

## mini walkthrough

```text
문제:
"이 웹 서버 로그와 SSH 로그를 보고, 계정 탈취 후 서버에 SSH로 접속한
 계정과 그 세션 ID를 답하시오."
첨부: access.log, auth.log

1. 첫 시도 (실패):
   grep 'login' access.log | grep -oE 'user=[a-z]+' 로 계정만 뽑고 끝냈다.
   -> user=jhkim2 하나만 나왔다. "정답은 jhkim2" 로 제출.

   왜 틀렸나:
   문제는 "SSH로 접속한 계정"을 물었는데 access.log 는 웹 로그인일 뿐이다.
   웹 계정과 SSH 계정이 같은 이름이라는 보장이 없다.

2. 접근 변경 - auth.log 를 본다
   $ grep -oE 'Accepted \S+ for \S+ from [0-9.]+ port [0-9]+' auth.log
   Accepted password for svc_deploy from 203.0.113.9 port 51422

   -> SSH 로 실제 접속한 계정은 svc_deploy, 웹 계정 jhkim2 와 다르다.

3. 왜 svc_deploy 인가 - 웹 로그에서 그 시각 전후 활동을 본다
   $ grep '203.0.113.9' access.log | tail -5
   203.0.113.9 - - [14/Mar/2026:16:19:40] "GET /admin/config?PHPSESSID=8f3ha2m9c1x0k5p7q2r4s6t8 HTTP/1.1" 200
   203.0.113.9 - - [14/Mar/2026:16:19:41] "GET /admin/config/download?file=id_rsa HTTP/1.1" 200

   -> jhkim2 세션(PHPSESSID=8f3ha2m9c1x0k5p7q2r4s6t8)으로 /admin/config 에서
      id_rsa 를 내려받았다. 그 키로 SSH 접속에 성공했다.

4. 세션과 계정 연결
   $ grep '8f3ha2m9c1x0k5p7q2r4s6t8' access.log | grep -oE 'user=[a-z0-9_]+' | sort -u
   user=jhkim2

   -> 세션 8f3ha2m9c1x0k5p7q2r4s6t8 는 jhkim2 로 로그인된 세션이 맞다.

5. 시각 대조
   웹: 16:19:41 (id_rsa 다운로드)
   SSH: 16:20:08 Accepted password for svc_deploy from 203.0.113.9 port 51422
   -> 27초 뒤 같은 IP 에서 SSH 접속. 인과관계 확정.

정답: 웹 계정 jhkim2 로 탈취한 id_rsa 로 svc_deploy 계정에 SSH 접속.
      관련 세션 ID: PHPSESSID=8f3ha2m9c1x0k5p7q2r4s6t8
```

1단계의 오답이 흔하다. **"계정"이라는 단어가 어느 로그의 계정인지 구분하지 않으면 엉뚱한 답을 낸다.** 세션 ID로 두 로그를 연결하는 것이 이 글의 실전 가치다.

## 막혔을 때 다음 체크

1. 어느 로그의 계정을 묻는지 문제 지문을 다시 읽었는가 — 웹/SSH/Windows 계정은 다를 수 있다
2. `invalid user` 여부로 성공/실패, 존재/미존재 계정을 나눴는가
3. 세션 ID 형식으로 프레임워크를 추정했는가 (형식표 참고)
4. 세션 ID와 계정을 시간/IP로 조인했는가 — 정규식 하나로는 안 나온다
5. 로그 회전 파일(`.1`, `.gz`)을 빠뜨리지 않았는가
6. `%u`가 `-`인 웹 로그에서 애플리케이션 자체 로그로 넘어갔는가
7. Windows 로그면 `TargetUserName`과 `TargetLogonId`를 [FOR-0104](./logon-id-session-linking.html)로 이어갔는가
8. 대소문자와 라우팅 접미사(`.node1`)를 정규화했는가

## 출처

- SRC-062 — OpenSSH sshd man page: `Accepted`/`Failed password`/`invalid user` 메시지 형식
- SRC-001 — Microsoft Learn, Event 4624: `TargetUserName`/`TargetLogonId` 필드 정의
- SRC-058 — Apache HTTP Server 로그 문서: Combined Log Format의 `%u` 필드 정의와 기본값
- SRC-060 — RFC 5424(Syslog): `auth.log`/`secure` 계열 메시지의 일반 구조
- 세션 ID의 정확한 길이·문자 집합은 프레임워크 버전과 설정(세션 핸들러)에 따라 다르다. 이 글의 표는 기본 설정 기준이며 실제 값으로 재확인할 것
- IIS `cs-username` 등 W3C 로그 필드 순서는 `#Fields:` 헤더 줄로 그때그때 확인할 것
