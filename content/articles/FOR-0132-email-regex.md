---
id: FOR-0132
title: "이메일 주소 regex: 실용 패턴과 RFC 문법의 간극"
slug: "email-regex"
category: "로그/Regex"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["eml", "maillog", "auth.log", "memory strings", "docx", "pst"]
file_paths: ["/var/log/maillog", "/var/log/mail.log"]
registry_paths: []
event_ids: []
protocols: ["SMTP", "IMAP", "HTTP"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "strings", "bulk_extractor"]
commands: ["grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,63}' mail.log | sort -u", "grep -Poi '(?<![\\w.%+-])[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}(?![\\w.-])' strings.txt", "python3 -c \"from email.utils import getaddresses; print(getaddresses(['A <a@b.com>, c@d.com']))\""]
regex_patterns: ["[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,63}", "(?<![\\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}(?![\\w.-])", "<[^<>@[:space:]]+@[^<>[:space:]]+>", "\"[^\"]+\"@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}", "[A-Za-z0-9._%+-]+@\\[(?:IPv6:)?[0-9A-Fa-f:.]+\\]", "(?:MAIL FROM|RCPT TO):\\s*<([^>]*)>"]
wireshark_filters: ["smtp.req.parameter contains \"@\"", "imf.from"]
tshark_fields: ["smtp.req.parameter", "imf.from", "imf.to"]
log_fields: ["from=", "to=", "MAIL FROM", "RCPT TO", "From", "Return-Path"]
file_formats: ["eml", "log", "txt", "csv", "docx"]
primary_terms: ["이메일 regex", "email 정규식", "메일 주소 추출"]
keywords: ["이메일 regex", "email 정규식", "메일 주소 추출", "addr-spec", "local part", "로컬 파트", "domain literal", "quoted local part", "MailAddress", "parseaddr", "MAIL FROM", "RCPT TO"]
aliases: ["이메일 정규식", "메일 주소 정규식", "이메일 추출", "메일 주소 뽑기", "grep 이메일", "email 주소 찾기", "이메일 수집 정규식"]
symptom_keywords: ["이메일 주소만 뽑고 싶다", "이메일 정규식이 이상한 걸 잡는다", "파일명이 이메일로 잡힌다", "openssh.com 이 이메일로 잡힌다", "메일 로그에서 발신자만 뽑고 싶다", "문서에서 이메일을 수집하고 싶다"]
related: ["FOR-0130", "FOR-0131", "FOR-0121"]
source_ids: ["SRC-076", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

RFC 문법의 이메일 주소는 인용 로컬 파트·주석·도메인 리터럴까지 허용해서 정규식 한 줄로 완전히 표현할 수 없다. 실무에서는 `[A-Za-z0-9._%+-]+@도메인패턴`으로 99%를 회수하고, 남는 오탐(`logo@2x.png`, `hmac-sha2-256-etm@openssh.com`)은 도메인 쪽 규칙과 파서로 걸러낸다.

## 개념

이메일 주소는 `로컬파트@도메인` 두 조각이다. 문제는 각 조각이 허용하는 것이 생각보다 훨씬 넓다는 점이다.

| 조각 | 형태 | 예 |
| --- | --- | --- |
| 로컬 파트 (dot-atom) | 영숫자와 특수문자, 점으로 구분 | `first.last`, `user+tag`, `a_b-c` |
| 로컬 파트 (quoted) | 큰따옴표로 감싸면 거의 아무 문자나 | `"very.unusual.@.unusual"` |
| 도메인 (dot-atom) | 일반 도메인 이름 | `example.co.kr` |
| 도메인 (literal) | 대괄호 안에 IP | `[192.0.2.1]`, `[IPv6:2001:db8::1]` |

로컬 파트에 합법적으로 들어가는 특수문자가 이렇게 많다.

```text
! # $ % & ' * + - / = ? ^ _ ` { | } ~ .
```

여기에 **주석**(`user(comment)@example.com`)과 **접힘 공백**까지 문법에 있다. 이 전부를 정규식으로 표현한 결과물이 유명한 "6,000자 이메일 정규식"이다. **실무에서는 쓰지 않는다.**

| 길이 제한 | 값 |
| --- | --- |
| 로컬 파트 | 64옥텟 |
| 도메인 | 255옥텟 |

### 실무에서 내리는 결정

| 문법에 있는 것 | 실무 패턴에서 | 왜 |
| --- | --- | --- |
| dot-atom 로컬 파트 | **포함한다** | 실제 주소의 99.9% |
| `+`, `_`, `-`, `.` | **포함한다** | 태그 주소·회사 계정에 흔하다 |
| `!#$%&'*/=?^\`{\|}~` | 보통 뺀다 | 실제로 거의 안 쓰이고 오탐을 늘린다 |
| 인용 로컬 파트 | 별도 패턴으로 | 흔치 않지만 있으면 놓치면 안 된다 |
| 도메인 리터럴 `[IP]` | 별도 패턴으로 | 스팸·직접 발송에서 나온다 |
| 주석 `(...)` | 무시한다 | 로그·문서에 실질적으로 없다 |
| 연속 점 `a..b` | 무시한다 | 문법 위반이지만 걸러도 얻는 것이 없다 |

**"정규식으로 이메일을 검증한다"는 목표를 버려야 한다.** 목표는 "텍스트에서 주소 후보를 회수한다"다. 검증은 파서와 도메인 규칙이 한다.

## 파일 / 경로

| 대상 | 경로/필드 | 주소가 나오는 형태 |
| --- | --- | --- |
| 메일 파일 | `*.eml`, `*.msg` | `From:`, `To:`, `Cc:`, `Return-Path:`, `Received:` |
| Postfix/sendmail 로그 | `/var/log/maillog`, `/var/log/mail.log` | `from=<a@b.com>`, `to=<c@d.com>` |
| SMTP 세션 (pcap) | `*.pcapng` | `MAIL FROM:<...>`, `RCPT TO:<...>` |
| 웹 로그 | `access.log` | 쿼리스트링·POST 본문의 `email=` |
| 문서 | `*.docx`, `*.xlsx`, `*.pdf` | 본문·메타데이터 작성자 |
| 브라우저 | `Login Data`, `Web Data` (SQLite) | 자동완성 값 |
| 메모리 덤프 | `*.raw` | `strings` 결과 (로그인 폼 입력값이 남는다) |
| SSH 인증 로그 | `/var/log/auth.log` | 주소가 아니라 **알고리즘 이름**이 `@` 를 쓴다 |

## 주요 필드

### 패턴 1 — 실무 표준 패턴 (가장 많이 쓴다)

```text
[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}
```

`grep -Ei` 로 그대로 돌아간다. 짧아서 손으로 칠 수 있다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `user@example.com`, `first.last@sub.example.co.kr`, `user+tag@example.org` |
| 매칭 안 됨 | `admin@localhost` (TLD 없음), `user@[192.0.2.1]`, 인용 로컬 파트 |
| **오탐** | `logo@2x.png`, `hmac-sha2-256-etm@openssh.com`, `%s@%s.com`, `v1.0@2026.03.14` |

`[a-z0-9.-]+\.[a-z]{2,63}` 부분이 느슨해서 `@2x.png` 같은 것이 통과한다. 하이픈·점의 위치를 검증하지 않기 때문이다.

### 패턴 2 — 도메인 쪽을 조인 실전 패턴 (PCRE / .NET / Python)

```text
(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])
```

| 조각 | 역할 |
| --- | --- |
| `(?<![\w.%+-])` | 앞에 글자·점이 붙어 있으면 거부 (로컬 파트가 잘리는 것 방지) |
| `[A-Za-z0-9._%+-]+` | 로컬 파트 (실무 문자 집합) |
| `(?:라벨\.)+[A-Za-z]{2,63}` | 하이픈 위치까지 검증한 도메인 (FOR-0130의 라벨 조각) |
| `(?![\w.-])` | 뒤에 더 이어지면 거부 |

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `user@example.com`, `a.b+c@mail.example.co.kr` |
| 매칭 안 됨 | `logo@2x.png` — `2x` 는 라벨로 통과하지만 TLD `png`… **여전히 매칭된다** |
| 남은 오탐 | `logo@2x.png`, `hmac-sha2-256-etm@openssh.com` (구조상 완전히 합법적인 주소다) |

**구조만으로는 못 잡는다.** `openssh.com` 은 실제로 존재하는 도메인이고 `hmac-sha2-256-etm` 은 합법적인 로컬 파트다. 형태로 구별할 방법이 없다.

### 패턴 3 — 오탐 제거 (제외 목록)

```text
# 파일 확장자 TLD 를 거부한다
(?i)(?<![\w.%+-])[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?!(?:png|jpg|jpeg|gif|svg|exe|dll|zip|pdf|txt|log|js|css)(?![a-z]))[a-z]{2,63}(?![\w.-])
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `user@example.com` |
| 매칭 안 됨 | `logo@2x.png`, `icon@3x.jpg`, `sprite@2x.svg` |
| 남은 오탐 | `hmac-sha2-256-etm@openssh.com`, `curve25519-sha256@libssh.org` |

SSH 알고리즘 이름은 **도메인 제외 목록**으로 처리한다.

```text
@(?:openssh\.com|libssh\.org|openssl\.org|ssh\.com)$
```

`auth.log`·`sshd` 디버그 로그에서 이메일을 뽑으면 결과의 대부분이 이것이다. 반드시 제외하고 세야 한다.

### 패턴 4 — 인용 로컬 파트

```text
"[^"\\]*(?:\\.[^"\\]*)*"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `"user name"@example.com`, `"a@b"@example.com` |
| 매칭 안 됨 | `user name@example.com` (인용 없이 공백) |
| 오탐 | JSON/코드의 `"key"@value` 형태 문자열 |

실전에서는 드물지만, **헤더 인젝션이나 파서 우회에 쓰이므로 메일 조사에서는 한 번 돌려 본다.**

### 패턴 5 — 도메인 리터럴

```text
[A-Za-z0-9._%+-]+@\[(?:IPv6:)?[0-9A-Fa-f:.]+\]
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `user@[192.0.2.1]`, `admin@[IPv6:2001:db8::1]` |
| 매칭 안 됨 | `user@192.0.2.1` (대괄호 없음 — 이건 문법 위반이지만 실제로 나온다) |
| 오탐 | 배열 인덱스 표기 `arr@[0]`, 로그의 `pid@[1234]` |

대괄호 없는 `user@192.0.2.1` 도 함께 잡으려면 별도 패턴을 쓴다.

```text
[A-Za-z0-9._%+-]+@[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b
```

### 패턴 6 — SMTP 명령과 메일 헤더에서

```text
# SMTP 세션 / Postfix 로그
(?:MAIL FROM|RCPT TO|from|to)=?:?\s*<([^>]*)>

# 메일 헤더 (표시 이름 + 주소)
^(?:From|To|Cc|Bcc|Return-Path|Reply-To):\s*(.*)$

# 꺾쇠 안의 주소만
<([^<>@\s]+@[^<>\s]+)>
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `MAIL FROM:<a@b.com>`, `from=<a@b.com>`, `To: "홍길동" <a@b.com>` |
| 매칭 안 됨 | 꺾쇠 없이 쓴 `To: a@b.com` (헤더 패턴으로는 잡히지만 꺾쇠 패턴으로는 안 잡힌다) |
| 오탐 | 반송 메시지의 빈 발신자 `MAIL FROM:<>`, HTML 태그 `<b@i>` |

**`MAIL FROM:<>` 은 빈 주소가 정상이다.** 반송(bounce) 메일의 발신자다. 파싱 코드가 여기서 죽지 않게 한다.

### 패턴 7 — 메모리·문서에서 대량 수집할 때

```text
(?i)(?<![\w.%+-])[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])
```

로컬 파트의 **첫/마지막 문자를 영숫자로 제한**하고 길이를 64자로 묶었다. `.user@`·`user.@`·`-x@` 같은 조각 매칭이 사라진다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `user@example.com`, `a@b.io` |
| 매칭 안 됨 | `.user@example.com` 의 선행 점, 65자 이상 로컬 파트 |
| 오탐 | 여전히 `logo@2x.png` 계열 (확장자 제외 목록과 함께 써야 한다) |

## 빠른 명령

### grep / ripgrep

```bash
# 1) 실무 표준 패턴 (ERE)
grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' mail.log | sort -u

# 2) 도메인 규칙까지 검증 + 경계 (PCRE 전용)
grep -Poi '(?<![\w.%+-])[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])' strings.txt | sort -u

# 3) 오탐 제거 후 빈도 — 실전 1회차 명령
grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' auth.log |
  tr 'A-Z' 'a-z' |
  grep -Ev '@(openssh\.com|libssh\.org|openssl\.org|ssh\.com)$' |
  grep -Ev '@[0-9]+x\.(png|jpg|jpeg|gif|svg)$' |
  grep -Ev '\.(png|jpg|jpeg|gif|svg|exe|dll|zip|pdf|txt|log|js|css)$' |
  sort | uniq -c | sort -nr | head -20

# 4) 도메인별로 묶어 세기 — 조직 파악
grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' *.eml |
  tr 'A-Z' 'a-z' | awk -F@ '{print $2}' | sort | uniq -c | sort -nr | head

# 5) 메일 로그에서 발신/수신 분리
grep -Eo 'from=<[^>]*>' /var/log/maillog | sed 's/from=<//; s/>//' | sort | uniq -c | sort -nr
grep -Eo 'to=<[^>]*>'   /var/log/maillog | sed 's/to=<//;   s/>//' | sort | uniq -c | sort -nr

# 6) eml 헤더만 (본문의 인용 주소를 제외한다)
awk 'BEGIN{RS=""} NR==1' msg.eml |
  grep -Ei '^(From|To|Cc|Bcc|Return-Path|Reply-To|Received):' -A0

# 7) 메모리 덤프 — 두 인코딩 모두
strings -a -n 6 mem.raw     | grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' | sort -u
strings -a -n 6 -el mem.raw | grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' | sort -u

# 8) 인용 로컬 파트 / 도메인 리터럴 (파서 우회 시도 확인)
grep -Eo '"[^"]+"@[a-z0-9.-]+\.[a-z]{2,63}' msg.eml
grep -Eo '[a-z0-9._%+-]+@\[(IPv6:)?[0-9a-fA-F:.]+\]' msg.eml

# 9) docx 안의 주소 (zip 이므로 풀어서 본다)
unzip -p report.docx word/document.xml |
  grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' | sort -u

# 10) ripgrep — 바이너리까지 훑는다
rg -aoiP '(?<![\w.%+-])[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])' . | sort -u
```

출력 예:

```text
$ grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' auth.log | sort | uniq -c | sort -nr | head -4
  41208 hmac-sha2-256-etm@openssh.com
  41208 hmac-sha2-512-etm@openssh.com
  20604 curve25519-sha256@libssh.org
      3 admin@example.co.kr
```

**상위 3개가 전부 SSH 알고리즘 이름이다.** 제외하지 않으면 결과를 읽을 수 없다.

### PowerShell

```powershell
# 정규식은 항상 작은따옴표
$re = '(?i)(?<![\w.%+-])[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])'
$cand = Select-String -Path .\strings.txt -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  ForEach-Object { $_.ToLower() } | Sort-Object -Unique

# .NET 파서가 최종 판정자다 — 정규식보다 정확하다
$parsed = foreach ($c in $cand) {
  try {
    $m = [System.Net.Mail.MailAddress]::new($c)
    [pscustomobject]@{ Address = $m.Address; User = $m.User; Host = $m.Host; Valid = $true }
  } catch {
    [pscustomobject]@{ Address = $c; User = $null; Host = $null; Valid = $false }
  }
}

# 오탐 제외 — 도메인 화이트/블랙리스트로 관리한다
$badHost = 'openssh.com','libssh.org','openssl.org','ssh.com'
$badTld  = 'png','jpg','jpeg','gif','svg','exe','dll','zip','pdf','txt','log','js','css'
$real = $parsed | Where-Object {
  $_.Valid -and $_.Host -notin $badHost -and ($_.Host -split '\.')[-1] -notin $badTld
}

# 도메인별 집계
$real | Group-Object Host | Sort-Object Count -Descending |
  Select-Object -First 20 Count, Name

# 표시 이름까지 함께 파싱 (헤더 원문에서)
$hdr = 'To: "홍길동" <hong@example.co.kr>, admin@example.co.kr'
[System.Net.Mail.MailAddress[]] ($hdr -replace '^To:\s*','' -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)') |
  Select-Object DisplayName, User, Host, Address

# 로컬 파트 64자 / 도메인 255자 제한 검증
$real | Where-Object { $_.User.Length -gt 64 -or $_.Host.Length -gt 255 }
```

### Python

```python
import re, collections
from email.utils import getaddresses, parseaddr

EMAIL = re.compile(r'''
    (?<![\w.%+-])
    [a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?          # 로컬 파트: 양끝은 영숫자, 최대 64
    @
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+       # 도메인 라벨
    [a-z]{2,63}                                        # TLD
    (?![\w.-])
''', re.IGNORECASE | re.VERBOSE)

BAD_HOST = {'openssh.com', 'libssh.org', 'openssl.org', 'ssh.com'}
BAD_TLD  = {'png','jpg','jpeg','gif','svg','exe','dll','zip','pdf','txt','log','js','css'}

def keep(addr: str) -> bool:
    """정규식이 아니라 규칙으로 판정한다."""
    local, _, host = addr.rpartition('@')
    if not local or not host:
        return False
    if len(local) > 64 or len(host) > 255:
        return False
    if host in BAD_HOST or host.rsplit('.', 1)[-1] in BAD_TLD:
        return False
    if re.fullmatch(r'\d+x', host.split('.')[0]):   # logo@2x.png 계열
        return False
    return True

text = open('strings.txt', encoding='utf-8', errors='replace').read()
cand = {m.group().lower() for m in EMAIL.finditer(text)}
addrs = sorted(a for a in cand if keep(a))

# 1) 도메인별 집계
for host, n in collections.Counter(a.rpartition('@')[2] for a in addrs).most_common(20):
    print(f'{n:6d}  {host}')

# 2) 헤더는 정규식이 아니라 표준 라이브러리로 분해한다
hdr = 'To: "Hong, Gildong" <hong@example.co.kr>, admin@example.co.kr'
print(getaddresses([hdr.split(':', 1)[1]]))
# [('Hong, Gildong', 'hong@example.co.kr'), ('', 'admin@example.co.kr')]

# 쉼표가 표시 이름 안에 들어간 경우를 정규식으로 쪼개면 반드시 틀린다.
# getaddresses 는 인용 문자열을 이해한다.

# 3) eml 전체를 파서로 읽는다 — 첨부·인코딩까지 처리된다
import email, email.policy
msg = email.message_from_binary_file(open('msg.eml', 'rb'), policy=email.policy.default)
print(msg['From'], '|', msg['Return-Path'])
for k in ('To', 'Cc', 'Bcc'):
    if msg[k]:
        print(k, getaddresses([str(msg[k])]))
for part in msg.walk():                      # base64/quoted-printable 본문도 디코딩된다
    if part.get_content_type() == 'text/plain':
        body = part.get_content()
        print(sorted({m.group().lower() for m in EMAIL.finditer(body)}))

# 4) parseaddr 는 검증기가 아니라 분해기다 — 이 차이를 기억한다
print(parseaddr('완전히 잘못된 값'))     # ('', '완전히') 처럼 이상한 결과가 나온다
```

**`email.utils.parseaddr` / `getaddresses` 는 검증기가 아니라 분해기다.** 잘못된 입력도 조용히 뭔가를 돌려준다. 반면 .NET 의 `MailAddress` 생성자는 실제로 예외를 던지므로 검증에 쓸 수 있다. 두 언어에서 하는 일이 다르다는 것을 알고 쓴다.

## 함께 보는 artifact

| 주소를 얻은 뒤 | 다음에 볼 것 |
| --- | --- |
| 발신 도메인 확정 | 그 도메인의 DNS 조회·SPF·MX 흔적 (FOR-0130) |
| 피싱 메일 발신자 | `Received:` 헤더 체인의 최초 IP → 전 로그 재검색 ([FOR-0128](./ipv4-regex.html)) |
| 메일 본문의 링크 | URL 추출 후 무해화 ([FOR-0131](./url-regex.html)) |
| 첨부 파일명 | 확장자·시그니처 대조 ([FOR-0001](./30sec-triage.html)) |
| 메모리에서만 발견된 주소 | 그 프로세스의 명령행 ([FOR-0214](./volatility-pslist.html)) |
| Windows 에서 대량 집계 | `Select-String -AllMatches` ([FOR-0121](./powershell-select-string.html)) |
| 유사 도메인 발신자 | `xn--` punycode 여부와 브랜드 유사도 |

## 흔한 실수

- **`.+@.+\..+` 로 시작하는 것.** 문장 전체가 하나로 잡힌다. `.+` 는 공백까지 먹기 때문에 `보낸사람 a@b.com 받는사람 c@d.com` 이 한 덩어리가 된다. 문자 클래스를 명시하고 공백을 배제한다.
- **SSH 알고리즘 이름을 걸러내지 않는 것.** `auth.log`·`sshd -ddd` 출력에서 이메일을 뽑으면 `hmac-sha2-256-etm@openssh.com`, `curve25519-sha256@libssh.org` 가 상위를 전부 차지한다. 형태로는 구별 불가능하므로 도메인 제외 목록으로 처리한다.
- **`@2x` 파일명을 놓치는 것.** `logo@2x.png`, `icon@3x.jpg` 는 고해상도 이미지 관례다. 웹 자산이 포함된 이미지·문서를 뒤지면 대량으로 나온다. 확장자 TLD 제외 목록이 필요하다.
- **쉼표로 헤더를 쪼개는 것.** `To: "Hong, Gildong" <a@b.com>, c@d.com` 을 `split(',')` 하면 표시 이름이 두 동로 갈린다. `getaddresses` / `MailAddress` 처럼 인용 문자열을 이해하는 파서를 쓴다.
- **로컬 파트 대소문자를 마음대로 합치는 것.** 도메인은 대소문자를 구분하지 않지만 로컬 파트의 대소문자 취급은 수신 서버가 정한다. 집계할 때는 소문자로 정규화하되 **원문 표기를 함께 보존**한다. 보고서에 원문 그대로 써야 하는 경우가 있다.
- **`+태그` 를 지워 버리는 것.** `user+github@example.com` 의 `+github` 는 어디서 유출됐는지 알려주는 결정적 단서다. 정규화한다고 지우면 안 된다.
- **`MAIL FROM:<>` 에서 파싱이 죽는 것.** 빈 발신자는 반송 메일의 정상 형태다. 빈 문자열을 허용하는 패턴(`<([^>]*)>`)을 쓴다.
- **메일 본문을 디코딩하지 않고 뒤지는 것.** 본문이 base64 또는 quoted-printable 이면 주소가 원문 형태로 존재하지 않는다. `=3D` 가 보이면 quoted-printable 이다. `email` 모듈로 파싱해 디코딩된 본문에서 검색한다.
- **표시 이름의 encoded-word 를 주소로 착각하는 것.** `=?utf-8?B?...?=` 는 표시 이름 인코딩이다. 주소 자체는 인코딩되지 않는다. 디코딩해 보고 주소와 표시 이름이 서로 다른 조직을 가리키면 그것이 피싱 지표다.
- **`user@localhost`, `root@srv01` 을 버리는 것.** TLD 가 없어 실무 패턴에 걸리지 않지만 내부 메일·cron 알림의 정상 형태다. TLD 없는 형태를 따로 한 번 훑는다.
- **메모리에서 ASCII 만 훑는 것.** 윈도우 프로세스 문자열은 UTF-16LE 가 많다. `strings -el` 을 함께 돌리지 않으면 로그인 폼에 입력된 주소를 놓친다.

## mini example

```text
문제:
"침해된 리눅스 서버에서 공격자가 정보를 보낸 외부 메일 주소를 구하세요."
첨부: auth.log, maillog, mem.raw

1. 첫 시도 (실패) — 전체 로그에 표준 패턴을 돌렸다
   $ cat auth.log maillog | grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' |
       sort | uniq -c | sort -nr | head -5
      41208 hmac-sha2-256-etm@openssh.com
      41208 hmac-sha2-512-etm@openssh.com
      20604 curve25519-sha256@libssh.org
      20604 umac-128-etm@openssh.com
       1204 root@web01.example.co.kr

   -> 상위 전부 SSH 암호 알고리즘 이름이다. openssh.com 은 실제 도메인이고
      hmac-sha2-256-etm 은 합법적인 로컬 파트라서 정규식으로는 구별할 수 없다.
      제외 목록이 필요하다.

2. 두 번째 시도 (실패) — 제외 목록을 적용했다
   $ cat auth.log maillog | grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' |
       tr 'A-Z' 'a-z' |
       grep -Ev '@(openssh\.com|libssh\.org|openssl\.org)$' |
       sort | uniq -c | sort -nr | head -5
       1204 root@web01.example.co.kr
        612 cron@web01.example.co.kr
         88 admin@example.co.kr
          4 backup@example.co.kr

   -> 전부 내부 도메인(example.co.kr)이다. "외부" 주소가 없다.
      maillog 를 직접 보니 발송 자체가 로컬 MTA 를 거치지 않았다.

   $ grep -c 'to=<' maillog
   0

3. 메일 로그에 없다면 프로세스가 직접 SMTP 를 말했다는 뜻이다.
   메모리를 본다. ASCII 와 UTF-16LE 를 모두 훑는다.
   $ strings -a -n 6 mem.raw | grep -Eoi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}' |
       tr 'A-Z' 'a-z' | grep -Ev '@(openssh\.com|libssh\.org)$' |
       grep -v 'example\.co\.kr' | sort -u
   drop.box.rcv@mail-relay.example-cdn.top
   noreply@ubuntu.com
   support@nginx.org

   -> ubuntu.com / nginx.org 는 패키지 메타데이터다.
      mail-relay.example-cdn.top 이 낯설다.

4. 그 주소가 어떤 문맥에 있었는지 확인 (주변 문자열을 함께 본다)
   $ strings -a -n 6 mem.raw | grep -B3 -A3 'drop.box.rcv@'
   MAIL FROM:<web01@localhost>
   RCPT TO:<drop.box.rcv@mail-relay.example-cdn.top>
   DATA
   Subject: WS01 dump 2026-03-14
   Content-Type: application/octet-stream; name="shadow.tar.gz"

   -> SMTP 세션이 메모리에 그대로 남아 있다. 첨부 이름이 shadow.tar.gz 다.

5. RCPT TO 만 정확히 다시 뽑는다 (꺾쇠 패턴이 가장 정확하다)
   $ strings -a -n 6 mem.raw | grep -Eo 'RCPT TO:<[^>]*>' | sort | uniq -c
         12 RCPT TO:<drop.box.rcv@mail-relay.example-cdn.top>

6. 교차검증 — 그 호스트로의 25/587 세션이 있는지
   $ grep -E 'mail-relay\.example-cdn\.top|:(25|587)\b' /var/log/syslog | head -2
   Mar 14 07:31:02 web01 kernel: [UFW ALLOW] SRC=10.10.20.5 DST=198.51.100.9 DPT=25
   -> 확정.

정답: drop.box.rcv@mail-relay.example-cdn.top (12회, shadow.tar.gz 첨부)
```

1·2단계가 이 글의 핵심이다. **`@` 를 쓰는 문자열은 이메일 말고도 많다.** SSH 알고리즘 이름과 `@2x` 파일명은 정규식으로 구별할 수 없으므로 제외 목록으로 관리하고, 결과가 전부 내부 도메인이면 발송 경로 자체가 MTA 를 우회했다는 신호로 읽는다.

## 출처

- SRC-076 — RFC 5321 / 5322 및 이메일 주소 문법: `local-part@domain` 구조, dot-atom 과 quoted-string 두 형태, 도메인 리터럴 대괄호 표기, 로컬 파트 64옥텟 / 도메인 255옥텟 길이 제한
- SRC-057 — Python 문서 `re`: `re.VERBOSE`, lookbehind, `fullmatch`. `email.utils.getaddresses` / `parseaddr` 와 `email` 패키지의 동작 근거는 같은 표준 라이브러리 문서
- 로컬 파트에 허용되는 특수문자 전체 목록과 주석(comment)·접힘 공백 문법은 이 글에서 "존재한다"는 사실만 서술하고, 어떤 조합이 유효한지는 단정하지 않았다. 실무 패턴은 dot-atom 만 대상으로 한다
- `System.Net.Mail.MailAddress` 가 어떤 입력을 거부하는지는 .NET 버전에 따라 다를 수 있으므로 실제 환경에서 확인할 것
- SSH 알고리즘 이름(`hmac-sha2-256-etm@openssh.com` 등)이 `@` 를 포함한다는 것은 로그에서 관측되는 형태다. 정확한 알고리즘 목록은 대상 시스템의 `ssh -Q` 출력으로 확인할 것
