---
id: FOR-0113
title: "grep -E 확장 정규표현식(ERE) 실전: BRE와의 차이와 lookaround 대안"
slug: "grep-e-regex"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "text log"]
file_paths: ["/var/log/auth.log", "/var/log/apache2/access.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["grep", "ripgrep", "sed", "awk"]
commands: ["grep -E '(GET|POST) /[^ ]*' access.log", "grep -Eo '[0-9]{1,3}(\\.[0-9]{1,3}){3}' access.log", "grep -E '\\<root\\>' auth.log", "grep -Ec 'union[[:space:]]+select' access.log", "rg -oP '(?<=cmd=)[^& ]+' access.log"]
regex_patterns: ["(GET|POST|PUT|DELETE) /[^ ]*", "[0-9]{1,3}(\\.[0-9]{1,3}){3}", "^[[:digit:]]{1,3}(\\.[[:digit:]]{1,3}){3}[[:space:]]", "\"[A-Z]+ [^\"]*\" (4[0-9]{2}|5[0-9]{2})", "(\\.\\./|%2e%2e%2f|\\.\\.%2f)", "union[[:space:]]+select", "\\<root\\>"]
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["log", "txt", "csv"]
primary_terms: ["grep -E", "확장 정규표현식", "ERE"]
keywords: ["grep -E", "ERE", "확장 정규표현식", "extended regex", "POSIX 문자 클래스", "[:alpha:]", "[:digit:]", "lookaround", "grep -P", "rg -P", "앵커", "단어 경계", "이스케이프"]
aliases: ["grep -E", "grep 정규식", "확장 정규식", "egrep", "grep or 조건", "grep 여러 패턴", "grep 반복 횟수"]
symptom_keywords: ["grep 에서 괄호가 안 먹는다", "grep 에서 plus 가 안 된다", "lookahead 가 안 된다", "grep -P 가 없다", "단어만 정확히 찾고 싶다", "역슬래시를 어디 붙여야 하나"]
related: ["FOR-0112", "FOR-0114", "FOR-0128"]
source_ids: ["SRC-015", "SRC-055"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`grep -E`는 `(` `)` `|` `+` `?` `{` `}`를 **이스케이프 없이** 쓰게 해 주는 POSIX ERE 모드이며, 실전에서 필요한 것은 `(A|B)` OR, `{n,m}` 반복, `[[:digit:]]` 문자 클래스 세 가지뿐이다 — 대신 **lookaround가 없으므로** `(?<=cmd=)` 같은 패턴은 `grep -P` 또는 `rg -P`로 가야 한다.

## 어떤 문제에서 필요한가

- 여러 패턴을 한 번에 OR로 걸어야 하는 상황 (`GET|POST|PUT`)
- IP·해시·타임스탬프처럼 **자릿수**가 정해진 값을 뽑아야 하는 상황 (`{1,3}`, `{32}`, `{64}`)
- 상태 코드 4xx·5xx만 걸러야 하는 상황 (`(4[0-9]{2}|5[0-9]{2})`)
- BRE에서 `grep '(a|b)'`가 아무것도 못 찾아 막힌 상황
- 특정 문자열 **뒤의 값만** 뽑으려는데 `-o`가 앞부분까지 함께 출력하는 상황

## 문제에서 처음 볼 단서

1. `grep '(GET|POST)'`가 **0건**을 반환한다 → BRE로 해석되어 리터럴 `(GET|POST)`를 찾은 것이다
2. `grep 'a+'`가 문자열 `a+`만 잡는다 → 같은 원인
3. `grep -P`가 `not compiled into this ... binary` 에러를 낸다 → 이 배포판에는 PCRE가 없다
4. `-o` 출력에 접두어가 붙는다 → lookbehind가 필요한 상황이다

먼저 지금 어느 방언인지 확인한다.

```bash
# BRE(기본)에서는 0건, ERE에서는 매칭된다
echo 'POST /upload.php' | grep '(GET|POST)'    ; echo "BRE  exit=$?"
echo 'POST /upload.php' | grep -E '(GET|POST)' ; echo "ERE  exit=$?"
```

```text
BRE  exit=1
POST /upload.php
ERE  exit=0
```

## 30초 절차

```bash
grep -Eo '(GET|POST|PUT|DELETE) /[^ ]*' access.log | sort | uniq -c | sort -nr | head
```

메서드별 요청 경로 빈도가 한 번에 나온다.

```text
   9821 GET /index.html
    412 GET /admin/
     88 POST /login.php
      3 POST /upload.php
      2 GET /uploads/av4tar.php
```

공격 스캔 신호를 한 줄로 훑을 때는 이렇게 쓴다.

```bash
grep -nE 'union[[:space:]]+select|\.\./|%2e%2e|cmd=|/etc/passwd|<script|base64_decode' access.log
```

## 상세 절차

### 1단계 — ERE 문법표

| 요소 | 의미 | 예 | 매칭됨 | 매칭 안 됨 |
| --- | --- | --- | --- | --- |
| `.` | 임의의 한 문자 (개행 제외) | `a.c` | `abc`, `a5c` | `ac`, `abbc` |
| `*` | 앞 요소 0회 이상 | `ab*c` | `ac`, `abc`, `abbc` | `adc` |
| `+` | 앞 요소 1회 이상 | `ab+c` | `abc`, `abbc` | `ac` |
| `?` | 앞 요소 0 또는 1회 | `colou?r` | `color`, `colour` | `colouur` |
| `{n}` | 정확히 n회 | `[0-9]{3}` | `200` | `20`, `2000`은 앞 3자리만 |
| `{n,}` | n회 이상 | `[0-9]{3,}` | `200`, `20000` | `20` |
| `{n,m}` | n~m회 | `[0-9]{1,3}` | `7`, `77`, `777` | (없음. 4자리는 앞 3자리만) |
| `(...)` | 그룹 | `(ab)+` | `ab`, `abab` | `aab` |
| `\|` | OR | `GET\|POST` | `GET`, `POST` | `HEAD` |
| `[...]` | 문자 집합 | `[aeiou]` | `a` | `b` |
| `[^...]` | 부정 집합 | `[^0-9]` | `a`, `-` | `5` |
| `^` | 줄 시작 | `^203\.` | `203.0.113.77 - -` | `x 203.0.113.77` |
| `$` | 줄 끝 | `200$` | `... 200` | `... 200 87` |

`grep -E`와 `grep`(BRE)의 차이는 **이스케이프 방향이 반대**라는 한 문장으로 요약된다.

| 하려는 것 | BRE (`grep`) | ERE (`grep -E`) |
| --- | --- | --- |
| 그룹 | `\(GET\|POST\)` | `(GET\|POST)` |
| 1회 이상 | `ab\+c` | `ab+c` |
| 0 또는 1회 | `colou\?r` | `colou?r` |
| 3회 반복 | `[0-9]\{3\}` | `[0-9]{3}` |
| **리터럴** 여는 괄호 | `(` | `\(` |
| **리터럴** 플러스 | `+` | `\+` |
| **리터럴** 중괄호 | `{` | `\{` |

즉 BRE에서 `\`를 붙여야 특수해지고, ERE에서는 `\`를 붙여야 리터럴이 된다. 로그에서 리터럴 `+`를 찾을 때 사고가 난다 — URL 인코딩의 공백이 `+`다.

```bash
# cmd=cat+/etc/passwd 처럼 + 가 든 값을 찾을 때
grep -E 'cat\+/etc/passwd' access.log      # O — 이스케이프
grep -E 'cat+/etc/passwd' access.log       # X — "cat" 의 t 가 1회 이상이라는 뜻
grep -F 'cat+/etc/passwd' access.log       # O — 가장 안전
```

### 2단계 — POSIX 문자 클래스

ERE에서 `\d`는 **동작하지 않는다.** 대신 대괄호 클래스를 쓴다. **반드시 대괄호를 두 겹**으로 감싼다.

| 클래스 | 의미 | 대응 |
| --- | --- | --- |
| `[[:digit:]]` | 숫자 | `[0-9]` |
| `[[:alpha:]]` | 영문자 | `[A-Za-z]` |
| `[[:alnum:]]` | 영숫자 | `[0-9A-Za-z]` |
| `[[:xdigit:]]` | 16진수 문자 | `[0-9A-Fa-f]` |
| `[[:space:]]` | 공백류 (스페이스·탭·개행) | `[ \t\n\r\f\v]` |
| `[[:blank:]]` | 스페이스와 탭만 | `[ \t]` |
| `[[:upper:]]` | 대문자 | `[A-Z]` |
| `[[:lower:]]` | 소문자 | `[a-z]` |
| `[[:punct:]]` | 구두점 | `!"#$%&'()*+,-./:;<=>?@[\]^_` 등 |
| `[[:print:]]` | 출력 가능 문자 | 공백 포함 |
| `[[:cntrl:]]` | 제어 문자 | `0x00`~`0x1F`, `0x7F` |

```bash
# O — 클래스는 대괄호 안에 들어간다
grep -E '[[:digit:]]{1,3}(\.[[:digit:]]{1,3}){3}' access.log

# X — 대괄호가 한 겹이면 :digt 같은 개별 문자 집합이 된다
grep -E '[:digit:]{1,3}' access.log
```

| 패턴 | 매칭됨 | 매칭 안 됨 |
| --- | --- | --- |
| `[[:digit:]]{1,3}` | `7`, `77`, `777` | `abc` |
| `[:digit:]{1,3}` | `d`, `:g:`, `it` (`d i g t :` 중 1~3자) | — 의도와 완전히 다르다 |

다른 집합과 섞을 때는 클래스를 대괄호 안에 함께 넣는다.

```bash
# 16진수 또는 콜론 (MAC 주소 후보)
grep -Eo '([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}' syslog
```

GNU 확장으로 `\w`(`[[:alnum:]_]`), `\W`, `\s`, `\S`, `\b`, `\B`, `\<`, `\>`는 ERE에서도 쓸 수 있다. 다만 POSIX 표준은 아니므로 이식성이 필요할 때는 클래스를 쓴다.

### 3단계 — 앵커와 단어 경계

| 앵커 | 의미 |
| --- | --- |
| `^` | 줄 시작 |
| `$` | 줄 끝 |
| `\<` | 단어 시작 (GNU) |
| `\>` | 단어 끝 (GNU) |
| `\b` | 단어 경계 양쪽 (GNU) |
| `\B` | 단어 경계가 **아닌** 위치 (GNU) |

앵커가 왜 필수인지 예시다. 상위 IP를 셀 때 앵커가 없으면 본문 안의 IP까지 잡힌다.

| 패턴 | `203.0.113.77 - - [...] "GET /?redir=1.2.3.4"` | 결과 |
| --- | --- | --- |
| `[0-9]{1,3}(\.[0-9]{1,3}){3}` | 매칭 2건 | 요청 IP와 파라미터 IP 둘 다 |
| `^[0-9]{1,3}(\.[0-9]{1,3}){3}` | 매칭 1건 | 요청 IP만 |
| `^[0-9]{1,3}(\.[0-9]{1,3}){3}[[:space:]]` | 매칭 1건 | 요청 IP만, 잘림 방지까지 |

`^203\.0\.113\.77`도 위험하다. `203.0.113.770`을 잡기 때문이다. 뒤에 경계를 붙인다.

| 패턴 | `203.0.113.77 - -` | `203.0.113.770 - -` |
| --- | --- | --- |
| `^203\.0\.113\.77` | 매칭 | **매칭 (오탐)** |
| `^203\.0\.113\.77[[:space:]]` | 매칭 | 매칭 안 됨 |
| `^203\.0\.113\.77\>` | 매칭 | 매칭 안 됨 |

단어 경계의 실전 예다.

| 패턴 | `root` | `chroot` | `rootkit` | `root:x:0:0` |
| --- | --- | --- | --- | --- |
| `root` | 매칭 | 매칭 | 매칭 | 매칭 |
| `\<root\>` | 매칭 | 매칭 안 됨 | 매칭 안 됨 | 매칭 |
| `^root$` | 매칭 | 매칭 안 됨 | 매칭 안 됨 | 매칭 안 됨 |

### 4단계 — lookaround가 없다는 사실과 그 대안

ERE에는 `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`가 **존재하지 않는다.** `grep -E '(?<=cmd=)[^& ]+'`는 매칭이 안 되거나 문법 에러가 난다.

포렌식에서 lookbehind가 절실한 상황은 하나로 정해져 있다. **"`cmd=` 뒤의 값만"** 같은 접두어 제거 추출이다. 대안이 네 가지다.

| 방법 | 명령 | 이식성 | 비고 |
| --- | --- | --- | --- |
| `-o` 후 `sed`로 접두어 제거 | `grep -Eo 'cmd=[^& ]+' \| sed 's/^cmd=//'` | **최고** | ERE만 쓴다. 어디서나 된다 |
| `-o` 후 `cut`으로 자르기 | `grep -Eo 'cmd=[^& ]+' \| cut -d= -f2-` | 높다 | `=`가 값에 또 나오면 `-f2-` 필요 |
| `grep -P` (PCRE) | `grep -oP '(?<=cmd=)[^& ]+'` | **낮다** | 빌드에 PCRE가 없으면 실패 |
| `rg -P` (PCRE2) | `rg -oP '(?<=cmd=)[^& ]+'` | 높다 (rg가 있으면) | ripgrep은 PCRE2를 내장 빌드로 제공한다 |

```bash
# PCRE 사용 가능 여부 판정 — 종료 코드 2 면 없다
grep -P '' /dev/null 2>/dev/null; echo "grep -P exit=$?"
rg -P '' --version >/dev/null 2>&1 && echo 'rg -P 사용 가능'
```

전방탐색(`(?=)`)이 필요한 경우도 대개 우회할 수 있다.

| 하려는 것 | PCRE | ERE 대안 |
| --- | --- | --- |
| `POST`이면서 `.php`인 줄 | `(?=.*POST)(?=.*\.php)` | `grep -E 'POST' \| grep -E '\.php'` (파이프로 AND) |
| `admin`이지만 `admin.css`는 제외 | `admin(?!\.css)` | `grep -E 'admin' \| grep -Ev 'admin\.css'` |
| 값만 추출 | `(?<=status=)[0-9]+` | `grep -Eo 'status=[0-9]+' \| cut -d= -f2` |

**ERE에서 AND는 파이프, NOT은 `-v`다.** 이 두 개를 알면 lookaround가 없어도 대부분 해결된다.

`grep -E`가 GNU 확장으로 역참조 `\1`을 지원하기는 하지만, POSIX ERE 표준에는 없고 구현마다 다르므로 대회장에서는 의존하지 않는다. 반복 문자 탐지가 필요하면 Python `re`로 옮긴다.

### 5단계 — 이스케이프 함정

| 잘못 쓴 것 | 실제 의미 | 올바른 것 |
| --- | --- | --- |
| `grep -E '192.168.1.1'` | `.`이 임의 문자 → `192a168b1c1` 매칭 | `'192\.168\.1\.1'` 또는 `grep -F` |
| `grep -E 'cmd=cat+/etc'` | `t`가 1회 이상 | `'cmd=cat\+/etc'` |
| `grep -E '[a-z]{2}'`를 `"..."`로 감쌈 | 셸이 `{}` 확장·`$` 치환에 관여 | 항상 **작은따옴표** |
| `grep -E '\d{3}'` | ERE에 `\d`가 없다. `d`가 3회 = `ddd` | `'[0-9]{3}'` |
| `grep -E '[\.]'` | 대괄호 안에서 `\`는 리터럴 → `\` 또는 `.` | `'[.]'` (대괄호 안의 `.`는 이미 리터럴) |
| `grep -E '[a-z-A-Z]'` | `-`의 위치가 애매해 범위 해석이 꼬인다 | `'[a-zA-Z-]'` (`-`는 맨 끝) |
| `grep -E '[]]'`를 `'[]'`로 씀 | 빈 집합 = 문법 오류 | `']'`를 넣으려면 **맨 앞**에: `'[]a]'` |
| `grep -E '[^]'` | 같은 이유로 오류 | `'[^]a]'` |
| `grep -E 'a{1,3'` | 닫히지 않은 `{` | `'a\{1,3'` 또는 제대로 닫는다 |

대괄호 안의 규칙 세 가지만 외운다.

| 문자 | 대괄호 안에서 리터럴이 되는 위치 |
| --- | --- |
| `]` | 맨 **앞** (`[]abc]`) |
| `^` | 맨 앞이 **아닌** 곳 (`[a^]`) |
| `-` | 맨 앞 또는 맨 **뒤** (`[-a]`, `[a-]`) |

그리고 **대괄호 안에서는 `\`가 이스케이프 문자가 아니다.** `[\.]`는 백슬래시와 점 두 문자의 집합이다.

### 6단계 — 로그용 실전 패턴

각 패턴에 매칭/비매칭 예시를 붙였다.

#### 상태 코드 4xx·5xx만

```text
"[A-Z]+ [^"]*" (4[0-9]{2}|5[0-9]{2})
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `"GET /admin/ HTTP/1.1" 403 199`, `"POST /x HTTP/1.1" 500 0` |
| 매칭 안 됨 | `"GET / HTTP/1.1" 200 4021`, `"GET / HTTP/1.1" 304 0` |
| 주의 | 응답 크기 `4021`은 `"..."` 뒤 첫 필드가 아니므로 잡히지 않는다 |

```bash
grep -Ec '"[A-Z]+ [^"]*" (4[0-9]{2}|5[0-9]{2})' access.log
```

#### 디렉터리 트래버설 (인코딩 변형 포함)

```text
(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e)
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `/download?f=../../etc/passwd`, `/download?f=%2e%2e%2fetc%2fpasswd`, `/x?f=..%2fetc` |
| 매칭 안 됨 | `/assets/../style.css`는 **매칭된다** (정상 경로도 잡힌다 — 오탐) |
| 대소문자 | `%2E%2E`는 `-i` 없이는 안 잡힌다. `grep -Ei` |

#### SQL 인젝션 후보

```text
(union[[:space:]]+select|or[[:space:]]+1=1|sleep\([0-9]+\)|information_schema|benchmark\()
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `?id=1 union select 1,2,3`, `?id=1' or 1=1--`, `?id=1 and sleep(5)` |
| 매칭 안 됨 | `?id=1+union+select+1` (URL 인코딩된 공백이 `+`) |
| 대응 | `[[:space:]]`를 `[[:space:]+%20]{1,}` 으로 넓히거나 디코딩 후 검색 |

이것이 실전에서 가장 자주 놓치는 부분이다. **URL 쿼리의 공백은 `+` 또는 `%20`이므로** 공백만 가정한 패턴은 0건을 반환한다.

```bash
# 인코딩 변형까지 함께
grep -Eio 'union(\+|%20|[[:space:]])+select' access.log | sort -u
```

#### 해시 후보 (자릿수로 구분한다)

```text
\<[[:xdigit:]]{32}\>      MD5
\<[[:xdigit:]]{40}\>      SHA-1
\<[[:xdigit:]]{64}\>      SHA-256
```

| 패턴 | 매칭됨 | 매칭 안 됨 |
| --- | --- | --- |
| `\<[[:xdigit:]]{32}\>` | `d41d8cd98f00b204e9800998ecf8427e` | 31자·33자 문자열, `g41d8c...`(g는 16진수 아님) |
| 경계 없는 `[[:xdigit:]]{32}` | 위 + **64자 문자열의 앞 32자** | — 오탐이 생긴다 |

#### 타임스탬프 구간

```text
14/Mar/2026:07:(1[0-9]|2[0-5]):[0-9]{2}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `[14/Mar/2026:07:19:02 +0900]`, `[14/Mar/2026:07:25:59 +0900]` |
| 매칭 안 됨 | `[14/Mar/2026:07:09:59 +0900]`, `[14/Mar/2026:07:26:00 +0900]` |
| 대안 | 구간이 넓으면 정규식보다 `awk`의 문자열 비교가 읽기 쉽다 |

## 출력 필드 해석

`-o`를 쓰면 매칭된 부분만 나오지만, **어느 줄에서 나왔는지가 사라진다.** 조합에 따라 출력이 이렇게 달라진다.

| 명령 | 출력 형태 | 언제 쓰나 |
| --- | --- | --- |
| `grep -E PAT f` | 줄 전체 | 문맥이 필요할 때 |
| `grep -nE PAT f` | `줄번호:줄전체` | "몇 번째 줄" 문제 |
| `grep -oE PAT f` | 매칭 부분만, 한 줄에 하나 | 집계 직전 |
| `grep -onE PAT f` | `줄번호:매칭부분` | 값과 위치를 함께 |
| `grep -cE PAT f` | 줄 수 | 빈도. **매칭 개수가 아니다** |
| `grep -oE PAT f \| wc -l` | 매칭 총 개수 | 진짜 개수 |

```bash
$ grep -onE '[0-9]{1,3}(\.[0-9]{1,3}){3}' access.log | head -4
1:203.0.113.77
2:192.168.10.24
3:203.0.113.77
3:1.2.3.4
```

3번 줄에 두 건이 있다. `-c`로는 이 사실을 볼 수 없다.

## pivot: 다음에 볼 artifact

| ERE로 얻은 것 | 다음 목표 |
| --- | --- |
| 후보 IP 목록 | 엄격 패턴으로 재검증 ([FOR-0128](./ipv4-regex.html)) |
| 매칭 줄 번호 | `sed -n 'N,Mp'`로 구간 전체 확인 ([FOR-0118](./head-tail-less.html)) |
| 값 목록 | 빈도 집계 ([FOR-0117](./sort-uniq.html)) |
| 필드 위치가 확실해졌다 | 정규식을 버리고 `awk` 완전 일치 ([FOR-0115](./awk-fields.html)) |
| lookaround가 필요하다 | `rg -P` ([FOR-0114](./ripgrep.html)) |
| 접두어를 떼야 한다 | `sed 's/^키=//'` ([FOR-0119](./sed-substitute.html)) |
| .NET 정규식이 편하다 | `Select-String` ([FOR-0121](./powershell-select-string.html)) |

## 흔한 함정

- **BRE에서 ERE 문법을 쓰는 것.** `grep '(GET|POST)'`는 0건이다. 에러가 아니라 조용히 아무것도 못 찾으므로 "로그에 없다"고 오판한다. `-E`를 붙였는지 항상 먼저 확인한다.
- **`\d`를 쓰는 것.** ERE에 없다. `\d{3}`은 `ddd`를 찾는다. `[0-9]{3}` 또는 `[[:digit:]]{3}`.
- **문자 클래스를 대괄호 한 겹으로 쓰는 것.** `[:digit:]`는 `d i g t :` 문자 집합이다. `[[:digit:]]`가 맞다.
- **lookaround를 ERE에서 쓰는 것.** `(?<=...)`는 없다. `-o` + `sed`/`cut`으로 접두어를 떼거나 `rg -P`로 옮긴다.
- **`.`을 이스케이프하지 않는 것.** `192.168.1.1`은 `192a168b1c1`도 잡는다. IP·도메인·파일명에는 `\.`이 필수다.
- **앵커를 안 붙이는 것.** `^203\.0\.113\.77`은 `203.0.113.770`을 잡는다. 뒤에 `[[:space:]]`나 `\>`를 붙인다.
- **대괄호 안에서 `\`로 이스케이프하려는 것.** `[\.]`는 백슬래시와 점의 집합이다. 대괄호 안의 `.`은 이미 리터럴이다.
- **URL 인코딩을 고려하지 않는 것.** 쿼리의 공백은 `+` 또는 `%20`이다. `union[[:space:]]+select`만으로는 `union+select`를 놓친다.
- **큰따옴표로 패턴을 감싸는 것.** 셸이 `$`·`` ` ``·`\`·`!`를 먼저 해석한다. 정규식은 항상 작은따옴표.
- **`{`가 리터럴이라고 가정하는 것.** ERE에서 `flag{`를 찾을 때 `grep -E 'flag{'`는 구현에 따라 오류이거나 리터럴로 처리된다. `grep -E 'flag\{'` 또는 `grep -F 'flag{'`가 안전하다.
- **역참조 `\1`에 의존하는 것.** POSIX ERE 표준에 없다. 필요하면 Python `re`로 옮긴다.
- **`-i`를 빠뜨리거나 남용하는 것.** `%2E%2E` 같은 인코딩 변형에는 `-i`가 필요하지만, flag 문자열이나 Base64에는 `-i`가 오탐을 만든다.

## 교차검증

같은 값을 세 방식으로 세서 일치하는지 확인한다.

```bash
# 1) ERE 앵커 패턴
grep -cE '^203\.0\.113\.77[[:space:]]' access.log

# 2) 고정 문자열 (정규식 오탐 없음)
grep -cF '203.0.113.77 - -' access.log

# 3) 필드 완전 일치 — 이것이 기준값이다
awk '$1=="203.0.113.77"' access.log | wc -l

# 4) ripgrep 으로 한 번 더
rg -c '^203\.0\.113\.77\s' access.log
```

값이 다르면 원인은 셋 중 하나다. 앵커 누락(오탐), `.` 미이스케이프(오탐), 또는 로그에 `- -` 대신 다른 identd 값이 들어 있는 경우(2번의 과소 계수)다. **`awk` 필드 완전 일치를 기준값으로 삼는다.**

## mini walkthrough

```text
문제:
"access.log 에서 SQL 인젝션 시도 횟수와 사용된 페이로드를 구하세요."
첨부: access.log (41,882줄)

1. 첫 시도 (실패):
   $ grep -c 'union select' access.log
   0
   -> 0건. "인젝션이 없다"고 결론 내리면 오답이다.
      원인 두 개: (a) 공백이 URL 인코딩되어 있다 (b) 대소문자가 섞여 있다

2. 형식 확인 — 실제로 어떻게 들어왔나
   $ grep -i 'union' access.log | head -2
   203.0.113.77 - - [14/Mar/2026:08:02:11 +0900] "GET /item.php?id=1+UNION+SELECT+1,2,3 HTTP/1.1" 200 512
   203.0.113.77 - - [14/Mar/2026:08:02:19 +0900] "GET /item.php?id=1%20union%20select%20user() HTTP/1.1" 200 488

   -> 공백이 + 와 %20 두 형태다. 대문자 UNION 도 있다.

3. 두 번째 시도 (부분 실패):
   $ grep -cEi 'union[[:space:]]+select' access.log
   0
   -> 여전히 0. [[:space:]] 는 리터럴 공백만 본다. + 와 %20 은 공백이 아니다.

4. 접근 변경 — 구분자 후보를 집합으로 넓힌다
   $ grep -cEi 'union(\+|%20|[[:space:]])+select' access.log
   47

   개수가 나왔다. 이제 페이로드를 본다.

5. 페이로드 추출 — URI 만 뽑는다
   $ grep -Ei 'union(\+|%20|[[:space:]])+select' access.log |
       grep -oE '"[A-Z]+ [^" ]+' | cut -d' ' -f2 | sort -u | head
   /item.php?id=1%20union%20select%20user()
   /item.php?id=1+UNION+SELECT+1,2,3
   /item.php?id=1+union+select+load_file('/etc/passwd')
   /item.php?id=-1+UNION+SELECT+1,table_name,3+FROM+information_schema.tables

6. 성공한 시도만 — 상태 코드 200
   $ grep -Ei 'union(\+|%20|[[:space:]])+select' access.log |
       grep -E '" 200 ' | wc -l
   41
   $ grep -Ei 'union(\+|%20|[[:space:]])+select' access.log |
       grep -oE '" [0-9]{3} ' | sort | uniq -c
        41 " 200
         4 " 403
         2 " 500

7. 다른 인젝션 유형도 함께 (한 번에 분류)
   $ grep -Eio 'union(\+|%20|[[:space:]])+select|or(\+|%20|[[:space:]])+1=1|sleep\([0-9]+\)|information_schema|load_file\(' access.log |
       tr 'A-Z' 'a-z' | sed 's/+/ /g; s/%20/ /g' | sort | uniq -c | sort -nr
        47 union select
        19 information_schema
        11 or 1=1
         6 load_file(
         3 sleep(5)

8. 교차검증 — 정규식 대신 URL 디코딩 후 단순 검색
   $ sed 's/+/ /g; s/%20/ /g' access.log | grep -ci 'union select'
   47
   같은 47. 정규식이 넓지도 좁지도 않았다.

정답: SQL 인젝션 47회 (성공 41회), 페이로드는 UNION SELECT 기반 컬럼 열거와
      information_schema.tables 덤프, load_file('/etc/passwd')
```

1·3단계의 실패가 핵심이다. **`grep -c`가 0을 반환했을 때 "없다"고 결론 내리면 안 된다.** 먼저 넓은 키워드(`union`) 하나로 원문을 보고, 실제 표기(인코딩·대소문자)를 확인한 뒤 패턴을 조립한다.

## 막혔을 때 다음 체크

1. `-E`를 붙였는가 — BRE에서는 `(` `|` `+` `{`가 리터럴이다
2. `\d`를 `[0-9]` 또는 `[[:digit:]]`로 바꿨는가
3. 문자 클래스를 대괄호 두 겹으로 감쌌는가
4. `.`을 `\.`로 이스케이프했는가
5. 패턴을 작은따옴표로 감쌌는가
6. 0건이 나왔을 때 넓은 키워드 하나로 원문을 확인했는가
7. URL 인코딩(`+`, `%20`, `%2e`)과 대소문자 변형을 고려했는가
8. 앵커(`^`, `$`, `\<`, `\>`, `[[:space:]]`)로 오탐을 막았는가
9. lookaround가 필요하면 `-o` + `sed`/`cut`으로 우회했는가, 아니면 `rg -P`로 갔는가
10. AND 조건을 파이프로, NOT 조건을 `-v`로 표현했는가
11. `-c`(줄 수)와 `-o | wc -l`(매칭 개수)를 구분했는가
12. 필드 위치가 확실해졌다면 `awk` 완전 일치로 옮겼는가

## 출처

- SRC-015 — GNU grep manual: BRE/ERE 문법 차이, POSIX 문자 클래스 목록, `\<` `\>` `\b` GNU 확장, `-P` 지원 여부와 lookaround 제약
- SRC-055 — ripgrep User Guide: `-P`(PCRE2)로 lookaround를 쓰는 대안과 기본 정규식 엔진의 차이
- ERE에서 리터럴 `{`의 처리와 역참조 `\1` 지원 여부는 구현·버전에 따라 다르므로 `grep -F`나 Python `re`로 우회할 것
- `[[:punct:]]`에 포함되는 정확한 문자 집합은 로케일에 따라 달라질 수 있다
