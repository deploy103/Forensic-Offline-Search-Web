---
id: FOR-0115
title: "awk로 로그 필드 추출·집계: $1 NF NR과 연관배열 카운트"
slug: "awk-fields"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "CSV log", "IIS W3C log"]
file_paths: ["/var/log/auth.log", "/var/log/apache2/access.log", "/var/log/nginx/access.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["awk", "gawk", "grep", "sort", "uniq"]
commands: ["awk '{print $1}' access.log", "awk -F: '{print $1}' /etc/passwd", "awk '$9==404 {print $7}' access.log", "awk '{c[$1]++} END {for (k in c) print c[k], k}' access.log", "awk -F'[][]' '{print $2}' access.log", "awk '{s+=$10} END {print s}' access.log"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["$1", "$4", "$7", "$9", "$10", "NF", "NR", "FNR", "FS", "OFS"]
file_formats: ["log", "txt", "csv", "tsv"]
primary_terms: ["awk", "awk 필드 추출", "필드 기준 집계"]
keywords: ["awk", "gawk", "필드 추출", "NF", "NR", "FNR", "FS", "OFS", "연관배열", "associative array", "END 블록", "printf", "필드 번호"]
aliases: ["awk 사용법", "awk 필드", "awk 집계", "awk 카운트", "awk 구분자", "awk 합계", "특정 열만 출력"]
symptom_keywords: ["특정 열만 뽑고 싶다", "필드 개수를 세고 싶다", "IP별 개수를 세고 싶다", "합계를 구하고 싶다", "정규식이 오탐을 낸다", "필드 번호가 안 맞는다"]
related: ["FOR-0116", "FOR-0117", "FOR-0111"]
source_ids: ["SRC-056", "SRC-058"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`awk`는 로그를 공백(또는 `-F`로 지정한 구분자)으로 잘라 `$1`·`$7`·`$9` 같은 **필드 번호로 접근**하게 해 주며, `{c[$1]++} END {for (k in c) print c[k], k}` 한 줄로 빈도 집계가 끝난다 — 필드 번호가 확실한 상황에서는 정규식보다 **오탐이 0**이라는 것이 결정적 이유다.

## 어떤 문제에서 필요한가

- "IP별 요청 수", "상태 코드별 개수", "전송 바이트 합계" 같은 집계형 문제
- 정규식으로 뽑았더니 본문 안의 값까지 섞여 개수가 틀리는 상황
- `$9 == 200`처럼 **완전 일치** 조건이 필요한 상황
- 두 로그를 키로 이어 붙여야 하는 상황
- CSV·TSV·`/etc/passwd`처럼 구분자가 정해진 파일에서 특정 열만 필요한 상황

## 문제에서 처음 볼 단서

1. 문제 지문에 "가장 많이", "몇 번", "합계", "평균" → 집계다. `awk`가 정답이다
2. 로그 형식이 확정됐다 → 필드 번호를 쓸 수 있다
3. `grep -c` 결과와 눈으로 센 값이 다르다 → 정규식이 넓게 잡힌 것이다
4. 구분자가 `:`·`,`·탭이다 → `-F`로 지정한다

먼저 필드 번호를 확정한다.

```bash
# 첫 줄의 필드를 번호와 함께 나열한다 — 이 한 줄이 이후 모든 작업의 기준이다
head -1 access.log | awk '{for (i=1; i<=NF; i++) printf "%d=[%s]\n", i, $i}'
```

```text
1=[203.0.113.77]
2=[-]
3=[-]
4=[[14/Mar/2026:07:11:02]
5=[+0900]]
6=["GET]
7=[/admin/]
8=[HTTP/1.1"]
9=[403]
10=[199]
11=["-"]
12=["Mozilla/5.0]
13=[(Windows]
```

**`$4`와 `$5`가 시각 하나로 쪼개지고 User-Agent가 여러 필드로 흩어진다는 사실**을 여기서 눈으로 확인해 두면 이후 실수가 없다.

## 30초 절차

```bash
awk '{c[$1]++} END {for (k in c) print c[k], k}' access.log | sort -nr | head -10
```

출력 예시:

```text
1842 203.0.113.77
311 192.168.10.24
96 198.51.100.5
41 10.0.0.50
```

동등한 관용구가 하나 더 있다. 짧아서 더 많이 쓰인다.

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -10
```

| | `awk` 배열 방식 | `sort \| uniq -c` 방식 |
| --- | --- | --- |
| 메모리 | 고유 키 수만큼 (IP 수만큼) | `sort`가 전체를 다룬다 |
| 속도 | 파일 1회 통과. 빠르다 | 정렬 비용이 있다 |
| 대용량 | 고유 키가 적으면 압도적으로 유리 | 고유 키가 매우 많으면 유리 |
| 가독성 | 조건·복합 키를 붙이기 쉽다 | 짧다 |

## 상세 절차

### 1단계 — 내장 변수 7개

| 변수 | 의미 | 기본값 |
| --- | --- | --- |
| `$0` | 레코드(줄) 전체 | — |
| `$1`, `$2`, ... | n번째 필드 | — |
| `$NF` | **마지막** 필드 | — |
| `$(NF-1)` | 마지막에서 두 번째 | — |
| `NF` | 이 줄의 필드 개수 | — |
| `NR` | 지금까지 읽은 레코드 번호 (전체 누적) | — |
| `FNR` | **현재 파일 안에서의** 레코드 번호 | — |
| `FS` | 입력 필드 구분자 | 공백류 |
| `OFS` | 출력 필드 구분자 | 스페이스 1개 |
| `RS` | 입력 레코드 구분자 | 개행 |
| `ORS` | 출력 레코드 구분자 | 개행 |
| `FILENAME` | 현재 파일 이름 | — |

```bash
awk '{print NR, NF, $1, $NF}' access.log | head -3
```

```text
1 13 203.0.113.77 "Mozilla/5.0
2 13 192.168.10.24 "curl/8.4.0"
3 9 198.51.100.5 87
```

3번 줄의 `NF`가 9다. **필드 개수가 줄마다 다르면 형식이 섞여 있다는 신호다.** 이것을 먼저 잡아야 한다.

```bash
# 필드 개수 분포 — 하나로 모이지 않으면 형식이 섞여 있다
awk '{print NF}' access.log | sort -n | uniq -c
```

```text
  41866 13
     14 9
      2 1
```

13이 정상(combined), 9는 User-Agent가 짧은 줄, 1은 빈 줄이나 깨진 줄이다. 2건은 직접 확인한다.

```bash
awk 'NF==1 {print NR": ["$0"]"}' access.log
```

`NR`과 `FNR`의 차이는 여러 파일을 함께 처리할 때 드러난다.

```bash
$ awk '{print FILENAME, FNR, NR}' a.log b.log | sed -n '1p;3p;4p'
a.log 1 1
a.log 3 3
b.log 1 4
```

`FNR==1`은 "각 파일의 첫 줄"이므로 CSV 헤더 건너뛰기에 쓴다.

### 2단계 — 구분자 지정 (`-F`)

| 목적 | 옵션 |
| --- | --- |
| 공백 (기본) | 생략 |
| 콜론 | `-F:` |
| 쉼표 | `-F,` |
| 탭 | `-F'\t'` |
| 파이프 | `-F'\|'` (정규식이므로 이스케이프) |
| 여러 문자 중 하나 | `-F'[:,]'` |
| 대괄호 | `-F'[][]'` |
| 두 글자 이상 | `-F' - '` (정규식으로 해석된다) |
| `FS`를 코드에서 | `awk 'BEGIN {FS=":"} {print $1}'` |

기본 `FS`(공백)에는 특별한 규칙이 있다. **연속된 공백·탭을 하나로 취급하고 줄 앞뒤 공백을 무시한다.** 이것이 `cut`과의 결정적 차이다 ([FOR-0116](./cut-fields.html)).

```bash
$ printf '  a   b\tc  \n' | awk '{print NF"|"$1"|"$2"|"$3"|"}'
3|a|b|c|
```

반면 `FS`를 **한 글자로 명시하면** 연속 구분자가 각각 세어지며 빈 필드가 생긴다.

```bash
$ printf 'a,,b\n' | awk -F, '{print NF"|"$1"|"$2"|"$3"|"}'
3|a||b|
```

이 차이가 CSV의 빈 필드를 살려 주므로 오히려 유용하다.

Apache 로그에서 대괄호와 따옴표를 구분자로 쓰는 실전 예다.

```bash
# 시각만 (대괄호 사이)
awk -F'[][]' '{print $2}' access.log | head -2

# User-Agent 만 (따옴표 기준 6번째 조각)
awk -F'"' '{print $6}' access.log | head -2

# 요청 줄 전체 (따옴표 기준 2번째 조각)
awk -F'"' '{print $2}' access.log | head -2
```

```text
14/Mar/2026:07:11:02 +0900
14/Mar/2026:07:11:09 +0900
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
curl/8.4.0
GET /admin/ HTTP/1.1
POST /upload.php HTTP/1.1
```

`-F'"'`로 잘랐을 때의 조각 번호다.

| 조각 | 내용 |
| --- | --- |
| `$1` | IP부터 `[시각]`까지 (앞부분 전체) |
| `$2` | 요청 줄 (`GET /admin/ HTTP/1.1`) |
| `$3` | ` 403 199 ` (상태 코드와 크기) |
| `$4` | Referer |
| `$5` | ` ` (공백 1개) |
| `$6` | User-Agent |

### 3단계 — 패턴 { 액션 } 구조

`awk` 프로그램은 `패턴 { 액션 }` 쌍의 나열이다. 둘 중 하나를 생략할 수 있다.

| 형태 | 의미 |
| --- | --- |
| `{ 액션 }` | 모든 줄에 실행 |
| `패턴` | 조건이 참인 줄을 그대로 출력 (`{print $0}` 생략) |
| `패턴 { 액션 }` | 조건이 참인 줄에만 실행 |
| `BEGIN { 액션 }` | 입력을 읽기 **전에** 1회 |
| `END { 액션 }` | 입력을 다 읽은 **후에** 1회 |
| `패턴1, 패턴2 { 액션 }` | 범위. 패턴1 줄부터 패턴2 줄까지 |

조건에 쓸 수 있는 것들이다.

| 조건 | 예 | 의미 |
| --- | --- | --- |
| 비교 | `$9 == 404` | 숫자로 보이면 수치 비교 |
| 문자열 비교 | `$1 == "203.0.113.77"` | **완전 일치** |
| 부등호 | `$10 > 100000` | 응답 크기 100KB 초과 |
| 정규식 (줄 전체) | `/POST/` | `$0`에 매칭 |
| 정규식 (필드) | `$7 ~ /\.php$/` | `$7`이 `.php`로 끝난다 |
| 부정 정규식 | `$7 !~ /\.(css\|js\|png)$/` | 정적 리소스 제외 |
| 논리 결합 | `$1=="1.2.3.4" && $9==200` | AND |
| 논리 결합 | `$9==403 \|\| $9==404` | OR |
| 필드 개수 | `NF != 13` | 형식이 다른 줄 |
| 줄 번호 | `NR >= 8840 && NR <= 8850` | 구간 |
| 존재 여부 | `$7` | `$7`이 빈 문자열/0이 아니면 참 |

```bash
# 404 를 낸 URI 목록
awk '$9==404 {print $7}' access.log | sort | uniq -c | sort -nr | head

# 특정 IP 의 성공한 POST 만
awk '$1=="203.0.113.77" && $6=="\"POST" && $9==200' access.log

# 정적 리소스를 뺀 URI 상위
awk '$7 !~ /\.(css|js|png|jpg|gif|ico|woff2?|svg)$/ {print $7}' access.log |
  sort | uniq -c | sort -nr | head

# 응답이 100KB 를 넘은 요청 (유출 후보)
awk '$10+0 > 100000 {print $1, $7, $10}' access.log

# 줄 번호 범위 (grep -n 으로 찾은 구간을 통째로)
awk 'NR>=8840 && NR<=8850' access.log

# 문자열 범위 (시작 패턴 ~ 종료 패턴)
awk '/07:19:00/,/07:21:00/' access.log
```

`$6=="\"POST"`의 따옴표가 눈에 걸린다. Apache combined에서 `$6`은 `"GET`처럼 **여는 따옴표를 포함**하기 때문이다. 깔끔하게 하려면 `-F'"'`로 요청 줄을 잘라 다시 쪼갠다.

```bash
awk -F'"' '{split($2, r, " "); print r[1], r[2]}' access.log | head -2
```

```text
GET /admin/
POST /upload.php
```

`$10+0 > 100000`의 `+0`은 **강제 수치 변환**이다. Apache는 응답 크기가 없을 때 `-`를 쓰므로, `-`는 `+0`으로 `0`이 되어 안전하게 비교된다. 이 습관이 오류를 막는다.

### 4단계 — 연관배열로 집계

`awk`의 배열은 **키가 문자열인 해시**다. 선언이 필요 없고, 없는 키를 읽으면 빈 문자열/0이다. 그래서 `c[$1]++`이 그대로 카운터가 된다.

```bash
# 1) 단일 키 빈도
awk '{c[$1]++} END {for (k in c) print c[k], k}' access.log | sort -nr | head

# 2) 복합 키 — IP + 상태 코드
awk '{c[$1" "$9]++} END {for (k in c) print c[k], k}' access.log | sort -nr | head

# 3) 합계
awk '{s += $10+0} END {printf "총 %d 바이트 (%.2f MB)\n", s, s/1048576}' access.log

# 4) 키별 합계 — IP 별 전송량
awk '{s[$1] += $10+0} END {for (k in s) printf "%12d  %s\n", s[k], k}' access.log |
  sort -nr | head

# 5) 최초/최종 시각 — IP 별
awk -F'[][]' '{split($1,a," "); ip=a[1]; if (!(ip in first)) first[ip]=$2; last[ip]=$2}
              END {for (k in first) print k, first[k], "~", last[k]}' access.log

# 6) 고유 개수 (distinct count) — IP 별 접근한 URI 종류 수
awk '{seen[$1" "$7]=1} END {for (k in seen) {split(k,a," "); n[a[1]]++}
      for (ip in n) print n[ip], ip}' access.log | sort -nr | head

# 7) 평균
awk '$9==200 {s+=$10+0; n++} END {if (n) printf "평균 %.1f 바이트 (n=%d)\n", s/n, n}' access.log

# 8) 최대값과 그 줄
awk '$10+0 > max {max=$10+0; line=$0} END {print max; print line}' access.log
```

`for (k in arr)`의 **순회 순서는 정해져 있지 않다.** 정렬된 출력이 필요하면 반드시 `sort`에 넘긴다. `gawk`에는 `PROCINFO["sorted_in"]`으로 순서를 지정하는 확장이 있지만, 이식성을 위해 `sort`를 쓰는 편이 안전하다.

`in` 연산자로 키 존재를 확인할 때는 `if (k in arr)`를 쓴다. `if (arr[k])`로 쓰면 **없는 키를 만들어 ���린다.**

### 5단계 — printf 서식

`print`는 필드를 `OFS`로 이어 붙이고 `ORS`로 끝낸다. 정렬된 표가 필요하면 `printf`를 쓴다. `printf`는 **개행을 자동으로 붙이지 않으므로 `\n`을 직접 넣는다.**

| 서식 | 의미 | 예 | 출력 |
| --- | --- | --- | --- |
| `%s` | 문자열 | `printf "%s\n", $1` | `203.0.113.77` |
| `%10s` | 오른쪽 정렬 폭 10 | `printf "%10s\n", $9` | `       403` |
| `%-15s` | 왼쪽 정렬 폭 15 | `printf "%-15s\|\n", $1` | `203.0.113.77   \|` |
| `%d` | 정수 | `printf "%d\n", $10` | `199` |
| `%6d` | 폭 6 정수 | `printf "%6d\n", c[k]` | `  1842` |
| `%.2f` | 소수 2자리 | `printf "%.2f\n", s/1048576` | `12.47` |
| `%%` | 리터럴 `%` | `printf "%d%%\n", p` | `47%` |
| `%x` | 16진수 | `printf "%x\n", 255` | `ff` |
| `%c` | 문자 | `printf "%c\n", 65` | `A` |

```bash
awk '{c[$1]++; t+=1}
     END {printf "%-16s %8s %7s\n", "IP", "요청수", "비율"
          for (k in c) printf "%-16s %8d %6.2f%%\n", k, c[k], 100*c[k]/t}' access.log |
  sort -k2 -nr | head -5
```

```text
203.0.113.77          1842  43.97%
192.168.10.24          311   7.42%
198.51.100.5            96   2.29%
10.0.0.50               41   0.98%
IP                  요청수    비율
```

헤더가 `sort` 때문에 아래로 밀렸다. 헤더를 살리려면 `END` 안에서 정렬하지 말고 파이프를 나눈다.

### 6단계 — 자주 쓰는 내장 함수

| 함수 | 하는 일 | 예 |
| --- | --- | --- |
| `length(s)` | 길이 | `length($7) > 200` — 비정상적으로 긴 URI |
| `substr(s, i, n)` | 부분 문자열 (**1부터**) | `substr($4, 2, 11)` — `[14/Mar/2026` |
| `index(s, t)` | `t`의 위치 (없으면 0) | `index($7, "..") > 0` |
| `split(s, arr, sep)` | 쪼개서 배열에. 반환값은 개수 | `n=split($4, d, ":")` |
| `sub(re, rep)` | 첫 매칭 1건 치환 | `sub(/^\[/, "", $4)` |
| `gsub(re, rep)` | 전체 치환. 반환값은 횟수 | `gsub(/"/, "", $0)` |
| `match(s, re)` | 매칭 위치. `RSTART`/`RLENGTH` 설정 | `if (match($7, /cmd=[^& ]+/))` |
| `toupper` / `tolower` | 대소문자 | `tolower($7)` |
| `sprintf(f, ...)` | 서식 문자열 반환 | `key = sprintf("%s|%s", $1, $9)` |
| `systime()` (gawk) | 현재 epoch | 보고용 타임스탬프 |
| `strftime(f, t)` (gawk) | epoch → 문자열 | `strftime("%F %T", $1)` |
| `mktime("Y M D H M S")` (gawk) | 문자열 → epoch | 시간 계산 |

`substr`은 **1부터 센다.** 0부터 세는 언어와 다르다.

```bash
# 시각에서 시:분만 (분 단위 요청량 그래프)
awk -F'[][]' '{print substr($2, 13, 5)}' access.log | sort | uniq -c
```

```text
     12 07:11
    488 07:19
   1044 07:20
    298 07:21
```

`match`와 `RSTART`/`RLENGTH`로 정규식 추출도 가능하다.

```bash
awk '{if (match($0, /cmd=[^& "]+/)) print substr($0, RSTART+4, RLENGTH-4)}' access.log |
  sort | uniq -c | sort -nr
```

```text
     41 id
     33 whoami
     12 cat+/etc/passwd
```

epoch 변환은 `gawk` 전용이다. 시간대를 명시해야 한다.

```bash
# UTC 기준 epoch -> KST 문자열 (gawk)
TZ=Asia/Seoul gawk 'BEGIN {print strftime("%F %T %Z", 1773450662)}'
```

`mawk`·`busybox awk`에는 `strftime`이 없으므로, 이식성이 필요하면 `date -d @초`로 넘긴다.

### 7단계 — 두 로그를 키로 잇기

`NR==FNR` 관용구가 표준이다. 첫 파일을 읽는 동안에만 `NR`과 `FNR`이 같다.

```bash
# 공격 IP 목록(ioc.txt)에 있는 IP 의 요청만 뽑는다
awk 'NR==FNR {ioc[$1]=1; next} $1 in ioc' ioc.txt access.log

# 웹 로그의 IP 를 인증 로그에서도 봤는지
awk 'NR==FNR {web[$1]=1; next}
     /Failed password/ {for (i=1;i<=NF;i++) if ($i=="from" && ($(i+1) in web)) print $(i+1)}' \
    <(awk '{print $1}' access.log | sort -u) auth.log | sort | uniq -c
```

`next`는 나머지 규칙을 건너뛰고 다음 레코드로 간다. 이것을 빼면 첫 파일의 줄이 두 번째 블록에도 들어가 결과가 오염된다.

## 출력 필드 해석

Apache/nginx **combined** 로그의 `awk` 필드 번호와, 각 필드로 무엇을 판정하는지다.

| 필드 | 이름 | 판정 |
| --- | --- | --- |
| `$1` | 클라이언트 IP | 공격 출처. 프록시 뒤라면 `X-Forwarded-For` 확인 |
| `$4`+`$5` | `[시각` + `오프셋]` | 타임라인 기준. `-F'[][]'`로 통째로 잡는 편이 낫다 |
| `$6` | `"메서드` | `"POST`는 업로드·로그인 후보 |
| `$7` | URI (쿼리 포함) | 공격 페이로드가 여기 있다 |
| `$8` | `프로토콜"` | `HTTP/1.0` 고정은 스크립트 도구 신호 |
| `$9` | 상태 코드 | **성공/실패 판정의 핵심** |
| `$10` | 응답 바이트 | 급증은 유출 성공 신호. `-`는 `+0`으로 처리 |
| `$11` | Referer | `"-"`면 직접 접근(도구) |
| `$12`~ | User-Agent | 여러 필드로 흩어진다. `-F'"'` `$6` 사용 |

상태 코드 판정표다.

| `$9` | 의미 | 포렌식 해석 |
| --- | --- | --- |
| `200` | 성공 | 공격이 통했다 |
| `201`/`204` | 생성/내용없음 | API 성공 |
| `301`/`302` | 리다이렉트 | 로그인 성공 후 이동인 경우가 많다 |
| `304` | 변경 없음 | 캐시. 노이즈 |
| `401`/`403` | 인증·권한 실패 | 시도했으나 막혔다 |
| `404` | 없음 | **스캔의 지문.** 404가 몰린 IP가 스캐너다 |
| `500` | 서버 오류 | 인젝션 시도가 쿼리를 깨뜨린 흔적 |

다른 형식의 필드 번호다.

| 형식 | IP | 시각 | 상태/결과 |
| --- | --- | --- | --- |
| Apache/nginx combined | `$1` | `$4 $5` | `$9` |
| syslog RFC3164 | 메시지 안 (`from` 다음) | `$1 $2 $3` | 메시지 문구 |
| IIS W3C | `#Fields:`의 `c-ip` 위치 | `$1 $2` | `sc-status` 위치 |
| `/etc/passwd` (`-F:`) | — | — | `$1`=계정 `$3`=UID `$7`=셸 |
| CSV (`-F,`) | 헤더 순서 | 헤더 순서 | 헤더 순서 |

IIS는 필드 순서가 설정마다 다르므로 번호를 고정하지 말고 헤더에서 계산한다.

```bash
# #Fields: 에서 c-ip 가 몇 번째인지 자동으로 찾아 그 필드를 집계한다
awk '/^#Fields:/ {for (i=2; i<=NF; i++) if ($i=="c-ip") col=i-1; next}
     /^#/ {next}
     col {c[$col]++}
     END {for (k in c) print c[k], k}' u_ex260314.log | sort -nr | head
```

`#Fields:` 줄은 `#Fields:` 자체가 `$1`이므로 필드 위치에서 1을 빼는 것이 요점이다.

## pivot: 다음에 볼 artifact

| `awk`로 얻은 것 | 다음 목표 |
| --- | --- |
| 상위 IP | pcap `ip.addr == <IP>`, EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) |
| 404가 몰린 IP | 스캐너 확정 → 그 IP의 200 응답만 재추출 |
| 200을 받은 URI | 업로드된 웹셸 경로 후보 |
| 응답 크기 급증 지점 | 데이터 유출 시각 |
| 최초/최종 시각 | 다른 로그를 같은 구간으로 자른다 ([FOR-0118](./head-tail-less.html)) |
| 필드 개수 이상(`NF`) | 형식이 섞인 줄 → 원문 확인 ([FOR-0111](./log-triage.html)) |
| 정규식 결과와 불일치 | `awk` 완전 일치를 기준값으로 채택 ([FOR-0113](./grep-e-regex.html)) |
| 값 목록 | 빈도 정렬 ([FOR-0117](./sort-uniq.html)) |

## 흔한 함정

- **필드 번호를 확인하지 않고 쓰는 것.** IIS는 `$1`이 날짜다. `head -1 | awk '{for(i=1;i<=NF;i++) print i, $i}'`로 한 번 찍어 보는 데 3초가 걸린다.
- **`$4`를 시각 전체라고 믿는 것.** Apache combined에서 시각은 `$4`+`$5`로 쪼개진다. `-F'[][]'`의 `$2`가 시각 전체다.
- **User-Agent를 `$12`로 뽑는 것.** 공백 때문에 여러 필드로 흩어진다. `-F'"'`의 `$6`을 쓴다.
- **`$10 > 100000`을 그냥 쓰는 것.** 응답 크기가 `-`인 줄에서 문자열 비교가 되어 결과가 어긋난다. `$10+0 > 100000`.
- **`for (k in arr)` 순서를 신뢰하는 것.** 정해진 순서가 없다. 출력은 항상 `sort`에 넘긴다.
- **`if (arr[k])`로 존재를 확인하는 것.** 없는 키를 생성해 배열이 오염된다. `if (k in arr)`.
- **`NR==FNR` 뒤에 `next`를 빼는 것.** 첫 파일의 줄이 두 번째 블록에서도 처리되어 집계가 부풀려진다.
- **정규식을 필드 없이 `$0`에 거는 것.** `/203.0.113.77/`는 Referer나 쿼리 안의 IP도 잡는다. 출처 IP를 세려면 `$1=="203.0.113.77"`.
- **`substr`을 0부터 센다고 가정하는 것.** `awk`는 1부터다.
- **`printf`에 `\n`을 안 붙이는 것.** 출력이 한 줄로 붙어 나온다.
- **`gawk` 전용 함수를 `mawk`에서 쓰는 것.** `strftime`·`mktime`·`gensub`·`PROCINFO`는 `gawk` 확장이다. `awk --version`으로 무엇인지 확인한다.
- **CSV를 `-F,`로 자르는 것.** 인용 필드 안의 쉼표(`"Seoul, KR"`)가 필드를 쪼갠다. 진짜 CSV는 전용 파서로 다룬다.
- **큰따옴표로 프로그램을 감싸는 것.** 셸이 `$1`을 먼저 확장해 빈 문자열로 만든다. `awk` 프로그램은 **항상 작은따옴표**.

## 교차검증

정규식 집계와 필드 집계를 나란히 세운다.

```bash
# 1) 필드 완전 일치 — 기준값
awk '$1=="203.0.113.77"' access.log | wc -l

# 2) 배열 카운트 — 같은 값이 나와야 한다
awk '{c[$1]++} END {print c["203.0.113.77"]+0}' access.log

# 3) 정규식 (앵커 있음)
grep -cE '^203\.0\.113\.77[[:space:]]' access.log

# 4) 정규식 (앵커 없음) — 여기서 숫자가 커진다
grep -c '203\.0\.113\.77' access.log
```

```text
1842
1842
1842
1849
```

4번이 7 더 많다. Referer나 쿼리 문자열에 그 IP가 들어간 줄이다. **필드 완전 일치가 기준값이고, 정규식은 앵커를 붙이더라도 보조 수단이다.**

합계도 두 방법으로 확인한다.

```bash
awk '{s+=$10+0} END {print s}' access.log
awk '{print $10}' access.log | grep -E '^[0-9]+$' | paste -sd+ - | bc
```

## mini walkthrough

```text
문제:
"침해된 웹 서버의 access.log 에서 (1) 스캐너 IP (2) 웹셸 경로
 (3) 유출된 데이터의 총 바이트를 구하세요."
첨부: access.log (41,882줄, Apache combined)

1. 첫 시도 (실패):
   $ awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -3
      9821 10.0.0.50
      8804 10.0.0.51
      1842 203.0.113.77

   -> 1·2위가 사설 IP. 이걸 "가장 많이 접속한 IP = 공격자" 로 쓰면 오답이다.
      빈도만으로는 판정이 안 된다.

2. 접근 변경 — 빈도가 아니라 "404 를 몇 개 만들었나" 로 본다
   $ awk '$9==404 {c[$1]++} END {for (k in c) print c[k], k}' access.log | sort -nr | head -3
      1391 203.0.113.77
         4 198.51.100.5
         1 10.0.0.51

   -> 203.0.113.77 이 404 를 1,391개 만들었다. 스캐너 확정.
      10.0.0.50/51 은 404 가 0건 = 정해진 엔드포인트만 치는 헬스체크다.

3. 그 IP 의 상태 코드 분포로 성공 지점을 찾는다
   $ awk '$1=="203.0.113.77" {c[$9]++} END {for (k in c) print k, c[k]}' access.log | sort -n
   200 89
   403 362
   404 1391

   -> 200 이 89건. 이 안에 업로드 성공과 웹셸 실행이 있다.

4. 200 을 받은 URI 를 본다
   $ awk '$1=="203.0.113.77" && $9==200 {print $6, $7}' access.log | sort | uniq -c | sort -nr
        74 "GET /u/av4tar.php
         9 "GET /
         5 "GET /item.php
         1 "POST /upload.php

   -> POST /upload.php 200 이 딱 1건 = 업로드 성공.
      /u/av4tar.php 를 74회 GET = 웹셸이다. (파일명이 shell 이 아니라 av4tar 라
      grep 'shell' 로는 못 찾는다)

5. 업로드 시각
   $ awk -F'[][]' '$0 ~ /POST \/upload\.php/ && $0 ~ /" 200 / {print $2}' access.log
   14/Mar/2026:07:19:44 +0900
   -> +0900 = KST. 그대로 07:19:44 KST.

6. 웹셸 요청의 응답 바이트 합계 — 유출량
   $ awk '$1=="203.0.113.77" && $7 ~ /^\/u\/av4tar\.php/ {s += $10+0; n++}
          END {printf "%d건 %d바이트 (%.2f MB)\n", n, s, s/1048576}' access.log
   74건 41938204 바이트 (40.00 MB)

7. 어느 명령이 큰 응답을 냈나 (유출의 실체)
   $ awk '$1=="203.0.113.77" && $7 ~ /av4tar/ {
            if (match($7, /cmd=[^&]+/)) print $10+0, substr($7, RSTART+4, RLENGTH-4)}' access.log |
       sort -nr | head -4
   41871104 tar+-czf+-+/var/www/data
      41118 cat+/etc/passwd
       2244 ls+-la+/var/www/data
         42 id

   -> tar 로 /var/www/data 를 통째로 스트리밍한 한 건이 41.8MB.
      이것이 유출의 본체다.

8. 교차검증 — 합계를 다른 방법으로
   $ grep '^203\.0\.113\.77 ' access.log | grep '/u/av4tar\.php' |
       awk '{print $10}' | paste -sd+ - | bc
   41938204
   일치.

정답: (1) 스캐너 203.0.113.77 (404 1,391건)
      (2) 웹셸 /u/av4tar.php (업로드 2026-03-14 07:19:44 KST)
      (3) 유출 41,938,204 바이트 (약 40MB, tar 스트리밍 1건이 41.8MB)
```

1단계의 실패가 이 글의 요지다. **빈도 1위는 공격자가 아니다.** `awk`의 조건부 집계(`$9==404 {c[$1]++}`)로 "무엇을 많이 했는가"를 봐야 판정이 된다. 그리고 4단계에서 웹셸 이름이 `av4tar.php`였다는 점 — 키워드 추측(`shell`)이 아니라 **필드 집계로 찾아야** 놓치지 않는다.

## 막혔을 때 다음 체크

1. `head -1 | awk '{for(i=1;i<=NF;i++) print i, $i}'`로 필드 번호를 확정했는가
2. `awk '{print NF}' | sort -n | uniq -c`로 형식이 섞인 줄을 걸렀는가
3. 시각을 `$4 $5`가 아니라 `-F'[][]'`의 `$2`로 잡았는가
4. 숫자 비교에 `+0`을 붙였는가 (`-`가 든 필드)
5. 문자열 완전 일치(`==`)를 썼는가, 정규식(`~`)이 넓게 잡히지 않았는가
6. `for (k in arr)` 출력을 `sort`에 넘겼는가
7. `NR==FNR` 블록 끝에 `next`가 있는가
8. 프로그램을 작은따옴표로 감쌌는가
9. 빈도 1위가 헬스체크·크롤러가 아닌지 상태 코드 분포로 확인했는가
10. `gawk` 전용 함수를 쓰지 않았는가 (`awk --version` 확인)
11. 합계·개수를 다른 방법으로 한 번 더 세서 일치했는가
12. 필드로 안 되는 형식(CSV 인용 필드, JSON)이면 전용 파서로 옮겼는가

## 출처

- SRC-056 — GNU Awk User's Guide: 내장 변수(`NR` `NF` `FNR` `FS` `OFS` `RS`), `패턴 { 액션 }` 구조, 연관배열과 `in` 연산자, `printf` 서식, 내장 함수(`substr` `split` `gsub` `match`/`RSTART`/`RLENGTH`), 기본 `FS`의 공백 축약 규칙
- SRC-058 — Apache HTTP Server, Log Files: Combined Log Format의 필드 순서와 `%b`가 값이 없을 때 `-`로 기록된다는 점
- `strftime`·`mktime`·`gensub`·`PROCINFO`는 `gawk` 확장이며 `mawk`·`busybox awk`에서는 동작하지 않는다. `awk --version`으로 구현을 확인할 것
- 상태 코드의 포렌식 해석(404 집중 = 스캐너 등)은 경험적 판단 기준이며 환경에 따라 달라진다
