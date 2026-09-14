---
id: FOR-0116
title: "cut으로 로그에서 원하는 필드(컬럼)만 잘라내기"
slug: "cut-fields"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "CSV log", "/etc/passwd"]
file_paths: ["/etc/passwd", "/var/log/auth.log", "/var/log/apache2/access.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["cut", "awk", "grep", "sort", "uniq"]
commands: ["cut -d: -f1 /etc/passwd", "cut -d' ' -f1 access.log", "cut -c1-16 access.log", "cut -d, -f2,4 data.csv", "cut --complement -f1 data.tsv"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["-d", "-f", "-c", "--complement", "--output-delimiter"]
file_formats: ["log", "txt", "csv", "tsv"]
primary_terms: ["cut 필드 추출", "cut -d -f"]
keywords: ["cut", "필드 추출", "구분자", "delimiter", "컬럼 추출", "CSV 파싱", "고정폭 추출", "complement", "output-delimiter"]
aliases: ["cut 명령어", "cut 사용법", "cut -d -f", "특정 컬럼만 뽑기", "특정 열 자르기", "cut 필드"]
symptom_keywords: ["특정 컬럼만 뽑고 싶다", "구분자로 잘라야 한다", "awk가 과한 것 같다", "필드 번호를 모르겠다", "출력이 원래 순서와 다르다"]
related: ["FOR-0115", "FOR-0117", "FOR-0112"]
source_ids: ["SRC-056", "SRC-058"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`cut -d'구분자' -f번호`는 구분자가 확실하고 필드 순서를 유지한 채 잘라내기만 하면 되는 상황에서 `awk`보다 빠르고 짧다 — 단, **구분자가 연속되거나 필드 안에 구분자가 들어 있으면(따옴표로 감싼 CSV) 조용히 틀린 결과를 낸다**는 점이 결정적 제약이다.

## 어떤 문제에서 필요한가

- `/etc/passwd`의 계정명만, `auth.log`의 타임스탬프만처럼 **구분자가 고정된 필드 하나(또는 몇 개)**만 필요할 때
- CSV/TSV에서 특정 열만 빠르게 훑어볼 때
- 고정폭 로그(예: 매 줄 앞 15자가 타임스탬프)에서 문자 위치로 잘라야 할 때
- `awk '{print $N}'`을 쓰기엔 프로그램이 과하다고 느껴지는 한 줄짜리 작업

## 문제에서 처음 볼 단서

1. 구분자가 한 종류로 고정되어 있다 (`:`, `,`, `\t`, 고정폭)
2. 필요한 필드가 처음부터 순서대로, 혹은 몇 번째인지 명확하다
3. 필드 안에 구분자 자체가 들어갈 가능성이 없다 (예: IP, 계정명, UID)
4. 반대로 따옴표로 감싼 CSV라면 `cut`을 쓰면 안 된다는 신호다

```bash
head -1 access.log | tr -s ' ' '\n' | nl
```

이 한 줄로 공백 기준 필드 번호를 눈으로 확인한다.

## 30초 절차

```bash
cut -d' ' -f1 access.log | sort -u
```

1. 구분자 확인 (`:`인지 `,`인지 공백인지)
2. `-f`로 필드 번호(들) 지정
3. 필요하면 `sort`/`uniq -c`로 이어서 집계
4. 필드 안에 구분자가 섞일 가능성이 있으면 `awk -F` 또는 CSV 전용 파서로 전환

## 상세 절차

### 1단계 — 기본 문법

```bash
cut -d<구분자> -f<필드번호> <파일>
```

| 옵션 | 의미 |
| --- | --- |
| `-d` | 구분자 (delimiter). 기본값은 **탭**(`\t`) |
| `-f` | 필드 번호. `1`, `1,3`, `1-3`, `2-` 형태 |
| `-c` | 문자(바이트) 위치. `-f`와 배타적 |
| `--complement` | 지정한 필드를 **제외한** 나머지 |
| `--output-delimiter` | 출력 시 사용할 구분자 (기본은 입력 구분자와 동일) |
| `-s` | 구분자가 없는 줄은 아예 출력하지 않음 (`--only-delimited`) |

```bash
# /etc/passwd: 계정명 / UID / 셸
cut -d: -f1 /etc/passwd
cut -d: -f1,3,7 /etc/passwd
cut -d: -f1-3 /etc/passwd
```

```text
root
daemon
jhkim
```

```bash
cut -d: -f1,3,7 /etc/passwd
```

```text
root:0:/bin/bash
daemon:1:/usr/sbin/nologin
jhkim:1001:/bin/bash
```

**출력 구분자는 기본적으로 입력 구분자와 같다.** 다르게 하려면 `--output-delimiter`를 쓴다.

```bash
cut -d: -f1,3,7 --output-delimiter=' | ' /etc/passwd
```

```text
root | 0 | /bin/bash
jhkim | 1001 | /bin/bash
```

### 2단계 — 공백 구분자의 함정

기본 `-d` 없이 공백 로그를 자르면 **연속 공백이 각각 구분자로 취급되어 빈 필드가 생긴다.**

```bash
$ printf 'a   b  c\n' | cut -d' ' -f2
<빈 줄>
```

두 번째 필드가 공백들 사이의 빈 문자열이기 때문이다. `awk`는 기본 `FS`에서 연속 공백을 하나로 묶어 처리하지만 `cut`은 그렇지 않다 ([FOR-0115](./awk-fields.html)). **이것이 `cut`과 `awk`의 결정적 차이다.**

```bash
# 여러 공백을 하나로 정규화한 뒤 cut
tr -s ' ' < file.log | cut -d' ' -f1

# 또는 처음부터 awk를 쓴다
awk '{print $1}' file.log
```

로그가 필드 사이에 정확히 공백 1개만 쓴다는 것이 보장된 경우에만 `cut -d' '`을 그대로 쓴다.

### 3단계 — 여러 문자 중 하나를 구분자로

`cut -d`는 **한 글자만** 받는다. 정규식이나 여러 문자 집합을 구분자로 쓸 수 없다.

```bash
# 대괄호를 구분자로 쓰고 싶다 (Apache 시각 필드)
# cut -d'[]' 는 동작하지 않는다 -> 첫 글자만 구분자로 취급됨
cut -d'[' -f2 access.log | cut -d']' -f1
```

```text
14/Mar/2026:07:11:02 +0900
```

두 번 잘라 붙이는 우회가 필요하다. 이런 상황이 반복되면 `awk -F'[][]'`가 더 짧다.

```bash
awk -F'[][]' '{print $2}' access.log
```

### 4단계 — 필드 범위와 complement

```bash
# CSV: 2번째부터 끝까지
cut -d, -f2- data.csv

# CSV: 1번째부터 3번째까지
cut -d, -f1-3 data.csv

# 첫 필드(IP)만 제거하고 나머지 전부
cut -d, -f1 --complement data.csv
```

```text
timestamp,user,action
2026-03-14T07:11:02Z,jhkim,login
```

`--complement`는 민감 정보(IP, 계정)를 지우고 나머지만 볼 때 유용하다.

### 5단계 — 문자/바이트 위치로 자르기 (`-c`)

구분자가 없는 고정폭 로그(레거시 시스템, 일부 감사 로그)에서 쓴다.

```bash
# 매 줄의 앞 19자가 타임스탬프인 고정폭 로그
cut -c1-19 fixedwidth.log

# 20번째 문자부터 끝까지
cut -c20- fixedwidth.log

# 특정 구간 여러 개
cut -c1-4,10-14 fixedwidth.log
```

```text
2026-03-14 07:11:02
```

`-c`는 UTF-8 멀티바이트 문자가 섞여 있으면 바이트 단위로 잘려 문자가 깨질 수 있다. 한글이 포함된 고정폭 로그는 `-c` 대신 실제 필드 구조를 확인한다.

### 6단계 — Windows에서 동등 작업

WSL/Git Bash가 없으면 PowerShell로 대체한다.

```powershell
# 콜론 구분 (/etc/passwd 유사 파일)
Get-Content .\passwd.txt | ForEach-Object { ($_ -split ':')[0] }

# 공백 구분, 여러 공백 정규화 후 1번째 필드
Get-Content .\access.log | ForEach-Object { ($_ -split '\s+')[0] }

# CSV는 Import-Csv가 cut보다 안전하다 (따옴표/쉼표 처리)
Import-Csv .\data.csv | Select-Object -ExpandProperty user
```

**PowerShell의 `Import-Csv`는 따옴표로 감싼 필드 안의 쉼표를 올바르게 처리한다.** `cut -d,`가 못 하는 부분이다.

## 출력 필드 해석

| 상황 | `cut`이 맞는가 | 이유 |
| --- | --- | --- |
| `/etc/passwd`, `-F:` 계열 | 맞다 | 구분자가 필드 안에 안 나온다 |
| 공백 1개 고정 로그 | 맞다 | 연속 공백 문제 없음 |
| 공백 개수가 들쭉날쭉한 로그 | 아니다 | `awk`나 `tr -s` 선처리 필요 |
| 따옴표 CSV (`"Seoul, KR"` 포함) | 아니다 | 필드 안 쉼표가 잘못 잘린다 |
| 고정폭, 구분자 없음 | `-c`로 가능 | 문자 위치가 안정적일 때만 |
| 여러 문자 중 하나로 구분(`[`, `]`, `"`) | 부분적으로 가능 | 한 글자씩 두 번 자르거나 `awk` 전환 |

## pivot: 다음에 볼 artifact

| `cut`으로 얻은 것 | 다음 목표 |
| --- | --- |
| IP 목록 | `sort \| uniq -c`로 빈도 집계 ([FOR-0117](./sort-uniq.html)) |
| 계정명 목록 | `/etc/shadow`, `auth.log`의 로그인 이력과 대조 |
| 타임스탬프 컬럼 | 특정 구간만 `awk`/`grep`으로 재추출 |
| UID 목록 | 0번(root) 또는 비정상 UID 재검토 |
| 필드 번호가 로그마다 다름을 확인 | 헤더 기반 자동 추출이 필요하면 `awk`로 전환 |

## 흔한 함정

- **공백 로그에 `cut -d' '`을 그냥 쓰는 것** → 연속 공백이 빈 필드를 만들어 필드 번호가 밀린다 → `tr -s ' '`로 정규화하거나 `awk`를 쓴다.
- **`-d`에 여러 문자를 넣는 것** → 첫 글자만 구분자로 취급되어 조용히 틀린다 → 한 글자씩 두 번 자르거나 `awk -F'[...]'`로 바꾼다.
- **따옴표 CSV를 `cut -d,`로 자르는 것** → 필드 안의 쉼표가 필드를 쪼갠다 → 진짜 CSV는 `csvkit`, Python `csv`, PowerShell `Import-Csv`로 다룬다.
- **`-f`와 `-c`를 혼동하는 것** → `-f`는 필드 번호, `-c`는 문자 위치다. 함께 쓰면 에러가 난다.
- **출력 구분자가 입력과 같다는 것을 잊는 것** → 여러 필드를 뽑았는데 원래 구분자로 다시 이어져 헷갈린다 → `--output-delimiter`로 명확히 한다.
- **UTF-8 멀티바이트 로그에 `-c`를 쓰는 것** → 한글 등이 바이트 중간에서 잘린다 → 필드 기반(`-f`)으로 바꾸거나 문자 경계를 확인한다.
- **필드 번호를 확인 없이 짐작하는 것** → 로그 형식이 버전마다 바뀔 수 있다 → `head -1`로 항상 먼저 확인한다.
- **`-s` 없이 구분자 없는 줄까지 그대로 출력해 혼란을 주는 것** → 헤더나 깨진 줄이 섞여 나온다 → `-s`(`--only-delimited`)로 구분자 있는 줄만 남긴다.

## 교차검증

```bash
# 1) cut 결과
cut -d' ' -f1 access.log | sort -u | wc -l

# 2) awk 결과 — 같은 값이 나와야 한다 (공백 1개 고정 가정)
awk '{print $1}' access.log | sort -u | wc -l

# 3) 다르면 공백 개수가 들쭉날쭉하다는 뜻 — 정규화 후 재비교
tr -s ' ' < access.log | cut -d' ' -f1 | sort -u | wc -l
```

세 결과가 다르면 원본 로그의 구분자가 균일하지 않다는 신호다. `awk` 또는 정규화된 `cut`을 최종 채택한다.

## mini walkthrough

```text
문제:
"auth.log 에서 실패한 로그인 시도의 IP 목록을 뽑아 빈도순으로 정렬하세요."
첨부: auth.log (SSH 인증 로그)
샘플 줄:
Mar 14 07:19:02 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.77 port 51422 ssh2

1. 첫 시도 (실패):
   $ grep 'Failed password' auth.log | cut -d' ' -f1
   Mar
   Mar
   Mar
   -> 공백 기준 1번째 필드는 월(Mar)이었다. IP는 훨씬 뒤에 있고,
      게다가 "from" 다음 필드 번호가 줄마다 다르다
      (invalid user 유무에 따라 필드 개수가 다르기 때문).

2. 필드 번호를 직접 확인
   $ head -1 auth.log | tr -s ' ' '\n' | nl
    1  Mar
    2  14
    3  07:19:02
    ...
   -> cut만으로는 "from 다음 단어"를 안정적으로 잡을 수 없다.
      cut은 고정 번호만 다루기 때문이다.

3. 접근 변경 — 필드 개수가 가변이면 cut 대신 grep -oE
   $ grep -oE 'from [0-9.]+' auth.log | cut -d' ' -f2 | sort | uniq -c | sort -nr | head
     412 203.0.113.77
      88 198.51.100.5
      3 10.0.0.50

   여기서 cut은 여전히 쓰인다 — 'from 1.2.3.4'라는 고정 2필드 조각을 잘라낼 때는
   구분자가 확실하므로(공백 1개) cut -d' ' -f2가 정확하다.

4. 검증
   $ grep -c 'Failed password' auth.log
   503
   $ grep -oE 'from [0-9.]+' auth.log | wc -l
   503
   -> 개수 일치. 누락 없음.

정답: 203.0.113.77 (412회) 가 가장 많은 실패 시도 IP
```

1단계의 실패가 이 글의 요지다. **`cut`은 필드 번호가 줄마다 흔들리는 로그에는 맞지 않는다.** 그런 경우 `grep -oE`로 고정된 조각(`from IP`)만 먼저 잘라낸 뒤, 그 조각 안에서는 구분자가 확실하므로 `cut`을 다시 쓰는 조합이 정답이다.

## 막혔을 때 다음 체크

1. `head -1 | tr -s ' ' '\n' | nl`로 필드 번호를 실제로 확인했는가
2. 구분자가 줄마다 정말 균일한가 (연속 공백, 가변 필드 개수)
3. 구분자가 한 글자인가 — 여러 글자면 `cut`이 아니라 `awk`/`grep -oE`
4. CSV라면 따옴표 안 쉼표 가능성을 배제했는가
5. `-f`와 `-c`를 헷갈리지 않았는가
6. 출력 구분자를 명시했는가 (`--output-delimiter`)
7. `awk` 결과와 개수를 대조했는가
8. UTF-8 멀티바이트 로그에서 `-c`로 문자가 깨지지 않았는가

## 출처

- SRC-056 — GNU Awk User's Guide(GNU coreutils cut과 동일 계열 문서로 필드/구분자 개념 공통): `-d`/`-f` 관용구와 `awk`의 필드 분리 방식 비교 근거
- SRC-058 — Apache HTTP Server, Log Files: 예시로 사용한 combined 로그 형식
- `cut` 자체의 옵션(`-c`, `--complement`, `--output-delimiter`, `-s`)은 GNU coreutils 구현 기준이며 버전에 따라 옵션 지원이 다를 수 있으므로 `cut --help`로 실제 환경에서 확인할 것
