---
id: FOR-0119
title: "sed로 로그 치환/정리하기: s/// -n -i -E 와 백레퍼런스"
slug: "sed-substitute"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "text log", "CSV log"]
file_paths: ["/var/log/auth.log", "/var/log/apache2/access.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["sed", "gsed", "grep", "awk", "Select-String"]
commands: ["sed 's/old/new/' file", "sed -n '10,20p' file", "sed -i.bak 's/old/new/g' file", "sed -E 's/([0-9]+)\\.([0-9]+)/\\2.\\1/' file", "sed '/pattern/d' file", "sed -n '/start/,/end/p' file"]
regex_patterns: ["s/old/new/g", "s/\\(.*\\)/\\1/", "/pattern/d"]
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["log", "txt", "csv"]
primary_terms: ["sed 치환", "sed -i"]
keywords: ["sed", "s///", "sed -n", "sed -i", "sed -E", "백레퍼런스", "backreference", "치환 플래그", "print", "delete", "in-place", "gsed"]
aliases: ["sed 사용법", "sed 치환하기", "sed 파일 수정", "sed 특정 줄만", "sed 정규식", "로그 마스킹", "일괄 치환"]
symptom_keywords: ["특정 문자열을 한번에 바꾸고 싶다", "특정 줄만 뽑고 싶다", "파일을 직접 수정하고 싶다", "sed -i 가 안 된다", "치환이 첫 번째만 되고 나머지는 안 된다", "괄호로 잡은 값을 재배치하고 싶다"]
related: ["FOR-0112", "FOR-0115", "FOR-0118", "FOR-0122"]
source_ids: ["SRC-056", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`sed`는 `s/패턴/치환/플래그`(치환), `-n 'N,Mp'`(구간 추출), `/패턴/d`(삭제), `-i`(직접 수정) 네 가지 조합에서 실전이 끝나며, 기본 문법이 BRE이므로 그룹은 `\(...\)`, 반복은 `\+`처럼 이스케이프해야 하고 ERE가 필요하면 `-E`를 붙인다.

## 어떤 문제에서 필요한가

- 로그에서 IP·계정명 등 민감정보를 마스킹해서 제출해야 하는 문제
- 특정 줄 범위만 뽑아 별도 파일로 만들어야 하는 문제
- 여러 파일에 같은 치환을 일괄 적용해야 하는 문제
- 로그 포맷을 다른 도구가 읽을 수 있는 형태로 바꿔야 하는 전처리(예: 구분자 변경)
- 정규식으로 잡은 값의 순서를 바꿔야 하는 문제(날짜 형식 변환 등)

## 문제에서 처음 볼 단서

1. 지문에 "치환", "바꿔라", "마스킹", "삭제" → `sed`가 정답 후보
2. "N번째 줄부터 M번째 줄까지" → `sed -n 'N,Mp'`
3. "파일을 직접 수정" → `-i` (백업본을 남기려면 `-i.bak`)
4. 괄호로 잡은 값의 순서를 바꿔야 한다 → 백레퍼런스 `\1` `\2`

먼저 원본을 건드리지 않고 확인한다.

```bash
sed -n '1,3p' access.log
```

`-i` 없이 실행하면 화면에만 출력되고 파일은 그대로다. **`-i`를 붙이기 전에 항상 `-i` 없이 먼저 결과를 확인한다.**

## 30초 절차

```bash
sed 's/Failed password/FAIL/' auth.log
```

```bash
sed -n '1,3p' file              # 미리보기
sed 's/old/new/g' file          # 치환 결과를 화면에 (원본 불변)
sed -i.bak 's/old/new/g' file   # 백업 남기고 실제 수정
diff file.bak file               # 무엇이 바뀌었는지 확인
```

## 상세 절차

### 1단계 — s/// 치환의 구조

```text
s / 패턴 / 치환 / 플래그
```

구분자는 `/`가 관례지만 패턴에 `/`가 많으면(경로 등) 다른 문자로 바꿀 수 있다.

```bash
sed 's|/var/www/html|/srv/web|' access.log
sed 's#C:\\Users\\admin#REDACTED#' notes.txt
```

플래그 표다.

| 플래그 | 의미 |
| --- | --- |
| (없음) | 줄에서 **첫 번째** 매칭만 치환 |
| `g` | 줄 안의 **모든** 매칭 치환 |
| `N` (숫자) | N번째 매칭만 치환 |
| `Ng` | N번째부터 끝까지 모두 치환 |
| `i` 또는 `I` | 대소문자 무시(GNU sed 확장) |
| `p` | 치환된 줄을 (자동 출력과 별개로) 한 번 더 출력 — `-n`과 함께 쓴다 |
| `w FILE` | 치환된 줄만 FILE에 기록 |

```bash
$ echo 'a-a-a-a' | sed 's/a/X/'
X-a-a-a
$ echo 'a-a-a-a' | sed 's/a/X/g'
X-X-X-X
$ echo 'a-a-a-a' | sed 's/a/X/2'
a-X-a-a
$ echo 'a-a-a-a' | sed 's/a/X/2g'
a-X-X-X
```

**플래그가 없으면 한 줄에 하나만 바뀐다는 것**이 가장 흔한 실수 지점이다. 로그 전체를 바꾸려면 거의 항상 `g`가 필요하다.

### 2단계 — BRE vs ERE, 백레퍼런스

기본 문법은 BRE(Basic Regular Expression)다. `grep`과 같은 규칙이다([FOR-0112](./grep-basics.html) 참고).

| | BRE (기본) | ERE (`-E` 또는 `-r`) |
| --- | --- | --- |
| 그룹 | `\(...\)` | `(...)` |
| OR | `\|` (GNU 확장, `\`\|`` 형태) | `\|` |
| 1회 이상 | `\+` | `+` |
| 반복 횟수 | `\{2,4\}` | `{2,4}` |

캡처한 그룹은 치환부에서 `\1` `\2`로 참조한다. 순서를 바꾸는 예다.

```bash
$ echo '2026-03-14' | sed -E 's/([0-9]{4})-([0-9]{2})-([0-9]{2})/\3\/\2\/\1/'
14/03/2026
```

BRE로 같은 것을 하면 괄호와 `+`를 전부 이스케이프해야 한다.

```bash
$ echo '2026-03-14' | sed 's/\([0-9]\{4\}\)-\([0-9]\{2\}\)-\([0-9]\{2\}\)/\3\/\2\/\1/'
14/03/2026
```

`&`는 **매칭된 전체 문자열**을 가리키는 특수 기호다. 값을 감싸거나 태그를 붙일 때 쓴다.

```bash
$ echo 'root admin guest' | sed 's/[a-z]\+/[&]/g'
[root] [admin] [guest]
```

### 3단계 — 줄 선택: -n과 p, 주소 지정

`sed`는 기본적으로 **모든 줄을 자동 출력**한다. `-n`을 주면 이 자동 출력이 꺼지고, `p` 명령으로 명시한 줄만 나온다.

| 주소 형태 | 의미 |
| --- | --- |
| `N` | N번째 줄 |
| `N,M` | N번째부터 M번째까지 |
| `N,+M` | N번째부터 N+M줄까지 |
| `N~M` | N번째부터 M줄 간격으로(GNU 확장, 예: 짝수 줄은 `2~2`) |
| `$` | 마지막 줄 |
| `/패턴/` | 패턴이 매칭되는 줄 |
| `/시작/,/끝/` | 시작 패턴부터 끝 패턴이 나올 때까지 |
| `N,/패턴/` | N번째 줄부터 패턴이 나오는 줄까지 |

```bash
# 10~20번째 줄만
sed -n '10,20p' access.log

# grep -n 으로 찾은 8840번째 줄 앞뒤 5줄
sed -n '8835,8845p' access.log

# 특정 패턴이 나오는 줄만 (grep과 같은 효과)
sed -n '/Failed password/p' auth.log

# 두 패턴 사이 구간 (첫 매칭부터 다음 매칭까지)
sed -n '/07:19:00/,/07:21:00/p' access.log

# 짝수 줄만
sed -n '0~2p' access.log
```

`-n '/패턴/p'`는 `grep '패턴'`과 결과가 같다. 차이는 `sed`는 이후 치환·삭제를 같은 파이프라인에서 이어 할 수 있다는 점이다.

### 4단계 — 삭제와 조건부 명령

| 명령 | 의미 |
| --- | --- |
| `d` | 매칭된 줄 삭제(출력 안 함) |
| `D` | 패턴 공간의 첫 줄만 삭제(멀티라인용) |
| `q` | 여기서 처리 종료(뒤는 읽지 않음) |
| `q N` | 종료 코드 N으로 종료 |
| `a 텍스트` | 매칭 줄 **뒤에** 텍스트 추가 |
| `i 텍스트` | 매칭 줄 **앞에** 텍스트 삽입 |
| `y/abc/xyz/` | 문자 단위 치환(tr과 같음, 정규식 아님) |

```bash
# 헬스체크 줄 제거
sed '/\/health/d' access.log > cleaned.log

# 처음 100줄만 보고 멈춘다 (대용량에서 head보다 유리한 경우는 드물지만 조건부 종료에 쓴다)
sed '100q' access.log

# 빈 줄 제거
sed '/^$/d' access.log

# 소문자로 통일 (y는 문자 대 문자 대응만, 정규식 아님)
echo 'ABC-def' | sed 'y/ABCDEF/abcdef/'
```

```text
abc-def
```

### 5단계 — 여러 명령 조합과 -e / -f

```bash
# -e 로 여러 치환을 한 번에
sed -e 's/Failed/FAIL/g' -e 's/Accepted/OK/g' auth.log

# 세미콜론으로 이어도 같다
sed 's/Failed/FAIL/g; s/Accepted/OK/g' auth.log

# 치환 목록을 파일로 관리
cat > rules.sed << 'EOF'
s/203\.0\.113\.77/ATTACKER_IP/g
s/svc_backup/COMPROMISED_ACCT/g
EOF
sed -f rules.sed auth.log
```

### 6단계 — -i (in-place) 수정

```bash
# 백업 없이 직접 수정 (되돌릴 수 없다 — 증거 원본에는 쓰지 않는다)
sed -i 's/old/new/g' notes.txt

# 백업을 남기고 수정 (권장)
sed -i.bak 's/old/new/g' notes.txt
ls
# notes.txt  notes.txt.bak
```

**증거 원본 파일에는 `-i`를 쓰지 않는다.** 항상 사본에 적용한다. GNU sed와 BSD/macOS sed는 `-i`의 인자 요구 방식이 다르다.

| 구현 | 백업 확장자 지정 |
| --- | --- |
| GNU sed(리눅스 기본) | `sed -i.bak '...'` (붙여 쓴다) |
| BSD/macOS sed | `sed -i '.bak' '...'` (공백 필요, 빈 문자열도 명시해야 함) |

이식성이 필요하면 `-i` 대신 리다이렉트로 대체한다.

```bash
sed 's/old/new/g' file > file.tmp && mv file.tmp file
```

### 7단계 — Windows/PowerShell, Python 대응

`sed`가 없는 환경에서는 PowerShell `-replace` 연산자로 같은 일을 한다. `-replace`는 내부적으로 .NET 정규식(사실상 PCRE에 가까운 문법)을 쓴다.

```powershell
# 치환 결과를 화면에 (원본 불변) — sed 's/old/new/g' 와 동일
(Get-Content .\auth.log) -replace 'Failed password', 'FAIL'

# 파일에 직접 반영 — sed -i 와 동일
(Get-Content .\auth.log) -replace 'Failed password', 'FAIL' | Set-Content .\auth.log

# 캡처 그룹 재배치 — sed -E 's/(\d{4})-(\d{2})-(\d{2})/\3\/\2\/\1/' 와 동일
'2026-03-14' -replace '(\d{4})-(\d{2})-(\d{2})', '$3/$2/$1'
```

```text
14/03/14
```

PowerShell에서는 백레퍼런스가 `\1`이 아니라 **`$1`**이다. 큰따옴표 문자열 안에서 `$1`을 그대로 쓰면 변수로 오인될 수 있으므로 치환 패턴은 작은따옴표로 감싼다.

Python은 `re.sub`로 같은 작업을 하며, 로직이 복잡해지면(조건부 치환, 여러 단계) `sed`보다 관리하기 쉽다.

```python
import re

with open('auth.log', encoding='utf-8', errors='replace') as f:
    text = f.read()

masked = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}', 'REDACTED_IP', text)
masked = re.sub(r'(\d{4})-(\d{2})-(\d{2})', r'\3/\2/\1', masked)

with open('auth_masked.log', 'w', encoding='utf-8') as f:
    f.write(masked)
```

`re.sub`의 백레퍼런스는 `sed`와 같은 `\1` 표기를 문자열 안에 쓰되, **raw string(`r'...'`)**으로 감싸야 `\3`이 이스케이프 시퀀스로 오인되지 않는다.

## 출력 필드 해석

| 상황 | 해석 |
| --- | --- |
| `-n` 없이 실행했는데 화면에 두 번 나온다 | `p` 플래그나 `p` 명령을 썼는데 자동 출력을 안 껐다. `-n`을 추가한다 |
| 치환이 줄마다 한 곳만 적용됨 | `g` 플래그 누락 |
| `sed: -e expression #1, char N: unterminated s command` | 구분자(`/`)가 패턴 안의 `/`와 충돌. 다른 구분자(`\|`, `#`)로 교체 |
| `sed: -i may not be used with stdin` | `-i`는 파일 인자가 있어야 한다. 파이프 입력에는 못 쓴다 |
| BRE에서 `+`가 그대로 남는다 | `+`가 리터럴로 해석됨. `\+`로 이스케이프하거나 `-E` 사용 |

## pivot: 다음에 볼 artifact

| sed로 얻은 것 | 다음 목표 |
| --- | --- |
| 구간만 뽑은 로그 | `awk`로 필드 집계 ([FOR-0115](./awk-fields.html)) |
| 마스킹된 로그 | 안전하게 공유·첨부 |
| 형식이 바뀐 로그(구분자 통일) | `csv`/`jq`로 재구조화 ([FOR-0126](./json-log-jq.html)) |
| 삭제로 남긴 노이즈 제거본 | `grep`으로 재검증 ([FOR-0112](./grep-basics.html)) |
| 복잡한 조건부 치환이 필요해짐 | Python `re.sub` + `re.subn`으로 전환 |

## 흔한 함정

- **`g` 플래그를 빼먹는 것.** 줄 하나에 매칭이 여러 개면 첫 번째만 바뀐다. 전체를 바꾸려면 거의 항상 `g`.
- **BRE에서 `(` `)` `+` `{}`를 그냥 쓰는 것.** BRE에서는 리터럴로 해석된다. `-E`를 붙이거나 `\(` `\+` `\{` 형태로 이스케이프한다.
- **`-i`를 증거 원본에 바로 쓰는 것.** 되돌릴 수 없다. 항상 `-i.bak`로 백업을 남기거나 사본에 적용한다.
- **GNU sed 문법을 macOS/BSD sed에 그대로 쓰는 것.** `-i.bak`는 GNU에서만 붙여 쓸 수 있다. BSD sed는 `-i ''`처럼 공백과 인자가 필수다.
- **`-n` 없이 `p` 명령을 쓰는 것.** 자동 출력과 `p`가 겹쳐 같은 줄이 두 번 나온다.
- **구분자로 `/`를 고집하다 패턴이 깨지는 것.** 경로처럼 `/`가 많은 패턴은 `sed 's|/a/b|/c/d|'`처럼 다른 구분자로 바꾼다.
- **`&`를 리터럴 앰퍼샌드로 착각하는 것.** 치환부의 `&`는 매칭 전체를 뜻하는 특수 문자다. 진짜 `&`를 넣으려면 `\&`로 이스케이프한다.
- **PowerShell `-replace`에서 백레퍼런스를 `\1`로 쓰는 것.** .NET 정규식 치환은 `$1`을 쓴다. `\1`은 그대로 리터럴 문자로 들어간다.
- **파이프 입력에 `-i`를 쓰려는 것.** `-i`는 실제 파일이 있어야 동작한다. `cmd | sed -i ...`는 에러다.

## 교차검증

치환 전후 줄 수와 매칭 개수가 의도와 맞는지 확인한다.

```bash
# 치환 전 매칭 줄 수
grep -c 'Failed password' auth.log

# 치환 후 같은 문자열이 남아있지 않은지
sed 's/Failed password/FAIL/g' auth.log | grep -c 'Failed password'
```

```text
4120
0
```

두 번째 값이 0이 아니면 일부 케이스(예: 대소문자, 공백 차이)가 패턴에서 빠진 것이다. `diff`로 실제 변경 라인 수도 확인한다.

```bash
diff <(cat auth.log) <(sed 's/Failed password/FAIL/g' auth.log) | grep -c '^>'
```

## mini walkthrough

```text
문제:
"auth.log 를 제출용으로 다듬으세요. (1) 모든 IP 를 REDACTED_IP 로 마스킹
 (2) 07:19:00~07:21:00 사이의 무차별 대입 구간만 별도 파일로 남기세요."
첨부: auth.log (88,214줄)

1. 첫 시도 (실패) - IP 마스킹:
   $ sed 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/REDACTED_IP/' auth.log \
       | grep -c '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
   3901

   -> g 플래그를 빼먹었다. 한 줄에 IP가 두 번 나오는 줄(예: 'from A via B')에서
      첫 번째만 바뀌고 두 번째는 그대로 남았다.

2. g 플래그 추가:
   $ sed 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/REDACTED_IP/g' auth.log \
       > auth_masked.log
   $ grep -c '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' auth_masked.log
   0

   -> 전부 치환됨.

3. 구간 추출 (두 번째 실패):
   $ sed -n '/07:19:00/,/07:21:00/p' auth.log > brute.log
   $ wc -l brute.log
   1

   -> syslog 시각은 초 단위까지 정확히 07:19:00 이 존재해야 매칭된다.
      실제로는 07:19:02 부터 시작해서 정확한 07:19:00 줄이 없었다.
      패턴 매칭 방식의 구간 추출은 "그 문자열이 정확히 있는 줄"만 잡는다.

4. 줄 번호 기반으로 전환:
   $ grep -n '07:19' auth.log | head -1
   40210:Mar 14 07:19:02 web01 sshd[2311]: Failed password for invalid user admin from 203.0.113.77 port 51022 ssh2
   $ grep -n '07:21' auth.log | tail -1
   44330:Mar 14 07:20:59 web01 sshd[2500]: Failed password for root from 203.0.113.77 port 51500 ssh2

   -> grep -n 으로 실제 줄 번호를 먼저 확정한 뒤 sed 로 자른다.

   $ sed -n '40210,44330p' auth.log > brute.log
   $ wc -l brute.log
   4121

5. 교차검증:
   $ grep -c 'Failed password' brute.log
   4120
   -> 구간 안의 시도 횟수와 앞서 awk/grep 으로 구한 상위 계정 집계(FOR-0115)의
      admin 4120건이 정확히 일치한다.

정답: auth_masked.log(IP 전부 마스킹), brute.log(40210~44330번 줄, 4,120건의 시도)
```

1단계와 3단계 모두 **패턴 기반 접근의 한계**를 보여준다. `g` 없이는 반쪽만 치환되고, 문자열 매칭 기반 구간 추출은 그 문자열이 정확히 존재해야만 동작한다. 실제 경계가 애매하면 `grep -n`으로 줄 번호를 먼저 확정하는 편이 안전하다.

## 막혔을 때 다음 체크

1. `-i` 없이 먼저 결과를 화면에서 확인했는가
2. `g` 플래그를 빼먹지 않았는가(치환이 반쪽만 되는 경우 1순위 의심)
3. BRE인지 ERE(`-E`)인지 확인하고 괄호·`+`·`{}`를 맞게 이스케이프했는가
4. 구분자 `/`가 패턴 안의 `/`와 충돌하지 않는가
5. 증거 원본이 아니라 사본에 `-i`를 적용했는가, 백업(`-i.bak`)을 남겼는가
6. GNU sed와 BSD sed의 `-i` 문법 차이를 확인했는가(실행 환경이 macOS인 경우)
7. 패턴 매칭 기반 구간 추출(`/시작/,/끝/`)이 실제로 그 문자열을 포함하는지, 아니면 `grep -n` + 줄 번호가 더 안전한지 판단했는가
8. 치환 전후 `grep -c`로 개수를 비교했는가
9. PowerShell로 옮길 때 백레퍼런스를 `\1`이 아니라 `$1`로 썼는가
10. 로직이 복잡해지면(조건부, 다단계) Python `re.sub`으로 전환할 시점인가

## 출처

- SRC-056 — GNU sed manual(GNU Awk User's Guide와 함께 등록된 sed 매뉴얼 계열): `s///` 플래그, BRE/ERE 문법 차이, 주소 지정(`N,M`, `/pat/`, `N~M`), `-i`의 GNU 방식
- SRC-057 — Python 공식 문서 `re` 모듈: `re.sub`의 백레퍼런스 표기(`\1`)와 raw string 필요성
- BSD/macOS sed의 `-i` 인자 요구 방식은 GNU sed와 다르므로 실행 환경에서 `sed --version`으로 구현을 확인할 것
- PowerShell `-replace`가 .NET 정규식(백레퍼런스 `$1`)을 쓴다는 점은 실제 PowerShell 세션에서 재확인할 것
