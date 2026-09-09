---
id: FOR-0122
title: "Python re.findall로 로그에서 값 뽑기: 그룹 개수가 반환형을 바꾼다"
slug: "python-re-findall"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["access.log", "auth.log", "strings dump", "text log"]
file_paths: ["/var/log/auth.log", "/var/log/apache2/access.log"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Python", "re", "collections.Counter"]
commands: ["python -c \"import re,sys;print(re.findall(r'ERROR.*',open(sys.argv[1]).read())[:5])\" app.log", "python3 -m pip install regex", "python parse.py access.log"]
regex_patterns: ["\\d{1,3}(?:\\.\\d{1,3}){3}", "(?:GET|POST|PUT|DELETE) (\\S+)", "Failed password for (?:invalid user )?(\\S+) from (\\S+)", "flag\\{[^}]+\\}"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ip", "method", "uri", "status", "user"]
file_formats: ["log", "txt", "csv", "json"]
primary_terms: ["re.findall", "python 정규식", "findall"]
keywords: ["re.findall", "findall", "Python regex", "re.compile", "re.IGNORECASE", "re.MULTILINE", "re.DOTALL", "re.VERBOSE", "Counter", "non-capturing group", "정규식 집계", "튜플 반환"]
aliases: ["python findall", "파이썬 정규식 전부 찾기", "re.findall 튜플", "findall 결과가 이상하다", "파이썬으로 IP 추출", "python 로그 파싱"]
symptom_keywords: ["findall 결과가 튜플로 나온다", "IP가 잘려서 나온다", "정규식이 일부만 잡는다", "큰 파일에서 메모리가 터진다", "UnicodeDecodeError가 난다", "몇 번 나왔는지 세고 싶다"]
related: ["FOR-0123", "FOR-0124", "FOR-0128"]
source_ids: ["SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`re.findall`의 반환형은 **패턴 안의 캡처 그룹 개수가 결정한다.** 그룹이 없으면 전체 매칭 문자열 리스트, 그룹이 하나면 그 그룹만, 두 개 이상이면 튜플 리스트다. 값 전체를 원하는데 그룹을 써서 조각만 받는 것이 이 함수에서 나오는 오답의 대부분이다.

## 어떤 문제에서 필요한가

- 로그 전체에서 IP, 계정명, URL, 해시, `flag{...}` 를 **전부** 뽑아 세야 하는 상황
- grep/awk로는 필드 위치가 일정하지 않아 못 자르는 로그
- 뽑은 값을 바로 빈도 집계해서 "가장 많이 요청한 IP", "가장 많이 실패한 계정"을 답해야 하는 상황
- 여러 로그 파일을 한 번에 훑어야 하는 상황
- Windows/Linux를 가리지 않고 같은 스크립트를 돌려야 하는 상황

## 문제에서 처음 볼 단서

1. 문제 지문의 "몇 개", "가장 많이", "모두 나열" — 전부 `findall` + `Counter`다
2. 로그 한 줄의 형식이 고정이면 `split()`이 더 빠르고 안전하다. 정규식은 **형식이 흔들릴 때** 쓴다
3. 파일 크기가 수백 MB 이상이면 `read()` 금지, 줄 단위 순회로 간다
4. 한글·비UTF8 바이트가 섞이면 `errors='replace'` 없이는 첫 줄에서 예외로 죽는다

먼저 세 줄을 눈으로 본다.

```python
with open('access.log', encoding='utf-8', errors='replace') as f:
    for i, line in zip(range(3), f):
        print(repr(line))
```

```text
'203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199\n'
'192.168.10.24 - - [14/Mar/2026:07:19:05 +0900] "GET /index.html HTTP/1.1" 200 5120\n'
'198.51.100.5 - - [14/Mar/2026:07:19:07 +0900] "GET /favicon.ico HTTP/1.1" 404 209\n'
```

`repr`로 봐야 줄 끝의 `\n`, `\r\n`, 탭이 보인다. 이것을 안 보고 만든 정규식은 뒤에서 어긋난다.

## 30초 절차

```bash
python -c "import re,sys;print(re.findall(r'ERROR.*',open(sys.argv[1]).read())[:5])" app.log
```

실전용 최소 스크립트는 다섯 줄이다.

```python
import re
from collections import Counter

text = open('access.log', encoding='utf-8', errors='replace').read()
ips = re.findall(r'\d{1,3}(?:\.\d{1,3}){3}', text)
print(Counter(ips).most_common(5))
```

```text
[('203.0.113.77', 1842), ('192.168.10.24', 311), ('198.51.100.5', 96),
 ('10.0.0.14', 41), ('192.168.10.7', 22)]
```

`(?:...)`가 핵심이다. `(...)`로 썼다면 결과가 `['10.', '10.', ...]`처럼 망가진다. 아래에서 이유를 본다.

## 상세 절차

### 1단계 — 반환형 규칙 세 가지를 외운다

`re.findall(pattern, string, flags=0)`은 겹치지 않는 모든 매칭을 리스트로 돌려준다. 그런데 리스트의 **원소가 무엇인지**는 그룹 개수가 정한다.

| 패턴의 캡처 그룹 수 | 반환 원소 | 예시 패턴 | `'a1b22'` 에 적용한 결과 |
| --- | --- | --- | --- |
| 0개 | 매칭 전체 문자열 | `[a-z]\d+` | `['a1', 'b22']` |
| 1개 | 그 그룹의 문자열 | `[a-z](\d+)` | `['1', '22']` |
| 2개 이상 | 그룹들의 튜플 | `([a-z])(\d+)` | `[('a','1'), ('b','22')]` |

`(?:...)`는 **캡처하지 않는 그룹**이므로 개수에 포함되지 않는다. 그래서 반복·선택만 묶고 싶을 때는 항상 `(?:...)`를 쓴다.

```python
import re

s = '192.168.10.24 접속, 203.0.113.77 접속'

re.findall(r'(\d{1,3}\.){3}\d{1,3}', s)      # ['10.', '113.']      <- 함정
re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', s)    # ['192.168.10.24', '203.0.113.77']
re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', s)  # ['192.168.10.24', '203.0.113.77']
```

첫 줄이 CTF에서 가장 자주 나오는 사고다. `(\d{1,3}\.){3}`는 그룹이 **세 번 반복**되지만 파이썬은 마지막 반복의 값만 보관한다. 그룹이 1개이므로 `findall`은 그 값(`'10.'`)만 돌려준다. IP가 잘려 나오면 무조건 이 문제다.

IP 정규식 자체의 정밀도는 [FOR-0128](./ipv4-regex.html)에서 다룬다. `\d{1,3}`은 `999.999.999.999`도 잡으므로 오탐을 걸러야 한다.

### 2단계 — 여러 값을 한 번에: 튜플 리스트

필드를 여러 개 동시에 뽑을 때는 튜플 반환을 오히려 이용한다.

```python
import re

pat = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+)'
rows = re.findall(pat, open('access.log', encoding='utf-8', errors='replace').read(),
                  re.MULTILINE)
print(rows[0])
```

```text
('203.0.113.77', '14/Mar/2026:07:19:02 +0900', 'GET', '/admin/', '403', '199')
```

`re.MULTILINE`이 없으면 `^`가 문자열 전체의 시작에만 붙어 첫 줄 하나만 매칭된다. 파일 전체를 `read()`해서 `^`를 쓸 때는 반드시 같이 준다.

튜플 인덱스를 세는 것이 귀찮고 위험하면 명명 그룹으로 올라간다(FOR-0124). `findall`은 명명 그룹의 이름을 무시하고 순서대로 튜플만 주므로, 이름으로 접근하려면 `finditer`가 필요하다(FOR-0123).

### 3단계 — 플래그

| 플래그 | 축약 | 하는 일 | 실전 용도 |
| --- | --- | --- | --- |
| `re.IGNORECASE` | `re.I` | 대소문자 무시 | `SELECT`/`select` SQLi 흔적 |
| `re.MULTILINE` | `re.M` | `^` `$`가 줄마다 적용 | 파일 전체를 read 했을 때 필수 |
| `re.DOTALL` | `re.S` | `.`이 줄바꿈도 매칭 | 여러 줄 XML·JSON 블록 |
| `re.VERBOSE` | `re.X` | 공백·`#` 주석 허용 | 긴 로그 패턴 가독성 |
| `re.ASCII` | `re.A` | `\w` `\d`를 ASCII로 제한 | 한글이 `\w`에 걸리는 것 방지 |

플래그는 `|`로 합친다. 인라인으로 `(?im)`처럼 패턴 앞에 붙여도 된다.

```python
re.findall(r'union\s+select', text, re.I | re.S)
re.findall(r'(?is)union\s+select', text)      # 위와 같다
```

`re.ASCII`는 한국어 로그에서 중요하다. 기본 유니코드 모드에서 `\w+`는 한글도 잡으므로, 영문 계정명만 뽑으려면 `re.A`를 주거나 `[A-Za-z0-9_]`로 명시한다.

```python
re.findall(r'user=(\w+)', 'user=관리자 user=admin')          # ['관리자', 'admin']
re.findall(r'user=(\w+)', 'user=관리자 user=admin', re.A)     # ['admin']
```

### 4단계 — `re.compile`로 재사용

같은 패턴을 수십만 줄에 적용할 때는 `re.compile`로 한 번만 컴파일한다.

```python
import re
from collections import Counter

IP  = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
UA  = re.compile(r'"[^"]*" "([^"]*)"$')
FAIL = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')

ips, uas, fails = Counter(), Counter(), Counter()
with open('access.log', encoding='utf-8', errors='replace') as f:
    for line in f:
        ips.update(IP.findall(line))
        uas.update(UA.findall(line))

for ip, n in ips.most_common(5):
    print(f'{n:>7}  {ip}')
```

```text
   1842  203.0.113.77
    311  192.168.10.24
     96  198.51.100.5
     41  10.0.0.14
     22  192.168.10.7
```

`re` 모듈은 내부에 컴파일 결과 캐시를 두므로 `re.compile`이 항상 극적으로 빠른 것은 아니다. 그래도 컴파일해 두면 (1) 패턴을 파일 상단에 모아 검토할 수 있고 (2) 플래그를 한 곳에 고정할 수 있고 (3) 캐시가 다른 패턴으로 밀려나도 재컴파일이 없다. 대회장에서는 가독성 쪽 이득이 더 크다.

`Counter.update(리스트)`는 리스트의 모든 원소를 한 번에 더한다. 줄마다 `findall` 결과를 그대로 던지면 집계가 끝난다.

### 5단계 — 대용량 파일: `read()`를 버린다

```python
# 나쁜 예 — 2GB 파일이면 그대로 메모리 2GB 이상
text = open('huge.log', encoding='utf-8', errors='replace').read()
hits = re.findall(PAT, text)

# 좋은 예 — 한 줄씩. 메모리는 한 줄 크기
hits = []
with open('huge.log', encoding='utf-8', errors='replace') as f:
    for line in f:
        hits.extend(PAT.findall(line))
```

| 방식 | 메모리 | `^`/`$` | 줄을 넘는 패턴 | 언제 |
| --- | --- | --- | --- | --- |
| `read()` + `findall` | 파일 크기만큼 | `re.M` 필요 | 가능 (`re.S`) | 수십 MB 이하 |
| 줄 단위 순회 | 한 줄 | 줄마다 자동 적용 | 불가 | 수백 MB 이상 |
| `mmap` + 바이트 패턴 | 거의 없음 | 바이트 모드 규칙 | 가능 | GB 단위 |

`mmap`은 오프셋이 필요할 때 쓴다. 바이트 패턴은 접두사 `rb`를 붙인다.

```python
import mmap, re

with open('memdump.raw', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for m in re.finditer(rb'flag\{[^}]{1,64}\}', mm):
        print(hex(m.start()), m.group().decode('ascii', 'replace'))
```

바이트 모드에서는 패턴도 `bytes`여야 한다. `str` 패턴을 `bytes`에 쓰면 `TypeError: cannot use a string pattern on a bytes-like object`가 난다.

### 6단계 — 인코딩 예외 회피

```python
# 이렇게 열면 비UTF8 바이트 한 개에 전체가 죽는다
open('mixed.log', encoding='utf-8')
# UnicodeDecodeError: 'utf-8' codec can't decode byte 0xb0 in position 4210

# 조사에서는 항상 이렇게 연다
open('mixed.log', encoding='utf-8', errors='replace')
```

| `errors` 값 | 동작 | 조사에서의 의미 |
| --- | --- | --- |
| `'strict'` (기본) | 예외 발생 | 스크립트가 중단된다 |
| `'replace'` | 깨진 바이트를 U+FFFD로 대체 | 위치가 보존되어 오프셋이 안 흔들린다 |
| `'ignore'` | 깨진 바이트를 버린다 | 문자 오프셋이 어긋난다. 오프셋을 쓸 거면 금지 |
| `'surrogateescape'` | 원본 바이트를 보존해 되돌릴 수 있다 | 원문 바이트를 다시 써야 할 때 |

한글 Windows에서 만든 로그는 CP949일 가능성이 높다. `encoding='cp949'`로 다시 열어 보면 판별된다.

## 출력 필드 해석

`findall`이 무엇을 돌려주는지 헷갈리면 아래를 그대로 확인한다.

| 상황 | 결과 | 확인 방법 |
| --- | --- | --- |
| 매칭 없음 | `[]` (빈 리스트, `None`이 아니다) | `if not hits:` |
| 그룹 없음 | `['전체매칭', ...]` | `type(hits[0]) is str` |
| 그룹 1개 | `['그룹값', ...]` | 값이 잘려 보이면 그룹을 잘못 쓴 것 |
| 그룹 2개 이상 | `[('a','b'), ...]` | `len(hits[0])`이 그룹 수 |
| 명명 그룹 사용 | 이름 무시, 순서대로 튜플 | 이름이 필요하면 `finditer` |
| 그룹이 매칭 안 됨 (`?` 뒤) | 해당 자리에 `''` (빈 문자열) | `None`이 아니라 `''`다 |
| 빈 매칭 가능한 패턴 | 빈 문자열도 원소로 포함된다 | `+` 대신 `*`를 쓰면 발생 |

마지막 두 줄이 특히 헷갈린다. `re.findall(r'a*', 'bab')`은 `['', 'a', '', '']`처럼 빈 문자열을 포함한다. 개수를 세는 문제에서 이것 때문에 답이 부풀어 오른다. 수량자는 의도가 "1개 이상"이면 반드시 `+`를 쓴다.

## pivot: 다음에 볼 artifact

| findall로 얻은 값 | 다음 목표 |
| --- | --- |
| 상위 IP | pcap `ip.addr == <IP>` / 방화벽 로그 / whois |
| 계정명 | EVTX 4624·4625 로그온 성공 여부 |
| URI·파일명 | 웹 루트의 실제 파일, $MFT 생성 시각 |
| User-Agent | 자동화 도구 식별 (sqlmap, curl, python-requests, nikto) |
| Base64 후보 | 디코딩 → 명령·URL·자격증명 |
| 매칭 **위치**가 필요해짐 | `finditer`로 전환 (FOR-0123) |
| 필드 이름으로 표를 만들어야 함 | 명명 그룹 + `csv.DictWriter` (FOR-0124, FOR-0125) |
| 시각 문자열 | 시간대 확정. `+0900`은 KST, `Z`는 UTC. 두 값을 섞으면 9시간 오차 |

## 흔한 함정

- **반복 그룹을 캡처 그룹으로 쓰는 것.** `(\d{1,3}\.){3}\d{1,3}`은 마지막 반복만 남겨 `'10.'`을 준다. 왜 틀리나: 파이썬은 반복된 그룹의 최종 값 하나만 보관한다. 어떻게: 반복 묶음은 `(?:...)`로, 전체를 받으려면 `((?:...)...)`로 감싼다.
- **그룹을 넣었는데 전체 매칭을 기대하는 것.** 그룹이 하나라도 있으면 `findall`은 전체 문자열을 주지 않는다. 전체와 부분을 동시에 원하면 `finditer` + `m.group(0)`·`m.group(1)`을 쓴다.
- **`read()` 후 `^`를 쓰면서 `re.MULTILINE`을 빼는 것.** `^`가 파일 전체의 첫 위치에만 붙어 결과가 1건만 나온다. 결과가 부자연스럽게 적으면 이것부터 본다.
- **`.*`의 탐욕성.** `"(.*)"`는 한 줄의 첫 따옴표부터 **마지막** 따옴표까지 삼킨다. 필드 하나만 원하면 `"([^"]*)"` 또는 `"(.*?)"`를 쓴다. 문자 클래스 부정형이 게으른 수량자보다 빠르다.
- **빈 매칭을 세는 것.** `*`나 `?`만으로 끝나는 패턴은 빈 문자열도 매칭으로 센다. 개수 문제의 답이 이상하게 크면 `+`로 바꾼다.
- **`errors`를 지정하지 않는 것.** 비UTF8 바이트 하나에 `UnicodeDecodeError`로 스크립트가 죽는다. 조사 대상 파일은 항상 `errors='replace'`로 연다. 오프셋을 쓸 계획이면 `'ignore'`는 절대 쓰지 않는다.
- **`str` 패턴을 `bytes` 데이터에 쓰는 것.** 메모리 덤프·바이너리는 `rb'...'` 패턴과 `'rb'` 모드로 통일한다. 섞으면 `TypeError`다.
- **결과를 눈으로 세는 것.** `len(hits)`와 `len(set(hits))`는 다르다. "몇 종류"와 "몇 번"을 구분해 묻는 문제가 많다. `Counter`로 둘 다 즉시 낸다.
- **한글이 `\w`에 걸리는 것.** 기본 모드의 `\w`는 유니코드 문자다. 영문 식별자만 원하면 `re.ASCII` 또는 `[A-Za-z0-9_]`.
- **정규식으로 CSV·JSON을 파싱하는 것.** 인용 필드 안의 콤마·줄바꿈, 이스케이프된 따옴표를 정규식으로 감당할 수 없다. `csv`·`json` 모듈로 넘어간다 (FOR-0125).

## 교차검증

정규식 결과는 반드시 다른 도구의 숫자와 맞춰 본다.

```python
import re
from collections import Counter
text = open('access.log', encoding='utf-8', errors='replace').read()
print(Counter(re.findall(r'^(\S+)', text, re.M)).most_common(3))
```

```bash
# 필드 기준 — 정규식 오탐이 없다. 이것이 기준값이다
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -3

# grep 로 특정 IP 건수만
grep -c '^203\.0\.113\.77 ' access.log
```

```powershell
Select-String -Path .\access.log -Pattern '^\S+' |
  ForEach-Object { $_.Matches[0].Value } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 3 Count, Name
```

세 결과가 다르면 원인은 셋 중 하나다.

| 차이 | 원인 |
| --- | --- |
| Python이 더 많다 | 패턴이 한 줄에서 여러 번 걸렸다. `^`와 `re.M`으로 줄 앞에 고정한다 |
| Python이 더 적다 | 인코딩 오류로 줄이 유실됐거나 `re.M`을 빼서 첫 줄만 봤다 |
| `grep -c`가 더 적다 | `grep -c`는 매칭된 **줄 수**다. 한 줄에 2건이면 1로 센다 |

PowerShell 쪽 세부는 [FOR-0121](./powershell-select-string.html)에 있다.

## mini walkthrough

```text
문제:
"auth.log 에서 무차별 대입에 사용된 계정 상위 3개와, 최종적으로 로그인에 성공한
 계정·출처 IP를 구하세요."
첨부: auth.log (88,214줄)

1. 형식 확인
   with open('auth.log', encoding='utf-8', errors='replace') as f:
       for i, l in zip(range(2), f): print(repr(l))
   -> 'Mar 14 07:19:02 web01 sshd[2311]: Failed password for invalid user admin
       from 203.0.113.77 port 51022 ssh2\n'
      'Mar 14 07:19:03 web01 sshd[2313]: Failed password for root from
       203.0.113.77 port 51028 ssh2\n'

2. 첫 시도 (실패):
   users = re.findall(r'for (invalid user )?(\S+) from', text)
   Counter(users).most_common(3)
   -> [(('invalid user ', 'admin'), 4120), (('', 'root'), 3901), ...]

   원소가 튜플이다. 그룹이 2개라서 튜플 리스트가 됐고,
   'invalid user ' 유무에 따라 같은 계정이 두 종류로 갈라진다.
   집계 자체가 무의미하다.

3. 접근 변경 — 앞의 그룹을 (?:...) 로 바꿔 캡처를 하나로 줄인다
   PAT = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')
   fails = Counter()
   with open('auth.log', encoding='utf-8', errors='replace') as f:
       for line in f:
           for user, ip in PAT.findall(line):
               fails[user] += 1
   print(fails.most_common(3))
   -> [('admin', 4120), ('root', 3901), ('test', 1204)]

   그룹이 2개이므로 findall 은 (user, ip) 튜플을 준다.
   이번에는 그것이 의도한 형태다.

4. 성공 로그인 찾기 — 두 번째 실패
   re.findall(r'Accepted password for (\S+) from (\S+)', text)
   -> []   0건. 그런데 침해는 성공했다고 지문에 있다.

   원인: 키 인증이었다. 메시지가 'Accepted publickey for ...' 다.
   문자열을 추측한 것이 실패의 원인이다.

5. 메시지 문자열을 로그에서 직접 확인
   print(Counter(re.findall(r'sshd\[\d+\]: (\w+(?: \w+)?)', text)).most_common(6))
   -> [('Failed password', 12043), ('Connection closed', 3300),
       ('Invalid user', 4120), ('Accepted publickey', 1), ...]

   'Accepted publickey' 가 정확히 1건.

6. 그 한 줄을 뽑는다
   PAT2 = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+) port')
   print(PAT2.findall(text))
   -> [('svc_backup', '203.0.113.77')]

7. 시간대
   syslog 의 'Mar 14 07:19:02' 에는 연도와 시간대가 없다.
   서버 /etc/timezone 또는 파일 mtime 으로 확정해야 한다.
   이 문제의 서버가 UTC 였으므로 07:19:02 UTC = 16:19:02 KST.

8. 교차검증
   grep -c 'Failed password for invalid user admin ' auth.log   -> 4120
   grep 'Accepted publickey' auth.log | wc -l                    -> 1

정답: 상위 계정 admin / root / test,
      성공 계정 svc_backup, 출처 203.0.113.77
```

2단계와 4단계가 교훈이다. **그룹 개수가 반환형을 바꾼다. 그리고 로그 메시지 문자열은 추측하지 말고 로그에서 뽑아 확인한다.**

## 막혔을 때 다음 체크

1. `repr()`로 원본 줄을 봤는가 — 탭·`\r`·이중 공백이 정규식을 깨뜨린다
2. 값이 잘려 나오면 반복 그룹을 `(?:...)`로 바꿨는가
3. 결과가 튜플이면 그룹 수를 세어 봤는가
4. `read()` 후 `^`를 썼는데 `re.MULTILINE`을 줬는가
5. 결과가 0건이면 패턴의 절반만 남겨 다시 시도했는가 (이분 탐색)
6. 문자열 상수를 추측하지 않고 로그에서 실제 메시지를 뽑아 확인했는가
7. `.*`가 한 줄을 다 삼키고 있지 않은가 — `[^"]*`로 바꿔 본다
8. `errors='replace'`로 열었는가
9. 개수 문제라면 `len()`과 `len(set())`을 둘 다 봤는가
10. 위치·오프셋이 필요해졌으면 `finditer`로 넘어갈 시점인가 (FOR-0123)
11. `awk`/`grep` 숫자와 맞춰 봤는가
12. 시각 문자열의 시간대를 확정했는가 — 연도가 없는 syslog는 특히 위험하다

## 출처

- SRC-057 — Python 공식 문서 `re` 모듈: `findall`의 그룹 개수별 반환형 규칙, 빈 매칭 포함 여부, 플래그(`re.I`/`re.M`/`re.S`/`re.X`/`re.A`), 바이트 패턴 제약
- `collections.Counter`, `mmap`, `open(errors=...)` 동작은 같은 Python 표준 라이브러리 문서 계열에서 확인했다. `research/sources.json`에는 SRC-057이 `re`/`csv`/`json` 묶음으로 등록되어 있어 그 범위 안에서 인용했다
- `re` 모듈 내부 컴파일 캐시의 크기와 교체 정책은 CPython 구현 세부이며 버전에 따라 다를 수 있다. 캐시 크기에 의존하는 판단은 하지 않았다
- 예시 로그 값(IP·계정·건수)은 설명용 가상 데이터다
