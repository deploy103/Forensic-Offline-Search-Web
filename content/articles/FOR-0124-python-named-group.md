---
id: FOR-0124
title: "Python 명명 캡처 그룹으로 로그를 표로 만들기: (?P<name>...)"
slug: "python-named-group"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["access.log", "auth.log", "syslog", "error.log"]
file_paths: ["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Python", "re", "csv", "pandas"]
commands: ["python -c \"import re;print(re.match(r'(?P<a>\\d+)-(?P<b>\\d+)','12-34').groupdict())\"", "python parse_apache.py access.log out.csv"]
regex_patterns: ["(?P<ip>\\S+) \\S+ \\S+ \\[(?P<time>[^\\]]+)\\]", "(?P<mon>[A-Z][a-z]{2})\\s+(?P<day>\\d{1,2}) (?P<time>\\d{2}:\\d{2}:\\d{2})", "Failed password for (?:invalid user )?(?P<user>\\S+) from (?P<ip>\\S+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ip", "time", "method", "uri", "status", "size", "referer", "ua", "user", "host", "proc", "pid"]
file_formats: ["log", "csv", "txt"]
primary_terms: ["named group", "(?P<name>", "명명 캡처"]
keywords: ["named group", "(?P<name>...)", "(?P=name)", "\\g<name>", "groupdict", "csv.DictWriter", "pandas", "Apache combined", "syslog 파싱", "명명 그룹", "정규식 필드 이름"]
aliases: ["파이썬 명명 그룹", "?P<name>", "정규식 이름 붙이기", "groupdict", "아파치 로그 파싱 파이썬", "syslog 정규식", "auth.log 파싱"]
symptom_keywords: ["그룹 번호가 헷갈린다", "로그를 표로 만들고 싶다", "정규식이 너무 길어서 못 읽겠다", "CSV로 저장하고 싶다", "치환할 때 이름을 쓰고 싶다", "닷넷 정규식이 파이썬에서 안 된다"]
related: ["FOR-0122", "FOR-0123", "FOR-0121"]
source_ids: ["SRC-057", "SRC-058"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`(?P<name>...)`로 그룹에 이름을 붙이면 `m.groupdict()`가 곧바로 dict를 주고, 그 dict를 `csv.DictWriter`에 던지면 로그 한 줄이 표 한 행이 된다. 그룹 번호를 세는 일이 사라지므로 필드가 다섯 개를 넘는 로그 파싱은 명명 그룹 없이 하지 않는다.

## 어떤 문제에서 필요한가

- Apache/nginx access log, syslog, `auth.log`를 필드별로 잘라 표로 만들어야 하는 상황
- 그룹이 6~10개라 `m.group(7)`이 무엇인지 세다가 틀리는 상황
- 결과를 CSV로 내보내 Timeline Explorer나 스프레드시트에서 정렬·필터해야 하는 상황
- 정규식이 길어져 다음 날 자기도 못 읽는 상황
- `re.sub`로 마스킹·정규화하면서 원래 값을 이름으로 참조해야 하는 상황
- PowerShell(.NET) 정규식을 그대로 붙여 넣었는데 파이썬에서 에러가 나는 상황

## 문제에서 처음 볼 단서

1. 로그 한 줄에 필드가 5개 이상이다
2. 문제가 "가장 많이 요청한 URI", "상태 코드별 건수"처럼 **필드 단위 집계**를 묻는다
3. 필드 구분자가 공백·대괄호·따옴표로 섞여 있어 `split()`으로 못 자른다
4. 최종 산출물이 표·CSV·타임라인이다

로그 한 줄을 `repr`로 먼저 본다. 여기서 필드 경계를 확정하지 않으면 정규식이 계속 어긋난다.

```python
with open('access.log', encoding='utf-8', errors='replace') as f:
    print(repr(next(f)))
```

```text
'203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199 "-" "sqlmap/1.7"\n'
```

## 30초 절차

```bash
python -c "import re;print(re.match(r'(?P<a>\d+)-(?P<b>\d+)','12-34').groupdict())"
```

```text
{'a': '12', 'b': '34'}
```

Apache combined 로그를 표로 바꾸는 완성 코드는 아래 열 줄이다.

```python
import re, csv

APACHE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
FIELDS = ['ip', 'ident', 'user', 'time', 'method', 'uri', 'proto',
          'status', 'size', 'referer', 'ua']

with open('access.log', encoding='utf-8', errors='replace') as fin, \
     open('access.csv', 'w', newline='', encoding='utf-8-sig') as fout:
    w = csv.DictWriter(fout, fieldnames=FIELDS)
    w.writeheader()
    bad = 0
    for line in fin:
        m = APACHE.match(line)
        if m:
            w.writerow(m.groupdict())
        else:
            bad += 1
print('unparsed lines:', bad)
```

```text
unparsed lines: 12
```

`bad`를 반드시 출력한다. 0이 아니면 그 줄들이 형식이 다른 줄이고, 거기에 답이 숨어 있는 경우가 많다.

## 상세 절차

### 1단계 — 문법 네 개

| 용도 | 문법 | 예 |
| --- | --- | --- |
| 그룹 정의 | `(?P<name>...)` | `(?P<ip>\S+)` |
| 패턴 안에서 역참조 | `(?P=name)` | `<(?P<tag>\w+)>.*?</(?P=tag)>` |
| 치환 문자열에서 참조 | `\g<name>` | `re.sub(p, r'\g<user>@X', s)` |
| 코드에서 값 접근 | `m.group('name')` / `m['name']` / `m.groupdict()` | `m['status']` |

이름은 파이썬 식별자 규칙을 따른다. 즉 문자·숫자·밑줄만 쓰고 숫자로 시작할 수 없다. **한 패턴 안에서 같은 이름을 두 번 쓰면 컴파일 에러다.**

```python
import re
re.compile(r'(?P<x>a)(?P<x>b)')
# re.error: redefinition of group name 'x' as group 2; was group 1 at position 12
```

명명 그룹도 캡처 그룹이므로 번호를 함께 갖는다. `m.group(1)`과 `m.group('ip')`가 같은 값일 수 있다는 뜻이고, `m.groups()`에도 포함된다.

```python
m = re.match(r'(?P<ip>\S+) (?P<st>\d+)', '10.0.0.1 200')
m.groups()        # ('10.0.0.1', '200')
m.group(1)        # '10.0.0.1'
m.group('ip')     # '10.0.0.1'
m.groupdict()     # {'ip': '10.0.0.1', 'st': '200'}
```

`findall`은 이름을 무시하고 튜플만 준다. 이름으로 접근하려면 `finditer`나 `match`/`search`를 쓴다.

### 2단계 — 역참조 `(?P=name)`

같은 값이 두 번 나타나는 구조를 잡을 때 쓴다. 태그 쌍, 따옴표 쌍, 반복된 IP가 대표적이다.

```python
import re

# 열고 닫는 태그가 같은 것만
re.findall(r'<(?P<tag>\w+)>(?P<body>.*?)</(?P=tag)>', '<b>hi</b><i>x</b>')
# [('b', 'hi')]      <i>x</b> 는 태그가 달라서 제외된다

# 출발지와 목적지가 같은 (자기 자신에게 보내는) 연결
re.search(r'src=(?P<ip>\S+) .*dst=(?P=ip)\b', 'src=10.0.0.5 proto=tcp dst=10.0.0.5')
```

역참조는 **정규식 엔진 안에서** 값이 같은지 비교한다. 파이썬 코드에서 비교하는 것보다 빠르고, 한 번의 스캔으로 끝난다.

### 3단계 — `re.VERBOSE`로 긴 패턴을 읽게 만든다

필드가 열 개인 패턴은 한 줄로 두면 검토가 불가능하다. `re.X`를 주면 패턴 안의 공백이 무시되고 `#` 주석을 쓸 수 있다.

```python
import re

APACHE = re.compile(r'''
    ^(?P<ip>\S+)\s+          # 클라이언트 IP
    (?P<ident>\S+)\s+        # identd (거의 항상 -)
    (?P<user>\S+)\s+         # HTTP 인증 사용자 (없으면 -)
    \[(?P<time>[^\]]+)\]\s+  # 14/Mar/2026:07:19:02 +0900
    "(?P<method>[A-Z]+)\s+   # GET / POST
     (?P<uri>\S+)\s*
     (?P<proto>[^"]*)"\s+
    (?P<status>\d{3})\s+     # 상태 코드
    (?P<size>\d+|-)          # 응답 바이트. 없으면 -
    (?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?   # combined 에만 있다
    ''', re.VERBOSE)
```

`re.X`에서 주의할 것 두 가지다.

- 공백을 매칭하려면 `\s`, `[ ]`, `\ `로 명시한다. 그냥 스페이스는 무시된다
- `#`을 리터럴로 쓰려면 `\#` 또는 `[#]`로 이스케이프한다

마지막 그룹을 `(?:...)?`로 감싼 것은 common 형식(필드 7개)과 combined 형식(필드 9개)을 한 패턴으로 받기 위해서다. Apache는 `LogFormat`에 따라 두 형식을 다 쓴다. 미매칭 그룹은 `None`이 되므로 `groupdict(default='')`로 빈 문자열로 받는다.

```python
m = APACHE.match('10.0.0.1 - - [14/Mar/2026:07:19:02 +0900] "GET / HTTP/1.1" 200 512')
m.groupdict(default='')['ua']    # ''  (None 대신)
```

### 4단계 — syslog / auth.log 완성 패턴

전통적인 syslog 줄은 `타임스탬프 호스트 프로세스[PID]: 메시지` 구조다.

```python
import re

SYSLOG = re.compile(r'''
    ^(?P<mon>[A-Z][a-z]{2})\s+   # Mar
    (?P<day>\d{1,2})\s+          # 14   (한 자리면 공백 2개)
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<proc>[^\[\s:]+)          # sshd
    (?:\[(?P<pid>\d+)\])?        # [2311]  없을 수도 있다
    :\s+
    (?P<msg>.*)$
    ''', re.VERBOSE)

line = 'Mar 14 07:19:02 web01 sshd[2311]: Failed password for invalid user admin from 203.0.113.77 port 51022 ssh2'
print(SYSLOG.match(line).groupdict())
```

```text
{'mon': 'Mar', 'day': '14', 'time': '07:19:02', 'host': 'web01',
 'proc': 'sshd', 'pid': '2311',
 'msg': 'Failed password for invalid user admin from 203.0.113.77 port 51022 ssh2'}
```

메시지 안쪽은 두 번째 패턴으로 한 겹 더 벗긴다. 이렇게 두 단으로 나누면 각 패턴이 짧아져 디버깅이 쉽다.

```python
SSH_FAIL = re.compile(
    r'^(?P<result>Failed|Accepted)\s+(?P<method>password|publickey)\s+for\s+'
    r'(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src>\S+)\s+port\s+(?P<port>\d+)'
)
```

전통 syslog의 치명적 특성 두 개를 반드시 기록한다.

| 특성 | 결과 | 대응 |
| --- | --- | --- |
| 연도가 없다 | 12월/1월 경계에서 연도를 잘못 붙인다 | 파일의 mtime, 로테이션 파일명, 내부 재부팅 이벤트로 확정 |
| 시간대가 없다 | UTC인지 KST인지 알 수 없다 | 호스트의 `/etc/timezone`, `/etc/localtime`, 같은 사건의 다른 로그와 대조 |
| 하루 한 자리는 공백 2개 | `\s+`가 아니면 매칭 실패 | 항상 `\s+`를 쓴다 |

RFC 5424 형식(`<134>1 2026-03-14T07:19:02.123Z host app 2311 - - msg`)은 ISO 8601 타임스탬프와 시간대를 포함하므로 훨씬 안전하다. 두 형식이 한 파일에 섞이는 경우도 있어 `bad` 카운트로 확인해야 한다.

### 5단계 — dict를 그대로 표로 만든다

`groupdict()`가 dict이므로 표 만들기가 곧바로 이어진다.

```python
import re, csv
from collections import Counter

rows, statuses = [], Counter()
with open('access.log', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = APACHE.match(line)
        if not m:
            continue
        d = m.groupdict(default='')
        d['status'] = int(d['status'])
        d['size'] = int(d['size']) if d['size'].isdigit() else 0
        rows.append(d)
        statuses[d['status']] += 1

print(statuses.most_common())
print(Counter(r['uri'] for r in rows if r['status'] == 200).most_common(5))

with open('access.csv', 'w', newline='', encoding='utf-8-sig') as fout:
    w = csv.DictWriter(fout, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
```

```text
[(200, 31204), (404, 7712), (403, 2140), (302, 611), (500, 215)]
[('/index.html', 9821), ('/style.css', 8004), ('/uploads/av4tar.php', 219),
 ('/upload.php', 87), ('/favicon.ico', 44)]
```

`newline=''`과 `encoding='utf-8-sig'` 두 개가 실무 필수다. 앞은 Windows에서 빈 줄이 끼는 것을 막고, 뒤는 Excel이 한글을 깨뜨리지 않게 BOM을 붙인다. CSV 쪽 세부는 FOR-0125에서 다룬다.

pandas가 설치돼 있으면 dict 리스트를 그대로 넘긴다.

```python
import pandas as pd
df = pd.DataFrame(rows)
print(df.groupby('status').size())
print(df[df.status == 200].uri.value_counts().head())
```

`pandas`는 표준 라이브러리가 아니므로 오프라인 대회장에 없을 수 있다. `csv` + `Counter`만으로 같은 결론이 나오도록 먼저 작성하고, pandas는 있으면 쓰는 보너스로 취급한다.

### 6단계 — `\g<name>` 치환

치환 문자열에서 명명 그룹을 참조한다. 번호(`\1`)보다 안전하고, 그룹을 추가해도 깨지지 않는다.

```python
import re

# 계정명만 남기고 IP 마스킹
line = 'Failed password for admin from 203.0.113.77 port 51022'
print(re.sub(r'from (?P<ip>\d+\.\d+)\.\d+\.\d+', r'from \g<ip>.x.x', line))
```

```text
Failed password for admin from 203.0.x.x port 51022
```

```python
# 날짜 형식 정규화: 14/Mar/2026 -> 2026-03-14
MON = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06',
       'Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
p = r'(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4})'
print(re.sub(p, lambda m: f"{m['y']}-{MON[m['mon']]}-{m['d']}", '14/Mar/2026:07:19:02'))
```

```text
2026-03-14:07:19:02
```

월 약어를 dict로 직접 매핑한 이유가 있다. `datetime.strptime`의 `%b`는 **로케일 의존**이다. 한국어 로케일에서는 `Mar`을 인식하지 못해 `ValueError`가 난다. 로그의 월 약어는 영어이므로 dict 매핑이 가장 안전하다.

| 참조 문법 | 어디서 쓰나 | 비고 |
| --- | --- | --- |
| `\g<name>` | `re.sub` 치환 문자열 | 이름 참조. 가장 안전 |
| `\g<1>` | `re.sub` 치환 문자열 | 번호 참조. `\g<1>0`처럼 뒤에 숫자가 와도 안전 |
| `\1` | `re.sub` 치환 문자열 | `\10`이 10번 그룹으로 해석되는 함정 |
| `(?P=name)` | 패턴 내부 | 치환 문자열에서 쓰면 안 된다 |
| `m['name']` | 파이썬 코드 | `m.group('name')`과 동일 |

치환 문자열은 항상 raw 문자열로 쓴다. `'\g<ip>'`는 되지만 `'\1'`은 제어문자가 되어 조용히 틀린다.

### 7단계 — .NET(PowerShell)과 문법이 다르다

같은 로그 패턴을 PowerShell과 파이썬에서 돌려야 할 때 반드시 걸리는 지점이다.

| 기능 | Python `re` | .NET / PowerShell |
| --- | --- | --- |
| 명명 그룹 정의 | `(?P<name>...)` | `(?<name>...)` 또는 `(?'name'...)` |
| 패턴 내 역참조 | `(?P=name)` | `\k<name>` |
| 치환에서 참조 | `\g<name>` | `${name}` |
| 코드에서 접근 | `m.group('name')` | `$m.Groups['name'].Value` |
| `(?P<...>)` 지원 | 표준 | **지원하지 않는다** |
| `(?<...>)` 지원 | Python 3.12+에서도 미지원 | 표준 |

PowerShell 쪽 예시는 [FOR-0121](./powershell-select-string.html)에 있다. 파이썬에서 `(?<name>...)`를 쓰면 이렇게 죽는다.

```python
import re
re.compile(r'(?<ip>\S+)')
# re.error: unknown extension ?<i at position 1
```

거꾸로 PowerShell에서 `(?P<ip>...)`를 쓰면 `Select-String`이 정규식 파싱 예외를 던진다. **패턴을 복사해 옮길 때는 `P` 하나만 넣거나 빼면 된다.** 그 외 문법(문자 클래스, 수량자, 전방·후방탐색, 인라인 옵션 `(?i)`)은 대체로 호환된다.

## 출력 필드 해석

Apache combined 로그의 필드 의미와 조사에서의 용도다.

| 그룹 이름 | Apache 지시자 | 의미 | 조사에서 보는 것 |
| --- | --- | --- | --- |
| `ip` | `%h` | 클라이언트 주소 | 공격자 식별. 프록시 뒤면 `X-Forwarded-For`를 봐야 한다 |
| `ident` | `%l` | identd 사용자 | 거의 항상 `-`. 무시 |
| `user` | `%u` | HTTP 인증 사용자 | `-`가 아니면 인증된 요청. 계정 탈취 흔적 |
| `time` | `%t` | `14/Mar/2026:07:19:02 +0900` | 오프셋으로 시간대 확정 |
| `method` | `%r`의 앞부분 | GET/POST/PUT/DELETE | POST·PUT은 업로드 의심 |
| `uri` | `%r`의 중간 | 경로와 쿼리스트링 | 웹셸·LFI·SQLi 파라미터 |
| `proto` | `%r`의 끝 | `HTTP/1.1` | 비정상 값이면 스캐너 |
| `status` | `%>s` | 상태 코드 | 200·302는 성공, 403·404는 실패 |
| `size` | `%b` | 응답 바이트. 본문 없으면 `-` | 급증 지점이 유출 성공 신호 |
| `referer` | `%{Referer}i` | 유입 경로 | `-`면 직접 접근 = 자동화 의심 |
| `ua` | `%{User-Agent}i` | 클라이언트 문자열 | `sqlmap`, `curl`, `python-requests`, `nikto` |

`time` 필드의 `+0900`이 KST를 뜻한다. `$MFT`·EVTX 같은 UTC 기준 artifact와 대조할 때는 9시간을 빼서 맞춘다. `%t`의 오프셋은 서버 로컬 시간대이므로, 서버가 UTC면 `+0000`으로 찍힌다.

`size`가 `-`인 이유는 응답 본문이 없었다는 뜻이다(304, HEAD 요청 등). `int()`로 바로 변환하면 `ValueError`가 나므로 위 코드처럼 `isdigit()` 방어가 필요하다.

## pivot: 다음에 볼 artifact

| 명명 그룹으로 얻은 필드 | 다음 목표 |
| --- | --- |
| `ip` 상위값 | pcap `ip.addr == <IP>` / 방화벽 로그 / 다른 서비스 로그의 같은 IP |
| `user` (인증된 요청) | EVTX 4624/4625, `/var/log/auth.log`의 같은 계정 |
| `uri`의 업로드 파일명 | 웹 루트의 실제 파일, `$MFT` 생성 시각, 파일 해시 |
| `status` 200 + 큰 `size` | 데이터 유출 성공 지점. 그 시각의 pcap |
| `ua` 문자열 | 공격 도구 특정. 같은 UA의 다른 요청 전부 |
| `time` | ±5분 창의 모든 artifact. 시간대 변환 후 |
| `proc`/`pid` (syslog) | 프로세스 단위 세션 추적 |
| 파싱 실패한 줄(`bad`) | 형식이 다른 줄. 공격 페이로드가 형식을 깨뜨린 경우가 많다 |
| dict 리스트 | CSV로 저장 → Timeline Explorer, 스프레드시트 (FOR-0125) |

## 흔한 함정

- **`(?<name>...)`를 파이썬에 쓰는 것.** .NET/PowerShell 문법이다. `re.error: unknown extension`으로 죽는다. 왜 틀리나: 파이썬은 `(?P<name>...)`만 인식한다. 어떻게: 옮길 때 `P`를 넣는다. 거꾸로 PowerShell에 붙일 때는 `P`를 뺀다.
- **같은 이름을 두 번 쓰는 것.** `(?P<x>a)|(?P<x>b)`는 컴파일 에러다. 왜 틀리나: 이름은 패턴 전체에서 유일해야 한다. 어떻게: `(?P<x1>a)|(?P<x2>b)`로 나누고 `m.lastgroup`으로 어느 쪽인지 판별한다.
- **미매칭 그룹을 문자열로 다루는 것.** `(?:...)?` 안의 그룹은 매칭되지 않으면 `None`이다. `d['ua'].lower()`가 `AttributeError`로 죽는다. 어떻게: `m.groupdict(default='')`를 쓴다.
- **`size`를 `int()`로 바로 변환하는 것.** Apache는 본문이 없으면 `-`를 찍는다. `ValueError: invalid literal for int()`. 어떻게: `int(v) if v.isdigit() else 0`.
- **`match`와 `search`를 혼동하는 것.** `match`는 문자열 **시작**에서만 본다. `^`를 넣고 `search`를 쓰거나 `match`를 쓰는 것 중 하나로 통일한다. 앞에 공백이 하나 있는 줄이 전부 실패하는 원인이 이것이다.
- **파싱 실패 줄을 세지 않는 것.** `if m:`로 조용히 건너뛰면 로그의 30%를 버려도 모른다. 왜 틀리나: 공격 페이로드에 따옴표·줄바꿈이 들어가면 그 줄만 형식이 깨진다. 어떻게: `bad` 카운터를 출력하고, 0이 아니면 그 줄들을 직접 본다.
- **`re.VERBOSE`에서 공백을 그냥 쓰는 것.** `re.X`는 패턴의 공백을 전부 무시한다. `ip time` 사이의 스페이스가 사라져 매칭이 안 된다. 어떻게: `\s+`, `[ ]`, `\ `로 명시한다.
- **`%b`를 `strptime`으로 파싱하는 것.** `%b`는 로케일 의존이라 한국어 환경에서 `Mar`을 못 읽고 `ValueError`가 난다. 어떻게: 월 약어를 dict로 직접 매핑하거나 로케일을 `C`로 고정한다.
- **syslog에 연도·시간대를 임의로 붙이는 것.** 전통 syslog에는 둘 다 없다. 파일 mtime과 로테이션 파일명으로 확정한 뒤 기록에 남긴다. 추측한 연도로 타임라인을 만들면 전체가 무의미해진다.
- **치환 문자열을 raw로 쓰지 않는 것.** `'\g<ip>'`는 우연히 동작하지만 `'\1'`은 제어문자가 된다. 항상 `r'...'`을 쓴다.
- **`findall`로 명명 그룹을 쓰는 것.** 이름이 무시되고 튜플만 온다. 이름이 필요하면 `finditer`/`match`/`search`를 쓴다.
- **`groupdict()`를 그대로 CSV에 쓰면서 `newline=''`을 빼는 것.** Windows에서 행마다 빈 줄이 끼어 행 수가 두 배로 보인다.

## 교차검증

명명 그룹 파싱 결과는 필드 기준 도구와 반드시 맞춰 본다.

```python
from collections import Counter
print(Counter(r['status'] for r in rows).most_common(5))
print(len(rows), 'parsed', bad, 'unparsed')
```

```bash
# awk 필드 기준 — 상태 코드는 combined 형식에서 9번째 필드
awk '{print $9}' access.log | sort | uniq -c | sort -rn | head -5

# 전체 줄 수와 파싱 성공 수의 합이 맞는지
wc -l access.log
```

```powershell
Select-String -Path .\access.log -Pattern '" (\d{3}) ' -AllMatches |
  ForEach-Object { $_.Matches[0].Groups[1].Value } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 5 Count, Name
```

| 차이 | 원인 |
| --- | --- |
| `parsed + bad != wc -l` | 마지막 줄에 줄바꿈이 없거나 파일 안에 NUL이 있다 |
| awk 결과가 다르다 | URI에 공백이 있어 필드 번호가 밀렸다. 정규식 쪽이 맞다 |
| 정규식이 훨씬 적다 | `match`를 썼는데 줄 앞에 공백·BOM이 있다 |
| 특정 상태 코드만 누락 | 그 줄에 따옴표가 홀수 개다. 공격 페이로드 의심 |

세 번째와 네 번째는 그 자체가 단서다. **형식을 깨뜨린 줄이 공격 줄인 경우가 많다.**

## mini walkthrough

```text
문제:
"access.log 를 파싱해 공격자가 업로드에 성공한 파일명과, 그 파일로 실행한
 명령 목록을 CSV 로 제출하세요."
첨부: access.log (41,882줄)

1. 한 줄 확인
   repr(next(open('access.log', encoding='utf-8', errors='replace')))
   -> '203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199 "-" "sqlmap/1.7"\n'
      combined 형식. 시간대 +0900 = KST.

2. 첫 시도 (실패):
   PAT = re.compile(r'^(?<ip>\S+) .* "(?<method>\S+) (?<uri>\S+)')
   -> re.error: unknown extension ?<i at position 1

   .NET 문법을 그대로 붙였다. PowerShell 에서 쓰던 패턴이었다.

3. 문법 교정 — P 를 넣는다
   PAT = re.compile(r'^(?P<ip>\S+) .* "(?P<method>\S+) (?P<uri>\S+)')
   parsed = sum(1 for l in open('access.log', encoding='utf-8', errors='replace')
                if PAT.match(l))
   -> 41870 / 41882.  12줄이 실패.

4. 두 번째 실패 — 실패한 12줄을 무시하려다 멈춘다
   업로드 성공 줄을 찾는데 안 나온다.
   for l in ...: if 'upload' in l and '200' in l: print(l)
   -> 아무것도 없음.

   실패한 12줄을 직접 본다.
   for i, l in enumerate(open('access.log', encoding='utf-8', errors='replace'), 1):
       if not PAT.match(l): print(i, repr(l))
   -> 8842 '203.0.113.77 - - [14/Mar/2026:07:19:44 +0900] "POST /upload.php?f="av4tar.php" HTTP/1.1" 200 87 "-" "curl/8.5"\n'
      ...
   URI 안에 따옴표가 들어 있어 combined 패턴의 "..." 경계가 깨졌다.
   즉 파싱 실패 줄이 바로 공격 줄이었다.

5. 완성 패턴 — 따옴표 대신 마지막 " 까지 게으르지 않게 잡고,
   요청 라인 전체를 한 그룹으로 받은 뒤 다시 쪼갠다
   FULL = re.compile(r'''
       ^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+
       \[(?P<time>[^\]]+)\]\s+
       "(?P<request>.*)"\s+
       (?P<status>\d{3})\s+(?P<size>\d+|-)
       (?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?
       ''', re.VERBOSE)
   REQ = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<uri>.*?)\s+(?P<proto>HTTP/\S+)$')

   -> 41882 / 41882.  전부 파싱됨.

6. 업로드 성공과 이후 실행 추출
   rows = []
   for line in open('access.log', encoding='utf-8', errors='replace'):
       m = FULL.match(line)
       if not m: continue
       d = m.groupdict(default='')
       r = REQ.match(d.pop('request'))
       if r: d.update(r.groupdict())
       rows.append(d)

   ups = [r for r in rows if r['method'] == 'POST' and r['status'] == '200'
          and 'upload' in r['uri']]
   print(ups)
   -> [{'ip':'203.0.113.77','time':'14/Mar/2026:07:19:44 +0900',
        'status':'200','method':'POST','uri':'/upload.php?f="av4tar.php"', ...}]

   cmds = [r for r in rows if 'av4tar.php' in r['uri'] and 'cmd=' in r['uri']]
   for r in cmds[:3]: print(r['time'], r['uri'])
   -> 14/Mar/2026:07:20:15 +0900 /uploads/av4tar.php?cmd=id
      14/Mar/2026:07:20:31 +0900 /uploads/av4tar.php?cmd=whoami
      14/Mar/2026:07:21:07 +0900 /uploads/av4tar.php?cmd=cat+/etc/passwd

7. CSV 로 저장
   import csv
   with open('attack.csv','w',newline='',encoding='utf-8-sig') as f:
       w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
       w.writeheader(); w.writerows(cmds)

8. 시간대
   +0900 이므로 위 시각은 KST. UTC 기준 artifact 와 대조할 때는 9시간을 뺀다.
   07:20:15 KST = 2026-03-13 22:20:15 UTC.

정답: 업로드 파일 av4tar.php (2026-03-14 07:19:44 KST) /
      실행 명령 id, whoami, cat /etc/passwd
```

2단계와 4단계가 교훈이다. **`(?<name>)`은 .NET이고 `(?P<name>)`이 파이썬이다. 그리고 파싱 실패 줄을 세지 않으면 답을 놓친다.**

## 막혔을 때 다음 체크

1. `(?P<name>...)`의 `P`를 넣었는가 — .NET 패턴을 붙여 넣지 않았는가
2. 그룹 이름이 중복되지 않는가
3. `match`인가 `search`인가 — 줄 앞 공백·BOM이 있으면 `match`가 전부 실패한다
4. 파싱 실패 줄 수를 출력했는가 — 그 줄에 답이 있을 수 있다
5. `groupdict(default='')`로 `None`을 막았는가
6. `int()` 변환 전에 `-` 값을 방어했는가
7. `re.VERBOSE`에서 공백을 `\s+`로 명시했는가
8. `findall`을 쓰고 있지 않은가 — 이름이 필요하면 `finditer`
9. 치환 문자열을 `r'...'`로 썼는가
10. syslog면 연도와 시간대를 무엇으로 확정했는가
11. CSV 저장에 `newline=''`과 `encoding='utf-8-sig'`를 줬는가
12. `awk`/`Select-String` 결과와 필드별 건수를 맞춰 봤는가

## 출처

- SRC-057 — Python 공식 문서 `re` 모듈: `(?P<name>...)`, `(?P=name)`, `\g<name>` 문법과 그룹 이름 중복 시 컴파일 에러, `groupdict(default=...)`, `re.VERBOSE`의 공백·주석 규칙, `findall`이 그룹 이름을 무시하는 동작
- SRC-058 — Apache HTTP Server Log Files 문서: common/combined 로그 형식의 `%h %l %u %t \"%r\" %>s %b` 지시자 정의와 각 필드 의미, 본문 없는 응답에서 `%b`가 `-`가 되는 동작
- .NET/PowerShell 정규식 문법(`(?<name>...)`, `\k<name>`, `${name}`)은 Microsoft의 .NET 정규식 문서가 1차 출처다. `research/sources.json`에 해당 SRC가 없어 이 글에서는 대조표만 제시했다. 추가를 권한다
- `strptime`의 `%b`가 로케일 의존이라는 점은 Python `datetime` 문서 범위이며, 실행 환경의 로케일에 따라 결과가 달라지므로 실제 환경에서 확인할 것
- 예시 로그 값(IP·파일명·건수)은 설명용 가상 데이터다
