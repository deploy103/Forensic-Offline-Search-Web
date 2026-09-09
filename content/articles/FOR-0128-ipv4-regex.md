---
id: FOR-0128
title: "IPv4 주소 regex: 느슨한 패턴과 엄격한 패턴 골라 쓰기"
slug: "ipv4-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["access.log", "auth.log", "syslog", "firewall log", "memory strings"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["IPv4", "TCP", "UDP"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "awk", "tshark"]
commands: ["grep -Eo '[0-9]{1,3}(\\.[0-9]{1,3}){3}' access.log", "rg -o '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'", "Select-String -Pattern '\\d{1,3}(\\.\\d{1,3}){3}' -AllMatches", "re.findall(r'(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])', text)"]
regex_patterns: ["[0-9]{1,3}(\\.[0-9]{1,3}){3}", "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])", "\\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\b", "(?<![\\d.])(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?![\\d.])", "\\b(?:10|127|169\\.254|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\."]
wireshark_filters: ["ip.addr == 203.0.113.77", "ip.src == 10.0.0.0/8"]
tshark_fields: ["ip.src", "ip.dst"]
log_fields: []
file_formats: ["log", "txt", "csv"]
keywords: ["IPv4 regex", "IP 정규식", "ip 추출", "dotted quad", "옥텟", "octet", "사설 IP", "private ip", "255 검증"]
aliases: ["ip 정규식", "regex ip", "ipv4 정규식", "ip 주소 찾기", "grep ip", "아이피 추출", "ip 뽑기"]
symptom_keywords: ["IP만 뽑고 싶다", "999.999.999.999가 잡힌다", "버전 번호가 IP로 잡힌다", "IP가 잘려서 나온다", "사설 IP만 걸러내고 싶다", "IP 빈도를 세고 싶다"]
related: ["FOR-0121", "FOR-0001"]
source_ids: ["SRC-012", "SRC-015", "SRC-007"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

로그에서 IP를 뽑을 때는 먼저 느슨한 `[0-9]{1,3}(\.[0-9]{1,3}){3}`로 후보를 전부 긁고, 오탐(버전 번호·타임스탬프·잘린 IP)이 섞여 문제가 될 때만 옥텟 범위를 검증하는 엄격한 패턴으로 바꾼다.

## 개념

IPv4는 0–255 범위의 정수 4개를 점으로 이은 표기(dotted quad)다. 정규식은 이 "0–255"를 표현할 방법이 없으므로 **네 구간으로 나눈 대안(alternation)** 으로 흉내낸다.

```text
(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])
 250-255  200-249    100-199    0-99
```

이 조각 하나가 "한 옥텟"이다. 점으로 3번 반복하고 마지막에 한 번 더 붙이면 완성된다.

포렌식에서는 두 가지 패턴을 **목적에 따라 골라 쓰는 것**이 정답이다.

| | 느슨한 패턴 | 엄격한 패턴 |
| --- | --- | --- |
| 목적 | 후보 전부 회수 (재현율 우선) | 정확한 추출 (정밀도 우선) |
| 길이 | 짧아서 손으로 칠 수 있다 | 길어서 복붙해야 한다 |
| 오탐 | 있음 (`999.1.1.1`, `1.2.3.4.5`) | 거의 없음 |
| 쓰는 곳 | 초기 탐색, `strings` 결과, 메모리 덤프 | 최종 목록화, 자동 집계 |

초기 탐색에서 엄격한 패턴을 쓰면 **잘린 IP나 변형 표기를 놓친다.** 순서를 지키는 것이 중요하다.

## 파일 / 경로

IP가 나오는 대표적인 곳이다.

| 대상 | 경로/형식 | IP가 있는 위치 |
| --- | --- | --- |
| Apache/Nginx access log | `access.log` | **1번째 필드** (또는 `X-Forwarded-For`) |
| Linux auth log | `/var/log/auth.log`, `/var/log/secure` | `from <IP>` |
| syslog | `/var/log/syslog`, `/var/log/messages` | 메시지 본문 |
| Windows EVTX 4624/4625 | `Security.evtx` | `IpAddress` 필드 |
| IIS log | `C:\inetpub\logs\LogFiles\W3SVC*\*.log` | `c-ip`, `s-ip` 필드 |
| 메모리 덤프 | `*.raw`, `*.mem` | `strings` 결과 전체 |
| pcap | `*.pcapng` | `ip.src` / `ip.dst` |
| 방화벽/프록시 로그 | 벤더별 | `src=`, `dst=` |

## 주요 필드

### 패턴 1 — 느슨한 후보 수집 (가장 많이 쓴다)

```text
[0-9]{1,3}(\.[0-9]{1,3}){3}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `10.0.0.1`, `203.0.113.77`, `192.168.1.100`, `0.0.0.0`, `255.255.255.255` |
| 매칭 안 됨 | `10.0.0`, `2001:db8::1`, `10.0.0.a` |
| **오탐** | `999.999.999.999`, `1.2.3.4.5`의 일부, 소프트웨어 버전 `10.1.2.3` |

### 패턴 2 — 경계를 붙인 느슨한 패턴

```text
\b(?:\d{1,3}\.){3}\d{1,3}\b
```

`\b`가 앞뒤에 붙어 문자열 중간의 숫자 덩어리를 덜 잡는다. 다만 **`1.2.3.4.5`에서 `1.2.3.4`를 여전히 잡는다** — `.`은 단어 문자가 아니므로 `\b`가 경계로 성립한다.

### 패턴 3 — 엄격한 옥텟 검증 (최종 목록화용)

```text
\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `0.0.0.0`, `10.0.0.1`, `192.168.1.1`, `255.255.255.255` |
| 매칭 안 됨 | `256.1.1.1`, `999.999.999.999`, `01.02.03.04`(선행 0) |
| 남은 오탐 | `1.2.3.4.5`에서 `1.2.3.4` |

### 패턴 4 — 완전 엄격 (lookaround 사용, 오탐 거의 0)

```text
(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])
```

`(?<![\d.])` / `(?![\d.])`가 앞뒤에 숫자나 점이 오는 것을 금지하므로 `1.2.3.4.5`와 `192.168.1.1000`을 완전히 배제한다.

> **주의**: lookaround는 **`grep -E`에서 동작하지 않는다.** `grep -P`(PCRE), `rg -P`, PowerShell(.NET), Python(`re`)에서만 쓸 수 있다. 이 제약이 도구 선택을 좌우한다.

### 패턴 5 — 사설/특수 IP만 (또는 제외)

```text
\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.
```

| 대역 | 의미 |
| --- | --- |
| `10.0.0.0/8` | 사설 (RFC 1918) |
| `172.16.0.0/12` | 사설 (RFC 1918) |
| `192.168.0.0/16` | 사설 (RFC 1918) |
| `127.0.0.0/8` | 루프백 |
| `169.254.0.0/16` | 링크 로컬 (DHCP 실패) |

"외부에서 들어온 접속만 보고 싶다"면 이 패턴으로 `-v` / `-NotMatch` 하면 된다.

## 빠른 명령

### grep / ripgrep

```bash
# 1) 후보 전부, 값만 출력
grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' access.log

# 2) 빈도 상위 10 — 공격자 찾기 기본기
grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' access.log | sort | uniq -c | sort -nr | head -10

# 3) 엄격한 옥텟 검증 (grep -E로 가능)
grep -Eo '\b(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\b' access.log

# 4) lookaround까지 (PCRE 필요)
grep -Po '(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])' access.log

# 5) ripgrep — 기본은 느슨, -P로 PCRE2 활성화
rg -o '\b(?:\d{1,3}\.){3}\d{1,3}\b' access.log
rg -oP '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])' access.log

# 6) 사설 IP 제외 = 외부 접속만
grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' access.log |
  grep -Ev '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' |
  sort | uniq -c | sort -nr

# 7) 필드 위치가 확실하면 정규식보다 awk가 정확하다
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head
```

### PowerShell

```powershell
# 후보 전부 + 빈도
Select-String -Path .\access.log -Pattern '\d{1,3}(\.\d{1,3}){3}' -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 10 Count, Name

# 엄격 + lookaround (.NET이므로 그대로 동작)
$re = '(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])'
Select-String -Path .\access.log -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# 사설 IP 제외
... | Where-Object { $_ -notmatch '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' }

# 유효성 검증은 정규식보다 .NET 파서가 확실하다
'999.1.1.1', '10.0.0.1' | ForEach-Object {
  [pscustomobject]@{ Value = $_; Valid = [System.Net.IPAddress]::TryParse($_, [ref]$null) }
}
```

### Python

```python
import re
from collections import Counter
import ipaddress

LOOSE  = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
STRICT = re.compile(
    r'(?<![\d.])'
    r'(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?![\d.])'
)

text = open('access.log', encoding='utf-8', errors='replace').read()

# 1) 후보 수집 후 표준 라이브러리로 검증하는 것이 가장 확실하다
valid = []
for cand in LOOSE.findall(text):
    try:
        ip = ipaddress.IPv4Address(cand)
    except ipaddress.AddressValueError:
        continue          # 999.1.1.1, 01.02.03.04 등 탈락
    valid.append(ip)

# 2) 빈도 상위
for ip, n in Counter(valid).most_common(10):
    print(f'{n:6d}  {ip}')

# 3) 공인 IP만 (사설/루프백/링크로컬 제외)
external = [ip for ip in valid if ip.is_global]

# 4) 특정 대역에 속하는지
net = ipaddress.ip_network('192.168.10.0/24')
inside = [ip for ip in valid if ip in net]
```

**정규식으로 유효성까지 검증하려 하지 말고, 느슨하게 뽑아 `ipaddress`/`IPAddress.TryParse`에 넘기는 것이 가장 짧고 정확하다.**

## 함께 보는 artifact

| IP를 얻은 뒤 | 다음 목표 |
| --- | --- |
| 공격 IP 확정 | pcap: `ip.addr == <IP>` → Follow TCP Stream |
| 공격 IP 확정 | EVTX 4624/4625의 `IpAddress` ([FOR-0083](./event-4624-logon.html)) |
| 내부 IP 확정 | DHCP 로그, ARP 테이블, `NetworkList` 레지스트리 |
| 대역이 낯설다 | 문제 지문의 네트워크 구성도 재확인 |
| 도메인도 함께 | DNS 응답에서 IP↔도메인 매핑 |
| 시각 + IP | 그 시각의 모든 로그를 IP로 재검색 |

## 흔한 실수

- **정규식으로 0–255를 검증하려 애쓰는 것.** 느슨하게 뽑고 언어의 IP 파서로 검증하는 편이 짧고 정확하다.
- **`\d{1,3}(\.\d{1,3}){3}`에 경계를 안 붙이는 것.** 버전 문자열 `nginx/1.20.1.3`, 타임스탬프 `2026.03.14.07` 같은 것이 섞인다.
- **`grep -E`에서 lookaround를 쓰는 것.** `-E`는 POSIX ERE로 lookaround가 없다. `-P`가 필요하고, 일부 배포판의 `grep`은 `-P`가 컴파일되어 있지 않다. `rg -P`가 더 안전하다.
- **`.`을 이스케이프하지 않는 것.** `\d{1,3}.\d{1,3}`의 `.`은 아무 문자다. `10a0b0c1`도 매칭된다.
- **선행 0 표기를 놓치는 것.** `010.001.001.001`은 엄격 패턴에서 탈락하지만 실제 로그에 등장할 수 있다. `ipaddress` 모듈은 Python 3.9+에서 선행 0을 **거부**한다.
- **`X-Forwarded-For`를 무시하는 것.** 프록시 뒤 로그에서 1번 필드는 프록시 IP다. 진짜 클라이언트는 `X-Forwarded-For` 헤더에 있고, 쉼표로 여러 개가 들어온다.
- **IPv6 로그에서 IPv4 패턴만 돌리는 것.** `::ffff:192.0.2.1` 같은 매핑 표기와 순수 IPv6를 모두 놓친다.
- **필드 위치가 확실한데 정규식을 쓰는 것.** `awk '{print $1}'`이 오탐 0이고 더 빠르다. 정규식은 위치가 불확실할 때의 도구다.
- **빈도만 보고 결론 내리는 것.** 정상 모니터링 봇이 1위인 경우가 흔하다. User-Agent와 요청 URI를 함께 본다.

## mini example

```text
문제:
"침해된 서버의 auth.log에서 SSH 무차별 대입을 시도한 IP와 시도 횟수를 구하세요."
첨부: auth.log (128,441줄)

1. 형식 확인
   $ head -2 auth.log
   Mar 14 07:11:02 web01 sshd[2841]: Failed password for invalid user admin from 203.0.113.77 port 51234 ssh2
   Mar 14 07:11:04 web01 sshd[2843]: Failed password for root from 203.0.113.77 port 51240 ssh2

2. 느슨하게 IP 전부 + 빈도
   $ grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' auth.log | sort | uniq -c | sort -nr | head -5
      9821 203.0.113.77
       412 198.51.100.5
        88 192.168.10.24
        12 127.0.0.1

3. 문제: 9821에는 성공/실패/기타 메시지가 섞여 있다.
   "Failed password" 줄로 먼저 좁힌 뒤 IP를 뽑아야 한다.

   $ grep 'Failed password' auth.log |
       grep -Eo 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' |
       awk '{print $2}' | sort | uniq -c | sort -nr | head -3
      4903 203.0.113.77
       201 198.51.100.5
         4 192.168.10.24

4. 캡처 그룹으로 사용자 이름까지 함께 (Python)
   >>> import re
   >>> pat = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) '
   ...                  r'from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})')
   >>> from collections import Counter
   >>> c = Counter()
   >>> for line in open('auth.log'):
   ...     m = pat.search(line)
   ...     if m: c[(m['ip'], m['user'])] += 1
   >>> c.most_common(5)
   [(('203.0.113.77','root'), 1841), (('203.0.113.77','admin'), 902),
    (('203.0.113.77','test'), 411), (('198.51.100.5','root'), 201), ...]

5. 성공한 로그온이 있는지 (핵심)
   $ grep 'Accepted password' auth.log | grep '203.0.113.77'
   Mar 14 07:18:39 web01 sshd[3901]: Accepted password for svc_backup from 203.0.113.77 port 52890 ssh2

   -> 4903회 실패 후 07:18:39에 svc_backup으로 성공.

6. 교차검증 — 필드 기준
   $ awk '/Failed password/ {for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' auth.log |
       sort | uniq -c | sort -nr | head -1
      4903 203.0.113.77
   정규식 결과와 일치.

정답: 203.0.113.77, 실패 4,903회 (07:18:39에 svc_backup 계정으로 성공)
```

3단계가 핵심이다. **IP를 먼저 뽑고 세면 안 되고, 관심 있는 이벤트로 줄을 먼저 좁힌 다음 IP를 뽑아야 한다.**

## 출처

- SRC-012 — RFC 791: IPv4 주소 구조 및 옥텟 범위
- SRC-015 — GNU grep manual: `-E`(ERE) vs `-P`(PCRE) 지원 범위, lookaround 제약
- SRC-007 — Microsoft Learn, Select-String: .NET 정규식이 lookaround를 지원한다는 근거
