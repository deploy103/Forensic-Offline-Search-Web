---
id: FOR-0129
title: "IPv6 주소 regex: :: 압축과 IPv4 매핑까지 놓치지 않기"
slug: "ipv6-regex"
category: "로그/Regex"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["access.log", "auth.log", "Security.evtx IpAddress", "netstat 출력", "memory strings"]
file_paths: ["/var/log/auth.log", "/proc/net/if_inet6"]
registry_paths: []
event_ids: []
protocols: ["IPv6", "ICMPv6", "DHCPv6"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "tshark"]
commands: ["grep -Eoi '([0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}' access.log", "grep -Po '(?i)(?:[\\da-f]{1,4}:){7}[\\da-f]{1,4}|(?:[\\da-f]{1,4}(?::[\\da-f]{1,4})*)?::(?:[\\da-f]{1,4}(?::[\\da-f]{1,4})*)?' access.log", "python3 -c \"import ipaddress; print(ipaddress.ip_address('::ffff:192.0.2.1').ipv4_mapped)\""]
regex_patterns: ["([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}", "([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}", "(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7}|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)", "::[fF]{4}:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}", "(?:%[0-9A-Za-z._-]+)?", "\\[[0-9A-Fa-f:.]+\\](?::[0-9]{1,5})?"]
wireshark_filters: ["ipv6.addr == 2001:db8::1", "ipv6.src == fe80::/10"]
tshark_fields: ["ipv6.src", "ipv6.dst"]
log_fields: ["c-ip", "IpAddress"]
file_formats: ["log", "txt", "csv"]
primary_terms: ["IPv6 regex", "ipv6 정규식"]
keywords: ["IPv6 regex", "IPv6 정규식", "ipv6 추출", ":: 압축", "zero compression", "IPv4 매핑", "IPv4-mapped", "존 인덱스", "zone index", "scope id", "링크로컬", "fe80", "대괄호 표기"]
aliases: ["ipv6 정규식", "ipv6 주소 찾기", "grep ipv6", "아이피v6 추출", "fe80 찾기", "::1 정규식", "ipv6 뽑기"]
symptom_keywords: ["IPv6가 안 잡힌다", "IPv6 주소만 뽑고 싶다", "IP 정규식에 IPv6가 걸리지 않는다", "MAC 주소가 IPv6로 잡힌다", "시각이 IPv6로 잡힌다", "::ffff: 로 시작하는 주소가 뭔지 모르겠다"]
related: ["FOR-0128", "FOR-0133", "FOR-0131"]
source_ids: ["SRC-012", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

IPv6는 `::` 압축·선행 0 생략·IPv4 매핑·존 인덱스까지 표기 변형이 많아 "완전한" 정규식이 스무 줄을 넘는다. 그래서 느슨한 후보 패턴으로 긁고 `ipaddress.ip_address()` / `[System.Net.IPAddress]::TryParse`로 확정하는 것이 유일하게 실용적인 방법이다.

## 개념

IPv6 주소는 128비트를 16비트씩 8그룹으로 나눠 콜론으로 이은 것이다. 문제는 **같은 주소를 쓰는 방법이 여러 가지**라는 점이다.

| 표기 | 예 | 규칙 |
| --- | --- | --- |
| 완전 표기 | `2001:0db8:0000:0000:0000:ff00:0042:8329` | 4자리 hex 8그룹, 총 39자 |
| 선행 0 생략 | `2001:db8:0:0:0:ff00:42:8329` | 그룹 안의 앞쪽 0을 지운다 |
| `::` 압축 | `2001:db8::ff00:42:8329` | 연속된 0 그룹을 `::`로 한 번만 |
| 루프백 | `::1` | `0:0:0:0:0:0:0:1` |
| 미지정 | `::` | 전부 0 |
| IPv4 매핑 | `::ffff:192.0.2.1` | 하위 32비트를 dotted quad로 |
| 링크로컬 + 존 인덱스 | `fe80::1%eth0`, `fe80::1%12` | 인터페이스를 지정한다 |
| URL 대괄호 | `http://[2001:db8::1]:8443/a` | 포트의 콜론과 구분하기 위해 |
| 프리픽스 | `2001:db8::/32` | 대역 표기 |

**대소문자를 가리지 않는다.** `2001:DB8::1`과 `2001:db8::1`은 같은 주소다. 로그마다 대문자로 찍는 장비가 있으므로 정규식에는 항상 `A-Fa-f`를 넣거나 `-i` / `(?i)`를 붙인다.

정규식이 표현할 수 없는 제약이 세 가지 있다.

| 제약 | 왜 정규식으로 어려운가 |
| --- | --- |
| `::`는 **딱 한 번**만 | "한 번만"을 세는 것은 정규식의 일이 아니다 |
| 그룹 총합이 **8개 이하** | `::`가 몇 그룹을 대신하는지에 따라 달라진다 |
| IPv4 부분의 옥텟이 0–255 | IPv4와 같은 문제 ([FOR-0128](./ipv4-regex.html)) |

그래서 순서가 정해져 있다. **느슨하게 후보를 뽑고, 파서가 판정한다.**

## 파일 / 경로

| 대상 | 경로/필드 | IPv6가 나오는 형태 |
| --- | --- | --- |
| Linux 인증 로그 | `/var/log/auth.log`, `/var/log/secure` | `from 2001:db8::5 port 51234` |
| nginx/Apache | `access.log` 1번 필드 | `2001:db8::5 - - [14/Mar/...]` |
| IIS 로그 | `C:\inetpub\logs\LogFiles\W3SVC*\*.log` | `c-ip`, `s-ip` 필드 |
| Windows 보안 로그 | `Security.evtx` 4624/4625 | `IpAddress`에 `::1`, `fe80::...` |
| 현재 연결 | `netstat -an`, `Get-NetTCPConnection` | `[::1]:445` 형태 |
| 인터페이스 목록 | `/proc/net/if_inet6` | 콜론 없는 32자 hex |
| pcap | `*.pcapng` | `ipv6.src`, `ipv6.dst` |
| 메모리 덤프 | `*.raw`, `*.mem` | `strings` 결과 |

`/proc/net/if_inet6`은 **콜론 없이 32자 hex**로 찍는다. 콜론 기반 패턴으로는 하나도 안 잡히므로 이 파일은 별도로 다룬다.

## 주요 필드

### 패턴 1 — 완전 표기 8그룹 (엄격)

```text
([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `2001:0db8:0000:0000:0000:ff00:0042:8329`, `1:2:3:4:5:6:7:8` |
| 매칭 안 됨 | `::1`, `2001:db8::1`, `fe80::1%eth0` (압축형 전부) |
| 오탐 | EUI-64 표기 `00:1a:2b:ff:fe:3c:4d:5e` (2자리 8그룹) |

압축형을 하나도 못 잡으므로 **실전 로그에서는 거의 쓸 수 없다.** 압축을 쓰지 않는 장비 로그에만 유효하다.

### 패턴 2 — 느슨한 후보 수집 (초기 탐색용)

```text
([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `::1`, `2001:db8::1`, `fe80::1`, `1:2:3:4:5:6:7:8` |
| 매칭 안 됨 | `2001.db8.0.1`, 콜론이 하나뿐인 `[::1]:445`의 `:445` 부분 |
| 오탐 | 시각 `07:11:02`, MAC `00:1a:2b:3c:4d:5e`, `sha256:abc:def` |

**오탐이 심하다.** 특히 syslog 타임스탬프(`07:11:02`)와 MAC 주소가 그대로 걸린다. 그래도 초기 탐색에서는 이 패턴을 먼저 쓴다 — 놓치는 것이 없어야 하기 때문이다.

### 패턴 3 — 실전 패턴 (완전 표기 또는 `::` 포함)

```text
(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7}|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
```

두 갈래다. 왼쪽은 "콜론으로 이어진 그룹 정확히 8개", 오른쪽은 "**`::`를 반드시 포함**하고 그 앞뒤에 그룹이 0개 이상".

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `::`, `::1`, `fe80::1`, `2001:db8::ff00:42:8329`, `2001:db8::`, `1:2:3:4:5:6:7:8` |
| 매칭 안 됨 | `07:11:02`, `00:1a:2b:3c:4d:5e` (`::`도 없고 8그룹도 아니다) |
| 오탐 | `2001::db8::1`에서 앞부분 `2001::db8`만 잘려 매칭, 그룹이 9개 이상인 문자열의 일부 |

`::`를 요구하는 것만으로 시각·MAC 오탐이 사라진다. **이것이 로그 분석의 기본 패턴이다.**

### 패턴 4 — IPv4 매핑 / 혼합 표기

```text
::[fF]{4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}
```

더 넓게 잡으려면 앞쪽 그룹을 허용한다.

```text
(?:[0-9A-Fa-f]{1,4}:){1,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `::ffff:192.0.2.1`, `::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`(뒤 패턴) |
| 매칭 안 됨 | `192.0.2.1` (순수 IPv4) |
| 오탐 | 버전 문자열이 콜론 뒤에 온 `build:1.2.3.4` |

**`::ffff:192.0.2.1`은 실제로는 IPv4 주소다.** Windows 이벤트 로그와 듀얼스택 서버 로그에서 흔히 나온다. IPv4 패턴만 돌리면 `192.0.2.1`은 잡히지만 앞의 `::ffff:`를 놓쳐 "IPv6 접속"이라는 사실을 잃는다. 반대로 IPv6 패턴만 돌리면 IPv4 부분이 잘린다. **두 패턴을 함께 돌린다.**

### 패턴 5 — 존 인덱스, 대괄호, 프리픽스 붙이기

| 붙일 것 | 패턴 조각 | 예 |
| --- | --- | --- |
| 존 인덱스 | `(?:%[0-9A-Za-z._-]+)?` | `fe80::1%eth0`, `fe80::1%12` |
| 프리픽스 | `(?:/\d{1,3})?` | `2001:db8::/32` |
| URL 대괄호 | `\[[0-9A-Fa-f:.]+\](?::[0-9]{1,5})?` | `[2001:db8::1]:8443` |

대괄호 표기를 잡을 때는 **주소 본체와 포트를 따로 캡처**한다. 그러지 않으면 `[2001:db8::1]:8443`의 `:8443`이 주소의 마지막 그룹으로 흡수된다.

### 경계 처리

앞뒤로 hex나 콜론이 붙는 것을 막아야 잘린 매칭이 사라진다.

```text
(?<![0-9A-Fa-f:])   ... 패턴 ...   (?![0-9A-Fa-f:])
```

`\b`는 여기서 쓸모가 없다. 콜론은 단어 문자가 아니라서 `\b`가 콜론 앞뒤에 항상 성립하기 때문이다. **lookbehind/lookahead가 필요하고, 그러면 `grep -E`로는 안 된다.**

## 빠른 명령

### grep / ripgrep

`grep -E`는 POSIX ERE라서 `(?:...)`, `\d`, lookaround가 **없다.** 아래 `-E` 예시는 모두 일반 그룹 `(...)`과 `[0-9]`만 쓴다.

```bash
# 1) 느슨한 후보 전부 (대소문자 무시)
grep -Eoi '([0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}' access.log

# 2) :: 를 포함한 것만 = 시각/MAC 오탐 제거 (ERE로도 된다)
grep -Eoi '(([0-9a-f]{1,4}:)*:)(([0-9a-f]{1,4}:)*[0-9a-f]{1,4})?' access.log | grep '::'

# 3) 실전 패턴 (PCRE. 8그룹 또는 :: 포함)
grep -Po '(?i)(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?::(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?' access.log

# 4) 경계까지 붙인 최종형 (PCRE 전용)
grep -Po '(?i)(?<![\da-f:])(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?::(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?)(?:%[\w.-]+)?(?![\da-f:])' access.log

# 5) IPv4 매핑만
grep -Eoi '::ffff:[0-9]{1,3}(\.[0-9]{1,3}){3}' Security.csv

# 6) 링크로컬(fe80::/10)만 — 같은 세그먼트 장비
grep -Eoi 'fe80:[0-9a-f:]*(%[a-z0-9]+)?' auth.log

# 7) 빈도 상위 (소문자로 정규화해서 세는 것이 핵심)
grep -Poi '(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?::(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?' access.log |
  tr 'A-Z' 'a-z' | sort | uniq -c | sort -nr | head -10

# 8) ripgrep — -P 로 PCRE2 활성화
rg -oiP '(?<![\da-f:])(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?::(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?(?![\da-f:])' access.log
```

출력 예:

```text
$ grep -Eoi '::ffff:[0-9]{1,3}(\.[0-9]{1,3}){3}' Security.csv | sort | uniq -c
     41 ::ffff:10.10.20.5
      7 ::ffff:203.0.113.77
```

### PowerShell

정규식은 **항상 작은따옴표**로 감싼다. 큰따옴표 안에서는 `$`가 변수로 확장된다.

```powershell
# 후보 수집 (.NET 정규식이므로 lookaround 그대로 동작)
$re = '(?i)(?<![\da-f:])(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?::(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?)(?![\da-f:])'
$cand = Select-String -Path .\access.log -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# 파서로 확정 — 이것이 정답이다
$cand | ForEach-Object {
  $ip = [System.Net.IPAddress]::Loopback
  [pscustomobject]@{
    Value  = $_
    Valid  = [System.Net.IPAddress]::TryParse($_, [ref]$ip)
    Family = if ([System.Net.IPAddress]::TryParse($_, [ref]$ip)) { $ip.AddressFamily } else { $null }
  }
} | Format-Table -AutoSize

# IPv4 매핑 되돌리기
$ip = [System.Net.IPAddress]::Parse('::ffff:192.0.2.1')
$ip.AddressFamily            # InterNetworkV6
$ip.MapToIPv4().ToString()   # 192.0.2.1

# 표기가 달라도 같은 주소인지 비교 — 문자열 비교는 틀린다
[System.Net.IPAddress]::Parse('2001:DB8:0:0:0:0:0:1').Equals(
  [System.Net.IPAddress]::Parse('2001:db8::1'))   # True
```

### Python

```python
import re, ipaddress
from collections import Counter

# 8그룹 또는 :: 포함. 앞뒤 경계까지
IPV6 = re.compile(r'''
    (?<![0-9A-Fa-f:])
    (?:
        [0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7}                    # 완전 표기
      | (?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?
        ::
        (?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?                 # :: 압축
    )
    (?:%[0-9A-Za-z._-]+)?                                            # 존 인덱스
    (?![0-9A-Fa-f:])
''', re.VERBOSE)

MAPPED = re.compile(r'(?:[0-9A-Fa-f]{1,4}:){1,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3}')

text = open('access.log', encoding='utf-8', errors='replace').read()

good, bad = [], []
for cand in set(IPV6.findall(text)) | set(MAPPED.findall(text)):
    base = cand.split('%')[0]        # 존 인덱스는 잘라서 넘기는 것이 안전하다
    try:
        good.append(ipaddress.ip_address(base))
    except ValueError:
        bad.append(cand)             # 2001::db8::1, 그룹 9개 등이 여기로 떨어진다

# 분류
mapped   = [i for i in good if getattr(i, 'ipv4_mapped', None)]        # ::ffff:192.0.2.1
linklocal = [i for i in good if i.is_link_local]                       # fe80::/10
globals_  = [i for i in good if i.is_global]                           # 외부 주소

print(ipaddress.ip_address('::ffff:192.0.2.1').ipv4_mapped)   # 192.0.2.1
print(ipaddress.ip_address('2001:DB8:0:0:0:0:0:1').compressed) # 2001:db8::1

# 표기 정규화 후 세야 같은 주소가 합쳐진다
for ip, n in Counter(i.compressed for i in good).most_common(10):
    print(f'{n:6d}  {ip}')

# 특정 대역
net = ipaddress.ip_network('2001:db8::/32')
inside = [i for i in good if i.version == 6 and i in net]
```

**정규식으로 유효성을 판정하려 하지 말고, 느슨하게 뽑아 `ipaddress.ip_address()` / `IPAddress.TryParse`에 넘긴다.** `::`가 두 번 나온 문자열, 그룹이 9개인 문자열, 옥텟이 300인 IPv4 매핑은 전부 여기서 걸러진다.

## 함께 보는 artifact

| IPv6를 얻은 뒤 | 다음에 볼 것 |
| --- | --- |
| 전역 주소 확정 | pcap `ipv6.addr == <주소>` → Follow TCP Stream |
| `fe80::` 링크로컬 | 하위 64비트가 MAC 기반(EUI-64)인지 확인 (FOR-0133) |
| `::ffff:` 매핑 | 실제 IPv4로 되돌려 IPv4 로그 재검색 ([FOR-0128](./ipv4-regex.html)) |
| 존 인덱스 `%12` | 그 호스트의 인터페이스 목록(`/proc/net/if_inet6`, `Get-NetIPAddress`) |
| `[주소]:포트` | URL 전체를 다시 파싱 (FOR-0131) |
| 결과를 Windows 에서 집계 | `Select-String -AllMatches` 사용법 ([FOR-0121](./powershell-select-string.html)) |
| Windows 4624 `IpAddress`가 `::1` | 로컬 로그온이다. 원격 접속으로 착각하지 않는다 |

## 흔한 실수

- **IPv4 패턴만 돌리는 것.** 듀얼스택 서버 로그의 절반이 IPv6인 경우가 흔하다. IPv4 정규식은 `2001:db8::1`을 하나도 못 잡고, `::ffff:192.0.2.1`에서는 뒤쪽만 잡아 앞의 `::ffff:`를 버린다. 두 패턴을 함께 돌린다.
- **`([0-9a-f]{1,4}:){2,7}...`를 그대로 쓰는 것.** syslog 타임스탬프 `07:11:02`와 MAC `00:1a:2b:3c:4d:5e`가 전부 IPv6로 잡힌다. `::`를 필수로 요구하거나 8그룹을 요구해서 걸러낸다.
- **`\b`로 경계를 잡으려는 것.** 콜론은 단어 문자가 아니므로 `\b`가 콜론 양쪽에서 항상 성립한다. 경계는 `(?<![0-9A-Fa-f:])` / `(?![0-9A-Fa-f:])`로 잡아야 하고, 이는 `grep -P`·PowerShell·Python 전용이다.
- **소문자만 쓰는 것.** `2001:DB8::1`로 찍는 장비가 있다. `-i` 또는 `(?i)`, 아니면 문자 클래스에 `A-F`를 넣는다.
- **표기를 정규화하지 않고 빈도를 세는 것.** `2001:db8:0:0:0:0:0:1`과 `2001:DB8::1`은 같은 주소인데 `uniq -c`가 둘로 센다. `ipaddress.ip_address(x).compressed`로 정규화한 뒤 센다.
- **대괄호 표기에서 포트를 주소에 흡수시키는 것.** `[2001:db8::1]:8443`을 통째로 넘기면 파서가 거부하거나 `8443`을 마지막 그룹으로 읽는다. 대괄호 안쪽만 잘라 넘긴다.
- **존 인덱스를 그대로 파서에 넘기는 것.** `fe80::1%eth0`은 라이브러리·버전에 따라 거부된다. `%` 앞까지만 잘라 검증하고, 인덱스는 별도 필드로 보관한다.
- **`::`가 두 번인 문자열을 정규식이 걸러줄 것으로 기대하는 것.** 패턴 3은 `2001::db8::1`에서 앞부분만 잘라 매칭한다. "정규식이 매칭했다"는 "유효한 주소다"가 아니다. 판정은 파서가 한다.
- **`/proc/net/if_inet6`을 콜론 패턴으로 뒤지는 것.** 이 파일은 콜론 없는 32자 hex로 찍는다. 별도 패턴 `^[0-9a-f]{32}`가 필요하다.
- **`::1`을 원격 접속으로 읽는 것.** IPv6 루프백이다. Windows 4624의 `IpAddress`가 `::1`이면 그 호스트에서 일어난 로컬 로그온이다.

## mini example

```text
문제:
"듀얼스택 웹서버의 access.log 에서 관리 페이지(/admin)에 가장 많이 접근한
 원격 주소를 구하세요. IPv4/IPv6 모두 고려하세요."
첨부: access.log (204,118줄)

1. 첫 시도 (실패) — IPv4 패턴만 돌렸다
   $ grep '/admin' access.log | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' |
       sort | uniq -c | sort -nr | head -3
        612 10.10.20.5
        188 203.0.113.77
         12 192.0.2.44

   -> 10.10.20.5 를 답으로 제출했으나 오답.
      로그를 직접 보니 IPv6 줄이 절반이었다.

   $ grep '/admin' access.log | grep -c ':'
   1904          # 전체 /admin 요청 2,516줄 중 1,904줄에 콜론이 있다

2. 두 번째 시도 (또 실패) — 느슨한 IPv6 패턴을 그냥 붙였다
   $ grep '/admin' access.log | grep -Eoi '([0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}' |
       sort | uniq -c | sort -nr | head -3
       2516 14:22:01
        907 2001:db8:aa:
        612 :

   -> 1위가 시각 필드다. 타임스탬프 14:22:01 이 IPv6 로 잡혔고,
      주소도 뒤가 잘려 2001:db8:aa: 로 끊겼다. 패턴이 너무 느슨하다.

3. :: 를 요구하고 경계를 붙인다 (PCRE)
   $ RE='(?i)(?<![\da-f:])(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?::(?:[\da-f]{1,4}(?::[\da-f]{1,4})*)?)(?![\da-f:])'
   $ grep '/admin' access.log | grep -Po "$RE" | tr 'A-Z' 'a-z' |
       sort | uniq -c | sort -nr | head -5
        901 2001:db8:aa::1f
        488 2001:db8:aa::1F
        301 ::1
        188 2001:db8:99::7
         25 fe80::20c:29ff:fe4b:1a2c

   -> 대소문자 표기가 갈려 1위가 두 줄로 쪼개져 있다.

4. 표기를 정규화해서 다시 센다
   >>> import re, ipaddress, collections
   >>> RE = re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7}'
   ...                 r'|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::'
   ...                 r'(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)(?![0-9A-Fa-f:])')
   >>> c = collections.Counter()
   >>> for line in open('access.log'):
   ...     if '/admin' not in line: continue
   ...     m = RE.search(line)
   ...     if not m: continue
   ...     try: ip = ipaddress.ip_address(m.group())
   ...     except ValueError: continue
   ...     c[ip.compressed] += 1
   >>> c.most_common(4)
   [('2001:db8:aa::1f', 1389), ('::1', 301), ('2001:db8:99::7', 188),
    ('fe80::20c:29ff:fe4b:1a2c', 25)]

5. ::1 은 루프백이므로 "원격"이 아니다. 제외한다.
   >>> [k for k in c if ipaddress.ip_address(k).is_loopback]
   ['::1']

6. 교차검증 — 필드 위치로 (nginx 기본 포맷은 1번 필드가 원격 주소)
   $ awk '$0 ~ "/admin" {print $1}' access.log | tr 'A-Z' 'a-z' |
       sort | uniq -c | sort -nr | head -2
       1389 2001:db8:aa::1f
        612 10.10.20.5
   정규식 결과와 일치.

정답: 2001:db8:aa::1f (1,389회)
```

2단계가 이 글의 핵심이다. **IPv6 후보 패턴은 반드시 `::` 요구 또는 8그룹 요구로 조여야 하고, 세기 전에 `compressed`로 표기를 정규화해야 한다.**

## 출처

- SRC-012 — RFC 791: IPv4 옥텟 구조. `::ffff:192.0.2.1` 매핑 표기의 dotted quad 부분 근거
- SRC-057 — Python 문서 `re`: `re.VERBOSE`, lookbehind/lookahead 지원 범위와 `findall` 동작
- IPv6 주소 구조(8그룹 128비트), `::` 1회 제약, IPv4 매핑 프리픽스, 텍스트 표기 권고, URI 대괄호 표기의 1차 규격은 `research/sources.json`에 아직 등록되어 있지 않다. 이 글의 표기 규칙은 실제 로그/도구 출력에서 관측되는 형태를 기준으로 서술했고, 최종 판정은 정규식이 아니라 `ipaddress` / `System.Net.IPAddress` 파서에 맡긴다
- `MapToIPv4()`, `IsIPv4MappedToIPv6` 등 .NET 멤버와 `ipaddress`의 `scope_id` 지원은 런타임 버전에 따라 다를 수 있으므로 실제 환경에서 확인할 것
