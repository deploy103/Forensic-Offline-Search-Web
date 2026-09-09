---
id: FOR-0130
title: "도메인·호스트명 regex: 라벨 규칙과 DNS 터널링 탐지 패턴"
slug: "domain-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["dns.log", "access.log", "proxy log", "Sysmon 22 DnsQuery", "hosts 파일", "memory strings"]
file_paths: ["C:\\Windows\\System32\\drivers\\etc\\hosts", "/etc/hosts", "/var/log/named/query.log"]
registry_paths: []
event_ids: []
protocols: ["DNS", "HTTP", "TLS"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "tshark", "awk"]
commands: ["grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}' dns.log", "grep -Poi '(?=.{4,253}(?![\\w.-]))(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}' dns.log", "tshark -r c.pcapng -T fields -e dns.qry.name -Y 'dns.flags.response==0'"]
regex_patterns: ["([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}", "(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+(?:xn--[A-Za-z0-9-]{2,59}|[A-Za-z]{2,63})\\.?", "(?<![\\w.-])(?=.{4,253}(?![\\w.-]))", "xn--[a-z0-9-]{2,59}", "[a-z0-9]{25,63}(\\.[a-z0-9-]{1,63})*\\.example\\.com", "_[a-z0-9-]+\\._(?:tcp|udp)\\."]
wireshark_filters: ["dns.qry.name contains \"example.com\"", "dns.qry.name.len > 40"]
tshark_fields: ["dns.qry.name", "dns.qry.name.len", "tls.handshake.extensions_server_name", "http.host"]
log_fields: ["dns.qry.name", "QueryName", "Host", "cs-host"]
file_formats: ["log", "txt", "csv", "pcapng"]
primary_terms: ["도메인 regex", "domain 정규식", "호스트명 정규식"]
keywords: ["도메인 regex", "domain 정규식", "호스트명 정규식", "hostname regex", "FQDN", "라벨", "label", "63자", "253자", "TLD", "punycode", "xn--", "IDN", "DNS 터널링", "DNS tunneling", "서브도메인"]
aliases: ["도메인 정규식", "도메인 추출", "fqdn 정규식", "호스트명 뽑기", "dns 도메인 grep", "서브도메인 추출", "punycode 정규식"]
symptom_keywords: ["도메인만 뽑고 싶다", "파일명이 도메인으로 잡힌다", "DNS 터널링을 찾고 싶다", "서브도메인이 비정상적으로 길다", "xn-- 로 시작하는 도메인이 뭔지 모르겠다", "도메인 목록에서 TLD만 세고 싶다"]
related: ["FOR-0131", "FOR-0128", "FOR-0146"]
source_ids: ["SRC-065", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

도메인 정규식은 "라벨(최대 63자) + 점 + TLD" 구조를 그대로 옮기면 되지만, 그렇게 만든 패턴은 `report.pdf`·`setup.exe`·`System.Net.Dns` 같은 파일명과 네임스페이스를 함께 잡는다. 느슨하게 뽑은 뒤 **TLD 목록 대조와 라벨 길이 검증**으로 확정해야 하고, DNS 터널링은 "비정상적으로 긴 라벨"로 따로 찾는다.

## 개념

도메인 이름은 **점으로 구분된 라벨(label)의 나열**이다. 규칙이 정규식으로 옮기기 쉬운 편이라, IPv6나 이메일보다 훨씬 짧게 쓸 수 있다.

| 규칙 | 값 | 정규식으로 옮기면 |
| --- | --- | --- |
| 라벨 길이 | 1–63옥텟 | `[A-Za-z0-9-]{1,63}` |
| 라벨 문자 | 영문자, 숫자, 하이픈 (LDH) | `[A-Za-z0-9-]` |
| 하이픈 위치 | 라벨 처음/끝에 올 수 없다 | `[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?` |
| 전체 길이 | 와이어 포맷 255옥텟 → 점 표기 최대 253자 | 선행 lookahead `(?=.{1,253}...)` |
| 대소문자 | 구분하지 않는다 | `(?i)` 또는 `-i` |
| 후행 점 | `example.com.` 은 루트까지 명시한 FQDN | 끝에 `\.?` |
| TLD | 순수 숫자 TLD는 없다 | `[A-Za-z]{2,63}` |
| 국제화 도메인 | A-label은 `xn--` 로 시작한다 | `xn--[A-Za-z0-9-]{2,59}` |

라벨 하나를 표현하는 조각이 이 글의 핵심이다.

```text
[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
 첫 글자      가운데(하이픈 허용, 최대 61)  마지막 글자
```

첫/마지막을 따로 떼어 놓으면 **하이픈으로 시작하거나 끝나는 라벨이 자동으로 배제**되고, 가운데를 `{0,61}`로 두면 합쳐서 최대 63자가 된다. 1글자 라벨(`a.example.com`)도 뒷부분이 `?`라서 매칭된다.

### 실무에서 규칙을 벗어나는 것들

| 형태 | 예 | 처리 |
| --- | --- | --- |
| 숫자로 시작하는 라벨 | `1e100.net`, `3com.com` | 실제로 널리 쓰인다. 첫 글자를 문자로 제한하면 놓친다 |
| 밑줄이 들어간 이름 | `_sip._tcp.example.com`, `sel._domainkey.example.com` | 호스트명 규칙에는 없지만 DNS 레코드 이름으로는 흔하다. SRV/DKIM 조회는 이 패턴으로 따로 잡는다 |
| 와일드카드 | `*.example.com` | 인증서 CN/SAN, 프록시 설정에 나온다 |
| 후행 점 | `example.com.` | DNS 쿼리 로그와 `tshark -e dns.qry.name` 출력에 자주 붙는다 |
| IDN | `한국.kr` → `xn--3e0b707e.kr` | 로그에는 A-label(`xn--`)로 찍히고, 화면에는 유니코드로 보인다 |

## 파일 / 경로

| 대상 | 경로/필드 | 도메인이 나오는 위치 |
| --- | --- | --- |
| BIND 쿼리 로그 | `/var/log/named/query.log` | `query: <도메인> IN A` |
| Windows DNS 클라이언트 로그 | `Microsoft-Windows-DNS-Client%4Operational.evtx` | `QueryName` |
| Sysmon DNS | `Microsoft-Windows-Sysmon%4Operational.evtx` 이벤트 22 | `QueryName`, `QueryResults` |
| pcap | `*.pcapng` | `dns.qry.name`, `tls.handshake.extensions_server_name`, `http.host` |
| 프록시/방화벽 로그 | 벤더별 | `cs-host`, `url`, `dstname` |
| hosts 파일 | `C:\Windows\System32\drivers\etc\hosts`, `/etc/hosts` | IP 뒤 호스트명들 |
| 브라우저 히스토리 | `History` (SQLite) | `urls.url` 안의 호스트 |
| 메모리 덤프 | `*.raw` | `strings` 결과 (C2 도메인이 남는다) |

## 주요 필드

### 패턴 1 — 느슨한 후보 수집

```text
([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}
```

`grep -E`에서도 그대로 돌아간다(비캡처 그룹·lookaround 없음). `-i`를 함께 준다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `example.com`, `www.example.co.kr`, `a.b.c.example.com`, `1e100.net`, `xn--3e0b707e.kr` |
| 매칭 안 됨 | `example` (점 없음), `-bad.example.com`의 `-`, `192.0.2.1` (TLD가 숫자) |
| **오탐** | `report.pdf`, `setup.exe`, `System.Net.Dns`, `payload.zip`, `libc.so`, `index.php` |

파일 확장자가 TLD처럼 생겼다는 것이 이 패턴의 최대 약점이다. `.pdf`, `.exe`, `.zip`, `.php`, `.so`, `.dll` 은 전부 `[a-z]{2,63}`을 만족한다.

### 패턴 2 — 경계와 전체 길이까지 (PCRE / .NET / Python)

```text
(?i)(?<![\w.-])(?=.{4,253}(?![\w.-]))(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})\.?(?![\w.-])
```

| 조각 | 역할 |
| --- | --- |
| `(?<![\w.-])` | 앞에 글자·숫자·점·하이픈이 붙어 있으면 거부 (잘린 매칭 방지) |
| `(?=.{4,253}(?![\w.-]))` | 이 위치에서 시작하는 이름 전체 길이를 4–253자로 제한 |
| `(?:xn--[a-z0-9-]{2,59}\|[a-z]{2,63})` | TLD는 문자만, 또는 punycode A-label |
| `\.?` | 후행 점 허용 |
| `(?![\w.-])` | 뒤에 더 이어지면 거부 |

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `example.com`, `example.com.`, `www.xn--3e0b707e.kr`, `mail.example.co.kr` |
| 매칭 안 됨 | `a.b` (3자), `x-.example.com`의 `x-` 라벨, 254자 이상 이름 |
| 남은 오탐 | `report.pdf`, `Update.exe` (구조상 완전히 합법적인 도메인과 구별할 수 없다) |

**구조만으로는 파일명 오탐을 없앨 수 없다.** 실제 TLD인지 대조하는 단계가 필요하다.

### 패턴 3 — 파일 확장자 오탐 제거

두 가지 방법이 있다.

```text
# (a) 흔한 확장자를 뒤에서 거부한다 (빠르지만 완전하지 않다)
(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?!(?:exe|dll|zip|pdf|png|jpg|jpeg|gif|txt|log|so|php|js|css|json|xml|csv|bak|tmp|dat|db|ini|md)(?![a-z]))[a-z]{2,63}

# (b) TLD 목록으로 화이트리스트 (정확하다)
(?i)\.(?:com|net|org|kr|co\.kr|io|ru|cn|top|xyz|info|biz|jp|de|uk)$
```

(b)가 원칙이다. 오프라인 환경에서는 IANA TLD 목록 파일을 준비해 두고 대조한다. 파일이 없으면 (a)로 시작하고, 남은 목록을 눈으로 훑는다.

| 항목 | 값 |
| --- | --- |
| (a) 매칭됨 | `example.com`, `evil.top` |
| (a) 매칭 안 됨 | `report.pdf`, `setup.exe`, `bundle.js` |
| (a) 오탐 | `notes.doc`, `archive.tar` (목록에 없는 확장자는 계속 통과한다) |

### 패턴 4 — DNS 터널링: 비정상적으로 긴 서브도메인

DNS 터널링은 데이터를 서브도메인 라벨에 실어 보낸다. 라벨이 63자를 넘을 수 없으므로 **63자에 가까운 라벨이 반복**되고, 같은 부모 도메인 아래 **유일한 서브도메인이 수천 개** 생긴다.

```text
# 25자 이상의 단일 라벨 + 고정 부모 도메인
(?i)\b[a-z0-9]{25,63}(?:\.[a-z0-9-]{1,63})*\.example\.com\b

# 부모를 모를 때: 40자 이상 라벨을 가진 이름 전체
(?i)(?<![\w.-])(?:[a-z0-9-]{1,63}\.)*[a-z0-9]{40,63}(?:\.[a-z0-9-]{1,63}){1,4}(?![\w.-])

# hex 로 인코딩된 라벨 (짝수 길이 hex 만으로 구성된 긴 라벨)
(?i)\b[0-9a-f]{32,63}\.[a-z0-9.-]+\b

# base32 로 인코딩된 라벨 (DNS 라벨은 대소문자 무시라 base32 를 많이 쓴다)
\b[a-z2-7]{32,63}\.[a-z0-9.-]+\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `mrxeys3ffqxgi2dbebbgc4tfebbgs4tf.tun.example.com` |
| 매칭 안 됨 | `www.example.com`, `cdn-static-assets.example.com` (라벨이 짧다) |
| 오탐 | CDN·클라우드의 정상 해시 서브도메인 (`d3a1b2c9e8f7g6h5.cloudfront.net`), 광고·추적 도메인 |

오탐이 있으므로 **길이만으로 단정하지 않는다.** 아래 세 가지를 함께 본다.

| 지표 | 정상 | 터널링 의심 |
| --- | --- | --- |
| 부모 도메인당 유일 서브도메인 수 | 수십 | 수백~수천 |
| 라벨 길이 분포 | 짧고 다양 | 최대치(63) 근처에 몰린다 |
| 질의 타입 | A, AAAA 위주 | TXT, NULL, CNAME 비중이 높다 |
| 응답 크기 | 작다 | TXT 응답이 계속 크다 |

### 패턴 5 — punycode / IDN

```text
xn--[a-z0-9-]{2,59}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `xn--3e0b707e` (`.kr` 한글), `xn--80ak6aa92e` |
| 매칭 안 됨 | `example`, `xn-abc` (하이픈 하나) |
| 오탐 | `xn--` 로 시작하는 임의의 문자열 (디코딩해 봐야 안다) |

`xn--` 라벨이 로그에 보이면 **반드시 디코딩해서 무엇으로 보이는지 확인한다.** 유사 문자(homograph)로 정상 브랜드를 흉내낸 피싱 도메인의 표준 수법이다.

## 빠른 명령

### grep / ripgrep

```bash
# 1) 후보 전부 (ERE. 비캡처 그룹·lookaround 를 쓰지 않는다)
grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}' dns.log | sort -u

# 2) 경계 + 전체 길이 제한 (PCRE 전용)
grep -Poi '(?<![\w.-])(?=.{4,253}(?![\w.-]))(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})\.?(?![\w.-])' dns.log

# 3) 파일 확장자 오탐 제거 후 빈도 (후행 점도 정규화)
grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}' dns.log |
  tr 'A-Z' 'a-z' | sed 's/\.$//' |
  grep -Ev '\.(exe|dll|zip|pdf|png|jpg|txt|log|so|php|js|css|json|xml|csv)$' |
  sort | uniq -c | sort -nr | head -20

# 4) eTLD+1 (등록 가능한 도메인)으로 묶어 세기 — 단순 2라벨 근사
grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}' dns.log |
  tr 'A-Z' 'a-z' | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -nr | head

# 5) DNS 터널링 후보 — 40자 이상 라벨
grep -Poi '(?<![\w.-])(?:[a-z0-9-]{1,63}\.)*[a-z0-9]{40,63}(?:\.[a-z0-9-]{1,63}){1,4}(?![\w.-])' dns.log

# 6) 부모 도메인별 유일 서브도메인 수 — 터널링의 진짜 지표
grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}' dns.log |
  tr 'A-Z' 'a-z' | sort -u | awk -F. '{print $(NF-1)"."$NF}' |
  sort | uniq -c | sort -nr | head

# 7) punycode 라벨만
grep -Eoi 'xn--[a-z0-9-]{2,59}(\.[a-z0-9-]{2,63})*' proxy.log | sort -u

# 8) SRV/DKIM 스타일 밑줄 이름
grep -Eo '_[a-z0-9-]+\._(tcp|udp)\.[a-z0-9.-]+' dns.log | sort -u

# 9) ripgrep
rg -oiP '(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])' dns.log

# 10) pcap 에서 바로 (정규식보다 필드가 정확하다)
tshark -r c.pcapng -T fields -e dns.qry.name -Y 'dns.flags.response==0' | sort | uniq -c | sort -nr | head
```

출력 예:

```text
$ grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}' dns.log | sort -u | wc -l
4118
$ ... | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -nr | head -3
   3901 example.com
     88 windowsupdate.com
     41 akamaiedge.net
```

`example.com` 아래 유일 서브도메인이 3,901개다. 정상 웹 트래픽에서는 나오지 않는 숫자다.

### PowerShell

```powershell
# 후보 수집 (.NET 정규식이므로 lookaround 사용 가능. 정규식은 항상 작은따옴표)
$re = '(?i)(?<![\w.-])(?=.{4,253}(?![\w.-]))(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})\.?(?![\w.-])'
$cand = Select-String -Path .\dns.log -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  ForEach-Object { $_.TrimEnd('.').ToLower() } | Sort-Object -Unique

# 정규식이 아니라 .NET 파서로 "호스트명인가"를 판정한다
$cand | ForEach-Object {
  [pscustomobject]@{ Name = $_; Kind = [System.Uri]::CheckHostName($_) }
} | Group-Object Kind | Select-Object Count, Name
# Dns / IPv4 / IPv6 / Basic / Unknown 으로 갈린다. Unknown 이면 호스트명이 아니다

# 라벨 길이 검증 — 63자 초과 라벨과 253자 초과 이름을 걸러낸다
$cand | Where-Object {
  $_.Length -le 253 -and -not ($_ -split '\.' | Where-Object { $_.Length -gt 63 -or $_.Length -eq 0 })
}

# 확장자 오탐 제거
$ext = 'exe','dll','zip','pdf','png','jpg','txt','log','so','php','js','css','json','xml','csv'
$dom = $cand | Where-Object { ($_ -split '\.')[-1] -notin $ext }

# punycode 되돌리기 — 피싱 도메인 확인
$idn = [System.Globalization.IdnMapping]::new()
$dom | Where-Object { $_ -like '*xn--*' } | ForEach-Object {
  [pscustomobject]@{ ALabel = $_; Unicode = $idn.GetUnicode($_) }
}

# 가장 긴 라벨 = DNS 터널링 후보
$dom | ForEach-Object {
  $max = ($_ -split '\.' | Measure-Object -Property Length -Maximum).Maximum
  [pscustomobject]@{ Name = $_; MaxLabel = $max }
} | Sort-Object MaxLabel -Descending | Select-Object -First 10
```

### Python

```python
import re, collections

DOMAIN = re.compile(r'''
    (?<![\w.-])
    (?=.{4,253}(?![\w.-]))                                  # 전체 길이 4-253
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+             # 라벨 + 점, 1회 이상
    (?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})                     # TLD 또는 punycode
    \.?                                                     # 후행 점
    (?![\w.-])
''', re.IGNORECASE | re.VERBOSE)

BAD_TLD = {'exe','dll','zip','pdf','png','jpg','jpeg','gif','txt','log','so',
           'php','js','css','json','xml','csv','bak','tmp','dat','db','ini','md'}

def valid_domain(name: str) -> bool:
    """정규식이 아니라 규칙을 코드로 검증한다. 이것이 최종 판정이다."""
    name = name.rstrip('.').lower()
    if not 1 <= len(name) <= 253:
        return False
    labels = name.split('.')
    if len(labels) < 2 or labels[-1] in BAD_TLD:
        return False
    for lab in labels:
        if not 1 <= len(lab) <= 63:
            return False
        if lab.startswith('-') or lab.endswith('-'):
            return False
        if not re.fullmatch(r'[a-z0-9-]+', lab):
            return False
    return bool(re.fullmatch(r'xn--[a-z0-9-]{2,59}|[a-z]{2,63}', labels[-1]))

text = open('dns.log', encoding='utf-8', errors='replace').read()
cand = {m.group().rstrip('.').lower() for m in DOMAIN.finditer(text)}
domains = sorted(d for d in cand if valid_domain(d))

# 1) eTLD+1 근사로 묶어 세기 (정확한 eTLD 는 공개 접미사 목록이 필요하다)
etld1 = collections.Counter('.'.join(d.split('.')[-2:]) for d in domains)
for parent, n in etld1.most_common(10):
    print(f'{n:6d}  {parent}')

# 2) DNS 터널링 지표 — 부모별 유일 서브도메인 수와 최대 라벨 길이
by_parent = collections.defaultdict(set)
for d in domains:
    by_parent['.'.join(d.split('.')[-2:])].add(d)

for parent, subs in sorted(by_parent.items(), key=lambda kv: -len(kv[1]))[:5]:
    maxlab = max(len(l) for s in subs for l in s.split('.'))
    print(f'{parent:30s} unique={len(subs):6d} max_label={maxlab}')

# 3) punycode 되돌리기 (표준 라이브러리 idna 코덱)
print('xn--3e0b707e'.encode('ascii').decode('idna'))     # 한국

# 4) 라벨 하나에 실린 데이터 복원 시도 (base32 / hex)
import base64, binascii
lab = 'mrxeys3ffqxgi2dbebbgc4tfebbgs4tf'
try:
    print(base64.b32decode(lab.upper() + '=' * (-len(lab) % 8)))
except binascii.Error:
    print('base32 아님')
```

**도메인은 정규식으로 "뽑고", 유효성은 코드로 "판정한다".** 라벨 63자·전체 253자·하이픈 위치·TLD 대조를 정규식 한 줄에 다 밀어 넣으면 읽을 수 없는 패턴이 되고, 그래도 "실제로 존재하는 TLD인가"는 여전히 검증할 수 없다.

## 함께 보는 artifact

| 도메인을 얻은 뒤 | 다음에 볼 것 |
| --- | --- |
| C2 도메인 후보 확정 | pcap `dns.qry.name contains "<도메인>"` → 응답 IP → 그 IP로 재검색 |
| 응답 IP 확보 | IPv4/IPv6 패턴으로 전 로그 재검색 ([FOR-0128](./ipv4-regex.html)) |
| 도메인 + 경로 | URL 전체 구조 파싱 (FOR-0131) |
| HTTPS 라 URL 이 안 보인다 | TLS SNI `tls.handshake.extensions_server_name` ([FOR-0146](./wireshark-30sec-triage.html)) |
| 브라우저에서 방문 여부 | `History` 의 `urls.url` ([FOR-0191](./chrome-history.html)) |
| hosts 파일 조작 의심 | `C:\Windows\System32\drivers\etc\hosts` 의 비표준 항목 |
| `xn--` 도메인 발견 | 디코딩 후 정상 브랜드와 시각 비교 (homograph 피싱) |

## 흔한 실수

- **`[a-z]+\.[a-z]+` 수준의 패턴으로 시작하는 것.** `report.pdf`, `setup.exe`, `bundle.js`, `System.Net.Dns`가 전부 도메인으로 잡힌다. 결과 목록 상위가 파일명으로 채워지면 이 실수다. TLD 대조가 필요하다.
- **라벨의 하이픈 위치를 검증하지 않는 것.** `[a-z0-9-]{1,63}`으로 두면 `-evil.example.com`, `evil-.example.com`이 통과한다. 첫/마지막 글자를 따로 떼어 `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`로 쓴다.
- **전체 길이 253자 제한을 빼는 것.** DNS 터널링 트래픽에는 253자를 넘는 조작된 이름이 섞인다. 길이 제한이 없으면 그 이름이 정상 도메인 목록에 섞여 들어간다. `(?=.{4,253}...)` lookahead로 잡는다 — 단 `grep -E`에서는 못 쓴다.
- **후행 점을 정규화하지 않는 것.** `tshark -e dns.qry.name`과 BIND 로그는 `example.com.`으로 찍는다. `example.com`과 별개 항목으로 세어져 빈도 순위가 쪼개진다. `sed 's/\.$//'` 또는 `TrimEnd('.')`로 먼저 정규화한다.
- **대소문자를 정규화하지 않는 것.** DNS는 대소문자를 구분하지 않지만 `uniq -c`는 구분한다. 일부 리졸버는 0x20 인코딩으로 질의 이름의 대소문자를 무작위로 섞어 보낸다 — 정규화하지 않으면 같은 도메인이 수십 줄로 흩어진다.
- **첫 글자를 문자로만 제한하는 것.** `1e100.net`, `3com.com`처럼 숫자로 시작하는 라벨이 실제로 쓰인다. `[A-Za-z]`가 아니라 `[A-Za-z0-9]`로 시작한다.
- **밑줄을 배제하는 것.** `_sip._tcp.example.com`, `sel._domainkey.example.com`은 정상 DNS 이름이다. 호스트명 규칙에 없다는 이유로 패턴에서 빼면 SRV·DKIM·ACME 조회 흔적을 통째로 놓친다.
- **라벨 길이만으로 DNS 터널링을 단정하는 것.** CDN과 클라우드 스토리지는 정상적으로 긴 해시 서브도메인을 쓴다. "부모 도메인당 유일 서브도메인 수", "TXT/NULL 질의 비율", "응답 크기"를 함께 봐야 결론이 선다.
- **`xn--` 도메인을 그냥 넘기는 것.** 디코딩하면 정상 브랜드로 보이는 피싱 도메인이다. `IdnMapping.GetUnicode()` 또는 파이썬 `idna` 코덱으로 반드시 되돌려 본다.
- **eTLD+1을 "마지막 두 라벨"로 계산하는 것.** `example.co.kr`은 마지막 두 라벨이 `co.kr`이 되어 전혀 다른 그룹으로 묶인다. `co.kr`, `com.au`, `github.io` 같은 다단 접미사는 공개 접미사 목록이 있어야 정확하다. 근사치임을 알고 쓴다.

## mini example

```text
문제:
"내부 DNS 서버 쿼리 로그에서 DNS 터널링에 사용된 도메인을 찾으세요."
첨부: query.log (612,004줄)

1. 첫 시도 (실패) — 느슨한 패턴으로 빈도 상위를 봤다
   $ grep -Eoi '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}' query.log |
       sort | uniq -c | sort -nr | head -5
     612004 named.log
     118204 in-addr.arpa
      88012 windowsupdate.com
      41003 akamaiedge.net
      12881 example.com

   -> 1위가 named.log 다. 로그 자체의 파일명이 매 줄에 찍혀 있었다.
      2위 in-addr.arpa 는 역방향 조회다. 둘 다 답이 아니다.
      "빈도 상위"는 터널링을 찾는 지표가 아니다. 터널링은 매 질의가 서로 다르다.

2. 두 번째 시도 (실패) — 질의 이름 필드만 잘라 다시 빈도를 봤다
   $ awk '/query:/ {for(i=1;i<=NF;i++) if($i=="query:") print $(i+1)}' query.log |
       sort | uniq -c | sort -nr | head -3
      88012 windowsupdate.com.
      41003 e1234.dscx.akamaiedge.net.
          1 mrxeys3ffqxgi2dbebbgc4tfebbgs4tf.tun.corp-cdn.net.

   -> 여전히 정상 도메인이 상위다. 터널링 도메인은 빈도 1 로 바닥에 깔린다.
      세는 축을 바꿔야 한다: "질의 수"가 아니라 "부모 도메인당 유일 서브도메인 수".

3. 축을 바꾼다 — 부모 도메인별 유일 서브도메인 개수
   $ awk '/query:/ {for(i=1;i<=NF;i++) if($i=="query:") print tolower($(i+1))}' query.log |
       sed 's/\.$//' | sort -u |
       awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -nr | head -5
      58911 corp-cdn.net
        412 akamaiedge.net
        118 windowsupdate.com
         44 example.com
         21 microsoft.com

   -> corp-cdn.net 아래 유일 서브도메인이 58,911개. 압도적이다.

4. 라벨 길이 분포 확인
   $ awk '/query:/ {for(i=1;i<=NF;i++) if($i=="query:") print $(i+1)}' query.log |
       grep -i 'corp-cdn\.net' | sed 's/\.$//' |
       awk -F. '{print length($1)}' | sort -n | uniq -c | tail -4
        112 60
       2904 61
      18442 62
      37401 63

   -> 첫 라벨 길이가 63(라벨 최대치)에 몰려 있다. 정상 도메인에서 나오지 않는 분포다.

5. 질의 타입 확인
   $ grep -io 'corp-cdn\.net[^ ]* IN [A-Z]*' query.log | awk '{print $NF}' |
       sort | uniq -c | sort -nr
      58120 TXT
        791 NULL
         12 A

   -> TXT/NULL 이 99%. 터널링 확정.

6. 라벨 내용 디코딩 (base32 시도)
   >>> import base64
   >>> lab = 'mrxeys3ffqxgi2dbebbgc4tfebbgs4tf'
   >>> base64.b32decode(lab.upper() + '=' * (-len(lab) % 8))
   b'd\xc7\x92\xcb\x94\xb0\xc3...'      # 첫 시도는 의미 없는 바이트

   -> 라벨 하나만으로는 안 된다. 같은 세션의 라벨을 시간순으로 이어붙여야 한다.
      시간순 정렬 후 첫 라벨들을 연결해 다시 디코딩하면 평문이 나온다.

정답: corp-cdn.net (유일 서브도메인 58,911개, 첫 라벨 63자 집중, TXT 질의 99%)
```

1·2단계가 이 글의 핵심이다. **DNS 터널링은 "가장 많이 질의된 도메인"이 아니라 "가장 많은 유일 서브도메인을 가진 부모 도메인"이다.** 세는 축을 잘못 잡으면 정상 트래픽만 계속 나온다.

## 출처

- SRC-065 — RFC 1035: 도메인 이름의 라벨 구조, 라벨 63옥텟 / 전체 255옥텟 제한, 대소문자 무시, preferred name syntax
- SRC-057 — Python 문서 `re`: `re.VERBOSE`, lookbehind/lookahead, `fullmatch`, `finditer`
- 국제화 도메인(punycode `xn--` 접두사, IDNA)과 공개 접미사(eTLD) 목록의 1차 규격은 `research/sources.json`에 등록되어 있지 않다. 이 글에서는 `xn--` 접두사의 형태와 `IdnMapping`/`idna` 코덱으로 되돌리는 방법만 다루고, 어떤 유니코드가 허용되는지는 단정하지 않는다
- 실제 TLD 존재 여부는 IANA TLD 목록 파일 대조가 필요하며, 오프라인 환경에서는 목록을 미리 내려 두어야 한다
- 밑줄이 들어간 이름(`_tcp`, `_domainkey`)은 호스트명 규칙이 아니라 서비스 레코드 이름 관례다. 어느 레코드 타입에서 어떤 접두사를 쓰는지는 실제 로그에서 확인할 것
