---
id: FOR-0133
title: "MAC 주소 정규식: 콜론/하이픈/Cisco 표기와 인증서 지문 오탐"
slug: "mac-address-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["arp log", "dhcp log", "syslog", "pcap", "ipconfig output", "known_hosts"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["Ethernet", "ARP", "DHCP"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "tshark"]
commands: ["grep -Eio '[0-9a-f]{2}(:[0-9a-f]{2}){5}' arp.log | sort -u", "rg -oi '\\b[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\\1){4}[0-9a-f]{2}\\b'", "Select-String -Pattern '([0-9A-F]{2}[:-]){5}[0-9A-F]{2}' -AllMatches"]
regex_patterns: ["[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", "[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}", "\\b(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\\1){4}[0-9A-Fa-f]{2}\\b", "[0-9A-Fa-f]{4}(\\.[0-9A-Fa-f]{4}){2}", "(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:.-])", "\\b[0-9A-Fa-f]{12}\\b"]
wireshark_filters: ["eth.addr == aa:bb:cc:dd:ee:ff", "arp.src.hw_mac == aa:bb:cc:dd:ee:ff", "wlan.sa == aa:bb:cc:dd:ee:ff"]
tshark_fields: ["eth.src", "eth.dst", "arp.src.hw_mac", "arp.dst.hw_mac", "wlan.sa", "wlan.da"]
log_fields: ["chaddr", "Physical Address", "HWaddr", "Station MAC"]
file_formats: ["log", "txt", "pcap", "pcapng", "csv"]
primary_terms: ["mac address regex", "mac 주소 정규식"]
keywords: ["MAC address regex", "MAC 주소 정규식", "이더넷 MAC", "OUI", "콜론 표기", "하이픈 표기", "Cisco dot notation", "chaddr", "ipconfig physical address", "arp -a", "SSH fingerprint 오탐", "인증서 지문 오탐"]
aliases: ["mac 정규식", "mac 주소 추출", "이더넷 주소 정규식", "mac 뽑기", "grep mac", "물리 주소 정규식", "네트워크 카드 주소 찾기"]
symptom_keywords: ["MAC 주소만 뽑고 싶다", "SSH fingerprint가 MAC으로 잡힌다", "하이픈과 콜론 표기가 섞여 있다", "IPv6 주소가 MAC처럼 보인다", "Cisco 장비 로그의 MAC 표기가 다르다"]
related: ["FOR-0128", "FOR-0129", "FOR-0171", "FOR-0172"]
source_ids: ["SRC-077", "SRC-068", "SRC-015", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

MAC 주소는 표기가 3가지(콜론 `aa:bb:cc:dd:ee:ff`, 하이픈 `AA-BB-CC-DD-EE-FF`, Cisco dot `aabb.ccdd.eeff`)로 갈리므로 로그 종류부터 확인하고 맞는 패턴을 쓰며, 콜론 표기 정규식은 **TLS/SSH 지문(fingerprint)** 문자열 안에서 오탐이 잦다는 것을 항상 의심한다.

## 개념

MAC(Media Access Control) 주소는 48비트(6바이트) 값이다. 표기 방식이 플랫폼마다 다르다.

| 표기 | 형태 | 대표 사용처 |
| --- | --- | --- |
| 콜론(colon) | `aa:bb:cc:dd:ee:ff` | Linux `ifconfig`/`ip link`, Wireshark, macOS |
| 하이픈(hyphen) | `AA-BB-CC-DD-EE-FF` | Windows `ipconfig /all`, `getmac` |
| Cisco dot | `aabb.ccdd.eeff` | Cisco IOS `show mac address-table`, 네트워크 장비 로그 |
| 구분자 없음 | `aabbccddeeff` | 일부 API 응답, 바이너리를 hex로 덤프한 결과 |

앞 3바이트는 **OUI**(Organizationally Unique Identifier)로 제조사를 가리킨다. `00:0C:29`는 VMware, `08:00:27`은 VirtualBox처럼 가상 환경 판별에 쓰인다. OUI 목록 자체는 IEEE가 관리하며 정규식으로는 검증하지 않는다 — 정규식은 "형태가 MAC처럼 생겼는가"만 판정하고, 진짜 할당된 주소인지는 OUI 데이터베이스 대조가 필요하다.

## 파일 / 경로

이 정규식이 실제로 쓰이는 로그와 출력이다.

| 대상 | 경로/명령 | MAC이 나오는 위치 |
| --- | --- | --- |
| Linux ARP 캐시 | `/proc/net/arp`, `arp -a` | `HWaddress` 컬럼 (콜론) |
| DHCP 서버 로그 | `/var/log/syslog` (isc-dhcp-server), `dhcpd.leases` | `DHCPACK ... to <IP> (<MAC>)`, lease 파일의 `hardware ethernet` |
| Windows `ipconfig /all` | 명령 출력 텍스트 | `Physical Address` (하이픈) |
| Windows `getmac` | 명령 출력 텍스트 | 표 형태 (하이픈) |
| pcap | `*.pcapng` | `eth.src`/`eth.dst`, ARP 패킷의 `arp.src.hw_mac` |
| 스위치/라우터 로그 | 벤더별 syslog | Cisco는 dot 표기가 섞여 나온다 |
| Wi-Fi AP 로그 | RADIUS, hostapd 로그 | `Station MAC`, `Calling-Station-Id` |
| SSH/TLS 지문 (오탐 원천) | `known_hosts`, `openssl x509 -fingerprint` | 콜론 구분 hex 바이트 나열 — **MAC이 아니다** |

## 주요 필드

이 글의 "필드"는 정규식의 캡처 그룹 구조다.

### 패턴 1 — 콜론 표기 (가장 흔하다)

```text
[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}
```

| 그룹 | 역할 |
| --- | --- |
| `[0-9A-Fa-f]{2}` (첫 부분) | 옥텟 1개 (1바이트, hex 2자리) |
| `(:[0-9A-Fa-f]{2}){5}` | `:옥텟`을 5번 반복 — 총 6옥텟 완성 |

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `aa:bb:cc:dd:ee:ff`, `00:1A:2B:3C:4D:5E`, `08:00:27:12:34:56` |
| 매칭 안 됨 | `aa:bb:cc:dd:ee` (5옥텟), `aa:bb:cc:dd:ee:ff:00` (7옥텟은 앞 6개만 잡힘) |
| **오탐** | SSH/TLS fingerprint의 연속된 6바이트, IPv6 주소 내부 우연 일치(드묾) |

### 패턴 2 — 하이픈 표기 (Windows)

```text
[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `00-1A-2B-3C-4D-5E` |
| 매칭 안 됨 | `00_1A_2B_3C_4D_5E` (언더스코어는 다른 구분자) |
| 오탐 | GUID/버전 문자열에서 우연히 하이픈-2자리hex가 6번 이어지는 경우 (극히 드묾) |

### 패턴 3 — 구분자를 하나로 고정 (역참조)

```text
\b(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b
```

| 그룹 | 역할 |
| --- | --- |
| `([:-])` | 첫 구분자를 캡처 그룹 1로 고정 |
| `\1` | 이후 모든 구분자가 **첫 구분자와 같아야** 매칭 |

콜론과 하이픈이 한 문서에 섞여 나올 때, `aa:bb-cc:dd-ee:ff`처럼 **구분자가 섞인 가짜 MAC**을 걸러낸다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF` |
| 매칭 안 됨 | `aa:bb-cc:dd-ee:ff` (구분자 혼용) |

### 패턴 4 — Cisco dot notation

```text
[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `001a.2b3c.4d5e` |
| 매칭 안 됨 | `001a.2b3c.4d5` (마지막 그룹이 3자리) |
| 오탐 | 버전 문자열 `1.2345.6789.abcd` 형태(드묾), 소수점 IP 아님 — 점 개수와 길이가 다름 |

Cisco 로그를 다룰 때는 콜론/하이픈 패턴만 쓰면 **전부 놓친다.** 장비 벤더를 먼저 확인한다.

### 패턴 5 — 경계 강화 (오탐 억제, PCRE/.NET/Python)

```text
(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:.-])
```

앞뒤에 hex/구분자가 더 붙어 있으면 거부한다. **20바이트짜리 SHA1 지문에서 우연히 6바이트만 잘라 매칭하는 사고를 줄인다** — 하지만 완전히 막지는 못한다. 지문 문자열도 정확히 `hex:hex:hex...`이므로 지문 중간의 임의 6바이트 구간은 여전히 이 패턴과 **구조적으로 동일**하다. 형태만으로는 구별 불가능하고, 길이(지문은 16~20바이트, MAC은 6바이트)로 구별해야 한다.

### 패턴 6 — 구분자 없는 12자리 (위험, 최후 수단)

```text
\b[0-9A-Fa-f]{12}\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `001a2b3c4d5e` |
| 오탐 | **매우 많다.** MD5 앞 12자리, GUID 조각, 세션 ID, 타임스탬프+시퀀스 조합 전부 걸린다 |

**구분자 없는 MAC은 문맥(주변 키워드 `mac=`, `chaddr`, `hwaddr`)과 함께 확인하지 않으면 쓰지 않는다.**

## 빠른 명령

### grep / ripgrep

```bash
# 1) 콜론 표기 후보 전부, 값만 출력
grep -Eio '[0-9a-f]{2}(:[0-9a-f]{2}){5}' arp.log | sort -u

# 2) 하이픈 표기 (ipconfig /all 텍스트 출력을 저장한 경우)
grep -Eio '[0-9a-f]{2}(-[0-9a-f]{2}){5}' ipconfig_all.txt

# 3) 구분자 고정(콜론/하이픈 혼용 걸러내기) - PCRE 역참조
grep -Pio '\b[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\b' mixed.log

# 4) Cisco dot 표기
grep -Eio '[0-9a-f]{4}(\.[0-9a-f]{4}){2}' switch.log

# 5) DHCP 로그에서 IP-MAC 쌍으로
grep -Eo 'DHCPACK on [0-9.]+ to ([0-9a-f]{2}:){5}[0-9a-f]{2}' -i /var/log/syslog

# 6) OUI(제조사 코드)만 빈도 집계 - VMware/VirtualBox 등 가상 환경 식별
grep -Eio '[0-9a-f]{2}(:[0-9a-f]{2}){5}' arp.log |
  awk -F: '{print $1":"$2":"$3}' | sort | uniq -c | sort -nr

# 7) ripgrep - PCRE2로 지문 오탐 억제 (앞뒤 hex 없음 강제)
rg -oiP '(?<![0-9a-f:.-])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f:.-])' capture.txt
```

### PowerShell

```powershell
# 정규식은 항상 작은따옴표
$re = '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'
Select-String -Path .\ipconfig_all.txt -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# ipconfig 출력에서 인터페이스 이름과 함께 뽑기
Get-Content .\ipconfig_all.txt | Select-String -Pattern 'Physical Address[.\s]*: ([0-9A-F-]+)' |
  ForEach-Object { $_.Matches[0].Groups[1].Value }

# 구분자 고정 (역참조는 .NET 그대로 지원)
$re2 = '[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}'
Select-String -Path .\mixed.log -Pattern $re2 -AllMatches |
  ForEach-Object { $_.Matches.Value }

# OUI 빈도 집계
Select-String -Path .\arp.log -Pattern $re -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  ForEach-Object { ($_ -split '[:-]')[0..2] -join ':' } |
  Group-Object | Sort-Object Count -Descending
```

### Python

```python
import re
from collections import Counter

COLON  = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
HYPHEN = re.compile(r'(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}')
FIXED  = re.compile(r'\b([0-9A-Fa-f]{2})([:-])(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}\b')
CISCO  = re.compile(r'[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}')

text = open('arp.log', encoding='utf-8', errors='replace').read()

macs = set(m.group() for m in FIXED.finditer(text))

# OUI(앞 3바이트)로 제조사 추정 목록과 대조 - 정규식이 아니라 룩업이 한다
KNOWN_OUI = {
    '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',
    '00:50:56': 'VMware',
    '00:1c:42': 'Parallels',
}
for mac in sorted(macs):
    oui = ':'.join(mac.lower().split(mac[2])[0:3]) if False else mac.lower()[:8]
    vendor = KNOWN_OUI.get(oui, '알 수 없음')
    print(f'{mac:20s} OUI={oui} vendor={vendor}')

# SSH/TLS 지문 오탐 배제 - 길이로 판정한다 (형태로는 구별 불가)
FINGERPRINT_LIKE = re.compile(r'(?:[0-9A-Fa-f]{2}:){15,19}[0-9A-Fa-f]{2}')
def looks_like_fingerprint(line: str) -> bool:
    return bool(FINGERPRINT_LIKE.search(line))

for line in text.splitlines():
    for m in FIXED.finditer(line):
        if looks_like_fingerprint(line):
            continue  # 같은 줄에 16~20바이트 지문이 있으면 그 조각일 가능성이 높다
        print(m.group())
```

## 함께 보는 artifact

| MAC을 얻은 뒤 | 다음 목표 |
| --- | --- |
| 공격자 내부 IP의 MAC 확정 | ARP 스푸핑 여부 확인 ([FOR-0171](./arp-analysis.html)) |
| DHCP 로그의 MAC-IP 쌍 | 시간대별 IP 재할당 추적 ([FOR-0172](./dhcp-analysis.html)) |
| pcap에서 뽑은 MAC | `eth.addr ==` 필터로 그 장치의 전체 트래픽 |
| OUI로 가상 환경 판정 | VM 여부가 사건 성격(내부망/실습 환경)을 가른다 |
| IPv4와 함께 쌍으로 | [FOR-0128](./ipv4-regex.html)의 IP 정규식과 같은 줄에서 동시 추출 |
| IPv6 링크로컬 주소 | EUI-64로 MAC이 임베드된 경우 대조 ([FOR-0129](./ipv6-regex.html)) |

## 흔한 실수

- **SSH/TLS 지문을 MAC으로 착각하는 것.** `known_hosts`의 `-E md5` 출력이나 인증서 지문은 콜론 구분 hex 바이트 나열이라 구조가 MAC과 동일하다. 바이트 개수(지문은 16~20바이트, MAC은 6바이트)로만 구별된다.
- **표기 방식을 하나만 준비하는 것.** Windows 로그(하이픈)와 Linux/pcap(콜론), Cisco(dot)를 같은 정규식으로 훑으면 절반을 놓친다. 로그 출처부터 확인한다.
- **구분자 혼용을 허용하는 것.** `aa:bb-cc:dd-ee:ff`처럼 문서 변환 과정에서 구분자가 깨진 문자열도 매칭해 버리면 실재하지 않는 MAC이 결과에 섞인다. 역참조로 구분자를 고정한다.
- **구분자 없는 12자리 hex를 무분별하게 쓰는 것.** MD5 해시 앞부분, GUID 조각, 세션 토큰이 전부 걸린다. 반드시 주변 키워드(`mac=`, `chaddr`, `hwaddr=`)와 함께 검증한다.
- **대소문자를 무시하고 집계하는 것.** `AA:BB:CC:DD:EE:FF`와 `aa:bb:cc:dd:ee:ff`를 다른 값으로 세면 빈도 집계가 반으로 쪼개진다. 소문자로 정규화한다.
- **브로드캐스트/멀티캐스트를 그대로 세는 것.** `ff:ff:ff:ff:ff:ff`(브로드캐스트)나 `01:00:5e:xx:xx:xx`(IPv4 멀티캐스트)는 특정 호스트가 아니다. 집계에서 제외하거나 별도로 표시한다.
- **OUI 룩업 없이 "낯선 제조사"를 판단하는 것.** OUI 앞 3바이트만 봐서는 제조사를 알 수 없다. IEEE OUI 데이터베이스나 오프라인 매핑 파일이 필요하다.
- **로컬 관리 주소(locally administered)를 실제 하드웨어 MAC으로 오인하는 것.** 두 번째 hex 자리의 두 번째 비트(`x2, x6, xA, xE`로 시작하는 두 번째 옥텟)가 1이면 소프트웨어가 무작위로 생성한 주소다. VM·프라이버시 MAC 랜덤화 기능에서 흔하다.

## mini example

```text
문제:
"사내망 DHCP 로그에서 미등록 장치(회사 자산 목록에 없는 MAC)가
 IP를 할당받은 시각과 그 MAC을 구하세요."
첨부: dhcp.log, asset_macs.txt (등록된 MAC 87개)

1. 첫 시도 (실패) - 구분자 없는 패턴으로 시작했다
   $ grep -Eo '[0-9a-f]{12}' dhcp.log | sort -u | wc -l
   1842

   -> 1842개나 나왔다. dhcp.log에는 lease 파일 해시, 트랜잭션 ID(xid)도
      12자리 hex로 찍혀 있어서 전부 섞였다. MAC이 아니다.

2. 로그 형식을 다시 확인
   $ grep 'DHCPACK' dhcp.log | head -2
   Mar 14 07:12:01 dhcpd: DHCPACK on 10.0.20.55 to 08:00:27:aa:11:22 via eth0
   Mar 14 07:12:03 dhcpd: DHCPACK on 10.0.20.56 to 3c:97:0e:5f:8a:91 via eth0

   -> 콜론 표기다. "DHCPACK on <IP> to <MAC>" 형태로 문맥이 고정되어 있다.

3. 문맥으로 좁혀서 재추출
   $ grep -Eo 'DHCPACK on [0-9.]+ to [0-9a-f:]{17}' dhcp.log |
       awk '{print $NF, $3}' | sort -u | head -3
   08:00:27:aa:11:22 10.0.20.55
   3c:97:0e:5f:8a:91 10.0.20.56
   3c:97:0e:5f:8a:91 10.0.20.55

4. 등록된 MAC과 대조
   $ grep -Eo 'DHCPACK on [0-9.]+ to [0-9a-f:]{17}' dhcp.log |
       awk '{print $NF}' | sort -u > seen_macs.txt
   $ comm -23 <(sort seen_macs.txt) <(sort -f asset_macs.txt)
   08:00:27:aa:11:22

5. OUI 확인
   08:00:27 -> VirtualBox
   -> 등록되지 않은 가상머신이 사내망에 붙었다.

6. 시각 확정
   $ grep '08:00:27:aa:11:22' dhcp.log | head -1
   Mar 14 07:12:01 dhcpd: DHCPACK on 10.0.20.55 to 08:00:27:aa:11:22 via eth0

정답: 08:00:27:aa:11:22, 2026-03-14 07:12:01 (UTC 기준, 로그 타임존 확인 필요),
      OUI가 VirtualBox — 미승인 가상머신
```

1~3단계가 핵심이다. **구분자 없는 hex는 로그에 섞인 다른 12자리 값과 구별이 안 되므로, 문맥 키워드로 먼저 좁힌 뒤 정규식을 적용한다.**

## 출처

- SRC-077 — IEEE 802 / MAC 주소 표기와 OUI 체계: 48비트 구조, OUI가 상위 24비트라는 사실, 로컬 관리 비트 위치
- SRC-068 — RFC 826(ARP): ARP 패킷 내 하드웨어 주소 필드 구조
- SRC-015 — GNU grep manual: `-P`(PCRE) 역참조 지원 여부
- SRC-057 — Python `re` 문서: 역참조(`\1`)와 `finditer` 동작
- Cisco IOS의 dot notation 필드명과 로그 문구는 장비/버전에 따라 다르므로 실제 장비 로그에서 확인할 것
- OUI-제조사 매핑 예시(`00:0c:29`=VMware 등)는 일반적으로 알려진 값이며, 정확한 대조는 IEEE 공개 OUI 데이터베이스로 할 것
