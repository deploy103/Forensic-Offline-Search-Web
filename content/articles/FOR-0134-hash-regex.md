---
id: FOR-0134
title: "MD5/SHA1/SHA256 해시 정규식: 길이로 구분하고 UUID 오탐 피하기"
slug: "hash-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["malware log", "yara scan result", "hash manifest", "git log", "memory strings"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["grep", "ripgrep", "PowerShell", "Python"]
commands: ["grep -Eo '\\b[0-9a-fA-F]{32}\\b' access.log | sort -u", "rg -oi '\\b[0-9a-f]{64}\\b' strings.txt", "Select-String -Pattern '\\b[0-9A-Fa-f]{40}\\b' -AllMatches"]
regex_patterns: ["\\b[0-9a-fA-F]{32}\\b", "\\b[0-9a-fA-F]{40}\\b", "\\b[0-9a-fA-F]{64}\\b", "\\b[0-9a-fA-F]{128}\\b", "(?i)\\b(?:md5|sha-?1|sha-?256)\\b\\s*[:=]?\\s*([0-9a-f]{32,128})", "(?<![0-9a-fA-F-])[0-9a-fA-F]{32}(?![0-9a-fA-F-])"]
wireshark_filters: []
tshark_fields: []
log_fields: ["md5", "sha1", "sha256", "hash", "checksum", "digest"]
file_formats: ["log", "txt", "csv", "json", "yara"]
primary_terms: ["md5 sha1 sha256 regex", "해시 정규식"]
keywords: ["MD5 regex", "SHA1 regex", "SHA256 regex", "해시 정규식", "해시값 추출", "32자 hex", "40자 hex", "64자 hex", "UUID 오탐", "git commit hash", "NTLM hash", "hex 길이 판정"]
aliases: ["해시 정규식", "해시값 정규식", "md5 정규식", "sha256 정규식", "해시 뽑기", "grep 해시", "해시 추출 regex"]
symptom_keywords: ["로그에서 해시값만 뽑고 싶다", "UUID가 MD5로 잡힌다", "git 커밋 해시가 SHA1으로 잡힌다", "해시 길이로 알고리즘을 구분하고 싶다", "hex 문자열 중 뭐가 해시인지 모르겠다"]
related: ["FOR-0010", "FOR-0136", "FOR-0114"]
source_ids: ["SRC-078", "SRC-015", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

해시는 정규식으로 "그 값이 진짜 해시인지" 검증할 수 없다 — **hex 문자열의 길이(32/40/64/128)로 알고리즘 후보만 좁힐 수 있을 뿐**이며, UUID(하이픈 제거 시 32자)와 Git 커밋 해시(40자)가 구조적으로 완전히 동일해 형태만으로는 절대 구별되지 않으므로 반드시 주변 키워드(`md5=`, `sha1:`, `commit`)로 문맥을 확인한다.

## 개념

해시 알고리즘의 출력은 고정 길이 이진 값이고, 로그·리포트에는 hex(16진수 2자리 = 1바이트) 문자열로 적힌다.

| 알고리즘 | 출력 비트 | hex 문자 수 |
| --- | --- | --- |
| MD5 | 128비트 | 32 |
| SHA-1 | 160비트 | 40 |
| SHA-256 | 256비트 | 64 |
| SHA-512 | 512비트 | 128 |

정규식이 검증할 수 있는 것은 **"hex 문자만으로 이루어진 정확히 이 길이의 문자열인가"** 뿐이다. 그 문자열이 실제로 무엇을 해시한 결과인지, 심지어 해시가 맞는지조차 정규식은 모른다.

### 구조가 같아서 구별 안 되는 것들

| 32자 hex | 40자 hex | 64자 hex |
| --- | --- | --- |
| MD5 | SHA-1 | SHA-256 |
| NTLM 해시 | Git 커밋/블롭 objectId (SHA-1 저장소) | 일부 blockchain 트랜잭션 ID |
| UUID/GUID에서 하이픈 제거 | SVN이 아닌 다른 VCS의 리비전 ID | — |
| 일부 세션 토큰 | — | — |

**길이가 같으면 정규식으로는 무엇도 구별할 수 없다.** 실전에서는 다음 순서로 좁힌다.

```text
1. 길이로 후보 알고리즘 압축 (32/40/64/128)
2. 주변 문자열(라벨)로 문맥 확인 - "md5=", "commit ", "SHA256:"
3. 그래도 애매하면 실제로 해시해 볼 원본 후보가 있는지 확인
```

## 파일 / 경로

| 대상 | 경로/형식 | 해시가 나오는 위치 |
| --- | --- | --- |
| 악성코드 분석 리포트 | `*.json`, `*.txt` | `md5`, `sha1`, `sha256` 필드 |
| YARA 스캔 결과 | 표준 출력, 로그 | 매치된 파일의 해시가 함께 출력되는 경우 |
| 해시 매니페스트 | `hashes.txt`, `manifest.csv` | `<hash>  <filename>` 형태 |
| Git 저장소 로그 | `.git/logs/HEAD`, `git log` 출력 | 40자 커밋/블롭 해시 |
| Amcache/Shimcache 파싱 결과 | EricZimmerman CSV | 실행 파일의 SHA-1 컬럼 |
| 메모리 문자열 | `*.raw` | `strings` 결과 안의 하드코딩된 해시 |
| 브라우저/앱 캐시 | 캐시 인덱스 파일 | 파일명 자체가 해시인 경우(SHA-1 등) |
| 인증서 지문 | `openssl x509 -fingerprint` | 콜론 구분 hex — [FOR-0133](./mac-address-regex.html)의 오탐 원천과 동일한 형태 |

## 주요 필드

### 패턴 1 — MD5 (32자)

```text
\b[0-9a-fA-F]{32}\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `d41d8cd98f00b204e9800998ecf8427`, `5f4dcc3b5aa765d61d8327deb882cf99` |
| 매칭 안 됨 | 31자 또는 33자 hex, `g0e8400e29b41d4a716446655440000`(g는 hex 아님) |
| **오탐** | UUID/GUID에서 하이픈을 제거한 값(`550e8400e29b41d4a716446655440000`), NTLM 해시 |

### 패턴 2 — SHA-1 (40자)

```text
\b[0-9a-fA-F]{40}\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| 매칭 안 됨 | 39자, 41자 |
| **오탐** | Git 커밋/블롭 objectId, 일부 세션 토큰 |

### 패턴 3 — SHA-256 (64자)

```text
\b[0-9a-fA-F]{64}\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 매칭 안 됨 | 63자, 65자 |
| 오탐 | 64자로 우연히 맞아떨어진 랜덤 hex 토큰(드묾, 길수록 우연 확률이 낮다) |

### 패턴 4 — 경계 강화 (긴 hex 블록에서 조각 추출 방지)

```text
(?<![0-9a-fA-F-])[0-9a-fA-F]{32}(?![0-9a-fA-F-])
```

앞뒤에 hex나 하이픈이 더 있으면 거부한다. **64자 SHA-256 문자열 안에서 앞 32자만 잘라 MD5로 오판하는 사고를 막는다.** lookaround이므로 `grep -E`에서는 동작하지 않고 `-P`/PowerShell/Python이 필요하다.

| 항목 | 값 |
| --- | --- |
| 매칭됨 | 독립된 32자 hex 문자열 |
| 매칭 안 됨 | 64자 SHA-256 문자열의 앞부분 32자(뒤에 hex가 더 있으므로 거부) |

### 패턴 5 — 라벨과 함께 캡처 (문맥 확인, 가장 신뢰도 높음)

```text
(?i)\b(?:md5|sha-?1|sha-?256)\b\s*[:=]?\s*([0-9a-f]{32,128})
```

| 캡처 그룹 | 역할 |
| --- | --- |
| `(?:md5\|sha-?1\|sha-?256)` | 알고리즘 라벨 (대소문자 무시, `sha1`/`sha-1` 모두 허용) |
| `([0-9a-f]{32,128})` | 실제 해시값 |

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `MD5: d41d8cd98f00b204e9800998ecf8427`, `sha256=e3b0c442...` |
| 매칭 안 됨 | 라벨 없이 hex만 있는 줄 |
| 장점 | **길이만으로 판정하는 패턴 1~3보다 오탐이 훨씬 적다** — 알고리즘이 로그에 명시되어 있기 때문 |

**라벨이 있는 로그에서는 패턴 5를 우선 쓴다.** 라벨이 없을 때만 길이 기반 패턴으로 후보를 좁힌다.

## 빠른 명령

### grep / ripgrep

```bash
# 1) MD5 후보 전부 (32자)
grep -Eo '\b[0-9a-fA-F]{32}\b' report.txt | sort -u

# 2) SHA-1 후보 전부 (40자)
grep -Eo '\b[0-9a-fA-F]{40}\b' report.txt | sort -u

# 3) SHA-256 후보 전부 (64자)
grep -Eo '\b[0-9a-fA-F]{64}\b' report.txt | sort -u

# 4) 라벨과 함께 있는 것만 (가장 정확) - 대소문자 무시
grep -Eio '(md5|sha-?1|sha-?256)[[:space:]]*[:=][[:space:]]*[0-9a-f]{32,128}' report.txt

# 5) 세 길이를 한 번에, 알고리즘 이름과 함께 출력
grep -Eo '\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b' report.txt |
  awk '{ n=length($0); alg = (n==32)?"MD5":(n==40)?"SHA1":"SHA256"; print alg, $0 }'

# 6) UUID 형태(하이픈 포함)는 먼저 제외하고 MD5 후보를 본다
grep -Eo '\b[0-9a-fA-F]{32}\b' report.txt |
  grep -vE '^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$'

# 7) ripgrep - lookaround으로 긴 hex 블록의 조각 매칭 방지 (PCRE2)
rg -oP '(?<![0-9a-f-])[0-9a-f]{64}(?![0-9a-f-])' -i strings.txt
```

### PowerShell

```powershell
# 정규식은 항상 작은따옴표
$re32 = '\b[0-9A-Fa-f]{32}\b'
$re40 = '\b[0-9A-Fa-f]{40}\b'
$re64 = '\b[0-9A-Fa-f]{64}\b'

# 길이별로 뽑아 알고리즘 라벨을 붙인다
Select-String -Path .\report.txt -Pattern $re32, $re40, $re64 -AllMatches |
  ForEach-Object { $_.Matches } | ForEach-Object {
    $alg = switch ($_.Value.Length) { 32 {'MD5'} 40 {'SHA1'} 64 {'SHA256'} }
    [pscustomobject]@{ Algorithm = $alg; Hash = $_.Value.ToLower() }
  } | Sort-Object Algorithm, Hash -Unique

# 라벨과 함께 있는 것만 (가장 정확)
$reLabeled = '(?i)\b(md5|sha-?1|sha-?256)\b\s*[:=]?\s*([0-9a-f]{32,128})'
Select-String -Path .\report.txt -Pattern $reLabeled -AllMatches |
  ForEach-Object { $_.Matches } | ForEach-Object {
    [pscustomobject]@{ Algorithm = $_.Groups[1].Value; Hash = $_.Groups[2].Value }
  }

# 파일을 직접 해시해서 후보와 대조 (검증은 정규식이 아니라 계산으로)
$candidate = 'd41d8cd98f00b204e9800998ecf8427'
$actual = (Get-FileHash .\sample.bin -Algorithm MD5).Hash.ToLower()
$actual -eq $candidate
```

### Python

```python
import re
import hashlib
from collections import defaultdict

LABELED = re.compile(r'(?i)\b(md5|sha-?1|sha-?256)\b\s*[:=]?\s*([0-9a-f]{32,128})')
BY_LEN  = re.compile(r'(?<![0-9a-fA-F-])[0-9a-fA-F]{32,128}(?![0-9a-fA-F-])')

ALG_BY_LEN = {32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512'}

text = open('report.txt', encoding='utf-8', errors='replace').read()

# 1) 라벨이 있는 것부터 (가장 신뢰도 높음)
labeled = [(m.group(1).upper().replace('-', ''), m.group(2).lower())
           for m in LABELED.finditer(text)]

# 2) 라벨 없는 hex 블록은 길이로만 후보 분류
found = defaultdict(set)
for m in BY_LEN.finditer(text):
    v = m.group()
    if len(v) in ALG_BY_LEN:
        found[ALG_BY_LEN[len(v)]].add(v.lower())

# 3) UUID 형태(32자 중 특정 위치가 4/8/10 등 버전·variant 비트)는 완전히 배제할 수 없다.
#    형태로는 구별 불가 -> 실제 해시 계산으로 검증한다.
def verify_md5(path: str, candidate: str) -> bool:
    h = hashlib.md5(open(path, 'rb').read()).hexdigest()
    return h == candidate.lower()

print('labeled:', labeled[:5])
print('MD5 후보 수:', len(found['MD5']))
```

**정규식은 후보를 좁히는 도구다. 최종 확정은 항상 실제 파일을 다시 해시해 비교하거나, 로그의 라벨을 신뢰하는 것으로 한다.**

## 함께 보는 artifact

| 해시를 얻은 뒤 | 다음 목표 |
| --- | --- |
| 악성코드 해시 확보 | 실제 파일 재계산 후 대조 ([FOR-0010](./hash-integrity.html)) |
| Amcache/Shimcache의 SHA-1 | 원본 실행 파일과 대조해 실행 여부 확정 |
| Git 커밋 해시(40자) | `.git/logs/HEAD`에서 시각·저자 대조 |
| YARA 매치 파일의 해시 | 다른 위치의 동일 해시 파일 검색(중복 배포 여부) |
| 로그의 hex 문자열이 해시가 아니었다 | [FOR-0136](./hex-string-regex.html)의 일반 hex 패턴으로 재분류 |
| Windows에서 대량 집계 | `Select-String -AllMatches` ([FOR-0114](./ripgrep.html)) |

## 흔한 실수

- **길이만 보고 알고리즘을 단정하는 것.** 32자는 MD5일 수도, UUID일 수도, NTLM 해시일 수도 있다. 라벨이 없으면 "32자 hex 후보"라고만 부르고, 확정하지 않는다.
- **UUID를 배제하지 않는 것.** UUID는 하이픈을 제거하면 정확히 32자 hex가 된다. 로그·설정 파일·API 응답에 UUID가 매우 흔하므로, MD5 후보 목록에서 UUID 패턴(`8-4-4-4-12` 자리 구성)을 먼저 걸러낸다.
- **Git 저장소가 있는 걸 모르고 40자 hex를 전부 SHA-1 파일 해시로 보는 것.** `.git` 디렉터리가 있으면 40자 hex 상당수가 커밋/블롭 objectId다. `git cat-file -t <hash>`로 실제 타입을 확인할 수 있다.
- **64자 SHA-256 문자열의 앞 32자를 MD5로 오판하는 것.** 긴 hex 블록에서 부분 매칭이 발생하면 경계(`\b`)만으로는 못 막는다. lookaround로 앞뒤에 hex가 더 있는지 확인한다.
- **대소문자를 정규화하지 않고 집계하는 것.** `D41D8CD9...`와 `d41d8cd9...`를 다른 값으로 세면 중복 탐지가 깨진다. 소문자로 통일한다.
- **해시가 맞는지 계산으로 검증하지 않고 결론 내리는 것.** 정규식 매칭은 "hex 문자열의 모양"만 확인한다. 그 값이 실제로 특정 파일의 해시인지는 그 파일을 다시 해시해서 비교해야 안다.
- **빈 파일/빈 문자열의 해시를 이상 값으로 취급하는 것.** `d41d8cd98f00b204e9800998ecf8427`(빈 파일 MD5), `da39a3ee5e6b4b0d3255bfef95601890afd80709`(빈 파일 SHA-1)은 정상적으로 자주 등장한다.
- **NTLM 해시와 MD5를 같은 것으로 취급하는 것.** 둘 다 32자 hex이지만 계산 방식이 다르다. `md5sum`으로 검증되지 않는 32자 값은 NTLM일 가능성을 의심한다.

## mini example

```text
문제:
"제공된 malware_report.json 에서 파일 해시 3종(MD5/SHA1/SHA256)을 뽑아
 실제 첨부 파일(sample.bin)의 해시와 일치하는지 확인하고, 일치하지 않으면
 어느 값이 조작됐는지 밝히세요."
첨부: malware_report.json, sample.bin

1. 첫 시도 (실패) - 길이만으로 뽑았다
   $ grep -Eo '\b[0-9a-fA-F]{32}\b' malware_report.json
   d41d8cd98f00b204e9800998ecf8427
   550e8400e29b41d4a716446655440000

   -> 두 개가 나왔다. 하나는 MD5, 하나는 report_id(UUID)였다.
      길이만으로는 구별할 수 없었다.

2. 라벨과 함께 다시 추출
   $ grep -Eio '"(md5|sha1|sha256)"\s*:\s*"[0-9a-f]+"' malware_report.json
   "md5": "d41d8cd98f00b204e9800998ecf8427"
   "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
   "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

   -> 라벨 덕에 UUID가 자동으로 배제됐다.

3. 실제 파일 해시 계산
   $ sha256sum sample.bin
   4c9f2a7e1b8d05c3a6e4f27b9d013c8a5f6e2b40c7d19a83e5f0b6c2d4a89173  sample.bin
   $ sha1sum sample.bin
   da39a3ee5e6b4b0d3255bfef95601890afd80709  sample.bin
   $ md5sum sample.bin
   d41d8cd98f00b204e9800998ecf8427  sample.bin

4. 대조
   MD5:    보고서 d41d8cd9... == 실제 d41d8cd9...  일치
   SHA1:   보고서 da39a3ee... == 실제 da39a3ee...  일치
   SHA256: 보고서 e3b0c442...  vs  실제 4c9f2a7e...  불일치

   -> MD5/SHA1은 둘 다 "빈 파일" 값이다. sample.bin이 실제로는
      비어 있지 않은데 보고서의 MD5/SHA1이 빈 파일 값과 같다는 것은
      보고서 작성 시 원본이 아니라 빈 파일을 해시했거나,
      SHA256 값만 사후에 다른 파일 것으로 바꿔치기했다는 뜻이다.

5. 교차검증 - report.json의 file_size 필드 확인
   $ grep -Eo '"file_size"\s*:\s*[0-9]+' malware_report.json
   "file_size": 18452

   -> sample.bin 실제 크기도 18452바이트. 빈 파일이 아니다.
      즉 MD5/SHA1은 애초에 잘못 기록됐고, SHA256만 진짜 값이다.

정답: SHA256 값(e3b0c442...)이 조작/오기재됐다 판단은 틀렸고,
      오히려 MD5·SHA1이 빈 파일 상수로 잘못 기재된 것이 조작 지점이다.
      실제 파일과 일치하는 것은 SHA256 하나뿐이다.
```

2단계가 핵심이다. **라벨이 있으면 반드시 라벨 기반 패턴을 우선 쓴다.** 길이만으로 뽑으면 UUID 같은 동형 문자열이 섞여 판정을 그르친다.

## 출처

- SRC-078 — NIST FIPS 180-4(SHA-1/256) 및 RFC 1321(MD5): 각 알고리즘의 출력 비트 수(128/160/256/512)와 hex 문자 수(32/40/64/128)
- SRC-015 — GNU grep manual: `-E`/`-P` 지원 범위, lookaround은 PCRE 전용
- SRC-057 — Python `re` 문서: lookaround, named group, `hashlib`로 실제 검증하는 방법
- 특정 32/40/64자 값이 MD5/SHA1/SHA256인지, UUID인지, NTLM인지는 **형태만으로 확정할 수 없다.** 이 글은 그 한계를 서술하며, 실제 판정은 라벨 또는 재계산으로 할 것을 권한다
