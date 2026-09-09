---
id: FOR-0185
title: "tshark -Y 로 디스플레이 필터 쓰기: bash / PowerShell / cmd 인용 문제"
slug: "tshark-display-filter"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "DNS", "TCP", "UDP", "TLS", "FTP"]
tools: ["tshark", "Wireshark", "editcap", "mergecap", "capinfos"]
commands: ["tshark -r capture.pcapng -Y 'http.request' -c 5", "tshark -r capture.pcapng -2 -R 'http' -Y 'http.time > 1'", "tshark -r capture.pcapng -Y 'frame contains 66:6c:61:67'", "mergecap -w merged.pcapng part1.pcapng part2.pcapng", "editcap -A 2026-03-16T09:00:00 -B 2026-03-16T10:00:00 in.pcapng out.pcapng", "editcap -c 20000 big.pcapng chunk.pcapng"]
regex_patterns: ["flag\\{[^}]+\\}"]
wireshark_filters: ["http.host == \"evil.com\"", "http.request.method == \"POST\"", "frame contains 66:6c:61:67", "frame matches r\"flag\\{.*\\}\"", "!(arp || icmp || dns)", "tcp.port in {80, 443, 8000..8010}", "dns.qry.name.len > 40", "tcp.flags.syn == 1 && tcp.flags.ack == 0"]
tshark_fields: ["frame.number", "frame.time_epoch", "ip.src", "http.host", "dns.qry.name", "tcp.stream"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["tshark -Y", "tshark 필터", "CLI 디스플레이 필터"]
keywords: ["tshark -Y", "display filter", "디스플레이 필터", "셸 인용", "quoting", "PowerShell 따옴표", "cmd 따옴표", "-2 two-pass", "-R read filter", "mergecap", "editcap", "필터 문법 오류"]
aliases: ["tshark 필터", "tshark -Y 안됨", "파워쉘 tshark 따옴표", "cmd tshark 필터", "필터 문법 오류", "isn't a valid display filter", "tshark 필터 따옴표"]
symptom_keywords: ["isn't a valid display filter 오류가 난다", "PowerShell에서 필터가 안 먹는다", "cmd에서 필터가 안 먹는다", "GUI에서는 되는데 tshark에서는 안 된다", "결과가 0줄이다", "여러 pcap을 한 번에 보고 싶다"]
related: ["FOR-0184", "FOR-0186", "FOR-0146"]
source_ids: ["SRC-010", "SRC-002"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

GUI 에서 잘 돌던 필터가 tshark 에서 `isn't a valid display filter` 로 죽으면 필터가 틀린 것이 아니라 **셸이 따옴표를 먹은 것**이다. bash 는 `-Y '필터 "값"'`, cmd 는 `-Y "필터 \"값\""`, PowerShell 은 `-Y '필터 \"값\"'` 로 각각 다르게 써야 한다.

## 어떤 문제에서 필요한가

- Wireshark GUI 로 찾은 필터를 스크립트로 옮겨 여러 pcap 에 반복 적용해야 할 때
- 문제 파일이 `part1.pcapng`, `part2.pcapng` 처럼 쪼개져 있을 때
- 캡처가 수백 MB 라 GUI 가 뜨지 않을 때
- 같은 필터를 필드 추출([FOR-0186](./tshark-extract-fields.html))·통계·객체 추출에 재사용해야 할 때

GUI 는 필터 입력창이 셸을 거치지 않으므로 따옴표 문제가 없다. **CLI 로 넘어오는 순간 셸이 한 겹 끼어든다.** 이 글은 그 한 겹을 다룬다.

## 문제에서 처음 볼 단서

1. `tshark: "…" isn't a valid display filter: …` — **오류 메시지에 tshark 가 실제로 받은 문자열이 그대로 찍힌다.** 여기서 따옴표가 사라졌는지 확인한다.
2. 오류 없이 **0줄**이 나온다 → 필터는 유효하지만 매칭이 없다. 필드 이름 또는 값이 틀렸다.
3. GUI 에서는 컬럼에 값이 보이는데 `-e` 로는 빈칸 → `-2` 또는 `-o` preference 문제다 ([FOR-0184](./tshark-basics.html)).
4. `"xxx" is neither a field nor a protocol name` → 필드 이름 오타 또는 그 버전에 없는 필드.

## 30초 절차

```bash
tshark -r capture.pcapng -n -Y 'http.request' -c 5
```

**필터를 새로 쓸 때는 항상 `-c 5` 를 먼저 붙인다.** 문법이 맞는지, 매칭이 있는지 1초 안에 확인된다. 통과하면 `-c` 를 떼고 전량 처리한다.

세 환경의 최소 동작 확인 명령:

```bash
# bash / zsh
tshark -r capture.pcapng -Y 'http.request.method == "POST"' -c 3
```

```powershell
# PowerShell
tshark -r capture.pcapng -Y 'http.request.method == \"POST\"' -c 3
```

```text
:: cmd.exe
tshark -r capture.pcapng -Y "http.request.method == \"POST\"" -c 3
```

## 상세 절차

### 1단계 — `-Y` / `-R` / `-2` 를 구분한다

| 옵션 | 언제 평가되나 | `-2` 필요 | 쓰는 상황 |
| --- | --- | --- | --- |
| `-Y <filter>` | 해석 후 출력 직전 | 아니오 | **기본.** 저장 파일 분석의 99% |
| `-R <filter>` | 1차 패스에서 걸러 이후 패스로 넘기지 않는다 | **예** | 대용량에서 2-pass 비용을 줄일 때 |
| `-2` | 전체를 두 번 읽는다 | — | 미래 정보가 필요한 필드를 채울 때 |

```bash
# 잘못됨 — -R 를 단독으로
tshark -r capture.pcapng -R 'http.request'
# tshark: -R without -2 is deprecated / 무시되거나 오류

# 올바름 — 단일 패스
tshark -r capture.pcapng -Y 'http.request'

# 올바름 — 2-pass. 1차에서 http 만 남기고, 그 중 1초 넘게 걸린 요청만 출력
tshark -r capture.pcapng -2 -R 'http' -Y 'http.time > 1'
```

`-2` 가 없으면 값이 채워지지 않는 대표 필드:

| 필드 | 의미 | 왜 2-pass 가 필요한가 |
| --- | --- | --- |
| `http.time` | 요청→응답 소요 시간 | 응답이 뒤에 있다 |
| `http.response_in` | 응답 프레임 번호 | 같음 |
| `http.request_in` | 요청 프레임 번호 (응답 쪽에서) | 앞을 참조하므로 단일 패스에서도 대개 채워진다 |
| `dns.response_in` / `dns.time` | DNS 응답 시간 | 응답이 뒤에 있다 |
| `smb2.time` | SMB 응답 시간 | 응답이 뒤에 있다 |

### 2단계 — 셸별 인용: 세 환경 대조표

`-Y` 뒤의 필터는 **공백을 포함한 하나의 인자**여야 하고, 필터 안의 문자열 리터럴은 **디스플레이 필터 문법상 큰따옴표**여야 한다. 이 두 요구가 셸마다 다르게 충돌한다.

| 필터 (GUI 입력창에 쓰는 원본) | bash / zsh | cmd.exe | PowerShell |
| --- | --- | --- | --- |
| `http.request` | `-Y 'http.request'` | `-Y "http.request"` | `-Y 'http.request'` |
| `tcp.stream eq 4` | `-Y 'tcp.stream eq 4'` | `-Y "tcp.stream eq 4"` | `-Y 'tcp.stream eq 4'` |
| `!(arp \|\| icmp)` | `-Y '!(arp \|\| icmp)'` | `-Y "!(arp \|\| icmp)"` | `-Y '!(arp \|\| icmp)'` |
| `http.host == "evil.com"` | `-Y 'http.host == "evil.com"'` | `-Y "http.host == \"evil.com\""` | `-Y 'http.host == \"evil.com\"'` |
| `frame contains "flag"` | `-Y 'frame contains "flag"'` | `-Y "frame contains \"flag\""` | `-Y 'frame contains \"flag\"'` |
| `frame matches r"flag\{.*\}"` | `-Y 'frame matches r"flag\{.*\}"'` | `-Y "frame matches r\"flag\{.*\}\""` | `-Y 'frame matches r\"flag\{.*\}\"'` |
| `frame contains 66:6c:61:67` | `-Y 'frame contains 66:6c:61:67'` | `-Y "frame contains 66:6c:61:67"` | `-Y 'frame contains 66:6c:61:67'` |

규칙을 문장으로:

| 셸 | 바깥 따옴표 | 안쪽 큰따옴표 | 이유 |
| --- | --- | --- | --- |
| bash / zsh | **작은따옴표** | 그대로 `"` | 작은따옴표 안에서는 `$` `` ` `` `!` `*` `\|` 가 전부 리터럴이다 |
| cmd.exe | **큰따옴표** | `\"` | cmd 는 작은따옴표를 특수문자로 취급하지 않는다. `'...'` 는 따옴표째로 tshark 에 넘어간다 |
| PowerShell | **작은따옴표** | `\"` | 작은따옴표로 PowerShell 의 변수 확장은 막지만, 네이티브 exe 로 넘길 때 안쪽 `"` 가 소실되므로 `\"` 로 미리 이스케이프한다 |

**PowerShell 이 가장 위험하다.** 작은따옴표만 쓰고 안쪽에 `"` 를 그대로 두면, PowerShell 이 인자를 다시 인용하는 과정에서 큰따옴표가 사라져 tshark 는 `http.host == evil.com` 을 받는다. 실행은 되지만 결과가 다르거나 오류가 난다.

확인 방법 — 일부러 틀린 필터를 넣어 **tshark 가 무엇을 받았는지 되읽는다**.

```powershell
tshark -r capture.pcapng -Y 'http.host == \"evil.com\" &&&'
```

```text
tshark: "http.host == "evil.com" &&&" isn't a valid display filter: ...
                       ^^^^^^^^^^  <- 큰따옴표가 살아 있으면 인용 성공
```

큰따옴표가 안 보이면 인용이 실패한 것이다. 이 되읽기 기법이 인용 문제를 5초 만에 판정한다.

PowerShell 의 우회로 두 가지:

```powershell
# 1) --% 이후는 PowerShell 이 손대지 않고 그대로 넘긴다 (가장 확실)
tshark.exe --% -r capture.pcapng -Y "http.host == \"evil.com\"" -c 3

# 2) 따옴표가 필요 없는 형태로 필터를 바꾼다
tshark -r capture.pcapng -Y 'http.host contains 65:76:69:6c'   # "evil" 의 hex
```

PowerShell 7.3 이상에서는 `$PSNativeCommandArgumentPassing` 이 `Standard` 면 `\"` 없이 `"` 를 그대로 써야 하고, `Windows`(레거시) 면 `\"` 가 맞다. 값을 확인한 뒤 형태를 고정한다.

```powershell
$PSNativeCommandArgumentPassing
```

### 3단계 — 따옴표를 아예 안 쓰는 회피법

세 환경에서 **똑같이 동작하는** 표기법이 있다. 스크립트를 이식할 때 이쪽을 쓴다.

| 하고 싶은 것 | 따옴표 쓰는 형태 | 따옴표 없는 대체 |
| --- | --- | --- |
| 문자열 포함 검색 | `frame contains "flag"` | `frame contains 66:6c:61:67` |
| HTTP POST 만 | `http.request.method == "POST"` | `http.request.method == 50:4f:53:54` 은 안 된다 — `http.request.method` 는 문자열 필드다. 대신 `http.request && frame contains 50:4f:53:54` |
| 특정 포트 여러 개 | `tcp.port == 80 \|\| tcp.port == 443` | `tcp.port in {80, 443, 8000..8010}` |
| 대소문자 무시 문자열 | `frame matches "(?i)flag"` | `matches` 는 기본적으로 대소문자를 구분하지 않는다. `(?i)` 는 붙여도 무해하다 |
| 필드 존재 여부 | — | `http.authorization` (필드명만 쓰면 "존재하는 패킷") |

문자열을 hex 로 바꾸는 방법:

```bash
printf 'flag' | xxd -i -c 16 | head -1     # 참고용
printf 'flag' | od -An -tx1 | tr ' ' ':' | sed 's/^://;s/:$//'
# 66:6c:61:67
```

```powershell
# PowerShell: 문자열 -> 콜론 구분 hex
(([Text.Encoding]::ASCII.GetBytes('flag') | ForEach-Object { $_.ToString('x2') }) -join ':')
# 66:6c:61:67
```

UTF-16LE 로 전송된 한글/영문은 바이트 사이에 `00` 이 끼므로 hex 검색이 유일한 방법이다.

```text
frame contains 66:00:6c:00:61:00:67:00
```

### 4단계 — 필터 문법 오류 진단표

| 오류 메시지 / 증상 | 원인 | 고치는 법 |
| --- | --- | --- |
| `"tcp port 80" isn't a valid display filter` | 캡처 필터(BPF) 문법을 `-Y` 에 넣었다 | `tcp.port == 80` |
| `"…" is neither a field nor a protocol name` | 필드 이름 오타 또는 그 버전에 없는 필드 | `tshark -G fields \| grep <조각>` 으로 실명 확인 |
| `Unexpected end of filter expression` | 괄호·따옴표가 짝이 안 맞는다. **셸이 따옴표를 먹은 대표 증상** | 위 인용 대조표 |
| `"POST" 가 필터에 없다`처럼 값이 벗겨져 있다 | PowerShell 인자 재인용 | `\"` 또는 `--%` |
| 오류는 없고 0줄 | 필터는 유효, 매칭 없음 | 필드만 남겨 단계적으로 넓힌다 (5단계) |
| `!=` 결과가 직관과 다르다 | Wireshark 3.6 부터 `!=` 는 `all_ne`(모든 occurrence 가 다름) 의미다 | 하나라도 다르면 참을 원하면 `!==`(`any_ne`), 특정 값 제외는 `!(field == value)` |
| `matches` 안의 백슬래시가 먹힌다 | 필터 엔진과 PCRE2 가 문자열을 **두 번** 파싱한다 | raw string 접두 `r` 사용: `matches r"flag\{.*\}"` |
| PDF/한글 문서에서 복사한 필터가 안 먹는다 | 둥근 따옴표(`“ ”`)가 섞였다 | 최신 버전은 둥근 따옴표를 허용하지만, 구버전은 오류다. **직접 타이핑한다** |
| `-Y` 를 두 번 썼는데 하나만 적용된다 | `-Y` 는 마지막 것만 유효하다 | `&&` 로 한 줄에 합친다 |

비교 연산자와 영문 별칭:

| 영문 | C 스타일 | 의미 |
| --- | --- | --- |
| `eq` (= `any_eq`) | `==` | 같음 (여러 occurrence 중 하나라도) |
| `ne` (= `all_ne`) | `!=` | 다름 (**모든** occurrence 가) |
| — (`all_eq`) | `===` | 모든 occurrence 가 같음 |
| — (`any_ne`) | `!==` | 하나라도 다름 |
| `gt` / `lt` | `>` / `<` | 큼 / 작음 |
| `ge` / `le` | `>=` / `<=` | 크거나 같음 / 작거나 같음 |
| `and` / `or` / `not` | `&&` / `\|\|` / `!` | 논리 연산 |
| `contains` | — | 바이트/문자열 포함. **대소문자 구분** |
| `matches` / `~` | — | PCRE2 정규식. **대소문자 무시** |
| `in` | — | `tcp.port in {80, 443, 8000..8010}` |

`contains` 는 대소문자를 구분하고 `matches` 는 구분하지 않는다. 이 비대칭이 "필터가 안 걸리는" 흔한 원인이다.

### 5단계 — 필터를 단계적으로 좁힌다

0줄이 나왔을 때 필터를 통째로 고치지 말고 **가장 넓은 것에서 한 조건씩 붙인다.**

```bash
# 1) 프로토콜만
tshark -r capture.pcapng -Y 'http' -c 3
# -> 3줄 나옴. HTTP 는 존재한다.

# 2) 요청만
tshark -r capture.pcapng -Y 'http.request' -c 3
# -> 3줄. 요청도 있다.

# 3) 필드가 채워지는지 (값 비교 없이 필드 존재만)
tshark -r capture.pcapng -Y 'http.host' -T fields -e http.host -c 5
# -> shop.example.com / cdn.example.com / ...
#    실제 값을 눈으로 확인한다. 여기서 오타/서브도메인 차이가 드러난다.

# 4) 이제 값 비교
tshark -r capture.pcapng -Y 'http.host == "shop.example.com"' -c 3

# 5) == 이 0줄이면 contains 로 완화
tshark -r capture.pcapng -Y 'http.host contains "shop"' -c 3
```

**3단계가 핵심이다.** `필드명만` 쓴 필터는 "그 필드가 존재하는 패킷"을 뜻하므로, 값을 모를 때 실제 값 목록을 먼저 뽑아 볼 수 있다.

### 6단계 — 여러 파일을 한 번에

pcap 이 여러 개로 쪼개져 있으면 합치거나 루프를 돈다.

```bash
# 시간순 병합 (기본). 이후 tcp.stream 번호가 재계산되므로 GUI 와 함께 쓰기 좋다
mergecap -w merged.pcapng part1.pcapng part2.pcapng part3.pcapng
capinfos merged.pcapng

# 병합하지 않고 파일별로 같은 필터를 돌린다 (원본 프레임 번호 유지)
for f in *.pcapng; do
  echo "=== $f"
  tshark -r "$f" -n -Y 'http.request' -T fields -e frame.time_epoch -e http.host -e http.request.uri
done

# 결과를 한 CSV 로 모으면서 파일명 컬럼을 붙인다
for f in *.pcapng; do
  tshark -r "$f" -n -Y 'dns.flags.response == 0' -T fields -e frame.time_epoch -e dns.qry.name |
    awk -v F="$f" -F'\t' '{print F"\t"$0}'
done > all_dns.tsv
```

```powershell
# PowerShell 루프 — 파일명 컬럼을 앞에 붙여 한 파일로 모은다
Get-ChildItem *.pcapng | ForEach-Object {
  $name = $_.Name
  tshark -r $_.FullName -n -Y 'http.request' -T fields -e frame.time_epoch -e http.host -e http.request.uri |
    ForEach-Object { "$name`t$_" }
} | Set-Content all_http.tsv
```

`editcap` 으로 자르기·시간 보정:

| 목적 | 명령 |
| --- | --- |
| 20,000 패킷 단위로 분할 | `editcap -c 20000 big.pcapng chunk.pcapng` |
| 60초 단위로 분할 | `editcap -i 60 big.pcapng slice.pcapng` |
| 시간 범위만 남기기 | `editcap -A 2026-03-16T09:00:00 -B 2026-03-16T10:00:00 in.pcapng out.pcapng` |
| 특정 프레임 번호만 남기기 | `editcap -r in.pcapng picked.pcapng 100-200 350 900-1000` |
| 특정 프레임 번호 **제외** | `editcap in.pcapng cut.pcapng 100-200` (`-r` 없으면 삭제) |
| 타임스탬프를 -9시간 이동 | `editcap -t -32400 in.pcapng shifted.pcapng` |
| pcapng → 구형 pcap 변환 | `editcap -F pcap in.pcapng out.pcap` |
| 중복 패킷 제거 | `editcap -d in.pcapng dedup.pcapng` |

`-t -32400` 은 **KST 로 잘못 기록된 캡처를 UTC 로 되돌릴 때** 쓴다. 9시간 = 32400초다. 원본은 반드시 보존하고 사본에만 적용한다.

## 출력 필드 해석

`-Y` 로 걸러낸 결과를 확인할 때 보는 것.

| 출력 | 의미 | 함정 |
| --- | --- | --- |
| 첫 컬럼 숫자 | 프레임 번호 | **필터를 걸어도 원본 번호를 유지한다.** 1, 2, 3 이 아니라 842, 1204 처럼 나온�� |
| 두 번째 컬럼 | 시각. 기본은 **상대 초** | `-t ud` 로 UTC 절대시각으로 바꾼다 |
| `Protocol` 컬럼 | 최종 판정 프로토콜 | 비표준 포트는 `TCP` 로만 — `-d` 필요 |
| `Info` 컬럼 | 요약 | `-e _ws.col.Info` 로 필드처럼 뽑을 수 있다 |
| stderr 의 경고 | dissector 경고, preference 경고 | `-Q` 로 죽이지 말고 한 번은 읽는다 |

프레임 번호가 원본 유지라는 점이 중요하다. 필터 결과에서 얻은 번호를 그대로 `-Y 'frame.number == 842' -V` 에 넣어 상세를 볼 수 있다.

## pivot: 다음에 볼 artifact

| 필터로 확정한 것 | 다음 목표 |
| --- | --- |
| 관심 `tcp.stream` 번호 | `-q -z follow,tcp,ascii,<n>` 또는 Follow Stream ([FOR-0146](./wireshark-30sec-triage.html)) |
| 관심 프레임 번호 | `-Y 'frame.number == N' -V -x` 로 전체 트리·hex |
| HTTP 요청 목록 | 필드 추출로 표 만들기 ([FOR-0186](./tshark-extract-fields.html)) |
| POST 요청 존재 | 본문·자격증명 ([FOR-0158](./http-post-find.html)) |
| 자격증명 후보 | 프로토콜별 위치 ([FOR-0187](./pcap-credentials.html)) |
| 파일 전송 스트림 | 파일 추출 ([FOR-0189](./pcap-file-extraction.html)) |
| `frame.time_epoch` | EVTX·access.log 대조 ([FOR-0083](./event-4624-logon.html)) |

## 흔한 함정

- **PowerShell 에서 작은따옴표만 쓰고 안쪽 큰따옴표를 그대로 두는 것.** PowerShell 이 네이티브 exe 로 인자를 넘길 때 안쪽 `"` 가 소실되어 tshark 는 `http.host == evil.com` 을 받는다. 오류가 안 날 수도 있어서 더 위험하다. `\"` 로 이스케이프하거나 `--%` 를 쓴다.
- **cmd.exe 에서 작은따옴표를 쓰는 것.** cmd 는 `'` 를 특수문자로 보지 않으므로 `'http.request'` 가 따옴표째 tshark 에 전달되어 `'http.request' isn't a valid display filter` 가 된다. cmd 에서는 무조건 큰따옴표다.
- **`-Y` 에 캡처 필터 문법을 넣는 것.** `-Y 'tcp port 80'` 은 오류다. BPF 는 `-f` 전용이고 저장 파일에는 적용되지 않는다. 디스플레이 필터는 `tcp.port == 80`.
- **`-R` 를 `-2` 없이 쓰는 것.** `-R` 는 1차 패스 필터라서 단일 패스에서는 의미가 없다. 버전에 따라 경고 후 무시되거나 오류가 난다. 기본은 항상 `-Y`.
- **0줄이 나오면 필터를 통째로 고치는 것.** 프로토콜만 → 필드만 → 값 비교 순서로 한 조건씩 붙여야 어디가 틀렸는지 드러난다. 특히 `필드명만` 쓴 필터로 **실제 값 목록**을 먼저 확인한다.
- **`contains` 의 대소문자를 잊는 것.** `contains` 는 구분하고 `matches` 는 구분하지 않는다. `frame contains "Password"` 가 0줄이면 `frame matches "password"` 로 바꾼다.
- **`matches` 정규식에서 백슬래시를 한 번만 쓰는 것.** 필터 엔진과 PCRE2 가 문자열을 두 번 파싱하므로 `\{` 가 사라진다. raw string 접두 `r` 을 붙여 `matches r"flag\{.*\}"` 로 쓴다.
- **`!=` 를 "그 값이 아닌 패킷"으로 이해하는 것.** Wireshark 3.6 이후 `!=` 는 `all_ne`(모든 occurrence 가 다름)다. `ip.addr != 10.0.0.1` 은 src/dst 둘 다 다른 패킷만 걸린다 — 의도가 "10.0.0.1 이 안 끼어 있는 패킷"이면 맞고, "10.0.0.1 이 dst 가 아닌 패킷"이면 틀리다. 명확하게 `!(ip.addr == 10.0.0.1)` 로 쓴다.
- **문제 지문 PDF 에서 필터를 복사하는 것.** 둥근 따옴표(U+201C/U+201D)와 전각 공백이 섞여 들어온다. 최신 Wireshark 는 둥근 따옴표를 허용하지만 구버전은 오류이고, 전각 공백은 어느 버전에서도 오류다. **직접 타이핑한다.**
- **`mergecap` 후에도 원본 프레임 번호를 쓰는 것.** 병합하면 프레임 번호와 `tcp.stream` 이 전부 재계산된다. 파일별 번호를 유지해야 하면 병합하지 말고 루프를 돈다.
- **`-Y` 를 여러 번 쓰는 것.** 마지막 하나만 적용된다. 조건은 `&&` 로 합친다.
- **`editcap -t` 를 원본에 적용하는 것.** 타임스탬프를 되돌릴 수 없다. 항상 사본에 적용하고 원본 해시를 먼저 남긴다.

## 교차검증

```bash
# 1) tshark 가 실제로 받은 필터 문자열 확인 — 일부러 오류를 낸다
tshark -r capture.pcapng -Y 'http.host == "evil.com" &&&' 2>&1 | head -2

# 2) 같은 조건을 두 표기로 세어 같은지 본다
tshark -r capture.pcapng -Y 'http.request.method == "POST"' | wc -l
tshark -r capture.pcapng -Y 'http.request && frame contains 50:4f:53:54' | wc -l

# 3) 필드 존재 개수 vs 값 비교 개수
tshark -r capture.pcapng -Y 'http.host' | wc -l
tshark -r capture.pcapng -Y 'http.host contains "example"' | wc -l

# 4) 필드 이름이 이 버전에 있는지
tshark -G fields | grep -P '\thttp\.host\t' | head -1
tshark -v | head -1

# 5) GUI 와 대조 — 같은 필터를 GUI 입력창에 넣고 우하단 Displayed 개수 비교
```

1)과 5)를 함께 쓰면 "필터가 틀렸는가 / 셸이 먹었는가 / 버전에 필드가 없는가"가 완전히 갈린다.

## mini walkthrough

```text
문제:
"내부 호스트가 접속한 C2 도메인 하나를 찾으세요. HTTP Host 헤더에 있습니다."
첨부: beacon.pcapng (24,880 packets)
환경: Windows 10, PowerShell 7.4

1. 첫 시도 (실패)
   PS> tshark -r beacon.pcapng -Y 'http.host == "cdn-update.example.net"' -c 5
   (아무 출력 없음, 오류도 없음)

   "도메인이 틀렸나?" 하고 도메인만 여러 번 바꿔 넣었지만 계속 0줄.

2. 무엇이 잘못됐나 — tshark 가 받은 문자열을 되읽는다
   PS> tshark -r beacon.pcapng -Y 'http.host == "cdn-update.example.net" &&&'
   tshark: "http.host == cdn-update.example.net &&&" isn't a valid display filter: ...
                        ^^^^ 큰따옴표가 사라졌다

   원인: PowerShell 이 네이티브 exe 에 인자를 넘길 때 안쪽 큰따옴표를 벗겼다.
        tshark 는 `http.host == cdn-update.example.net` 을 받았고,
        이것은 문법상 유효하지 않거나 다르게 해석되어 0줄이 되었다.

3. 접근 변경 — 안쪽 큰따옴표를 \" 로 이스케이프
   PS> tshark -r beacon.pcapng -Y 'http.host == \"cdn-update.example.net\"' -c 5
   (여전히 0줄)

   -> 인용은 고쳐졌다. 이제는 정말 값이 틀린 것이다.
      필터를 통째로 고치지 말고 넓은 쪽에서 다시 시작한다.

4. 단계적으로 좁힌다 — 값을 모를 때는 필드 존재만
   PS> tshark -r beacon.pcapng -n -Y 'http.host' -T fields -e http.host |
         Group-Object | Sort-Object Count -Descending | Select-Object -First 6 Count, Name

   Count  Name
   1842   cdn.example.com
    311   shop.example.com
    288   ocsp.digicert.com
    204   updatesvc-cdn.example.net      <-- 이름이 비슷하지만 다르다
      9   www.example.org

   -> 기억한 도메인은 cdn-update... 였지만 실제는 updatesvc-cdn... 이었다.

5. 비콘 여부 확정 — 요청 간격이 일정한지
   PS> tshark -r beacon.pcapng -n -Y 'http.host contains \"updatesvc\"' `
         -T fields -e frame.time_epoch -e http.request.uri |
         Select-Object -First 6

   1773645302.418221  /api/v1/ping
   1773645362.501990  /api/v1/ping
   1773645422.489113  /api/v1/ping
   1773645482.512004  /api/v1/ping
   1773645542.498771  /api/v1/ping
   1773645602.505330  /api/v1/ping

   간격이 정확히 60초 ±0.1초. 사람 트래픽이 아니다. C2 비콘 확정.

6. 시각 환산
   1773645302 -> UTC 2026-03-16 09:55:02 -> KST 2026-03-16 18:55:02

7. 이식 가능한 형태로 고정 — 따옴표를 없앤다
   PS> tshark -r beacon.pcapng -n -Y 'http.host contains 75:70:64:61:74:65:73:76:63' `
         -T fields -e frame.time_epoch -e http.host -e http.request.uri
   (bash / cmd / PowerShell 어디서든 같은 문자열로 동작한다)

정답: updatesvc-cdn.example.net (60초 간격 비콘)
```

1단계에서 "0줄이니까 도메인이 틀렸다"고 결론짓고 도메인만 바꿔 넣은 것이 시간 낭비였다. **0줄과 오류를 구분하고, 인용을 먼저 검증한 다음 값을 의심하는 순서**가 정답이다.

## 막혔을 때 다음 체크

1. 오류인가 0줄인가 — 오류면 인용/문법, 0줄이면 값/필드
2. 일부러 `&&&` 를 붙여 tshark 가 받은 필터 문자열을 되읽었는가
3. 셸에 맞는 인용을 썼는가 — bash `'…"…"…'` / cmd `"…\"…\"…"` / PowerShell `'…\"…\"…'`
4. PowerShell 이면 `--%` 로 우회해 봤는가, `$PSNativeCommandArgumentPassing` 을 확인했는가
5. `-c 5` 를 붙여 빠르게 반복했는가
6. `필드명만` 쓴 필터로 실제 값 목록을 먼저 뽑았는가
7. `==` 대신 `contains` 로 완화해 봤는가
8. `contains`(대소문자 구분) 를 `matches`(무시) 로 바꿔 봤는가
9. `matches` 정규식에 raw string 접두 `r` 을 붙였는가
10. `-2` 가 필요한 필드(`http.time`, `http.response_in`)인가
11. `tshark -G fields | grep <조각>` 으로 이 버전에 필드가 있는지 확인했는가
12. `!=` 를 `!(… == …)` 로 바꿔 봤는가
13. 필터를 문서에서 복사했는가 — 둥근 따옴표/전각 공백을 지우고 직접 타이핑
14. 파일이 여러 개인가 → `mergecap` 또는 루프
15. 파일이 너무 큰가 → `editcap -A/-B` 로 시간 범위를 먼저 잘라낸다

## 출처

- SRC-010 — Wireshark tshark man page: `-Y`(디스플레이 필터, 단일 패스), `-R`(1차 패스 읽기 필터, `-2` 필요), `-2`(2-pass, 되감기 가능한 입력 필요), `-f`(pcap-filter), `-c`(필터에 걸러진 패킷도 포함), `-G fields`
- SRC-002 — Wireshark Display Filter Reference: `http.host`, `http.time`, `http.response_in`, `dns.qry.name`, `frame.time_epoch`, `tcp.stream` 필드 정의
- Wireshark User's Guide "Building Display Filter Expressions" 절: 비교 연산자와 영문 별칭(`eq`/`any_eq`, `ne`/`all_ne`, `all_eq`/`===`, `any_ne`/`!==`), `contains` 의 콜론 구분 바이트열 지원, `matches` 가 대소문자를 구분하지 않는다는 점, raw string 접두 `r`, 문자열 리터럴은 큰따옴표라는 규칙, Wireshark 3.6 에서 `!=` 의미가 `all_ne` 로 변경된 사실
- PowerShell 의 네이티브 명령 인자 전달 방식은 버전과 `$PSNativeCommandArgumentPassing` 설정에 따라 달라진다. 7.3 이상에서 `Standard` 모드면 `\"` 대신 `"` 를 그대로 쓴다. **실제 환경에서 `&&&` 되읽기로 한 번 확인한 뒤 형태를 고정할 것**
- `editcap -A/-B` 의 시각 문법은 버전에 따라 `YYYY-MM-DDTHH:MM:SS`(ISO 8601) 와 `YYYY-MM-DD HH:MM:SS` 를 각각 받으므로 `editcap -h` 로 확인할 것
