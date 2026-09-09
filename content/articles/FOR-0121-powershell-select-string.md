---
id: FOR-0121
title: "PowerShell Select-String으로 로그 검색하기 (Windows용 grep)"
slug: "powershell-select-string"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["access.log", "auth.log", "text log", "CSV log"]
file_paths: ["C:\\inetpub\\logs\\LogFiles", "C:\\Windows\\System32\\LogFiles"]
registry_paths: []
event_ids: []
protocols: []
tools: ["PowerShell", "Select-String", "Get-Content", "Timeline Explorer"]
commands: ["Select-String -Path .\\access.log -Pattern 'POST'", "Select-String -Path *.log -Pattern '\\d{1,3}(\\.\\d{1,3}){3}' -AllMatches", "sls -Path .\\auth.log -Pattern 'Failed password' -Context 1,1", "Get-Content .\\app.log -Tail 50"]
regex_patterns: ["(?<ip>\\d{1,3}(?:\\.\\d{1,3}){3})", "\"(?<method>GET|POST|PUT|DELETE) (?<uri>[^ ]+)", "Failed password for (?:invalid user )?(?<user>\\S+) from (?<ip>\\S+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["LineNumber", "Filename", "Line", "Matches", "Context"]
file_formats: ["log", "csv", "txt", "json"]
keywords: ["Select-String", "PowerShell grep", "sls", "로그 검색", "정규식", "regex", "Context", "AllMatches", "NotMatch", "SimpleMatch"]
aliases: ["파워쉘 grep", "powershell 로그 검색", "sls", "select-string", "윈도우에서 grep", "grep 대신", "파워쉘 정규식"]
symptom_keywords: ["윈도우에 grep이 없다", "로그가 너무 크다", "특정 IP를 찾고 싶다", "몇 번째 줄인지 알고 싶다", "앞뒤 줄도 보고 싶다", "한글이 깨진다", "대소문자 구분이 안 된다"]
related: ["FOR-0083", "FOR-0128"]
source_ids: ["SRC-007", "SRC-015"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Select-String`은 Windows 기본 탑재 grep이며, `-Pattern`에 .NET 정규식을 넣고 `-Context`로 앞뒤 줄을 함께 뽑으면 대회장에서 별도 툴 설치 없이 로그 분석을 끝낼 수 있다 — 단 **기본이 대소문자 무시**라는 점이 grep과 다르다.

## 어떤 문제에서 필요한가

- 대회장 PC가 Windows이고 WSL/ripgrep을 못 쓰는 상황
- 수만 줄 `access.log`에서 공격 IP와 최초 요청 시각을 찾아야 하는 상황
- 매칭된 줄만이 아니라 **줄 번호**와 **앞뒤 문맥**이 필요한 상황
- 정규식 캡처 그룹으로 필드를 뽑아 집계까지 해야 하는 상황

## 문제에서 처음 볼 단서

1. 첨부가 `.log`, `.txt`, `.csv` 텍스트다
2. 문제 지문에 "접속 로그", "몇 번", "최초", "가장 많이" 같은 집계 표현
3. 파일 크기가 수 MB~수백 MB → GUI 편집기로 열면 안 된다
4. 로그 첫 줄의 형식(Apache combined / syslog / JSON / CSV)이 이후 정규식을 결정한다

로그를 만나면 무조건 **첫 3줄과 마지막 3줄**을 먼저 본다.

```powershell
Get-Content .\access.log -TotalCount 3
Get-Content .\access.log -Tail 3
(Get-Content .\access.log).Count      # 총 줄 수
```

## 30초 절차

```powershell
Select-String -Path .\access.log -Pattern 'POST|cmd=|/admin|\.php|union|select' -CaseSensitive:$false
```

IP 빈도 상위 10개:

```powershell
Select-String -Path .\access.log -Pattern '^\S+' |
  ForEach-Object { $_.Matches[0].Value } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 10 Count, Name
```

출력 예시:

```text
Count Name
----- ----
 1842 203.0.113.77
  311 192.168.10.24
   96 198.51.100.5
```

1위가 나머지와 자릿수 차이로 벌어지면 그것이 공격자다.

## 상세 절차

### 1단계 — 옵션 6개만 외운다

| 옵션 | 하는 일 | grep 대응 |
| --- | --- | --- |
| `-Pattern` | .NET 정규식 (배열도 가능 = OR) | `-E` |
| `-Path` / `-LiteralPath` | 대상 파일. 와일드카드 가능 | 파일 인자 |
| `-SimpleMatch` | 정규식이 아니라 **문자 그대로** 검색 | `-F` |
| `-CaseSensitive` | 대소문자 구분 **(안 주면 무시)** | 기본이 반대 |
| `-Context 2,3` | 앞 2줄, 뒤 3줄 함께 출력 | `-B 2 -A 3` |
| `-NotMatch` | 매칭되지 **않는** 줄만 | `-v` |
| `-AllMatches` | 한 줄 안의 모든 매칭 반환 | `-o` |
| `-List` | 파일당 첫 매칭 1건만 | `-l` 유사 |
| `-Quiet` | 매칭 여부만 `$true`/`$false` | `-q` |

별칭은 `sls`다. 타이핑을 줄이려면 `sls -Path x.log -Pattern 'y'`.

> **grep과 가장 다른 점**: `Select-String`은 기본이 **대소문자 무시**다. `-CaseSensitive`를 명시하지 않으면 `Flag`와 `flag`가 모두 걸린다. 이 차이가 CTF에서 오답을 만드는 흔한 원인이다.

### 2단계 — 정규식은 .NET 문법

grep(POSIX)이 아니라 .NET이므로 다음이 그대로 된다.

| 기능 | 문법 | 예 |
| --- | --- | --- |
| 명명 캡처 | `(?<name>...)` | `(?<ip>\d{1,3}(?:\.\d{1,3}){3})` |
| 비캡처 그룹 | `(?:...)` | `(?:GET|POST)` |
| 전방탐색 | `(?=...)` / `(?!...)` | `flag(?=\{)` |
| 후방탐색 | `(?<=...)` / `(?<!...)` | `(?<=user=)\w+` |
| 게으른 수량자 | `*?` `+?` | `".*?"` |
| 유니코드 속성 | `\p{L}`, `\p{Hangul}` | 한글 포함 여부 |
| 인라인 옵션 | `(?i)` `(?m)` `(?s)` | `(?i)flag` |

후방탐색이 되기 때문에 `awk`/`cut` 없이 값만 뽑을 수 있다.

```powershell
# user= 뒤의 값만 추출
Select-String -Path .\app.log -Pattern '(?<=user=)[\w.\-]+' -AllMatches |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
```

### 3단계 — 캡처 그룹으로 표를 만든다

`Select-String`의 출력은 문자열이 아니라 **`MatchInfo` 객체**다. 여기서 값을 꺼내 표로 바꾸는 것이 PowerShell의 진짜 강점이다.

```powershell
$re = '^(?<ip>\S+) \S+ \S+ \[(?<time>[^\]]+)\] "(?<method>\S+) (?<uri>\S+) [^"]*" (?<status>\d{3}) (?<size>\S+)'

Select-String -Path .\access.log -Pattern $re |
  ForEach-Object {
    $g = $_.Matches[0].Groups
    [pscustomobject]@{
      Line   = $_.LineNumber
      Ip     = $g['ip'].Value
      Time   = $g['time'].Value
      Method = $g['method'].Value
      Uri    = $g['uri'].Value
      Status = [int]$g['status'].Value
    }
  } |
  Where-Object { $_.Status -ge 200 -and $_.Method -eq 'POST' } |
  Sort-Object Line | Format-Table -AutoSize
```

객체가 되면 `Where-Object`, `Group-Object`, `Sort-Object`, `Export-Csv`가 전부 쓸 수 있다.

```powershell
# 상태 코드별 개수
... | Group-Object Status | Select-Object Count, Name

# 특정 IP의 요청 흐름만 CSV로
... | Where-Object { $_.Ip -eq '203.0.113.77' } | Export-Csv attacker.csv -NoTypeInformation -Encoding UTF8
```

### 4단계 — `-Context`로 공격 전후를 본다

공격 요청 한 줄만 봐서는 성공 여부를 모른다. 앞뒤를 함께 본다.

```powershell
sls -Path .\access.log -Pattern 'cmd=|/shell\.php' -Context 2,3
```

```text
  access.log:8841:203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199
  access.log:8842:203.0.113.77 - - [14/Mar/2026:07:19:44 +0900] "POST /upload.php HTTP/1.1" 200 87
> access.log:8843:203.0.113.77 - - [14/Mar/2026:07:20:15 +0900] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 42
  access.log:8844:203.0.113.77 - - [14/Mar/2026:07:20:31 +0900] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 38
  access.log:8845:203.0.113.77 - - [14/Mar/2026:07:21:07 +0900] "GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1841
```

`>`가 매칭 줄, 나머지가 문맥이다. 8842의 `POST /upload.php 200`이 업로드 성공 지점이고, 8843부터 웹셸 실행이 시작됐다는 흐름이 한눈에 보인다.

### 5단계 — 큰 파일과 인코딩

```powershell
# 여러 파일 한 번에 (파일명이 출력에 포함된다)
sls -Path .\logs\*.log -Pattern 'Failed password'

# 재귀 검색
Get-ChildItem -Recurse -Include *.log | sls -Pattern 'flag\{'

# UTF-8 로그에서 한글이 깨질 때
sls -Path .\app.log -Pattern '실패' -Encoding utf8

# 파이프라인으로 스트리밍 (수 GB 파일에서 메모리 절약)
Get-Content .\huge.log -ReadCount 1000 | sls -Pattern 'ERROR'
```

## 출력 필드 해석

`MatchInfo` 객체의 속성이다.

| 속성 | 내용 | 쓰는 곳 |
| --- | --- | --- |
| `LineNumber` | 파일 내 줄 번호 (1부터) | "몇 번째 줄" 문제의 정답 |
| `Filename` | 파일 이름만 | 다중 파일 검색 시 출처 구분 |
| `Path` | 전체 경로 | 위와 동일 |
| `Line` | 매칭된 줄 전체 | 원문 확인 |
| `Matches` | `Match` 객체 배열 | `.Groups['name'].Value`로 캡처 접근 |
| `Matches[0].Value` | 매칭된 문자열 | 값만 필요할 때 |
| `Matches[0].Index` | 줄 안에서의 위치 | 오프셋 계산 |
| `Context.PreContext` | 앞 줄 배열 | `-Context` 사용 시 |
| `Context.PostContext` | 뒤 줄 배열 | 위와 동일 |
| `Pattern` | 매칭된 패턴 | `-Pattern`을 배열로 준 경우 어느 패턴이 걸렸는지 |

`-Pattern`에 배열을 주면 어느 패턴에 걸렸는지 분류할 수 있다.

```powershell
sls -Path .\access.log -Pattern 'union.*select', '\.\./\.\.', 'cmd=', '<script' |
  Group-Object Pattern | Select-Object Count, Name
```

```text
Count Name
----- ----
   47 union.*select
   12 ../..
  219 cmd=
    3 <script
```

공격 유형별 시도 횟수가 바로 나온다.

## pivot: 다음에 볼 artifact

| 로그에서 얻은 것 | 다음 목표 |
| --- | --- |
| 공격 IP | pcap의 `ip.addr == <IP>` — 실제 페이로드 |
| 업로드된 파일명 | `$MFT` ([FOR-0021](./mft-basics.html)) — 디스크상 생성 시각 |
| 계정 이름 | EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) — 로그온 성공 여부 |
| 요청 시각 | 그 시각 ±5분의 모든 로그와 artifact |
| User-Agent | 도구 식별 (sqlmap, curl, python-requests, nikto) |
| Base64 문자열 | 디코딩 → 명령/URL/자격증명 |
| 응답 크기 급증 | 데이터 유출 성공 지점 |

## 흔한 함정

- **대소문자.** grep 습관대로 두면 `-CaseSensitive` 없이 대소문자 무시로 동작한다. flag 문자열을 정확히 찾을 때는 반드시 명시한다.
- **`Matches`가 배열이라는 점.** `-AllMatches` 없이도 `Matches`는 배열이다. `$_.Matches.Value`는 여러 값을 반환할 수 있으니 단일 값이 필요하면 `$_.Matches[0].Value`.
- **`-AllMatches` 미사용.** 한 줄에 IP가 2개 있으면 기본 동작은 첫 것만 준다. 전부 필요하면 `-AllMatches`.
- **정규식 안의 `\`.** PowerShell 문자열은 **작은따옴표**를 쓰면 이스케이프 지옥을 피한다. `'\d{1,3}'`은 되지만 `"\d{1,3}"`도 대개 되고, `"$"`처럼 `$`가 들어가면 큰따옴표에서 변수로 해석된다. **정규식은 항상 작은따옴표.**
- **인코딩.** UTF-8 로그를 기본 인코딩으로 읽으면 한글이 깨진다. `-Encoding utf8`. Windows PowerShell 5.1과 PowerShell 7의 기본 인코딩이 다르다.
- **`-SimpleMatch`를 잊는 것.** `192.168.1.1`을 검색할 때 `.`은 정규식에서 아무 문자다. 문자 그대로 찾으려면 `-SimpleMatch`.
- **`Get-Content`로 전체를 메모리에 올리는 것.** `(Get-Content huge.log)`는 파일 전체를 배열로 만든다. `Select-String -Path`는 스트리밍이므로 큰 파일에 안전하다.
- **줄 번호를 0부터 세는 것.** `LineNumber`는 1부터다.
- **`Format-Table`을 파이프 중간에 두는 것.** 서식 객체로 변해 이후 `Where-Object`가 동작하지 않는다. 항상 마지막에.

## 교차검증

같은 결론을 다른 도구로 확인한다.

```powershell
# PowerShell
sls -Path .\access.log -Pattern '^203\.0\.113\.77' | Measure-Object | Select-Object Count
```

```bash
# ripgrep (있다면)
rg -c '^203\.0\.113\.77' access.log

# grep + wc
grep -c '^203\.0\.113\.77' access.log

# awk — 필드 기준이라 정규식 오탐이 없다
awk '$1=="203.0.113.77"' access.log | wc -l
```

네 숫자가 같아야 한다. 다르면 정규식이 의도보다 넓게(또는 좁게) 잡힌 것이다. 특히 `^203\.0\.113\.77`은 `203.0.113.770`도 잡을 수 있으므로 `awk`의 필드 완전 일치가 기준값이 된다.

## mini walkthrough

```text
문제:
"웹 서버 access.log에서 공격자 IP와 웹셸 업로드에 성공한 시각을 구하세요."
첨부: access.log (41,882줄)

1. 형식 확인
   Get-Content .\access.log -TotalCount 1
   -> 203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199
      => Apache combined 형식, 시간대 +0900 (KST)

2. IP 빈도
   sls -Path .\access.log -Pattern '^\S+' |
     ForEach-Object { $_.Matches[0].Value } |
     Group-Object | Sort-Object Count -Descending | Select-Object -First 5

   Count Name
    1842 203.0.113.77      <- 압도적
     311 192.168.10.24
      96 198.51.100.5

3. 첫 시도 (실패):
   sls -Path .\access.log -Pattern 'shell'
   -> 0건. 파일명이 shell이 아니었다.

4. 접근 변경 — 공격자 IP의 POST 요청만
   $re = '^(?<ip>\S+).*\[(?<time>[^\]]+)\] "(?<m>\S+) (?<uri>\S+)[^"]*" (?<st>\d{3})'
   sls -Path .\access.log -Pattern $re |
     ForEach-Object { $g=$_.Matches[0].Groups
       [pscustomobject]@{L=$_.LineNumber;Ip=$g['ip'].Value;T=$g['time'].Value
                         M=$g['m'].Value;U=$g['uri'].Value;S=$g['st'].Value} } |
     Where-Object { $_.Ip -eq '203.0.113.77' -and $_.M -eq 'POST' } |
     Format-Table -AutoSize

   L     Ip            T                          M    U           S
   8842  203.0.113.77  14/Mar/2026:07:19:44 +0900 POST /upload.php 200
   8901  203.0.113.77  14/Mar/2026:07:31:20 +0900 POST /upload.php 403

   POST 200이 한 건. 이것이 업로드 성공.

5. 확증 — 그 직후 무엇을 요청했나
   sls -Path .\access.log -Pattern 'upload\.php' -Context 0,4

   > 8842: POST /upload.php ... 200 87
     8843: GET /uploads/av4tar.php?cmd=id ... 200 42
     8844: GET /uploads/av4tar.php?cmd=whoami ... 200 38

   웹셸 이름은 av4tar.php 였다. 3단계에서 'shell'로 찾은 것이 실패한 이유.

6. 교차검증
   awk '$1=="203.0.113.77" && $6=="\"POST"' access.log
   -> 같은 2건 확인

정답: IP 203.0.113.77 / 업로드 성공 시각 2026-03-14 07:19:44 (KST)
```

3단계의 실패가 교훈이다. **파일명을 추측하지 말고 시간 흐름(`-Context`)으로 찾는다.**

## 막혔을 때 다음 체크

1. `Get-Content -TotalCount 1`로 **로그 형식**을 확인했는가 — 형식이 정규식을 결정한다
2. `-CaseSensitive` 유무를 의도대로 줬는가
3. `-Context 2,3`으로 앞뒤를 봤는가 — 성공/실패 판정은 문맥에 있다
4. 정규식을 작은따옴표로 감쌌는가
5. `-Encoding utf8`이 필요한가 (한글 깨짐)
6. `-AllMatches`가 필요한가 (한 줄 다중 매칭)
7. 상태 코드로 성공만 걸렀는가 (`200`, `302` vs `403`, `404`)
8. 응답 크기(`size`) 급증 지점이 있는가 — 유출 성공 신호
9. User-Agent를 봤는가 — 자동화 도구 식별
10. `Group-Object`로 집계했는가 — 눈으로 세면 틀린다

## 출처

- SRC-007 — Microsoft Learn, Select-String: 전체 파라미터와 `MatchInfo` 속성
- SRC-015 — GNU grep manual: `-B`/`-A`/`-v`/`-F` 대응 관계 확인용
