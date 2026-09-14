---
id: FOR-0118
title: "head/tail/less로 큰 로그 파일 빠르게 훑기: -n -f +G 페이징"
slug: "head-tail-less"
category: "로그/Regex"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "text log", "IIS log"]
file_paths: ["/var/log/auth.log", "/var/log/syslog", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: []
tools: ["head", "tail", "less", "more", "wc", "split", "Get-Content"]
commands: ["head -n 50 access.log", "tail -n 100 access.log", "tail -f app.log", "tail -F app.log", "less +G access.log", "less +F access.log", "wc -l access.log", "split -l 100000 huge.log part_"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["log", "txt", "csv"]
primary_terms: ["head tail less", "less 페이저"]
keywords: ["head", "tail", "less", "more", "tail -f", "tail -F", "less +G", "less +F", "wc -l", "페이저", "pager", "대용량 로그", "Get-Content -Tail"]
aliases: ["큰 로그 파일 열기", "로그 실시간 보기", "파일 끝만 보기", "로그 페이징", "less 검색", "tail 실시간 감시"]
symptom_keywords: ["로그 파일이 너무 커서 안 열린다", "cat 하면 터미널이 멈춘다", "실시간으로 로그를 보고 싶다", "파일 끝부분만 보고 싶다", "메모장이 파일을 못 연다"]
related: ["FOR-0112", "FOR-0119", "FOR-0111", "FOR-0117"]
source_ids: []
last_verified: "2026-09-10"
status: "draft"
---

## 한 줄 결론

수백 MB~수 GB짜리 로그는 절대 `cat`이나 메모장으로 통째로 열지 않는다. `head -n`으로 형식을 확인하고, `tail -n`/`tail -f`로 최근·실시간 부분만 보고, `less +G`로 끝에서부터 검색하며 훑는 것이 대용량 로그를 여는 첫 순서다.

## 어떤 문제에서 필요한가

- 로그 파일이 수백 MB 이상이라 텍스트 에디터가 멈추거나 아예 안 열리는 상황
- 파일 형식을 아직 모를 때 "처음/마지막 몇 줄"만 빠르게 확인해야 하는 상황
- 공격이 재현되고 있는 실시간 로그를 지켜봐야 하는 상황(honeypot, 재현 스크립트)
- `grep -n`으로 찾은 줄 번호 주변 맥락만 봐야 하는 상황
- 정규식을 아직 못 세운 초반 단계에서 눈으로 스크롤하며 패턴을 찾아야 하는 상황

## 문제에서 처음 볼 단서

1. 파일 크기가 수십~수백 MB 이상이다 → `cat`/메모장 금지, `head`/`tail`/`less`부터
2. 지문에 "실시간"·"모니터링"·"지금 공격 중" → `tail -f`
3. `grep`으로 줄 번호를 이미 찾았다 → 그 줄 주변만 `less` 또는 `sed -n`으로
4. 로그 형식을 모른다 → `head -n 5`로 먼저 육안 확인
5. 파일이 로테이션되는 서비스 로그다(`app.log`, `app.log.1`) → `tail -F`(대문자)가 필요

먼저 크기와 줄 수부터 잰다.

```bash
ls -lh access.log
wc -l access.log
```

```text
-rw-r--r-- 1 user user 1.2G Mar 14 08:00 access.log
4128421 access.log
```

1.2GB, 412만 줄이라는 사실을 확인하고 나면 "절대 전체를 화면에 뿌리지 않는다"는 원칙이 선다.

## 30초 절차

```bash
tail -n 100 access.log
```

```bash
head -n 5 access.log          # 형식 확인
tail -n 100 access.log        # 최근 상황
wc -l access.log              # 총 줄 수
less +G access.log            # 끝에서부터 위로 스크롤하며 검색
```

## 상세 절차

### 1단계 — head/tail 기본 옵션

| 옵션 | 의미 | 예 |
| --- | --- | --- |
| `-n N` | 앞/뒤 N줄 | `head -n 20 f`, `tail -n 20 f` |
| `-n +N` | N번째 줄부터 **끝까지** (`tail` 전용 관용구) | `tail -n +1000 f` |
| `-n -N` | 마지막 N줄을 **제외한** 전부 (GNU `head` 확장) | `head -n -10 f` |
| `-c N` | 앞/뒤 N **바이트** | `tail -c 500 f` |
| `-q` | 여러 파일을 헤더 없이 이어서 | `head -q -n5 a.log b.log` |
| `-v` | 파일마다 `==> 이름 <==` 헤더 강제 표시 | `tail -v -n5 a.log` |

```bash
$ head -n 3 access.log
203.0.113.77 - - [14/Mar/2026:07:11:02 +0900] "GET /admin/ HTTP/1.1" 403 199
192.168.10.24 - - [14/Mar/2026:07:11:09 +0900] "POST /upload.php HTTP/1.1" 200 87
198.51.100.5 - - [14/Mar/2026:07:11:11 +0900] "GET /favicon.ico HTTP/1.1" 404 209

$ tail -n +4128400 access.log | head -n 3
4128400: ...
```

`tail -n +N`으로 "N줄부터 끝까지"를 뽑아 `head`와 조합하면 임의의 구간을 잘라낼 수 있다. `grep -n`으로 찾은 줄 번호 주변을 통째로 볼 때 쓴다.

### 2단계 — tail -f / -F: 실시간 감시

| 옵션 | 동작 | 언제 |
| --- | --- | --- |
| `-f` | 파일 끝을 계속 읽는다. **파일 디스크립터(inode)를 따라간다** | 로테이션 없는 단순 append 로그 |
| `-F` | `-f`와 같지만 파일이 삭제·재생성(로테이션)되면 **이름으로 다시 연다** | logrotate로 갈아치우는 서비스 로그 |
| `--pid=PID` | PID가 죽으면 `tail`도 종료 | 재현 스크립트와 함께 실행할 때 |
| `--retry` | 파일이 아직 없어도 기다렸다 열림 | 서비스가 아직 로그를 안 만들었을 때 |

```bash
tail -f app.log
```

```text
203.0.113.77 - - [14/Mar/2026:08:02:11 +0900] "GET /admin/ HTTP/1.1" 403 199
203.0.113.77 - - [14/Mar/2026:08:02:12 +0900] "GET /admin/backup/ HTTP/1.1" 404 210
^C
```

`Ctrl+C`로 종료한다. 이걸 모르면 셸이 멈춘 것으로 착각한다.

로테이션이 걸린 서비스는 `-f` 대신 반드시 `-F`를 쓴다.

```bash
tail -F /var/log/nginx/access.log
```

여러 파일을 동시에 감시하면 파일이 바뀔 때마다 헤더로 구분된다.

```bash
$ tail -f auth.log app.log
==> auth.log <==
Mar 14 08:02:20 web01 sshd[3010]: Failed password for root from 203.0.113.77
==> app.log <==
203.0.113.77 - - [14/Mar/2026:08:02:21 +0900] "GET /admin/ HTTP/1.1" 403 199
```

### 3단계 — less: 페이저의 핵심 조작

`less`는 파일 전체를 메모리에 올리지 않고 필요한 부분만 읽으므로 수 GB 파일도 즉시 연다.

| 키 | 동작 |
| --- | --- |
| `G` | 파일 끝으로 |
| `g` | 파일 처음으로 |
| `/패턴` | 아래 방향 검색 |
| `?패턴` | 위 방향 검색 |
| `n` / `N` | 다음 / 이전 매칭 |
| `&패턴` | 매칭되는 줄만 **필터링해서 표시** (grep처럼) |
| `v` | `$EDITOR`로 현재 위치를 열어 편집 |
| `F` | `tail -f`처럼 실시간 추적 시작 |
| `Ctrl+C` | `F` 모드 중단(포워드 모드 유지, `less`는 안 꺼짐) |
| `q` | 종료 |
| `=` | 현재 줄 번호·파일 크기 정보 |

실행 옵션이다.

| 옵션 | 의미 |
| --- | --- |
| `+G` | 열자마자 끝으로 이동 |
| `+F` | 열자마자 추적 모드(사실상 `tail -f` 대체) |
| `+/패턴` | 열자마자 그 패턴을 검색 |
| `-N` | 줄 번호 표시 |
| `-S` | 긴 줄 줄바꿈하지 않고 자름(좌우 화살표로 스크롤) |
| `-I` | 검색을 대소문자 무시로 |
| `-M` | 상태줄에 퍼센트·줄 번호 표시 |

```bash
less -N +G access.log
```

```text
4128419 203.0.113.77 - - [14/Mar/2026:07:59:58 +0900] "GET /admin/ HTTP/1.1" 403 199
4128420 203.0.113.77 - - [14/Mar/2026:07:59:59 +0900] "POST /upload.php HTTP/1.1" 200 87
4128421 203.0.113.77 - - [14/Mar/2026:08:00:00 +0900] "GET /u/av4tar.php?cmd=id HTTP/1.1" 200 42
access.log lines 4128401-4128421/4128421 (END)
```

`less`의 검색은 기본 정규식을 지원한다. `/av4tar\.php`처럼 이스케이프한 패턴을 그대로 쓸 수 있다. 검색 안에서 필터만 보고 싶으면 `&`를 쓴다.

```text
&av4tar\.php
```

이 줄만 걸러 보여준다. 필터를 해제하려면 `&`만 입력하고 Enter.

압축된 로테이션 로그는 `zless`(`less`의 gzip 버전)로 그대로 넘긴다.

```bash
zless access.log.2.gz
```

### 4단계 — wc / split: 크기 파악과 분할

| 명령 | 출력 |
| --- | --- |
| `wc -l file` | 줄 수 |
| `wc -c file` | 바이트 수 |
| `wc -L file` | 가장 긴 줄의 길이(글자 수) |
| `wc -l < file` | 파일명 없이 숫자만(스크립트에서 유용) |

일부 도구가 초대형 파일에서 느리거나 메모리를 다 쓰면 줄 단위로 쪼갠다.

```bash
# 10만 줄씩 분할 (part_aa, part_ab, ...)
split -l 100000 huge.log part_

# 패턴이 나올 때마다 분할 (예: 날짜가 바뀌는 지점)
csplit huge.log '/^Mar 15/' '{*}'
```

### 5단계 — Windows/PowerShell 대응

| 목적 | Linux | PowerShell |
| --- | --- | --- |
| 앞 N줄 | `head -n 20 f` | `Get-Content f -Head 20` |
| 뒤 N줄 | `tail -n 20 f` | `Get-Content f -Tail 20` |
| 실시간 추적 | `tail -f f` | `Get-Content f -Tail 20 -Wait` |
| 줄 수 | `wc -l f` | `(Get-Content f | Measure-Object -Line).Lines` |
| 페이저 | `less f` | `more f` (기능이 훨씬 적다) |

```powershell
Get-Content 'C:\case\app.log' -Tail 50 -Wait
```

`Get-Content`는 **줄 단위로 전체를 파이프라인에 태우는** 방식이라 수백 MB 파일에서 `head`/`tail`보다 눈에 띄게 느리다. `-Tail`/`-Head`는 내부적으로 필요한 부분만 읽도록 최적화되어 있지만, `Get-Content f | Select-Object -First 20`처럼 파일 전체를 읽은 뒤 앞부분만 자르는 형태는 피한다.

```powershell
# 느림 - 파일 전체를 다 읽는다
Get-Content .\huge.log | Select-Object -First 20

# 빠름 - Head 옵션이 내부에서 앞부분만 읽는다
Get-Content .\huge.log -Head 20
```

인코딩도 확인한다. 한국어 Windows 애플리케이션 로그가 UTF-16LE나 CP949로 저장된 경우 `-Encoding`을 명시하지 않으면 글자가 깨진다.

```powershell
Get-Content .\app.log -Tail 20 -Encoding utf8
```

## 출력 필드 해석

| 위치 | 의미 |
| --- | --- |
| `tail -f`의 `==> 파일명 <==` | 여러 파일을 동시에 볼 때 방금 출력이 어느 파일인지 |
| `less` 하단 상태줄 `lines 4128401-4128421/4128421 (END)` | 현재 보이는 줄 범위 / 전체 줄 수, `END`는 파일 끝 |
| `less -M` 상태줄의 퍼센트 | 파일에서 현재 위치의 대략적 진행률 |
| `wc -l` 출력의 숫자 | 개행 문자(`\n`) 개수 — 마지막 줄에 개행이 없으면 실제 줄 수보다 1 작게 나온다 |
| `head -q` 결과에 파일명 헤더가 없음 | `-q`가 강제로 헤더를 없앤 것. 여러 파일을 이어붙여 파이프에 넘길 때 씀 |

## pivot: 다음에 볼 artifact

| head/tail/less로 확인한 것 | 다음 목표 |
| --- | --- |
| 로그 형식(필드 배치) | `awk -F`로 필드 번호 확정 ([FOR-0115](./awk-fields.html)) |
| 관심 줄 번호 | `sed -n 'N,Mp'`로 구간 치환/추출 ([FOR-0119](./sed-substitute.html)) |
| 최근/최종 이벤트 시각 | 다른 로그를 같은 시간대로 잘라 상관 분석 |
| 파일이 너무 커서 `grep`도 느리다 | `split`으로 쪼갠 뒤 병렬로 `grep` |
| 형식을 모르겠다 | 로그 형식 판별 절차 ([FOR-0111](./log-triage.html)) |
| 빈도 집계가 필요 | `sort \| uniq -c` ([FOR-0117](./sort-uniq.html)) |
| 실시간 로그의 특정 문자열만 | `tail -f \| grep --line-buffered 'PATTERN'` |

## 흔한 함정

- **큰 파일을 `cat`으로 바로 여는 것.** 터미널 스크롤백이 넘치고 화면이 멈춘 것처럼 보인다. 항상 `head`/`tail`/`less`부터 시작한다.
- **`tail -f`를 켠 채로 다음 명령을 못 치는 것.** `Ctrl+C`로 종료해야 셸이 돌아온다. 멈췄다고 창을 강제로 닫지 않는다.
- **로테이션되는 로그에 `-f`를 쓰는 것.** logrotate가 파일을 교체하면 `-f`는 옛 inode를 계속 읽어 새 로그를 놓친다. 서비스 로그는 `-F`가 기본이어야 한다.
- **`head -n -N`을 아무 `head`에서나 되는 문법으로 아는 것.** 마지막 N줄을 제외하는 음수 문법은 GNU 확장이다. macOS 기본 `head`(BSD)에는 없다.
- **`less` 종료 방법을 몰라 창을 닫는 것.** `q`로 나온다. `Ctrl+C`는 `less` 자체를 끄지 않고 `F`(follow) 모드만 중단시킨다.
- **`less` 검색이 기본으로 대소문자를 구분한다는 것을 잊는 것.** `FLAG{`와 `flag{`가 섞인 로그에서 `/flag` 검색은 절반을 놓친다. `-I` 옵션이나 검색 중 `-I` 토글을 쓴다.
- **`wc -l` 결과를 그대로 "이벤트 개수"로 믿는 것.** 여러 줄에 걸친 레코드(스택 트레이스, JSON pretty-print)가 있으면 줄 수와 이벤트 수가 다르다.
- **PowerShell `Get-Content`로 전체를 읽은 뒤 `Select-Object -First`로 자르는 것.** 파일 전체를 메모리에 올린 뒤 자르므로 대용량에서 느리다. `-Head`/`-Tail` 파라미터를 직접 쓴다.
- **인코딩을 확인하지 않고 `less`/`Get-Content`로 보는 것.** UTF-16LE 로그는 `less`에서 각 글자 사이에 `^@`가 끼어 보인다. `file -i`로 먼저 인코딩을 확인한다.

## 교차검증

`head`/`tail`로 잘라낸 범위가 맞는지 `wc`와 `grep`으로 재확인한다.

```bash
# 방법 1: wc -l 로 총 줄 수
wc -l access.log

# 방법 2: 마지막 줄 번호를 grep -c '^' 로 재확인 (개행 유무와 무관하게 안전)
grep -c '^' access.log
```

```text
4128421 access.log
4128421
```

두 값이 다르면 마지막 줄에 개행이 없는 것이다. `tail -n +N`으로 잘라낸 구간의 줄 수도 검산한다.

```bash
tail -n +4128400 access.log | wc -l    # 22 (4128421 - 4128400 + 1)
```

## mini walkthrough

```text
문제:
"서버가 다운되기 직전 5GB짜리 app.log 에서 마지막 공격 요청의 시각과
 명령어를 구하세요. 로그는 logrotate 로 매시간 로테이션된다."
첨부: app.log (5.1GB, 진행 중에도 계속 append)

1. 첫 시도 (실패):
   $ cat app.log | tail -100
   -> cat 이 5GB 전체를 파이프에 흘려보내려다 몇 초간 응답이 없다.
      "멈췄다"고 착각해 Ctrl+C 로 끊고 파일이 손상된 줄 알았다.
      cat 은 여기서 불필요한 중간 단계였다.

2. 접근 변경 — tail 만으로 직접
   $ tail -n 100 app.log
   -> 즉시 응답. cat 을 거칠 필요가 없었다.

3. 실시간 감시 시도 (두 번째 실패):
   $ tail -f app.log
   -> 새 줄이 전혀 안 뜬다. 그런데 서버는 여전히 요청을 받고 있다는
      대시보드가 있었다. logrotate 가 이미 파일을 새 inode 로 교체한 뒤였다.
      -f 는 옛 파일을 계속 붙들고 있었다.

4. 대문자 F 로 전환
   $ tail -F app.log
   203.0.113.77 - - [14/Mar/2026:08:59:58 +0900] "GET /admin/ HTTP/1.1" 403 199
   203.0.113.77 - - [14/Mar/2026:08:59:59 +0900] "GET /u/av4tar.php?cmd=id HTTP/1.1" 200 42
   -> 파일 교체를 감지해 새 파일을 다시 열었다. 이제 실시간으로 잡힌다.

5. 서버가 다운된 시점 확인 - less 로 끝에서부터
   $ less -N +G app.log
   5123841 203.0.113.77 - - [14/Mar/2026:09:14:02 +0900] "GET /u/av4tar.php?cmd=cat+/etc/shadow HTTP/1.1" 200 1204
   5123842 203.0.113.77 - - [14/Mar/2026:09:14:03 +0900] "GET /u/av4tar.php?cmd=rm+-rf+/var/log HTTP/1.1" 500 0
   app.log lines 5123822-5123842/5123842 (END)
   -> 마지막 줄이 500 에러. rm -rf 로 로그 자체를 지우려던 시도가
      서버 크래시 직전 마지막 요청이었다.

6. 교차검증 - 줄 수와 grep -c '^' 비교
   $ wc -l app.log        # 5123842
   $ grep -c '^' app.log  # 5123842
   일치. 마지막 줄에 개행이 있었다는 뜻이다.

정답: 09:14:03 KST(+0900), cmd=rm+-rf+/var/log (로그 삭제 시도 직후 서버 다운)
```

1단계와 3단계가 이 글의 핵심이다. **불필요한 `cat`을 거치지 않는다. 로테이션되는 로그에는 `-f`가 아니라 `-F`를 쓴다.**

## 막혔을 때 다음 체크

1. `ls -lh`로 파일 크기를 먼저 확인했는가 — 큰 파일에 `cat`을 쓰지 않았는가
2. `head -n 5`로 형식을 확인했는가
3. 로그가 로테이션되는 서비스라면 `tail -F`(대문자)를 썼는가
4. `less`를 종료할 때 `q`를 쓰는 것을 아는가(`Ctrl+C`는 follow만 중단)
5. `less` 검색에서 대소문자를 놓치지 않았는가(`-I`)
6. `wc -l`과 `grep -c '^'`을 비교해 마지막 줄 개행 여부를 확인했는가
7. 인코딩이 UTF-16LE/CP949인지 `file -i`로 확인했는가
8. PowerShell에서 `-Head`/`-Tail`을 직접 썼는가(`Select-Object -First`로 전체를 읽지 않았는가)
9. 압축된 로테이션 로그(`.gz`)라면 `zless`로 넘어갔는가
10. 여전히 느리면 `split`으로 쪼개서 처리할 시점인가

## 출처

- 본문의 `head`/`tail`/`less`/`wc`/`split` 옵션 동작은 GNU Coreutils와 GNU less의 일반적으로 알려진 표준 동작이나, `research/sources.json`에 해당 매뉴얼이 아직 등록되지 않아 `source_ids`를 비워 두고 `status: draft`로 표시했다
- GNU 확장(`head -n -N`, `-F`의 로테이션 재오픈 동작)은 배포판·버전에 따라 다를 수 있으므로 실제 환경에서 `--version`으로 구현을 확인할 것
- PowerShell `Get-Content -Head/-Tail/-Wait`의 성능 특성은 실제 환경에서 파일 크기별로 재확인할 것
- 오케스트레이터에게: GNU Coreutils Manual(`head`, `tail`, `wc`, `split`)과 GNU less 매뉴얼을 `research/sources.json`에 추가할 것을 요청한다
