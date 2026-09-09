---
id: FOR-0114
title: "ripgrep(rg) 옵션 레퍼런스: grep과 다른 기본값과 -P -z -u 활용"
slug: "ripgrep"
category: "로그/Regex"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["access.log", "auth.log", "syslog", "소스 트리", "압축 로그"]
file_paths: ["/var/log", "/var/log/apache2"]
registry_paths: []
event_ids: []
protocols: []
tools: ["ripgrep", "rg", "grep", "PowerShell"]
commands: ["rg 'Failed password' auth.log", "rg -c 'POST' access.log", "rg -oP '(?<=cmd=)[^& ]+' access.log", "rg -z 'POST /upload' access.log.*.gz", "rg -uu --glob '*.log' 'flag{'", "rg -tjson 'password' .", "rg --files-with-matches 'flag{' ."]
regex_patterns: ["flag\\{[^}]+\\}", "(?<=cmd=)[^& ]+", "\\b\\d{1,3}(\\.\\d{1,3}){3}\\b"]
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["log", "txt", "json", "csv", "gz", "raw"]
primary_terms: ["ripgrep", "rg", "rg 옵션"]
keywords: ["ripgrep", "rg", "rg 옵션", "PCRE2", "--glob", "--type", "--no-ignore", "--hidden", "-uu", "search-zip", "gitignore", "빠른 grep"]
aliases: ["rg 사용법", "ripgrep 옵션", "rg grep 차이", "빠른 grep", "rg 압축 검색", "rg lookahead", "rg 숨김파일"]
symptom_keywords: ["rg 가 파일을 건너뛴다", "숨김 파일이 검색되지 않는다", "gitignore 때문에 못 찾는다", "grep -P 가 없다", "압축 로그를 검색하고 싶다", "검색이 너무 느리다"]
related: ["FOR-0112", "FOR-0113", "FOR-0111"]
source_ids: ["SRC-055", "SRC-015"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`rg`는 인자 없이도 **현재 디렉터리를 재귀 검색**하고 **ignore 파일과 숨김 파일과 바이너리를 자동으로 건너뛰는** 것이 `grep`과 가장 다른 점이며, 증거물 트리에서는 그 자동 제외가 곧 누락이므로 `rg -uu`(또는 `--no-ignore --hidden`)를 기본값으로 삼는다.

## 개념

`grep`과 `rg`는 같은 목적의 도구지만 **기본값이 정반대**다. 이 표가 이 글의 핵심이다.

| 항목 | `grep` 기본 | `rg` 기본 |
| --- | --- | --- |
| 재귀 | 안 한다 (`-r` 필요) | **한다** (인자 없으면 `.`) |
| `.gitignore` / `.ignore` | 무시한다 | **존중한다** (건너뛴다) |
| 숨김 파일·디렉터리 | 검색한다 | **건너뛴다** |
| 바이너리 파일 | `Binary file ... matches` | 건너뛰고 경고를 낸다 |
| 줄 번호 | 안 붙는다 (`-n` 필요) | 터미널 출력 시 **붙는다** |
| 파일명 헤딩 | `파일:줄` 접두어 | 파일명을 **한 번** 위에 출력 |
| 색 | 안 붙는다 | 붙는다 |
| 정규식 방언 | BRE (`-E`로 ERE, `-P`로 PCRE) | Rust regex (`\d` 등 지원, **lookaround 없음**), `-P`로 PCRE2 |
| 압축 파일 | 못 읽는다 (`zgrep` 필요) | `-z`로 읽는다 |
| 병렬 | 단일 스레드 | **멀티스레드** |

포렌식에서 위험한 줄은 2·3·4번이다. **증거물 폴더에 `.gitignore`가 있거나 파일이 `.`으로 시작하면 `rg`는 조용히 건너뛴다.** 검색 결과가 0건일 때 "없다"가 아니라 "제외됐다"일 수 있다.

정규식 엔진 차이도 알아 둔다.

| 문법 | `grep -E` | `rg` 기본 | `rg -P` |
| --- | --- | --- | --- |
| `\d` `\w` `\s` | `\d` **안 됨** | 된다 | 된다 |
| `{n,m}` `(...)` `\|` | 된다 | 된다 | 된다 |
| 게으른 수량자 `*?` | 안 됨 | **된다** | 된다 |
| lookahead `(?=)` | 안 됨 | **안 됨** | 된다 |
| lookbehind `(?<=)` | 안 됨 | **안 됨** | 된다 |
| 역참조 `\1` | 구현 의존 | **안 됨** | 된다 |
| 유니코드 클래스 `\p{L}` | 로케일 의존 | 된다 | 된다 |

Rust regex는 lookaround와 역참조를 지원하지 않는 대신 입력 길이에 선형인 시간을 보장한다. 이것이 속도의 근거다. lookaround가 필요하면 `-P`로 PCRE2 엔진으로 갈아탄다.

## 파일 / 경로

`rg`를 쓰는 상황별 대상이다.

| 상황 | 명령 | 주의 |
| --- | --- | --- |
| 로그 한 개 | `rg PAT access.log` | `grep`과 동일 |
| 로그 폴더 전체 | `rg PAT /var/log` | 권한 에러는 stderr로 나온다 |
| CTF 첨부 폴더 | `rg -uu PAT .` | `-uu` 없으면 숨김·ignore 파일 누락 |
| 압축 로테이션 로그 | `rg -z PAT access.log.*.gz` | `.gz` `.bz2` `.xz` `.zst` 등 |
| 마운트된 이미지 | `rg -uu --binary PAT /mnt/evidence` | 바이너리 포함 |
| 메모리 덤프 한 개 | `rg -a -o PAT memdump.raw` | `-o` 필수 |

## 주요 필드

옵션별로 **동작과 매칭/비매칭**을 붙였다. 공통 입력은 다음 4줄이다.

```text
1: 203.0.113.77 - - [14/Mar/2026:07:11:02 +0900] "GET /admin/ HTTP/1.1" 403 199
2: 192.168.10.24 - - [14/Mar/2026:07:11:09 +0900] "POST /upload.php HTTP/1.1" 200 87
3: 203.0.113.77 - - [14/Mar/2026:07:20:15 +0900] "GET /u/av4tar.php?cmd=id HTTP/1.1" 200 42
4: Mar 14 07:11:02 web01 sshd[2841]: Failed password for root from 203.0.113.77
```

### 대소문자

| 옵션 | 긴 이름 | 동작 |
| --- | --- | --- |
| (없음) | — | **대소문자 구분** (grep과 같다) |
| `-i` | `--ignore-case` | 무시 |
| `-S` | `--smart-case` | 패턴이 **전부 소문자면** 무시, 대문자가 하나라도 있으면 구분 |
| `-s` | `--case-sensitive` | 구분 강제 (`-i`/`-S`를 덮어쓴다) |

| 명령 | `POST` | `post` | 이유 |
| --- | --- | --- | --- |
| `rg 'post'` | 매칭 안 됨 | 매칭 | 기본은 구분 |
| `rg -i 'post'` | 매칭 | 매칭 | 무시 |
| `rg -S 'post'` | 매칭 | 매칭 | 패턴이 전부 소문자 → 무시 |
| `rg -S 'POST'` | 매칭 | 매칭 안 됨 | 패턴에 대문자 → 구분 |

`-S`는 편하지만 **패턴에 대문자가 하나 섞이는 순간 동작이 바뀐다.** 정확한 개수를 세는 상황에서는 `-s` 또는 `-i`를 명시한다.

### 매칭 범위

| 옵션 | 긴 이름 | 동작 |
| --- | --- | --- |
| `-w` | `--word-regexp` | 단어 경계에서만 |
| `-x` | `--line-regexp` | 줄 전체가 일치 |
| `-v` | `--invert-match` | 매칭되지 않는 줄 |
| `-F` | `--fixed-strings` | 정규식이 아니라 문자 그대로 |
| `-P` | `--pcre2` | PCRE2 엔진 (lookaround·역참조) |
| `-U` | `--multiline` | 패턴이 개행을 넘어갈 수 있다 |
| `--multiline-dotall` | — | `-U`와 함께 `.`이 개행에도 매칭 |
| `-e PAT` | `--regexp=PAT` | 패턴 여러 개 (OR) |
| `-f FILE` | `--file=FILE` | 파일의 패턴 목록 전부 OR |
| `-m N` | `--max-count=N` | 파일당 N건에서 멈춘다 |

| 명령 | 위 4줄 중 매칭 | 이유 |
| --- | --- | --- |
| `rg -w 'root'` | 4번 | `for root from`의 `root`가 단어 |
| `rg -w 'oot'` | 없음 | 앞이 `r`이라 경계가 아니다 |
| `rg -F '192.168.10.24'` | 2번 | 리터럴 |
| `rg '192.168.10.24'` | 2번 | (`.`이 임의 문자지만 이 입력에서는 결과가 같다) |
| `rg -x '200'` | 없음 | 줄 전체가 `200`인 줄이 없다 |

### 출력 형태

| 옵션 | 긴 이름 | 동작 |
| --- | --- | --- |
| `-n` | `--line-number` | 줄 번호 (터미널 출력 시 기본 ON) |
| `-N` | `--no-line-number` | 줄 번호 끄기 (**파이프로 넘길 때 필수**) |
| `-c` | `--count` | 매칭된 **줄 수** |
| `--count-matches` | — | 매칭 **개수** (한 줄 여러 건을 각각 센다) |
| `-l` | `--files-with-matches` | 파일 이름만 |
| `--files-without-match` | — | 매칭 없는 파일 이름만 |
| `-o` | `--only-matching` | 매칭 부분만 |
| `-r TEXT` | `--replace=TEXT` | 매칭 부분을 치환해 출력 (`$1` 참조 가능) |
| `-A N` / `-B N` / `-C N` | `--after-context` 등 | 뒤/앞/앞뒤 문맥 |
| `--no-filename` | — | 파일명 접두어 제거 |
| `--with-filename` | — | 파일명 접두어 강제 |
| `--no-heading` | — | `파일:줄:내용` 형태로 (grep 스타일) |
| `--vimgrep` | — | `파일:줄:열:내용` — 한 줄에 여러 매칭도 각각 출력 |
| `--json` | — | 구조화 출력 (스크립트 처리용) |
| `--files` | — | 검색하지 않고 **대상 파일 목록만** 출력 |
| `--sort path` | — | 결과를 경로 순으로 정렬 (**병렬을 끈다**) |
| `-j N` | `--threads=N` | 스레드 수. `-j1`이면 순서가 안정된다 |

`-r`은 `sed` 없이 접두어를 떼는 데 쓴다.

```bash
$ rg -No -r '$1' 'cmd=([^& ]+)' access.log
id
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | 3번 줄의 `cmd=id` → 출력은 `id` |
| 매칭 안 됨 | 1·2·4번 줄 |
| 주의 | 치환 텍스트의 `$1`은 셸 확장을 피하려 **작은따옴표** 필수 |

`grep`의 `-h`(파일명 숨김)에 해당하는 짧은 옵션은 **`rg`에서 `-h`가 도움말**이므로 쓰면 안 된다. `--no-filename`을 쓴다.

### 파일 선택 — 여기가 grep과 가장 크게 다르다

| 옵션 | 동작 |
| --- | --- |
| `-g GLOB` / `--glob GLOB` | glob에 맞는 파일만. `!`로 시작하면 제외 |
| `--iglob GLOB` | 대소문자 무시 glob |
| `-t TYPE` / `--type TYPE` | 파일 타입만 (`-tlog`, `-tjson`, `-tpy`) |
| `-T TYPE` / `--type-not TYPE` | 그 타입 제외 |
| `--type-list` | 정의된 타입과 확장자 목록 출력 |
| `--no-ignore` | `.gitignore`/`.ignore`/`.rgignore` 무시하고 전부 검색 |
| `--hidden` | 숨김 파일·디렉터리 포함 |
| `--binary` | 바이너리 파일도 검색 (매칭 위치만 보고) |
| `-a` / `--text` | 바이너리를 텍스트로 취급 |
| `-u` | `--no-ignore` |
| `-uu` | `--no-ignore --hidden` |
| `-uuu` | `--no-ignore --hidden --binary` |
| `-z` / `--search-zip` | 압축 파일을 풀어서 검색 |
| `-L` / `--follow` | 심볼릭 링크 따라가기 |
| `--max-filesize SIZE` | 이 크기 초과 파일 건너뛰기 (`--max-filesize 50M`) |
| `--one-file-system` | 다른 파일시스템으로 넘어가지 않는다 |

```bash
# 로그만
rg -g '*.log' 'Failed password' /var/log

# 로그만, 단 로테이션된 숫자 확장자는 제외
rg -g '*.log' -g '!*.log.[0-9]*' 'POST' /var/log

# 특정 디렉터리 제외
rg -g '!node_modules/**' -g '!.git/**' 'password' .

# 타입으로
rg -tjson 'password' .
rg -Tjson 'password' .        # JSON 만 제외
rg --type-list | head -5
```

`--type-list` 출력 예시다.

```text
agda: *.agda, *.lagda
aidl: *.aidl
alire: alire.toml
amake: *.mk, *.bp
asciidoc: *.adoc, *.asc, *.asciidoc
```

**증거물에서는 `-uu`를 기본으로 붙인다.**

| 명령 | `.env` (숨김) | `logs/debug.log` (`.gitignore`에 등재) | `image.dd` (바이너리) |
| --- | --- | --- | --- |
| `rg 'password' .` | 건너뜀 | 건너뜀 | 건너뜀 |
| `rg -u 'password' .` | 건너뜀 | **검색됨** | 건너뜀 |
| `rg -uu 'password' .` | **검색됨** | 검색됨 | 건너뜀 |
| `rg -uuu 'password' .` | 검색됨 | 검색됨 | **검색됨** |

`.gitignore` 규칙은 기본적으로 git 저장소 안에서만 적용된다(`--no-require-git`로 항상 적용하게 바꿀 수 있다). 그러나 `.ignore`와 `.rgignore`는 저장소 여부와 무관하게 적용되므로, **첨부 폴더에 `.ignore`가 한 줄 들어 있는 것만으로 검색 대상이 사라진다.** 무엇이 검색되는지 먼저 확인한다.

```bash
# 실제로 검색될 파일 목록을 눈으로 본다 (검색은 하지 않는다)
rg --files | wc -l
rg -uu --files | wc -l        # 숫자가 다르면 제외된 파일이 있다는 뜻
rg --files --glob '*.log'
```

### 압축 파일

```bash
# 로테이션 로그 전체 (비압축 + gz 혼재)
rg -z 'POST /upload' access.log access.log.1 access.log.*.gz

# 개수만, 파일별
rg -cz 'cmd=' access.log*
```

```text
access.log:74
access.log.1:19
access.log.2.gz:3
access.log.3.gz:1
```

| 항목 | 값 |
| --- | --- |
| `-z`가 처리하는 것 | `.gz`, `.bz2`, `.xz`, `.lz4`, `.zst`, `.br` 등 스트림 압축 |
| `-z`가 처리하지 **않는** 것 | `.zip`, `.7z`, `.rar` 같은 **아카이브**(여러 파일 컨테이너) |
| 대안 | ZIP은 먼저 풀거나 `unzip -p` 후 파이프 |

지원 형식은 빌드와 설치된 외부 디코더에 따라 다를 수 있으므로 실제 환경에서 확인한다.

### PCRE2 (`-P`)

```bash
# lookbehind — 접두어 제거 추출
rg -NoP '(?<=cmd=)[^& ]+' access.log

# lookahead — POST 이면서 .php 인 줄
rg -P '(?=.*POST)(?=.*\.php)' access.log

# 부정 lookahead — admin 이지만 admin.css 는 제외
rg -P 'admin(?!\.css)' access.log

# 역참조 — 같은 IP 가 두 번 나오는 줄
rg -P '(\b\d{1,3}(?:\.\d{1,3}){3}\b).*\1' access.log
```

| 패턴 | 매칭됨 | 매칭 안 됨 |
| --- | --- | --- |
| `(?<=cmd=)[^& ]+` | 3번 줄에서 `id` | 1·2·4번 줄 |
| `(?=.*POST)(?=.*\.php)` | 2번 줄 | 3번 줄(`GET`), 1번 줄 |
| `admin(?!\.css)` | 1번 줄의 `admin` | `/static/admin.css` 같은 줄 |

`-P`는 선형 시간 보장을 포기하므로 `(a+)+b` 같은 파괴적 백트래킹 패턴에서 멈출 수 있다. 필요할 때만 켠다.

### 종료 코드

| 코드 | 의미 |
| --- | --- |
| `0` | 한 건 이상 매칭됨 |
| `1` | 매칭 없음 |
| `2` | 오류 (일부 파일 접근 실패 등) |

`grep`과 같으므로 조건문에서 그대로 쓸 수 있다. 단 `rg`는 **일부 파일을 못 읽어도 검색을 계속하고 종료 코드 2를 낼 수 있으므로**, 0건과 오류를 구분할 때는 stderr를 함께 본다.

## 빠른 명령

```bash
rg -uu -g '*.log' 'flag\{' .
```

실전 조합이다.

```bash
# 1) 첨부 폴더 전체에서 flag 후보 (제외 없이)
rg -uu -o 'flag\{[^}]{1,200}\}' . | sort -u

# 2) 상위 IP — 줄 번호를 끄고 값만 뽑아 집계
rg -No '^\d{1,3}(\.\d{1,3}){3}' access.log | sort | uniq -c | sort -nr | head

# 3) 압축 포함 전체 로그에서 웹셸 명령
rg -zNo -r '$1' 'cmd=([^& ]+)' access.log* | sort | uniq -c | sort -nr

# 4) 공격 유형별 분류 (패턴을 여러 개 준다)
rg -c -e 'union.*select' -e '\.\./' -e 'cmd=' -e '<script' access.log

# 5) IOC 목록 일괄 검색
printf '%s\n' 203.0.113.77 198.51.100.5 evil.example.com > ioc.txt
rg -Ff ioc.txt --no-heading -n /var/log

# 6) 자격증명 흔적 — 설정 파일만
rg -uu -g '*.{conf,cfg,ini,yaml,yml,json,env}' -i 'password|passwd|secret|api[_-]?key|token' .

# 7) 개인키 파일 찾기
rg -uu -l 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' .

# 8) 여러 줄에 걸친 패턴 (JSON 블록 등)
rg -U --multiline-dotall '"user":\s*"admin".*?"result":\s*"ok"' app.json

# 9) 결과 순서를 고정해야 할 때 (재현 가능한 보고서)
rg -n --sort path 'Failed password' /var/log

# 10) 검색 대상이 무엇인지 먼저 확인
rg -uu --files | wc -l

# 11) 메모리 덤프에서 문자열 (바이너리)
rg -a -o 'https?://[A-Za-z0-9._~:/?#@!$&*+,;=%-]{4,200}' memdump.raw | sort -u | head -30

# 12) 크기 제한으로 거대한 이미지 파일 건너뛰기
rg -uu --max-filesize 100M 'flag\{' .
```

Windows PowerShell에서 `rg`가 없을 때의 대응은 [FOR-0121](./powershell-select-string.html), `grep`으로 되돌아갈 때의 옵션 대응은 [FOR-0112](./grep-basics.html)에 있다.

## 함께 보는 artifact

| `rg`로 얻은 것 | 다음 목표 |
| --- | --- |
| 매칭 파일 목록(`-l`) | 그 파일 하나를 `head`/`less`로 정독 ([FOR-0118](./head-tail-less.html)) |
| 매칭 줄 번호(`-n`) | `sed -n 'N,Mp'`로 구간 추출 |
| 값 목록(`-No`) | 빈도 집계 ([FOR-0117](./sort-uniq.html)) |
| 필드 위치가 확실해짐 | `awk` 완전 일치로 재계산 ([FOR-0115](./awk-fields.html)) |
| 0건 | `-uu --files`로 **검색 대상 자체**를 확인 |
| 로그 형식을 모른다 | 형식 판별 ([FOR-0111](./log-triage.html)) |
| ERE 문법이 필요하다 | `grep -E` ([FOR-0113](./grep-e-regex.html)) |

## 흔한 실수

- **`rg`의 자동 제외를 모르는 것.** 증거물 폴더에 `.gitignore`나 `.ignore`가 있으면 조용히 건너뛴다. 0건이 나왔을 때 `rg -uu --files`로 검색 대상을 먼저 확인한다.
- **숨김 파일이 검색된다고 가정하는 것.** `.env`, `.bash_history`, `.ssh/`는 기본으로 제외된다. `--hidden` 또는 `-uu`.
- **바이너리에서 0건을 "없다"로 읽는 것.** 기본으로 건너뛴다. `--binary`(위치만) 또는 `-a`(내용 출력)가 필요하다.
- **`-a` 없이 `-uuu`를 쓰고 결과가 이상하다고 판단하는 것.** `--binary`는 "바이너리도 검색하되 매칭 내용은 보여주지 않는" 모드에 가깝다. 내용이 필요하면 `-a -o`.
- **파이프에 넘길 때 `-N`을 빼먹는 것.** 터미널이 아니면 줄 번호가 기본으로 꺼지지만, `-n`을 명시했거나 `--vimgrep`을 쓰면 접두어가 붙어 이후 `awk`가 어긋난다. 집계 전에는 `-No`.
- **`-h`로 파일명을 숨기려는 것.** `rg -h`는 도움말이다. `--no-filename`을 쓴다.
- **lookaround를 기본 엔진에서 쓰는 것.** `rg '(?<=cmd=)x'`는 `regex parse error`를 낸다. `-P`가 필요하다.
- **`-z`를 ZIP에 쓰는 것.** `-z`는 스트림 압축(`.gz` 등) 전용이다. `.zip`은 `unzip -p`로 풀어 파이프한다.
- **`-S`(smart-case)에 의존해 개수를 세는 것.** 패턴에 대문자가 섞이면 동작이 바뀐다. 개수가 답이면 `-i`나 `-s`를 명시한다.
- **결과 순서를 신뢰하는 것.** 멀티스레드이므로 출력 순서가 실행마다 다를 수 있다. 재현성이 필요하면 `--sort path` 또는 `-j1`.
- **`--glob`과 `--type`을 혼동하는 것.** `-tlog`는 `rg`가 정의한 타입 목록에 의존한다. 확장자를 직접 지정하려면 `-g '*.log'`가 확실하다.
- **`rg`가 없는 대회장을 가정하지 않는 것.** 기본 설치에 없는 도구다. `grep`/`awk`로 같은 결과를 낼 수 있는 경로를 항상 함께 준비한다.

## mini example

```text
문제:
"첨부된 웹 서버 백업 폴더에서 하드코딩된 DB 자격증명을 찾으세요."
첨부: webroot.tar 를 풀어 놓은 폴더 (파일 8,412개, 일부 압축 로그 포함)

1. 첫 시도 (실패):
   $ rg -i 'password' .
   ./config/app.php
   12:    'password' => '',
   ./docs/README.md
   88:  password 를 설정하세요

   -> 빈 값과 문서만 나왔다. 실제 자격증명은 없는 것처럼 보인다.

2. 왜 0건에 가까운지 확인 — 검색 대상 자체를 센다
   $ rg --files | wc -l
   2104
   $ rg -uu --files | wc -l
   8412

   -> 6,308개가 제외되고 있었다. 원인을 본다.
   $ ls -a
   .  ..  .git  .gitignore  .ignore  config  docs  logs  storage  vendor
   $ cat .ignore
   storage/
   logs/
   *.bak

   -> .ignore 파일이 storage/, logs/, *.bak 를 전부 제외하고 있었다.
      공격자가 남긴 파일이 바로 그 안에 있을 가능성이 높다.

3. 접근 변경 — -uu 로 다시
   $ rg -uu -i 'password' . | head
   ./config/app.php:12:    'password' => '',
   ./config/app.php.bak:12:    'password' => 'Pr0d!DB_2026',
   ./storage/.env:4:DB_PASSWORD=Pr0d!DB_2026
   ./storage/.env.old:4:DB_PASSWORD=Str0ng-Old-Pw
   ./logs/deploy.log:1841:mysql -u root -p'Pr0d!DB_2026' -h 10.0.0.31

   -> .bak, 숨김 .env, 제외된 logs/ 에서 전부 나왔다.

4. 값만 정리해서 뽑는다
   $ rg -uu -No -r '$1' -i '(?:db_)?password[= ]*[:=>]*\s*[\x27"]?([^\x27"\s,;]{4,})' . |
       sort -u
   Pr0d!DB_2026
   Str0ng-Old-Pw

5. 압축된 로그까지 확인 — -z 추가
   $ rg -uuz -No -i 'Pr0d!DB_2026' logs/ | wc -l
   14
   $ rg -uuz -l -i 'Pr0d!DB_2026' logs/
   logs/deploy.log
   logs/deploy.log.2.gz
   logs/mysql-slow.log.1.gz

   -> gz 안에도 남아 있었다. -z 없이는 못 봤다.

6. 교차검증 — grep 으로 같은 결과가 나오는지
   $ grep -rn --include='*' -i 'Pr0d!DB_2026' . 2>/dev/null | wc -l
   14
   $ zgrep -r -i 'Pr0d!DB_2026' logs/ 2>/dev/null | wc -l
   14
   일치. grep 은 애초에 ignore 파일을 보지 않으므로 -uu 없이도 전부 찾는다.

정답: DB 계정 root / 암호 Pr0d!DB_2026 (구 암호 Str0ng-Old-Pw), 대상 호스트 10.0.0.31
```

1·2단계가 이 글 전체의 요지다. **`rg`가 0건을 반환했을 때 가장 먼저 의심할 것은 정규식이 아니라 파일 제외다.** `rg --files`와 `rg -uu --files`의 개수를 비교하면 즉시 드러난다.

## 출처

- SRC-055 — ripgrep User Guide / GUIDE.md: 기본 동작(재귀·ignore 존중·숨김 제외·바이너리 건너뛰기), `-u`/`-uu`/`-uuu` 누적 의미, `--glob`/`--type`, `-z`, `-P`(PCRE2), `--files`, `--sort`
- SRC-015 — GNU grep manual: `grep` 기본 동작과의 비교 근거(재귀 미수행, ignore 파일 무시, 종료 코드)
- `-z`가 지원하는 압축 형식과 `-P`(PCRE2) 사용 가능 여부는 ripgrep 빌드에 따라 다르므로 `rg --version`과 실제 파일로 확인할 것
- `.gitignore`가 git 저장소 밖에서 적용되는지(`--no-require-git`)는 버전에 따라 동작이 달라질 수 있다
- `--type-list` 항목은 ripgrep 버전마다 달라진다
