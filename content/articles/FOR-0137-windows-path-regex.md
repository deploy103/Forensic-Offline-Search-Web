---
id: FOR-0137
title: "Windows 경로 regex: 백슬래시 이스케이프와 UNC·확장 길이 접두"
slug: "windows-path-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["CommandLine", "Image", "TargetFilename", "ConsoleHost_history.txt", "Prefetch", "memory strings"]
file_paths: ["C:\\Windows\\Temp", "C:\\Users\\Public", "C:\\ProgramData", "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp", "C:\\Users\\%USERNAME%\\AppData\\Roaming"]
registry_paths: []
event_ids: []
protocols: ["SMB"]
tools: ["grep", "ripgrep", "PowerShell", "Python", "Select-String"]
commands: ["grep -Eio '[a-z]:\\\\[^\"<>|]+' cmdline.txt", "grep -F '\\\\?\\' cmdline.txt", "Select-String -Path .\\cmdline.txt -Pattern '(?i)[a-z]:\\\\[^\"]+' -AllMatches"]
regex_patterns: ["[A-Za-z]:\\\\", "[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*", "\\\\\\\\[A-Za-z0-9._-]+\\\\[^\\\\/:*?\"<>|\\r\\n]+", "%[A-Za-z_][A-Za-z0-9_()]*%", "(?i)[A-Za-z]:\\\\(?:Windows\\\\Temp|ProgramData|Users\\\\Public|PerfLogs)\\\\", "(?i)^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\.|$)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["CommandLine", "Image", "ParentImage", "TargetFilename", "ProcessName"]
file_formats: ["log", "csv", "json", "txt"]
primary_terms: ["Windows 경로 regex", "윈도우 경로 정규식", "UNC 경로 regex"]
keywords: ["Windows path regex", "윈도우 경로 정규식", "백슬래시 이스케이프", "UNC", "확장 길이 경로", "MAX_PATH", "예약 이름", "환경변수 경로", "AppData", "Temp", "드라이브 문자", "실행 파일 경로 추출"]
aliases: ["윈도우 경로 정규식", "경로 regex", "백슬래시 몇 개", "unc 정규식", "경로 뽑기", "exe 경로 추출", "커맨드라인에서 경로"]
symptom_keywords: ["백슬래시를 몇 개 써야 하는지 모르겠다", "경로가 중간에 잘려서 나온다", "UNC 경로가 안 잡힌다", "커맨드라인에서 실행 파일만 뽑고 싶다", "의심 경로만 걸러내고 싶다", "%TEMP% 가 무슨 경로인지 모르겠다"]
related: ["FOR-0138", "FOR-0128", "FOR-0121", "FOR-0088"]
source_ids: ["SRC-079", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Windows 경로를 정규식으로 잡을 때 규칙은 하나다 — **정규식 엔진에 `\\`(백슬래시 2개)가 도달해야 리터럴 백슬래시 1개를 매칭**하므로, 문자열 리터럴이 백슬래시를 삼키는 문법(셸 큰따옴표·Python 일반 문자열·JSON)에서는 4개를 쓰고 삼키지 않는 문법(셸/PowerShell 작은따옴표·Python raw)에서는 2개를 쓴다.

## 개념

Windows 경로는 네 가지 형태가 전부다. 이 네 개를 구분해서 써야 로그에서 경로를 놓치지 않는다.

| 형태 | 예 | 정규식 조각 | 비고 |
| --- | --- | --- | --- |
| 드라이브 절대경로 | `C:\Windows\System32\cmd.exe` | `[A-Za-z]:\\` | 가장 흔함 |
| 드라이브 상대경로 | `C:temp\a.txt` | `[A-Za-z]:(?!\\)` | 드라이브별 CWD 기준. 실전에서 드묾 |
| 루트 상대경로 | `\Windows\System32` | `^\\(?!\\)` | 현재 드라이브 기준 |
| UNC | `\\FILESRV01\share$\a.exe` | `\\\\[^\\/:*?"<>\|]+\\` | 원격. 랜섬웨어 확산 경로 |
| 확장 길이(로컬) | `\\?\C:\very\long\path` | `\\\\\?\\[A-Za-z]:\\` | `MAX_PATH` 260자 제한 우회 |
| 확장 길이(UNC) | `\\?\UNC\FILESRV01\share` | `\\\\\?\\UNC\\` | 위의 UNC 버전 |
| 장치 네임스페이스 | `\\.\PhysicalDrive0`, `\\.\C:` | `\\\\\.\\` | 디스크 직접 접근. 이미징 도구 |

경로 구성요소에 **쓸 수 없는 문자**는 다음과 같다. 이 목록이 그대로 "경로 문자" 부정 문자 클래스가 된다.

```text
< > : " / \ | ? *      그리고 0x00~0x1F 제어문자
```

따라서 "한 구성요소"는 `[^\\/:*?"<>|\r\n]+` 로 표현한다. 구분자로 `/`도 Win32 API가 받아주지만 명령행에서는 스위치와 헷갈리므로 실제 로그에는 `\`가 압도적으로 많다. 둘 다 받으려면 `[\\/]`를 쓴다.

### 예약 이름

파일 이름 부분이 다음과 같으면 확장자가 붙어 있어도 장치로 해석된다.

```text
CON  PRN  AUX  NUL  COM1..COM9  LPT1..LPT9
```

```text
(?i)^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)
```

`nul.txt`로 쓰면 파일이 만들어지지 않고 버려진다. 안티포렌식으로 `> nul` 리다이렉션이나 `copy evil.exe \\.\C:\...` 같은 우회에 쓰이므로 명령행 로그에서 이 이름이 보이면 의도를 확인한다.

### 후행 공백과 점

Win32 계층은 경로 끝의 공백과 점을 조용히 잘라낸다. 그래서 `evil.exe ` (뒤 공백)와 `evil.exe.`은 `evil.exe`가 된다. 반면 `\\?\` 접두를 쓰면 잘라내지 않으므로 **탐색기로는 지울 수 없는 파일**이 만들어진다. 이런 파일이 있으면 `\\?\` 접두 경로로 접근한다.

## 파일 / 경로

경로 문자열이 실제로 나오는 자리다.

| 대상 | 필드/파일 | 경로가 있는 위치 |
| --- | --- | --- |
| Security 4688 | `NewProcessName`, `ParentProcessName`, `CommandLine` | 전체 경로 그대로 |
| Sysmon Event 1 | `Image`, `ParentImage`, `CommandLine`, `CurrentDirectory` | 전체 경로 |
| Sysmon Event 11 | `TargetFilename` | 생성된 파일 |
| PowerShell 4104 | `ScriptBlockText` | 스크립트 안의 경로 |
| PSReadLine 히스토리 | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | 사용자가 친 명령 원문 |
| Prefetch | `*.pf` 내부 파일 참조 목록 | `\VOLUME{...}\WINDOWS\...` 형식 |
| 레지스트리 Run 키 | 값 데이터 | 인용부호 포함/미포함 혼재 |
| 작업 스케줄러 | `C:\Windows\System32\Tasks\` 하위 XML | `<Command>`, `<Arguments>` |
| 메모리 덤프 | `strings` 결과 | 잘린 경로가 많다 |

### 환경변수 경로 — 실제 값 대응표

로그에는 확장 전 형태(`%TEMP%`)와 확장 후 형태(`C:\Users\hong\AppData\Local\Temp`)가 섞여 나온다. **둘 다 잡아야 한다.**

| 변수 | 일반적 확장 결과 |
| --- | --- |
| `%SystemRoot%`, `%windir%` | `C:\Windows` |
| `%TEMP%`, `%TMP%` (사용자) | `C:\Users\<user>\AppData\Local\Temp` |
| `%TEMP%` (SYSTEM 컨텍스트) | `C:\Windows\Temp` |
| `%APPDATA%` | `C:\Users\<user>\AppData\Roaming` |
| `%LOCALAPPDATA%` | `C:\Users\<user>\AppData\Local` |
| `%USERPROFILE%` | `C:\Users\<user>` |
| `%ProgramData%` | `C:\ProgramData` |
| `%PUBLIC%` | `C:\Users\Public` |
| `%ProgramFiles%` | `C:\Program Files` |
| `%ProgramFiles(x86)%` | `C:\Program Files (x86)` |
| `%ComSpec%` | `C:\Windows\System32\cmd.exe` |

변수 참조 자체를 잡는 패턴이다. 괄호가 들어가는 `%ProgramFiles(x86)%`까지 포함한다.

```text
%[A-Za-z_][A-Za-z0-9_()]*%
```

## 주요 필드

### 패턴 1 — 드라이브 절대경로 (가장 많이 쓴다)

```text
[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `C:\Windows\System32\cmd.exe`, `D:\`, `C:\Program Files (x86)\App\a.exe` |
| 매칭 안 됨 | `\\SRV\share\a.exe`, `/var/log/syslog`, `HKLM\Software` |
| 주의 | 공백을 허용하므로 `C:\Program Files\...` 뒤의 산문까지 삼킨다 |

공백이 문제라면 공백을 제외한 변형을 쓴다. 대신 `Program Files`가 중간에 끊긴다.

```text
[A-Za-z]:\\[^\s"<>|]*
```

**공백을 포함한 경로를 정확히 잡는 유일하게 안전한 방법은 인용부호를 기준으로 삼는 것이다.**

```text
"([A-Za-z]:\\[^"]+)"
```

### 패턴 2 — UNC

```text
\\\\[A-Za-z0-9._-]+\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `\\FILESRV01\share\a.exe`, `\\10.0.0.5\C$\Windows`, `\\srv.corp.local\dfs\x` |
| 매칭 안 됨 | `\\?\C:\x` (호스트 자리에 `?` 불가), `\\.\C:` |
| 포렌식 의미 | 원격 실행/확산, 관리 공유(`C$`, `ADMIN$`, `IPC$`) 접근 |

관리 공유만 따로 본다.

```text
(?i)\\\\[^\\]+\\(?:ADMIN\$|IPC\$|[A-Z]\$)(?:\\|\b)
```

### 패턴 3 — 확장 길이 접두

```text
\\\\\?\\(?:UNC\\)?
```

백슬래시 5개 + `\?` + 백슬래시 2개다. `\\?\`라는 **4글자**를 매칭하는 데 정규식 소스에서 8글자가 필요하다. 이 지점에서 대부분 틀린다.

| 리터럴 | 정규식 소스 | 길이 |
| --- | --- | --- |
| `\\` | `\\\\` | 4 |
| `\\?\` | `\\\\\?\\` | 8 |
| `\\.\` | `\\\\\.\\` | 8 |
| `\\?\UNC\` | `\\\\\?\\UNC\\` | 13 |

`MAX_PATH`는 260자(널 종료 포함)다. `\\?\`를 붙이면 약 32,767자까지 쓸 수 있고, 경로 정규화(후행 공백/점 제거, `.`·`..` 해석, `/`→`\` 변환)를 **건너뛴다**. 그래서 `\\?\C:\case\a..`처럼 정상 API로는 만들 수 없는 이름이 존재할 수 있다.

### 패턴 4 — 명령행에서 실행 파일 경로만

```text
(?i)(?:[A-Za-z]:\\|\\\\)[^"\s]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|com|pif|msi|msc|cpl|sys)\b
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `C:\Users\hong\AppData\Local\Temp\upd.exe`, `\\SRV\s\p.ps1` |
| 매칭 안 됨 | `cmd.exe` (경로 없는 이름만), `"C:\Program Files\a b.exe"` (공백) |
| 짝 패턴 | 인용부호 버전 `"([^"]+\.(?:exe\|dll\|ps1))"` 를 함께 돌린다 |

경로 없이 파일명만 나오는 경우(`cmd.exe /c ...`)를 놓치므로, 이름만 잡는 패턴을 별도로 돌린다.

```text
(?i)\b[\w.$-]+\.(?:exe|dll|ps1|bat|cmd|vbs|hta|scr)\b
```

### 패턴 5 — 의심 경로 (가장 실전적)

정상 프로그램은 `C:\Program Files`, `C:\Windows\System32`에서 실행된다. **아래 경로에서 실행 파일이 돌면 그 자체가 신호다.**

```text
(?i)[A-Za-z]:\\(?:Windows\\Temp|Windows\\Tasks|ProgramData|Users\\Public|PerfLogs|Recovery|\$Recycle\.Bin|Users\\[^\\]+\\(?:AppData\\(?:Local|Roaming|LocalLow)|Downloads|Favorites|Music|Pictures|Videos))\\
```

| 경로 | 정상 용도 | 공격에서의 용도 |
| --- | --- | --- |
| `C:\Windows\Temp` | 설치 프로그램 임시 파일 | SYSTEM 권한 페이로드 드롭. **가장 흔하다** |
| `C:\Users\<u>\AppData\Local\Temp` | 브라우저·오피스 임시 파일 | 메일/문서 첨부 실행, 압축 해제 후 실행 |
| `C:\Users\<u>\AppData\Roaming` | 애플리케이션 설정 | 지속성(Run 키 대상), 사용자 권한 상주 |
| `C:\ProgramData` | 전 사용자 공용 데이터 | ACL이 느슨해 쓰기 가능. 상주 |
| `C:\Users\Public` | 공용 문서 | 전 사용자 접근 가능. 측면 이동 스테이징 |
| `C:\PerfLogs` | 성능 로그(보통 빈 폴더) | **정상적으로는 비어 있다.** 파일이 있으면 의심 |
| `C:\Windows\Tasks`, `C:\Windows\System32\Tasks` | 작업 스케줄러 | 작업 등록 지속성 |
| `C:\$Recycle.Bin` | 휴지통 | 삭제된 것처럼 숨기기 |
| `C:\Windows\System32\spool\drivers\color` | 색 프로파일 | System32 하위인데 쓰기 가능. 우회 스테이징 |

### 백슬래시를 몇 개 쓰는가 — 언어별 표

**규칙 하나만 기억한다: 정규식 엔진에 `\\` 2글자가 도달해야 한다.** 문자열 리터럴이 백슬래시를 이스케이프 문자로 취급하면 2배로 쓴다.

| 컨텍스트 | 백슬래시 1개를 매칭하려면 | 엔진이 받는 것 |
| --- | --- | --- |
| `grep -E '...'` (셸 작은따옴표) | `\\` | `\\` |
| `grep -E "..."` (셸 큰따옴표) | `\\\\` | `\\` |
| `grep -F` / `-SimpleMatch` | `\` (정규식 아님) | 해당 없음 |
| PowerShell `'...'` **(권장)** | `\\` | `\\` |
| PowerShell `"..."` | `\\` | `\\` |
| Python `r'...'` **(권장)** | `\\` | `\\` |
| Python `'...'` | `\\\\` | `\\` |
| JSON 파일 (Sigma 룰, 설정) | `\\\\` | `\\` |
| JavaScript `/.../` 리터럴 | `\\` | `\\` |
| JavaScript `new RegExp('...')` | `\\\\` | `\\` |
| YAML 큰따옴표 | `\\\\` | `\\` |
| YAML 작은따옴표 | `\\` | `\\` |

PowerShell은 백슬래시가 이스케이프 문자가 아니다(백틱 `` ` ``이 이스케이프다). 그래서 큰따옴표에서도 2개면 된다. 대신 큰따옴표 안의 `$`는 **변수로 확장**되므로 `$Recycle.Bin`·`$MFT`가 들어가는 경로와 정규식은 **항상 작은따옴표**로 감싼다.

Windows 경로를 정규식으로 쓸 필요가 없을 때는 아예 이스케이프를 언어에 맡긴다.

```python
import re
lit = re.escape(r'C:\Users\hong\AppData\Local\Temp')   # 자동 이스케이프
```

```powershell
$pat = [regex]::Escape('C:\Users\hong\AppData\Local\Temp')
```

## 빠른 명령

```bash
grep -Eio '[a-z]:\\\\[^"<>|]+' cmdline.txt | sort -u
```

```bash
# 1) 드라이브 절대경로 후보 전부 (셸 작은따옴표 -> 백슬래시 2개)
grep -Eio '[a-z]:\\[^"<>|]+' cmdline.txt | sort -u

# 2) 실행 파일 경로만
grep -Eio '(?:[a-z]:\\|\\\\)[^"[:space:]]*\.(exe|dll|ps1|bat|cmd|vbs|hta|scr)' cmdline.txt |
  sort | uniq -c | sort -nr

# 3) UNC 경로 (관리 공유 포함)
grep -Eio '\\\\[a-z0-9._-]+\\[^\\/:*?"<>|]+' cmdline.txt | sort -u

# 4) 확장 길이 접두 -- 정상 로그에는 거의 없다
grep -F '\\?\' cmdline.txt

# 5) 의심 경로에서 실행된 것만
grep -Eio '[a-z]:\\(windows\\temp|programdata|users\\public|perflogs|users\\[^\\]+\\appdata\\(local|roaming))\\[^"[:space:]]*' cmdline.txt |
  sort | uniq -c | sort -nr

# 6) 환경변수 형태 (확장 전)
grep -Eo '%[A-Za-z_][A-Za-z0-9_()]*%' cmdline.txt | sort | uniq -c | sort -nr

# 7) 예약 이름 오용
grep -Eiow '(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.[a-z0-9]+)?' cmdline.txt

# 8) ripgrep -- PCRE2 로 lookaround까지
rg -oiP '(?<=")[a-z]:\\[^"]+(?=")' cmdline.txt
```

`grep -E`에서 백슬래시를 4개 쓰는 것과 2개 쓰는 것을 헷갈리면 아무것도 안 잡힌다. **작은따옴표를 쓰면 항상 2개다.**

```powershell
# 실행 파일 경로 + 빈도 (정규식은 작은따옴표)
Select-String -Path .\cmdline.txt -AllMatches -Pattern '(?i)(?:[a-z]:\\|\\\\)[^"\s]*\.(?:exe|dll|ps1|bat|cmd|vbs|hta|scr)' |
  ForEach-Object { $_.Matches.Value } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 20 Count, Name

# 의심 경로만
$susp = '(?i)[a-z]:\\(?:Windows\\Temp|ProgramData|Users\\Public|PerfLogs|Users\\[^\\]+\\AppData\\(?:Local|Roaming))\\'
Select-String -Path .\cmdline.txt -Pattern $susp

# 인용부호로 감싸인 경로 (공백 포함 경로를 정확히 뽑는 방법)
Select-String -Path .\cmdline.txt -AllMatches -Pattern '"([a-z]:\\[^"]+)"' |
  ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique

# NTFS 메타파일이 들어가는 경로는 반드시 작은따옴표
Get-Item -LiteralPath 'C:\$Recycle.Bin' -Force

# 경로 정규화는 정규식보다 .NET 이 정확하다
[System.IO.Path]::GetFullPath('C:\Windows\..\Windows\System32\cmd.exe')
[System.IO.Path]::GetFileName('C:\Users\hong\AppData\Local\Temp\upd.exe')
```

```python
import re
from collections import Counter

WIN_ABS   = re.compile(r'(?i)[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
WIN_EXE   = re.compile(r'(?i)(?:[a-z]:\\|\\\\)[^"\s]*\.(?:exe|dll|ps1|bat|cmd|vbs|hta|scr)')
UNC       = re.compile(r'(?i)\\\\[a-z0-9._-]+\\[^\\/:*?"<>|\r\n]+')
EXTLEN    = re.compile(r'\\\\\?\\(?:UNC\\)?')
SUSPECT   = re.compile(
    r'(?i)[a-z]:\\(?:Windows\\Temp|Windows\\Tasks|ProgramData|Users\\Public|PerfLogs'
    r'|\$Recycle\.Bin|Users\\[^\\]+\\AppData\\(?:Local|Roaming|LocalLow))\\'
)
ENVVAR    = re.compile(r'%[A-Za-z_][A-Za-z0-9_()]*%')

text = open('cmdline.txt', encoding='utf-8', errors='replace').read()

# 실행 파일 경로 빈도
for p, n in Counter(m.lower() for m in WIN_EXE.findall(text)).most_common(20):
    print(f'{n:6d}  {p}')

# 의심 경로가 들어간 줄만
for line in text.splitlines():
    if SUSPECT.search(line):
        print(line)

# 경로 분해는 정규식이 아니라 ntpath 로
import ntpath
p = r'C:\Users\hong\AppData\Local\Temp\upd.exe'
print(ntpath.dirname(p), ntpath.basename(p), ntpath.splitext(p)[1])
```

`re.escape()`와 `ntpath`를 쓰면 백슬래시 개수를 세지 않아도 된다. **정규식은 "찾을 때"만 쓰고, "분해할 때"는 경로 라이브러리를 쓴다.**

## 함께 보는 artifact

| 경로에서 얻은 것 | 다음 목표 |
| --- | --- |
| `C:\...\Temp\upd.exe` 같은 실행 경로 | Prefetch·Amcache·ShimCache로 실행 시각 확정 |
| 실행 파일명 | 4688 / Sysmon Event 1 ([FOR-0088](./event-4688-process-creation.html)) |
| 파일 생성 경로 | `$MFT` ([FOR-0021](./mft-basics.html))로 디스크상 생성/수정 시각 |
| UNC `\\HOST\C$` | 4624 Logon Type 3 + 공유 접근 ([FOR-0083](./event-4624-logon.html)) |
| `AppData\Roaming` 상주 파일 | Run/RunOnce 레지스트리 ([FOR-0063](./run-runonce.html)) |
| `\\?\` 접두 파일 | 탐색기로 못 보는 파일. `dir /a`와 `$MFT`로 확인 |
| 다운로드 경로 | 브라우저 다운로드 DB, Zone.Identifier ADS ([FOR-0035](./alternate-data-streams.html)) |
| Linux 쪽 경로가 섞여 있다 | 컨테이너/WSL 여부 확인 |

## 흔한 실수

- **백슬래시를 2개 쓸 자리에 1개를 쓰는 것.** `C:\Windows`를 정규식 `C:\Windows`로 검색하면 `\W`가 "단어 문자가 아닌 것"으로 해석되어 엉뚱한 것이 잡힌다. `\d` `\s` `\b` `\t` `\n` 도 같은 사고를 낸다 — `\temp`는 탭+`emp`다.
- **셸 큰따옴표에서 개수를 안 늘리는 것.** `grep -E "C:\\Windows"`는 셸이 `\\`를 `\`로 줄여 정규식에 `\W`가 도달한다. 작은따옴표를 쓰거나 4개로 늘린다.
- **공백을 허용하는 패턴으로 뒤의 산문까지 삼키는 것.** `C:\Program Files\App\a.exe was launched by ...` 전체가 한 매칭이 된다. 인용부호 기준(`"([A-Za-z]:\\[^"]+)"`)이나 확장자 앵커(`\.exe\b`)로 끝을 고정한다.
- **UNC를 `\\\\`로만 시작 판정하는 것.** `\\?\`와 `\\.\`도 백슬래시 2개로 시작한다. 호스트 자리에 `?`/`.`이 오는 경우를 먼저 제외(`\\\\(?![?.]\\)`)해야 한다.
- **대소문자를 구분하는 것.** Windows 경로는 대소문자를 구분하지 않는다. 로그에는 `C:\WINDOWS\system32\CMD.EXE`가 섞여 나오므로 `(?i)`나 `grep -i`가 필수다. 반대로 `Select-String`은 기본이 대소문자 무시라 `-CaseSensitive`를 잘못 켜면 놓친다.
- **환경변수 형태를 무시하는 것.** `%TEMP%\a.exe`와 `C:\Users\hong\AppData\Local\Temp\a.exe`는 같은 파일이지만 정규식으로는 전혀 다르다. 두 패턴을 모두 돌리고 결과를 합친다.
- **`/`를 구분자로 쓴 경로를 놓치는 것.** Win32 API가 `C:/Windows/System32`를 받아주므로 스크립트·JSON 설정·웹 로그에 실제로 등장한다. `[\\/]`로 받는다.
- **후행 공백·점을 정규식이 잘라주리라 기대하는 것.** 정규식은 아무것도 정규화하지 않는다. `evil.exe `와 `evil.exe`는 다른 문자열이므로 `\s*$`로 명시해 흡수하거나 비교 전에 `TrimEnd()` 한다.
- **`$` 들어간 경로를 PowerShell 큰따옴표에 넣는 것.** `"C:\$Recycle.Bin"`은 `$Recycle` 변수로 확장되어 경로가 `C:\.Bin`이 된다. 명령이 조용히 실패한다. `'C:\$Recycle.Bin'`으로 쓴다. 관리 공유 `C$`도 같은 이유로 작은따옴표를 쓴다.
- **경로 분해를 정규식으로 하는 것.** 디렉터리/파일명/확장자 분리는 `ntpath`, `[System.IO.Path]`, `Split-Path`가 정확하다. 정규식은 "찾기"용이다.
- **8.3 단축 이름을 놓치는 것.** `C:\PROGRA~1\...`, `C:\Users\hong\AppDa~1\...` 형태가 로그에 남는다. `~\d` 를 포함한 이름을 따로 검색한다.

## mini example

```text
문제:
"침해 서버의 프로세스 생성 명령행 덤프(cmdline.txt, 24,180줄)에서
 정상 프로그램 디렉터리 밖에서 실행된 실행 파일의 전체 경로를 구하세요."

1. 형식 확인
   $ head -2 cmdline.txt
   2026-03-14T07:19:02+09:00 4688 SYSTEM "C:\Windows\System32\svchost.exe -k netsvcs"
   2026-03-14T07:19:44+09:00 4688 CORP\hong "C:\Program Files\Google\Chrome\Application\chrome.exe"

2. 첫 시도 (실패):
   $ grep -Eo 'C:\Windows' cmdline.txt | head -3
   (0건)

   이유: 정규식 엔진이 받은 것은 `C:\Windows` 이고 `\W` 는 "단어 문자가 아닌 것" 이다.
        `C:` 뒤에 비단어 문자 + `indows` 를 찾으므로 실제 경로와 맞지 않는다.
        백슬래시를 2개 써야 한다.

   $ grep -Eo 'C:\\Windows' cmdline.txt | wc -l
   18042
   -> 정상 동작.

3. 두 번째 시도 (부분 실패) -- 실행 파일 경로 전체를 뽑으려 했다
   $ grep -Eio '[a-z]:\\[^"]+' cmdline.txt | head -3
   C:\Windows\System32\svchost.exe -k netsvcs
   C:\Program Files\Google\Chrome\Application\chrome.exe
   C:\Windows\System32\cmd.exe /c whoami

   인자까지 붙어 나왔다. `[^"]+` 가 공백을 허용하기 때문이다.

4. 접근 변경 -- 확장자로 끝을 고정
   $ grep -Eio '[a-z]:\\[^"]*?\.(exe|dll|ps1|bat|cmd|vbs|hta|scr)' cmdline.txt |
       tr 'A-Z' 'a-z' | sort | uniq -c | sort -nr | head -5
     18042 c:\windows\system32\svchost.exe
      2210 c:\program files\google\chrome\application\chrome.exe
      1904 c:\windows\system32\cmd.exe
       311 c:\windows\explorer.exe
        14 c:\programdata\intel\driverupdate.exe

   `-Eio` 의 `-o` 는 게으른 수량자가 없는 ERE 에서는 최장 일치를 하므로,
   실제로는 grep -P 또는 다음처럼 공백 제외 클래스를 쓰는 편이 안전하다.

   $ grep -Eio '[a-z]:\\[^"[:space:]]*\.(exe|dll|ps1)' cmdline.txt | sort -u | wc -l
   187

5. 정상 디렉터리를 제외 -- 의심 경로만 남긴다
   $ grep -Eio '[a-z]:\\[^"[:space:]]*\.(exe|dll|ps1|bat|cmd|vbs|hta|scr)' cmdline.txt |
       tr 'A-Z' 'a-z' |
       grep -Ev '^c:\\(windows\\(system32|syswow64|winsxs)|program files( \(x86\))?)\\' |
       sort | uniq -c | sort -nr
        14 c:\programdata\intel\driverupdate.exe
         6 c:\users\hong\appdata\local\temp\upd.exe
         3 c:\users\public\p.ps1
         1 c:\windows\temp\a.dll

6. 원문에서 문맥 확인
   $ grep -i 'driverupdate.exe' cmdline.txt | head -2
   2026-03-14T07:31:20+09:00 4688 NT AUTHORITY\SYSTEM "C:\ProgramData\Intel\DriverUpdate.exe -s"
   2026-03-14T07:31:21+09:00 4688 NT AUTHORITY\SYSTEM "cmd.exe /c schtasks /create /tn IntelUpd /tr C:\ProgramData\Intel\DriverUpdate.exe /sc minute /mo 30"

   `C:\ProgramData` 는 정상 프로그램의 실행 위치가 아니고,
   `Intel` 이라는 이름과 달리 30분 주기 작업으로 등록되어 있다.

7. 교차검증 -- 환경변수 형태로도 남았는지
   $ grep -Eio '%[a-z_][a-z0-9_()]*%[^"[:space:]]*' cmdline.txt | sort -u
   %ComSpec%
   %ProgramData%\Intel\DriverUpdate.exe
   %TEMP%\upd.exe

   같은 파일이 확장 전 형태로도 존재한다. 5단계 목록만 봤다면 이 줄들을 놓쳤다.

정답: C:\ProgramData\Intel\DriverUpdate.exe
      (보조 흔적: C:\Users\hong\AppData\Local\Temp\upd.exe, C:\Users\Public\p.ps1)
```

2단계와 3단계가 핵심이다. **백슬래시는 2개, 경로의 끝은 확장자나 인용부호로 고정한다.** 그리고 7단계처럼 `%TEMP%` 형태를 별도로 한 번 더 훑지 않으면 같은 파일의 절반을 놓친다.

## 출처

- SRC-079 — Microsoft Learn, Naming Files, Paths, and Namespaces: 금지 문자 목록, 예약 이름(CON/PRN/AUX/NUL/COM/LPT), `MAX_PATH` 260, `\\?\` 확장 길이 접두와 정규화 생략, `\\.\` 장치 네임스페이스, 후행 공백·점 처리
- SRC-057 — Python 문서, `re`: `re.escape()`, raw string 표기, 문자 클래스와 lookaround 동작
- 예약 이름 목록은 Windows 버전에 따라 `COM0`/`LPT0`와 상위 문자 변형이 추가로 명시되는 경우가 있으므로 대상 시스템의 MS 문서 원문에서 확인할 것
- `%TEMP%` 등 환경변수의 확장 결과는 프로필·정책·실행 컨텍스트(SYSTEM vs 사용자)에 따라 달라지므로 대상 시스템의 실제 값으로 확인할 것
- 표에 정리한 "정상적으로는 비어 있는 디렉터리"(`C:\PerfLogs` 등)는 설치된 소프트웨어에 따라 예외가 있으므로 기준선과 비교할 것
