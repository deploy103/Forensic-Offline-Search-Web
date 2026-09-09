---
id: FOR-0063
title: "Run·RunOnce와 자동실행 지속성 레지스트리 키 전수 점검"
slug: "run-runonce"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Run", "RunOnce", "Winlogon", "Image File Execution Options", "AppInit_DLLs", "Services", "TaskCache", "Startup 폴더"]
file_paths: ["C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Users\\<user>\\NTUSER.DAT", "C:\\Windows\\System32\\Tasks", "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"]
registry_paths: ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit", "SYSTEM\\CurrentControlSet\\Services", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjectDelayLoad", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "RECmd", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r SOFTWARE -p run", "rip.exe -r NTUSER.DAT -p run", "rip.exe -r SYSTEM -p services", "rip.exe -r SOFTWARE -p winlogon"]
regex_patterns: ["(?i)(powershell|pwsh).{0,40}(-enc|-e |-ec|frombase64string)", "(?i)(rundll32|mshta|regsvr32|wscript|cscript|msbuild)\\.exe"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ImagePath", "ServiceDll", "Start", "Userinit", "Shell", "Debugger", "AppInit_DLLs", "Load", "LastWrite"]
file_formats: ["regf"]
primary_terms: ["Run", "RunOnce", "자동실행", "지속성 레지스트리"]
keywords: ["Run", "RunOnce", "자동실행", "지속성", "persistence", "Winlogon", "Userinit", "Image File Execution Options", "IFEO", "Debugger", "AppInit_DLLs", "RunServices", "Policies Explorer Run", "BootExecute", "시작 폴더"]
aliases: ["자동실행 레지스트리", "run 키", "runonce", "부팅 시 실행", "악성코드 지속성", "persistence 키", "시작프로그램 레지스트리", "ifeo 하이재킹"]
symptom_keywords: ["재부팅해도 악성코드가 살아난다", "부팅할 때 뭐가 실행되는지 알고 싶다", "지속성 흔적을 찾아야 한다", "자동실행 항목을 전부 보고 싶다", "시작프로그램에 이상한 게 있다", "언제 등록됐는지 알고 싶다"]
related: ["FOR-0051", "FOR-0053", "FOR-0055", "FOR-0061"]
source_ids: ["SRC-017", "SRC-086", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

자동실행 지속성은 `Run`·`RunOnce` 두 키만 보면 절반을 놓친다. `Policies\Explorer\Run`, `Winlogon`의 `Userinit`/`Shell`, `Windows NT\CurrentVersion\Windows`의 `Load`/`Run`, `Image File Execution Options`의 `Debugger`, `AppInit_DLLs`, `Services`의 `Start=2`, 그리고 `WOW6432Node`까지 **전수 표대로** 훑어야 한다.

## 어떤 문제에서 필요한가

- "재부팅 후에도 악성코드가 다시 실행되는 이유는 무엇인가"
- "지속성(persistence)이 어디에 등록되어 있는가"
- "그 항목이 언제 등록되었는가"
- "정상 프로그램으로 위장한 자동실행 항목을 찾아라"

레지스트리 자동실행은 MITRE ATT&CK의 T1547.001(Registry Run Keys / Startup Folder), T1546.012(IFEO Injection), T1546.010(AppInit DLLs), T1547.004(Winlogon Helper DLL), T1543.003(Windows Service)에 대응한다. 문제 지문에 "지속성", "재부팅", "자동으로 실행"이 있으면 이 표가 답의 위치다.

## 문제에서 처음 볼 단서

1. 첨부에 `SOFTWARE`, `SYSTEM`, `NTUSER.DAT` 세 hive가 함께 있다 → 자동실행 전수 점검 대상
2. 지문에 "재부팅", "로그온할 때마다", "지속성", "startup"
3. 다른 artifact에서 나온 악성 실행 파일 경로가 있는데 **어떻게 실행되었는지**가 비어 있는 상황
4. 값 데이터에 `powershell -enc`, `rundll32`, `mshta`, `regsvr32`, 인용 없는 `C:\Program Files\...` 경로가 보인다

## 30초 절차

```powershell
rip.exe -r "C:\case\SOFTWARE" -p run > run_software.txt
```

사용자 키와 서비스까지 한 번에.

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p run    > run_user.txt
rip.exe -r "C:\case\SOFTWARE"   -p winlogon > winlogon.txt
rip.exe -r "C:\case\SYSTEM"     -p services > services.txt
```

GUI라면 RegistryExplorer로 hive를 열고 아래 표의 경로를 순서대로 찍는다. 대량이면 RECmd 배치 파일로 한 번에 뽑는다.

## 상세 절차

### 1단계 — 자동실행 지속성 키 전수 표

hive 파일명 기준으로 적었다. 실행 중 시스템의 `HKLM\SOFTWARE\...`는 `SOFTWARE` hive, `HKCU\Software\...`는 그 사용자의 `NTUSER.DAT`이다.

| 위치 | 키 / 값 | 트리거 | 비고 |
| --- | --- | --- | --- |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 로그온 | 가장 흔한 1순위 |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | 로그온 1회 | 실행 후 값이 삭제되므로 **LastWrite만 남는 경우**가 있다 |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices` | 부팅(레거시) | 9x 계열 잔재. 있으면 그 자체로 의심 |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce` | 부팅 1회(레거시) | 위와 동일 |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx` | 로그온 1회 | `Depend` 서브키로 DLL 로드 가능 |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\Run` | 로그온 | 관리자 권한 없이 등록 가능 → 실전 최다 |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\RunOnce` | 로그온 1회 | |
| HKLM/HKCU | `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | 로그온 | **정책 경로라 시작프로그램 UI에 안 보인다.** 은닉 목적 |
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` → `Userinit` | 로그온 | 정상값은 `userinit.exe,` 로 끝난다. 콤마 뒤 추가 항목이 하이재킹 |
| HKLM | `...\Winlogon` → `Shell` | 로그온 | 정상값은 `explorer.exe`. 다른 값이면 쉘 교체 |
| HKLM | `...\Winlogon` → `Notify` | 로그온(레거시) | Vista 이전. 존재 자체가 이상 신호 |
| HKLM | `...\Winlogon` → `Taskman` | 로그온 | 작업 관리자 교체 |
| HKLM/HKCU | `Software\Microsoft\Windows NT\CurrentVersion\Windows` → `Load` | 로그온 | 원래는 거의 비어 있다 |
| HKLM/HKCU | `Software\Microsoft\Windows NT\CurrentVersion\Windows` → `Run` | 로그온 | 위와 동일. `CurrentVersion\Run`과 **다른 키**다 |
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` → `AppInit_DLLs` | 모든 user32.dll 로드 프로세스 | `LoadAppInit_DLLs`=1 이어야 동작 |
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` → `Debugger` | 그 exe 실행 시 | **디버거 하이재킹.** `sethc.exe`, `taskmgr.exe`, `notepad.exe` 대상이 흔함 |
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<exe>` → `MonitorProcess` | 그 exe 종료 시 | IFEO 사촌. `GlobalFlag`와 함께 본다 |
| HKLM | `SYSTEM\CurrentControlSet\Services\<name>` → `Start`, `ImagePath` | 부팅/요청 | `Start=2`가 자동 시작 |
| HKLM | `SYSTEM\CurrentControlSet\Services\<name>\Parameters` → `ServiceDll` | svchost 로드 | `ImagePath`가 `svchost.exe -k ...`면 실체는 여기 |
| HKLM | `SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` | 커널 초기화 | 정상값은 `autocheck autochk *` |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad` | Explorer 시작 | CLSID로 DLL 로드 |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects` | IE 시작 | 레거시 BHO |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler` | Explorer 시작 | |
| HKLM/HKCU | `Software\Classes\*\shellex\ContextMenuHandlers` | 우클릭/쉘 확장 | Shell Extension 지속성 |
| HKCU | `Software\Classes\CLSID\{...}\InProcServer32` | COM 호출 시 | **COM 하이재킹.** HKCU가 HKLM보다 우선 조회된다 |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` → `Startup` | 로그온 | 시작 폴더 **경로 자체를 바꿔** 은닉 |
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` | 스케줄 | 작업 스케줄러의 레지스트리 측 인덱스 |

### 2단계 — WOW6432Node를 반드시 함께 본다

64비트 Windows에서 **32비트 프로세스가 쓴** `HKLM\SOFTWARE\...` 값은 실제로 `HKLM\SOFTWARE\WOW6432Node\...`에 저장된다(레지스트리 리다이렉션).

```text
64비트 항목: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
32비트 항목: SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

`RunOnce`, `Policies\Explorer\Run`, `Image File Execution Options`, `Windows NT\CurrentVersion\Windows` 모두 `WOW6432Node` 대응 경로가 있다. 32비트 악성코드는 여기에만 남아 **64비트 경로만 본 분석에서는 통째로 누락된다.** 리다이렉션의 배경은 [FOR-0055](./software-installed-programs.html)에서 다룬다.

### 3단계 — 값 데이터의 의심 신호

값 이름은 아무 문자열이나 가능하므로(정상 이름 위장이 쉽다) **판단은 값 데이터로 한다.**

| 신호 | 예 | 왜 의심스러운가 |
| --- | --- | --- |
| 사용자/임시 경로 | `C:\Users\jhkim\AppData\Local\Temp\svchost.exe` | 정상 자동실행은 대개 `Program Files`·`Windows`에 있다 |
| `AppData`·`ProgramData` | `C:\ProgramData\update\run.exe` | 권한 없이 쓸 수 있는 폴더 |
| 시스템 파일명 위장 | `C:\Users\...\lsass.exe` | 정상 `lsass.exe`는 `System32`에만 있다 |
| 인용 없는 공백 경로 | `C:\Program Files\My App\app.exe` (따옴표 없음) | unquoted service path 하이재킹 여지 |
| PowerShell 인코딩 | `powershell -nop -w hidden -enc SQBFAFgA...` | Base64 명령. `-enc`/`-e`/`-ec` 모두 같은 축약 |
| LOLBin 로더 | `rundll32.exe C:\...\a.dll,Start` | DLL을 서명된 바이너리로 실행 |
| `mshta` | `mshta.exe javascript:...` / `mshta http://...` | HTA/스크립트 실행, 원격 로드 |
| `regsvr32` | `regsvr32 /s /u /i:http://... scrobj.dll` | Squiblydoo. 원격 스크립트 실행 |
| `wscript`/`cscript` | `wscript.exe C:\Users\...\a.vbs` | 스크립트 지속성 |
| URL 직접 등장 | `http://`, `https://`, `\\1.2.3.4\share\` | 원격 페이로드 또는 UNC 실행 |
| 이중 확장자 | `report.pdf.exe` | 사용자 속임 |
| 랜덤 문자열 | `C:\Windows\Temp\a8f3d2.exe` | 드롭퍼 관례 |

정규식으로 훑을 때는 PowerShell에서 **작은따옴표**를 쓴다. 큰따옴표 안의 `$`는 변수로 확장된다.

```powershell
# 자동실행 덤프 전체에서 의심 신호만 뽑기
Select-String -Path .\run_*.txt, .\winlogon.txt, .\services.txt `
  -Pattern '(?i)(powershell|pwsh).{0,40}(-enc|-e |-ec|frombase64string)'

Select-String -Path .\run_*.txt -Pattern '(?i)(rundll32|mshta|regsvr32|wscript|cscript|msbuild)\.exe'

Select-String -Path .\run_*.txt -Pattern '(?i)\\(Temp|AppData|ProgramData)\\'
```

### 4단계 — Winlogon 정상값과 비교

| 값 | 정상 데이터 | 하이재킹 형태 |
| --- | --- | --- |
| `Userinit` | `C:\Windows\system32\userinit.exe,` | `...userinit.exe,C:\Users\...\evil.exe` (콤마 뒤 추가) |
| `Shell` | `explorer.exe` | `explorer.exe,evil.exe` 또는 아예 다른 exe |
| `Taskman` | 값 자체가 없음 | 임의 exe 지정 |
| `Notify` | 최신 Windows에는 서브키 없음 | 서브키 존재 = 레거시 또는 조작 |

`Userinit` 끝의 **콤마 하나**를 놓치기 쉽다. 정상값도 콤마로 끝나므로, 콤마 뒤에 무엇이 있는지가 판단 기준이다.

### 5단계 — Services에서 자동 시작만 걸러내기

`SYSTEM\CurrentControlSet\Services\<name>`의 `Start` 값이 시작 방식이다. 어느 ControlSet이 활성인지는 [FOR-0053](./system-controlset.html)의 `Select` 키로 먼저 확인한다.

| `Start` | 의미 |
| --- | --- |
| `0` | Boot (부트 드라이버) |
| `1` | System (커널 초기화) |
| `2` | **Automatic (부팅 시 자동 시작)** |
| `3` | Manual (요청 시) |
| `4` | Disabled |

| `Type` | 의미 |
| --- | --- |
| `0x01` | 커널 드라이버 |
| `0x02` | 파일시스템 드라이버 |
| `0x10` | 자체 프로세스 서비스 |
| `0x20` | 공유 프로세스 서비스(svchost) |

```powershell
rip.exe -r "C:\case\SYSTEM" -p services > services.txt
Select-String -Path .\services.txt -Pattern '(?i)\\(Temp|AppData|ProgramData|Users)\\'
```

`ImagePath`가 `%SystemRoot%\System32\svchost.exe -k netsvcs`처럼 svchost 호스팅이면 실제 코드는 `Parameters\ServiceDll`에 있다. **`ImagePath`만 보고 정상이라고 판단하면 안 된다.**

### 6단계 — IFEO Debugger 확인

```text
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe
  Debugger = C:\Windows\System32\cmd.exe
```

원래 이 키는 디버거를 붙이기 위한 정상 기능이다. 값 `Debugger`가 있으면 **그 exe를 실행할 때 지정된 프로그램이 대신 뜬다.** 접근성 도구(`sethc.exe`, `utilman.exe`, `osk.exe`)나 `taskmgr.exe` 아래 `Debugger`가 있으면 백도어로 본다. `Image File Execution Options`의 대부분 서브키는 `GlobalFlag`·`MitigationOptions`만 가진 정상 항목이므로, **`Debugger` 값이 있는 서브키만** 추린다.

### 7단계 — 등록 시각은 키 LastWrite로 추정

레지스트리 값에는 개별 타임스탬프가 없다. 있는 것은 **키 단위 LastWrite(FILETIME, UTC)** 하나다.

```text
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time: 2026-03-14 07:15:44Z
  OneDrive        = "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background
  SecurityUpdate  = C:\Users\jhkim\AppData\Local\Temp\svcupd.exe
```

LastWrite `2026-03-14 07:15:44Z`는 **이 키에 마지막으로 가해진 변경**의 시각이다. 값이 하나만 수상하면 그 값의 등록 시각으로 볼 여지가 크지만, 여러 값이 있으면 어느 값이 그때 바뀐 것인지는 레지스트리만으로 알 수 없다. FILETIME은 1601-01-01 UTC 기준 100ns이고 Unix epoch와의 차이는 `11644473600`초, KST는 +9시간이다.

## 출력 필드 해석

| 필드 | 해석 | 주의 |
| --- | --- | --- |
| 값 이름 | 표시용 라벨. 아무 문자열이나 가능 | `Windows Update`처럼 정상 위장이 쉽다. 판단 근거로 쓰지 않는다 |
| 값 데이터 | 실제 실행되는 명령행 | 인자 포함. 여기가 핵심 |
| `Userinit` | 로그온 시 실행 체인 | 콤마 뒤 추가 항목 확인 |
| `Shell` | 사용자 쉘 | `explorer.exe` 외의 값은 즉시 의심 |
| `Debugger` (IFEO) | 대상 exe 대신 실행될 프로그램 | 존재 자체가 강한 신호 |
| `AppInit_DLLs` | 전역 로드 DLL 목록 | `LoadAppInit_DLLs`가 0이면 미동작 |
| `Start` (Services) | 시작 방식 | `2`가 자동 |
| `ImagePath` | 서비스 실행 파일 | svchost면 `ServiceDll`을 봐야 한다 |
| 키 `LastWrite` | 마지막 변경 시각(UTC) | 값별 시각은 없다 |

## pivot: 다음에 볼 artifact

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 자동실행 실행 파일 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일 생성 시각, 현재 존재 여부, timestomp 흔적 |
| 실행 파일명 | Prefetch (`C:\Windows\Prefetch`) | 실제로 실행됐는가, 몇 번, 언제 |
| 실행 파일명 | Amcache (`Amcache.hve`) | SHA-1 해시, 최초 등록 시각 |
| 키 LastWrite 시각 | EVTX Security 4688 ([FOR-0088](./event-4688-process-creation.html)) | 그 시각 전후의 프로세스 생성과 명령행 |
| 서비스 이름 | System 로그 7045 ([FOR-0090](./event-7045-service-install.html)) | 설치 시각과 실행 파일 |
| `powershell -enc` 값 | Base64 디코드 → PowerShell 4104 ([FOR-0097](./powershell-4104-scriptblock.html)) | 실제 스크립트 본문 |
| 값 데이터의 URL/UNC | PCAP·프록시 로그·DNS 캐시 | 페이로드 다운로드 통신 |
| 사용자가 등록했는가 | UserAssist ([FOR-0061](./userassist.html)) | 등록 도구를 사람이 실행했는지 |
| 레지스트리 밖 지속성 | `C:\Windows\System32\Tasks\*`, 시작 폴더 | XML 작업 정의, LNK |

## 흔한 함정

- **`Run`과 `RunOnce`만 보고 끝낸다.** 실전에서 가장 많이 놓치는 것이 `Policies\Explorer\Run`과 `Winlogon\Userinit`이다. 정책 경로는 시작프로그램 UI에도 안 나온다 → 위 전수 표를 순서대로 다 찍는다.
- **`WOW6432Node`를 건너뛴다.** 32비트 악성코드의 자동실행은 리다이렉션되어 여기에만 있다 → 모든 HKLM 경로에 대해 `WOW6432Node` 대응 경로를 함께 본다.
- **값 이름으로 정상 여부를 판단한다.** 값 이름은 공격자가 자유롭게 정한다. `Adobe Updater`라는 이름으로 `Temp\a.exe`를 등록할 수 있다 → 판단은 **값 데이터**로 한다.
- **`ImagePath`만 보고 서비스를 정상 처리한다.** `svchost.exe -k <group>`은 껍데기다. 실제 코드는 `Parameters\ServiceDll`이다 → svchost 서비스는 반드시 `ServiceDll`까지 확인한다.
- **`Image File Execution Options` 서브키가 많아서 포기한다.** 대부분은 `GlobalFlag`만 있는 정상 항목이다 → `Debugger` 값이 존재하는 서브키만 추리면 몇 개로 줄어든다.
- **`RunOnce`가 비어 있으니 없었다고 결론 낸다.** `RunOnce` 값은 실행 후 삭제되는 것이 정상 동작이다. **비어 있어도 키 LastWrite가 최근이면 무언가 실행되고 지워진 것**이다 → LastWrite와 `$UsnJrnl`·hive 슬랙을 함께 본다.
- **키 LastWrite를 "그 값의 등록 시각"으로 단정한다.** 값이 여러 개면 어느 값의 변경인지 알 수 없다 → 파일 생성 시각(`$MFT`)·Prefetch·EVTX로 좁힌다.
- **`Userinit`의 콤마를 놓친다.** 정상값도 `userinit.exe,`로 끝난다. 콤마 자체가 이상 신호가 아니라 **콤마 뒤의 내용**이 신호다.
- **`AppInit_DLLs`에 값이 있으면 무조건 실행됐다고 본다.** `LoadAppInit_DLLs`가 `0`이거나 Secure Boot 환경이면 로드되지 않는다 → 두 값을 같이 읽는다.
- **레지스트리만 본다.** 작업 스케줄러(`C:\Windows\System32\Tasks`의 XML), 시작 폴더 LNK, WMI 이벤트 구독은 레지스트리 Run 키에 없다 → 아래 절차를 함께 돌린다.
- **`ControlSet001`을 무조건 현재로 가정한다.** 활성 ControlSet은 `SYSTEM\Select`의 `Current` 값이 정한다 → 먼저 확인한다.
- **시간대를 안 맞춘다.** 키 LastWrite는 UTC다. 문제가 KST를 요구하면 +9시간.

## 교차검증

```powershell
# 1) 레지스트리 자동실행 — SOFTWARE / NTUSER.DAT / SYSTEM 세 hive 전부
rip.exe -r "C:\case\SOFTWARE"   -p run       > run_software.txt
rip.exe -r "C:\case\NTUSER.DAT" -p run       > run_user.txt
rip.exe -r "C:\case\SOFTWARE"   -p winlogon  > winlogon.txt
rip.exe -r "C:\case\SYSTEM"     -p services  > services.txt

# 2) 레지스트리 밖 지속성 — 작업 스케줄러 XML 과 시작 폴더
Get-ChildItem -Recurse 'C:\case\C\Windows\System32\Tasks' -File |
  Select-String -Pattern '(?i)(Temp|AppData|ProgramData|powershell|rundll32|mshta)'
Get-ChildItem -Recurse 'C:\case\C\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
Get-ChildItem -Recurse 'C:\case\C\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'

# 3) 실행 사실 — Prefetch
PECmd.exe -d "C:\case\C\Windows\Prefetch" --csv "C:\case\out"

# 4) 파일이 언제 생겼나 (NTFS 메타파일 경로는 반드시 작은따옴표)
MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
```

| 조합 결과 | 해석 |
| --- | --- |
| Run 키 O, Prefetch O, `$MFT` O | 등록·실행·파일 모두 확인. 결론 확정 |
| Run 키 O, Prefetch X | 등록만 되고 아직 실행되지 않았거나 Prefetch가 삭제·비활성 |
| Run 키 X, Prefetch O | 지속성이 스케줄러·서비스·시작 폴더 쪽이다 |
| Run 키 값 삭제, LastWrite만 최근 | `RunOnce` 실행 후 자동 삭제 또는 반포렌식 정리 |
| 여러 키에 같은 경로 | 다중 지속성. 하나만 지워도 살아난다 |

## mini walkthrough

```text
문제:
"재부팅 후에도 다시 실행되는 악성 프로그램의 실행 경로와, 그 지속성이
 등록된 레지스트리 키를 답하세요.
 첨부: SOFTWARE, SYSTEM, NTUSER.DAT (+ .LOG1/.LOG2), Prefetch 폴더"

1. 첫 시도 (실패)
   rip.exe -r SOFTWARE -p run > r.txt
   rip.exe -r NTUSER.DAT -p run >> r.txt

   HKLM\...\CurrentVersion\Run
     SecurityHealth = %windir%\system32\SecurityHealthSystray.exe
   HKCU\...\CurrentVersion\Run
     OneDrive = "C:\Users\jhkim\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background

   -> 전부 정상. "지속성 없음" 이라고 결론.

   왜 틀렸는가:
   Run/RunOnce 두 키만 봤다. 그리고 64비트 경로만 봤다.
   Prefetch 에는 명백히 낯선 실행 파일이 있으므로 결론이 모순이다.

2. 모순 확인
   PECmd.exe -d Prefetch\ --csv out\
   -> SVCUPD.EXE-3F2A91C4.pf  RunCount 6  LastRun 2026-03-14 07:16:02
      -> svcupd.exe 는 정상 Windows 구성요소가 아니다. 반드시 어딘가에서 뜬다.

3. 피벗 1 — WOW6432Node 확인
   RegistryExplorer 로 SOFTWARE hive 를 열고
   SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run 확인
   -> 값 없음. 여기도 아니다.

4. 피벗 2 — 전수 표를 위에서부터 찍는다
   SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
   LastWrite 2026-03-14 07:15:44Z
     SecurityUpdate = C:\Users\jhkim\AppData\Local\Temp\svcupd.exe

   -> 정책 경로였다. 시작프로그램 UI 와 -p run 플러그인 출력에
      안 잡히는 위치라서 1단계에서 놓쳤다.

5. 두 번째 지속성도 있는지 확인 (다중 지속성 가정)
   SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
     Userinit = C:\Windows\system32\userinit.exe,C:\Users\jhkim\AppData\Local\Temp\svcupd.exe
   -> 콤마 뒤에 같은 파일. 지속성이 두 곳에 걸려 있다.

   SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
     Debugger 값을 가진 서브키 없음 -> IFEO 는 사용 안 함

6. 실행 파일 확인
   MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
   Import-Csv C:\case\out\mft.csv |
     Where-Object { $_.FileName -eq 'svcupd.exe' }
   -> Created0x10 2026-03-14 07:14:58   (Run 키 LastWrite 07:15:44 보다 46초 앞)
      파일 생성 -> 지속성 등록 순서가 논리적으로 맞는다.

7. 시간대 변환
   07:15:44Z (UTC) + 9h = 2026-03-14 16:15:44 KST

정답:
  실행 경로  C:\Users\jhkim\AppData\Local\Temp\svcupd.exe
  지속성 키  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
             (+ Winlogon\Userinit 하이재킹 병행)
```

## 막혔을 때 다음 체크

1. **전수 표를 위에서 아래로 다 찍었는가** — `Run`/`RunOnce`에서 멈추지 않았는가
2. **`WOW6432Node` 대응 경로를 봤는가**
3. **`Winlogon`의 `Userinit`·`Shell`·`Taskman`을 봤는가** — 콤마 뒤를 확인했는가
4. **`Windows NT\CurrentVersion\Windows`의 `Load`/`Run`을 봤는가** — `CurrentVersion\Run`과 다른 키다
5. **`Image File Execution Options`에서 `Debugger` 값이 있는 서브키만 추렸는가**
6. **`Services`에서 `Start=2`를 걸렀는가. svchost면 `ServiceDll`까지 봤는가**
7. **활성 ControlSet을 `SYSTEM\Select`로 확인했는가**
8. 레지스트리에서 안 나온다 → `C:\Windows\System32\Tasks` XML → 시작 폴더 LNK → WMI 구독 → `User Shell Folders\Startup` 리다이렉션
9. 값이 지워진 흔적이 의심된다 → `RunOnce` 키 LastWrite, hive 슬랙, `$UsnJrnl`의 hive 변경 기록
10. 여러 사용자 → 모든 프로필의 `NTUSER.DAT`. hive 위치는 [FOR-0051](./registry-hive-map.html)

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: hive 파일과 `HKLM`/`HKCU` 매핑, `SOFTWARE`·`SYSTEM`·`NTUSER.DAT`의 위치
- SRC-086 — MITRE ATT&CK Enterprise Techniques: T1547.001(Registry Run Keys / Startup Folder), T1546.012(IFEO Injection), T1546.010(AppInit DLLs), T1547.004(Winlogon Helper DLL), T1543.003(Windows Service), T1546.015(COM Hijacking)의 지속성 위치 분류
- SRC-099 — RegRipper 3.0 repository: `run`, `winlogon`, `services` 계열 플러그인과 `rip.exe` 옵션
- 플러그인 이름은 배포 버전에 따라 다르므로 `rip.exe -l`로 실제 목록을 확인할 것
- `AppInit_DLLs`의 실제 로드 여부는 `LoadAppInit_DLLs` 값과 Secure Boot 설정에 따라 달라진다. 환경에서 확인할 것
