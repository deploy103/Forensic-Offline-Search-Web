---
id: FOR-0091
title: "Event ID 1102 감사 로그 삭제: UserData 구조와 삭제 구간 역추적"
slug: "event-1102-log-cleared"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "1102", "LogFileCleared", "UserData", "EventRecordID", "EVTX", "반포렌식"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C:\\Windows\\System32\\winevt\\Logs"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog"]
event_ids: ["1102", "1100", "104"]
protocols: []
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "wevtutil", "Timeline Explorer"]
commands: ["Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=1102}", "EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv", "wevtutil qe Security.evtx /q:\"*[System[(EventID=1102)]]\" /f:xml", "Get-WinEvent -Path Security.evtx -Oldest -MaxEvents 1"]
regex_patterns: ["(?i)wevtutil(\\.exe)?\\s+cl\\b", "(?i)Clear-EventLog", "(?i)event::(clear|drop)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "EventRecordID", "Channel", "BackupPath"]
file_formats: ["evtx"]
primary_terms: ["1102", "감사 로그 삭제", "이벤트 로그 지움", "로그 삭제 흔적"]
keywords: ["1102", "로그 삭제", "log cleared", "LogFileCleared", "UserData", "104", "1100", "4719", "wevtutil cl", "Clear-EventLog", "EventRecordID", "반포렌식", "anti-forensics"]
aliases: ["1102", "로그 지운 흔적", "이벤트 로그 삭제", "로그가 비어있다", "wevtutil cl 흔적", "로그 삭제 시각", "누가 로그를 지웠나"]
symptom_keywords: ["로그가 텅 비어 있다", "로그를 누가 지웠는지 알고 싶다", "1102가 파싱되지 않는다", "XPath 필터가 안 먹는다", "삭제된 구간을 메우고 싶다", "이벤트 개수가 너무 적다"]
related: ["FOR-0083", "FOR-0088", "FOR-0038", "FOR-0103"]
source_ids: ["SRC-022", "SRC-026", "SRC-109"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

1102는 Security 로그가 지워졌음을 기록하고 **누가 지웠는지(`SubjectUserName`, `SubjectLogonId`)까지 남기지만**, 페이로드가 일반 `EventData` 가 아니라 `UserData\LogFileCleared` 구조라서 평소 쓰는 파서·XPath 필터가 그대로 통하지 않는다.

## 어떤 문제에서 필요한가

- "로그가 비어 있다. 지워진 것인가, 원래 없었던 것인가"
- "누가 언제 로그를 지웠나" (반포렌식 행위 자체가 답인 문제)
- "삭제된 구간에 무슨 일이 있었나" (다른 artifact 로 메우기)
- "이벤트 개수가 비정상적으로 적다"
- "공격자의 마지막 행동은 무엇이었나" — 침입 → 활동 → **로그 삭제** 순서가 전형적이다

로그 삭제는 그 자체가 침해의 증거다. 정상 운영에서 관리자가 Security 로그를 손으로 지우는 일은 거의 없다.

## 문제에서 처음 볼 단서

1. `Security.evtx` 의 이벤트 수가 수백 건 이하로 부자연스럽게 적다 → 1102 확인
2. 가장 오래된 레코드의 시각이 며칠 전에 불과하다 → 삭제 또는 롤오버
3. 지문에 "은폐", "흔적 삭제", "반포렌식", "로그가 없다" → 1102 확정
4. 4624/4688 이 특정 시각 이후에만 존재한다 → 그 경계가 삭제 시점
5. `EventRecordID` 가 1부터 시작한다 → 새로 만들어진 로그 파일

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=1102} | Format-List
```

이어서 로그가 커버하는 구간과 첫 레코드 번호를 확인한다. **여기서 삭제 여부가 거의 결정된다.**

```powershell
# 가장 오래된 레코드 / 가장 최근 레코드
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -MaxEvents 1 |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId, Id
Get-WinEvent -Path 'C:\case\Security.evtx' -MaxEvents 1 |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId, Id

# 전체 건수
(Get-WinEvent -Path 'C:\case\Security.evtx').Count
```

가장 오래된 레코드의 `RecordId` 가 `1` 이거나 한 자리 수라면 **그 파일은 삭제 이후에 새로 시작된 로그다.**

## 상세 절차

### 1단계 — 1102 는 UserData 구조라는 것을 먼저 안다

**이 절이 이 글의 핵심이다.** 대부분의 Security 이벤트(4624, 4688, 4697 …)는 페이로드를 `<EventData><Data Name="...">` 로 담는다. 1102 는 다르다.

```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" />
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <TimeCreated SystemTime="2026-03-14T15:41:22.9931044Z" />
    <EventRecordID>1</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN10-DEV</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-1004336348-1177238915-682003330-1103</SubjectUserSid>
      <SubjectUserName>svc_backup</SubjectUserName>
      <SubjectDomainName>WIN10-DEV</SubjectDomainName>
      <SubjectLogonId>0x1a2b3c</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>
```

여기서 나오는 실전 문제 세 가지:

| 문제 | 원인 | 해결 |
| --- | --- | --- |
| `$_.Properties` 가 비어 있거나 기대한 순서가 아니다 | `Get-WinEvent` 의 `Properties` 는 `EventData` 기준으로 채워진다 | `[xml]$_.ToXml()` 로 받아 `$x.Event.UserData.LogFileCleared` 를 직접 읽는다 |
| XPath 로 `*[EventData[Data[@Name='SubjectUserName']=...]]` 필터가 0건 | 1102 에는 `EventData` 노드가 없다 | 페이로드 조건을 XPath 에 넣지 말고 `EventID` 로만 걸러 낸 뒤 코드에서 판정한다 |
| `LogFileCleared` 를 XPath 로 지정해도 0건 | `LogFileCleared` 에 **별도의 기본 네임스페이스**가 선언되어 있어, 접두어 없는 XPath 로는 선택되지 않는다 | XPath 로 페이로드를 파지 말고 `[xml]` 객체 탐색이나 EvtxECmd 로 처리한다 |

올바른 추출:

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=1102} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $u = $x.Event.UserData.LogFileCleared
    [pscustomobject]@{
      TimeUTC  = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      RecordId = $_.RecordId
      Who      = '{0}\{1}' -f $u.SubjectDomainName, $u.SubjectUserName
      Sid      = $u.SubjectUserSid
      LogonId  = $u.SubjectLogonId
      Computer = $x.Event.System.Computer
    }
  } | Format-List
```

출력 예시:

```text
TimeUTC  : 2026-03-14 15:41:22
RecordId : 1
Who      : WIN10-DEV\svc_backup
Sid      : S-1-5-21-1004336348-1177238915-682003330-1103
LogonId  : 0x1a2b3c
Computer : WIN10-DEV
```

`SubjectLogonId` = `0x1a2b3c` 를 얻었다면 그 값으로 4624 를 찾아 **로그를 지운 사람이 어디서 들어왔는지**까지 확정할 수 있다([FOR-0083](./event-4624-logon.html)).

`TimeCreated SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 변환해 표시하므로 두 화면의 숫자가 다르다. **KST 답은 UTC + 9시간** (15:41:22Z → 2026-03-15 00:41:22 KST — 날짜가 바뀌는 구간이라 특히 주의한다).

### 2단계 — 1102 와 104 를 구분한다

| 항목 | 1102 | 104 |
| --- | --- | --- |
| 기록되는 채널 | `Security` | `System` |
| Provider | `Microsoft-Windows-Eventlog` | `Microsoft-Windows-Eventlog` |
| 의미 | **Security(감사) 로그가 지워졌다** | **다른 로그(System, Application, Operational 등)가 지워졌다** |
| 페이로드 구조 | `UserData\LogFileCleared` | `UserData\LogFileCleared` (동일 계열) |
| 주체 정보 | 있다 | 있다 |
| 어느 로그가 지워졌는지 | Security 로 고정 | 페이로드에 대상 채널 이름이 들어간다 |

즉 **"System 로그를 지웠다"는 흔적은 1102 가 아니라 System 채널의 104 다.** 두 채널을 모두 열어야 삭제 전체 그림이 나온다.

```powershell
# Security 로그 삭제
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=1102}

# 다른 채널 삭제 (System 채널에 기록됨)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=104} | Format-List
```

104 는 어느 채널이 지워졌는지를 페이로드에 담으므로, PowerShell/Operational · Sysmon/Operational · TerminalServices 등 **가장 결정적인 로그만 골라 지운** 정황도 잡아낸다.

### 3단계 — EventRecordID 로 삭제를 역추적한다

`EventRecordID` 는 채널 안에서 단조 증가하는 일련번호다. 이 성질이 삭제 탐지의 지표가 된다.

| 관찰 | 해석 |
| --- | --- |
| 가장 오래된 레코드의 `EventRecordID` = `1` | 로그 파일이 **비워진 뒤 새로 시작**됐다. 1102(또는 104)가 그 첫 레코드인 경우가 많다 |
| 1102 의 `EventRecordID` = `1` | 지운 직후 그 사실만 기록됐다 = 삭제 확정 |
| `EventRecordID` 가 중간에서 급격히 낮아진다 | 서로 다른 시점의 EVTX 조각이 섞였거나, 파일이 교체됐다 |
| `EventRecordID` 는 연속인데 시각이 크게 점프한다 | 삭제가 아니라 **시스템이 꺼져 있던 구간**이다. 6005/6006 으로 확인한다 |
| 번호가 연속인데 특정 EventID 만 사라졌다 | 로그 삭제가 아니라 **감사 정책 변경**(4719) 가능성 |

```powershell
# RecordId 와 시각을 나란히 놓고 불연속 구간을 찾는다
$e = Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId, Id

# 번호가 뒤로 가거나 큰 구멍이 생기는 지점
for ($i = 1; $i -lt $e.Count; $i++) {
  $gap = $e[$i].RecordId - $e[$i-1].RecordId
  if ($gap -ne 1) { '{0}  {1} -> {2}  (gap {3})' -f $e[$i].UTC, $e[$i-1].RecordId, $e[$i].RecordId, $gap }
}
```

번호 구멍(gap)은 삭제만이 아니라 **덮어쓰기(롤오버)나 파일 손상**으로도 생긴다. 단독으로 결론을 내지 말고 1102/104 와 함께 판단한다.

### 4단계 — 1102 자체가 지워진 경우를 판정한다

**가장 중요한 함정이다.** 공격자가 로그를 지운 뒤 **한 번 더 지우면** 1102 도 함께 사라진다. 그러면 "삭제 이벤트가 없으니 삭제가 없었다"는 오판으로 이어진다.

이때는 **간접 증거**로 판정한다.

| 간접 증거 | 판정 논리 |
| --- | --- |
| 로그의 최초 레코드 시각이 시스템 설치 시각·최초 부팅 시각보다 훨씬 늦다 | 그 사이의 로그가 사라졌다 |
| 최초 레코드 시각이 **직전 부팅(6005)보다도 늦다** | 부팅 이후에 파일이 비워졌다 |
| 로그 파일 크기가 최대 크기에 한참 못 미치는데 오래된 기록이 없다 | 롤오버가 아니다. 롤오버는 파일이 꽉 찬 상태에서 일어난다 |
| Security 는 비어 있는데 System·Application 은 몇 달치가 있다 | 특정 채널만 표적으로 지워졌다 |
| `$MFT` / `$UsnJrnl` 에서 해당 `.evtx` 파일의 수정·크기 변경 기록이 사건 시각과 일치 | 그 시각에 파일이 재생성됐다 |
| 4688 / 4104 에 `wevtutil cl` · `Clear-EventLog` 실행 기록이 있는데 1102 가 없다 | 삭제 후 재삭제 |

```powershell
# 로그 커버 구간 vs 부팅 시각 비교
$secOld = (Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -MaxEvents 1).TimeCreated.ToUniversalTime()
$boots  = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005} |
  Select-Object -ExpandProperty TimeCreated | ForEach-Object { $_.ToUniversalTime() }
"Security 최초 레코드 : $secOld"
"부팅 이력            : $($boots -join ', ')"
```

`Security 최초 레코드` 가 마지막 부팅보다 늦으면, 그 부팅 이후에 로그가 비워졌다는 뜻이다. **이 비교 하나로 1102 없이도 삭제를 주장할 수 있다.**

파일 포맷 수준에서 더 확실히 하려면 EVTX 헤더를 직접 본다. EVTX 파일은 `ElfFile\x00` 시그니처로 시작하고, 64KiB 청크마다 `ElfChnk\x00` 헤더가 있으며, 헤더에는 파일이 담고 있는 **첫/마지막 레코드 번호**가 들어 있다. 첫 레코드 번호가 1 이면 그 파일은 생성 이후 한 번도 롤오버되지 않은 새 파일이다.

### 5단계 — 삭제 도구의 실행 흔적을 찾는다

로그를 지우려면 무언가를 실행해야 한다. **그 실행 기록은 다른 곳에 남는다.**

| 도구/방법 | 찾는 위치 | 검색 문자열 |
| --- | --- | --- |
| `wevtutil cl Security` | 4688 `CommandLine`, 4104 | `wevtutil`, `cl `, `clear-log` |
| `Clear-EventLog -LogName Security` | 4104(스크립트 블록), 4103, PowerShell 콘솔 히스토리 | `Clear-EventLog` |
| `Remove-EventLog` / `Limit-EventLog` | 4104 | `EventLog` |
| `mimikatz` `event::clear` | 4688(`mimikatz.exe`), 4104, Prefetch, Amcache | `mimikatz`, `event::` |
| `Get-WinEvent` 기반 자체 스크립트 | 4104 | `.ClearLog(`, `EventLogSession` |
| GUI(이벤트 뷰어에서 "로그 지우기") | 4688 의 `eventvwr.exe` 실행, UserAssist | `eventvwr` |
| 로그 파일 직접 삭제/교체 | `$MFT`, `$UsnJrnl`, `$LogFile` | `.evtx` 파일명 |

```powershell
# 4688 명령행에서 삭제 도구 흔적
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} |
  Where-Object { $_.Message -match '(?i)wevtutil|Clear-EventLog|mimikatz|eventvwr' } |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Message

# PowerShell 스크립트 블록(4104)에서
Get-WinEvent -FilterHashtable @{
  Path='C:\case\Microsoft-Windows-PowerShell%4Operational.evtx'; Id=4104
} | Where-Object { $_.Message -match '(?i)Clear-EventLog|wevtutil|ClearLog|EventLogSession' }
```

역설적으로, **삭제 명령을 실행한 4688 이 남아 있다면 그 4688 은 삭제된 구간 이후에 기록된 것**이다. 즉 공격자가 지운 뒤에도 활동했다는 뜻이고, 삭제 시점의 경계를 좁히는 데 쓸 수 있다.

### 6단계 — 삭제된 구간을 다른 artifact 로 메운다

로그가 사라졌다고 사건이 사라지는 것은 아니다. Windows 는 같은 사실을 여러 곳에 중복 기록한다.

| 사라진 정보 | 대체 artifact |
| --- | --- |
| 로그온(4624) | RDP 채널(TerminalServices), `NTUSER.DAT` 로드 시각, ProfileList, SRUM, 마지막 로그온 시각(SAM) |
| 프로세스 실행(4688) | Prefetch, Amcache, AppCompatCache, UserAssist, SRUM, `$MFT`, Sysmon/Operational |
| 서비스 설치(4697/7045) | SYSTEM hive `Services` 키, `$MFT` 의 이미지 파일 |
| 파일 접근/생성 | `$MFT`, `$UsnJrnl`, `$LogFile`, LNK, JumpList, 최근 문서 |
| 네트워크 활동 | SRUM 네트워크 사용량, DNS 캐시, 브라우저 히스토리, 방화벽 로그 |
| PowerShell 실행 | `ConsoleHost_history.txt`, 4104(다른 채널이라 함께 지워지지 않는 경우가 많다) |
| 시간대 전체 | 다른 호스트의 EVTX, 도메인 컨트롤러 로그, 프록시·방화벽 로그 |

**공격자는 보통 Security 채널만 지운다.** PowerShell/Operational, Sysmon/Operational, TerminalServices, Windows Defender 채널은 그대로 남아 있는 경우가 매우 흔하다. `winevt\Logs` 디렉터리의 모든 `.evtx` 를 EvtxECmd 로 한 번에 파싱해 통합 타임라인을 만드는 것이 정석이다.

## 출력 필드 해석

| 필드 (경로) | 의미 | 읽는 법 |
| --- | --- | --- |
| `System\TimeCreated\@SystemTime` | 삭제 시각 (**UTC**) | KST 는 +9시간 |
| `System\EventRecordID` | 레코드 번호 | `1` 이면 삭제 직후 새 로그의 첫 레코드 |
| `System\Computer` | 어느 호스트에서 지웠나 | 다중 호스트 사건에서 중요 |
| `System\Provider\@Name` | `Microsoft-Windows-Eventlog` | 4624 등의 `Microsoft-Windows-Security-Auditing` 과 다르다 |
| `UserData\LogFileCleared\SubjectUserSid` | 삭제한 계정의 SID | ProfileList·SAM 과 대조 |
| `UserData\LogFileCleared\SubjectUserName` | **삭제한 계정 이름** | 이 이벤트의 존재 이유 |
| `UserData\LogFileCleared\SubjectDomainName` | 계정 도메인 | 로컬이면 컴퓨터 이름 |
| `UserData\LogFileCleared\SubjectLogonId` | 삭제한 세션의 Logon ID | 4624 로 출처 IP 추적 |

### 함께 봐야 하는 이벤트

| Event ID | 채널 | 의미 | 왜 함께 보나 |
| --- | --- | --- | --- |
| `1102` | Security | Security 로그 삭제 | 본편 |
| `104` | System | 다른 채널의 로그 삭제 | 표적 삭제 탐지 |
| `1100` | Security | **이벤트 로그 서비스 종료** | 정상 종료 시에도 나오지만, 종료 후 파일을 교체하는 수법의 신호 |
| `4719` | Security | 시스템 감사 정책 변경 | 지우는 대신 **끄는** 수법. 이후 구간이 통째로 비게 된다 |
| `4616` | Security | 시스템 시각 변경 | 타임라인 자체를 흔드는 수법. 순서가 뒤엉킨다 |
| `4608` / `6005` | Security / System | 시작 이벤트 | 로그가 커버해야 하는 구간의 하한선 |
| `4688` / `4104` | Security / PowerShell | 삭제 도구 실행 | 누가 무엇으로 지웠나 |

1100 은 시스템을 정상 종료할 때도 기록되므로 단독으로는 증거가 아니다. **1100 직후에 로그가 끊기고 다음 6005 이후 기록만 남는다면** 서비스를 멈춰 놓고 파일을 손댄 정황을 의심한다.

## pivot: 다음에 볼 artifact

| 1102에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `SubjectLogonId` | 4624 ([FOR-0083](./event-4624-logon.html)) | 지운 사람의 계정·출처 IP·Logon Type |
| `SubjectUserSid` | SAM hive, ProfileList | 계정 실체와 생성 시각 |
| 삭제 시각 | 4688 ([FOR-0088](./event-4688-process-creation.html)) | `wevtutil cl` / `mimikatz` 실행 |
| 삭제 시각 | `$MFT` / `$UsnJrnl` ([FOR-0021](./mft-basics.html)) | `.evtx` 파일 수정, 도구 파일 생성·삭제 |
| 삭제 시각 | 그 직전 구간의 모든 채널 | 지우려 했던 활동의 정체 |
| 로그 최초 레코드 시각 | 6005 / 4608 | 삭제 구간의 경계 확정 |
| `Computer` | 다른 호스트의 EVTX | 같은 계정이 다른 곳에서도 지웠는지 |
| 삭제 정황 | Prefetch / Amcache / SRUM | 로그 없이 실행 사실 복원 |
| 삭제 정황 | 타임스탬프 조작 흔적 ([FOR-0038](./timestomp-detection.html)) | 반포렌식이 여기서 끝나지 않았을 가능성 |

## 흔한 함정

- **`EventData` 기준 파서로 1102 를 읽고 필드가 비었다고 판단한다.** 1102 의 페이로드는 `UserData\LogFileCleared` 다. `[xml]$_.ToXml()` 로 받아 `$x.Event.UserData.LogFileCleared` 를 읽어야 계정이 나온다.
- **XPath 로 페이로드 조건을 건다.** `LogFileCleared` 에는 별도의 기본 네임스페이스가 선언되어 있어 접두어 없는 XPath 로는 선택되지 않는다. `EventID` 로만 필터하고 판정은 코드에서 한다.
- **1102 가 없으니 삭제가 없었다고 결론 낸다.** 1102 자체가 다음 삭제에 함께 지워진다. **최초 레코드 시각 vs 부팅/설치 시각** 비교로 간접 판정해야 한다.
- **1102 만 찾고 104 를 빠뜨린다.** System·PowerShell·Sysmon 채널의 삭제는 System 채널의 104 에 남는다. 표적 삭제일수록 여기서 잡힌다.
- **번호 구멍을 곧바로 삭제로 단정한다.** `EventRecordID` gap 은 롤오버·손상으로도 생긴다. 파일 크기와 최대 크기 설정을 함께 본다.
- **시각 점프를 삭제로 오해한다.** 시스템이 꺼져 있던 구간은 원래 로그가 없다. 6005/6006 으로 가동 구간을 먼저 그린다.
- **로그가 지워졌다고 조사를 멈춘다.** Prefetch·Amcache·`$MFT`·`$UsnJrnl`·SRUM·레지스트리는 그대로 있다. 대체 artifact 표를 순서대로 소진한다.
- **UTC/로컬 혼동.** EVTX `SystemTime` 은 UTC 다. 삭제 시각처럼 사건의 종료 시점을 특정할 때 9시간 차이는 날짜를 바꿔 놓는다. KST 답은 +9시간.
- **삭제한 계정을 곧바로 범인으로 확정한다.** 도용된 자격증명일 수 있다. `SubjectLogonId` 로 4624 를 찾아 출처 IP·Logon Type 을 확인해야 "누가"가 완성된다.
- **감사 정책을 끈 경우(4719)를 삭제와 구분하지 않는다.** 지우면 과거가 사라지고, 끄면 미래가 기록되지 않는다. 증거 해석이 완전히 다르다.

## 교차검증

```powershell
# 1) Security 로그 삭제 (1102)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=1102} | Format-List

# 2) 다른 채널의 삭제 (System 채널 104)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=104} | Format-List

# 3) 로그 서비스 종료 / 감사 정책 변경 / 시각 변경
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=1100,4719,4616} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id, Message

# 4) 커버 구간 확인 — 최초 레코드가 마지막 부팅보다 늦으면 비워졌다는 뜻
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -MaxEvents 3 |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId, Id
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}

# 5) 삭제 도구 실행 흔적
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} |
  Where-Object { $_.Message -match '(?i)wevtutil|Clear-EventLog|mimikatz' }

# 6) winevt\Logs 전체를 한 번에 파싱해 남아 있는 채널을 찾는다
# EvtxECmd 는 -d 로 디렉터리 전체를 처리한다
EvtxECmd.exe -d 'C:\case\winevt\Logs' --csv 'C:\case\out' --csvf all.csv
```

## mini walkthrough

```text
문제:
"2026-03-14 침해 사고입니다. 공격자가 로그를 지운 시각과 사용한 계정을 구하세요.
 첨부: Security.evtx (312 events), System.evtx"

1. 첫 시도 (실패):
   wevtutil qe Security.evtx /q:"*[System[(EventID=1102)]] and \
     *[EventData[Data[@Name='SubjectUserName']='Administrator']]" /f:xml
   -> 0건.
   "1102 가 없다 = 삭제가 없었다"고 결론 낼 뻔했다.

2. 왜 틀렸나:
   EventID=1102 조건만 남기고 다시 돌리니 1건이 나왔다.
   즉 EventID 는 맞았고, EventData 조건이 문제였다.
   1102 의 페이로드는 EventData 가 아니라 UserData\LogFileCleared 다.
   존재하지 않는 노드를 조건으로 걸었으니 항상 0건이었다.
   -> 다른 Security 이벤트와 같은 구조라고 가정한 것이 실수.

3. 올바른 추출:
   Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=1102} |
     ForEach-Object { ([xml]$_.ToXml()).Event.UserData.LogFileCleared }

   SubjectUserSid    : S-1-5-21-...-1103
   SubjectUserName   : svc_backup
   SubjectDomainName : WIN10-DEV
   SubjectLogonId    : 0x1a2b3c

   그리고 그 이벤트의 EventRecordID = 1, TimeCreated = 2026-03-14T15:41:22Z.
   RecordId 1 -> 이 파일은 삭제 직후 새로 시작된 로그다.

4. 커버 구간 확인:
   Security.evtx 최초 레코드 = 2026-03-14 15:41:22Z (= 1102 자신)
   System.evtx 의 6005(부팅)  = 2026-03-14 06:02:11Z
   -> 부팅은 06:02, 로그는 15:41 부터. 그 사이 9시간 반의 감사 기록이 사라졌다.

5. 삭제 도구:
   남아 있는 4688 (15:41 이후) 에는 흔적이 없었다.
   PowerShell Operational 4104 는 지워지지 않았다:
     15:40:58Z  wevtutil cl Security; wevtutil cl System
   -> 삭제 24초 전에 명령이 실행됐다. System 도 지우려 했다.

6. System 채널 확인:
   Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=104}
   -> 15:41:25Z, 대상 채널 System, 주체 svc_backup.
   1102(Security) 와 104(System) 가 3초 차이로 짝을 이룬다.

7. 삭제된 구간 메우기:
   Prefetch: 09:14 rclone.exe, 11:02 7z.exe 실행 기록 (로그에는 없는 구간)
   $UsnJrnl: 10:40~11:30 사이 대량 파일 읽기 후 아카이브 생성
   -> 지우려 했던 것은 데이터 반출 활동이었다.

8. 시각 변환:
   15:41:22Z 는 UTC. KST 는 +9시간 -> 2026-03-15 00:41:22.
   날짜가 넘어가므로 답을 적을 때 반드시 확인한다.

정답: 삭제 시각 2026-03-14 15:41:22 UTC (KST 03-15 00:41:22), 계정 WIN10-DEV\svc_backup
```

1단계의 실패가 이 글의 존재 이유다. **1102 는 다른 Security 이벤트와 페이로드 구조가 다르다.** `EventData` 를 전제한 XPath·파서는 조용히 0건을 돌려주고, 그 0건이 "삭제 없음"이라는 오답으로 직결된다.

## 막혔을 때 다음 체크

1. `EventID` 만으로 필터해 봤는가 — 페이로드 조건이 0건의 원인인 경우가 대부분이다
2. `[xml]$_.ToXml()` 로 `UserData\LogFileCleared` 를 직접 읽었는가
3. System 채널의 104 를 확인했는가 — 표적 삭제는 여기 있다
4. 가장 오래된 레코드의 시각과 `RecordId` 를 확인했는가 — `RecordId` = 1 이면 새 파일
5. 최초 레코드 시각을 6005/4608(부팅)과 비교했는가 — 1102 없이 삭제를 증명하는 방법
6. 파일 크기가 최대 크기에 도달했는지 확인해 롤오버를 배제했는가
7. 1100(서비스 종료) · 4719(감사 정책 변경) · 4616(시각 변경)을 함께 봤는가
8. 4688 / 4104 에서 `wevtutil cl` · `Clear-EventLog` · `mimikatz` 를 찾았는가
9. `winevt\Logs` 의 **모든** `.evtx` 를 파싱했는가 — 지워지지 않은 채널이 거의 항상 있다
10. 삭제 구간을 Prefetch · Amcache · `$MFT` · `$UsnJrnl` · SRUM · 레지스트리로 메웠는가
11. `SubjectLogonId` 로 4624 를 찾아 출처 IP 를 확정했는가
12. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가 — 날짜가 바뀔 수 있다

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 1102 와 4719 의 위치와 의미, Security 채널 이벤트 목록
- SRC-026 — Libyal libevtx / EVTX 파일 포맷 문서: `ElfFile` 파일 시그니처, 64KiB 청크(`ElfChnk`) 구조, 파일 헤더가 담는 첫/마지막 레코드 번호와 `EventRecordID` 의 단조 증가 성질
- SRC-109 — MITRE ATT&CK T1070 (Indicator Removal): 이벤트 로그 삭제·타임스탬프 조작 등 반포렌식 기법과 대체 artifact 접근의 근거
- 1102 / 104 의 `UserData\LogFileCleared` 하위 요소 구성(특히 104 가 담는 대상 채널·백업 경로 필드 이름)은 Windows 버전에 따라 다를 수 있으므로 실제 이벤트 XML 에서 확인할 것
- 로그를 비운 직후 `EventRecordID` 가 1 부터 다시 시작하는 동작은 실무에서 널리 관찰되지만, 버전·설정에 따라 다를 수 있으므로 실제 파일의 첫 레코드 번호를 직접 확인할 것
- `mimikatz` 의 `event::` 계열 명령 이름은 버전에 따라 다를 수 있다. 문자열 검색은 도구 이름과 명령 이름을 모두 시도할 것
</content>
