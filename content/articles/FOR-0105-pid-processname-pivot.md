---
id: FOR-0105
title: "PID·ProcessName으로 pivot하기: 16진수 함정과 프로세스 계보 재구성"
slug: "pid-processname-pivot"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["NewProcessId", "ProcessId", "ProcessGuid", "NewProcessName", "ParentProcessName", "Security.evtx"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"]
registry_paths: []
event_ids: ["4689"]
protocols: []
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "Volatility 3", "Event Viewer"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --csv 'C:\\case\\out' --csvf sec.csv", "[Convert]::ToInt32('1a4c', 16)", "vol.py -f mem.raw windows.pstree"]
regex_patterns: ["0x[0-9a-fA-F]{2,8}", "\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\}"]
wireshark_filters: []
tshark_fields: []
log_fields: ["NewProcessId", "NewProcessName", "ProcessId", "ParentProcessName", "CommandLine", "TokenElevationType", "ProcessGuid", "ParentProcessGuid", "Image", "ParentImage"]
file_formats: ["evtx", "csv"]
primary_terms: ["PID pivot", "프로세스 이름으로 추적", "PID 재사용"]
keywords: ["PID", "NewProcessId", "ProcessId", "ProcessGuid", "부모 프로세스", "프로세스 계보", "process tree", "16진수", "hex", "10진수", "4689", "pslist", "PID 재사용"]
aliases: ["pid 추적", "부모 프로세스 찾기", "프로세스 트리 만들기", "pid 16진수", "0x1a4c pid", "프로세스 계보", "누가 실행했나"]
symptom_keywords: ["PID가 16진수로 나온다", "부모 프로세스를 못 찾겠다", "PID가 겹친다", "같은 PID가 두 프로세스를 가리킨다", "프로세스 트리를 만들고 싶다", "메모리 덤프 PID와 로그 PID가 안 맞는다"]
related: ["FOR-0104", "FOR-0214", "FOR-0110"]
source_ids: ["SRC-021", "SRC-024", "SRC-006"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4688의 `NewProcessId`(자식)와 `ProcessId`(부모)는 **16진수**이고 Sysmon의 `ProcessId`는 **10진수**이므로 진법을 통일하지 않으면 조인이 통째로 빈다. 그리고 **PID는 재사용되므로 PID 단독으로 추적하면 안 된다** — Sysmon의 `ProcessGuid`, 없으면 `(PID + 생성 시각)` 조합을 키로 쓴다.

## 어떤 문제에서 필요한가

- "이 프로세스를 실행한 것은 무엇인가" — 부모를 거슬러 올라가 루트까지 찾는 문제
- 명령행이 수상한 프로세스를 하나 찾았고, 그 앞뒤 계보를 그려야 하는 문제
- 메모리 덤프의 PID와 EVTX의 PID를 맞춰야 하는 문제
- 같은 PID가 로그 안에서 여러 프로그램을 가리켜 어느 것인지 가려야 하는 문제
- 프로세스가 몇 초 살아 있었는지(생존 구간)를 근거와 함께 답해야 하는 문제

## 문제에서 처음 볼 단서

1. 4688이 있고 `CommandLine` 이 채워져 있다 → 여기서 시작한다. 가장 정보가 많다
2. 4688에 `CommandLine` 이 비어 있다 → 명령행 감사가 꺼져 있다. Sysmon 1 또는 PowerShell 4103/4104로 우회
3. Sysmon 채널이 있다 → `ProcessGuid` 를 키로 쓴다. **PID 재사용 문제가 사라진다**
4. 메모리 덤프가 함께 있다 → `windows.pstree` 의 PID(10진수)와 대조 ([FOR-0214](./volatility-pslist.html))
5. PID가 `0x` 로 시작한다 → Security 채널이다. Sysmon과 섞기 전에 변환

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
```

그다음 진법을 맞춘다. 이 한 줄을 먼저 손에 익힌다.

```powershell
[Convert]::ToInt32('1a4c', 16)   # 6732  (0x1a4c -> 10진수)
'0x{0:x}' -f 6732                # 0x1a4c (10진수 -> 16진수)
```

4688만 뽑아 부모-자식 표를 만든다.

```powershell
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4688)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      RecordId = $_.RecordId
      TimeUTC  = $x.Event.System.TimeCreated.SystemTime
      Pid      = $d['NewProcessId']
      PidDec   = [Convert]::ToInt64(($d['NewProcessId'] -replace '^0[xX]',''), 16)
      Ppid     = $d['ProcessId']
      Image    = $d['NewProcessName']
      Parent   = $d['ParentProcessName']
      Cmd      = $d['CommandLine']
      Session  = $d['SubjectLogonId']
      User     = $d['SubjectUserName']
    }
  } | Sort-Object RecordId | Format-Table TimeUTC, Pid, Ppid, Image, Cmd -AutoSize
```

## 상세 절차

### 1단계 — 진법 대응표 (최대 함정)

| 소스 | PID 필드 | 진법 | 예시 |
| --- | --- | --- | --- |
| Security 4688 | `NewProcessId` (자식) | **16진수** | `0x1a4c` |
| Security 4688 | `ProcessId` (부모) | **16진수** | `0x2f8` |
| Security 4689 | `ProcessId` (종료된 프로세스) | **16진수** | `0x1a4c` |
| Security 4624 / 4672 / 4673 | `ProcessId` | **16진수** | `0x2f8` |
| Sysmon 1 / 3 / 11 / 13 | `ProcessId`, `ParentProcessId` | **10진수** | `6732` |
| Volatility `windows.pslist` / `pstree` | `PID`, `PPID` | **10진수** | `6732` |
| 작업 관리자 / `tasklist` | PID | **10진수** | `6732` |
| PowerShell 4103 `ContextInfo` | Host Process ID | **10진수** | `6732` |

**`0x1a4c` 를 그대로 `1a4c` 로 읽고 Sysmon에서 찾으면 아무것도 안 나온다.** 반대로 Sysmon의 `6732` 를 Security에서 문자열로 찾아도 안 나온다. 조인 전에 한쪽으로 통일한다.

```powershell
function Get-PidDec {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $t = $Text.Trim()
  if ($t -match '^0[xX]') { return [Convert]::ToInt64(($t -replace '^0[xX]',''), 16) }
  return [int64]$t
}

Get-PidDec '0x1a4c'   # 6732
Get-PidDec '6732'     # 6732
```

주의: `0x` 접두사 없이 `1a4c` 처럼 나오는 경우가 있다. 그때는 **문자에 a-f가 있으면 16진수**로 판정할 수밖에 없다. `1234` 처럼 모두 숫자면 진법 판정이 불가능하므로, **소스가 무엇인지로 결정한다** — Security 채널이면 16진수다.

### 2단계 — PID 단독 추적을 금지하는 이유

Windows는 프로세스가 끝나면 그 PID를 **재사용**한다. 바쁜 시스템에서는 몇 분 안에 같은 PID가 다른 프로그램에 붙는다.

| 키 | 유일성 | 언제 쓰나 |
| --- | --- | --- |
| `ProcessGuid` (Sysmon) | **부팅·호스트를 넘어 유일** | Sysmon이 있으면 무조건 이것 |
| `LogonGuid` + PID | 세션 안에서 유일 | Kerberos 환경 |
| **PID + 생성 시각** | 실질적으로 유일 | Sysmon이 없을 때의 표준 대안 |
| PID + 생존 구간(4688~4689) | 유일 | 4689가 켜져 있을 때 |
| PID 단독 | **유일하지 않다** | 쓰지 않는다 |

`ProcessGuid` 는 Sysmon이 프로세스마다 새로 만드는 식별자이므로 PID처럼 재사용되지 않는다. Sysmon 채널이 있으면 PID 대신 이것을 조인 키로 쓴다.

```powershell
# Sysmon 이 있으면 ProcessGuid 로 pivot 한다 (PID 재사용 무관)
Get-WinEvent -Path 'C:\case\Microsoft-Windows-Sysmon%4Operational.evtx' -Oldest |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    if ($x.Event.EventData) { $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' } }
    if ($d['ProcessGuid'] -eq '{c8f6f2a1-6b41-6612-3a00-000000001e00}') {
      [pscustomobject]@{
        RecordId = $_.RecordId
        TimeUTC  = $x.Event.System.TimeCreated.SystemTime
        EventId  = $_.Id
        Image    = $d['Image']
        Detail   = $d['CommandLine'] + $d['TargetFilename'] + $d['DestinationIp']
      }
    }
  } | Sort-Object RecordId | Format-Table -AutoSize
```

### 3단계 — 같은 PID가 여러 프로세스를 가리키는지 판별

```powershell
# 같은 PID 로 4688 이 두 번 이상 나오면 재사용이다
$procs = Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4688)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      RecordId = $_.RecordId
      TimeUTC  = $x.Event.System.TimeCreated.SystemTime
      PidDec   = Get-PidDec $d['NewProcessId']
      PpidDec  = Get-PidDec $d['ProcessId']
      Image    = $d['NewProcessName']
      Cmd      = $d['CommandLine']
      Session  = $d['SubjectLogonId']
    }
  }

$procs | Group-Object PidDec | Where-Object { $_.Count -gt 1 } |
  ForEach-Object {
    "PID {0} : {1} processes" -f $_.Name, $_.Count
    $_.Group | Select-Object TimeUTC, Image | Format-Table -AutoSize
  }
```

출력 예시:

```text
PID 6732 : 3 processes
TimeUTC                       Image
2026-03-14T07:20:08.4410021Z  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2026-03-14T07:52:19.7710004Z  C:\Windows\System32\notepad.exe
2026-03-14T08:41:03.2010887Z  C:\Program Files\7-Zip\7z.exe
```

**같은 PID 6732가 세 번 등장했다.** 이 상태에서 "PID 6732가 7z.exe"라고 단정하면 오답이다. 판별은 시각으로 한다.

| 판별 기준 | 방법 |
| --- | --- |
| 어느 구간의 6732인가 | 그 PID의 4688 시각과 다음 4688 시각 사이 |
| 4689가 있는가 | `ProcessId` = `0x1a4c` 인 4689의 시각이 생존 구간의 끝 |
| 부모가 같은가 | `ProcessId`(부모)가 다르면 확실히 다른 프로세스 |
| Sysmon이 있는가 | `ProcessGuid` 가 다르면 확실히 다른 프로세스 |

### 4단계 — 프로세스 계보 재구성 (부모로 거슬러 올라가기)

4688의 `ProcessId`(부모 PID)를 키로 그 부모 자신의 4688을 찾고, 다시 그 부모의 부모를 찾는다. 루트(`services.exe`, `explorer.exe`, `winlogon.exe`)에 닿거나 4688이 없어지면 멈춘다.

```powershell
# $procs 는 3단계에서 만든 목록
function Get-Ancestry {
  param([int64]$TargetPid, [datetime]$Before, [int]$Depth = 8)

  $chain = @()
  $curPid = $TargetPid
  $curTime = $Before

  for ($i = 0; $i -lt $Depth; $i++) {
    # 그 시각 이전에 생성된 같은 PID 중 가장 최근 것이 진짜 부모다
    $cand = $procs |
      Where-Object { $_.PidDec -eq $curPid -and ([datetime]$_.TimeUTC) -le $curTime } |
      Sort-Object { [datetime]$_.TimeUTC } |
      Select-Object -Last 1
    if (-not $cand) { break }
    $chain += $cand
    $curPid = $cand.PpidDec
    $curTime = [datetime]$cand.TimeUTC
  }
  $chain
}

Get-Ancestry -TargetPid 6732 -Before ([datetime]'2026-03-14T07:21:00Z') |
  Select-Object TimeUTC, PidDec, PpidDec, Image, Cmd | Format-Table -AutoSize
```

출력 예시 (자식 → 부모 순):

```text
TimeUTC                       PidDec PpidDec Image                                  Cmd
2026-03-14T07:20:08.4410021Z  6732   4188    ...\v1.0\powershell.exe                powershell.exe -enc SQBFAFgA...
2026-03-14T07:19:31.0021110Z  4188   1044    C:\Windows\System32\cmd.exe            cmd.exe
2026-03-14T07:19:04.1180022Z  1044   760     C:\Windows\System32\rdpclip.exe        rdpclip.exe
```

**`-le $curTime` 조건이 이 함수의 핵심이다.** 그것 없이 PID로만 찾으면 재사용된 나중 프로세스를 부모로 잡는다.

`ParentProcessName` 필드가 채워져 있으면 이 작업이 훨씬 쉽다. 하지만 이 필드는 Windows 버전에 따라 **없을 수도 있다.** 없으면 위 방식으로 PID 조인이 유일한 방법이다.

Sysmon이 있으면 GUID로 잇는다. 재사용 걱정이 없다.

```text
Sysmon 1: ProcessGuid  <- 이 프로세스
          ParentProcessGuid  -> 부모의 ProcessGuid 와 정확히 일치
```

### 5단계 — 생존 구간 확정 (4689)

4689(프로세스 종료)는 `ProcessId`(16진수)와 `ProcessName` 을 담는다. 4688과 짝지어 생존 구간을 만든다.

```powershell
$exits = Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4689)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $x.Event.System.TimeCreated.SystemTime
      PidDec  = Get-PidDec $d['ProcessId']
      Image   = $d['ProcessName']
      Status  = $d['Status']
    }
  }

# 시작-종료 짝짓기: 시작 이후 최초의 같은 PID 종료
foreach ($p in $procs) {
  $e = $exits |
    Where-Object { $_.PidDec -eq $p.PidDec -and ([datetime]$_.TimeUTC) -ge ([datetime]$p.TimeUTC) } |
    Sort-Object { [datetime]$_.TimeUTC } | Select-Object -First 1
  $endTime = '(running)'
  $life = ''
  if ($e) {
    $endTime = $e.TimeUTC
    $life = [math]::Round((([datetime]$e.TimeUTC) - ([datetime]$p.TimeUTC)).TotalSeconds, 1)
  }
  [pscustomobject]@{
    PidDec = $p.PidDec; Image = $p.Image
    StartUTC = $p.TimeUTC; EndUTC = $endTime; LifeSec = $life
  }
} | Format-Table -AutoSize
```

| 관찰 | 해석 |
| --- | --- |
| 4689가 없다 | 프로세스 종료 감사가 꺼져 있다(기본값), 또는 이미지 획득 시각까지 살아 있었다 |
| 생존 시간이 1초 미만 | 실행 즉시 종료. 로더/드로퍼 또는 오류 |
| 생존 시간이 수 시간 | 상주. 지속성·C2 후보 |
| 4689의 `ProcessName` 이 4688의 `NewProcessName` 과 다르다 | **PID 재사용이다.** 짝이 잘못 붙었다 |

**마지막 행이 검산이다.** 4688과 4689의 이미지 이름이 다르면 짝짓기가 틀렸다.

### 6단계 — ProcessName 이 전체 경로인가 파일명인가

| 소스 / 필드 | 형태 | 예시 |
| --- | --- | --- |
| 4688 `NewProcessName` | 전체 경로 | `C:\Windows\System32\cmd.exe` |
| 4688 `ParentProcessName` | 전체 경로 (있을 때) | `C:\Windows\explorer.exe` |
| 4689 `ProcessName` | 전체 경로 | `C:\Windows\System32\cmd.exe` |
| 4624 / 4672 `ProcessName` | 전체 경로 | `C:\Windows\System32\lsass.exe` |
| Sysmon 1 `Image` | 전체 경로 | `C:\Windows\System32\cmd.exe` |
| Sysmon 1 `OriginalFileName` | **PE 리소스의 원래 파일명** | 이름을 바꿔도 원본이 드러난다 |
| Volatility `pslist` 의 이름 | **파일명, 최대 15자로 잘림** | `powershell.ex` |
| Prefetch `ExecutableName` | 파일명(대문자) | `POWERSHELL.EXE` |

두 가지 결과가 나온다.

- **경로로 필터하면 안전하지만, 파일명으로 필터하면 놓친다.** `C:\Users\Public\svchost.exe` 는 정상 `svchost.exe` 와 파일명이 같다. 경로를 봐야 위장이 드러난다
- **Volatility의 이름은 잘린다.** `powershell.exe` 를 찾으려면 `powershell` 로 부분 일치 검색한다

```powershell
# 정상 경로가 아닌 곳에서 실행된 시스템 프로세스 이름 찾기 (위장 탐지)
$procs | Where-Object {
  $_.Image -match '\\(svchost|lsass|services|csrss|winlogon|explorer)\.exe$' -and
  $_.Image -notmatch '^C:\\Windows\\(System32|SysWOW64)\\' -and
  $_.Image -notmatch '^C:\\Windows\\explorer\.exe$'
} | Select-Object TimeUTC, PidDec, Image, Cmd | Format-Table -AutoSize
```

### 7단계 — 메모리 덤프의 PID와 대조

```bash
# 메모리에서 프로세스 트리 (PID/PPID 는 10진수)
vol.py -f mem.raw windows.pstree
vol.py -f mem.raw windows.pslist
vol.py -f mem.raw windows.cmdline --pid 6732
```

| 대조 결과 | 해석 |
| --- | --- |
| 로그의 PID가 메모리에도 있다 | 획득 시각에 살아 있었다. `windows.cmdline` 으로 명령행 확보 |
| 로그에는 있고 메모리에 없다 | 이미 종료됐다. 4689 시각과 일치하는지 확인 |
| 메모리에는 있고 4688에 없다 | **감사 이전에 실행됐거나 4688이 지워졌다.** `psscan` 으로 종료된 프로세스까지 본다 |
| 같은 PID인데 이름이 다르다 | 재사용. 획득 시각 기준으로 어느 쪽인지 판정 |

Volatility의 출력 해석은 [FOR-0214](./volatility-pslist.html)에 있다. 여기서는 **PID가 10진수라는 점**과 **이름이 잘린다는 점**만 기억한다.

## 출력 필드 해석

| 필드 | 소스 | 의미 |
| --- | --- | --- |
| `NewProcessId` | 4688 | **생성된(자식) 프로세스의 PID.** 16진수 |
| `NewProcessName` | 4688 | 자식의 전체 경로 |
| `ProcessId` | 4688 | **부모 프로세스의 PID.** 16진수. 이름이 헷갈리기 쉽다 |
| `ParentProcessName` | 4688 | 부모의 전체 경로. Windows 버전에 따라 없을 수 있다 |
| `CommandLine` | 4688 | 전체 명령행. **별도 정책을 켜야 채워진다.** 비어 있으면 정책 미설정 |
| `TokenElevationType` | 4688 | `%%1936` 기본 / `%%1937` 상승 / `%%1938` 제한 토큰 |
| `SubjectLogonId` | 4688 | 실행한 세션 (FOR-0104의 조인 키) |
| `SubjectUserName` | 4688 | 실행한 계정 |
| `MandatoryLabel` | 4688 | 무결성 수준 SID. `S-1-16-12288` = System, `S-1-16-8192` = High |
| `ProcessId` | 4689 | **종료된** 프로세스의 PID. 16진수 |
| `Status` | 4689 | 종료 코드 |
| `ProcessGuid` | Sysmon 1 | 재사용 없는 유일 키 |
| `ParentProcessGuid` | Sysmon 1 | 부모의 `ProcessGuid` |
| `Image` / `ParentImage` | Sysmon 1 | 전체 경로 |
| `OriginalFileName` | Sysmon 1 | PE에 박힌 원래 파일명 |
| `IntegrityLevel` | Sysmon 1 | `Medium` / `High` / `System` |

`TokenElevationType` 의 `%%1937`(상승)은 UAC 승격을 거쳤다는 뜻이다. `%%1938`(제한)은 관리자 계정이지만 승격 없이 실행됐다는 뜻이다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| `SubjectLogonId` | 4624 (FOR-0104) | 어느 세션·어느 IP에서 실행됐나 |
| 계보의 루트 | 4624 / 7045 / 4698 | 로그온·서비스·작업 스케줄러 중 무엇이 시작점인가 |
| `NewProcessName` 경로 | `$MFT` / `$J` ([FOR-0050](./ntfs-artifact-timeline.html)) | 그 실행 파일이 언제 어디서 만들어졌나 |
| `CommandLine` 이 비어 있다 | Sysmon 1, PowerShell 4103/4104 | 명령행 원본 확보 |
| PID (10진수) | 메모리 `windows.cmdline` / `pstree` ([FOR-0214](./volatility-pslist.html)) | 획득 시각의 실제 인자와 메모리 내용 |
| 프로세스 이름 | Prefetch / Amcache | 4688이 없던 구간의 실행 흔적 |
| `ProcessGuid` | Sysmon 3 / 11 / 13 | 그 프로세스의 네트워크·파일·레지스트리 행위 |
| 위장 경로 | `$MFT` 생성 시각, 다운로드 흔적 | 어디서 왔나 |

## 흔한 함정

- **16진수와 10진수를 섞는 것.** Security의 `0x1a4c` 와 Sysmon의 `6732` 는 같은 프로세스다. 문자열로 비교하면 절대 매칭되지 않는다. → 조인 전에 한쪽 진법으로 정규화한다.
- **`ProcessId` 를 자식 PID로 읽는 것.** 4688에서 자식은 `NewProcessId` 이고 `ProcessId` 는 **부모**다. 이름 때문에 뒤집어 읽는 사고가 가장 많다. → 필드 이름을 표에서 확인하고 쓴다.
- **PID 단독으로 추적하는 것.** PID는 재사용된다. 같은 PID의 4688이 여러 개면 시각으로 구간을 나눠야 한다. → `ProcessGuid` 또는 `(PID + 생성 시각)` 을 키로 쓴다.
- **부모를 PID만으로 찾는 것.** 재사용된 나중 프로세스를 부모로 잡는다. → "자식 생성 시각 이전에 생성된 같은 PID 중 가장 최근 것"으로 찾는다.
- **파일명으로 정상 여부를 판정하는 것.** `C:\Users\Public\svchost.exe` 는 파일명이 정상과 같다. → 항상 전체 경로로 판정한다.
- **Volatility의 프로세스 이름을 그대로 검색하는 것.** 15자로 잘려 `powershell.ex` 로 나온다. → 부분 일치로 검색한다.
- **`CommandLine` 이 비어 있는 것을 "인자 없이 실행"으로 읽는 것.** 명령행 감사 정책이 꺼져 있으면 필드 자체가 비거나 없다. → 다른 4688의 `CommandLine` 도 전부 비었는지 확인해 정책 문제인지 판정한다.
- **4689가 없는 것을 "종료되지 않았다"로 읽는 것.** 프로세스 종료 감사는 기본으로 꺼져 있다. → 없음을 근거로 쓰지 않는다.
- **4688과 4689를 PID만으로 짝짓는 것.** 재사용된 PID의 4689가 붙는다. → 이미지 이름이 일치하는지 검산한다.
- **같은 초의 4688 순서를 시각으로 정하는 것.** 프로세스 생성은 1초에 여러 개가 몰린다. → `EventRecordId` 로 정렬한다 (FOR-0103).
- **UTC/KST 혼동.** EVTX `SystemTime` 은 UTC다. 생존 구간과 실행 시각을 그대로 제출하면 9시간 어긋난다. → 축은 UTC로 두고 답을 낼 때만 +9시간.
- **`TokenElevationType` 을 무시하는 것.** `%%1937` 은 UAC 승격을 거친 실행이다. 권한 상승 서술의 직접 근거다.

## 교차검증

```powershell
# 1) 같은 프로세스가 4688 과 Sysmon 1 에 모두 있는가 (진법 변환 검산)
$secPid = '0x1a4c'
$dec = [Convert]::ToInt64(($secPid -replace '^0[xX]',''), 16)
"hex $secPid = dec $dec"

Get-WinEvent -Path 'C:\case\Microsoft-Windows-Sysmon%4Operational.evtx' -Oldest -FilterXPath '*[System[(EventID=1)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    if ([int64]$d['ProcessId'] -eq $dec) { $d['Image'] + ' | ' + $d['ProcessGuid'] }
  }

# 2) 4688 의 NewProcessName 과 4689 의 ProcessName 이 일치하는가
$procs | Where-Object { $_.PidDec -eq $dec } | Select-Object TimeUTC, Image
$exits | Where-Object { $_.PidDec -eq $dec } | Select-Object TimeUTC, Image

# 3) 계보의 각 단계가 같은 세션인가 (다르면 권한 전환이 있었다)
$procs | Where-Object { $_.PidDec -in 6732,4188,1044 } |
  Select-Object TimeUTC, PidDec, PpidDec, Session, Image | Format-Table -AutoSize

# 4) 실행 파일이 디스크에 실제로 있었는가
Import-Csv 'C:\case\out\mft.csv' | Where-Object { $_.FileName -eq 'rclone.exe' } |
  Select-Object ParentPath, FileName, Created0x10, InUse
```

```bash
# 5) 메모리와 대조 (PID 10진수)
vol.py -f mem.raw windows.pstree | grep -i 'powershell\|6732'
vol.py -f mem.raw windows.cmdline --pid 6732
```

## mini walkthrough

```text
문제:
"powershell.exe 가 인코딩된 명령을 실행했습니다.
 이 powershell 을 실행한 최초의 프로세스(계보의 루트)를 구하세요.
 첨부: Security.evtx, Microsoft-Windows-Sysmon%4Operational.evtx"

1. 4688 에서 powershell 을 찾는다
   Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest `
     -FilterXPath '*[System[(EventID=4688)]]' | ...

   TimeUTC                       NewProcessId ProcessId NewProcessName            CommandLine
   2026-03-14T07:20:08.4410021Z  0x1a4c       0x105c    ...\powershell.exe        powershell.exe -enc SQBFAFgA...

   자식 PID = 0x1a4c, 부모 PID = 0x105c

2. 첫 시도 (실패):
   Sysmon 에서 부모를 찾으려고 PID 를 그대로 검색했다.

   Get-WinEvent -Path 'C:\case\Microsoft-Windows-Sysmon%4Operational.evtx' -Oldest |
     Where-Object { $_.Message -match '105c' }
   -> 0건.

   무엇이 틀렸나:
     Security 의 0x105c 는 16진수다. Sysmon 의 ProcessId 는 10진수 4188 로 기록된다.
     '105c' 라는 문자열은 Sysmon 로그에 존재하지 않는다.

   [Convert]::ToInt32('105c', 16)  -> 4188
   다시 검색 -> Sysmon 1: ProcessId=4188 Image=C:\Windows\System32\cmd.exe

3. 두 번째 시도 (실패):
   cmd.exe(4188)의 부모를 4688 에서 PID 로만 찾았다.

   $procs | Where-Object { $_.PidDec -eq 4188 } | Select TimeUTC, Image

   TimeUTC                       Image
   2026-03-14T07:19:31.0021110Z  C:\Windows\System32\cmd.exe
   2026-03-14T09:14:52.6610220Z  C:\Windows\System32\taskhostw.exe

   같은 PID 4188 이 두 개다. 뒤의 taskhostw.exe 를 부모로 잡아
   "작업 스케줄러가 시작점" 이라고 답했다. 오답.

   무엇이 틀렸나:
     PID 는 재사용된다. 07:20:08 에 생성된 자식의 부모는
     07:20:08 보다 먼저 생성된 4188 이어야 한다.
     09:14:52 의 taskhostw.exe 는 사건 이후의 다른 프로세스다.

4. 접근 변경 — "자식 생성 시각 이전 + 가장 최근" 조건을 넣는다
   Get-Ancestry -TargetPid 6732 -Before ([datetime]'2026-03-14T07:21:00Z')

   TimeUTC                       PidDec PpidDec Image
   2026-03-14T07:20:08.4410021Z  6732   4188    ...\powershell.exe
   2026-03-14T07:19:31.0021110Z  4188   1044    C:\Windows\System32\cmd.exe
   2026-03-14T07:19:04.1180022Z  1044   760     C:\Windows\System32\rdpclip.exe

   1044 의 부모 760 에 대한 4688 이 없다 -> 감사 시작 이전에 실행된 프로세스다.

5. 세 번째 확인 — Sysmon ProcessGuid 로 검산
   Sysmon 1 에서 ProcessGuid 체인을 따라간다.
     powershell.exe  ProcessGuid {...1e00}  ParentProcessGuid {...1c40}
     cmd.exe         ProcessGuid {...1c40}  ParentProcessGuid {...1a80}
     rdpclip.exe     ProcessGuid {...1a80}  ParentProcessGuid {...0300}
     svchost.exe     ProcessGuid {...0300}  (services.exe 하위)

   GUID 체인이 4단계의 PID 체인과 일치한다. 재사용 오류가 없다는 확증이다.

6. 루트 판정
   rdpclip.exe 는 RDP 세션에서 실행되는 클립보드 프로세스다.
   4688 의 SubjectLogonId = 0x1a2b3c 를 4624 로 되짚으면
   Logon Type 10 (RDP), IpAddress 203.0.113.77.

정답: RDP 세션(4624 Type 10, LogonId 0x1a2b3c)에서 시작된
      rdpclip.exe -> cmd.exe -> powershell.exe 계보.
      계보의 실질적 루트는 RDP 로그온이다.
```

세 번의 교정이 핵심이다. **① 진법을 통일하지 않으면 조인이 0건이다.** **② PID로만 부모를 찾으면 재사용된 다른 프로세스를 잡는다** — 시각 조건이 필수다. **③ `ProcessGuid` 체인으로 검산**하면 재사용 오류를 확실히 배제할 수 있다.

## 막혔을 때 다음 체크

1. Security의 PID를 10진수로 변환했는가 (`[Convert]::ToInt32(...,16)`)
2. `NewProcessId`(자식)와 `ProcessId`(부모)를 뒤집어 읽지 않았는가
3. 같은 PID의 4688이 여러 개인가 — 재사용 여부를 먼저 확인
4. 부모를 찾을 때 "자식 생성 시각 이전"이라는 조건을 넣었는가
5. Sysmon이 있는가 — 있으면 `ProcessGuid` 로 다시 검산
6. `CommandLine` 이 비어 있는가 — 전부 비었으면 정책 문제다
7. 4689가 있는가 — 있으면 생존 구간, 없으면 감사 미설정
8. 4688/4689 짝의 이미지 이름이 일치하는가
9. 전체 경로로 판정했는가 (파일명만으로는 위장을 못 잡는다)
10. Volatility 이름이 15자로 잘린 것을 감안했는가
11. 같은 초의 4688을 `EventRecordId` 로 정렬했는가
12. `SubjectLogonId` 로 4624까지 되짚었는가
13. `TokenElevationType` 으로 승격 여부를 확인했는가
14. 답 시각을 KST(+9시간)로 낼지 확인했는가

## 출처

- SRC-021 — Microsoft Learn, Event 4688: `NewProcessId`(자식, 16진수), `NewProcessName`, `ProcessId`(부모, 16진수), `ParentProcessName`, `CommandLine`, `TokenElevationType`(`%%1936`/`%%1937`/`%%1938`), `MandatoryLabel`, `SubjectLogonId` 필드 정의와 명령행 감사가 별도 설정이라는 근거
- SRC-024 — Microsoft Learn, Sysmon: Event 1의 `ProcessGuid`, `ProcessId`, `Image`, `OriginalFileName`, `ParentProcessGuid`, `ParentProcessId`, `ParentImage`, `IntegrityLevel`, `LogonId` 필드 구성과 `ProcessGuid` 가 프로세스를 유일하게 식별한다는 근거
- SRC-006 — Volatility 3 문서: `windows.pslist`, `windows.pstree`, `windows.cmdline` 의 PID/PPID 출력
- 4689(프로세스 종료)의 `ProcessId`/`ProcessName`/`Status` 필드는 Microsoft 감사 정책 문서 기준이며, 이 글에서는 생존 구간 판정 용도로만 사용했다. 정확한 필드 목록은 실제 이벤트 XML에서 확인할 것
- `ParentProcessName` 필드의 존재 여부와 Volatility 출력의 이름 절단 길이는 Windows/도구 버전에 따라 다르므로 실제 데이터에서 확인할 것
