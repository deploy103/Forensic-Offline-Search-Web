---
id: FOR-0092
title: "Event ID 4608 Windows 시작: 부팅 세션으로 로그를 구간화한다"
slug: "event-4608-startup"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "System.evtx", "4608", "4609", "부팅 세션", "Security State Change", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"]
registry_paths: []
event_ids: ["4608", "4609", "4616"]
protocols: []
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4608}", "Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4608,4609}", "EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv", "auditpol /get /subcategory:\"Security State Change\""]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeCreated", "SystemTime", "EventRecordID", "Computer", "BootMode", "StartTime", "StopTime"]
file_formats: ["evtx"]
primary_terms: ["4608", "Windows 시작", "부팅 이벤트 보안로그"]
keywords: ["4608", "4609", "Windows 시작", "Windows 시작 중", "부팅 이벤트", "부팅 세션", "가동 시간", "uptime", "Kernel-General 12", "Kernel-Power 41", "1074", "4616", "Security State Change"]
aliases: ["4608", "언제 부팅했나", "부팅 시각 이벤트", "재부팅 흔적", "windows 시작 이벤트", "가동 시간 계산", "몇 번째 부팅"]
symptom_keywords: ["언제 부팅했는지 알고 싶다", "재부팅이 몇 번 있었는지", "이 사건이 몇 번째 부팅에서 일어났나", "로그에 구멍이 있다", "가동 시간을 계산해야 한다", "4608이 없다"]
related: ["FOR-0093", "FOR-0094", "FOR-0091", "FOR-0103"]
source_ids: ["SRC-022", "SRC-026", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4608은 Security 감사 하위 시스템이 부팅과 함께 올라왔음을 알리는 이벤트로 **페이로드가 사실상 없다 — 값은 오직 "시각" 자체**다. 이 시각들로 로그를 부팅 세션 단위로 잘라 놓으면 "이 사건은 몇 번째 부팅 중에 일어났는가"를 답할 수 있다.

## 어떤 문제에서 필요한가

- "시스템이 언제 부팅됐나 / 몇 번 재부팅됐나"
- "이 이벤트는 몇 번째 부팅 세션에서 발생했나" (지속성 검증의 핵심)
- "로그에 비어 있는 구간이 있다. 삭제인가, 꺼져 있었던 것인가"
- "시스템 가동 시간(uptime)은 얼마인가"
- "재부팅 후에도 악성코드가 살아남았나" — 서비스/Run 키 지속성은 **부팅 경계를 넘어야** 증명된다
- "타임스탬프가 뒤엉켰다" (4616 시각 변경과 함께)

부팅 이벤트는 사건 시각 자체를 답하는 문제로도 나오지만, 진짜 가치는 **다른 모든 이벤트를 배치할 좌표계**를 만들어 주는 것이다.

## 문제에서 처음 볼 단서

1. 지문에 "부팅", "재부팅", "시작", "가동 시간" → 4608 + 6005 확인
2. 지속성 문제 → 악성 프로세스 실행 시각이 **부팅 경계 뒤쪽**인지 확인
3. 로그 중간에 몇 시간~며칠의 공백 → 종료 구간인지 삭제인지 판정
4. 타임라인 순서가 이상하다 → 4616(시각 변경) 확인
5. 4608 이 하나도 없다 → 감사 미설정 또는 로그 삭제. System 채널 6005 로 이동

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4608,4609} | Format-Table
```

부팅/종료 이벤트를 한 표로 모은다. Security 채널만으로는 부족하므로 System 채널까지 합친다.

```powershell
$sec = Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4608,4609,4616} -ErrorAction SilentlyContinue
$sys = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=12,13,41,1074,6005,6006,6008,6009} -ErrorAction SilentlyContinue

$sec + $sys |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')}},
                @{n='Ch';e={$_.LogName}}, Id,
                @{n='What';e={($_.Message -split "`n")[0]}} |
  Sort-Object UTC | Format-Table -AutoSize
```

이 한 표가 곧 시스템의 전원 이력이다.

## 상세 절차

### 1단계 — 4608 의 성질을 이해한다

| 항목 | 값 |
| --- | --- |
| 채널 | `Security` |
| Provider | `Microsoft-Windows-Security-Auditing` |
| 메시지 | "Windows is starting up." (한국어 OS: "Windows가 시작되고 있습니다.") |
| 페이로드 | **없다.** `EventData` 가 비어 있거나 존재하지 않는다 |
| 감사 하위 범주 | `Audit Security State Change` (System 범주) |
| 대응 종료 이벤트 | 4609 ("Windows is shutting down.") |
| 발생 빈도 | 부팅 1회당 1건 |
| 위치 | 부팅 후 Security 채널의 매우 앞쪽 레코드 |

원본 XML:

```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4608</EventID>
    <Level>0</Level>
    <Task>12288</Task>
    <TimeCreated SystemTime="2026-03-14T06:02:14.1120833Z" />
    <EventRecordID>2</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN10-DEV</Computer>
  </System>
  <EventData />
</Event>
```

**읽을 필드가 `TimeCreated` 와 `EventRecordID` 뿐이다.** 그래서 4608 을 다루는 기술은 "필드 해석"이 아니라 "다른 이벤트와 엮는 방법"이다.

`SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 변환해 보여주므로 두 화면의 숫자가 다르다. **KST 답은 UTC + 9시간**(06:02:14Z → 15:02:14 KST). 부팅 시각은 날짜 경계에 걸리는 일이 많아 특히 조심한다. 시스템의 실제 시간대는 SYSTEM hive 의 `TimeZoneInformation` 으로 확정한다([FOR-0054](./system-timezone.html)).

### 2단계 — 부팅/종료 이벤트 세트를 전부 모은다

**이 표가 이 글의 핵심이다.** 4608 하나로는 아무것도 못 한다. 여러 Provider 의 이벤트를 겹쳐야 전원 이력이 완성된다.

| Event ID | 채널 | Provider | 의미 | 신뢰도/특징 |
| --- | --- | --- | --- | --- |
| `4608` | Security | Security-Auditing | Windows 시작 (감사 서브시스템 기동) | 감사 정책 의존. 페이로드 없음 |
| `4609` | Security | Security-Auditing | Windows 종료 | **정상 종료 때만.** 크래시·전원 차단 시 없다 |
| `4616` | Security | Security-Auditing | 시스템 시각 변경 | 타임라인 신뢰성 판정에 필수 |
| `12` | System | Microsoft-Windows-Kernel-General | 운영 체제가 시작됨 | **커널 관점의 부팅 시각.** OS 버전·부팅 모드 정보 포함 |
| `13` | System | Microsoft-Windows-Kernel-General | 운영 체제가 종료됨 | 커널 관점의 종료 시각 |
| `6005` | System | EventLog | **이벤트 로그 서비스 시작** | 부팅 시각 지표로 가장 널리 쓰인다 ([FOR-0093](./event-6005-eventlog-start.html)) |
| `6006` | System | EventLog | 이벤트 로그 서비스 종료 | 정상 종료 지표 ([FOR-0094](./event-6006-eventlog-stop.html)) |
| `6008` | System | EventLog | **이전 시스템 종료가 예기치 않았음** | 페이로드에 마지막 종료 시각을 담는다 |
| `6009` | System | EventLog | 부팅 시 OS 버전 정보 기록 | 부팅마다 1건. 버전 확인용 |
| `41` | System | Microsoft-Windows-Kernel-Power | 정상 종료 없이 재부팅됨 | 전원 차단·강제 리셋·크래시 |
| `1074` | System | User32 (또는 해당 프로세스) | **종료/재시작이 요청됨** | 요청한 프로세스·사용자·이유까지 담는다. 정보량 최다 |

읽는 순서:

1. `6005` 로 부팅 시각 목록을 만든다 (가장 잘 남는다)
2. `4608` 로 그 부팅에서 **감사가 켜져 있었는지** 확인한다
3. `6006` / `4609` / `13` 로 종료 시각을 채운다
4. 종료 이벤트가 없는 부팅 경계에는 `6008` / `41` 을 대입한다 → 비정상 종료
5. `1074` 로 "누가 왜 껐는지"를 채운다
6. `4616` 이 있으면 그 구간의 시각 해석을 보류한다

### 3단계 — 부팅 세션으로 로그를 구간화한다

부팅 시각 목록이 나오면, 모든 이벤트를 "몇 번째 부팅 세션"에 속하는지로 라벨링할 수 있다. **이것이 4608 의 실전 용도다.**

```powershell
# 1) 부팅 경계 만들기 (4608 우선, 없으면 6005 로 보강)
$boot4608 = Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4608} -ErrorAction SilentlyContinue |
  ForEach-Object { $_.TimeCreated.ToUniversalTime() }
$boot6005 = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005} -ErrorAction SilentlyContinue |
  ForEach-Object { $_.TimeCreated.ToUniversalTime() }

$boots = @($boot4608) + @($boot6005) | Sort-Object -Unique

# 2) 임의의 이벤트에 세션 번호를 붙인다
function Get-BootSession {
  param($TimeUtc, $Boots)
  $n = 0
  foreach ($b in $Boots) { if ($TimeUtc -ge $b) { $n++ } }
  return $n
}

# 3) 예: 4688 을 세션별로 묶어 본다
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}},
                @{n='Session';e={Get-BootSession $_.TimeCreated.ToUniversalTime() $boots}},
                Id |
  Group-Object Session | Select-Object Name, Count
```

세션 번호가 붙으면 다음 판정이 가능해진다.

| 관찰 | 판정 |
| --- | --- |
| 악성 프로세스가 **세션 1과 세션 2 모두**에서 실행됐다 | 재부팅을 넘어 살아남았다 → **지속성 확정** |
| 악성 프로세스가 세션 2에만 있다 | 그 세션에서 처음 심어졌다 → 침입 시점 후보 |
| 서비스 등록(7045)은 세션 1, 실행(7036)은 세션 2 | 등록 후 재부팅으로 발동. auto start 지속성 |
| 로그온(4624)이 세션 경계 직후 수 초 안에 발생 | 자동 로그온 또는 서비스 계정 |
| 문제의 사건이 세션 3에 있고 세션 3의 부팅이 사용자 요청(1074)이었다 | 사용자가 직접 재부팅한 뒤의 활동 |

### 4단계 — 가동 시간(uptime)을 계산한다

```powershell
# 부팅/종료 이벤트를 한 줄로 세워 구간을 만든다
$ev = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005,6006} -ErrorAction SilentlyContinue |
  ForEach-Object {
    $kind = 'DOWN'
    if ($_.Id -eq 6005) { $kind = 'UP' }
    [pscustomobject]@{ UTC = $_.TimeCreated.ToUniversalTime(); Kind = $kind }
  } | Sort-Object UTC

$start = $null
foreach ($e in $ev) {
  if ($e.Kind -eq 'UP') { $start = $e.UTC }
  elseif ($start) {
    '{0} ~ {1}  ({2:N1} 시간)' -f $start, $e.UTC, ($e.UTC - $start).TotalHours
    $start = $null
  }
}
if ($start) { "$start ~ (종료 기록 없음 — 비정상 종료 또는 로그 끝)" }
```

출력 예시:

```text
2026-03-11 02:14:07 ~ 2026-03-13 21:40:55  (67.4 시간)
2026-03-14 06:02:11 ~ (종료 기록 없음 — 비정상 종료 또는 로그 끝)
```

종료 기록이 없는 구간은 (a) 이미지 획득 시점까지 계속 켜져 있었거나 (b) 비정상 종료다. **어느 쪽인지는 다음 부팅 뒤의 6008 / 41 유무로 가른다**([FOR-0094](./event-6006-eventlog-stop.html)).

### 5단계 — 4608 이 없는 구간을 해석한다

`6005` 는 있는데 `4608` 이 없는 부팅 세션이 나오면, 그 구간은 **감사 기록을 신뢰할 수 없는 구간**이다.

| 관찰 | 가능한 원인 | 확인 방법 |
| --- | --- | --- |
| 4608 이 전 구간에서 하나도 없다 | `Audit Security State Change` 하위 범주가 꺼져 있다 | `auditpol /get /subcategory:"Security State Change"`, SECURITY hive 의 감사 정책 |
| 특정 세션에만 4608 이 없다 | 그 세션 이후 Security 로그가 지워졌다 | **1102** ([FOR-0091](./event-1102-log-cleared.html)), 최초 레코드 시각 |
| 4608 이 있는데 그 앞의 레코드가 4608 보다 오래됐다 | 로그가 부팅을 넘어 누적된 정상 상태 | 정상 |
| Security 채널의 최초 레코드가 4608 이고 `EventRecordID` = 1~3 | 로그가 비워진 뒤 새로 시작 | 1102, 롤오버 여부 |
| 4608 시각이 6005 보다 **한참 앞이다** | 시각 조작 가능성 | **4616**, 6005/6008 대조 |

**"4608 이 없는 구간 = 로그 삭제 또는 감사 미설정"** — 이 두 가지를 구분하는 방법은 전 구간에 4608 이 없는지(정책), 특정 구간만 없는지(삭제)를 보는 것이다.

## 출력 필드 해석

4608 자체에는 읽을 페이로드가 없으므로, 함께 보는 이벤트의 필드를 정리한다.

| 이벤트 | 주요 필드 | 의미 |
| --- | --- | --- |
| `4608` | (없음). `TimeCreated`, `EventRecordID`, `Computer` | 시각과 레코드 번호가 전부 |
| `4609` | (없음) | 정상 종료 시각 |
| `4616` | `SubjectUserName`, `SubjectLogonId`, `PreviousTime`, `NewTime`, `ProcessName` | **누가 어떤 프로세스로 시각을 어떻게 바꿨나** |
| `12` (Kernel-General) | `StartTime`, OS 버전 정보, `BootMode` | 커널 부팅 시각과 부팅 모드(정상/안전 모드) |
| `13` (Kernel-General) | `StopTime` | 커널 종료 시각 |
| `6008` | 마지막 종료 시각(날짜/시각) | **비정상 종료가 언제 일어났는지** |
| `6009` | OS 버전·빌드·프로세서 정보 | 부팅 시점의 시스템 구성 |
| `41` (Kernel-Power) | `BugcheckCode`, `PowerButtonTimestamp` 등 | 크래시인지 전원 차단인지 구분 단서 |
| `1074` | 프로세스 이름, 사용자, 이유 코드, 종료 유형, 주석 | **누가 왜 껐는지.** 위치 기반 `param1`~`param7` 로 저장된다 |

`4616` 은 특별히 중요하다. `PreviousTime` 과 `NewTime` 의 차이가 크면 그 구간의 모든 타임스탬프 해석이 흔들린다. `ProcessName` 이 `svchost.exe`(시간 동기화 서비스)면 정상적인 NTP 보정일 수 있지만, `cmd.exe` / `powershell.exe` / `net.exe` 라면 **의도적 조작**이다.

## pivot: 다음에 볼 artifact

| 4608에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 부팅 시각 목록 | 6005 ([FOR-0093](./event-6005-eventlog-start.html)) | 더 잘 남는 부팅 지표로 교차검증 |
| 종료 기록 없는 경계 | 6008 / 41 ([FOR-0094](./event-6006-eventlog-stop.html)) | 비정상 종료 확정과 그 시각 |
| 부팅 세션 번호 | 4688 ([FOR-0088](./event-4688-process-creation.html)) | 세션별 실행 프로세스 → 지속성 판정 |
| 부팅 세션 번호 | 4624 ([FOR-0083](./event-4624-logon.html)) | 세션별 로그온. 부팅 직후 로그온은 자동 로그온 의심 |
| 부팅 직후 실행 | 7045 / 7036, Run 키, 예약 작업 | 어떤 지속성이 발동했나 |
| 4608 이 없는 구간 | 1102 ([FOR-0091](./event-1102-log-cleared.html)) | 로그 삭제 여부 |
| 4616 존재 | 그 구간의 모든 타임스탬프 | 시각 조작 보정 |
| 부팅 시각 | `$MFT` ([FOR-0021](./mft-basics.html)) | 부팅마다 갱신되는 파일(pagefile, 로그, Prefetch)의 시각 |
| 부팅 시각 | Prefetch, SRUM | 부팅 직후 실행 목록 |

## 흔한 함정

- **4608 을 "부팅 시각"으로 그대로 답한다.** 4608 은 **감사 서브시스템이 준비된 시각**이다. 커널 부팅(`12`)이나 전원 인가 시각보다 뒤다. 문제가 "부팅 시각"을 물으면 6005 또는 Kernel-General 12 를 함께 제시하는 편이 안전하다.
- **4609 가 없으면 종료가 없었다고 본다.** 4609 는 정상 종료에서만 나온다. 전원 차단·크래시·강제 리셋에서는 아예 기록되지 않는다. 그 경우 다음 부팅의 6008 / 41 이 증거다.
- **4608 을 4609 와 기계적으로 짝짓는다.** 비정상 종료가 끼면 `4608 → 4608` 이 연속으로 나온다. 무조건 짝지으면 가동 시간이 며칠로 부풀거나 음수가 된다.
- **로그의 공백을 곧바로 삭제로 단정한다.** 시스템이 꺼져 있던 구간에는 원래 이벤트가 없다. 공백의 양 끝에 종료/부팅 이벤트가 있으면 정상이다.
- **감사 미설정과 로그 삭제를 구분하지 않는다.** 전 구간에 4608 이 없으면 정책 문제, 특정 구간만 없으면 삭제 가능성이다.
- **4616 을 무시한 채 타임라인을 확정한다.** 시각이 바뀐 구간에서는 `EventRecordID` 순서가 시각 순서보다 신뢰도가 높다. 순서 판정은 레코드 번호로 한다.
- **UTC/로컬 혼동.** EVTX `SystemTime` 은 UTC 다. 부팅 시각은 새벽·심야에 걸리는 경우가 많아 +9시간을 적용하면 날짜가 바뀐다. KST 로 답할 때 날짜까지 다시 확인한다.
- **하나의 채널만 본다.** 4608/4609 는 Security, 6005/6006/6008/12/13/41/1074 는 System 이다. 한 채널만 열면 전원 이력의 절반이 사라진다.
- **부팅 세션 라벨링 없이 지속성을 주장한다.** "재부팅 후에도 실행됐다"는 주장은 부팅 경계를 명시해야 성립한다. 시각만 나열하면 근거가 약하다.
- **가상 머신 스냅샷 복원을 고려하지 않는다.** 스냅샷을 되돌리면 부팅 이력이 시간을 거슬러 보일 수 있다. 레코드 번호와 시각이 동시에 역행하면 이 가능성을 검토한다.

## 교차검증

```powershell
# 1) Security 채널의 시작/종료/시각 변경
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4608,4609,4616} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId, Id |
  Sort-Object UTC

# 2) System 채널의 전원 이력 전체
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=12,13,41,1074,6005,6006,6008,6009} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id,
                @{n='Msg';e={($_.Message -split "`n")[0]}} |
  Sort-Object UTC | Format-Table -AutoSize

# 3) 4608 과 6005 의 시각 차이 (정상적으로는 수 초 이내)
$a = Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4608} |
  ForEach-Object { $_.TimeCreated.ToUniversalTime() } | Sort-Object
$b = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005} |
  ForEach-Object { $_.TimeCreated.ToUniversalTime() } | Sort-Object
Compare-Object $a $b | Format-Table -AutoSize

# 4) 시각 변경의 주체 확인
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4616} | Format-List Message

# 5) 감사 정책 상태 (라이브 시스템)
auditpol /get /subcategory:"Security State Change"
```

EvtxECmd 로 여러 채널을 한 번에 뽑아 Timeline Explorer 에서 정렬하면 전원 이력 표가 즉시 만들어진다.

```powershell
EvtxECmd.exe -d 'C:\case\winevt\Logs' --csv 'C:\case\out' --csvf all.csv
```

## mini walkthrough

```text
문제:
"악성 서비스가 재부팅 후에도 동작했는지 판정하고, 그 사건이 몇 번째 부팅
 세션에서 시작됐는지 답하세요. 또 시스템 가동 시간을 구하세요.
 첨부: Security.evtx, System.evtx"

1. 첫 시도 (실패):
   4608 과 4609 를 시간순으로 세워 짝을 지었다.

   4608  2026-03-11 02:14:09Z
   4608  2026-03-14 06:02:14Z
   4609  2026-03-15 22:10:03Z

   4608(03-11) 과 4609(03-15) 를 짝지어 "가동 시간 116시간" 이라고 계산했다.
   그런데 중간에 4608 이 또 있다. 즉 03-11 세션은 4609 없이 끝났다.
   116시간은 두 세션을 합쳐 버린 값이었다.
   -> 4608/4609 를 기계적으로 1:1 로 짝지은 것이 실수.

2. 왜 4609 가 없었나 — System 채널을 봤다:
   6005  2026-03-11 02:14:07Z
   6006  없음
   6008  2026-03-14 06:02:20Z  "이전 시스템 종료(2026-03-13 21:40:55)가 예기치 않았습니다"
   41    2026-03-14 06:02:09Z  Kernel-Power

   03-13 21:40:55Z 에 비정상 종료가 있었다.
   4609 가 없는 이유가 설명된다. 종료 시각은 6008 의 페이로드에 있었다.

3. 올바른 전원 이력:
   세션 1 : 2026-03-11 02:14:07Z ~ 2026-03-13 21:40:55Z  (약 67.4시간, 비정상 종료)
   세션 2 : 2026-03-14 06:02:11Z ~ 2026-03-15 22:10:03Z  (약 40.1시간, 정상 종료)

4. 사건을 세션에 배치 — 7045 와 7036:
   7045  2026-03-13 19:22:41Z  wqmtsbrv 서비스 설치 (auto start)  -> 세션 1
   7036  2026-03-13 19:22:42Z  wqmtsbrv 실행 중                    -> 세션 1
   7036  2026-03-14 06:02:35Z  wqmtsbrv 실행 중                    -> 세션 2

   같은 서비스가 세션 1과 세션 2 모두에서 실행됐다.
   부팅 경계를 넘었다 -> 지속성 확정.

5. 4608 이 없는 구간 점검:
   세션 1에는 4608 이 있는데 세션 2에는 없었다.
   Security.evtx 의 최초 레코드 = 2026-03-14 15:41:22Z, RecordId = 1
   -> 세션 2 중간에 로그가 지워졌다(1102 확인). 세션 2의 4608 은 그때 함께 사라졌다.
   그래서 세션 2의 부팅 시각은 6005(06:02:11Z)로 확정했다.

6. 시각 신뢰성:
   4616 은 0건. 시각 조작은 없었다.

7. 시각 변환:
   서비스 설치 2026-03-13 19:22:41Z -> KST 2026-03-14 04:22:41.
   날짜가 넘어간다. UTC 로 답할지 KST 로 답할지 지문을 확인한다.

정답: 지속성 있음(세션 1에서 설치, 세션 2에서 재실행).
      사건 시작은 세션 1(2026-03-11 02:14:07Z 부팅).
      세션 1 가동 약 67.4시간, 세션 2 가동 약 40.1시간.
```

1단계의 실패가 이 글의 핵심이다. **4608 과 4609 는 1:1 대응이 아니다.** 비정상 종료가 끼면 4609 는 아예 없고, 그 사실은 다음 부팅의 6008 / 41 에만 남는다. 부팅 세션 경계는 **Security 채널만으로 그릴 수 없다.**

## 막혔을 때 다음 체크

1. Security 와 System 두 채널을 모두 열었는가 — 4608/4609 와 6005/6006 은 다른 파일이다
2. 4608 개수와 6005 개수가 일치하는가 — 다르면 감사 미설정 또는 로그 삭제
3. 4609 가 없는 경계에 6008 / 41 이 있는지 확인했는가 — 비정상 종료 판정
4. `1074` 를 읽어 "누가 왜 껐는지"를 확인했는가
5. 4616 이 있는지 확인했는가 — 있으면 그 구간의 시각 해석을 보류하고 `EventRecordID` 순서를 쓴다
6. 모든 관심 이벤트에 부팅 세션 번호를 붙였는가
7. 지속성을 주장할 때 **부팅 경계를 넘는 실행 기록**을 제시했는가
8. 로그 공백의 양 끝에 종료/부팅 이벤트가 있는지 확인했는가 (있으면 정상, 없으면 삭제 의심)
9. 4608 이 전 구간에 없으면 → 감사 정책, 특정 구간만 없으면 → 1102
10. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가 — 부팅 시각은 날짜가 바뀌기 쉽다

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 4608 / 4609 / 4616 이 속한 `Audit Security State Change` 하위 범주와 각 이벤트의 의미
- SRC-026 — Libyal libevtx / EVTX 파일 포맷 문서: `EventRecordID` 의 단조 증가 성질(시각이 조작된 구간에서 순서 판정에 쓰는 근거)과 채널별 파일 구조
- SRC-004 — Eric Zimmerman 문서: EvtxECmd 로 `winevt\Logs` 디렉터리 전체를 한 CSV 로 뽑아 Timeline Explorer 에서 다채널 타임라인을 만드는 방법
- Kernel-General 12/13 의 필드 이름(`StartTime`, `StopTime`, `BootMode`)과 1074 의 `param1`~`param7` 배치, 41(Kernel-Power)의 필드 구성은 Windows 버전에 따라 다를 수 있으므로 실제 이벤트 XML 에서 확인할 것
- `Audit Security State Change` 하위 범주의 기본 활성 여부는 OS 버전과 적용된 보안 기준선에 따라 다르다. 4608 이 없다는 사실만으로 로그 삭제를 단정하지 말 것
- `auditpol` 하위 범주 이름은 OS 언어에 따라 현지화되므로 한국어 OS 에서는 `auditpol /get /category:*` 로 전체 목록을 확인할 것
</content>
