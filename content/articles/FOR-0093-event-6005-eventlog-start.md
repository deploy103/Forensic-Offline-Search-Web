---
id: FOR-0093
title: "Event ID 6005 EventLog 서비스 시작: 가장 믿을 수 있는 부팅 시각 지표"
slug: "event-6005-eventlog-start"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["System.evtx", "6005", "6009", "EventLog 서비스", "부팅 시각", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\pagefile.sys", "C:\\Windows\\Prefetch"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"]
event_ids: ["6005", "6009"]
protocols: []
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Registry Explorer", "Timeline Explorer"]
commands: ["Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=6005}", "Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=6005,6006,6008,6009}", "EvtxECmd.exe -f System.evtx --csv . --csvf sys.csv", "wevtutil qe System.evtx /q:\"*[System[(EventID=6005)]]\" /f:text"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeCreated", "SystemTime", "EventRecordID", "Computer", "ProviderName"]
file_formats: ["evtx"]
primary_terms: ["6005", "EventLog 서비스 시작", "부팅 시각 판정"]
keywords: ["6005", "6009", "부팅 시각", "boot time", "EventLog 서비스", "event log service was started", "System.evtx", "부팅 이력", "롤오버", "ShutdownTime", "InstallDate"]
aliases: ["6005", "부팅 시각 찾기", "언제 켰나", "부팅 이력 표", "6005 6006", "컴퓨터 켠 시각", "system.evtx 부팅"]
symptom_keywords: ["부팅 시각을 확정해야 한다", "부팅이 몇 번 있었는지 알고 싶다", "6005만 있고 6006이 없다", "부팅 시각이 역행한다", "가장 오래된 로그가 최초 부팅인지 모르겠다"]
related: ["FOR-0092", "FOR-0094", "FOR-0091", "FOR-0053"]
source_ids: ["SRC-022", "SRC-026", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

6005는 EventLog 서비스가 기동했음을 System 채널에 남기며, 이 서비스가 **부팅 아주 초기에 시작되기 때문에 그 시각이 실질적인 부팅 시각으로 통용된다** — 감사 정책과 무관하게 기록되므로 4608보다 훨씬 잘 남는다.

## 어떤 문제에서 필요한가

- "시스템이 언제 부팅됐나" — 가장 직접적으로 답하는 이벤트
- "부팅이 몇 번 있었나 / 부팅 이력 표를 만들어야 한다"
- "직전 종료가 정상이었나" (6006 유무 → 6008 확인)
- "이 사건은 어느 부팅 세션에 속하나" ([FOR-0092](./event-4608-startup.html)의 구간화)
- "시각이 조작됐나" (6005 시각이 역행하면 4616 확인)
- "이 이미지의 OS 버전은 무엇인가" (6009)

Security 채널이 지워지거나 감사가 꺼져 있어도 **System 채널의 6005 는 거의 항상 남는다.** 부팅 시각을 물으면 여기서 시작한다.

## 문제에서 처음 볼 단서

1. 첨부에 `System.evtx` 가 있다 → 6005 를 먼저 뽑아 전원 이력 표를 만든다
2. 지문에 "부팅", "전원", "켠 시각", "재부팅 횟수" → 6005 확정
3. 4608 이 없거나 Security 로그가 비어 있다 → 6005 가 유일한 부팅 지표
4. 타임스탬프 순서가 이상하다 → 6005 시각의 단조성 확인
5. OS 버전을 물었다 → 같은 부팅의 6009

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005} | Sort-Object RecordId
```

부팅 이력 표를 바로 만든다.

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005,6006,6008,6009} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')}},
                @{n='KST';e={$_.TimeCreated.ToUniversalTime().AddHours(9).ToString('yyyy-MM-dd HH:mm:ss')}},
                Id, RecordId,
                @{n='Msg';e={($_.Message -split "`n")[0]}} |
  Sort-Object UTC | Format-Table -AutoSize
```

출력 예시:

```text
UTC                 KST                 Id   RecordId Msg
---                 ---                 --   -------- ---
2026-03-11 02:14:07 2026-03-11 11:14:07 6005     10021 이벤트 로그 서비스가 시작되었습니다.
2026-03-11 02:14:07 2026-03-11 11:14:07 6009     10022 Microsoft (R) Windows (R) ...
2026-03-13 21:40:55 2026-03-14 06:40:55 6006     10402 이벤트 로그 서비스가 중지되었습니다.
2026-03-14 06:02:11 2026-03-14 15:02:11 6005     10403 이벤트 로그 서비스가 시작되었습니다.
2026-03-14 06:02:11 2026-03-14 15:02:11 6009     10404 Microsoft (R) Windows (R) ...
```

**UTC 와 KST 를 처음부터 두 컬럼으로 뽑아 두면 답을 적을 때 실수하지 않는다.**

## 상세 절차

### 1단계 — 6005 가 왜 부팅 시각 지표로 쓰이는지 이해한다

| 항목 | 값 |
| --- | --- |
| 채널 | `System` (`C:\Windows\System32\winevt\Logs\System.evtx`) |
| Provider / Source | `EventLog` |
| 메시지 | "The Event log service was started." (한국어 OS: "이벤트 로그 서비스가 시작되었습니다.") |
| 페이로드 | 사실상 없다. **값은 시각 자체** |
| 감사 정책 필요 여부 | **불필요.** 기본으로 기록된다 |
| 발생 빈도 | 부팅 1회당 1건 |
| 왜 부팅 시각인가 | EventLog 서비스는 부팅 초기에 기동한다. 이후의 모든 이벤트가 기록되기 시작하는 기준점이므로, 이 시각 이전의 System 채널 이벤트는 (이전 부팅의 것을 제외하면) 존재하지 않는다 |

**엄밀히 말하면 6005 는 "전원 인가 시각"이 아니라 "이벤트 로깅이 가능해진 시각"이다.** 전원 인가 → 펌웨어 → 부트 로더 → 커널 초기화 → 서비스 기동 순서이므로 6005 는 실제 전원 인가보다 수 초~수십 초 뒤다. 그래도 로그로 확인 가능한 가장 이른 시각이고, 편차가 작아 실무에서 부팅 시각으로 통용된다.

더 앞선 시각이 필요하면 같은 채널의 `12`(Microsoft-Windows-Kernel-General, 운영 체제 시작)를 함께 제시한다. 둘의 차이는 보통 수 초 이내다.

`TimeCreated SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 변환해 표시하므로 두 화면의 숫자가 다르다. **KST 답은 UTC + 9시간.** 시스템의 실제 시간대는 SYSTEM hive 의 `TimeZoneInformation` 으로 확정한다([FOR-0054](./system-timezone.html)).

### 2단계 — 6005 / 6006 / 6008 / 6009 세트로 읽는다

이 네 개가 EventLog Provider 의 전원 관련 이벤트 세트다. **항상 함께 뽑는다.**

| Event ID | 의미 | 언제 기록되나 | 포렌식 가치 |
| --- | --- | --- | --- |
| `6005` | 이벤트 로그 서비스 시작 | 부팅 초기 | **부팅 시각** |
| `6006` | 이벤트 로그 서비스 중지 | 정상 종료 과정 | **정상 종료 시각** ([FOR-0094](./event-6006-eventlog-stop.html)) |
| `6008` | 이전 시스템 종료가 예기치 않았음 | **부팅 직후** | 페이로드에 **마지막 종료 시각**을 담는다 |
| `6009` | 부팅 시 OS 버전·빌드·프로세서 정보 | 부팅 직후 | 이미지의 OS 판정, 부팅 1회당 1건이므로 부팅 카운터로도 쓸 수 있다 |

핵심 판정 논리:

| 관찰 | 판정 |
| --- | --- |
| `6005` → `6006` → `6005` | 정상 종료 후 재부팅. 깔끔한 가동 구간 |
| `6005` → (6006 없음) → `6005` | **비정상 종료.** 다음 부팅 직후의 `6008` 로 종료 시각을 얻는다 |
| `6005` 뒤에 `6008` 이 붙어 있다 | 직전 종료가 비정상이었음을 이 부팅이 보고하는 것 |
| `6005` 개수 ≠ `6009` 개수 | 로그 롤오버로 일부가 잘렸다 |
| 마지막 `6005` 뒤에 `6006` 이 없다 | 이미지 획득 시점까지 켜져 있었거나, 획득 직전 강제 종료 |
| `6005` 시각이 앞의 `6005` 보다 **이르다** | 시각 조작(4616) 또는 VM 스냅샷 복원 |

**6008 은 부팅 직후에 기록되지만 그 페이로드가 가리키는 시각은 "이전 종료"다.** 이벤트 기록 시각과 페이로드 시각을 혼동하면 종료 시각과 부팅 시각이 뒤바뀐다.

### 3단계 — 부팅 이력 표를 만든다

```powershell
$ev = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005,6006} -ErrorAction SilentlyContinue |
  ForEach-Object {
    $kind = 'DOWN'
    if ($_.Id -eq 6005) { $kind = 'UP' }
    [pscustomobject]@{
      UTC  = $_.TimeCreated.ToUniversalTime()
      Kind = $kind
      Rec  = $_.RecordId
    }
  } | Sort-Object UTC

$n = 0
$start = $null
foreach ($e in $ev) {
  if ($e.Kind -eq 'UP') {
    if ($start) { '세션 {0}: {1} ~ (종료 기록 없음 — 비정상 종료 의심)' -f $n, $start }
    $n++
    $start = $e.UTC
  } else {
    if ($start) {
      '세션 {0}: {1} ~ {2}  ({3:N1} 시간, 정상 종료)' -f $n, $start, $e.UTC, ($e.UTC - $start).TotalHours
      $start = $null
    }
  }
}
if ($start) { '세션 {0}: {1} ~ (로그 끝 / 획득 시점까지 가동)' -f $n, $start }
```

출력 예시:

```text
세션 1: 2026-03-11 02:14:07 ~ 2026-03-13 21:40:55  (67.4 시간, 정상 종료)
세션 2: 2026-03-14 06:02:11 ~ (로그 끝 / 획득 시점까지 가동)
```

이 표가 나오면 모든 이벤트를 "몇 번째 세션"에 배치할 수 있다. 지속성 판정(부팅 경계를 넘는 실행)은 이 표 없이 성립하지 않는다.

### 4단계 — 6009 로 OS 버전을 확정한다

6009 는 부팅 시점의 OS 버전·빌드·서비스 팩·프로세서 정보를 메시지로 남긴다. 이미지의 OS 를 특정해야 하는 문제에서 유용하다.

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6009} |
  Select-Object -First 1 -ExpandProperty Message
```

활용:

| 목적 | 6009 로 알 수 있는 것 |
| --- | --- |
| OS 버전·빌드 판정 | 어떤 artifact 가 존재해야 하는지 결정된다 (예: AppCompatCache 포맷, Amcache 유무) |
| 부팅 횟수 세기 | 부팅 1회당 1건이므로 `6005` 와 개수가 맞아야 한다 |
| 업데이트 시점 탐지 | 빌드 번호가 바뀐 부팅이 업데이트 적용 시점 |
| 아키텍처 확인 | 프로세서 정보로 32/64비트 판단 보조 |

6009 의 개수가 6005 보다 적으면 로그가 잘린 것이고, 6009 의 빌드 번호가 중간에 바뀌면 그 부팅에서 OS 업데이트가 적용된 것이다.

### 5단계 — 다른 artifact 로 교차검증한다

6005 만으로 부팅 시각을 단정하기 전에 최소 하나는 대조한다.

| 대조 대상 | 어디서 | 무엇을 비교하나 |
| --- | --- | --- |
| Kernel-General `12` | System 채널 | 커널 시작 시각. 6005 와 수 초 이내여야 한다 |
| Security `4608` | Security 채널 ([FOR-0092](./event-4608-startup.html)) | 감사 서브시스템 기동 시각. 6005 와 근접 |
| `ShutdownTime` 레지스트리 값 | `HKLM\SYSTEM\CurrentControlSet\Control\Windows\ShutdownTime` | **마지막 종료 시각**이 FILETIME(REG_BINARY)으로 저장된다. 6006 또는 6008 페이로드와 일치해야 한다 |
| OS 설치 시각 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate` | Unix epoch 초. 가장 오래된 6005 가 이보다 이르면 논리적으로 불가능 → 로그 조작·교체 |
| `pagefile.sys` 시각 | `$MFT` ([FOR-0021](./mft-basics.html)) | 부팅마다 갱신되는 파일. 6005 와 근접해야 한다 |
| 부팅 관련 Prefetch | `C:\Windows\Prefetch` | 부팅 트레이스 `.pf` 의 마지막 실행 시각이 최근 부팅과 일치 |
| SYSTEM hive 자체 수정 시각 | `$MFT` / hive 헤더 | 마지막 종료·부팅 시각과 정합성 |
| SRUM | `SRUDB.dat` | 부팅 후 앱·네트워크 사용 시작 시각 |

FILETIME 은 **1601-01-01 UTC 기준 100나노초 단위**다. Unix epoch 와의 차이는 `11644473600` 초다. `ShutdownTime` 값을 손으로 계산할 때 쓴다.

```powershell
# ShutdownTime (REG_BINARY, 8바이트 리틀엔디언 FILETIME) 해석 예
$bytes = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Windows' -Name ShutdownTime).ShutdownTime
$ft = [BitConverter]::ToInt64($bytes, 0)
[DateTime]::FromFileTimeUtc($ft).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
```

오프라인 hive 라면 Registry Explorer 로 같은 값을 열어 읽는다. `CurrentControlSet` 은 `Select\Current` 가 가리키는 `ControlSet00N` 임을 먼저 확인한다([FOR-0053](./system-controlset.html)).

### 6단계 — 시각 조작을 탐지한다

6005 의 시각은 부팅마다 단조 증가해야 한다. 역행하면 무언가 잘못됐다.

```powershell
# RecordId 순서와 시각 순서가 어긋나는 6005 를 찾는다
$b = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId |
  Sort-Object RecordId

for ($i = 1; $i -lt $b.Count; $i++) {
  if ($b[$i].UTC -lt $b[$i-1].UTC) {
    '역행 발견: Rec {0} ({1}) -> Rec {2} ({3})' -f $b[$i-1].RecordId, $b[$i-1].UTC, $b[$i].RecordId, $b[$i].UTC
  }
}
```

| 관찰 | 원인 후보 | 확인 |
| --- | --- | --- |
| `RecordId` 는 증가하는데 시각이 역행 | **시스템 시각이 뒤로 조작됐다** | Security 채널 `4616`(이전 시각/새 시각/주체 프로세스) |
| 시각도 `RecordId` 도 역행 | 다른 시점의 EVTX 파일이 섞였거나 교체됐다 | 파일 해시, `$MFT` 의 `.evtx` 시각 |
| 부팅 시각이 미래다 | 시각 조작 또는 CMOS 배터리 문제 | 4616, 다른 호스트 로그 |
| 같은 시각의 6005 가 두 번 | VM 스냅샷 복원 | 가상 디스크 메타데이터 |

`4616` 의 `ProcessName` 이 `svchost.exe`(시간 동기화)면 정상 NTP 보정일 수 있다. `cmd.exe` / `powershell.exe` / `net.exe` 라면 의도적 조작이며, 그 구간의 모든 타임스탬프 해석을 보류하고 `EventRecordID` 순서로 사건 순서를 판정한다.

## 출력 필드 해석

6005 는 페이로드가 없으므로 System 블록의 필드가 전부다.

```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="EventLog" />
    <EventID Qualifiers="32768">6005</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-14T06:02:11.4471203Z" />
    <EventRecordID>10403</EventRecordID>
    <Channel>System</Channel>
    <Computer>WIN10-DEV</Computer>
  </System>
  <EventData />
</Event>
```

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `Provider\@Name` | `EventLog` | 6005/6006/6008/6009 는 모두 이 Provider. `Service Control Manager`(7045)와 다르다 |
| `EventID\@Qualifiers` | 레거시 이벤트 소스 표시 | 값 해석은 필요 없다. 필터는 EventID 로 한다 |
| `TimeCreated\@SystemTime` | **부팅 시각 (UTC)** | KST 는 +9시간 |
| `EventRecordID` | 채널 내 일련번호 | 시각이 조작된 구간에서 **순서 판정의 근거** |
| `Channel` | `System` | Security 채널에는 없다 |
| `Computer` | 호스트 이름 | 다중 호스트 사건에서 필수 |
| `EventData` | 비어 있음 | 6005 는 읽을 페이로드가 없다 |

## pivot: 다음에 볼 artifact

| 6005에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 부팅 시각 목록 | 6006 / 6008 ([FOR-0094](./event-6006-eventlog-stop.html)) | 종료가 정상이었나, 종료 시각은 언제인가 |
| 부팅 시각 목록 | 4608 ([FOR-0092](./event-4608-startup.html)) | 그 부팅에서 감사가 켜져 있었나 |
| 부팅 세션 경계 | 7045 / 7036 | 부팅 직후 시작된 서비스 = 지속성 발동 |
| 부팅 세션 경계 | 4688 ([FOR-0088](./event-4688-process-creation.html)) | 세션별 실행 프로세스, 부팅 경계를 넘는 실행 |
| 부팅 세션 경계 | 4624 ([FOR-0083](./event-4624-logon.html)) | 부팅 직후 로그온(자동 로그온·서비스 계정) |
| 부팅 시각 | Prefetch, SRUM, Amcache | 부팅 직후 실행 목록 |
| 부팅 시각 | `ShutdownTime` (SYSTEM hive) | 마지막 종료 시각과의 정합성 |
| 6005 개수 ≠ 6009 개수 | 로그 롤오버 판정 | 파일 크기, 최초 레코드 번호 |
| 6005 가 아예 없는 구간 | 1102 / 104 ([FOR-0091](./event-1102-log-cleared.html)) | 로그 삭제 여부 |
| 6005 시각 역행 | 4616 | 시각 조작의 주체와 폭 |

## 흔한 함정

- **6005 를 전원 인가 시각으로 단정한다.** 6005 는 EventLog 서비스 기동 시각이다. 실제 전원 인가보다 수 초~수십 초 뒤다. 정밀도가 필요한 문제에서는 Kernel-General `12` 를 함께 제시한다.
- **가장 오래된 6005 를 "최초 부팅"으로 답한다.** `System.evtx` 는 최대 크기에 도달하면 오래된 레코드를 덮어쓴다(롤오버). 최초 레코드 번호와 파일 크기를 확인해 로그가 커버하는 구간을 먼저 정한다. OS 설치 시각은 SOFTWARE hive 의 `InstallDate` 로 확인한다.
- **6006 이 없는 것을 로그 손실로 본다.** 비정상 종료에서는 6006 이 원래 기록되지 않는다. 다음 부팅의 `6008` 이 그 사실과 종료 시각을 보고한다.
- **6008 의 기록 시각을 종료 시각으로 읽는다.** 6008 은 **부팅 직후**에 기록되고, 페이로드가 가리키는 시각이 이전 종료 시각이다. 둘을 혼동하면 종료와 부팅이 뒤바뀐다.
- **6005 개수를 그대로 부팅 횟수로 답한다.** 롤오버로 잘렸을 수 있다. `6009` 개수와 맞는지, 최초 레코드가 잘려 있지 않은지 확인한다.
- **UTC/로컬 혼동.** EVTX `SystemTime` 은 UTC 다. 부팅은 새벽·심야에 걸리는 일이 많아 +9시간을 적용하면 날짜가 바뀐다. 표를 만들 때 UTC/KST 두 컬럼을 함께 뽑는다.
- **시각 역행을 파일 손상으로 넘긴다.** `RecordId` 는 증가하는데 시각이 역행하면 **시스템 시각 조작**이 1순위 원인이다. 4616 을 확인한다.
- **Security 채널에서 6005 를 찾는다.** 6005 는 System 채널이다. 채널을 틀리면 0건이 나온다.
- **6005 를 서비스 재시작으로 해석하지 않는다.** 일반적으로 6005 는 부팅 1회당 1건이지만, EventLog 서비스가 재시작되는 상황에서 부팅 없이 나타날 여지가 있다. 같은 시각에 6009 나 Kernel-General 12 가 함께 있는지로 진짜 부팅인지 가른다.
- **부팅 이력을 만들고 사건을 배치하지 않는다.** 부팅 이력은 그 자체가 답인 경우도 있지만, 대부분은 다른 이벤트를 배치할 좌표계로 쓰는 것이 목적이다.

## 교차검증

```powershell
# 1) 부팅/종료/비정상종료/버전 한 번에
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005,6006,6008,6009} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id, RecordId |
  Sort-Object UTC | Format-Table -AutoSize

# 2) 커널 관점 부팅/종료 (6005 와 수 초 이내여야 정상)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=12,13} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id

# 3) 강제 종료/전원 차단 여부
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=41,1074} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id, Message | Format-List

# 4) Security 채널의 부팅 이벤트와 대조
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4608,4616} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id

# 5) 로그가 커버하는 구간 (롤오버 판정)
Get-WinEvent -Path 'C:\case\System.evtx' -Oldest -MaxEvents 1 |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, RecordId
(Get-Item 'C:\case\System.evtx').Length
```

오프라인 레지스트리 대조:

```text
Registry Explorer 로 SYSTEM hive 를 열고
  SYSTEM\Select\Current                                  -> 1
  SYSTEM\ControlSet001\Control\Windows\ShutdownTime       -> REG_BINARY (FILETIME)
      = 마지막 종료 시각. 6006 또는 6008 페이로드와 일치해야 한다

SOFTWARE hive
  Microsoft\Windows NT\CurrentVersion\InstallDate         -> Unix epoch 초
      = OS 설치 시각. 가장 오래된 6005 가 이보다 이르면 논리적으로 불가능
```

## mini walkthrough

```text
문제:
"사건 당일 시스템이 부팅된 시각(KST)과, 그 직전 종료가 정상이었는지 판정하세요.
 첨부: System.evtx, SYSTEM hive"

1. 첫 시도 (실패):
   Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=6005} | Sort-Object RecordId
   -> 가장 오래된 6005 가 2026-03-11 02:14:07Z 였다.
   이것을 "이 시스템의 최초 부팅"이라 적고, 사건 당일 부팅도 이 값으로 답했다.

2. 왜 틀렸나:
   (a) 사건 당일은 03-14 인데 03-11 값을 썼다. 그날의 6005 를 따로 봐야 한다.
   (b) 더 근본적으로, "가장 오래된 6005 = 최초 부팅" 이 성립하지 않는다.
       Get-WinEvent -Path System.evtx -Oldest -MaxEvents 1
         -> RecordId = 9884  (1 이 아니다)
       (Get-Item System.evtx).Length -> 최대 크기에 도달
       => 롤오버로 그 앞의 부팅 기록이 덮여 사라졌다.
       SOFTWARE hive 의 InstallDate 는 2025-08-02 였다. 최초 부팅은 훨씬 전이다.
   -> 로그가 커버하는 구간을 확인하지 않은 것이 실수.

3. 방향 전환 — 사건 당일 구간만 본다:
   6005  2026-03-14 06:02:11Z   RecordId 10403
   6009  2026-03-14 06:02:11Z   RecordId 10404
   6009 가 같은 시각에 붙어 있다 -> 진짜 부팅이다(서비스 재시작이 아니다).

4. 직전 종료 판정:
   03-14 06:02:11Z 이전에 6006 이 있는가?
     마지막 6006 = 2026-03-13 21:40:55Z ... 가 아니라 0건이었다.
   대신 부팅 직후에:
     6008  2026-03-14 06:02:20Z  "이전 시스템 종료(2026-03-13 21:40:55)가 예기치 않았습니다"
     41    2026-03-14 06:02:09Z  Kernel-Power
   -> 직전 종료는 비정상. 종료 시각은 6008 페이로드의 2026-03-13 21:40:55.

5. 교차검증:
   SYSTEM hive ShutdownTime = 2026-03-13 21:40:55 UTC -> 6008 페이로드와 일치.
   Kernel-General 12 = 2026-03-14 06:02:08Z -> 6005 보다 3초 이르다. 정상 범위.
   $MFT 의 pagefile.sys 수정 시각 = 2026-03-14 06:02:1x -> 일치.

6. 시각 조작 점검:
   6005 시각은 RecordId 순서와 함께 단조 증가. 역행 없음.
   Security 채널 4616 은 0건. 시각 조작 없음.

7. 시각 변환:
   부팅 2026-03-14 06:02:11Z -> KST +9 -> 2026-03-14 15:02:11
   종료 2026-03-13 21:40:55Z -> KST +9 -> 2026-03-14 06:40:55  (날짜가 바뀐다)

정답: 부팅 2026-03-14 15:02:11 KST.
      직전 종료는 비정상(6006 없음, 6008 + Kernel-Power 41),
      종료 시각 2026-03-14 06:40:55 KST.
```

1단계의 실패가 핵심이다. **"가장 오래된 로그 = 시스템의 시작"이 아니다.** System 채널은 롤오버되며, 최초 레코드 번호와 파일 크기를 확인하지 않으면 잘린 로그의 첫 줄을 최초 부팅으로 착각한다. 4단계에서 종료 시각이 **이벤트 기록 시각이 아니라 6008 페이로드 안에** 있었다는 점도 함께 기억한다.

## 막혔을 때 다음 체크

1. `System.evtx` 를 열었는가 — 6005 는 Security 채널에 없다
2. 6005 / 6006 / 6008 / 6009 를 **한 번에** 뽑았는가
3. 최초 레코드 번호와 파일 크기를 확인해 롤오버 구간을 배제했는가
4. 6005 개수와 6009 개수가 일치하는가
5. 6006 이 없는 경계마다 6008 / 41 을 확인했는가
6. 6008 의 **페이로드 시각**(이전 종료)과 **기록 시각**(부팅)을 구분했는가
7. Kernel-General 12 와 6005 의 차이가 수 초 이내인가
8. `ShutdownTime` 레지스트리 값과 6006/6008 이 일치하는가
9. 6005 시각이 `RecordId` 순서와 함께 단조 증가하는가 — 역행하면 4616
10. 부팅 이력 표를 만들어 사건 이벤트에 세션 번호를 붙였는가
11. 6005 가 아예 없는 구간이 있으면 1102 / 104 를 확인했는가
12. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가 — 날짜가 바뀔 수 있다

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: Security 채널 부팅/종료 이벤트(4608/4609/4616)와 System 채널 EventLog Provider 이벤트의 역할 구분, 감사 정책 의존성 여부
- SRC-026 — Libyal libevtx / EVTX 파일 포맷 문서: `EventRecordID` 의 단조 증가 성질, 64KiB 청크 구조와 롤오버(오래된 청크 덮어쓰기) 동작, 파일 헤더의 첫/마지막 레코드 번호
- SRC-004 — Eric Zimmerman 문서: EvtxECmd 로 System 채널을 CSV 로 뽑아 Timeline Explorer 에서 부팅 이력 표를 만드는 방법
- 6009 가 담는 정보 항목(OS 버전·빌드·서비스 팩·프로세서)과 6008 페이로드의 필드 배치는 Windows 버전에 따라 다를 수 있으므로 실제 이벤트 XML 에서 확인할 것
- EventLog 서비스가 부팅 없이 재시작되는 상황에서 6005 가 기록될 수 있는지는 OS 버전과 서비스 의존성 구성에 따라 다르다. 같은 시각의 6009 / Kernel-General 12 유무로 진짜 부팅인지 판정할 것
- `ShutdownTime` 값의 위치는 활성 ControlSet 에 따라 달라진다. 오프라인 hive 에서는 `Select\Current` 를 먼저 확인할 것
</content>
