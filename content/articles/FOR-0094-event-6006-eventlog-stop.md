---
id: FOR-0094
title: "Event ID 6006 EventLog 서비스 종료: 정상 종료와 강제 차단을 가른다"
slug: "event-6006-eventlog-stop"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["System.evtx", "6006", "6008", "Kernel-Power 41", "1074", "종료 시각", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\MEMORY.DMP", "C:\\Windows\\Minidump"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"]
event_ids: ["6006", "6008", "1074", "41"]
protocols: []
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Registry Explorer", "Timeline Explorer"]
commands: ["Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=6006}", "Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=6006,6008,41,1074}", "EvtxECmd.exe -f System.evtx --csv . --csvf sys.csv", "wevtutil qe System.evtx /q:\"*[System[(EventID=6008)]]\" /f:text"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeCreated", "SystemTime", "EventRecordID", "Computer", "BugcheckCode", "StopTime"]
file_formats: ["evtx"]
primary_terms: ["6006", "EventLog 서비스 종료", "종료 시각 판정", "6008"]
keywords: ["6006", "6008", "종료 시각", "shutdown", "비정상 종료", "unexpected shutdown", "Kernel-Power 41", "1074", "강제 종료", "전원 차단", "반포렌식", "System.evtx"]
aliases: ["6006", "언제 껐나", "종료 시각 찾기", "비정상 종료 판정", "6008 무슨 뜻", "강제 종료 흔적", "누가 껐나", "kernel-power 41"]
symptom_keywords: ["종료 시각을 확정해야 한다", "6006이 없다", "정상 종료인지 강제 종료인지 모르겠다", "누가 껐는지 알고 싶다", "종료 직전 활동을 보고 싶다", "로그가 종료 시점에서 끊겼다"]
related: ["FOR-0093", "FOR-0092", "FOR-0091", "FOR-0103"]
source_ids: ["SRC-022", "SRC-026", "SRC-109"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

6006은 EventLog 서비스가 정상적인 종료 절차 안에서 멈췄음을 기록하므로 **정상 종료 시각의 지표**다. **6006 없이 다음 6005 가 나오면 비정상 종료**이고, 그때 종료 시각은 다음 부팅 직후의 6008 페이로드와 Kernel-Power 41 에서 얻는다.

## 어떤 문제에서 필요한가

- "시스템이 언제 종료됐나"
- "정상 종료인가 강제 차단인가" — 반포렌식 판정의 출발점
- "누가 왜 껐나" (1074)
- "종료 직전에 무슨 일이 있었나" — 공격의 마지막 국면이 여기 있다
- "시스템 가동 구간표를 만들어 사건을 배치해야 한다"
- "메모리 증거가 왜 없나" (전원 차단으로 파괴)

종료는 사건의 끝을 표시한다. **공격자가 흔적을 지운 뒤 전원을 내리는 패턴**이 흔하므로, 종료 방식 자체가 증거가 된다.

## 문제에서 처음 볼 단서

1. 지문에 "종료", "껐다", "전원", "마지막으로" → 6006 + 6008 확인
2. 로그가 특정 시각에서 뚝 끊겼다 → 그 지점이 종료 또는 로그 삭제
3. 6006 이 없다 → 비정상 종료. 6008 / 41 로 이동
4. 메모리 덤프가 없거나 손상됐다 → 강제 차단 가능성
5. 1102(로그 삭제) 직후 로그가 끝난다 → 삭제 후 전원 차단. 전형적인 반포렌식 순서

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6006,6008,41,1074}
```

종료 관련 이벤트를 한 표로 세운다.

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6005,6006,6008,41,1074,13} -ErrorAction SilentlyContinue |
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
2026-03-11 02:14:07 2026-03-11 11:14:07 6005    10021 이벤트 로그 서비스가 시작되었습니다.
2026-03-13 21:38:02 2026-03-14 06:38:02 1074    10390 프로세스 C:\Windows\System32\shutdown.exe 가 종료를 시작했습니다...
2026-03-13 21:38:44 2026-03-14 06:38:44 6006    10394 이벤트 로그 서비스가 중지되었습니다.
2026-03-14 06:02:09 2026-03-14 15:02:09 41      10401 시스템이 먼저 정상적으로 종료되지 않고 다시 부팅되었습니다.
2026-03-14 06:02:20 2026-03-14 15:02:20 6008    10406 이전 시스템 종료(2026-03-13 23:51:07)가 예기치 않았습니다.
```

이 표에서 **1074 → 6006 은 정상 종료**, **41 + 6008 은 비정상 종료**로 읽는다. 위 예에서는 03-13 21:38 에 정상 종료가 있었고, 그 뒤 다시 켜진 다음 03-13 23:51:07 에 비정상 종료가 한 번 더 있었다.

## 상세 절차

### 1단계 — 6006 의 성질을 이해한다

| 항목 | 값 |
| --- | --- |
| 채널 | `System` (`C:\Windows\System32\winevt\Logs\System.evtx`) |
| Provider / Source | `EventLog` |
| 메시지 | "The Event log service was stopped." (한국어 OS: "이벤트 로그 서비스가 중지되었습니다.") |
| 페이로드 | 사실상 없다. **값은 시각 자체** |
| 감사 정책 필요 여부 | **불필요.** 기본으로 기록된다 |
| 언제 기록되나 | **정상 종료/재시작 절차에서 서비스가 멈출 때** |
| 기록되지 않는 경우 | 전원 차단, 강제 리셋, 배터리 소진, 커널 크래시(BSOD), VM 강제 정지 |
| 대응 시작 이벤트 | 6005 ([FOR-0093](./event-6005-eventlog-start.html)) |

**6006 은 "종료가 있었다"가 아니라 "질서 있는 종료가 있었다"를 뜻한다.** 이 구분이 이 글의 전부다.

원본 XML:

```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="EventLog" />
    <EventID Qualifiers="32768">6006</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-13T21:38:44.8812470Z" />
    <EventRecordID>10394</EventRecordID>
    <Channel>System</Channel>
    <Computer>WIN10-DEV</Computer>
  </System>
  <EventData />
</Event>
```

`TimeCreated SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 변환해 표시하므로 두 화면의 숫자가 다르다. **KST 답은 UTC + 9시간**(21:38:44Z → 다음 날 06:38:44 KST). 종료는 밤에 몰리므로 날짜가 바뀌는 일이 특히 많다. 시스템 시간대는 SYSTEM hive 의 `TimeZoneInformation` 으로 확정한다([FOR-0054](./system-timezone.html)).

### 2단계 — 판정 체인: 6006 유무로 갈라진다

**이 절차가 이 글의 핵심이다.**

```text
부팅(6005) 발견
   |
   +-- 다음 6005 사이에 6006 이 있는가?
        |
        +-- 있다  --> 정상 종료. 종료 시각 = 6006 시각
        |             1074 를 찾아 "누가 왜" 를 채운다
        |             Kernel-General 13 으로 커널 종료 시각 교차확인
        |
        +-- 없다  --> 비정상 종료 확정
                      |
                      +-- 다음 부팅 직후 6008 이 있는가?
                      |     --> 있다: 페이로드의 시각 = 실제 마지막 종료 시각
                      |
                      +-- Kernel-Power 41 이 있는가?
                      |     --> 있다: 정상 종료 없이 재부팅됨
                      |          BugcheckCode 가 0 이 아니면 커널 크래시(BSOD)
                      |          0 이면 전원 차단/강제 리셋 쪽
                      |
                      +-- 1074 가 있는가?
                            --> 있다: 종료 요청은 있었으나 완료되지 못했다
                            --> 없다: 요청 자체가 없었다 = 전원 차단/리셋
```

| 조합 | 판정 | 해석 |
| --- | --- | --- |
| `1074` → `6006` → (다음) `6005` | 정상 종료 | 사용자/프로세스가 요청하고 질서 있게 내려갔다 |
| `6006` 만 있고 `1074` 없음 | 정상 종료 | 요청 이벤트가 로그에서 밀렸거나 다른 경로의 종료 |
| `6006` 없음 + `6008` + `41`, `BugcheckCode` = 0 | **전원 차단/강제 리셋** | 반포렌식 의심. 아래 4단계 |
| `6006` 없음 + `6008` + `41`, `BugcheckCode` ≠ 0 | **커널 크래시(BSOD)** | `MEMORY.DMP` / `Minidump` 확인 |
| `6006` 없음 + `6008` 없음 + `41` 없음 | 로그가 잘렸거나 삭제됐다 | 1102 / 104 / 롤오버 확인 |
| `1074` 있음 + `6006` 없음 | 종료를 시작했지만 완료 전에 전원이 끊겼다 | 종료 중 강제 차단 |
| 마지막 `6005` 뒤에 아무 종료 이벤트 없음 | 이미지 획득 시점까지 가동 중이었다 | 라이브 획득이면 정상 |

### 3단계 — 6008 에서 실제 종료 시각을 꺼낸다

6008 은 **부팅 직후에 기록되지만, 그 내용은 이전 종료에 관한 것**이다.

| 구분 | 시각 |
| --- | --- |
| 6008 의 `TimeCreated` | **이 부팅**의 시각 (종료 시각이 아니다) |
| 6008 의 페이로드에 담긴 날짜/시각 | **직전의 비정상 종료 시각** |

```powershell
# 6008 의 기록 시각과 페이로드를 함께 본다
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6008} |
  ForEach-Object {
    [pscustomobject]@{
      기록시각_UTC = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      페이로드     = ($_.Message -replace "`r?`n", ' ')
    }
  } | Format-List
```

출력 예시:

```text
기록시각_UTC : 2026-03-14 06:02:20
페이로드     : 이전 시스템 종료(2026-03-13 23:51:07)가 예기치 않았습니다.
```

**답으로 적어야 하는 종료 시각은 `2026-03-13 23:51:07` 이다.** 기록 시각 `06:02:20` 은 부팅 시각이다. 이 둘을 바꿔 적는 실수가 가장 흔하다.

6008 페이로드의 시각이 UTC 인지 로컬인지는 렌더링 방식에 따라 달라질 수 있으므로, **반드시 `ShutdownTime` 레지스트리 값과 대조해 확정한다.**

```powershell
# SYSTEM hive 의 마지막 종료 시각 (FILETIME, 8바이트 리틀엔디언)
$bytes = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Windows' -Name ShutdownTime).ShutdownTime
[DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes, 0)).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
```

FILETIME 은 **1601-01-01 UTC 기준 100나노초 단위**이며, Unix epoch 와의 차이는 `11644473600` 초다. 오프라인 hive 라면 Registry Explorer 로 같은 값을 읽는다.

### 4단계 — 1074 를 읽어 "누가 왜"를 채운다

**종료 관련 이벤트 중 정보량이 가장 많은 것은 1074 다.** 6006 은 시각만 주지만, 1074 는 종료를 요청한 프로세스·사용자·이유·종료 유형·주석까지 담는다.

| 1074 가 담는 정보 | 포렌식 활용 |
| --- | --- |
| 종료를 시작한 **프로세스 이름** | `shutdown.exe` → 명령행 종료. `explorer.exe` → 시작 메뉴. `wusa.exe`/`TrustedInstaller.exe` → 업데이트 |
| 요청한 **사용자 계정** | 그 시각의 4624 세션과 연결 |
| **이유(reason) 텍스트와 코드** | 계획된 종료인지 예기치 않은 것인지, 운영 체제/애플리케이션/하드웨어 구분 |
| **종료 유형** | `restart` 인지 `power off` 인지 |
| 주석(comment) | `shutdown /c "..."` 로 넣은 문자열이 그대로 남는다 |
| 대상 컴퓨터 이름 | 원격 종료(`shutdown /m \\host`) 판별 |

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=1074} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Message | Format-List
```

메시지에 렌더된 값을 그대로 읽는 편이 안전하다. 원본 XML 에서는 이 값들이 **이름 없는 위치 기반 `param1`~`param7` 형태**로 저장되므로, 파서에 따라 순서만 보이고 의미가 붙지 않는다.

판정 포인트:

| 관찰 | 해석 |
| --- | --- |
| 1074 의 프로세스가 `shutdown.exe` 이고 사용자가 공격 계정 | 공격자가 직접 재부팅했다. 지속성 발동을 확인하려는 목적일 수 있다 |
| 1074 가 원격 종료(`\\host` 형태) | 다른 호스트에서 명령을 보냈다. 측면 이동 정황 |
| 1074 가 아예 없는데 시스템이 꺼졌다 | **종료 요청이 없었다 = 전원 차단/강제 리셋** |
| 1074 뒤에 6006 이 없다 | 종료 절차 중에 전원이 끊겼다 |
| 업데이트 프로세스의 1074 | 정상 재부팅. 배경 노이즈 |

### 5단계 — 강제 종료를 반포렌식으로 해석한다

전원을 내리는 행위는 단순한 사고일 수도 있지만, 침해 사건의 마지막 국면에서는 **의도적 증거 파괴**일 수 있다.

| 강제 종료가 파괴하는 것 | 이유 |
| --- | --- |
| **메모리 증거** | 프로세스 목록, 복호화된 자격증명, C2 연결, 인젝션 코드가 전부 사라진다 |
| **아직 디스크에 기록되지 않은 이벤트 로그** | EventLog 서비스가 정상 종료 절차에서 버퍼를 내보내지 못한다. 마지막 몇 초~몇 분의 로그가 유실될 수 있다 |
| 파일 시스템 일관성 | `$LogFile` 에 미완료 트랜잭션이 남는다. 반대로 이것이 증거가 되기도 한다 |
| 임시 파일·프리페치 갱신 | 마지막 실행 정보가 갱신되지 않을 수 있다 |
| 서비스의 정상 종료 로그(7036 등) | 남지 않는다 |

역으로, 강제 종료는 **자신의 흔적을 남긴다.**

| 강제 종료가 남기는 흔적 | 어디서 확인 |
| --- | --- |
| 다음 부팅의 `6008` | System 채널. 종료 시각 포함 |
| `Kernel-Power 41` | System 채널. 정상 종료 없이 재부팅됨 |
| `6006` 의 부재 | 가동 구간표의 구멍 |
| EVTX 파일 헤더의 dirty 상태 | EVTX 포맷에는 파일이 정상적으로 닫히지 않았음을 나타내는 플래그가 있다 |
| `$LogFile` 의 미완료 트랜잭션 | NTFS 저널 |
| 크래시 덤프 유무 | `C:\Windows\MEMORY.DMP`, `C:\Windows\Minidump` (BSOD 였다면 존재) |

**판정 문장 예:** "6006 이 없고 다음 부팅에서 6008 과 Kernel-Power 41(BugcheckCode 0)이 관측되며 1074 가 존재하지 않으므로, 종료 요청 없이 전원이 차단된 것이다. 1102(로그 삭제)가 그 직전 4분 안에 있었으므로 흔적 삭제 후 강제 차단으로 판단한다."

### 6단계 — 종료 직전 구간을 집중 분석한다

**공격의 마지막 행동은 종료 직전에 몰린다.** 종료 시각이 확정되면 그 앞 구간을 좁게 잘라 전수 검토한다.

```powershell
# 종료 시각 기준 앞 15분을 모든 채널에서 뽑는다
$stop  = [datetime]::ParseExact('2026-03-13 23:51:07', 'yyyy-MM-dd HH:mm:ss', $null)
$from  = $stop.AddMinutes(-15)

Get-ChildItem 'C:\case\winevt\Logs\*.evtx' | ForEach-Object {
  Get-WinEvent -FilterHashtable @{Path=$_.FullName; StartTime=$from; EndTime=$stop} -ErrorAction SilentlyContinue
} |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, LogName, Id,
                @{n='Msg';e={($_.Message -split "`n")[0]}} |
  Sort-Object UTC | Format-Table -AutoSize
```

이 구간에서 특히 찾을 것:

| 찾을 것 | Event ID / 위치 | 의미 |
| --- | --- | --- |
| 로그 삭제 | 1102 (Security), 104 (System) | 흔적 제거 ([FOR-0091](./event-1102-log-cleared.html)) |
| 감사 정책 변경 | 4719 | 기록을 끊었다 |
| 이벤트 로그 서비스 종료 | 1100 | 정상 종료 시에도 나오지만 순서를 본다 |
| 대량 파일 삭제 | `$UsnJrnl` 의 `FileDelete`, 4663 | 데이터 파괴/증거 삭제 |
| 섀도 복사본 삭제 | 4688 의 `vssadmin delete shadows` | 복구 방해 |
| 아카이브 생성·반출 | 4688 의 `7z`/`rar`/`rclone`, 프록시 로그 | 데이터 반출 완료 |
| 서비스 삭제 | 7045 이후 레지스트리 부재 | 지속성 회수 |
| 계정 삭제/비활성 | 4726, 4725 | 계정 흔적 제거 |
| 시각 변경 | 4616 | 타임라인 교란 |

### 7단계 — 가동 구간표를 만들어 사건을 배치한다

부팅(6005)과 종료(6006 또는 6008 페이로드)를 짝지어 표를 만든다. **이 표가 모든 타임라인의 골격이다.**

| 세션 | 부팅 (UTC) | 종료 (UTC) | 가동 | 종료 방식 | 근거 |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-03-11 02:14:07 | 2026-03-13 21:38:44 | 67.4시간 | 정상 | `1074`(shutdown.exe) + `6006` |
| 2 | 2026-03-13 22:05:31 | 2026-03-13 23:51:07 | 1.8시간 | **강제 차단** | `6006` 부재, 다음 부팅의 `6008` + `41`, `1074` 없음 |
| 3 | 2026-03-14 06:02:11 | (없음) | — | 획득 시점까지 가동 | 마지막 `6005` 이후 종료 이벤트 없음 |

이제 임의의 이벤트를 세션에 배치할 수 있다.

```powershell
# 관심 이벤트가 어느 세션에 속하는지
$sessions = @(
  [pscustomobject]@{ N=1; From=[datetime]'2026-03-11T02:14:07Z'; To=[datetime]'2026-03-13T21:38:44Z' },
  [pscustomobject]@{ N=2; From=[datetime]'2026-03-13T22:05:31Z'; To=[datetime]'2026-03-13T23:51:07Z' },
  [pscustomobject]@{ N=3; From=[datetime]'2026-03-14T06:02:11Z'; To=[datetime]'9999-12-31T00:00:00Z' }
)

$t = [datetime]'2026-03-13T23:47:10Z'
($sessions | Where-Object { $t -ge $_.From -and $t -le $_.To }).N
```

| 배치 결과 | 판정 |
| --- | --- |
| 사건 이벤트가 강제 차단된 세션의 **끝 부분**에 몰려 있다 | 활동 직후 전원을 내렸다. 반포렌식 |
| 지속성 흔적이 세션 2에 등록되고 세션 3에서 실행됐다 | 부팅 경계를 넘었다 → 지속성 확정 ([FOR-0092](./event-4608-startup.html)) |
| 세션 사이 공백(꺼져 있던 구간)에 사건 시각이 놓였다 | 시각이 잘못됐다. 4616 또는 타임스탬프 조작 확인 |
| 세션 2의 로그가 종료 몇 분 전부터 비어 있다 | 강제 차단으로 버퍼가 유실됐거나 로그를 지웠다 |

## 출력 필드 해석

| 이벤트 | 채널 | 읽을 것 | 주의 |
| --- | --- | --- | --- |
| `6006` | System | `TimeCreated`(UTC), `EventRecordID` | 페이로드 없음. **정상 종료에서만 존재** |
| `6008` | System | `TimeCreated`(= 부팅 시각), 페이로드의 날짜/시각(= **이전 종료 시각**) | 두 시각을 혼동하지 않는다 |
| `41` | System, Kernel-Power | `BugcheckCode`, 전원 관련 타임스탬프 필드 | `BugcheckCode` ≠ 0 이면 커널 크래시. 필드 구성은 버전에 따라 다르다 |
| `1074` | System, User32 등 | 렌더된 메시지 전체 | 원본 XML 은 이름 없는 `param1`~`param7`. 메시지를 읽는 편이 안전 |
| `13` | System, Kernel-General | `StopTime` | 커널 관점의 종료 시각. 6006 과 근접해야 한다 |
| `1100` | Security | `TimeCreated` | 이벤트 로그 서비스 종료. 정상 종료 시에도 기록된다 |
| `4609` | Security | `TimeCreated` | Windows 종료(감사). 정상 종료에서만 |
| `ShutdownTime` | SYSTEM hive | FILETIME 8바이트 | 마지막 종료 시각. 6006/6008 과 대조 |

## pivot: 다음에 볼 artifact

| 6006 에서 얻은 것(또는 부재) | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 종료 시각 | 6005 ([FOR-0093](./event-6005-eventlog-start.html)) | 다음 부팅 시각, 가동 구간 완성 |
| 6006 부재 | 6008 / 41 | 실제 종료 시각과 강제 여부 |
| 종료 방식 | 1074 | 누가 왜 껐는지 |
| 종료 시각 | 그 앞 15분의 전 채널 | 공격의 마지막 행동 |
| 종료 시각 | 1102 / 104 ([FOR-0091](./event-1102-log-cleared.html)) | 종료 직전 로그 삭제 |
| 종료 시각 | `$UsnJrnl` / `$MFT` ([FOR-0021](./mft-basics.html)) | 종료 직전 파일 삭제·생성 |
| 강제 차단 판정 | `C:\Windows\MEMORY.DMP`, `Minidump` | BSOD 였는지, 메모리 증거가 남았는지 |
| 강제 차단 판정 | `$LogFile` | 미완료 트랜잭션 |
| 가동 구간표 | 모든 사건 이벤트 | 세션 배치, 지속성 판정 |
| 종료 시각 | `ShutdownTime` (SYSTEM hive) | 로그와 레지스트리의 정합성 |

## 흔한 함정

- **로그의 마지막 레코드 시각을 종료 시각으로 답한다.** 강제 차단에서는 종료 자체가 기록되지 않으므로 마지막 레코드는 종료와 무관한 아무 이벤트다. 종료 시각은 6006, 없으면 **다음 부팅의 6008 페이로드**에서 얻는다.
- **6008 의 기록 시각을 종료 시각으로 읽는다.** 6008 은 부팅 직후에 기록된다. 종료 시각은 페이로드 안에 있다. **이것이 이 주제에서 가장 흔한 오답이다.**
- **6006 이 없으니 로그가 손실됐다고 본다.** 비정상 종료에서는 6006 이 원래 없다. 부재 자체가 판정 근거다.
- **6006 이 있으면 무조건 정상 종료라고 본다.** 6006 뒤에 다시 41/6008 이 나오면 그 이후 별도의 비정상 종료가 있었다는 뜻이다. 세션 단위로 끊어서 본다.
- **1074 를 빠뜨린다.** 종료 관련 이벤트 중 정보량이 가장 많다. "누가 왜 껐나"는 여기서만 나온다.
- **`param1`~`param7` 을 필드 이름으로 착각한다.** 1074 의 원본 XML 은 이름 없는 위치 기반 데이터다. 의미는 렌더된 메시지에서 읽는다.
- **강제 종료를 무조건 반포렌식으로 단정한다.** 정전·하드웨어 장애·VM 강제 정지도 같은 흔적을 남긴다. `BugcheckCode`, 크래시 덤프, 직전 구간의 활동을 함께 보고 판단한다.
- **UTC/로컬 혼동.** EVTX `SystemTime` 은 UTC 다. 종료는 밤에 몰려 +9시간을 적용하면 날짜가 바뀐다. 6008 페이로드의 시각이 UTC 인지도 `ShutdownTime` 과 대조해 확인한다.
- **종료 직전 구간을 건너뛴다.** 사건의 결말(반출 완료, 로그 삭제, 서비스 회수)이 대부분 여기 있다. 종료 시각이 나오면 반드시 앞 구간을 좁게 훑는다.
- **가동 구간표 없이 사건 시각을 나열한다.** 시스템이 꺼져 있던 구간에 놓인 타임스탬프는 그 자체로 조작 신호다. 구간표가 있어야 그것을 알아챌 수 있다.

## 교차검증

```powershell
# 1) 종료 관련 이벤트 전체
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=6006,6008,41,1074,13} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id, RecordId | Sort-Object UTC

# 2) Security 채널의 종료 이벤트와 대조
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4609,1100} -ErrorAction SilentlyContinue |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id

# 3) 41 의 상세 (커널 크래시인지 전원 차단인지)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=41} | ForEach-Object {
  ([xml]$_.ToXml()).Event.EventData.Data | Select-Object Name, '#text'
}

# 4) 1074 의 요청 주체와 이유
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=1074} | Format-List TimeCreated, Message

# 5) 종료 직전 15분의 Security 채널
$stop = [datetime]'2026-03-13T23:51:07Z'
Get-WinEvent -FilterHashtable @{
  Path='C:\case\Security.evtx'; StartTime=$stop.AddMinutes(-15); EndTime=$stop
} -ErrorAction SilentlyContinue | Sort-Object RecordId |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id
```

오프라인 레지스트리 대조:

```text
Registry Explorer 로 SYSTEM hive 를 열고
  SYSTEM\Select\Current                              -> 1
  SYSTEM\ControlSet001\Control\Windows\ShutdownTime   -> FILETIME (마지막 종료 시각)
  SYSTEM\ControlSet001\Control\CrashControl           -> 덤프 설정 (덤프가 없는 이유 확인)
```

## mini walkthrough

```text
문제:
"시스템이 마지막으로 종료된 시각과 방식(정상/강제)을 판정하고,
 종료 직전 활동을 요약하세요.
 첨부: System.evtx, Security.evtx, SYSTEM hive"

1. 첫 시도 (실패):
   System.evtx 의 마지막 레코드를 종료 시각으로 답했다.
     Get-WinEvent -Path System.evtx -MaxEvents 1
       2026-03-13 23:50:58Z  Id 7036  "Windows Update 서비스가 중지됨"
   "23:50:58Z 에 종료" 라고 적었다.

2. 왜 틀렸나:
   7036 은 서비스 상태 변경일 뿐 시스템 종료가 아니다.
   6006 을 확인하니 이 구간에는 0건.
   즉 정상 종료 절차가 실행되지 않았다.
   로그의 마지막 레코드는 "마지막으로 기록에 성공한 이벤트"일 뿐이며,
   강제 차단에서는 종료 자체가 기록되지 않는다.
   -> 마지막 레코드를 종료 시각으로 쓴 것이 실수.

3. 방향 전환 — 다음 부팅의 6008 을 본다:
   6005  2026-03-14 06:02:11Z  (다음 부팅)
   41    2026-03-14 06:02:09Z  Kernel-Power, BugcheckCode = 0
   6008  2026-03-14 06:02:20Z  "이전 시스템 종료(2026-03-13 23:51:07)가 예기치 않았습니다"

   실제 종료 시각 = 2026-03-13 23:51:07.
   마지막 레코드(23:50:58)보다 9초 뒤였다.

4. 강제 차단 확증:
   1074 검색 -> 이 구간에 0건. 종료 요청 자체가 없었다.
   BugcheckCode = 0 -> BSOD 가 아니다.
   C:\Windows\MEMORY.DMP, Minidump -> 없음.
   => 전원 차단 또는 강제 리셋.

5. 시각 정합성:
   SYSTEM hive ShutdownTime = 2026-03-13 23:51:07 UTC
   -> 6008 페이로드와 일치. 페이로드 시각이 UTC 기준임을 확인했다.

6. 종료 직전 15분 (23:36 ~ 23:51) 전 채널:
   23:38:14Z  4688  vssadmin.exe delete shadows /all /quiet
   23:41:52Z  4688  7z.exe a -p out.7z C:\Users\jhkim\Documents
   23:45:03Z  4104  Invoke-WebRequest ... (반출)
   23:47:10Z  $UsnJrnl FileDelete 대량 (도구 파일 정리)
   23:48:22Z  1102  Security 로그 삭제 (svc_backup)
   23:50:58Z  7036  Windows Update 서비스 중지
   (23:51:07Z 전원 차단)

   순서가 명확하다: 복구 방해 -> 아카이브 -> 반출 -> 도구 삭제 -> 로그 삭제 -> 전원 차단.

7. 가동 구간표:
   세션 2 : 2026-03-13 22:05:31Z ~ 2026-03-13 23:51:07Z (1.8시간, 강제 차단)
   세션 3 : 2026-03-14 06:02:11Z ~ (획득 시점까지)

8. 시각 변환:
   2026-03-13 23:51:07Z -> KST +9 -> 2026-03-14 08:51:07.
   날짜가 넘어간다.

정답: 마지막 종료 2026-03-13 23:51:07 UTC (KST 2026-03-14 08:51:07),
      방식은 강제 차단(6006 부재, 6008 + Kernel-Power 41, 1074 없음).
      직전 활동은 섀도 삭제 -> 데이터 아카이브 -> 반출 -> 도구/로그 삭제.
```

1단계의 실패가 이 글의 핵심이다. **로그의 마지막 레코드는 종료 시각이 아니다.** 강제 차단에서는 종료가 기록되지 않으므로, 종료 시각은 오직 **다음 부팅의 6008 페이로드**(또는 `ShutdownTime` 레지스트리)에만 남는다.

## 막혔을 때 다음 체크

1. 6006 이 있는지 세션별로 확인했는가 — 부재 자체가 판정 근거다
2. 6006 이 없으면 **다음 부팅의 6008 페이로드**를 읽었는가
3. 6008 의 기록 시각(부팅)과 페이로드 시각(종료)을 구분했는가
4. Kernel-Power 41 의 `BugcheckCode` 로 크래시/전원 차단을 갈랐는가
5. 1074 를 찾아 요청 주체·이유·종료 유형을 확인했는가
6. 1074 가 없다는 사실을 "요청 없는 차단"의 근거로 썼는가
7. `ShutdownTime` 레지스트리 값과 로그의 종료 시각이 일치하는가
8. 크래시 덤프(`MEMORY.DMP`, `Minidump`) 존재 여부를 확인했는가
9. 종료 직전 15분을 **모든 채널**에서 훑었는가
10. 그 구간에 1102 / 4719 / 4616 이 있는지 확인했는가
11. 가동 구간표를 만들고 사건 이벤트를 세션에 배치했는가
12. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가 — 종료는 날짜가 바뀌기 쉽다

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: Security 채널의 4609 / 1100 과 System 채널 EventLog Provider 이벤트의 역할 구분, 감사 정책 의존성 여부
- SRC-026 — Libyal libevtx / EVTX 파일 포맷 문서: 파일 헤더의 플래그(정상적으로 닫히지 않은 파일 표시)와 청크·레코드 구조, `EventRecordID` 의 단조 증가 성질
- SRC-109 — MITRE ATT&CK T1070 (Indicator Removal): 로그 삭제·흔적 제거 기법과, 종료 직전 구간에 반포렌식 행위가 집중되는 패턴의 근거
- 6008 페이로드에 담긴 날짜/시각이 UTC 인지 로컬 시간인지는 렌더링과 OS 버전에 따라 달라질 수 있다. **반드시 `ShutdownTime` 레지스트리 값과 대조해 확정할 것**
- Kernel-Power 41 의 EventData 필드 구성(`BugcheckCode` 등)과 1074 의 `param1`~`param7` 배치는 Windows 버전에 따라 다르므로 실제 이벤트 XML 에서 확인할 것
- 강제 차단 시 이벤트 로그 버퍼가 유실되는 범위는 시스템 상태에 따라 다르다. "마지막 몇 초의 로그가 없다"를 단정하지 말고 마지막 레코드 시각과 실제 종료 시각의 차이로 제시할 것
</content>
