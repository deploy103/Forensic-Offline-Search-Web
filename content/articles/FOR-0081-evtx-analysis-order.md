---
id: FOR-0081
title: "EVTX 분석 순서: winevt\\Logs 채널 우선순위와 30초 트리아지"
slug: "evtx-analysis-order"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["EVTX", "winevt", "Security.evtx", "System.evtx", "Application.evtx", "Sysmon Operational", "TaskScheduler Operational", "WMI-Activity Operational", "Bits-Client Operational", "DriverFrameworks-UserMode Operational", "ElfFile"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WMI-Activity%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Bits-Client%4Operational.evtx"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog"]
event_ids: []
protocols: []
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "Event Viewer", "wevtutil"]
commands: ["EvtxECmd.exe -d 'C:\\case\\Logs' --csv 'C:\\case\\out' --csvf all.csv", "Get-ChildItem *.evtx | Sort-Object Length -Descending", "wevtutil qe Security.evtx /c:1 /f:text"]
regex_patterns: ["%4", "ElfFile"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Channel", "Provider", "EventId", "TimeCreated", "Computer", "EventRecordId"]
file_formats: ["evtx"]
primary_terms: ["EVTX 분석 순서", "이벤트 로그 뭐부터", "evtx 트리아지", "winevt Logs", "event log"]
keywords: ["EVTX", "winevt", "이벤트 로그", "분석 순서", "채널", "Security.evtx", "System.evtx", "Sysmon", "TaskScheduler", "WMI-Activity", "Bits-Client", "롤오버", "트리아지", "Event ID 빈도"]
aliases: ["evtx 뭐부터 봐야", "이벤트 로그 어디 있나", "evtx 파일 목록", "윈도우 로그 분석 순서", "이벤트 로그 우선순위", "evtx 폴더 경로", "%4가 뭔가"]
symptom_keywords: ["evtx 파일이 너무 많다", "어느 로그부터 봐야 할지 모르겠다", "이벤트 로그가 비어 있다", "로그가 삭제된 것 같다", "파일명에 %4가 있다", "이벤트 ID를 뭘 봐야 하나"]
related: ["FOR-0082", "FOR-0083", "FOR-0091", "FOR-0108"]
source_ids: ["SRC-022", "SRC-026", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

EVTX 분석은 **파일 목록 → 전체 CSV 변환 → Event ID 빈도 집계 → 시간 범위 확인** 순서로 들어간다. `C:\Windows\System32\winevt\Logs\`의 채널 파일 중 `Security.evtx`·`System.evtx`·PowerShell·Sysmon 네 개가 전체 정보량의 대부분을 갖고 있고, 나머지는 문제 유형이 정해진 뒤에만 연다.

## 어떤 문제에서 필요한가

- 첨부로 `winevt\Logs` 폴더 전체 또는 EVTX 수십 개가 주어졌다
- "침입 시각을 특정하라", "무슨 일이 일어났는지 타임라인을 만들라" 같은 범위가 넓은 문제
- 어느 채널에 답이 있는지 모르는 상태에서 시간을 낭비하고 있다
- 특정 채널이 비어 있어서 "로그가 삭제되었는가"를 판단해야 한다

디스크 이미지에서는 이 폴더만 먼저 뽑는다. Windows 가 실행 중이면 파일이 잠겨 있으므로 원시 접근(FTK Imager, Arsenal Image Mounter) 또는 볼륨 섀도를 쓴다.

## 문제에서 처음 볼 단서

1. **파일명 자체가 단서다.** `Microsoft-Windows-<Provider>%4<Channel>.evtx` 구조이고, **`%4`는 `/`의 URL 인코딩**이다. `Microsoft-Windows-PowerShell%4Operational.evtx` = 채널 `Microsoft-Windows-PowerShell/Operational`.
2. **파일 크기 순으로 정렬한다.** 큰 파일에 정보가 있다. `Security.evtx`가 몇 MB면 정상, 68KB 근처면 사실상 비어 있다.
3. **없는 파일이 단서다.** Sysmon 채널이 있으면 그 문제는 Sysmon 문제다. `Microsoft-Windows-TerminalServices-*`가 크면 RDP 문제다.
4. 문제 지문의 단어 → 채널 매핑: "로그인/접속" → Security, "서비스/부팅" → System, "스크립트" → PowerShell, "예약 작업" → TaskScheduler, "USB" → DriverFrameworks-UserMode, "다운로드" → Bits-Client.

## 30초 절차

```powershell
EvtxECmd.exe -d 'C:\Windows\System32\winevt\Logs' --csv 'C:\case\out' --csvf all.csv
```

`-d`는 하위 폴더까지 재귀 처리하고, 모든 채널을 **하나의 CSV**로 합친다. 채널 구분은 `Channel` 컬럼에 남는다.

이어서 4개 명령으로 지도를 그린다.

```powershell
# 1) 파일 목록과 크기 — 큰 것부터. 68KB 근처는 사실상 빈 로그
Get-ChildItem 'C:\case\Logs\*.evtx' |
  Sort-Object Length -Descending |
  Select-Object Name, @{n='KB';e={[int]($_.Length/1KB)}} | Format-Table -AutoSize

# 2) Event ID 빈도 집계 — 무엇을 볼지 여기서 정한다
Import-Csv 'C:\case\out\all.csv' |
  Group-Object Channel, EventId |
  Sort-Object Count -Descending |
  Select-Object -First 40 Count, Name | Format-Table -AutoSize

# 3) 채널별 시간 범위 — 짧으면 롤오버/삭제 의심
Import-Csv 'C:\case\out\all.csv' |
  Group-Object Channel |
  ForEach-Object {
    $t = $_.Group.TimeCreated | Sort-Object
    [pscustomobject]@{ Channel=$_.Name; Count=$_.Count; First=$t[0]; Last=$t[-1] }
  } | Format-Table -AutoSize

# 4) 감사 정책 자체가 조작되었는지 — 1102(로그 삭제), 4719(감사 정책 변경)
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '1102','4719','104' } |
  Select-Object TimeCreated, Channel, EventId, MapDescription
```

2번의 빈도표가 이 글의 핵심 산출물이다. **상위 40행만 보면 그 시스템에서 무슨 일이 일어났는지 윤곽이 잡힌다.**

## 상세 절차

### 1단계 — 채널 우선순위표

`C:\Windows\System32\winevt\Logs\` 안의 파일이다. 위에서부터 순서대로 연다.

| 순위 | 파일 | 채널 | 무엇이 들어 있나 | 포렌식 가치 |
| --- | --- | --- | --- | --- |
| 0 | `Microsoft-Windows-Sysmon%4Operational.evtx` | Sysmon/Operational | 프로세스 생성(명령행·해시·부모), 네트워크 연결, 파일 생성, 레지스트리 변경 | **있으면 무조건 1순위.** 기본 로그가 못 보는 것을 다 본다 |
| 1 | `Security.evtx` | Security | 로그온/로그오프, 권한 부여, 프로세스 생성(4688), 공유 접근, 계정 변경, 로그 삭제 | 최고. 침입 경로의 8할이 여기 |
| 2 | `System.evtx` | System | 서비스 설치(7045), 서비스 상태(7034~7036), 부팅/종료(6005·6006·6008), 비정상 재부팅(Kernel-Power 41), 드라이버 로드 | 지속성·안티포렌식 흔적 |
| 3 | `Microsoft-Windows-PowerShell%4Operational.evtx` | PowerShell/Operational | 4104(ScriptBlock 원문), 4103(파이프라인/모듈) | **난독화 스크립트 원문이 여기 남는다** |
| 4 | `Windows PowerShell.evtx` | Windows PowerShell | 400/403(엔진 상태 변화), 600(공급자 수명), 800(파이프라인 상세) | 4104가 꺼져 있을 때의 대체 증거 |
| 5 | `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` | .../Operational | 21(세션 로그온), 22(셸 시작), 23(로그오프), 24(연결 끊김), 25(재연결) | RDP 세션의 시작·끝과 사용자명 |
| 6 | `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | .../Operational | 1149(사용자 인증 성공, 원본 IP 포함) | **RDP 접속 IP**를 가장 깔끔하게 준다 |
| 7 | `Microsoft-Windows-TaskScheduler%4Operational.evtx` | TaskScheduler/Operational | 106(작업 등록), 140(수정), 141(삭제), 200/201(액션 시작/완료), 129(작업 프로세스 생성) | 예약 작업 지속성. 실제 실행 파일 경로가 200/201에 |
| 8 | `Microsoft-Windows-WMI-Activity%4Operational.evtx` | WMI-Activity/Operational | 5857(공급자 로드), 5858(오류), 5860/5861(이벤트 소비자 등록) | **5861 = WMI 영구 이벤트 구독 지속성** |
| 9 | `Microsoft-Windows-Windows Defender%4Operational.evtx` | Windows Defender/Operational | 1116(악성코드 탐지), 1117(조치), 5001(실시간 보호 비활성), 5007(설정 변경) | 탐지된 파일의 **경로와 이름**이 그대로 남는다 |
| 10 | `Application.evtx` | Application | 1000(응용 프로그램 오류), 1001(WER), 1002(응답 없음), MsiInstaller 1033/11707(설치) | 크래시 = 익스플로잇 시도 흔적. 설치 이력 |
| 11 | `Microsoft-Windows-Bits-Client%4Operational.evtx` | Bits-Client/Operational | 3(작업 생성), 59(전송 시작), 60(전송 완료) — **URL과 저장 경로** | `bitsadmin`/`Start-BitsTransfer` 다운로드 반출·유입 |
| 12 | `Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx` | .../Operational | USB 장치 연결·제거 시각 | USB 문제에서 **초 단위 연결 시각**. 단 Windows 10 이후 **기본 비활성**이라 없는 경우가 많다 |

Sysmon 채널을 0순위에 둔 이유는, 존재한다는 사실 자체가 "출제자가 Sysmon 로그로 풀라고 준 것"이라는 신호이기 때문이다.

### 2단계 — 파일명 규칙 (`%4`)

| 파일명 | 실제 채널 이름 |
| --- | --- |
| `Security.evtx` | `Security` |
| `Windows PowerShell.evtx` | `Windows PowerShell` (공백 포함, `%4` 없음 — 레거시 채널) |
| `Microsoft-Windows-PowerShell%4Operational.evtx` | `Microsoft-Windows-PowerShell/Operational` |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | `Microsoft-Windows-Windows Defender/Operational` (파일명에 공백이 있다) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager%4Admin.evtx` | `.../LocalSessionManager/Admin` (Admin 채널은 Operational 과 별개 파일) |

`%4`는 채널 이름의 `/`를 파일명에 넣을 수 없어 URL 인코딩한 것이다. `Get-WinEvent -FilterHashtable`에 **경로로 줄 때는 `%4`가 든 파일명 그대로**, **채널 이름으로 줄 때는 `/`로** 쓴다. 이 둘을 섞으면 "채널을 찾을 수 없다"는 에러가 난다.

```powershell
# 파일에서 읽기 — Path 에는 %4 가 든 실제 파일명
Get-WinEvent -FilterHashtable @{Path='C:\case\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'; Id=4104}

# 라이브 시스템에서 읽기 — LogName 에는 / 가 든 채널명
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}
```

또한 파일명에 공백이 들어가는 채널(`Windows PowerShell.evtx`, `Microsoft-Windows-Windows Defender%4Operational.evtx`)은 **반드시 인용부호로 감싼다.** 감싸지 않으면 두 개의 인자로 쪼개진다.

### 3단계 — 삭제·롤오버 판정

EVTX 는 헤더 4096바이트 + 64KB(65,536바이트) 단위 청크로 구성된다. 따라서 레코드가 거의 없는 파일은 **69,632바이트(약 68KB) 근처**에 머문다.

| 관찰 | 해석 | 확증 방법 |
| --- | --- | --- |
| 크기가 68KB 근처 | 사실상 빈 로그 | 레코드 수 0~수십 건 |
| `Security.evtx`만 작고 나머지는 크다 | **선택적 삭제 의심** | 1102 확인. 삭제 직후엔 1102 하나만 남는 경우가 많다 |
| 시간 범위가 사건 시각을 포함하지 않고 몇 시간뿐 | 롤오버(가득 차서 덮어씀) 또는 삭제 후 재수집 | 첫 레코드의 `EventRecordId`가 1이 아니면 앞부분이 사라진 것 |
| 첫 `EventRecordId`가 1 인데 시간 범위가 짧다 | **로그를 지우고 새로 시작했다** | 1102 / 104 |
| 특정 Event ID 가 전 구간에서 0건 | 그 감사 하위 범주가 꺼져 있었다 | 4719, `PolAdtEv`(SECURITY 하이브) |

```powershell
# 첫 레코드가 1번인지 — 앞이 잘렸는지 지워졌는지의 판별선
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.Channel -eq 'Security' } |
  Sort-Object { [int]$_.EventRecordId } |
  Select-Object -First 3 EventRecordId, TimeCreated, EventId
```

`EventRecordId`는 채널 단위로 단조 증가하고 재사용되지 않는다. **시각보다 신뢰도가 높은 순서 지표**이므로, 시간 조작이 의심되면 이 값으로 정렬한다.

### 4단계 — 감사 정책이 꺼져 있었는지 점검

"4624 가 없다"는 "로그온이 없었다"가 아니다. 셋 중 하나다.

| Event ID | 채널 | 의미 |
| --- | --- | --- |
| 1102 | Security | **감사 로그가 지워졌다.** 지운 계정과 시각이 이 이벤트 안에 남는다 |
| 4719 | Security | 시스템 감사 정책이 변경되었다. 어떤 하위 범주가 켜지고 꺼졌는지 포함 |
| 104 | System | 다른 채널(System/Application 등)의 로그가 지워졌다 |
| 4907 | Security | 개체의 감사 설정이 변경되었다 |

1102 는 로그를 비운 뒤에도 남는다. **로그가 텅 비었는데 1102 가 하나 있으면 그 시각이 곧 안티포렌식 시각이다.**

## 출력 필드 해석

EvtxECmd 로 전체를 합친 CSV 에서 트리아지에 쓰는 컬럼만 정리한다.

| 컬럼 | 의미 | 트리아지에서의 용도 |
| --- | --- | --- |
| `Channel` | 채널 이름 (`/` 형태) | 어느 로그에서 온 레코드인지. 합친 CSV 에서 필수 |
| `Provider` | 이벤트를 쓴 공급자 | 같은 Event ID 가 공급자별로 의미가 다르다 (`1`은 공급자마다 전부 다르다) |
| `EventId` | 이벤트 ID | 빈도 집계의 축 |
| `TimeCreated` | 발생 시각 (**UTC**) | 타임라인 축 |
| `EventRecordId` | 채널 내 단조 증가 번호 | 순서 확정, 앞부분 손실 판정 |
| `Computer` | 기록된 호스트 이름 | 여러 호스트의 로그가 섞였는지 확인 |
| `MapDescription` | 맵으로 정규화된 사람이 읽을 설명 | 빈도표에 이걸 붙이면 바로 읽힌다 |
| `UserName` | 맵이 채운 계정 | 계정별 집계 |
| `RemoteHost` | 맵이 채운 원격 호스트/IP | IP 별 집계 |
| `Payload` | **원본 EventData JSON** | 맵이 없는 이벤트의 유일한 정보원 |
| `SourceFile` | 어느 `.evtx` 에서 왔는가 | 파일 단위 되짚기 |

**EVTX 내부 `SystemTime`은 항상 UTC 로 저장된다.** EvtxECmd CSV 의 `TimeCreated`도 UTC 다. Event Viewer 는 이를 시스템 로컬 시간대로 변환해 보여주므로 두 화면의 숫자가 다르다. **답을 KST 로 요구하면 +9시간**을 더한다. 대상 시스템의 시간대는 SYSTEM 하이브의 `TimeZoneInformation`([FOR-0054](./system-timezone.html))에서 확인한다.

## pivot: 다음에 볼 artifact

| 빈도표에서 본 것 | 다음에 열 것 | 확인할 것 |
| --- | --- | --- |
| 4624/4625 가 많다 | [FOR-0083](./event-4624-logon.html), [FOR-0084](./event-4625-failed-logon.html) | Logon Type, IP, 계정, 실패→성공 전환점 |
| 4672 가 특정 계정에 붙어 있다 | [FOR-0087](./event-4672-special-privileges.html) | `SeDebugPrivilege` 유무 |
| 4648 이 있다 | [FOR-0086](./event-4648-explicit-credentials.html) | 어느 계정으로 어느 서버에 접속했나 |
| 4634/4647 로 세션 길이를 알고 싶다 | [FOR-0085](./event-4634-4647-logoff.html) | `TargetLogonId` 조인 |
| 7045 가 있다 | System 채널 상세 | 설치된 서비스 이름과 `ImagePath` |
| 4104 가 있다 | PowerShell/Operational | 스크립트 원문, Base64 디코드 |
| 106/200 이 있다 | TaskScheduler/Operational | 등록된 작업 이름과 실행 파일 |
| 5861 이 있다 | WMI-Activity/Operational | `__EventFilter` / `CommandLineEventConsumer` 쿼리 |
| 1116/1117 이 있다 | Windows Defender/Operational | 탐지 파일 경로 → `$MFT`([FOR-0021](./mft-basics.html))에서 생성 시각 |
| 59/60 이 있다 | Bits-Client/Operational | 다운로드 URL 과 저장 경로 |
| 1102 만 남았다 | 파일시스템 쪽으로 전환 | Prefetch, `$UsnJrnl`([FOR-0027](./usnjrnl-basics.html)), Amcache |

## 흔한 함정

- **Event Viewer 로 EVTX 를 하나씩 열어 보는 것.** 파일 30개를 GUI 로 넘기는 사이에 시간이 끝난다. 전체를 CSV 하나로 합쳐 빈도 집계부터 하는 것이 순서다. 채널 구분은 `Channel` 컬럼이 해 준다.
- **Security.evtx 만 보고 끝내는 것.** 서비스 설치(7045)와 부팅 이력은 System 채널에만 있다. 스크립트 원문은 PowerShell 채널에만 있다. Security 에는 없는 정보를 Security 에서 찾다가 "로그에 없다"고 결론 내리는 실수가 가장 잦다.
- **`%4`를 `/`로 바꿔서 파일 경로에 쓰는 것.** `Get-WinEvent -Path`에는 실제 파일명(`%4` 포함)을 준다. `/`로 쓰면 경로가 존재하지 않아 실패한다. 반대로 `-FilterHashtable @{LogName=...}`에는 `/`를 쓴다.
- **Event ID 만으로 이벤트를 식별하는 것.** Event ID 는 **공급자별로 독립**이다. `Provider`가 다르면 같은 `1`도 전혀 다른 이벤트다(Sysmon 1 = 프로세스 생성, Kernel-General 1 = 시스템 시각 변경). 빈도 집계는 반드시 `Channel, EventId` 또는 `Provider, EventId` 쌍으로 한다.
- **"로그가 비어 있다 = 사건이 없었다"로 결론 내는 것.** 감사 정책 미설정, 롤오버, 1102 삭제 세 가지를 배제해야 성립한다. 첫 `EventRecordId`와 1102/4719/104 를 먼저 확인한다.
- **시간 범위를 확인하지 않는 것.** 사건 시각이 로그의 시간 범위 밖이면 그 로그로는 절대 풀 수 없다. 다른 artifact 로 전환하는 판단을 30초 안에 내려야 한다.
- **UTC/로컬 혼동.** EVTX `SystemTime`은 UTC 다. Event Viewer 화면 값은 로컬 변환값이다. 두 값을 같은 타임라인에 섞으면 9시간 오차가 생긴다. KST 답은 +9시간.
- **여러 호스트의 로그를 한 CSV 에 합쳐 놓고 `Computer` 를 무시하는 것.** 서로 다른 PC 의 로컬 시각과 계정이 섞여 인과가 뒤집힌다. 합친 뒤 `Computer` 로 먼저 나눈다.
- **잠긴 파일을 그대로 복사하려 하는 것.** 실행 중 Windows 에서 `winevt\Logs`는 잠겨 있다. 원시 접근이나 볼륨 섀도(`--vss`)를 쓴다.

## 교차검증

```powershell
# A) 빈도표에 MapDescription 을 붙여 읽히게 만든다
Import-Csv 'C:\case\out\all.csv' |
  Group-Object Channel, EventId |
  Sort-Object Count -Descending | Select-Object -First 25 |
  ForEach-Object {
    [pscustomobject]@{
      Count = $_.Count
      Key   = $_.Name
      Desc  = ($_.Group | Select-Object -First 1).MapDescription
    }
  } | Format-Table -AutoSize

# B) 사건 시각 ±10분의 모든 채널 레코드 — 채널을 넘나드는 인과가 보인다
$t0 = [datetime]::Parse('2026-03-14T07:10:00Z').ToUniversalTime()
Import-Csv 'C:\case\out\all.csv' |
  Where-Object {
    $ts = [datetime]::Parse($_.TimeCreated)
    $ts -ge $t0.AddMinutes(-10) -and $ts -le $t0.AddMinutes(10)
  } | Sort-Object TimeCreated |
  Select-Object TimeCreated, Channel, EventId, MapDescription, UserName, RemoteHost

# C) 채널이 아예 없을 때 — 파일 존재 여부부터
'Security','System','Microsoft-Windows-Sysmon%4Operational' | ForEach-Object {
  $p = "C:\case\Logs\$_.evtx"
  [pscustomobject]@{ File=$_; Exists=(Test-Path $p) }
}
```

B 의 "전 채널 ±10분" 쿼리가 실전에서 가장 강력하다. 4624(Security) → 4104(PowerShell) → 7045(System) → 59(BITS)가 몇 초 간격으로 줄지어 나오면 그 자체가 공격 시나리오다.

## mini walkthrough

```text
문제:
"침해된 워크스테이션의 로그를 드립니다. 공격자가 지속성을 확보한 방법과
 그 시각(KST)을 구하세요.
 첨부: winevt_Logs.zip (evtx 34개)"

1. 첫 시도 (실패한 접근):
   파일명이 익숙한 Security.evtx 를 Event Viewer 로 열었다.
   -> 4624/4625/4672 가 12,000건. 스크롤만 하다 5분을 썼고
      "지속성"에 해당하는 이벤트를 못 찾았다.
   왜 틀렸나: 지속성 흔적(서비스 설치, 예약 작업, WMI 구독)은
   Security 채널에 거의 없다. 채널을 잘못 골랐다.

2. 방향 전환 — 파일 크기부터 본다:
   Get-ChildItem *.evtx | Sort-Object Length -Descending

     Name                                              KB
     Security.evtx                                  20480
     System.evtx                                     5120
     Microsoft-Windows-TaskScheduler%4Operational     1024
     Microsoft-Windows-PowerShell%4Operational         512
     Microsoft-Windows-WMI-Activity%4Operational        68   <- 사실상 빈 로그
     Application.evtx                                 1024
     (이하 28개는 모두 68~70KB)

   -> TaskScheduler 채널이 1MB 나 된다. 워크스테이션치고 크다.

3. 전체를 하나로 합쳐 빈도 집계:
   EvtxECmd.exe -d . --csv out --csvf all.csv
   -> 41,902행

   Count  Channel, EventId
   ------ ------------------
    9,884 Security, 4624
    7,120 Security, 4672
      612 Security, 4625
      331 TaskScheduler/Operational, 200
      330 TaskScheduler/Operational, 201
      118 System, 7036
        9 TaskScheduler/Operational, 106   <- 작업 등록 9건
        3 PowerShell/Operational, 4104
        1 Security, 1102                   <- 로그 삭제 1건

4. 106(작업 등록) 9건을 본다:
   ... Channel -like 'TaskScheduler*' -and EventId -eq 106

   TimeCreated              PayloadData1 / MapDescription
   2026-03-13 22:41:07Z     \Microsoft\Windows\UpdateOrchestrator\...
   ...
   2026-03-14 07:22:19Z     \WindowsUpdateCheck              <- 이름이 수상하다

   경로가 \Microsoft\Windows\ 아래가 아니라 루트에 있다. 정상 작업이 아니다.

5. 같은 작업의 200(액션 시작)에서 실제 실행 파일:
   2026-03-14 07:22:31Z  C:\Users\Public\wuauclt.exe
   -> 정상 wuauclt.exe 는 C:\Windows\System32 에 있다. 경로가 가짜다.

6. 1102 확인 — 왜 WMI 채널이 비어 있었나:
   Security, 1102 @ 2026-03-14 07:29:44Z, SubjectUserName=svc_backup
   -> 지속성 확보 7분 뒤 감사 로그를 지웠다.
      WMI 채널이 68KB 였던 것도 같은 맥락으로 재해석된다.

7. 시간대 변환:
   EVTX SystemTime 은 UTC. 07:22:19Z + 9h = 2026-03-14 16:22:19 KST

정답: 예약 작업 \WindowsUpdateCheck 등록(C:\Users\Public\wuauclt.exe),
      2026-03-14 16:22:19 KST
```

1단계의 실패가 이 글의 요점이다. **채널 선택이 잘못되면 아무리 오래 봐도 답이 없다.** 2~3단계처럼 크기 정렬과 빈도 집계로 "어디를 볼지"를 먼저 정하면 34개 파일이 3개로 줄어든다.

## 막혔을 때 다음 체크

1. `Get-ChildItem`으로 크기 정렬을 했는가 — 68KB 근처 파일은 전부 후보에서 제외
2. 전체를 CSV 하나로 합쳐 `Channel, EventId` 빈도표를 만들었는가
3. 채널별 시간 범위가 사건 시각을 **포함하는지** 확인했는가
4. 1102 / 4719 / 104 를 확인했는가 — 없는 로그의 이유가 여기 있다
5. 첫 `EventRecordId`가 1인가 — 1이면 로그를 새로 시작한 것
6. 문제 지문의 키워드를 채널 우선순위표에 대입했는가 — "서비스"면 System, "스크립트"면 PowerShell
7. `Provider`를 무시하고 Event ID 만으로 필터하고 있지 않은가
8. Sysmon 채널이 있는데 안 봤다면 지금 본다 — 기본 로그보다 정보량이 훨씬 많다
9. 답이 KST 인지 UTC 인지 문제 지문을 다시 읽었는가

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 감사 하위 범주별 Event ID 대응과 1102·4719 의 의미
- SRC-026 — libevtx (EVTX) 포맷 문서: `ElfFile` 시그니처, 4096바이트 헤더, 65,536바이트 청크 구조, `EventRecordId` 단조 증가 성질
- SRC-004 — Eric Zimmerman 문서: EvtxECmd 의 `-d` 재귀 처리, 여러 채널을 하나의 CSV 로 합칠 때의 `Channel`/`SourceFile` 컬럼
- 채널 파일명·기본 활성 여부·최대 크기는 Windows 버전과 감사 정책에 따라 다르므로 실제 폴더 목록에서 확인할 것. `DriverFrameworks-UserMode/Operational`은 Windows 10 이후 기본 비활성인 경우가 많다
</content>
</invoke>
