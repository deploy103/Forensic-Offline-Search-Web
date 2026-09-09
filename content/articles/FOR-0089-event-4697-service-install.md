---
id: FOR-0089
title: "Event ID 4697 서비스 설치 감사: 누가 서비스를 등록했는지까지 남는다"
slug: "event-4697-service-install"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4697", "ServiceFileName", "ServiceType", "Security System Extension", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\config\\SYSTEM"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC"]
event_ids: ["4697"]
protocols: ["SMB"]
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Registry Explorer", "RegRipper"]
commands: ["Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4697}", "EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv", "auditpol /get /subcategory:\"Security System Extension\"", "sc qc PSEXESVC"]
regex_patterns: ["(?i)\\\\(Temp|AppData|ProgramData|Users\\\\Public)\\\\", "(?i)(cmd\\.exe|powershell|rundll32|mshta)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType", "ServiceAccount"]
file_formats: ["evtx"]
primary_terms: ["4697", "서비스 설치 보안로그", "서비스 등록 감사"]
keywords: ["4697", "서비스 설치", "service install", "ServiceFileName", "ServiceType", "ServiceStartType", "Security System Extension", "PSEXESVC", "PsExec", "지속성", "측면 이동", "Security.evtx"]
aliases: ["4697", "서비스 누가 만들었나", "서비스 등록 기록", "psexec 흔적", "서비스 지속성", "4697 7045 차이"]
symptom_keywords: ["누가 서비스를 설치했는지 알고 싶다", "4697이 안 보인다", "서비스 이름이 이상하다", "PsExec 흔적을 찾고 싶다", "ServiceType 숫자가 뭔지 모르겠다"]
related: ["FOR-0090", "FOR-0088", "FOR-0083", "FOR-0053"]
source_ids: ["SRC-022", "SRC-017", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4697은 서비스가 설치될 때 Security 채널에 기록되며, **`ServiceFileName`(무엇이 서비스로 등록됐나)과 `SubjectUserName`/`SubjectLogonId`(누가 등록했나)를 함께 준다** — 주체 정보가 없는 7045와 짝을 이루어 봐야 한다.

## 어떤 문제에서 필요한가

- "공격자가 어떤 지속성을 심었나" (서비스 기반 지속성)
- "누가 이 서비스를 만들었나" — 7045로는 절대 답할 수 없는 질문
- "PsExec 같은 원격 실행 도구가 사용됐나" (`PSEXESVC`)
- "커널 드라이버가 로드됐나" (`ServiceType` = `0x1`)
- "로그온 세션과 서비스 등록을 연결하고 싶다" ([FOR-0083](./event-4624-logon.html)의 `TargetLogonId` → 4697의 `SubjectLogonId`)

서비스는 SYSTEM 권한으로 부팅 시 자동 실행되는 가장 강력한 지속성 수단이다. 그래서 서비스 등록 이벤트는 건수가 적고 신호 대 잡음비가 매우 높다. **4697은 전부 읽어도 된다.**

## 문제에서 처음 볼 단서

1. 지문에 "지속성", "재부팅 후에도", "서비스" → 4697 + 7045 동시 확인
2. 원격 실행/측면 이동 정황 → `ServiceName` 이 `PSEXESVC` 인지 확인
3. `.sys` 파일이 문제에 등장 → `ServiceType` = `0x1` (커널 드라이버) 검색
4. 4624 Type 3 직후 몇 초 안에 서비스가 생겼다 → 원격 서비스 생성(측면 이동)
5. 4697이 하나도 없다 → **감사 정책이 꺼져 있었을 가능성이 크다.** 즉시 7045로 이동([FOR-0090](./event-7045-service-install.html))

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4697} | Format-List Message
```

건수가 적으므로 필터 없이 전부 본다. 필드를 표로 펼치려면:

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4697} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC  = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      Who      = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
      LogonId  = $d['SubjectLogonId']
      Name     = $d['ServiceName']
      Image    = $d['ServiceFileName']
      Type     = $d['ServiceType']
      Start    = $d['ServiceStartType']
      Account  = $d['ServiceAccount']
    }
  } | Sort-Object TimeUTC | Format-Table -AutoSize
```

## 상세 절차

### 1단계 — 4697이 기록될 조건을 먼저 확정한다

4697은 **감사 정책이 켜져 있어야만** 남는다. 기본 설정에서는 대부분 기록되지 않는다.

| 항목 | 값 |
| --- | --- |
| 채널 | `Security` |
| Provider | `Microsoft-Windows-Security-Auditing` |
| 필요한 감사 하위 범주 | `Audit Security System Extension` (System 범주) |
| 기본 활성 여부 | 일반적으로 **비활성**. 조직 정책이나 강화 설정이 있을 때만 켜져 있다 |
| 지원 시작 | Windows 10 / Windows Server 2016 계열부터 |
| 대체 이벤트 | System 채널 7045 (기본으로 기록됨) |

```powershell
# 라이브 시스템에서 하위 범주 상태 확인
auditpol /get /subcategory:"Security System Extension"
```

**4697이 0건인 것은 "서비스 설치가 없었다"는 증거가 아니다.** 감사가 꺼져 있었다는 뜻일 가능성이 훨씬 크다. 그 판정을 하려면 같은 구간의 7045를 반드시 확인한다.

### 2단계 — 필드를 읽는다

원본 EventData의 실제 XML 필드 이름이다.

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `SubjectUserSid` | 서비스를 설치한 주체의 SID | `S-1-5-18` = SYSTEM |
| `SubjectUserName` | **주체 계정 이름** | 7045에는 없는 정보. 4697의 존재 이유 |
| `SubjectDomainName` | 주체 도메인 | 로컬이면 컴퓨터 이름 |
| `SubjectLogonId` | 주체의 로그온 세션 ID (16진수) | 4624와 이어붙이는 키 |
| `ServiceName` | 서비스의 내부 이름 (레지스트리 키 이름) | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` |
| `ServiceFileName` | **실행 이미지 경로 (인자 포함)** | 판단의 핵심. 아래 3단계 |
| `ServiceType` | 서비스 종류 코드 | 아래 표 |
| `ServiceStartType` | 시작 방식 코드 | 아래 표 |
| `ServiceAccount` | 실행 계정 | `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, 또는 도메인 계정. 드라이버는 값이 없을 수 있다 |

`TimeCreated SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 변환해 보여주므로 두 화면의 숫자가 다르다. **KST 답은 UTC + 9시간.** 시스템 시간대는 SYSTEM hive 의 `TimeZoneInformation` 으로 확인한다([FOR-0054](./system-timezone.html)).

### ServiceType 값

레지스트리 `Services\<name>\Type` 값과 같은 상수를 쓴다. 4697에서는 16진수로 기록된다.

| 값 | 의미 | 포렌식 함의 |
| --- | --- | --- |
| `0x1` | 커널 드라이버 | **가장 위험.** 루트킷·EDR 무력화 드라이버(BYOVD) |
| `0x2` | 파일 시스템 드라이버 | 필터 드라이버. 은닉·후킹 가능 |
| `0x10` | own process (자체 프로세스로 실행되는 서비스) | 일반 exe 서비스. 공격자 서비스의 대부분 |
| `0x20` | share process (svchost 같은 공유 프로세스) | DLL 서비스. `ServiceDll` 을 함께 확인 |
| `0x110` | own process + interactive | 데스크톱과 상호작용. 현대 Windows 에서 매우 이례적 |
| `0x120` | share process + interactive | 위와 동일. 이례적 |

`0x110` / `0x120` 은 `0x10` / `0x20` 에 대화형 플래그가 더해진 값이다. 현대 Windows 는 세션 0 격리 때문에 대화형 서비스를 사실상 쓰지 않는다. **보이면 의심한다.**

### ServiceStartType 값

레지스트리 `Services\<name>\Start` 값과 같다. 4697에서는 십진수로 기록된다.

| 값 | 이름 | 의미 | 포렌식 함의 |
| --- | --- | --- | --- |
| `0` | boot start | 부트 로더가 로드 | 커널 드라이버. 최고 수준 지속성 |
| `1` | system start | 커널 초기화 중 로드 | 드라이버 |
| `2` | auto start | 부팅 시 자동 시작 | **지속성 확정.** 재부팅해도 살아난다 |
| `3` | demand start (manual) | 요청 시 시작 | PsExec 같은 일회성 원격 실행 |
| `4` | disabled | 비활성 | 방어 도구를 끄려는 시도일 수 있다 |

판단 조합:

- `ServiceType` = `0x10` + `ServiceStartType` = `2` → **부팅 지속성**
- `ServiceType` = `0x10` + `ServiceStartType` = `3` → 일회성 원격 실행 도구 (PsExec 계열)
- `ServiceType` = `0x1` + `ServiceStartType` = `0`/`1` → 드라이버 로드. 커널 수준 침해

### 3단계 — ServiceFileName 에서 의심 신호를 뽑는다

정상 서비스의 `ServiceFileName` 은 거의 예외 없이 `%SystemRoot%\System32\...` 또는 `C:\Program Files\...` 의 서명된 실행 파일이다.

| 신호 | 예 | 왜 의심인가 |
| --- | --- | --- |
| 사용자 임시/프로필 경로 | `C:\Users\jhkim\AppData\Local\Temp\svc.exe` | 정상 서비스는 사용자 프로필에 설치되지 않는다 |
| `ProgramData` / `Users\Public` | `C:\ProgramData\upd\host.exe` | 권한이 느슨해 공격자가 선호한다 |
| 루트 직하 | `C:\svc.exe`, `C:\Windows\PSEXESVC.exe` | 설치 프로그램이 만드는 위치가 아니다 |
| 인터프리터를 서비스로 등록 | `cmd.exe /c ...`, `powershell.exe -enc ...` | **서비스 이미지는 원래 서비스 컨트롤 API 를 구현해야 한다.** cmd/powershell 은 서비스가 아니다 |
| 프록시 실행 LOLBin | `rundll32.exe ...`, `mshta.exe ...`, `regsvr32.exe ...` | 서비스로 등록될 이유가 없다 |
| 공백 있는 인용 없는 경로 | `C:\Program Files\My App\svc.exe` (따옴표 없음) | 상위 경로 하이재킹(`C:\Program.exe`) 취약. 그 자체가 취약점 신호 |
| UNC 경로 | `\\10.0.0.5\share\svc.exe` | 원격 이미지 실행. 측면 이동 |
| 확장자 위장 | `svc.exe.dll`, `update.tmp` | 서비스 이미지로 부자연스럽다 |
| 무작위 문자열 이름 | `mtqkfhjr.exe` | 자동 생성된 페이로드 |

```powershell
$svc = Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4697} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $_.TimeCreated.ToUniversalTime()
      Who     = $d['SubjectUserName']
      Name    = $d['ServiceName']
      Image   = $d['ServiceFileName']
      Type    = $d['ServiceType']
      Start   = $d['ServiceStartType']
    }
  }

# 경로/인터프리터 기반 1차 선별
$svc | Where-Object {
  $_.Image -match '(?i)\\(Temp|AppData|ProgramData|Users\\Public)\\' -or
  $_.Image -match '(?i)(cmd\.exe|powershell|pwsh|rundll32|mshta|regsvr32|wscript|cscript)' -or
  $_.Image -match '^\\\\'
} | Format-List
```

### 4단계 — SYSTEM hive 의 Services 키와 대조한다

4697은 "등록 시점"의 스냅샷이다. 등록 이후 값이 바뀌었거나, 서비스가 삭제되었을 수 있다. **현재 상태는 레지스트리에서 본다.**

| 레지스트리 값 | 4697의 대응 필드 | 확인 목적 |
| --- | --- | --- |
| `HKLM\SYSTEM\CurrentControlSet\Services\<Name>\ImagePath` | `ServiceFileName` | 등록 후 경로가 변경됐는지 |
| `...\Type` | `ServiceType` | 종류가 바뀌었는지 |
| `...\Start` | `ServiceStartType` | manual 로 만든 뒤 auto 로 바꿨는지 |
| `...\ObjectName` | `ServiceAccount` | 실행 계정 변경 |
| `...\DisplayName` | (4697에 없음) | 정상 서비스를 사칭하는 표시 이름 |
| `...\Description` | (4697에 없음) | 비어 있거나 오타가 있으면 의심 |
| `...\Parameters\ServiceDll` | (4697에 없음) | `ServiceType` = `0x20` 인 서비스의 실제 DLL |
| 키의 LastWrite 시각 | 4697의 `TimeCreated` | 두 시각이 어긋나면 사후 수정 |

`CurrentControlSet` 은 실제로는 `Select` 키의 `Current` 값이 가리키는 `ControlSet00N` 이다. 오프라인 hive 에서는 반드시 그 매핑을 먼저 확인한다([FOR-0053](./system-controlset.html)).

**4697에 있는데 레지스트리에 없다** → 서비스가 사후에 삭제됐다. 지우고 나간 것 자체가 강한 증거다.
**레지스트리에 있는데 4697/7045가 없다** → 감사 미설정 또는 로그 삭제. 1102를 확인한다.

### 5단계 — 지속성/측면 이동 판정

| 흔적 | 해석 |
| --- | --- |
| `ServiceName` = `PSEXESVC`, `ServiceFileName` = `C:\Windows\PSEXESVC.exe` | **PsExec 실행.** 원격 관리자 권한 실행 도구. 측면 이동의 고전 |
| `ServiceName` 이 무작위 8자 내외 문자열 | 자동화된 원격 실행/페이로드 프레임워크 |
| 4624 Type 3 → 수 초 뒤 4697 → 그 뒤 4688 | 원격 인증 → 서비스 등록 → 페이로드 실행. **완전한 측면 이동 체인** |
| `ServiceStartType` = `3` 인 서비스가 등록 후 곧 삭제 | 일회성 원격 실행. 지속성이 목적이 아님 |
| `ServiceStartType` = `2` + Temp 경로 | 재부팅 생존을 노린 지속성 |
| `ServiceType` = `0x1` 인 미서명 `.sys` | 드라이버 로드. 방어 도구 무력화 시도 |

PsExec 은 대상 호스트에 서비스를 만들어 원격 명령을 실행한다. 그래서 **4697/7045 + 4624 Type 3 + 5145(공유 접근)** 가 함께 나타난다. 세 개가 같은 시각대에 모이면 측면 이동으로 판정한다.

## 출력 필드 해석

### 원본 XML 예시

```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4697</EventID>
    <TimeCreated SystemTime="2026-03-14T08:11:52.7712031Z" />
    <EventRecordID>52310</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SRV-FILE01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1108</Data>
    <Data Name="SubjectUserName">adm_backup</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3f21a</Data>
    <Data Name="ServiceName">PSEXESVC</Data>
    <Data Name="ServiceFileName">C:\Windows\PSEXESVC.exe</Data>
    <Data Name="ServiceType">0x10</Data>
    <Data Name="ServiceStartType">3</Data>
    <Data Name="ServiceAccount">LocalSystem</Data>
  </EventData>
</Event>
```

읽는 순서: `ServiceFileName`(무엇) → `SubjectUserName` + `SubjectLogonId`(누가) → `ServiceStartType`(지속성인가 일회성인가) → `TimeCreated`(언제, UTC).

### 4697 vs 7045 — 반드시 둘을 함께 본다

**이 표가 이 글의 핵심이다.** 하나만 보면 반드시 놓친다.

| 항목 | Security 4697 | System 7045 |
| --- | --- | --- |
| 채널 | `Security` | `System` |
| Provider | `Microsoft-Windows-Security-Auditing` | `Service Control Manager` |
| 기본 활성 | **아니다** (감사 정책 필요) | **그렇다** (기본으로 기록) |
| 주체(누가 설치했나) | **`SubjectUserName` / `SubjectLogonId` 로 제공** | **없음** |
| 이미지 경로 필드 | `ServiceFileName` | `ImagePath` |
| 서비스 이름 필드 | `ServiceName` | `ServiceName` |
| 종류 필드 | `ServiceType` (숫자 코드) | `ServiceType` (렌더된 문자열) |
| 시작 방식 필드 | `ServiceStartType` (숫자 코드) | `StartType` (렌더된 문자열) |
| 실행 계정 필드 | `ServiceAccount` | `AccountName` |
| 로그온 세션 연결 | 가능 | 불가능 |
| 실전 적중률 | 낮다 (꺼져 있는 경우가 많다) | **높다** |

결론: **7045로 "무엇이 설치됐나"를 찾고, 4697로 "누가 설치했나"를 채운다.** 4697이 없으면 주체는 같은 시각대의 4624/4688로 간접 추정한다.

## pivot: 다음에 볼 artifact

| 4697에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `SubjectLogonId` | 4624 ([FOR-0083](./event-4624-logon.html)) | 그 세션의 계정·출처 IP·Logon Type |
| `SubjectLogonId` | 4688 ([FOR-0088](./event-4688-process-creation.html)) | `sc create` / `New-Service` 명령행 자체 |
| `ServiceName` | 7045 ([FOR-0090](./event-7045-service-install.html)) | 같은 등록의 SCM 측 기록, 시작/중지 이력 |
| `ServiceName` | `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` | 현재 값, DisplayName, ServiceDll, 키 LastWrite |
| `ServiceFileName` 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일의 생성·수정 시각, 삭제 여부 |
| `ServiceFileName` 파일명 | Prefetch, Amcache | 실제로 실행됐는지, 몇 번 |
| `ServiceName` | System 채널 7036 | 서비스가 실제로 시작됐는지 |
| 등록 시각 | 같은 구간의 5140/5145 | 원격 공유 접근(측면 이동 확증) |
| `ServiceAccount` | SAM hive | 전용 계정을 만들어 썼는지 |

## 흔한 함정

- **4697이 0건인 것을 "서비스 설치가 없었다"로 읽는다.** 이 이벤트는 감사 정책(`Audit Security System Extension`)이 켜져 있을 때만 남고, 기본값은 보통 꺼져 있다. 반드시 7045를 함께 본다.
- **7045만 보고 "누가 했는지 알 수 없다"로 끝낸다.** 7045에는 주체가 없지만 4697에는 있다. 4697이 없더라도 같은 시각의 4624/4688로 주체를 좁힐 수 있다.
- **`ServiceType` 을 십진수로 읽는다.** 4697의 `ServiceType` 은 `0x10` 같은 16진수다. `0x10` 은 16이며 "16번 종류"가 아니라 own process 다.
- **`ServiceStartType` 3(manual)을 안전하다고 본다.** PsExec 계열 원격 실행은 manual 로 등록되고 즉시 시작된다. 지속성이 아니라 **실행 자체**가 사건이다.
- **`ServiceName` 과 `DisplayName` 을 혼동한다.** 4697에 남는 것은 레지스트리 키 이름(`ServiceName`)이다. Event Viewer 나 서비스 관리 콘솔에 보이는 표시 이름과 다를 수 있고, 공격자는 표시 이름만 정상처럼 꾸민다.
- **인용 없는 경로를 그냥 넘긴다.** `C:\Program Files\App\svc.exe` 가 따옴표 없이 등록되면 `C:\Program.exe` 하이재킹이 가능하다. 그 자체가 취약점이며, 실제 실행 파일은 다른 것일 수 있다.
- **UTC/로컬 혼동.** EVTX 내부 `SystemTime` 은 UTC 다. Event Viewer 는 로컬 변환값을 보여준다. KST 답은 +9시간.
- **커널 드라이버(`0x1`)를 사용자 모드 서비스와 같은 무게로 본다.** 드라이버 등록은 커널 수준 침해다. 우선순위를 가장 높게 둔다.
- **삭제된 서비스를 추적하지 않는다.** 레지스트리에 없어도 4697/7045는 남는다. **없어진 서비스가 오히려 더 강한 증거다.**
- **여러 ControlSet 을 확인하지 않는다.** 오프라인 SYSTEM hive 에서 `ControlSet001` 만 보고 판단하면 `Select\Current` 가 다른 세트를 가리키는 경우 엉뚱한 값을 읽는다.

## 교차검증

```powershell
# 1) 4697 — 주체 포함 서비스 설치 (Security)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4697} | Format-List Message

# 2) 7045 — 같은 설치의 SCM 기록 (System). 기본 활성이므로 이쪽이 더 잘 남는다
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7045} | Format-List Message

# 3) 서비스가 실제로 시작됐는지 (7036) / 시작 유형이 바뀌었는지 (7040)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7036,7040} |
  Where-Object { $_.Message -match 'PSEXESVC' }

# 4) 등록 명령 자체 (4688). sc create / New-Service / wmic
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4688} |
  Where-Object { $_.Message -match 'sc(\.exe)?\s+create|New-Service|wmic.*service' }

# 5) 원격 등록이면 그 인증 (4624 Type 3) 과 공유 접근 (5145)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4624,5145} |
  Where-Object { $_.TimeCreated -gt '2026-03-14 08:10:00' -and $_.TimeCreated -lt '2026-03-14 08:15:00' }
```

오프라인 hive 대조:

```text
Registry Explorer 로 SYSTEM hive 를 열고
  SYSTEM\Select\Current  -> 예: 1  (즉 ControlSet001 이 활성)
  SYSTEM\ControlSet001\Services\PSEXESVC
    ImagePath   = C:\Windows\PSEXESVC.exe
    Type        = 0x10 (16)
    Start       = 3
    ObjectName  = LocalSystem
    (키 LastWrite 시각을 4697 시각과 비교)
```

## mini walkthrough

```text
문제:
"파일 서버가 침해됐습니다. 공격자가 원격 실행에 사용한 도구의 서비스 이름과
 등록한 계정을 구하세요.
 첨부: Security.evtx, System.evtx"

1. 첫 시도 (실패):
   Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4697}
   -> "지정한 쿼리와 일치하는 이벤트가 없습니다."
   0건이었다. "서비스 설치가 없었다"고 결론 낼 뻔했다.

2. 왜 틀렸나:
   4697 은 Audit Security System Extension 하위 범주가 켜져 있어야 남는다.
   이 서버는 기본 감사 설정이었다. 즉 4697 이 없는 것은
   "설치가 없었다"가 아니라 "감사가 꺼져 있었다"는 뜻이다.
   -> Security 채널만 붙잡은 것이 실수였다.

3. 방향 전환 — System 채널의 7045 로 이동:
   Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=7045} | Format-List

   TimeCreated : 2026-03-14 08:11:52Z
   ServiceName : PSEXESVC
   ImagePath   : C:\Windows\PSEXESVC.exe
   ServiceType : user mode service
   StartType   : demand start
   AccountName : LocalSystem

   서비스는 있었다. 하지만 7045 에는 "누가" 가 없다.

4. 주체를 채운다 — 같은 시각대의 4624:
   08:11:52Z 앞뒤 2분의 4624 중 LogonType=3 만 남기니 1건.
     TargetUserName = adm_backup
     TargetDomainName = CORP
     IpAddress = 10.20.30.44
     TargetLogonId = 0x3f21a

5. 확증 — 5145(공유 접근):
   같은 0x3f21a 로 IPC$ / ADMIN$ 접근 기록.
   PsExec 은 ADMIN$ 에 PSEXESVC.exe 를 복사한 뒤 서비스로 등록한다. 패턴 일치.

6. 확증 — 파일 흔적:
   $MFT 에서 C:\Windows\PSEXESVC.exe 의 생성 시각 08:11:49Z.
   서비스 등록(08:11:52Z) 3초 전. 복사 -> 등록 순서가 맞는다.

7. 시각 변환:
   EVTX SystemTime 은 UTC. 08:11:52Z -> KST 17:11:52.

정답: 서비스 이름 PSEXESVC, 등록 계정 CORP\adm_backup (10.20.30.44 에서 원격)
```

1단계의 실패가 이 글의 존재 이유다. **4697은 "있으면 최고, 없는 것이 정상"인 이벤트다.** 없을 때 7045로 즉시 갈아타고, 주체는 4624/4688로 되채우는 것이 실전 절차다.

## 막혔을 때 다음 체크

1. 4697이 0건이면 → 즉시 System 채널 7045 ([FOR-0090](./event-7045-service-install.html))
2. `ServiceFileName` 경로가 `System32` / `Program Files` 밖인 건을 전부 뽑았는가
3. `ServiceFileName` 이 `cmd.exe` / `powershell` / `rundll32` / `mshta` 로 시작하는 건이 있는가
4. `ServiceType` = `0x1` / `0x2`(드라이버)와 `0x110` / `0x120`(대화형)을 따로 확인했는가
5. `ServiceStartType` = `2`(auto)인 건을 지속성 후보로 분리했는가
6. `SubjectLogonId` 로 4624를 찾아 출처 IP를 확정했는가
7. `ServiceName` 이 레지스트리 `Services` 키에 아직 있는지 대조했는가 — 없으면 삭제된 것
8. `Select\Current` 를 확인해 올바른 ControlSet 을 봤는가
9. 같은 시각대의 5145(공유 접근)와 4688(`sc create`)을 함께 묶었는가
10. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 4697 이 속한 `Audit Security System Extension` 하위 범주와 이벤트 활성 조건, 4697 의 EventData 필드 구성
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: SYSTEM hive 위치와 `CurrentControlSet\Services` 키 구조 대조 근거
- SRC-086 — MITRE ATT&CK Enterprise Techniques: 서비스 생성 기반 지속성·측면 이동(원격 서비스 등록)·취약 드라이버 로드의 근거
- `ServiceAccount` 가 드라이버 등록 시 비어 있는지 여부, 그리고 Event Viewer 의 필드 표시명은 Windows 버전에 따라 다를 수 있으므로 실제 이벤트 XML 에서 확인할 것
- `auditpol` 하위 범주 이름은 OS 언어에 따라 현지화된다. 한국어 OS 에서는 영문 이름으로 조회되지 않을 수 있으므로 `auditpol /get /category:*` 로 전체 목록을 확인할 것
</content>
