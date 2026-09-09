---
id: FOR-0090
title: "Event ID 7045 새 서비스 설치: 기본 감사에서도 남는 지속성 흔적"
slug: "event-7045-service-install"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["System.evtx", "7045", "ImagePath", "Service Control Manager", "SCM", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\PSEXESVC.exe"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services", "HKLM\\SYSTEM\\Select"]
event_ids: ["7045", "7000", "7009", "7024", "7031", "7034", "7035", "7036", "7040"]
protocols: ["SMB"]
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Registry Explorer", "Timeline Explorer"]
commands: ["Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=7045}", "EvtxECmd.exe -f System.evtx --csv . --csvf sys.csv", "wevtutil qe System.evtx /q:\"*[System[(EventID=7045)]]\" /f:text", "sc qc <ServiceName>"]
regex_patterns: ["(?i)^[a-z]{6,10}$", "(?i)\\\\(Temp|AppData|ProgramData)\\\\"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"]
file_formats: ["evtx"]
primary_terms: ["7045", "서비스 설치", "새 서비스가 설치되었습니다"]
keywords: ["7045", "서비스 설치", "service installed", "ImagePath", "Service Control Manager", "SCM", "System.evtx", "7036", "7040", "7034", "지속성", "PSEXESVC"]
aliases: ["7045", "새 서비스가 설치되었습니다", "서비스 설치 로그", "system.evtx 서비스", "서비스 지속성 흔적", "삭제된 서비스 찾기"]
symptom_keywords: ["서비스가 언제 설치됐는지 알고 싶다", "지속성 흔적을 찾고 싶다", "4697이 없다", "서비스 이름이 무작위 문자열이다", "삭제된 서비스를 추적하고 싶다"]
related: ["FOR-0089", "FOR-0088", "FOR-0053", "FOR-0083"]
source_ids: ["SRC-022", "SRC-017", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

7045는 Service Control Manager 가 서비스 등록을 받을 때 System 채널에 남기며, **감사 정책을 켜지 않은 기본 설정에서도 기록되기 때문에 실전 적중률이 4697보다 훨씬 높다** — 서비스 기반 지속성을 찾는 첫 삽이 여기다.

## 어떤 문제에서 필요한가

- "재부팅 후에도 살아남는 지속성이 심어졌나"
- "4697이 0건인데 서비스 설치를 확인해야 한다" (감사 정책이 꺼진 시스템)
- "이미 삭제된 서비스의 흔적을 찾아야 한다"
- "원격 실행 도구(PsExec 계열)가 쓰였나"
- "악성 드라이버가 등록됐나"

`System.evtx` 는 Security 채널과 달리 어느 이미지에서나 거의 항상 존재하고, 7045 는 하루 0~2건 수준으로 드물다. **건수가 적으므로 전수 검토가 가능하다.**

## 문제에서 처음 볼 단서

1. 첨부에 `System.evtx` 가 있다 → 7045 를 가장 먼저 본다
2. 지문에 "지속성", "서비스", "재부팅", "자동 실행" → 7045 확정
3. Security 채널의 4697 이 0건이다 → 감사 미설정. 7045 가 유일한 서비스 설치 기록
4. 알 수 없는 `.exe` 나 `.sys` 파일 이름이 주어졌다 → `ImagePath` 로 검색
5. 측면 이동 정황 → `ServiceName` 이 `PSEXESVC` 이거나 무작위 문자열인지 확인

## 30초 절차

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7045} | Format-List
```

전부 읽고, 표로 정리한다.

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7045} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
      Name    = $d['ServiceName']
      Image   = $d['ImagePath']
      Type    = $d['ServiceType']
      Start   = $d['StartType']
      Account = $d['AccountName']
    }
  } | Sort-Object TimeUTC | Format-Table -AutoSize
```

출력 예시:

```text
TimeUTC              Name       Image                                    Type               Start         Account
-------              ----       -----                                    ----               -----         -------
2026-03-11 02:14:07  PEAUTH     \SystemRoot\system32\drivers\peauth.sys  kernel mode driver system start
2026-03-14 08:11:52  PSEXESVC   C:\Windows\PSEXESVC.exe                  user mode service  demand start  LocalSystem
2026-03-14 08:19:03  wqmtsbrv   C:\Windows\wqmtsbrv.exe                  user mode service  auto start    LocalSystem
```

세 번째 줄이 답이다. **무작위 문자열 이름 + `C:\Windows\` 루트 + auto start** 세 신호가 겹친다.

## 상세 절차

### 1단계 — 채널과 Provider 를 정확히 잡는다

| 항목 | 값 |
| --- | --- |
| 채널 | `System` (`C:\Windows\System32\winevt\Logs\System.evtx`) |
| Provider / Source | `Service Control Manager` |
| 메시지 | "A service was installed in the system." (한국어 OS: "새 서비스가 설치되었습니다") |
| 감사 정책 필요 여부 | **불필요.** 기본 설정에서 기록된다 |
| 존재하는 Windows | Windows 7 / Server 2008 R2 계열 이후 |
| Security 채널의 대응 이벤트 | 4697 ([FOR-0089](./event-4697-service-install.html)) |

`Security.evtx` 를 아무리 파도 7045 는 없다. **채널을 틀리면 0건이 나온다** — 이것이 가장 흔한 실수다.

### 2단계 — 필드를 읽는다

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `ServiceName` | 서비스 내부 이름 (레지스트리 키 이름) | 무작위 문자열이면 강한 의심 |
| `ImagePath` | **실행 이미지 경로 (인자 포함)** | 판단의 핵심. 아래 3단계 |
| `ServiceType` | 서비스 종류 | 7045 는 `user mode service` / `kernel mode driver` 같이 **렌더된 문자열**로 기록된다 |
| `StartType` | 시작 방식 | `auto start` / `demand start` / `system start` / `boot start` / `disabled` |
| `AccountName` | 실행 계정 | `LocalSystem`, `NT AUTHORITY\LocalService` 등. 드라이버는 비어 있을 수 있다 |

4697 은 같은 정보를 `0x10` / `3` 같은 **숫자 코드**로 준다. 두 이벤트를 한 표로 합칠 때는 이 차이를 반드시 정규화한다.

| 개념 | 7045 (문자열) | 4697 / 레지스트리 (숫자) |
| --- | --- | --- |
| 커널 드라이버 | `kernel mode driver` | `Type` = `0x1` |
| 파일 시스템 드라이버 | `file system driver` | `Type` = `0x2` |
| 자체 프로세스 서비스 | `user mode service` | `Type` = `0x10` |
| 부트 시작 | `boot start` | `Start` = `0` |
| 시스템 시작 | `system start` | `Start` = `1` |
| 자동 시작 | `auto start` | `Start` = `2` |
| 요청 시 시작 | `demand start` | `Start` = `3` |
| 비활성 | `disabled` | `Start` = `4` |

`TimeCreated SystemTime` 은 **UTC** 로 저장된다. Event Viewer 는 로컬 시간대로 바꿔 보여주므로 화면 값과 원본 값이 다르다. **KST 답은 UTC + 9시간.** 시스템 시간대는 SYSTEM hive 의 `TimeZoneInformation` 으로 확정한다([FOR-0054](./system-timezone.html)).

### 3단계 — ImagePath 를 정상 패턴과 대조한다

정상 서비스의 `ImagePath` 는 몇 가지 형태로 수렴한다.

| 정상 패턴 | 예 |
| --- | --- |
| 시스템 서비스 exe | `C:\Windows\System32\<name>.exe` |
| svchost 공유 서비스 | `C:\Windows\System32\svchost.exe -k <GroupName>` |
| 드라이버 | `\SystemRoot\System32\drivers\<name>.sys`, `system32\DRIVERS\<name>.sys` |
| 설치형 애플리케이션 | `"C:\Program Files\<Vendor>\<App>\<svc>.exe"` (따옴표로 감싸짐) |
| WOW64 애플리케이션 | `"C:\Program Files (x86)\..."` |

의심 패턴:

| 신호 | 예 | 왜 의심인가 |
| --- | --- | --- |
| `C:\Windows\` 루트 직하의 exe | `C:\Windows\wqmtsbrv.exe` | 정상 서비스는 `System32` 아래에 설치된다. `PSEXESVC.exe` 도 이 위치다 |
| 사용자 임시/프로필 경로 | `C:\Users\jhkim\AppData\Local\Temp\a.exe` | 정상 서비스가 사용자 프로필에 설치되는 일은 없다 |
| `ProgramData` / `Users\Public` | `C:\ProgramData\svc\host.exe` | 권한이 느슨한 위치 |
| 인터프리터가 이미지 | `cmd.exe /c ...`, `powershell.exe -nop -w hidden -enc ...` | 서비스 이미지는 서비스 컨트롤 API 를 구현해야 한다. cmd/powershell 은 서비스로 정상 동작하지 않는다 — **그런데도 등록했다는 것이 곧 악용** |
| 프록시 실행 LOLBin | `rundll32.exe ...,Start`, `mshta.exe`, `regsvr32.exe` | 서비스로 등록될 이유가 없다 |
| UNC 경로 | `\\10.20.30.44\share\svc.exe` | 원격 이미지. 측면 이동 |
| 공백 포함 + 따옴표 없음 | `C:\Program Files\My App\svc.exe` | 상위 경로 하이재킹 취약. 실제 실행 파일이 다를 수 있다 |
| 확장자가 서비스답지 않음 | `.dat`, `.tmp`, `.dll` 단독 | 정상 서비스 이미지가 아니다 |
| 미서명 `.sys` | `C:\Users\...\drv.sys` | 취약 드라이버 로드(방어 도구 무력화) |

```powershell
$s = Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7045} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $_.TimeCreated.ToUniversalTime()
      Name    = $d['ServiceName']
      Image   = $d['ImagePath']
      Start   = $d['StartType']
    }
  }

$s | Where-Object {
  $_.Image -notmatch '(?i)\\System32\\' -or
  $_.Image -match '(?i)(cmd\.exe|powershell|pwsh|rundll32|mshta|regsvr32|wscript|cscript)' -or
  $_.Image -match '(?i)\\(Temp|AppData|ProgramData|Users\\Public)\\' -or
  $_.Image -match '^\\\\'
} | Format-List
```

### 4단계 — ServiceName 의 무작위성을 본다

정상 서비스 이름은 벤더·제품·기능을 담은 의미 있는 문자열이다(`Spooler`, `WinDefend`, `TrustedInstaller`, `NVDisplay.ContainerLocalSystem`). 자동화된 원격 실행 도구는 **탐지 회피를 위해 이름을 매번 무작위로 만든다.**

| 신호 | 해석 |
| --- | --- |
| 의미 없는 소문자 영문 6~10자 (`wqmtsbrv`, `mtqkfhjr`) | 자동 생성. 원격 실행 프레임워크 계열 |
| `ServiceName` 과 `ImagePath` 파일명이 같은 무작위 문자열 | 같은 도구가 둘 다 생성 |
| `PSEXESVC` | **PsExec.** 원격 관리자 권한 실행. 측면 이동의 고전 |
| 정상 서비스 이름의 한 글자 변형 (`Spooler` vs `Spoo1er`, `WinDefend` vs `WinDefendr`) | 위장 |
| 정상 이름인데 `ImagePath` 가 다른 경로 | **하이재킹.** 이름만 빌렸다 |
| 같은 무작위 이름이 여러 호스트에서 발견 | 도구 구성 파일에 고정된 이름. IOC 로 활용 |

```powershell
# 의미 없어 보이는 소문자 영문만으로 된 짧은 이름 후보
$s | Where-Object { $_.Name -match '^[a-z]{6,10}$' } | Format-Table -AutoSize
```

무작위성 판정은 기계적으로 할 수 없다. **모음/자음 배열이 발음 불가능한지, 제품명으로 검색되는 이름인지**를 사람이 판단한다.

### 5단계 — 같은 채널의 관련 SCM 이벤트로 수명을 그린다

7045 는 "등록"만 알려준다. 실제로 실행됐는지, 언제 죽었는지, 시작 유형이 바뀌었는지는 같은 Provider 의 다른 이벤트에 있다.

| Event ID | 의미 | 포렌식 활용 |
| --- | --- | --- |
| `7045` | 새 서비스가 설치됨 | 등록 시각. 지속성 시작점 |
| `7036` | 서비스가 실행/중지 상태로 전환됨 | **가장 건수가 많다.** 서비스가 실제로 돌았는지 확인 |
| `7035` | 서비스에 시작/중지 제어 신호를 보냄 | 제어 요청 시점 |
| `7040` | 서비스 **시작 유형이 변경됨** | manual 로 등록한 뒤 auto 로 바꾸는 2단계 지속성 |
| `7034` | 서비스가 예기치 않게 종료됨 | 페이로드 크래시. 공격 실패 흔적 |
| `7031` | 서비스가 예기치 않게 종료되어 복구 동작이 수행됨 | 반복 크래시 + 자동 재시작 설정 |
| `7024` | 서비스가 서비스별 오류로 종료됨 | 오류 코드가 함께 남는다 |
| `7000` | 서비스를 시작할 수 없음 | 이미지 삭제 후 재부팅 → 시작 실패 |
| `7009` | 서비스 연결 대기 시간 초과 | PsExec 계열이 남기기도 한다 |

```powershell
# 특정 서비스의 전체 수명
$name = 'wqmtsbrv'
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7000,7009,7024,7031,7034,7035,7036,7040,7045} |
  Where-Object { $_.Message -match $name } |
  Select-Object @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}, Id, Message |
  Sort-Object UTC | Format-List
```

해석 조합:

- `7045` 뒤에 `7036`(실행 중)이 있다 → **실제로 실행됐다**
- `7045` 뒤에 `7036` 이 없다 → 등록만 하고 시작하지 못했거나, 로그가 잘렸다
- `7045`(demand start) → `7040`(auto 로 변경) → 재부팅 후 `7036` → 2단계 지속성 확립
- `7000` / `7034` 가 반복된다 → 이미지가 삭제됐거나 페이로드가 불안정하다. **이미지 삭제 시각의 단서**

### 6단계 — 삭제된 서비스도 7045 는 남는다

이것이 7045 의 가장 큰 실전 가치다.

| 상태 | 레지스트리 `Services` 키 | 7045 |
| --- | --- | --- |
| 서비스가 지금도 존재 | 있다 | 있다 |
| 공격자가 등록 후 삭제 (`sc delete`) | **없다** | **있다** |
| 감사 정책이 꺼져 있었다 | 있다 | 있다 (7045 는 감사와 무관) |
| 로그가 삭제됐다(1102) 또는 롤오버 | 있다 | 없을 수 있다 |

**레지스트리에 없고 7045 에만 있는 서비스는 "지우고 나간 흔적"이다.** 정상 소프트웨어도 제거 과정에서 서비스를 삭제하지만, 그때는 Uninstall 키·설치 로그·MSI 흔적이 함께 남는다. 아무 흔적 없이 서비스만 사라졌다면 반포렌식이다.

## 출력 필드 해석

### 원본 XML 예시

```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager" />
    <EventID Qualifiers="16384">7045</EventID>
    <TimeCreated SystemTime="2026-03-14T08:19:03.1194821Z" />
    <EventRecordID>10442</EventRecordID>
    <Channel>System</Channel>
    <Computer>SRV-FILE01</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">wqmtsbrv</Data>
    <Data Name="ImagePath">C:\Windows\wqmtsbrv.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
```

읽는 순서: `ImagePath`(무엇) → `StartType`(지속성인가) → `ServiceName`(도구 식별) → `TimeCreated`(언제, UTC).
7045 에는 **주체(누가)가 없다.** 그 답은 4697 또는 같은 시각대의 4624/4688 에서 가져온다.

## pivot: 다음에 볼 artifact

**7045 → 레지스트리 → 파일 시스템 → 실행** 순서로 잇는 것이 정석이다.

| 7045에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `ServiceName` | `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` ([FOR-0053](./system-controlset.html)) | 현재 존재 여부, `ImagePath`·`Start` 변경, `DisplayName`, `ServiceDll`, 키 LastWrite |
| `ServiceName` | 4697 ([FOR-0089](./event-4697-service-install.html)) | **누가 설치했나** (감사가 켜져 있었다면) |
| `ImagePath` 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일의 생성·수정 시각, 삭제 여부, 원래 크기 |
| `ImagePath` 파일명 | Prefetch, Amcache, AppCompatCache | 실제 실행 여부와 실행 횟수 |
| 등록 시각 | 4688 ([FOR-0088](./event-4688-process-creation.html)) | `sc create` / `New-Service` / `wmic` 명령행 |
| 등록 시각 | 4624 ([FOR-0083](./event-4624-logon.html)) | 그 시각 로그온 세션과 출처 IP |
| 등록 시각 | 5140 / 5145 | `ADMIN$` / `IPC$` 접근 (원격 등록의 증거) |
| `ServiceName` | 7036 / 7040 / 7034 | 실행 여부, 시작 유형 변경, 크래시 |
| `AccountName` | SAM hive | 전용 계정 생성 여부 |
| 파일 해시 | 다른 호스트의 7045 | 동일 도구의 확산 범위 |

## 흔한 함정

- **Security 채널에서 7045 를 찾는다.** 7045 는 **System 채널**이다. 채널을 틀리면 무조건 0건이 나오고 "지속성이 없다"는 오답으로 이어진다.
- **4697 이 없으니 서비스 설치 기록이 없다고 판정한다.** 4697 은 감사 정책이 필요해 대개 꺼져 있다. 7045 는 기본으로 남는다. **순서를 7045 먼저로 뒤집는다.**
- **7045 에서 "누가"를 찾으려 한다.** 이 이벤트에는 주체 필드가 없다. 4697 또는 같은 시각대의 4624/4688 로 가야 한다.
- **`ServiceType` 을 숫자로 검색한다.** 7045 는 `user mode service` 같은 문자열이다. `0x10` 으로 grep 하면 안 나온다. 반대로 4697 은 숫자다. 두 채널을 합칠 때 정규화가 필요하다.
- **레지스트리에 없는 서비스를 "오탐"으로 처리한다.** 등록 후 삭제된 서비스가 **가장 강한 증거**다. 7045 만 남았다는 사실 자체를 결론에 쓴다.
- **`demand start` 를 안전하다고 본다.** PsExec 계열 원격 실행은 demand start 로 등록되어 즉시 실행되고 삭제된다. 지속성이 아니라 **실행 자체**가 사건이다.
- **정상 이름을 그대로 신뢰한다.** `ServiceName` 이 `Spooler` 라도 `ImagePath` 가 `System32\spoolsv.exe` 가 아니면 하이재킹이다. 이름과 경로를 **쌍으로** 검증한다.
- **UTC/로컬 혼동.** EVTX `SystemTime` 은 UTC 다. Event Viewer 표시값은 로컬 변환값이다. KST 답은 +9시간.
- **7036 의 폭발적인 건수에 파묻힌다.** 7036 은 정상 시스템에서도 수천 건이다. 반드시 `ServiceName` 으로 좁혀서 본다.
- **`System.evtx` 롤오버를 고려하지 않는다.** System 채널은 기본 크기가 작아 오래된 7045 가 덮여 사라질 수 있다. 가장 오래된 레코드의 시각을 확인해 "로그가 커버하는 구간"을 먼저 정한다.

## 교차검증

```powershell
# 1) 7045 — 서비스 설치 전수 (System)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7045} | Format-List

# 2) 같은 서비스의 실행/상태 변경 이력
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7035,7036,7040} |
  Where-Object { $_.Message -match 'wqmtsbrv' }

# 3) 크래시/시작 실패 (이미지 삭제 시점의 단서)
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx';Id=7000,7024,7031,7034} |
  Where-Object { $_.Message -match 'wqmtsbrv' }

# 4) 주체 보강 — 4697 (있으면) / 4688 (등록 명령) / 4624 (세션)
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx';Id=4697,4688,4624} |
  Where-Object { $_.TimeCreated -gt '2026-03-14 08:15:00' -and $_.TimeCreated -lt '2026-03-14 08:25:00' }

# 5) 로그가 커버하는 구간 확인 (롤오버 판정)
$ev = Get-WinEvent -Path 'C:\case\System.evtx' -Oldest
$ev[0].TimeCreated; $ev[-1].TimeCreated
```

오프라인 SYSTEM hive 대조:

```text
Registry Explorer 로 SYSTEM hive 를 열고
  SYSTEM\Select\Current                       -> 1  (ControlSet001 이 활성)
  SYSTEM\ControlSet001\Services\wqmtsbrv      -> 키 자체가 없음
      => sc delete 로 지웠다. 7045 만 남은 상황.
  SYSTEM\ControlSet001\Services\PSEXESVC      -> 키 있음
      ImagePath = C:\Windows\PSEXESVC.exe
      Start     = 3
      Type      = 0x10
```

## mini walkthrough

```text
문제:
"침해된 서버에서 공격자가 심은 지속성 서비스의 이름과 실행 파일 경로를 구하세요.
 첨부: System.evtx, Security.evtx, SYSTEM hive"

1. 첫 시도 (실패):
   SYSTEM hive 의 ControlSet001\Services 를 전수 훑어 이상한 서비스를 찾았다.
   -> 이상한 것이 하나도 없었다. 전부 정상 Windows 서비스와 설치된 소프트웨어.
   "지속성이 없다"고 결론 낼 뻔했다.

2. 왜 틀렸나:
   레지스트리는 "현재 상태"다. 공격자가 sc delete 로 지우고 나가면
   레지스트리에는 아무 흔적도 남지 않는다.
   과거 등록 사실은 이벤트 로그에만 남는다.
   -> 현재 상태만 본 것이 실수였다.

3. 방향 전환 — System 채널의 7045 전수:
   Get-WinEvent -FilterHashtable @{Path='System.evtx';Id=7045} | Format-List

   3건 중 2건은 정상(드라이버 설치, 벤더 소프트웨어).
   남은 1건:
     TimeCreated : 2026-03-14 08:19:03Z
     ServiceName : wqmtsbrv
     ImagePath   : C:\Windows\wqmtsbrv.exe
     ServiceType : user mode service
     StartType   : auto start
     AccountName : LocalSystem

   무작위 이름 + C:\Windows\ 루트 + auto start + LocalSystem.
   레지스트리에는 이 키가 없다 -> 등록 후 삭제됐다.

4. 실제로 실행됐는지 확인 (7036):
   08:19:04Z  wqmtsbrv 서비스가 실행 중 상태로 전환되었습니다.
   -> 등록 1초 뒤 시작. 실행됐다.

5. 언제 사라졌나 (7000/7034):
   03-15 01:02:11Z  7000 wqmtsbrv 서비스를 시작할 수 없습니다.
   -> 재부팅 시 시작 실패. 즉 그 사이에 이미지 파일이 지워졌다.

6. 파일 흔적 교차검증 ($MFT):
   C:\Windows\wqmtsbrv.exe
     생성 2026-03-14 08:18:57Z  (등록 6초 전 — 복사 후 등록)
     $UsnJrnl 에 FileDelete  2026-03-14 23:47:10Z

7. 주체 보강:
   08:19:03Z 앞뒤의 4688 은 명령행 정책이 꺼져 있어 경로만 남았지만
   sc.exe 실행 기록이 있었고, 같은 SubjectLogonId 의 4624 는
   LogonType 3 / IpAddress 10.20.30.44 였다.

8. 시각 변환:
   EVTX SystemTime 은 UTC. 08:19:03Z -> KST 17:19:03.

정답: 서비스 wqmtsbrv, 이미지 C:\Windows\wqmtsbrv.exe
```

1단계의 실패가 핵심이다. **레지스트리는 현재, 7045 는 과거다.** 지속성 조사에서 두 개를 반대 순서로 보면 지우고 나간 공격자를 놓친다.

## 막혔을 때 다음 체크

1. `System.evtx` 를 열었는가 — 7045 는 Security 채널에 없다
2. 7045 를 **전수** 읽었는가 (보통 한 자리 수 건수다)
3. `ImagePath` 가 `System32` / `Program Files` / `drivers` 밖인 건을 뽑았는가
4. `ImagePath` 가 `cmd.exe` / `powershell` / `rundll32` / `mshta` 인 건이 있는가
5. `ServiceName` 이 무작위 문자열이거나 정상 이름의 변형인 건이 있는가
6. `StartType` = `auto start` 인 건을 지속성 후보로 분리했는가
7. 각 후보에 대해 7036(실행) · 7040(유형 변경) · 7000/7034(실패·크래시)를 이어붙였는가
8. 레지스트리 `Services` 키와 대조해 **없어진 서비스**를 찾았는가
9. `ImagePath` 의 파일을 `$MFT` · `$UsnJrnl` · Prefetch 로 추적했는가
10. 주체가 필요하면 → 4697, 없으면 같은 시각대 4688 / 4624
11. `System.evtx` 의 가장 오래된 레코드 시각을 확인해 롤오버 구간을 배제했는가
12. 답을 UTC 로 낼지 KST(+9)로 낼지 지문을 다시 읽었는가

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: Security 채널 4697 과 System 채널 7045 의 역할 구분, 감사 정책 의존성 여부
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: SYSTEM hive 의 `CurrentControlSet\Services` 대조와 `Select` 키 해석 근거
- SRC-086 — MITRE ATT&CK Enterprise Techniques: 서비스 생성 지속성, 원격 서비스 등록 기반 측면 이동, 취약 드라이버 로드, 흔적 삭제(서비스 삭제)의 근거
- 7045 의 `ServiceType` / `StartType` 은 SCM 이 렌더한 문자열로 기록되며 **OS 언어에 따라 현지화된다.** 한국어 OS 에서는 다른 문자열이 들어갈 수 있으므로 실제 이벤트 XML 에서 확인하고 필터를 짤 것
- 7045 가 존재하는 최소 Windows 버전, 그리고 7031 / 7034 의 메시지 차이는 OS 버전에 따라 표현이 다를 수 있으므로 실제 로그에서 확인할 것
- 무작위 서비스 이름의 길이·문자 구성은 도구와 버전마다 다르다. 특정 길이를 IOC 로 단정하지 말고 정상 이름 목록과의 대조로 판단할 것
</content>
