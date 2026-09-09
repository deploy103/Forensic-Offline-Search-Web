---
id: FOR-0102
title: "Sysmon Event ID 13 RegistryEvent: 레지스트리를 바꾼 프로세스 특정"
slug: "sysmon-event-13-registry-set"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Sysmon", "RegistryEvent", "TargetObject", "Details", "SetValue", "지속성"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"]
registry_paths: ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "HKCU\\Software\\Classes\\CLSID"]
event_ids: ["13", "12", "14"]
protocols: []
tools: ["Sysmon", "EvtxECmd", "Registry Explorer", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path sysmon.evtx -FilterXPath '*[System[EventID=13]]'", "EvtxECmd.exe -f sysmon.evtx --csv out --csvf sysmon.csv"]
regex_patterns: ["^\\\\REGISTRY\\\\(MACHINE|USER)\\\\", "HKU\\\\S-1-5-21-[0-9-]+"]
wireshark_filters: []
tshark_fields: []
log_fields: ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "NewName", "User"]
file_formats: ["evtx"]
primary_terms: ["Sysmon 13", "Sysmon RegistryEvent", "sysmon 레지스트리 변경"]
keywords: ["Sysmon", "Event ID 13", "RegistryEvent", "SetValue", "TargetObject", "Details", "12", "14", "레지스트리 변경", "지속성", "IFEO", "AppInit_DLLs", "COM 하이재킹", "evtx"]
aliases: ["sysmon 레지스트리 변경", "sysmon 13", "누가 레지스트리를 바꿨나", "레지스트리 지속성 탐지", "registry set 이벤트", "sysmon 12 14", "레지스트리 변경 주체"]
symptom_keywords: ["레지스트리를 바꾼 프로세스를 알고 싶다", "LastWrite로는 누가 바꿨는지 모른다", "지속성 등록 시점을 알고 싶다", "TargetObject 경로가 이상하게 나온다", "Details가 Binary Data로 나온다", "CurrentControlSet으로 검색해도 안 나온다"]
related: ["FOR-0077", "FOR-0099", "FOR-0063"]
source_ids: ["SRC-024", "SRC-017", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Sysmon Event ID 13은 레지스트리 값 설정마다 **바꾼 프로세스(`Image`)와 경로(`TargetObject`), 새 데이터(`Details`)** 를 남긴다. hive 분석은 키의 `LastWrite` 시각만 알고 주체를 모르므로, "누가 이 값을 썼는가"에 답하는 것은 이 로그뿐이다.

## 어떤 문제에서 필요한가

- "Run 키에 등록한 프로세스는 무엇인가" — 지속성 등록 주체
- "서비스가 언제 어떤 `ImagePath`로 만들어졌는가"
- "IFEO `Debugger`가 언제 심어졌는가"
- "이 레지스트리 값을 누가 지웠는가" — Event 12
- hive의 `LastWrite`만으로는 시점·주체가 불충분할 때
- 값이 여러 번 바뀐 이력 복원 (hive에는 마지막 상태만 남는다)

레지스트리 hive 자체의 구조와 파일 위치는 [FOR-0051](./registry-hive-map.html)을, `LastWrite`의 한계는 FOR-0077을 본다. **이 로그가 그 한계를 정확히 보완한다.**

## 문제에서 처음 볼 단서

1. 지문에 "지속성", "자동 실행 등록", "누가 등록했나" → Event 13
2. 레지스트리 경로가 하나 주어졌다 → `TargetObject`로 필터(단, 정규화 필요)
3. 지문에 "값이 삭제됐다", "키가 사라졌다" → Event 12
4. 지문에 "이름이 바뀐 키" → Event 14
5. hive에서 값은 찾았는데 시점을 모른다 → Event 13의 `UtcTime`

## 30초 절차

```powershell
# 원본: Microsoft-Windows-Sysmon%4Operational.evtx -> sysmon.evtx
Get-WinEvent -Path 'C:\case\sysmon.evtx' -FilterXPath '*[System[EventID=13]]' | Format-List
```

객체로 뽑고 경로를 **정규화**해 둔다. 이 정규화가 이 글의 실전 핵심이다.

```powershell
$sm = 'C:\case\sysmon.evtx'

function Normalize-RegPath([string]$p) {
  $q = $p
  $q = $q -replace '^\\REGISTRY\\MACHINE\\', 'HKLM\'
  $q = $q -replace '^\\REGISTRY\\USER\\',    'HKU\'
  $q = $q -replace '^HKLM\\System\\ControlSet\d{3}\\', 'HKLM\SYSTEM\CurrentControlSet\'
  $q = $q -replace '^HKLM\\SYSTEM\\ControlSet\d{3}\\', 'HKLM\SYSTEM\CurrentControlSet\'
  return $q
}

$p13 = Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=12 or EventID=13 or EventID=14]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime  = [datetime]::Parse($d['UtcTime'])
      Id       = $_.Id
      Type     = $d['EventType']
      Image    = $d['Image']
      Guid     = $d['ProcessGuid']
      Target   = Normalize-RegPath $d['TargetObject']
      Raw      = $d['TargetObject']
      Details  = $d['Details']
      NewName  = $d['NewName']
      User     = $d['User']
    }
  } | Sort-Object UtcTime

$p13 | Where-Object { $_.Id -eq 13 } |
  Select-Object UtcTime, Image, Target, Details | Format-Table -AutoSize
```

## 상세 절차

### 1단계 — 12 / 13 / 14 를 함께 본다

| ID | 이름 | `EventType` 값 | 추가 필드 | 무엇을 알려주는가 |
| --- | --- | --- | --- | --- |
| 12 | RegistryEvent (Object create and delete) | `CreateKey`, `DeleteKey`, `DeleteValue` | — | 키/값의 **생성·삭제** |
| 13 | RegistryEvent (Value Set) | `SetValue` | `Details` | **값 데이터 기록** |
| 14 | RegistryEvent (Key and Value Rename) | `RenameKey`, `RenameValue` | `NewName` | 이름 변경 전/후 |

세 이벤트를 반드시 함께 조회한다. 공격자는 **12(CreateKey) → 13(SetValue)** 순서로 지속성을 심고, 흔적 제거 때는 **12(DeleteValue)** 만 남긴다. 13만 보면 삭제 흔적을 통째로 놓친다.

| 필드 | 의미 |
| --- | --- |
| `RuleName` | 설정 규칙 태그. 지정 안 하면 빈 값 |
| `EventType` | 위 표의 동작 종류 |
| `UtcTime` | **이미 UTC인 변경 시각** |
| `ProcessGuid` / `ProcessId` | 변경을 수행한 프로세스 |
| `Image` | **변경 주체의 실행 파일 경로** |
| `TargetObject` | 대상 키/값의 전체 경로 |
| `Details` | **설정된 값 데이터**(13만) |
| `NewName` | 변경 후 이름(14만) |
| `User` | 변경 주체의 실행 계정 |

### 2단계 — TargetObject 경로 정규화 (실전 함정)

`TargetObject`는 커널 표기와 축약 표기가 섞여 나온다. 문제 지문의 경로를 그대로 검색하면 **0건이 나오고 "흔적이 없다"고 오판**하게 된다.

| 실제 로그에 나오는 형태 | 사람이 아는 형태 |
| --- | --- |
| `HKLM\SOFTWARE\...` | `HKEY_LOCAL_MACHINE\SOFTWARE\...` (동일) |
| `\REGISTRY\MACHINE\SOFTWARE\...` | `HKLM\SOFTWARE\...` |
| `\REGISTRY\USER\S-1-5-21-...\Software\...` | `HKCU\Software\...`(해당 사용자) |
| `HKU\S-1-5-21-1004\Software\...` | `HKCU\Software\...` |
| `HKU\S-1-5-21-1004_Classes\CLSID\...` | `HKCU\Software\Classes\CLSID\...` |
| `HKLM\System\ControlSet001\Services\...` | `HKLM\SYSTEM\CurrentControlSet\Services\...` |

**가장 많이 걸리는 것이 마지막 줄이다.** `CurrentControlSet`은 실행 중에만 존재하는 심볼릭 링크이므로 로그에는 `ControlSet001`(또는 `ControlSet002`)로 기록된다. `CurrentControlSet`으로 검색하면 서비스 지속성이 전부 안 잡힌다. ControlSet 번호와 `Select` 키의 의미는 [FOR-0051](./registry-hive-map.html)에 정리돼 있다.

`HKU\<SID>`는 사용자를 SID로만 알려 준다. SID → 사용자 이름 변환이 필요하다.

```powershell
# SID 별 변경 건수 (사용자 특정)
$p13 | Where-Object { $_.Target -match '^HKU\\S-1-5-21' } |
  Group-Object { ($_.Target -split '\\')[1] } | Sort-Object Count -Descending |
  Select-Object Count, Name
```

SID와 계정 이름 매핑은 `ProfileList` 또는 SAM hive에서 얻는다.

### 3단계 — Details 읽기

`Details`는 값 데이터를 문자열로 표현한 것이며, 타입에 따라 접두가 붙는다.

| `Details` 예시 | 원래 값 타입 | 해석 |
| --- | --- | --- |
| `C:\Windows\Temp\svchost.exe` | `REG_SZ` | 문자열 그대로 |
| `DWORD (0x00000001)` | `REG_DWORD` | 16진수. `1` |
| `QWORD (0x0000000000000001)` | `REG_QWORD` | 64비트 정수 |
| `Binary Data` | `REG_BINARY` | **내용이 표시되지 않는다** |
| 긴 문자열이 도중에 끊김 | 길이 초과 | **잘려서 기록된다** |

| 상황 | 대응 |
| --- | --- |
| `Details = Binary Data` | 값 자체는 로그에 없다 → hive에서 그 값을 직접 읽는다(Registry Explorer) |
| `Details`가 잘려 있다 | 마지막 상태는 hive에 있다 → Event 13으로 **시점과 주체**, hive로 **전체 데이터** |
| `Details = (Empty)` 유형 표기 | 빈 값 설정. 값 삭제와 구분해야 한다(삭제는 Event 12) |

**즉 Event 13과 hive 분석은 역할이 갈린다.** 시점·주체·변경 이력은 Event 13, 최종 데이터 전문은 hive다.

### 4단계 — 지속성 탐지 실전 필터

```powershell
$persist = @(
  '\\CurrentVersion\\Run$',
  '\\CurrentVersion\\Run\\',
  '\\CurrentVersion\\RunOnce',
  '\\CurrentVersion\\RunServices',
  '\\CurrentControlSet\\Services\\[^\\]+\\ImagePath',
  '\\CurrentControlSet\\Services\\[^\\]+\\ServiceDll',
  '\\CurrentVersion\\Winlogon\\(Shell|Userinit|Taskman|Notify)',
  '\\Image File Execution Options\\[^\\]+\\(Debugger|GlobalFlag)',
  '\\CurrentVersion\\Windows\\(AppInit_DLLs|LoadAppInit_DLLs)',
  '\\CLSID\\\{[^}]+\}\\InprocServer32',
  '\\CurrentVersion\\Explorer\\Shell Folders',
  '\\Environment\\UserInitMprLogonScript'
) -join '|'

$p13 | Where-Object { $_.Target -match $persist } |
  Select-Object UtcTime, Id, Type, Image, User, Target, Details |
  Sort-Object UtcTime | Format-Table -AutoSize
```

출력:

```text
UtcTime             Id Type      Image                       Target                                                         Details
-------             -- ----      -----                       ------                                                         -------
2026-03-14 07:31:02 13 SetValue  C:\Windows\Temp\svchost.exe  HKU\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\Run\Updater  C:\Windows\Temp\svchost.exe
2026-03-14 07:33:47 13 SetValue  C:\Windows\System32\sc.exe   HKLM\SYSTEM\CurrentControlSet\Services\WinSvcHlp\ImagePath     C:\ProgramData\Intel\ime.exe
2026-03-14 07:35:20 13 SetValue  C:\...\v1.0\powershell.exe   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger  C:\Windows\System32\cmd.exe
2026-03-14 09:44:11 12 DeleteValue C:\Windows\Temp\svchost.exe HKU\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\Run\Updater
```

| 대상 | 기법 | 판정 근거 |
| --- | --- | --- |
| `...\CurrentVersion\Run` / `RunOnce` | 로그온 시 자동 실행 | `Details`의 경로가 사용자 쓰기 가능 폴더면 확정 |
| `...\Services\<name>\ImagePath` | 서비스 지속성 | System.evtx 7045와 시각 대조 |
| `...\Winlogon\Shell` / `Userinit` | 셸 하이재킹 | 정상값은 `explorer.exe` / `userinit.exe`뿐 |
| `...\Image File Execution Options\<exe>\Debugger` | IFEO 하이재킹 | 접근성 도구(`sethc.exe`, `utilman.exe`)면 백도어 |
| `...\Windows\AppInit_DLLs` | 모든 프로세스에 DLL 주입 | 값이 비어 있는 것이 정상 |
| `...\CLSID\{...}\InprocServer32` | **COM 하이재킹** | `HKU`(사용자) 쪽에 생기면 `HKLM`보다 우선하므로 강한 신호 |
| `...\Environment\UserInitMprLogonScript` | 로그온 스크립트 | 값 자체가 드물다 |

마지막 줄(Event 12 `DeleteValue`)이 중요하다. **공격자가 작업을 마치고 Run 값을 지웠다.** hive만 보면 그 값은 애초에 없었던 것처럼 보인다. Event 12/13이 있어야 "등록했다가 지웠다"는 사실이 남는다.

### 5단계 — hive 분석과의 결정적 차이

| 질문 | 레지스트리 hive | **Sysmon 12/13/14** |
| --- | --- | --- |
| 현재 값 | 답한다 | 마지막 `SetValue`의 `Details`(잘릴 수 있음) |
| 값이 바뀐 시각 | 키 단위 `LastWrite`만 | **값 단위로 정확히** |
| **누가 바꿨는가** | **모른다** | **답한다** (`Image`, `User`, `ProcessGuid`) |
| 값별 변경 시각 | 불가(키 단위) | 값마다 개별 이벤트 |
| 여러 번 바뀐 이력 | 마지막 상태만 | **모든 변경이 순서대로** |
| 삭제된 값 | 흔적 없음(슬랙 제외) | Event 12에 남는다 |
| 조사 가능 구간 | 이미지 획득 시점의 상태 | Sysmon 설치 이후 |

hive의 `LastWrite`는 **키**의 마지막 수정 시각이므로, 같은 키 안의 다른 값을 나중에 건드리면 원래 관심 값의 변경 시각을 알 수 없게 된다. Event 13은 값 단위로 시각을 남기므로 이 한계가 없다.

### 6단계 — 프로세스 주체로 정상/비정상 가르기

```powershell
# 지속성 경로를 건드린 프로세스 분포
$p13 | Where-Object { $_.Target -match $persist } |
  Group-Object Image | Sort-Object Count -Descending | Select-Object Count, Name
```

| `Image` | 판정 |
| --- | --- |
| `C:\Windows\System32\svchost.exe`, `services.exe`, `TrustedInstaller.exe` | 대개 정상 시스템 동작 |
| 설치 프로그램(`msiexec.exe`, `setup.exe`) | 정상 설치. 시각을 설치 이벤트와 대조 |
| `reg.exe`, `sc.exe`, `schtasks.exe`, `powershell.exe`, `cmd.exe` | **수동 조작.** 명령행을 Sysmon 1에서 확인 |
| `\Temp\`·`\AppData\`의 실행 파일 | **악성 확정 후보** |
| `rundll32.exe`, `regsvr32.exe`, `mshta.exe` | LOLBin. 로드된 모듈을 확인 |

`reg.exe`가 값을 썼다면 Sysmon 1의 `CommandLine`에 **완전한 명령**이 남아 있다. 두 로그를 `ProcessGuid`로 잇는다([FOR-0083](./event-4624-logon.html)의 세션 피벗과 같은 방식이다).

## 출력 필드 해석

`UtcTime`은 **이미 UTC**다. Event Viewer 상단 시각은 EVTX `SystemTime`(UTC)을 로컬 시간대로 변환해 보여 준다. 답이 KST면 +9시간. 이미지의 시간대 설정 확인은 [FOR-0054](./system-timezone.html)를 본다.

| 상황 | 해석 |
| --- | --- |
| `TargetObject`가 `\REGISTRY\`로 시작 | 커널 표기. `HKLM`/`HKU`로 정규화해 비교 |
| `HKU\<SID>_Classes` | 사용자별 `Software\Classes`. COM 하이재킹의 주요 무대 |
| 같은 값에 13이 연속 다수 | 정상 프로그램의 주기적 상태 저장(노이즈) |
| `Details`가 hive 값과 다르다 | 이후에 또 변경됐다. 마지막 13을 찾는다 |
| Event 13이 거의 없다 | 설정에서 경로 기준으로만 켜 둔 상태. 제외 규칙을 확인 |
| `EventType`이 비어 있다 | 파싱 문제. XML 원문을 확인 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `ProcessGuid` | Sysmon 1 | 변경 주체의 명령행·부모·해시 |
| `Details`의 실행 파일 경로 | Sysmon 11 · `$MFT` | 그 파일이 언제 어떻게 생겼는가 |
| `Details`의 실행 파일 경로 | Sysmon 1의 `Image` | 실제로 실행됐는가(지속성 발동) |
| `Services\<name>\ImagePath` | System.evtx 7045 / Security 4697 | 서비스 설치 이벤트와 시각 일치 |
| `Run` 값 이름 | hive의 Run 키 현재 상태 (FOR-0063) | 값이 아직 남아 있는가 |
| `TargetObject`의 `HKU\<SID>` | `ProfileList` · SAM | SID → 사용자 이름 |
| `UtcTime` | 4624 세션 ([FOR-0083](./event-4624-logon.html)) | 어느 로그온 세션의 행위인가 |
| Event 12 `DeleteValue` | hive 슬랙·트랜잭션 로그 | 삭제된 값의 잔존 데이터 |
| 변경 시각 | 키의 `LastWrite`(FOR-0077) | 두 시각이 일치하는지, 이후 다른 변경이 있었는지 |

## 흔한 함정

- **`CurrentControlSet`으로 검색하는 것.** 로그에는 `ControlSet001`로 기록된다 → 서비스 지속성이 전부 누락된다 → 정규화 함수로 `ControlSet\d{3}` → `CurrentControlSet` 치환 후 검색한다.
- **`HKCU`로 검색하는 것.** 로그는 `HKU\<SID>` 또는 `\REGISTRY\USER\<SID>`로 남는다 → 0건이 나온다 → SID 형태로 검색하거나 정규화한다.
- **`\REGISTRY\MACHINE\` 표기를 다른 하이브로 착각하는 것.** `HKLM`과 같은 곳이다 → 접두만 다르다.
- **`Details = Binary Data`를 로그 손상으로 보는 것.** 이진 값은 내용이 표시되지 않는 정상 동작이다 → 데이터가 필요하면 hive에서 그 값을 직접 읽는다.
- **잘린 `Details`를 전체 값으로 답하는 것.** 긴 데이터는 끊긴다 → 최종 데이터는 hive에서 확인하고, Event 13은 시점·주체 근거로 쓴다.
- **Event 13만 조회하는 것.** 삭제(값/키)는 Event 12에 있다 → 12/13/14를 한 번에 조회한다.
- **`Image`가 시스템 프로세스면 무조건 정상으로 넘기는 것.** DLL 주입된 `svchost.exe`도 시스템 경로다 → `ProcessGuid`로 Sysmon 1을 확인해 부모와 명령행을 본다.
- **hive의 `LastWrite`를 값 변경 시각으로 답하는 것.** `LastWrite`는 키 단위이며 같은 키의 다른 값 변경으로도 갱신된다 → 값 단위 시각은 Event 13이 유일한 근거다.
- **`UtcTime`에 9시간을 또 더하는 것.** 이미 UTC다 → KST 답에만 한 번 적용한다.
- **노이즈를 그대로 두고 보는 것.** 정상 프로그램이 초당 수십 건씩 값을 쓴다 → 지속성 경로 화이트리스트로 먼저 좁힌다.

## 교차검증

```powershell
$sm = 'C:\case\sysmon.evtx'

# 1) 지속성 경로 변경 전체 (12/13/14 동시)
$p13 | Where-Object { $_.Target -match $persist } | Format-Table UtcTime, Id, Type, Image, Target, Details -AutoSize

# 2) 변경 주체의 명령행 (Sysmon 1)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=1]]' |
  Where-Object { $_.Message -match 'reg\.exe|sc\.exe|schtasks' } |
  Select-Object -First 10 TimeCreated, Message

# 3) 서비스 설치 이벤트와 대조
Get-WinEvent -FilterHashtable @{Path='C:\case\System.evtx'; Id=7045}

# 4) 등록된 파일이 실제로 실행됐는가
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=1]]' |
  Where-Object { $_.Message -match 'ime\.exe' } | Select-Object TimeCreated

# 5) 삭제된 값 (12) 만 따로
$p13 | Where-Object { $_.Id -eq 12 -and $_.Type -match 'Delete' } |
  Select-Object UtcTime, Type, Image, Target
```

Event 13의 시각, 7045의 서비스 설치 시각, hive의 `LastWrite`가 정합해야 한다. 세 값이 어긋나면 이후 추가 변경이 있었다는 뜻이다.

## mini walkthrough

```text
문제:
"공격자가 등록한 지속성 두 가지와, 각각을 등록한 프로세스를 답하시오.
 첨부: Microsoft-Windows-Sysmon%4Operational.evtx, SYSTEM/SOFTWARE/NTUSER.DAT"

1. 첫 시도 (실패):
   문제 지문의 경로 표기를 그대로 써서 검색했다.

     $p | Where-Object { $_.Target -match 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' }
     -> 0건
     $p | Where-Object { $_.Target -match 'CurrentControlSet\\Services' }
     -> 0건

   "레지스트리 지속성은 없다" 고 결론 내리고 예약 작업을 뒤졌다. 오답.

   왜 틀렸나:
   Sysmon 의 TargetObject 표기가 다르다.
     - HKCU 는 HKU\S-1-5-21-...  로 기록된다
     - CurrentControlSet 은 ControlSet001 로 기록된다
   사람이 쓰는 경로 문자열로는 매칭되지 않는다.

2. 피벗 — 원본 TargetObject 를 그대로 몇 건 출력해 표기를 확인했다.

     HKU\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\Run\Updater
     HKLM\System\ControlSet001\Services\WinSvcHlp\ImagePath
     \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\...

   -> 세 가지 표기가 섞여 있었다. 정규화 함수를 만들어 다시 검색.

3. 정규화 후 결과:
   07:31:02  13 SetValue
     Image   C:\Windows\Temp\svchost.exe
     Target  HKU\S-1-5-21-1004\...\CurrentVersion\Run\Updater
     Details C:\Windows\Temp\svchost.exe
     User    WIN10\jhkim

   07:33:47  13 SetValue
     Image   C:\Windows\System32\sc.exe
     Target  HKLM\SYSTEM\CurrentControlSet\Services\WinSvcHlp\ImagePath
     Details C:\ProgramData\Intel\ime.exe
     User    NT AUTHORITY\SYSTEM

4. sc.exe 의 명령행 확인 (같은 ProcessGuid 로 Sysmon 1):
   07:33:47  sc.exe create WinSvcHlp binPath= "C:\ProgramData\Intel\ime.exe" start= auto
     Parent -> powershell.exe -nop -w hidden -enc ...

5. hive 와 대조:
   NTUSER.DAT 의 Run 키에는 Updater 값이 없었다.
   -> Event 12 를 확인: 09:44:11 DeleteValue (Image = Temp\svchost.exe)
      등록했다가 지웠다. hive 만 보면 존재 자체를 놓친다.
   SYSTEM hive 에는 WinSvcHlp 서비스가 남아 있었고 LastWrite 는 07:33:47.

6. 시간대: UtcTime 은 이미 UTC. 07:31:02 UTC = 16:31:02 KST (+9h)

정답:
  (1) HKCU Run\Updater = C:\Windows\Temp\svchost.exe  등록 주체 C:\Windows\Temp\svchost.exe (이후 삭제)
  (2) 서비스 WinSvcHlp ImagePath = C:\ProgramData\Intel\ime.exe  등록 주체 sc.exe (부모 powershell.exe)
```

1단계의 0건이 이 글에서 가장 중요한 함정이다. **경로 표기를 정규화하지 않으면 있는 증거도 없다고 답한다.** 그리고 5단계에서 보듯 **hive에서 사라진 값도 Event 12/13에는 남는다.**

## 막혔을 때 다음 체크

1. `TargetObject`를 정규화했는가 → `ControlSet001`, `HKU\<SID>`, `\REGISTRY\MACHINE\`
2. 원본 `TargetObject` 몇 건을 그냥 출력해 봤는가 → 표기 확인이 가장 빠른 진단
3. 12/14도 함께 조회했는가 → 삭제·이름 변경이 여기 있다
4. `Details`가 잘렸거나 `Binary Data`인가 → 최종 데이터는 hive에서 읽는다
5. `Image`가 `reg.exe`/`sc.exe`/`powershell.exe`인가 → Sysmon 1의 명령행에 전체 명령이 있다
6. Event 13이 거의 없는가 → 설정 제외. hive `LastWrite`와 트랜잭션 로그로 보완
7. 서비스 지속성이면 7045/4697과 시각을 맞췄는가
8. 등록된 파일이 실제로 실행됐는가 → 같은 경로가 Sysmon 1의 `Image`로 등장하는지 확인
9. `HKU\<SID>`의 사용자 이름을 확정했는가 → `ProfileList`/SAM으로 변환

## 출처

- SRC-024 — Microsoft Learn, Sysmon: Event ID 12/13/14 RegistryEvent의 필드와 `EventType` 값, 레지스트리 경로 축약 표기
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `HKLM`/`HKU` 루트 키와 hive 파일 대응, `CurrentControlSet` 표기
- SRC-086 — MITRE ATT&CK Enterprise: Run 키·서비스·IFEO·AppInit_DLLs·COM 하이재킹 등 레지스트리 기반 지속성 기법
- `Details`의 문자열 길이 제한(잘리는 기준 바이트 수)은 문서화된 상수를 확인하지 못해 단정하지 않았다. 잘린 것으로 보이면 hive에서 값을 직접 읽을 것
- 경로 축약 표기(`\REGISTRY\MACHINE\` vs `HKLM\`)가 어느 조건에서 어떤 형태로 나오는지는 Sysmon 버전과 이벤트 경로에 따라 다르다. **실제 로그의 원본 `TargetObject`를 먼저 출력해 확인**한 뒤 정규화 규칙을 확정할 것
