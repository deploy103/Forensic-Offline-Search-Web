---
id: FOR-0055
title: "SOFTWARE hive로 설치 프로그램·OS 버전·ProfileList 확인"
slug: "software-installed-programs"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["SOFTWARE hive", "Uninstall", "WOW6432Node", "ProfileList", "Windows NT CurrentVersion", "Run"]
file_paths: ["C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Users\\<user>\\NTUSER.DAT"]
registry_paths: ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", "SOFTWARE\\Classes"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r SOFTWARE -p uninstall", "rip.exe -r SOFTWARE -p winver", "rip.exe -r SOFTWARE -p profilelist"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["DisplayName", "DisplayVersion", "InstallDate", "InstallLocation", "Publisher", "UninstallString", "ProductName", "CurrentBuild", "RegisteredOwner", "ProfileImagePath"]
file_formats: ["regf"]
primary_terms: ["SOFTWARE hive", "Uninstall", "ProfileList", "설치 프로그램", "WOW6432Node"]
keywords: ["SOFTWARE hive", "Uninstall", "설치 프로그램", "DisplayName", "InstallDate", "WOW6432Node", "ProfileList", "ProfileImagePath", "ProductName", "CurrentBuild", "RegisteredOwner", "Run 키", "자동실행"]
aliases: ["설치된 프로그램 목록", "software hive", "언인스톨 키", "윈도우 버전 확인", "설치 시각", "sid 프로필 경로", "profilelist", "자동실행 레지스트리"]
symptom_keywords: ["어떤 프로그램이 설치돼 있었나", "윈도우 버전을 알고 싶다", "OS 설치 시각이 필요하다", "SID가 어느 폴더인지", "설치 목록에 없는 프로그램이 실행됐다", "자동실행 항목을 찾고 싶다"]
related: ["FOR-0051", "FOR-0052", "FOR-0061", "FOR-0063"]
source_ids: ["SRC-017", "SRC-004", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SOFTWARE` hive는 `Microsoft\Windows\CurrentVersion\Uninstall`(설치 프로그램 목록), `Microsoft\Windows NT\CurrentVersion`(OS 버전·설치 시각·등록 소유자), `Microsoft\Windows NT\CurrentVersion\ProfileList`(SID ↔ 프로필 폴더) 세 곳으로 "이 PC에 무엇이 설치되어 있었고 누구의 것인가"를 답한다.

## 어떤 문제에서 필요한가

- "이 PC에 어떤 프로그램이 설치되어 있었나" / "특정 도구(VPN, 원격제어, 압축, 삭제 도구)를 설치했나"
- "Windows 버전과 빌드는? OS를 언제 설치했나? 등록 소유자는 누구인가"
- "`S-1-5-21-...-1001`이 어느 사용자 폴더인가" — 사용자별 artifact 귀속의 필수 단계
- "부팅 때 자동으로 실행되는 것이 있나" (시스템 전역)
- "실행 이력에는 있는데 설치 목록에 없는 프로그램" — portable 실행 파일 또는 드롭된 악성코드

## 문제에서 처음 볼 단서

1. 첨부에 `SOFTWARE`(확장자 없음, 다른 hive보다 파일이 크다)가 있다
2. 문제가 프로그램 이름·버전·설치 시각을 묻는다
3. EVTX나 다른 artifact에 SID만 있고 사용자 이름이 없다
4. 32비트 프로그램인데 `Uninstall`에 안 보인다 → `WOW6432Node` 아래를 봐야 한다
5. 문제가 "정품 등록자", "조직명", "OS 설치일" 같은 시스템 신원을 묻는다

## 30초 절차

```powershell
rip.exe -r "C:\case\SOFTWARE" -p uninstall > uninstall.txt
```

```text
Microsoft\Windows\CurrentVersion\Uninstall
LastWrite Time 2026-03-14 06:41:02Z

2026-03-14 06:41:02Z
  7-Zip 23.01 (x64) v.23.01
2026-03-12 22:07:55Z
  Eraser 6.2.0.2993 v.6.2.0.2993
2026-03-10 04:31:18Z
  Google Chrome v.132.0.6834.160
```

이어서 OS 정보와 프로필 매핑을 뽑는다.

```powershell
rip.exe -r "C:\case\SOFTWARE" -p winver
rip.exe -r "C:\case\SOFTWARE" -p profilelist
```

GUI라면 RegistryExplorer로 `SOFTWARE`를 열고 다음 세 경로만 먼저 본다.

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
SOFTWARE\Microsoft\Windows NT\CurrentVersion
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
```

## 상세 절차

### 1단계 — `Uninstall` 키 구조

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
├── {AC76BA86-1033-1033-7760-BC15014EA700}      <- MSI ProductCode(GUID)
├── 7-Zip                                        <- 설치 프로그램이 정한 이름
└── Google Chrome
```

키 이름은 MSI `ProductCode` GUID이거나 프로그램이 정한 문자열이다. **키 이름 자체는 표시 이름이 아니므로 `DisplayName` 값을 읽어야 한다.**

| 값 이름 | 타입 | 의미 / 주의 |
| --- | --- | --- |
| `DisplayName` | `REG_SZ` | 제어판에 보이는 이름. **이것이 프로그램 이름이다** |
| `DisplayVersion` | `REG_SZ` | 버전 문자열 |
| `InstallDate` | `REG_SZ` | **`YYYYMMDD` 8자리 날짜만.** 시각이 없다 |
| `InstallLocation` | `REG_SZ` | 설치 폴더. 비어 있는 프로그램도 많다 |
| `InstallSource` | `REG_SZ` | 설치 파일이 있던 경로. **`Downloads`/`Temp`/`E:\` 면 출처 단서** |
| `Publisher` | `REG_SZ` | 제작사. 비어 있거나 오타면 의심 |
| `UninstallString` | `REG_SZ` | 제거 명령. 실제 실행 파일 경로가 여기 드러나는 경우가 많다 |
| `QuietUninstallString` | `REG_SZ` | 무인 제거 명령 |
| `EstimatedSize` | `REG_DWORD` | 대략 크기(**KB 단위**) |
| `DisplayIcon` | `REG_SZ` | 아이콘 경로. 주 실행 파일 경로가 드러난다 |
| `ModifyPath` | `REG_SZ` | 변경 명령 |
| `SystemComponent` | `REG_DWORD` | `1`이면 제어판 목록에서 숨겨진다. **은닉 수단으로 쓰일 수 있다** |
| `WindowsInstaller` | `REG_DWORD` | `1`이면 MSI 설치 |

```powershell
# 특정 프로그램만
Select-String -Path uninstall.txt -Pattern 'Eraser|CCleaner|VeraCrypt|AnyDesk|TeamViewer|7-Zip|WinRAR'
```

### 2단계 — `WOW6432Node` (32비트 프로그램)

64비트 Windows에서 **32비트 프로그램은 다른 경로에 등록된다.**

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall           <- 64비트 프로그램
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall  <- 32비트 프로그램
```

`WOW6432Node`는 `SOFTWARE` 아래 어디에나 병렬로 존재할 수 있다(`WOW6432Node\Microsoft\Windows\CurrentVersion\Run`도 있다). **한쪽만 보고 "설치되지 않았다"고 결론 내리는 것이 이 hive의 대표적 오답 경로다.**

사용자 단독 설치(`per-user install`)는 또 다른 곳에 있다.

| 설치 범위 | hive | 경로 |
| --- | --- | --- |
| 전체 사용자, 64비트 | `SOFTWARE` | `Microsoft\Windows\CurrentVersion\Uninstall` |
| 전체 사용자, 32비트 | `SOFTWARE` | `WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` |
| 특정 사용자만 | `NTUSER.DAT` | `Software\Microsoft\Windows\CurrentVersion\Uninstall` |

Chrome, Teams처럼 사용자 폴더에 설치되는 프로그램은 `NTUSER.DAT` 쪽에만 있는 경우가 있다. **세 곳을 모두 확인한다.**

### 3단계 — `Windows NT\CurrentVersion` (OS 신원)

```text
SOFTWARE\Microsoft\Windows NT\CurrentVersion
```

| 값 이름 | 의미 |
| --- | --- |
| `ProductName` | `Windows 10 Pro` 등 에디션 이름 |
| `EditionID` | `Professional`, `Enterprise` 등 |
| `CurrentBuild` / `CurrentBuildNumber` | 빌드 번호 (예: `19045`) |
| `DisplayVersion` | `22H2` 같은 표시 버전 (최신 빌드에 존재) |
| `ReleaseId` | 구버전의 릴리스 식별자 (예: `2009`) |
| `UBR` | Update Build Revision. 빌드 뒤에 붙는 패치 번호 |
| `CurrentMajorVersionNumber` / `CurrentMinorVersionNumber` | `10` / `0` |
| `BuildLabEx` | 상세 빌드 문자열 |
| `InstallDate` | **`REG_DWORD`, Unix epoch 초(UTC).** OS 설치 시각 |
| `InstallTime` | **`REG_QWORD`, FILETIME(UTC).** 같은 시각을 더 정밀하게 |
| `RegisteredOwner` | 설치 시 입력한 소유자 이름 |
| `RegisteredOrganization` | 조직명 |
| `SystemRoot` / `PathName` | `C:\Windows` |
| `ProductId` | 제품 ID |

**같은 이름 `InstallDate`가 위치에 따라 완전히 다른 형식이다.** 이것을 혼동하면 값이 통째로 의미를 잃는다.

| 위치 | `InstallDate` 타입 | 형식 | 변환 |
| --- | --- | --- | --- |
| `Uninstall\<프로그램>` | `REG_SZ` | `20260314` (날짜만) | 변환 불필요. 시각 정보 없음 |
| `Windows NT\CurrentVersion` | `REG_DWORD` | `1773465600` (Unix 초) | UTC → KST +9h |

```powershell
# InstallDate (REG_DWORD, Unix 초) -> KST
$unix = 1773465600
[datetimeoffset]::FromUnixTimeSeconds($unix).UtcDateTime.AddHours(9)
```

`InstallTime`(`REG_QWORD`)이 있으면 그쪽이 FILETIME이므로 초 단위 이하까지 나온다. FILETIME은 1601-01-01 UTC 기준 100ns, Unix와의 차이는 `11644473600`초다 ([FOR-0054](./system-timezone.html)).

### 4단계 — `ProfileList` (SID ↔ 프로필 폴더)

```text
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
├── S-1-5-18                                              <- LocalSystem
├── S-1-5-19                                              <- LocalService
├── S-1-5-20                                              <- NetworkService
└── S-1-5-21-3419281148-2201972856-1043271217-1001        <- 실제 사용자
```

| 값 이름 | 의미 |
| --- | --- |
| `ProfileImagePath` | **프로필 폴더 경로** (`C:\Users\jhkim`). 이 글에서 가장 중요한 값 |
| `Sid` | 이진 형태의 SID. 키 이름과 같은 값 |
| `Flags` / `State` | 프로필 상태 플래그 |
| `RefCount` | 로드 참조 수 |
| `LocalProfileLoadTimeLow` / `High` | 프로필 로드 시각의 FILETIME 하위/상위 32비트 (빌드에 따라 존재) |
| `LocalProfileUnloadTimeLow` / `High` | 프로필 언로드 시각의 FILETIME 하위/상위 32비트 (빌드에 따라 존재) |

`...LoadTimeLow`/`High`는 **두 DWORD를 합쳐 하나의 64비트 FILETIME**으로 읽어야 한다. 값의 존재 여부와 정확한 이름이 빌드마다 다르므로 파서 출력으로 확인한다. 존재한다면 "그 사용자가 마지막으로 로그온/로그오프한 시각"의 유력한 근거가 된다.

`SAM`의 RID와 여기 SID의 마지막 숫자를 맞추면 계정 ↔ 폴더 표가 완성된다 ([FOR-0052](./sam-user-accounts.html)).

| SID | ProfileImagePath | SAM RID | 결론 |
| --- | --- | --- | --- |
| `...-1001` | `C:\Users\jhkim` | 1001 | 정상 사용자 |
| `...-1004` | `C:\Users\svc_helpdesk` | 1004 | 최근 생성 계정 |
| `...-1002` | `C:\Users\temp2` | (SAM에 없음) | **삭제된 계정의 잔존 프로필** |
| `S-1-5-18` | `C:\Windows\system32\config\systemprofile` | — | 시스템 계정 |

### 5단계 — 시스템 전역 자동실행

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

값 이름이 표시 이름, 데이터가 실행할 명령줄이다.

```text
SecurityHealth   REG_EXPAND_SZ  %windir%\system32\SecurityHealthSystray.exe
OneDriveSetup    REG_SZ         C:\Windows\SysWOW64\OneDriveSetup.exe /thfirstsetup
updater          REG_SZ         C:\Users\jhkim\AppData\Roaming\svc\updater.exe -s
```

의심 판단 기준은 서비스와 같다.

```text
- 데이터 경로가 AppData / Temp / ProgramData / Users 아래다
- powershell / mshta / rundll32 / wscript 가 인자와 함께 들어 있다
- Base64 로 보이는 긴 문자열이 인자에 있다
- 값 이름이 정상 항목과 한두 글자 다르다
```

사용자별 자동실행은 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`이다. 시스템 전역과 사용자별을 모두 봐야 한다.

### 6단계 — `Classes` 서브키

```text
SOFTWARE\Classes
├── .txt                     <- 확장자 -> ProgID 매핑
├── .exe
├── txtfile\shell\open\command
└── CLSID\{GUID}\InProcServer32
```

`SOFTWARE\Classes`는 `HKCR`의 **머신 부분**이고, 사용자 부분은 `UsrClass.dat`(=`HKCU\Software\Classes`)다. 둘을 합친 뷰가 `HKCR`이다 ([FOR-0051](./registry-hive-map.html)).

| 무엇을 보나 | 경로 예 |
| --- | --- |
| 확장자 연결 하이재킹 | `SOFTWARE\Classes\<ProgID>\shell\open\command` — 정상 프로그램 대신 다른 실행 파일이 지정됨 |
| COM 하이재킹 | `SOFTWARE\Classes\CLSID\{GUID}\InProcServer32` — 등록된 DLL 경로 |
| 어떤 프로그램이 확장자를 등록했나 | `SOFTWARE\Classes\.<ext>` 의 기본값(ProgID) |

`.exe` 연결이 비정상 명령으로 바뀌어 있으면 모든 실행이 그 프로그램을 경유한다.

### 7단계 — 그 외 자주 쓰는 SOFTWARE 키

| 경로 (`SOFTWARE\` 이후) | 무엇을 알 수 있나 |
| --- | --- |
| `Microsoft\Windows\CurrentVersion\App Paths\<exe>` | 실행 파일 별칭과 실제 경로 |
| `Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell`, `Userinit` — 로그온 지속성 하이재킹 지점 |
| `Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` | 접속한 네트워크 이름과 최초/최종 접속 시각. **이 시각은 로컬 시각으로 기록되는 것으로 알려져 있으므로 파서 출력으로 확인한다** |
| `Microsoft\Windows Search` | 인덱싱 설정 |
| `Policies\Microsoft\Windows Defender` | 실시간 보호 비활성화 여부 |
| `Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions` | Known Folder 정의 |

### 8단계 — 설치 시각 문제를 다루는 방법

`Uninstall` 항목의 시각 근거는 두 개뿐이고 둘 다 불완전하다.

| 근거 | 정밀도 | 한계 |
| --- | --- | --- |
| `InstallDate` (`REG_SZ`) | **날짜만** (`20260314`) | 시각이 없다. 설치 프로그램이 안 쓰면 값 자체가 없다 |
| 그 `Uninstall\<키>`의 LastWrite | 초 단위 (UTC) | 설치 후 업데이트·수리로 갱신될 수 있다 |

"몇 시 몇 분에 설치했나"를 요구하면 레지스트리만으로는 부족하다. 다음으로 보강한다.

| 보강 근거 | 무엇을 얻나 |
| --- | --- |
| `InstallLocation` 폴더의 `$MFT` 생성 시각 | 파일이 실제로 디스크에 쓰인 시각 ([FOR-0021](./mft-basics.html)) |
| `C:\Windows\Installer\*.msi` 의 `$MFT` 시각 | MSI 캐시 생성 시각 |
| Application EVTX `MsiInstaller` 이벤트 (1033/11707 등) | 설치 성공 시각과 제품명 |
| Prefetch의 설치 프로그램 `.pf` | 설치 프로그램이 실행된 시각 |
| `Amcache.hve` | 설치 파일의 SHA-1과 최초 등록 시각 |

### 9단계 — 악성 프로그램 흔적으로 해석하기

`Uninstall` 목록은 **정식 설치 절차를 거친 프로그램만** 기록한다. 이 성질이 오히려 판단 근거가 된다.

| 관찰 | 해석 |
| --- | --- |
| `Uninstall`에 없는데 Prefetch·UserAssist·Amcache에 실행 이력이 있다 | **portable 실행 파일 또는 드롭된 악성코드.** 설치 과정이 없었다 |
| `Uninstall`에 있는데 `InstallLocation` 폴더가 `$MFT`에 없다 | 제거되었거나 삭제됨. `$UsnJrnl`로 삭제 시각 확인 ([FOR-0027](./usnjrnl-basics.html)) |
| `SystemComponent = 1`인 사용자 프로그램 | 제어판 목록에서 일부러 숨김 |
| `Publisher`가 비었고 `InstallSource`가 `Downloads` | 인터넷에서 받은 비서명 프로그램 |
| 데이터 삭제·와이핑 도구가 설치되어 있다 | 반포렌식 시도. 설치 시각과 사고 시각을 비교 |
| `Uninstall` 키 LastWrite가 사고 시각대에 몰려 있다 | 그 시각대에 설치·제거 활동이 있었다 |
| `Run` 값이 `AppData` 경로를 가리킨다 | 지속성 확보 흔적 |

"설치 목록에 없다"는 **부재 증거로 쓸 수 있는 강한 신호**다. 실행 이력만 있고 설치 이력이 없으면 사용자가 파일을 받아 그냥 실행했다는 결론으로 이어진다.

## 출력 필드 해석

| 필드 | 어디서 | 결론에 어떻게 쓰나 |
| --- | --- | --- |
| `DisplayName` + `DisplayVersion` | `Uninstall\<키>` | 프로그램 신원. 답으로 그대로 제출하는 값 |
| `InstallDate` (`REG_SZ`) | `Uninstall\<키>` | 설치 **날짜**. 시각은 다른 근거로 |
| `InstallSource` | `Uninstall\<키>` | 설치 파일 출처(다운로드 폴더, USB 드라이브 문자) |
| `UninstallString` / `DisplayIcon` | `Uninstall\<키>` | 실제 실행 파일 경로 노출 |
| 키 LastWrite | `Uninstall\<키>` | 설치/변경 시각(UTC). 초 단위 근거 |
| `ProductName` + `CurrentBuild` + `UBR` | `Windows NT\CurrentVersion` | OS 신원. artifact 해석 기준(빌드별 동작 차이) |
| `InstallDate` (`REG_DWORD`) | `Windows NT\CurrentVersion` | OS 설치 시각. Unix 초(UTC) |
| `RegisteredOwner` | `Windows NT\CurrentVersion` | 설치자 이름. 문제의 답이 되는 경우가 많다 |
| `ProfileImagePath` | `ProfileList\<SID>` | SID → 사용자 폴더 매핑 |
| `Run` 값 데이터 | `CurrentVersion\Run` | 지속성 실행 명령 |

키 LastWrite와 `InstallTime`은 FILETIME 기반이므로 **UTC**다. `InstallDate`(`REG_SZ`)는 시각이 없어 시간대 변환 대상이 아니다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| `ProfileImagePath` | 그 폴더의 `NTUSER.DAT` | 사용자별 실행 이력 ([FOR-0061](./userassist.html)) |
| `ProfileImagePath` | 그 폴더의 `UsrClass.dat` | ShellBags |
| SID | `SAM\Domains\Account\Users` | 계정명·RID·로그온 이력 ([FOR-0052](./sam-user-accounts.html)) |
| `InstallLocation` / `DisplayIcon` 경로 | Prefetch, `Amcache.hve` | 그 프로그램이 실제로 실행됐는가 |
| `InstallSource` 경로 | 브라우저 Downloads, LNK, USB 이력 | 설치 파일을 어디서 받았는가 |
| `InstallLocation` 폴더 | `$MFT` / `$UsnJrnl` | 파일 생성·삭제 시각 ([FOR-0021](./mft-basics.html)) |
| `Run` 값의 실행 파일 | Prefetch, 4688, Sysmon 1 | 실제 실행과 명령행 |
| `CurrentBuild` | 해당 빌드의 artifact 동작 | 빌드별로 존재하는 artifact가 다르다 |
| 설치 목록에 없는 실행 이력 | `Amcache.hve`, Shimcache | 해시·경로로 파일 신원 특정 |

## 흔한 함정

- **`WOW6432Node`를 안 보는 것.** 64비트 Windows에서 32비트 프로그램은 `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`에 있다. 한쪽만 보고 "설치 안 됨"으로 결론 내리면 오답이다. `Run` 키도 마찬가지다.
- **`Uninstall` 키 이름을 프로그램 이름으로 답하는 것.** 키 이름은 `{AC76BA86-...}` 같은 GUID일 수 있다. 이름은 `DisplayName` 값이다.
- **`InstallDate` 두 종류를 혼동하는 것.** `Uninstall` 아래는 `REG_SZ` `YYYYMMDD`(날짜만), `Windows NT\CurrentVersion` 아래는 `REG_DWORD` Unix 초다. 후자를 문자열로 읽거나 전자를 epoch로 변환하면 값이 무의미해진다.
- **`InstallDate`로 "몇 시에 설치했나"를 답하려는 것.** 날짜만 있다. 시각은 키 LastWrite, `$MFT`, MsiInstaller 이벤트로 보강한다.
- **`Uninstall`에 없으니 실행되지 않았다고 결론 내리는 것.** portable exe, 드롭된 악성코드, 압축 해제 후 바로 실행한 파일은 설치 흔적이 없다. Prefetch/Amcache/UserAssist로 넘어간다.
- **사용자 단독 설치를 놓치는 것.** Chrome 등은 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Uninstall`에만 있을 수 있다.
- **`ProfileImagePath`의 폴더명을 계정명으로 단정하는 것.** 계정 이름을 바꿔도 폴더명은 안 바뀌고, 충돌 시 `이름.컴퓨터명` 접미사가 붙는다. 계정명은 `SAM`으로 확정한다.
- **`ProfileList`에는 있는데 `SAM`에는 없는 SID를 무시하는 것.** 삭제된 로컬 계정 또는 도메인 계정이다. 삭제 계정 추적의 유일한 단서일 수 있다.
- **`LocalProfileLoadTimeLow`/`High`를 각각 독립된 시각으로 읽는 것.** 두 DWORD를 합쳐 하나의 64비트 FILETIME으로 읽는다. 값의 존재와 이름은 빌드마다 다르므로 파서로 확인한다.
- **키 LastWrite를 로컬 시각으로 읽는 것.** FILETIME이므로 UTC다. KST는 +9시간.
- **`SOFTWARE`가 커서 GUI 탐색만 하는 것.** hive 중 가장 크다. `rip.exe -r SOFTWARE -a`로 일괄 덤프한 뒤 텍스트 검색하는 편이 빠르다 ([FOR-0121](./powershell-select-string.html)).

## 교차검증

```powershell
# 1) 설치 목록 3곳 모두
rip.exe -r SOFTWARE -p uninstall > u64.txt
# (WOW6432Node 와 NTUSER.DAT 쪽은 RegistryExplorer 로 직접 확인)

# 2) OS 신원과 프로필
rip.exe -r SOFTWARE -p winver
rip.exe -r SOFTWARE -p profilelist

# 3) 실행 이력과 대조 — 설치 없이 실행된 것 찾기
rip.exe -r NTUSER.DAT -p userassist > ua.txt
Select-String -Path ua.txt -Pattern 'Downloads|Temp|AppData'

# 4) 파일이 실제로 있었는지
Import-Csv mft.csv | Where-Object { $_.ParentPath -like '*Program Files*Eraser*' }

# 5) 설치 이벤트
EvtxECmd.exe -f Application.evtx --csv . --csvf app.csv
Import-Csv app.csv | Where-Object { $_.Provider -like '*MsiInstaller*' }
```

| 조합 | 결론 |
| --- | --- |
| `Uninstall`에 있고 `$MFT`에 폴더도 있다 | 정상 설치, 현재도 존재 |
| `Uninstall`에 있는데 폴더가 없다 | 제거됨. `$UsnJrnl`로 삭제 시각 |
| `Uninstall`에 없는데 Prefetch/UserAssist에 있다 | portable 실행 또는 드롭 |
| `Uninstall`에 없고 실행 이력도 없는데 파일만 있다 | 실행되지 않은 채 남은 파일 |

## mini walkthrough

```text
문제:
"이 PC에서 증거 인멸에 사용된 것으로 보이는 도구의 이름과 버전,
 그리고 그 도구를 설치한 사용자의 프로필 폴더를 구하세요.
 첨부: SOFTWARE, SAM, SYSTEM, NTUSER.DAT (jhkim)"

1. 첫 시도 (실패):
   rip.exe -r SOFTWARE -p uninstall | Select-String 'Eraser|CCleaner|Wipe|Shred'
   -> 아무것도 안 나온다.
      "삭제 도구는 설치되지 않았다"고 결론 내리고 다른 방향을 파기 시작했다.

   왜 틀렸나 (두 가지):
   (a) uninstall 플러그인이 본 것은 64비트 경로 하나뿐이었다.
       32비트 프로그램은 SOFTWARE\WOW6432Node\...\Uninstall 에 있다.
   (b) 검색어를 제품명으로만 좁혔다. Publisher / UninstallString 쪽에
       단서가 남는 경우를 놓쳤다.

2. 피벗: 세 위치를 모두 덤프하고 전체 텍스트에서 찾는다
   RegistryExplorer 로 SOFTWARE 를 열고
   SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
   -> 항목 하나가 걸린다

     키 이름         : Eraser
     DisplayName     : Eraser 6.2.0.2993
     DisplayVersion  : 6.2.0.2993
     Publisher       : The Eraser Project
     InstallDate     : 20260312            <- REG_SZ, 날짜만
     InstallLocation : C:\Program Files (x86)\Eraser\
     InstallSource   : C:\Users\jhkim\Downloads\
     키 LastWrite    : 2026-03-12 22:07:55Z

3. 설치 시각 정밀화
   InstallDate 는 20260312 (시각 없음).
   키 LastWrite = 2026-03-12 22:07:55Z (UTC).
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time, Bias = -540
   -> 2026-03-13 07:07:55 KST

4. 두 번째로 틀린 판단:
   InstallSource 가 C:\Users\jhkim\Downloads\ 이므로
   "설치자는 jhkim" 이라고 바로 답하려 했다.
   -> InstallSource 는 설치 파일이 있던 경로일 뿐이다.
      전역 설치는 관리자 권한으로 다른 계정이 수행할 수도 있다.
      사용자 귀속은 UserAssist(사용자별 hive)로 확정해야 한다.

5. 사용자 귀속 확정
   rip.exe -r NTUSER.DAT -p userassist | Select-String -i 'eraser'
   -> 2026-03-12 22:06:41Z  C:\Users\jhkim\Downloads\Eraser 6.2.0.2993.exe (1)
      설치 프로그램을 실행한 것이 jhkim 본인.

   SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
     S-1-5-21-3419281148-2201972856-1043271217-1001
       ProfileImagePath = C:\Users\jhkim
   SAM RID 1001 = jhkim  -> 매핑 일치

6. 교차검증
   - $MFT: C:\Program Files (x86)\Eraser\Eraser.exe 생성 2026-03-12 22:07:5x
   - Prefetch: ERASER.EXE-xxxxxxxx.pf 존재 = 설치 후 실제 실행됨
   - $UsnJrnl: 같은 날 다수 파일 삭제 레코드

정답: Eraser 6.2.0.2993 / C:\Users\jhkim
      (설치 2026-03-13 07:07:55 KST)
```

## 막혔을 때 다음 체크

1. **`WOW6432Node` 아래를 봤는가** — 32비트 프로그램
2. **`NTUSER.DAT`의 `Uninstall`도 봤는가** — 사용자 단독 설치
3. 키 이름이 아니라 `DisplayName` 값을 읽었는가
4. `InstallDate`가 어느 위치의 것인지 확인했는가 (`REG_SZ` 날짜 vs `REG_DWORD` Unix 초)
5. 시각이 필요하면 키 LastWrite / `$MFT` / MsiInstaller 이벤트로 보강했는가
6. `SystemComponent = 1`로 숨겨진 항목이 있는가
7. `ProfileList`에는 있는데 `SAM`에는 없는 SID가 있는가 (삭제 계정)
8. 설치 목록에 없는데 실행 이력이 있는가 → portable/드롭된 파일. Amcache로 이동
9. `Run`/`RunOnce`와 `Winlogon`의 `Shell`/`Userinit`을 확인했는가
10. `SOFTWARE`가 dirty인가 → `rla`로 `.LOG1`/`.LOG2` 반영

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SOFTWARE` hive가 `HKLM\SOFTWARE`로 마운트되고 `SOFTWARE\Classes`가 `HKCR`의 머신 부분이라는 점, 64비트 OS에서 32비트 뷰가 `WOW6432Node`로 분리된다는 점
- SRC-014 — Microsoft Learn, File Times: 키 LastWrite와 `InstallTime`이 FILETIME(UTC, 1601 기준 100ns)이라는 점, Unix epoch 차이 `11644473600`초
- SRC-004 — Eric Zimmerman 문서: RegistryExplorer로 `SOFTWARE` 탐색, `rla` 로그 반영, Timeline Explorer로 CSV 정렬
- `Uninstall` 아래 값 구성은 설치 프로그램이 채우는 것이므로 프로그램마다 존재하는 값이 다르다. 실제 hive에서 확인할 것
- `ProfileList`의 `LocalProfileLoadTime*` / `LocalProfileUnloadTime*` 값은 Windows 빌드에 따라 존재 여부와 이름이 다르므로 파서 출력으로 확인할 것
- `NetworkList\Profiles`의 시각 필드가 로컬 시각으로 기록된다는 점은 파서 출력과 다른 artifact의 시각으로 교차확인할 것
- RegRipper 플러그인 이름(`uninstall`, `winver`, `profilelist`)과 `-a` 옵션 동작은 버전에 따라 다를 수 있으므로 `rip.exe -l`로 확인할 것
