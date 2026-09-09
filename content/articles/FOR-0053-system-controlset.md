---
id: FOR-0053
title: "SYSTEM hive ControlSet 구조와 Select 키로 활성 세트 판정"
slug: "system-controlset"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["SYSTEM hive", "Select", "ControlSet001", "ControlSet002", "MountedDevices", "Services", "USBSTOR"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\Prefetch"]
registry_paths: ["SYSTEM\\Select", "SYSTEM\\MountedDevices", "SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName", "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation", "SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\\PrefetchParameters", "SYSTEM\\ControlSet001\\Control\\FileSystem", "SYSTEM\\ControlSet001\\Control\\Windows", "SYSTEM\\ControlSet001\\Services", "SYSTEM\\ControlSet001\\Enum\\USBSTOR"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "AppCompatCacheParser", "FTK Imager"]
commands: ["rip.exe -r SYSTEM -p compname", "rip.exe -r SYSTEM -p services", "AppCompatCacheParser.exe -f SYSTEM --csv ."]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Current", "LastKnownGood", "Failed", "EnablePrefetcher", "NtfsDisableLastAccessUpdate", "ImagePath", "Start", "ShutdownTime"]
file_formats: ["regf"]
primary_terms: ["ControlSet", "CurrentControlSet", "Select 키", "ControlSet001"]
keywords: ["SYSTEM hive", "ControlSet", "ControlSet001", "CurrentControlSet", "Select", "Services", "ImagePath", "MountedDevices", "USBSTOR", "EnablePrefetcher", "NtfsDisableLastAccessUpdate", "ComputerName"]
aliases: ["controlset", "CurrentControlSet 없음", "system hive 구조", "select 키", "컴퓨터 이름 찾기", "서비스 목록 레지스트리", "controlset001 002 차이"]
symptom_keywords: ["CurrentControlSet 키가 없다", "어느 ControlSet을 봐야 하나", "컴퓨터 이름을 알고 싶다", "악성 서비스를 찾고 싶다", "레지스트리 경로가 트리에 안 보인다", "prefetch가 비어 있다"]
related: ["FOR-0051", "FOR-0054", "FOR-0066", "FOR-0067"]
source_ids: ["SRC-017", "SRC-004", "SRC-027"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

오프라인 `SYSTEM` hive에는 `CurrentControlSet` 심볼릭 링크가 존재하지 않으므로, **`SYSTEM\Select`의 `Current` 값을 읽어 `ControlSet001`/`ControlSet002` 중 활성 세트를 먼저 확정**한 다음 그 아래 `Control`·`Services`·`Enum`을 파고들어야 한다.

## 어떤 문제에서 필요한가

`SYSTEM` hive는 "이 컴퓨터가 무엇이었는가"를 답한다. 다음 질문은 모두 여기서 시작한다.

- "컴퓨터 이름이 무엇인가"
- "시간대가 무엇인가" (모든 타임스탬프 보정의 전제)
- "어떤 서비스가 등록되어 있었나, 악성 서비스가 있나"
- "USB를 꽂았나, 어떤 장치였나, 어느 드라이브 문자였나"
- "Prefetch가 비어 있는데 원래 꺼져 있었나"
- "파일 접근 시각을 근거로 쓸 수 있나" (Last Access 갱신 여부)
- "언제 마지막으로 종료됐나"

## 문제에서 처음 볼 단서

1. 첨부에 `SYSTEM`(확장자 없음)이 있다
2. 문제가 컴퓨터 이름·시간대·서비스·USB·네트워크 설정을 묻는다
3. 다른 글이나 블로그의 경로가 `HKLM\SYSTEM\CurrentControlSet\...`로 적혀 있는데, 내가 연 hive 트리에는 `CurrentControlSet`이 안 보인다
4. 트리에 `ControlSet001`과 `ControlSet002`가 **둘 다** 있어서 어느 쪽을 볼지 모르겠다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -p compname
```

```text
ComputerName    = DESKTOP-K7P2N9
TCP/IP Hostname = DESKTOP-K7P2N9
```

RegRipper 플러그인은 `Select\Current`를 스스로 읽어 활성 ControlSet으로 알아서 들어간다. **GUI(RegistryExplorer)로 직접 트리를 탐색할 때만 활성 세트를 손으로 판정해야 한다.**

```text
1) SYSTEM\Select 를 열어 Current 값을 읽는다      -> 예: 1
2) 그 번호로 경로를 만든다                        -> SYSTEM\ControlSet001\...
3) 참고 문서의 CurrentControlSet 을 ControlSet001 로 치환해서 이동한다
```

## 상세 절차

### 1단계 — `SYSTEM\Select` (hive 루트 바로 아래)

`Select`는 `ControlSet` **밖**, hive 루트에 있다. 값은 모두 `REG_DWORD`이고 데이터가 세트 번호다.

| 값 이름 | 의미 | 읽는 법 |
| --- | --- | --- |
| `Current` | **마지막 부팅에서 실제로 사용된 세트** | `1` → `ControlSet001`. 오프라인 분석은 항상 이 값을 쓴다 |
| `Default` | 다음 부팅에서 쓸 세트 | 보통 `Current`와 같다 |
| `Failed` | 부팅에 실패한 것으로 표시된 세트 | `0`이면 실패 이력 없음 |
| `LastKnownGood` | 마지막으로 정상 부팅한 세트 | 복구 부팅 시 사용 |

```text
SYSTEM\Select
  Current       REG_DWORD  0x00000001
  Default       REG_DWORD  0x00000001
  Failed        REG_DWORD  0x00000000
  LastKnownGood REG_DWORD  0x00000001
```

이 경우 활성 세트는 `ControlSet001`이다. `Current = 2`면 `ControlSet002`를 봐야 하고, `ControlSet001`을 보고 답을 내면 **과거 설정으로 답한 셈이 된다.**

### 2단계 — `ControlSet001` vs `ControlSet002`

| 상황 | 해석 |
| --- | --- |
| `ControlSet001`만 있다 | 최신 Windows에서 흔하다. 판정 불필요하지만 그래도 `Select`를 확인한다 |
| 두 개 있고 `Current = 1` | `002`는 이전 부팅/LastKnownGood 사본. **비교하면 설정 변경 이력을 볼 수 있다** |
| 두 개 있고 `Current = 2` | `001`이 과거 사본이다 |
| `ControlSet003` 이상이 있다 | 부팅 실패·복구가 반복된 시스템 |

두 세트의 같은 키를 비교하면 "언제 어떤 서비스가 추가/변경됐는지"의 단서가 나온다. 비활성 세트에만 있는 서비스는 제거된 서비스이고, 활성 세트에만 있으면 최근에 추가된 서비스다.

### 3단계 — 오프라인 경로 표기법

문서와 도구의 표기가 서로 다르다. 셋을 서로 번역할 수 있어야 한다.

| 문맥 | 표기 예 |
| --- | --- |
| 라이브 시스템 / 일반 문서 | `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` |
| RegistryExplorer로 `SYSTEM` 파일을 열었을 때 | `SYSTEM\ControlSet001\Control\TimeZoneInformation` |
| RegRipper 출력 / 플러그인 내부 경로 | `ControlSet001\Control\TimeZoneInformation` (hive 이름 생략) |

이 사전의 `registry_paths` 메타데이터는 **hive 파일 이름을 앞에 붙인 오프라인 표기**를 쓴다. 검색할 때 `CurrentControlSet`으로 찾아도 되도록 두 표기를 모두 기억한다.

### 4단계 — `Control` 아래에서 볼 것

경로는 모두 `SYSTEM\ControlSet001\` 다음에 이어진다.

| 키 | 값 | 무엇을 알 수 있나 |
| --- | --- | --- |
| `Control\ComputerName\ComputerName` | `ComputerName` | 호스트 이름. 형제 키 `ActiveComputerName`은 휘발성이라 오프라인 hive에 없을 수 있다 |
| `Control\TimeZoneInformation` | `TimeZoneKeyName`, `Bias`, `ActiveTimeBias` | 시간대. 모든 시각 보정의 기준 ([FOR-0054](./system-timezone.html)) |
| `Control\Session Manager\Memory Management\PrefetchParameters` | `EnablePrefetcher` | Prefetch가 켜져 있었나 |
| `Control\FileSystem` | `NtfsDisableLastAccessUpdate` | Last Access 시각을 근거로 쓸 수 있나 |
| `Control\Windows` | `ShutdownTime` | 마지막 정상 종료 시각 (8바이트 FILETIME, UTC) |
| `Control\Session Manager\AppCompatCache` | `AppCompatCache` | Shimcache — 실행/존재 이력. 키와 값 이름이 같다. 전용 파서 필요 |
| `Control\Terminal Server` | `fDenyTSConnections` | `0`이면 RDP 허용 상태 |
| `Control\CrashControl` | `CrashDumpEnabled`, `DumpFile` | 덤프 파일 위치 |
| `Control\Session Manager\Environment` | `TEMP`, `Path` 등 | 시스템 환경 변수 |
| `Control\Lsa` | `LimitBlankPasswordUse` 등 | 인증 정책 |

#### `EnablePrefetcher` 값

| 값 | 의미 |
| --- | --- |
| `0` | Prefetch 비활성 — **`C:\Windows\Prefetch`가 비어 있는 이유** |
| `1` | 애플리케이션 실행 prefetch만 |
| `2` | 부팅 prefetch만 |
| `3` | 둘 다 (일반적인 기본값) |

Prefetch 문제에서 `.pf` 파일이 없을 때, 이 값이 `0`이면 "반포렌식으로 삭제됐다"가 아니라 "원래 꺼져 있었다"가 정답이다. 서버 에디션과 일부 SSD 환경에서 기본으로 꺼진다.

#### `NtfsDisableLastAccessUpdate` 값

| 값 | 의미 |
| --- | --- |
| `0` | 사용자 관리, Last Access 갱신 **켜짐** |
| `1` | 사용자 관리, 갱신 **꺼짐** |
| `2` | 시스템 관리, 갱신 켜짐 |
| `3` | 시스템 관리, 갱신 꺼짐 |

Windows 10 1803 이후의 기본값은 시스템 관리 모드이며, 값이 `0x80000003` 같은 형태로 보이는 환경이 있다. **이 값이 갱신 꺼짐이면 `$MFT`의 Last Access 시각으로 "파일을 열어 봤다"를 주장할 수 없다** ([FOR-0021](./mft-basics.html)). Last Access를 근거로 쓰기 전에 반드시 확인한다. 현재 상태는 라이브에서 `fsutil behavior query disablelastaccess`로도 확인된다.

### 5단계 — `Services` (악성 서비스 탐지)

`SYSTEM\ControlSet001\Services\<서비스명>`에 서비스와 드라이버가 모두 들어 있다.

| 값 | 의미 |
| --- | --- |
| `ImagePath` | 실행 파일 경로. 서비스는 `.exe`, 드라이버는 `\??\C:\...\.sys` 또는 `system32\drivers\...` |
| `Start` | 시작 방식 (아래 표) |
| `Type` | 서비스 종류 (아래 표) |
| `DisplayName` | 서비스 관리자에 표시되는 이름 |
| `ObjectName` | 실행 계정 (`LocalSystem`, `NT AUTHORITY\NetworkService` 등) |
| `Description` | 설명. 비어 있으면 의심 신호 |
| `Parameters\ServiceDll` | `svchost.exe`로 호스팅되는 서비스의 실제 DLL — **여기가 악성 DLL 등록 지점이다** |

`Start` 값:

| 값 | 의미 |
| --- | --- |
| `0` | Boot — 부트 로더가 로드 (핵심 드라이버) |
| `1` | System — 커널 초기화 중 로드 |
| `2` | Automatic — 부팅 시 자동 시작 |
| `3` | Manual (Demand) — 요청 시 시작 |
| `4` | Disabled — 비활성 |

`Type` 값:

| 값 | 의미 |
| --- | --- |
| `1` | 커널 드라이버 |
| `2` | 파일 시스템 드라이버 |
| `0x10` (16) | 자체 프로세스로 실행되는 Win32 서비스 |
| `0x20` (32) | 프로세스를 공유하는 Win32 서비스 (`svchost.exe`) |

의심 판단 기준:

```text
- ImagePath 가 C:\Users\..., \Temp\, \AppData\, \ProgramData\ 를 가리킨다
- ImagePath 에 확장자가 없거나 인자로 powershell/cmd 가 붙어 있다
- Start = 2 (자동) 인데 Description 이 비어 있다
- ServiceDll 이 정상 시스템 DLL 경로가 아니다
- 서비스명이 정상 서비스와 한두 글자 차이다 (예: 정상 svchost 계열 이름 흉내)
- 그 서비스 키의 LastWrite 가 사고 시각대에 몰려 있다
```

```powershell
rip.exe -r "C:\case\SYSTEM" -p services > services.txt
Select-String -Path services.txt -Pattern 'Users\\|\\Temp\\|AppData|ProgramData'
```

서비스 설치는 Security EVTX 4697, System EVTX 7045와 대조한다.

### 6단계 — `Enum\USBSTOR`

`SYSTEM\ControlSet001\Enum\USBSTOR` 아래에 USB 대용량 저장장치의 열거 정보가 남는다. 키 이름은 다음 형태다.

```text
Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001120521105424&0
                                             ^^^^^^^^^^^^^^^^^^^^^
                                             장치 인스턴스 ID (대개 시리얼)
```

| 얻는 것 | 설명 |
| --- | --- |
| 제조사 / 모델 / 리비전 | `Ven_`, `Prod_`, `Rev_` 토큰 |
| 시리얼 번호 | 인스턴스 ID. 두 번째 문자가 `&`이면 시리얼이 없는 장치라 OS가 생성한 값 |
| 연결 시각 | 인스턴스 키의 LastWrite (키에 값이 적으므로 신뢰도가 비교적 높다) |
| `FriendlyName` | 표시 이름 |

USB는 이 키 하나로 끝나지 않는다. `Services\USBSTOR`, `Control\DeviceClasses\{GUID}`, `Enum\USB`, 사용자 hive의 `MountPoints2`, `setupapi.dev.log`를 함께 봐야 "언제 처음/마지막 꽂았고 어느 드라이브 문자였나"가 완성된다. **구체적인 키와 값은 도구 출력으로 확인하고, 이 글에서는 `Enum\USBSTOR`가 출발점이라는 것만 확정한다.**

### 7단계 — `MountedDevices` (ControlSet 밖에 있다)

```text
SYSTEM\MountedDevices        <- Select 와 마찬가지로 hive 루트 바로 아래
```

`ControlSet001\...` 아래를 아무리 찾아도 없다. 이 키를 놓치는 것이 가장 흔한 실수다.

| 값 이름 | 데이터 |
| --- | --- |
| `\DosDevices\C:` | 그 드라이브 문자에 매핑된 볼륨 식별 정보 (이진) |
| `\DosDevices\E:` | USB를 꽂았을 때 붙은 드라이브 문자 |
| `\??\Volume{GUID}` | 볼륨 GUID ↔ 같은 이진 식별 정보 |

데이터 형태로 종류를 가른다.

| 데이터 모양 | 의미 |
| --- | --- |
| 12바이트 정도의 짧은 이진 | MBR 디스크 서명 4바이트 + 파티션 시작 오프셋 8바이트 ([FOR-0019](./mbr-gpt.html)) |
| UTF-16LE로 `\??\STORAGE#Volume#...` 같은 문자열이 보이는 긴 이진 | USB 등 착탈식 장치. **문자열 안에 장치 시리얼이 들어 있다** |

```powershell
rip.exe -r "C:\case\SYSTEM" -p mountdev
```

`USBSTOR`에서 얻은 시리얼을 `MountedDevices` 값 데이터에서 문자열로 검색하면 **그 USB가 어느 드라이브 문자였는지**가 확정된다. 이 문자로 LNK·Prefetch·ShellBags의 `E:\...` 경로가 설명된다.

## 출력 필드 해석

| 필드 | 어디서 | 결론에 어떻게 쓰나 |
| --- | --- | --- |
| `Select\Current` | hive 루트 | 이후 모든 경로의 세트 번호를 결정 |
| `ComputerName` | `Control\ComputerName\ComputerName` | EVTX의 `Computer` 필드와 일치해야 한다. 다르면 다른 PC의 로그다 |
| `TimeZoneKeyName` / `Bias` | `Control\TimeZoneInformation` | UTC ↔ 로컬 변환 |
| `ShutdownTime` | `Control\Windows` | 8바이트 FILETIME(UTC). 이 시각 이후의 활동은 다른 부팅 세션이다 |
| `EnablePrefetcher` | `PrefetchParameters` | `0`이면 Prefetch 부재가 정상 |
| `NtfsDisableLastAccessUpdate` | `Control\FileSystem` | 갱신 꺼짐이면 Last Access를 증거로 못 쓴다 |
| `ImagePath` + `Start` | `Services\<name>` | 자동 시작 + 사용자 폴더 경로 = 지속성 흔적 |
| 서비스 키 LastWrite | `Services\<name>` | 서비스가 등록/변경된 시각 |
| `Enum\USBSTOR` 키 이름 | `Enum\USBSTOR` | 장치 모델과 시리얼 |
| `\DosDevices\E:` | `MountedDevices` | 착탈식 장치의 드라이브 문자 |

`ShutdownTime`을 손으로 변환할 때는 8바이트를 리틀엔디언으로 읽어 FILETIME으로 해석한다. Unix epoch와의 차이는 `11644473600`초, 단위는 100ns다. 결과는 UTC이므로 KST는 +9시간이다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| `Select\Current` = N | `ControlSet00N\...` 전체 | 나머지 모든 SYSTEM 분석 |
| `TimeZoneKeyName` | 모든 타임스탬프 | 로컬 시각 변환 ([FOR-0054](./system-timezone.html)) |
| `ComputerName` | EVTX의 `Computer` 필드 | 로그가 이 PC 것인지 |
| 의심 `ImagePath` | 그 파일의 Prefetch, Amcache, `$MFT` | 실제 실행 여부와 파일 생성 시각 |
| 의심 서비스명 | System EVTX 7045, Security 4697 | 서비스 설치 시각과 계정 |
| `AppCompatCache` | `AppCompatCacheParser.exe -f SYSTEM --csv .` | 실행/존재 이력 목록 |
| USB 시리얼 | `MountedDevices`, 사용자 hive `MountPoints2` | 드라이브 문자, 사용자별 마운트 |
| USB 드라이브 문자 | LNK, Jump List, ShellBags, `RecentDocs` | 그 드라이브에서 무엇을 열었나 |
| `ShutdownTime` | System EVTX 6006/6008, 1074 | 종료 방식(정상/비정상) |
| SID가 필요한 시점 | `SOFTWARE\...\ProfileList` | 사용자 매핑 ([FOR-0052](./sam-user-accounts.html)) |

## 흔한 함정

- **`CurrentControlSet` 경로를 오프라인 hive에 그대로 입력하는 것.** 커널이 부팅 때 만드는 휘발성 심볼릭 링크라 파일에 없다. "키가 없다 = hive가 손상됐다"로 오판해 시간을 버린다. `Select\Current`로 실제 이름을 만든다.
- **`Select`를 확인하지 않고 `ControlSet001`을 기본값으로 가정하는 것.** `Current = 2`인 시스템에서 `001`을 읽으면 **이전 부팅의 설정**으로 답하게 된다. 시간대나 서비스 목록이 통째로 틀린다.
- **`MountedDevices`를 `ControlSet001` 아래에서 찾는 것.** hive 루트에 있다. `Select`도 같다. "루트에 있는 키"를 따로 기억한다.
- **Prefetch가 비어 있다고 반포렌식으로 단정하는 것.** `EnablePrefetcher = 0`이면 원래 기록되지 않는 환경이다. 삭제 주장을 하기 전에 이 값을 본다.
- **Last Access 시각으로 "파일을 열어 봤다"고 주장하는 것.** `NtfsDisableLastAccessUpdate`가 갱신 꺼짐이면 그 시각은 갱신되지 않은 과거 값이다. Windows 7 이후 기본이 꺼짐 쪽이라 이 실수가 특히 흔하다.
- **서비스 키 LastWrite를 서비스 설치 시각으로 단정하는 것.** 서비스 키에는 값이 여러 개라 어느 값 변경 때문인지 알 수 없다. 설치 시각은 System EVTX 7045로 확정한다.
- **`ImagePath`가 `system32`를 가리키니 정상이라고 넘어가는 것.** `svchost.exe -k <그룹>` 형태면 실제 코드는 `Parameters\ServiceDll`에 있다. 그쪽을 확인해야 한다.
- **비활성 ControlSet을 무시하는 것.** 두 세트의 차이가 "무엇이 언제 바뀌었는지"의 유일한 단서일 수 있다.
- **`ShutdownTime`을 로컬 시각으로 읽는 것.** FILETIME이므로 UTC다.
- **`Enum\USBSTOR`만 보고 USB 분석을 끝내는 것.** 드라이브 문자·최초 연결·사용자 귀속은 `MountedDevices`, 사용자 hive, `setupapi.dev.log`를 합쳐야 나온다.

## 교차검증

```powershell
# 1) 활성 세트 확정 (GUI로 직접 확인)
#    RegistryExplorer: SYSTEM\Select -> Current

# 2) 컴퓨터 이름 — 레지스트리 vs EVTX
rip.exe -r SYSTEM -p compname
EvtxECmd.exe -f System.evtx --csv . --csvf sys.csv
Import-Csv sys.csv | Select-Object -First 1 Computer

# 3) 서비스 — 레지스트리 vs 이벤트 로그
rip.exe -r SYSTEM -p services > svc.txt
Import-Csv sys.csv | Where-Object { $_.EventId -eq 7045 }

# 4) Shimcache — 실행/존재 이력
AppCompatCacheParser.exe -f "C:\case\SYSTEM" --csv "C:\case\out"

# 5) 종료 시각 — 레지스트리 vs 이벤트
#    Control\Windows\ShutdownTime  vs  System EVTX 1074 / 6006 / 6008
```

레지스트리에는 있는데 EVTX에는 없다면 로그가 잘렸거나 감사가 꺼져 있었다 — `SECURITY\Policy\PolAdtEv`를 확인한다 ([FOR-0056](./security-hive-overview.html)).

## mini walkthrough

```text
문제:
"이미지에서 추출한 SYSTEM hive가 첨부됩니다. 이 PC에 마지막으로 연결된
 USB 저장장치의 모델명과 그때 할당된 드라이브 문자를 구하세요."

1. 첫 시도 (실패):
   RegistryExplorer 로 SYSTEM 을 열고
   SYSTEM\CurrentControlSet\Enum\USBSTOR 로 이동하려 했다.
   -> CurrentControlSet 이 트리에 없다.
      다음으로 ControlSet001\Enum\USBSTOR 을 열어 장치 3개를 찾고
      LastWrite 가 가장 최근인 것을 답으로 골랐다.

   왜 틀렸나 (두 겹의 실수):
   (a) CurrentControlSet 은 휘발성 링크라 오프라인 hive에 없다.
   (b) 그래서 대충 ControlSet001 을 골랐는데, 이 hive 는 Current = 2 였다.
       ControlSet001 은 이전 부팅의 사본이라 마지막 USB가 반영되어 있지 않았다.

2. 피벗: Select 를 먼저 읽는다
   SYSTEM\Select
     Current       = 2
     Default       = 2
     Failed        = 0
     LastKnownGood = 2
   -> 활성 세트는 ControlSet002

3. SYSTEM\ControlSet002\Enum\USBSTOR
     Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001120521105424&0
       LastWrite 2026-03-14 07:04:19Z          <- 가장 최근
     Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_\0018F30D9B21...&0
       LastWrite 2026-03-02 23:51:07Z

   모델: SanDisk Cruzer Blade, 시리얼 4C530001120521105424

4. 드라이브 문자 — ControlSet 아래를 찾다가 또 막힌다
   ControlSet002\...\MountedDevices 는 존재하지 않는다.
   MountedDevices 는 hive 루트에 있다.

   SYSTEM\MountedDevices
     \DosDevices\C:  -> 짧은 이진 (MBR 서명 + 오프셋) = 내장 디스크
     \DosDevices\E:  -> 이진 데이터 안에 UTF-16LE 문자열
                        \??\STORAGE#Volume#...4C530001120521105424...
   -> 시리얼이 일치. 이 USB 는 E: 였다

5. 교차검증
   - ShellBags / RecentDocs 에 E:\ 경로 항목이 있는가 -> 있다
   - 시간대: SYSTEM\ControlSet002\Control\TimeZoneInformation
       TimeZoneKeyName = Korea Standard Time
     2026-03-14 07:04:19 UTC + 9h = 2026-03-14 16:04:19 KST

정답: SanDisk Cruzer Blade (시리얼 4C530001120521105424), 드라이브 E:
```

## 막혔을 때 다음 체크

1. **`SYSTEM\Select`의 `Current`를 읽었는가** — 모든 경로의 전제다
2. 참고 문서의 `CurrentControlSet`을 `ControlSet00N`으로 치환했는가
3. 찾는 키가 `Select`/`MountedDevices`처럼 **hive 루트**에 있는 것은 아닌가
4. `ControlSet002`(비활성)와 비교해 봤는가 — 제거/추가된 항목이 보인다
5. Prefetch·Last Access를 근거로 쓰려는데 `EnablePrefetcher`/`NtfsDisableLastAccessUpdate`를 확인했는가
6. 서비스가 의심스러운데 `Parameters\ServiceDll`을 봤는가
7. `SYSTEM`이 dirty인가 → `rla`로 `.LOG1`/`.LOG2` 반영 ([FOR-0051](./registry-hive-map.html))
8. RegRipper 플러그인 이름을 모르겠으면 `rip.exe -l` 로 목록 확인
9. 시각을 UTC로 두고 KST 문제를 풀고 있지 않은가

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM` hive가 `HKLM\SYSTEM`으로 마운트되는 구조, `CurrentControlSet`이 부팅 시 만들어지는 링크라는 점
- SRC-027 — Libyal libregf, REGF 포맷 문서: hive 루트 바로 아래 키 배치와 `nk` 키 LastWrite의 의미
- SRC-004 — Eric Zimmerman 문서: RegistryExplorer의 오프라인 hive 트리 표기, `AppCompatCacheParser`로 `SYSTEM`에서 Shimcache 추출, `rla` 로그 반영
- `Enum\USBSTOR` 이외의 USB 관련 키(`DeviceClasses`, `MountPoints2`)의 정확한 하위 구조는 Windows 버전에 따라 다르므로 실제 hive에서 도구 출력으로 확인할 것
- `NtfsDisableLastAccessUpdate`의 기본값과 `0x8000000x` 표기는 Windows 빌드에 따라 다르므로 대상 시스템에서 확인할 것
- RegRipper 플러그인 이름(`compname`, `services`, `mountdev`)은 버전에 따라 다를 수 있으므로 `rip.exe -l`로 확인할 것
