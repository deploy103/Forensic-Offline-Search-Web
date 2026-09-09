---
id: FOR-0066
title: "USBSTOR 키로 연결된 USB 저장장치와 시리얼 번호 찾기"
slug: "usbstor"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["USBSTOR", "Enum\\USBSTOR", "DeviceClasses", "ContainerID", "setupapi.dev.log", "device instance ID"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\INF\\setupapi.dev.log"]
registry_paths: ["SYSTEM\\ControlSet001\\Enum\\USBSTOR", "SYSTEM\\ControlSet001\\Enum\\USB", "SYSTEM\\ControlSet001\\Control\\DeviceClasses", "SYSTEM\\ControlSet001\\Services\\USBSTOR", "SYSTEM\\ControlSet001\\Enum\\USBSTOR\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r SYSTEM -p usbstor", "rip.exe -r SYSTEM -p usbdevices", "rip.exe -r SYSTEM -p devclass"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["FriendlyName", "DeviceDesc", "Mfg", "Service", "ContainerID", "HardwareID", "ClassGUID", "ConfigFlags"]
file_formats: ["regf"]
primary_terms: ["USBSTOR", "USB 흔적", "usb 꽂은 기록", "USB 장치 연결"]
keywords: ["USBSTOR", "USB", "USB 장치 연결", "device instance ID", "시리얼 번호", "serial number", "SYSTEM hive", "FriendlyName", "DeviceDesc", "ContainerID", "VID", "PID", "setupapi.dev.log", "DeviceClasses"]
aliases: ["usbstor", "usb 꽂은 기록", "USB 흔적", "usb 연결 흔적", "usb 시리얼 번호", "어떤 usb를 썼나", "usb 모델명 찾기", "이동식 디스크 흔적"]
symptom_keywords: ["USB를 꽂았는지 알고 싶다", "어떤 USB 장치였는지 모르겠다", "USB 시리얼 번호가 필요하다", "USB를 언제 연결했는지 알고 싶다", "시리얼이 이상한 값으로 보인다", "USBSTOR에 장치가 여러 개다"]
related: ["FOR-0053", "FOR-0067", "FOR-0075", "FOR-0071"]
source_ids: ["SRC-098", "SRC-017", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SYSTEM\ControlSet001\Enum\USBSTOR` 아래의 `Disk&Ven_<제조사>&Prod_<모델>&Rev_<리비전>` 키와 그 하위 **장치 인스턴스 ID 키 이름이 곧 USB 저장장치의 시리얼 번호**이며, 인스턴스 ID의 **두 번째 문자가 `&`이면 시리얼이 없는 장치라서 OS가 만들어 준 임시 ID**이므로 그 값을 시리얼로 답하면 틀린다.

## 어떤 문제에서 필요한가

"USB를 꽂았나"로 시작하는 모든 문제의 출발점이다. `SYSTEM` hive의 ControlSet 판정 자체는 [FOR-0053](./system-controlset.html)에서 끝내고, 이 글은 그 아래 `Enum\USBSTOR`만 파고든다.

- "이 PC에 연결된 USB 저장장치의 제조사·모델명은 무엇인가"
- "그 장치의 시리얼 번호는 무엇인가" (문제 정답으로 가장 많이 요구되는 값)
- "장치가 몇 개 연결되었나, 마지막으로 연결된 것은 어느 것인가"
- "언제 처음 꽂았나 / 마지막으로 꽂았나 / 언제 뺐나"
- "USB에서 파일을 복사해 갔는가" — 그 시작점이 여기서 얻는 시리얼이다

시리얼을 확보하면 드라이브 문자([FOR-0067](./mounteddevices.html))와 사용자 귀속([FOR-0075](./usb-serial-drive-letter.html))으로 이어진다.

## 문제에서 처음 볼 단서

1. 첨부에 `SYSTEM`(확장자 없음)이 있고 지문에 "USB", "이동식", "외장", "유출"이 있다
2. 지문이 **시리얼 번호**나 **모델명**을 요구한다 → `Enum\USBSTOR` 키 이름이 곧 답이다
3. LNK·ShellBags·Prefetch에 `E:\`, `F:\` 같은 낯선 드라이브 문자가 보인다 → 그 문자의 주인을 여기서 찾는다
4. `C:\Windows\INF\setupapi.dev.log`가 첨부에 함께 있다 → **최초 설치 시각**을 물어보려는 문제다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -p usbstor
```

```text
USBStor
ControlSet001\Enum\USBSTOR

Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00 [2026-03-14 07:04:19Z]
  S/N: 4C530001120521105424&0 [2026-03-14 07:04:19Z]
    FriendlyName  : SanDisk Cruzer Blade USB Device
    DeviceDesc    : @disk.inf,%disk_devdesc%;Disk drive
    Mfg           : @disk.inf,%genmanufacturer%;(Standard disk drives)
    Service       : disk
    ContainerID   : {b9a4c1e2-8f31-5c47-9c02-1d7a3e5f6b88}
```

GUI로 갈 때는 RegistryExplorer에서 다음 경로를 그대로 따라간다.

```text
SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001120521105424&0
```

## 상세 절차

### 1단계 — 키 이름 자체가 정보다

`Enum\USBSTOR` 아래는 두 계층이다. **1계층은 장치 모델, 2계층은 그 모델의 개별 물리 장치**다.

```text
SYSTEM\ControlSet001\Enum\USBSTOR
  Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00      <- 1계층: 모델
    4C530001120521105424&0                          <- 2계층: 장치 인스턴스 ID
    4C530001071022114235&0                          <- 같은 모델의 다른 개체
  Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP
    0018F30D9B21EFB0A9331B27&0
```

| 토큰 | 의미 | 주의 |
| --- | --- | --- |
| `Disk` | 장치 종류. 대용량 저장장치는 `Disk`, CD/DVD는 `CdRom`, 일부 장치는 `Other` | `Disk`만 보고 넘기면 광학 매체를 놓친다 |
| `Ven_` | 제조사 문자열 | 장치가 보고한 값. 실제 브랜드와 다를 수 있다 |
| `Prod_` | 모델 문자열 | 공백은 `_`로 치환되어 있다 |
| `Rev_` | 펌웨어 리비전 | 비어 있는 장치도 있다 (`Rev_` 로 끝난다) |
| 2계층 키 이름 | **장치 인스턴스 ID = 대개 시리얼 번호** | 아래 2단계의 판정을 거쳐야 한다 |

`Prod_Cruzer_Blade`의 `_`는 원래 공백이다. 답을 적을 때 `Cruzer Blade`로 되돌리는지, 키 이름 그대로 쓰는지는 문제 지문의 표기를 따른다.

### 2단계 — 인스턴스 ID가 진짜 시리얼인지 판정한다

USB 대용량 저장장치는 시리얼 번호를 보고할 의무가 없다. 보고하지 않는 장치에는 **OS가 인스턴스 ID를 만들어 붙인다.** 판정 규칙은 단순하다.

```text
4C530001120521105424&0     두 번째 문자 = 'C'  -> 장치가 보고한 실제 시리얼
7&1ec2a1c4&0               두 번째 문자 = '&'  -> 시리얼 없음. OS가 생성한 ID
```

| 인스턴스 ID 모양 | 판정 | 포렌식 의미 |
| --- | --- | --- |
| 두 번째 문자가 `&`가 아니다 | 장치가 보고한 시리얼 | **다른 PC에서도 같은 값이 나온다.** 장치 동일성 입증에 쓸 수 있다 |
| 두 번째 문자가 `&`다 | OS 생성 ID | 그 PC의 그 포트 열거 결과에 종속된다. 다른 PC에서는 다른 값이 된다. 장치 동일성 근거로 쓸 수 없다 |

끝의 `&0`은 시리얼의 일부가 아니라 **같은 물리 장치 안의 인터페이스/LUN 번호**를 뜻하는 접미사다. 시리얼만 물으면 `&0`을 떼고 `4C530001120521105424`를 답한다. 반대로 `MountedDevices`나 `MountPoints2`의 문자열과 대조할 때는 `&0`이 붙은 전체 문자열이 그대로 들어 있으므로 떼지 말고 검색한다.

### 3단계 — 인스턴스 키의 값들

| 값 이름 | 내용 | 활용 |
| --- | --- | --- |
| `FriendlyName` | `SanDisk Cruzer Blade USB Device` | 사람이 읽는 모델명. 문제 정답으로 가장 무난한 표기 |
| `DeviceDesc` | `@disk.inf,%disk_devdesc%;Disk drive` | INF 리소스 참조 형태. 세미콜론 뒤의 문자열이 표시값 |
| `Mfg` | 제조사 (INF 리소스 참조 형태) | `Ven_` 토큰과 교차 확인 |
| `Service` | 이 장치를 담당한 드라이버 서비스 (`disk`, `cdrom` 등) | `Services\<이름>`으로 이동할 수 있다 |
| `ClassGUID` | 장치 클래스 GUID. 디스크 드라이브는 `{4d36e967-e325-11ce-bfc1-08002be10318}` | 장치 종류 확정 |
| `ContainerID` | **같은 물리 장치의 모든 인터페이스에 공통으로 붙는 GUID** | `Enum\USB`의 VID/PID 항목과 이 디스크 항목을 하나의 물리 장치로 묶는 열쇠 |
| `HardwareID` / `CompatibleIDs` | `USBSTOR\DiskSanDisk_Cruzer_Blade____1.00` 등 | 모델 문자열의 원본 |
| `ConfigFlags` | 구성 플래그 | 값 자체를 결론으로 쓰지 않는다 |

### 4단계 — 시각: 키 LastWrite와 그 한계

인스턴스 키의 LastWrite는 **대체로 그 장치가 마지막으로 연결된 시각**에 가깝다. 인스턴스 키에는 값이 몇 개뿐이고 그 값들이 장치 열거 때 갱신되기 때문이다. 그러나 다음 한계를 반드시 함께 말해야 한다.

| 한계 | 내용 |
| --- | --- |
| "마지막 연결"이 아니라 "마지막 키 갱신" | 드라이버 재설치, Windows 업데이트, 장치 관리자 조작으로도 갱신된다 |
| 제거 시각과 구분되지 않는다 | 연결과 제거 중 어느 쪽인지 LastWrite만으로는 알 수 없다 |
| 트랜잭션 로그 미반영 | `.LOG1`/`.LOG2`를 `rla`로 반영하지 않으면 마지막 갱신이 hive에 없을 수 있다 |
| 1계층(모델) 키의 LastWrite | 그 모델의 **어느** 개체 때문에 갱신됐는지 알 수 없다. 항상 2계층(인스턴스) 키를 본다 |

LastWrite는 REGF의 `nk` 레코드에 FILETIME(1601-01-01 UTC 기준 100ns)으로 저장되므로 **출력은 UTC**다. KST 답을 요구하면 +9시간이다. `2026-03-14 07:04:19Z` → `2026-03-14 16:04:19 KST`.

### 5단계 — `Properties` 하위의 타임스탬프 (버전 의존, 단정 금지)

인스턴스 키 아래에는 `Properties` 서브키가 있고, 그 아래 GUID로 묶인 장치 속성이 들어 있다. 그중 다음 GUID 아래의 숫자 키들이 **최초 연결 / 마지막 연결 / 마지막 제거 시각**을 담는다고 알려져 있다.

```text
SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_...&Rev_...\<인스턴스 ID>
  \Properties\{83da6326-97a6-4088-9453-a1923f573b29}
    \0064\00000000     (기본값에 8바이트 FILETIME)
    \0065\00000000
    \0066\00000000
    \0067\00000000
```

| 인덱스 | 널리 알려진 대응 | 신뢰도 |
| --- | --- | --- |
| `0064` | 최초 설치/연결 시각 | 통용되는 해석 |
| `0065` | 최초 설치 시각(다른 정의) 또는 미사용 | 버전에 따라 존재하지 않는다 |
| `0066` | 마지막 연결(arrival) 시각 | Windows 8 이후에서 주로 관찰된다 |
| `0067` | 마지막 제거(removal) 시각 | Windows 8 이후에서 주로 관찰된다 |

**이 대응은 Windows 버전과 빌드에 따라 다르므로 답의 근거로 단정하지 않는다.** 인덱스와 의미의 결합은 OS가 내부적으로 쓰는 속성 키 번호이고, 존재 여부·개수·의미가 버전마다 바뀐다. 실무 절차는 다음과 같다.

1. `Properties` 아래에 어떤 숫자 키가 실제로 존재하는지 먼저 눈으로 센다
2. 각 키의 8바이트를 FILETIME으로 변환해 **시각 목록**을 만든다
3. 가장 이른 값을 "최초", 가장 늦은 값을 "최근"으로 놓고, **어느 인덱스가 어느 의미인지는 파서 출력의 라벨을 따른다**
4. 파서가 라벨을 주지 않으면 `setupapi.dev.log`의 최초 설치 시각(6단계)과 EVTX로 의미를 확정한다

```powershell
# RegRipper 플러그인 목록에서 USB 관련 플러그인을 먼저 확인한다
rip.exe -l | Select-String 'usb|mount|devclass|port'
rip.exe -r "C:\case\SYSTEM" -p usbdevices
```

`usbstor`는 `Enum\USBSTOR`를, `usbdevices`는 `Enum\USB` 쪽 항목을 다룬다. **플러그인 이름과 출력 컬럼은 RegRipper 버전에 따라 다르므로 `rip.exe -l`로 확인한다.**

### 6단계 — 함께 봐야 하는 다른 키

`Enum\USBSTOR`만으로는 "저장장치가 있었다"까지만 나온다. 나머지 세 곳을 합쳐야 결론이 선다.

| 경로 | 얻는 것 | 왜 필요한가 |
| --- | --- | --- |
| `SYSTEM\ControlSet001\Enum\USB\VID_xxxx&PID_xxxx\<인스턴스>` | 벤더 ID / 제품 ID | 장치가 보고한 **숫자 식별자**. `Ven_`/`Prod_` 문자열이 조작·모호할 때 이쪽이 더 단단하다 |
| `SYSTEM\ControlSet001\Control\DeviceClasses\{GUID}` | 장치 인터페이스 등록 항목 | 디스크/볼륨 인터페이스가 실제로 열거된 흔적. 아래 GUID 표 참고 |
| `SYSTEM\ControlSet001\Services\USBSTOR` | USBSTOR 드라이버 자체 | `Start` 값으로 드라이버가 비활성됐는지(USB 차단 정책) 확인 |
| `SYSTEM\MountedDevices` | 드라이브 문자 매핑 | [FOR-0067](./mounteddevices.html). 시리얼 → `\DosDevices\X:` |

`DeviceClasses` 아래에서 쓰는 인터페이스 클래스 GUID는 다음 세 개다.

| GUID | 인터페이스 |
| --- | --- |
| `{53f56307-b6bf-11d0-94f2-00a0c91efb8b}` | 디스크 장치 인터페이스 |
| `{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}` | 볼륨 장치 인터페이스 |
| `{a5dcbf10-6530-11d2-901f-00c04fb951ed}` | USB 장치 인터페이스 |

`DeviceClasses` 아래의 서브키 이름 안에는 `##?#USBSTOR#Disk&Ven_...#<시리얼>&0#{...}` 형태로 **시리얼이 그대로 박혀 있다.** 시리얼 문자열로 hive 전체를 검색하면 이 키들이 함께 걸린다.

`VID`/`PID`를 얻으면 IEEE/USB-IF 벤더 목록으로 제조사를 재확인할 수 있다. 다만 오프라인 환경에서는 목록이 없으므로, **`VID_0781`을 SanDisk라고 외워서 쓰지 말고 `Ven_` 문자열과의 일치만 근거로 삼는다.**

### 7단계 — `setupapi.dev.log`로 최초 설치 시각 확정

레지스트리 LastWrite가 "마지막"만 알려주는 데 반해, **최초로 그 장치의 드라이버가 설치된 시각은 텍스트 로그에 평문으로 남는다.**

```text
C:\Windows\INF\setupapi.dev.log        (Vista 이후)
C:\Windows\setupapi.log                (XP)
```

```powershell
Select-String -Path 'C:\case\INF\setupapi.dev.log' -Pattern '4C530001120521105424' -Context 2,6
```

```text
>>>  [Device Install (Hardware initiated) - SWD\WPDBUSENUM\...4C530001120521105424&0...]
>>>  Section start 2026/03/02 21:14:07.113
     dvi: {Build Driver List} 21:14:07.128
     ndv: Selected driver installs from section [disk_install] in 'c:\windows\inf\disk.inf'
<<<  Section end 2026/03/02 21:14:08.402
<<<  [Exit status: SUCCESS]
```

| 필드 | 해석 |
| --- | --- |
| `Section start` | **그 장치가 이 PC에 처음 설치된 시각** |
| 시간대 | 이 로그는 **로컬 시각**이다. 레지스트리 LastWrite(UTC)와 직접 비교하면 9시간이 틀어진다 |
| `Device Install (Hardware initiated)` | 실제로 장치를 물리적으로 꽂아서 발생한 설치 |
| `Exit status: SUCCESS` | 설치 성공. 실패 항목은 장치가 인식되지 않은 시도다 |

시간대 처리를 한 번 더 적는다. **`setupapi.dev.log` = 로컬 시각, 레지스트리 LastWrite와 `Properties` FILETIME = UTC.** 시간대 값은 `SYSTEM\ControlSet001\Control\TimeZoneInformation`에서 확인한다([FOR-0054](./system-timezone.html)).

## 출력 필드 해석

| 얻은 값 | 어디서 | 결론에 어떻게 쓰나 |
| --- | --- | --- |
| `Ven_` / `Prod_` / `Rev_` | 1계층 키 이름 | 제조사·모델·리비전 답안 |
| 인스턴스 ID | 2계층 키 이름 | 시리얼 번호 답안. 두 번째 문자 `&` 판정 필수 |
| `&0` 접미사 | 인스턴스 ID 끝 | 시리얼 답안에서는 제거, 문자열 검색에서는 유지 |
| `FriendlyName` | 인스턴스 키 값 | 사람이 읽는 모델명 |
| `ContainerID` | 인스턴스 키 값 | `Enum\USB`의 VID/PID 항목과 동일 장치임을 묶는 근거 |
| 인스턴스 키 LastWrite | REGF `nk` | 마지막 연결 **추정** 시각(UTC). 단정 금지 |
| `Properties\{83da6326-...}` 하위 8바이트 | Properties | FILETIME 시각 목록. 의미는 파서 라벨을 따른다 |
| `Section start` | `setupapi.dev.log` | 최초 설치 시각(로컬) |

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 시리얼 (`&0` 포함) | `SYSTEM\MountedDevices` ([FOR-0067](./mounteddevices.html)) | 그 USB가 어느 드라이브 문자였나 |
| 시리얼 | `NTUSER.DAT\...\Explorer\MountPoints2` | **어느 사용자**가 마운트했나 |
| 시리얼 | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` | 볼륨 레이블(사용자가 붙인 이름) |
| 시리얼 | `C:\Windows\INF\setupapi.dev.log` | 최초 설치 시각 |
| 드라이브 문자 | LNK, Jump List, ShellBags, RecentDocs | 그 드라이브에서 무엇을 열었나 |
| 연결 시각 구간 | `$MFT`, `$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html)) | 그 시각대에 복사·생성된 파일 |
| 연결 시각 구간 | BAM/DAM ([FOR-0071](./bam-dam.html)) | 그 시각대에 어떤 프로그램이 실행됐나 |
| 전체 조립이 필요할 때 | [FOR-0075](./usb-serial-drive-letter.html) | 시리얼 → 문자 → 사용자 → 시각 워크플로 |

## 흔한 함정

- **`&0`까지 포함해 시리얼로 답하는 것.** `&0`은 인터페이스/LUN 접미사다 → 채점 문자열과 불일치해 오답이 된다 → 시리얼만 물으면 `&`부터 잘라낸다. 단, 문자열 검색용으로는 원형을 보관한다.
- **`7&1ec2a1c4&0`을 시리얼로 답하는 것.** 두 번째 문자가 `&`이므로 OS가 만든 ID다 → 다른 PC에서는 값이 달라지므로 장치 동일성 근거가 못 된다 → 그 장치는 "시리얼 미보고 장치"로 서술하고, 동일성은 `Ven_`/`Prod_`/`Rev_`와 `VID`/`PID`, 볼륨 시리얼로 보강한다.
- **인스턴스 키 LastWrite를 "마지막 연결 시각"으로 단정하는 것.** 드라이버 갱신·장치 관리자 조작으로도 갱신된다 → 시각을 단독 근거로 쓰면 반박당한다 → `setupapi.dev.log`, EVTX, `$UsnJrnl`과 최소 2중 확인한다.
- **1계층(모델) 키의 LastWrite를 읽는 것.** 같은 모델의 개체가 여럿이면 어느 것 때문에 갱신됐는지 알 수 없다 → 반드시 2계층 인스턴스 키의 LastWrite를 본다.
- **`Properties`의 `0064`/`0066`/`0067` 대응을 외운 대로 단정하는 것.** 버전 의존이다 → 인덱스와 의미의 결합을 답안 근거로 쓰면 틀릴 수 있다 → 시각 목록만 뽑고 라벨은 파서 출력과 `setupapi.dev.log`로 확정한다.
- **`CurrentControlSet` 경로로 찾는 것.** 오프라인 hive에는 그 키가 없다 → `Select\Current`로 활성 세트를 먼저 정한다([FOR-0053](./system-controlset.html)).
- **`Enum\USBSTOR`가 비어 있으면 "USB를 안 꽂았다"고 결론하는 것.** MTP 모드 스마트폰·카메라는 `USBSTOR`가 아니라 WPD 쪽으로, 외장 SSD 중 UASP 장치도 표기가 달라질 수 있다 → `Enum\USB`, `DeviceClasses`, `MountedDevices`, `setupapi.dev.log`를 함께 본다.
- **트랜잭션 로그를 반영하지 않는 것.** `rla` 없이 파싱하면 마지막 연결 기록이 hive 본문에 아직 없을 수 있다 → `SYSTEM`, `SYSTEM.LOG1`, `SYSTEM.LOG2`를 같은 폴더로 꺼내 `rla`를 돌린다.
- **UTC와 로컬을 섞는 것.** 레지스트리는 UTC, `setupapi.dev.log`는 로컬이다 → 같은 표에 넣기 전에 한쪽으로 통일하고 표에 시간대를 명시한다.
- **`Ven_`을 브랜드 그대로 믿는 것.** 컨트롤러 제조사가 그대로 노출되어 케이스 브랜드와 다른 경우가 흔하다 → `FriendlyName`, `VID`/`PID`, 볼륨 레이블로 교차 확인한다.

## 교차검증

```powershell
# 1) USBSTOR — 장치와 시리얼
rip.exe -r "C:\case\SYSTEM" -p usbstor > usbstor.txt

# 2) 같은 시리얼이 hive 안 다른 키에도 있는지 (DeviceClasses, MountedDevices)
rip.exe -r "C:\case\SYSTEM" -p devclass > devclass.txt
rip.exe -r "C:\case\SYSTEM" -p mountdev > mountdev.txt
Select-String -Path usbstor.txt, devclass.txt, mountdev.txt -Pattern '4C530001120521105424'

# 3) 최초 설치 시각 (로컬 시각)
Select-String -Path 'C:\case\INF\setupapi.dev.log' -Pattern '4C530001120521105424' -Context 2,4

# 4) 시간대 확인 후 UTC/KST 통일
rip.exe -r "C:\case\SYSTEM" -p timezone
```

세 곳(`Enum\USBSTOR`, `DeviceClasses`, `MountedDevices`)에서 같은 시리얼이 나오면 그 장치가 실제로 마운트까지 되었다는 뜻이다. `Enum\USBSTOR`에만 있고 `MountedDevices`에 없으면 **드라이버는 설치됐지만 볼륨이 마운트되지 않았거나, 이후 다른 장치가 그 문자를 덮어썼다**는 뜻이다.

## mini walkthrough

```text
문제:
"압수한 PC의 SYSTEM hive와 setupapi.dev.log 가 첨부됩니다.
 2026-03-02 에 이 PC에 처음 설치된 USB 저장장치의 시리얼 번호를 구하세요."

1. 첫 시도 (실패):
   rip.exe -r SYSTEM -p usbstor 출력에서 장치가 3개 나왔다.
   LastWrite 가 가장 최근인 항목을 골라 인스턴스 ID 를 그대로 적었다.

     Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07
       7&1ec2a1c4&0        LastWrite 2026-03-14 08:55:02Z   <- 이걸 답으로 냈다

   왜 틀렸나 (두 겹의 실수):
   (a) 문제가 물은 것은 "2026-03-02 에 처음 설치된" 장치인데,
       LastWrite(= 마지막 갱신 추정)로 골랐다. 최초 설치는 LastWrite 로 알 수 없다.
   (b) 7&1ec2a1c4&0 은 두 번째 문자가 '&' 다. 장치가 시리얼을 보고하지 않아
       OS 가 만든 ID 이므로 애초에 "시리얼 번호"라는 답이 성립하지 않는다.

2. 피벗: 최초 설치는 setupapi.dev.log 에서 찾는다
   Select-String -Path setupapi.dev.log -Pattern 'Section start 2026/03/02' -Context 1,3

     >>>  [Device Install (Hardware initiated) - SWD\WPDBUSENUM\...
           _??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#
           4C530001120521105424&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}]
     >>>  Section start 2026/03/02 21:14:07.113
     <<<  [Exit status: SUCCESS]

   -> 후보 시리얼: 4C530001120521105424&0

3. 레지스트리에서 그 장치를 확정한다
   SYSTEM\ControlSet001\Enum\USBSTOR
     Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
       4C530001120521105424&0        LastWrite 2026-03-14 07:04:19Z
         FriendlyName = SanDisk Cruzer Blade USB Device
         ContainerID  = {b9a4c1e2-8f31-5c47-9c02-1d7a3e5f6b88}

   두 번째 문자 = 'C' -> 장치가 보고한 실제 시리얼이다.

4. Properties 확인 — 단정하지 않는다
   ...\4C530001120521105424&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}
     0064\00000000  -> FILETIME 2026-03-02 12:14:07Z
     0066\00000000  -> FILETIME 2026-03-14 07:04:19Z
     0067\00000000  -> FILETIME 2026-03-14 07:31:48Z

   0064 가 setupapi.dev.log 의 2026/03/02 21:14:07(로컬, KST)과
   9시간 차이로 정확히 일치한다 -> 이 hive 에서는 0064 = 최초 설치로 읽을 수 있다.
   (인덱스 의미는 이렇게 다른 출처와 맞아떨어질 때만 근거로 쓴다.)

5. 시간대 통일
   Control\TimeZoneInformation -> TimeZoneKeyName = Korea Standard Time
   2026-03-02 12:14:07Z + 9h = 2026-03-02 21:14:07 KST  (로그와 일치)

정답: 4C530001120521105424
      (SanDisk Cruzer Blade, 최초 설치 2026-03-02 21:14:07 KST)
```

## 막혔을 때 다음 체크

1. `SYSTEM\Select`의 `Current`로 활성 ControlSet을 확정했는가 ([FOR-0053](./system-controlset.html))
2. `rla`로 `SYSTEM.LOG1`/`.LOG2`를 반영했는가
3. 인스턴스 ID의 **두 번째 문자**를 확인했는가 — `&`면 시리얼 미보고 장치다
4. `&0` 접미사를 답에서 떼야 하는 문제인가, 검색용으로 유지해야 하는 상황인가
5. `Disk` 말고 `CdRom`·`Other` 서브키도 봤는가
6. `Enum\USBSTOR`가 비었으면 `Enum\USB`, `Control\DeviceClasses`, `MountedDevices`, `setupapi.dev.log`로 넓혔는가
7. `Properties` 하위 숫자 키를 세어 보고, 인덱스 의미를 다른 출처로 검증했는가
8. `setupapi.dev.log`(로컬)와 레지스트리(UTC)를 같은 시간대로 통일했는가
9. 드라이브 문자가 필요하면 [FOR-0067](./mounteddevices.html), 사용자 귀속까지 필요하면 [FOR-0075](./usb-serial-drive-letter.html)로 이동
10. RegRipper 플러그인 이름을 모르겠으면 `rip.exe -l | Select-String 'usb'`

## 출처

- SRC-098 — Microsoft Learn, USB 장치 레지스트리 항목: `USBSTOR` 열거 구조, `Disk&Ven_&Prod_&Rev_` 키 형식, 장치 인스턴스 ID와 시리얼 번호의 관계(시리얼 미보고 장치는 OS가 ID를 생성한다는 규칙), 장치 인터페이스 클래스 GUID
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM` hive의 위치와 오프라인 마운트 시 경로 표기
- SRC-099 — RegRipper 3.0 저장소: `usbstor`, `usbdevices`, `devclass`, `mountdev` 플러그인의 존재와 `rip.exe -l`/`-p` 옵션
- `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` 아래 `0064`/`0065`/`0066`/`0067`의 **인덱스와 의미의 대응은 Windows 버전·빌드에 따라 다르다.** 이 글은 통용되는 해석만 표로 제시하고 단정하지 않는다. 실제 사건에서는 파서가 붙인 라벨과 `setupapi.dev.log` 시각으로 교차 확인할 것
- RegRipper 플러그인 이름과 출력 컬럼은 버전에 따라 다를 수 있으므로 `rip.exe -l`로 확인할 것
- `setupapi.dev.log`의 항목 형식과 필드 이름은 Windows 빌드에 따라 다르므로 실제 파일에서 확인할 것
