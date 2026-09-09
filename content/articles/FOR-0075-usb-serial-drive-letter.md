---
id: FOR-0075
title: "USB 시리얼에서 드라이브 문자·사용자·시각까지 잇는 종합 절차"
slug: "usb-serial-drive-letter"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["USBSTOR", "MountedDevices", "MountPoints2", "Windows Portable Devices", "setupapi.dev.log", "LNK", "ShellBags", "$UsnJrnl"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "C:\\Windows\\INF\\setupapi.dev.log", "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent", "C:\\Windows\\System32\\winevt\\Logs", "C:\\$Extend\\$UsnJrnl"]
registry_paths: ["SYSTEM\\ControlSet001\\Enum\\USBSTOR", "SYSTEM\\MountedDevices", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"]
event_ids: ["6416", "1006"]
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "EvtxECmd", "FTK Imager", "KAPE", "analyzeMFT", "NTFS Log Tracker"]
commands: ["rip.exe -r SYSTEM -f system", "rip.exe -r NTUSER.DAT -p mp2", "rip.exe -r SOFTWARE -p portdev"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["FriendlyName", "_LabelFromReg", "BaseClass", "Volume Serial Number", "Drive Type", "Local Base Path"]
file_formats: ["regf", "lnk", "evtx"]
primary_terms: ["USB 드라이브 문자 연결", "USB serial 매핑", "어느 드라이브 문자였나"]
keywords: ["USB", "드라이브 문자", "drive letter", "시리얼 번호", "MountPoints2", "Windows Portable Devices", "볼륨 레이블", "setupapi.dev.log", "LNK", "ShellBags", "사용자 귀속", "6416", "1006", "워크플로"]
aliases: ["어느 드라이브 문자였나", "usb 어느 드라이브였나", "usb serial 매핑", "누가 usb를 꽂았나", "usb 유출 추적", "usb 볼륨 레이블", "usb 사용자 특정", "usb 종합 분석"]
symptom_keywords: ["USB가 어느 드라이브 문자였는지 알고 싶다", "누가 USB를 연결했는지 알고 싶다", "USB로 파일을 복사했는지 확인하고 싶다", "MountedDevices에 그 시리얼이 없다", "볼륨 레이블을 알고 싶다", "USB 연결 시각을 확정하고 싶다"]
related: ["FOR-0066", "FOR-0067", "FOR-0071", "FOR-0053"]
source_ids: ["SRC-098", "SRC-017", "SRC-099", "SRC-029"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

USB 유출 사건은 **시리얼 → 드라이브 문자 → 사용자 → 시각 → 파일**의 다섯 단계를 순서대로 잇는 문제이며, 각 고리는 `Enum\USBSTOR` → `MountedDevices` → `MountPoints2` → `setupapi.dev.log`/EVTX → LNK·ShellBags·`$UsnJrnl`가 담당한다. 어느 고리가 끊기든 그 단계 전용의 대안 경로가 따로 있으므로 절차를 포기하지 않는다.

## 어떤 문제에서 필요한가

이 글은 새 artifact를 소개하지 않는다. **앞의 네 글을 조립하는 워크플로 글**이다.

- "USB를 꽂아 자료를 유출했다. 장치·사용자·시각·파일을 모두 특정하라"
- "이 LNK의 `E:\...` 경로가 어느 물리 장치의 것인지 증명하라"
- "여러 사용자 중 **누가** 그 USB를 마운트했는지 가려라"
- "USB의 볼륨 레이블이 무엇이었나"
- "USB 연결 구간에 어떤 파일이 오갔나"

단계별 상세는 각 전담 글에 있다.

| 단계 | 전담 글 |
| --- | --- |
| 장치와 시리얼 | [FOR-0066](./usbstor.html) |
| 드라이브 문자 | [FOR-0067](./mounteddevices.html) |
| 그 시각의 실행 프로그램 | [FOR-0071](./bam-dam.html) |
| hive 위치와 ControlSet 판정 | [FOR-0053](./system-controlset.html) |
| 같은 시각의 네트워크 | [FOR-0072](./networklist.html) |

## 문제에서 처음 볼 단서

1. 첨부에 `SYSTEM` + `SOFTWARE` + 사용자별 `NTUSER.DAT`이 **함께** 있다 → 사용자 귀속을 묻는 문제다
2. `setupapi.dev.log` 또는 `winevt\Logs`가 함께 있다 → 시각 확정을 묻는 문제다
3. 어떤 artifact에 `E:\`, `F:\` 같은 문자가 보이는데 이미지에 그 파티션이 없다 → 착탈식이다
4. 지문에 "볼륨 레이블", "장치 이름"이 있다 → Windows Portable Devices까지 가야 한다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -f system > system_all.txt
```

한 번에 `usbstor`·`mountdev`·`devclass`를 포함한 `SYSTEM` 계열 플러그인이 돌아간다. 그 뒤 사용자 hive와 `SOFTWARE`를 각각 돌린다.

```powershell
rip.exe -r "C:\case\SOFTWARE" -f software > software_all.txt
rip.exe -r "C:\case\jhkim\NTUSER.DAT" -p mp2 > mp2_jhkim.txt
```

그다음 **시리얼 문자열 하나로 전부 검색**하는 것이 이 워크플로의 핵심 동작이다.

```powershell
Select-String -Path *.txt -Pattern '4C530001120521105424'
```

## 상세 절차

### 전체 흐름

```text
[1] Enum\USBSTOR        장치 + 시리얼          <- 출발점
        |
[2] MountedDevices      \DosDevices\X: 확정
        |
[3] MountPoints2        어느 사용자가 마운트했나 (사용자별 NTUSER.DAT)
        |
[4] WPD Devices         볼륨 레이블
        |
[5] setupapi.dev.log    최초 설치 시각 (로컬)
        |
[6] EVTX                연결/제거 시각
        |
[7] LNK / ShellBags     그 드라이브의 파일 접근
        |
[8] $MFT / $UsnJrnl     실제로 오간 파일
```

### 1단계 — `Enum\USBSTOR`에서 장치와 시리얼 확보

```text
SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
  \4C530001120521105424&0
```

시리얼 판정 규칙(두 번째 문자가 `&`면 OS 생성 ID)과 `&0` 접미사 처리는 [FOR-0066](./usbstor.html)에 있다. **이 단계의 산출물은 두 개**다.

| 산출물 | 형태 | 어디에 쓰나 |
| --- | --- | --- |
| 검색용 문자열 | `4C530001120521105424&0` (접미사 포함) | 이후 모든 단계의 grep 키 |
| 답안용 시리얼 | `4C530001120521105424` | 문제 정답 |

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| `Enum\USBSTOR`가 비어 있다 | `Control\DeviceClasses\{53f56307-...}` 서브키 이름에 같은 인스턴스 경로가 들어 있다 |
| 시리얼이 OS 생성 ID다 (`7&...&0`) | 시리얼로 장치 동일성을 주장하지 않고, `Ven_`/`Prod_`/`Rev_` + `Enum\USB`의 `VID`/`PID` + 볼륨 레이블 조합으로 특정한다 |
| hive가 dirty다 | `rla`로 `.LOG1`/`.LOG2` 반영 후 재시도 |
| `SYSTEM`이 아예 없다 | `setupapi.dev.log`만으로도 장치 인스턴스 경로 전체가 나온다 |

### 2단계 — `MountedDevices`에서 드라이브 문자 확정

**드라이브 문자에서 시리얼을 찾는 방향(문자 → 장치)이 아니라, 시리얼로 값 전체를 검색하는 방향(장치 → 문자)으로 간다.** 드라이브 문자는 재사용되므로 문자에서 출발하면 마지막 장치만 보인다.

```powershell
rip.exe -r "C:\case\SYSTEM" -p mountdev > mountdev.txt
Select-String -Path mountdev.txt -Pattern '4C530001120521105424' -Context 1,1
```

```text
  \DosDevices\E:
> _??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001120521105424&0#{53f56307-...}
  \??\Volume{9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}
```

값 데이터의 두 형태(12바이트 고정 디스크 / UTF-16LE 문자열)와 hex 판독 절차는 [FOR-0067](./mounteddevices.html)에 있다. **이 단계의 산출물은 드라이브 문자와 볼륨 GUID 두 개**다.

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| 그 시리얼이 `MountedDevices`에 없다 | 이후 다른 장치가 그 문자를 덮어썼다. 3단계 `MountPoints2`와 7단계 LNK의 볼륨 정보로 당시 문자를 복원한다 |
| `\??\Volume{GUID}`에만 있고 `\DosDevices\X:`가 없다 | 그 볼륨은 마지막 상태에서 문자를 갖지 않았다. `MountPoints2`의 볼륨 GUID와 LNK의 볼륨 시리얼로 우회한다 |
| 문자가 여러 개 걸린다 | 같은 장치에 파티션이 여럿이거나 시점이 다른 매핑이다. 시각 단계(5·6)로 시점을 나눈다 |

### 3단계 — `MountPoints2`로 사용자 귀속

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
  {9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}      <- 볼륨 GUID 형태
  E                                            <- 드라이브 문자 형태
  ##10.0.0.5#share                             <- 네트워크 공유 (\\10.0.0.5\share)
  CPC\Volume\{...}                             <- 내부 캐시
```

**이 키는 사용자 hive에 있다.** 즉 `MountPoints2`에 항목이 있다는 것 자체가 **그 사용자 세션이 그 볼륨을 마운트했다**는 뜻이고, 이것이 USB 사건에서 사용자를 특정하는 정본 근거다.

| 서브키 이름 형태 | 의미 |
| --- | --- |
| `{볼륨 GUID}` | 2단계에서 얻은 볼륨 GUID와 대조한다. 일치하면 그 사용자가 그 볼륨을 마운트했다 |
| 드라이브 문자 한 글자 (`E`) | 그 사용자 세션에서 그 문자가 쓰였다 |
| `##server#share` | 네트워크 공유. `\\server\share`의 `\`가 `#`로 치환된 형태다 |

| 서브키의 값 | 의미 |
| --- | --- |
| `_LabelFromReg` | 레지스트리에서 가져온 표시 라벨. 존재하면 볼륨 레이블 후보 |
| `BaseClass` | `Volume` 또는 `Drive` |
| `_Autorun`, `_AutorunStatus` | autorun 관련 값. 존재 여부가 환경에 따라 다르다 |

```powershell
# 사용자별로 전부 돌린다. 한 사용자만 보고 결론내면 틀린다.
Get-ChildItem 'C:\case\users' -Directory | ForEach-Object {
    $hive = Join-Path $_.FullName 'NTUSER.DAT'
    if (Test-Path $hive) {
        "=== $($_.Name)"
        rip.exe -r $hive -p mp2
    }
} > mp2_all.txt

Select-String -Path mp2_all.txt -Pattern '9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02' -Context 3,3
```

서브키의 LastWrite는 **그 사용자 세션에서 그 볼륨이 마지막으로 마운트된 시각**에 가깝지만, 다른 키와 마찬가지로 단독 근거로 쓰지 않는다.

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| 어떤 사용자 hive에도 없다 | 사용자가 항목을 지웠거나(반포렌식), 사용자 세션 없이 마운트됐다. LNK·Jump List·ShellBags(사용자별)로 귀속을 시도한다 |
| 사용자가 한 명뿐인데 항목이 있다 | 귀속은 성립하지만 "그 사람이 물리적으로 꽂았다"는 아니다. 로그온 세션(4624)과 시각을 대조한다 |
| SID만 있고 이름을 모른다 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath` ([FOR-0052](./sam-user-accounts.html)) |

### 4단계 — Windows Portable Devices로 볼륨 레이블

```text
SOFTWARE\Microsoft\Windows Portable Devices\Devices\<장치 키>
```

서브키 이름 안에 **USBSTOR 인스턴스 경로(따라서 시리얼) 또는 볼륨 GUID**가 들어 있다. 그래서 2단계까지 얻은 값 중 아는 쪽으로 검색하면 걸린다.

```text
SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#
  4C530001120521105424&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
    FriendlyName = USB_DATA
```

| 값 | 의미 |
| --- | --- |
| `FriendlyName` | **그 장치의 볼륨 레이블.** 사용자가 포맷 때 붙인 이름이 그대로 들어 있는 경우가 많다 |

```powershell
rip.exe -r "C:\case\SOFTWARE" -p portdev > portdev.txt
Select-String -Path portdev.txt -Pattern '4C530001120521105424' -Context 0,3
```

`FriendlyName`이 `이동식 디스크`나 빈 문자열이면 레이블이 없는 장치다. 레이블이 `USB_DATA`처럼 특정적이면 **LNK·ShellBags에 남은 볼륨 레이블과 대조해 같은 장치임을 이중으로 증명**할 수 있다.

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| WPD에 항목이 없다 | LNK의 볼륨 레이블 필드, ShellBags의 항목명, `MountPoints2`의 `_LabelFromReg`를 본다 |
| 레이블이 여러 값으로 다르다 | 중간에 포맷·이름 변경이 있었다. 시각 순서를 세워 어느 시점의 레이블인지 특정한다 |

### 5단계 — `setupapi.dev.log`로 최초 설치 시각

```powershell
Select-String -Path 'C:\case\INF\setupapi.dev.log' -Pattern '4C530001120521105424' -Context 2,6
```

```text
>>>  [Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_SanDisk&
     Prod_Cruzer_Blade&Rev_1.00#4C530001120521105424&0#{53f56307-...}]
>>>  Section start 2026/03/02 21:14:07.113
<<<  [Exit status: SUCCESS]
```

**이 로그의 시각은 로컬 시각이다.** 레지스트리 LastWrite와 `Properties` FILETIME은 UTC다. 표에 넣기 전에 한쪽으로 통일한다.

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| 로그에 그 시리얼이 없다 | 로그가 순환되어 잘렸다. `Enum\USBSTOR` 하위 `Properties`의 FILETIME 목록과 EVTX로 대체한다 |
| 항목이 있으나 `Exit status`가 실패다 | 드라이버 설치가 실패한 시도다. 그 시점에 마운트는 되지 않았을 수 있다 |
| 최초와 최근을 구분해야 한다 | `setupapi.dev.log` = 최초 설치, `Enum\USBSTOR` 인스턴스 키 LastWrite = 최근 갱신 추정 |

### 6단계 — EVTX로 연결/제거 시각

**채널 존재 여부와 활성 여부가 환경마다 다르다.** 있으면 가장 정확한 시각원이고, 없으면 5단계와 7단계로 대체한다.

| 채널 | 대표 Event ID | 무엇이 남나 | 주의 |
| --- | --- | --- | --- |
| `Microsoft-Windows-Partition/Diagnostic` | `1006` | 디스크 연결 시 모델·시리얼·`VID`/`PID`와 디스크 레이아웃 | Windows 10 이후에서 USB 시각 확정의 주력. 필드명은 버전에 따라 다르다 |
| `Security` | `6416` | 새 외부 장치가 인식됨 | **"PNP 활동 감사"가 켜져 있어야 기록된다.** 기본 정책에서는 없다 |
| `Microsoft-Windows-DriverFrameworks-UserMode/Operational` | `2003`, `2100`, `2101`, `2102` 등 | UMDF 장치의 연결·전원 전이 → 연결/제거 시각 추정 | Windows 7·8에서 유용. **Windows 10 이후에는 이 로그가 기본 비활성인 환경이 많다** |
| `System` (원본 `UserPnp`) | `20001` | 드라이버 설치 결과와 장치 인스턴스 ID | 최초 설치 시각의 교차검증용 |
| `Microsoft-Windows-Kernel-PnP/Configuration` | `400`, `410` 등 | 장치 구성 이벤트 | 채널 존재 여부가 환경에 따라 다르다 |

```powershell
EvtxECmd.exe -d 'C:\case\winevt\Logs' --csv 'C:\case\out' --csvf evtx_all.csv
Import-Csv 'C:\case\out\evtx_all.csv' |
  Where-Object { $_.Payload -match '4C530001120521105424' } |
  Select-Object TimeCreated, EventId, Channel, MapDescription |
  Sort-Object TimeCreated
```

```text
TimeCreated              EventId  Channel                                MapDescription
2026-03-02T12:14:08.0Z   20001    System                                 Driver install
2026-03-14T07:04:19.0Z   1006     Microsoft-Windows-Partition/Diagnostic Disk arrival
2026-03-14T07:31:48.0Z   1006     Microsoft-Windows-Partition/Diagnostic Disk arrival
```

**EVTX의 `TimeCreated`는 UTC다.** `setupapi.dev.log`(로컬)와 나란히 놓지 않는다. Event ID·필드 이름·`MapDescription`은 OS 버전과 EvtxECmd 맵 버전에 따라 다르므로 **실제 출력에서 확인한다.**

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| DriverFrameworks 로그가 비활성이다 | `Partition/Diagnostic` → `System`(20001) → `setupapi.dev.log` 순으로 내려간다 |
| 시리얼로 검색해도 안 걸린다 | 페이로드가 `VID`/`PID`나 모델명만 담는 이벤트가 있다. 모델 문자열로 다시 검색한다 |
| 로그가 삭제됐다 | Security 1102(감사 로그 삭제)를 확인하고, 시각은 레지스트리·`$UsnJrnl`로 재구성한다 |

### 7단계 — LNK·Jump List·ShellBags로 파일 접근

이 단계는 **USB 자체가 없어도** "그 드라이브에서 무엇을 열었나"를 답한다.

| artifact | 위치 | 얻는 것 |
| --- | --- | --- |
| LNK (최근 항목) | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk` | 대상 경로, **볼륨 시리얼 번호**, 볼륨 레이블, 드라이브 종류 |
| Jump List | `...\Recent\AutomaticDestinations\*.automaticDestinations-ms` | 앱별로 열었던 파일 목록 |
| ShellBags | `UsrClass.dat`의 `BagMRU`/`Bags` | 탐색기로 **폴더를 열어 본** 흔적. 파일이 지워져도 폴더 구조가 남는다 |

LNK 내부의 볼륨 정보가 이 워크플로의 두 번째 연결 고리다.

| LNK 필드 | 의미 |
| --- | --- |
| Drive Type | `2` = 착탈식(removable), `3` = 고정 디스크, `4` = 네트워크, `5` = CD-ROM |
| Volume Serial Number | 파일시스템이 포맷 때 만든 32비트 값. **볼륨 GUID와 다른 값이다** |
| Volume Label | 볼륨 레이블. 4단계의 `FriendlyName`과 대조 |
| Local Base Path | `E:\report\salary.xlsx` 같은 실제 경로 |

`Drive Type = 2`이고 `Volume Label`이 4단계의 `FriendlyName`과 같다면, 그 LNK는 그 USB의 파일을 가리킨다고 말할 수 있다.

**실패했을 때의 대안**

| 상황 | 대안 |
| --- | --- |
| LNK가 없다 | Jump List → ShellBags → `RecentDocs` → Office MRU 순으로 내려간다 |
| 드라이브 문자만 있고 볼륨 정보가 없다 | 문자 재사용 가능성 때문에 단독으로는 약하다. 시각 구간으로 장치를 좁힌다 |
| ShellBags에 폴더는 있는데 파일이 없다 | ShellBags는 폴더 중심이다. 파일은 LNK·Jump List·`$UsnJrnl`로 본다 |

### 8단계 — `$MFT` / `$UsnJrnl`로 실제로 오간 파일

**방향에 따라 남는 곳이 다르다는 것이 이 단계의 핵심이다.**

| 방향 | PC의 `C:` 볼륨에 남는가 | 무엇을 본다 |
| --- | --- | --- |
| USB → PC (가져옴) | **남는다.** `C:`에 파일이 새로 생성된다 | `$MFT`의 생성 시각, `$UsnJrnl`의 `FileCreate`/`DataExtend`/`Close` ([FOR-0028](./usn-reason-flags.html)) |
| PC → USB (내보냄) | **`C:`에는 파일 생성 기록이 없다** | LNK·Jump List·ShellBags·Prefetch, 그리고 원본 파일의 접근 흔적 |
| USB 안에서만 이동 | `C:`에 없다 | USB 이미지가 있어야 한다 |

**"USB로 복사해 갔다"는 결론을 `C:`의 `$UsnJrnl`에서 직접 찾으려 하면 실패한다.** 내보내기는 대상 볼륨에 기록되기 때문이다. 대신 다음 정황을 모은다.

```powershell
# USB 연결 구간(UTC)에 C: 에서 벌어진 파일 활동
Import-Csv 'C:\case\out\usn.csv' |
  Where-Object { [datetime]$_.UpdateTimestamp -ge '2026-03-14T07:04:19Z' -and
                 [datetime]$_.UpdateTimestamp -le '2026-03-14T07:31:48Z' } |
  Select-Object UpdateTimestamp, Name, UpdateReasons |
  Sort-Object UpdateTimestamp
```

```powershell
# 같은 구간에 실행된 압축/복사 도구 (BAM)
rip.exe -r "C:\case\clean\SYSTEM" -p bam | Select-String '7z|rar|robocopy|xcopy|explorer'
```

`$MFT`/`$J` 파싱 자체는 별도 도구로 한다. 경로는 **작은따옴표**로 감싼다.

```powershell
analyzeMFT.py -f 'C:\case\$MFT' -o 'C:\case\out\mft.csv'
```

## 출력 필드 해석

| 단계 | 산출물 | 다음 단계에 넘기는 형태 |
| --- | --- | --- |
| 1 | 모델, 시리얼 | `4C530001120521105424&0` (검색용) / `4C530001120521105424` (답안용) |
| 2 | 드라이브 문자, 볼륨 GUID | `E:`, `{9f3a7c10-...}` |
| 3 | 사용자 SID/이름 | `S-1-5-21-...-1013` → `jhkim` |
| 4 | 볼륨 레이블 | `USB_DATA` |
| 5 | 최초 설치 시각 | `2026-03-02 21:14:07` **(로컬)** |
| 6 | 연결/제거 시각 | `2026-03-14T07:04:19Z` **(UTC)** |
| 7 | 접근한 파일 목록 | `E:\report\salary.xlsx` + 볼륨 시리얼 |
| 8 | 오간 파일 | `$UsnJrnl` 레코드 시각과 이유 플래그 |

시간대 정리를 한 표에 못 박는다.

| 출처 | 시간대 |
| --- | --- |
| 레지스트리 키 LastWrite, `Properties` FILETIME | UTC |
| EVTX `TimeCreated` | UTC |
| `$MFT` / `$UsnJrnl` 타임스탬프 | UTC |
| `setupapi.dev.log` `Section start` | **로컬** |
| `NetworkList`의 `DateCreated`/`DateLastConnected` | **로컬** ([FOR-0072](./networklist.html)) |

KST 환산은 UTC + 9시간이다. FILETIME과 Unix epoch의 차이는 `11644473600`초다.

## pivot: 다음에 볼 artifact

| 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 시리얼 | `MountedDevices`, WPD, `setupapi.dev.log`, EVTX | 문자·레이블·시각 |
| 볼륨 GUID | 사용자별 `MountPoints2` | 사용자 귀속 |
| 드라이브 문자 | LNK, Jump List, ShellBags, `RecentDocs` | 파일 접근 |
| 볼륨 레이블 | LNK의 Volume Label | 같은 장치임의 이중 증명 |
| 연결 시각 구간 | BAM/DAM ([FOR-0071](./bam-dam.html)), Prefetch | 그 구간에 실행된 도구 |
| 연결 시각 구간 | `$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html)) | 그 구간의 파일 생성·삭제 |
| 사용자 SID | Security 4624 ([FOR-0083](./event-4624-logon.html)) | 그 시각에 실제로 로그온한 세션 |
| 같은 시각의 네트워크 | `NetworkList` ([FOR-0072](./networklist.html)) | 어디에서 벌어진 일인가 |

## 흔한 함정

- **드라이브 문자에서 출발하는 것.** 문자는 재사용된다 → `\DosDevices\E:`에는 **마지막** 장치만 남아 있어 다른 USB를 지목하게 된다 → 항상 시리얼에서 출발해 문자를 찾는다.
- **`MountPoints2`를 한 사용자 hive에서만 확인하는 것.** 이 키는 사용자별이다 → "귀속 불가"라고 잘못 결론한다 → `C:\Users\*` 전부의 `NTUSER.DAT`을 돌린다.
- **`MountPoints2`의 존재를 "물리적으로 꽂았다"로 확대하는 것.** 그 세션이 볼륨을 마운트했다는 뜻이다 → 원격 세션·자동 마운트 가능성을 배제하지 못한다 → 4624 로그온 세션과 시각을 대조한다.
- **볼륨 GUID와 볼륨 시리얼 번호를 같은 값으로 보는 것.** 전자는 마운트 매니저의 128비트 식별자, 후자는 파일시스템의 32비트 값이다 → 대조가 영원히 실패한다 → 각각 다른 필드로 다룬다.
- **`setupapi.dev.log`(로컬)와 EVTX·레지스트리(UTC)를 같은 표에 섞는 것.** 9시간이 어긋난다 → 사건 순서가 뒤집힌다 → 표의 열 이름에 시간대를 반드시 적는다.
- **`C:`의 `$UsnJrnl`에서 "USB로 내보낸 파일"을 찾는 것.** 내보내기는 대상 볼륨에 기록된다 → 아무것도 못 찾고 "복사 안 했다"고 결론한다 → LNK·Jump List·ShellBags·Prefetch로 정황을 모은다.
- **EVTX 채널이 없는 것을 "USB를 안 꽂았다"로 읽는 것.** DriverFrameworks 로그는 Windows 10 이후 기본 비활성인 환경이 많고 6416은 감사 정책이 필요하다 → 없는 것이 정상인 경우가 많다 → 레지스트리와 `setupapi.dev.log`로 판단한다.
- **`Enum\USBSTOR`의 인스턴스 키 LastWrite를 "USB를 뺀 시각"으로 단정하는 것.** 연결·제거·드라이버 갱신 중 무엇인지 구분되지 않는다 → 시각을 근거로 한 결론이 반박된다 → EVTX나 `Properties` 시각 목록과 교차한다.
- **`Properties\{83da6326-...}`의 인덱스 의미를 외운 대로 쓰는 것.** 버전 의존이다 → 최초·마지막이 뒤바뀐다 → 파서 라벨과 `setupapi.dev.log`로 확정한다([FOR-0066](./usbstor.html)).
- **`CurrentControlSet` 경로로 찾는 것.** 오프라인 hive에는 없다 → `Select\Current`로 세트를 정한다([FOR-0053](./system-controlset.html)).
- **`rla`를 건너뛰는 것.** USB 관련 키는 자주 갱신된다 → 최근 연결이 hive 본문에 없을 수 있다 → `SYSTEM`·`SOFTWARE`·`NTUSER.DAT`을 각각 로그와 함께 반영한다.
- **한 개 artifact로 결론하는 것.** 이 워크플로의 목적은 다섯 고리를 잇는 것이다 → 하나만 제시하면 대안 설명(다른 장치·다른 사용자)을 배제할 수 없다 → 최소 시리얼·문자·사용자·시각 네 값을 함께 제시한다.

## 교차검증

```powershell
# 0) 모든 hive 에 트랜잭션 로그 반영
rla.exe -f 'C:\case\SYSTEM'   --out 'C:\case\clean'
rla.exe -f 'C:\case\SOFTWARE' --out 'C:\case\clean'

# 1) 시리얼 하나로 레지스트리 전체 훑기
rip.exe -r 'C:\case\clean\SYSTEM'   -f system   > system_all.txt
rip.exe -r 'C:\case\clean\SOFTWARE' -f software > software_all.txt
Select-String -Path system_all.txt, software_all.txt -Pattern '4C530001120521105424'

# 2) 사용자별 MountPoints2
Get-ChildItem 'C:\case\users' -Directory | ForEach-Object {
    "=== $($_.Name)"; rip.exe -r (Join-Path $_.FullName 'NTUSER.DAT') -p mp2
} > mp2_all.txt

# 3) 최초 설치 (로컬 시각)
Select-String -Path 'C:\case\INF\setupapi.dev.log' -Pattern '4C530001120521105424' -Context 2,4

# 4) EVTX (UTC)
EvtxECmd.exe -d 'C:\case\winevt\Logs' --csv 'C:\case\out' --csvf evtx_all.csv
Import-Csv 'C:\case\out\evtx_all.csv' | Where-Object { $_.Payload -match '4C530001' }

# 5) 그 구간의 파일 활동과 실행
Import-Csv 'C:\case\out\usn.csv' | Where-Object { $_.Name -like '*.xlsx' }
rip.exe -r 'C:\case\clean\SYSTEM' -p bam | Select-String '7z|rar|robocopy'
```

네 값(시리얼, 드라이브 문자, 사용자, 시각)이 서로를 지지하면 결론이 성립한다. 하나라도 다른 장치를 가리키면 **문자 재사용**을 먼저 의심한다.

## mini walkthrough

```text
문제:
"퇴사자 PC 이미지에서 다음을 모두 구하세요.
   (a) 2026-03-14 오후에 연결된 USB 저장장치의 모델과 시리얼
   (b) 그 장치의 볼륨 레이블
   (c) 그 장치를 마운트한 사용자 계정
   (d) 연결 시각과 제거 시각 (KST)
   (e) 그 드라이브에서 열린 파일
 첨부: SYSTEM, SOFTWARE, jhkim/NTUSER.DAT, spark/NTUSER.DAT,
       UsrClass.dat 2개, setupapi.dev.log, winevt\Logs, $MFT, $J"

------------------------------------------------------------------
1. 첫 시도 (실패) — 드라이브 문자에서 출발했다
------------------------------------------------------------------
   ShellBags 에 E:\project 폴더가 보였다. 그래서 곧바로
   SYSTEM\MountedDevices 의 \DosDevices\E: 를 읽었다.

     \DosDevices\E: (228 bytes)
       _??_USBSTOR#Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07#
       7&1ec2a1c4&0#{53f56307-...}

   이것을 (a) 의 답으로 냈다: Generic Flash Disk, 시리얼 7&1ec2a1c4&0

   왜 틀렸나 (두 겹의 실수):
   (a) 드라이브 문자는 재사용된다. MountedDevices 의 \DosDevices\E: 에는
       "마지막으로 E: 를 차지한 장치" 만 남는다. 3월 14일에 꽂힌 장치가
       아니라 그 뒤 3월 20일에 꽂힌 다른 USB 였다.
   (b) 7&1ec2a1c4&0 은 두 번째 문자가 '&' 다. 장치가 시리얼을 보고하지
       않아 OS 가 만든 ID 이므로 "시리얼 번호" 라는 답 자체가 성립하지 않는다.

   교훈: 문자 -> 장치 방향이 아니라, 장치 -> 문자 방향으로 간다.

------------------------------------------------------------------
2. 방향 전환 — USBSTOR 에서 출발한다
------------------------------------------------------------------
   rip.exe -r clean\SYSTEM -p usbstor

     Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
       4C530001120521105424&0    LastWrite 2026-03-14 07:31:48Z
         FriendlyName = SanDisk Cruzer Blade USB Device
     Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07
       7&1ec2a1c4&0             LastWrite 2026-03-20 02:11:09Z
     Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP
       0018F30D9B21EFB0A9331B27&0  LastWrite 2026-02-27 08:41:55Z

   3월 14일 후보 = SanDisk Cruzer Blade / 4C530001120521105424
   두 번째 문자 'C' -> 장치가 보고한 실제 시리얼. OK

------------------------------------------------------------------
3. 시리얼로 MountedDevices 를 역방향 검색
------------------------------------------------------------------
   Select-String -Path mountdev.txt -Pattern '4C530001120521105424' -Context 2,2

     \??\Volume{9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}
       _??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#
       4C530001120521105424&0#{53f56307-...}

   -> 볼륨 GUID 는 나왔지만 \DosDevices\X: 항목이 없다.
      나중에 Generic Flash Disk 가 E: 를 덮어썼기 때문이다.
      당시의 드라이브 문자는 MountedDevices 로 확정할 수 없다.
      => 3단계(MountPoints2)와 7단계(LNK)로 우회한다.

------------------------------------------------------------------
4. 두 번째 시도 (실패) — 사용자 hive 를 하나만 봤다
------------------------------------------------------------------
   rip.exe -r jhkim\NTUSER.DAT -p mp2

     MountPoints2
       {6b8d0f11-2f4a-11f0-9b31-806e6f6e6963}
       C
       D

   볼륨 GUID {9f3a7c10-...} 가 없다.
   "USB 를 마운트한 사용자를 특정할 수 없다" 고 (c) 를 공란으로 두었다.

   왜 틀렸나:
   MountPoints2 는 사용자별 키다. 첨부에는 NTUSER.DAT 이 두 개
   (jhkim, spark) 있었는데 하나만 확인했다. 두 번째 hive 에 답이 있었다.

   rip.exe -r spark\NTUSER.DAT -p mp2

     MountPoints2
       {9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}   LastWrite 2026-03-14 07:05:02Z
         _LabelFromReg = USB_DATA
         BaseClass     = Volume
       E                                        LastWrite 2026-03-14 07:05:02Z

   -> spark 세션이 그 볼륨을 마운트했고, 그때 문자는 E: 였다.
      (MountedDevices 로는 못 얻은 문자를 여기서 회수했다)

   SID -> 계정 확인:
   SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
     S-1-5-21-...-1014  ProfileImagePath = C:\Users\spark

------------------------------------------------------------------
5. 볼륨 레이블 확정 (b)
------------------------------------------------------------------
   rip.exe -r SOFTWARE -p portdev | Select-String '4C530001' -Context 0,2

     SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#
     4C530001120521105424&0#{53f56307-...}
       FriendlyName = USB_DATA

   MountPoints2 의 _LabelFromReg 와 일치 -> 레이블 USB_DATA 확정

------------------------------------------------------------------
6. 시각 (d) — 두 시간대를 섞지 않는다
------------------------------------------------------------------
   최초 설치 (로컬):
     setupapi.dev.log -> Section start 2026/03/02 21:14:07.113

   연결/제거 (UTC):
     EvtxECmd.exe -d winevt\Logs --csv out --csvf evtx_all.csv
     Payload 에 4C530001120521105424 가 있는 레코드:
       2026-03-14T07:04:19Z  1006  Partition/Diagnostic
       2026-03-14T07:31:48Z  1006  Partition/Diagnostic

   DriverFrameworks-UserMode/Operational 은 이 이미지에 파일 자체가 없었다
   (Windows 10 기본 비활성). 대안 경로대로 Partition/Diagnostic 을 썼다.

   Enum\USBSTOR 인스턴스 키 LastWrite = 2026-03-14 07:31:48Z
     -> EVTX 의 두 번째 1006 과 일치. "마지막 갱신" 의 정체가 확인됐다.

   시간대: SYSTEM\ControlSet001\Control\TimeZoneInformation
           TimeZoneKeyName = Korea Standard Time (UTC+9)
     연결  2026-03-14 07:04:19Z + 9h = 2026-03-14 16:04:19 KST
     제거  2026-03-14 07:31:48Z + 9h = 2026-03-14 16:31:48 KST
     최초 설치 2026-03-02 21:14:07 (이미 로컬 = KST. 추가 변환 금지)

------------------------------------------------------------------
7. 파일 접근 (e)
------------------------------------------------------------------
   spark 의 Recent\*.lnk 를 파싱:
     salary.xlsx.lnk
       Local Base Path      = E:\project\salary.xlsx
       Drive Type           = 2 (removable)
       Volume Label         = USB_DATA          <- 5단계와 일치
       Volume Serial Number = 9C4A-71E3         <- 볼륨 GUID 와 다른 값이다
       Target Modified      = 2026-03-14 07:22:11Z

   spark 의 UsrClass.dat ShellBags:
     E:\ -> E:\project     (폴더를 탐색기로 열어 봤다)

   구간 내 실행 (BAM):
     2026-03-14 07:19:40Z \Device\HarddiskVolume3\Program Files\7-Zip\7zG.exe

------------------------------------------------------------------
8. 어느 방향으로 오간 파일인가
------------------------------------------------------------------
   C: 의 $UsnJrnl 에서 salary.xlsx 를 찾았다 -> 없다.
   이것이 정상이다. PC -> USB 방향(내보내기)은 대상 볼륨인 USB 에
   기록되고 C: 의 $UsnJrnl 에는 남지 않는다.

   같은 구간 C: 의 $UsnJrnl 에는 다음이 있었다:
     07:19:44  project_backup.7z   FileCreate|DataExtend|Close
     07:21:02  project_backup.7z   RenameNewName
   -> 7-Zip 으로 C: 에 압축을 만든 뒤 USB 로 옮긴 정황.
      LNK(E:\project\salary.xlsx)와 ShellBags(E:\project)가
      "USB 쪽에서 파일을 다뤘다" 를 보강한다.

------------------------------------------------------------------
정답
------------------------------------------------------------------
 (a) SanDisk Cruzer Blade, 시리얼 4C530001120521105424
 (b) 볼륨 레이블 USB_DATA
 (c) spark (S-1-5-21-...-1014), 당시 드라이브 문자 E:
 (d) 연결 2026-03-14 16:04:19 KST / 제거 2026-03-14 16:31:48 KST
     (최초 설치 2026-03-02 21:14:07 KST)
 (e) E:\project\salary.xlsx (LNK), E:\project 폴더 탐색(ShellBags)
```

## 막혔을 때 다음 체크

1. **시리얼에서 출발했는가** — 드라이브 문자에서 출발하면 문자 재사용에 걸린다
2. 시리얼의 두 번째 문자가 `&`인지 확인했는가 (OS 생성 ID면 동일성 주장 금지)
3. `MountedDevices`에 문자가 없다면 → `MountPoints2`와 LNK로 당시 문자를 회수했는가
4. `MountPoints2`를 **모든 사용자** `NTUSER.DAT`에서 확인했는가
5. SID를 `ProfileList`로 계정 이름으로 바꿨는가
6. 볼륨 레이블을 WPD `FriendlyName`과 LNK `Volume Label` 양쪽에서 확인했는가
7. `setupapi.dev.log`(로컬)와 EVTX·레지스트리(UTC)를 구분해 표기했는가
8. EVTX 채널이 없다면 `Partition/Diagnostic` → `System`(20001) → `setupapi.dev.log`로 내려갔는가
9. "내보낸 파일"을 `C:`의 `$UsnJrnl`에서 찾고 있지 않은가 (거기엔 없다)
10. 모든 hive에 `rla`를 돌렸는가
11. 활성 ControlSet을 `Select\Current`로 정했는가
12. 최종 답에 시리얼·문자·사용자·시각 **네 값이 모두** 들어 있는가

## 출처

- SRC-098 — Microsoft Learn, USB 장치 레지스트리 항목: `USBSTOR` 열거 구조, 장치 인스턴스 ID와 시리얼의 관계, 장치 인스턴스 경로 표기(`_??_USBSTOR#Disk&Ven_...#<인스턴스 ID>#{인터페이스 GUID}`)가 볼륨 매핑·WPD 키 이름에 그대로 쓰인다는 점
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM`·`SOFTWARE`·`NTUSER.DAT`의 파일 위치와 오프라인 경로 표기, `MountedDevices`가 ControlSet 밖에 있다는 구조
- SRC-099 — RegRipper 3.0 저장소: `usbstor`, `mountdev`, `mp2`, `portdev`, `bam`, `profilelist` 플러그인과 `rip.exe -r/-p/-f/-l` 옵션
- SRC-029 — Libyal liblnk, Windows Shortcut (LNK) 포맷 문서: LNK의 Volume Information 블록(드라이브 종류, 볼륨 시리얼 번호, 볼륨 레이블)과 Local Base Path 필드 정의
- **EVTX 채널과 Event ID(`1006`, `6416`, `20001`, DriverFrameworks 계열)의 존재·활성 여부와 페이로드 필드명은 Windows 버전·감사 정책에 따라 다르다.** 채널이 없는 것이 정상인 환경이 많으므로, 이 글은 우선순위와 대안 경로만 제시하고 특정 ID의 존재를 전제하지 않는다. 실제 출력은 EvtxECmd CSV에서 확인할 것
- RegRipper 플러그인·프로파일 이름(`-f system`, `-f software`)과 EvtxECmd의 `MapDescription`은 도구 버전에 따라 다를 수 있으므로 `rip.exe -l` 및 실제 CSV 헤더로 확인할 것
- `Windows Portable Devices\Devices` 서브키 이름 형식과 `MountPoints2` 하위 값(`_LabelFromReg`, `BaseClass`)의 존재 여부는 Windows 버전에 따라 다르므로 실제 hive에서 확인할 것
