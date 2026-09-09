---
id: FOR-0068
title: "ShellBags로 삭제된 폴더 이름과 USB 경로 복원하기"
slug: "shellbags"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["ShellBags", "BagMRU", "Bags", "NodeSlot", "NodeSlots", "MRUListEx", "UsrClass.dat", "shell item"]
file_paths: ["C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1", "C:\\Users\\<user>\\NTUSER.DAT"]
registry_paths: ["UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags", "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags", "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"]
event_ids: []
protocols: []
tools: ["ShellBags Explorer", "SBECmd", "RegistryExplorer", "RegRipper", "rla", "FTK Imager", "KAPE", "Timeline Explorer"]
commands: ["rip.exe -r UsrClass.dat -p shellbags", "SBECmd.exe -d C:\\case\\hives --csv C:\\case\\out", "rla.exe -f UsrClass.dat --out C:\\case\\clean"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["AbsolutePath", "ShellType", "NodeSlot", "MRUPosition", "LastWriteTime", "CreatedOn", "ModifiedOn", "AccessedOn", "MFTEntry", "MFTSequenceNumber", "HasExplored"]
file_formats: ["regf"]
primary_terms: ["ShellBags", "BagMRU", "폴더 탐색 흔적", "삭제된 폴더 이름"]
keywords: ["ShellBags", "BagMRU", "Bags", "NodeSlot", "MRUListEx", "UsrClass.dat", "shell item", "폴더 탐색", "삭제된 폴더", "USB 경로", "네트워크 공유", "SBECmd", "ShellBags Explorer", "탐색기 흔적"]
aliases: ["쉘백", "shellbag", "폴더 열어본 기록", "삭제된 폴더 이름 찾기", "usb 폴더 구조", "탐색기로 뭘 봤나", "bagmru"]
symptom_keywords: ["삭제된 폴더 이름을 알고 싶다", "USB 안의 폴더 구조가 필요하다", "폴더를 열어봤는지 확인하고 싶다", "NTUSER.DAT에 BagMRU가 없다", "레지스트리 값이 숫자 이름으로만 있다", "네트워크 공유에 접근했는지"]
related: ["FOR-0058", "FOR-0062", "FOR-0066", "FOR-0051"]
source_ids: ["SRC-017", "SRC-004", "SRC-100"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

ShellBags는 탐색기가 폴더별 뷰 설정을 저장하려고 만든 부산물이지만, 그 부산물인 `BagMRU` 트리에 **이미 삭제되거나 언마운트된 폴더·USB·네트워크 경로의 이름이 그대로 남아** 있으므로, 디스크에 흔적이 없는 폴더 계층을 복원하는 거의 유일한 수단이다.

## 어떤 문제에서 필요한가

- "삭제된 폴더의 이름을 구하시오" — 디스크에서 폴더가 사라졌는데 이름을 알아야 한다
- "USB 안에 어떤 폴더가 있었는가" — USB 이미지가 없고 PC 이미지만 있다
- "피의자가 접근한 네트워크 공유 경로는?" — `\\10.10.20.5\share\...`
- "이 폴더를 사용자가 실제로 열어 봤는가" — 자동 생성 파일과 사람의 탐색을 구분해야 한다
- 압축 파일 안의 폴더, ZIP 내부 탐색 흔적

`$MFT`가 "그 폴더가 이 볼륨에 있었다"를 말해 준다면, ShellBags는 **"그 폴더를 이 사용자가 탐색기로 열었다"**를 말해 준다. 볼륨 자체가 없어졌을 때도 남는 것이 결정적 차이다.

## 문제에서 처음 볼 단서

1. 첨부에 `UsrClass.dat`이 있다 → ShellBags는 무조건 확인 대상
2. 지문에 "폴더", "경로", "디렉터리 구조", "어디에 저장했나"가 나온다
3. `USBSTOR`에서 장치는 찾았는데 **그 안의 내용**을 물어본다
4. 레지스트리 트리에 `0`, `1`, `2`, `3` 같은 숫자 이름 서브키가 계층으로 늘어서 있고 값이 전부 이진이다 → `BagMRU`다
5. `$MFT`·`$UsnJrnl`에 폴더 이름이 전혀 없는데 문제는 폴더 이름을 요구한다

## 30초 절차

```powershell
rip.exe -r "C:\case\UsrClass.dat" -p shellbags > shellbags.txt
```

GUI라면 ShellBags Explorer에 `UsrClass.dat`을 올리는 것이 가장 빠르다. 트리 좌측이 복원된 폴더 계층이고, 우측 그리드가 항목별 시각이다.

```text
ShellBags Explorer -> File -> Load offline hive -> UsrClass.dat
SBECmd.exe -d C:\case\hives --csv C:\case\out
```

RegistryExplorer로 열 때의 경로는 다음 하나다. **`NTUSER.DAT`이 아니다.**

```text
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```

## 상세 절차

### 1단계 — hive 확보와 로그 반영

`UsrClass.dat`은 사용자가 로그온 중이면 잠겨 있고, 최신 변경이 `.LOG1`/`.LOG2`에만 있을 수 있다. **폴더를 하나 여는 것만으로 갱신되는 키**라서 트랜잭션 로그 미반영의 영향이 특히 크다.

```powershell
# UsrClass.dat, UsrClass.dat.LOG1, UsrClass.dat.LOG2 를 같은 폴더에 꺼낸 뒤
rla.exe -f "C:\case\UsrClass.dat" --out "C:\case\clean"
```

추출 경로는 사용자마다 다르다. **`C:\Users` 아래 모든 프로필에서 꺼낸다.**

```text
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat
C:\Users\<user>\NTUSER.DAT                 (보조 BagMRU)
```

### 2단계 — 두 개의 BagMRU 위치

| hive | 키 경로 | 무엇이 들어 있나 |
| --- | --- | --- |
| `UsrClass.dat` | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` | **주 트리.** 로컬 폴더·USB·네트워크·ZIP 내부까지 대부분 여기 |
| `UsrClass.dat` | `Local Settings\Software\Microsoft\Windows\Shell\Bags` | `NodeSlot`이 가리키는 뷰 설정 저장소 |
| `UsrClass.dat` | `Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` | 32비트 컨텍스트용. 환경에 따라 존재. 놓치기 쉽다 |
| `NTUSER.DAT` | `Software\Microsoft\Windows\Shell\BagMRU`, `...\Bags` | 데스크톱 등 일부 항목. 주 트리보다 훨씬 작지만 **여기만 남은 항목이 있을 수 있다** |
| `NTUSER.DAT` | `Software\Microsoft\Windows\ShellNoRoam\BagMRU` | XP 계열 레거시 위치 |

**네 위치를 모두 파싱한다.** ShellBags Explorer/SBECmd에 `UsrClass.dat`과 `NTUSER.DAT`을 함께 주면 한 번에 처리한다.

### 3단계 — BagMRU 트리 구조

`BagMRU`는 **폴더 계층을 그대로 옮긴 트리**다. 루트가 데스크톱이고, 그 아래 숫자 서브키가 한 단계씩 내려간다.

```text
BagMRU                          <- 데스크톱 (루트)
 ├ NodeSlot     = 1
 ├ NodeSlots    = (REG_BINARY)  <- 어느 Bags 슬롯이 사용 중인지
 ├ MRUListEx    = (REG_BINARY)  <- 자식 0,1,2.. 를 최근 사용 순으로 나열
 ├ 0            = (REG_BINARY)  <- 자식 키 "0" 에 해당하는 shell item 바이트
 ├ 1            = (REG_BINARY)
 ├ 0\           <- 서브키. 여기 안의 값 이름도 다시 0,1,2..
 │   ├ NodeSlot  = 12
 │   ├ MRUListEx
 │   ├ 0         = (REG_BINARY)
 │   └ 0\ ...
 └ 1\ ...
```

핵심 규칙 3개다.

| 규칙 | 내용 |
| --- | --- |
| 이름 | 서브키 `N`의 **이름 문자열이 정보가 아니다.** 그 폴더 이름은 **부모 키의 값 `N`** 에 든 shell item 바이트 안에 있다 |
| 순서 | `MRUListEx`는 4바이트 리틀엔디언 인덱스를 최근 사용 순으로 나열하고 `FF FF FF FF`로 끝난다. **첫 인덱스가 가장 최근에 접근한 자식** |
| 뷰 설정 | `NodeSlot` 값이 `Bags\<NodeSlot>\Shell` 을 가리킨다. 그 아래에 `ItemPos...`, `Mode`, `IconSize`, `ColInfo` 등 창 설정이 있다 |

`Bags\<N>\Shell` 아래에 `ItemPos1920x1080(1)` 같은 값이 있으면 **그 해상도의 창에서 아이콘을 직접 배치했다는 뜻**이므로, 단순 통과가 아니라 사람이 그 폴더를 붙잡고 작업한 근거가 된다.

### 4단계 — shell item 안에 무엇이 들어 있나

각 이진 값은 `ITEMIDLIST`의 한 조각(shell item)이다. 첫 2바이트가 크기, 그다음 1바이트가 **class type**이고, 그 값으로 항목 종류가 갈린다.

| class type | 항목 종류 | 파서가 붙이는 이름 |
| --- | --- | --- |
| `0x1F` | 루트 폴더 (Known Folder GUID) | `Root folder` — 내 PC, 네트워크, 휴지통 등 |
| `0x2X` | 볼륨 | `Volume` — `C:\`, `E:\` 같은 드라이브 |
| `0x31` | **디렉터리** | `Directory` — 가장 중요한 종류 |
| `0x32` | 파일 | `File entry` |
| `0x4X` | 네트워크 위치 | `Network location` — `\\host\share` |
| `0x61` | URI | FTP/HTTP 등 |
| `0x71` | 제어판 | `Control Panel` |

`0x31` 디렉터리 항목 안에는 최소한 다음이 들어 있다.

| 필드 | 내용 | 주의 |
| --- | --- | --- |
| 짧은 이름(8.3) | `PROJEC~1` 형태 | 긴 이름은 확장 블록에 따로 있다 |
| 수정 시각 | **DOS date/time** | 2초 단위, **로컬 시각**. UTC가 아니다 |
| 파일 속성 | `FILE_ATTRIBUTE_DIRECTORY` 등 | 폴더/파일 판정 |
| 확장 블록 `0xBEEF0004` | 긴 이름(UTF-16LE), 생성·접근 DOS 시각 | 버전에 따라 필드가 늘어난다 |
| 확장 블록의 파일 참조 | **MFT 엔트리 번호 + 시퀀스 번호** | 확장 블록 버전이 충분히 높을 때만 존재 |

**MFT 엔트리 번호가 들어 있는 것이 ShellBags의 숨은 무기다.** 폴더 이름이 아니라 번호로 `$MFT`를 조회하면 이름이 바뀌었거나 삭제된 엔트리도 특정된다 ([FOR-0021](./mft-basics.html)).

바이트 오프셋 단위의 수동 파싱은 확장 블록 버전마다 필드 위치가 달라진다. **오프셋을 세지 말고 파서 출력을 쓴다** — 이 글은 필드의 존재와 의미까지만 단정한다.

### 5단계 — 파서로 뽑아 표로 읽는다

```powershell
# 폴더에 UsrClass.dat / NTUSER.DAT 을 모아 놓고 일괄 처리
SBECmd.exe -d "C:\case\clean" --csv "C:\case\out"
```

```powershell
# 키트 안 도구만으로 갈 때
rip.exe -r "C:\case\clean\UsrClass.dat" -p shellbags > shellbags.txt
```

RegRipper 출력 예시다.

```text
Shellbags
Local Settings\Software\Microsoft\Windows\Shell\BagMRU

2026-04-08 14:02:11Z  Desktop\My Computer\E:\  [Volume]
2026-04-08 14:02:19Z  Desktop\My Computer\E:\proj_backup  [Directory]
2026-04-08 14:03:44Z  Desktop\My Computer\E:\proj_backup\2026_price  [Directory]
2026-04-08 14:11:02Z  Desktop\Network\10.10.20.5\design  [Network]
2026-03-30 21:40:55Z  Desktop\My Computer\C:\Users\hjlee\Documents\salary  [Directory]
```

## 출력 필드 해석

SBECmd/ShellBags Explorer의 주요 컬럼이다.

| 컬럼 | 의미 | 어떻게 쓰나 |
| --- | --- | --- |
| `AbsolutePath` | 트리를 거슬러 재구성한 전체 경로 | **답으로 그대로 쓰는 값.** 삭제된 폴더 이름이 여기 나온다 |
| `ShellType` | shell item class type의 이름 | `Directory`/`Volume`/`Network`를 구분해 USB·공유 판정 |
| `Value` | 그 단계의 항목 이름 | 마지막 구성요소 |
| `NodeSlot` | `Bags\<N>` 슬롯 번호 | 뷰 설정이 실제로 저장됐는가 = 창을 열었는가의 보조 근거 |
| `MRUPosition` | `MRUListEx` 안의 위치 | `0`이면 그 부모에서 **가장 최근에 접근한 자식** |
| `LastWriteTime` | 그 `BagMRU` 키의 LastWrite (FILETIME, **UTC**) | 사실상 "이 폴더에 마지막으로 무언가 일어난 시각" |
| `CreatedOn` / `ModifiedOn` / `AccessedOn` | shell item 안에 박힌 **대상 폴더의** DOS 시각 | **로컬 시각, 2초 단위.** 기록된 시점의 스냅숏이다 |
| `MFTEntry` / `MFTSequenceNumber` | 확장 블록의 파일 참조 | `$MFT` 조회 키. 비어 있는 행도 많다 |
| `HasExplored` | 뷰 설정까지 만들어졌는가 | 참이면 실제로 창으로 열어 봤다는 쪽에 무게 |
| `FirstInteracted` / `LastInteracted` | 파서가 유도한 상호작용 시각 | 항목 종류에 따라 비어 있다. 근거로 쓸 때 원본 필드를 함께 제시 |

### 두 종류의 시각을 절대 섞지 않는다

| 시각 | 단위/기준 | 무엇의 시각인가 |
| --- | --- | --- |
| `LastWriteTime` | FILETIME, 1601-01-01 UTC 기준 100ns → **UTC** | **레지스트리 키**가 갱신된 시각 ≈ 사용자가 탐색한 시각 |
| `CreatedOn`/`ModifiedOn`/`AccessedOn` | DOS date/time, 2초 단위 → **로컬 시각** | **대상 폴더 자체**의 타임스탬프. 탐색 시각이 아니다 |

`LastWriteTime`을 KST로 답하려면 +9시간 한다. 반대로 `ModifiedOn`은 이미 그 PC의 로컬 시각이므로 **더하면 안 된다.** 시간대 기준은 `SYSTEM\ControlSet001\Control\TimeZoneInformation`으로 먼저 확정한다 ([FOR-0054](./system-timezone.html)).

이 두 시각의 조합이 강력하다. **`ModifiedOn`은 "탐색 당시 그 폴더의 수정 시각"의 스냅숏**이므로, 현재 `$MFT`의 값과 다르면 그 사이에 폴더가 변경됐거나 타임스탬프가 조작된 것이다 ([FOR-0038](./timestomp-detection.html)).

## pivot: 다음에 볼 artifact

| ShellBags에서 얻은 것 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| `E:\` 같은 이동식 볼륨 경로 | `SYSTEM\ControlSet001\Enum\USBSTOR`, `SYSTEM\MountedDevices` | 그 드라이브 문자가 어느 USB였는지, 연결 시각 |
| 볼륨 GUID / 드라이브 문자 | `NTUSER.DAT\...\Explorer\MountPoints2` | 그 사용자가 실제로 마운트했는가 |
| `\\host\share` 경로 | `MountPoints2`의 `##host#share`, 4624 Logon Type 3 | 원격 접근 사실과 계정 |
| `MFTEntry` 번호 | `$MFT` ([FOR-0021](./mft-basics.html)) | 현재 이름·삭제 여부·MACB |
| 폴더 이름 | `RecentDocs`, LNK, Jump List | 그 폴더 **안의 파일**을 열었는가 |
| 탐색 시각 | `UserAssist` ([FOR-0061](./userassist.html)), BAM | 같은 시각대에 어떤 프로그램을 실행했는가 |
| 사용자별 `UsrClass.dat` | `SOFTWARE\...\ProfileList` | 어느 SID의 활동인가 |
| ZIP 내부 경로 항목 | `$MFT`의 그 압축 파일, 브라우저 다운로드 | 압축 파일의 출처 |

## 흔한 함정

- **`NTUSER.DAT`에서 `BagMRU`를 찾고 "없다"고 결론 내는 것** → Windows 7 이후 주 트리는 `UsrClass.dat`에 있다 → `AppData\Local\Microsoft\Windows\UsrClass.dat`을 꺼낸다. `NTUSER.DAT` 쪽은 보조로만 본다.
- **파서 없이 트리를 손으로 읽는 것** → 서브키 이름은 `0`, `1`, `2`뿐이고 폴더 이름은 부모 키의 이진 값 안에 있다. 확장 블록 버전에 따라 필드 위치가 달라 손으로는 사실상 해석 불가다 → ShellBags Explorer/SBECmd, RegistryExplorer 플러그인, RegRipper `shellbags` 중 하나를 반드시 쓴다.
- **ShellBags를 파일 접근 증거로 쓰는 것** → ShellBags는 **폴더**를 탐색기 창으로 열었다는 증거다. 그 안의 파일을 읽었다는 뜻이 아니다 → 파일 접근은 `RecentDocs`·LNK·Jump List·`$MFT`의 `$SI` accessed로 간다.
- **키 `LastWrite`를 "이 폴더를 방문한 시각"으로 단정하는 것** → 자식이 추가되거나 `MRUListEx`가 재배열될 때도 갱신된다. 부모 키는 자식 폴더 하나를 새로 열 때마다 갱신된다 → "그 시각에 이 계층에서 무언가 있었다"까지만 주장하고, 자식 항목의 시각과 함께 제시한다.
- **`ModifiedOn`에 +9시간을 더하는 것** → shell item의 DOS date/time은 이미 로컬 시각이다. FILETIME인 `LastWriteTime`에만 보정한다 → 컬럼별로 기준을 확인하고 표에 단위를 명시한다.
- **항목이 있으면 사람이 열었다고 단정하는 것** → 설치 프로그램, 저장/열기 대화상자, 일부 셸 확장이 항목을 만들 수 있다 → `NodeSlot`/`HasExplored`/`Bags`의 `ItemPos` 존재 여부로 "창을 실제로 열었는가"를 보강하고, `UserAssist`·`RecentDocs`와 교차한다.
- **항목이 없으면 방문하지 않았다고 단정하는 것** → 탐색기가 아닌 프로그램(콘솔 `cd`, 스크립트, 애플리케이션 자체 파일 대화상자 일부)으로 접근하면 남지 않는다. 사용자가 `Bags`/`BagMRU`를 삭제했을 수도 있다 → 부재는 반증이 아니다. `$UsnJrnl`·LNK로 보완한다.
- **사용자 한 명만 보는 것** → ShellBags는 프로필별이다 → `C:\Users` 아래 모든 `UsrClass.dat`을 센 뒤 시작한다 ([FOR-0051](./registry-hive-map.html)).
- **`rla`를 건너뛰는 것** → 폴더를 열 때마다 갱신되는 키라 마지막 탐색이 `.LOG1`에만 있을 수 있다 → 반드시 반영 후 파싱한다.
- **`Wow6432Node` 아래 사본을 빼먹는 것** → 32비트 컨텍스트의 탐색 흔적이 그쪽에만 남는 경우가 있다 → 파서에 hive 전체를 주고 결과 개수를 비교한다.

## 교차검증

같은 "이 폴더를 열었다"를 최소 두 곳에서 확인한다.

```powershell
# 1) ShellBags — 경로 자체
Select-String -Path "C:\case\out\*_UsrClass.csv" -Pattern 'proj_backup'
```

```powershell
# 2) MountPoints2 — 그 드라이브를 이 사용자가 마운트했는가
rip.exe -r "C:\case\clean\NTUSER.DAT" -p mp2
```

```powershell
# 3) USBSTOR — 드라이브 문자의 실체와 연결 시각
rip.exe -r "C:\case\clean\SYSTEM" -p usbstor
```

```powershell
# 4) RecentDocs / LNK — 그 폴더 안의 파일을 실제로 열었는가
rip.exe -r "C:\case\clean\NTUSER.DAT" -p recentdocs
```

| 조합 | 해석 |
| --- | --- |
| ShellBags + `MountPoints2` + `USBSTOR` 일치 | 그 사용자가 그 USB를 꽂고 그 폴더를 열었다 — 결론 확정 |
| ShellBags에만 있고 `USBSTOR`에 장치 없음 | 다른 PC에서 로밍된 프로필이거나 네트워크/가상 경로. `ShellType` 재확인 |
| ShellBags에는 있고 `$MFT`에 폴더 없음 | **삭제된 폴더.** ShellBags가 이름의 유일한 근거가 된다 |
| ShellBags 시각과 `$UsnJrnl` 폴더 생성 시각이 어긋남 | 폴더가 나중에 다시 만들어졌거나 시스템 시각 조작 |

## mini walkthrough

```text
문제:
"사용자 hjlee가 외부 저장장치로 옮긴 자료의 폴더 이름과 그 시각(KST)을 구하시오.
 USB 이미지는 확보되지 않았다.
 첨부: SYSTEM, SOFTWARE, SAM, NTUSER.DAT(+LOG1/2), UsrClass.dat(+LOG1/2)"

1. 첫 시도 (실패):
   RegistryExplorer 로 NTUSER.DAT 을 열고
   NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU 로 이동
   -> 서브키가 2개뿐이고 전부 Desktop 관련. USB 경로가 없다.
      "이 사용자는 USB 폴더를 열지 않았다"고 결론 낼 뻔했다.

   왜 틀렸나:
   Windows 7 이후 ShellBags 의 주 트리는 UsrClass.dat 에 있다.
   NTUSER.DAT 쪽은 데스크톱 등 일부 항목만 담은 보조 트리다.

2. 접근 변경 — UsrClass.dat + 로그 반영
   rla.exe -f UsrClass.dat --out clean\
   SBECmd.exe -d clean\ --csv out\

   AbsolutePath                                      ShellType  MRUPosition  LastWriteTime
   Desktop\My Computer\E:\                           Volume     0            2026-04-08 14:02:11Z
   Desktop\My Computer\E:\proj_backup                Directory  0            2026-04-08 14:02:19Z
   Desktop\My Computer\E:\proj_backup\2026_price     Directory  0            2026-04-08 14:03:44Z
   Desktop\My Computer\C:\Users\hjlee\Documents\salary  Directory 1          2026-03-30 21:40:55Z

3. 두 번째로 틀린 판단:
   "E: 는 D 다음 드라이브니까 두 번째 파티션"이라고 가정했다.
   -> MountedDevices 를 보니 \DosDevices\E: 의 이진 값이
      \??\USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001231205117495&0#{...}
      = 이동식 USB 였다. 파티션이 아니다.
      드라이브 문자는 추측하지 않고 MountedDevices 로 확인한다.

4. 사용자 특정
   SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
     S-1-5-21-3623811015-3361044348-30300820-1002 -> C:\Users\hjlee
   UsrClass.dat 을 꺼낸 프로필이 hjlee 이므로 활동 주체 확정.

5. 시간대 보정
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time,  ActiveTimeBias = 0xFFFFFDE4 (= -540분)
   LastWriteTime 은 FILETIME(UTC) 이므로 +9h
     2026-04-08 14:03:44Z -> 2026-04-08 23:03:44 KST

   주의: 같은 행의 ModifiedOn 은 DOS date/time = 이미 로컬 시각이므로 더하지 않는다.

6. 교차검증
   rip.exe -r clean\NTUSER.DAT -p mp2
     -> {6ac1... } 및 E 항목 존재 = hjlee 세션에서 마운트됨
   rip.exe -r clean\SYSTEM -p usbstor
     -> Cruzer Blade, LastArrival 2026-04-08 14:01:58Z (= 23:01:58 KST)
   USB 연결 13초 뒤 E:\ 탐색, 21초 뒤 proj_backup 진입 — 순서가 자연스럽다.

7. $MFT 대조
   E: 는 이미지가 없으므로 확인 불가.
   C:\Users\hjlee\Documents\salary 는 $MFT 에 없다 -> 삭제된 폴더.
   ShellBags 가 그 이름의 유일한 근거다.

정답:
  E:\proj_backup\2026_price — 2026-04-08 23:03:44 KST 탐색
  (원본 폴더 C:\Users\hjlee\Documents\salary 는 삭제됨, ShellBags 에만 이름이 남음)
```

1단계와 3단계가 이 글의 요점이다. **hive를 잘못 골라 "흔적 없음"으로 결론 내는 것, 드라이브 문자를 추측하는 것**이 ShellBags 문제의 대표적 두 오답이다.

## 막혔을 때 다음 체크

1. `UsrClass.dat`을 열었는가 — `NTUSER.DAT`만 봤다면 그것이 원인이다
2. `rla`로 `.LOG1`/`.LOG2`를 반영했는가
3. `NTUSER.DAT`의 `Shell\BagMRU`, `ShellNoRoam\BagMRU`, `Wow6432Node` 사본까지 봤는가
4. `C:\Users` 아래 **모든** 프로필의 `UsrClass.dat`을 처리했는가
5. `ShellType`을 확인했는가 — `Volume`/`Network`/`Directory`에 따라 pivot 대상이 다르다
6. 드라이브 문자를 `MountedDevices`로 실체 확인했는가 — 추측 금지
7. `LastWriteTime`(UTC)과 `ModifiedOn`(로컬)을 섞지 않았는가
8. `MFTEntry`가 있는 행을 `$MFT`로 조회했는가 — 이름이 바뀐 폴더도 특정된다
9. 항목이 하나도 없다면 → 탐색기가 아닌 경로로 접근했을 가능성. `$UsnJrnl`·LNK·Jump List·콘솔 히스토리로 전환
10. 파서 결과가 비었다면 → hive를 잘못 지정했거나 플러그인 이름이 틀렸다. `rip.exe -l`로 플러그인 이름을 확인한다

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `UsrClass.dat`이 `HKCU\Software\Classes`로 마운트된다는 점, 사용자 hive의 위치
- SRC-004 — Eric Zimmerman 문서: ShellBags Explorer/SBECmd의 출력 컬럼, RegistryExplorer의 ShellBags 플러그인, `rla`의 트랜잭션 로그 반영
- SRC-100 — Microsoft Learn, Known Folder GUIDs: `0x1F` 루트 폴더 항목의 GUID가 어떤 폴더에 대응하는지 대조표
- shell item(`ITEMIDLIST`)의 **바이트 오프셋과 확장 블록(`0xBEEF0004`) 내부 필드 위치는 확장 블록 버전마다 다르므로 이 글은 필드의 존재와 의미까지만 단정하고 오프셋은 파서에 맡긴다.** 수동 파싱이 필요하면 libyal의 shell item 포맷 문서를 참조할 것 (현재 `research/sources.json`에 미등록)
- SBECmd/ShellBags Explorer의 컬럼명(`HasExplored`, `FirstInteracted` 등)과 RegRipper 플러그인 출력 형식은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- `Wow6432Node` 아래 `BagMRU` 사본의 존재 여부는 환경에 따라 다르므로 실제 hive에서 확인할 것
- mini walkthrough의 시각·SID·시리얼은 설명을 위한 예시 값이다
