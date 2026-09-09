---
id: FOR-0080
title: "Registry 종합 CTF 풀이: USB 자료 반출 사건을 hive 5개로 끝까지"
slug: "registry-ctf-walkthrough"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["SAM", "SYSTEM", "SOFTWARE", "NTUSER.DAT", "UsrClass.dat", "USBSTOR", "MountedDevices", "MountPoints2", "UserAssist", "BAM", "ShellBags", "RecentDocs", "TypedPaths", "Run"]
file_paths: ["C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"]
registry_paths: ["SYSTEM\\Select", "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation", "SYSTEM\\ControlSet001\\Enum\\USBSTOR", "SYSTEM\\MountedDevices", "SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "ShellBags Explorer", "AppCompatCacheParser", "FTK Imager", "Timeline Explorer", "DCode"]
commands: ["rla.exe -d C:\\case\\hives --out C:\\case\\clean", "rip.exe -l", "rip.exe -r SYSTEM -p usbstor"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Current", "ActiveTimeBias", "TimeZoneKeyName", "ProfileImagePath", "MRUListEx", "LastArrival", "LastRemoval", "Run Count", "Last Executed"]
file_formats: ["regf"]
primary_terms: ["Registry 종합 풀이", "레지스트리 CTF", "hive 종합 분석"]
keywords: ["Registry CTF", "종합 풀이", "hive 분석 순서", "USB 반출", "USBSTOR", "MountedDevices", "MountPoints2", "ShellBags", "UserAssist", "BAM", "TypedPaths", "Run 키", "타임라인"]
aliases: ["레지스트리 문제 풀이", "hive 분석 순서", "레지스트리 ctf", "usb 반출 분석", "레지스트리 종합", "hive 뭐부터"]
symptom_keywords: ["레지스트리 hive를 어디서부터 봐야 할지 모르겠다", "USB 반출을 증명해야 한다", "hive가 여러 개인데 순서를 모르겠다", "증거를 시간순으로 정리해야 한다", "답변을 어떻게 써야 할지 모르겠다"]
related: ["FOR-0051", "FOR-0066", "FOR-0067", "FOR-0074"]
source_ids: ["SRC-017", "SRC-099", "SRC-098", "SRC-019"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

레지스트리 종합 문제는 **hive 순서(SAM → SYSTEM → SOFTWARE → NTUSER.DAT → UsrClass.dat)와 두 개의 전제(활성 ControlSet, 시간대)를 먼저 고정**한 뒤 계정 → 장치 → 실행 → 파일 접근 → 의도 → 지속성 순으로 쌓아 올리면, 마지막에 시간순 표 하나로 답변이 완성된다.

## 어떤 문제에서 필요한가

- 첨부가 `SAM`, `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `UsrClass.dat` 세트로 통째로 주어진다
- "누가, 언제, 어떤 장치로, 무슨 파일을 가져갔는가"를 한 번에 물어본다
- 배점이 큰 시나리오 문제로 소문항이 5~10개 붙어 있다
- 답을 시간순으로 서술하라고 요구한다
- 개별 artifact는 아는데 **순서와 연결**이 안 잡힌다

## 문제에서 처음 볼 단서

1. hive 개수를 센다 — 사용자 hive가 몇 명 것인지가 조사 범위다
2. `.LOG1`/`.LOG2`가 함께 있는가 — 있으면 반드시 `rla`부터
3. 지문의 동사: "실행", "복사", "접근", "연결", "등록" — 각각 다른 artifact다
4. 답 형식이 KST인지 UTC인지
5. `UsrClass.dat`이 있으면 ShellBags 문항이 있다고 보면 된다

## 30초 절차

```powershell
rla.exe -d "C:\case\hives" --out "C:\case\clean"
```

전제 두 개를 먼저 고정한다. 이 두 값 없이 뒤의 모든 시각은 무의미하다.

```text
1) SYSTEM\Select                      -> Current = 1  => ControlSet001
2) SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName / ActiveTimeBias -> 모든 FILETIME 을 KST 로 보정할 근거
```

## 상세 절차

### 시나리오

```text
"외주 인력이 야간에 사무실 PC 에서 USB 로 자료를 반출했다는 신고입니다.
 아래 hive 로 다음을 판정하시오.
  ① 반출에 사용된 계정과 그 계정의 성격
  ② 사용된 USB 장치와 연결/제거 시각 (KST)
  ③ 그 계정이 실행한 도구
  ④ 접근한 파일과 폴더
  ⑤ 반출 의도를 보여 주는 흔적
  ⑥ 지속성(재접속용) 흔적
 첨부: SAM, SYSTEM, SOFTWARE, SECURITY (+각 .LOG1/.LOG2)
       jhkim/NTUSER.DAT, jhkim/UsrClass.dat
       tempadm/NTUSER.DAT, tempadm/UsrClass.dat (+각 .LOG1/.LOG2)"
```

### 0단계 — 로그 반영과 hive 확인

```powershell
# 모든 hive 를 한 폴더에 모으고 로그를 반영한다
rla.exe -d "C:\case\hives" --out "C:\case\clean"
```

```bash
# 정말 hive 인지, dirty 였는지 확인
for f in SAM SYSTEM SOFTWARE SECURITY; do xxd -l 16 "$f"; done
```

반영 전 hive도 **지우지 않고 남긴다.** 삭제된 항목이 반영 전 상태에만 남아 있을 수 있다 ([FOR-0078](./registry-deleted-keys.html)).

### 1단계 — SAM: 계정 목록과 성격

```powershell
rip.exe -r "C:\case\clean\SAM" -p samparse > 01_sam.txt
```

```text
Machine SID : S-1-5-21-3623811015-3361044348-30300820

Username        : Administrator [500]
  Account Created : 2025-09-29 02:14:07Z
  Last Login Date : Never
  Account Disabled

Username        : jhkim [1001]
  Account Created : 2025-09-29 02:31:55Z
  Last Login Date : 2026-04-08 00:12:40Z
  Login Count     : 214

Username        : tempadm [1003]
  Account Created : 2026-04-08 12:40:11Z      <- 사건 당일 생성
  Last Login Date : 2026-04-08 12:55:38Z
  Login Count     : 1
  Password does not expire
```

| 관측 | 판정 |
| --- | --- |
| `tempadm` 생성 시각이 사건 당일, 로그온 1회 | **사건용으로 만든 계정** |
| RID 1002가 비어 있다 | 그 번호의 계정이 삭제된 적이 있다. 별도 확인 대상 |
| 머신 SID 확보 | 이후 모든 SID의 로컬/도메인 판별 기준 |

머신 SID를 여기서 반드시 적어 둔다 ([FOR-0052](./sam-user-accounts.html)).

### 2단계 — SYSTEM: 전제 2개 + 장치

#### ① 활성 ControlSet

```text
SYSTEM\Select
  Current = 1   -> ControlSet001
```

#### ② 시간대

```text
SYSTEM\ControlSet001\Control\TimeZoneInformation
  TimeZoneKeyName  = Korea Standard Time
  Bias             = 0xFFFFFDE4  (= -540 분)
  ActiveTimeBias   = 0xFFFFFDE4  (= -540 분)
  DaylightBias     = 0
```

`UTC = 로컬 + Bias`이므로 `Bias = -540`은 로컬이 UTC+9라는 뜻이다. **레지스트리의 FILETIME은 전부 UTC이므로 답을 KST로 낼 때 +9시간 한다** ([FOR-0054](./system-timezone.html)).

#### ③ USB 장치

```powershell
rip.exe -r "C:\case\clean\SYSTEM" -p usbstor > 02_usbstor.txt
```

```text
SYSTEM\ControlSet001\Enum\USBSTOR
Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
  4C530001231205117495&0
    FriendlyName  : SanDisk Cruzer Blade USB Device
    Properties\{83da6326-97a6-4088-9453-a1923f573b29}
      0064 (최초 설치) : 2026-04-08 12:58:03Z
      0066 (마지막 연결): 2026-04-08 13:01:58Z
      0067 (마지막 제거): 2026-04-08 13:52:33Z
```

인스턴스 ID `4C530001231205117495&0`에서 **두 번째 문자가 `&`가 아니므로 장치가 실제 시리얼을 보고한 것**이다. `&`가 두 번째 문자면 시리얼이 없는 장치이고 그 문자열로는 개별 식별이 안 된다 ([FOR-0066](./usbstor.html)).

#### ④ 드라이브 문자와 볼륨 GUID

```powershell
rip.exe -r "C:\case\clean\SYSTEM" -p mountdev > 03_mounteddev.txt
```

```text
SYSTEM\MountedDevices
\DosDevices\C:      -> (12바이트: 디스크 서명 + 오프셋)  = 내장 디스크
\DosDevices\E:      -> \??\USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
                        #4C530001231205117495&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
\??\Volume{7ac2f19d-3b41-11f0-9c22-8c16455a2d70}
                    -> (위와 같은 문자열)
```

**이것이 연결의 핵심 고리다.**

| 얻은 것 | 어디서 |
| --- | --- |
| USB 시리얼 → 드라이브 문자 `E:` | `\DosDevices\E:`의 이진 데이터에 시리얼 문자열 |
| USB 시리얼 → 볼륨 GUID | `\??\Volume{...}`의 이진 데이터가 **같은 문자열** |
| 볼륨 GUID → 사용자 | 그 GUID가 어느 사용자의 `MountPoints2`에 있는가 |

드라이브 문자는 **추측하지 않는다.** 이 표의 이진 데이터가 유일한 근거다 ([FOR-0067](./mounteddevices.html)).

#### ⑤ BAM: 사용자별 실행

```powershell
rip.exe -r "C:\case\clean\SYSTEM" -p bam > 04_bam.txt
```

```text
SYSTEM\ControlSet001\Services\bam\State\UserSettings\
S-1-5-21-3623811015-3361044348-30300820-1003
  \Device\HarddiskVolume3\Windows\System32\robocopy.exe   2026-04-08 13:12:05Z
  \Device\HarddiskVolume3\Program Files\7-Zip\7zFM.exe    2026-04-08 13:07:44Z
  \Device\HarddiskVolume3\Windows\System32\cmd.exe        2026-04-08 13:05:12Z
```

값 데이터의 **앞 8바이트가 FILETIME**이다. 키 LastWrite가 아니다 ([FOR-0071](./bam-dam.html)). `HarddiskVolume3`이 어느 드라이브인지는 `MountedDevices`로 환산한다.

### 3단계 — SOFTWARE: SID ↔ 사용자, OS 정보

```powershell
rip.exe -r "C:\case\clean\SOFTWARE" -p profilelist > 05_profilelist.txt
rip.exe -r "C:\case\clean\SOFTWARE" -p winver     > 06_winver.txt
```

```text
ProfileList
  S-1-5-21-3623811015-3361044348-30300820-1001 -> C:\Users\jhkim
  S-1-5-21-3623811015-3361044348-30300820-1003 -> C:\Users\tempadm

CurrentVersion
  ProductName  : Windows 10 Pro
  CurrentBuild : 19045
  InstallDate  : 2025-09-29 02:10:44Z  (Unix epoch DWORD)
  RegisteredOwner : FIN
```

| 판정 | 근거 |
| --- | --- |
| BAM의 `-1003` = `tempadm` | 접두어가 머신 SID와 동일 → **로컬 계정** |
| RID 1002의 프로필이 없다 | 삭제된 계정. `$Recycle.Bin`에 SID 폴더가 남았는지 확인 |

SID 해부와 로컬/도메인 판별은 [FOR-0074](./sid-user-mapping.html)를 따른다.

### 4단계 — NTUSER.DAT (tempadm): 마운트·실행·파일·의도·지속성

```powershell
$h = "C:\case\clean\tempadm\NTUSER.DAT"
rip.exe -r $h -p mp2         > 07_mp2.txt
rip.exe -r $h -p userassist  > 08_userassist.txt
rip.exe -r $h -p recentdocs  > 09_recentdocs.txt
rip.exe -r $h -p typedpaths  > 10_typedpaths.txt
rip.exe -r $h -p run         > 11_run.txt
```

#### ① MountPoints2 — 그 사용자가 그 볼륨을 마운트했다

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
  {7ac2f19d-3b41-11f0-9c22-8c16455a2d70}     <- MountedDevices 의 볼륨 GUID 와 동일
  E
  ##192.168.20.5#design
```

**볼륨 GUID가 일치하므로 "이 USB를 이 사용자 세션에서 마운트했다"가 성립한다.** `##서버#공유` 항목은 네트워크 공유 접근 흔적이다.

#### ② UserAssist — 사용자가 직접 실행한 것

```text
{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}
2026-04-08 13:07:44Z  {7C5A40EF-...}\7-Zip\7zFM.exe (3)
2026-04-08 13:05:12Z  {1AC14E77-...}\cmd.exe (1)
```

괄호 안이 실행 횟수다. 값 데이터 오프셋 `0x3C`의 FILETIME이 마지막 실행 시각이며 **키 LastWrite보다 이쪽이 정확하다** ([FOR-0061](./userassist.html)).

#### ③ RecentDocs — 열어 본 파일

```text
NTUSER.DAT\...\Explorer\RecentDocs\.xlsx
  MRUListEx = 02 00 00 00 00 00 00 00 01 00 00 00 FF FF FF FF
  2 = price_2026.xlsx      <- MRUListEx 첫 인덱스 = 가장 최근
  0 = salary_list.xlsx
  1 = client_master.xlsx
  LastWrite 2026-04-08 13:20:33Z
```

**시각은 최신 항목(`price_2026.xlsx`) 하나에만 귀속된다.** 나머지 두 개는 순서만 말할 수 있다 ([FOR-0062](./recentdocs.html), [FOR-0077](./registry-lastwrite-caveats.html)).

#### ④ TypedPaths — 의도

```text
NTUSER.DAT\...\Explorer\TypedPaths
  url1 = E:\proj_backup
  url2 = \\192.168.20.5\design
  LastWrite 2026-04-08 13:04:22Z
```

**주소창에 직접 입력한 경로**이므로 우연한 탐색이 아니라 목적지를 알고 이동한 것이다. `url1`이 가장 최근 입력이다 ([FOR-0064](./typedpaths.html)).

#### ⑤ Run — 지속성

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
  OneDriveHelper = C:\Users\tempadm\AppData\Roaming\odh\odhelper.exe
  LastWrite 2026-04-08 13:41:09Z
```

이름은 정상 서비스를 흉내 내지만 경로가 `AppData\Roaming`이다 ([FOR-0063](./run-runonce.html)).

### 5단계 — UsrClass.dat (tempadm): ShellBags

```powershell
SBECmd.exe -d "C:\case\clean\tempadm" --csv "C:\case\out"
```

```text
AbsolutePath                                        ShellType  MRUPosition  LastWriteTime
Desktop\My Computer\E:\                             Volume     0            2026-04-08 13:02:19Z
Desktop\My Computer\E:\proj_backup                  Directory  0            2026-04-08 13:04:51Z
Desktop\My Computer\C:\Users\jhkim\Documents\price  Directory  1            2026-04-08 13:19:02Z
Desktop\Network\192.168.20.5\design                 Network    0            2026-04-08 13:33:40Z
```

**`C:\Users\jhkim\Documents\price` 항목이 결정적이다** — `tempadm`이 다른 사용자의 문서 폴더를 탐색했다. 그 폴더가 현재 `$MFT`에 없으면 삭제된 폴더이고, ShellBags가 그 이름의 유일한 근거가 된다 ([FOR-0068](./shellbags.html)).

## 출력 필드 해석

각 단계에서 답으로 쓸 값과 그 근거의 강도다.

| 소문항 | 답의 근거 | 강도 | 보강 |
| --- | --- | --- | --- |
| ① 계정 | `SAM` 생성 시각 + 로그온 1회 + `ProfileList` | 강 | EVTX 4720/4624 |
| ② USB | `USBSTOR` Properties의 `0066`/`0067` FILETIME | 강 | `setupapi.dev.log`, EVTX |
| ② 드라이브 문자 | `MountedDevices`의 이진 데이터 | 강 | ShellBags의 `E:\` 항목 |
| ② 사용자 귀속 | `MountPoints2`의 볼륨 GUID 일치 | 강 | — |
| ③ 실행 | BAM 값 앞 8바이트 + UserAssist `0x3C` | 강 | Prefetch, 4688 |
| ④ 파일 | `RecentDocs` MRU 최신 항목 | **중** | LNK/Jump List, `$MFT` |
| ④ 폴더 | ShellBags `AbsolutePath` | 강 | `$MFT`, `$UsnJrnl` |
| ⑤ 의도 | `TypedPaths` 직접 입력 | 강 | 브라우저·검색 기록 |
| ⑥ 지속성 | `Run` 값 + 경로 이상 | 강 | Amcache/Prefetch로 실제 실행 확인 |

**"중" 강도는 답변에 한계를 함께 적는다.** RecentDocs는 최신 항목 외에는 시각이 없다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 것 | 다음에 열 것 | 무엇을 얻나 |
| --- | --- | --- |
| USB 시리얼 | `setupapi.dev.log`, EVTX 장치 로그 | 최초 연결 시각 독립 확증 |
| 실행 파일 경로 | Prefetch, Amcache ([FOR-0079](./appcompatcache.html)) | 실행 횟수·해시 |
| 파일 이름 | LNK, Jump List, `$MFT`, `$UsnJrnl` | 복사·삭제 사실과 시각 |
| 폴더 경로 | `$MFT` | 폴더가 실제로 있었는가, 삭제됐는가 |
| 계정 SID | `$Recycle.Bin\<SID>`, EVTX 4624/4720 | 삭제 파일과 로그온 이력 |
| `Run` 항목 경로 | Prefetch, Amcache | 실제로 실행된 적이 있는가 |
| 네트워크 공유 경로 | 4624 Logon Type 3, SMB 로그 | 원격 접근 계정 |
| 시간대 | 모든 artifact | 최종 답의 KST 변환 |

## 흔한 함정

- **`CurrentControlSet` 경로를 오프라인 hive에 입력하는 것** → 부팅 시 만들어지는 링크라 파일에 없다 → `Select\Current`로 실제 번호를 확인한다 ([FOR-0053](./system-controlset.html)).
- **시간대를 확보하지 않고 시각을 답하는 것** → 레지스트리 FILETIME은 UTC다 → `TimeZoneInformation`을 먼저 읽고, 마지막에 한 번만 +9시간 한다.
- **키 LastWrite로 USB 연결 시각을 답하는 것** → 값이 여러 개인 키의 시각이고 로그 미반영 영향도 크다 → `Properties` 하위의 FILETIME을 쓴다.
- **드라이브 문자를 순서로 추측하는 것** → `E:`가 USB인지 파티션인지는 `MountedDevices`만이 말해 준다 → 이진 데이터를 읽는다.
- **플러그인 이름을 짐작해 쓰는 것** → 빈 출력이 나오고 "흔적 없음"으로 오판한다 → `rip.exe -l`로 목록을 먼저 본다.
- **`rla`를 건너뛰는 것** → 사건 당일의 항목이 `.LOG1`에만 있어 통째로 누락된다 → 항상 먼저 반영하고, 반영 전 hive도 보관한다.
- **사용자 hive를 하나만 보는 것** → 반출자는 새로 만든 계정을 쓴다 → 모든 프로필의 `NTUSER.DAT`·`UsrClass.dat`을 처리한다.
- **`RecentDocs`의 LastWrite를 모든 항목의 시각으로 쓰는 것** → 최신 항목 하나뿐이다 → 나머지는 `MRUListEx` 순서만 주장한다.
- **BAM의 `\Device\HarddiskVolumeN`을 그대로 답에 쓰는 것** → 드라이브 문자가 아니다 → `MountedDevices`로 환산한다.
- **Shimcache 항목을 "실행했다"의 근거로 제시하는 것** → 존재 증거다 → 실행은 BAM·UserAssist·Prefetch로 확증한다 ([FOR-0076](./recent-execution-crosscheck.html)).
- **ShellBags를 파일 접근 증거로 쓰는 것** → 폴더를 탐색기로 열었다는 증거다 → 파일은 `RecentDocs`·LNK로 간다.
- **`MountPoints2`만으로 USB를 특정하는 것** → 볼륨 GUID만 있고 시리얼이 없다 → `MountedDevices`를 거쳐 `USBSTOR`까지 연결해야 장치가 특정된다.

## 교차검증

```powershell
# 1) 장치 -> 드라이브 문자 -> 사용자 3단 연결이 끊기지 않는지
Select-String -Path "C:\case\03_mounteddev.txt" -Pattern '4C530001231205117495'
Select-String -Path "C:\case\07_mp2.txt"        -Pattern '7ac2f19d'
```

```powershell
# 2) 실행 시각을 두 곳에서 (BAM = 서비스 계열, UserAssist = 셸 계열)
Select-String -Path "C:\case\04_bam.txt","C:\case\08_userassist.txt" -Pattern '7zFM|robocopy'
```

```powershell
# 3) 파일 접근을 레지스트리 밖에서
Import-Csv "C:\case\out\mft.csv" | Where-Object { $_.FileName -match 'price_2026' } |
  Format-Table FileName, ParentPath, Created0x10, LastModified0x10, InUse
```

```powershell
# 4) 지속성 항목이 실제로 실행됐는가
AppCompatCacheParser.exe -f "C:\case\clean\SYSTEM" --csv "C:\case\out" --csvf shim.csv
Import-Csv "C:\case\out\shim.csv" | Where-Object { $_.Path -match 'odhelper' }
```

| 연결이 끊기는 지점 | 무엇을 의심하나 |
| --- | --- |
| `MountedDevices`에 시리얼이 없다 | 다른 PC에서 쓴 장치, 또는 항목이 덮여 사라졌다 |
| `MountPoints2`에 볼륨 GUID가 없다 | 그 사용자 세션에서 마운트되지 않았다. 다른 사용자 확인 |
| BAM에는 있고 UserAssist에 없다 | 콘솔·스크립트 실행. Explorer 경유가 아니다 |
| ShellBags에는 폴더가 있고 `$MFT`에 없다 | **삭제된 폴더.** ShellBags가 유일한 이름 근거 |

## mini walkthrough

```text
[실패 1] CurrentControlSet 을 찾다가 시간을 버렸다

  RegistryExplorer 로 SYSTEM 을 열고
  SYSTEM\CurrentControlSet\Enum\USBSTOR 로 이동
  -> CurrentControlSet 이라는 키가 트리에 없다.
     "hive 가 깨졌나?" 하며 다른 hive 를 열어 봤다.

  왜 틀렸나:
  CurrentControlSet 은 부팅 시 커널이 만드는 휘발성 심볼릭 링크다.
  디스크 파일에는 ControlSet001 / ControlSet002 만 있다.

  수정:
  SYSTEM\Select 의 Current = 1  ->  ControlSet001\Enum\USBSTOR


[실패 2] 플러그인 이름을 잘못 써서 빈 출력이 나왔다

  rip.exe -r clean\tempadm\NTUSER.DAT -p mountpoints2
  -> 빈 출력. "이 사용자는 USB 를 마운트하지 않았다"고 결론 낼 뻔했다.

  rip.exe -r clean\tempadm\NTUSER.DAT -p shellbag
  -> 역시 빈 출력.

  왜 틀렸나:
  둘 다 존재하지 않는 플러그인 이름이었다.
  rip.exe -l | Select-String 'mount|shell'
    -> mp2, shellbags 가 실제 이름이었다.

  수정:
  rip.exe -r ... -p mp2        -> 볼륨 GUID 3개 출력
  rip.exe -r ... -p shellbags  -> 항목 출력
  교훈: 빈 출력을 "흔적 없음"으로 읽기 전에 도구 문제를 배제한다.


[실패 3] 키 LastWrite 로 USB 연결 시각을 답했다가 어긋났다

  USBSTOR\...\4C530001231205117495&0 의 키 LastWrite = 2026-03-02 01:44:07Z
  -> "3월 2일 10:44 KST 에 USB 를 꽂았다"고 적었다.

  그런데 ShellBags 의 E:\ 탐색은 2026-04-08 13:02:19Z,
  BAM 의 robocopy 실행은 2026-04-08 13:12:05Z 였다. 한 달 넘게 어긋난다.

  원인 두 개가 겹쳐 있었다:
   (a) 트랜잭션 로그 미반영 hive 를 읽었다 (반영 후 LastWrite 는 04-08 로 바뀐다)
   (b) 그 인스턴스 키에는 값이 여러 개라 LastWrite 가 어느 값의 시각인지 알 수 없다

  수정:
  rla 로 반영한 뒤, 값 안에 자체 FILETIME 이 있는 곳으로 갈아탔다.
    Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066 = 2026-04-08 13:01:58Z (연결)
    Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0067 = 2026-04-08 13:52:33Z (제거)
  ShellBags 탐색(13:02:19Z)이 연결 21초 뒤 -> 순서가 자연스럽다. 확정.


[실패 4] BAM 의 볼륨 번호를 드라이브 문자로 추측했다

  \Device\HarddiskVolume3\Windows\System32\robocopy.exe 를
  "D:\Windows\System32\robocopy.exe" 로 옮겨 적었다.
  -> MountedDevices 확인 결과 HarddiskVolume3 = C: 였다.
     시스템 폴더가 D: 에 있을 이유가 없다는 점에서도 자기모순이었다.
  교훈: 볼륨 번호와 드라이브 문자는 항상 MountedDevices 로 환산한다.


[최종 정리] 확정된 사실을 시간순 표로

  모든 시각은 레지스트리 FILETIME(UTC) 이며 KST = UTC + 9h

  | UTC                  | KST                  | 사실                                   | 근거 |
  | 2026-04-08 12:40:11Z | 2026-04-08 21:40:11  | tempadm 계정 생성 (RID 1003)            | SAM |
  | 2026-04-08 12:55:38Z | 2026-04-08 21:55:38  | tempadm 최초/유일 로그온                 | SAM Last Login |
  | 2026-04-08 12:58:03Z | 2026-04-08 21:58:03  | USB 최초 설치 (SanDisk Cruzer Blade)     | USBSTOR 0064 |
  | 2026-04-08 13:01:58Z | 2026-04-08 22:01:58  | USB 연결 (E: 로 마운트)                  | USBSTOR 0066 + MountedDevices |
  | 2026-04-08 13:02:19Z | 2026-04-08 22:02:19  | E:\ 탐색기 탐색                          | ShellBags |
  | 2026-04-08 13:04:22Z | 2026-04-08 22:04:22  | 주소창에 E:\proj_backup 직접 입력         | TypedPaths url1 |
  | 2026-04-08 13:05:12Z | 2026-04-08 22:05:12  | cmd.exe 실행                            | UserAssist + BAM |
  | 2026-04-08 13:07:44Z | 2026-04-08 22:07:44  | 7zFM.exe 실행 (3회)                     | UserAssist 0x3C |
  | 2026-04-08 13:12:05Z | 2026-04-08 22:12:05  | robocopy.exe 실행                       | BAM 앞 8바이트 |
  | 2026-04-08 13:19:02Z | 2026-04-08 22:19:02  | C:\Users\jhkim\Documents\price 폴더 탐색 | ShellBags |
  | 2026-04-08 13:20:33Z | 2026-04-08 22:20:33  | price_2026.xlsx 열람 (MRU 최신 항목)      | RecentDocs |
  | 2026-04-08 13:33:40Z | 2026-04-08 22:33:40  | \\192.168.20.5\design 접근               | ShellBags + MountPoints2 |
  | 2026-04-08 13:41:09Z | 2026-04-08 22:41:09  | Run 키에 OneDriveHelper 등록             | NTUSER.DAT Run |
  | 2026-04-08 13:52:33Z | 2026-04-08 22:52:33  | USB 제거                                | USBSTOR 0067 |

  경과 시간: 로그온 후 약 57분. 연결 → 탐색 → 압축 → 복사 → 제거가 한 세션 안에서 완결.
```

### 답변 서술 템플릿

시간순 표를 그대로 문장으로 옮긴다. **각 문장에 근거 artifact를 괄호로 붙이는 것이 채점에서 갈린다.**

```text
1. 결론 한 줄
   "로컬 계정 tempadm(RID 1003)이 2026-04-08 22:01~22:52 KST 사이에
    SanDisk Cruzer Blade(시리얼 4C530001231205117495)를 E: 로 연결하고
    사내 자료를 반출했다."

2. 계정
   - tempadm 은 사건 당일 21:40:11 KST 에 생성되고 21:55:38 KST 에 1회 로그온했다 (SAM)
   - 머신 SID 접두어가 동일하므로 로컬 계정이다 (SAM 머신 SID + ProfileList)

3. 장치와 사용자 귀속 (3단 연결을 명시한다)
   - USBSTOR 인스턴스 4C530001231205117495&0 의 연결/제거 시각 (Properties 0066/0067)
   - MountedDevices\DosDevices\E: 의 이진 데이터가 같은 시리얼을 담고 있다
   - 같은 볼륨 GUID {7ac2f19d-...} 가 tempadm 의 MountPoints2 에 있다
     => 이 USB 를 이 계정 세션에서 E: 로 마운트했다

4. 행위 (시간순, 근거 병기)
   ... 표의 각 행을 한 문장으로 ...

5. 한계 명시
   - RecentDocs 의 시각은 MRU 최신 항목(price_2026.xlsx)에만 귀속된다.
     salary_list.xlsx / client_master.xlsx 는 접근 순서만 확인되고 시각은 미확정이다.
   - 파일이 실제로 USB 로 복사되었는지는 레지스트리만으로는 확정되지 않는다.
     $UsnJrnl / LNK / USB 볼륨 이미지가 추가로 필요하다.
   - Shimcache 항목은 파일의 존재 증거로만 인용했다.

6. 추가 확보 권고
   $MFT / $UsnJrnl, Prefetch, Security.evtx(4720/4624/4634), USB 볼륨 이미지
```

**5번(한계 명시)을 쓰는 답안이 감점을 피한다.** 레지스트리는 "열었다·실행했다·마운트했다"를 말하고, "복사했다"는 파일시스템 증거의 몫이다.

## 막혔을 때 다음 체크

1. `rla`로 모든 hive의 로그를 반영했는가 — 반영 전 hive도 남겼는가
2. `Select\Current`로 활성 ControlSet을 정했는가
3. `TimeZoneInformation`을 읽고 모든 시각을 같은 기준으로 모았는가
4. 머신 SID를 확보했는가 — 모든 SID의 로컬/도메인 판별 기준이다
5. 사용자 hive를 **전부** 처리했는가 — 새로 만든 계정이 범인이다
6. `rip.exe -l`로 플러그인 이름을 확인했는가 — 빈 출력의 최대 원인
7. USB 3단 연결(`USBSTOR` → `MountedDevices` → `MountPoints2`)이 끊기지 않는가
8. 볼륨 번호·드라이브 문자를 `MountedDevices`로 환산했는가
9. 시각의 근거가 키 LastWrite인가 값 안의 FILETIME인가 — 후자를 우선했는가
10. MRU 키의 시각을 최신 항목에만 귀속시켰는가
11. 실행 증거를 주체가 다른 2곳(BAM·UserAssist·Prefetch)에서 확인했는가
12. 답변에 근거 artifact와 **한계**를 함께 적었는가

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: hive와 루트키 대응, `CurrentControlSet`이 휘발성 링크라는 점, 사용자 hive의 위치
- SRC-099 — RegRipper 3.0 저장소: `samparse`·`usbstor`·`mountdev`·`mp2`·`profilelist`·`userassist`·`bam`·`recentdocs`·`typedpaths`·`run`·`shellbags`·`winver` 플러그인의 존재와 출력 형식, `rip.exe -l`로 목록을 얻는 방법
- SRC-098 — Microsoft Learn, USB device registry entries: `Enum\USBSTOR` 아래 장치/인스턴스 키 구조와 인스턴스 ID가 장치 시리얼에서 온다는 점(시리얼이 없으면 두 번째 문자가 `&`)
- SRC-019 — Microsoft Learn, Well-known SIDs: `S-1-5-21-<머신/도메인 식별자>-<RID>` 구조와 RID 500/1000번대의 의미, 머신 SID 접두어 비교로 로컬 계정을 판별하는 근거
- **`Properties\{83da6326-97a6-4088-9453-a1923f573b29}` 아래 `0064`/`0065`/`0066`/`0067`의 의미(최초 설치·설치·마지막 연결·마지막 제거) 대응은 Windows 버전에 따라 달라질 수 있으므로 실제 hive에서 확인할 것.** 값 자체는 FILETIME이다
- `MountedDevices`의 고정 디스크 항목이 12바이트(디스크 서명 + 파티션 오프셋)라는 점과 이동식 항목이 `\??\USBSTOR#...` 문자열이라는 점은 관측되는 형태이며, 상세 해석은 `MountedDevices` 전담 글을 따를 것
- SBECmd/ShellBags Explorer, AppCompatCacheParser의 컬럼명과 RegRipper 플러그인 출력 형식은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- 시나리오의 계정명·시리얼·볼륨 GUID·시각·파일명은 전부 설명을 위한 예시 값이다
