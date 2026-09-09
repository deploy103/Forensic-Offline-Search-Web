---
id: FOR-0057
title: "NTUSER.DAT 기본: 사용자별 hive와 포렌식 키 인덱스"
slug: "ntuser-dat"
category: "Registry"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["NTUSER.DAT", "NTUSER.DAT.LOG1", "NTUSER.DAT.LOG2", "MRUListEx", "MountPoints2", "RunMRU", "ComDlg32"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\ntuser.dat.LOG1", "C:\\Users\\<user>\\ntuser.dat.LOG2", "C:\\Users\\<user>\\ntuser.ini", "%UserProfile%\\NTUSER.DAT"]
registry_paths: ["HKCU", "HKU\\<SID>", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", "HKCU\\Network", "HKCU\\Printers", "HKCU\\Volatile Environment", "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r NTUSER.DAT -a", "rla.exe -f NTUSER.DAT --out .", "reg load HKU\\case C:\\case\\NTUSER.DAT"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["MRUListEx", "MRUList", "LastWrite", "RemotePath", "url1"]
file_formats: ["regf"]
primary_terms: ["NTUSER.DAT", "HKCU", "사용자 hive", "사용자별 레지스트리"]
keywords: ["NTUSER.DAT", "HKCU", "사용자 hive", "사용자별 레지스트리", "HKU", "SID", "MRUListEx", "RunMRU", "TypedPaths", "MountPoints2", "ComDlg32", "트랜잭션 로그", "LOG1", "flush"]
aliases: ["ntuser.dat", "엔티유저닷댓", "사용자 레지스트리", "HKCU 어느 파일", "사용자 hive 위치", "ntuser 어떤 키 봐야", "사용자별 흔적"]
symptom_keywords: ["NTUSER.DAT에서 무엇을 봐야 하는지 모르겠다", "HKCU가 어느 파일인지", "사용자 활동 흔적을 찾고 싶다", "최신 변경이 hive에 안 보인다", "사용자가 여러 명이다"]
related: ["FOR-0051", "FOR-0058", "FOR-0060", "FOR-0061"]
source_ids: ["SRC-017", "SRC-027", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`NTUSER.DAT`은 프로필 폴더 최상단에 사용자 1명당 1개 존재하며 로그온 시 `HKU\<SID>`(= 그 사용자에게는 `HKCU`)로 마운트되는 hive로, **"누가" 무엇을 실행·열람·입력했는지**를 담는 사용자 활동 아티팩트의 본체다. 이 글은 그 안에서 실제로 열어볼 키의 인덱스다.

## 개념

| 항목 | 내용 |
| --- | --- |
| 파일 위치 | `C:\Users\<user>\NTUSER.DAT` (프로필 폴더 최상단, 숨김+시스템 속성) |
| 마운트되는 키 | `HKU\<SID>`. 그중 현재 로그온 사용자의 것이 `HKCU`로 한 번 더 노출된다 |
| 개수 | **프로필 1개당 정확히 1개.** `C:\Users` 아래 폴더 수 = hive 수 |
| 형식 | `regf` (선두 4바이트 `72 65 67 66`) |
| 시각 단위 | 키 LastWrite는 FILETIME, **항상 UTC** |
| 사용자 특정 | 파일 자체가 사용자별이므로 "누가"는 파일 경로로 이미 증명된다 |

`HKCU`는 파일이 아니라 **현재 세션의 SID hive를 가리키는 별칭**이다. 오프라인 분석에서는 `HKCU\...` 경로를 항상 `NTUSER.DAT\...`(hive 루트 기준)으로 바꿔 읽는다. SID ↔ 프로필 폴더 대응은 `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`에서 확인한다. 루트키와 파일의 전체 대응표는 [FOR-0051](./registry-hive-map.html)에 있다.

`Default` 프로필(`C:\Users\Default\NTUSER.DAT`)은 새 계정을 만들 때 복사되는 템플릿이므로 사람의 활동 흔적으로 읽지 않는다.

## 파일 / 경로

프로필 폴더 최상단에서 hive와 **함께 존재하는 파일들**이다. 추출할 때 전부 같은 폴더로 꺼낸다.

| 파일 | 역할 | 꼭 꺼내야 하나 |
| --- | --- | --- |
| `NTUSER.DAT` | hive 본체 | 필수 |
| `ntuser.dat.LOG1` | 트랜잭션 로그 1 | **필수** (최신 변경이 여기에만 있을 수 있다) |
| `ntuser.dat.LOG2` | 트랜잭션 로그 2 | **필수** |
| `NTUSER.DAT{GUID}.TM.blf` | CLFS 기반 트랜잭션 레지스트리(TxR) 로그 | 있으면 함께 |
| `NTUSER.DAT{GUID}.TMContainer0000...regtrans-ms` | 같은 TxR 컨테이너 | 있으면 함께 |
| `ntuser.ini` | 로밍 프로필 제외 목록 | 참고용 |

### 잠김과 flush — 최신성 문제

| 사실 | 포렌식 의미 |
| --- | --- |
| 로그온 중에는 hive가 커널에 열려 있어 일반 복사가 실패한다 | FTK Imager([FOR-0016](./ftk-imager-open-image.html))·이미지 마운트([FOR-0017](./arsenal-image-mounter.html))·KAPE 같은 로우레벨 접근이나 VSS를 쓴다 |
| 변경은 즉시 파일에 쓰이지 않고 커널이 지연 기록(lazy flush)한다 | 라이브에서 뽑은 hive는 **직전 수 분의 변경이 파일에 없을 수 있다** |
| 로그오프·종료 시 hive가 정리되고 sequence number가 일치(clean)한다 | 반대로 강제 종료/전원 차단 이미지의 hive는 dirty로 남는다 |
| dirty hive의 미반영 변경은 `.LOG1`/`.LOG2`에 있다 | `rla`로 반영하지 않으면 "마지막 실행", "마지막 입력"이 틀린다 |

dirty 판정은 base block의 primary sequence number(`0x04`)와 secondary(`0x08`)를 비교한다. 두 값이 다르면 dirty다. 로그 반영 절차와 `rla` 사용법은 [FOR-0061](./userassist.html)에서 다룬다.

`NTUSER.DAT`의 `$MFT` 상 마지막 수정 시각은 "마지막 flush 시각"이며 실무에서 마지막 로그오프/종료의 **근사값**으로 쓰이지만, 백그라운드 flush로도 갱신되므로 그것만으로 로그오프 시각을 단정하지 않는다. 로그온/로그오프 확정은 Security 로그 4624/4634로 간다([FOR-0083](./event-4624-logon.html)).

## 주요 필드

### 포렌식 가치가 있는 키 인덱스

경로는 **hive 루트 기준**이다. 아래 표에서 `<EXP>`는 `Software\Microsoft\Windows\CurrentVersion\Explorer`를 줄인 것이다.

| 키 | 남는 것 | 전담 글 |
| --- | --- | --- |
| `<EXP>\UserAssist\{GUID}\Count` | GUI로 직접 실행한 프로그램, 실행 횟수, 마지막 실행(FILETIME) | [FOR-0061](./userassist.html) |
| `<EXP>\RecentDocs` | 최근 열어본 문서. 확장자별 서브키 + `MRUListEx` | [FOR-0062](./recentdocs.html) |
| `<EXP>\RunMRU` | 실행(Win+R) 창에 타이핑한 명령. 값 이름 `a`,`b`,`c`... + `MRUList` | 이 글 |
| `<EXP>\TypedPaths` | 탐색기 주소창에 직접 입력한 경로. 값 `url1`~`urlN` | [FOR-0064](./typedpaths.html) |
| `Software\Microsoft\Internet Explorer\TypedURLs` | 주소창에 입력한 URL. 값 `url1`~`urlN` | [FOR-0065](./typedurls.html) |
| `<EXP>\WordWheelQuery` | 탐색기 검색창 검색어(UTF-16LE) + `MRUListEx` | FOR-0070 |
| `<EXP>\ComDlg32\OpenSavePidlMRU\<ext>` | 열기/저장 대화상자로 열거나 저장한 파일. shell item(PIDL)로 저장 | 이 글 |
| `<EXP>\ComDlg32\LastVisitedPidlMRU` | 대화상자를 띄운 **실행 파일 ↔ 그 프로그램이 마지막에 본 폴더** 쌍 | 이 글 |
| `<EXP>\ComDlg32\CIDSizeMRU` | 대화상자 크기를 기억하는 실행 파일 이름 목록(보조 실행 흔적) | 이 글 |
| `Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` | 사용자 단위 자동실행 | [FOR-0063](./run-runonce.html) |
| `Software\Microsoft\Windows NT\CurrentVersion\Windows` (`Load`, `Run`) | 구형 자동실행 경로. 값이 있으면 의심 | [FOR-0063](./run-runonce.html) |
| `<EXP>\MountPoints2` | 사용자가 마운트한 볼륨·네트워크 공유(드라이브 문자, 볼륨 GUID) | [FOR-0067](./mounteddevices.html) |
| `Network\<드라이브문자>` | 매핑된 네트워크 드라이브. `RemotePath`, `UserName`, `ProviderName` | 이 글 |
| `Printers\Connections`, `Printers\Settings` | 연결한 프린터. 네트워크 프린터면 `\\서버\프린터` 경로가 남는다 | 이 글 |
| `Software\Microsoft\Terminal Server Client\Servers\<host>` | **이 PC에서 RDP로 접속해 나간 대상 호스트**. `UsernameHint` 값에 사용한 계정 | 이 글 |
| `<EXP>\Shell Folders`, `User Shell Folders` | Desktop/Downloads/Documents의 실제 경로. 리다이렉트 여부 확인 | 이 글 |
| `<EXP>\FileExts\.<ext>\UserChoice` | 확장자별 사용자 지정 기본 프로그램 | [FOR-0058](./usrclass-dat.html) 비교 |
| `Software\Microsoft\Office\<버전>\<앱>\File MRU` | Office 최근 파일. 항목 문자열 안에 FILETIME이 hex로 들어 있다 | 이 글 |
| `Volatile Environment` | 로그온 시 만들어지는 **휘발성** 키(`USERPROFILE`, `HOMEPATH`, `LOGONSERVER` 등) | 아래 주의 |

`Volatile Environment`는 이름 그대로 휘발성 키로 설계되어 있어 **디스크의 hive 파일에는 존재하지 않는 것이 정상**이다. 이 값들이 필요하면 라이브 시스템의 `HKCU`나 메모리 덤프에서 본다. 오프라인 hive에서 이 키가 안 보인다고 hive가 손상됐다고 판단하지 않는다.

`MountPoints2`의 서브키 형태는 세 가지다.

| 서브키 형태 | 의미 |
| --- | --- |
| `E` 처럼 문자 1개 | 그 드라이브 문자로 마운트한 볼륨. 키 LastWrite ≈ 마지막 마운트 시점 |
| `##?#Volume{GUID}` | 볼륨 GUID로 참조된 마운트. `SYSTEM\MountedDevices`와 GUID로 연결한다 |
| `##서버#공유` | 사용자가 붙인 네트워크 공유(`\\서버\공유`) |

### MRU 순서 필드 읽는 법

MRU 계열 키는 "가장 최근"이 어느 값인지를 별도 값으로 저장한다. 이걸 무시하면 순서를 거꾸로 읽는다.

| 값 이름 | 형식 | 읽는 법 |
| --- | --- | --- |
| `MRUList` | 문자열 (`"cab"`) | 문자 순서가 최신순. 첫 글자가 가장 최근 값의 이름 |
| `MRUListEx` | 이진 | 4바이트 리틀엔디언 정수의 배열이 최신순. `FF FF FF FF`가 끝 표시 |

```text
MRUListEx = 02 00 00 00 | 00 00 00 00 | 01 00 00 00 | FF FF FF FF
-> 최신순 = 값 "2", 값 "0", 값 "1"
```

값 자체에는 타임스탬프가 없다. 키 LastWrite는 **가장 최근 1건**의 시각으로만 쓸 수 있고, 나머지 항목은 순서만 알 수 있다. 항목별 시각이 필요하면 LNK·Jump List·`$MFT`로 교차검증한다.

## 빠른 명령

```powershell
rip.exe -r 'C:\case\NTUSER.DAT' -a > 'C:\case\ntuser_all.txt'
```

```powershell
# 1) 트랜잭션 로그를 먼저 반영한다 (LOG1/LOG2 가 같은 폴더에 있어야 한다)
rla.exe -f 'C:\case\NTUSER.DAT' --out 'C:\case\clean'

# 2) 특정 키만 빠르게
rip.exe -r 'C:\case\clean\NTUSER.DAT' -p runmru
rip.exe -r 'C:\case\clean\NTUSER.DAT' -p comdlg32
rip.exe -r 'C:\case\clean\NTUSER.DAT' -p mp2

# 3) 프로필이 여러 개일 때 전부 훑기
Get-ChildItem 'C:\case\Users' -Directory | ForEach-Object {
  $h = Join-Path $_.FullName 'NTUSER.DAT'
  if (Test-Path $h) { rip.exe -r $h -a > "C:\case\out\$($_.Name).txt" }
}
```

플러그인 이름(`runmru`, `comdlg32`, `mp2`)은 RegRipper 버전마다 다르므로 **먼저 `rip.exe -l`로 확인한다**([FOR-0060](./regripper.html)).

라이브 Windows에서 다른 사용자의 hive를 논리 경로로 보려면 임시 마운트한다.

```powershell
# 관리자 권한. 분석이 끝나면 반드시 unload 한다
reg load HKU\case 'C:\case\NTUSER.DAT'
reg query 'HKU\case\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
reg unload HKU\case
```

## 함께 보는 artifact

| 이 hive에서 얻은 것 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 실행 파일 경로(UserAssist) | Prefetch, `Amcache.hve` | 실제 실행 사실, SHA-1, 최초 실행 |
| 문서 경로(RecentDocs, ComDlg32) | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent`의 LNK | 대상 경로, 볼륨 시리얼, MAC 시각 |
| 폴더 경로 흔적이 없다 | `UsrClass.dat`의 ShellBags ([FOR-0058](./usrclass-dat.html)) | 탐색기로 실제 방문한 폴더 |
| `MountPoints2`의 볼륨 GUID | `SYSTEM\MountedDevices`, `USBSTOR` | 장치 시리얼, 드라이브 문자 매핑 |
| `Network\<letter>`의 `RemotePath` | Security 4624 Logon Type 3, SMB 트래픽 | 공유 접근 시점과 계정 |
| `Terminal Server Client\Servers` | 접속 대상 호스트의 EVTX(TerminalServices 로그, 4624 Type 10) | 측면 이동 여부와 사용 계정 |
| SID만 있고 사용자 이름을 모른다 | `SOFTWARE\...\ProfileList`, `SAM` ([FOR-0052](./sam-user-accounts.html)) | SID ↔ 계정명 ↔ 프로필 폴더 |
| 삭제된 값이 필요하다 | RegistryExplorer의 Deleted Records ([FOR-0059](./registry-explorer.html)) | 지워진 키/값 복구 |

## 흔한 실수

- **`HKCU\...` 경로를 오프라인 hive 트리에 그대로 찾는 것.** hive 루트가 곧 `HKCU`다. `NTUSER.DAT\Software\...`로 바꿔 읽는다. 툴에서 `HKCU`라는 노드를 찾다가 시간을 버린다.
- **`.LOG1`/`.LOG2`를 남겨두고 hive만 추출하는 것.** dirty hive의 최신 변경은 로그에만 있다. "마지막에 입력한 경로", "마지막 실행"을 묻는 문제에서 그대로 오답이 된다.
- **ShellBags를 `NTUSER.DAT`에서 찾는 것.** Windows 7 이후 `BagMRU`/`Bags`는 `UsrClass.dat`에 있다. XP 시절 `Software\Microsoft\Windows\Shell\BagMRU` 기억으로 헤매지 않는다.
- **`MountedDevices`를 `NTUSER.DAT`에서 찾는 것.** 그것은 `SYSTEM` hive **루트**의 키다. `NTUSER.DAT`에 있는 사용자 측 대응물은 `MountPoints2`다.
- **`MRUList`/`MRUListEx`를 무시하고 값 이름 순서(`a`,`b`,`c` 또는 `0`,`1`,`2`)로 최신순을 판단하는 것.** 값 이름은 생성 순서일 뿐 최신순이 아니다.
- **키 LastWrite를 항목마다 있는 시각으로 착각하는 것.** 키 단위 시각이고 마지막 1회뿐이다. 값이 10개면 어느 값 때문에 갱신됐는지 알 수 없다.
- **LastWrite를 로컬 시각으로 읽는 것.** FILETIME이므로 UTC다. KST는 +9시간, Unix epoch와의 차이는 `11644473600`초다.
- **프로필 하나만 보고 끝내는 것.** `C:\Users` 아래 모든 프로필의 hive를 세고 시작한다. `Default`·`Public`은 템플릿/공용이므로 사람 활동으로 읽지 않는다.
- **`Volatile Environment`가 없다고 hive가 깨졌다고 판단하는 것.** 휘발성 키라 파일에 없는 것이 정상이다.

## mini example

```text
문제:
"이미지에서 추출한 C:\Users\jhkim\ 폴더가 주어진다. 사용자 jhkim 이 외부
 저장장치를 어떤 드라이브 문자로 붙였고, 어떤 네트워크 공유를 사용했는지
 구하세요."

1. 폴더 내용 확인
   NTUSER.DAT / ntuser.dat.LOG1 / ntuser.dat.LOG2 / ntuser.ini
   -> hive + 트랜잭션 로그가 모두 있다. 좋다.

2. 첫 시도 (실패):
   RegistryExplorer 로 NTUSER.DAT 을 열고
   MountedDevices 키를 찾았다.
   -> 트리에 그런 키가 없다. "hive가 잘린 건가?" 하고 다시 추출까지 했다.

   왜 틀렸나:
   MountedDevices 는 SYSTEM hive 루트의 키다. 사용자 hive 에는 없다.
   NTUSER.DAT 쪽 대응물은
   Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 다.

3. 두 번째로 틀린 판단:
   hive 를 바로 파싱했더니 MountPoints2 아래 항목이 3개뿐이고
   LastWrite 가 사건 시각보다 40분 이르다.
   -> primary(0x04)=0x2F, secondary(0x08)=0x31 로 불일치. dirty hive 였다.
      로그를 반영하지 않아 가장 최근 마운트가 빠져 있었다.

4. 피벗: 로그 반영 후 재파싱
   rla.exe -f NTUSER.DAT --out clean\
   rip.exe -r clean\NTUSER.DAT -p mp2

   MountPoints2
     E                       LastWrite 2026-03-14 07:05:11Z
     ##?#Volume{7b1f...c3}   LastWrite 2026-03-14 07:05:11Z
     ##fileserv#share01      LastWrite 2026-03-14 06:41:02Z

5. 네트워크 드라이브는 별도 키에서 확정
   Network\Z
     RemotePath   = \\fileserv\share01
     UserName     = jhkim
     ProviderName = Microsoft Windows Network

6. USB 실체 확인 (pivot)
   SYSTEM\MountedDevices 에서 \??\Volume{7b1f...c3} 의 데이터가
   USBSTOR 인스턴스(시리얼)와 일치하는지 대조한다.

7. UTC -> KST
   2026-03-14 07:05:11 UTC + 9h = 2026-03-14 16:05:11 KST

정답: E: 드라이브로 마운트(2026-03-14 16:05:11 KST), 공유는 \\fileserv\share01 (Z:)
```

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `NTUSER.DAT`이 `HKU\<SID>`/`HKCU`로 마운트된다는 점, 프로필당 1개라는 구조
- SRC-027 — Libyal libregf, REGF 포맷 문서: `regf` 시그니처, sequence number로 dirty 판정, LastWrite가 키(`nk`)에만 존재한다는 점
- SRC-099 — RegRipper 3.0 저장소: `rip.exe`의 `-r`/`-p`/`-a` 옵션과 사용자 hive 대상 플러그인 존재
- 플러그인 이름(`runmru`, `comdlg32`, `mp2`)은 RegRipper 버전에 따라 다르므로 `rip.exe -l`로 실제 목록을 확인할 것
- Office `File MRU`의 하위 경로는 Office 버전마다 다르므로 실제 hive에서 `Software\Microsoft\Office` 아래를 직접 확인할 것
- `Volatile Environment`가 오프라인 hive에 나타나는지는 환경/획득 방식에 따라 보고가 갈리므로, 이 키의 값을 근거로 쓸 때는 라이브 `HKCU` 또는 메모리에서 재확인할 것
