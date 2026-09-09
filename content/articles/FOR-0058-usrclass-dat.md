---
id: FOR-0058
title: "UsrClass.dat 기본: ShellBags가 사는 hive와 HKCU\\Software\\Classes"
slug: "usrclass-dat"
category: "Registry"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["UsrClass.dat", "UsrClass.dat.LOG1", "UsrClass.dat.LOG2", "BagMRU", "Bags", "NodeSlot", "MuiCache", "ProgID"]
file_paths: ["C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2", "%LocalAppData%\\Microsoft\\Windows\\UsrClass.dat"]
registry_paths: ["HKCU\\Software\\Classes", "HKU\\<SID>_Classes", "UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags", "HKCU\\Software\\Classes\\CLSID", "HKCU\\Software\\Classes\\Applications"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r UsrClass.dat -p shellbags", "rla.exe -f UsrClass.dat --out .", "xxd -l 16 UsrClass.dat"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["NodeSlot", "MRUListEx", "ProgId", "InprocServer32"]
file_formats: ["regf"]
primary_terms: ["UsrClass.dat", "HKCU\\Software\\Classes", "탐색기 활동 hive"]
keywords: ["UsrClass.dat", "HKCU\\Software\\Classes", "BagMRU", "Bags", "ShellBags", "HKCR", "파일 연결", "ProgID", "MuiCache", "AppData\\Local\\Microsoft\\Windows", "트랜잭션 로그", "사용자 hive"]
aliases: ["usrclass.dat", "유저클래스", "쉘백 어느 파일", "shellbags 위치", "탐색기 방문 폴더 hive", "HKCU Software Classes 파일", "파일 연결 레지스트리"]
symptom_keywords: ["NTUSER.DAT에 BagMRU가 없다", "ShellBags가 어느 파일에 있는지", "폴더를 열어봤는지 알고 싶다", "확장자 기본 프로그램이 바뀌었다", "UsrClass.dat이 무슨 파일인지"]
related: ["FOR-0051", "FOR-0057", "FOR-0068", "FOR-0069"]
source_ids: ["SRC-017", "SRC-027", "SRC-100"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`UsrClass.dat`은 `AppData\Local\Microsoft\Windows`에 있는 두 번째 사용자 hive로 `HKCU\Software\Classes`(= `HKU\<SID>_Classes`)에 마운트되며, **ShellBags(`BagMRU`/`Bags`)와 사용자별 파일 연결·COM 등록**이 여기에 산다. `NTUSER.DAT`만 열고 "탐색기 흔적이 없다"고 결론 내리는 사고가 이 파일을 몰라서 생긴다.

## 개념

| 항목 | 내용 |
| --- | --- |
| 파일 위치 | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| 마운트되는 키 | `HKU\<SID>_Classes`, 즉 `HKCU\Software\Classes` |
| `HKCR`와의 관계 | `HKCR` = `HKLM\SOFTWARE\Classes`(머신 전역) + 이 파일(사용자 전용)의 병합 뷰. **충돌 시 사용자 쪽이 우선** |
| 개수 | 프로필당 1개. `NTUSER.DAT`과 짝을 이룬다 |
| 형식 | `regf`. `NTUSER.DAT`과 완전히 동일한 포맷 |
| 크기 | 탐색기를 많이 쓴 계정에서는 `NTUSER.DAT`보다 커지는 일도 흔하다 |

`HKCU\Software\Classes`는 `NTUSER.DAT` 안의 하위 키가 **아니다.** 로그온 시 커널이 별도 파일을 그 지점에 붙인다. 그래서 오프라인에서 `NTUSER.DAT`을 열면 `Software\Classes`가 비어 있거나 껍데기만 보인다. 루트키와 파일의 전체 대응은 [FOR-0051](./registry-hive-map.html)에 정리되어 있다.

## 파일 / 경로

### 추출 시 함께 꺼낼 파일

`UsrClass.dat` 하나만 꺼내면 dirty hive에서 가장 최근 폴더 방문이 누락된다. 같은 폴더에서 아래를 **전부** 꺼낸다.

| 파일 | 역할 |
| --- | --- |
| `UsrClass.dat` | hive 본체 |
| `UsrClass.dat.LOG1` | 트랜잭션 로그 1 (미반영 최신 변경) |
| `UsrClass.dat.LOG2` | 트랜잭션 로그 2 |
| `UsrClass.dat{GUID}.TM.blf` | CLFS 트랜잭션 레지스트리 로그 (있으면) |
| `UsrClass.dat{GUID}.TMContainer0000...regtrans-ms` | 같은 TxR 컨테이너 (있으면) |

폴더 단위로 통째 확보하는 편이 안전하다. `AppData\Local\Microsoft\Windows` 아래에는 함께 볼 아티팩트가 더 있다.

| 같은 폴더 아래 | 무엇인가 |
| --- | --- |
| `Explorer\thumbcache_*.db` | 썸네일 캐시. 지워진 이미지의 미리보기가 남는다 |
| `Explorer\iconcache_*.db` | 아이콘 캐시 |
| `WebCache\WebCacheV01.dat` | IE/레거시 Edge 히스토리·쿠키 (ESE DB) |
| `INetCache\`, `History\` | 브라우저 캐시/기록 잔재 |
| `Recent\` (Roaming 쪽) | LNK와 Jump List. 경로는 `AppData\Roaming\Microsoft\Windows\Recent` |

### 트랜잭션 로그와 dirty 판정

base block의 primary sequence number(`0x04`)와 secondary(`0x08`)를 비교해 다르면 dirty다.

```bash
xxd -l 16 UsrClass.dat
```

```text
00000000: 7265 6766 3a01 0000 3c01 0000 ....   (primary 0x13a != secondary 0x13c -> dirty)
```

dirty면 `rla`로 `.LOG1`/`.LOG2`를 반영한 뒤 파싱한다. 반영 절차는 [FOR-0061](./userassist.html)에서 다룬 것과 동일하며, 파일 이름만 바뀐다. 로그오프 전에 획득한 이미지일수록 dirty일 확률이 높고, 그 미반영 부분이 **바로 사건 시각의 폴더 방문**인 경우가 많다.

## 주요 필드

### ShellBags — 이 hive의 핵심

| 항목 | 값 |
| --- | --- |
| 키 경로 | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` |
| 짝 키 | `Local Settings\Software\Microsoft\Windows\Shell\Bags` |
| 의미 | **탐색기 창으로 실제로 열어본 폴더**의 계층과 그 창의 표시 설정 |
| 증거력 | 폴더가 삭제되고 볼륨이 분리된 뒤에도 **경로 이름이 남는다.** USB·네트워크 공유·삭제된 폴더 추적의 결정적 근거 |

`BagMRU`는 폴더 계층을 그대로 트리로 옮긴 구조다. 각 키 아래 값의 역할은 다음과 같다.

| 값 이름 | 내용 |
| --- | --- |
| `0`, `1`, `2` ... | 자식 폴더 하나를 나타내는 shell item(PIDL) 바이트. 폴더 이름과 시각이 이 안에 들어 있다 |
| `MRUListEx` | 같은 부모 아래 자식들의 최신 접근 순서(4바이트 리틀엔디언 배열, `FF FF FF FF`로 끝) |
| `NodeSlot` | `Bags\<NodeSlot>\Shell\{GUID}`로 이어지는 번호. 그 창의 보기 모드·크기가 저장된다 |

shell item 파싱, 항목 내부 타임스탬프의 신뢰도, `NodeSlot` 해석은 분량이 크므로 전담 글 [FOR-0068](./shellbags.html)에서 다룬다. 여기서는 **"어느 파일 어느 키에 있는가"** 만 확정한다.

경로의 최상단은 실제 문자열이 아니라 Known Folder GUID(예: 데스크톱, 내 PC)로 시작한다. GUID ↔ 폴더 대응은 [FOR-0061](./userassist.html)의 Known Folder 표와 같은 목록을 쓴다.

> Windows XP 시절에는 ShellBags가 `NTUSER.DAT`의 `Software\Microsoft\Windows\Shell\BagMRU`와 `ShellNoRoam\BagMRU`에 있었다. Windows 7 이후로는 `UsrClass.dat`이다. 오래된 자료를 보고 `NTUSER.DAT`을 뒤지면 아무것도 못 찾는다.

### 파일 연결 (사용자별 오버라이드)

| 키 (hive 루트 기준) | 내용 |
| --- | --- |
| `.<확장자>` (예: `.txt`) | 기본값(default value)에 ProgID 문자열. `OpenWithProgids`, `OpenWithList` 서브키 |
| `<ProgID>\shell\open\command` | 그 형식을 열 때 실행되는 **실제 명령행**. `"%1"` 인자 포함 |
| `Applications\<exe이름>\shell\open\command` | 특정 실행 파일의 열기 명령. "연결 프로그램" 목록의 출처 |
| `CLSID\{GUID}\InprocServer32` | 사용자별 COM 등록. 값이 사용자 폴더의 DLL을 가리키면 **COM 하이재킹 의심** |
| `Local Settings\MuiCache\<n>\52C64B7E` | 실행 파일 경로 ↔ 창 제목/설명 캐시 (실행 흔적 보조). 전담 글 FOR-0069 |

**어떤 프로그램이 실제 기본값인지**를 정하는 사용자 선택은 이 hive가 아니라 `NTUSER.DAT`의 `Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.<ext>\UserChoice`에 `ProgId`와 `Hash`로 저장된다. 두 hive를 같이 봐야 "무엇으로 열리도록 되어 있었는가"가 완성된다([FOR-0057](./ntuser-dat.html)).

악성 지속성 관점에서 이 hive가 중요한 이유는 **관리자 권한 없이 쓸 수 있고 `HKLM`보다 우선**한다는 점이다. 확장자 하나의 `shell\open\command`가 사용자 폴더의 스크립트를 가리키면 그것만으로 지속성이 성립한다.

### NTUSER.DAT 과 UsrClass.dat 역할 구분

| 알고 싶은 것 | 열 파일 | 키 |
| --- | --- | --- |
| 사용자가 직접 실행한 프로그램·횟수 | `NTUSER.DAT` | `...\Explorer\UserAssist` |
| 최근 열어본 문서 | `NTUSER.DAT` | `...\Explorer\RecentDocs` |
| 주소창/실행창에 입력한 문자열 | `NTUSER.DAT` | `TypedPaths`, `TypedURLs`, `RunMRU` |
| 열기/저장 대화상자 이력 | `NTUSER.DAT` | `...\Explorer\ComDlg32` |
| 사용자 자동실행 | `NTUSER.DAT` | `...\CurrentVersion\Run` |
| **탐색기 창으로 방문한 폴더** | **`UsrClass.dat`** | `Local Settings\...\Shell\BagMRU` ([FOR-0068](./shellbags.html)) |
| 폴더 창의 보기 설정 | `UsrClass.dat` | `Local Settings\...\Shell\Bags` |
| 확장자 ↔ ProgID ↔ 실행 명령 | `UsrClass.dat` | 루트의 `.<ext>`, `<ProgID>` |
| 사용자별 COM 등록/하이재킹 | `UsrClass.dat` | `CLSID\{GUID}\InprocServer32` |
| 실행 파일 이름/설명 캐시(MUICache) | `UsrClass.dat` | `Local Settings\MuiCache\<n>\52C64B7E` |
| UWP/스토어 앱 등록 정보 | `UsrClass.dat` | `Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel` |

두 파일은 항상 **쌍으로** 확보한다. 하나만 있으면 사용자 활동의 절반이 비어 있다.

## 빠른 명령

```powershell
rip.exe -r 'C:\case\UsrClass.dat' -p shellbags > 'C:\case\shellbags.txt'
```

```powershell
# 1) 로그 반영 먼저 (LOG1/LOG2 를 같은 폴더에 둔 상태에서)
rla.exe -f 'C:\case\UsrClass.dat' --out 'C:\case\clean'

# 2) hive 인지 확인 (선두 4바이트가 regf)
Format-Hex -Path 'C:\case\clean\UsrClass.dat' -Count 16

# 3) 사용자별로 두 hive 를 같이 모으기
Get-ChildItem 'C:\case\Users' -Directory | ForEach-Object {
  $u = $_.Name
  Copy-Item "$($_.FullName)\NTUSER.DAT*" "C:\case\hives\$u\" -ErrorAction SilentlyContinue
  Copy-Item "$($_.FullName)\AppData\Local\Microsoft\Windows\UsrClass.dat*" "C:\case\hives\$u\" -ErrorAction SilentlyContinue
}
```

GUI로는 RegistryExplorer에 `UsrClass.dat`을 로드해 `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`로 이동한다([FOR-0059](./registry-explorer.html)). ShellBags를 폴더 트리 형태로 복원해 보려면 같은 제작자의 ShellBags Explorer(GUI)/`SBECmd`(CLI)가 전용 도구이지만 기본 툴킷에는 포함되어 있지 않으므로, 없으면 RegRipper의 shellbags 플러그인으로 대체한다. 플러그인 이름은 `rip.exe -l`로 먼저 확인한다([FOR-0060](./regripper.html)).

## 함께 보는 artifact

| 이 hive에서 얻은 것 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| `BagMRU`의 폴더 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 폴더가 실제로 존재했는지, 언제 생기고 지워졌는지 |
| 볼륨 루트가 낯선 드라이브 문자 | `NTUSER.DAT\...\MountPoints2`, `SYSTEM\MountedDevices` | 그 문자가 어떤 USB/공유였는지 |
| `\\서버\공유` 형태의 항목 | Security 4624 Logon Type 3, SMB 트래픽 | 공유 접근 시점과 계정 |
| 폴더는 알았지만 파일이 필요하다 | LNK(`Recent`), Jump List, `RecentDocs` | 그 폴더 안에서 실제로 연 파일 |
| 확장자 `shell\open\command`가 수상하다 | 그 실행 파일의 Prefetch, `Amcache.hve` | 실제 실행 여부와 해시 |
| `CLSID\...\InprocServer32`가 사용자 폴더 DLL | 그 DLL의 `$MFT` 시각, 메모리 ([FOR-0214](./volatility-pslist.html)) | 로드된 프로세스 |
| 지워진 이미지의 흔적 | 같은 폴더의 `thumbcache_*.db` | 삭제된 사진의 미리보기 |

## 흔한 실수

- **`NTUSER.DAT`에서 `BagMRU`를 찾다가 "ShellBags가 없다"고 결론내는 것.** Windows 7 이후 위치는 `UsrClass.dat`이다. 애초에 두 hive를 같이 꺼내면 생기지 않는 실수다.
- **`UsrClass.dat`만 꺼내고 `.LOG1`/`.LOG2`를 두고 오는 것.** 탐색기 활동은 로그오프 직전까지 계속 쌓이므로 미반영 변경이 남을 확률이 높다. 사건 시각의 폴더 방문이 통째로 빠진다.
- **`AppData\Roaming` 쪽에서 찾는 것.** 이 파일은 `AppData\Local\Microsoft\Windows`에 있다. `Roaming\Microsoft\Windows`에는 `Recent`(LNK)와 Jump List가 있다.
- **`HKCU\Software\Classes`를 `NTUSER.DAT` 내부 키로 취급하는 것.** 별도 파일이 그 지점에 마운트된 것이다. `NTUSER.DAT`에서 그 경로를 찾으면 비어 있다.
- **`HKCR`에서 본 값을 머신 전역 설정으로 단정하는 것.** `HKCR`는 병합 뷰이고 사용자 쪽(`UsrClass.dat`)이 우선한다. "이 확장자가 무엇으로 열리는가"는 사용자별로 다르다.
- **ShellBags 항목이 있다 = 그 폴더가 그 시각에 존재했다, 로 단정하는 것.** 항목은 창을 열었던 사실의 흔적이며, shell item 안의 시각은 폴더의 현재 시각이 아니라 **기록 당시 캐시된 값**이다. 시각 결론은 `$MFT`와 교차검증한다.
- **ShellBags에 없다 = 방문하지 않았다, 로 단정하는 것.** 주소창에 경로를 타이핑해 들어간 경우, 대화상자로만 접근한 경우는 다른 키(`TypedPaths`, `ComDlg32`)에 남는다.
- **키 LastWrite를 항목별 방문 시각으로 쓰는 것.** LastWrite는 키 단위·마지막 1회다. `MRUListEx`는 순서만 알려주고 시각은 알려주지 않는다.
- **시간대 보정 누락.** 이 hive의 모든 FILETIME은 UTC다. KST는 +9시간, Unix epoch와의 차이는 `11644473600`초다.

## mini example

```text
문제:
"직원이 사내 공유에서 자료를 빼내 USB로 옮긴 것으로 의심된다. 사용자
 jhkim 이 탐색기로 열어본 폴더 중 외부 저장장치와 공유 경로를 찾으세요.
 첨부: jhkim 프로필 폴더 전체"

1. 첫 시도 (실패):
   NTUSER.DAT 을 RegistryExplorer 로 열고
   Software\Microsoft\Windows\Shell\BagMRU 를 찾았다.
   -> 그런 키가 없다. Software\Classes 도 비어 있다.
      "hive 가 손상됐다"고 판단해 다시 추출했다.

   왜 틀렸나:
   Windows 7 이후 ShellBags 는 UsrClass.dat 에 있고,
   HKCU\Software\Classes 자체가 별도 파일이라 NTUSER.DAT 에는 없다.

2. 피벗: 올바른 파일 찾기
   AppData\Local\Microsoft\Windows\UsrClass.dat
   같은 폴더에 UsrClass.dat.LOG1 / .LOG2 도 있다.

3. 두 번째로 틀린 접근:
   UsrClass.dat 만 작업 폴더로 복사해 파싱했다.
   -> BagMRU 최상위 항목이 8개, 최신 LastWrite 가 사건 전날이다.
      Format-Hex 로 헤더를 보니 primary 0x13a, secondary 0x13c 로 불일치.
      dirty hive 였고 사건 당일 방문 기록이 로그에만 있었다.

4. 로그 반영 후 재파싱
   rla.exe -f UsrClass.dat --out clean\
   rip.exe -r clean\UsrClass.dat -p shellbags > bags.txt

   Select-String -Path bags.txt -Pattern '^\\\\|E:\\|F:\\'

   E:\backup\2026Q1
   E:\backup\2026Q1\hr
   \\fileserv\share01\personnel
   \\fileserv\share01\personnel\payroll

5. 교차검증
   - E: 가 어떤 장치였는지 -> NTUSER.DAT\...\MountPoints2 + SYSTEM\MountedDevices
   - \\fileserv 접근 시각    -> Security 4624 (Logon Type 3)
   - 그 폴더 안의 파일       -> Recent 폴더의 LNK, RecentDocs

정답: E:\backup\2026Q1\hr (USB), \\fileserv\share01\personnel\payroll (공유)
      두 경로 모두 UsrClass.dat 의 BagMRU 에서 확인
```

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `UsrClass.dat`이 `HKU\<SID>_Classes`(= `HKCU\Software\Classes`)로 마운트된다는 점, `HKCR`가 머신/사용자 Classes의 병합 뷰라는 점
- SRC-027 — Libyal libregf, REGF 포맷 문서: `UsrClass.dat`이 `NTUSER.DAT`과 동일한 `regf` 포맷이라는 점, sequence number 불일치로 dirty 판정, LastWrite가 키 단위라는 점
- SRC-100 — Microsoft Learn, Known Folder GUIDs: `BagMRU` 최상단 항목이 실제 경로 문자열이 아니라 Known Folder로 시작하는 이유
- `Local Settings\MuiCache\<n>\52C64B7E`의 숫자 서브키와 `AppModel` 하위 구조는 Windows 버전에 따라 다르므로 실제 hive에서 확인할 것
- ShellBags Explorer / `SBECmd`는 기본 툴킷에 포함되어 있지 않다. 사용 전 배포판 존재를 확인하고, 없으면 RegRipper 플러그인으로 대체할 것
