---
id: FOR-0051
title: "Registry hive 전체 지도: 루트키와 디스크상 파일 대응표"
slug: "registry-hive-map"
category: "Registry"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Registry hive", "SAM", "SYSTEM", "SOFTWARE", "SECURITY", "DEFAULT", "NTUSER.DAT", "UsrClass.dat", "Amcache.hve", "regf"]
file_paths: ["C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Windows\\System32\\config\\SECURITY", "C:\\Windows\\System32\\config\\DEFAULT", "C:\\Windows\\System32\\config\\BCD-Template", "C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"]
registry_paths: ["HKLM\\SAM", "HKLM\\SYSTEM", "HKLM\\SOFTWARE", "HKLM\\SECURITY", "HKU\\.DEFAULT", "HKCU", "HKCU\\Software\\Classes", "HKCR", "HKCC"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "FTK Imager", "KAPE", "HxD", "xxd / hexdump"]
commands: ["xxd -l 16 SYSTEM", "rla.exe -d C:\\case\\config --out C:\\case\\clean", "reg save HKLM\\SYSTEM C:\\out\\SYSTEM"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["LastWrite", "primary sequence number", "secondary sequence number", "root key offset"]
file_formats: ["regf", "hve"]
primary_terms: ["Registry hive", "레지스트리 hive", "hive", "regf", "hive 파일 어디"]
keywords: ["Registry", "hive", "HKLM", "HKCU", "HKU", "HKCR", "HKCC", "NTUSER.DAT", "UsrClass.dat", "Amcache.hve", "regf", "config 폴더", "LastWrite", "트랜잭션 로그"]
aliases: ["레지스트리 hive", "hive 파일 어디", "레지스트리 파일 위치", "NTUSER.DAT 위치", "config 폴더", "hive 종류", "HKLM 어느 파일"]
symptom_keywords: ["어느 hive를 봐야 하는지 모르겠다", "레지스트리 파일이 어디 있는지", "hive 파일인지 확인하고 싶다", "확장자 없는 파일이 나왔다", "HKLM이 무슨 파일인지"]
related: ["FOR-0053", "FOR-0057", "FOR-0058", "FOR-0061"]
source_ids: ["SRC-017", "SRC-027", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Windows 레지스트리는 하나의 파일이 아니라 여러 개의 `regf` 형식 hive 파일이며, 목적(계정·시간대·설치 프로그램·사용자 활동·탐색기 흔적)에 따라 열어야 할 파일이 정해져 있으므로 **문제를 읽고 hive를 먼저 고르는 것**이 레지스트리 분석의 첫 단계다.

## 개념

레지스트리의 논리 트리(`HKLM\...`)는 실행 중인 커널이 여러 hive 파일을 마운트해 합쳐 만든 **뷰**다. 이미지에서 파일만 꺼내면 그 뷰가 없으므로, 오프라인 분석에서는 항상 "어느 파일의 어느 키"로 생각한다.

- hive 파일 1개 = 트리 1개. 확장자는 대개 없다(`SYSTEM`, `SAM`) 또는 `.DAT`/`.hve`
- 파일 선두 4바이트가 `regf`(`72 65 67 66`)이면 레지스트리 hive다
- 선두 4096바이트(`0x1000`)가 base block(헤더), 그 뒤부터 실제 키/값 데이터(hive bin)
- 키는 `nk` 레코드, 값은 `vk` 레코드로 저장된다. **타임스탬프는 키(`nk`)에만 있고 값(`vk`)에는 없다**

### base block에서 바로 쓰는 필드

| 오프셋 | 내용 | 포렌식 용도 |
| --- | --- | --- |
| `0x00` | 시그니처 `regf` | hive 여부 판정 |
| `0x04` | primary sequence number | 아래 dirty 판정 |
| `0x08` | secondary sequence number | 아래 dirty 판정 |
| `0x0C` | 헤더 기록 시각 (FILETIME, UTC) | hive가 마지막으로 정리된 시점 |
| `0x24` | root key offset | 파서가 루트를 찾는 값 |
| `0x30` | hive 파일 경로 (UTF-16LE, 64바이트) | 이 hive가 원래 어디 있었는지 |
| `0x1FC` | 체크섬 | 손상 판정 |

**primary와 secondary sequence number가 다르면 그 hive는 정상 종료되지 않은 상태(dirty)이고, 최신 변경이 `.LOG1`/`.LOG2`에만 있다.** 이때 `rla`로 로그를 반영하지 않으면 마지막 활동을 놓친다. 트랜잭션 로그 반영 절차는 [FOR-0061](./userassist.html)에서 다룬다.

## 파일 / 경로

### 시스템 hive (`C:\Windows\System32\config\`)

| 파일 | 마운트되는 루트키 | 무엇이 들어 있나 |
| --- | --- | --- |
| `SAM` | `HKLM\SAM` | 로컬 사용자/그룹 계정 메타데이터 |
| `SYSTEM` | `HKLM\SYSTEM` | ControlSet, 서비스, 시간대, 장치, MountedDevices |
| `SOFTWARE` | `HKLM\SOFTWARE` | 설치 프로그램, OS 버전, ProfileList, 자동실행 |
| `SECURITY` | `HKLM\SECURITY` | 감사 정책, 도메인 SID, LSA Secrets |
| `DEFAULT` | `HKU\.DEFAULT` | 프로필이 없는 컨텍스트(`SYSTEM` 계정)의 사용자 설정 |
| `BCD-Template` | (마운트 안 됨) | 부트 설정 **템플릿**. 실제 부팅에 쓰이는 BCD 저장소가 아니다 |

`config` 폴더에는 같은 이름의 `.LOG1`, `.LOG2`, 그리고 `RegBack` 폴더(구버전 백업)가 함께 있다. **hive를 꺼낼 때 로그 파일도 같은 폴더로 함께 꺼낸다.**

### 사용자 hive

| 파일 | 마운트되는 루트키 | 무엇이 들어 있나 |
| --- | --- | --- |
| `C:\Users\<user>\NTUSER.DAT` | `HKCU` (= `HKU\<SID>`) | UserAssist, RecentDocs, Run, TypedPaths, TypedURLs |
| `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKCU\Software\Classes` (= `HKU\<SID>_Classes`) | **ShellBags**(BagMRU/Bags), 사용자별 파일 연결 |

### 파일이 없는 루트키

| 루트키 | 실체 |
| --- | --- |
| `HKCR` | `HKLM\SOFTWARE\Classes` + `HKCU\Software\Classes`(=`UsrClass.dat`)를 합친 가상 뷰 |
| `HKCC` | `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current` 로 가는 링크 |
| `HKLM\HARDWARE` | 부팅 때 메모리에만 만들어지는 휘발성 hive. **디스크에 파일이 없다** |
| `HKLM\SYSTEM\CurrentControlSet` | 부팅 때 만들어지는 심볼릭 링크. 오프라인 hive에는 없다 ([FOR-0053](./system-controlset.html)) |

### hive 형식이지만 레지스트리 트리가 아닌 파일

| 파일 | 내용 |
| --- | --- |
| `C:\Windows\AppCompat\Programs\Amcache.hve` | 실행/설치된 프로그램의 경로·SHA-1·크기·컴파일 시각 |
| `C:\Windows\System32\config\BBI`, `ELAM`, `DRIVERS` 등 | 환경에 따라 존재하는 보조 hive |

`Amcache.hve`는 `regf` 파일이므로 RegistryExplorer로 그냥 열린다.

## 주요 필드

### 목적별 인덱스 — "이걸 알고 싶으면 이 hive"

| 알고 싶은 것 | 열 hive | 대표 키 |
| --- | --- | --- |
| 사용자 계정 목록, RID, 마지막 로그온 | `SAM` | `SAM\Domains\Account\Users` ([FOR-0052](./sam-user-accounts.html)) |
| 시간대 (모든 시각 보정의 전제) | `SYSTEM` | `Control\TimeZoneInformation` ([FOR-0054](./system-timezone.html)) |
| 컴퓨터 이름 | `SYSTEM` | `Control\ComputerName\ComputerName` |
| 서비스 / 드라이버 / 악성 서비스 | `SYSTEM` | `Services\<name>` |
| USB 연결 이력 | `SYSTEM` | `Enum\USBSTOR`, 루트의 `MountedDevices` |
| 실행 이력 (Shimcache) | `SYSTEM` | `Control\Session Manager\AppCompatCache` |
| 실행 이력 (해시 포함) | `Amcache.hve` | `Root\InventoryApplicationFile` |
| OS 버전 / 설치 시각 | `SOFTWARE` | `Microsoft\Windows NT\CurrentVersion` ([FOR-0055](./software-installed-programs.html)) |
| 설치된 프로그램 목록 | `SOFTWARE` | `Microsoft\Windows\CurrentVersion\Uninstall` |
| SID ↔ 프로필 폴더 매핑 | `SOFTWARE` | `Microsoft\Windows NT\CurrentVersion\ProfileList` |
| 감사 정책 / 도메인 가입 | `SECURITY` | `Policy\PolAdtEv`, `Policy\PolPrDmN` ([FOR-0056](./security-hive-overview.html)) |
| 사용자가 직접 실행한 프로그램 | `NTUSER.DAT` | `...\Explorer\UserAssist` ([FOR-0061](./userassist.html)) |
| 최근 열어본 문서 | `NTUSER.DAT` | `...\Explorer\RecentDocs` |
| 주소창에 입력한 경로/URL | `NTUSER.DAT` | `...\Explorer\TypedPaths`, `...\TypedURLs` |
| 탐색기로 방문한 폴더 (ShellBags) | `UsrClass.dat` | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` |
| 사용자별 자동실행 | `NTUSER.DAT` | `Software\Microsoft\Windows\CurrentVersion\Run` |

### LastWrite 시각의 의미와 한계

| 사실 | 설명 |
| --- | --- |
| 단위 | FILETIME (1601-01-01 UTC 기준 100ns). **항상 UTC** |
| 대상 | **키에만 붙는다.** 값 하나하나에는 시각이 없다 |
| 의미 | 그 키의 값이 마지막으로 추가/변경/삭제된 시각 |
| 한계 1 | 값이 10개인 키에서 **어느 값이 그때 바뀐 것인지 알 수 없다** |
| 한계 2 | 하위 키가 바뀌어도 부모 키의 LastWrite는 갱신되지 않는다 |
| 한계 3 | 이전 변경 이력이 없다. 마지막 1회뿐이다 |
| 한계 4 | 값 데이터 안에 별도 FILETIME이 있으면(UserAssist의 Last Executed 등) **그쪽이 더 정확하다** |

값이 하나뿐인 키(예: `USBSTOR\<device>` 아래 인스턴스 키)에서는 LastWrite가 그 값의 시각과 사실상 같아지므로 "USB를 마지막에 꽂은 시각" 같은 결론에 쓸 수 있다.

## 빠른 명령

```bash
xxd -l 16 SYSTEM
```

```text
00000000: 7265 6766 2900 0000 2900 0000 ....   ("regf" = 레지스트리 hive)
```

primary(`0x04`)와 secondary(`0x08`)가 둘 다 `0x29`로 같으므로 이 hive는 clean이다.

```powershell
# 1) 트랜잭션 로그를 폴더 단위로 일괄 반영
rla.exe -d "C:\case\config" --out "C:\case\clean"

# 2) 어떤 hive인지 모르는 파일을 RegRipper로 판정 (루트키 이름이 찍힌다)
rip.exe -r "C:\case\unknown.dat" -p profilelist

# 3) 라이브 시스템에서 hive 저장 (관리자 권한 필요)
reg save HKLM\SYSTEM C:\out\SYSTEM
reg save HKLM\SOFTWARE C:\out\SOFTWARE
reg save HKLM\SAM C:\out\SAM
```

이미지에서 꺼내는 방법은 상황별로 다르다.

| 상황 | 방법 |
| --- | --- |
| E01/RAW 이미지 | FTK Imager로 열고 `Windows\System32\config` 폴더 → Export Files ([FOR-0016](./ftk-imager-open-image.html)) |
| 이미지 마운트 후 | Arsenal Image Mounter로 마운트 → 탐색기로 복사 ([FOR-0017](./arsenal-image-mounter.html)) |
| 라이브 시스템 | KAPE의 `RegistryHives` 타깃, 또는 위 `reg save` |
| Linux / Sleuth Kit | `fls -o <offset> -r image.dd \| grep -i ntuser` → `icat`으로 추출 |

## 함께 보는 artifact

| 이 글에서 얻은 것 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| hive 목록 확보 | `SYSTEM\Select` | 활성 ControlSet 번호 ([FOR-0053](./system-controlset.html)) |
| 활성 ControlSet | `Control\TimeZoneInformation` | 모든 시각 보정 기준 ([FOR-0054](./system-timezone.html)) |
| `SAM`의 RID/사용자명 | `SOFTWARE\...\ProfileList` | SID ↔ `C:\Users\<name>` 매핑 |
| 프로필 폴더 이름 | 해당 `NTUSER.DAT`, `UsrClass.dat` | 사용자별 활동 |
| 프로그램 경로 | `Amcache.hve`, Prefetch | 실행 사실과 해시 |
| hive 파일 자체의 생성/수정 시각 | `$MFT` ([FOR-0021](./mft-basics.html)) | hive가 언제 디스크에 생겼는지, 반포렌식 흔적 |

## 흔한 실수

- **`CurrentControlSet` 경로를 오프라인 hive에 그대로 입력하는 것.** 그 키는 부팅 때 만들어지는 링크라 파일에 없다. `Select\Current` 값을 읽어 `ControlSet001` 같은 실제 이름으로 바꿔야 한다.
- **`.LOG1`/`.LOG2`를 빼놓고 hive만 추출하는 것.** dirty hive의 최신 변경은 로그에만 있다. `rla`를 거치지 않으면 "마지막 실행", "마지막 USB 연결" 같은 답이 틀린다.
- **`BCD-Template`을 부트 설정으로 읽는 것.** 이름 그대로 템플릿이다. 실제 부트 구성은 시스템 예약 파티션의 `\Boot\BCD`에 있다.
- **ShellBags를 `NTUSER.DAT`에서 찾는 것.** Windows 7 이후 `BagMRU`는 `UsrClass.dat`에 있다. `NTUSER.DAT`만 열고 "없다"고 결론 내리는 사고가 흔하다.
- **키 LastWrite를 "값이 만들어진 시각"으로 단정하는 것.** 키 단위 시각이므로 값이 여러 개면 어느 값 때문인지 알 수 없다. 값 데이터에 자체 타임스탬프가 있으면 그것을 쓴다.
- **LastWrite를 로컬 시각으로 읽는 것.** FILETIME이므로 UTC다. KST 답을 요구하면 +9시간 한다. Unix epoch와의 차이는 `11644473600`초다.
- **`HKLM\HARDWARE`나 `HKCC`에 해당하는 파일을 찾아 헤매는 것.** 휘발성이라 디스크에 없다. 하드웨어 정보가 필요하면 `SYSTEM\ControlSet001\Enum`이나 메모리 덤프로 간다.
- **사용자가 여러 명인데 프로필 하나만 보는 것.** `C:\Users` 아래 모든 폴더의 `NTUSER.DAT`과 `UsrClass.dat`을 세어 보고 시작한다.

## mini example

```text
문제:
"압축을 풀었더니 확장자 없는 파일 5개(SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT)와
 ntuser.dat 1개가 들어 있습니다. 이 PC의 컴퓨터 이름과 마지막에 로그온한
 로컬 사용자를 구하세요."

1. 파일 정체 확인
   for f in *; do xxd -l 4 "$f"; done
   -> 전부 7265 6766 ("regf") = 레지스트리 hive 6개

2. 첫 시도 (실패):
   RegistryExplorer로 SYSTEM을 열고
   SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName 으로 이동
   -> CurrentControlSet 이라는 키가 트리에 없다.
      "hive가 손상됐나?" 하고 다른 hive를 뒤지느라 시간을 버렸다.

   왜 틀렸나:
   CurrentControlSet 은 부팅 시 커널이 만드는 휘발성 심볼릭 링크다.
   디스크 파일에는 ControlSet001 / ControlSet002 만 존재한다.

3. 피벗: Select 키로 활성 ControlSet 판정
   SYSTEM\Select
     Current      = 1
     LastKnownGood= 1
   -> 활성은 ControlSet001

   SYSTEM\ControlSet001\Control\ComputerName\ComputerName
     ComputerName = DESKTOP-K7P2N9
   (같은 부모의 ActiveComputerName 은 휘발성이라 없을 수 있다)

4. 두 번째로 틀린 판단:
   "마지막 로그온"을 NTUSER.DAT 의 LastWrite 로 답하려 했다.
   -> NTUSER.DAT 은 로그오프/종료 시점에도 갱신되므로 로그온 시각이 아니다.
      SAM 의 F 값에 계정별 마지막 로그온 시각이 있으므로 그쪽이 근거다.

5. rip.exe -r SAM -p samparse
     Username : jhkim  [1001]
     Last Login Date : 2026-03-14 07:11:38Z
     Username : Administrator [500]
     Last Login Date : Never

6. UTC -> KST 보정
   2026-03-14 07:11:38 UTC + 9h = 2026-03-14 16:11:38 KST

정답: DESKTOP-K7P2N9 / jhkim (2026-03-14 16:11:38 KST)
```

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: 루트키와 `System32\config` 파일 대응, `HKCR`/`HKCC`가 가상 뷰라는 점
- SRC-027 — Libyal libregf, REGF 포맷 문서: `regf` 시그니처, base block 오프셋, sequence number로 dirty 판정, `nk` 키에만 LastWrite가 있다는 점
- SRC-004 — Eric Zimmerman 문서: `rla`의 로그 반영, RegistryExplorer로 `Amcache.hve` 등 임의 regf 열기
- `config` 폴더의 보조 hive 구성과 도구 메뉴 경로는 Windows 버전·도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
