---
id: FOR-0069
title: "MUICache로 실행된 프로그램의 경로와 FileDescription 확인"
slug: "muicache"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["MUICache", "MuiCache", "UsrClass.dat", "FileDescription", "FriendlyAppName", "ShellNoRoam"]
file_paths: ["C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "C:\\Users\\<user>\\NTUSER.DAT"]
registry_paths: ["UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "NTUSER.DAT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache", "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "RECmd", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r UsrClass.dat -p muicache", "rip.exe -r NTUSER.DAT -p muicache", "rla.exe -f UsrClass.dat --out ."]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["FileDescription", "FriendlyAppName", "ApplicationCompany", "LangID", "LastWrite"]
file_formats: ["regf", "pe"]
primary_terms: ["MUICache", "실행 파일 설명 캐시"]
keywords: ["MUICache", "MuiCache", "UsrClass.dat", "FileDescription", "FriendlyAppName", "ApplicationCompany", "ShellNoRoam", "실행 흔적", "삭제된 프로그램 경로", "GUI 실행"]
aliases: ["muicache", "실행 파일 설명", "filedescription 레지스트리", "삭제된 프로그램 경로", "실행했던 프로그램 목록", "usrclass muicache", "프로그램 정체 확인"]
symptom_keywords: ["프로그램이 실행된 적 있는지 알고 싶다", "삭제된 프로그램의 경로가 필요하다", "파일 이름을 바꿔서 정체를 모르겠다", "실행 횟수 없이 실행 사실만 필요하다", "Prefetch가 없는데 실행 흔적을 찾아야 한다", "muicache가 뭔지"]
related: ["FOR-0058", "FOR-0061", "FOR-0076", "FOR-0079"]
source_ids: ["SRC-017", "SRC-099", "SRC-100"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`MuiCache`는 **값 이름이 실행 파일의 전체 경로, 값 데이터가 그 파일의 `FileDescription` 리소스 문자열**인 캐시다. Explorer가 GUI로 프로그램을 띄울 때 표시용 이름을 캐시하므로 "그 경로에서 실행되었다"의 간접 증거가 되고, 파일이 지워진 뒤에도 경로와 설명이 남는다.

## 어떤 문제에서 필요한가

- "이 프로그램이 실행된 적 있는가" — Prefetch가 비활성/삭제된 환경에서의 대안
- "삭제된 프로그램이 어디에 있었는가" — 파일이 없어도 **경로 문자열**이 남는다
- "이름을 바꿔 놓은 실행 파일의 정체는 무엇인가" — `FileDescription`은 원본 리소스라 이름을 바꿔도 그대로다
- "이 사용자가 어떤 프로그램들을 다뤘는가" — 사용자별 hive라 계정이 자동으로 특정된다

[FOR-0061](./userassist.html)의 UserAssist가 실행 **횟수와 시각**을 주는 반면 MUICache는 **경로와 정체**만 준다. 대신 UserAssist가 비어 있거나 정리된 경우에도 남아 있는 경우가 있어 교차검증 가치가 크다.

## 문제에서 처음 볼 단서

1. 첨부에 `UsrClass.dat`이 있다 → ShellBags와 함께 MUICache를 반드시 본다
2. 지문에 "실행한 적", "설치되지 않은 프로그램", "정체를 밝혀라"
3. 실행 파일이 이미 삭제되어 `$MFT`에도 없고 **경로만이라도** 필요한 상황
4. 레지스트리 값 이름이 `C:\...\xxx.exe` 처럼 **전체 경로 자체**이고 데이터가 사람이 읽는 설명 문장이다

## 30초 절차

```powershell
rip.exe -r "C:\case\UsrClass.dat" -p muicache
```

구버전 환경이면 `NTUSER.DAT`에도 같은 플러그인을 돌린다.

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p muicache
```

GUI라면 RegistryExplorer로 `UsrClass.dat`을 열고 다음 경로로 이동한다.

```text
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
```

값이 문자열이라 **디코딩 없이 눈으로 바로 읽힌다.**

## 상세 절차

### 1단계 — 어느 hive의 어느 경로인가

| 환경 | hive | 키 경로 | 실행 중 시스템에서의 경로 |
| --- | --- | --- | --- |
| Windows 7 이후 (현행) | `UsrClass.dat` | `Local Settings\Software\Microsoft\Windows\Shell\MuiCache` | `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` |
| Windows XP (구버전) | `NTUSER.DAT` | `Software\Microsoft\Windows\ShellNoRoam\MUICache` | `HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache` |

`UsrClass.dat`의 위치는 다음이다.

```text
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2
```

`HKCU\Software\Classes`는 `NTUSER.DAT`이 아니라 **`UsrClass.dat`으로 매핑**된다. 이 사실을 모르면 `NTUSER.DAT`만 파싱하고 "MUICache 없음"이라고 잘못 결론 낸다. hive와 마운트 지점의 전체 대응표는 [FOR-0051](./registry-hive-map.html)에 있다.

일부 Windows 10/11 빌드에서는 `Local Settings\MuiCache\<인덱스>\<해시>` 형태의 별도 하위 구조도 관측된다. **이 구조의 내부 의미는 여기서 단정하지 않는다.** 값이 보이면 이름과 데이터를 기록하고 파서 출력으로 확인한다.

### 2단계 — 로그 반영

```powershell
rla.exe -f "C:\case\UsrClass.dat" --out "C:\case\clean"
rip.exe -r "C:\case\clean\UsrClass.dat" -p muicache > muicache.txt
```

`UsrClass.dat.LOG1`/`.LOG2`를 같은 폴더에 함께 꺼낸 뒤 replay한다. MUICache는 프로그램을 처음 띄울 때 갱신되므로 최근 항목이 로그에만 있을 수 있다.

### 3단계 — 값 이름과 값 데이터의 구조

이 artifact의 핵심은 **키·값 배치가 거꾸로**라는 점이다. 보통 값 이름이 라벨이고 데이터가 내용인데, MUICache는 **값 이름이 데이터(경로)** 다.

| 위치 | 내용 |
| --- | --- |
| 값 이름 | 실행 파일의 **전체 경로** (예: `C:\Users\jhkim\Downloads\dump_tool.exe`) |
| 값 데이터 | 그 PE 파일의 **`FileDescription`** 버전 리소스 문자열 |

Windows 7 이후에는 같은 경로에 접미사가 붙은 값이 함께 생긴다.

| 값 이름 형태 | 값 데이터 | 의미 |
| --- | --- | --- |
| `<경로>` | `FileDescription` | 파일 설명 |
| `<경로>.FriendlyAppName` | 표시용 앱 이름 | 쉘이 UI에 쓰는 이름 |
| `<경로>.ApplicationCompany` | 회사명 | PE의 `CompanyName` 리소스 |
| `@<DLL경로>,-<숫자>` | 리소스 문자열 | DLL 내부 문자열 리소스 캐시(프로그램 실행 증거가 아니다) |
| `LangID` | 언어 식별자 | 캐시 언어. artifact 값 아님 |

`@`로 시작하는 항목과 `LangID`는 **프로그램 실행과 무관한 문자열 리소스 캐시**이므로 분석에서 제외한다. 남는 것이 실제로 볼 항목이다.

### 4단계 — 출력 읽기

```powershell
rip.exe -r "C:\case\clean\UsrClass.dat" -p muicache > muicache.txt
```

```text
MUICache
Local Settings\Software\Microsoft\Windows\Shell\MuiCache
LastWrite Time: 2026-03-14 07:39:12Z

C:\Windows\system32\notepad.exe                          -> 메모장
C:\Program Files\7-Zip\7zFM.exe                          -> 7-Zip File Manager
C:\Program Files\7-Zip\7zFM.exe.FriendlyAppName          -> 7-Zip File Manager
C:\Program Files\7-Zip\7zFM.exe.ApplicationCompany       -> Igor Pavlov
C:\Users\jhkim\Downloads\dump_tool.exe                   -> Mimikatz for Windows
C:\Users\jhkim\Downloads\dump_tool.exe.ApplicationCompany-> gentilkiwi
C:\Users\jhkim\AppData\Local\Temp\svcupd.exe             -> Remote Access Service
@C:\Windows\system32\shell32.dll,-22019                  -> 문서
LangID                                                   -> (이진값)
```

읽는 순서는 이렇다.

1. `@`로 시작하는 항목과 `LangID`를 먼저 제외한다
2. 경로가 `Windows`·`Program Files`인 항목은 정상 배경으로 넘긴다
3. **`Users`·`Downloads`·`Temp`·`AppData`·`ProgramData` 경로만** 남긴다
4. 남은 항목의 `FileDescription`을 읽는다 — `dump_tool.exe`의 설명이 `Mimikatz for Windows`다. **파일명은 위장이고 설명이 정체를 폭로했다**
5. `.ApplicationCompany`가 `gentilkiwi`로 제작자까지 나온다

### 5단계 — 노이즈 제거

```powershell
# @ 로 시작하는 리소스 캐시와 LangID 제거, 사용자/임시 경로만 남기기
Select-String -Path .\muicache.txt -Pattern '^[A-Za-z]:\\' |
  Where-Object { $_.Line -notmatch '^\s*@' } |
  Where-Object { $_.Line -match '\\(Users|Temp|AppData|ProgramData|Downloads)\\' }
```

정규식은 PowerShell에서 **항상 작은따옴표**로 감싼다. 큰따옴표 안의 `$`는 변수로 확장된다.

### 6단계 — FileDescription을 무기로 쓰기

`FileDescription`은 PE 파일의 버전 리소스에 컴파일 시점에 박히는 문자열이다. **파일명을 바꿔도, 확장자를 바꿔도 변하지 않는다.**

| 값 이름(경로) | 값 데이터(`FileDescription`) | 판단 |
| --- | --- | --- |
| `C:\Users\...\Downloads\dump_tool.exe` | `Mimikatz for Windows` | 자격증명 덤프 도구. 이름 위장 |
| `C:\Users\...\Temp\svcupd.exe` | `Remote Access Service` | 정상 서비스명 흉내. 경로가 이상 |
| `C:\Users\...\report.pdf.exe` | `Nullsoft Install System` | 설치 프로그램. 이중 확장자 |
| `C:\Users\...\a.exe` | `AnyDesk` | 원격제어 도구 반출 경로 |
| `C:\Windows\Temp\x.exe` | 빈 문자열 | 리소스 없음. 직접 컴파일된 도구 가능 |

`FileDescription`이 **비어 있는 것도 정보**다. 정식 배포되는 상용/오픈소스 바이너리는 대개 버전 리소스를 갖고 있다.

### 7단계 — 무엇이 없는지 확정하고 다음으로 넘긴다

| 필요한 정보 | MUICache에 있는가 | 어디로 가야 하는가 |
| --- | --- | --- |
| 실행 파일 경로 | **있다** | — |
| 파일 설명·제작사 | **있다** | — |
| 실행 횟수 | 없다 | UserAssist, Prefetch |
| 실행 시각 | 없다 | Prefetch, Amcache, UserAssist, EVTX 4688 |
| 명령행 인자 | 없다 | EVTX 4688, PowerShell 4104 |
| 파일 해시 | 없다 | Amcache (`Amcache.hve`) |
| 실행 사용자 | hive 소유자로 간접 확인 | `ProfileList`, SAM |

## 출력 필드 해석

| 필드 | 해석 | 주의 |
| --- | --- | --- |
| 값 이름 | 실행 파일 전체 경로 | 이것이 핵심 데이터다 |
| 값 데이터 | `FileDescription` 리소스 | 이름을 바꿔도 원본 유지 |
| `.FriendlyAppName` | 쉘 표시용 이름 | 같은 경로의 보조 정보 |
| `.ApplicationCompany` | PE `CompanyName` | 제작자 식별에 유용 |
| `@<dll>,-<n>` 항목 | DLL 문자열 리소스 캐시 | **실행 증거 아님. 제외** |
| `LangID` | 캐시 언어 | artifact 값 아님 |
| 키 `LastWrite` | 이 키가 마지막 갱신된 시각(FILETIME, UTC) | 개별 항목의 시각이 아니다 |

키 LastWrite는 FILETIME이므로 1601-01-01 UTC 기준 100ns 단위다. Unix epoch 차이는 `11644473600`초, KST는 +9시간이다. 시스템 시간대는 [FOR-0054](./system-timezone.html)로 확인한다. **다만 항목이 수십 개인 키의 LastWrite 하나로 개별 프로그램의 실행 시각을 주장할 수는 없다.**

## pivot: 다음에 볼 artifact

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 실행 파일 경로 | Prefetch (`C:\Windows\Prefetch\<NAME>-<HASH>.pf`) | 실행 횟수·최초/최근 실행 시각·참조 파일 |
| 실행 파일 경로 | UserAssist ([FOR-0061](./userassist.html)) | 사용자가 직접 실행했는가, 몇 번 |
| 실행 파일 경로 | Amcache (`Amcache.hve`) | SHA-1 해시, 최초 등록 시각 |
| 실행 파일 경로 | AppCompatCache (Shimcache, `SYSTEM` hive) | 경로·파일 크기·마지막 수정 시각 |
| 실행 파일 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일 생성·삭제 시각, 현재 존재 여부 |
| `FileDescription` 문자열 | 도구 정체 확인 → 관련 artifact | Mimikatz면 LSASS 접근, 원격제어면 통신 |
| 파일이 있던 폴더 | ShellBags ([FOR-0068](./shellbags.html)) | 그 폴더를 탐색했는가 |
| `Downloads` 경로 | 브라우저 History ([FOR-0191](./chrome-history.html)) | 어디서 받았는가 |
| 설치 프로그램인가 | `SOFTWARE\...\Uninstall` ([FOR-0055](./software-installed-programs.html)) | 정식 설치 여부 |

## 흔한 함정

- **`NTUSER.DAT`에서 현행 MUICache를 찾는다.** Windows 7 이후 `MuiCache`는 `HKCU\Software\Classes` 아래, 즉 **`UsrClass.dat`** 에 있다 → `UsrClass.dat`을 확보한다. `NTUSER.DAT`의 `ShellNoRoam\MUICache`는 XP 계열 경로다.
- **`@`로 시작하는 항목을 프로그램 실행 증거로 센다.** `@C:\Windows\system32\shell32.dll,-22019` 같은 항목은 DLL 내부 문자열 리소스 캐시다 → 분석 전에 `@` 항목과 `LangID`를 제외한다.
- **키 LastWrite를 개별 프로그램의 실행 시각으로 쓴다.** MUICache에는 **항목별 타임스탬프가 전혀 없다.** LastWrite는 키 전체가 마지막으로 갱신된 시각 하나다 → 시각이 답이면 Prefetch·Amcache·UserAssist·4688으로 간다.
- **실행 횟수를 찾는다.** MUICache에는 횟수 개념이 없다. 있으면 1, 없으면 0의 이진 정보다 → 횟수는 UserAssist(Run Count)나 Prefetch다.
- **MUICache에 있으면 반드시 실행됐다고 단정한다.** 이 캐시는 Explorer가 **표시용 이름을 필요로 할 때** 만든다. 폴더를 열어 아이콘/설명 표시가 이루어지는 등 실행 이외의 경로로 항목이 생길 여지가 있다 → "실행되었다"는 **간접 증거**로 다루고 Prefetch·Amcache·UserAssist로 보강한다.
- **없으면 실행되지 않았다고 단정한다.** 콘솔에서 실행한 프로그램, 서비스·스케줄러가 띄운 프로세스는 쉘 표시 이름이 필요 없어 남지 않는다 → Prefetch → Amcache → Shimcache → BAM/DAM → 4688 순으로 이동한다.
- **파일명만 보고 정체를 판단한다.** `dump_tool.exe`라는 이름은 아무 의미가 없다. **`FileDescription`이 원본 리소스**이므로 이름보다 신뢰도가 높다 → 값 데이터를 먼저 읽는다.
- **`FileDescription`을 절대 진실로 믿는다.** 반대 방향의 함정이다. 리소스는 공격자가 위조할 수 있다. `svcupd.exe`의 설명이 `Remote Access Service`라고 해서 정상 서비스가 아니다 → 최종 판단은 해시(Amcache)와 실제 바이너리 분석이다.
- **hive 로그를 반영하지 않는다.** `rla` 없이 `UsrClass.dat`만 파싱하면 최근 항목이 빠진다.
- **사용자를 하나만 본다.** `UsrClass.dat`은 사용자별이다. 프로필이 여러 개면 모두 파싱한다.
- **Known Folder GUID 형태가 섞였다고 당황한다.** 값 이름에 `{...}` GUID가 들어오면 Known Folder ID다. 실제 경로로 치환해 읽는다.

## 교차검증

MUICache는 단독으로 결론을 내지 않는다. "경로와 정체"를 확보하고 나머지는 다른 artifact가 답한다.

```powershell
# 1) MUICache — 경로와 FileDescription
rip.exe -r "C:\case\clean\UsrClass.dat" -p muicache | Select-String 'dump_tool'

# 2) UserAssist — 사용자가 직접 실행했는가 + 횟수 + 마지막 시각
rip.exe -r "C:\case\clean\NTUSER.DAT" -p userassist | Select-String 'dump_tool'

# 3) Prefetch — 실행 사실과 최근 실행 시각
PECmd.exe -d "C:\case\C\Windows\Prefetch" --csv "C:\case\out"

# 4) Amcache — SHA-1 해시와 최초 등록
AmcacheParser.exe -f "C:\case\Amcache.hve" --csv "C:\case\out"

# 5) $MFT — 파일이 언제 생기고 언제 사라졌나 (메타파일 경로는 반드시 작은따옴표)
MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
```

| 조합 결과 | 해석 |
| --- | --- |
| MUICache O, UserAssist O, Prefetch O | 사용자가 GUI로 직접 실행. 결론 확정 |
| MUICache O, UserAssist X, Prefetch O | 쉘 표시는 됐으나 사용자 직접 실행 기록은 없다. 스크립트·다른 프로그램이 호출 |
| MUICache O, Prefetch X | Prefetch 삭제/비활성. Amcache·Shimcache로 보강 |
| MUICache O, `$MFT` X | 실행 후 파일 삭제. `$UsnJrnl`·`$Recycle.Bin`으로 삭제 시각 추적 |
| MUICache X, Prefetch O | 콘솔·서비스·스케줄러 실행. 사용자 GUI 조작이 아니다 |
| MUICache의 `FileDescription`과 Amcache 해시가 불일치하는 알려진 도구 | 리소스 위조 의심 |

## mini walkthrough

```text
문제:
"삭제된 자격증명 덤프 도구의 원래 저장 경로와 그 도구의 실제 정체를
 답하세요. 도구 파일 자체는 이미지에 남아 있지 않습니다.
 첨부: NTUSER.DAT(+LOG1/2), UsrClass.dat(+LOG1/2), Amcache.hve, $MFT"

1. 첫 시도 (실패)
   rip.exe -r NTUSER.DAT -p muicache
   -> "MUICache key not found" 출력.
      "이 시스템에는 MUICache 가 없다" 고 결론.

   왜 틀렸는가:
   Windows 7 이후 MuiCache 는 HKCU\Software\Classes 아래에 있고
   그 마운트 지점의 hive 는 NTUSER.DAT 이 아니라 UsrClass.dat 이다.
   첨부에 UsrClass.dat 이 따로 온 것이 이미 힌트였다.

2. 피벗 1 — 올바른 hive
   rla.exe -f UsrClass.dat --out clean\
   rip.exe -r clean\UsrClass.dat -p muicache > mc.txt
   -> 항목 180여 개. 대부분 @ 로 시작하는 리소스 캐시.

3. 두 번째 실수
   항목 수가 많아 눈으로 훑다가 @C:\Windows\system32\shell32.dll,-22019
   같은 줄을 "실행된 프로그램" 으로 세기 시작했다.
   -> @ 항목은 DLL 문자열 리소스 캐시다. 실행 증거가 아니다.

4. 피벗 2 — 노이즈 제거 후 사용자 경로만
   Select-String -Path .\mc.txt -Pattern '^[A-Za-z]:\\' |
     Where-Object { $_.Line -match '\\(Users|Temp|AppData|Downloads)\\' }

   C:\Users\jhkim\Downloads\dump_tool.exe                    -> Mimikatz for Windows
   C:\Users\jhkim\Downloads\dump_tool.exe.ApplicationCompany -> gentilkiwi
   C:\Users\jhkim\AppData\Local\Temp\svcupd.exe              -> Remote Access Service

   -> 파일명은 dump_tool.exe 이지만 FileDescription 이 정체를 폭로했다.

5. 파일이 정말 없는지 확인
   MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
   Import-Csv C:\case\out\mft.csv |
     Where-Object { $_.FileName -eq 'dump_tool.exe' }
   -> 결과 없음. 파일은 삭제됐다. 그런데 MUICache 에는 경로가 남았다.
      이것이 이 artifact 의 가치다.

6. 교차검증 — 해시로 정체 확정
   AmcacheParser.exe -f Amcache.hve --csv out\
   -> dump_tool.exe  SHA-1 확보 + 최초 등록 2026-03-14 07:36:41
      FileDescription 은 위조 가능하므로 해시가 최종 근거다.

7. 실행 횟수/시각은 MUICache 에 없으므로 UserAssist 로
   rip.exe -r clean\NTUSER.DAT -p userassist | Select-String 'dump_tool'
   -> 2026-03-14 07:38:05Z  C:\Users\jhkim\Downloads\dump_tool.exe (3)
      07:38:05Z + 9h = 2026-03-14 16:38:05 KST

정답:
  원래 경로  C:\Users\jhkim\Downloads\dump_tool.exe
  실제 정체  Mimikatz (FileDescription "Mimikatz for Windows", 제작자 gentilkiwi)
```

## 막혔을 때 다음 체크

1. **`UsrClass.dat`을 파싱했는가** — `NTUSER.DAT`이 아니다(XP 제외)
2. **`rla`로 `.LOG1`/`.LOG2`를 반영했는가**
3. **`@` 항목과 `LangID`를 제외했는가** — 노이즈를 실행 증거로 세지 않았는가
4. **`.FriendlyAppName`·`.ApplicationCompany` 접미사 항목을 함께 읽었는가** — 제작사가 정체 판단에 결정적일 수 있다
5. **사용자/임시 경로로 필터했는가** — `Windows`·`Program Files`는 배경 노이즈다
6. 실행 시각·횟수가 필요하다 → Prefetch → UserAssist → Amcache → Shimcache → BAM/DAM → EVTX 4688
7. 명령행 인자가 필요하다 → EVTX 4688, PowerShell 4104
8. `FileDescription`이 비어 있다 → 버전 리소스 없는 바이너리. Amcache 해시로 식별
9. 사용자가 여러 명인가 → 모든 프로필의 `UsrClass.dat`. hive 위치는 [FOR-0051](./registry-hive-map.html)
10. XP 이미지인가 → `NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\MUICache`

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `UsrClass.dat`의 위치와 `HKCU\Software\Classes` 매핑, hive가 사용자별이라는 근거
- SRC-099 — RegRipper 3.0 repository: `muicache` 플러그인과 `rip.exe -r ... -p ...` 사용법, `UsrClass.dat`/`NTUSER.DAT` 양쪽 지원
- SRC-100 — Microsoft Learn, Known Folder GUIDs: 값 이름에 `{...}` 형태가 들어올 때의 실제 경로 치환 근거
- 일부 Windows 10/11 빌드에 나타나는 `Local Settings\MuiCache\<인덱스>\<해시>` 하위 구조의 내부 의미는 단정하지 않았다. 파서 출력으로 확인할 것
- MUICache 항목이 생성되는 정확한 트리거는 Windows 버전에 따라 차이가 보고되므로 "실행의 간접 증거"로 다루고 Prefetch·Amcache·UserAssist로 보강할 것
- 플러그인 이름은 배포 버전에 따라 다르므로 `rip.exe -l`로 확인할 것
