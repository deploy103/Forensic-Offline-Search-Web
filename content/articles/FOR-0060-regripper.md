---
id: FOR-0060
title: "RegRipper 3.0 사용법: rip.exe 옵션과 hive별 플러그인"
slug: "regripper"
category: "Registry"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Registry hive", "RegRipper plugin", "TLN", "Amcache.hve"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Windows\\System32\\config\\SAM", "C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"]
registry_paths: []
event_ids: []
protocols: []
tools: ["RegRipper", "rip.exe", "rr.exe", "rla", "RegistryExplorer", "Timeline Explorer"]
commands: ["rip.exe -r C:\\case\\SYSTEM -a", "rip.exe -l", "rip.exe -r C:\\case\\NTUSER.DAT -p userassist", "rip.exe -r C:\\case\\SYSTEM -aT", "rip.exe -r C:\\case\\SAM -p samparse"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["LastWrite Time", "TLN time", "TLN source", "TLN host", "TLN user", "TLN description"]
file_formats: ["regf", "hve", "tln"]
primary_terms: ["RegRipper", "rip.exe", "레지스트리 플러그인"]
keywords: ["RegRipper", "rip.exe", "rr.exe", "플러그인", "plugin", "TLN", "타임라인", "hive 파싱", "samparse", "usbstor", "profilelist", "amcache", "프로파일", "Select-String"]
aliases: ["regripper 사용법", "레그리퍼", "rip.exe 옵션", "레지스트리 일괄 추출", "플러그인 목록 보기", "hive 텍스트로 뽑기", "regripper tln"]
symptom_keywords: ["hive를 한 번에 텍스트로 뽑고 싶다", "플러그인 이름을 모르겠다", "플러그인이 출력이 비어 있다", "레지스트리로 타임라인을 만들고 싶다", "GUI 없이 hive를 파싱하고 싶다"]
related: ["FOR-0051", "FOR-0057", "FOR-0059", "FOR-0121"]
source_ids: ["SRC-099", "SRC-017", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

RegRipper는 hive 파일을 **키별 전용 플러그인으로 파싱해 텍스트로 떨어뜨리는** CLI 도구이며, `rip.exe -r <hive> -a`로 그 hive에 해당하는 플러그인을 전부 돌린 뒤 `Select-String`으로 후처리하는 것이 실전에서 가장 빠른 레지스트리 트리아지다. 플러그인 이름은 버전마다 다르므로 **항상 `rip.exe -l`로 먼저 확인한다.**

## 어떤 문제에서 필요한가

- hive 여러 개를 짧은 시간에 통째로 훑어야 한다 (GUI로 클릭할 시간이 없다)
- 결과를 텍스트로 받아 `Select-String`·`grep`으로 걸러내고 싶다
- 알려진 키(USB, 시간대, 계정, 설치 프로그램, 실행 흔적)의 **정답을 바로 뽑고** 싶다
- 레지스트리 항목들을 하나의 타임라인으로 합치고 싶다 (TLN 출력)
- GUI를 못 쓰는 환경이거나, 같은 작업을 스크립트로 반복해야 한다

반대로 **어느 키에 무엇이 있는지 모를 때 트리를 헤매는 용도로는 부적합**하다. 그건 RegistryExplorer의 일이다([FOR-0059](./registry-explorer.html)).

## 문제에서 처음 볼 단서

1. 첨부에 hive가 3개 이상 → 손으로 클릭할 게 아니라 `-a`로 일괄 처리한다
2. 지문이 "USB 시리얼", "설치된 프로그램", "계정 목록", "시간대" 처럼 **정형화된 값**을 묻는다 → 전용 플러그인이 있다
3. 답이 시각의 순서 문제다 → `-aT`로 TLN을 뽑아 정렬한다
4. hive와 함께 `.LOG1`/`.LOG2`가 왔다 → RegRipper는 로그를 반영하지 않으므로 `rla`를 먼저 돌린다

## 30초 절차

```powershell
rip.exe -r 'C:\case\SYSTEM' -a > 'C:\case\out\system.txt'
```

1. `rla`로 트랜잭션 로그를 먼저 반영한다 (dirty hive 대비)
2. hive마다 `-a`로 전부 뽑아 텍스트 파일로 저장한다
3. `Select-String`으로 필요한 부분만 걸러 읽는다
4. 원하는 값이 안 나오면 `rip.exe -l`로 플러그인 이름을 확인해 `-p`로 개별 실행한다

```powershell
# 로그 반영 -> 일괄 덤프 -> 검색
rla.exe -d 'C:\case\hives' --out 'C:\case\clean'
rip.exe -r 'C:\case\clean\SYSTEM'   -a | Out-File -Encoding utf8 'C:\case\out\system.txt'
rip.exe -r 'C:\case\clean\SOFTWARE' -a | Out-File -Encoding utf8 'C:\case\out\software.txt'
Select-String -Path 'C:\case\out\*.txt' -Pattern 'USBSTOR|SerialNumber|TimeZone'
```

## 상세 절차

### 1단계 — rip.exe 옵션

| 옵션 | 의미 | 비고 |
| --- | --- | --- |
| `-r <hive>` | 파싱할 hive 파일 경로 | 필수. 경로에 공백이 있으면 인용부호 |
| `-p <plugin>` | 플러그인 **1개**만 실행 | 이름은 `-l`로 확인한 것만 쓴다 |
| `-f <profile>` | 프로파일(플러그인 세트) 실행 | 프로파일 파일은 `plugins` 폴더에 있다 |
| `-l` | 사용 가능한 플러그인 **전체 목록** 출력 | 작업 시작 전 한 번은 본다 |
| `-a` | 그 hive 종류에 해당하는 플러그인을 **전부** 실행 | 실무에서 가장 많이 쓴다 |
| `-aT` | 같은 방식으로 **TLN 형식** 출력 | 타임라인용 |

버전에 따라 목록을 CSV로 뽑는 스위치, hive 종류를 추정하는 스위치, TLN의 host/user 필드를 지정하는 스위치가 함께 제공된다. **정확한 스위치 집합은 `rip.exe -h`(또는 인자 없이 실행)로 확인한다.** 문서에서 본 옵션이 내 버전에 없을 수 있다.

RegRipper 3.0에서는 프로파일보다 `-a`가 권장 경로다. 프로파일은 "이 hive에 이 플러그인들을 돌려라"를 적어 둔 목록 파일이므로, 필요하면 직접 만들어 재사용한다.

`rip.exe`는 자기 배포 폴더의 `plugins` 디렉터리를 찾아 동작한다. 플러그인을 못 찾는다는 오류가 나면 **`rip.exe`가 있는 폴더에서 실행**하거나 전체 경로로 호출한다.

### 2단계 — 플러그인 이름은 반드시 먼저 확인한다

이 도구에서 시간을 가장 많이 낭비하는 원인은 **없는 플러그인 이름을 타이핑하는 것**이다. 이름은 버전과 배포본마다 추가·개명된다.

```powershell
# 전체 목록
rip.exe -l > 'C:\case\out\plugins.txt'

# "usb" 가 들어간 플러그인만
Select-String -Path 'C:\case\out\plugins.txt' -Pattern 'usb' -Context 0,1

# hive 별로 어떤 플러그인이 있는지 훑기
Select-String -Path 'C:\case\out\plugins.txt' -Pattern 'ntuser|software|system|sam'
```

목록에는 플러그인 이름과 대상 hive, 한 줄 설명이 함께 나온다. **목록에 없는 이름은 존재하지 않는다.** 추측해서 넣으면 오류이거나, 더 나쁘게는 조용히 빈 출력이 나온다.

### 3단계 — hive별 주요 플러그인

아래는 실전에서 자주 쓰는 것들이다. 각자의 환경에서 `-l`로 존재를 확인한 뒤 사용한다.

| hive | 플러그인 | 무엇이 나오나 |
| --- | --- | --- |
| `SYSTEM` | `timezone` | 시간대(Bias, StandardName). **모든 시각 보정의 전제** ([FOR-0054](./system-timezone.html)) |
| `SYSTEM` | `computername` | 컴퓨터 이름 ([FOR-0073](./computer-name.html)) |
| `SYSTEM` | `usbstor` | 연결된 USB 저장장치의 벤더/제품/시리얼과 키 시각 ([FOR-0066](./usbstor.html)) |
| `SYSTEM` | `mountdev` | `MountedDevices`. 드라이브 문자 ↔ 볼륨/장치 매핑 ([FOR-0067](./mounteddevices.html)) |
| `SYSTEM` | `services` | 서비스와 ImagePath. 악성 서비스 탐지 |
| `SOFTWARE` | `uninstall` | 설치된 프로그램(DisplayName, InstallDate) ([FOR-0055](./software-installed-programs.html)) |
| `SOFTWARE` | `profilelist` | SID ↔ 프로필 폴더 매핑 |
| `SOFTWARE` | `run` | 머신 단위 자동실행 |
| `SOFTWARE` | `networklist` | 접속한 무선/유선 네트워크 이름과 최초/마지막 연결 |
| `SAM` | `samparse` | 로컬 계정, RID, 마지막 로그온, 로그인 횟수, 그룹 ([FOR-0052](./sam-user-accounts.html)) |
| `NTUSER.DAT` | `userassist` | GUI로 직접 실행한 프로그램·횟수·마지막 실행 ([FOR-0061](./userassist.html)) |
| `NTUSER.DAT` | `recentdocs` | 최근 열어본 문서 ([FOR-0062](./recentdocs.html)) |
| `NTUSER.DAT` | `typedpaths` | 탐색기 주소창에 입력한 경로 ([FOR-0064](./typedpaths.html)) |
| `NTUSER.DAT` | `runmru` | 실행(Win+R) 창에 입력한 명령 |
| `UsrClass.dat` | `shellbags` | 탐색기로 방문한 폴더 ([FOR-0068](./shellbags.html)) |
| `Amcache.hve` | `amcache` | 실행 파일 경로·SHA-1·크기 |

**`shellbags`는 Windows 7 이후 `UsrClass.dat`에 대고 돌려야 한다.** `NTUSER.DAT`에 돌리면 빈 출력이 나오고, 그걸 "흔적 없음"으로 오해하는 일이 잦다([FOR-0058](./usrclass-dat.html)).

각 hive에서 무엇을 볼지 자체가 헷갈리면 [FOR-0051](./registry-hive-map.html)의 목적별 인덱스를, `NTUSER.DAT` 내부 키 목록은 [FOR-0057](./ntuser-dat.html)을 먼저 본다.

### 4단계 — 트랜잭션 로그는 RegRipper가 반영하지 않는다

RegRipper는 hive 파일을 그대로 읽는다. dirty hive라면 `.LOG1`/`.LOG2`의 미반영 변경은 **보이지 않는다.**

```powershell
# 반드시 먼저: 폴더 안의 hive 를 전부 정리해 clean hive 생성
rla.exe -d 'C:\case\hives' --out 'C:\case\clean'
```

dirty 여부는 base block의 primary sequence number(`0x04`)와 secondary(`0x08`)를 비교해 판정한다. 다르면 dirty다. 이 단계를 건너뛰면 "마지막 실행", "마지막 USB 연결" 같은 답이 **한 세대 이전 값으로 조용히 틀린다.**

### 5단계 — 출력을 텍스트로 받아 후처리하는 실전 패턴

플러그인 출력은 사람이 읽는 텍스트다. 파일로 받아 검색하는 것이 전제다.

```powershell
# 1) hive 전체를 hive 이름별 파일로
$hives = @{
  'SYSTEM'       = 'C:\case\clean\SYSTEM'
  'SOFTWARE'     = 'C:\case\clean\SOFTWARE'
  'SAM'          = 'C:\case\clean\SAM'
  'NTUSER'       = 'C:\case\clean\NTUSER.DAT'
  'USRCLASS'     = 'C:\case\clean\UsrClass.dat'
}
foreach ($k in $hives.Keys) {
  rip.exe -r $hives[$k] -a | Out-File -Encoding utf8 "C:\case\out\$k.txt"
}

# 2) 키워드로 한 번에 훑기 (파일명:행번호와 함께 나온다)
Select-String -Path 'C:\case\out\*.txt' -Pattern 'SerialNumber|USBSTOR' 

# 3) 앞뒤 문맥까지 (플러그인 출력은 여러 줄이 한 항목이다)
Select-String -Path 'C:\case\out\NTUSER.txt' -Pattern 'Downloads|Temp|AppData' -Context 1,2

# 4) 의심 확장자만
Select-String -Path 'C:\case\out\*.txt' -Pattern '\.(exe|ps1|bat|vbs|scr)\b'

# 5) 결과 개수만 세기
(Select-String -Path 'C:\case\out\NTUSER.txt' -Pattern 'updater\.exe').Count
```

`>` 리다이렉션은 PowerShell 5.1에서 **UTF-16LE**로 저장한다. WSL의 `grep`이나 다른 도구에 넘길 파일이면 위처럼 `Out-File -Encoding utf8`을 쓴다. `Select-String` 사용법은 [FOR-0121](./powershell-select-string.html)에 정리되어 있다.

### 6단계 — TLN 출력으로 타임라인 만들기

`-aT`는 결과를 **TLN(TimeLiNe) 형식**의 한 줄 레코드로 낸다. 파이프로 구분된 5개 필드다.

| 위치 | 필드 | 내용 |
| --- | --- | --- |
| 1 | time | **Unix epoch 초(UTC)** |
| 2 | source | 출처 태그(예: `REG`) |
| 3 | host | 시스템 이름 |
| 4 | user | 사용자 |
| 5 | description | 무슨 일이 있었는지 |

```powershell
# hive 마다 TLN 을 뽑아 한 폴더에 모은다
rip.exe -r 'C:\case\clean\SYSTEM'     -aT | Out-File -Encoding utf8 'C:\case\tln\system.txt'
rip.exe -r 'C:\case\clean\SOFTWARE'   -aT | Out-File -Encoding utf8 'C:\case\tln\software.txt'
rip.exe -r 'C:\case\clean\NTUSER.DAT' -aT | Out-File -Encoding utf8 'C:\case\tln\ntuser.txt'

# 시간 역순으로 합쳐 보기
Get-Content 'C:\case\tln\*.txt' |
  Where-Object { $_ -match '^\d+\|' } |
  Sort-Object { [long](($_ -split '\|')[0]) } -Descending |
  Select-Object -First 40
```

epoch를 사람이 읽는 시각으로 바꿀 때는 KST 오프셋을 바로 적용한다.

```powershell
# epoch(UTC) -> KST
[datetimeoffset]::FromUnixTimeSeconds(1773729167).ToOffset([timespan]::FromHours(9))
```

Unix epoch와 FILETIME의 차이는 `11644473600`초다. 레지스트리 원본 값은 FILETIME이고 TLN은 epoch이므로, 두 출력의 시각이 다르게 보이면 단위를 먼저 의심한다.

TLN 레코드는 EVTX·`$MFT`·Prefetch 타임라인과 같은 표에 합칠 수 있다. 여러 아티팩트를 합칠 때는 CSV로 정규화해 Timeline Explorer로 보는 편이 낫다.

### 7단계 — GUI (rr.exe)

배포판에는 GUI인 `rr.exe`가 함께 들어 있다. hive 파일과 결과를 저장할 리포트 파일을 지정하고 실행하면, 그 hive에 해당하는 플러그인을 돌려 리포트를 만든다. 옵션 조합·파이프 후처리가 필요 없을 때, 또는 CLI 사용이 부담될 때 쓴다. 세밀한 제어(플러그인 지정, TLN, 후처리)는 `rip.exe`가 낫다.

## 출력 필드 해석

플러그인마다 출력 형태가 다르지만 공통 요소가 있다.

| 출력 요소 | 의미 | 주의 |
| --- | --- | --- |
| 플러그인 이름/버전 머리줄 | 어느 플러그인이 무엇을 읽었는지 | 출력이 이 줄만 있고 내용이 없으면 **키가 없거나 hive가 안 맞는 것** |
| 키 경로 | 플러그인이 읽은 키 | 결론에 근거로 그대로 인용할 수 있다 |
| `LastWrite Time` | 그 키의 마지막 변경 시각. FILETIME **UTC** | 값 단위가 아니다. 마지막 1회뿐 |
| 값 나열 | 값 이름 = 데이터 | 값 자체에는 시각이 없다 |
| 시각 뒤의 `Z` | UTC 표기 | KST는 +9시간 |
| 빈 출력 | 그 키가 hive에 없다 | **"흔적이 없다"와 다르다.** hive를 잘못 골랐을 수 있다 |

출력 문구와 컬럼 배치는 플러그인 버전에 따라 바뀌므로, 답으로 제출할 값은 RegistryExplorer로 원본 키를 한 번 더 확인하는 편이 안전하다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| `timezone`의 Bias | 모든 시각 보정 ([FOR-0054](./system-timezone.html)) | 로컬 시각 ↔ UTC 변환 |
| `usbstor`의 시리얼 | `mountdev`, `NTUSER.DAT\...\MountPoints2` | 드라이브 문자와 사용자 연결 |
| `profilelist`의 SID | 해당 `NTUSER.DAT`/`UsrClass.dat` ([FOR-0057](./ntuser-dat.html)) | 사용자별 활동 |
| `samparse`의 마지막 로그온 | Security 4624/4625 ([FOR-0083](./event-4624-logon.html)) | 로그온 유형과 출처 IP |
| `userassist`의 실행 파일 | Prefetch, `Amcache.hve` | 실행 사실·해시 |
| `run`/`services`의 ImagePath | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일이 언제 생겼는지 |
| `shellbags`의 폴더 경로 | `$MFT`, LNK, Jump List | 폴더 존재 여부와 그 안의 파일 |
| 값이 안 나온다 | RegistryExplorer 트리·삭제 레코드 ([FOR-0059](./registry-explorer.html)) | 지워진 값 복구 |

## 흔한 함정

- **플러그인 이름을 기억으로 타이핑하는 것.** `usb`, `shellbag`, `time`처럼 비슷한 이름을 넣으면 오류이거나 빈 출력이다. 작업 시작할 때 `rip.exe -l`을 파일로 받아 두고 거기서 복사한다.
- **빈 출력을 "흔적 없음"으로 결론내는 것.** hive 종류 불일치(예: `shellbags`를 `NTUSER.DAT`에 실행), 키 부재, dirty hive 미반영 중 하나일 수 있다. 원인을 구분하기 전에 결론을 내지 않는다.
- **`rla` 없이 dirty hive를 파싱하는 것.** RegRipper는 트랜잭션 로그를 반영하지 않는다. 가장 최근 변경이 빠진 결과를 정상 결과로 착각한다.
- **`-a`만 믿고 끝내는 것.** `-a`는 그 hive에 매핑된 플러그인을 돌리는 것이고, 매핑에서 빠진 플러그인은 실행되지 않는다. 특정 키가 필요하면 `-p`로 직접 지정한다.
- **`>`로 저장한 파일을 다른 도구에 넘기는 것.** PowerShell 5.1의 리다이렉션은 UTF-16LE다. `Out-File -Encoding utf8`로 저장한다.
- **`LastWrite Time`을 값이 만들어진 시각으로 단정하는 것.** 키 단위·마지막 1회다. 값 데이터 안에 자체 FILETIME이 있으면 그쪽이 정확하다.
- **시간대 보정 누락.** 출력의 `Z`는 UTC다. TLN은 Unix epoch(UTC)다. KST는 +9시간, FILETIME과 epoch의 차이는 `11644473600`초다.
- **`Amcache.hve`를 hive가 아니라고 생각해 건너뛰는 것.** `regf` 파일이므로 `-r`로 그대로 먹인다.
- **사용자 hive를 하나만 돌리는 것.** 프로필마다 `NTUSER.DAT`과 `UsrClass.dat`이 따로 있다. `C:\Users` 아래를 세고 반복문으로 돌린다.
- **`rip.exe`를 플러그인 폴더가 없는 위치로 복사해 쓰는 것.** 배포 폴더 구조를 유지한 채 실행한다.

## 교차검증

RegRipper 결과는 항상 다른 경로로 한 번 더 확인한다.

```powershell
# 1) RegRipper 로 값 확보
rip.exe -r 'C:\case\clean\SYSTEM' -p usbstor | Out-File -Encoding utf8 'C:\case\out\usb.txt'
Select-String -Path 'C:\case\out\usb.txt' -Pattern 'SerialNumber|FriendlyName' -Context 0,2

# 2) 같은 키를 GUI 로 눈으로 확인 (RegistryExplorer 북마크 -> USBSTOR)

# 3) 사용자 쪽 대응물과 대조
rip.exe -r 'C:\case\clean\NTUSER.DAT' -p mp2 | Select-String 'Volume|#'

# 4) 파일시스템 근거
Import-Csv 'C:\case\out\mft.csv' | Where-Object { $_.ParentPath -like '*Removable*' }
```

세 곳이 같은 장치·같은 시각을 가리키면 결론이 단단해진다. RegRipper와 GUI 결과가 다르면 **어느 hive 파일을 먹였는지**(원본 vs `rla` 적용본)를 먼저 확인한다.

## mini walkthrough

```text
문제:
"압수 PC 이미지에서 뽑은 SYSTEM, SOFTWARE, NTUSER.DAT (+ 각 .LOG1/.LOG2) 가
 주어진다. 이 PC에 연결된 USB 저장장치의 시리얼 번호와, 그 장치가 붙은
 시각을 KST 로 구하세요."

1. 첫 시도 (실패):
   rip.exe -r NTUSER.DAT -p usbstor
   -> 출력이 플러그인 머리줄만 나오고 내용이 없다.
      "USB 흔적이 없다"고 판단할 뻔했다.

   왜 틀렸나:
   USBSTOR 는 SYSTEM hive 의 키다(Enum\USBSTOR).
   사용자 hive 에 없는 키를 읽으라고 했으니 빈 출력이 정상이다.
   빈 출력은 "없음"이 아니라 "여기가 아님"일 수 있다.

2. 두 번째로 틀린 접근:
   rip.exe -r SYSTEM -p usb
   -> 플러그인을 찾을 수 없다는 오류. 이름을 추측한 탓이다.

3. 피벗 1: 플러그인 이름을 목록에서 확정
   rip.exe -l | Out-File -Encoding utf8 plugins.txt
   Select-String -Path plugins.txt -Pattern 'usb'
     usbstor    SYSTEM   Get USBStor key details
     usbdevices SYSTEM   (환경에 따라 존재)
   -> 쓸 이름은 usbstor

4. 피벗 2: 로그를 먼저 반영
   rla.exe -d hives\ --out clean\
   (SYSTEM 의 primary 0x88 != secondary 0x8a 로 dirty 였다)

5. 본 작업
   rip.exe -r clean\SYSTEM -a | Out-File -Encoding utf8 out\system.txt
   Select-String -Path out\system.txt -Pattern 'USBSTOR' -Context 0,6

     USBSTOR
     Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00 [2026-03-14 07:05:09Z]
       S/N: 4C530001120216108095  [2026-03-14 07:05:11Z]
         FriendlyName  : SanDisk Cruzer Blade USB Device

6. 사용자 연결 확인 (pivot)
   rip.exe -r clean\NTUSER.DAT -p mp2 | Select-String 'Volume|^  E'
   -> E 드라이브 서브키 LastWrite 2026-03-14 07:05:11Z
      (jhkim 프로필의 hive 이므로 "누가"까지 확정된다)

7. 시간 보정
   2026-03-14 07:05:11 UTC + 9h = 2026-03-14 16:05:11 KST

8. 타임라인으로 정리
   rip.exe -r clean\SYSTEM -aT | Out-File -Encoding utf8 tln\system.txt
   Get-Content tln\*.txt | Sort-Object { [long](($_ -split '\|')[0]) } -Descending |
     Select-Object -First 20

정답: S/N 4C530001120216108095 (SanDisk Cruzer Blade), 2026-03-14 16:05:11 KST
```

## 막혔을 때 다음 체크

1. **`rip.exe -l`로 플러그인 이름을 확인했는가** — 추측한 이름은 쓰지 않는다
2. **hive 종류가 맞는가** — `shellbags`는 `UsrClass.dat`, `usbstor`는 `SYSTEM`, `samparse`는 `SAM`
3. **`rla`로 트랜잭션 로그를 반영했는가** — dirty hive면 최신 값이 빠진다
4. 출력이 비었는가 → 위 1~3을 순서대로 확인한 뒤에도 비어 있으면 RegistryExplorer로 트리를 직접 본다
5. 값은 나오는데 시각이 이상한가 → FILETIME(UTC) vs TLN epoch 단위 혼동, 그리고 KST +9 보정을 확인
6. 결과가 너무 많은가 → `-p`로 좁히고 `Select-String -Context`로 항목 단위로 읽는다
7. 다른 도구에 넘길 파일인가 → `Out-File -Encoding utf8`로 저장했는지 확인
8. 플러그인을 못 찾는다는 오류가 나는가 → `rip.exe`를 배포 폴더에서 실행한다
9. 지워진 값이 필요한가 → RegRipper로는 안 된다. RegistryExplorer의 삭제 레코드로 간다
10. 사용자가 여러 명인가 → 프로필마다 `NTUSER.DAT` + `UsrClass.dat`를 반복 실행한다

## 출처

- SRC-099 — RegRipper 3.0 저장소: `rip.exe`의 `-r`/`-p`/`-f`/`-l`/`-a`/`-aT` 옵션, 플러그인이 hive 종류별로 매핑된다는 구조, `plugins` 폴더와 프로파일, GUI(`rr.exe`)의 존재
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: 각 플러그인이 대상으로 하는 hive와 루트키의 대응
- SRC-004 — Eric Zimmerman 도구 문서: `rla`로 트랜잭션 로그를 반영해 clean hive를 만드는 절차, RegistryExplorer와의 역할 분담
- **플러그인 이름과 출력 문구는 RegRipper 배포본·버전마다 다르다.** 이 글의 플러그인 표와 출력 예시는 형식 이해용이며, 실제 사용 전 `rip.exe -l`로 존재를 확인할 것
- `-h`로 노출되는 전체 스위치 집합(목록 CSV 출력, hive 종류 추정, TLN의 host/user 지정 등)은 버전에 따라 다르므로 실제 도움말에서 확인할 것
