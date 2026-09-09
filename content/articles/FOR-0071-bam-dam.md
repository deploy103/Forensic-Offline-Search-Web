---
id: FOR-0071
title: "BAM/DAM 키로 사용자별 마지막 실행 시각 얻기"
slug: "bam-dam"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["BAM", "DAM", "Background Activity Moderator", "UserSettings", "\\Device\\HarddiskVolume"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM"]
registry_paths: ["SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings", "SYSTEM\\ControlSet001\\Services\\bam\\UserSettings", "SYSTEM\\ControlSet001\\Services\\dam\\State\\UserSettings", "SYSTEM\\ControlSet001\\Services\\bam", "SYSTEM\\ControlSet001\\Services\\dam"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "FTK Imager", "KAPE", "DCode"]
commands: ["rip.exe -r SYSTEM -p bam", "rip.exe -r SYSTEM -p profilelist"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["SequenceNumber", "Version", "LastExecuted", "SID"]
file_formats: ["regf"]
primary_terms: ["BAM", "DAM", "Background Activity Moderator", "bam 실행 시각"]
keywords: ["BAM", "DAM", "Background Activity Moderator", "Desktop Activity Moderator", "UserSettings", "SID", "마지막 실행", "FILETIME", "HarddiskVolume", "SYSTEM hive", "실행 흔적", "Windows 10 1709"]
aliases: ["bam", "dam", "bam 키", "bam 실행 시각", "bam 실행 흔적", "누가 실행했나 sid", "마지막 실행 시각 레지스트리", "background activity moderator"]
symptom_keywords: ["누가 그 프로그램을 실행했는지 알고 싶다", "마지막 실행 시각이 필요하다", "UserAssist에 안 나온다", "Prefetch가 없는데 실행 증거가 필요하다", "Device HarddiskVolume 경로를 못 읽는다", "SID가 누구인지 모르겠다"]
related: ["FOR-0061", "FOR-0067", "FOR-0052", "FOR-0053"]
source_ids: ["SRC-017", "SRC-014", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID>` 아래의 **값 이름이 실행 파일의 `\Device\HarddiskVolumeN\...` 경로**이고 **값 데이터 앞 8바이트가 그 프로그램의 마지막 실행 FILETIME(UTC)** 이므로, SID별로 나뉜 이 키만으로 "누가 무엇을 마지막으로 언제 실행했나"가 한 번에 나온다.

## 어떤 문제에서 필요한가

BAM(Background Activity Moderator)은 백그라운드 활동을 조절하기 위해 OS가 유지하는 목록이지만, 포렌식에서는 **사용자별 실행 시각 표**로 쓰인다. UserAssist가 못 잡는 실행을 잡는다.

- "그 악성 실행 파일을 **어느 계정**이 실행했나" — 값이 SID별로 분리되어 있다
- "마지막 실행 시각이 언제인가"
- "UserAssist·Prefetch가 비었는데 실행 증거가 필요하다"
- "콘솔·스크립트로 실행된 프로그램도 잡히나" — BAM은 GUI 여부와 무관하다
- "사고 시각 근처에 어떤 프로그램이 돌았나" — SID별 목록을 시간순으로 정렬한다

USB 사건에서는 연결 시각 구간에 실행된 복사·압축 도구를 찾는 데 쓴다.

## 문제에서 처음 볼 단서

1. 첨부에 `SYSTEM`이 있고 문제가 "누가 실행했는가"를 묻는다
2. `NTUSER.DAT`이 없거나 UserAssist가 비어 있다 → BAM은 `SYSTEM`에만 있으므로 여전히 쓸 수 있다
3. 지문에 Windows 10/11이 명시된다 → BAM은 **Windows 10 1709 이후**에 존재한다
4. 값 이름이 `\Device\HarddiskVolume3\Users\...` 형태로 보인다 → 드라이브 문자 변환이 필요한 상황이다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -p bam
```

```text
bam
ControlSet001\Services\bam\State\UserSettings

S-1-5-21-3623811015-3361044348-30300820-1013
2026-03-14 07:38:05Z  \Device\HarddiskVolume3\Users\jhkim\Downloads\dump_tool.exe
2026-03-14 07:36:44Z  \Device\HarddiskVolume3\Windows\System32\cmd.exe
2026-03-14 07:31:02Z  \Device\HarddiskVolume3\Program Files\7-Zip\7zG.exe
2026-03-13 22:05:19Z  \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

S-1-5-18
2026-03-14 06:02:11Z  \Device\HarddiskVolume3\Windows\System32\svchost.exe
```

GUI라면 RegistryExplorer로 다음 경로를 연다.

```text
SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-...-1013
```

## 상세 절차

### 1단계 — 경로는 두 가지다 (빌드에 따라 다르다)

```text
SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID>    <- 현재 형태
SYSTEM\ControlSet001\Services\bam\UserSettings\<SID>          <- 초기 빌드 (State 없음)
SYSTEM\ControlSet001\Services\dam\State\UserSettings\<SID>    <- DAM (같은 구조)
```

`State` 서브키의 유무는 Windows 빌드에 따라 다르다. **두 경로를 모두 열어 보고, 있는 쪽을 쓴다.** 활성 ControlSet 번호는 `SYSTEM\Select`의 `Current`로 정한다([FOR-0053](./system-controlset.html)).

| 키 | 정식 이름 | 내용 |
| --- | --- | --- |
| `bam` | Background Activity Moderator | 백그라운드 활동 조절 대상 목록. 실무에서 보는 것은 대개 이쪽 |
| `dam` | Desktop Activity Moderator | 절전/연결 대기(Modern Standby) 관련. 구조는 같고 항목이 훨씬 적거나 비어 있다 |

`dam`이 비어 있는 것은 정상이다. 노트북·태블릿에서만 채워지는 경향이 있다.

### 2단계 — SID 서브키 = 사용자 특정

`UserSettings` 아래 서브키 이름이 **SID 그 자체**다. 이것이 BAM의 가장 큰 강점이다. Prefetch·Amcache·Shimcache는 실행 사실만 알려주고 실행 주체를 알려주지 않는다.

| SID | 정체 |
| --- | --- |
| `S-1-5-18` | LocalSystem (서비스·시스템 프로세스) |
| `S-1-5-19` | LocalService |
| `S-1-5-20` | NetworkService |
| `S-1-5-21-<도메인/머신>-<RID>` | 실제 사용자 계정. RID `1000` 이상이 일반 사용자 |
| `S-1-5-21-...-500` | 내장 Administrator |

SID를 계정 이름으로 바꾸려면 다음 둘 중 하나를 본다.

```powershell
rip.exe -r "C:\case\SOFTWARE" -p profilelist
rip.exe -r "C:\case\SAM" -p samparse
```

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>`의 `ProfileImagePath`가 `C:\Users\jhkim`이면 그 SID가 jhkim이다([FOR-0052](./sam-user-accounts.html)).

### 3단계 — 값 이름 = 실행 파일의 커널 경로

```text
값 이름: \Device\HarddiskVolume3\Users\jhkim\Downloads\dump_tool.exe
         \_________________/  \_________________________________/
          볼륨 (커널 표기)      볼륨 내 경로
```

드라이브 문자가 아니라 **커널 장치 경로**로 저장된다. `C:\Users\jhkim\...`로 검색하면 아무것도 안 나온다. 이름 검색은 파일명 부분으로 한다.

```powershell
rip.exe -r "C:\case\SYSTEM" -p bam > bam.txt
Select-String -Path bam.txt -Pattern 'dump_tool|7z|rar|powershell|cmd\.exe'
```

일부 항목은 `\Device\HarddiskVolume...` 대신 다음 형태로 보인다.

| 값 이름 형태 | 의미 |
| --- | --- |
| `\Device\HarddiskVolumeN\...` | 로컬 볼륨의 실행 파일 |
| `SequenceNumber`, `Version` | 경로가 아니라 BAM 자체의 관리용 값. **실행 기록이 아니므로 제외한다** |
| 앱 패키지 식별자 형태의 긴 문자열 | Store 앱. 경로 변환이 성립하지 않는다 |

### 4단계 — 값 데이터 앞 8바이트 = 마지막 실행 FILETIME

```text
값 데이터 (예: 24바이트)
  0x00 - 0x07   마지막 실행 시각 FILETIME (리틀엔디언, UTC)
  0x08 - ...    나머지 바이트. 의미가 공개되어 있지 않다
```

| 오프셋 | 크기 | 필드 | 비고 |
| --- | --- | --- | --- |
| `0x00` | 8 | **마지막 실행 시각 (FILETIME)** | 1601-01-01 UTC 기준 100ns 단위 |
| `0x08` 이후 | 가변 | 미공개 | **여기서 어떤 값도 주장하지 않는다** |

FILETIME 수동 변환 절차다.

```text
hex (리틀엔디언 8바이트):  C0 6E 3A 4B 12 8F DC 01
빅엔디언으로 뒤집기:        01 DC 8F 12 4B 3A 6E C0
=> 100ns 단위 정수 -> 1e7 로 나누면 1601-01-01 부터의 초
=> 그 초에서 11644473600 을 빼면 Unix epoch 초
=> 결과는 UTC. KST 는 +9시간
```

DCode에 8바이트를 그대로 넣으면 변환된다. 데이터 길이가 24바이트라도 **뒤 16바이트는 건드리지 않는다.**

```powershell
# 라이브 시스템에서 앞 8바이트만 시각으로 환산하는 예
$sid  = 'S-1-5-21-3623811015-3361044348-30300820-1013'
$key  = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid"
$item = Get-Item $key
foreach ($name in $item.GetValueNames()) {
    if ($name -in @('SequenceNumber', 'Version')) { continue }
    $data = $item.GetValue($name)
    if ($data -isnot [byte[]] -or $data.Length -lt 8) { continue }
    $ft = [BitConverter]::ToInt64($data, 0)
    '{0:yyyy-MM-dd HH:mm:ss}Z  {1}' -f [DateTime]::FromFileTimeUtc($ft), $name
}
```

`FromFileTimeUtc`는 UTC `DateTime`을 돌려준다. 로컬 시각으로 보려면 `FromFileTime`을 쓰되 **어느 쪽을 썼는지 답안에 명시한다.**

### 5단계 — `\Device\HarddiskVolumeN`을 드라이브 문자로 바꾸기

`HarddiskVolumeN`의 `N`은 볼륨 관리자가 부팅 때 열거 순서로 붙이는 번호이고, **레지스트리에 "N ↔ 드라이브 문자" 대응이 직접 저장되어 있지 않다.** 그래서 다음 순서로 좁힌다.

| 단계 | 무엇을 하나 | 근거 |
| --- | --- | --- |
| 1 | `SYSTEM\MountedDevices`에서 존재하는 볼륨과 드라이브 문자 목록을 뽑는다 | [FOR-0067](./mounteddevices.html) |
| 2 | 12바이트 항목의 파티션 시작 오프셋으로 파티션 순서를 정한다 | 오프셋 ÷ 512 = 시작 섹터 |
| 3 | `mmls`로 이미지의 파티션 순서를 확인해 볼륨 순번과 맞춘다 | [FOR-0040](./tsk-mmls.html) |
| 4 | BAM 경로의 하위 경로가 `\Users\<이름>\...`이면 그 볼륨은 시스템 볼륨(대개 `C:`)이다 | 경로 내용 자체가 힌트 |
| 5 | 두 표기를 함께 담는 artifact로 확정한다 | Prefetch의 볼륨 정보, LNK, EVTX |

**`HarddiskVolume1`이 곧 `C:`라고 단정하지 않는다.** 시스템 예약 파티션·복구 파티션 때문에 `C:`가 `HarddiskVolume2`나 `HarddiskVolume3`인 환경이 매우 흔하다. 실무에서는 **같은 hive의 BAM 항목 중 `\Windows\System32\...`가 들어 있는 볼륨 번호를 시스템 볼륨으로 확정**하는 것이 가장 빠르다.

```text
\Device\HarddiskVolume3\Windows\System32\cmd.exe
                        ^^^^^^^^^^^^^^^^^
=> HarddiskVolume3 = Windows 가 설치된 볼륨 = 대개 C:
=> 같은 hive 의 다른 HarddiskVolume 번호는 다른 파티션 또는 착탈식 볼륨
```

### 6단계 — 다른 실행 artifact와의 비교

| artifact | 무엇을 증명 | 사용자 특정 | GUI 실행만? | 실행 횟수 | 시각 보존 |
| --- | --- | --- | --- | --- | --- |
| **BAM/DAM** | 실행 사실 + 마지막 시각 | **가능 (SID별)** | 무관 | 없음 | **최근 약 1주일 분량만 남는 경향** |
| UserAssist ([FOR-0061](./userassist.html)) | 사람이 Explorer로 실행 | 가능 (hive별) | **GUI 실행만** | 있음 | 오래 남는다 |
| Prefetch | 실행 사실 + 로드 파일 | 불가 | 무관 | 있음 | 최근 8회 시각 |
| Amcache | 파일 존재/등록 + 해시 | 불가 | 무관 | 없음 | 오래 남는다 |
| Shimcache | 파일 존재 (실행 미보장) | 불가 | 무관 | 없음 | 오래 남는다 |
| EVTX 4688 | 실행 + 명령행 + 부모 | 가능 (계정 필드) | 무관 | 이벤트 수로 | 감사 정책·로그 크기에 종속 |

BAM의 약점은 **보존 기간**이다. 오래된 실행은 목록에서 빠진다. "BAM에 없다 = 실행되지 않았다"는 절대 성립하지 않는다. 반대로 강점은 **GUI 여부와 무관**하다는 점이라, `cmd.exe`에서 타이핑해 실행한 프로그램도 잡힌다. UserAssist가 놓치는 바로 그 구멍을 메운다.

## 출력 필드 해석

| 필드 | 어디서 | 결론에 어떻게 쓰나 |
| --- | --- | --- |
| SID 서브키 이름 | `UserSettings\<SID>` | 실행 주체. `ProfileList`로 계정명 환산 |
| 값 이름의 파일 경로 | 값 이름 | 실행된 파일. 사용자 폴더·`Temp`·`Downloads`면 강한 의심 신호 |
| 값 이름의 볼륨 번호 | `\Device\HarddiskVolumeN` | 어느 볼륨의 파일인가. `MountedDevices`로 문자 환산 |
| 데이터 앞 8바이트 | 값 데이터 `0x00` | 마지막 실행 시각(UTC). FILETIME |
| `SequenceNumber` / `Version` | SID 키의 값 | BAM 관리용. 실행 기록이 아니다 |
| 키 LastWrite | `UserSettings\<SID>` | 그 SID의 목록이 마지막으로 갱신된 시각. 개별 실행 시각과 다르다 |

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| SID | `SOFTWARE\...\ProfileList`, `SAM` ([FOR-0052](./sam-user-accounts.html)) | 계정 이름 |
| `\Device\HarddiskVolumeN` | `SYSTEM\MountedDevices` ([FOR-0067](./mounteddevices.html)) | 드라이브 문자. 착탈식이면 USB |
| 실행 파일 경로 | Prefetch, Amcache | 실행 횟수, 로드한 파일, SHA-1 |
| 실행 파일 경로 | UserAssist ([FOR-0061](./userassist.html)) | 사람이 직접 눌러 실행했는지 |
| 마지막 실행 시각 | EVTX Security 4624/4688 ([FOR-0083](./event-4624-logon.html)) | 그 시각의 로그온 세션과 명령행 |
| 마지막 실행 시각 | `$MFT`, `$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html)) | 그 시각에 만들어진/지워진 파일 |
| 착탈식 볼륨 번호 | `Enum\USBSTOR` ([FOR-0066](./usbstor.html)) | USB에서 직접 실행된 프로그램 |

## 흔한 함정

- **`C:\Users\...` 로 검색하는 것.** 값 이름은 `\Device\HarddiskVolumeN\Users\...`다 → 문자열 검색이 0건이라 "기록이 없다"고 오판한다 → 파일명만으로 검색한다.
- **`HarddiskVolume1`을 `C:`로 단정하는 것.** 시스템 예약/복구 파티션 때문에 번호가 밀린다 → 엉뚱한 볼륨의 파일로 답한다 → 같은 목록에서 `\Windows\System32\`가 있는 번호를 시스템 볼륨으로 잡고, `MountedDevices`·`mmls`로 검증한다.
- **값 데이터 전체를 타임스탬프로 변환하는 것.** 앞 8바이트만 FILETIME이다 → 24바이트를 통째로 넣으면 변환 도구가 엉뚱한 값을 낸다 → 정확히 `0x00`부터 8바이트만 잘라낸다.
- **`SequenceNumber`/`Version`을 실행 기록으로 세는 것.** 경로가 아닌 관리용 값이다 → 실행 건수가 부풀려진다 → 값 이름이 `\Device\`로 시작하는 것만 센다.
- **"BAM에 없다 = 실행 안 됐다"로 결론하는 것.** 최근 약 1주일 분량만 남는 경향이 있다 → 오래된 실행을 부정해 버린다 → Prefetch·Amcache·Shimcache·EVTX로 반드시 보완한다.
- **BAM 시각을 "그 프로그램의 모든 실행"으로 확대하는 것.** 항목당 시각은 **마지막 1회**뿐이다 → 여러 번 실행한 타임라인을 못 만든다 → 횟수·이전 시각은 UserAssist(횟수)와 Prefetch(최근 8회)로 채운다.
- **`S-1-5-18` 항목을 사용자 행위로 해석하는 것.** LocalSystem은 서비스·시스템 프로세스다 → "관리자가 실행했다"로 잘못 서술한다 → `S-1-5-21-...-<RID>` 항목만 사용자 행위로 다룬다.
- **Windows 7·8 이미지에서 BAM을 찾는 것.** Windows 10 1709 이후에 존재한다 → 키가 없다고 hive가 손상됐다고 오판한다 → OS 빌드를 `SOFTWARE\Microsoft\Windows NT\CurrentVersion`에서 먼저 확인한다.
- **`State` 서브키만 찾고 포기하는 것.** 초기 빌드는 `Services\bam\UserSettings\<SID>`다 → 키가 없다고 결론한다 → 두 경로를 모두 확인한다.
- **FILETIME을 로컬 시각으로 읽는 것.** 결과는 UTC다 → 9시간 틀린 답을 낸다 → KST 요구 시 +9시간, 표에 시간대를 반드시 적는다.
- **`rla`로 트랜잭션 로그를 반영하지 않는 것.** BAM은 자주 갱신되는 키라 최신 항목이 `.LOG1`/`.LOG2`에 있을 확률이 높다 → 마지막 실행이 누락된다 → `SYSTEM`과 두 로그를 함께 꺼내 반영한다.

## 교차검증

```powershell
# 1) BAM — 사용자별 마지막 실행
rip.exe -r "C:\case\clean\SYSTEM" -p bam > bam.txt

# 2) SID -> 계정 이름
rip.exe -r "C:\case\SOFTWARE" -p profilelist > profiles.txt

# 3) 같은 프로그램을 UserAssist 에서 확인 (사람이 직접 눌렀는가)
rip.exe -r "C:\case\clean\NTUSER.DAT" -p userassist | Select-String 'dump_tool'

# 4) Prefetch — 실행 횟수와 최근 8회 시각
#    (WinPrefetchView 로 Prefetch 폴더를 열어 Run Count 확인)

# 5) 파일 생성 시각 — MFT 와 대조
Import-Csv 'C:\case\out\mft.csv' | Where-Object { $_.FileName -like '*dump_tool*' }

# 6) 볼륨 번호 -> 드라이브 문자
rip.exe -r "C:\case\SYSTEM" -p mountdev > mountdev.txt
```

BAM 시각과 Prefetch의 마지막 실행 시각이 일치하면 결론이 단단해진다. **BAM에는 있는데 Prefetch에 없으면** Prefetch가 삭제됐거나 `EnablePrefetcher = 0`인 환경이다([FOR-0053](./system-controlset.html)).

## mini walkthrough

```text
문제:
"SYSTEM, SOFTWARE hive 가 첨부됩니다. 2026-03-14 오후(KST)에 압축 도구를 실행한
 사용자의 계정 이름과 그 실행 시각(KST)을 구하세요."

1. 첫 시도 (실패):
   RegistryExplorer 로 SYSTEM 을 열고
   SYSTEM\ControlSet001\Services\bam\UserSettings 를 찾았다. 없다.
   "이 이미지에는 BAM 이 없다" 고 판단하고 Prefetch 를 요청하려 했다.

   왜 틀렸나:
   이 빌드는 State 계층이 있는 형태였다.
     Services\bam\State\UserSettings\<SID>
   State 를 빼놓고 찾은 것이 전부였다. 두 경로를 모두 확인해야 한다.

2. 올바른 경로에서 SID 목록 확보
   SYSTEM\ControlSet001\Services\bam\State\UserSettings
     S-1-5-18
     S-1-5-21-3623811015-3361044348-30300820-1001
     S-1-5-21-3623811015-3361044348-30300820-1013

3. 두 번째 실수 — 경로 검색이 0건
   Select-String -Path bam.txt -Pattern 'C:\\Program Files\\7-Zip'
   -> 0 건. "7-Zip 은 안 돌았다" 고 판단했다.

   왜 틀렸나:
   값 이름은 드라이브 문자가 아니라 커널 경로다.
     \Device\HarddiskVolume3\Program Files\7-Zip\7zG.exe
   'C:\' 로 검색하면 절대 걸리지 않는다. 파일명으로 검색해야 한다.

   Select-String -Path bam.txt -Pattern '7z|winrar|zip'
   -> S-1-5-21-...-1013
      값: \Device\HarddiskVolume3\Program Files\7-Zip\7zG.exe

4. 시각 계산
   값 데이터 앞 8바이트: 40 D5 1C 52 12 8F DC 01
   -> FILETIME -> 2026-03-14 07:31:02Z (UTC)
   -> KST = 2026-03-14 16:31:02

   시간대 확인: SYSTEM\ControlSet001\Control\TimeZoneInformation
               TimeZoneKeyName = Korea Standard Time  (UTC+9)

5. SID -> 계정
   SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
     S-1-5-21-...-1013  ProfileImagePath = C:\Users\jhkim
   -> jhkim

6. 볼륨 번호 검증
   같은 목록에 \Device\HarddiskVolume3\Windows\System32\cmd.exe 가 있다
   -> HarddiskVolume3 = Windows 설치 볼륨 = C:
   MountedDevices 의 \DosDevices\C: (12바이트, offset 1048576) 와 정합

7. 교차검증
   - UserAssist(NTUSER.DAT of jhkim) 에 7zG.exe 항목 존재, Run Count 4
   - $UsnJrnl 에 같은 시각대의 .zip 파일 생성 레코드 존재

정답: jhkim, 2026-03-14 16:31:02 KST (7zG.exe)
```

## 막혔을 때 다음 체크

1. `Services\bam\State\UserSettings`와 `Services\bam\UserSettings` **두 경로를 다** 봤는가
2. `dam` 쪽도 봤는가 (비어 있는 것이 정상이다)
3. `SYSTEM\Select`의 `Current`로 활성 ControlSet을 정했는가
4. `rla`로 `SYSTEM.LOG1`/`.LOG2`를 반영했는가
5. 검색을 `C:\`가 아니라 **파일명**으로 했는가
6. 값 데이터 **앞 8바이트만** FILETIME으로 변환했는가
7. `SequenceNumber`/`Version`을 실행 기록에서 제외했는가
8. `\Device\HarddiskVolumeN`을 `\Windows\System32` 항목으로 시스템 볼륨과 대조했는가
9. SID를 `ProfileList`로 계정 이름으로 바꿨는가
10. 찾는 실행이 1주일보다 오래됐을 가능성이 있는가 → Prefetch·Amcache·Shimcache·4688로 이동
11. OS가 Windows 10 1709 이전은 아닌가 → BAM 자체가 없다

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM` hive의 위치와 `Services` 계층 구조, 오프라인 hive 경로 표기
- SRC-014 — Microsoft Learn, File Times: 값 데이터 앞 8바이트를 FILETIME(1601-01-01 UTC 기준 100ns)으로 해석하는 근거와 Unix epoch 차이 `11644473600`초
- SRC-099 — RegRipper 3.0 저장소: `bam`, `profilelist`, `mountdev` 플러그인의 존재와 `rip.exe` 옵션
- **`State` 서브키의 유무, 값 데이터의 전체 길이, `0x08` 이후 바이트의 의미는 Windows 빌드에 따라 다르다.** 이 글은 앞 8바이트 FILETIME만 근거로 쓰고 나머지는 주장하지 않는다. 실제 hive에서 파서 출력과 대조할 것
- BAM 항목의 **보존 기간(최근 약 1주일)** 은 관찰된 경향이며 OS가 보장하는 값이 아니다. "없다"를 실행 부정의 근거로 쓰지 말 것
- `\Device\HarddiskVolumeN`의 번호와 드라이브 문자의 대응은 레지스트리에 직접 저장되지 않으므로, `MountedDevices`·파티션 테이블·경로 내용으로 추론하고 다른 artifact로 검증할 것
- RegRipper 플러그인 이름과 출력 형식은 버전에 따라 다를 수 있으므로 `rip.exe -l`로 확인할 것
