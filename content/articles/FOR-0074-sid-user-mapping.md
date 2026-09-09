---
id: FOR-0074
title: "SID를 사용자 이름으로 바꾸기: ProfileImagePath와 S-1-5-21 해부"
slug: "sid-user-mapping"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["SID", "ProfileImagePath", "ProfileList", "SAM", "BAM", "$Recycle.Bin", "머신 SID", "RID"]
file_paths: ["C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Windows\\System32\\config\\SAM", "C:\\Users", "C:\\$Recycle.Bin"]
registry_paths: ["SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "SAM\\Domains\\Account\\Users\\Names", "SAM\\Domains\\Account", "SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings", "SECURITY\\Policy\\PolAcDmS", "SECURITY\\Policy\\PolPrDmN"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "FTK Imager", "EvtxECmd", "KAPE"]
commands: ["rip.exe -r SOFTWARE -p profilelist", "rip.exe -r SAM -p samparse", "wmic useraccount get name,sid"]
regex_patterns: ["S-1-5-21-\\d+-\\d+-\\d+-\\d+", "S-1-5-(18|19|20)", "S-1-5-32-5\\d\\d"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ProfileImagePath", "Sid", "Flags", "State", "TargetUserSid", "SubjectUserSid", "TargetUserName", "RID"]
file_formats: ["regf"]
primary_terms: ["SID 매핑", "SID 사용자 연결", "ProfileImagePath", "S-1-5-21"]
keywords: ["SID", "ProfileImagePath", "ProfileList", "S-1-5-21", "S-1-5-18", "RID", "머신 SID", "도메인 SID", "well-known SID", "SAM Names", "TargetUserSid", "삭제된 계정"]
aliases: ["sid 사용자 이름", "sid 매핑", "s-1-5-21 누구", "sid 어느 계정", "sid 해석", "휴지통 sid", "profileimagepath"]
symptom_keywords: ["SID만 나오고 이름을 모르겠다", "이 SID가 누구인지", "S-1-5-18이 무슨 계정인지", "삭제된 계정의 SID만 남았다", "로컬인지 도메인 계정인지", "휴지통 폴더 이름이 SID다"]
related: ["FOR-0052", "FOR-0055", "FOR-0073", "FOR-0056"]
source_ids: ["SRC-019", "SRC-017", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

SID를 사용자 이름으로 바꾸는 정공법은 `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>`의 `ProfileImagePath` 값이며, 그것이 없으면 `SAM\Domains\Account\Users\Names`와 프로필 폴더 이름으로 우회하고, **머신 SID 접두어가 같은지로 로컬 계정과 도메인 계정을 가른다.**

## 어떤 문제에서 필요한가

- `$Recycle.Bin\S-1-5-21-...-1002` 폴더가 나왔는데 누구의 휴지통인지 모른다
- EVTX의 `TargetUserSid`만 있고 `TargetUserName`이 비어 있거나 `-`다
- BAM의 `UserSettings\<SID>` 아래 실행 기록을 사용자에게 귀속시켜야 한다
- 파일 소유자가 SID로만 표시된다
- 계정이 삭제되어 이름이 어디에도 없다
- 로컬 계정인지 도메인 계정인지에 따라 사건 해석이 완전히 달라진다

## 문제에서 처음 볼 단서

1. `S-1-5-21-`로 시작하는 긴 문자열 → 로컬 또는 도메인 사용자. 매핑이 필요하다
2. `S-1-5-18`, `S-1-5-19`, `S-1-5-20` → 사용자가 아니다. 시스템 계정이므로 사람에게 귀속시키지 않는다
3. `S-1-5-32-`로 시작 → 내장 그룹이다
4. 마지막 숫자(RID)가 `500`이면 내장 Administrator, `1000` 이상이면 나중에 만든 계정
5. 첨부에 `SOFTWARE` hive가 있다 → 30초 안에 끝난다

## 30초 절차

```powershell
rip.exe -r "C:\case\SOFTWARE" -p profilelist
```

RegistryExplorer 경로다.

```text
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-3623811015-3361044348-30300820-1002
  ProfileImagePath = C:\Users\hjlee        <- 프로필 폴더 = 사실상의 사용자
  Flags            = 0
  State            = 0
```

라이브 시스템이면 한 줄로 전체 대조표가 나온다.

```powershell
wmic useraccount get name,sid
Get-LocalUser | Select-Object Name, SID
```

## 상세 절차

### 1단계 — SID 구조 해부

```text
S - 1 - 5 - 21 - 3623811015 - 3361044348 - 30300820 - 1002
│   │   │    │   └──────────┬──────────┘   └───────┘   └──┘
│   │   │    │              │                  │        └ RID (상대 식별자)
│   │   │    │              │                  └───────── 머신/도메인 식별자 3번째
│   │   │    │              └──────────────────────────── 머신/도메인 식별자 (32비트 3개)
│   │   │    └─────────────────────────────────────────── 서브오소리티 21 = 로컬 머신 또는 도메인
│   │   └──────────────────────────────────────────────── 식별자 권한 5 = NT AUTHORITY
│   └──────────────────────────────────────────────────── 리비전 1 (항상 1)
└──────────────────────────────────────────────────────── SID 문자열 표기 접두어
```

| 부분 | 의미 | 포렌식 용도 |
| --- | --- | --- |
| `S-1-5` | NT 권한(`NT AUTHORITY`) | 여기서 시작하지 않는 SID는 `Everyone` 같은 특수 SID다 |
| `-21-` | "로컬 머신 또는 도메인이 발급" | **이것이 있으면 사람 계정 후보** |
| 32비트 3개 | **머신 SID 또는 도메인 SID** | 같으면 같은 발급자. 로컬/도메인 판별의 핵심 |
| 마지막 숫자 | RID | 계정 종류와 생성 순서 |

`S-1-5-21-A-B-C`까지가 **발급자**, 그 뒤 RID가 **그 발급자 안에서의 계정 번호**다. 발급자 부분을 접두어라고 부른다.

### 2단계 — 잘 알려진 SID (매핑이 필요 없는 것들)

| SID | 계정/그룹 | 해석 |
| --- | --- | --- |
| `S-1-0-0` | Nobody(Null) | 소유자 미지정 |
| `S-1-1-0` | **Everyone** | 모든 사용자. 권한 설정에 등장 |
| `S-1-2-0` | Local | 로컬 로그온 사용자 |
| `S-1-3-0` | Creator Owner | ACL 상속용 자리표시자 |
| `S-1-5-7` | Anonymous Logon | 익명 접근 |
| `S-1-5-11` | Authenticated Users | 인증된 모든 사용자 |
| `S-1-5-18` | **Local System** | 서비스/커널 컨텍스트. **사람이 아니다** |
| `S-1-5-19` | **Local Service** | 낮은 권한 서비스 |
| `S-1-5-20` | **Network Service** | 네트워크 접근용 서비스 |
| `S-1-5-32-544` | **Administrators** | 내장 관리자 그룹 |
| `S-1-5-32-545` | Users | 내장 사용자 그룹 |
| `S-1-5-32-546` | Guests | 내장 게스트 그룹 |
| `S-1-5-32-547` | Power Users | 레거시 그룹 |
| `S-1-5-32-555` | Remote Desktop Users | RDP 허용 그룹 |
| `S-1-5-113` | Local account | 로컬 계정임을 나타내는 조건 SID |
| `S-1-5-114` | Local account and member of Administrators group | 로컬 관리자 조건 SID |

RID만으로 정체가 정해지는 것들이다.

| RID | 계정 | 비고 |
| --- | --- | --- |
| `500` | Administrator (내장) | 이름을 바꿔도 RID는 500이다 |
| `501` | Guest (내장) | 기본 비활성 |
| `502` | krbtgt | 도메인 컨트롤러에만 존재 |
| `503` | DefaultAccount | Windows 10 이후 |
| `504` | WDAGUtilityAccount | Defender Application Guard용 |
| `512` / `513` / `519` | Domain Admins / Domain Users / Enterprise Admins | **도메인 SID 접두어와 함께 나온다** |
| `1000` 이상 | 사후 생성된 로컬 계정 | 보통 1000, 1001, 1002... 순서대로 발급 |

**RID 순서는 계정 생성 순서의 단서다.** `1001`이 `1002`보다 먼저 만들어진 계정이다. 다만 계정을 삭제하고 다시 만들면 번호가 건너뛰므로, 빈 번호는 **삭제된 계정의 흔적**이다.

### 3단계 — SID → 사용자 이름 매핑 3가지 경로

#### ① `ProfileList` (1순위)

```text
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
  ProfileImagePath = C:\Users\hjlee            (REG_EXPAND_SZ)
  Sid              = (REG_BINARY, 같은 SID의 이진 형태)
  Flags            = 0
  State            = 0
```

| 값 | 의미 |
| --- | --- |
| `ProfileImagePath` | **프로필 폴더 경로.** 사실상 사용자 이름의 근거 |
| `Sid` | 키 이름의 SID를 이진으로 중복 저장 |
| `Flags` / `State` | 프로필 상태 플래그. 임시 프로필·손상 프로필 판정에 쓴다 |
| `ProfileLoadTime*` / `LocalProfileLoadTime*` / `LocalProfileUnloadTime*` | FILETIME을 `High`/`Low` 두 DWORD로 나눠 저장. **로그온/로그오프 시각의 보조 근거** |

시각 값들은 OS 버전에 따라 있거나 없다. 있으면 `High`를 상위 32비트, `Low`를 하위 32비트로 합쳐 FILETIME(1601-01-01 UTC 기준 100ns)으로 읽는다. **존재하지 않는 값을 있다고 쓰지 않는다.**

도메인 계정도 그 PC에 로그온한 적이 있으면 `ProfileList`에 항목이 생긴다. 이때 `ProfileImagePath`가 `C:\Users\hjlee.CORP` 처럼 도메인 접미사가 붙는 경우가 있다.

#### ② `SAM\Domains\Account\Users\Names` (로컬 계정)

```text
SAM\Domains\Account\Users\Names\hjlee        <- 키 이름이 사용자 이름
SAM\Domains\Account\Users\000003EA           <- RID 를 16진 8자리로 쓴 키 (0x3EA = 1002)
  F = (REG_BINARY)   계정 플래그, 마지막 로그온·비밀번호 시각
  V = (REG_BINARY)   이름·풀네임·설명·해시
```

`Names\<사용자명>` 키의 기본 값은 데이터가 비어 있고, **그 값의 자료형 숫자가 RID**로 쓰인다. RegistryExplorer는 이것을 자동으로 풀어 보여 주고, RegRipper `samparse`는 사용자명과 RID를 쌍으로 출력한다. 손으로 읽을 때만 이 트릭이 필요하다 ([FOR-0052](./sam-user-accounts.html)).

머신 SID의 접두어는 `SAM\Domains\Account`의 `V` 값 끝부분에 3개의 32비트 값으로 들어 있다. **바이트 오프셋은 파서에 맡긴다** — RegRipper `samparse`가 머신 SID를 함께 출력한다.

#### ③ 프로필 폴더 이름 (최후 수단)

```text
C:\Users\hjlee
C:\Users\hjlee.CORP        <- 같은 이름의 도메인 계정이 나중에 로그온
C:\Users\hjlee.000         <- 프로필 생성 충돌 시 붙는 접미사
```

**폴더 이름은 계정 이름과 다를 수 있다.** 계정 이름을 바꿔도 폴더는 그대로 남고, 접미사가 붙은 폴더는 "같은 이름의 다른 계정이 존재했다"는 신호다. 그러므로 폴더 이름은 ①·②가 실패할 때만 쓰고, 근거로 제시할 때 한계를 함께 적는다.

### 4단계 — 로컬 계정과 도메인 계정 구분

접두어 비교 한 줄로 끝난다.

```text
머신 SID (SAM 에서)  : S-1-5-21-3623811015-3361044348-30300820
사용자 A             : S-1-5-21-3623811015-3361044348-30300820-1002   -> 접두어 동일 = 로컬 계정
사용자 B             : S-1-5-21-1004336348-1177238915-682003330-1145  -> 접두어 다름  = 도메인 계정
```

| 관측 | 판정 | 추가 확인 |
| --- | --- | --- |
| 접두어 = 머신 SID | **로컬 계정** | `SAM\Domains\Account\Users`에 RID가 존재해야 한다 |
| 접두어 ≠ 머신 SID, RID ≥ 1000 | **도메인 계정** | `SECURITY\Policy\PolAcDmS`(계정 도메인 SID), `PolPrDmN`(주 도메인 이름)과 대조 |
| 접두어 ≠ 머신 SID, RID = 500 | 다른 컴퓨터의 내장 Administrator | 로밍 프로필이나 다른 이미지의 파일이 섞였을 가능성 |
| `S-1-5-32-`, `S-1-5-18/19/20` | 계정 매핑 대상이 아니다 | 서비스/그룹으로 처리 |

도메인 SID가 여러 개 보이면 다중 도메인 또는 신뢰 관계 환경이다. 도메인 여부 판정은 [FOR-0073](./computer-name.html)의 `NV Domain`과 함께 본다.

### 5단계 — SID가 나타나는 artifact 표

| artifact | SID가 나오는 위치 | 얻는 것 |
| --- | --- | --- |
| `$Recycle.Bin` | `C:\$Recycle.Bin\<SID>\` 하위 폴더 이름 | 누가 삭제했는가 ([FOR-0030](./recycle-bin-i-r.html)) |
| BAM | `SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID>` | 그 사용자가 실행한 프로그램과 마지막 실행 시각 |
| 레지스트리 사용자 트리 | `HKU\<SID>`, `HKU\<SID>_Classes` | 어떤 `NTUSER.DAT`/`UsrClass.dat`가 누구 것인지 |
| UserAssist | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | 사용자별 GUI 실행 ([FOR-0061](./userassist.html)) |
| EVTX | `TargetUserSid`, `SubjectUserSid` | 이름이 비었을 때의 유일한 주체 식별자 |
| NTFS 보안 기술자 | 파일/폴더 소유자 SID | 누가 만든 파일인가 |
| ProfileList | 키 이름 자체 | SID ↔ 프로필 폴더 |
| SRUM | 앱 사용 기록의 사용자 식별 테이블 | 사용자별 네트워크 사용량 |
| 작업 스케줄러 XML | `<UserId>` | 작업을 등록/실행한 주체 |
| 서비스/프로세스 토큰 (메모리) | 토큰의 소유자 SID | 실행 컨텍스트 |

**`$Recycle.Bin`의 SID 폴더는 계정이 삭제된 뒤에도 남는다.** 그래서 "이미 없는 계정"의 존재를 증명하는 데 자주 쓰인다.

### 6단계 — 삭제된 계정의 SID만 남은 경우

| 남아 있는 것 | 무엇을 말해 주나 |
| --- | --- |
| `ProfileList\<SID>` 항목이 남아 있다 | 프로필 삭제가 불완전했다. `ProfileImagePath`로 이름 복원 가능 |
| `ProfileList`에 없고 `$Recycle.Bin\<SID>`만 있다 | 계정과 프로필이 지워졌다. **이름은 다른 곳에서 찾아야 한다** |
| `SAM`에 RID가 없고 RID 번호가 비어 있다 | 그 번호의 계정이 삭제됐다. 인접 RID의 생성 시각으로 시간 범위를 좁힌다 |
| EVTX에 `TargetUserSid`와 `TargetUserName`이 함께 있는 오래된 이벤트 | **이름 복원의 1순위.** 삭제 전 로그온 기록이 매핑을 준다 |
| `C:\Users\<name>` 폴더가 남아 있다 | 폴더 이름이 후보. `$MFT`에서 삭제된 폴더 이름도 찾는다 |

```powershell
# 삭제된 계정의 이름을 EVTX 에서 복원한다 — SID 로 검색하는 것이 요령
Import-Csv "C:\case\out\evt.csv" |
  Where-Object { $_.PayloadData1 -match 'S-1-5-21-3623811015-3361044348-30300820-1003' -or
                 $_.Payload      -match 'S-1-5-21-3623811015-3361044348-30300820-1003' } |
  Select-Object -First 5 TimeCreated, EventId, UserName, Payload
```

계정 생성/삭제 이벤트(4720 생성, 4726 삭제)가 남아 있으면 SID와 이름이 한 이벤트에 함께 들어 있으므로 그것이 가장 깔끔한 근거다.

## 출력 필드 해석

RegRipper `profilelist` 출력 예시다.

```text
profilelist v.20200525
ProfileList
Software\Microsoft\Windows NT\CurrentVersion\ProfileList

Path: C:\Users\hjlee
SID : S-1-5-21-3623811015-3361044348-30300820-1002

Path: C:\Users\jhkim
SID : S-1-5-21-3623811015-3361044348-30300820-1001

Path: C:\Windows\ServiceProfiles\LocalService
SID : S-1-5-19
```

| 관측 | 해석 |
| --- | --- |
| `C:\Users\<name>` | 사람 계정. 접두어를 머신 SID와 비교한다 |
| `C:\Windows\ServiceProfiles\...` | 서비스 계정. 사람에게 귀속시키지 않는다 |
| `C:\Windows\system32\config\systemprofile` | `S-1-5-18` = SYSTEM |
| RID가 `1000` 이상인데 폴더가 없다 | 프로필이 삭제됐다. 계정은 있었다 |
| 같은 이름의 폴더가 접미사와 함께 둘 | 로컬 계정과 도메인 계정이 이름이 겹쳤다 |

## pivot: 다음에 볼 artifact

| 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| SID ↔ 사용자명 | 그 프로필의 `NTUSER.DAT`, `UsrClass.dat` | 사용자별 활동 전체 ([FOR-0051](./registry-hive-map.html)) |
| RID | `SAM\Domains\Account\Users\<RID 16진>` | 계정 플래그, 마지막 로그온, 로그온 실패 횟수 |
| 머신 SID | 다른 이미지의 머신 SID | 같은 PC인지 판정 ([FOR-0073](./computer-name.html)) |
| 도메인 SID | `SECURITY\Policy\PolAcDmS`, `PolPrDmN` | 도메인 이름과 가입 상태 ([FOR-0056](./security-hive-overview.html)) |
| SID | `$Recycle.Bin\<SID>` | 그 사용자의 삭제 파일 |
| SID | BAM `UserSettings\<SID>` | 그 사용자의 실행 이력 |
| SID | EVTX `TargetUserSid` 필터 | 그 사용자의 로그온/권한 사용 ([FOR-0083](./event-4624-logon.html)) |
| 사용자명 | UserAssist, ShellBags | GUI 실행과 폴더 탐색 |

## 흔한 함정

- **`S-1-5-18`을 사람 계정으로 귀속시키는 것** → SYSTEM은 서비스·스케줄러·설치 프로그램의 컨텍스트다 → 사람의 행위로 쓰려면 그 프로세스를 누가 띄웠는지(부모 프로세스, 서비스 등록자)를 따로 증명한다.
- **RID만 보고 계정을 특정하는 것** → RID `1001`은 PC마다 다른 사람이다 → 접두어(머신/도메인 SID)까지 포함한 전체 SID로 비교한다.
- **`ProfileImagePath`의 폴더 이름을 계정 이름으로 단정하는 것** → 계정 이름을 바꿔도 폴더는 그대로다 → `SAM\Domains\Account\Users\Names`로 확인한다.
- **접두어 비교를 건너뛰고 로컬 계정이라고 단정하는 것** → 도메인 계정도 `ProfileList`에 들어온다 → 머신 SID를 먼저 확보한 뒤 비교한다.
- **RID `500`을 "Administrator라는 이름의 계정"으로 읽는 것** → 이름은 변경 가능하고 RID만 불변이다 → 이름이 아니라 RID로 내장 관리자를 판정한다.
- **`Everyone`(`S-1-1-0`)을 사용자로 세는 것** → 권한 설정용 특수 SID다 → 사용자 목록에서 제외한다.
- **`ProfileList`에 없는 SID를 "존재하지 않는 계정"으로 결론 내는 것** → 그 PC에 한 번도 로그온하지 않은 도메인 계정은 항목이 없다. 삭제된 계정도 없다 → EVTX·`$Recycle.Bin`·`SAM`을 함께 본다.
- **`Users` 폴더 개수로 사용자 수를 세는 것** → `Public`, `Default`, `Default User`(정션), `All Users`(정션)는 사람이 아니다 → `ProfileList`의 `C:\Users\*` 항목만 센다.
- **16진 RID 키 이름을 10진으로 오해하는 것** → `SAM`의 사용자 키 이름 `000003E9`는 16진 = 1001이다 → 변환 후 비교한다.
- **시간대 보정 누락** → `ProfileList`의 로드/언로드 시각과 `SAM`의 마지막 로그온 시각은 FILETIME(UTC)이다 → KST 답이면 +9시간, Unix 환산은 `11644473600`초 차이다.

## 교차검증

```powershell
# 1) ProfileList — SID -> 프로필 폴더
rip.exe -r "C:\case\SOFTWARE" -p profilelist
```

```powershell
# 2) SAM — 사용자명, RID, 머신 SID, 마지막 로그온
rip.exe -r "C:\case\SAM" -p samparse
```

```powershell
# 3) 프로필 폴더 실물 — hive 가 실제로 있는가
Get-ChildItem "C:\case\mount\Users" -Directory | Select-Object Name, CreationTimeUtc
```

```powershell
# 4) EVTX — SID 와 이름이 함께 있는 이벤트로 확증
Import-Csv "C:\case\out\evt.csv" |
  Where-Object { $_.Payload -match 'S-1-5-21-.*-1002' } |
  Select-Object -First 3 TimeCreated, EventId, UserName
```

네 곳이 같은 이름을 가리키면 확정이다. `ProfileList`와 `SAM`이 어긋나면 계정 이름이 변경됐거나 프로필 폴더가 재사용된 경우다.

## mini walkthrough

```text
문제:
"C:\$Recycle.Bin 아래 SID 폴더가 3개 있습니다. 자료를 삭제한 사용자의 이름을
 구하고, 그 계정이 로컬인지 도메인 계정인지 판정하시오.
 첨부: SAM, SYSTEM, SOFTWARE, SECURITY, $Recycle.Bin 폴더 트리"

   $Recycle.Bin\S-1-5-21-3623811015-3361044348-30300820-1001   ($I/$R 없음)
   $Recycle.Bin\S-1-5-21-3623811015-3361044348-30300820-1003   ($I/$R 4쌍 있음)
   $Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1145  ($I/$R 1쌍 있음)

1. 첫 시도 (실패):
   "RID 가 큰 1145 가 가장 나중에 만든 계정이니 그 사용자다"라고 판단했다.
   -> RID 크기 비교는 같은 발급자 안에서만 의미가 있다.
      1145 의 접두어(1004336348-...)는 나머지 둘과 다르다. 다른 발급자다.
      RID 를 비교하기 전에 접두어를 봐야 했다.

2. 머신 SID 확보
   rip.exe -r SAM -p samparse
     Machine SID : S-1-5-21-3623811015-3361044348-30300820
     Username : jhkim [1001]
     Username : Administrator [500]
   -> 1001 = jhkim (로컬).  1003 은 SAM 에 없다.  1145 는 접두어가 달라 도메인 계정.

3. ProfileList 로 1003 매핑
   rip.exe -r SOFTWARE -p profilelist
     Path: C:\Users\jhkim   SID: ...-1001
     Path: C:\Users\hjlee   SID: ...-1003      <- SAM 에는 없지만 프로필은 남았다
     Path: C:\Users\ksp     SID: S-1-5-21-1004336348-1177238915-682003330-1145
   -> 1003 = hjlee.  SAM 에 없으므로 계정이 삭제된 상태.
      $I/$R 이 4쌍 있는 SID 가 이 계정이다.

4. 두 번째로 틀린 판단:
   "프로필 폴더가 C:\Users\hjlee 니까 계정 이름도 hjlee"라고 단정했다.
   -> 폴더 이름은 계정 이름 변경 후에도 바뀌지 않는다. 근거가 약하다.
      EVTX 로 확증한다:
      Import-Csv evt.csv | Where-Object { $_.Payload -match '\-1003' } |
        Select-Object -First 2 TimeCreated, EventId, UserName
        2026-03-02 01:12:44Z  4624  hjlee
        2026-04-09 08:44:10Z  4726  (계정 삭제, TargetUserName=hjlee)
      => 로그온 이벤트와 삭제 이벤트가 SID 와 이름을 함께 준다. 확정.

5. 로컬/도메인 판정
   hjlee  : S-1-5-21-3623811015-3361044348-30300820-1003
            접두어 = 머신 SID  -> 로컬 계정 (삭제됨)
   ksp    : S-1-5-21-1004336348-1177238915-682003330-1145
            접두어 ≠ 머신 SID  -> 도메인 계정
   SECURITY\Policy\PolPrDmN = CORP 로 도메인 존재 확인
   SECURITY\Policy\PolAcDmS 의 SID 가 1004336348-... 와 일치 -> 확정

6. 시간대 보정
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time
   4726 삭제 시각 2026-04-09 08:44:10Z -> 2026-04-09 17:44:10 KST
   삭제된 파일 4건의 $I 시각도 모두 UTC 이므로 동일하게 +9h.

정답:
  삭제 주체 = hjlee (로컬 계정, S-1-5-21-...-1003, 2026-04-09 17:44:10 KST 에 계정까지 삭제됨)
  ksp 는 도메인 계정으로 별개 주체
```

1단계와 4단계가 요점이다. **RID를 접두어 없이 비교하는 것, 폴더 이름을 계정 이름으로 단정하는 것**이 SID 문제의 대표적 두 오답이다.

## 막혔을 때 다음 체크

1. 머신 SID를 확보했는가 — 접두어 비교 없이는 로컬/도메인을 말할 수 없다
2. `ProfileList`를 봤는가 — 1순위 매핑
3. `SAM\Domains\Account\Users\Names`로 이름을 확증했는가
4. SID가 `S-1-5-18/19/20`이나 `S-1-5-32-`로 시작하지 않는가 — 사람이 아니다
5. RID가 `500`인가 — 이름이 무엇이든 내장 관리자다
6. `ProfileList`에 없다면 → `$Recycle.Bin`, EVTX `TargetUserSid`, `$MFT`의 삭제된 프로필 폴더
7. 계정이 삭제됐다면 → 4720/4726 이벤트에서 SID와 이름이 함께 나오는 항목
8. 16진 RID 키 이름을 10진으로 변환했는가
9. 도메인 SID가 여러 개인가 → 다중 도메인/신뢰 환경. 각 접두어를 따로 관리한다
10. FILETIME 시각을 KST로 보정했는가

## 출처

- SRC-019 — Microsoft Learn, Well-known SIDs / Security identifiers: SID 문자열 구조(리비전·식별자 권한·서브오소리티·RID), `S-1-1-0`·`S-1-5-18/19/20`·`S-1-5-32-544` 등 well-known SID와 RID 500/501/502/503의 의미
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SOFTWARE`/`SAM` hive의 위치와 `HKU\<SID>` 마운트 관계
- SRC-099 — RegRipper 3.0 저장소: `profilelist`·`samparse` 플러그인이 읽는 키와 출력 형식(머신 SID·RID·사용자명)
- `ProfileList\<SID>` 하위의 `ProfileLoadTimeLow/High`·`LocalProfileLoadTimeLow/High`·`LocalProfileUnloadTimeLow/High` **값의 존재 여부는 OS 버전에 따라 다르므로 실제 hive에서 확인할 것.** 없으면 없다고 기록한다
- `SAM\Domains\Account`의 `V` 값 안에서 머신 SID가 놓인 **바이트 오프셋은 이 글에서 단정하지 않고 파서(`samparse`, RegistryExplorer)의 출력에 맡긴다**
- `SECURITY\Policy\PolAcDmS`·`PolPrDmN`의 값 구조는 SRC-096(MS-LSAD) 계열 문서에 근거가 있으며, 이 글은 대조용 위치만 제시한다
- 계정 생성/삭제 이벤트(4720/4726)의 필드 정의는 Event Log 전담 글의 몫이며, 이 글은 SID↔이름 매핑 용도로만 참조한다
- mini walkthrough의 SID·시각·계정명은 설명을 위한 예시 값이다
