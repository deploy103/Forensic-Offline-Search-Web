---
id: FOR-0052
title: "SAM hive로 로컬 사용자 계정·RID·마지막 로그온 분석"
slug: "sam-user-accounts"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["SAM", "RID", "F value", "V value", "SID", "ProfileList"]
file_paths: ["C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\config\\SOFTWARE"]
registry_paths: ["SAM\\Domains\\Account\\Users", "SAM\\Domains\\Account\\Users\\Names", "SAM\\Domains\\Account", "SAM\\Domains\\Builtin\\Aliases", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r SAM -p samparse", "rip.exe -r SOFTWARE -p profilelist", "rla.exe -f SAM --out ."]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Last Login Date", "Pwd Reset Date", "Pwd Fail Date", "Login Count", "Embedded RID", "Account Flags"]
file_formats: ["regf"]
primary_terms: ["SAM", "SAM hive", "RID"]
keywords: ["SAM", "로컬 계정", "RID", "SID", "F value", "V value", "Administrator", "Guest", "마지막 로그온", "로그온 횟수", "계정 플래그", "ProfileList", "samparse"]
aliases: ["sam hive", "사용자 계정 목록", "로컬 계정 분석", "RID 500", "계정이 몇 개인지", "마지막 로그온 시각", "sid 사용자 매핑", "samparse"]
symptom_keywords: ["사용자가 몇 명인지 알고 싶다", "SID가 누구인지 모르겠다", "계정이 언제 만들어졌는지", "숨겨진 계정을 찾고 싶다", "마지막으로 로그온한 사람이 누군지", "폴더 이름과 계정 이름이 다르다"]
related: ["FOR-0051", "FOR-0055", "FOR-0056", "FOR-0083"]
source_ids: ["SRC-017", "SRC-019", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SAM` hive의 `Domains\Account\Users\<RID 16진수>` 아래 `F`(로그온 시각·횟수·플래그)와 `V`(사용자명·풀네임·홈디렉터리) 두 이진 값에 로컬 계정의 모든 메타데이터가 들어 있고, RegRipper의 `samparse` 플러그인이 이 두 값을 한 번에 해석해 준다.

## 어떤 문제에서 필요한가

- "이 PC에 계정이 몇 개인가, 이름이 무엇인가"
- "마지막으로 로그온한 계정과 시각은?"
- "공격자가 만든 백도어 계정이 있는가" (RID가 비정상적으로 크거나 이름이 시스템 계정 흉내)
- "`C:\Users\jhkim` 폴더의 SID는 무엇인가" → `NTUSER.DAT`, EVTX, ShellBags를 사용자에 묶는 열쇠
- "계정이 비활성인가, 잠겼는가, 암호가 없는가"

계정 자격증명(해시) 추출은 이 글의 범위가 아니다. **여기서는 계정 메타데이터만 다룬다.**

## 문제에서 처음 볼 단서

1. 첨부에 `SAM`(확장자 없음, `regf` 시그니처)이 있다
2. 문제에 "사용자", "계정", "누가", "몇 명", "SID" 같은 단어가 있다
3. EVTX에 `S-1-5-21-...-1001` 형태의 SID만 나오고 이름이 없다 → `SAM` + `ProfileList`로 이름을 붙인다
4. `C:\Users` 폴더 목록과 계정 목록의 개수가 다르다 → 삭제된 계정 또는 프로필 없는 계정

## 30초 절차

```powershell
rip.exe -r "C:\case\SAM" -p samparse
```

```text
Username        : jhkim [1001]
Full Name       :
User Comment    :
Account Type    : Default Admin User
Account Created : 2026-03-10 04:22:07Z
Name            : jhkim
Last Login Date : 2026-03-14 07:11:38Z
Pwd Reset Date  : 2026-03-10 04:22:41Z
Pwd Fail Date   : 2026-03-14 07:10:55Z
Login Count     : 14
  --> Normal user account
```

이름과 RID, 마지막 로그온, 로그온 횟수가 한 번에 나온다. SID를 완성하려면 이어서 `ProfileList`를 본다.

```powershell
rip.exe -r "C:\case\SOFTWARE" -p profilelist
```

`SAM`이 dirty 상태(base block의 primary/secondary sequence number 불일치)면 먼저 `rla`로 `SAM.LOG1`/`SAM.LOG2`를 반영한다 — 절차는 [FOR-0051](./registry-hive-map.html)과 [FOR-0061](./userassist.html)에 있다.

## 상세 절차

### 1단계 — 키 구조 파악

```text
SAM
└── SAM
    └── Domains
        ├── Account          (V 값에 머신 SID가 들어 있다)
        │   ├── Users
        │   │   ├── 000001F4     <- RID 500 (Administrator)
        │   │   ├── 000001F5     <- RID 501 (Guest)
        │   │   ├── 000001F7     <- RID 503 (DefaultAccount)
        │   │   ├── 000003E9     <- RID 1001 (일반 사용자)
        │   │   └── Names
        │   │       ├── Administrator
        │   │       ├── Guest
        │   │       └── jhkim
        │   └── Groups
        └── Builtin
            └── Aliases          (Administrators 등 로컬 그룹 멤버십)
```

RegistryExplorer로 열면 루트 이름이 `SAM`이고 그 아래 다시 `SAM` 키가 한 번 더 나온다. RegRipper 경로 표기는 `SAM\Domains\Account\Users`처럼 앞의 hive 이름을 생략한다.

### 2단계 — RID 읽기

키 이름은 **RID를 8자리 16진수로 쓴 것**이다. 손으로 변환한다.

| 키 이름 | RID(10진수) | 계정 |
| --- | --- | --- |
| `000001F4` | 500 | Administrator (내장 관리자) |
| `000001F5` | 501 | Guest |
| `000001F7` | 503 | DefaultAccount |
| `000001F8` | 504 | WDAGUtilityAccount (환경에 따라 존재) |
| `000003E8` | 1000 | 최초로 만든 일반 사용자 |
| `000003E9` | 1001 | 두 번째 일반 사용자 |
| `000003EA` | 1002 | 세 번째 일반 사용자 |

일반 사용자 RID는 **1000부터 순서대로 증가**한다. 그래서 RID 자체가 **계정 생성 순서**를 알려준다. RID 1000이 없고 1001, 1002만 있으면 1000번 계정이 삭제된 것이다.

`Names` 서브키에는 사용자명이 그대로 키 이름으로 있고, 그 키의 기본값(default value)의 **데이터가 아니라 타입 필드**에 RID가 들어 있는 특이한 구조다. 손으로 읽지 말고 파서 출력의 `[RID]`를 쓴다.

### 3단계 — `F` 값 (고정 길이 이진 값)

`Users\<RID>\F`는 계정의 시각·카운터·플래그를 담은 고정 길이 이진 값이다. 담고 있는 항목은 다음과 같다.

| 항목 | 의미 | 형식 |
| --- | --- | --- |
| Last Login | 마지막 대화형 로그온 성공 시각 | FILETIME (UTC) |
| Password Last Set / Pwd Reset | 암호를 마지막으로 설정·변경한 시각 | FILETIME (UTC) |
| Account Expires | 계정 만료 시각. 없으면 `Never` | FILETIME (UTC) |
| Last Incorrect Password / Pwd Fail | 마지막 로그온 실패 시각 | FILETIME (UTC) |
| RID | 이 계정의 RID (키 이름과 같아야 한다) | DWORD |
| Account Flags (ACB) | 비활성·잠김·암호 만료 안 함 등 | 비트 플래그 |
| Login Count | 성공 로그온 횟수 | WORD |
| Bad Password Count | 연속 실패 횟수 | WORD |

**`F` 값의 각 항목이 몇 번째 바이트인지는 문서마다 다르게 인용되므로 손으로 오프셋을 세지 않는다.** `rip.exe -p samparse` 또는 RegistryExplorer의 SAM 플러그인 출력에 나온 값을 근거로 쓴다. 오프셋을 직접 확인해야 하는 상황이라면, 키 이름의 RID와 `F` 안의 RID DWORD가 일치하는 지점을 기준점으로 삼아 검증한다.

### 4단계 — Account Flags (ACB) 해석

파서는 보통 텍스트로 풀어 주지만, 값이 숫자로만 보일 때의 대응표다.

| 비트 | 의미 | 포렌식 해석 |
| --- | --- | --- |
| `0x0001` | Account Disabled | 비활성 계정. Guest는 보통 여기 해당 |
| `0x0002` | Home directory required | 거의 안 쓰임 |
| `0x0004` | Password not required | **암호 없이 로그온 가능** — 강한 의심 신호 |
| `0x0008` | Temporary duplicate account | 임시 복제 계정 |
| `0x0010` | Normal user account | 일반 계정. 대부분 여기 |
| `0x0020` | MNS logon account | 클러스터용 |
| `0x0040` | Interdomain trust account | 도메인 신뢰 |
| `0x0080` | Workstation trust account | 컴퓨터 계정 |
| `0x0100` | Server trust account | 도메인 컨트롤러 계정 |
| `0x0200` | Password does not expire | 서비스/백도어 계정에서 흔함 |
| `0x0400` | Account auto locked | 실패 누적으로 잠김 |

`0x0004`(암호 불필요) + `0x0200`(암호 만료 안 함) 조합에 일반 사용자 RID가 붙어 있으면 공격자가 심은 계정을 의심한다.

### 5단계 — `V` 값 (가변 길이 이진 값)

`Users\<RID>\V`는 문자열들을 모아 둔 가변 길이 값이다. 값 앞부분이 **(오프셋, 길이, 타입) 묶음의 테이블**이고 그 뒤에 실제 데이터(UTF-16LE)가 붙는다.

| `V`에 들어 있는 항목 | 비고 |
| --- | --- |
| 사용자명 (Username) | `Names` 서브키 이름과 같다 |
| 풀네임 (Full Name) | 비어 있는 경우가 많다 |
| 코멘트 (Comment) | 내장 계정은 기본 설명이 들어 있다 |
| 사용자 코멘트 (User Comment) | 관리자가 넣은 메모 |
| 홈 디렉터리 / 홈 드라이브 | 도메인 환경에서 채워진다 |
| 스크립트 경로 / 프로필 경로 | 로그온 스크립트 |
| 허용 워크스테이션 / 로그온 허용 시간 | 정책 |
| LM 해시 / NT 해시 위치 | **이 글에서는 다루지 않는다** |

**테이블의 오프셋은 값의 선두 기준이 아니라 데이터 영역 시작점 기준의 상대값이다. 기준점을 손으로 계산하면 거의 틀리므로 파서를 쓴다.** 문자열만 급히 확인할 때는 `strings -el`로 UTF-16LE 문자열을 뽑아 교차확인한다.

### 6단계 — SID 완성

로컬 계정의 SID는 다음과 같이 조립된다.

```text
S-1-5-21-<머신 SID 3개 서브오소리티>-<RID>

예: 머신 SID  S-1-5-21-3419281148-2201972856-1043271217
    RID 1001
    -> S-1-5-21-3419281148-2201972856-1043271217-1001
```

머신 SID는 `SAM\Domains\Account`의 `V` 값 안에 들어 있고, `SECURITY\Policy\PolAcDmS`에도 계정 도메인 SID로 남아 있다 ([FOR-0056](./security-hive-overview.html)). 이진 값을 직접 자르는 대신, **`SOFTWARE\...\ProfileList`의 서브키 이름이 이미 완성된 SID**이므로 그것을 그대로 읽는 편이 빠르고 안전하다.

### 7단계 — `ProfileList`와 대조

```powershell
rip.exe -r "C:\case\SOFTWARE" -p profilelist
```

```text
Path : C:\Users\jhkim
SID  : S-1-5-21-3419281148-2201972856-1043271217-1001

Path : C:\Users\svc_backup
SID  : S-1-5-21-3419281148-2201972856-1043271217-1003
```

`SAM`의 RID와 `ProfileList` SID의 마지막 숫자를 맞추면 **계정 ↔ 프로필 폴더**가 확정된다. 이 표를 만들어 두면 이후 모든 사용자별 artifact의 소유자가 정해진다. `ProfileList`의 다른 값은 [FOR-0055](./software-installed-programs.html)에서 다룬다.

| RID | 계정명 (SAM) | SID 끝 | 프로필 폴더 (ProfileList) |
| --- | --- | --- | --- |
| 500 | Administrator | -500 | (프로필 없음 = 로그온한 적 없음) |
| 1001 | jhkim | -1001 | `C:\Users\jhkim` |
| 1003 | svc_backup | -1003 | `C:\Users\svc_backup` |

### 8단계 — 계정 생성 시각 추정

`SAM`에는 "생성 시각" 필드가 명시적으로 없다. 그래서 다음 근거를 조합한다.

| 근거 | 강도 | 설명 |
| --- | --- | --- |
| `Names\<username>` 키의 LastWrite | 강 | 이 키는 계정 생성 때 만들어지고 이후 이름 변경이 없으면 갱신되지 않는다. RegistryExplorer/RegRipper가 이 값을 "Account Created"로 보여준다 |
| `Users\<RID>` 키의 LastWrite | 약 | 로그온·암호 변경마다 갱신되므로 생성 시각이 아니다 |
| `F`의 Password Last Set | 중 | 계정 생성 시 암호를 정하므로 생성 시각과 대개 같거나 직후 |
| RID 순서 | 중 | 1000 → 1001 → 1002 순서대로 만들어졌다 |
| `C:\Users\<name>` 폴더의 `$MFT` 생성 시각 | 중 | 계정 생성이 아니라 **첫 로그온** 시각 ([FOR-0021](./mft-basics.html)) |
| Security EVTX 4720 | 강 | 계정 생성 이벤트. 감사가 켜져 있었다면 가장 확실하다 |

`F`의 Password Last Set과 `Names` 키 LastWrite가 몇 초 이내로 붙어 있으면 그 시각을 생성 시각으로 결론 낸다.

### 9단계 — 그룹 멤버십

`SAM\Domains\Builtin\Aliases` 아래 키가 로컬 그룹이고, 키 이름은 그룹 RID의 16진수다.

| 키 이름 | RID | 그룹 |
| --- | --- | --- |
| `00000220` | 544 | Administrators |
| `00000221` | 545 | Users |
| `00000222` | 546 | Guests |
| `00000227` | 551 | Backup Operators |
| `0000022B` | 555 | Remote Desktop Users |

`Members` 아래에 멤버의 SID가 들어 있다. **일반 사용자 RID가 `00000220`(Administrators)에 들어 있으면 권한 상승 흔적**이므로 4732(그룹에 멤버 추가) 이벤트와 대조한다.

## 출력 필드 해석

| samparse 출력 필드 | 의미 | 주의 |
| --- | --- | --- |
| `Username [RID]` | 계정명과 RID | RID ≥ 1000 이면 사람이 만든 계정 |
| `Account Created` | `Names` 키 LastWrite 기반 추정치 | 명시적 필드가 아니다. 4720과 교차검증 |
| `Last Login Date` | 마지막 성공 로그온 (UTC) | `Never`면 한 번도 로그온 안 함 |
| `Pwd Reset Date` | 마지막 암호 설정 (UTC) | 계정 생성 시각의 근거로 쓴다 |
| `Pwd Fail Date` | 마지막 로그온 실패 (UTC) | 4625와 대조 |
| `Login Count` | 성공 로그온 누적 횟수 | **네트워크 로그온은 잘 반영되지 않는다.** 0인데 4624가 있는 경우가 있다 |
| `Embedded RID` | `F` 안의 RID | 키 이름과 다르면 hive 손상 또는 조작 |
| `--> ...` 줄 | ACB 플래그 텍스트 | `Password does not expire`, `Account disabled` 확인 |
| `Account Type` | 파서가 플래그로 추정한 분류 | 참고용. 실제 권한은 `Builtin\Aliases`로 확인 |

시각은 전부 FILETIME이라 **UTC**다. 출력 끝의 `Z`가 그 뜻이다. KST 답이 필요하면 +9시간, 변환 상수는 `11644473600`초다 ([FOR-0054](./system-timezone.html)).

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| SID (`...-1001`) | `SOFTWARE\...\ProfileList` | 프로필 폴더 경로 |
| 프로필 폴더 | `C:\Users\<name>\NTUSER.DAT` | 그 사용자의 실행 이력 ([FOR-0061](./userassist.html)) |
| 프로필 폴더 | `...\UsrClass.dat` | ShellBags(방문 폴더) |
| 계정명 / SID | Security EVTX 4624/4625/4720/4732 | 로그온 경로·실패·계정 생성 ([FOR-0083](./event-4624-logon.html)) |
| Last Login 시각 | 그 시각 전후의 EVTX·Prefetch | 로그온 직후 무엇을 실행했나 |
| 프로필 폴더 생성 시각 | `$MFT` ([FOR-0021](./mft-basics.html)) | 첫 로그온 시점, 삭제된 프로필 |
| 감사 이벤트가 아예 없음 | `SECURITY\Policy\PolAdtEv` | 감사 정책이 꺼져 있었나 ([FOR-0056](./security-hive-overview.html)) |

## 흔한 함정

- **RID를 10진수로 읽는 것.** 키 이름 `000003E9`는 3E9번이 아니라 **1001**이다. 16진수 변환을 빼먹고 "RID 3E9 계정"이라고 답하면 오답이다.
- **`Login Count`를 실제 로그온 횟수로 단정하는 것.** 대화형 로그온 위주로 증가하고 네트워크·서비스 로그온은 반영이 일정하지 않다. `Login Count 0`인데 4624가 여러 건 있는 상황이 정상적으로 발생한다. 횟수를 근거로 쓸 때는 반드시 EVTX와 대조한다.
- **`Users\<RID>` 키 LastWrite를 계정 생성 시각으로 쓰는 것.** 로그온·암호 변경마다 갱신된다. 생성 시각은 `Names\<username>` 키 LastWrite와 Password Last Set으로 추정한다.
- **`F`/`V` 값의 오프셋을 기억에 의존해 손으로 세는 것.** 인용되는 오프셋이 문서마다 어긋난다. 파서 출력을 근거로 쓰고, 꼭 필요하면 `F` 안의 RID DWORD로 기준점을 검증한다.
- **`C:\Users` 폴더 이름을 계정명으로 단정하는 것.** 프로필 폴더는 첫 로그온 때 만들어지고 이후 계정 이름을 바꿔도 폴더명은 그대로다. 이름이 충돌하면 `jhkim.DESKTOP-K7P2N9` 같은 접미사가 붙는다. 매핑은 `ProfileList` SID로만 확정한다.
- **`SAM`에 없는 계정을 "존재하지 않았다"로 결론 내리는 것.** 도메인 계정은 `SAM`에 없다(그 SID는 `S-1-5-21-<도메인>`이고 `ProfileList`에만 남는다). 삭제된 로컬 계정도 `SAM`에서 사라지지만 `ProfileList`와 `C:\Users`에는 흔적이 남는다.
- **Administrator가 `Never`라서 관리자 활동이 없다고 보는 것.** 실제 관리 작업은 RID 1000번대 계정이 Administrators 그룹에 들어가 수행하는 경우가 대부분이다. `Builtin\Aliases\00000220\Members`를 본다.
- **시간대 보정 누락.** samparse 출력은 UTC다. 문제가 로컬 시각을 요구하면 `SYSTEM\ControlSet001\Control\TimeZoneInformation`을 먼저 읽는다.
- **트랜잭션 로그 미반영.** 계정 생성/암호 변경이 종료 직전에 일어났다면 그 변경이 `SAM.LOG1`에만 있을 수 있다.

## 교차검증

같은 계정 사실을 최소 두 곳에서 확인한다.

```powershell
# 1) SAM — 계정 목록, RID, 마지막 로그온, 플래그
rip.exe -r SAM -p samparse > sam.txt

# 2) SOFTWARE — SID와 프로필 폴더
rip.exe -r SOFTWARE -p profilelist > profiles.txt

# 3) EVTX — 계정 생성(4720), 그룹 추가(4732), 로그온(4624)
EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv
Import-Csv sec.csv | Where-Object { $_.EventId -in 4720,4726,4732 } |
  Select-Object TimeCreated, EventId, PayloadData1

# 4) 프로필 폴더가 실제로 언제 만들어졌나
Import-Csv mft.csv | Where-Object { $_.ParentPath -eq '.\Users' }
```

| 조합 | 결론 |
| --- | --- |
| `SAM`에 있고 `ProfileList`에도 있다 | 로그온한 적 있는 정상 계정 |
| `SAM`에 있는데 `ProfileList`에 없다 | 만들어졌지만 로그온한 적 없다 |
| `SAM`에 없는데 `ProfileList`에 있다 | 삭제된 계정 또는 도메인 계정 |
| `SAM`에 있는데 4720이 없다 | 감사 정책이 꺼졌거나 로그가 지워졌다(1102) |

## mini walkthrough

```text
문제:
"침해 사고 이미지에서 공격자가 만든 백도어 계정의 이름과 생성 시각(KST)을 구하세요.
 첨부: SAM, SOFTWARE, SYSTEM, Security.evtx"

1. 첫 시도 (실패):
   rip.exe -r SAM -p samparse | Select-String 'Last Login'
   -> Last Login 이 가장 최근인 계정은 jhkim (2026-03-14 07:11:38Z).
      "jhkim이 백도어"라고 결론 냈다.

   왜 틀렸나:
   jhkim 은 RID 1001, ProfileList 에 C:\Users\jhkim 이 있고
   프로필 폴더 생성이 2026-03-10 이다. 사고(3/14) 전부터 쓰던 정상 계정이다.
   "마지막 로그온이 최근"은 백도어의 근거가 아니다.

2. 피벗: RID 순서와 플래그로 다시 본다
   rip.exe -r SAM -p samparse > sam.txt

     Username : Administrator [500]   Last Login : Never
     Username : Guest [501]           --> Account disabled
     Username : DefaultAccount [503]  --> Account disabled
     Username : jhkim [1001]          Login Count : 14
     Username : svc_helpdesk [1004]   Login Count : 1
       Account Created : 2026-03-14 06:58:12Z
       Pwd Reset Date  : 2026-03-14 06:58:12Z
       --> Password does not expire
       --> Normal user account

   RID 1004 = 가장 나중에 만들어진 계정.
   생성 시각이 사고 시각대(3/14 07시)와 붙어 있고
   "Password does not expire" 가 붙어 있다. 이름은 서비스 계정을 흉내낸 것.

3. 두 번째 확인 — 권한 상승 여부
   RegistryExplorer 로 SAM\Domains\Builtin\Aliases\00000220\Members
   -> RID 500, 1001 외에 1004 의 SID 가 들어 있다 = Administrators 소속

4. SID 완성
   rip.exe -r SOFTWARE -p profilelist
   -> C:\Users\svc_helpdesk
      S-1-5-21-3419281148-2201972856-1043271217-1004

5. EVTX 교차검증
   4720 (계정 생성)  2026-03-14 06:58:12Z  TargetUserName=svc_helpdesk
   4732 (그룹 추가)  2026-03-14 06:58:20Z  Administrators
   -> SAM 의 추정 생성 시각과 초 단위로 일치

6. 시간대 보정
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time  (Bias -540)
   2026-03-14 06:58:12 UTC + 9h = 2026-03-14 15:58:12 KST

정답: svc_helpdesk / 2026-03-14 15:58:12 KST
```

## 막혔을 때 다음 체크

1. **RID를 16진수에서 10진수로 바꿨는가** — `000003E9` = 1001
2. **RID가 가장 큰 계정을 봤는가** — 가장 최근에 만들어진 계정이다
3. **ACB 플래그를 읽었는가** — `Password not required`, `Password does not expire`, `Account disabled`
4. `Names` 서브키 LastWrite로 생성 시각을 추정했는가
5. `ProfileList`로 SID ↔ 폴더 표를 만들었는가
6. `Builtin\Aliases\00000220`(Administrators) 멤버를 확인했는가
7. `SAM`은 dirty가 아닌가 — `rla`로 `.LOG1`/`.LOG2` 반영
8. 계정이 `SAM`에 없다면 → 도메인 계정 또는 삭제 계정. `ProfileList`와 `C:\Users`, EVTX 4726(삭제)으로 이동
9. 시각을 UTC로 답하고 있지 않은가 — 문제가 KST를 요구하는지 확인
10. 해시가 필요한 문제인가 → 이 글의 범위가 아니다. 계정 메타데이터만으로 답이 되는지 다시 읽는다

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SAM` hive가 `HKLM\SAM`으로 마운트되고 파일이 `System32\config`에 있다는 점
- SRC-019 — Microsoft Learn, Well-known SIDs / Security Identifiers: RID 500·501·503의 의미, 일반 사용자 RID가 1000부터 시작, 로컬 그룹 RID 544·545·546·551·555, `S-1-5-21-<머신>-<RID>` 조립 규칙, ACB 계정 플래그 비트값
- SRC-004 — Eric Zimmerman 문서: RegistryExplorer의 SAM 플러그인이 `F`/`V` 값을 표로 디코딩하는 점, `rla`로 트랜잭션 로그 반영
- `F`/`V` 값의 개별 바이트 오프셋은 공개 문서 간 인용이 어긋나므로 이 글에서는 항목만 나열했다. 오프셋이 필요하면 파서 출력과 대조해 실제 파일에서 확인할 것
- RegRipper 플러그인 이름과 출력 필드 표기는 버전에 따라 다를 수 있으므로 `rip.exe -l`로 목록을 확인할 것
