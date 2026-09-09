---
id: FOR-0056
title: "SECURITY hive 개요: 감사 정책·도메인 SID·LSA Secrets"
slug: "security-hive-overview"
category: "Registry"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["SECURITY hive", "PolAdtEv", "PolAcDmS", "PolPrDmN", "LSA Secrets", "Cache", "NL$"]
file_paths: ["C:\\Windows\\System32\\config\\SECURITY", "C:\\Windows\\System32\\GroupPolicy\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv"]
registry_paths: ["SECURITY\\Policy", "SECURITY\\Policy\\PolAdtEv", "SECURITY\\Policy\\PolAcDmN", "SECURITY\\Policy\\PolAcDmS", "SECURITY\\Policy\\PolPrDmN", "SECURITY\\Policy\\PolPrDmS", "SECURITY\\Policy\\Secrets", "SECURITY\\Cache", "SECURITY\\SAM"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r SECURITY -p auditpol", "rip.exe -r SECURITY -p polacdms", "reg save HKLM\\SECURITY C:\\out\\SECURITY"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["PolAdtEv", "PolAcDmN", "PolAcDmS", "PolPrDmN", "PolPrDmS", "CurrVal", "CupdTime", "OupdTime"]
file_formats: ["regf"]
primary_terms: ["SECURITY hive", "LSA Secrets", "PolAdtEv"]
keywords: ["SECURITY hive", "감사 정책", "PolAdtEv", "LSA Secrets", "PolAcDmS", "PolPrDmN", "머신 SID", "도메인 가입", "캐시 자격증명", "NL$", "$MACHINE.ACC", "audit policy"]
aliases: ["security hive", "감사 정책 확인", "audit policy 레지스트리", "lsa secrets", "머신 sid", "도메인 가입 여부", "4624가 없다"]
symptom_keywords: ["로그온 이벤트가 하나도 없다", "감사가 켜져 있었는지 알고 싶다", "도메인에 가입돼 있었나", "머신 SID를 알고 싶다", "SECURITY hive를 못 읽는다", "서비스 계정 자격증명이 어디 있나"]
related: ["FOR-0051", "FOR-0052", "FOR-0083"]
source_ids: ["SRC-017", "SRC-019", "SRC-004"]
last_verified: "2026-09-10"
status: "draft"
---

## 한 줄 결론

`SECURITY` hive는 LSA 정책 데이터베이스이며, **감사 정책(`Policy\PolAdtEv`)·계정/도메인 이름과 SID(`Policy\PolAcDmN`·`PolAcDmS`·`PolPrDmN`·`PolPrDmS`)·암호화된 LSA Secrets(`Policy\Secrets`)·도메인 캐시 자격증명(`Cache`)** 을 담고 있어서 "왜 로그온 이벤트가 없는가", "이 PC가 도메인에 가입돼 있었는가", "머신 SID가 무엇인가"에 답한다.

## 개념

`SECURITY`는 `HKLM\SECURITY`로 마운트되는 LSA(Local Security Authority)의 정책 저장소다. 다른 hive와 성격이 다른 두 가지 특징이 있다.

- **접근 권한이 `SYSTEM`으로 제한된다.** 관리자로 로그온해도 `regedit`에서 내용이 보이지 않는다. 라이브에서 보려면 백업 권한을 쓰는 `reg save`나 `SYSTEM` 토큰(PsExec 계열의 `-s`)이 필요하다. **오프라인 hive 파일을 꺼내 보는 것이 정석이다.**
- **값 대부분이 암호화된 이진 데이터다.** LSA Secrets와 캐시 자격증명은 부트키(`SYSTEM\ControlSet001\Control\Lsa`의 클래스 이름들로 조립)로 파생된 키로 암호화되어 있다. **이 글은 복호화를 다루지 않는다. "무엇이 들어 있고 어떤 결론에 쓰는가"만 다룬다.**

암호화되지 않은 채로 바로 결론에 쓸 수 있는 것은 **키의 존재 여부, 서브키 이름, 키 LastWrite 시각**이다. 이 세 가지만으로도 도메인 가입·서비스 계정 구성·자격증명 캐시 사용 여부가 드러난다.

파일 크기가 다른 hive보다 훨씬 작아서(수십 KB 수준) 트리 전체를 눈으로 훑을 수 있다.

## 파일 / 경로

| 항목 | 경로 |
| --- | --- |
| hive 파일 | `C:\Windows\System32\config\SECURITY` |
| 트랜잭션 로그 | `C:\Windows\System32\config\SECURITY.LOG1`, `SECURITY.LOG2` |
| 마운트 위치 | `HKLM\SECURITY` |
| 고급 감사 정책 GPO 원본 | `C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv` |

추출은 다른 hive와 같다 — FTK Imager로 `config` 폴더 Export, KAPE의 레지스트리 타깃, 또는 라이브에서 `reg save`. 로그 반영(`rla`)과 dirty 판정은 [FOR-0051](./registry-hive-map.html)을 따른다.

```powershell
# 라이브: 관리자 + 백업 권한으로 저장. regedit 로는 내용이 보이지 않는다
reg save HKLM\SECURITY C:\out\SECURITY
```

### 트리 구조

```text
SECURITY
├── Policy
│   ├── PolAdtEv          <- 감사 정책 (이진)
│   ├── PolAcDmN          <- 계정 도메인 이름 (= 로컬 SAM 도메인, 보통 컴퓨터 이름)
│   ├── PolAcDmS          <- 계정 도메인 SID (= 머신 SID)
│   ├── PolPrDmN          <- 주 도메인 이름 (가입한 도메인 / 미가입이면 워크그룹)
│   ├── PolPrDmS          <- 주 도메인 SID (도메인 미가입이면 비어 있다)
│   ├── PolEKList         <- LSA 암호화 키 (Vista 이후). 복호화용, 여기서는 다루지 않음
│   ├── Secrets           <- LSA Secrets
│   │   ├── $MACHINE.ACC
│   │   ├── DefaultPassword
│   │   ├── NL$KM
│   │   ├── DPAPI_SYSTEM
│   │   └── _SC_<서비스명>
│   └── (그 외 Pol* 키들)
├── Cache                 <- 도메인 캐시 자격증명 (NL$1 ~ NL$n)
└── SAM                   <- HKLM\SAM 으로 가는 링크
```

**서브키 이름과 배치는 Windows 버전에 따라 다르고 일부는 값이 아니라 키 형태로 존재한다. 위 구조는 방향을 잡는 지도로 쓰고, 실제 이름은 RegistryExplorer 트리나 RegRipper 출력으로 확인한다.**

## 주요 필드

### `Policy\PolAdtEv` — 감사 정책

시스템이 어떤 종류의 보안 이벤트를 기록하도록 설정되어 있었는지가 이진 데이터로 들어 있다.

| 이 값으로 답하는 질문 | 결론 |
| --- | --- |
| "Security.evtx에 4624가 하나도 없다" | 로그온 감사가 꺼져 있었다면 **정상이다.** 로그 삭제를 의심하기 전에 이 값을 본다 |
| "4688(프로세스 생성)이 없다" | 프로세스 추적 감사는 기본으로 꺼져 있다. 없는 것이 정상 |
| "성공은 있는데 실패(4625)가 없다" | 성공만 감사하도록 설정된 경우 |
| "감사 정책이 언제 바뀌었나" | `PolAdtEv` **키의 LastWrite** 시각 + Security EVTX 4719 |

**`PolAdtEv` 이진 데이터의 바이트 배치는 Windows 버전마다 다르고 공개 문서 간 인용이 일치하지 않는다. 손으로 비트를 세지 말고 `rip.exe -p auditpol` 출력이나 `audit.csv`를 근거로 쓴다.** Vista 이후의 고급 감사 정책(하위 범주 단위)은 GPO의 `audit.csv`와 LSA 정책에 함께 반영되므로 두 곳을 대조한다.

감사 관련 이벤트 대응표:

| Event ID | 의미 | 어떻게 쓰나 |
| --- | --- | --- |
| 4719 | 시스템 감사 정책이 변경됨 | 정책 변경 시각과 변경자 확정 |
| 1102 | 감사 로그가 지워짐 | 이벤트가 "없는" 다른 이유 |
| 4624 / 4625 | 로그온 성공 / 실패 | 이 감사 범주가 켜져 있어야 남는다 ([FOR-0083](./event-4624-logon.html)) |

### `Policy\PolAcDmN` / `PolAcDmS` / `PolPrDmN` / `PolPrDmS`

| 키 | 담고 있는 것 | 포렌식 결론 |
| --- | --- | --- |
| `PolAcDmN` | **계정 도메인 이름** — 로컬 SAM의 도메인 이름. 워크그룹 PC면 컴퓨터 이름과 같다 | 컴퓨터 이름 교차검증 |
| `PolAcDmS` | **계정 도메인 SID** = **머신 SID** (`S-1-5-21-x-y-z`) | 로컬 계정 SID 조립의 앞부분. `SAM`/`ProfileList`와 일치해야 한다 |
| `PolPrDmN` | **주 도메인 이름** — 가입한 AD 도메인 이름. 미가입이면 워크그룹 이름이거나 비어 있다 | **도메인 가입 여부 판정** |
| `PolPrDmS` | **주 도메인 SID** | 도메인 SID. 미가입이면 비어 있다 |

판정 규칙:

| 관찰 | 결론 |
| --- | --- |
| `PolPrDmN`이 비었거나 `WORKGROUP` | 도메인 미가입 독립 PC |
| `PolPrDmN`에 도메인 이름이 있고 `PolPrDmS`에 SID가 있다 | **AD 도메인 가입** |
| `Secrets\$MACHINE.ACC`가 존재한다 | 컴퓨터 계정 암호가 저장되어 있다 = 도메인 가입의 강한 증거 |
| `Cache`에 `NL$` 항목이 있다 | 도메인 계정이 이 PC에서 로컬 로그온한 적 있다 |
| `PolAcDmS`와 `ProfileList` SID 앞부분이 다르다 | 다른 PC의 hive가 섞여 있다 |

머신 SID는 `SAM\Domains\Account`의 `V` 값에도 들어 있다 ([FOR-0052](./sam-user-accounts.html)). 두 곳이 일치하는지 확인하면 hive 묶음이 같은 PC의 것임을 검증할 수 있다.

### `Policy\Secrets` — LSA Secrets

서비스 계정 암호, 컴퓨터 계정 암호, 자동 로그온 암호 등이 **암호화되어** 저장된다. 각 시크릿은 서브키로, 그 아래 다시 값/키가 나뉜다.

| 서브키 / 값 | 의미 |
| --- | --- |
| `CurrVal` | 현재 시크릿 (암호화) |
| `OldVal` | 이전 시크릿 (암호화) |
| `CupdTime` | `CurrVal`이 갱신된 시각 (FILETIME, UTC) |
| `OupdTime` | `OldVal`이 갱신된 시각 (FILETIME, UTC) |

자주 보이는 시크릿 이름과 그것이 알려주는 사실:

| 시크릿 이름 | 무엇을 뜻하나 |
| --- | --- |
| `$MACHINE.ACC` | 컴퓨터 계정 암호 → **도메인에 가입되어 있다** |
| `DefaultPassword` | 자동 로그온(autologon)용 암호 → **자동 로그온이 구성되어 있었다** |
| `NL$KM` | 도메인 캐시 자격증명 암호화 키 → `Cache` 항목과 짝 |
| `DPAPI_SYSTEM` | 머신 단위 DPAPI 마스터키 재료 |
| `_SC_<서비스명>` | 그 서비스가 **특정 사용자 계정으로 실행되도록 구성**되어 있다 |
| `L$...` / `aspnet_WP_PASSWORD` 등 | 애플리케이션이 저장한 시크릿 |

**복호화는 이 글의 범위가 아니다.** 그러나 복호화 없이도 다음 결론이 나온다.

```text
- 이름 목록만으로: 도메인 가입 / 자동 로그온 구성 / 어떤 서비스가 사용자 계정으로 도는지
- CupdTime 만으로: 컴퓨터 계정 암호가 마지막으로 갱신된 시각 (도메인 통신이 살아 있던 시점)
- _SC_ 목록과 SYSTEM\...\Services\<name>\ObjectName 대조: 서비스 실행 계정 확정
```

`DefaultPassword`가 존재하면 `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`의 `AutoAdminLogon`, `DefaultUserName`을 함께 확인한다.

### `Cache` — 도메인 캐시 자격증명

| 항목 | 의미 |
| --- | --- |
| `NL$1` ~ `NL$n` | 로컬에 캐시된 도메인 로그온 자격증명 슬롯 (암호화) |
| 항목 개수 | 도메인 계정이 이 PC에서 몇 명(몇 슬롯) 로그온했는지의 상한 |
| 캐시 개수 설정 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`의 `CachedLogonsCount` |

**`Cache`에 항목이 있으면 도메인 계정이 이 PC에 로컬 로그온한 적이 있다는 뜻이다.** DC와 연결이 끊긴 상태에서도 로그온할 수 있게 하는 기능이므로, 노트북 등 오프라인 로그온 이력의 근거가 된다. 슬롯 내부의 사용자 이름·도메인은 복호화 없이는 확정할 수 없다.

### `SAM` 링크

`SECURITY\SAM`은 `HKLM\SAM`으로 가는 링크다. 오프라인 hive에서는 링크 대상이 없으므로 비어 보이거나 링크 키만 존재한다. **`SECURITY` 파일 안에 계정 정보가 들어 있는 것이 아니다.** 계정은 `SAM` 파일에서 본다.

## 빠른 명령

```powershell
rip.exe -r "C:\case\SECURITY" -p auditpol
```

```text
auditpol
Policy\PolAdtEv
LastWrite Time 2026-03-14 06:52:31Z

Auditing is enabled.
  Audit System Events              N
  Audit Logon Events               N
  Audit Object Access              N
  Audit Privilege Use              N
  Audit Process Tracking           N
  Audit Policy Change              S/F
  Audit Account Management         S/F
  Audit Directory Service Access   N
  Audit Account Logon Events       N
```

`Audit Logon Events`가 `N`(없음)이면 **4624/4625가 남지 않는 것이 정상이다.** 로그 삭제를 주장할 근거가 사라진다.

```powershell
# 도메인/머신 SID
rip.exe -r "C:\case\SECURITY" -p polacdms

# SECURITY hive 전체를 적용 가능한 플러그인으로 일괄 덤프
rip.exe -r "C:\case\SECURITY" -a > security_all.txt

# 사용 가능한 플러그인 목록 확인 (이름이 버전마다 다르다)
rip.exe -l
```

```text
polacdms
Policy\PolAcDmN
LastWrite Time 2026-03-10 04:19:41Z
  Machine SID : S-1-5-21-3419281148-2201972856-1043271217
  Machine Name: DESKTOP-K7P2N9

Policy\PolPrDmN
  Primary Domain Name: (empty)
```

GUI로는 RegistryExplorer에서 `SECURITY`를 열고 `Policy` 아래 서브키 **이름 목록**과 각 키의 LastWrite를 먼저 훑는다. 이진 값 자체는 대부분 암호화되어 있으므로 이름과 시각이 실질적인 산출물이다.

## 함께 보는 artifact

| 이 hive에서 얻은 것 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 감사 정책이 꺼져 있다 | Security EVTX | 이벤트 부재가 정상인지 확정 ([FOR-0083](./event-4624-logon.html)) |
| `PolAdtEv` LastWrite | Security EVTX 4719, 1102 | 정책이 언제/누가 바꿨나, 로그가 지워졌나 |
| 머신 SID (`PolAcDmS`) | `SAM`, `SOFTWARE\...\ProfileList` | 로컬 계정 SID 조립 및 hive 묶음 검증 ([FOR-0052](./sam-user-accounts.html)) |
| `PolPrDmN`에 도메인 이름 | EVTX 4624의 `TargetDomainName` | 도메인 계정 로그온 여부 |
| `Cache`에 `NL$` 존재 | EVTX 4624 Logon Type 2/11 | 캐시 자격증명 로그온(Type 11) 흔적 |
| `Secrets\_SC_<서비스>` | `SYSTEM\ControlSet001\Services\<서비스>` | `ObjectName`(실행 계정), `ImagePath` |
| `Secrets\DefaultPassword` | `SOFTWARE\...\Winlogon` | `AutoAdminLogon`, `DefaultUserName` |
| `Secrets\$MACHINE.ACC`의 `CupdTime` | System EVTX, 네트워크 설정 | 도메인 통신이 살아 있던 시점 |
| hive 목록 전체 | [FOR-0051](./registry-hive-map.html) | 다른 hive로의 분기 |

## 흔한 실수

- **라이브 `regedit`으로 `HKLM\SECURITY`를 열어 "비어 있다"고 결론 내리는 것.** ACL이 `SYSTEM`으로 제한되어 관리자에게도 하위 키가 보이지 않는다. 오프라인 hive 파일이나 `reg save`로 확보한 사본을 본다.
- **Security 이벤트가 없으면 곧바로 로그 삭제로 단정하는 것.** 감사 정책이 꺼져 있었을 가능성을 `PolAdtEv`로 먼저 배제한다. 특히 4688(프로세스 추적)은 기본이 꺼짐이라 없는 것이 정상이다.
- **`PolAdtEv` 이진 데이터를 손으로 비트 단위로 해석하는 것.** 배치가 버전마다 다르고 인용 문서가 서로 어긋난다. 파서 출력과 `audit.csv`를 근거로 쓴다.
- **`PolAcDmS`(계정 도메인 SID)와 `PolPrDmS`(주 도메인 SID)를 혼동하는 것.** 앞은 머신 SID, 뒤는 가입한 도메인의 SID다. 워크그룹 PC는 `PolPrDmS`가 비어 있다.
- **`SECURITY\SAM`에서 계정 정보를 찾으려는 것.** 링크일 뿐이다. 계정은 `SAM` 파일에서 본다.
- **`Cache`에 항목이 있으니 그 사용자 이름을 알 수 있다고 생각하는 것.** 슬롯 내부는 암호화되어 있다. 복호화 없이 확정할 수 있는 것은 "도메인 계정 로컬 로그온이 있었다"는 사실과 슬롯 개수까지다.
- **`Secrets`의 `CupdTime`을 로컬 시각으로 읽는 것.** FILETIME이므로 UTC다. KST는 +9시간, Unix 차이는 `11644473600`초 ([FOR-0054](./system-timezone.html)).
- **트랜잭션 로그를 반영하지 않는 것.** 감사 정책 변경이 종료 직전에 있었다면 그 변경이 `SECURITY.LOG1`에만 있다. `rla`를 먼저 돌린다.
- **`SECURITY`만으로 도메인 가입을 부정하는 것.** `PolPrDmN`이 비어 보이더라도 `$MACHINE.ACC`의 존재, `Cache` 항목, `SYSTEM\...\Services\Tcpip\Parameters`의 `Domain` 값을 함께 본다.
- **복호화에 시간을 쓰는 것.** CTF에서 `SECURITY` hive가 주어질 때 요구되는 답은 대개 "감사가 꺼져 있었다", "도메인에 가입돼 있었다", "머신 SID는 무엇이다" 수준이다. 이름·존재·시각으로 답이 나오는지 먼저 확인한다.

## mini example

```text
문제:
"침해 사고 조사 중입니다. Security.evtx 에 로그온 이벤트가 전혀 없습니다.
 공격자가 로그를 지운 것인지 판단하고, 근거를 제시하세요.
 첨부: SECURITY, SYSTEM, SOFTWARE, Security.evtx"

1. 첫 시도 (실패):
   EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv
   Import-Csv sec.csv | Group-Object EventId | Sort-Object Count -Descending
   -> 4624/4625 가 0건. 1102(로그 삭제)도 0건.
      "1102 가 없으니 로그를 지운 게 아니라 EVTX 파일이 교체됐다"고 추정하고
      $MFT 에서 Security.evtx 의 생성 시각을 파는 데 시간을 썼다.

   왜 틀렸나:
   "이벤트가 없다"의 원인을 삭제/교체에서만 찾았다.
   애초에 기록되지 않았을 가능성 — 감사 정책 자체가 꺼져 있는 경우 —
   를 확인하지 않았다. 이건 SECURITY hive 로 5초에 배제할 수 있었다.

2. 피벗: 감사 정책을 먼저 본다
   rip.exe -r SECURITY -p auditpol

     Policy\PolAdtEv
     LastWrite Time 2026-03-14 06:52:31Z
       Audit Logon Events        N
       Audit Account Logon Events N
       Audit Policy Change       S/F
       Audit Account Management  S/F

   -> 로그온 감사가 N(비활성). 4624/4625 가 없는 것이 정상이다.

3. 그런데 LastWrite 가 사고 시각대(3/14 06:52)다
   원래 꺼져 있었던 게 아니라 사고 당일에 꺼진 것일 수 있다.
   Audit Policy Change 는 S/F 로 켜져 있으므로 4719 가 남아 있어야 한다.

   Import-Csv sec.csv | Where-Object { $_.EventId -eq 4719 }
   -> 2026-03-14 06:52:31Z  4719  Audit Policy Change
      SubcategoryGuid: Logon  Changes: Success removed, Failure removed
      SubjectUserName: svc_helpdesk

   PolAdtEv 의 LastWrite 와 4719 의 시각이 초 단위로 일치.

4. 두 번째로 틀릴 수 있었던 판단:
   "svc_helpdesk 가 도메인 계정이다"라고 가정하려 했다.
   rip.exe -r SECURITY -p polacdms
     Machine SID        : S-1-5-21-3419281148-2201972856-1043271217
     Primary Domain Name: (empty)
   SECURITY\Policy\Secrets 에 $MACHINE.ACC 없음, SECURITY\Cache 비어 있음
   -> 도메인 미가입 독립 PC. svc_helpdesk 는 로컬 계정이다.
      SAM 에서 RID 1004 로 확인된다.

5. 결론 구성
   - 로그온 이벤트 부재의 직접 원인: 감사 정책에서 로그온 감사 제거
   - 그 변경 시각: 2026-03-14 06:52:31 UTC = 15:52:31 KST
   - 변경 주체: 로컬 계정 svc_helpdesk (RID 1004)
   - 로그 삭제(1102)는 없었다 -> "지운 것"이 아니라 "끈 것"

정답: 로그 삭제가 아니라 감사 정책 비활성화.
      2026-03-14 15:52:31 KST 에 로컬 계정 svc_helpdesk 가
      로그온 감사(성공/실패)를 제거했다. 근거는 SECURITY\Policy\PolAdtEv
      (Audit Logon Events = N, LastWrite 06:52:31Z)와 Security EVTX 4719.
```

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SECURITY` hive가 `HKLM\SECURITY`로 마운트되고 파일이 `System32\config`에 있다는 점, hive 접근 권한이 제한된다는 점
- SRC-019 — Microsoft Learn, Well-known SIDs / Security Identifiers: `S-1-5-21-x-y-z` 머신 SID 구조, 계정 도메인 SID와 도메인 SID의 구분
- SRC-004 — Eric Zimmerman 문서: RegistryExplorer로 오프라인 `SECURITY` hive 열기, `rla`로 트랜잭션 로그 반영
- **`status: draft` 이유** — `Policy\PolAdtEv`의 이진 배치, `Policy\Secrets`/`Cache` 하위 구조와 시크릿 이름 목록, `PolEKList`의 존재 여부는 Windows 버전에 따라 다르고 접근 가능한 1차 문서로 전체를 확정하지 못했다. 이 글의 서브키 이름과 배치는 **방향을 잡는 지도**로만 쓰고, 실제 값은 `rip.exe -r SECURITY -a`와 RegistryExplorer 트리로 확인할 것
- RegRipper 플러그인 이름(`auditpol`, `polacdms`)과 출력 형식은 버전에 따라 다르므로 `rip.exe -l`로 확인할 것
- 고급 감사 정책(하위 범주 단위) 설정은 `audit.csv`와 라이브의 `auditpol /get /category:*` 출력으로 교차확인할 것
