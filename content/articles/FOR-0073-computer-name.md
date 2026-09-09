---
id: FOR-0073
title: "컴퓨터 이름(호스트명) 찾기: ComputerName vs ActiveComputerName"
slug: "computer-name"
category: "Registry"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["ComputerName", "ActiveComputerName", "Hostname", "NV Hostname", "Domain", "NV Domain", "SYSTEM hive"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\INF\\setupapi.dev.log", "C:\\Windows\\Panther\\unattend.xml", "C:\\Windows\\System32\\Tasks"]
registry_paths: ["SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName", "SYSTEM\\ControlSet001\\Control\\ComputerName\\ActiveComputerName", "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters", "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SECURITY\\Policy\\PolPrDmN"]
event_ids: ["6011"]
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "FTK Imager", "EvtxECmd", "KAPE"]
commands: ["rip.exe -r SYSTEM -p compname", "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\"", "rip.exe -r SYSTEM -p ips"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["ComputerName", "ActiveComputerName", "Hostname", "NV Hostname", "Domain", "NV Domain", "DhcpDomain", "Computer", "WorkstationName"]
file_formats: ["regf"]
primary_terms: ["컴퓨터 이름", "ComputerName", "호스트명 찾기"]
keywords: ["ComputerName", "ActiveComputerName", "호스트명", "hostname", "NetBIOS 이름", "NV Hostname", "Domain", "SYSTEM hive", "이미지 식별", "컴퓨터 이름 변경", "도메인 가입", "6011"]
aliases: ["컴퓨터 이름", "호스트명", "pc 이름 찾기", "hostname 어디", "이 이미지 누구 pc", "netbios 이름", "컴퓨터 이름 바뀐 흔적"]
symptom_keywords: ["이 이미지가 어느 PC인지 모르겠다", "컴퓨터 이름을 구해야 한다", "호스트명이 어디 있는지", "이름이 두 개로 나온다", "이미지가 여러 개라 헷갈린다", "도메인 가입 여부를 알고 싶다"]
related: ["FOR-0053", "FOR-0051", "FOR-0074", "FOR-0056"]
source_ids: ["SRC-017", "SRC-094", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

컴퓨터 이름의 정답은 `SYSTEM` hive의 `ControlSet001\Control\ComputerName\ComputerName` 값이고, 같은 부모 아래 `ActiveComputerName`이 **다른 값으로 함께 존재하면 이름이 변경된 뒤 재부팅 전이라는 신호**이므로 두 키를 항상 같이 읽는다.

## 어떤 문제에서 필요한가

- "이 이미지의 컴퓨터 이름을 구하시오" — 단답 문제로 자주 나온다
- 첨부 이미지·hive·EVTX가 여러 개인데 **어느 것이 같은 PC의 것인지** 짝을 맞춰야 한다
- EVTX의 `Computer` 필드와 hive의 이름이 다르다
- 4624의 `WorkstationName`이 이 PC인지 접속해 온 상대 PC인지 판정해야 한다
- 도메인 환경인지 워크그룹인지 먼저 확정해야 SID·계정 해석이 갈린다 ([FOR-0074](./sid-user-mapping.html))

## 문제에서 처음 볼 단서

1. 첨부에 `SYSTEM` hive가 있다 → 30초 안에 답이 나온다
2. `SYSTEM`이 없고 EVTX만 있다 → 모든 이벤트의 `System\Computer` 요소가 대안
3. 이미지가 2개 이상이다 → 이름 확보가 **가장 먼저 할 일**이다
4. 지문에 "감염 PC", "관리자 PC", "피의자 PC"처럼 여러 대가 등장한다
5. 답이 FQDN(`PC01.corp.local`)인지 NetBIOS 이름(`PC01`)인지 지문을 다시 읽는다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -p compname
```

RegistryExplorer로 열 때의 경로다. **`CurrentControlSet`이 아니라 실제 `ControlSet001`로 들어간다** ([FOR-0053](./system-controlset.html)).

```text
SYSTEM\ControlSet001\Control\ComputerName\ComputerName
  ComputerName = DESKTOP-K7P2N9      <- 이것이 답
```

라이브 시스템이라면 이렇게 본다.

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
```

## 상세 절차

### 1단계 — 활성 ControlSet을 먼저 정한다

오프라인 `SYSTEM` hive에는 `CurrentControlSet`이 없다. `Select` 키의 `Current` 값이 활성 세트 번호다.

```text
SYSTEM\Select
  Current       = 1     -> ControlSet001 이 활성
  Default       = 1
  Failed        = 0
  LastKnownGood = 1
```

`ControlSet001`과 `ControlSet002`가 모두 있으면 **둘 다 읽고 이름이 같은지 비교한다.** 다르면 그 사이에 이름이 바뀌었다는 강한 단서다.

### 2단계 — 두 키의 차이

`Control\ComputerName` 아래에는 서브키가 두 개 있고, 둘 다 `ComputerName`이라는 **같은 이름의 값**을 가진다. 경로 끝이 세 번 반복되는 형태가 정상이다.

| 키 | 값 | 의미 |
| --- | --- | --- |
| `Control\ComputerName\ComputerName` | `ComputerName` | **영구 값.** 이름 변경 시 즉시 갱신되고, 다음 부팅에서 실제로 적용될 이름 |
| `Control\ComputerName\ActiveComputerName` | `ComputerName` | **현재 적용 중인 이름.** 부팅 시 설정되며 재부팅까지 바뀌지 않는다 |

| 관측 | 해석 |
| --- | --- |
| 두 값이 같다 | 정상 상태. 그 값이 답이다 |
| 두 값이 다르다 | **이름을 변경한 뒤 재부팅하지 않은 상태에서 이미지를 떴다.** `ComputerName` = 새 이름, `ActiveComputerName` = 이미지 시점의 이름 |
| `ActiveComputerName` 키가 없다 | 오프라인 hive에서 흔하다. `ComputerName`만으로 답한다 |

`ActiveComputerName`은 실행 중인 시스템에서 채워지는 성격의 키라 **오프라인 hive에는 없거나 마지막으로 기록된 값만 남아 있을 수 있다.** 있으면 비교하고, 없으면 없다고 적는다 — 지어내지 않는다.

### 3단계 — TCP/IP 쪽 이름과 도메인

호스트명은 네트워크 스택에도 따로 저장된다. 여기서 **도메인 가입 여부**가 갈린다.

```text
SYSTEM\ControlSet001\Services\Tcpip\Parameters
  Hostname      = desktop-k7p2n9     <- 현재 적용 중인 DNS 호스트명
  NV Hostname   = desktop-k7p2n9     <- 영구 저장된 DNS 호스트명
  Domain        = corp.local         <- 현재 적용 중인 DNS 접미사 (비어 있으면 워크그룹)
  NV Domain     = corp.local         <- 영구 저장된 DNS 접미사
  SearchList    = corp.local         <- DNS 검색 순서
```

| 값 | 의미 | 진단 |
| --- | --- | --- |
| `Hostname` | 적용 중인 DNS 호스트명 | `NV Hostname`과 다르면 변경 후 재부팅 전 |
| `NV Hostname` | 영구(non-volatile) 호스트명 | `Control\ComputerName\ComputerName`과 일치해야 정상 |
| `Domain` / `NV Domain` | DNS 도메인 접미사 | **비어 있으면 워크그룹**, 값이 있으면 도메인 또는 수동 설정 |
| `SearchList` | DNS 검색 도메인 목록 | 사내망 도메인 이름의 단서 |

인터페이스별 DHCP 값은 한 단계 아래에 있고, DHCP로 받은 도메인·IP·서버가 남는다.

```text
SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{인터페이스GUID}
  DhcpIPAddress, DhcpDefaultGateway, DhcpDomain, DhcpNameServer, DhcpServer
  LeaseObtainedTime / LeaseTerminatesTime  (Unix epoch 초, DWORD)
```

`DhcpIPAddress`는 **마지막으로 받은 IP**다. 사건 시각의 IP인지는 리스 시각으로 확인한다. Unix epoch → UTC 변환이며 FILETIME과의 차이는 `11644473600`초다.

도메인 가입 여부는 `SECURITY` hive의 `Policy\PolPrDmN`(주 도메인 이름)로 한 번 더 확인한다 ([FOR-0056](./security-hive-overview.html)).

### 4단계 — 호스트명이 나오는 다른 위치

`SYSTEM` hive가 없을 때, 또는 hive의 값을 교차검증할 때 쓴다.

| 위치 | 필드 / 형태 | 누구의 이름인가 | 주의 |
| --- | --- | --- | --- |
| 모든 EVTX 이벤트 | `<System><Computer>` 요소 | **그 로그를 기록한 PC** | 구성에 따라 FQDN 또는 NetBIOS. 로그 파일 전체에서 유일해야 정상 |
| Security 4624/4625 | `WorkstationName` | **접속해 온 쪽(클라이언트)** | 이 PC의 이름이 아니다. 로컬 로그온에서는 이 PC 이름이 들어가기도 한다 |
| Security 4648 | `TargetServerName` | 접속 대상 서버 | 상대 이름 수집용 |
| LNK 파일 | 분산 링크 추적 블록의 `MachineID` | **그 바로가기를 만든 PC** | 소문자 NetBIOS 이름. USB 안의 LNK로 원본 PC를 특정할 수 있다 |
| LNK 파일 | 볼륨 정보 블록의 볼륨 레이블·시리얼 | 대상 볼륨 | 호스트명이 아니다. 볼륨 식별용 |
| Prefetch(.pf) | 참조 파일 목록의 UNC 경로 | **원격 호스트** | Prefetch 자체는 이 PC의 이름을 담지 않는다 |
| 작업 스케줄러 XML (`System32\Tasks`) | `<Author>`, `<UserId>` | 작업을 만든 계정 (`HOST\user` 형태가 흔하다) | 형식이 환경마다 다르다. 값이 SID일 수도 있다 |
| `C:\Windows\Panther\unattend.xml` | `<ComputerName>` | 설치 시 지정한 이름 | 있으면 최초 이름. 이후 변경 이력과 비교 |
| hive base block (`0x30`) | hive의 원래 파일 경로 | 파일 경로 | 사용자명 확인에 유용, 호스트명은 없다 ([FOR-0051](./registry-hive-map.html)) |
| `C:\Windows\INF\setupapi.dev.log` | 장치 설치 이력 | — | **호스트명이 없는 경우가 많다.** 이름 찾기용이 아니라 USB 최초 연결 시각 대조용으로 쓴다 |

핵심은 두 줄이다. **EVTX의 `Computer`는 "이 PC", 4624의 `WorkstationName`은 "상대 PC"다.** 이 둘을 뒤집으면 사건 관계도가 통째로 반대가 된다 ([FOR-0083](./event-4624-logon.html)).

### 5단계 — 이미지가 여러 개일 때 판정 절차

```text
1. 각 이미지에서 SYSTEM hive 추출 -> ControlSet001\Control\ComputerName\ComputerName
2. 같은 이름이 둘 이상이면 다음으로 구분한다
   a. SOFTWARE\Microsoft\Windows NT\CurrentVersion 의 InstallDate (Unix epoch, UTC)
   b. 같은 키의 ProductName / CurrentBuild / RegisteredOwner
   c. SYSTEM\ControlSet001\Control\IDConfigDB\Hardware Profiles\0001 의 HwProfileGuid
   d. SAM 의 머신 SID (S-1-5-21-A-B-C) — 재설치하면 달라진다
3. EVTX 는 Computer 필드로 hive 와 짝을 맞춘다
4. 짝이 맞지 않는 파일이 남으면 그것이 제3의 PC 것이다
```

머신 SID가 다르면 **다른 설치본**이다. 이름이 같아도 별개 PC로 취급한다. 머신 SID 추출은 [FOR-0074](./sid-user-mapping.html)에 있다.

### 6단계 — 이름이 변경된 흔적 탐지

| 근거 | 어디서 | 무엇이 보이면 변경 |
| --- | --- | --- |
| 두 키 불일치 | `ComputerName` vs `ActiveComputerName` | 값이 다르다 |
| TCP/IP 불일치 | `Hostname` vs `NV Hostname` | 값이 다르다 |
| ControlSet 간 불일치 | `ControlSet001` vs `ControlSet002` | 같은 값이 서로 다르다 |
| System 로그 6011 | System.evtx, 원본 `EventLog` | 이전 이름과 새 이름이 한 이벤트에 함께 기록된다 |
| EVTX `Computer` 값 변화 | 오래된 로그부터 시간순 | 어느 시점부터 이름이 바뀐다 |
| 키 LastWrite | `Control\ComputerName\ComputerName` | 설치 시각보다 훨씬 뒤면 변경 의심 ([FOR-0077](./registry-lastwrite-caveats.html)) |

```powershell
# EVTX 전체에서 Computer 필드의 고유값과 등장 구간을 센다
EvtxECmd.exe -d "C:\case\winevt" --csv "C:\case\out" --csvf evt.csv
Import-Csv "C:\case\out\evt.csv" | Group-Object Computer |
  Select-Object Name, Count | Sort-Object Count -Descending
```

이름이 두 개 이상 나오면 그 경계 시각을 찾는다. 그 시각이 개명 시점이거나, **다른 PC의 로그가 섞여 들어온 시점**이다.

## 출력 필드 해석

RegRipper `compname` 플러그인 출력 예시다.

```text
compname v.20090727
ComputerName    = DESKTOP-K7P2N9
TCP/IP Hostname = desktop-k7p2n9
```

| 항목 | 해석 | 답으로 쓸 때 |
| --- | --- | --- |
| `ComputerName` | NetBIOS 컴퓨터 이름. 최대 15자, 대문자 표기가 일반적 | 단답은 이 값 |
| `TCP/IP Hostname` | DNS 호스트명. 보통 소문자 | FQDN을 요구하면 `Domain`을 붙인다 |
| `Domain`이 있음 | 도메인 가입 또는 DNS 접미사 수동 설정 | `PC01.corp.local` 형태로 답 |
| `Domain`이 비어 있음 | 워크그룹 | NetBIOS 이름만으로 답 |

**대소문자는 근거가 아니다.** NetBIOS 이름은 대문자로 표시되는 것이 관례일 뿐이므로, 답의 대소문자를 지문 형식에 맞춘다.

## pivot: 다음에 볼 artifact

| 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 컴퓨터 이름 | EVTX의 `Computer` 필드 | hive와 로그가 같은 PC인지 |
| 컴퓨터 이름 | 4624 `WorkstationName` | 이 PC에서 나간 로그온과 들어온 로그온 구분 |
| `Domain` / `NV Domain` | `SECURITY\Policy\PolPrDmN`, `PolAcDmS` | 도메인 가입 여부와 도메인 SID |
| 머신 SID | `SOFTWARE\...\ProfileList` | 로컬 계정과 도메인 계정 구분 ([FOR-0074](./sid-user-mapping.html)) |
| `DhcpIPAddress` | PCAP, 방화벽 로그, 웹 서버 로그 | 이 PC의 IP로 네트워크 증거 연결 |
| `InstallDate` | `$MFT`의 `C:\Windows` 생성 시각 | 재설치·이미지 복제 판정 |
| 활성 ControlSet | `Control\TimeZoneInformation` | 이후 모든 시각 보정의 전제 ([FOR-0054](./system-timezone.html)) |

## 흔한 함정

- **`CurrentControlSet` 경로를 오프라인 hive에 그대로 입력하는 것** → 그 키는 부팅 때 만들어지는 링크라 파일에 없다 → `Select\Current`를 읽고 `ControlSet001`로 바꿔 들어간다.
- **`ActiveComputerName`을 무조건 답으로 쓰는 것** → 오프라인 hive에서는 없거나 과거 값일 수 있다 → 기본 답은 `ComputerName`이고, `ActiveComputerName`은 불일치 탐지에만 쓴다.
- **4624의 `WorkstationName`을 이 PC의 이름으로 읽는 것** → 그것은 접속해 온 클라이언트 이름이다 → 이 PC의 이름은 이벤트의 `Computer` 필드다.
- **`Hostname`과 `ComputerName`이 대소문자만 달라 다른 값이라고 판단하는 것** → NetBIOS는 대문자, DNS는 소문자로 표시되는 것이 관례다 → 문자열을 소문자로 정규화해 비교한다.
- **`Domain` 값이 있으면 무조건 도메인 가입이라고 단정하는 것** → DNS 접미사를 수동 설정한 워크그룹 PC도 값이 있다 → `SECURITY\Policy\PolPrDmN`과 4624의 `TargetDomainName`으로 확인한다.
- **FQDN을 요구하는데 NetBIOS 이름만 답하는 것** → 15자 제한 때문에 잘린 이름일 수도 있다 → `NV Hostname` + `NV Domain`을 조합한다.
- **`setupapi.dev.log`에서 호스트명을 찾으려 시간을 버리는 것** → 그 파일은 장치 설치 로그다 → 호스트명은 hive에서 얻고, 그 파일은 USB 최초 연결 시각용으로 쓴다.
- **이미지가 여러 개인데 이름만으로 묶는 것** → 조직에서 이름이 중복되거나 이미지 복제로 같아질 수 있다 → 머신 SID·`InstallDate`·`HwProfileGuid`로 이중 확인한다.
- **`rla`를 건너뛰는 것** → 이름을 방금 바꾼 시나리오에서 최신 값이 `.LOG1`에만 있을 수 있다 → hive와 로그를 같이 꺼내 반영한다.
- **컴퓨터 이름의 LastWrite를 개명 시각으로 단정하는 것** → 키 단위 시각이라 다른 값 변경으로도 갱신된다 → 6011 이벤트나 EVTX `Computer` 값의 변화로 시각을 확정한다.

## 교차검증

```powershell
# 1) hive
rip.exe -r "C:\case\SYSTEM" -p compname
```

```powershell
# 2) 네트워크 쪽 이름과 도메인
rip.exe -r "C:\case\SYSTEM" -p ips
```

```powershell
# 3) EVTX 의 Computer 필드가 hive 와 같은가
Import-Csv "C:\case\out\evt.csv" | Select-Object -Unique Computer
```

```powershell
# 4) 이름 변경 이벤트 (있으면 이전/새 이름이 함께 나온다)
Import-Csv "C:\case\out\evt.csv" | Where-Object { $_.EventId -eq 6011 } |
  Format-Table TimeCreated, Computer, PayloadData1, MapDescription
```

세 곳(hive, TCP/IP, EVTX)이 일치하면 확정이다. 하나만 다르면 그 하나가 다른 PC의 파일이거나 개명 전후의 파일이다.

## mini walkthrough

```text
문제:
"두 대의 PC 에서 수집한 파일이 섞였습니다. 각 hive 와 EVTX 가 어느 PC 의 것인지
 분류하고, 침해가 발생한 PC 의 컴퓨터 이름을 답하시오.
 첨부: SYSTEM_A, SYSTEM_B, SOFTWARE_A, SOFTWARE_B, Security.evtx, System.evtx"

1. 첫 시도 (실패):
   RegistryExplorer 로 SYSTEM_A 를 열고
   SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName 으로 이동
   -> CurrentControlSet 도 없고, ControlSet001 아래에도 ActiveComputerName 이 없다.
      "hive 가 손상됐다"고 판단하고 다른 파일을 뒤졌다.

   왜 틀렸나:
   (1) CurrentControlSet 은 부팅 시 만들어지는 링크로 파일에 없다.
   (2) ActiveComputerName 은 실행 중 채워지는 키라 오프라인 hive 에 없을 수 있다.
   영구 값인 Control\ComputerName\ComputerName 을 봐야 했다.

2. 접근 변경
   SYSTEM_A\Select\Current = 1
   SYSTEM_A\ControlSet001\Control\ComputerName\ComputerName
     ComputerName = FIN-PC02
   SYSTEM_B\ControlSet001\Control\ComputerName\ComputerName
     ComputerName = FIN-PC02          <- 이름이 같다

3. 두 번째로 틀린 판단:
   "이름이 같으니 같은 PC 의 hive 를 두 번 받은 것"이라고 결론 낼 뻔했다.
   -> SOFTWARE_A\Microsoft\Windows NT\CurrentVersion
        InstallDate = 0x6516A3C0 (Unix epoch) -> 2023-09-29 UTC
      SOFTWARE_B 의 InstallDate -> 2025-02-11 UTC
      SAM 의 머신 SID 도 서로 다르다.
      => 이름만 재사용한 별개 설치본. 두 대가 맞다.

4. TCP/IP 로 구분점 확보
   SYSTEM_A\ControlSet001\Services\Tcpip\Parameters
     NV Hostname = fin-pc02,  NV Domain = (없음)        -> 워크그룹
   SYSTEM_B\...\Parameters
     NV Hostname = fin-pc02,  NV Domain = corp.local    -> 도메인 가입
   A 와 B 는 도메인 가입 상태가 다르다.

5. EVTX 짝 맞추기
   Import-Csv evt.csv | Select-Object -Unique Computer
     FIN-PC02
     FIN-PC02.corp.local
   -> FQDN 로 찍힌 로그는 B(도메인 가입) 것, NetBIOS 로 찍힌 로그는 A 것.

6. 세 번째로 틀린 판단:
   Security.evtx 의 4624 WorkstationName = FIN-PC07 을 보고
   "FIN-PC07 도 첨부에 있는 PC"라고 적었다.
   -> WorkstationName 은 접속해 온 클라이언트 이름이다.
      첨부에 없는 제3의 PC 이며, 그 PC 가 원격 로그온의 출발점이다.

7. 시간대 보정
   SYSTEM_B\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time, ActiveTimeBias = -540분
   EVTX 시각은 UTC 로 저장되므로 KST 답은 +9h.

정답:
  침해 PC = FIN-PC02.corp.local (도메인 가입 인스턴스, SYSTEM_B / SOFTWARE_B)
  워크그룹 FIN-PC02 는 이름만 같은 별개 설치본
  침입 출발지 FIN-PC07 은 첨부에 없는 제3의 PC
```

## 막혔을 때 다음 체크

1. `Select\Current`로 활성 ControlSet을 정했는가
2. `Control\ComputerName\ComputerName`(영구 값)을 봤는가 — `ActiveComputerName`만 찾다 실패하지 않았는가
3. `ControlSet001`과 `ControlSet002`의 값이 같은가
4. `Tcpip\Parameters`의 `NV Hostname`/`NV Domain`을 함께 읽었는가
5. `SYSTEM`이 없다면 → EVTX의 `Computer` 필드, LNK의 `MachineID`, 작업 스케줄러 XML로 전환
6. 이미지가 여러 개면 → 머신 SID·`InstallDate`로 별개 설치본인지 확인했는가
7. 4624의 `WorkstationName`을 이 PC 이름으로 오해하지 않았는가
8. 답 형식이 NetBIOS인가 FQDN인가 — 지문을 다시 읽었는가
9. 이름 변경 의심이면 → System 로그 6011, EVTX `Computer` 값의 시간별 변화
10. `rla`로 트랜잭션 로그를 반영했는가

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM` hive가 `HKLM\SYSTEM`으로 마운트된다는 점과 `Control` 하위 구조
- SRC-094 — Microsoft Learn, Windows registry information for advanced users: `Select` 키의 `Current`/`LastKnownGood`으로 활성 ControlSet을 판정하는 근거, control set 개념
- SRC-099 — RegRipper 3.0 저장소: `compname`·`ips` 플러그인이 읽는 키와 출력 형식
- **`ActiveComputerName`의 존재 여부는 hive를 뜬 상태(실행 중/정상 종료)에 따라 달라지므로, 실제 hive에서 키가 있는지 먼저 확인하고 없으면 없다고 기록할 것.** 이 글은 두 값이 모두 있을 때의 해석만 단정한다
- **System 로그 6011(원본 `EventLog`)의 기록 여부는 환경과 이름 변경 방식에 따라 다르므로 실제 로그에서 확인할 것.** 없어도 개명이 없었다는 반증은 아니다
- LNK의 `MachineID`(분산 링크 추적 블록)와 Prefetch의 참조 파일 목록은 각 포맷 문서(SRC-029 liblnk, SRC-030 libscca)에 근거가 있으며, 이 글은 "어디에 호스트명이 나오는가"의 대조표만 제공한다
- 작업 스케줄러 XML의 `<Author>` 형식과 `unattend.xml`의 존재 여부는 환경마다 다르므로 실제 파일에서 확인할 것
- mini walkthrough의 이름·시각·SID는 설명을 위한 예시 값이다
