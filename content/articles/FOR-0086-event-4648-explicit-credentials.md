---
id: FOR-0086
title: "Event ID 4648 명시적 자격증명 로그온: runas와 측면 이동을 한 줄로 잡는다"
slug: "event-4648-explicit-credentials"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4648", "TargetServerName", "TargetInfo", "NewCredentials", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]
registry_paths: []
event_ids: ["4648"]
protocols: ["SMB", "RDP", "NTLM", "Kerberos"]
tools: ["EvtxECmd", "PowerShell", "Timeline Explorer", "Event Viewer", "wevtutil"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --inc 4648 --csv 'C:\\case\\out' --csvf x.csv", "Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4648}", "wevtutil qe Security.evtx /q:\"*[System[(EventID=4648)]]\" /f:text"]
regex_patterns: ["\"TargetServerName\":\"([^\"]+)\"", "\"SubjectUserName\":\"([^\"]+)\""]
wireshark_filters: []
tshark_fields: []
log_fields: ["SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserName", "TargetDomainName", "TargetServerName", "TargetInfo", "ProcessName", "ProcessId", "IpAddress", "IpPort", "TargetLogonGuid"]
file_formats: ["evtx"]
primary_terms: ["4648", "명시적 자격증명", "runas 흔적", "자격증명 도용"]
keywords: ["4648", "명시적 자격증명", "explicit credentials", "runas", "net use", "PsExec", "mstsc /admin", "NewCredentials", "측면 이동", "lateral movement", "TargetServerName", "Security.evtx"]
aliases: ["4648", "runas 기록", "다른 계정으로 접속", "자격증명 도용 흔적", "측면 이동 흔적", "net use 흔적", "psexec 흔적", "누가 어느 서버에 붙었나"]
symptom_keywords: ["다른 계정 자격증명을 썼는지 알고 싶다", "측면 이동 경로를 찾아야 한다", "runas를 썼는지 확인해야 한다", "어느 서버에 접속했는지 알고 싶다", "4648이 너무 많다", "도용된 계정을 찾아야 한다"]
related: ["FOR-0083", "FOR-0087", "FOR-0085", "FOR-0106"]
source_ids: ["SRC-022", "SRC-001", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4648 은 **"A 계정으로 로그인한 사람이 B 계정의 자격증명을 써서 C 서버에 접속했다"를 이벤트 하나로 보여주는 유일한 이벤트**다. `SubjectUserName`(실제 사람) → `TargetUserName`(빌려 쓴 계정) → `TargetServerName`(접속 대상)의 삼각 관계가 그대로 남으므로, 측면 이동 추적에서 4624 보다 정보량이 많다.

## 어떤 문제에서 필요한가

- "공격자가 어느 계정의 자격증명을 훔쳐 어디로 이동했는가"
- "이 사용자가 관리자 계정을 도용했는가" (`runas`, `mstsc /admin`)
- "측면 이동의 출발지 호스트는 어디인가"
- "탈취된 자격증명이 실제로 사용되었는가"
- 4624 Type 3 만으로는 "누가 그 계정을 썼는지"를 알 수 없을 때

4624 는 **대상 호스트**에 "이 계정이 로그온했다"만 남긴다. 4648 은 **출발지 호스트**에 "누가 그 계정을 썼는지"를 남긴다. 두 이벤트를 이어야 사람과 계정이 연결된다.

## 문제에서 처음 볼 단서

1. `SubjectUserName` ≠ `TargetUserName` → **자격증명을 빌려 썼다.** 이 한 줄이 판정선이다
2. `TargetServerName` 이 localhost/자기 호스트명이 아니다 → 원격 접속. 측면 이동 후보
3. `ProcessName` 이 `runas.exe` / `mstsc.exe` / `net.exe` / `powershell.exe` / 낯선 실행 파일
4. `TargetUserName` 이 관리자·서비스 계정인데 `SubjectUserName` 은 일반 사용자 → **권한 상승 시도**
5. 같은 `SubjectLogonId` 로 4648 이 여러 대상에 연속 발생 → 자동화된 이동 스캔
6. 4624 Logon Type 9(NewCredentials)가 같은 시각에 있다 → `runas /netonly` 계열

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --inc 4648 --csv 'C:\case\out' --csvf x.csv
```

삼각 관계 표를 만든다. **`SubjectUserName` ≠ `TargetUserName` 인 행만 남기면 대부분의 노이즈가 사라진다.**

```powershell
$x = Import-Csv 'C:\case\out\x.csv'

# 원본 EventData 필드 이름으로 값을 뽑는다 (컬럼 배치 변화에 안전)
function Fld { param($p,$n)
  $m=[regex]::Match($p,'"'+[regex]::Escape($n)+'"\s*:\s*"?([^",}]*)'); if($m.Success){$m.Groups[1].Value}else{''} }

$x | ForEach-Object {
  [pscustomobject]@{
    Time    = $_.TimeCreated
    Who     = Fld $_.Payload 'SubjectUserName'      # 실제 사람 (요청 주체)
    LogonId = (Fld $_.Payload 'SubjectLogonId').ToLower()
    Used    = Fld $_.Payload 'TargetUserName'       # 빌려 쓴 계정
    Server  = Fld $_.Payload 'TargetServerName'     # 접속 대상
    Info    = Fld $_.Payload 'TargetInfo'
    Proc    = Fld $_.Payload 'ProcessName'
    Ip      = Fld $_.Payload 'IpAddress'
  }
} |
  Where-Object { $_.Who -notmatch '\$$' -and $_.Used -notmatch '\$$' -and $_.Who -ne $_.Used } |
  Sort-Object Time | Format-Table -AutoSize
```

## 상세 절차

### 1단계 — 필드표: 세 주체를 구분한다

4648 의 필드는 **요청한 쪽(Subject)** 과 **사용된 자격증명(Target)** 과 **대상 서버(TargetServer)** 세 덩어리다. 이 구분이 흔들리면 이벤트 전체가 무의미해진다.

| 필드 | 어느 덩어리 | 의미 | 실전 해석 |
| --- | --- | --- | --- |
| `SubjectUserSid` | 요청 주체 | 실제로 명령을 실행한 계정의 SID | 사람 또는 그 사람이 실행한 프로세스 |
| `SubjectUserName` | 요청 주체 | **실제 사람의 계정 이름** | 책임 소재. 여기가 진짜 행위자 |
| `SubjectDomainName` | 요청 주체 | 그 계정의 도메인 | 로컬이면 컴퓨터 이름 |
| `SubjectLogonId` | 요청 주체 | **그 사람의 세션 ID (16진수)** | 4624/4672/4688 과의 조인 키 |
| `LogonGuid` | 요청 주체 | 주체 세션의 GUID | Kerberos 환경에서 티켓 상관에 쓴다 |
| `TargetUserName` | 사용된 자격증명 | **써 보려 한 계정 이름** | 도용 대상 계정 |
| `TargetDomainName` | 사용된 자격증명 | 그 계정의 도메인 | — |
| `TargetLogonGuid` | 사용된 자격증명 | 대상 자격증명의 로그온 GUID | 대상 호스트의 4769/4624 와 상관 |
| `TargetServerName` | 대상 | **접속하려 한 서버 이름** | `localhost` 면 로컬 권한 상승, 원격 호스트면 측면 이동 |
| `TargetInfo` | 대상 | 대상에 대한 부가 정보 | `TargetServerName` 과 같거나 서비스/SPN 문자열 |
| `ProcessId` | 실행 맥락 | 요청 프로세스의 PID (16진수) | 4688 과 조인 |
| `ProcessName` | 실행 맥락 | **요청 프로세스의 전체 경로** | `runas.exe`, `mstsc.exe`, `net.exe` 등 |
| `IpAddress` / `IpPort` | 대상 | 대상의 주소/포트 | 대개 `-`. 값이 있으면 실제 원격 세션 |

**4648 에는 `TargetLogonId` 가 없다.** 있는 것은 `TargetLogonGuid` 다. 세션 조인은 `SubjectLogonId` 로만 한다.

읽는 순서는 항상 이렇다.

```text
SubjectUserName  →  TargetUserName  →  TargetServerName
 (누가)              (무슨 계정으로)     (어디에)
    jhkim               svc_admin          FILE-SRV01
    ^ 이 사람이         ^ 이 계정을 써서    ^ 여기에 붙었다
```

### 2단계 — 어떤 행위가 4648 을 만드는가

| 행위 | 명령 예시 | `ProcessName` | `TargetServerName` | 정상/의심 |
| --- | --- | --- | --- | --- |
| `runas` | `runas /user:DOM\admin cmd.exe` | `runas.exe` | 자기 호스트 | 관리자 승격. 맥락에 따라 |
| `runas /netonly` | `runas /netonly /user:DOM\admin cmd.exe` | `runas.exe` | 자기 호스트 | **Logon Type 9 와 짝. 자격증명 도용 강한 신호** |
| RDP 재인증 | `mstsc /admin`, `mstsc /v:host` | `mstsc.exe` | 대상 호스트 | 원격 접속 |
| 공유 연결 | `net use \\SRV\C$ /user:DOM\admin` | `net.exe` | 대상 호스트 | **관리 공유 접근 = 측면 이동 정석** |
| 원격 실행 | PsExec 계열, WMI, WinRM | 도구 실행 파일 | 대상 호스트 | 측면 이동 |
| 예약 작업 등록 | `schtasks /ru`, `/s` 원격 등록 | `schtasks.exe` | 자기 또는 대상 호스트 | 지속성 |
| 서비스 등록 | `sc \\host create` | `sc.exe` | 대상 호스트 | 지속성 + 측면 이동 |
| 자격증명 입력 UI | 네트워크 자격증명 프롬프트 | `explorer.exe`, `svchost.exe` | 대상 호스트 | 사용자 조작 |
| 스케줄러 작업 실행 | 저장된 자격증명으로 작업 실행 | `svchost.exe`, `taskeng.exe` | 자기 호스트 | **정상 노이즈** |
| 서비스 자격증명 갱신 | 서비스가 저장 자격증명 재사용 | `services.exe`, `svchost.exe` | 자기 호스트 | **정상 노이즈** |

MITRE ATT&CK 관점으로는 유효 계정 사용(T1078), 대체 인증 자료 사용(T1550), 원격 서비스를 통한 측면 이동(T1021)의 흔적이 이 하나의 이벤트에 모인다.

### 3단계 — 정상 노이즈와 구분하는 기준

4648 은 정상 시스템에서도 꾸준히 발생한다. 무작정 "자격증명 도용"으로 읽으면 오답이다.

| 기준 | 정상 노이즈 | 의심 |
| --- | --- | --- |
| `SubjectUserName` | `SYSTEM`, 컴퓨터 계정(`WIN10$`), `LOCAL SERVICE` | **일반 사용자 계정** |
| `SubjectLogonId` | `0x3e7` / `0x3e5` / `0x3e4` | 대화형 세션 ID (4624 Type 2/10 과 짝) |
| `ProcessName` | `services.exe`, `svchost.exe`, `taskeng.exe`, `taskhostw.exe` | `runas.exe`, `net.exe`, `mstsc.exe`, `powershell.exe`, `cmd.exe`, `C:\Users\...` 아래 실행 파일 |
| `TargetUserName` | 서비스 계정이 자기 자신 | **관리자 계정, 다른 사용자 계정** |
| `TargetServerName` | 자기 호스트명, `localhost` | **다른 호스트명** |
| 반복 패턴 | 정확히 일정한 간격으로 무한 반복 (스케줄러) | 짧은 구간에 여러 대상으로 확산 |
| 발생 시각 | 업무 시간, 정기 작업 시각 | 새벽, 침입 구간 |
| `Subject` vs `Target` | **같다** (자기 자신 재인증) | **다르다** |

가장 효율적인 단일 필터는 이것이다.

```powershell
# 노이즈를 한 번에 걷어낸다: 시스템 주체 제거 + 자기 자신 재인증 제거
$sus = $x | ForEach-Object {
  [pscustomobject]@{
    Time    = $_.TimeCreated
    Who     = Fld $_.Payload 'SubjectUserName'
    LogonId = (Fld $_.Payload 'SubjectLogonId').ToLower()
    Used    = Fld $_.Payload 'TargetUserName'
    Server  = Fld $_.Payload 'TargetServerName'
    Proc    = Fld $_.Payload 'ProcessName'
  }
} | Where-Object {
  $_.LogonId -notin '0x3e7','0x3e5','0x3e4','0x0' -and
  $_.Who -notmatch '\$$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$' -and
  $_.Used -notmatch '\$$' -and
  $_.Who -ne $_.Used
}

$sus | Group-Object Who, Used, Server | Sort-Object Count -Descending |
  Select-Object Count, Name | Format-Table -AutoSize

# 프로세스 분포 — runas.exe / net.exe / mstsc.exe 가 보이면 즉시 확대
$sus | Group-Object Proc | Sort-Object Count -Descending | Format-Table Count, Name
```

`Who, Used, Server` 3중 그룹화가 실전에서 가장 빠르다. **정상 환경에서는 이 조합이 몇 개뿐이고, 침해된 환경에서는 하나의 `Who` 가 여러 `Server` 로 퍼진다.**

### 4단계 — Logon Type 9 (NewCredentials)와의 짝

`runas /netonly` 는 **현재 세션의 로컬 신원은 그대로 두고 네트워크 인증만 다른 자격증명으로 바꾼다.** 그 결과 같은 호스트에 두 이벤트가 거의 동시에 남는다.

| 이벤트 | 남는 위치 | 무엇을 말하나 |
| --- | --- | --- |
| 4648 | 출발지 호스트 | 누가(`SubjectUserName`) 어떤 계정을(`TargetUserName`) 쓰려 했는가 |
| 4624 **Logon Type 9** | 출발지 호스트 | 그 대체 자격증명 세션이 실제로 만들어졌다 |
| 4624 Logon Type 3 | **대상 호스트** | 그 계정이 대상에서 네트워크 로그온에 성공했다 |

```powershell
# 4648 과 같은 SubjectLogonId 를 가진 4624 Type 9 를 찾는다
$all = Import-Csv 'C:\case\out\all.csv'
$type9 = $all | Where-Object { $_.EventId -eq '4624' -and (Fld $_.Payload 'LogonType') -eq '9' } |
  ForEach-Object {
    [pscustomobject]@{
      Time    = $_.TimeCreated
      User    = Fld $_.Payload 'TargetUserName'
      NewId   = (Fld $_.Payload 'TargetLogonId').ToLower()
      SubjId  = (Fld $_.Payload 'SubjectLogonId').ToLower()
      Proc    = Fld $_.Payload 'ProcessName'
    }
  }
$type9 | Format-Table -AutoSize
```

**Logon Type 9 는 정상 워크스테이션에서 거의 발생하지 않는다.** 4648 + Type 9 조합이 보이면 그 시각을 침해 타임라인의 기준점으로 삼는다. Logon Type 표 전체는 [FOR-0083](./event-4624-logon.html)에 있다.

### 5단계 — 측면 이동 추적: 4648 → 대상 호스트의 4624 Type 3

이것이 4648 을 쓰는 최종 목적이다.

```text
[출발지 호스트 WIN10-FIN01]                  [대상 호스트 FILE-SRV01]

07:22:05  4648                                07:22:06  4624 Type 3
  SubjectUserName  = jhkim            ────▶     TargetUserName  = svc_admin
  SubjectLogonId   = 0x2f4e10                    TargetLogonId   = 0x7b21a4
  TargetUserName   = svc_admin                   IpAddress       = 10.0.0.24
  TargetServerName = FILE-SRV01                  WorkstationName = WIN10-FIN01
  ProcessName      = C:\Windows\System32\net.exe
                                              07:22:06  4672
                                                SubjectLogonId  = 0x7b21a4
                                                PrivilegeList   = SeBackup...

  ▲ "사람"이 여기 있다                          ▲ "계정"만 여기 있다
```

추적 절차:

| 단계 | 무엇을 | 어디서 |
| --- | --- | --- |
| 1 | `SubjectLogonId` 로 4624 를 찾아 그 사람의 접속 경로 확정 | 출발지 Security |
| 2 | `TargetUserName` + `TargetServerName` 기록 | 출발지 4648 |
| 3 | `ProcessName` 으로 사용 도구 확정 | 출발지 4648 → 4688 |
| 4 | 대상 호스트에서 같은 시각(±5초) `TargetUserName` 의 4624 Type 3 을 찾는다 | **대상** Security |
| 5 | 그 4624 의 `WorkstationName`/`IpAddress` 가 출발지와 일치하는지 확인 | 대상 Security |
| 6 | 대상의 새 `TargetLogonId` 로 4672 / 4688 / 5140 / 5145 를 잇는다 | 대상 Security |
| 7 | 대상에서 또 4648 이 나오면 1번으로 돌아간다 (다단 이동) | 대상 Security |

```powershell
# 4648 하나를 잡고 대상 호스트 로그에서 짝을 찾는 쿼리
$t0   = [datetime]'2026-03-14T07:22:05Z'
$acct = 'svc_admin'

Import-Csv 'C:\case\out\srv01.csv' |
  Where-Object {
    $_.EventId -eq '4624' -and
    (Fld $_.Payload 'TargetUserName') -eq $acct -and
    [math]::Abs((([datetime]$_.TimeCreated) - $t0).TotalSeconds) -le 10
  } | ForEach-Object {
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Type    = Fld $_.Payload 'LogonType'
      LogonId = Fld $_.Payload 'TargetLogonId'
      Ip      = Fld $_.Payload 'IpAddress'
      Wks     = Fld $_.Payload 'WorkstationName'
    }
  } | Format-Table -AutoSize
```

7번의 재귀가 중요하다. **다단 측면 이동은 각 호스트의 4648 을 이어 붙여 경로 그래프를 만들면 그대로 드러난다.**

## 출력 필드 해석

```text
EvtxECmd CSV 한 행 (4648, 값은 예시)

TimeCreated : 2026-03-14 07:22:05.4471290Z      <- UTC
EventId     : 4648
Channel     : Security
Computer    : WIN10-FIN01
Payload     : {"SubjectUserSid":"S-1-5-21-1111111111-2222222222-3333333333-1002",
               "SubjectUserName":"jhkim","SubjectDomainName":"CONTOSO",
               "SubjectLogonId":"0x2f4e10",
               "LogonGuid":"{00000000-0000-0000-0000-000000000000}",
               "TargetUserName":"svc_admin","TargetDomainName":"CONTOSO",
               "TargetLogonGuid":"{00000000-0000-0000-0000-000000000000}",
               "TargetServerName":"FILE-SRV01","TargetInfo":"FILE-SRV01",
               "ProcessId":"0x1a4c","ProcessName":"C:\\Windows\\System32\\net.exe",
               "IpAddress":"-","IpPort":"-"}
```

읽는 법: `jhkim` 이라는 사람이 `svc_admin` 자격증명으로 `FILE-SRV01` 에 `net.exe` 로 붙었다. `IpAddress` 가 `-` 인 것은 정상이며(대상 주소가 이름으로만 지정됨), 대상 IP 는 대상 호스트의 4624 에서 얻는다.

`LogonGuid` 가 모두 0 이면 NTLM 경로다. 값이 채워져 있으면 Kerberos 이므로 DC 의 4769(서비스 티켓 요청)와 상관할 수 있다.

**EVTX 내부 `SystemTime` 은 항상 UTC 로 저장되고, EvtxECmd CSV 의 `TimeCreated` 도 UTC 다.** Event Viewer 는 로컬 시간대로 변환해 보여준다. **KST 로 답해야 하면 +9시간**: `07:22:05Z` → `16:22:05 KST`. 출발지와 대상이 서로 다른 호스트일 때 한쪽만 로컬 시각으로 읽으면 9시간 차이 때문에 짝을 찾지 못한다. **호스트 간 상관은 반드시 UTC 로만 한다.** 시간대 확인은 [FOR-0054](./system-timezone.html).

## pivot: 다음에 볼 artifact

| 4648 에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `SubjectLogonId` | 4624 ([FOR-0083](./event-4624-logon.html)) | 그 사람이 어디서 어떻게 들어왔는가 |
| `SubjectLogonId` | 4672 ([FOR-0087](./event-4672-special-privileges.html)) | 그 세션이 관리자 권한이었는가 |
| `SubjectLogonId` | 4688 | 세션 내 실행 명령 전체 |
| `SubjectLogonId` | 4634 / 4647 ([FOR-0085](./event-4634-4647-logoff.html)) | 세션 창을 확정해 활동 범위를 자른다 |
| `ProcessId` + `ProcessName` | 4688 (같은 PID) | 명령행 인자 — `net use` 의 대상 공유 등 |
| `TargetUserName` + `TargetServerName` | **대상 호스트**의 4624 Type 3 | 실제로 접속에 성공했는가 |
| `TargetUserName` | 4625 ([FOR-0084](./event-4625-failed-logon.html)) | 자격증명이 틀렸다면 실패로 남는다 |
| `TargetServerName` | 대상의 5140 / 5145 | 접근한 공유와 개별 파일 |
| `TargetServerName` | 대상의 7045 / TaskScheduler 106 | 원격으로 심은 서비스·예약 작업 |
| Logon Type 9 동반 | Sysmon 1 / 10 | `runas` 를 실행한 프로세스와 LSASS 접근 |
| `LogonGuid` 가 채워짐 | DC 의 4769 | 요청된 서비스 티켓(SPN) |
| 도용된 계정 | SAM / ProfileList ([FOR-0052](./sam-user-accounts.html)) | 그 계정의 정체와 권한 |

## 흔한 함정

- **`SubjectUserName` 과 `TargetUserName` 을 뒤집어 읽는 것.** `Subject` 가 **실제 행위자**이고 `Target` 이 **빌려 쓴 계정**이다. 반대로 읽으면 피해 계정을 공격자로 지목하게 된다. 이 이벤트에서 가장 치명적인 오독이다.
- **4648 에서 `TargetLogonId` 를 찾는 것.** 4648 에는 없다. 있는 것은 `TargetLogonGuid` 이고, 세션 조인 키는 `SubjectLogonId` 다.
- **4648 을 "접속 성공"으로 읽는 것.** 4648 은 **시도**를 기록한다. 자격증명이 틀렸어도 남는다. 성공 여부는 대상 호스트의 4624 또는 4625 로 확인한다.
- **`SubjectUserName` = `TargetUserName` 인 행을 분석하는 것.** 자기 자신으로 재인증한 것이고, 스케줄러·서비스가 만드는 정상 노이즈의 대부분이다. 먼저 제외한다.
- **`TargetServerName` 이 자기 호스트명인 행을 측면 이동으로 세는 것.** 로컬 `runas` 다. 권한 상승일 수는 있지만 이동은 아니다.
- **`ProcessName` 을 무시하는 것.** `services.exe`/`svchost.exe`/`taskeng.exe` 주체의 4648 은 거의 전부 노이즈다. 반대로 `runas.exe`/`net.exe`/`mstsc.exe`/사용자 프로필 아래 실행 파일은 즉시 확대 대상이다.
- **`IpAddress` 가 `-` 라서 원격이 아니라고 판단하는 것.** 4648 의 `IpAddress` 는 대개 `-` 다. 대상이 원격인지는 `TargetServerName` 으로 판단한다.
- **출발지 호스트 로그만 보고 끝내는 것.** 4648 은 출발지에만 남는다. 접속이 성사되었는지는 **대상 호스트의 4624** 를 봐야 알 수 있다. 대상 로그가 없으면 "시도했다"까지만 결론 낼 수 있다.
- **여러 호스트의 시각을 로컬 시간대로 섞어 상관하는 것.** UTC 로 통일하지 않으면 ±5초 창에서 짝을 절대 찾을 수 없다.
- **16진수 대소문자.** `SubjectLogonId` 가 `0x2F4E10` / `0x2f4e10` 로 섞여 나온다. 조인 전에 `.ToLower()` 로 정규화한다.
- **감사 정책이 꺼진 경우를 배제하지 않는 것.** 4648 은 Audit Logon 하위 범주에 속한다. 전 구간 0건이면 4719(감사 정책 변경)와 1102(로그 삭제)를 확인한다.
- **컴퓨터 계정(`WIN10$`) 주체를 사람으로 세는 것.** 도메인 인증 과정의 정상 동작이다.

## 교차검증

```powershell
# A) 4648 과 같은 SubjectLogonId 의 전 이벤트 — 세션 전체 이야기
$sid = '0x2f4e10'
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.Payload -imatch [regex]::Escape($sid) } |
  Sort-Object TimeCreated |
  Select-Object TimeCreated, EventId, MapDescription

# B) 4648 의 ProcessId 로 4688 을 찾아 명령행 인자를 얻는다
$pid4648 = '0x1a4c'
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -eq '4688' -and $_.Payload -imatch [regex]::Escape($pid4648) } |
  Select-Object TimeCreated, MapDescription, ExecutableInfo

# C) 하나의 주체가 몇 개의 대상 서버로 퍼졌는가 — 확산 폭 측정
$sus | Group-Object Who | ForEach-Object {
  [pscustomobject]@{
    Who     = $_.Name
    Servers = ($_.Group.Server | Sort-Object -Unique) -join ', '
    Accts   = ($_.Group.Used   | Sort-Object -Unique) -join ', '
    Count   = $_.Count
  }
} | Sort-Object Count -Descending | Format-Table -AutoSize

# D) Logon Type 9 동반 여부 — runas /netonly 확정
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -eq '4624' -and (Fld $_.Payload 'LogonType') -eq '9' } |
  Select-Object TimeCreated, UserName, MapDescription

# E) XPath 로 특정 대상 서버의 4648 만
wevtutil qe 'C:\case\Security.evtx' /lf:true /f:text `
  /q:"*[System[(EventID=4648)]] and *[EventData[Data[@Name='TargetServerName']='FILE-SRV01']]"
```

C 의 출력이 측면 이동 보고서의 핵심 표다. 한 `Who` 가 3개 이상의 `Servers` 로 퍼져 있으면 그 계정이 공격의 축이다.

## mini walkthrough

```text
문제:
"침입자는 워크스테이션에서 시작해 파일 서버로 이동했습니다.
 (1) 도용된 계정, (2) 이동 시각(KST), (3) 사용한 도구를 구하세요.
 첨부: WIN10-FIN01_Security.evtx, FILE-SRV01_Security.evtx"

1. EvtxECmd.exe -d . --csv out --csvf all.csv
   -> 두 호스트 로그가 한 CSV(Computer 컬럼으로 구분). 4648 은 1,204건.

2. 첫 시도 (실패한 접근):
   4648 을 TargetUserName 으로 집계했다.

     Count TargetUserName
     ----- --------------
      1146 WIN10-FIN01$
        38 jhkim
        14 svc_admin
         6 SYSTEM

   "WIN10-FIN01$ 계정이 1,146번 도용됐다"고 결론 냈다. 오답.

   왜 틀렸나: 컴퓨터 계정의 자기 재인증(SubjectUserName = TargetUserName)이
   대부분이었고, 이는 도메인 환경의 정상 동작이다.
   TargetUserName 만 세면 정상 노이즈가 1위를 차지한다.

3. 두 번째 시도 (또 실패):
   노이즈를 걷어내고 Subject != Target 만 남겼다.

     Count Who, Used, Server
     ----- -----------------
        14 jhkim, svc_admin, FILE-SRV01

   14건을 찾았다. 그런데 "jhkim 이 공격자"라고 답했다가 다시 오답.

   왜 틀렸나: jhkim 의 4624 를 확인하지 않았다. jhkim 세션의 출처를 보니
   Logon Type 10, IpAddress 203.0.113.77 (공인 IP)였다.
   jhkim 은 계정이 탈취된 정규 사용자이고, 도용된 계정은 svc_admin 이다.
   문제가 물은 것은 "도용된 계정" = TargetUserName 쪽이다.

4. 확정 — 14건의 상세:
   Time                  Who    Used       Server      Proc
   2026-03-14 07:22:05Z  jhkim  svc_admin  FILE-SRV01  C:\Windows\System32\net.exe
   2026-03-14 07:22:41Z  jhkim  svc_admin  FILE-SRV01  C:\Windows\System32\net.exe
   ...  (12건 더, 07:31 까지)

   ProcessName 이 net.exe -> net use 로 관리 공유에 붙었다.

5. ProcessId 로 4688 을 찾아 명령행 확인:
   07:22:04Z  4688  C:\Windows\System32\net.exe
              CommandLine: net use \\FILE-SRV01\C$ /user:CONTOSO\svc_admin ********
   -> 도구와 대상 공유가 확정됐다.

6. 대상 호스트에서 짝 찾기 (±10초, UTC 로):
   FILE-SRV01, 07:22:06Z  4624  Type 3
     TargetUserName  = svc_admin
     TargetLogonId   = 0x7b21a4
     IpAddress       = 10.0.0.24
     WorkstationName = WIN10-FIN01     <- 출발지와 일치. 이동 확정
   FILE-SRV01, 07:22:06Z  4672
     SubjectLogonId  = 0x7b21a4        <- 관리자 권한 세션

7. 처음에 UTC 를 놓쳐 겪은 문제:
   FILE-SRV01 로그를 Event Viewer(로컬 KST)로 열어 16:22:06 을 보고
   출발지의 07:22:05Z 와 ±10초 창에서 짝을 못 찾았다.
   두 로그를 모두 EvtxECmd CSV(UTC)로 통일하자 즉시 일치했다.

8. 대상 세션의 후속 활동 (0x7b21a4):
   07:23:11Z  5145  \\FILE-SRV01\C$  \Users\ceo\Documents\M&A_2026.xlsx
   07:26:02Z  5145  ... (문서 다수 읽기)

9. 시각 변환: 07:22:05Z + 9h = 2026-03-14 16:22:05 KST

정답: (1) 도용된 계정 svc_admin (탈취된 사용자 계정은 jhkim)
      (2) 2026-03-14 16:22:05 KST
      (3) net use 로 관리 공유 C$ 접속 (net.exe)
```

2단계와 3단계의 실패가 이 글의 요점이다. **`TargetUserName` 만 세면 컴퓨터 계정 노이즈가 1위를 먹고, `Subject` 와 `Target` 의 역할을 뒤집으면 피해자와 도용 계정이 바뀐다.** 7단계의 시간대 실수도 호스트 간 상관에서 반복적으로 나온다.

## 막혔을 때 다음 체크

1. `SubjectUserName`(행위자)과 `TargetUserName`(도용 계정)을 정확히 구분했는가
2. `SubjectUserName` = `TargetUserName` 행과 `$` 로 끝나는 계정을 제외했는가
3. `SubjectLogonId` 가 `0x3e7`/`0x3e5`/`0x3e4` 인 행을 제외했는가
4. `ProcessName` 을 봤는가 — `runas.exe`/`net.exe`/`mstsc.exe` 가 있으면 그 행부터
5. `TargetServerName` 이 자기 호스트인지 원격인지 구분했는가
6. `Who, Used, Server` 3중 그룹화를 해 봤는가 — 확산 폭이 한눈에 보인다
7. `ProcessId` 로 4688 을 찾아 **명령행 인자**를 얻었는가
8. 대상 호스트 로그에서 같은 시각의 4624 Type 3 을 찾았는가 (UTC 로 비교)
9. 4624 Logon Type 9 가 동반되는가 — `runas /netonly` 확정
10. 대상 호스트에서 또 4648 이 나오는가 — 다단 이동
11. 4648 이 전 구간 0건이면 → 4719 / 1102 확인
12. 답이 UTC 인지 KST 인지 확인했는가 (+9시간)

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 4648 이 속한 Audit Logon 하위 범주와 이벤트 발생 조건
- SRC-001 — Microsoft Learn, Event 4624: Logon Type 9(NewCredentials)의 정의와 `SubjectLogonId` / `TargetLogonId` 의 상관 방법
- SRC-086 — MITRE ATT&CK Enterprise: 유효 계정 사용(T1078), 대체 인증 자료 사용(T1550), 원격 서비스 측면 이동(T1021) 기법에서 명시적 자격증명 사용이 남기는 흔적
- 4648 의 `TargetInfo` 값 형식과 `LogonGuid` 채움 여부는 인증 패키지(NTLM/Kerberos)와 OS 버전에 따라 다르므로 실제 이벤트에서 확인할 것
</content>
