---
id: FOR-0085
title: "Event ID 4634 / 4647 로그오프: TargetLogonId로 세션 지속 시간을 계산한다"
slug: "event-4634-4647-logoff"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4634", "4647", "세션 지속시간", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"]
registry_paths: []
event_ids: ["4634", "4647"]
protocols: ["RDP", "SMB"]
tools: ["EvtxECmd", "PowerShell", "Timeline Explorer", "Event Viewer"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --inc 4624,4634,4647 --csv 'C:\\case\\out'", "Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4634,4647}", "wevtutil qe Security.evtx /q:\"*[EventData[Data[@Name='TargetLogonId']='0x1a2b3c']]\" /f:text"]
regex_patterns: ["\"TargetLogonId\":\"?(0x[0-9a-fA-F]+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType"]
file_formats: ["evtx"]
primary_terms: ["4634", "4647", "로그오프", "세션 종료"]
keywords: ["4634", "4647", "로그오프", "logoff", "세션 종료", "세션 지속시간", "TargetLogonId", "Audit Logoff", "6008", "Kernel-Power 41", "Security.evtx"]
aliases: ["4634", "4647", "로그아웃 기록", "언제 로그오프했나", "세션 얼마나 있었나", "접속 시간 계산", "4634 4647 차이"]
symptom_keywords: ["세션이 얼마나 유지됐는지 알고 싶다", "언제 로그아웃했는지 모르겠다", "4634가 너무 많다", "로그오프 이벤트가 없다", "4634와 4647 중 뭘 봐야 하나", "체류 시간을 구해야 한다"]
related: ["FOR-0083", "FOR-0084", "FOR-0095", "FOR-0104"]
source_ids: ["SRC-022", "SRC-001", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4634 와 4647 은 단독으로는 거의 쓸모가 없고, **4624 와 `TargetLogonId` 로 짝지어 세션 지속 시간을 계산하는 것**이 유일한 주 용도다. 4647 은 사용자가 명시적으로 로그오프를 실행한 것이고, 4634 는 세션이 사라졌다는 일반 통보(네트워크 세션 종료 포함)라서 Logon Type 3 에서는 노이즈로 쏟아진다.

## 어떤 문제에서 필요한가

- "공격자가 몇 분 동안 머물렀는가" (체류 시간 = dwell time)
- "이 계정의 세션은 언제 끝났는가"
- "사용자가 직접 로그아웃했는가, 아니면 강제 종료·전원 차단인가"
- "RDP 접속이 끊긴 것인가 로그오프한 것인가"
- 세션 창을 확정해 그 구간의 4688·5145·4104 만 잘라내야 할 때

로그오프 이벤트만 보고 답이 나오는 문제는 없다. **항상 4624 와의 조인이 전제**다.

## 문제에서 처음 볼 단서

1. 문제 지문의 "몇 분", "얼마 동안", "체류", "지속" → 4624/4634 조인 확정
2. `TargetLogonId` 값이 하나 주어졌다 → 그 값으로 4624 와 4634/4647 을 각각 찾으면 끝
3. 4634 가 4624 보다 훨씬 많다 → Logon Type 3 노이즈. 먼저 걷어낸다
4. 관심 세션에 4634 가 **없다** → 정상 종료가 아니다. 6008 / Kernel-Power 41 로 전환
5. 4647 이 있다 → 사람이 앉아서 직접 로그오프했다. 대화형(2) 또는 RDP(10) 세션

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --inc 4624,4634,4647 --csv 'C:\case\out' --csvf s.csv
```

세션 표를 바로 만든다.

```powershell
$s = Import-Csv 'C:\case\out\s.csv'

# 원본 EventData 필드 이름으로 값을 뽑는다 (컬럼 배치 변화에 안전)
function Fld { param($p,$n)
  $m=[regex]::Match($p,'"'+[regex]::Escape($n)+'"\s*:\s*"?([^",}]*)'); if($m.Success){$m.Groups[1].Value}else{''} }

$ev = $s | ForEach-Object {
  [pscustomobject]@{
    Time    = [datetime]$_.TimeCreated
    Id      = $_.EventId
    User    = Fld $_.Payload 'TargetUserName'
    LogonId = (Fld $_.Payload 'TargetLogonId').ToLower()
    Type    = Fld $_.Payload 'LogonType'
  }
}

# LogonId 로 4624 와 4634/4647 을 조인해 세션 표를 만든다
$ev | Where-Object { $_.LogonId -and $_.LogonId -notin '0x3e7','0x3e5','0x3e4','0x0' -and $_.User -notmatch '\$$' } |
  Group-Object LogonId | ForEach-Object {
    $g   = $_.Group | Sort-Object Time
    $on  = $g | Where-Object Id -eq '4624' | Select-Object -First 1
    $off = $g | Where-Object { $_.Id -in '4634','4647' } | Select-Object -Last 1
    [pscustomobject]@{
      LogonId  = $_.Name
      User     = ($g | Select-Object -First 1).User
      Type     = $on.Type
      Logon    = $on.Time
      Logoff   = $off.Time
      OffId    = $off.Id
      Minutes  = if ($on -and $off) { [math]::Round(($off.Time - $on.Time).TotalMinutes,1) } else { $null }
    }
  } | Where-Object { $_.Type -in '2','10','9','11','12' } |
  Sort-Object Logon | Format-Table -AutoSize
```

마지막 `Type -in '2','10','9','11','12'` 필터가 핵심이다. **Logon Type 3 을 빼지 않으면 표가 수천 행이 된다.**

## 상세 절차

### 1단계 — 4634 와 4647 의 차이

| 항목 | 4634 | 4647 |
| --- | --- | --- |
| 메시지 | An account was logged off | User initiated logoff |
| 무엇을 뜻하나 | **세션이 종료되어 더 이상 존재하지 않는다** | **사용자가 로그오프 기능을 실행했다** |
| 누가 유발하나 | 시스템 (세션 정리 시점) | 사용자 (시작 메뉴 로그아웃, `logoff` 명령 등) |
| `LogonType` 필드 | **있다** | **없다** |
| 흔한 Logon Type | 3 이 압도적, 그다음 5/2/10 | 2, 10 (대화형 계열) |
| 발생 보장 | 세션이 정상 정리되면 발생. 크래시·전원 차단 시 **없다** | 사용자가 명시적으로 로그오프할 때만 |
| 개수 | 매우 많다 (Type 3 노이즈) | 적다 — **그래서 가치가 높다** |
| 감사 하위 범주 | Audit Logoff | Audit Logoff |

두 이벤트는 **배타적이지 않다.** 사용자가 콘솔에서 직접 로그오프하면 4647 과 4634 가 **둘 다** 나오고, 보통 4647 이 먼저 기록된다. 따라서 세션 종료 시각을 하나만 골라야 한다면 **같은 `TargetLogonId` 의 마지막 이벤트 시각**을 쓴다.

### 2단계 — 필드표

**4647 의 필드 이름은 Event Viewer 화면에 "주체(Subject)"로 표시되지만, 실제 XML 이름은 `Target*` 이다.** `Data[@Name='SubjectLogonId']` 로 XPath 필터를 짜면 4647 은 한 건도 잡히지 않는다. 이것이 이 이벤트에서 가장 많이 나오는 실수다.

| 필드 | 4634 | 4647 | 의미 |
| --- | --- | --- | --- |
| `TargetUserSid` | 있다 | 있다 | 로그오프한 계정의 SID. `S-1-5-18` = SYSTEM |
| `TargetUserName` | 있다 | 있다 | 계정 이름. `$` 로 끝나면 컴퓨터 계정 |
| `TargetDomainName` | 있다 | 있다 | 도메인. 로컬이면 컴퓨터 이름 |
| `TargetLogonId` | 있다 | 있다 | **세션 ID (16진수).** 4624 와의 조인 키 |
| `LogonType` | **있다** | **없다** | 4634 에서만 접속 방식을 알 수 있다 |

`TargetLogonId` 의 성질:

| 성질 | 내용 |
| --- | --- |
| 범위 | **같은 컴퓨터의 같은 부팅 구간 안에서만 유일**하다 |
| 재부팅 후 | 값이 재사용될 수 있다. 부팅 경계를 넘어 조인하면 엉뚱한 세션이 붙는다 |
| 표기 | `0x1a2b3c` 형태. 대소문자가 섞여 나오므로 `.ToLower()` 로 정규화한다 |
| 고정값 | `0x3e7` = SYSTEM, `0x3e5` = LOCAL SERVICE, `0x3e4` = NETWORK SERVICE, `0x0` = 없음 |

### 3단계 — 세션 지속시간 계산 실전 쿼리

위 30초 절차의 조인을 그대로 쓰되, 실전에서는 세 가지를 추가한다.

```powershell
# (1) 부팅 경계를 구해 LogonId 재사용을 차단한다
$boot = Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '4608','6005','6009','12' -or ($_.EventId -eq '41') } |
  ForEach-Object { [datetime]$_.TimeCreated } | Sort-Object

# (2) LogonId + 부팅 구간을 합친 키로 그룹화
function BootEpoch { param([datetime]$t)
  ($boot | Where-Object { $_ -le $t } | Select-Object -Last 1) }

$sessions = $ev |
  Where-Object { $_.LogonId -and $_.LogonId -notin '0x3e7','0x3e5','0x3e4','0x0' -and $_.User -notmatch '\$$' } |
  Group-Object { "$($_.LogonId)|$(BootEpoch $_.Time)" } | ForEach-Object {
    $g   = $_.Group | Sort-Object Time
    $on  = $g | Where-Object Id -eq '4624' | Select-Object -First 1
    $off = $g | Where-Object { $_.Id -in '4634','4647' } | Select-Object -Last 1
    [pscustomobject]@{
      LogonId   = ($g | Select-Object -First 1).LogonId
      User      = ($g | Select-Object -First 1).User
      Type      = $on.Type
      LogonUtc  = $on.Time
      LogoffUtc = $off.Time
      OffId     = $off.Id
      Duration  = if ($on -and $off) { $off.Time - $on.Time } else { $null }
    }
  }

# (3) 오래 유지된 대화형/RDP 세션 순으로 — 공격자 체류 구간이 여기 있다
$sessions | Where-Object { $_.Type -in '2','10' -and $_.Duration } |
  Sort-Object Duration -Descending | Select-Object -First 20 |
  Format-Table LogonId, User, Type, LogonUtc, LogoffUtc, OffId,
    @{n='Min';e={[math]::Round($_.Duration.TotalMinutes,1)}} -AutoSize
```

출력 예시:

```text
LogonId   User        Type LogonUtc             LogoffUtc            OffId Min
-------   ----        ---- --------             ---------            ----- ---
0x1a2b3c  svc_backup  10   2026-03-14 07:18:44  2026-03-14 07:41:12  4634  22.5
0x2f4e10  jhkim       10   2026-03-14 09:02:11  2026-03-14 18:05:47  4647  543.6
0x30a112  jhkim       2    2026-03-13 00:12:03                             (null)
```

읽는 법: `svc_backup` 은 22.5분 머물고 4634(세션 정리)로 끝났다 — 사용자가 로그오프 버튼을 누르지 않았다는 뜻이다. `jhkim` 의 RDP 세션은 4647 로 끝났으므로 사람이 직접 로그아웃했다. 세 번째 행은 로그오프 이벤트가 아예 없다 → 4단계로 간다.

### 4단계 — 4634 가 없는 세션의 해석

세션에 로그오프 이벤트가 없다는 것은 **세션이 정상적으로 정리되지 않았다**는 뜻이다. 원인은 셋 중 하나다.

| 원인 | 확인할 이벤트 | 채널 | 판정 |
| --- | --- | --- | --- |
| 비정상 종료 / 전원 차단 | **6008** (이전 시스템 종료가 예기치 않았음) | System | 6008 시각이 세션 마지막 활동 직후면 확정 |
| 크래시 / 강제 리셋 | **41** (Kernel-Power, 정상 종료 없이 재부팅) | System | 6008 과 함께 나오는 경우가 많다 |
| 정상 종료였지만 로그오프 감사가 누락 | 1074 (종료 요청), 6006 (이벤트 로그 서비스 정지) | System | 종료 절차는 밟았다 |
| 로그가 잘렸다 / 삭제됐다 | 1102, `EventRecordId` 빈 구간 | Security | 세션은 끝났지만 기록이 사라졌다 |
| 감사 정책에서 Audit Logoff 가 꺼져 있었다 | 4719 | Security | 4634 가 **전 구간에서 0건**이면 이쪽 |
| 세션이 아직 살아 있는 채로 수집됐다 | 로그 마지막 시각과 비교 | — | 이미지 획득 시점까지 유지된 세션 |

```powershell
# 로그오프 이벤트가 없는 세션과 종료 이벤트를 나란히 놓는다
$shutdown = Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '6008','41','1074','6006','6005' } |
  Select-Object TimeCreated, EventId, MapDescription | Sort-Object TimeCreated

$sessions | Where-Object { -not $_.LogoffUtc } |
  Select-Object LogonId, User, Type, LogonUtc
$shutdown
```

`Type -eq '3'` 세션에 4634 가 없는 것은 흔하고 의미도 약하다. **판정 가치가 있는 것은 Type 2 / 10 세션의 누락**이다.

### 5단계 — Logon Type 3 노이즈

4634 의 대부분은 Logon Type 3 이다. 파일 공유 접근, 그룹 정책 적용, 이름 확인 같은 짧은 네트워크 세션이 초 단위로 열리고 닫히기 때문이다.

| 노이즈 원인 | 특징 | 처리 |
| --- | --- | --- |
| SMB 공유 접근 | Type 3, 지속시간 수 초, 4624/4634 가 쌍으로 대량 | Type 3 제외 후 별도 분석 |
| 컴퓨터 계정 인증 | `TargetUserName` 이 `$` 로 끝남 | 제외 |
| SYSTEM / 서비스 | `TargetLogonId` = `0x3e7`/`0x3e5`/`0x3e4` | 제외 |
| `ANONYMOUS LOGON` | 널 세션 | 제외 (단, NTLM 널 세션 자체는 별도로 의심) |
| `UMFD-*`, `DWM-*` | 데스크톱 관리자 세션 | 제외 |

```powershell
# 노이즈 제거 전/후 건수 비교 — 이 숫자를 보면 필터의 효과가 명확하다
$raw = ($ev | Where-Object { $_.Id -in '4634','4647' }).Count
$net = ($ev | Where-Object {
  $_.Id -in '4634','4647' -and $_.Type -ne '3' -and
  $_.LogonId -notin '0x3e7','0x3e5','0x3e4','0x0' -and
  $_.User -notmatch '\$$|^UMFD-|^DWM-|ANONYMOUS'
}).Count
[pscustomobject]@{ Raw=$raw; Filtered=$net }
```

Type 3 세션의 지속시간 자체는 거의 정보가 없지만, **한 세션이 비정상적으로 길게(수십 분 이상) 유지된 Type 3** 은 예외다. 원격 도구가 공유를 물고 있는 신호일 수 있다.

### 6단계 — RDP 세션은 TerminalServices 로그와 대조

Logon Type 10 세션은 Security 채널만으로는 "끊김"과 "로그오프"를 구분하지 못한다. `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` 를 함께 본다.

| Event ID | 의미 | Security 채널의 대응 |
| --- | --- | --- |
| 21 | 세션 로그온 성공 | 4624 Type 10 |
| 22 | 셸(explorer) 시작 알림 | — |
| **23** | **세션 로그오프 성공** | 4647 / 4634 |
| **24** | **세션 연결 끊김 (disconnect)** | 4634 가 나오지 않는 경우가 많다 |
| **25** | **세션 재연결 성공** | 4624 Type 10 이 다시 나온다 |

핵심 구분:

| 관찰 | 해석 |
| --- | --- |
| 21 → 23 | 사용자가 정상 로그오프했다. 세션 종료 |
| 21 → 24 | **세션을 끊었을 뿐 로그오프하지 않았다.** 프로세스는 계속 살아 있다 |
| 21 → 24 → 25 → 23 | 끊었다가 다시 붙어서 작업을 이어갔다. **24~25 사이도 세션은 유효하다** |
| 4634 없음 + 24 있음 | 정상. disconnect 는 로그오프가 아니다 |

**24 → 25 구간을 세션 종료로 오해하면 체류 시간을 크게 과소평가한다.** RDP 문제에서는 4624/4634 지속시간이 아니라 21 부터 23 까지를 세션으로 본다. 세부 내용은 RDP 전용 로그 글에서 다룬다.

## 출력 필드 해석

```text
EvtxECmd CSV (4634, 값은 예시)

TimeCreated : 2026-03-14 07:41:12.7654321Z     <- UTC
EventId     : 4634
Channel     : Security
Payload     : {"TargetUserSid":"S-1-5-21-1111111111-2222222222-3333333333-1108",
               "TargetUserName":"svc_backup","TargetDomainName":"WIN10-FIN01",
               "TargetLogonId":"0x1a2b3c","LogonType":"10"}

EvtxECmd CSV (4647, 값은 예시)

TimeCreated : 2026-03-14 18:05:47.1112223Z
EventId     : 4647
Payload     : {"TargetUserSid":"S-1-5-21-1111111111-2222222222-3333333333-1002",
               "TargetUserName":"jhkim","TargetDomainName":"CONTOSO",
               "TargetLogonId":"0x2f4e10"}
               ^ LogonType 이 없다. 4647 에는 이 필드가 존재하지 않는다
```

지속시간 계산에서의 시간대 처리:

| 항목 | 값 |
| --- | --- |
| EVTX 내부 `SystemTime` | **UTC** — 포맷 자체가 UTC 로 저장한다 |
| EvtxECmd CSV `TimeCreated` | UTC 그대로 |
| Event Viewer 화면 | 시스템 로컬 시간대로 변환된 값 |
| **지속시간(차이)** | 두 값 모두 UTC 이므로 **시간대와 무관하게 정확하다** |
| 로그온·로그오프 **시각**을 답할 때 | KST 는 **UTC + 9시간** |

즉 "몇 분 머물렀나"는 UTC 로 계산해도 되지만, "몇 시에 로그오프했나"는 반드시 +9 를 적용한다. **한 표 안에서 UTC 시각과 KST 시각을 섞으면 지속시간이 9시간 틀어진다.** 대상 시스템의 시간대는 [FOR-0054](./system-timezone.html)에서 확인한다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `TargetLogonId` | 4624 ([FOR-0083](./event-4624-logon.html)) | 세션 시작 시각, Logon Type, IP |
| 세션 창 (시작~종료) | 4688 | 그 구간에서 실행된 프로세스와 명령행 |
| 세션 창 | 4104 (PowerShell/Operational) | 그 구간의 스크립트 원문 |
| 세션 창 | 5140 / 5145 | 그 구간에 접근한 공유와 파일 |
| 세션 창 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 구간에 생성·수정된 파일 |
| 같은 `SubjectLogonId` | 4672 ([FOR-0087](./event-4672-special-privileges.html)) | 그 세션이 관리자 권한이었는가 |
| 같은 `SubjectLogonId` | 4648 ([FOR-0086](./event-4648-explicit-credentials.html)) | 그 세션에서 다른 자격증명을 썼는가 |
| 로그오프 이벤트 없음 | System 채널 6008 / 41 / 1074 | 비정상 종료였는가 |
| Type 10 세션 | TerminalServices-LocalSessionManager 21/23/24/25 | 로그오프인가 disconnect 인가 |
| 4634 가 전 구간 0건 | 4719 / 1102 | Audit Logoff 가 꺼졌는가, 로그가 지워졌는가 |

## 흔한 함정

- **4647 에서 `SubjectLogonId` 를 찾는 것.** Event Viewer 는 "주체(Subject)" 라고 표시하지만 **실제 XML 필드 이름은 `TargetLogonId`** 다. `Data[@Name='SubjectLogonId']` XPath 나 `$p.SubjectLogonId` 는 4647 에서 항상 빈 값을 반환한다. 원본 이름을 쓴다.
- **4647 에서 `LogonType` 을 읽으려는 것.** 4647 에는 그 필드가 없다. 접속 방식은 같은 `TargetLogonId` 의 4624 또는 4634 에서 가져온다.
- **4634 하나만 보고 세션 종료 시각을 정하는 것.** 사용자가 직접 로그오프하면 4647 과 4634 가 모두 나온다. 같은 `TargetLogonId` 의 **마지막** 로그오프 이벤트를 종료 시각으로 쓴다.
- **Logon Type 3 을 걸러내지 않는 것.** 4634 의 대부분이 초 단위 SMB 세션이라 표가 수천 행이 되고 진짜 세션이 묻힌다. Type 3·컴퓨터 계정·`0x3e7`/`0x3e5`/`0x3e4` 를 먼저 제외한다.
- **재부팅을 넘어 `TargetLogonId` 로 조인하는 것.** Logon ID 는 **같은 부팅 구간 안에서만 유일**하다. 부팅 경계를 무시하면 어제의 4624 에 오늘의 4634 가 붙어 지속시간이 수십 시간으로 나온다.
- **로그오프 이벤트가 없는 것을 "세션이 계속 살아 있다"로만 해석하는 것.** 전원 차단·크래시(6008 / Kernel-Power 41), 로그 삭제(1102), 감사 정책 누락(4719) 모두 같은 모습이다. System 채널을 반드시 교차 확인한다.
- **RDP 의 24(disconnect)를 로그오프로 세는 것.** disconnect 는 세션을 유지한 채 연결만 끊은 것이다. 25(재연결) 이후에도 같은 세션이 이어지므로 체류 시간이 실제보다 짧게 나온다.
- **16진수 대소문자.** `Payload` 의 값은 `0x1A2B3C` / `0x1a2b3c` 가 섞여 나온다. 조인 전에 `.ToLower()` 로 정규화하지 않으면 짝이 안 맞아 지속시간이 전부 `null` 이 된다.
- **UTC 와 로컬 시각을 섞어 지속시간을 계산하는 것.** 한쪽을 Event Viewer 화면(로컬)에서, 다른 쪽을 CSV(UTC)에서 읽으면 9시간 오차가 생긴다. 계산은 UTC 로만 하고, 답을 낼 때만 +9 한다.
- **컴퓨터 계정 세션을 사람으로 세는 것.** `WIN10$` 는 사용자가 아니다.
- **`0x3e7` 을 계정 이름처럼 취급하는 것.** SYSTEM 세션 ID 다. 부팅 시 대량 발생한다.

## 교차검증

```powershell
# A) 특정 세션의 전체 수명 — 4624/4672/4648/4688/4634/4647 을 한 축에
$sid = '0x1a2b3c'
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.Payload -imatch [regex]::Escape($sid) } |
  Sort-Object TimeCreated |
  Select-Object TimeCreated, EventId, MapDescription

# B) 4624 개수와 로그오프 개수의 균형 — 크게 어긋나면 감사 누락/삭제
$ev | Group-Object Id | Format-Table Count, Name

# C) System 채널의 종료 이벤트와 나란히 비교
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '6005','6006','6008','41','1074' } |
  Sort-Object TimeCreated | Select-Object TimeCreated, EventId, MapDescription

# D) RDP 세션은 TerminalServices 채널로 재확인
Get-WinEvent -FilterHashtable @{
  Path='C:\case\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx'
  Id=21,23,24,25
} | Sort-Object TimeCreated | Select-Object TimeCreated, Id, Message

# E) XPath 로 직접 — 4647 은 TargetLogonId 로 잡아야 한다
wevtutil qe 'C:\case\Security.evtx' /lf:true /f:text `
  /q:"*[System[(EventID=4647)]] and *[EventData[Data[@Name='TargetLogonId']='0x2f4e10']]"
```

B 에서 4624 가 900건인데 4634+4647 이 40건이라면, 세션 대부분이 정리되지 않았거나 Audit Logoff 가 꺼져 있었다는 뜻이다. 지속시간 계산 자체를 포기하고 다른 artifact 로 세션 창을 잡아야 한다.

## mini walkthrough

```text
문제:
"침입자가 RDP 로 접속해 머문 시간을 분 단위로 구하세요.
 첨부: Security.evtx, Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"

1. EvtxECmd.exe -d . --csv out --csvf all.csv
   -> 4624: 9,102건 / 4634: 8,877건 / 4647: 12건

2. 첫 시도 (실패한 접근):
   4624 와 4634 를 TargetLogonId 로 그냥 조인했다.

     LogonId   User        Type Logon                Logoff               Min
     0x1a2b3c  svc_backup  10   2026-03-14 07:18:44  2026-03-14 07:24:03  5.3

   "5.3분 머물렀다"고 답했다. 오답.

   왜 틀렸나 (두 가지):
   (a) 같은 LogonId 의 4634 가 여러 건 있었고, Select-Object -First 를 써서
       가장 이른 4634 를 골랐다. 세션 종료는 마지막 이벤트로 잡아야 한다.
   (b) 더 근본적으로, RDP 세션은 disconnect(24) 로 잠시 끊겼다가
       reconnect(25) 로 이어질 수 있는데 Security 채널만 봤다.

3. 수정 1 — 마지막 로그오프 이벤트로 바꾼다:
   $off = $g | Where-Object { $_.Id -in '4634','4647' } | Select-Object -Last 1

     LogonId   User        Type Logon                Logoff               OffId  Min
     0x1a2b3c  svc_backup  10   2026-03-14 07:18:44  2026-03-14 07:41:12  4634   22.5

   4647 이 아니라 4634 로 끝났다 -> 사용자가 로그오프 버튼을 누른 게 아니다.

4. 수정 2 — TerminalServices 채널과 대조:
   TimeCreated            Id  내용
   2026-03-14 07:18:45Z   21  세션 로그온 성공 (svc_backup)
   2026-03-14 07:24:05Z   24  세션 연결 끊김            <- 여기서 끝난 게 아니었다
   2026-03-14 07:31:50Z   25  세션 재연결 성공
   2026-03-14 07:41:10Z   23  세션 로그오프 성공

   -> 2단계에서 본 07:24:03 은 disconnect 시점이었다.
      Security 채널의 4634 가 그 시점에도 하나 찍혀 있어서 오해했다.

5. Security 채널 재확인 — 같은 LogonId 로 4624 가 두 번:
   07:18:44Z  4624 Type 10  TargetLogonId 0x1a2b3c
   07:31:51Z  4624 Type 10  TargetLogonId 0x1a2b3c   <- 재연결
   07:41:12Z  4634 Type 10  TargetLogonId 0x1a2b3c   <- 최종 종료

6. 세션 정의를 21(로그온) ~ 23(로그오프)으로 잡는다:
   07:18:45Z -> 07:41:10Z = 22분 25초
   Security 기준(07:18:44 -> 07:41:12) = 22분 28초. 일치한다.

7. 세션 창으로 활동 잘라내기 (교차검증):
   07:19:31Z  4688  cmd.exe
   07:20:08Z  4688  powershell.exe -enc SQBFAFgA...
   07:33:12Z  4688  rclone.exe          <- 재연결 이후 구간. 세션에 포함된다
   -> 24~25 구간을 종료로 봤다면 이 활동을 세션 밖으로 잘라냈을 것이다.

8. 시각 변환 (참고): 07:18:44Z + 9h = 2026-03-14 16:18:44 KST
   지속시간 22.5분은 UTC/KST 어느 쪽으로 계산해도 같다.

정답: 약 22.5분 (2026-03-14 16:18:44 ~ 16:41:12 KST)
```

2단계의 두 실패가 이 글의 요점이다. **로그오프는 `-Last 1` 로 잡고, RDP 세션은 24/25 를 확인하지 않으면 체류 시간이 실제의 4분의 1로 나온다.**

## 막혔을 때 다음 체크

1. `TargetLogonId` 를 `.ToLower()` 로 정규화했는가 — 대소문자 불일치로 조인이 전부 실패한다
2. 로그오프를 **마지막** 이벤트(`-Last 1`)로 잡았는가
3. 4647 에서 `SubjectLogonId` 를 찾고 있지 않은가 — 실제 이름은 `TargetLogonId`
4. Logon Type 3·컴퓨터 계정·`0x3e7`/`0x3e5`/`0x3e4` 를 제외했는가
5. 부팅 경계를 넘어 조인하고 있지 않은가 — Logon ID 는 부팅 구간 안에서만 유일
6. Type 10 이면 TerminalServices 21/23/24/25 를 대조했는가 — disconnect 를 종료로 세지 말 것
7. 로그오프가 없는 세션이면 System 채널의 6008 / Kernel-Power 41 / 1074 를 확인했는가
8. 4634 가 전 구간 0건이면 → 4719(감사 정책 변경), 1102(로그 삭제)
9. 지속시간은 UTC 끼리 계산하고, **시각을 답할 때만** +9시간 했는가
10. 세션 창이 확정되면 그 구간의 4688 / 4104 / 5145 로 넘어갔는가

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 4634 / 4647 이 속한 Audit Logoff 하위 범주, 두 이벤트의 발생 조건 차이
- SRC-001 — Microsoft Learn, Event 4624: `TargetLogonId` 의 의미와 "같은 컴퓨터의 같은 부팅 구간에서만 유일" 이라는 성질, 4634/4647 과의 상관 방법
- SRC-004 — Eric Zimmerman 문서: EvtxECmd 의 `--inc` 필터와 `Payload` 원본 JSON 컬럼
- 4647 의 EventData 필드 이름이 화면 표시("Subject")와 달리 `Target*` 인 점은 Microsoft 문서의 이벤트 XML 예시로 확인했다. TerminalServices 채널의 21/23/24/25 의미는 Windows 버전에 따라 표현이 다를 수 있으므로 실제 이벤트 화면에서 확인할 것
</content>
