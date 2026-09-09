---
id: FOR-0096
title: "RDP 1149 RemoteConnectionManager: 인증 성공은 로그온 성공이 아니다"
slug: "rdp-remoteconnectionmanager"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["RemoteConnectionManager", "RdpCoreTS", "Param3", "RDP 인증", "RDP-Tcp"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"]
registry_paths: []
event_ids: ["1149", "261", "1148", "1150", "131", "98"]
protocols: ["RDP"]
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path rcm.evtx -FilterXPath '*[System[EventID=1149]]'", "wevtutil qe Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational /f:text", "EvtxECmd.exe -f rcm.evtx --csv out --csvf rcm.csv"]
regex_patterns: ["<Param3>([^<]+)</Param3>"]
wireshark_filters: ["tcp.port == 3389"]
tshark_fields: []
log_fields: ["Param1", "Param2", "Param3"]
file_formats: ["evtx"]
primary_terms: ["RemoteConnectionManager", "1149", "RDP 인증 성공", "rdp 연결 시도"]
keywords: ["1149", "RemoteConnectionManager", "RdpCoreTS", "261", "131", "RDP", "인증 성공", "Param3", "무차별 대입", "brute force", "3389", "원격 데스크톱", "evtx"]
aliases: ["1149", "rdp 연결 시도", "rdp 인증 성공", "rdp 무차별 대입", "rdp 접속 로그 어디", "3389 접속 기록", "rdp 스캔 흔적"]
symptom_keywords: ["1149가 무슨 뜻인지 모르겠다", "1149는 있는데 4624가 없다", "RDP 접속 IP가 비어 있다", "RDP 무차별 대입을 증명해야 한다", "RDP 로그가 세 개나 있어 헷갈린다"]
related: ["FOR-0083", "FOR-0095", "FOR-0084"]
source_ids: ["SRC-025", "SRC-022", "SRC-020"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

1149는 "RDP **인증**이 통과했다"만 말한다. 로그온이 성립했는지, 데스크톱을 실제로 받았는지는 모른다. 그래서 RDP 문제는 항상 **4624 Type 10 / LSM 21 / RCM 1149 세 개를 같이** 놓고 조합으로 읽는다.

## 어떤 문제에서 필요한가

- "RDP 접속 시도가 있었는가" — 성공·실패를 가리기 전 단계
- "1149는 있는데 4624 Type 10이 없다. 접속한 건가?"
- "RDP 무차별 대입을 증명하라"
- "접속 원본 IP를 구하라" — `Param3`
- 4624의 `IpAddress`가 비어 있거나 `-`인데 RDP인 경우

세션 안에서 무슨 일이 있었는지(연결 끊김/재연결/체류 시간)는 LocalSessionManager 전담 글(FOR-0095)이, 로그온 자체의 판정과 Logon ID 피벗은 [FOR-0083](./event-4624-logon.html)이 담당한다.

## 문제에서 처음 볼 단서

1. 첨부에 `RemoteConnectionManager`가 있다 → 1149를 먼저 센다
2. 지문에 "접속 시도", "몇 번 시도했는가" → 261 + 4625 조합
3. 지문에 "성공한 계정" → 1149의 `Param1`
4. 지문에 "공격자 IP" → 1149의 `Param3`
5. `Param3`가 비어 있다 → `RdpCoreTS` 131로 우회

## 30초 절차

```powershell
# 원본: Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx -> rcm.evtx
Get-WinEvent -Path 'C:\case\rcm.evtx' -FilterXPath '*[System[EventID=1149]]' | Format-List
```

`Param1/Param2/Param3`만 표로 뽑는 형태:

```powershell
$rcm = 'C:\case\rcm.evtx'
Get-WinEvent -Path $rcm -FilterXPath '*[System[EventID=1149]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $p = @($x.Event.UserData.EventXML.ChildNodes | ForEach-Object { $_.InnerText })
    [pscustomobject]@{
      TimeUtc = $_.TimeCreated.ToUniversalTime()
      User    = $p[0]
      Domain  = $p[1]
      Address = $p[2]
    }
  } | Sort-Object TimeUtc | Format-Table -AutoSize
```

출력 예시:

```text
TimeUtc              User        Domain  Address
-------              ----        ------  -------
2026-03-14 07:18:41  svc_backup  WIN10   203.0.113.77
2026-03-14 09:12:27  svc_backup  WIN10   203.0.113.77
2026-03-14 11:40:03  Administrator       45.146.164.9
```

세 번째 줄은 도메인이 비어 있다. 로컬 계정 이름을 그대로 던지는 스캐너의 전형적인 모양이다.

## 상세 절차

### 1단계 — 이 채널의 Event ID

| ID | 채널 | 내용 | 요소 |
| --- | --- | --- | --- |
| 261 | RemoteConnectionManager/Operational | 리스너 RDP-Tcp가 연결을 수신 | 연결 자체. 사용자·IP 없음 |
| 1149 | RemoteConnectionManager/Operational | 사용자 인증 성공 | `Param1`=사용자, `Param2`=도메인, `Param3`=원본 주소 |

1149에는 중요한 전제가 하나 더 있다. **NLA(Network Level Authentication)가 요구되는 구성에서만 기록된다.** NLA를 끈 서버에서는 접속이 성공해도 1149가 남지 않는다. 그래서 "1149가 없다"는 로그 삭제의 증거가 아니라 **NLA 미사용 구성의 증거**일 수 있다.

261은 **TCP 연결이 들어왔다**만 말한다. 사용자 정보가 없으므로 IP를 얻을 수 없지만, **개수**가 의미를 갖는다. 261이 수백 건인데 1149가 1건이면 스캔/무차별 대입 후 1회 성공이다.

다음 두 ID는 같은 채널에서 관측되지만, 렌더링 메시지 문구가 OS 빌드에 따라 달라 이 글에서는 의미를 단정하지 않는다. **실제 로그의 메시지를 읽고 판단한다.**

| ID | 다루는 법 |
| --- | --- |
| 1148 | 존재하면 메시지 원문을 그대로 인용하고, 시각만 타임라인에 넣는다 |
| 1150 | 위와 동일. 1149 앞뒤에 붙어 나오는 경우가 있으므로 시간순 정렬해 문맥으로 읽는다 |

### 2단계 — 세 로그가 답하는 질문이 다르다

**이 표가 이 글의 핵심이다.**

| 로그 | 채널 | 대표 ID | 답하는 질문 | 얻는 값 |
| --- | --- | --- | --- | --- |
| Security | `Security` | 4624 (Type 10) | **로그온이 성립했는가** | `TargetLogonId`, 계정, `IpAddress` |
| LocalSessionManager | `...TerminalServices-LocalSessionManager/Operational` | 21, 24, 25 | **세션이 언제 생기고 끊겼는가** | `SessionID`, `Address` |
| RemoteConnectionManager | `...TerminalServices-RemoteConnectionManager/Operational` | 1149, 261 | **인증이 통과했는가 / 연결이 들어왔는가** | `Param1`, `Param3` |

시간 순서는 보통 **261 → 1149 → 4624(Type 10) → 21 → 22**다. 초 단위로 몇 초 안에 몰려 있다.

### 3단계 — 조합 해석표

| 1149 | 4624 T10 | LSM 21 | 해석 | 다음 행동 |
| --- | --- | --- | --- | --- |
| O | O | O | 정상적인 완전 접속 | `TargetLogonId`로 세션 내 활동 추적 |
| O | X | X | **인증만 통과. 세션을 못 받았다** — RDP 접근 권한 없음, 세션 수 제한, 사용자가 즉시 취소 | 4625와 정책 이벤트 확인. "접속했다"고 답하면 안 된다 |
| O | O | X | 세션 채널이 비활성이거나 그 부분만 삭제 | 1102, 채널 활성 여부, `RdpCoreTS` |
| X | O | O | **NLA 미사용 구성**이거나 RCM 채널이 없거나 지워졌다. Type 10은 RDP 경로이므로 접속은 있었다 | LSM `Address`를 원본 IP로 채택 |
| X | X | O | 21만 남았다 — 로그 정리의 흔적 | LSM만으로 타임라인 작성 |
| O | O(다른 IP) | O(또 다른 IP) | 게이트웨이/점프 호스트 경유 | 가장 바깥 공인 IP를 공격자 출처로 |
| 261만 다수 | X | X | 연결은 들어왔으나 인증 실패 | **스캔 또는 무차별 대입**. 4625로 계정 목록 확보 |

`O / X / X`(1149만 있음)를 "RDP 접속 성공"으로 답하는 것이 이 주제에서 가장 자주 나오는 오답이다. 1149는 NLA 단계의 자격증명 검증 결과이며, 그 뒤 세션 생성은 별개의 관문이다.

### 4단계 — Param3가 비어 있을 때

| 상황 | 대응 |
| --- | --- |
| `Param3`가 빈 값 | `RdpCoreTS/Operational` 131의 클라이언트 IP:포트를 쓴다 |
| `Param3`가 사설 IP | RD 게이트웨이/점프 호스트 경유. 그 호스트의 로그를 요청 |
| `Param2`(도메인)가 빈 값 | 로컬 계정으로 직접 인증. 외부 스캐너의 전형 |
| 전체 이벤트가 없음 | 채널 비활성 또는 삭제. pcap `tcp.port == 3389`로 대체 |

`RdpCoreTS`는 `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx`에 있다.

| ID | 내용 | 값 |
| --- | --- | --- |
| 131 | 서버가 클라이언트로부터 새 TCP 연결을 수락 | **클라이언트 IP와 포트** |
| 98 | 전송 계층 연결 관련 이벤트 | 메시지 문구를 실제 로그에서 확인한 뒤 인용한다 |

131은 인증 이전 단계이므로 **실패한 시도의 IP도 남는다.** 무차별 대입의 원본 IP를 세는 데는 1149보다 131이 유용하다. 단 131도 "세션이 열렸다"는 뜻은 아니고 **RDP 서비스에 네트워크로 닿았다**는 뜻일 뿐이다. 이 채널은 구형 OS에는 없고 기본 구성에서 데스크톱 OS 위주로 기록되며, 메시지 표현이 빌드마다 다르다.

### 5단계 — 무차별 대입 탐지

```powershell
$sec = 'C:\case\Security.evtx'
$rcm = 'C:\case\rcm.evtx'

# 1) 실패 로그온을 계정·IP별로 집계
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4625} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ User = $d['TargetUserName']; Ip = $d['IpAddress']; Type = $d['LogonType'] }
  } |
  Group-Object Ip, User | Sort-Object Count -Descending |
  Select-Object -First 10 Count, Name

# 2) 그 IP 로 성공한 1149 가 있는지
Get-WinEvent -Path $rcm -FilterXPath '*[System[EventID=1149]]' |
  Where-Object { $_.Message -match '45\.146\.164\.9' }
```

출력:

```text
Count Name
----- ----
  214 45.146.164.9, Administrator
   96 45.146.164.9, admin
   41 45.146.164.9, sql
    3 192.168.10.24, jhkim
```

무차별 대입의 형태는 **한 IP + 여러 계정 이름 + 4625 대량**이다. 여기에 1149가 한 건 끼어 있으면 "그 계정에서 뚫렸다"가 확정된다.

| 지표 | 무차별 대입 | 정상 사용 |
| --- | --- | --- |
| 4625 건수 | 수십~수천 | 0~수 건(오타) |
| 시도 계정 수 | 여러 개(`admin`, `test`, `sql`) | 1개 |
| 시도 간격 | 수 초 이하로 규칙적 | 불규칙 |
| 261 대비 1149 비율 | 극단적으로 낮음 | 1:1에 가깝다 |
| 4625의 `LogonType` | 3 또는 10 | — |

4625의 `Status`/`SubStatus` 코드 해석은 4625 전담 글(FOR-0084)의 몫이므로, 여기서는 건수 집계까지만 쓴다.

## 출력 필드 해석

1149는 `EventData`가 아니라 **`UserData/EventXML`** 아래에 `Param1..Param3`이라는 이름 없는 순서 기반 요소로 들어간다. 이름이 의미를 말해 주지 않으므로 **순서를 외워야 한다.**

| 요소 | 내용 | 예시 | 주의 |
| --- | --- | --- | --- |
| `Param1` | 사용자 이름 | `svc_backup` | 도메인 접두어 없음 |
| `Param2` | 도메인 | `WIN10` / 빈 값 | 빈 값 = 로컬 계정 직접 인증 |
| `Param3` | 원본 네트워크 주소 | `203.0.113.77` | 빈 값이면 131로 우회 |

렌더링된 Message 문자열에서 뽑을 때는 정규식보다 XML 파싱이 안전하다. Event Viewer의 한글 UI는 요소 이름을 보여주지 않고 문장으로 합쳐 버린다.

시간대는 EVTX `SystemTime` 기준 **UTC**다. Event Viewer는 로컬 시간대로 변환해 표시하므로 두 화면의 숫자가 다르다. 답이 KST면 +9시간을 더한다. 이미지의 시간대 설정은 SYSTEM hive의 `TimeZoneInformation`으로 확정한다([FOR-0054](./system-timezone.html)).

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `Param1` (계정) | 4624 Type 10 | 로그온 성립 여부와 `TargetLogonId` |
| `Param1` | 4625 | 같은 계정에 대한 선행 실패 시도 횟수 |
| `Param3` (IP) | LSM 21 `Address` | IP 일치 여부 → 경유 판정 |
| `Param3` | pcap `ip.addr == <IP> && tcp.port == 3389` | 실제 트래픽과 세션 개수 |
| 1149 시각 | LSM 21/22 | 세션이 실제로 생성됐는지 |
| 261 건수 | `RdpCoreTS` 131 | 실패 시도까지 포함한 원본 IP 목록 |
| 1149 계정 | SAM hive 계정 목록 | 그 계정이 실재하는지, 언제 만들어졌는지 |
| 성공 직후 시각 | 4688 · Sysmon 1 | 접속 후 첫 실행 명령 |

## 흔한 함정

- **1149를 "로그온 성공"으로 읽는 것.** 1149는 인증(자격증명 검증) 단계의 성공이다 → 세션이 생겼는지는 모른다 → 4624 Type 10과 LSM 21이 함께 있어야 "접속 성공"이라고 답한다.
- **1149 건수를 접속 횟수로 세는 것.** 재연결·NLA 재협상으로 한 접속에서 여러 건이 남을 수 있다 → 실제 접속 횟수는 LSM 21/25 개수로 센다.
- **`Param1/Param2/Param3`를 이름으로 조회하려는 것.** 의미 있는 필드 이름이 없다 → 순서(1=사용자, 2=도메인, 3=주소)로 접근한다.
- **`Param3`가 비어 있으면 IP를 포기하는 것.** `RdpCoreTS` 131에 클라이언트 IP:포트가 남는다 → 그 채널을 열거나 pcap/방화벽 로그로 넘어간다.
- **261을 IP 증거로 쓰는 것.** 261에는 원본 주소가 없다 → 건수(스캔 강도)로만 쓴다.
- **1149가 없어서 "RDP 접속이 없었다"고 결론 내리는 것.** 1149는 NLA가 요구되는 구성에서만 남고, 이 채널만 삭제되거나 비활성인 경우도 흔하다 → 4624 Type 10, LSM 21, `RdpCoreTS` 131, 1102를 확인한다.
- **무차별 대입을 1149 개수로 증명하려는 것.** 1149는 성공만 남는다 → 실패 증거는 4625와 261/131이다.
- **`Param2`가 빈 값인 것을 로그 손상으로 보는 것.** 로컬 계정으로 직접 인증하면 정상적으로 빈 값이다 → 오히려 외부 스캐너의 신호로 읽는다.
- **Event Viewer 로컬 시각을 그대로 답하는 것.** 내부 저장은 UTC다 → KST 요구 시 +9시간.

## 교차검증

```powershell
$sec = 'C:\case\Security.evtx'
$rcm = 'C:\case\rcm.evtx'
$lsm = 'C:\case\lsm.evtx'
$core = 'C:\case\rdpcorets.evtx'

# 1) 인증 성공 (계정 + 원본 IP)
Get-WinEvent -Path $rcm -FilterXPath '*[System[EventID=1149]]' | Format-List TimeCreated, Message

# 2) 연결 수신 건수 (스캔 강도)
(Get-WinEvent -Path $rcm -FilterXPath '*[System[EventID=261]]').Count

# 3) 로그온 성립 여부
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s+10' }

# 4) 세션 생성 여부
Get-WinEvent -Path $lsm -FilterXPath '*[System[EventID=21]]'

# 5) 실패 시도까지 포함한 클라이언트 IP
Get-WinEvent -Path $core -FilterXPath '*[System[EventID=131]]' |
  Select-Object -First 20 TimeCreated, Message
```

네 로그의 시각이 몇 초 내에 정렬되면 하나의 접속이다. 261만 있고 나머지가 비어 있는 구간은 실패 시도 구간이다.

## mini walkthrough

```text
문제:
"공격자가 RDP 로 침입에 성공한 계정과 시각을 구하시오.
 첨부: Security.evtx,
       ...RemoteConnectionManager%4Operational.evtx (1149 총 4건)"

1. 첫 시도 (실패):
   1149 만 보고 가장 이른 것을 답했다.
     07:02:15  1149  Param1=Administrator  Param2=(빈 값)  Param3=45.146.164.9
   -> "Administrator, 07:02:15" 로 제출. 오답.

   왜 틀렸나:
   같은 시각의 Security.evtx 를 확인하지 않았다.
     4624 Type 10  : 없음
     4625          : 07:02:15 에 Administrator 실패 1건 (동일 IP)
   즉 인증 단계 이후 세션 생성이 되지 않았고, 오히려 로그온은 실패였다.
   1149 는 "인증 성공"이라 적혀 있어도 그 접속이 성립했음을 보장하지 않는다.

2. 피벗 — 세 로그를 시간순으로 합쳐 보았다.
   06:58:40  261   (연결 수신)            x 412건, 06:58~07:16
   07:02:15  1149  Administrator  45.146.164.9
   07:02:15  4625  Administrator  45.146.164.9  Type 10
   ...
   07:18:41  1149  svc_backup     203.0.113.77
   07:18:44  4624  svc_backup     203.0.113.77  Type 10  LogonId 0x1a2b3c
   07:18:44  21    WIN10\svc_backup  Session 2  203.0.113.77
   07:18:44  22    WIN10\svc_backup  Session 2  203.0.113.77

   -> 1149 + 4624 Type 10 + 21 + 22 가 모두 갖춰진 것은 svc_backup 뿐이다.

3. 무차별 대입 증거 정리:
   4625 집계 -> 45.146.164.9 에서 214건(Administrator), 96건(admin), 41건(sql)
   261 412건 대비 1149 4건 -> 성공률 1% 미만. 스캔/대입 확정.
   단, 뚫린 계정은 이 IP 가 아니라 203.0.113.77 의 svc_backup 이었다.

4. 시간대 변환:
   07:18:44 UTC = 16:18:44 KST (+9h)

정답: 계정 svc_backup, 2026-03-14 07:18:44 UTC (16:18:44 KST)
```

1단계의 오답이 이 글 제목 그대로의 함정이다. **1149 한 건만 보고 답하지 않는다.** 4624 Type 10과 LSM 21이 짝을 이루는 1149만 실제 접속이다.

## 막혔을 때 다음 체크

1. 1149가 여러 건인가 → 4624 Type 10과 LSM 21이 함께 있는 건만 남긴다
2. `Param3`가 비어 있는가 → `RdpCoreTS` 131, 방화벽, pcap `tcp.port == 3389`
3. 1149가 아예 없는가 → 채널 비활성/삭제. 4624 Type 10과 LSM 21로 대체하고 1102를 확인한다
4. 4625가 대량인가 → IP·계정별로 집계해 무차별 대입 여부를 먼저 확정한다
5. 261만 대량인가 → 인증까지 가지 못한 스캔이다. 계정 유출 증거는 아니다
6. IP가 두 개로 갈리는가 → 게이트웨이 경유. 가장 바깥 공인 IP를 출처로 답한다
7. 접속 이후 행위가 필요한가 → 4624의 `TargetLogonId`([FOR-0083](./event-4624-logon.html))로 4688을 엮는다
8. 체류 시간을 물어보는가 → LocalSessionManager의 24/25 쌍이 필요하다

## 출처

- SRC-025 — Microsoft Learn, Remote Desktop Services / Terminal Services 이벤트: RemoteConnectionManager 채널, 1149(사용자 인증 성공)와 261(리스너 연결 수신)
- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 대조에 쓰는 4624/4625/1102의 정의
- SRC-020 — Microsoft Learn, Event 4625: 실패 로그온 집계로 무차별 대입을 판정하는 근거
- 1149는 `UserData/EventXML` 아래 `Param1..Param3` 순서 기반 요소를 쓴다. 요소 표기는 OS 빌드에 따라 다를 수 있으므로 **실제 EVTX의 XML 보기로 확인**한 뒤 파싱한다
- 1148·1150의 렌더링 메시지 문구는 빌드에 따라 달라 이 글에서 의미를 단정하지 않았다. 실제 로그의 Message 원문을 근거로 쓸 것
- `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` 채널은 구형 OS에 없을 수 있고 기본 구성에서 기록 범위가 OS 종류에 따라 다르다. 131은 "서버가 클라이언트의 새 TCP 연결을 수락"으로 확인했으나, **98의 정확한 메시지 문구는 확인하지 못해 단정하지 않았다.** 실제 이벤트의 Message 원문으로 확인할 것
- 1149가 NLA 요구 구성에서만 기록된다는 점은 로그 부재를 해석할 때 결정적이므로 대상 서버의 NLA 설정(보안 계층)을 함께 확인할 것
