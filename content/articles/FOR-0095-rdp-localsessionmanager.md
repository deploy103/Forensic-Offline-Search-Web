---
id: FOR-0095
title: "RDP 세션 로그 LocalSessionManager: 21/24/25로 접속 구간 나누기"
slug: "rdp-localsessionmanager"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["LocalSessionManager", "TerminalServices", "RDP 세션", "Source Network Address", "SessionID"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", "%SystemRoot%\\System32\\winevt\\Logs"]
registry_paths: []
event_ids: ["21", "22", "23", "24", "25", "39", "40"]
protocols: ["RDP"]
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path lsm.evtx -FilterXPath '*[System[EventID=21]]'", "wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /f:text", "EvtxECmd.exe -f lsm.evtx --csv out --csvf lsm.csv"]
regex_patterns: ["<Address>([^<]+)</Address>", "<SessionID>(\\d+)</SessionID>"]
wireshark_filters: []
tshark_fields: []
log_fields: ["User", "SessionID", "Address", "TargetSession", "Source", "Reason"]
file_formats: ["evtx"]
primary_terms: ["LocalSessionManager", "RDP 세션 로그", "rdp 접속 상세"]
keywords: ["LocalSessionManager", "TerminalServices", "RDP", "21", "24", "25", "세션 로그온", "세션 연결 끊김", "재연결", "Source Network Address", "SessionID", "원격 데스크톱", "evtx"]
aliases: ["rdp 접속 상세", "rdp 세션 로그", "원격 데스크톱 로그", "이벤트 21 24 25", "rdp 언제 끊겼나", "rdp 클라이언트 ip", "터미널 서비스 로그"]
symptom_keywords: ["RDP로 접속한 IP를 알고 싶다", "RDP 세션이 언제 끊겼는지", "4624에 IP가 안 나온다", "RDP 접속 시간을 계산해야 한다", "세션 ID가 뭔지 모르겠다", "재접속 흔적을 찾고 싶다"]
related: ["FOR-0083", "FOR-0096", "FOR-0104"]
source_ids: ["SRC-025", "SRC-022", "SRC-001"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`은 **RDP 세션의 생애주기**를 기록한다. 21(로그온) → 24(연결 끊김) → 25(재연결) → 23(로그오프) 순서를 세션 ID로 묶으면 공격자가 실제로 화면 앞에 앉아 있던 구간이 그대로 나온다.

## 어떤 문제에서 필요한가

- "RDP로 접속한 클라이언트 IP는 무엇인가" — 4624의 `IpAddress`가 비어 있거나 신뢰가 안 갈 때
- "공격자가 원격 데스크톱에 몇 시부터 몇 시까지 붙어 있었나" (세션 지속시간)
- "중간에 끊고 다시 붙었는가" — 24/25 쌍
- "콘솔 로그인인가 원격인가" — `Address`가 `LOCAL`인지 IP인지
- "같은 계정으로 다른 사람이 밀고 들어왔는가" — 39
- 4624 Type 10과 IP가 다르다 → 점프 호스트/프록시 경유 판정

성공 로그온 자체의 판정과 `TargetLogonId` 피벗은 [FOR-0083](./event-4624-logon.html)이 담당한다. 이 글은 **그 세션 안에서 무슨 일이 있었는지**를 다룬다.

## 문제에서 처음 볼 단서

1. 첨부 파일명에 `TerminalServices-LocalSessionManager`가 보인다 → RDP 문제 확정
2. 문제 지문의 "원격 데스크톱", "3389", "원격 접속 시간" → 이 로그
3. 4624에서 `LogonType = 10`을 이미 찾았다 → 같은 시각의 21을 대조
4. "접속 시간을 구하라"(지속시간) → 21/25와 23/24의 시각 차이
5. 세션 ID가 문제에 주어졌다 → `SessionID`로 바로 필터

## 30초 절차

원본 파일명이 길어 짧게 복사해 두고 시작한다.

```powershell
# 원본: Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx -> lsm.evtx
Get-WinEvent -Path 'C:\case\lsm.evtx' -FilterXPath '*[System[EventID=21]]' | Format-List
```

세션 흐름 전체를 한 표로 보는 형태:

```powershell
$lsm = 'C:\case\lsm.evtx'
Get-WinEvent -Path $lsm |
  Where-Object { $_.Id -in 21,22,23,24,25,39,40 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    foreach ($n in $x.Event.UserData.EventXML.ChildNodes) { $d[$n.LocalName] = $n.InnerText }
    [pscustomobject]@{
      TimeUtc = $_.TimeCreated.ToUniversalTime()
      Id      = $_.Id
      User    = $d['User']
      Session = $d['SessionID']
      Address = $d['Address']
    }
  } | Sort-Object TimeUtc | Format-Table -AutoSize
```

출력 예시:

```text
TimeUtc              Id User              Session Address
-------              -- ----              ------- -------
2026-03-14 07:18:44  21 WIN10\svc_backup  2       203.0.113.77
2026-03-14 07:18:44  22 WIN10\svc_backup  2       203.0.113.77
2026-03-14 07:41:02  24 WIN10\svc_backup  2       203.0.113.77
2026-03-14 09:12:30  25 WIN10\svc_backup  2       203.0.113.77
2026-03-14 09:58:11  23 WIN10\svc_backup  2
```

이 다섯 줄이 곧 답이다. 07:18~07:41 작업, 1시간 31분 공백, 09:12~09:58 재작업.

## 상세 절차

### 1단계 — Event ID 표를 먼저 외운다

| ID | 렌더링 메시지 요지 | 주요 요소 | 포렌식 의미 |
| --- | --- | --- | --- |
| 21 | Session logon succeeded | `User`, `SessionID`, `Address` | **세션 시작. 클라이언트 IP가 여기 있다** |
| 22 | Shell start notification received | `User`, `SessionID`, `Address` | explorer.exe 등 셸이 떴다 = 실제 데스크톱 사용 |
| 23 | Session logoff succeeded | `User`, `SessionID` | 정상 로그오프. 세션 완전 종료 |
| 24 | Session has been disconnected | `User`, `SessionID`, `Address` | **창만 닫음. 세션과 프로세스는 살아 있다** |
| 25 | Session reconnection succeeded | `User`, `SessionID`, `Address` | 끊긴 세션에 다시 붙었다 |
| 39 | Session X has been disconnected by session Y | `TargetSession`, `Source` | X와 Y가 같으면 **사용자가 메뉴에서 "연결 끊기"를 선택**, 다르면 **다른 세션이 강제로 끊음**(동시접속 충돌) |
| 40 | Session X has been disconnected, reason code Z | `Session`, `Reason` | 끊김 원인 코드. 24와 짝을 이뤄 나온다 |

39는 두 세션 번호를 비교해야 의미가 갈린다. 같은 번호면 사용자가 클라이언트 창을 닫은 것이 아니라 **메뉴로 정상 연결 끊기**를 한 것이고, 번호가 다르면 다른 세션(관리자 또는 같은 계정의 다른 접속)이 이 세션을 밀어낸 것이다. 후자는 계정 공유·탈취 신호다.

핵심은 **23과 24의 차이**다. 24는 로그오프가 아니다. 세션은 disconnected 상태로 남고, 그 안에서 돌던 프로세스(백도어, 다운로드, 압축)는 계속 실행된다. 24 이후 25 없이 23이 나오면 원격에서 재접속하지 않고 세션이 정리된 것이다.

### 2단계 — 24/25 쌍으로 작업 구간을 나눈다

공격자는 RDP 창을 닫아 두고 몇 시간 뒤 다시 붙는다. 그러면 4624는 **한 건**(또는 재연결 시 추가 1건)뿐이지만 실제 활동은 두 덩어리다.

| 구간 | 시작 이벤트 | 종료 이벤트 | 이 구간에서 찾을 것 |
| --- | --- | --- | --- |
| 1차 작업 | 21 (또는 25) | 24 | 초기 정찰, 도구 다운로드 |
| 유휴 | 24 | 25 | 세션은 살아 있음. 이 구간의 프로세스 생성은 **백그라운드 작업** |
| 2차 작업 | 25 | 24 또는 23 | 데이터 수집, 유출 |

유휴 구간에 4688/Sysmon 1이 찍혀 있으면 사람이 조작한 것이 아니라 예약 작업이나 남겨 둔 스크립트다. 이 구분이 "공격자가 직접 한 행위"와 "자동화된 행위"를 갈라 준다.

### 3단계 — Address 값 판정

| `Address` 값 | 판정 |
| --- | --- |
| 공인 IP (`203.0.113.77`) | 외부에서 직접 RDP. 3389 노출 |
| 사설 IP (`192.168.x`, `10.x`, `172.16-31.x`) | **내부 측면 이동**. 그 IP의 호스트를 다음 조사 대상으로 |
| `LOCAL` | 콘솔 세션. 물리 키보드 또는 하이퍼바이저 콘솔. 원격이 아니다 |
| `::1`, `127.0.0.1` | 로컬에서 자기 자신에게 RDP. 터널링(포트 포워딩) 의심 |
| 빈 값 / 없음 | 23처럼 주소 요소가 없는 이벤트이거나, 세션 재구성 과정 이벤트 |

`LOCAL`을 IP가 지워진 것으로 오해하는 실수가 잦다. 콘솔 로그인은 원래 `LOCAL`이다.

### 4단계 — 세션 지속시간 계산

```powershell
$lsm = 'C:\case\lsm.evtx'
$ev = Get-WinEvent -Path $lsm | Where-Object { $_.Id -in 21,23,24,25 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    foreach ($n in $x.Event.UserData.EventXML.ChildNodes) { $d[$n.LocalName] = $n.InnerText }
    [pscustomobject]@{ T = $_.TimeCreated.ToUniversalTime(); Id = $_.Id; S = $d['SessionID'] }
  } | Sort-Object T

# 세션 ID 2 의 활성 구간만 뽑아 합산
$open = $null; $total = [timespan]::Zero
foreach ($e in $ev | Where-Object { $_.S -eq '2' }) {
  if ($e.Id -in 21,25) { $open = $e.T }
  elseif ($e.Id -in 23,24 -and $open) { $total += ($e.T - $open); $open = $null }
}
"활성 시간 합계: $total"
```

출력:

```text
활성 시간 합계: 01:08:37
```

문제가 "총 접속 시간"을 물으면 **24로 끊긴 유휴 구간을 빼야** 이 값이 나온다. 21부터 23까지를 그냥 뺄셈하면 2시간 39분이 되어 틀린다.

### 5단계 — 4624 Type 10과 대조

```powershell
# Security.evtx 의 Type 10 만
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx'; Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s+10' } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUtc = $_.TimeCreated.ToUniversalTime()
      User    = $d['TargetUserName']
      Ip      = $d['IpAddress']
      LogonId = $d['TargetLogonId']
      Session = $d['ProcessName']
    }
  } | Format-Table -AutoSize
```

| 4624 Type 10 `IpAddress` | LSM 21 `Address` | 해석 |
| --- | --- | --- |
| 동일한 공인 IP | 동일 | 그 IP에서 직접 접속. 단순 |
| `192.168.10.24` | `192.168.10.24` | 내부 호스트 경유. 그 호스트도 침해됐을 가능성 |
| 사설 IP | **다른 공인 IP** | RDP 게이트웨이/점프 호스트 경유. 진짜 출처는 LSM 쪽 |
| 값 있음 | `LOCAL` | Type 10인데 콘솔? 시각이 다른 별개 세션을 잘못 짝지은 것 |
| 값 있음 | 21 자체가 없음 | 로그가 지워졌거나 채널이 비활성. 1102/104 확인 |

두 로그의 IP가 다르면 **둘 다 답이 아니라 경로**다. 지문이 "공격자의 IP"를 물으면 보통 가장 바깥(공인) IP를 원한다.

## 출력 필드 해석

이 채널의 이벤트는 `EventData`가 아니라 **`UserData/EventXML`** 구조를 쓴다. Event Viewer의 "자세히 > XML 보기"에서 실제 요소 이름을 확인하고 그 이름으로 파싱해야 한다.

| 요소 | 나타나는 ID | 의미 |
| --- | --- | --- |
| `User` | 21, 22, 23, 24, 25 | `DOMAIN\user` 또는 `HOSTNAME\user` 형태 |
| `SessionID` | 21, 22, 23, 24, 25 | 터미널 세션 번호. 4624의 필드가 아니라 **세션 번호**다 |
| `Address` | 21, 22, 24, 25 | 렌더링 메시지의 "Source Network Address". 클라이언트 IP 또는 `LOCAL` |
| `TargetSession` | 39 | 끊긴 쪽 세션 번호 |
| `Source` | 39 | 끊은 쪽 세션 번호 |
| `Session` | 40 | 대상 세션 번호 |
| `Reason` | 40 | 끊김 이유 코드(정수) |

`SessionID`는 Sysmon 1의 `TerminalSessionId`와 같은 축이다. 세션 2에서 실행된 프로세스를 찾으려면 Sysmon 1에서 `TerminalSessionId=2`로 필터한다. 콘솔 세션은 보통 1(구형 OS는 0)이므로, `TerminalSessionId >= 2`인 프로세스는 원격 세션에서 돌았다고 볼 여지가 크다.

40의 `Reason` 코드는 값별 의미가 환경·버전에 따라 갈리고 정상 종료에도 값이 붙는다. **코드 숫자로 원인을 단정하지 말고** 24/25/23 순서로 판단한다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `Address` (클라이언트 IP) | 4624 Type 10 / 4625 | 같은 IP의 성공·실패 로그온 전체 |
| `Address` | pcap `ip.addr == <IP> && tcp.port == 3389` | 실제 RDP 트래픽, 세션 시작 시각 |
| `User` | 4624의 `TargetLogonId` → 4688 | 그 세션에서 실행한 명령 |
| `SessionID` | Sysmon 1의 `TerminalSessionId` | 원격 세션에서 생성된 프로세스만 추림 |
| 21 시각 | `RemoteConnectionManager` 1149 | 인증 성공 시각과 원본 IP 재확인 |
| 24/25 구간 | 4688 · Sysmon 1 타임스탬프 | 사람 조작 vs 백그라운드 자동 실행 구분 |
| 23 시각 | 4634 / 4647 | 세션 종료의 Security 측 대응 이벤트 |
| 24 / 25 시각 | Security 4779 / 4778 | 세션 연결 끊김·재연결의 Security 측 대응 이벤트(`SessionName`, `ClientAddress`) |
| 21 직후 시각 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 시각에 만들어진 파일(도구 업로드) |
| 접속 사용자 프로필 | `HKCU\Software\Microsoft\Terminal Server Client\Servers` | 반대 방향(이 호스트에서 나간 RDP) 흔적 |

## 흔한 함정

- **24를 로그오프로 읽는 것.** 24는 disconnected이며 세션과 프로세스가 살아 있다 → "접속 종료 시각"을 24로 답하면 틀린다 → 정상 종료는 23(그리고 Security 4634/4647)으로 확인한다.
- **21부터 23까지를 그대로 접속 시간으로 계산하는 것.** 중간의 24~25 유휴 구간이 포함되어 실제 조작 시간보다 크게 나온다 → 24/25 쌍을 빼고 활성 구간만 합산한다.
- **`Address = LOCAL`을 "IP가 지워졌다"로 보는 것.** 콘솔 세션의 정상 값이다 → 원격이 아니라는 **판정 근거**로 쓴다.
- **`EventData`로 파싱하려다 빈 값이 나오는 것.** 이 채널은 `UserData/EventXML`이다 → XML 보기로 요소 이름을 확인하고 `UserData` 경로로 접근한다.
- **`SessionID`를 Logon ID와 혼동하는 것.** `SessionID`는 `2` 같은 작은 정수, Logon ID는 `0x1a2b3c` 형태의 16진수다 → 세션 간 피벗은 `SessionID`, Security 이벤트 간 피벗은 `TargetLogonId`로 한다.
- **로그가 없어서 "RDP 접속이 없었다"고 결론 내리는 것.** 이 채널은 크기가 작아 빨리 순환하고, 공격자가 개별 채널만 지우기도 한다 → `RemoteConnectionManager` 1149, `RdpCoreTS`, 4624 Type 10, 방화벽/pcap으로 교차확인한다.
- **Event Viewer의 로컬 시각을 그대로 답하는 것.** EVTX의 `SystemTime`은 UTC이고 Event Viewer는 로컬 시간대로 변환해 보여준다 → 답이 KST면 UTC +9시간. 이미지의 시간대는 SYSTEM hive의 `TimeZoneInformation`으로 확정한다([FOR-0054](./system-timezone.html)).
- **39의 두 세션 번호를 비교하지 않는 것.** 번호가 같으면 사용자가 메뉴로 끊은 것이고 다르면 다른 세션이 밀어낸 것이다 → 번호가 다를 때만 동시접속 충돌(계정 공유·탈취)로 읽고, 두 세션의 `Address`를 모두 확인한다.
- **여러 사용자가 있는 서버에서 세션을 섞는 것.** 같은 시간대에 여러 `SessionID`가 병렬로 돈다 → 항상 `SessionID` + `User`로 묶은 뒤 시간순으로 읽는다.

## 교차검증

```powershell
$lsm = 'C:\case\lsm.evtx'
$rcm = 'C:\case\rcm.evtx'      # RemoteConnectionManager%4Operational.evtx
$sec = 'C:\case\Security.evtx'

# 1) LSM 21 — 세션 시작과 클라이언트 IP
Get-WinEvent -Path $lsm -FilterXPath '*[System[EventID=21]]' | Format-List TimeCreated, Message

# 2) RCM 1149 — 인증 성공 (같은 IP 인지)
Get-WinEvent -Path $rcm -FilterXPath '*[System[EventID=1149]]' | Format-List TimeCreated, Message

# 3) Security 4624 Type 10 — Logon ID 확보
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s+10' }

# 4) Security 4634/4647 — 23 과 짝이 맞는지
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4634,4647}

# 5) 로그 삭제 흔적
Get-WinEvent -FilterHashtable @{Path=$sec; Id=1102}
```

세 로그의 시각이 초 단위로 일치하는지 본다. 1149는 21보다 **앞서거나 같다**(인증이 세션 생성보다 먼저). 순서가 뒤바뀌어 보이면 서로 다른 접속 시도를 짝지은 것이다.

## mini walkthrough

```text
문제:
"공격자가 RDP로 접속해 있던 총 시간(분)과 클라이언트 IP를 구하시오.
 첨부: Security.evtx,
       Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"

1. 첫 시도 (실패):
   Security.evtx 에서 4624 Type 10 을 찾아 시각을 뺐다.
     4624 Type 10  2026-03-14 07:18:44Z  svc_backup  203.0.113.77
     4634          2026-03-14 09:58:11Z  (같은 LogonId)
   -> 09:58:11 - 07:18:44 = 159분 이라고 답했다. 오답.

   왜 틀렸나:
   4624/4634 는 "세션이 존재한 구간"이다. 화면이 연결돼 있던 구간이 아니다.
   RDP 창을 닫아도(24) 세션은 유지되므로 4634 는 그때 나오지 않는다.

2. 피벗 — LocalSessionManager 를 열었다.
   Get-WinEvent -Path 'C:\case\lsm.evtx' |
     Where-Object { $_.Id -in 21,22,23,24,25,39,40 }

   07:18:44  21  WIN10\svc_backup  Session 2  203.0.113.77
   07:18:44  22  WIN10\svc_backup  Session 2  203.0.113.77
   07:41:02  24  WIN10\svc_backup  Session 2  203.0.113.77   <- 창 닫음
   09:12:30  25  WIN10\svc_backup  Session 2  203.0.113.77   <- 재연결
   09:58:11  23  WIN10\svc_backup  Session 2

   활성 구간 = (07:41:02 - 07:18:44) + (09:58:11 - 09:12:30)
             = 22분 18초 + 45분 41초 = 68분 (01:08:37)

3. 유휴 구간(07:41~09:12)에 무엇이 있었나 — Sysmon 1 대조:
   08:05:12  C:\Windows\System32\schtasks.exe  (TerminalSessionId=2)
   -> 세션은 살아 있었고 예약 작업이 돌았다. 사람이 앉아 있진 않았다.
      "총 접속 시간"이 활성 시간을 뜻한다는 근거가 된다.

4. IP 교차검증 — RemoteConnectionManager 1149:
   07:18:41  1149  Param1=svc_backup  Param2=WIN10  Param3=203.0.113.77
   -> 21 보다 3초 앞선다. 인증 -> 세션 생성 순서로 정합.

5. 시간대 확인:
   EVTX SystemTime 은 UTC. SYSTEM hive TimeZoneInformation = Korea Standard Time.
   지문이 KST 를 요구하면 16:18:44 ~ 18:58:11 (+9h).

정답: 클라이언트 IP 203.0.113.77, 활성 접속 시간 68분
```

1단계의 오답이 이 글의 존재 이유다. **4634는 24를 모른다.** Security 로그만으로 RDP 체류 시간을 답하면 거의 항상 과대 계산된다.

## 막혔을 때 다음 체크

1. 21이 하나도 없는가 → 채널이 비활성이거나 지워졌다. `RemoteConnectionManager` 1149와 `RdpCoreTS` 131로 우회
2. `Address`가 전부 `LOCAL`인가 → 원격 접속이 아니라 콘솔/VM 콘솔 작업이다. 문제의 전제를 다시 읽는다
3. 21은 있는데 22가 없는가 → 셸이 뜨지 못한 세션. 접속 실패에 가깝다
4. 같은 `SessionID`가 여러 사용자에게 걸쳐 있는가 → 세션 번호는 재사용된다. `User` + 시각으로 구간을 잘라 본다
5. 39가 있는가 → 동시 접속 충돌. 두 세션의 `Address`를 모두 답 후보로 남긴다
6. 시각 계산이 안 맞는가 → UTC 기준으로 다시 계산하고, KST 요구 시 +9시간
7. 세션 내부 행위가 필요한가 → 4624의 `TargetLogonId`([FOR-0083](./event-4624-logon.html))로 4688/5145를 엮는다
8. IP가 두 개로 갈리는가 → 점프 호스트 경유다. 그 중간 호스트의 EVTX를 요청하거나 pcap으로 확인

## 출처

- SRC-025 — Microsoft Learn, Remote Desktop Services / Terminal Services 이벤트: LocalSessionManager 채널의 21/22/23/24/25/39/40 의미
- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 대조에 쓰는 4634/4647/1102의 정의
- SRC-001 — Microsoft Learn, Event 4624: Logon Type 10과 `IpAddress` 필드 정의
- 이 채널은 `EventData`가 아닌 `UserData/EventXML` 구조를 쓴다. `Address`·`SessionID`·`TargetSession`·`Source`·`Reason` 요소 이름은 OS 버전에 따라 표기가 다를 수 있으므로 **실제 EVTX의 XML 보기로 확인한 뒤** 파싱 스크립트를 확정할 것
- Event 40의 `Reason` 코드별 의미는 값이 재사용되고 버전 차이가 커서 이 글에서는 단정하지 않았다. 코드 해석이 필요하면 대상 OS 문서에서 직접 확인할 것
