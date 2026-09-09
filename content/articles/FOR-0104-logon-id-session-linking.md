---
id: FOR-0104
title: "Logon ID로 세션 전체 조립하기: TargetLogonId·SubjectLogonId 조인 절차"
slug: "logon-id-session-linking"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Logon ID", "TargetLogonId", "SubjectLogonId", "TargetLinkedLogonId", "Security.evtx", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]
registry_paths: []
event_ids: []
protocols: []
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "sqlite3", "Event Viewer"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --csv 'C:\\case\\out' --csvf sec.csv", "Get-WinEvent -Path 'C:\\case\\Security.evtx' -Oldest -FilterXPath \"*[EventData[Data='0x1a2b3c']]\""]
regex_patterns: ["0x[0-9a-fA-F]{1,16}", "\"(Target|Subject)LogonId\":\\s*\"?(0x[0-9a-fA-F]+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["TargetLogonId", "SubjectLogonId", "TargetLinkedLogonId", "LogonGuid", "TargetUserName", "SubjectUserName", "LogonType", "ElevatedToken"]
file_formats: ["evtx", "csv"]
primary_terms: ["Logon ID 세션 연결", "세션 추적", "LogonId 조인"]
keywords: ["Logon ID", "TargetLogonId", "SubjectLogonId", "TargetLinkedLogonId", "세션", "session", "조인", "join", "4634", "4647", "UAC 분리 토큰", "0x3e7", "LogonGuid"]
aliases: ["logon id 추적", "세션 묶기", "세션 전체 활동", "로그온 아이디로 찾기", "TargetLogonId SubjectLogonId 차이", "세션 시작 종료", "0x3e7 제외"]
symptom_keywords: ["로그인 후 무엇을 했는지 알고 싶다", "세션별로 정리하고 싶다", "LogonId가 이벤트마다 필드가 다르다", "16진수 표기가 달라 검색이 안 된다", "세션이 언제 끝났는지 모르겠다", "관리자 승격 세션을 잇고 싶다"]
related: ["FOR-0083", "FOR-0105", "FOR-0107"]
source_ids: ["SRC-001", "SRC-022", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Logon ID 조인은 **필드 이름이 이벤트마다 `TargetLogonId` 인지 `SubjectLogonId` 인지 다르다는 것**과 **16진수 표기를 정규화해야 한다는 것** 두 가지에서 실패하며, 이 둘을 표와 스크립트로 고정한 뒤 `4624`(시작)~`4634`/`4647`(종료) 시각 구간으로 한정하면 세션별 활동표가 기계적으로 만들어진다.

## 어떤 문제에서 필요한가

- "공격자가 로그인한 뒤 무엇을 했는가" — 답이 이벤트 하나가 아니라 활동 목록인 문제
- 여러 사용자가 동시에 붙어 있어 어느 행위가 누구의 것인지 배정해야 하는 문제
- 관리자로 승격한 세션과 원래 세션을 이어야 하는 문제 (UAC 분리 토큰)
- 세션이 유지된 시간(체류 시간)을 근거와 함께 답해야 하는 문제
- 4688에는 계정 이름이 있는데 그 계정이 **어디서 접속했는지**를 알아야 하는 문제 (역방향 조인)

Logon Type과 `TargetLogonId` 의 개념은 [FOR-0083](./event-4624-logon.html)에 있다. **이 글은 그 개념을 실제로 조인해서 표로 만드는 절차 자체**를 다룬다.

## 문제에서 처음 볼 단서

1. 4624를 하나 특정했다 → 그 `TargetLogonId` 가 이후 모든 작업의 키다
2. 4688을 하나 특정했다 → 그 `SubjectLogonId` 로 4624를 역추적해 IP와 접속 방식을 얻는다
3. 5145로 파일 접근을 찾았다 → `SubjectLogonId` 로 어느 세션이 접근했는지 확정
4. 4672가 있다 → 그 `SubjectLogonId` 가 관리자 권한 세션이다
5. 4776만 있고 4624가 없다 → **4776에는 Logon ID가 없다.** 계정·`Workstation`·시각으로만 엮어야 한다

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
```

CSV가 나오면 세션 ID 하나를 고정하고 payload 전체를 문자열로 긁는다. Logon ID는 어느 필드에 들어 있든 **같은 문자열**이므로 이것이 가장 빠르다.

```powershell
$sid = '0x1a2b3c'
Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Payload -match $sid } |
  Sort-Object { [int64]$_.EventRecordId } |
  Format-Table EventRecordId, TimeCreated, EventId, UserName, MapDescription
```

단, 이 방법은 `0x1a2b3c` 와 `0x001A2B3C` 를 같은 값으로 보지 못한다. 정확한 조인은 아래 2단계의 정규화를 거친다.

## 상세 절차

### 1단계 — 어느 이벤트의 어느 필드인가 (이 표가 절반이다)

같은 세션 ID가 이벤트에 따라 `Target*` 로도 `Subject*` 로도 들어간다. 이름을 헷갈리면 조인이 통째로 비어 나온다.

| Event ID | 의미 | 세션 ID가 들어가는 필드 | 그 필드가 가리키는 것 |
| --- | --- | --- | --- |
| 4624 | 로그온 성공 | **`TargetLogonId`** | **새로 만들어진 세션** (조인의 기준값) |
| 4624 | 로그온 성공 | `SubjectLogonId` | 이 로그온을 **요청한** 주체. 보통 `0x3e7`(SYSTEM) |
| 4624 | 로그온 성공 | `TargetLinkedLogonId` | UAC 분리 토큰의 **짝 세션** |
| 4634 | 로그오프 (세션 종료) | **`TargetLogonId`** | 끝난 세션 |
| 4647 | 사용자가 직접 로그오프 | **`TargetLogonId`** | 끝난 세션 |
| 4672 | 특수 권한 부여 | **`SubjectLogonId`** | 권한을 받은 세션 |
| 4688 | 프로세스 생성 | **`SubjectLogonId`** | 프로세스를 만든 세션 |
| 4689 | 프로세스 종료 | **`SubjectLogonId`** | 프로세스를 끝낸 세션 |
| 4648 | 명시적 자격증명 로그온 시도 | **`SubjectLogonId`** | 시도한 쪽 세션 |
| 5140 | 네트워크 공유 접근 | **`SubjectLogonId`** | 접근한 세션 |
| 5145 | 공유 객체 접근 권한 검사 | **`SubjectLogonId`** | 접근한 세션 |
| 4625 | 로그온 실패 | **없음** (`SubjectLogonId` 는 시도한 프로세스의 것) | 실패했으므로 세션이 만들어지지 않았다 |
| 4776 | NTLM 자격증명 검증 | **없음** | 계정 + `Workstation` + 시각으로만 연결 |
| 4768 / 4769 | Kerberos 티켓 요청 | **없음** | 계정 + `IpAddress` + 시각으로만 연결 |
| Sysmon 1 | 프로세스 생성 | `LogonId` (+ `LogonGuid`) | Sysmon 채널의 같은 세션 |

정리하면 이렇게 외운다.

```text
4624 / 4634 / 4647  -> Target   (세션 자체가 주인공)
그 밖의 거의 전부    -> Subject  (그 세션이 행위자)
4625 / 4776 / 4768 / 4769 -> 없음 (계정·IP·시각으로 엮는다)
```

### 2단계 — 16진수 표기 정규화

EVTX 원본은 보통 `0x1a2b3c` 처럼 소문자·선행 0 없이 쓰지만, 도구·엑셀·문제 지문에서는 `0x001A2B3C` `0X1A2B3C` `1a2b3c` 가 섞여 나온다. **문자열 비교로 조인하면 여기서 조용히 실패한다.**

| 표기 | 같은 값인가 | 문자열 비교 결과 |
| --- | --- | --- |
| `0x1a2b3c` | 기준 | — |
| `0x1A2B3C` | 같다 | 대소문자 차이로 불일치 |
| `0x001A2B3C` | 같다 | 선행 0 때문에 불일치 |
| `1a2b3c` | 같다 | `0x` 없어서 불일치 |
| `1715004` (10진수) | 같다 | 완전히 다른 문자열 |

정규화는 **정수로 변환**하는 것이 유일하게 안전하다.

```powershell
function Get-LogonIdValue {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $t = $Text.Trim() -replace '^0[xX]', ''
  try { return [Convert]::ToUInt64($t, 16) } catch { return $null }
}

Get-LogonIdValue '0x1a2b3c'    # 1715004
Get-LogonIdValue '0x001A2B3C'  # 1715004
Get-LogonIdValue '1a2b3c'      # 1715004
```

정규화한 뒤 표준 표기로 되돌려 표에 쓴다.

```powershell
'0x{0:x}' -f 1715004   # 0x1a2b3c
```

### 3단계 — 예약 세션 ID 제외

세 개는 시스템 세션이고, 이것을 조인 키로 쓰면 수만 행이 한 세션으로 뭉친다.

| 값 | 세션 | 조치 |
| --- | --- | --- |
| `0x3e7` | SYSTEM | 제외 |
| `0x3e5` | LOCAL SERVICE | 제외 |
| `0x3e4` | NETWORK SERVICE | 제외 |
| `0x0` | 세션 없음 (실패 로그온 등) | 제외 |

```powershell
$reserved = @('0x3e7','0x3e5','0x3e4','0x0')
# 정규화 후 비교하려면 정수 집합으로
$reservedInt = $reserved | ForEach-Object { Get-LogonIdValue $_ }
```

`0x3e7` 을 제외하면 안 되는 경우가 하나 있다. **SYSTEM 권한으로 실행된 악성 프로세스**를 볼 때는 `SubjectLogonId = 0x3e7` 인 4688이 오히려 표적이다. 이때는 세션 조인 대신 프로세스 계보로 접근한다(FOR-0105).

### 4단계 — 세션 목록부터 만든다

조인 전에 "세션이 몇 개이고 각각 누구의 것인가"를 먼저 확정한다.

```powershell
# 세션 인벤토리: 4624 에서 사람이 쓴 세션만 뽑는다
$sessions = Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4624)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      RecordId = $_.RecordId
      TimeUTC  = $x.Event.System.TimeCreated.SystemTime
      LogonId  = $d['TargetLogonId']
      Linked   = $d['TargetLinkedLogonId']
      User     = $d['TargetUserName']
      Domain   = $d['TargetDomainName']
      Type     = $d['LogonType']
      Ip       = $d['IpAddress']
      Wks      = $d['WorkstationName']
      Elevated = $d['ElevatedToken']
    }
  } |
  Where-Object {
    $_.User -notmatch '\$$' -and
    $_.LogonId -notin @('0x3e7','0x3e5','0x3e4','0x0')
  }

$sessions | Format-Table TimeUTC, LogonId, User, Type, Ip, Wks, Elevated -AutoSize
```

출력 예시:

```text
TimeUTC                       LogonId   User        Type Ip             Wks       Elevated
2026-03-14T07:19:02.4718235Z  0x1a2b3c  svc_backup  10   203.0.113.77   KALI      %%1842
2026-03-14T07:19:02.5011980Z  0x1a2b41  svc_backup  10   203.0.113.77   KALI      %%1843
2026-03-14T09:02:11.1120044Z  0x2f4e10  jhkim       2    -             -          %%1843
```

`%%1842` 는 상승된 토큰(Yes), `%%1843` 은 아님(No)이다. 첫 두 행은 **같은 로그온의 분리 토큰 쌍**이다 — 5단계에서 잇는다.

### 5단계 — 세션 시작~종료 구간 확정

```powershell
# 종료 이벤트(4634/4647)를 LogonId 로 붙인다
$logoffs = Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4634 or EventID=4647)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $x.Event.System.TimeCreated.SystemTime
      LogonId = $d['TargetLogonId']
      EventId = $_.Id
    }
  }

# 정규화한 정수를 키로 하는 해시테이블에 종료 이벤트를 담는다
$endMap = @{}
foreach ($l in $logoffs) {
  $k = Get-LogonIdValue $l.LogonId
  if ($null -ne $k -and -not $endMap.ContainsKey($k)) { $endMap[$k] = $l }
}

$sessions | ForEach-Object {
  $k = Get-LogonIdValue $_.LogonId
  $e = $endMap[$k]
  $endTime = '(no logoff)'
  $endId   = ''
  if ($e) { $endTime = $e.TimeUTC; $endId = $e.EventId }
  [pscustomobject]@{
    LogonId  = $_.LogonId
    User     = $_.User
    Type     = $_.Type
    StartUTC = $_.TimeUTC
    EndUTC   = $endTime
    EndEvent = $endId
  }
} | Format-Table -AutoSize
```

| 관찰 | 해석 |
| --- | --- |
| 4634와 4647이 모두 있다 | 사용자가 로그오프를 눌렀고(4647) 세션이 실제로 끝났다(4634) |
| 4634만 있다 | 세션이 끊겼다. RDP 연결 종료·타임아웃·강제 종료 |
| 종료 이벤트가 없다 | 세션이 **이미지 획득 시각까지 살아 있었다**, 또는 로그가 그 지점에서 끊겼다 |
| 4634가 로그온보다 앞선 시각 | 다른 세션의 것을 잘못 붙였다. 정규화·중복 키를 확인 |

**종료 이벤트가 없는 세션의 구간 상한은 "로그의 마지막 레코드 시각"으로 잡는다.** 그 근거 계산은 FOR-0103에 있다.

### 6단계 — 세션별 활동표 만들기 (PowerShell)

```powershell
# 대상 세션 하나의 활동 전체
$target = Get-LogonIdValue '0x1a2b3c'

$fields = 'TargetLogonId','SubjectLogonId'

Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    if ($x.Event.EventData) { $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' } }
    $ids = foreach ($f in $fields) { if ($d.ContainsKey($f)) { Get-LogonIdValue $d[$f] } }
    if ($ids -contains $target) {
      $detail = ''
      if     ($d['CommandLine'])    { $detail = $d['CommandLine'] }
      elseif ($d['NewProcessName']) { $detail = $d['NewProcessName'] }
      elseif ($d['ShareName'])      { $detail = $d['ShareName'] + ' ' + $d['RelativeTargetName'] }
      elseif ($d['PrivilegeList'])  { $detail = ($d['PrivilegeList'] -replace '\s+', ' ') }
      [pscustomobject]@{
        RecordId = $_.RecordId
        TimeUTC  = $x.Event.System.TimeCreated.SystemTime
        EventId  = $_.Id
        Actor    = $d['SubjectUserName']
        Detail   = $detail
      }
    }
  } |
  Sort-Object RecordId |
  Format-Table -AutoSize
```

출력 예시:

```text
RecordId TimeUTC                       EventId Actor       Detail
1184571  2026-03-14T07:19:02.4718235Z  4624    -           
1184572  2026-03-14T07:19:02.4903117Z  4672    svc_backup  SeDebugPrivilege SeImpersonatePrivilege ...
1184573  2026-03-14T07:19:31.0021110Z  4688    svc_backup  C:\Windows\System32\cmd.exe
1184574  2026-03-14T07:20:08.4410021Z  4688    svc_backup  powershell.exe -enc SQBFAFgA...
1184880  2026-03-14T07:31:44.9120033Z  5145    svc_backup  \\*\C$ Users\Public\out.7z
1185101  2026-03-14T07:44:02.1180094Z  4634    -           
```

### 7단계 — CSV를 LogonId로 그룹핑 (Python)

행이 수십만이면 PowerShell의 XML 파싱이 느리다. EvtxECmd CSV를 만들어 놓고 Python으로 돌린다.

```python
import csv, re, collections

RESERVED = {0x3e7, 0x3e5, 0x3e4, 0x0}
FIELD_RE = re.compile(r'"(Target|Subject)LogonId"\s*:\s*"?(0x[0-9a-fA-F]+)', re.I)

def norm(h):
    try:
        return int(h, 16)
    except ValueError:
        return None

sessions = collections.defaultdict(list)

with open(r'C:\case\out\sec.csv', encoding='utf-8-sig', newline='') as f:
    for row in csv.DictReader(f):
        payload = row.get('Payload') or ''
        ids = {norm(m.group(2)) for m in FIELD_RE.finditer(payload)}
        for lid in ids - RESERVED:
            if lid is None:
                continue
            sessions[lid].append(row)

for lid, rows in sorted(sessions.items(), key=lambda kv: -len(kv[1])):
    rows.sort(key=lambda r: int(r['EventRecordId']))
    eids = collections.Counter(r['EventId'] for r in rows)
    print(f"0x{lid:x}  events={len(rows):5d}  "
          f"{rows[0]['TimeCreated']} ~ {rows[-1]['TimeCreated']}  {dict(eids)}")
```

출력 예시:

```text
0x1a2b3c  events=  412  2026-03-14 07:19:02 ~ 2026-03-14 07:44:02  {'4688': 388, '5145': 18, '4672': 3, '4624': 1, '4634': 1}
0x2f4e10  events=   57  2026-03-14 09:02:11 ~ 2026-03-14 17:31:40  {'4688': 54, '4624': 1, '4672': 1, '4634': 1}
0x1a2b41  events=    2  2026-03-14 07:19:02 ~ 2026-03-14 07:44:02  {'4624': 1, '4634': 1}
```

**세션별 이벤트 개수가 곧 우선순위다.** 412개를 가진 세션이 사건의 본체다.

payload 컬럼의 JSON 형태(키 이름, 인용 방식)는 EvtxECmd 버전에 따라 다르므로, 정규식을 쓰기 전에 payload 한 줄을 눈으로 확인한다.

### 8단계 — TargetLinkedLogonId 로 UAC 분리 토큰 잇기

관리자 계정으로 로그온하면 Windows는 **일반 권한 토큰과 상승 권한 토큰 두 개**를 만들고, 4624가 두 번 기록된다. 두 세션 ID는 서로를 `TargetLinkedLogonId` 로 가리킨다.

| 세션 | `TargetLogonId` | `TargetLinkedLogonId` | `ElevatedToken` |
| --- | --- | --- | --- |
| 상승된 쪽 | `0x1a2b3c` | `0x1a2b41` | `%%1842` (Yes) |
| 일반 쪽 | `0x1a2b41` | `0x1a2b3c` | `%%1843` (No) |

**둘 중 하나만 조인하면 활동의 절반이 빠진다.** UAC 승격 없이 실행한 프로세스는 일반 세션 쪽에 붙는다.

```powershell
# 짝 세션까지 포함해 조인 키 집합을 만든다
$primary = '0x1a2b3c'
$keys = @($primary)

Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4624)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    if ((Get-LogonIdValue $d['TargetLogonId']) -eq (Get-LogonIdValue $primary)) {
      if ($d['TargetLinkedLogonId'] -and $d['TargetLinkedLogonId'] -ne '0x0') {
        $keys += $d['TargetLinkedLogonId']
      }
    }
  }

$keySet = $keys | ForEach-Object { Get-LogonIdValue $_ } | Sort-Object -Unique
$keySet | ForEach-Object { '0x{0:x}' -f $_ }
```

`TargetLinkedLogonId` 가 `0x0` 이면 분리 토큰이 없는 로그온(표준 사용자, 서비스, 네트워크 로그온)이다.

### 9단계 — 시각 구간으로 한정한다 (재사용 함정 차단)

Logon ID는 **같은 컴퓨터에서 재부팅 사이에만 유일**하다. 재부팅하면 다시 낮은 값부터 발급되므로, 며칠치 로그에서 같은 `0x1a2b3c` 가 서로 무관한 두 세션을 가리킬 수 있다.

```powershell
# 재부팅 경계를 먼저 찾는다 (System 채널)
Get-WinEvent -Path 'C:\case\System.evtx' -Oldest -FilterXPath '*[System[(EventID=6005 or EventID=6006 or EventID=6013)]]' |
  Select-Object TimeCreated, Id, ProviderName | Format-Table -AutoSize
```

그리고 조인은 **세션 시작~종료 시각 안으로 잘라서** 한다.

```powershell
$start = [datetime]'2026-03-14T07:19:02Z'
$end   = [datetime]'2026-03-14T07:44:02Z'

Import-Csv 'C:\case\out\sec.csv' |
  Where-Object {
    $_.Payload -match '0x1a2b3c' -and
    ([datetime]$_.TimeCreated) -ge $start -and ([datetime]$_.TimeCreated) -le $end
  } |
  Sort-Object { [int64]$_.EventRecordId }
```

| 재사용을 의심할 신호 | 확인 |
| --- | --- |
| 같은 Logon ID의 4624가 두 번 이상 | 각 4624 사이가 별개 세션 |
| 활동 시각이 세션 종료 이후로 이어진다 | 다른 세션의 것을 붙였다 |
| 같은 Logon ID인데 `TargetUserName` 이 다르다 | 확정적 재사용 |
| 로그 구간 안에 재부팅(6005/6006)이 있다 | 경계 앞뒤를 분리해서 조인 |

## 출력 필드 해석

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `TargetLogonId` | 만들어진/끝난 세션 ID | 조인의 기준값. 16진수 |
| `SubjectLogonId` | 행위를 한 세션 ID | 4688·4672·5145 등의 주체 |
| `TargetLinkedLogonId` | 분리 토큰의 짝 세션 | `0x0` 이면 없음 |
| `LogonGuid` | 로그온의 GUID (Kerberos 환경) | 4624와 4768/4769를 잇는 보조 키. 값이 전부 0이면 미사용 |
| `ElevatedToken` | `%%1842`=Yes / `%%1843`=No | 어느 쪽이 상승 세션인지 |
| `TargetUserName` / `TargetDomainName` | 세션의 주인 | `$` 로 끝나면 컴퓨터 계정 |
| `SubjectUserName` | 행위 주체 계정 | 4688에서는 프로세스를 실행한 계정 |
| `LogonType` | 접속 방식 | 세션 성격 판정 ([FOR-0083](./event-4624-logon.html)) |

`LogonGuid` 는 도메인/Kerberos 환경에서만 의미 있는 값이 들어간다. 로컬 NTLM 로그온에서는 `{00000000-0000-0000-0000-000000000000}` 이므로 조인 키로 쓰면 전부 한 덩어리가 된다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 세션의 4688 목록 | `NewProcessId` / `ProcessId` (FOR-0105) | 프로세스 계보와 명령행 |
| 세션의 5140/5145 | `ShareName` / `RelativeTargetName` | 어떤 파일을 열었나 |
| 세션의 `IpAddress` / `WorkstationName` | 공격자 단말 특정 (FOR-0106) | 다른 호스트 EVTX와 대조 |
| 세션 시작 직전 | 4625 집계 | 무차별 대입 여부 |
| 세션 구간의 시각 | `$MFT` / `$J` ([FOR-0050](./ntfs-artifact-timeline.html)) | 그 세션이 만든/지운 파일 |
| Logon Type 10 세션 | TerminalServices 채널 21/24/25, 1149 | RDP 클라이언트 IP 재확인 |
| 상승 세션(`%%1842`) | 4672의 `PrivilegeList` | 어떤 특수 권한을 받았나 |
| 세션 종료 이벤트 없음 | 로그 마지막 레코드 시각 (FOR-0103) | 구간 상한 근거 |

## 흔한 함정

- **모든 이벤트에서 `TargetLogonId` 를 찾는 것.** 4688·4672·5145는 `SubjectLogonId` 다. `TargetLogonId` 로만 조인하면 세션 활동이 4624/4634 두 줄로 끝난다. → 1단계 표를 옆에 두고 두 필드를 모두 본다.
- **문자열로 조인하는 것.** `0x1a2b3c` ≠ `0x001A2B3C` ≠ `1a2b3c`. → 16진수 파싱으로 정수 정규화한 뒤 비교한다.
- **10진수와 16진수를 섞는 것.** Sysmon의 `ProcessId` 는 10진수인데 `LogonId` 는 16진수다. 한 스크립트 안에서 진법이 섞이면 조인이 빈다. → 필드별 진법을 표로 고정한다.
- **`0x3e7` 을 조인 키로 쓰는 것.** SYSTEM 세션이라 수만 행이 한 덩어리가 된다. → 예약 ID 4개를 먼저 제외한다.
- **분리 토큰의 한쪽만 조인하는 것.** 관리자 로그온은 세션이 두 개다. 승격 없이 실행한 프로세스는 다른 쪽에 붙는다. → `TargetLinkedLogonId` 로 짝을 찾아 키 집합을 만든다.
- **Logon ID가 영구 유일하다고 믿는 것.** 재부팅 사이에서만 유일하다. → 4624~4634 시각 구간으로 잘라서 조인하고, 6005/6006으로 재부팅 경계를 확인한다.
- **4776/4768/4769를 Logon ID로 엮으려는 것.** 이 이벤트에는 세션 ID가 없다. → 계정 + `Workstation`/`IpAddress` + 시각(±수 초)으로 엮는다.
- **4625를 세션에 붙이는 것.** 실패 로그온은 세션을 만들지 않는다. → 계정과 IP로만 연결한다.
- **`LogonGuid` 를 로컬 환경에서 조인 키로 쓰는 것.** 전부 0이므로 모든 이벤트가 한 세션이 된다. → Kerberos 환경에서만 쓴다.
- **같은 초 순서를 시각으로 정하는 것.** 세션 안의 인과가 뒤집힌다. → `EventRecordId` 로 정렬한다 (FOR-0103).
- **UTC/KST 혼동.** EVTX `SystemTime` 은 UTC다. 세션 시작·종료 시각을 그대로 제출하면 9시간 어긋난다. → 축은 UTC, 답을 낼 때만 +9시간.
- **payload 정규식을 확인 없이 쓰는 것.** EvtxECmd payload의 JSON 키 표기는 버전에 따라 다르다. → payload 한 줄을 눈으로 보고 정규식을 맞춘다.

## 교차검증

```powershell
# 1) 조인 결과의 세션 시작·종료가 4624/4634 와 일치하는가
Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Payload -match '0x1a2b3c' -and $_.EventId -in 4624,4634,4647 } |
  Select-Object EventRecordId, TimeCreated, EventId | Sort-Object { [int64]$_.EventRecordId }

# 2) 같은 Logon ID 의 4624 가 두 번 이상 나오는가 (재사용 검사)
Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.EventId -eq 4624 -and $_.Payload -match '0x1a2b3c' } |
  Measure-Object | Select-Object Count

# 3) XPath 로 직접 뽑아 개수를 대조한다 (문자열 매칭이 과다 검출됐는지)
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath "*[EventData[Data[@Name='SubjectLogonId']='0x1a2b3c']]" |
  Measure-Object | Select-Object Count

# 4) 세션 계정이 4688 의 SubjectUserName 과 일치하는가
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4688)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    if ($d['SubjectLogonId'] -eq '0x1a2b3c') { $d['SubjectUserName'] }
  } | Sort-Object -Unique

# 5) 분리 토큰 짝이 실제로 존재하는가
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath "*[EventData[Data[@Name='TargetLinkedLogonId']='0x1a2b3c']]" |
  Measure-Object | Select-Object Count
```

3번의 XPath 개수와 1번의 문자열 매칭 개수가 크게 다르면, 문자열 매칭이 **다른 필드에 우연히 같은 값이 들어간 행**까지 잡은 것이다. 정확한 조인은 필드를 지정한 XPath 쪽이다.

## mini walkthrough

```text
문제:
"공격자가 RDP 로 접속한 뒤 실행한 명령을 모두 나열하고,
 세션이 유지된 시간을 KST 로 답하세요.
 첨부: Security.evtx (82,364 events)"

1. 세션 인벤토리
   EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
   4624 중 사람 세션만: 3개
     0x1a2b3c  svc_backup  Type 10  203.0.113.77  Elevated=%%1842
     0x1a2b41  svc_backup  Type 10  203.0.113.77  Elevated=%%1843
     0x2f4e10  jhkim       Type 2   -             Elevated=%%1843

2. 첫 시도 (실패):
   Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest `
     -FilterXPath "*[EventData[Data[@Name='TargetLogonId']='0x1a2b3c']]" |
     Measure-Object
   -> Count : 2

   4624 하나, 4634 하나. 실행한 명령이 하나도 없다.
   "이 세션은 아무것도 안 했다" 로 결론? 오답.

   무엇이 틀렸나:
     4688 은 TargetLogonId 를 갖지 않는다. SubjectLogonId 다.
     TargetLogonId 만으로 조인하면 세션 시작/종료 두 줄만 나온다.

3. 접근 변경 — SubjectLogonId 도 함께 본다
   Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest `
     -FilterXPath "*[EventData[Data[@Name='SubjectLogonId']='0x1a2b3c']]" |
     Measure-Object
   -> Count : 410

   두 필드를 합쳐 412 행. 이것이 세션 전체다.

4. 두 번째 시도 (실패):
   활동 목록에서 4688 을 뽑았는데 cmd.exe / powershell.exe 뿐이고,
   문제에서 언급한 "압축 도구 실행"이 안 보인다.

   무엇이 틀렸나:
     0x1a2b3c 는 상승 토큰(%%1842) 세션이다.
     TargetLinkedLogonId = 0x1a2b41 인 일반 토큰 세션이 따로 있고,
     승격 없이 실행한 7z.exe 는 그쪽에 기록됐다.

5. 짝 세션까지 포함
   키 집합 = { 0x1a2b3c, 0x1a2b41 }

   두 키로 다시 조인한 4688 목록:
     07:19:31Z  C:\Windows\System32\cmd.exe                        (0x1a2b3c)
     07:20:08Z  powershell.exe -enc SQBFAFgA...                    (0x1a2b3c)
     07:30:58Z  C:\Users\svc_backup\Downloads\7z.exe a out.7z ...  (0x1a2b41)
     07:41:02Z  C:\Users\svc_backup\Downloads\rclone.exe copy ...  (0x1a2b3c)

6. 세 번째 시도 (실패):
   세션 종료를 찾으려고 4647 만 봤다 -> 없음.
   "로그오프 기록이 없으니 세션이 계속 살아 있었다" 로 결론? 오답.

   4634 로 다시 검색:
     07:44:02Z  4634  TargetLogonId=0x1a2b3c
     07:44:02Z  4634  TargetLogonId=0x1a2b41
   4647(사용자 주도 로그오프)은 없고 4634(세션 종료)만 있다.
   => 사용자가 로그오프 버튼을 누른 것이 아니라 연결이 끊긴 것이다.

7. 구간 계산
   시작 2026-03-14T07:19:02.4718235Z
   종료 2026-03-14T07:44:02Z
   유지 시간 = 약 25분 00초

   KST 변환 (+9h):
   2026-03-14 16:19:02 ~ 16:44:02 KST

정답:
 실행 명령 4건 (cmd.exe / powershell.exe -enc / 7z.exe / rclone.exe)
 세션 유지 2026-03-14 16:19:02 ~ 16:44:02 KST (약 25분)
```

세 번의 교정이 이 글의 핵심이다. **① 필드 이름이 이벤트마다 다르다** — `TargetLogonId` 만으로는 활동이 안 나온다. **② 관리자 로그온은 세션이 두 개다** — 분리 토큰 짝을 놓치면 실행 목록의 일부가 사라진다. **③ 종료 이벤트는 4634와 4647 둘 다 봐야 한다** — 어느 쪽이 있는지가 "끊겼는가 / 스스로 나갔는가"를 구분한다.

## 막혔을 때 다음 체크

1. `TargetLogonId` 와 `SubjectLogonId` 를 **둘 다** 조인했는가
2. 16진수를 정수로 정규화했는가 (`0x001A2B3C` 문제)
3. `0x3e7/0x3e5/0x3e4/0x0` 을 제외했는가
4. `TargetLinkedLogonId` 로 짝 세션을 찾아 키 집합을 만들었는가
5. `ElevatedToken` 값(`%%1842`/`%%1843`)으로 어느 쪽이 상승 세션인지 확인했는가
6. 4634와 4647을 **둘 다** 검색했는가
7. 종료 이벤트가 없다면 로그 마지막 레코드 시각을 상한으로 잡았는가
8. 조인 범위를 세션 시각 구간으로 잘랐는가 (Logon ID 재사용)
9. 로그 구간에 재부팅(6005/6006)이 있는가
10. 같은 Logon ID의 4624가 두 번 이상 나오는가
11. 세션 안 정렬을 `EventRecordId` 로 했는가
12. 4776/4768/4769는 계정·IP·시각으로 엮었는가 (Logon ID 없음)
13. XPath 개수와 payload 문자열 매칭 개수를 대조했는가
14. 답을 KST(+9시간)로 낼지 확인했는가

## 출처

- SRC-001 — Microsoft Learn, Event 4624: `TargetLogonId`, `SubjectLogonId`, `TargetLinkedLogonId`, `LogonGuid`, `ElevatedToken`(`%%1842`/`%%1843`) 필드 정의와 "Logon ID는 같은 컴퓨터에서 재부팅 사이에만 유일하다"는 근거, 예약 세션 ID(`0x3e7`/`0x3e5`/`0x3e4`)
- SRC-022 — Microsoft Learn, 고급 보안 감사 정책 설정: 4634·4647(로그오프), 4672(특수 권한), 4688/4689(프로세스), 4648(명시적 자격증명), 5140/5145(공유 접근), 4776(NTLM 검증), 4768/4769(Kerberos)의 EventData 필드 구성
- SRC-004 — Eric Zimmerman 문서: EvtxECmd CSV의 `Payload` 컬럼과 `EventRecordId` 컬럼, Timeline Explorer에서의 필터링
- EvtxECmd `Payload` 컬럼의 JSON 키 표기와 컬럼 구성은 버전에 따라 다르므로 실제 CSV 한 줄을 확인한 뒤 정규식을 작성할 것
- System 채널의 6005/6006/6013(EventLog 서비스 시작·종료, 가동 시간)은 재부팅 경계 판정 보조용으로만 사용했다. 정식 정의는 Microsoft 문서에서 확인할 것
