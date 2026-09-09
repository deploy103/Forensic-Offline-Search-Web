---
id: FOR-0087
title: "Event ID 4672 특수 권한 로그온: PrivilegeList로 관리자 세션을 확정한다"
slug: "event-4672-special-privileges"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4672", "PrivilegeList", "SeDebugPrivilege", "SeBackupPrivilege", "Audit Special Logon", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]
registry_paths: []
event_ids: ["4672"]
protocols: []
tools: ["EvtxECmd", "PowerShell", "Timeline Explorer", "Event Viewer", "wevtutil"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --inc 4672 --csv 'C:\\case\\out' --csvf p.csv", "Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4672}", "wevtutil qe Security.evtx /q:\"*[System[(EventID=4672)]]\" /f:text"]
regex_patterns: ["Se[A-Za-z]+Privilege", "\"SubjectLogonId\":\"?(0x[0-9a-fA-F]+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList"]
file_formats: ["evtx"]
primary_terms: ["4672", "특수 권한 로그온", "관리자 권한 로그온"]
keywords: ["4672", "특수 권한", "PrivilegeList", "SeDebugPrivilege", "SeBackupPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege", "Audit Special Logon", "관리자 세션", "0x3e7", "Security.evtx"]
aliases: ["4672", "관리자로 로그인했나", "특수 권한 로그온", "sedebugprivilege", "권한 상승 흔적", "0x3e7 4672", "관리자 권한 확인"]
symptom_keywords: ["관리자 권한으로 로그인했는지 알고 싶다", "4672가 너무 많다", "PrivilegeList가 무슨 뜻인지 모르겠다", "SeDebugPrivilege를 봤다", "권한 상승이 있었는지 확인해야 한다", "SYSTEM 4672가 계속 나온다"]
related: ["FOR-0083", "FOR-0086", "FOR-0085", "FOR-0104"]
source_ids: ["SRC-022", "SRC-001", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4672 는 로그온 세션에 민감 권한이 부여되었음을 기록하고, **`SubjectLogonId` 로 4624 의 `TargetLogonId` 와 짝지어 "이 세션은 관리자 권한이었다"를 확정하는 것**이 주 용도다. `0x3e7`(SYSTEM) 4672 는 부팅 시 대량으로 쏟아지는 노이즈이므로, **비-SYSTEM 세션의 4672 만 남기면 그 시스템에서 관리자 권한을 쥔 세션 목록이 그대로 나온다.**

## 어떤 문제에서 필요한가

- "공격자가 관리자 권한을 획득했는가"
- "이 로그온 세션은 일반 사용자인가 관리자인가"
- "권한 상승이 언제 일어났는가"
- "어떤 권한을 쥐었는가" (데이터 반출용 백업 권한? 자격증명 탈취용 디버그 권한?)
- 4624 만으로는 권한 수준을 알 수 없을 때 (`ElevatedToken` 이 없는 이벤트 버전)

4672 는 **단독으로는 아무 의미가 없다.** 계정 이름과 권한 목록만 있고 접속 방식·출처 IP·세션 시작 시각이 없다. 반드시 4624 와 짝지어 읽는다.

## 문제에서 처음 볼 단서

1. `SubjectLogonId` ≠ `0x3e7` / `0x3e5` / `0x3e4` → **사람이 쥔 관리자 권한.** 여기부터 본다
2. 4624 직후 1초 내에 4672 가 따라온다 → 그 로그온은 관리자 로그온이다
3. `SubjectUserName` 이 서비스 계정인데 4672 가 붙었다 → 서비스 계정으로 대화형 접속했다는 이상 신호
4. `PrivilegeList` 에 `SeBackupPrivilege` / `SeRestorePrivilege` → 파일 ACL 우회 = **데이터 반출 준비**
5. `PrivilegeList` 에 `SeLoadDriverPrivilege` → 드라이버 로드 = 루트킷 가능성
6. 특정 계정의 4672 가 **평소에는 없는데 사건 구간에만 있다** → 그 계정이 관리자 그룹에 새로 들어갔다(4728/4732 확인)

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --inc 4672 --csv 'C:\case\out' --csvf p.csv
```

SYSTEM 노이즈를 걷어내고 관리자 세션 목록을 만든다.

```powershell
$p = Import-Csv 'C:\case\out\p.csv'

# 원본 EventData 필드 이름으로 값을 뽑는다 (컬럼 배치 변화에 안전)
function Fld { param($p,$n)
  $m=[regex]::Match($p,'"'+[regex]::Escape($n)+'"\s*:\s*"?([^",}]*)'); if($m.Success){$m.Groups[1].Value}else{''} }

$adm = $p | ForEach-Object {
  [pscustomobject]@{
    Time    = $_.TimeCreated
    User    = Fld $_.Payload 'SubjectUserName'
    Domain  = Fld $_.Payload 'SubjectDomainName'
    Sid     = Fld $_.Payload 'SubjectUserSid'
    LogonId = (Fld $_.Payload 'SubjectLogonId').ToLower()
    Privs   = Fld $_.Payload 'PrivilegeList'
  }
} | Where-Object {
  $_.LogonId -notin '0x3e7','0x3e5','0x3e4','0x0' -and
  $_.User -notmatch '\$$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$'
}

# 관리자 권한을 쥔 세션 목록 — 이 표가 이 글의 산출물
$adm | Sort-Object Time | Format-Table Time, User, LogonId -AutoSize

# 건수 비교로 노이즈 제거 효과를 확인한다
[pscustomobject]@{ Raw = $p.Count; NonSystem = $adm.Count }
```

`Raw` 가 7,000건인데 `NonSystem` 이 12건으로 줄어드는 것이 정상이다. **그 12건이 전부 검토 대상이다.**

## 상세 절차

### 1단계 — 필드표

4672 의 EventData 는 다섯 개뿐이다. 전부 "권한을 받은 주체"에 관한 것이다.

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `SubjectUserSid` | 권한을 받은 계정의 SID | `S-1-5-18` = SYSTEM, `S-1-5-19` = LOCAL SERVICE, `S-1-5-20` = NETWORK SERVICE. `S-1-5-21-...-500` = 내장 Administrator |
| `SubjectUserName` | 계정 이름 | `$` 로 끝나면 컴퓨터 계정 |
| `SubjectDomainName` | 계정 도메인 | 로컬이면 컴퓨터 이름 |
| `SubjectLogonId` | **세션 ID (16진수)** | **4624 의 `TargetLogonId` 와 같은 값.** 조인 키 |
| `PrivilegeList` | **부여된 민감 권한 목록** | 공백/개행으로 구분된 `Se*Privilege` 문자열들 |

`PrivilegeList` 는 여러 권한이 하나의 문자열에 들어간다. 개별 권한을 세려면 쪼개야 한다.

```powershell
# 권한별 빈도 — 어떤 권한이 어느 계정에 붙었는지
$adm | ForEach-Object {
  $u = $_.User
  ($_.Privs -split '[\s,;]+') | Where-Object { $_ -match '^Se\w+Privilege$' } |
    ForEach-Object { [pscustomobject]@{ User=$u; Priv=$_ } }
} | Group-Object Priv, User | Sort-Object Count -Descending |
  Select-Object Count, Name | Format-Table -AutoSize
```

**4672 에는 `LogonType`·`IpAddress`·`WorkstationName` 이 없다.** 접속 방식과 출처는 같은 `SubjectLogonId` 를 가진 4624 에서 가져온다([FOR-0083](./event-4624-logon.html)).

### 2단계 — PrivilegeList 권한 의미표

4672 는 Microsoft 가 "민감(sensitive)" 으로 분류한 고정된 권한 집합에 대해서만 발생한다. 그 집합은 다음 13개다.

| 권한 | 무엇을 할 수 있게 하는가 | 공격 관점의 의미 | 우선순위 |
| --- | --- | --- | --- |
| `SeDebugPrivilege` | **다른 프로세스의 메모리를 열고 조작** | **LSASS 메모리 덤프 = 자격증명 탈취.** 프로세스 인젝션 | 최상 |
| `SeBackupPrivilege` | 파일 ACL 을 **우회해 읽기** | 접근 권한 없는 문서·하이브·`$MFT` 를 읽는다. **데이터 반출** | 최상 |
| `SeRestorePrivilege` | 파일 ACL 을 **우회해 쓰기**, 소유자 변경 | 시스템 파일 교체, 하이브 덮어쓰기 | 최상 |
| `SeTakeOwnershipPrivilege` | 임의 객체의 **소유권 강제 획득** | ACL 로 막힌 대상을 통째로 가져간다 | 높음 |
| `SeLoadDriverPrivilege` | 커널 **드라이버 로드/언로드** | **루트킷, 취약 드라이버 악용(BYOVD)** | 최상 |
| `SeSecurityPrivilege` | 보안 로그 관리, 감사 설정 변경 | **감사 로그 조작·삭제(1102 의 전제)** | 최상 |
| `SeTcbPrivilege` | **운영체제의 일부로 동작** | 사실상 무제한. 토큰을 임의로 만든다 | 최상 |
| `SeImpersonatePrivilege` | 인증 후 **클라이언트 가장** | 토큰 가장 권한 상승(서비스 계정 탈출) | 높음 |
| `SeAssignPrimaryTokenPrivilege` | 프로세스에 **기본 토큰 할당** | 다른 계정 컨텍스트로 프로세스 생성 | 높음 |
| `SeCreateTokenPrivilege` | **액세스 토큰 직접 생성** | 임의 신원 위조. 기본적으로 아무에게도 없다 | 최상 |
| `SeEnableDelegationPrivilege` | 계정을 **위임 신뢰 대상으로 설정** | Kerberos 위임 악용 | 높음 |
| `SeAuditPrivilege` | 보안 감사 항목 **생성** | 위조 감사 레코드 삽입 | 보통 |
| `SeSystemEnvironmentPrivilege` | **펌웨어 환경 변수** 수정 | 부트 단계 지속성 | 보통 |

`SeSystemtimePrivilege`(시스템 시각 변경)는 **이 민감 권한 집합에 포함되지 않으므로 4672 의 `PrivilegeList` 에는 나타나지 않는다.** 시각 조작 흔적은 4672 가 아니라 Security 채널의 4616(시스템 시간 변경)과 System 채널의 Kernel-General 이벤트에서 찾는다. 권한의 *사용*(부여가 아니라)은 4673 / 4674 에 남는다.

### 3단계 — SeDebugPrivilege 를 정확히 읽는다

여기서 흔한 오해를 바로잡는다. **`SeDebugPrivilege` 는 기본 설정에서 Administrators 그룹에 부여되어 있다.** 따라서 기본 구성 시스템에서 관리자 계정이 로그온하면 그 4672 의 `PrivilegeList` 에는 거의 항상 `SeDebugPrivilege` 가 들어간다.

| 명제 | 참/거짓 |
| --- | --- |
| `SeDebugPrivilege` 가 4672 에 있다 = 자격증명 탈취가 일어났다 | **거짓.** 부여되었을 뿐 사용 여부는 알 수 없다 |
| `SeDebugPrivilege` 가 4672 에 있다 = 그 세션은 관리자 권한이다 | **참.** 기본 구성에서는 사실상 관리자 판별선 |
| 비-SYSTEM 세션의 4672 를 최우선으로 본다 | **참.** 이것이 실전 필터다 |
| `SeDebugPrivilege` 의 실제 사용을 확인하려면 4672 를 본다 | **거짓.** 4673(권한 사용) 또는 Sysmon 10(프로세스 접근)을 본다 |

즉 `SeDebugPrivilege` 는 **"이 세션은 관리자다"** 라는 강력한 신호이고, **"자격증명을 훔쳤다"** 는 별도 증거를 요구한다. 실전 필터는 이렇게 짠다.

```powershell
# 최우선 검토 대상: 비-SYSTEM 세션 중 SeDebugPrivilege 를 쥔 것
$adm | Where-Object { $_.Privs -match 'SeDebugPrivilege' } |
  Sort-Object Time | Format-Table Time, User, LogonId -AutoSize

# 그중에서도 특히: 관리자여야 할 이유가 없는 계정
$adm | Where-Object {
  $_.Privs -match 'SeDebugPrivilege' -and
  $_.User -notmatch '^(Administrator|admin|it_admin)$'
} | Sort-Object Time | Format-Table Time, User, LogonId -AutoSize

# 데이터 반출 신호: 백업/복원 권한
$adm | Where-Object { $_.Privs -match 'SeBackupPrivilege|SeRestorePrivilege' } |
  Sort-Object Time | Format-Table Time, User, Privs -AutoSize

# 루트킷 신호: 드라이버 로드 권한
$adm | Where-Object { $_.Privs -match 'SeLoadDriverPrivilege' } |
  Sort-Object Time | Format-Table Time, User, LogonId -AutoSize
```

### 4단계 — 4624 와 짝지어 관리자 세션을 확정한다 (주 용도)

`SubjectLogonId`(4672) = `TargetLogonId`(4624) 다. 이 조인이 4672 의 존재 이유다.

```powershell
$all = Import-Csv 'C:\case\out\all.csv'   # 4624 와 4672 가 함께 든 CSV

# 4624 를 LogonId 키로 색인
$logons = @{}
$all | Where-Object { $_.EventId -eq '4624' } | ForEach-Object {
  $id = (Fld $_.Payload 'TargetLogonId').ToLower()
  if ($id -and -not $logons.ContainsKey($id)) {
    $logons[$id] = [pscustomobject]@{
      Time = $_.TimeCreated
      User = Fld $_.Payload 'TargetUserName'
      Type = Fld $_.Payload 'LogonType'
      Ip   = Fld $_.Payload 'IpAddress'
      Wks  = Fld $_.Payload 'WorkstationName'
    }
  }
}

# 4672 에 4624 정보를 붙인다 — 관리자 세션 완성표
$all | Where-Object { $_.EventId -eq '4672' } | ForEach-Object {
  $id = (Fld $_.Payload 'SubjectLogonId').ToLower()
  $l  = $logons[$id]
  [pscustomobject]@{
    PrivTime = $_.TimeCreated
    LogonId  = $id
    User     = Fld $_.Payload 'SubjectUserName'
    LogonUtc = $l.Time
    Type     = $l.Type
    Ip       = $l.Ip
    Wks      = $l.Wks
    HasDebug = [bool]($_.Payload -match 'SeDebugPrivilege')
  }
} | Where-Object {
  $_.LogonId -notin '0x3e7','0x3e5','0x3e4','0x0' -and $_.User -notmatch '\$$'
} | Sort-Object PrivTime | Format-Table -AutoSize
```

출력 예시:

```text
PrivTime               LogonId   User        LogonUtc               Type Ip             HasDebug
--------               -------   ----        --------               ---- --             --------
2026-03-14 07:18:44Z   0x1a2b3c  svc_backup  2026-03-14 07:18:44Z   10   203.0.113.77   True
2026-03-14 09:02:11Z   0x2f4e10  jhkim       2026-03-14 09:02:11Z   10   192.168.10.24  True
2026-03-13 00:12:03Z   0x30a112  jhkim       2026-03-13 00:12:03Z   2    -              True
```

이 표 한 장이 "누가 언제 어디서 관리자 권한으로 들어왔는가"의 완성형이다. `svc_backup` 이 공인 IP 에서 RDP 로 관리자 권한 세션을 만든 것이 즉시 보인다.

**4672 인데 짝이 되는 4624 가 없는 경우**도 있다. 원인은 세 가지다.

| 원인 | 판정 |
| --- | --- |
| 4624 가 로그의 시간 범위 밖 (롤오버) | 첫 `EventRecordId` 확인 |
| Audit Logon 은 꺼졌는데 Audit Special Logon 은 켜져 있었다 | 4719 확인. 4624 가 전 구간 0건 |
| 재부팅을 넘어 조인했다 | Logon ID 는 **부팅 구간 안에서만 유일**하다 |

### 5단계 — SYSTEM 노이즈의 정체

`SubjectLogonId = 0x3e7` 의 4672 는 부팅 직후와 서비스 시작마다 발생한다. 이유는 SYSTEM 이 위 13개 권한을 전부 갖고 있어서, SYSTEM 컨텍스트의 로그온이 만들어질 때마다 4672 가 찍히기 때문이다.

| 세션 ID | 계정 | 4672 발생 양상 | 처리 |
| --- | --- | --- | --- |
| `0x3e7` | SYSTEM (`S-1-5-18`) | 부팅 시 수십~수백 건, 이후 지속 | **제외.** 단 시각은 부팅 시점 추정에 쓸 수 있다 |
| `0x3e5` | LOCAL SERVICE (`S-1-5-19`) | 서비스 시작 시 | 제외 |
| `0x3e4` | NETWORK SERVICE (`S-1-5-20`) | 서비스 시작 시 | 제외 |
| 컴퓨터 계정 | `WIN10$` | 도메인 인증 과정 | 제외 |
| 그 외 16진수 | 사람 또는 서비스 계정의 실제 세션 | 사건 구간에 소수 | **전부 검토** |

역으로 이용하는 방법도 있다. **`0x3e7` 4672 가 짧은 시간에 폭발적으로 몰린 지점은 부팅 시각의 근사치**다. 6005/4608 이 지워졌을 때 부팅 경계를 추정하는 데 쓸 수 있다.

```powershell
# 0x3e7 4672 의 분 단위 밀도 — 급증 지점이 부팅 근처
$p | Where-Object { (Fld $_.Payload 'SubjectLogonId').ToLower() -eq '0x3e7' } |
  Group-Object { ([datetime]$_.TimeCreated).ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name
```

## 출력 필드 해석

```text
EvtxECmd CSV 한 행 (4672, 값은 예시)

TimeCreated : 2026-03-14 07:18:44.9912345Z      <- UTC
EventId     : 4672
Channel     : Security
Computer    : WIN10-FIN01
Payload     : {"SubjectUserSid":"S-1-5-21-1111111111-2222222222-3333333333-1108",
               "SubjectUserName":"svc_backup","SubjectDomainName":"WIN10-FIN01",
               "SubjectLogonId":"0x1a2b3c",
               "PrivilegeList":"SeSecurityPrivilege SeTakeOwnershipPrivilege
                                SeLoadDriverPrivilege SeBackupPrivilege
                                SeRestorePrivilege SeDebugPrivilege
                                SeSystemEnvironmentPrivilege SeImpersonatePrivilege"}
```

읽는 법: `svc_backup` 세션(`0x1a2b3c`)에 백업·복원·소유권·드라이버 로드·디버그·보안 로그 권한이 전부 부여되었다. 이는 **로컬 Administrators 그룹 구성원의 표준 권한 세트**이므로 "관리자 권한 세션 확정"으로 읽고, 개별 권한의 *사용*은 별도로 확증한다.

`PrivilegeList` 는 원본 XML 에서 개행과 탭이 섞인 문자열로 저장된다. CSV 로 나오면 공백으로 보이는 경우가 많으므로 `-split '[\s,;]+'` 로 쪼갠다.

**EVTX 내부 `SystemTime` 은 항상 UTC 로 저장되고, EvtxECmd CSV 의 `TimeCreated` 도 UTC 다.** Event Viewer 는 로컬 시간대로 변환해 보여준다. **KST 로 답해야 하면 +9시간**: `07:18:44Z` → `16:18:44 KST`. 4624 와 4672 는 보통 같은 초에 찍히므로, 한쪽을 로컬 시각으로 읽으면 조인은 되지만 답이 9시간 틀린다. 대상 시스템의 시간대는 [FOR-0054](./system-timezone.html)에서 확인한다.

## pivot: 다음에 볼 artifact

| 4672 에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `SubjectLogonId` | 4624 ([FOR-0083](./event-4624-logon.html)) | 접속 방식, 출처 IP, 워크스테이션 |
| `SubjectLogonId` | 4634 / 4647 ([FOR-0085](./event-4634-4647-logoff.html)) | 관리자 세션의 지속 시간 |
| `SubjectLogonId` | 4688 | 그 관리자 세션에서 실행한 명령 |
| `SubjectLogonId` | 4648 ([FOR-0086](./event-4648-explicit-credentials.html)) | 그 권한으로 다른 서버에 붙었는가 |
| `SubjectLogonId` | 5140 / 5145 | 접근한 공유와 파일 |
| `SubjectUserName` | 4728 / 4732 / 4756 | **그 계정이 언제 관리자 그룹에 들어갔는가** |
| `SubjectUserName` | 4720 / 4738 | 계정 생성·변경 시각 |
| `SeDebugPrivilege` | Sysmon 10 (ProcessAccess), 4673 | **LSASS 접근이 실제로 있었는가** |
| `SeBackupPrivilege` | 5145, `$MFT` ([FOR-0021](./mft-basics.html)) | ACL 우회로 읽어 간 파일 |
| `SeSecurityPrivilege` | 1102, 4719 | 감사 로그를 실제로 지웠는가 |
| `SeLoadDriverPrivilege` | System 채널 7045, Sysmon 6 | 로드된 드라이버와 서비스 |
| `0x3e7` 4672 밀도 급증 | 6005 / 4608 / Kernel-Power 41 | 부팅 시각 확정 |
| 4672 만 있고 4624 없음 | 4719 / 1102 / `EventRecordId` | 감사 정책 변경, 로그 삭제, 롤오버 |

## 흔한 함정

- **`SeDebugPrivilege` 를 보고 곧바로 "자격증명 탈취"라고 단정하는 것.** 이 권한은 기본 설정에서 Administrators 그룹에 부여되어 있어 **모든 관리자 로그온의 4672 에 거의 항상 포함된다.** 부여는 사용이 아니다. 실제 사용은 4673 또는 Sysmon 10(LSASS 프로세스 접근)으로 확증한다.
- **`0x3e7` 을 계정 이름이나 특별한 값으로 취급하는 것.** SYSTEM 세션 ID 다. 부팅 시 수백 건이 정상적으로 발생한다. 제외하지 않으면 표가 SYSTEM 으로 가득 찬다.
- **4672 만 보고 결론을 내는 것.** 4672 에는 `LogonType`·`IpAddress`·`WorkstationName` 이 **없다.** 접속 방식과 출처를 알려면 반드시 4624 와 조인해야 한다.
- **4672 의 필드를 `Target*` 으로 찾는 것.** 4672 는 `Subject*` 만 갖는다. `TargetLogonId` 는 존재하지 않는다. 반대로 4634/4647 은 `Target*` 만 갖는다 — 이벤트마다 접두어가 다르다.
- **`PrivilegeList` 를 하나의 값으로 필터하는 것.** 여러 권한이 한 문자열에 개행·탭·공백으로 섞여 있다. `-eq 'SeDebugPrivilege'` 는 절대 맞지 않는다. `-match` 또는 `-split` 을 쓴다.
- **`SeSystemtimePrivilege` 를 `PrivilegeList` 에서 찾는 것.** 민감 권한 집합에 없으므로 4672 에 나타나지 않는다. 시각 조작은 4616(시스템 시간 변경)에서 찾는다.
- **4672 가 없으면 관리자 권한이 없었다고 결론 내는 것.** Audit Special Logon 하위 범주가 꺼져 있으면 아예 기록되지 않는다. 4719 를 확인하고, 4624 의 `ElevatedToken` 또는 4688 의 실행 내용으로 대체 판정한다.
- **재부팅을 넘어 `SubjectLogonId` 로 조인하는 것.** Logon ID 는 **같은 컴퓨터의 같은 부팅 구간에서만 유일**하다. 부팅 경계를 무시하면 다른 세션이 잘못 붙는다.
- **16진수 대소문자.** `0x1A2B3C` / `0x1a2b3c` 가 섞여 나온다. 조인 전에 `.ToLower()` 로 정규화하지 않으면 짝이 하나도 안 맞는다.
- **정상 관리자 활동을 전부 공격으로 세는 것.** 도메인 컨트롤러와 관리용 점프 호스트에서는 비-SYSTEM 4672 가 상시 발생한다. 워크스테이션에서는 드물다. **호스트 역할에 따라 기준선이 완전히 다르다.**
- **UTC/KST 혼동.** 4624 와 4672 는 같은 초에 찍히므로 조인 자체는 성공하지만, 시각을 로컬로 읽으면 답이 9시간 틀린다.

## 교차검증

```powershell
# A) 4624 와 4672 가 같은 LogonId 로 짝을 이루는지 (관리자 로그온 확정)
$sid = '0x1a2b3c'
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.Payload -imatch [regex]::Escape($sid) } |
  Sort-Object TimeCreated |
  Select-Object TimeCreated, EventId, MapDescription

# B) 그 계정이 관리자 그룹에 언제 들어갔는가 — 4728/4732/4756
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '4720','4728','4732','4756','4738' } |
  Select-Object TimeCreated, EventId, MapDescription, UserName

# C) 권한이 실제로 사용되었는가 — 4673 (Audit Sensitive Privilege Use)
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '4673','4674' } |
  Select-Object TimeCreated, EventId, MapDescription

# D) 감사 정책이 Special Logon 을 기록하고 있었는가
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in '4719','1102' } |
  Select-Object TimeCreated, EventId, MapDescription

# E) XPath 로 특정 세션의 4672 만
wevtutil qe 'C:\case\Security.evtx' /lf:true /f:text `
  /q:"*[System[(EventID=4672)]] and *[EventData[Data[@Name='SubjectLogonId']='0x1a2b3c']]"

# F) 도구 독립 검증 — 건수 대조
(Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx'; Id=4672}).Count
```

B 가 특히 강력하다. **4672 가 나타난 계정이 사건 직전에 4732(로컬 그룹 구성원 추가)로 Administrators 에 들어갔다면 권한 상승 시각이 초 단위로 확정된다.**

## mini walkthrough

```text
문제:
"공격자가 관리자 권한을 획득한 시각(KST)과 그때 사용한 계정을 구하세요.
 첨부: Security.evtx (48,213 events)"

1. EvtxECmd.exe -f Security.evtx --inc 4624,4672,4732 --csv out --csvf all.csv
   -> 4672 가 7,120건.

2. 첫 시도 (실패한 접근):
   4672 를 SeDebugPrivilege 로 필터했다.

     Import-Csv out\all.csv |
       Where-Object { $_.EventId -eq '4672' -and $_.Payload -match 'SeDebugPrivilege' }
     -> 7,118건. 거의 줄지 않았다.

   왜 틀렸나 (두 가지):
   (a) SeDebugPrivilege 는 SYSTEM 도 갖고 있다. SYSTEM 4672 가 7천 건이므로
       이 권한으로 필터하는 것은 필터가 아니다.
   (b) 애초에 SeDebugPrivilege 는 Administrators 기본 권한이라
       "특별히 수상한 권한"이 아니다. 판별력이 없다.

3. 방향 전환 — 주체 세션 ID 로 먼저 걷어낸다:
     Import-Csv out\all.csv |
       Where-Object { $_.EventId -eq '4672' } | ForEach-Object {
         [pscustomobject]@{
           Time = $_.TimeCreated
           User = Fld $_.Payload 'SubjectUserName'
           Id   = (Fld $_.Payload 'SubjectLogonId').ToLower()
         }
       } | Where-Object { $_.Id -notin '0x3e7','0x3e5','0x3e4' -and $_.User -notmatch '\$$' }

   -> 7,120건 -> 12건. 볼 수 있는 크기가 됐다.

     Time                   User        Id
     2026-03-13 00:12:03Z   jhkim       0x30a112
     2026-03-13 08:41:55Z   Administrator 0x9c114
     ... (8건 생략, 모두 jhkim / Administrator)
     2026-03-14 07:18:44Z   svc_backup  0x1a2b3c   <- 처음 보는 계정
     2026-03-14 09:02:11Z   jhkim       0x2f4e10

4. 4624 와 조인해 접속 방식과 출처를 붙인다:
     PrivTime               LogonId   User        Type Ip
     2026-03-14 07:18:44Z   0x1a2b3c  svc_backup  10   203.0.113.77
     2026-03-14 09:02:11Z   0x2f4e10  jhkim       10   192.168.10.24

   -> svc_backup: 서비스 계정인데 RDP(Type 10), 공인 IP. 조합이 부자연스럽다.

5. 세 번째 확인 (여기서 한 번 더 막혔다):
   "svc_backup 은 원래 관리자였나?"를 확인하지 않고 07:18:44 를 답했다.
   그런데 svc_backup 의 4672 는 이 한 건이 전부였다.
   평소에 관리자 권한을 쓴 적이 없는 계정이라는 뜻이다.

   -> 4732 를 확인한다:
     2026-03-14 07:20:31Z  4732  Administrators 그룹에 svc_backup 추가
                                 (SubjectUserName=svc_backup, SubjectLogonId=0x1a2b3c)

   즉 07:18:44 에 이미 관리자 권한으로 로그온했고(계정이 원래 로컬 관리자였다),
   07:20:31 에 자기 자신을 그룹에 명시적으로 추가해 지속성을 확보했다.
   "권한 획득 시각"은 4672 가 처음 붙은 07:18:44 다.

6. PrivilegeList 확인:
   SeSecurityPrivilege SeTakeOwnershipPrivilege SeLoadDriverPrivilege
   SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege
   SeSystemEnvironmentPrivilege SeImpersonatePrivilege
   -> SeBackupPrivilege 존재. ACL 우회 읽기 가능 = 데이터 반출 능력.

7. 세션 활동 확인 (0x1a2b3c 로 4688):
   07:19:31Z  cmd.exe
   07:20:08Z  powershell.exe -enc SQBFAFgA...
   07:24:55Z  C:\Users\svc_backup\Downloads\rclone.exe   <- 반출 도구

8. 시각 변환: 07:18:44Z + 9h = 2026-03-14 16:18:44 KST

정답: svc_backup, 2026-03-14 16:18:44 KST
```

2단계의 실패가 이 글의 요점이다. **`SeDebugPrivilege` 로 필터하면 7,120건이 7,118건이 된다 — SYSTEM 이 그 권한을 갖고 있고, 관리자면 누구나 갖고 있기 때문이다.** 실제로 작동하는 필터는 권한 이름이 아니라 **`SubjectLogonId` 가 `0x3e7`/`0x3e5`/`0x3e4` 가 아니라는 조건**이고, 그것만으로 7,120건이 12건이 된다.

## 막혔을 때 다음 체크

1. `SubjectLogonId` 가 `0x3e7`/`0x3e5`/`0x3e4`/`0x0` 인 행을 제외했는가 — 이것만으로 99% 감소
2. 컴퓨터 계정(`$` 로 끝남)을 제외했는가
3. `SubjectLogonId` 를 `.ToLower()` 로 정규화하고 4624 와 조인했는가
4. 4672 만 보고 `LogonType`/`IpAddress` 를 찾고 있지 않은가 — 그 필드는 4624 에 있다
5. `PrivilegeList` 를 `-split` 으로 쪼개 개별 권한을 셌는가
6. `SeBackupPrivilege` / `SeRestorePrivilege` / `SeLoadDriverPrivilege` / `SeSecurityPrivilege` 가 있는가 — 각각 반출·루트킷·로그 조작 신호
7. 그 계정이 **평소에도** 4672 를 갖는 계정인가 — 기준선 비교가 판정의 절반이다
8. 4728 / 4732 / 4756 을 확인했는가 — 관리자 그룹 편입 시각
9. 권한의 실제 사용이 필요하면 4673 / Sysmon 10 을 봤는가
10. 4672 가 전 구간 0건이면 → 4719(감사 정책 변경), 1102(로그 삭제)
11. 호스트 역할을 고려했는가 — DC/점프 호스트는 비-SYSTEM 4672 가 정상적으로 많다
12. 답이 UTC 인지 KST 인지 확인했는가 (+9시간)

## 출처

- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 4672 가 속한 Audit Special Logon 하위 범주, 4673/4674(권한 사용) 및 4728/4732/4756(그룹 편입)과의 관계
- SRC-001 — Microsoft Learn, Event 4624: `TargetLogonId` 와 4672 의 `SubjectLogonId` 가 동일한 세션 식별자라는 점, Logon ID 가 같은 부팅 구간에서만 유일하다는 점
- SRC-086 — MITRE ATT&CK Enterprise: `SeDebugPrivilege` 를 이용한 OS 자격증명 덤프, `SeLoadDriverPrivilege` 를 이용한 취약 드라이버 악용, `SeBackupPrivilege` 를 이용한 ACL 우회 데이터 수집
- `PrivilegeList` 에 실제로 나타나는 권한 집합은 로컬 보안 정책의 권한 할당에 따라 달라진다. 위 13개는 Microsoft 가 민감 권한으로 분류한 목록이며, 개별 시스템에서는 실제 이벤트의 `PrivilegeList` 값을 그대로 확인할 것
</content>
