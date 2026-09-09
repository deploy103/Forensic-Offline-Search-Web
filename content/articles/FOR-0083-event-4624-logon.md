---
id: FOR-0083
title: "Event ID 4624 성공 로그온 분석: 누가 어디서 어떻게 들어왔나"
slug: "event-4624-logon"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4624", "Logon Type", "Logon ID", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "%SystemRoot%\\System32\\winevt\\Logs"]
registry_paths: []
event_ids: ["4624", "4625", "4634", "4647", "4648", "4672", "4688", "4776", "4778", "4779", "5140", "5145"]
protocols: ["RDP", "SMB", "NTLM", "Kerberos"]
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "Timeline Explorer"]
commands: ["EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv", "Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4624}", "wevtutil qe Security.evtx /q:\"*[System[(EventID=4624)]]\" /f:text"]
regex_patterns: ["Logon Type:\\s+(\\d+)", "0x[0-9a-fA-F]{4,}"]
wireshark_filters: []
tshark_fields: []
log_fields: ["TargetUserName", "TargetLogonId", "LogonType", "IpAddress", "WorkstationName", "AuthenticationPackageName", "LogonProcessName", "ElevatedToken", "SubjectLogonId"]
file_formats: ["evtx"]
keywords: ["4624", "로그온", "logon", "Logon Type", "Logon ID", "성공 로그온", "RDP 접속", "원격 접속", "누가 로그인", "Security.evtx"]
aliases: ["4624", "누가 로그인", "로그인 성공", "로그온 성공", "원격 로그인 흔적", "rdp 접속 기록", "logon type 10", "누가 접속했나"]
symptom_keywords: ["누가 로그인했는지 알고 싶다", "언제 접속했는지", "원격에서 들어왔는지", "IP를 알고 싶다", "로그온 타입이 뭔지 모르겠다", "0x3e7이 뭔가", "로그가 너무 많다"]
related: ["FOR-0061", "FOR-0121"]
source_ids: ["SRC-001", "SRC-004", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4624는 성공한 로그온을 기록하며, **Logon Type**으로 접속 방식을, **IpAddress**로 출처를, **TargetLogonId**로 그 세션에서 벌어진 모든 후속 활동을 연결한다 — 이 세 필드만 잡으면 침입 경로가 그려진다.

## 어떤 문제에서 필요한가

- "공격자가 언제 어떤 계정으로 로그인했는가"
- "원격(RDP)으로 들어온 흔적이 있는가"
- "접속한 IP는 무엇인가"
- "로그인 후 무엇을 했는가" (Logon ID로 세션 내 활동 추적)
- "내부자인가 외부 침입인가" (Logon Type 2 vs 3 vs 10)

Security.evtx에서 4624는 수천 건이 나온다. **필터 없이 보면 무조건 실패한다.** Logon Type과 계정 이름으로 먼저 줄이는 것이 이 글의 핵심이다.

## 문제에서 처음 볼 단서

1. 첨부에 `Security.evtx`가 있다 → 4624/4625/4672를 가장 먼저 본다
2. 문제 지문의 "접속", "로그인", "원격", "누가" → 4624 확정
3. IP가 하나 주어졌다 → `IpAddress`로 바로 필터
4. 계정 이름이 하나 주어졌다 → `TargetUserName`으로 필터한 뒤 Logon ID 확보
5. 시각이 하나 주어졌다 → 그 시각 ±5분의 4624 전부

## 30초 절차

```powershell
EvtxECmd.exe -f "C:\case\Security.evtx" --csv "C:\case\out" --csvf sec.csv
```

CSV가 나오면 Timeline Explorer로 열고 `EventId` = 4624 필터 → `PayloadData` 컬럼에서 Logon Type과 계정을 읽는다.

CSV 없이 PowerShell만으로:

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx'; Id=4624} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      Time    = $_.TimeCreated
      User    = $d['TargetUserName']
      Type    = $d['LogonType']
      LogonId = $d['TargetLogonId']
      Ip      = $d['IpAddress']
      Wks     = $d['WorkstationName']
      AuthPkg = $d['AuthenticationPackageName']
    }
  } |
  Where-Object { $_.User -notmatch '\$$' -and $_.Type -in 2,3,10 } |
  Sort-Object Time | Format-Table -AutoSize
```

`-notmatch '\$$'`가 중요하다. 컴퓨터 계정(`WIN10$`)과 시스템 계정을 빼면 남는 건수가 보통 10분의 1로 줄어든다.

## 상세 절차

### 1단계 — Logon Type으로 접속 방식 확정

**이 표가 4624 분석의 절반이다.**

| Type | 이름 | 실제 의미 | CTF에서의 신호 |
| --- | --- | --- | --- |
| 2 | Interactive | 콘솔에 직접 로그인 (키보드) | 물리적 접근 또는 VM 콘솔 |
| 3 | Network | 네트워크 공유/SMB/원격 접근 | **가장 흔한 측면 이동** |
| 4 | Batch | 예약 작업 실행 | 스케줄러 지속성 |
| 5 | Service | 서비스 시작 | 서비스 기반 지속성 (7045와 함께) |
| 7 | Unlock | 화면 잠금 해제 | 사용자가 자리에 있었다 |
| 8 | NetworkCleartext | 평문 자격증명 네트워크 로그온 | IIS 기본 인증 등. **평문 노출** |
| 9 | NewCredentials | `runas /netonly` | **자격증명 도용 강한 신호** |
| 10 | RemoteInteractive | **RDP / 터미널 서비스** | 원격 데스크톱 침입 |
| 11 | CachedInteractive | 캐시된 자격증명 로그인 | 도메인 컨트롤러 미접속 상태 |
| 12 | CachedRemoteInteractive | 캐시 기반 RDP | 위와 동일 |
| 13 | CachedUnlock | 캐시 기반 잠금 해제 | — |

실전 우선순위: **10 (RDP) → 3 (네트워크) → 9 (자격증명 도용) → 2 (콘솔)**.

### 2단계 — 노이즈 제거

4624의 90% 이상은 분석 가치가 없다. 다음을 먼저 버린다.

| 버릴 대상 | 판별 방법 |
| --- | --- |
| SYSTEM 로그온 | `TargetLogonId` = `0x3e7` |
| LOCAL SERVICE | `TargetLogonId` = `0x3e5` |
| NETWORK SERVICE | `TargetLogonId` = `0x3e4` |
| 컴퓨터 계정 | `TargetUserName`이 `$`로 끝남 (`WIN10$`) |
| 서비스/배치 | `LogonType` = 5 또는 4 (별도로 볼 때 제외) |
| `ANONYMOUS LOGON` | `TargetUserName` = `ANONYMOUS LOGON` (단, NTLM 널 세션은 별도로 의심) |
| `UMFD-*`, `DWM-*` | 데스크톱 관리자 세션 |

```powershell
Import-Csv sec.csv |
  Where-Object {
    $_.EventId -eq 4624 -and
    $_.PayloadData1 -notmatch '0x3e7|0x3e5|0x3e4' -and
    $_.UserName -notmatch '\$$|^UMFD-|^DWM-|ANONYMOUS'
  }
```

> EvtxECmd CSV의 컬럼 배치는 버전에 따라 다르다. `PayloadData1..6`과 `Payload` 컬럼을 실제로 한 번 열어 확인한 뒤 필터를 짠다. 확실하게 하려면 `Payload`(원본 JSON) 컬럼을 정규식으로 긁는 편이 안전하다.

### 3단계 — IpAddress로 출처 확정

| `IpAddress` 값 | 의미 |
| --- | --- |
| `-` | 로컬 로그온. 네트워크 출처 없음 |
| `127.0.0.1` / `::1` | 로컬 루프백. 로컬에서 실행된 원격 도구 |
| `10.x` / `172.16-31.x` / `192.168.x` | 내부망. **측면 이동** 후보 |
| 공인 IP | 외부에서 직접 접속. 방화벽 노출 |

`IpPort`도 함께 본다. 값이 있으면 실제 TCP 세션이 있었다는 뜻이다.

### 4단계 — TargetLogonId로 세션 전체를 연결

**여기가 4624 분석의 핵심 기술이다.** `TargetLogonId`(예: `0x1a2b3c`)는 그 로그온 세션의 고유 ID이며, 세션이 유지되는 동안 발생한 다른 이벤트에 같은 값이 들어간다.

```powershell
# 관심 세션 ID를 고정
$sid = '0x1a2b3c'

# 그 세션에서 발생한 모든 이벤트
Import-Csv sec.csv | Where-Object { $_.Payload -like "*$sid*" } |
  Select-Object TimeCreated, EventId, MapDescription |
  Sort-Object TimeCreated
```

| 이벤트 | Logon ID가 들어가는 필드 | 알 수 있는 것 |
| --- | --- | --- |
| 4624 | `TargetLogonId` | 세션 시작 |
| 4672 | `SubjectLogonId` | **관리자 권한으로 로그온** |
| 4688 | `SubjectLogonId` | 그 세션에서 실행한 프로세스와 명령행 |
| 4634 | `TargetLogonId` | 세션 종료 |
| 4647 | `TargetLogonId` | 사용자가 직접 로그오프 |
| 4648 | `SubjectLogonId` | 다른 자격증명으로 접속 시도 |
| 5140 / 5145 | `SubjectLogonId` | 접근한 네트워크 공유와 파일 |

즉 **4624 → 4672 → 4688 × N → 4634** 를 하나의 Logon ID로 엮으면 "로그인 후 무엇을 했는가"가 완성된다.

## 출력 필드 해석

원본 EventData의 실제 필드 이름이다. Event Viewer의 한글 표시명이 아니라 이 이름으로 검색해야 정확하다.

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `TargetUserName` | 로그온한 계정 | `$` 끝은 컴퓨터 계정 |
| `TargetDomainName` | 계정 도메인 | 로컬이면 컴퓨터 이름 |
| `TargetUserSid` | 계정 SID | `S-1-5-18` = SYSTEM |
| `TargetLogonId` | **세션 ID (16진수)** | 후속 이벤트 연결 키 |
| `LogonType` | 접속 방식 | 위 표 참조 |
| `IpAddress` / `IpPort` | 출처 IP / 포트 | `-`면 로컬 |
| `WorkstationName` | 접속한 클라이언트 이름 | 공격자가 자기 PC 이름을 남기는 경우가 많다 |
| `AuthenticationPackageName` | `Kerberos` / `NTLM` / `Negotiate` | 도메인 환경에서 **NTLM은 이상 신호** |
| `LogonProcessName` | `User32`(콘솔) / `NtLmSsp`(네트워크 NTLM) / `Kerberos` / `Advapi`(runas) | 어떤 경로로 인증했는지 |
| `ProcessName` | 로그온을 수행한 프로세스 | `winlogon.exe`, `svchost.exe`, `services.exe` |
| `ElevatedToken` | `%%1842` = Yes, `%%1843` = No | Yes면 관리자 권한 세션 |
| `SubjectUserName` / `SubjectLogonId` | 이 로그온을 **요청한** 주체 | 보통 SYSTEM(`0x3e7`) |
| `LmPackageName` | `NTLM V1` / `NTLM V2` / `-` | **NTLM V1은 취약, 강한 의심** |
| `KeyLength` | 세션 키 길이 | 0이면 Kerberos 또는 로컬 |
| `TargetLinkedLogonId` | 연결된 다른 세션 (UAC 분리 토큰) | 관리자 승격 추적 |

`ElevatedToken`이 `%%1842`인 4624는 그 직후에 거의 항상 4672가 따라온다. 둘이 짝을 이루면 "관리자로 로그인 성공"이 확정된다.

## pivot: 다음에 볼 artifact

| 4624에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `TargetLogonId` | 4688 (프로세스 생성) | 실행한 명령과 인자 |
| `TargetLogonId` | 5140/5145 | 접근한 공유·파일 |
| `TargetUserName` | 4625 (실패 로그온) | 앞선 무차별 대입 시도 |
| `IpAddress` | pcap의 `ip.addr == <IP>` | 실제 트래픽 내용 |
| `LogonType` = 10 | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` (21, 24, 25) | RDP 세션 상세, 클라이언트 IP |
| `LogonType` = 3 + NTLM | 4776 (NTLM 자격증명 검증) | 인증 시도 원본 |
| 로그온 시각 | UserAssist / Prefetch ([FOR-0061](./userassist.html)) | 그 세션에서 실행한 GUI 프로그램 |
| 로그온 시각 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 시각에 생성·삭제된 파일 |
| `WorkstationName` | DHCP 로그, ARP, 다른 호스트의 EVTX | 공격자 단말 특정 |

## 흔한 함정

- **로그온 시각 ≠ 이벤트 기록 시각.** 대개 같지만 시스템 부하/시간 동기화 문제로 어긋날 수 있다. `EventRecordID` 순서가 시간 순서보다 신뢰도가 높다.
- **Logon Type 3을 무조건 공격으로 보는 것.** 파일 공유 접근, 그룹 정책 적용 등 정상 트래픽이 대부분이다. 계정과 IP로 정상 기준선을 먼저 만든다.
- **`IpAddress = -`를 "숨겼다"로 오해하는 것.** 로컬 로그온에서는 원래 `-`다.
- **4624만 보고 4625를 빠뜨리는 것.** 침입 직전의 실패 시도가 공격 방식(무차별 대입 vs 유효 자격증명 사용)을 알려준다.
- **컴퓨터 계정을 사용자로 세는 것.** `WIN10$`는 사람이 아니다.
- **UTC/로컬 혼동.** EVTX 내부 `SystemTime`은 **UTC**다. Event Viewer는 이를 로컬 시간대로 변환해 보여주므로 두 화면의 숫자가 다르다. EvtxECmd CSV는 UTC로 출력한다. 답이 KST면 +9시간.
- **감사 정책이 꺼져 있던 구간을 고려하지 않는 것.** 4624가 없다면 정말 로그온이 없었을 수도, 감사가 꺼졌을 수도 있다. 1102(로그 삭제)와 4719(감사 정책 변경)를 확인한다.
- **`0x3e7`을 계정으로 취급하는 것.** 이건 SYSTEM 세션 ID다.
- **NTLM V1을 정상으로 넘기는 것.** 현대 도메인 환경에서 `LmPackageName = NTLM V1`은 다운그레이드 공격 신호일 수 있다.

## 교차검증

```powershell
# 1) 4624 — 로그온 성공 (Logon ID 확보)
Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s+10' }

# 2) 4672 — 같은 시각 관리자 권한 부여 여부
Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4672}

# 3) 4625 — 그 계정에 대한 사전 실패 시도
Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4625} |
  Where-Object { $_.Message -match 'attacker01' }

# 4) RDP 전용 로그 — Logon Type 10의 클라이언트 IP 재확인
Get-WinEvent -FilterHashtable @{
  Path='Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx'
  Id=21,24,25
}

# 5) 4688 — 그 Logon ID로 실행된 프로세스
Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4688} |
  Where-Object { $_.Message -match '0x1a2b3c' }
```

RDP 문제라면 4624 Type 10과 TerminalServices 21/25의 IP가 일치해야 한다. 불일치하면 프록시·점프 호스트를 경유한 것이다.

## mini walkthrough

```text
문제:
"2026-03-14에 침입이 있었습니다. 공격자가 사용한 계정과 접속 IP를 구하세요.
 첨부: Security.evtx (48,213 events)"

1. EvtxECmd.exe -f Security.evtx --csv out --csvf sec.csv
   -> 48,213행. 그대로는 못 본다.

2. 첫 시도 (실패한 접근):
   EventId=4624만 필터 -> 여전히 9,842행.
   대부분 TargetLogonId=0x3e7(SYSTEM)과 WIN10$ 컴퓨터 계정이었다.

3. 노이즈 제거 후:
   Import-Csv out\sec.csv |
     Where-Object { $_.EventId -eq 4624 -and
                    $_.Payload -notmatch '0x3e7|0x3e5|0x3e4' -and
                    $_.Payload -notmatch '"TargetUserName":"[^"]*\$"' }
   -> 137행. 볼 수 있는 크기.

4. Logon Type 10(RDP)만:
   ... | Where-Object { $_.Payload -match '"LogonType":"?10' }

   TimeCreated              TargetUserName  IpAddress      TargetLogonId
   2026-03-14 07:18:44Z     svc_backup      203.0.113.77   0x1a2b3c
   2026-03-14 09:02:11Z     jhkim           192.168.10.24  0x2f4e10

   svc_backup 은 서비스 계정인데 RDP로 로그인했다. 정상 계정은 이렇게 안 쓴다.
   IP도 공인 IP다. -> 이것이 공격자.

5. 확증 — 앞선 실패 시도 확인 (4625)
   ... EventId=4625, TargetUserName=svc_backup
   -> 07:11:02 ~ 07:18:39 사이 214건 실패. 무차별 대입 후 성공.

6. 확증 — 관리자 권한 (4672)
   SubjectLogonId=0x1a2b3c 인 4672 존재 -> 관리자 세션

7. pivot — 세션 내 활동 (4688, 같은 Logon ID)
   0x1a2b3c 로 실행된 프로세스:
     07:19:31  C:\Windows\System32\cmd.exe
     07:20:08  powershell.exe -enc SQBFAFgA...
     07:24:55  C:\Users\svc_backup\Downloads\rclone.exe

정답: 계정 svc_backup, IP 203.0.113.77
```

3단계의 노이즈 제거가 9,842행을 137행으로 줄인 지점이고, 4단계에서 "서비스 계정 + RDP + 공인 IP"라는 **조합의 부자연스러움**이 결정타였다.

## 막혔을 때 다음 체크

1. `$`로 끝나는 계정과 `0x3e7/0x3e5/0x3e4`를 제외했는가 — 이것만으로 대개 90% 감소
2. Logon Type 10 → 3 → 9 → 2 순서로 훑었는가
3. 4625(실패)를 함께 봤는가 — 공격 방식이 드러난다
4. 4672가 짝지어 있는가 — 관리자 세션 여부
5. `TargetLogonId`로 4688을 엮었는가 — 실제 명령이 여기 있다
6. 4624가 아예 없다면 → **1102**(감사 로그 삭제), **4719**(감사 정책 변경) 확인
7. RDP 문제인데 정보가 부족하면 → `TerminalServices-LocalSessionManager/Operational` 21/24/25, `RemoteConnectionManager` 1149
8. 계정이 정상 사용자라면 → 그 계정의 정상 로그온 패턴(시간대·IP·Logon Type)과 비교해 이탈 지점을 찾는다
9. 시간대를 UTC로 답했는지 KST로 답해야 하는지 문제 지문을 다시 읽는다

## 출처

- SRC-001 — Microsoft Learn, Event 4624: 전체 EventData 필드 정의와 Logon Type 표
- SRC-004 — Eric Zimmerman 문서: EvtxECmd CSV 출력 형식과 맵 파일
- SRC-014 — Microsoft Learn, File Times: EVTX `SystemTime`의 UTC 기준
