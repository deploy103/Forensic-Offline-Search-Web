---
id: FOR-0084
title: "Event ID 4625 실패 로그온: Status/SubStatus 코드로 공격 유형을 판정한다"
slug: "event-4625-failed-logon"
category: "Event Log"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Security.evtx", "4625", "Status", "SubStatus", "FailureReason", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]
registry_paths: []
event_ids: ["4625"]
protocols: ["NTLM", "Kerberos", "SMB", "RDP"]
tools: ["EvtxECmd", "PowerShell", "Timeline Explorer", "Event Viewer", "wevtutil"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --inc 4625 --csv 'C:\\case\\out' --csvf f.csv", "Get-WinEvent -FilterHashtable @{Path='Security.evtx';Id=4625}", "wevtutil qe Security.evtx /q:\"*[System[(EventID=4625)]]\" /f:text"]
regex_patterns: ["0xC0000[0-9A-Fa-f]{3}", "\"SubStatus\":\"?(0x[0-9A-Fa-f]+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["TargetUserName", "TargetDomainName", "LogonType", "Status", "SubStatus", "FailureReason", "WorkstationName", "IpAddress", "IpPort", "ProcessName", "LogonProcessName", "AuthenticationPackageName"]
file_formats: ["evtx"]
primary_terms: ["4625", "실패 로그온", "로그인 실패", "무차별 대입 흔적"]
keywords: ["4625", "실패 로그온", "failed logon", "Status", "SubStatus", "0xC000006A", "0xC0000064", "brute force", "password spray", "계정 열거", "무차별 대입", "Security.evtx", "FailureReason"]
aliases: ["4625", "로그인 실패 기록", "비밀번호 틀린 기록", "무차별 대입 확인", "brute force 흔적", "0xc000006a", "0xc0000064", "계정 잠김 원인"]
symptom_keywords: ["로그인 실패가 몇 번인지 알고 싶다", "무차별 대입 공격인지 판단해야 한다", "계정이 왜 잠겼는지 모르겠다", "SubStatus 코드가 무슨 뜻인지 모르겠다", "실패 뒤에 성공했는지 알고 싶다", "어느 IP에서 시도했는지"]
related: ["FOR-0083", "FOR-0081", "FOR-0087", "FOR-0106"]
source_ids: ["SRC-020", "SRC-022", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4625 는 실패한 로그온을 기록하고, **답은 `SubStatus` 코드 하나에 들어 있다.** `0xC0000064`(계정이 존재하지 않음)가 몰려 있으면 계정 목록을 모르고 뿌리는 열거·스프레이 공격, `0xC000006A`(비밀번호 틀림)가 몰려 있으면 계정은 이미 알고 비밀번호를 뚫는 무차별 대입이다.

## 어떤 문제에서 필요한가

- "무차별 대입 공격이 있었는가", "몇 번 시도했는가"
- "계정이 왜 잠겼는가" (0xC0000234 의 출처 추적)
- "공격자가 계정 목록을 알고 있었는가" (열거 vs 대입 판정)
- "실패한 뒤 결국 성공했는가" (4625 → 4624 전환점)
- "어느 IP/워크스테이션에서 시도했는가"

4625 는 실패 이벤트라 정상 사용자의 오타도 섞인다. **건수만 보고 공격이라 단정하면 틀린다.** 계정·IP·시각 분포와 `SubStatus` 조합으로 판정한다.

## 문제에서 처음 볼 단서

1. 짧은 시간에 4625 가 수백 건 → 자동화 도구. 사람 손이 아니다
2. `TargetUserName`이 매번 다르다 → **계정 열거 또는 패스워드 스프레이**
3. `TargetUserName`이 하나뿐이고 반복 → **무차별 대입**
4. `IpAddress`가 공인 IP → 외부 노출. 내부망 IP → 측면 이동
5. `WorkstationName`이 시스템의 다른 호스트명과 이질적 → 공격자 단말 이름
6. `LogonType` = 3 이 대부분 → 네트워크(SMB/WinRM) 또는 **NLA 가 켜진 RDP**
7. 성공 로그온([FOR-0083](./event-4624-logon.html))이 실패 구간 직후에 하나 있다 → 그 계정이 뚫린 계정

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --inc 4625 --csv 'C:\case\out' --csvf f.csv
```

CSV 가 나오면 세 가지를 집계한다. **이 세 표가 공격 유형을 결정한다.**

```powershell
$f = Import-Csv 'C:\case\out\f.csv'

# 원본 EventData 필드 이름으로 값을 뽑는다 (컬럼 배치 변화에 안전)
function Fld { param($p,$n)
  $m=[regex]::Match($p,'"'+[regex]::Escape($n)+'"\s*:\s*"?([^",}]*)'); if($m.Success){$m.Groups[1].Value}else{''} }

$rows = $f | ForEach-Object {
  [pscustomobject]@{
    Time      = $_.TimeCreated
    User      = Fld $_.Payload 'TargetUserName'
    Domain    = Fld $_.Payload 'TargetDomainName'
    Type      = Fld $_.Payload 'LogonType'
    Status    = Fld $_.Payload 'Status'
    SubStatus = Fld $_.Payload 'SubStatus'
    Ip        = Fld $_.Payload 'IpAddress'
    Wks       = Fld $_.Payload 'WorkstationName'
    Proc      = Fld $_.Payload 'ProcessName'
  }
}

# 1) SubStatus 분포 — 공격 유형 판정
$rows | Group-Object SubStatus | Sort-Object Count -Descending | Format-Table Count, Name

# 2) 계정 분포 — 계정 수가 많으면 열거/스프레이, 하나면 대입
$rows | Group-Object User | Sort-Object Count -Descending | Select-Object -First 15 Count, Name

# 3) IP 분포 — 단일 IP 면 단일 공격자, 다수면 분산
$rows | Group-Object Ip | Sort-Object Count -Descending | Select-Object -First 15 Count, Name
```

## 상세 절차

### 1단계 — Status / SubStatus 코드표 (이 글의 핵심)

**둘 중 의미를 담고 있는 쪽은 대개 `SubStatus` 다.** `Status`는 상위 실패 분류로 `0xC000006D`(STATUS_LOGON_FAILURE)가 대부분이고, 구체적 이유는 `SubStatus`에 들어간다. 반대로 계정 잠김·비활성처럼 인증 이전에 거절된 경우에는 **`Status` 자체가 구체적 코드**를 갖고 `SubStatus`는 `0x0`이 된다.

| 코드 | 의미 | 어느 필드에 주로 | 포렌식 해석 |
| --- | --- | --- | --- |
| `0xC000006D` | 일반 로그온 실패 (사용자명 또는 인증 정보 오류) | `Status` | 상위 분류. **여기서 멈추지 말고 `SubStatus`를 본다** |
| `0xC000006A` | 사용자명은 맞고 **비밀번호가 틀렸다** | `SubStatus` | **계정은 이미 알고 있다.** 무차별 대입 / 스프레이 |
| `0xC0000064` | 사용자명이 **존재하지 않는다** | `SubStatus` | **계정 목록을 모른다.** 계정 열거 / 사전 공격 |
| `0xC0000234` | 계정이 **잠겨 있다** | `Status` | 잠금 정책 발동. 4740 과 짝 |
| `0xC0000072` | 계정이 **비활성**이다 | `Status` | 비활성 계정을 노렸다 = 오래된 계정 목록 보유 |
| `0xC0000070` | **워크스테이션 제한** 위반 | `Status` | 허용되지 않은 단말에서 시도 |
| `0xC000006F` | **허용된 시간 외** 로그온 | `Status` | 근무 시간 정책 위반. 새벽 접근 신호 |
| `0xC0000193` | 계정이 **만료**되었다 | `Status` | 퇴사자/임시 계정 |
| `0xC0000071` | **비밀번호가 만료**되었다 | `Status` | 비밀번호는 맞았다는 뜻 — **자격증명 유출 신호** |
| `0xC0000133` | 도메인 컨트롤러와의 **시각 차이**가 너무 크다 | `Status` | Kerberos 실패. **타임스탬프 신뢰도 자체를 의심해야 한다** |
| `0xC0000224` | 다음 로그온 시 **비밀번호 변경이 필요**하다 | `Status` | 비밀번호는 맞았다 |

판정에서 특히 중요한 두 줄만 다시 정리한다.

| SubStatus | 공격자가 아는 것 | 대응하는 공격 유형 |
| --- | --- | --- |
| `0xC0000064` (계정 없음) | **아무것도 모른다** — 이름을 추측해서 뿌리는 중 | 계정 열거(user enumeration), 사전 기반 스프레이 |
| `0xC000006A` (비밀번호 틀림) | **유효한 계정 이름을 안다** — 비밀번호만 남았다 | 무차별 대입(brute force), 패스워드 스프레이 |

`0xC0000071`(비밀번호 만료)과 `0xC0000224`(변경 필요)는 **비밀번호 자체는 맞았다**는 뜻이다. 이 두 코드가 공격 구간에 섞여 있으면 유출된 자격증명을 쓴 것으로 봐야 한다. 건수는 적어도 가치가 가장 높다.

`FailureReason`은 `%%2313` 같은 리소스 문자열 참조로 저장된다(`%%2313` = 사용자명 또는 비밀번호 오류). 표시 문자열은 OS 언어에 따라 달라지므로 **판정 근거로는 `Status`/`SubStatus` 숫자를 쓴다.**

### 2단계 — 필드표

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `TargetUserName` | 실패한 대상 계정 | 존재하지 않는 계정도 그대로 기록된다 |
| `TargetDomainName` | 대상 도메인 | 비어 있거나 `-`면 도메인을 몰랐다는 뜻 |
| `TargetUserSid` | 대상 SID | 계정이 없으면 `S-1-0-0` |
| `LogonType` | 시도한 접속 방식 | 3=네트워크, 10=RDP, 2=콘솔, 8=평문 |
| `Status` | 상위 실패 코드 | 대개 `0xC000006D` |
| `SubStatus` | **구체적 실패 코드** | 여기가 답이다 |
| `FailureReason` | `%%23xx` 리소스 참조 | 언어 의존. 숫자 코드를 우선 |
| `WorkstationName` | 시도한 클라이언트 이름 | 공격 도구가 자기 호스트명을 남기는 경우가 많다. 빈 값도 신호 |
| `IpAddress` | 출처 IP | `-`면 로컬 시도 |
| `IpPort` | 출처 포트 | 값이 있으면 실제 TCP 세션 존재 |
| `ProcessName` | 인증을 처리한 프로세스 | `lsass.exe`, `winlogon.exe`, `svchost.exe` |
| `LogonProcessName` | 로그온 처리기 | `NtLmSsp`(네트워크 NTLM), `User32`(콘솔), `Advapi`(runas/서비스), `Kerberos` |
| `AuthenticationPackageName` | 인증 패키지 | `NTLM` / `Kerberos` / `Negotiate` |
| `SubjectUserName` / `SubjectLogonId` | 이 시도를 **요청한** 주체 | 대개 `-` / `0x0`. 값이 있으면 기존 세션에서 시도한 것 |
| `TransmittedServices` | 위임 경로 | 값이 있으면 제약 위임 관련 |

### 3단계 — 공격 유형 판정표

| 관찰 | 무차별 대입 | 패스워드 스프레이 | 계정 열거 | 정상 오타 |
| --- | --- | --- | --- | --- |
| 계정 수 | **1개** | 많음 (수십~수백) | 많음 | 1개 |
| 계정당 시도 수 | 수십~수천 | **1~3회** (잠금 회피) | 1~2회 | 1~3회 |
| 지배적 `SubStatus` | `0xC000006A` | `0xC000006A` | **`0xC0000064`** | `0xC000006A` |
| 시각 간격 | 초 단위, 규칙적 | 계정을 순회, 잠금 임계 밑으로 분산 | 초 단위 | 불규칙, 수 분 |
| IP | 1개 | 1~수개 | 1개 | 사용자 평소 IP |
| `WorkstationName` | 동일값 반복 또는 공백 | 동일값 반복 | 동일값 반복 | 사용자 PC 이름 |
| 마지막 결과 | 4624 성공 또는 `0xC0000234` 잠김 | 어느 계정 하나에서 4624 | 성공 없음 → 이후 대입으로 전환 | 곧 4624 성공 |

판정 쿼리:

```powershell
# 계정 수 vs 계정당 시도 수 — 이 두 숫자로 대입/스프레이가 갈린다
$g = $rows | Group-Object User
[pscustomobject]@{
  Accounts       = $g.Count
  TotalAttempts  = $rows.Count
  MaxPerAccount  = ($g | Measure-Object Count -Maximum).Maximum
  MedianPerAcct  = ($g.Count | Measure-Object -Average).Average
}

# 분당 시도 수 — 사람 손인지 자동화인지
$rows | Group-Object { ([datetime]$_.Time).ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

# 계정 x SubStatus 교차표 — 열거 뒤 대입으로 전환한 지점이 보인다
$rows | Group-Object User, SubStatus | Sort-Object Count -Descending |
  Select-Object -First 20 Count, Name
```

마지막 교차표가 가장 유용하다. 같은 계정에 대해 `0xC0000064` → `0xC000006A`로 코드가 바뀌는 순간이 **"그 계정이 실재한다는 것을 공격자가 알아낸 시점"** 이다.

### 4단계 — 4625 뒤의 4624 성공 찾기

무차별 대입의 결론은 "뚫렸는가"다. 실패 구간의 마지막 시각 이후 같은 계정의 4624 를 찾는다.

```powershell
$all = Import-Csv 'C:\case\out\all.csv'   # 4624 와 4625 가 함께 든 CSV

# 실패한 계정 목록
$failed = $all | Where-Object { $_.EventId -eq '4625' } |
  ForEach-Object { Fld $_.Payload 'TargetUserName' } | Sort-Object -Unique

# 그 계정들의 성공 로그온
$all | Where-Object { $_.EventId -eq '4624' } | ForEach-Object {
  $u = Fld $_.Payload 'TargetUserName'
  if ($failed -contains $u -and $u -notmatch '\$$') {
    [pscustomobject]@{
      Time    = $_.TimeCreated
      User    = $u
      Type    = Fld $_.Payload 'LogonType'
      Ip      = Fld $_.Payload 'IpAddress'
      LogonId = Fld $_.Payload 'TargetLogonId'
    }
  }
} | Sort-Object Time | Format-Table -AutoSize
```

성공한 4624 의 `TargetLogonId`가 나오면 거기서부터는 [FOR-0083](./event-4624-logon.html)의 세션 추적으로 넘어간다. 그 세션에 4672 가 붙어 있는지도 즉시 확인한다([FOR-0087](./event-4672-special-privileges.html)).

### 5단계 — 4771 / 4776 과의 관계

4625 는 **로그온을 시도받은 컴퓨터**에 남는다. 자격증명을 실제로 검증한 컴퓨터(도메인 환경이면 도메인 컨트롤러)에는 다른 이벤트가 남는다.

| Event ID | 어디에 남나 | 무엇인가 | 실패 코드 필드 |
| --- | --- | --- | --- |
| 4625 | 로그온 대상 컴퓨터 | 로그온 실패 | `Status` / `SubStatus` (`0xC00000xx`) |
| 4776 | 자격증명 검증자 (DC 또는 로컬) | **NTLM** 자격증명 검증 시도/실패 | `Status` (`0xC0000064`, `0xC000006A` 등 동일 계열) |
| 4771 | 도메인 컨트롤러 | **Kerberos** 사전 인증 실패 | `Status` = Kerberos 오류 코드 (아래) |
| 4768 / 4769 | 도메인 컨트롤러 | Kerberos TGT / 서비스 티켓 요청 | 실패 시 오류 코드 포함 |
| 4740 | 계정을 잠근 컴퓨터 | 계정 잠김 | `CallerComputerName`에 잠금 유발 단말 |
| 4767 | — | 계정 잠금 해제 | — |

4771 의 주요 Kerberos 오류 코드:

| 코드 | 의미 |
| --- | --- |
| `0x6` | 클라이언트 주체를 찾을 수 없음 (계정 없음) — 열거 신호 |
| `0x12` | 자격증명이 취소됨 (비활성/잠김/만료) |
| `0x17` | 비밀번호 만료 |
| `0x18` | **사전 인증 실패 = 비밀번호 틀림** |

즉 Kerberos 환경에서의 대입/열거 구분은 4771 의 `0x18` vs `0x6`이고, 이는 4625 의 `0xC000006A` vs `0xC0000064`와 정확히 같은 판정선이다.

**로컬 계정 대입은 4625 에만, 도메인 계정 대입은 DC 의 4771/4776 에만 남는 경우가 있다.** 4625 가 적은데 공격이 의심되면 DC 로그를 요구한다.

## 출력 필드 해석

```text
EvtxECmd CSV 한 행 (4625, 값은 예시)

TimeCreated  : 2026-03-14 07:11:02.1234567Z      <- UTC
EventId      : 4625
Channel      : Security
Computer     : WIN10-FIN01
Payload      : {"SubjectUserSid":"S-1-0-0","SubjectUserName":"-",
                "SubjectDomainName":"-","SubjectLogonId":"0x0",
                "TargetUserSid":"S-1-0-0","TargetUserName":"svc_backup",
                "TargetDomainName":"WIN10-FIN01","Status":"0xc000006d",
                "FailureReason":"%%2313","SubStatus":"0xc000006a",
                "LogonType":"3","LogonProcessName":"NtLmSsp ",
                "AuthenticationPackageName":"NTLM","WorkstationName":"KALI",
                "TransmittedServices":"-","LmPackageName":"-","KeyLength":"0",
                "ProcessId":"0x0","ProcessName":"-",
                "IpAddress":"203.0.113.77","IpPort":"49312"}
```

이 한 행에서 읽어야 하는 것: `SubStatus = 0xc000006a` → **계정 이름은 유효하다, 비밀번호를 뚫는 중**. `WorkstationName = KALI` → 공격 도구 단말. `LogonType = 3` + `NtLmSsp` → SMB/WinRM 또는 NLA 가 켜진 RDP.

코드 값은 **대소문자가 섞여 나온다**(`0xc000006a` / `0xC000006A`). 필터할 때 `-imatch`를 쓰거나 소문자로 정규화한다.

**시각은 UTC 다.** EVTX 의 `SystemTime`은 항상 UTC 로 저장되고 EvtxECmd CSV 도 UTC 로 출력한다. Event Viewer 는 로컬 시간대로 변환해 보여준다. **KST 로 답해야 하면 +9시간**: `07:11:02Z` → `16:11:02 KST`. 대상 시스템의 시간대는 [FOR-0054](./system-timezone.html)에서 확인한다.

## pivot: 다음에 볼 artifact

| 4625 에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 실패한 계정 이름 | 4624 ([FOR-0083](./event-4624-logon.html)) | 결국 성공했는가, `TargetLogonId` |
| `IpAddress` | pcap `ip.addr == <IP>` | 실제 인증 트래픽, 사용된 도구 특징 |
| `IpAddress` | 방화벽/프록시 로그 | 접근 경로, 다른 대상 호스트 |
| `WorkstationName` | DHCP·ARP·다른 호스트 EVTX | 공격자 단말 특정 |
| `SubStatus = 0xC0000234` | 4740 | 잠금을 유발한 `CallerComputerName` |
| `SubStatus = 0xC0000133` | System 채널 시각 변경, `TimeZoneInformation` | **타임스탬프 신뢰성 자체를 재검토** |
| 도메인 계정 실패 | DC 의 4771 / 4776 / 4768 | 실제 검증 결과와 오류 코드 |
| `LogonType = 3` 다수 | TerminalServices 채널 | NLA RDP 였는지, SMB 였는지 |
| 성공 후 세션 | 4672 ([FOR-0087](./event-4672-special-privileges.html)), 4648 ([FOR-0086](./event-4648-explicit-credentials.html)) | 권한 상승, 측면 이동 |
| 실패 시각대 | Prefetch / UserAssist ([FOR-0061](./userassist.html)) | 로컬에서 실행된 도구 흔적 |

## 흔한 함정

- **`Status`만 보고 판정하는 것.** `Status = 0xC000006D`는 "실패했다"는 말밖에 하지 않는다. 계정 열거인지 비밀번호 대입인지는 **`SubStatus`에만 있다.** 이 실수 하나로 정반대 결론이 나온다.
- **`SubStatus`가 `0x0`인데 코드가 없다고 포기하는 것.** 잠김(`0xC0000234`)·비활성(`0xC0000072`)·만료(`0xC0000193`)처럼 인증 이전 거절은 `Status` 자체가 구체적 코드다. `SubStatus`가 `0x0`이면 `Status`를 읽는다.
- **`FailureReason` 문자열로 판정하는 것.** `%%2313` 같은 리소스 참조이고 표시 문자열은 OS 언어에 따라 달라진다. 한국어 Windows 의 표시명으로 grep 하면 영문 시스템에서 안 맞는다. 숫자 코드를 쓴다.
- **건수만으로 공격이라 단정하는 것.** 서비스 계정의 만료된 비밀번호가 스케줄러에서 반복 재시도되면 하루 수천 건의 4625 가 정상적으로 발생한다. `ProcessName`·`LogonType`·간격의 규칙성을 함께 본다.
- **4625 가 없으면 대입이 없었다고 결론 내는 것.** 도메인 계정에 대한 시도는 DC 의 4771/4776 에만 남을 수 있다. 또 감사 정책의 "Audit Logon" 실패 감사가 꺼져 있으면 아예 기록되지 않는다(4719 확인).
- **RDP 대입인데 `LogonType = 10`을 찾는 것.** NLA(네트워크 수준 인증)가 켜진 RDP 의 인증 실패는 **`LogonType = 3`으로 기록되는 경우가 많다.** Type 10 만 필터하면 RDP 대입을 통째로 놓친다.
- **`0xC0000071`/`0xC0000224`를 노이즈로 버리는 것.** 이 둘은 **비밀번호가 맞았다**는 뜻이다. 건수가 1건이어도 자격증명 유출의 직접 증거다.
- **`0xC0000133`(시각 차이)을 단순 설정 오류로 넘기는 것.** 시각이 어긋난 구간의 모든 타임스탬프 해석이 흔들린다. 타임라인을 만들기 전에 처리해야 한다.
- **코드 대소문자.** `Payload`의 값은 `0xc000006a`처럼 소문자로 나오는 경우가 많다. `-match '0xC000006A'`는 PowerShell 에서 기본적으로 대소문자를 구분하지 않지만, 다른 도구(grep, Python)에서는 놓친다.
- **UTC/KST 혼동.** 4625 의 시각 분포가 판정 근거인데 시간대를 잘못 잡으면 "새벽 3시 대입"이 "정오 정상 로그인"으로 뒤바뀐다.
- **컴퓨터 계정(`WIN10$`) 실패를 사람으로 세는 것.** 도메인 신뢰 문제로 발생하는 정상 실패다.

## 교차검증

```powershell
# A) 실패 → 성공 전환 시각 (계정별 마지막 실패와 첫 성공)
$all = Import-Csv 'C:\case\out\all.csv'
$all | Where-Object { $_.EventId -in '4624','4625' } | ForEach-Object {
  [pscustomobject]@{
    Time = [datetime]$_.TimeCreated
    Id   = $_.EventId
    User = Fld $_.Payload 'TargetUserName'
    Ip   = Fld $_.Payload 'IpAddress'
  }
} | Where-Object { $_.User -notmatch '\$$' } |
  Group-Object User | ForEach-Object {
    $s = $_.Group | Sort-Object Time
    [pscustomobject]@{
      User       = $_.Name
      Fails      = ($s | Where-Object Id -eq '4625').Count
      LastFail   = ($s | Where-Object Id -eq '4625' | Select-Object -Last 1).Time
      FirstOk    = ($s | Where-Object Id -eq '4624' | Select-Object -First 1).Time
    }
  } | Where-Object { $_.Fails -gt 5 -and $_.FirstOk } | Format-Table -AutoSize

# B) 계정 잠김 확인 — 4740 과 4625(0xC0000234) 대조
$all | Where-Object { $_.EventId -eq '4740' } |
  Select-Object TimeCreated, MapDescription, UserName

# C) 감사 정책이 실패를 기록하고 있었는지 — 4719 확인
$all | Where-Object { $_.EventId -in '4719','1102' } |
  Select-Object TimeCreated, EventId, MapDescription

# D) 도구 독립 검증 — Get-WinEvent 로 건수 대조
(Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx'; Id=4625}).Count
```

A 의 출력에서 `Fails`가 크고 `FirstOk`가 `LastFail` 직후인 계정이 곧 뚫린 계정이다.

## mini walkthrough

```text
문제:
"외부에서 무차별 대입 공격이 있었습니다. 공격자가 최종적으로 획득한 계정과
 최초 성공 시각(KST)을 구하세요.
 첨부: Security.evtx"

1. EvtxECmd.exe -f Security.evtx --inc 4624,4625 --csv out --csvf all.csv
   -> 4625 가 2,847건, 4624 가 9,102건.

2. 첫 시도 (실패한 접근):
   4625 를 건수로만 집계했다.

     Count User
     ----- ----
      1912 administrator
       402 admin
       311 test
       ...

   "administrator 에 1,912번 대입했다"고 결론 내고 4624 에서 administrator 를 찾았다.
   -> administrator 의 성공 로그온이 없다. 막혔다.

   왜 틀렸나: SubStatus 를 보지 않았다. 계정 이름만 세면
   "존재하지 않는 계정에 뿌린 것"과 "실재하는 계정을 뚫은 것"이 한 덩어리로 섞인다.

3. 방향 전환 — SubStatus 분포부터:
     Count Name
     ----- ----
      2603 0xc0000064     <- 계정이 존재하지 않음
       241 0xc000006a     <- 비밀번호 틀림
         2 0xc0000071     <- 비밀번호 만료 (!)
         1 0xc0000234     <- 계정 잠김

   -> 2,603건은 계정 열거였다. 실재하는 계정은 0xc000006a 쪽에만 있다.

4. 0xc000006a 만 다시 계정 집계:
     Count User
     ----- ----
       198 svc_backup
        41 jhkim
         2 (0xc0000071 계정: helpdesk)

   -> administrator 는 애초에 존재하지 않는 계정이었다(0xc0000064).
      실재 계정은 svc_backup, jhkim, helpdesk 세 개.

5. 0xc0000071(비밀번호 만료) 2건을 본다 — helpdesk:
   비밀번호가 맞았다는 뜻이다. 유출된 자격증명이다.
   하지만 만료 상태라 로그인은 못 했다. 성공 로그온 없음.

6. svc_backup 의 시간 순서:
   07:11:02Z ~ 07:18:39Z  4625 x 198  (0xc000006a, IP 203.0.113.77, Wks=KALI)
   07:18:44Z              4624        (LogonType 10, IP 203.0.113.77)
   07:18:44Z              4672        (SubjectLogonId 0x1a2b3c)

   -> 실패 198건 직후 성공. 획득 계정 확정.

7. jhkim 은 41건 실패 후 성공이 없다 -> 뚫리지 않았다.

8. 시각 변환: 07:18:44Z + 9h = 2026-03-14 16:18:44 KST

정답: svc_backup, 2026-03-14 16:18:44 KST
      (부수 발견: helpdesk 자격증명도 유출 상태 — 0xC0000071)
```

2단계의 실패가 이 글의 요점이다. **계정 이름 빈도는 공격자의 사전 목록을 보여줄 뿐이고, 실제로 존재하는 계정은 `SubStatus`가 알려준다.** 3~4단계에서 `0xC0000064`를 걷어내자 2,847건이 241건으로 줄고, 후보 계정이 3개로 확정되었다.

## 막혔을 때 다음 체크

1. `SubStatus`를 봤는가 — `Status`만 보면 판정이 불가능하다
2. `SubStatus`가 `0x0`이면 `Status`를 읽었는가
3. `0xC0000064`(계정 없음)를 걷어내고 다시 집계했는가 — 후보가 대폭 줄어든다
4. `0xC0000071` / `0xC0000224`가 있는가 — **비밀번호가 맞은 시도**다. 최우선
5. 실패 구간 직후의 4624 를 찾았는가 — 그것이 침입 시각이다
6. `LogonType`을 3 만 보거나 10 만 보고 있지 않은가 — NLA RDP 는 3 으로 남는다
7. 4625 가 거의 없다면 → DC 의 4771 / 4776, 그리고 4719(감사 정책 변경)
8. 계정 잠김이 있으면 4740 의 `CallerComputerName`을 봤는가
9. 계정 수와 계정당 시도 수를 계산했는가 — 대입/스프레이/열거의 판별선
10. 답이 UTC 인지 KST 인지 확인했는가 (+9시간)

## 출처

- SRC-020 — Microsoft Learn, Event 4625: 전체 EventData 필드 정의와 `Status`/`SubStatus` 코드별 의미 (`0xC000006D`, `0xC000006A`, `0xC0000064`, `0xC0000234`, `0xC0000072`, `0xC0000070`, `0xC000006F`, `0xC0000193`, `0xC0000071`, `0xC0000133`, `0xC0000224`)
- SRC-022 — Microsoft Learn, Advanced security audit policy settings: 4771 / 4776 / 4740 / 4767 이 어느 감사 하위 범주에서 어느 컴퓨터에 기록되는지
- SRC-004 — Eric Zimmerman 문서: EvtxECmd 의 `--inc` 필터와 `Payload` 원본 JSON 컬럼
- `FailureReason` 의 `%%23xx` 리소스 문자열 대응표와 4771 오류 코드 전체 목록은 OS 버전·언어에 따라 다를 수 있으므로 실제 이벤트 화면에서 확인할 것
</content>
