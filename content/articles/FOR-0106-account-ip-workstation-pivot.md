---
id: FOR-0106
title: "계정·IP·WorkstationName 3축 pivot: 공격자 단말과 측면 이동 경로 특정"
slug: "account-ip-workstation-pivot"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["IpAddress", "WorkstationName", "TargetUserName", "ShareName", "Security.evtx", "EVTX"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\dhcp", "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"]
event_ids: []
protocols: ["SMB", "RDP", "NTLM", "Kerberos", "DHCP", "ARP"]
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "Wireshark", "tshark"]
commands: ["EvtxECmd.exe -d 'C:\\case\\winevt' --csv 'C:\\case\\out' --csvf all.csv", "tshark -r cap.pcapng -Y \"ip.addr==203.0.113.77\" -T fields -e frame.time -e eth.src"]
regex_patterns: ["\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "\"WorkstationName\":\\s*\"([^\"]*)\""]
wireshark_filters: ["ip.addr == 203.0.113.77", "smb2 || smb"]
tshark_fields: ["ip.src", "ip.dst", "eth.src", "nbns.name"]
log_fields: ["IpAddress", "IpPort", "WorkstationName", "Workstation", "TargetUserName", "SubjectUserName", "TargetServerName", "ShareName", "RelativeTargetName", "SourceIp", "DestinationIp"]
file_formats: ["evtx", "csv", "pcapng"]
primary_terms: ["계정 IP pivot", "WorkstationName 추적", "공격자 단말 특정"]
keywords: ["IpAddress", "WorkstationName", "계정", "IP", "단말", "측면 이동", "lateral movement", "pivot", "ShareName", "TargetServerName", "DHCP", "ARP", "위조"]
aliases: ["ip로 계정 찾기", "workstationname 위조", "공격자 pc 이름", "측면 이동 경로", "접속 ip 추적", "어느 단말에서 접속했나", "IpAddress가 -로 나온다"]
symptom_keywords: ["접속한 IP를 알고 싶다", "WorkstationName이 이상하다", "IpAddress가 -로 나온다", "어느 PC에서 들어왔는지 모르겠다", "측면 이동 경로를 그려야 한다", "IP와 단말을 연결하고 싶다"]
related: ["FOR-0083", "FOR-0104", "FOR-0108"]
source_ids: ["SRC-001", "SRC-020", "SRC-022"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

계정·IP·`WorkstationName` 세 축은 **이벤트마다 다른 필드 이름으로 흩어져 있고**, 한 축을 잡으면 나머지 두 축으로 확장해 공격자 단말을 특정할 수 있다 — 단 `WorkstationName` 은 클라이언트가 스스로 신고한 값이라 위조 가능하므로 IP는 pcap/DHCP/ARP로, 계정은 SID로 각각 고정해야 확증이 된다.

## 어떤 문제에서 필요한가

- "공격자가 어느 단말에서 접속했는가" — IP만으로는 단말 이름이 안 나오는 문제
- "이 IP로 접속한 계정 전부를 나열하라" — 한 축에서 나머지로 확장하는 문제
- 여러 호스트의 EVTX가 주어지고 측면 이동 경로를 그려야 하는 문제
- `IpAddress` 가 `-` 또는 `::1` 로 나와 출처를 못 잡는 문제
- 도메인 환경에서 어느 계정이 어느 서버에 접근했는지 매트릭스를 만들어야 하는 문제

## 문제에서 처음 볼 단서

1. 지문에 IP 하나가 주어졌다 → `IpAddress` 로 전 채널 검색. 가장 빠른 시작점
2. 지문에 계정 하나가 주어졌다 → `TargetUserName` → 그 계정의 IP 집합 → 그 IP의 다른 계정
3. 지문에 PC 이름이 주어졌다 → `WorkstationName` / `Workstation` / `Computer`
4. EVTX가 여러 호스트 분량이다 → `Computer` 컬럼으로 호스트를 구분하고 호스트 간 IP를 잇는다
5. pcap이 함께 있다 → IP↔MAC 고정이 가능하다. 여기서 위조 판정이 끝난다

## 30초 절차

```powershell
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
```

세 축을 한 번에 훑는 집계다. **어느 축이 가장 좁은지 보고 시작점을 정한다.**

```powershell
$csv = Import-Csv 'C:\case\out\all.csv'

# IP 축
$csv | Where-Object { $_.RemoteHost -and $_.RemoteHost -ne '-' } |
  Group-Object RemoteHost | Sort-Object Count -Descending |
  Select-Object -First 20 Name, Count

# 계정 축 (컴퓨터 계정 제외)
$csv | Where-Object { $_.UserName -and $_.UserName -notmatch '\$$' } |
  Group-Object UserName | Sort-Object Count -Descending |
  Select-Object -First 20 Name, Count
```

`RemoteHost` / `UserName` 컬럼은 EvtxECmd가 payload에서 뽑아 채우는 편의 컬럼이다. **비어 있는 이벤트가 있으므로 정확한 집계는 `Payload` 원본에서 필드 이름으로 뽑는다.**

## 상세 절차

### 1단계 — 세 축이 어느 이벤트의 어느 필드에 있는가

이 표가 이 글의 본체다. 필드 이름이 조금씩 달라서 한 이름으로 검색하면 절반이 빠진다.

| 이벤트 | 채널 | 계정 필드 | IP 필드 | 단말/서버 필드 |
| --- | --- | --- | --- | --- |
| 4624 (로그온 성공) | Security | `TargetUserName`, `TargetDomainName`, `TargetUserSid` | `IpAddress`, `IpPort` | `WorkstationName` |
| 4625 (로그온 실패) | Security | `TargetUserName`, `TargetDomainName` | `IpAddress`, `IpPort` | `WorkstationName` |
| 4648 (명시적 자격증명) | Security | `SubjectUserName`(시도한 쪽), `TargetUserName`(사용한 계정) | `IpAddress`, `IpPort` | **`TargetServerName`**, `TargetInfo` |
| 4776 (NTLM 검증) | Security | `TargetUserName` | **없음** | **`Workstation`** (`Name` 접미사 없음) |
| 4768 / 4769 (Kerberos) | Security | `TargetUserName`, `ServiceName` | `IpAddress`, `IpPort` | 없음 |
| 5140 (공유 접근) | Security | `SubjectUserName`, `SubjectUserSid` | `IpAddress`, `IpPort` | `ShareName`, `ShareLocalPath` |
| 5145 (공유 객체 접근 검사) | Security | `SubjectUserName` | `IpAddress`, `IpPort` | `ShareName`, `RelativeTargetName` |
| 1149 (RDP 인증 성공) | TerminalServices-RemoteConnectionManager/Operational | `Param1`(사용자), `Param2`(도메인) | **`Param3`**(원본 주소) | 없음 |
| 21 / 24 / 25 (RDP 세션) | TerminalServices-LocalSessionManager/Operational | `User` | 원본 주소 필드 | `SessionID` |
| Sysmon 3 (네트워크 연결) | Sysmon/Operational | `User` | **`SourceIp`, `DestinationIp`** (+ 포트) | `SourceHostname`, `DestinationHostname` |
| 모든 이벤트 | 공통 | — | — | `Computer` (**로그를 남긴 호스트 자신**) |

주의점 세 가지.

- **4776에는 IP가 없다.** NTLM 검증은 인증 서버가 남기는 이벤트이고 원본 IP가 들어가지 않는다. 계정 + `Workstation` + 시각으로만 엮는다
- **1149와 21/24/25는 `EventData` 가 아니라 `UserData` 구조**다. `Get-WinEvent` 의 XPath를 `EventData[...]` 로 쓰면 매칭되지 않는다
- **`Computer` 는 접속한 쪽이 아니라 기록한 쪽**이다. 여러 호스트의 EVTX를 합쳤을 때 이 컬럼이 "목적지 호스트"가 된다

### 2단계 — IpAddress 값 해석

| 값 | 의미 | 실전 판정 |
| --- | --- | --- |
| `-` | 네트워크 출처가 없다 | 콘솔 로그온(Type 2), 서비스(Type 5), 배치(Type 4). **"숨겼다"가 아니다** |
| `127.0.0.1` / `::1` | 루프백 | 로컬에서 실행된 원격 도구, 포트 포워딩, 터널의 끝단 |
| `::ffff:192.168.1.10` | IPv4-mapped IPv6 | 실제로는 `192.168.1.10`. **문자열 검색이 빗나가는 원인** |
| `fe80::...` | 링크 로컬 IPv6 | 같은 세그먼트. MAC 기반 주소면 EUI-64에서 MAC 추출 가능 |
| `10.x` / `172.16-31.x` / `192.168.x` | 사설 IP | 내부망. **측면 이동 후보** |
| 공인 IP | 외부 직접 접속 | 방화벽/포트 포워딩 노출 |
| `0.0.0.0` | 미확정 | 드라이버·서비스 계층 기록. 출처 근거로 쓰지 않는다 |

IPv4/IPv6 표기 혼재 때문에 검색이 빗나가므로, 검색 전에 정규화한다.

```powershell
function Get-IpNormalized {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
  $t = $Text.Trim()
  if ($t -match '^::ffff:(\d{1,3}(\.\d{1,3}){3})$') { return $Matches[1] }
  if ($t -eq '::1') { return '127.0.0.1' }
  return $t
}

Get-IpNormalized '::ffff:192.168.10.24'   # 192.168.10.24
Get-IpNormalized '::1'                    # 127.0.0.1
```

IPv4 추출 정규식 자체가 필요하면 [FOR-0128](./ipv4-regex.html)의 패턴을 쓴다. 여기서는 필드 값이 이미 IP이므로 정규화만 한다.

### 3단계 — WorkstationName 은 자기 신고 값이다

`WorkstationName` 은 클라이언트가 인증 요청에 실어 보내는 문자열이다. 서버는 검증하지 않는다. **즉 위조가 가능하다.**

그런데 이것이 오히려 강한 지표가 된다. 공격 도구는 사람이 쓰는 PC와 다른 형태의 값을 남긴다.

| 관찰 형태 | 해석 | 확증 방법 |
| --- | --- | --- |
| 정상 호스트명 (`DESKTOP-A1B2C3`, `PC-JHKIM`) | 사내 자산일 가능성 | 자산 목록·DHCP·다른 호스트 EVTX와 대조 |
| **빈 값 / `-`** | 클라이언트가 값을 안 보냈다. 스크립트·라이브러리 기반 도구에서 흔하다 | 같은 IP의 다른 이벤트에서 이름이 나오는지 |
| 무의미한 무작위 문자열 | 도구가 임의 생성한 값 | 같은 IP의 다른 접속에서 값이 매번 바뀌는지 확인 |
| 사내 명명 규칙에서 벗어난 이름 | 외부 단말 | 자산 목록에 없으면 확정적 신호 |
| IP 자체가 이름으로 들어옴 | 이름 대신 주소를 넣는 클라이언트 | 도구 종류 추정 단서 |
| **같은 IP인데 이름이 여러 개** | 위조 또는 NAT 뒤의 여러 단말 | 세션 시각으로 분리 |
| **같은 이름인데 IP가 여러 개** | 이름 위조 또는 DHCP 재할당 | DHCP 로그로 시각별 IP 확인 |

**특정 공격 도구의 기본 `WorkstationName` 값을 단정하지 않는다.** 도구·버전·옵션에 따라 다르다. 판정은 "그 조직의 정상 패턴에서 벗어났는가"로 한다.

```powershell
# 같은 IP 에서 관측된 WorkstationName 이 여러 개인가 (위조 신호)
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4624 or EventID=4625)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC = $x.Event.System.TimeCreated.SystemTime
      EventId = $_.Id
      User    = $d['TargetUserName']
      Ip      = Get-IpNormalized $d['IpAddress']
      Wks     = $d['WorkstationName']
    }
  } |
  Where-Object { $_.Ip -and $_.Ip -ne '-' } |
  Group-Object Ip |
  ForEach-Object {
    $names = ($_.Group.Wks | Sort-Object -Unique) -join ', '
    [pscustomobject]@{ Ip = $_.Name; Count = $_.Count; Workstations = $names }
  } | Sort-Object Count -Descending | Format-Table -AutoSize
```

출력 예시:

```text
Ip              Count Workstations
192.168.10.24    1842 PC-JHKIM
203.0.113.77      219 , KALI, X7QZL2
10.0.0.15          64 SRV-FILE01
```

`203.0.113.77` 은 이름이 세 개(빈 값 포함)다. **한 IP에서 이름이 흔들리면 그 이름은 증거로 못 쓴다.** IP만 확증값으로 남긴다.

### 4단계 — 한 축에서 나머지 두 축으로 확장

| 시작 축 | 1차 확장 | 2차 확장 | 확증 기준 |
| --- | --- | --- | --- |
| IP | 그 IP의 4624/4625 → 계정 집합 | 그 계정의 다른 IP → 재사용 여부 | pcap에서 같은 시각 같은 IP의 세션 존재 |
| 계정 | 그 계정의 4624 → IP 집합 | 그 IP의 다른 계정 → 도구가 여러 계정을 시도했나 | 4625 시도 계정 목록과 겹침 |
| 단말명 | `WorkstationName` 일치 → IP 집합 | 그 IP의 계정 집합 | 다른 호스트 EVTX의 `Computer` 와 이름 일치 |
| 공유 경로 | 5140/5145의 `ShareName` → `SubjectLogonId` | Logon ID로 세션 전체 (FOR-0104) | 같은 시각 `$MFT`/`$J` 의 파일 접근 |

```powershell
$csv = Import-Csv 'C:\case\out\all.csv'

# 1) IP -> 계정 집합
$ip = '203.0.113.77'
$csv | Where-Object { $_.Payload -match [regex]::Escape($ip) } |
  ForEach-Object { if ($_.Payload -match '"TargetUserName":\s*"([^"]*)"') { $Matches[1] } } |
  Group-Object | Sort-Object Count -Descending | Select-Object Name, Count

# 2) 계정 -> IP 집합
$user = 'svc_backup'
$csv | Where-Object { $_.Payload -match ('"TargetUserName":\s*"' + [regex]::Escape($user) + '"') } |
  ForEach-Object { if ($_.Payload -match '"IpAddress":\s*"([^"]*)"') { $Matches[1] } } |
  Group-Object | Sort-Object Count -Descending | Select-Object Name, Count

# 3) 계정 x IP x 이벤트 매트릭스
$csv | Where-Object { $_.EventId -in 4624,4625 } |
  ForEach-Object {
    $u = if ($_.Payload -match '"TargetUserName":\s*"([^"]*)"') { $Matches[1] } else { '' }
    $i = if ($_.Payload -match '"IpAddress":\s*"([^"]*)"') { $Matches[1] } else { '' }
    [pscustomobject]@{ User = $u; Ip = $i; EventId = $_.EventId }
  } |
  Where-Object { $_.User -notmatch '\$$' -and $_.Ip -and $_.Ip -ne '-' } |
  Group-Object User, Ip, EventId |
  Select-Object Name, Count | Sort-Object Count -Descending | Format-Table -AutoSize
```

payload의 JSON 키 표기는 EvtxECmd 버전에 따라 다르다. **정규식을 쓰기 전에 payload 한 줄을 눈으로 확인한다.** 확실하게 하려면 3단계처럼 `Get-WinEvent` + XML 파싱으로 필드 이름을 직접 지정한다.

각 확장 단계의 확증 기준:

| 주장 | 이것만으로는 부족 | 확증에 필요한 것 |
| --- | --- | --- |
| "이 IP가 공격자다" | 4624 하나 | 4625 실패 누적 또는 그 세션의 악성 행위(4688/5145) |
| "이 계정이 탈취됐다" | 로그온 성공 기록 | 정상 사용 패턴(시간대·IP·Logon Type)과의 이탈 |
| "이 PC가 공격 단말이다" | `WorkstationName` 일치 | 그 PC의 EVTX에 대응하는 발신 흔적(4648/4624 Type 3의 반대편) |
| "여기서 저기로 이동했다" | 목적지의 4624 | 출발지의 4648 또는 발신 프로세스(Sysmon 3) |

### 5단계 — 여러 호스트 EVTX로 측면 이동 경로 그리기

호스트별 EVTX를 각각 CSV로 만들고 `Computer` 컬럼을 유지한 채 합친다(방법은 FOR-0107).

```powershell
# 호스트별로 폴더를 나눠 뽑는다
EvtxECmd.exe -d 'C:\case\host-WS01\winevt' --csv 'C:\case\out' --csvf ws01.csv
EvtxECmd.exe -d 'C:\case\host-SRV01\winevt' --csv 'C:\case\out' --csvf srv01.csv

# 로그온 엣지 목록: (출발 IP) -> (도착 호스트, 계정, Logon Type)
$edges = @('ws01.csv','srv01.csv') | ForEach-Object {
  Import-Csv (Join-Path 'C:\case\out' $_) | Where-Object { $_.EventId -eq 4624 }
} | ForEach-Object {
  $u = if ($_.Payload -match '"TargetUserName":\s*"([^"]*)"') { $Matches[1] } else { '' }
  $i = if ($_.Payload -match '"IpAddress":\s*"([^"]*)"') { $Matches[1] } else { '' }
  $t = if ($_.Payload -match '"LogonType":\s*"?(\d+)') { $Matches[1] } else { '' }
  [pscustomobject]@{ SrcIp = $i; DstHost = $_.Computer; User = $u; Type = $t; TimeUTC = $_.TimeCreated }
}

$edges | Where-Object { $_.SrcIp -notin @('-','127.0.0.1','::1') -and $_.User -notmatch '\$$' } |
  Sort-Object TimeUTC | Format-Table TimeUTC, SrcIp, DstHost, User, Type -AutoSize
```

출력 예시가 곧 경로다.

```text
TimeUTC                 SrcIp           DstHost   User        Type
2026-03-14 07:19:02Z    203.0.113.77    WS01      svc_backup  10
2026-03-14 07:33:41Z    192.168.10.24   SRV01     svc_backup  3
2026-03-14 07:35:12Z    192.168.10.24   SRV01     Administrator 3
```

```text
외부 203.0.113.77 --RDP(Type 10)--> WS01(192.168.10.24) --SMB(Type 3)--> SRV01
```

**두 번째 줄의 `SrcIp` 가 첫 번째 줄의 목적지 호스트 IP와 같다는 것이 경로의 연결 증거다.** 이 대응이 안 맞으면 경유지가 하나 더 있다.

호스트 IP를 확정하려면 그 호스트의 로그에서 자기 IP를 찾는다.

| 방법 | 무엇을 보나 |
| --- | --- |
| 다른 호스트의 4624 `IpAddress` | 그 호스트가 접속했을 때 남은 주소 |
| 그 호스트의 Sysmon 3 `SourceIp` | 자기 발신 주소가 직접 기록된다 |
| `SYSTEM` hive `Services\Tcpip\Parameters\Interfaces\<GUID>` | `IPAddress` / `DhcpIPAddress` 값 |
| DHCP 서버 로그 (`%SystemRoot%\System32\dhcp\DhcpSrvLog-*.log`) | 시각별 IP↔MAC↔호스트명 |
| pcap의 ARP / NBNS / DHCP | IP↔MAC↔이름 |

### 6단계 — IP↔단말을 외부 증거로 고정

`WorkstationName` 이 위조 가능하므로 최종 확증은 EVTX 밖에서 온다.

| 증거원 | 얻는 것 | 한계 |
| --- | --- | --- |
| DHCP 서버 로그 | 임대 시각, IP, MAC, 신고된 호스트명 | 고정 IP 단말은 안 나온다. 호스트명은 여기서도 자기 신고 값 |
| ARP 캐시 / pcap의 ARP | IP↔MAC (같은 세그먼트에서만) | 라우터를 넘으면 MAC이 바뀐다 |
| pcap의 NBNS/mDNS 이름 등록 | 단말이 방송한 이름 | 이것도 자기 신고 값 |
| pcap의 실제 세션 | 그 시각 그 IP가 정말 통신했는가 | 캡처 구간 밖은 불가 |
| 스위치/방화벽 로그 | 포트 단위 위치 | 보통 첨부되지 않는다 |
| MAC의 OUI | 제조사 | 가상화·MAC 랜덤화로 무의미할 수 있다 |

```bash
# pcap 에서 해당 IP 의 MAC 을 고정한다
tshark -r cap.pcapng -Y "ip.addr==203.0.113.77" -T fields -e frame.time -e eth.src -e ip.src -e ip.dst | head

# ARP 로 IP<->MAC 대응 확인
tshark -r cap.pcapng -Y "arp" -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u

# 단말이 방송한 이름 (NBNS)
tshark -r cap.pcapng -Y "nbns" -T fields -e ip.src -e nbns.name | sort -u
```

pcap 쪽 절차의 상세는 [FOR-0146](./wireshark-30sec-triage.html)에 있다.

**EVTX `SystemTime` 은 UTC**이고, pcap의 프레임 시각은 캡처 장비의 시각(보통 로컬)이다. 두 축을 맞추려면 EVTX는 UTC로 두고 pcap 시각을 UTC로 환산한 뒤 비교한다. 답이 KST면 마지막에 +9시간.

## 출력 필드 해석

| 필드 | 의미 | 신뢰도 |
| --- | --- | --- |
| `IpAddress` | 접속 원본 IP | **높다.** TCP 세션이 실제로 있었다는 뜻 (NAT/프록시 경유는 별개) |
| `IpPort` | 원본 포트 | 값이 있으면 실제 소켓이 있었다. `0` 이면 네트워크 세션이 아니다 |
| `WorkstationName` | 클라이언트가 신고한 이름 | **낮다.** 위조 가능. 패턴 단서로만 |
| `Workstation` (4776) | 같은 성질의 값, 필드 이름만 다름 | 낮다 |
| `TargetUserName` | 로그온 대상 계정 | 높다. `$` 로 끝나면 컴퓨터 계정 |
| `TargetUserSid` | 계정 SID | **가장 높다.** 이름 변경·중복에 영향받지 않는다 |
| `SubjectUserName` | 행위 주체 계정 | 높다 |
| `TargetServerName` (4648) | 접속 대상 서버 이름 | 중간. 발신 측 기록 |
| `ShareName` / `RelativeTargetName` (5140/5145) | 접근한 공유와 그 안의 경로 | 높다 |
| `Computer` | **로그를 기록한 호스트** | 높다. 접속자가 아니라 목적지 |
| `SourceIp` / `DestinationIp` (Sysmon 3) | 발신·수신 주소 | 높다. 출발지 관점의 유일한 직접 증거 |
| `Status` / `SubStatus` (4625) | 실패 이유 코드 | 계정 존재 여부·비밀번호 오류 구분에 쓴다 |

계정은 이름보다 **SID로 고정**한다. 이름은 바뀌고 재사용되지만 `S-1-5-21-...-1001` 은 그 시스템에서 유일하다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 확정된 IP | pcap `ip.addr == <IP>` ([FOR-0146](./wireshark-30sec-triage.html)) | 실제 전송 내용, MAC |
| 확정된 계정 | 그 계정의 4624 `TargetLogonId` (FOR-0104) | 세션 내 활동 전부 |
| 계정 SID | SAM / ProfileList | 계정 생성 시각, 프로필 폴더 |
| `WorkstationName` | 다른 호스트의 EVTX `Computer` | 그 단말의 발신 기록 |
| `ShareName` / `RelativeTargetName` | `$MFT` / `$J` ([FOR-0050](./ntfs-artifact-timeline.html)) | 실제로 읽힌/복사된 파일 |
| Logon Type 10 + IP | TerminalServices 채널 (1149, 21/24/25) | RDP 클라이언트 주소 재확인 |
| Logon Type 3 + NTLM | 4776의 `Workstation` | 인증 요청의 신고 단말명 |
| 외부 IP | 방화벽/프록시 로그 | 반출 트래픽 |
| IP↔MAC | DHCP 로그, ARP | 물리 단말 특정 |

## 흔한 함정

- **`WorkstationName` 을 확증 증거로 쓰는 것.** 클라이언트가 신고한 문자열이고 서버는 검증하지 않는다. → 패턴 단서로만 쓰고, 단말 특정은 IP+MAC으로 한다.
- **`IpAddress = -` 를 은폐로 읽는 것.** 콘솔·서비스·배치 로그온은 원래 네트워크 출처가 없다. → `LogonType` 을 함께 보고 `-` 가 정상인 유형인지 판정한다.
- **`::ffff:192.168.10.24` 를 문자열로 검색하는 것.** `192.168.10.24` 로 검색하면 앞의 접두사 때문에 매칭이 빗나가거나, 반대로 IPv6 표기만 검색해 IPv4 기록을 놓친다. → 정규화 함수를 거친다.
- **4776에서 IP를 찾는 것.** 이 이벤트에는 IP 필드가 없다. → 계정 + `Workstation` + 시각으로 4624/4625와 엮는다.
- **`Computer` 를 접속자 이름으로 읽는 것.** 로그를 남긴 호스트 자신이다. → 여러 호스트를 합쳤을 때 목적지 컬럼으로 쓴다.
- **1149/21/24/25를 `EventData` XPath로 찾는 것.** 이 이벤트는 `UserData` 구조다. → `Get-WinEvent` 결과의 XML을 직접 파싱하거나 EvtxECmd CSV의 payload를 쓴다.
- **NAT/프록시를 고려하지 않는 것.** 여러 단말이 같은 공인 IP로 보인다. → 포트·세션 시각·`WorkstationName` 조합으로 분리하고, 불확실하면 "이 IP 뒤의 단말"이라고 서술한다.
- **한 축만으로 결론 내는 것.** IP만 있으면 누가, 계정만 있으면 어디서가 빈다. → 세 축을 모두 채운 뒤 서술한다.
- **DHCP 임대 시각을 무시하는 것.** 같은 IP가 하루 뒤에 다른 단말에 할당된다. → 사건 시각의 임대 기록으로 한정한다.
- **성공(4624)만 보고 실패(4625)를 빠뜨리는 것.** 4625의 계정 목록이 공격 도구의 사전을 드러낸다. → 두 이벤트를 같은 축에 올린다.
- **계정을 이름으로 고정하는 것.** 이름 변경·동일 이름 재생성이 있다. → SID로 고정한다.
- **UTC/로컬 혼동.** EVTX는 UTC, pcap은 캡처 장비 로컬 시각인 경우가 많다. → 전부 UTC로 환산해 비교하고, 답을 낼 때만 KST(+9시간).
- **같은 초 순서를 시각으로 정하는 것.** 로그온 폭주 구간에서 인과가 뒤집힌다. → `EventRecordId` 로 정렬한다 (FOR-0103).

## 교차검증

```powershell
# 1) 그 IP 로 성공한 로그온과 실패한 로그온을 나란히 본다
$ip = '203.0.113.77'
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath "*[EventData[Data[@Name='IpAddress']='$ip']]" |
  Select-Object RecordId, TimeCreated, Id | Sort-Object RecordId | Format-Table -AutoSize

# 2) 그 IP 의 WorkstationName 이 일관적인가
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath "*[EventData[Data[@Name='IpAddress']='$ip']]" |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $d['WorkstationName']
  } | Group-Object | Select-Object Name, Count

# 3) 그 계정이 접근한 공유 경로
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=5145)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    if ($d['SubjectUserName'] -eq 'svc_backup') {
      '{0} {1} {2} {3}' -f $x.Event.System.TimeCreated.SystemTime, $d['IpAddress'], $d['ShareName'], $d['RelativeTargetName']
    }
  }

# 4) RDP 채널의 원본 주소가 4624 의 IpAddress 와 일치하는가 (UserData 구조)
Get-WinEvent -Path 'C:\case\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx' -Oldest |
  Where-Object { $_.Id -eq 1149 } |
  ForEach-Object { ([xml]$_.ToXml()).Event.UserData.InnerXml } | Select-Object -First 5
```

```bash
# 5) pcap 으로 그 IP 가 실제로 통신했는지, MAC 이 무엇인지 고정
tshark -r cap.pcapng -Y "ip.addr==203.0.113.77" -T fields -e frame.time -e eth.src -e tcp.dstport | head -20
```

4번은 `UserData` 구조라 `EventData` 파싱 코드가 통하지 않는다. `InnerXml` 을 그대로 보고 `Param1`/`Param2`/`Param3` 을 읽는다.

## mini walkthrough

```text
문제:
"세 대의 호스트 EVTX 가 있습니다. 최초 침입 단말의 IP 와,
 공격자가 마지막으로 도달한 호스트를 구하세요.
 첨부: host-WS01/, host-SRV01/, host-DC01/ (각 winevt 폴더)"

1. 세 호스트를 각각 CSV 로 뽑는다
   EvtxECmd.exe -d 'C:\case\host-WS01\winevt'  --csv 'C:\case\out' --csvf ws01.csv
   EvtxECmd.exe -d 'C:\case\host-SRV01\winevt' --csv 'C:\case\out' --csvf srv01.csv
   EvtxECmd.exe -d 'C:\case\host-DC01\winevt'  --csv 'C:\case\out' --csvf dc01.csv

2. 첫 시도 (실패):
   WorkstationName 축으로 시작했다.

   Import-Csv out\ws01.csv | Where-Object { $_.EventId -eq 4624 } |
     ForEach-Object { if ($_.Payload -match '"WorkstationName":\s*"([^"]*)"') { $Matches[1] } } |
     Group-Object | Sort-Object Count -Descending

   Name              Count
   WS01               1402
   PC-JHKIM            188
   KALI                 12
   X7QZL2                9
   (빈 값)               7

   "KALI 가 공격 단말" 이라고 답했다. 오답 처리.

   무엇이 틀렸나:
     WorkstationName 은 클라이언트가 신고하는 값이다.
     같은 IP 에서 KALI / X7QZL2 / 빈 값이 섞여 나왔으므로
     이름 자체가 위조되고 있다. 이름은 단말 식별자로 쓸 수 없다.
     문제가 요구한 것은 IP 다.

3. 접근 변경 — IP 축으로 다시 시작
   IP 별로 4624/4625 를 집계하고 WorkstationName 의 다양성을 함께 본다.

   Ip              Count Workstations
   192.168.10.24    1842 PC-JHKIM
   203.0.113.77      219 (빈 값), KALI, X7QZL2
   10.0.0.15          64 SRV-FILE01

   203.0.113.77 : 공인 IP + 이름 불일치 + 4625 다수 -> 최초 침입 단말

4. 두 번째 시도 (실패):
   203.0.113.77 로 SRV01/DC01 의 4624 를 검색했다.
   Import-Csv out\srv01.csv | Where-Object { $_.Payload -match '203\.0\.113\.77' }
   -> 0건.

   "공격자는 WS01 에서 멈췄다" 로 결론? 오답.

   무엇이 틀렸나:
     측면 이동은 공격자 IP 로 일어나지 않는다.
     WS01 을 발판으로 삼으면 SRV01 에는 WS01 의 내부 IP 로 접속한다.
     즉 다음 엣지의 SrcIp 는 192.168.10.24 다.

5. 접근 변경 — 엣지 목록을 만들어 연결한다
   TimeUTC                 SrcIp           DstHost  User          Type
   2026-03-14 07:19:02Z    203.0.113.77    WS01     svc_backup    10
   2026-03-14 07:33:41Z    192.168.10.24   SRV01    svc_backup     3
   2026-03-14 07:35:12Z    192.168.10.24   SRV01    Administrator  3
   2026-03-14 07:52:08Z    10.0.0.15       DC01     Administrator  3

   경로:
     203.0.113.77 --RDP--> WS01(192.168.10.24)
                   --SMB--> SRV01(10.0.0.15)
                   --SMB--> DC01

   각 엣지의 SrcIp 가 앞 엣지 목적지의 자기 IP 와 일치한다.

6. 호스트 IP 확증
   WS01 의 IP 가 정말 192.168.10.24 인가:
     - SRV01 의 4624 IpAddress = 192.168.10.24, WorkstationName = WS01
     - WS01 의 Sysmon 3 SourceIp = 192.168.10.24
     - WS01 의 SYSTEM hive Interfaces\<GUID>\DhcpIPAddress = 192.168.10.24
   세 근거가 일치 -> 확정.

7. 세 번째 시도 (실패):
   "마지막 도달 호스트는 DC01" 로 답을 내려다가, DC01 의 4624 Type 3 이
   Administrator 로 되어 있어 정상 관리 작업일 가능성을 확인하지 않았다.

   확증:
     DC01 의 그 세션 LogonId 로 4688/5145 를 조인 -> ntdsutil 실행 기록
     같은 시각 DC01 에 4672(SeDebugPrivilege 포함) 존재
   -> 정상 관리 작업이 아니다. 침해 확정.

8. 시간대 정리
   전부 UTC 기록이다. KST 로 답하면 +9시간.
   07:19:02Z -> 16:19:02 KST (침입 시작)
   07:52:08Z -> 16:52:08 KST (DC01 도달)

정답: 최초 침입 단말 IP = 203.0.113.77
      마지막 도달 호스트 = DC01 (2026-03-14 16:52:08 KST)
```

세 번의 교정이 핵심이다. **① `WorkstationName` 으로 시작하면 위조된 이름을 답으로 낸다** — IP를 축으로 잡는다. **② 측면 이동의 다음 엣지는 공격자 IP가 아니라 발판 호스트의 내부 IP다.** **③ 도착 호스트의 로그온이 정상 관리 작업이 아님을 세션 활동으로 확증**해야 경로가 완성된다.

## 막혔을 때 다음 체크

1. IP를 정규화했는가 (`::ffff:` 접두사, `::1`)
2. `IpAddress` 가 `-` 인 이유가 `LogonType` 으로 설명되는가
3. 같은 IP에서 `WorkstationName` 이 여러 개인가 — 위조 신호
4. 4776에서 IP를 찾으려 하지 않았는가 (필드 없음)
5. `Computer` 를 목적지로 읽었는가
6. 1149/21/24/25를 `UserData` 로 파싱했는가
7. 4625를 함께 봤는가 — 시도 계정 목록이 도구를 드러낸다
8. 계정을 SID로 고정했는가
9. 측면 이동 엣지의 `SrcIp` 가 앞 엣지 목적지의 자기 IP와 일치하는가
10. 호스트 IP를 두 가지 이상의 근거로 확증했는가
11. DHCP 임대 시각으로 IP↔단말을 사건 시각에 한정했는가
12. pcap이 있으면 IP↔MAC을 고정했는가
13. NAT/프록시 가능성을 서술에 반영했는가
14. 같은 초 순서를 `EventRecordId` 로 정렬했는가
15. 답 시각이 UTC인지 KST(+9시간)인지 확인했는가

## 출처

- SRC-001 — Microsoft Learn, Event 4624: `TargetUserName`, `TargetUserSid`, `IpAddress`, `IpPort`, `WorkstationName` 필드 정의와 `WorkstationName` 이 클라이언트가 제공하는 값이라는 근거, `IpAddress` 가 `-` 로 기록되는 경우
- SRC-020 — Microsoft Learn, Event 4625: 실패 로그온의 `TargetUserName`, `IpAddress`, `WorkstationName`, `Status`/`SubStatus` 필드 정의
- SRC-022 — Microsoft Learn, 고급 보안 감사 정책 설정: 4648(`TargetServerName`, `TargetInfo`), 4776(`Workstation`, IP 필드 없음), 4768/4769(`IpAddress`), 5140/5145(`ShareName`, `RelativeTargetName`, `IpAddress`)의 EventData 구성
- EvtxECmd CSV의 `RemoteHost`/`UserName` 편의 컬럼과 `Payload` JSON 키 표기는 버전에 따라 다르므로 실제 CSV를 확인한 뒤 정규식을 작성할 것
- TerminalServices 채널의 1149(`Param1`~`Param3`)와 21/24/25는 `UserData` 구조라는 점만 사용했다. 각 이벤트의 정식 필드 이름과 의미는 Microsoft의 RDS 이벤트 문서에서 확인할 것
- 특정 공격 도구가 남기는 `WorkstationName` 기본값은 도구·버전·옵션에 따라 다르므로 이 글에서는 단정하지 않았다. 판정은 조직의 정상 패턴과의 이탈로 한다
- DHCP 서버 로그 경로(`%SystemRoot%\System32\dhcp\DhcpSrvLog-*.log`)와 형식은 Windows Server 버전에 따라 다를 수 있으므로 실제 파일에서 확인할 것
