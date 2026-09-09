---
id: FOR-0100
title: "Sysmon Event ID 3 NetworkConnect: 프로세스와 통신을 잇는 유일한 로그"
slug: "sysmon-event-3-network-connect"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Sysmon", "NetworkConnect", "DnsQuery", "Initiated", "DestinationIp", "ProcessGuid"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"]
registry_paths: []
event_ids: ["3", "22"]
protocols: ["TCP", "UDP", "DNS", "HTTP", "TLS"]
tools: ["Sysmon", "EvtxECmd", "Wireshark", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path sysmon.evtx -FilterXPath '*[System[EventID=3]]'", "EvtxECmd.exe -f sysmon.evtx --csv out --csvf sysmon.csv"]
regex_patterns: ["DestinationIp:\\s*([0-9]{1,3}(?:\\.[0-9]{1,3}){3})"]
wireshark_filters: ["ip.addr == 45.146.164.9 && tcp.port == 4444", "tcp.flags.syn == 1 && tcp.flags.ack == 0"]
tshark_fields: ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch"]
log_fields: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"]
file_formats: ["evtx"]
primary_terms: ["Sysmon 3", "Sysmon NetworkConnect", "sysmon 네트워크 연결"]
keywords: ["Sysmon", "Event ID 3", "NetworkConnect", "DestinationIp", "DestinationPort", "Initiated", "비콘", "beacon", "C2", "DnsQuery", "Sysmon 22", "프로세스 네트워크 연결", "evtx"]
aliases: ["sysmon 네트워크 연결", "sysmon 3", "어떤 프로세스가 통신했나", "비콘 탐지", "c2 통신 찾기", "sysmon 22 dns", "프로세스별 접속 ip"]
symptom_keywords: ["어떤 프로세스가 외부로 통신했는지 알고 싶다", "pcap에 프로세스 정보가 없다", "C2 서버 IP를 찾아야 한다", "비콘 주기를 계산해야 한다", "도메인을 IP와 프로세스에 연결해야 한다"]
related: ["FOR-0099", "FOR-0146", "FOR-0101"]
source_ids: ["SRC-024", "SRC-086", "SRC-012"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Sysmon Event ID 3은 **어느 프로세스가 어느 IP·포트로 연결했는지**를 한 줄에 기록한다. pcap은 프로세스를 모르고 4624는 페이로드를 모르므로, 호스트에서 이 둘을 잇는 로그는 사실상 이것뿐이다.

## 어떤 문제에서 필요한가

- "C2 서버 IP는 무엇인가" — `DestinationIp`
- "이 통신을 일으킨 프로세스는 무엇인가" — pcap만으로는 절대 알 수 없는 값
- "비콘(주기적 통신)이 있는가" — 같은 목적지로 규칙적 간격 반복
- "`rundll32.exe`가 외부로 나갔는가" — 정상 시스템 프로세스의 비정상 통신
- "도메인 → IP → 프로세스"를 연결 — Sysmon 22와 묶는다
- pcap이 없는 문제에서 네트워크 증거 확보

프로세스 자체(명령행·부모·해시)는 Sysmon 1 전담 글(FOR-0099)에서 얻는다. 여기서는 그 `ProcessGuid`가 만든 연결을 다룬다.

## 문제에서 처음 볼 단서

1. 첨부에 Sysmon evtx가 있고 지문이 "통신", "접속", "유출" → Event 3
2. IP가 하나 주어졌다 → `DestinationIp`로 바로 필터
3. 지문에 "주기", "몇 초마다", "규칙적" → 비콘 분석
4. 지문에 "도메인" → Sysmon 22(DnsQuery) 먼저
5. pcap과 Sysmon이 함께 있다 → 시각·IP·포트 3개로 대조

## 30초 절차

```powershell
# 원본: Microsoft-Windows-Sysmon%4Operational.evtx -> sysmon.evtx
Get-WinEvent -Path 'C:\case\sysmon.evtx' -FilterXPath '*[System[EventID=3]]' | Format-List
```

객체로 뽑아 두고 시작한다.

```powershell
$sm = 'C:\case\sysmon.evtx'

$p3 = Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=3]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime   = [datetime]::Parse($d['UtcTime'])
      Image     = $d['Image']
      User      = $d['User']
      Guid      = $d['ProcessGuid']
      Proto     = $d['Protocol']
      Initiated = $d['Initiated']
      Src       = $d['SourceIp']
      SrcPort   = $d['SourcePort']
      Dst       = $d['DestinationIp']
      DstHost   = $d['DestinationHostname']
      DstPort   = [int]$d['DestinationPort']
      DstPortNm = $d['DestinationPortName']
    }
  } | Sort-Object UtcTime

# 아웃바운드 목적지 상위 목록
$p3 | Where-Object { $_.Initiated -eq 'true' } |
  Group-Object Image, Dst, DstPort | Sort-Object Count -Descending |
  Select-Object -First 20 Count, Name | Format-Table -AutoSize
```

출력 예시:

```text
Count Name
----- ----
 1284 C:\Program Files\Google\Chrome\Application\chrome.exe, 142.250.76.100, 443
  173 C:\Windows\Temp\svchost.exe, 45.146.164.9, 4444
   31 C:\Windows\System32\rundll32.exe, 185.220.101.7, 443
    2 C:\Users\svc_backup\Downloads\rclone.exe, 45.146.164.9, 8080
```

두 번째 줄과 세 번째 줄이 답이다. `\Temp\`의 실행 파일과 `rundll32.exe`는 외부로 나가지 않는다.

## 상세 절차

### 1단계 — 필드표

| 필드 | 의미 | 실전 활용 |
| --- | --- | --- |
| `RuleName` | 매칭된 설정 규칙 태그 | 설정에서 지정했을 때만 값이 있다 |
| `UtcTime` | **이미 UTC인 연결 시각** | 변환하지 않는다 |
| `ProcessGuid` | 연결을 만든 프로세스 GUID | **Sysmon 1과 잇는 키** |
| `ProcessId` | PID | 재사용됨. 단독 사용 금지 |
| `Image` | 연결을 만든 실행 파일 경로 | 경로 자체가 1차 판정 근거 |
| `User` | 실행 계정 | 서비스 계정의 외부 연결은 이상 신호 |
| `Protocol` | `tcp` / `udp` | UDP는 기록이 누락되기 쉽다 |
| `Initiated` | `true`=아웃바운드, `false`=인바운드 | **방향 판정의 유일한 근거** |
| `SourceIsIpv6` | 출발지가 IPv6인가 | `true`면 IPv6 주소 표기 |
| `SourceIp` | 출발지 IP | 보통 이 호스트의 IP |
| `SourceHostname` | 출발지 호스트명 | 자기 호스트 이름. 비어 있을 수 있다 |
| `SourcePort` | 출발지 포트 | 아웃바운드면 임의 고포트 |
| `SourcePortName` | 출발지 포트의 서비스명 | 대개 빈 값 |
| `DestinationIsIpv6` | 목적지가 IPv6인가 | — |
| `DestinationIp` | **목적지 IP** | C2 후보 |
| `DestinationHostname` | 목적지 호스트명 | **역방향 조회 결과. 비어 있는 경우가 많다** |
| `DestinationPort` | **목적지 포트** | 4444, 8080, 1337 등은 즉시 의심 |
| `DestinationPortName` | 목적지 포트 서비스명 | `https`, `http`, `ldap` 등 |

### 2단계 — 이 로그의 값: 세 가지 증거의 빈칸을 메운다

| 증거 | 아는 것 | 모르는 것 |
| --- | --- | --- |
| pcap | 패킷 전문, 페이로드, 바이트 수 | **어느 프로세스가 보냈는지** |
| Security 4624/4625 | 계정, 로그온 IP | 통신 내용, 프로세스 |
| Sysmon 1 | 프로세스, 명령행, 부모 | 통신 여부 |
| **Sysmon 3** | **프로세스 + 목적지 IP/포트 + 시각** | 페이로드, 전송량 |

즉 Sysmon 3은 페이로드를 모른다. 그래서 **pcap이 있으면 Sysmon 3으로 프로세스를 특정하고, pcap으로 내용을 읽는** 순서가 정석이다.

### 3단계 — 방향 판정

| `Initiated` | 의미 | 읽는 법 |
| --- | --- | --- |
| `true` | 이 호스트의 프로세스가 **밖으로** 연결 | `DestinationIp`가 상대방 |
| `false` | 밖에서 이 호스트로 **들어온** 연결 | `SourceIp`가 상대방 |

`Initiated`를 무시하고 항상 `DestinationIp`를 상대방으로 읽으면, 인바운드 이벤트에서 자기 호스트 IP를 공격자 IP로 답하게 된다.

```powershell
# 방향을 정규화해 "상대방 주소" 컬럼을 만든다
$p3 | Select-Object UtcTime, Image, Initiated,
  @{n='Peer';     e={ if ($_.Initiated -eq 'true') { $_.Dst }     else { $_.Src } }},
  @{n='PeerPort'; e={ if ($_.Initiated -eq 'true') { $_.DstPort } else { $_.SrcPort } }} |
  Format-Table -AutoSize
```

### 4단계 — 비콘 탐지 (간격 통계)

C2 비콘은 **같은 목적지로 일정 간격 반복**이다. 간격의 표준편차가 작으면 사람이 아니라 타이머다.

```powershell
$p3 | Where-Object { $_.Initiated -eq 'true' } |
  Group-Object { "{0}|{1}|{2}" -f $_.Image, $_.Dst, $_.DstPort } |
  Where-Object { $_.Count -ge 10 } |
  ForEach-Object {
    $t = ($_.Group | Sort-Object UtcTime).UtcTime
    $gaps = for ($i = 1; $i -lt $t.Count; $i++) { ($t[$i] - $t[$i-1]).TotalSeconds }
    $mean = ($gaps | Measure-Object -Average).Average
    $sd   = if ($gaps.Count -gt 1) {
              [Math]::Sqrt((($gaps | ForEach-Object { [Math]::Pow($_ - $mean, 2) }) |
                Measure-Object -Sum).Sum / ($gaps.Count - 1))
            } else { 0 }
    [pscustomobject]@{
      Target   = $_.Name
      Hits     = $_.Count
      MeanSec  = [Math]::Round($mean, 1)
      StdDev   = [Math]::Round($sd, 1)
      Jitter   = if ($mean -gt 0) { [Math]::Round($sd / $mean * 100, 1) } else { 0 }
      FirstUtc = $t[0]
      LastUtc  = $t[-1]
    }
  } | Sort-Object Jitter | Format-Table -AutoSize
```

출력:

```text
Target                                              Hits MeanSec StdDev Jitter FirstUtc            LastUtc
------                                              ---- ------- ------ ------ --------            -------
C:\Windows\Temp\svchost.exe|45.146.164.9|4444        173    60.2    2.1    3.5  2026-03-14 07:22:05 2026-03-14 10:14:47
C:\...\rundll32.exe|185.220.101.7|443                 31   300.9   18.4    6.1  2026-03-14 07:41:10 2026-03-14 10:12:33
C:\...\chrome.exe|142.250.76.100|443                1284     8.1   57.3  707.4  2026-03-14 06:02:11 2026-03-14 18:44:02
```

| Jitter(표준편차/평균) | 판정 |
| --- | --- |
| 0 ~ 15% | **비콘 확정.** 타이머 기반 주기 통신 |
| 15 ~ 40% | 지터를 넣은 비콘 가능. 기간을 늘려 재계산 |
| 40% 이상 | 사람/애플리케이션의 불규칙 통신 |

위 출력에서 60초 주기(지터 3.5%)가 비콘이고, 300초 주기의 `rundll32.exe`는 더 은밀한 두 번째 채널이다. Chrome은 지터가 707%로 정상이다.

CSV로 내려 SQLite에서 볼 때는 같은 계산을 이렇게 한다.

```sql
-- sysmon3(utc_time, image, dst_ip, dst_port) 테이블 가정
WITH ordered AS (
  SELECT image, dst_ip, dst_port, utc_time,
         LAG(utc_time) OVER (PARTITION BY image, dst_ip, dst_port ORDER BY utc_time) AS prev_t
  FROM sysmon3
),
gaps AS (
  SELECT image, dst_ip, dst_port,
         (julianday(utc_time) - julianday(prev_t)) * 86400.0 AS gap
  FROM ordered WHERE prev_t IS NOT NULL
)
SELECT image, dst_ip, dst_port,
       COUNT(*) AS hits,
       ROUND(AVG(gap), 1) AS mean_sec,
       ROUND(SQRT(AVG(gap * gap) - AVG(gap) * AVG(gap)), 1) AS sd_sec
FROM gaps
GROUP BY image, dst_ip, dst_port
HAVING hits >= 10
ORDER BY sd_sec / (mean_sec + 0.001) ASC;
```

### 5단계 — 비정상 조합 필터

정상 환경에서 **외부로 나가지 않는 프로세스**들이 있다. 이들이 나가면 그 자체가 침해다.

```powershell
$never = 'rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|' +
         'notepad\.exe|calc\.exe|winword|excel|powerpnt|' +
         'cmd\.exe|schtasks|whoami|net\.exe|net1\.exe|' +
         'installutil|regasm|regsvcs|msbuild|msiexec|w3wp'

$p3 | Where-Object { $_.Initiated -eq 'true' -and $_.Image -match $never } |
  Select-Object UtcTime, Image, User, Dst, DstPort, DstHost |
  Sort-Object UtcTime | Format-Table -AutoSize
```

| 조합 | 의미 |
| --- | --- |
| `rundll32.exe` → 외부 443 | 로드된 DLL이 C2와 통신. 지속성 DLL 의심 |
| `regsvr32.exe` → 외부 | Squiblydoo류 원격 스크립틀릿 실행 |
| `mshta.exe` → 외부 | HTA 원격 실행 |
| `certutil.exe` / `bitsadmin.exe` → 외부 | 파일 다운로드 LOLBin |
| `powershell.exe` → 외부 비표준 포트 | 다운로더 또는 리버스 셸 |
| `winword.exe` → 외부 | 문서 내 원격 템플릿·매크로 다운로드 |
| `w3wp.exe` → 외부 | 웹셸이 밖으로 연결(리버스 채널) |
| 임의 프로세스 → 4444/1337/8080/9001 | 흔한 리스너 포트 |
| `\Temp\`·`\AppData\` 실행 파일 → 외부 | 드롭된 바이너리의 통신 |

포트만으로 판정하지 않는다. **정상 포트(443)를 쓰는 C2가 더 흔하다.** 프로세스와 목적지 조합, 그리고 주기성이 근거다.

### 6단계 — Sysmon 22(DnsQuery)로 도메인 → IP → 프로세스

`DestinationHostname`은 역방향 조회 결과라 대개 비어 있다. 도메인을 알려면 DNS 질의 이벤트를 봐야 한다.

| Event 22 필드 | 의미 |
| --- | --- |
| `UtcTime` | 질의 시각(UTC) |
| `ProcessGuid` / `ProcessId` / `Image` | 질의한 프로세스 |
| `QueryName` | **질의한 도메인** |
| `QueryStatus` | 0이면 성공, 그 외는 오류 코드 |
| `QueryResults` | **응답 레코드 목록**(주소들이 `;`로 이어짐) |
| `User` | 실행 계정 |

```powershell
$p22 = Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=22]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime = [datetime]::Parse($d['UtcTime'])
      Image   = $d['Image']
      Guid    = $d['ProcessGuid']
      Query   = $d['QueryName']
      Status  = $d['QueryStatus']
      Results = $d['QueryResults']
    }
  } | Sort-Object UtcTime

# Event 3 의 목적지 IP 가 어느 도메인의 응답에 들어 있었는지 역추적
$target = '185.220.101.7'
$p22 | Where-Object { $_.Results -match [regex]::Escape($target) } |
  Select-Object UtcTime, Image, Query, Results | Format-Table -AutoSize
```

출력:

```text
UtcTime             Image                              Query                     Results
-------             -----                              -----                     -------
2026-03-14 07:41:08 C:\Windows\System32\rundll32.exe   cdn-metrics.example.org   type: 5 cdn-metrics...;::ffff:185.220.101.7;
```

DNS 질의 시각(07:41:08)이 연결 시각(07:41:10)보다 **2초 앞선다.** 이 순서가 맞아야 같은 사건이다. 순서가 뒤바뀌면 IP를 하드코딩한 통신이거나 캐시 사용이다.

| 패턴 | 해석 |
| --- | --- |
| 22 없이 3만 있다 | **IP 하드코딩 C2** 또는 DNS 캐시 히트. 도메인 증거 없음 |
| 22의 `QueryName`이 무작위 문자열 + 긴 서브도메인 | DNS 터널링/DGA 의심 |
| `QueryStatus`가 0이 아닌 질의 반복 | 죽은 C2 도메인에 계속 시도 |
| 같은 도메인을 여러 프로세스가 질의 | 정상 CDN일 가능성 |

### 7단계 — pcap과 대조

세 값이 모두 맞아야 같은 연결이다.

| 대조 축 | Sysmon 3 | pcap |
| --- | --- | --- |
| 시각 | `UtcTime` (UTC) | 캡처 시각(캡처 장비 시간대 확인 필수) |
| IP | `DestinationIp` | `ip.dst` |
| 포트 | `DestinationPort` + `SourcePort` | `tcp.dstport` + `tcp.srcport` |

**`SourcePort`가 가장 강한 연결 키다.** 같은 목적지로 여러 연결이 있을 때 출발 포트가 세션을 유일하게 지정한다.

```text
ip.addr == 45.146.164.9 && tcp.port == 4444
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 45.146.164.9
```

pcap 쪽 첫 SYN 시각과 Sysmon 3의 `UtcTime`이 초 단위로 일치하면 확정이다. 어긋나면 캡처 장비의 시간대·NTP 오차를 먼저 의심한다. Wireshark 초기 훑기 절차는 [FOR-0146](./wireshark-30sec-triage.html), HTTP 본문에서 유출 데이터를 찾는 방법은 [FOR-0158](./http-post-find.html)을 본다.

## 출력 필드 해석

`UtcTime`은 **이미 UTC**다. Event Viewer 상단에 보이는 시각은 EVTX `SystemTime`(UTC)을 조회 PC의 로컬 시간대로 변환한 값이므로 둘이 다르게 보인다. 답이 KST면 `UtcTime` + 9시간.

| 상황 | 해석 |
| --- | --- |
| `DestinationHostname`이 빈 값 | 정상. 역방향 조회 실패/미수행. Sysmon 22로 도메인을 얻는다 |
| `DestinationIp`가 `::ffff:1.2.3.4` | IPv4-mapped IPv6 표기. 실제로는 IPv4다 |
| `SourceHostname`이 FQDN | 이 호스트의 이름. 상대방이 아니다 |
| `Protocol = udp`인 건수가 극히 적음 | 설정에서 제외됐거나 UDP 기록 특성. 없다고 통신이 없었던 것은 아니다 |
| 같은 목적지 연속 다수 | 재시도 또는 비콘. 간격을 계산해 구분 |
| `DestinationPortName`이 빈 값 | 알려진 서비스 포트가 아니다. 오히려 의심 신호 |

IP 문자열을 로그에서 뽑을 때 쓰는 정규식은 [FOR-0128](./ipv4-regex.html)을 참고한다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `ProcessGuid` | Sysmon 1 (FOR-0099) | 명령행·부모·해시 |
| `ProcessGuid` | Sysmon 11 | 통신 전후에 만든 파일(다운로드 산물) |
| `DestinationIp` | Sysmon 22 `QueryResults` | 그 IP를 준 도메인 |
| `DestinationIp` + `SourcePort` | pcap | 실제 페이로드와 전송량 |
| `DestinationIp` | 방화벽·프록시 로그 | 전송 바이트(유출량 산정) |
| `Image` | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 실행 파일의 생성·삭제 시각 |
| `User` | 4624 ([FOR-0083](./event-4624-logon.html)) | 어느 로그온 세션에서 실행됐는가 |
| 비콘 시작 시각 | 그 시각 직전의 Sysmon 1/11 | 감염 경로(최초 실행) |
| 비콘 종료 시각 | Sysmon 5 · 4689 | 프로세스 종료 또는 탐지·차단 시점 |

## 흔한 함정

- **`Initiated`를 무시하는 것.** `false`는 인바운드다 → `DestinationIp`가 자기 호스트여서 자기 IP를 공격자로 답하게 된다 → 방향에 따라 상대방 주소를 골라 쓴다.
- **`DestinationHostname`이 비었다고 도메인이 없다고 결론 내리는 것.** 이 필드는 역방향 조회 결과다 → Sysmon 22의 `QueryName`/`QueryResults`로 도메인을 얻는다.
- **포트 번호만으로 악성 판정하는 것.** 현대 C2는 443/80을 쓴다 → 프로세스·경로·주기성 조합으로 판단한다.
- **Sysmon 3의 건수를 트래픽 양으로 읽는 것.** 이벤트는 연결 시도 단위이며 전송 바이트가 없다 → 유출량은 pcap·프록시·SRUM으로 구한다.
- **`UtcTime`에 다시 9시간을 더하는 것.** 이미 UTC다 → KST 답에만 +9시간을 한 번 적용한다.
- **Sysmon 3이 없어서 통신이 없었다고 보는 것.** Sysmon 3은 노이즈가 커서 설정에서 대량 제외되는 대표 이벤트다 → 설정을 확인하고 pcap·방화벽·`netstat` 메모리 흔적으로 보완한다.
- **PID로 프로세스를 특정하는 것.** PID는 재사용된다 → `ProcessGuid`로 Sysmon 1과 잇는다.
- **비콘 판정을 건수로만 하는 것.** Chrome은 수천 건이지만 정상이다 → 간격의 표준편차(지터)로 판정한다.
- **`::ffff:` 접두 IP를 IPv6로 보고 넘기는 것.** IPv4-mapped 표기다 → 뒤쪽 IPv4로 정규화해 비교한다.
- **pcap 시각과 그대로 비교하는 것.** 캡처 장비의 시간대·NTP 오차가 있다 → 첫 SYN과 `UtcTime`의 오프셋을 먼저 구해 보정한다.

## 교차검증

```powershell
$sm = 'C:\case\sysmon.evtx'

# 1) 아웃바운드 목적지 요약 (공인 IP만)
$p3 | Where-Object {
  $_.Initiated -eq 'true' -and
  $_.Dst -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|::1$)'
} | Group-Object Dst, DstPort | Sort-Object Count -Descending |
  Select-Object -First 15 Count, Name

# 2) 그 목적지를 만든 프로세스의 Sysmon 1 (명령행)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=1]]' |
  Where-Object { $_.Message -match 'svchost\.exe' -and $_.Message -match 'Temp' } |
  Select-Object -First 3 TimeCreated, Message

# 3) DNS 질의로 도메인 확보
$p22 | Where-Object { $_.Results -match '45\.146\.164\.9' } | Select-Object UtcTime, Query, Image

# 4) 통신 전후에 생성된 파일 (Sysmon 11)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=11]]' |
  Where-Object { $_.Message -match 'svchost\.exe' } | Select-Object -First 10 TimeCreated, Message

# 5) 인바운드 연결만 (측면 이동 수신 측)
$p3 | Where-Object { $_.Initiated -eq 'false' } |
  Select-Object UtcTime, Image, Src, SrcPort, DstPort | Format-Table -AutoSize
```

Sysmon 3의 목적지, Sysmon 22의 도메인, pcap의 세션이 같은 시각대에 정렬되면 통신 경로가 확정된다.

## mini walkthrough

```text
문제:
"침해된 호스트의 C2 서버 주소와 비콘 주기(초)를 구하시오.
 첨부: Microsoft-Windows-Sysmon%4Operational.evtx (Event 3: 41,882건)"

1. 첫 시도 (실패):
   Event 3 에서 DestinationPort 가 4444, 1337, 31337 인 것만 찾았다.
   -> 0건. "C2 통신이 없다" 고 판단하고 멈췄다. 오답.

   왜 틀렸나:
   포트 목록으로 필터한 것이 문제였다. 이 사건의 C2 는 443 을 썼다.
   비표준 포트 목록은 오래된 가정이다.

2. 피벗 — 포트를 버리고 "프로세스 + 목적지 + 주기"로 접근했다.
   먼저 아웃바운드를 프로세스별로 집계:
     Count Name
     ----- ----
      1284 chrome.exe, 142.250.76.100, 443
       288 rundll32.exe, 185.220.101.7, 443     <- rundll32 가 외부로?
        94 svchost.exe(C:\Windows\Temp\), 45.146.164.9, 443

   rundll32.exe 는 정상 환경에서 외부로 나가지 않는다. 후보 확정.

3. 간격 통계로 비콘 판정:
     Target                                 Hits MeanSec StdDev Jitter
     rundll32.exe|185.220.101.7|443          288    30.1    0.9    3.0
     svchost.exe(Temp)|45.146.164.9|443       94   120.4   11.8    9.8
     chrome.exe|142.250.76.100|443          1284     8.1   57.3  707.4

   -> rundll32 는 30초 주기(지터 3%). 비콘 확정.
      Temp\svchost.exe 는 120초 주기의 두 번째 채널.

4. 도메인 확인 (Sysmon 22):
   185.220.101.7 을 QueryResults 에 포함한 질의:
     07:41:08  rundll32.exe  cdn-metrics.example.org
   -> DNS 질의가 첫 연결 2초 전. 같은 사건 확정.

5. 최초 실행 경로 (Sysmon 1, 같은 ProcessGuid):
   07:41:05  rundll32.exe C:\ProgramData\Intel\ime.dll,Start
     ParentProcessGuid -> 07:41:04  cmd.exe /c rundll32 ...
       ParentProcessGuid -> 07:20:08  powershell.exe -nop -w hidden -enc ...

6. 시간대: UtcTime 은 UTC. 07:41:08 UTC = 16:41:08 KST (+9h)

정답: C2 185.220.101.7 (cdn-metrics.example.org, TCP 443), 비콘 주기 30초
```

1단계의 실패가 이 주제의 대표 오답이다. **포트로 C2를 찾지 않는다.** "나가지 않아야 할 프로세스가 나갔다" + "간격이 규칙적이다" 두 축이 실제 판정 근거다.

## 막혔을 때 다음 체크

1. `Initiated`로 방향을 갈랐는가 → 인바운드에서 상대방은 `SourceIp`다
2. 사설 IP·루프백을 걸러 냈는가 → 공인 IP만 남기면 후보가 급감한다
3. 포트가 아니라 프로세스로 걸렀는가 → `rundll32`/`regsvr32`/`mshta`/LOLBin 우선
4. 간격 표준편차를 계산했는가 → 건수가 아니라 규칙성이 비콘의 정의다
5. Sysmon 22를 봤는가 → 도메인은 여기에만 있다
6. Event 3이 거의 없는가 → 설정 제외 가능성. pcap·방화벽으로 보완
7. `ProcessGuid`로 Sysmon 1을 엮었는가 → 명령행과 감염 경로가 거기 있다
8. 유출량이 필요한가 → Sysmon 3에는 바이트 수가 없다. pcap/프록시/SRUM으로 간다
9. pcap 시각이 어긋나는가 → 첫 SYN 기준으로 오프셋을 구해 보정한다

## 출처

- SRC-024 — Microsoft Learn, Sysmon: Event ID 3 NetworkConnect와 Event ID 22 DnsQuery의 필드 목록, 채널 이름
- SRC-086 — MITRE ATT&CK Enterprise: C2 채널·비콘·LOLBin 아웃바운드 통신의 탐지 관점
- SRC-012 — RFC 791 IPv4: 사설 주소 대역 판별과 IPv4 주소 표기 기준
- Sysmon 3은 설정 파일의 포함/제외 규칙에 크게 좌우되며 UDP 기록 특성도 버전에 따라 다르다. 로그가 비어 있는 것을 "통신 없음"으로 해석하지 말고 설정을 확인할 것
- Event 22의 `QueryResults` 표기 형식(`type: 5` 등 접두)은 Sysmon 버전에 따라 다를 수 있으므로 실제 이벤트로 확인할 것
- 비콘 판정의 지터 임계값(15%/40%)은 경험적 기준이며 공식 문서의 수치가 아니다. 후보 정렬용으로만 쓰고 최종 판정은 목적지·프로세스와 함께 할 것
