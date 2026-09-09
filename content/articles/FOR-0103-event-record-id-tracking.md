---
id: FOR-0103
title: "EventRecordID로 이벤트 순서 확정하기: 같은 초의 인과와 번호 gap 판독"
slug: "event-record-id-tracking"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["EventRecordID", "EVTX", "ElfFile", "ElfChnk", "EVTX chunk", "Security.evtx"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]
registry_paths: []
event_ids: []
protocols: []
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "wevtutil", "Event Viewer"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --csv 'C:\\case\\out' --csvf sec.csv", "wevtutil qe Security.evtx /lf:true /c:1 /f:xml", "Format-Hex -Path 'C:\\case\\Security.evtx' -Count 64"]
regex_patterns: ["<EventRecordID>(\\d+)</EventRecordID>"]
wireshark_filters: []
tshark_fields: []
log_fields: ["EventRecordID", "EventRecordId", "RecordId", "TimeCreated", "SystemTime", "ChunkNumber", "Channel"]
file_formats: ["evtx", "csv"]
primary_terms: ["EventRecordID", "레코드 번호 추적", "이벤트 순서 판정"]
keywords: ["EventRecordID", "EventRecordId", "RecordId", "레코드 번호", "이벤트 순서", "같은 초", "gap", "롤오버", "로그 삭제", "EVTX chunk", "ElfFile", "ElfChnk", "단조 증가"]
aliases: ["EventRecordID", "이벤트 레코드 번호", "같은 초 순서", "이벤트 순서 정하기", "레코드 번호 비어 있음", "로그 지운 구간", "evtx 손상"]
symptom_keywords: ["같은 초에 일어난 이벤트 순서를 모르겠다", "레코드 번호가 건너뛴다", "로그가 지워진 것 같다", "이벤트 순서가 뒤집혀 보인다", "evtx 파일이 손상됐다", "로그가 언제부터 남아 있는지 알고 싶다"]
related: ["FOR-0083", "FOR-0107", "FOR-0110"]
source_ids: ["SRC-026", "SRC-022", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`EventRecordID` 는 EVTX 파일(채널) 하나 안에서만 1부터 단조 증가하는 시퀀스이므로, **같은 초에 몰린 이벤트의 인과 순서는 `TimeCreated` 로는 알 수 없고 `EventRecordID` 로만 확정된다** — 번호의 빈 구간(gap)은 롤오버·로그 삭제·파일 손상 중 하나이고, 번호가 갑자기 낮아지면 로그가 지워지고 새 파일로 다시 시작된 것이다.

## 어떤 문제에서 필요한가

- "A가 먼저인가 B가 먼저인가"를 물어보는 문제인데 두 이벤트의 `TimeCreated` 가 **같은 초**다
- 로그온(4624) 직후 프로세스 생성(4688)이 같은 초에 있어 "로그온 후 실행"인지 "실행 후 로그온"인지 판정해야 한다
- 특정 시각 구간의 이벤트가 사라진 것 같은데, 삭제인지 롤오버인지 구분해야 한다
- "이 로그는 언제부터 언제까지를 담고 있는가"를 근거와 함께 답해야 한다 (없다는 사실을 증거로 쓰려면 이 계산이 먼저다)
- EVTX 파일이 손상되어 파서가 중간에 멈춘다 — 어디까지 읽혔는지 번호로 확인해야 한다

`TimeCreated` 의 `SystemTime` 은 100ns 정밀도를 가지지만, **도구가 CSV로 내보낼 때 초 단위로 잘려 나오는 경우가 많다.** 잘린 시각으로 정렬하면 같은 초 안의 순서는 정렬 알고리즘이 정하는 임의 순서가 된다. 그래서 순번이 필요하다.

## 문제에서 처음 볼 단서

1. 정답 후보 두 이벤트의 시각이 초까지 동일하다 → `EventRecordID` 비교 확정
2. 시간순 서술을 요구하는데 이벤트가 초당 수십 개다 → 시각 + 번호 이중 정렬
3. "언제 로그를 지웠나" / "지운 구간을 추정하라" → 번호 gap과 번호 급락
4. 파서가 `n` 건만 읽고 끝났다 → 마지막으로 읽힌 번호와 파일 크기 대조
5. 여러 채널을 합쳐 놓았다 → **채널별로 번호가 독립**이므로 채널 컬럼 없이는 정렬 자체가 무의미

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
```

CSV가 나오면 **시각 다음에 번호**로 이중 정렬한다. 이 두 줄이 이 글의 전부다.

```powershell
Import-Csv 'C:\case\out\sec.csv' |
  Sort-Object { $_.Channel }, { [datetime]$_.TimeCreated }, { [int64]$_.EventRecordId } |
  Format-Table EventRecordId, TimeCreated, Channel, EventId, UserName, MapDescription
```

CSV 없이 원본 EVTX만 있을 때:

```powershell
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest |
  Select-Object RecordId, TimeCreated, Id, ProviderName |
  Sort-Object RecordId | Format-Table -AutoSize
```

`Get-WinEvent -Path` 는 기본이 **최신순**이다. `-Oldest` 를 빠뜨리면 화면 순서가 실제 발생 순서의 역순이 되어 그대로 오답이 된다.

## 상세 절차

### 1단계 — EventRecordID 의 성질 확정

원본 XML의 위치는 `Event/System/EventRecordID` 다. 표기가 도구마다 달라지므로 표로 고정한다.

| 표기 | 어디서 보이나 | 비고 |
| --- | --- | --- |
| `EventRecordID` | 원본 EVTX XML (`wevtutil qe ... /f:xml`, Event Viewer의 XML 탭) | **정식 이름.** `ID` 가 대문자 |
| `EventRecordId` | EvtxECmd CSV 컬럼 | 마지막 `d` 가 소문자. 컬럼명은 버전에 따라 다를 수 있다 |
| `RecordId` | `Get-WinEvent` 가 돌려주는 객체의 속성 | .NET `EventRecord` 의 속성명 |
| `EventRecordNumber` | 일부 서드파티 파서 | 같은 값을 가리킨다 |

성질:

| 성질 | 내용 | 실전 의미 |
| --- | --- | --- |
| 범위 | **채널(= evtx 파일) 단위** | Security의 1,000번과 System의 1,000번은 무관 |
| 증가 방향 | 기록되는 순서대로 단조 증가 (1부터) | 작을수록 과거 |
| 재사용 | 없음. 같은 파일에서 같은 번호가 두 번 나오지 않는다 | 중복 행이 보이면 CSV를 두 번 합친 것 |
| 크기 | 64비트 정수 | 문자열 정렬하면 `9` > `10` 이 된다. 반드시 `[int64]` 캐스팅 |
| 초기화 | 로그를 지우면(1102/104) 새 파일이 만들어지고 **1부터 다시 시작** | 번호 급락의 원인 |
| 롤오버 | 파일이 꽉 차면 오래된 레코드부터 밀려난다. 번호는 계속 커진다 | 첫 레코드 번호가 1이 아니면 이미 밀려난 것 |

### 2단계 — 같은 초 순서 확정

시각으로 1차 정렬, 번호로 2차 정렬한다. 순서를 반대로 하면 안 된다 — 채널이 섞여 있으면 번호 우선 정렬이 채널 간 순서를 조작해 버린다.

```powershell
# 사건 시각 07:19:0x 초 안에 몰린 이벤트의 실제 순서
Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Channel -eq 'Security' -and $_.TimeCreated -like '2026-03-14 07:19:0*' } |
  Sort-Object { [int64]$_.EventRecordId } |
  Format-Table EventRecordId, TimeCreated, EventId, UserName, MapDescription
```

출력 예시:

```text
EventRecordId TimeCreated            EventId UserName    MapDescription
1184571       2026-03-14 07:19:02Z   4624    svc_backup  Logon Type 10 (RemoteInteractive)
1184572       2026-03-14 07:19:02Z   4672    svc_backup  Special privileges assigned
1184573       2026-03-14 07:19:02Z   4688    svc_backup  cmd.exe
1184574       2026-03-14 07:19:02Z   4688    svc_backup  powershell.exe
```

네 이벤트가 모두 `07:19:02Z` 다. 시각만으로는 "관리자 권한이 로그온보다 먼저 부여됐다"는 불가능한 서술이 나올 수 있다. 번호가 4624 → 4672 → 4688 순서를 확정한다.

원본 XML에서 직접 100ns 정밀도의 시각을 꺼내 검증할 수도 있다.

```powershell
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4688)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      RecordId   = $_.RecordId
      SystemTime = $x.Event.System.TimeCreated.SystemTime
      EventId    = $_.Id
    }
  } | Format-Table -AutoSize
```

`SystemTime` 은 `2026-03-14T07:19:02.4718235Z` 처럼 소수부까지 나온다. **여기서도 두 이벤트의 소수부가 동일하면 번호가 유일한 근거다.**

### 3단계 — gap(번호 불연속) 탐지

```powershell
$ids = Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Channel -eq 'Security' } |
  ForEach-Object { [int64]$_.EventRecordId } |
  Sort-Object

for ($i = 1; $i -lt $ids.Count; $i++) {
  $d = $ids[$i] - $ids[$i - 1]
  if ($d -ne 1) {
    '{0} -> {1} : {2} records missing' -f $ids[$i - 1], $ids[$i], ($d - 1)
  }
}
```

출력 예시:

```text
1184610 -> 1185204 : 593 records missing
```

gap이 나왔다면 **원인을 반드시 하나로 확정한다.** 원인별 판별표다.

| gap의 원인 | 판별 근거 | 추가 확인 |
| --- | --- | --- |
| 롤오버 | 파일 **앞부분**(첫 레코드 번호 > 1)에서만 잘린다. 중간 gap은 만들지 않는다 | 첫 레코드 번호와 파일 크기 |
| 로그 삭제 | 삭제 후에는 번호가 **1로 재시작**한다. 같은 파일 안의 중간 gap이 아니다 | 1102(Security 감사 로그 지움), 104(다른 채널 지움) |
| 선택적 레코드 제거(도구 사용) | 파일 **중간**에 gap이 있으면서 시각은 연속 | 청크 헤더의 첫/마지막 레코드 번호와 실제 레코드 대조 |
| 파일 손상 | 파서가 특정 청크에서 오류를 뱉고 그 구간이 통째로 빈다 | EvtxECmd 콘솔 경고, `ChunkNumber` 컬럼의 불연속 |
| 필터 걸린 CSV | `--inc` 로 특정 이벤트만 뽑았다 | **가장 흔한 착각.** 필터 없이 다시 뽑아 비교 |

**필터 걸린 CSV로 gap을 판정하는 것이 이 절차의 최대 오답 경로다.** `--inc 4624,4688` 로 뽑은 CSV는 당연히 번호가 촘촘히 빈다. gap 판정은 항상 **필터 없는 전체 CSV**로 한다.

### 4단계 — 번호 급락 = 로그가 지워지고 새로 시작됐다

```powershell
# 번호가 앞 행보다 작아지는 지점을 찾는다 (기록 순서대로 읽었을 때)
$rows = Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Channel -eq 'Security' } |
  Sort-Object { [datetime]$_.TimeCreated }

for ($i = 1; $i -lt $rows.Count; $i++) {
  if ([int64]$rows[$i].EventRecordId -lt [int64]$rows[$i - 1].EventRecordId) {
    '{0} : {1} -> {2}  (RESET)' -f $rows[$i].TimeCreated, $rows[$i - 1].EventRecordId, $rows[$i].EventRecordId
  }
}
```

시각은 앞으로 가는데 번호가 뒤로 가는 지점은 **파일이 교체된 지점**이다. 실전에서 이런 조합이 나온다.

| 관찰 | 해석 |
| --- | --- |
| 마지막 번호 1,185,204 → 다음 번호 1 | 로그 전체 삭제. 1102 또는 104가 새 파일의 **1번 또는 2번 레코드**로 남는다 |
| 새 파일의 1번 레코드가 1102 자체 | 지운 행위만 남고 그 이전은 전부 소실 |
| 새 파일의 1번 레코드가 1102가 아니다 | 백업/보관 파일(`Archive-Security-*.evtx`)이 별도로 있는지 확인 |
| 번호가 1이 아니라 중간값에서 시작 | 삭제가 아니라 **일부만 추출한 파일**(CTF 출제자가 잘라 낸 것) |

`1102` 는 Security 채널의 "감사 로그를 지웠다", `104` 는 `Microsoft-Windows-Eventlog` 공급자가 System 채널에 남기는 "로그 파일을 지웠다"다. 지워진 채널 이름은 104의 payload에 들어간다.

### 5단계 — 로그 보존 구간 계산

"그 시각에는 로그가 없었다"를 근거 있게 말하려면 첫/마지막 레코드의 번호와 시각이 필요하다.

```powershell
$rows = Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Channel -eq 'Security' } |
  Sort-Object { [int64]$_.EventRecordId }

[pscustomobject]@{
  FirstRecordId = $rows[0].EventRecordId
  FirstTimeUTC  = $rows[0].TimeCreated
  LastRecordId  = $rows[-1].EventRecordId
  LastTimeUTC   = $rows[-1].TimeCreated
  RecordCount   = $rows.Count
  SpanHours     = [math]::Round((([datetime]$rows[-1].TimeCreated) - ([datetime]$rows[0].TimeCreated)).TotalHours, 2)
} | Format-List
```

출력 예시와 해석:

```text
FirstRecordId : 1102841
FirstTimeUTC  : 2026-03-12 22:04:11
LastRecordId  : 1185204
LastTimeUTC   : 2026-03-14 07:45:11
RecordCount   : 82364
SpanHours     : 33.68
```

- 첫 번호가 1이 아니다 → **롤오버가 이미 일어났다.** 2026-03-12 22:04:11Z 이전은 관측 불가
- `LastRecordId - FirstRecordId + 1 = 82,364` 가 `RecordCount` 와 일치 → **중간 gap 없음**. 불일치하면 그 차이가 사라진 레코드 수다
- 관측 구간: 2026-03-12 22:04Z ~ 2026-03-14 07:45Z. KST로는 2026-03-13 07:04 ~ 2026-03-14 16:45

**EVTX 내부 `SystemTime` 은 UTC다.** EvtxECmd CSV도 UTC로 출력한다. 답을 KST로 요구하면 **+9시간**을 더한다. 위 구간을 KST로 쓰지 않고 UTC로 제출하면 9시간 어긋난 답이 된다.

로그 크기 설정도 함께 본다. 롤오버 여부의 확증이다.

```powershell
# 라이브 시스템에서 채널의 최대 크기와 보존 정책
wevtutil gl Security
```

오프라인 이미지라면 `SYSTEM` hive의 `ControlSet00X\Services\EventLog\Security` 아래 `MaxSize` 값을 본다. 기본값은 Windows 버전에 따라 다르므로 **실제 값을 읽어서** 인용한다.

### 6단계 — 채널이 다르면 번호로 비교할 수 없다

이 절이 이 글에서 가장 자주 틀리는 부분이다.

| 비교 대상 | 번호 비교 가능? | 대안 |
| --- | --- | --- |
| Security의 4624 ↔ Security의 4688 | 가능 | 그대로 `EventRecordId` |
| Security의 4688 ↔ PowerShell/Operational의 4104 | **불가능** | 시각(소수부까지) + 인과 규칙 |
| Security의 4624 ↔ TerminalServices의 21 | **불가능** | 시각 + `SessionID`/계정 일치 |
| 같은 채널의 백업 파일 ↔ 현재 파일 | 조건부 | 같은 파일 계보라면 번호 연속. 지운 뒤라면 불연속 |

채널 간 순서는 **필연적 인과**로 정한다.

| 관계 | 필연적 순서 |
| --- | --- |
| 4624(로그온) → 그 `TargetLogonId` 를 가진 모든 이벤트 | 로그온이 먼저 |
| 4688(프로세스 생성) → 그 프로세스가 남긴 4104/Sysmon 이벤트 | 생성이 먼저 |
| 7045(서비스 설치) → 4624 Type 5(서비스 로그온) | 설치가 먼저 |
| 1102(로그 지움) → 같은 채널의 다른 이벤트 | 1102 이후 번호는 재시작된 파일의 것 |

디스크 artifact와의 순서 판정은 별도 문제다. `$MFT`/`$J` 축과 EVTX 축을 하나로 합치는 방법은 [FOR-0050](./ntfs-artifact-timeline.html)에 있다. 이 글은 EVTX 안에서의 순서만 다룬다.

### 7단계 — 청크 구조와 손상 시 부분 복구

EVTX는 **고정 크기 블록** 구조다. 손상되어도 살아 있는 블록은 그대로 읽힌다.

| 구조 | 크기 | 시그니처 | 담고 있는 것 |
| --- | --- | --- | --- |
| 파일 헤더 | 4,096바이트 | `ElfFile\x00` | 첫/마지막 청크 번호, 다음 레코드 식별자, dirty 플래그 |
| 청크 | 65,536바이트 (64KB) | `ElfChnk\x00` | 청크 헤더 + 그 청크에 속한 이벤트 레코드들 |
| 청크 헤더 | 청크 앞부분 | — | 그 청크의 **첫/마지막 레코드 번호와 식별자** |
| 이벤트 레코드 | 가변 | `2A 2A 00 00` | 레코드 식별자, 시각, BinXML 본문 |

```powershell
# 파일 시그니처 확인 (ElfFile 이 보여야 정상 EVTX)
Format-Hex -Path 'C:\case\Security.evtx' -Count 64
```

손상 대응 순서:

1. `EvtxECmd.exe -f ...` 를 그냥 돌린다. 파서가 **읽을 수 있는 레코드만** 뽑고 오류를 콘솔에 남긴다. 이것만으로 대부분 해결된다
2. 마지막으로 읽힌 `EventRecordId` 를 확인한다. 파일 크기 / 65,536 으로 총 청크 수를 추정해 어느 지점에서 멈췄는지 본다
3. 청크 단위로 남아 있으므로, 손상 구간 **이후**의 청크에도 유효한 레코드가 있을 수 있다. 파서가 첫 오류에서 멈췄다면 파일을 잘라 뒤쪽만 따로 넣어 본다
4. 파일 헤더의 dirty 플래그가 서 있으면 로그 서비스가 정상 종료되지 않은 것이다. 마지막 청크의 레코드가 헤더에 반영되지 않았을 수 있다

```powershell
# 총 청크 수 추정 (헤더 4096바이트 제외)
$len = (Get-Item 'C:\case\Security.evtx').Length
[math]::Floor(($len - 4096) / 65536)
```

## 출력 필드 해석

| 컬럼 / 필드 | 읽는 법 |
| --- | --- |
| `EventRecordId` | **채널 내부의 순번.** `[int64]` 로 캐스팅해서 정렬 |
| `TimeCreated` | UTC. CSV에서는 초 단위로 잘려 나올 수 있다 |
| `Channel` | 번호 비교의 유효 범위. **이 컬럼 없이 합친 CSV는 정렬 불가** |
| `ChunkNumber` | 그 레코드가 있던 청크 번호. 손상 구간 특정에 쓴다 (컬럼 존재 여부는 버전에 따라 다르다) |
| `SourceFile` | 어느 evtx 파일에서 왔는지. 여러 파일을 합쳤을 때 채널 판정 보조 |
| `RecordNumber` | 일부 EvtxECmd 버전이 함께 내보내는 별도 순번. `EventRecordId` 와 값이 다를 수 있으므로 **하나를 정해서 끝까지 쓴다** |
| `EventId` | 이벤트 종류. 번호와 무관 |

`Get-Member` 로 실제 컬럼명을 먼저 확인하고 스크립트를 맞춘다.

```powershell
Import-Csv 'C:\case\out\sec.csv' | Select-Object -First 1 | Get-Member -MemberType NoteProperty
```

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 확정된 이벤트 순서 | 4624의 `TargetLogonId` ([FOR-0083](./event-4624-logon.html)) | 그 순서 안의 세션 활동 전체 |
| 중간 gap | 1102 / 104 / 4719 / 1100 | 삭제·정책변경·서비스중지 중 무엇인가 |
| 번호 1로 재시작 | 재시작 직전 시각 | 삭제 시점 확정 |
| 첫 레코드 번호 > 1 | `MaxSize` 설정, 백업 evtx 파일 | 관측 구간 하한 확정 |
| 관측 구간 밖의 사건 | `$MFT` / `$J` / Prefetch ([FOR-0050](./ntfs-artifact-timeline.html)) | 로그 없이 그 시각을 메운다 |
| 손상 청크 | 같은 시각의 다른 채널 | 같은 사건의 중복 기록 |
| 특정 번호 구간 | 원본 XML (`wevtutil qe`) | CSV에서 잘린 필드 원본 확인 |

## 흔한 함정

- **`EventRecordId` 를 문자열로 정렬하는 것.** `1184571` 과 `999999` 를 문자열 비교하면 `999999` 가 더 크다고 나온다. → CSV의 모든 값은 문자열이다. `[int64]$_.EventRecordId` 로 캐스팅한다.
- **채널 간에 번호를 비교하는 것.** 번호는 파일별로 독립 증가한다. Security 1,000번이 System 999번보다 나중이라는 근거는 없다. → 채널로 먼저 그룹핑하고, 채널 간 순서는 시각과 인과로 정한다.
- **필터 걸린 CSV로 gap을 판정하는 것.** `--inc` 나 `Where-Object` 로 걸러낸 결과는 원래 번호가 빈다. → gap 판정은 필터 없는 전체 CSV에서만 한다.
- **gap을 무조건 "로그 삭제"로 읽는 것.** 삭제는 gap을 만들지 않고 **번호를 1로 되돌린다.** 중간 gap은 손상 또는 선택적 제거의 신호다. → 위 3단계 판별표로 원인을 하나로 좁힌다.
- **번호가 1부터 시작하지 않는 것을 삭제로 읽는 것.** 롤오버가 정상 동작이다. → `MaxSize` 와 첫 레코드 시각을 함께 제시해 롤오버임을 증명한다.
- **`Get-WinEvent -Path` 에서 `-Oldest` 를 빠뜨리는 것.** 기본이 최신순이라 화면 순서가 역순이다. 그대로 "첫 이벤트"라고 쓰면 실제로는 마지막 이벤트다. → `-Oldest` 를 붙이거나 `Sort-Object RecordId` 를 반드시 건다.
- **`TimeCreated` 만으로 인과를 서술하는 것.** CSV의 시각은 초 단위로 잘려 나오는 경우가 많다. 같은 초 안에서는 정렬이 임의 순서다. → 시각 + 번호 이중 정렬을 습관으로 한다.
- **UTC/KST 혼동.** EVTX `SystemTime` 은 UTC이고 Event Viewer는 로컬 시간대로 변환해 보여준다. 같은 레코드가 두 화면에서 다른 시각으로 보인다. → 축은 UTC로 고정하고 답을 낼 때만 +9시간.
- **여러 evtx를 합친 CSV에 `Channel` 컬럼을 남기지 않는 것.** 정렬 근거가 사라진다. → 합칠 때 `Channel` 과 `SourceFile` 을 반드시 보존한다.
- **번호 중복 행을 그냥 두는 것.** 같은 채널에서 같은 번호가 두 번 나오면 CSV를 두 번 이어 붙인 것이다. → `Sort-Object EventRecordId -Unique` 로 확인한다.

## 교차검증

```powershell
# 1) 번호 연속성: 이론상 개수와 실제 개수가 같은가
$ids = Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.Channel -eq 'Security' } |
  ForEach-Object { [int64]$_.EventRecordId } | Sort-Object
'span={0} count={1} missing={2}' -f ($ids[-1] - $ids[0] + 1), $ids.Count, (($ids[-1] - $ids[0] + 1) - $ids.Count)

# 2) 중복 번호 확인 (CSV 이중 병합 사고)
$ids | Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object Name, Count

# 3) 삭제·정책변경·서비스중지 이벤트가 gap 시각과 맞는가
Import-Csv 'C:\case\out\sec.csv' |
  Where-Object { $_.EventId -in 1102,104,1100,4719 } |
  Select-Object EventRecordId, TimeCreated, Channel, EventId, UserName |
  Sort-Object { [datetime]$_.TimeCreated }

# 4) 원본 XML 에서 같은 번호의 레코드를 직접 확인
wevtutil qe 'C:\case\Security.evtx' /lf:true /q:"*[System[(EventRecordID=1184573)]]" /f:xml

# 5) 100ns 정밀도 시각으로 번호 순서를 재확인
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest |
  Where-Object { $_.RecordId -ge 1184571 -and $_.RecordId -le 1184574 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{ RecordId = $_.RecordId; SystemTime = $x.Event.System.TimeCreated.SystemTime; Id = $_.Id }
  } | Format-Table -AutoSize
```

4번의 `wevtutil` XPath는 `EventRecordID` (대문자 ID)로 써야 한다. CSV 컬럼명(`EventRecordId`)을 그대로 넣으면 아무것도 안 나온다.

## mini walkthrough

```text
문제:
"침해 호스트의 Security.evtx 입니다.
 (1) 공격자가 관리자 권한을 얻은 것은 RDP 로그온 전인가 후인가
 (2) 로그가 지워진 구간의 길이를 추정하세요
 첨부: Security.evtx"

1. EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
   -> 82,364 행

2. 첫 시도 (실패):
   Import-Csv out\sec.csv |
     Where-Object { $_.EventId -in 4624,4672 } |
     Sort-Object TimeCreated |
     Format-Table TimeCreated, EventId, UserName

   TimeCreated            EventId UserName
   2026-03-14 07:19:02Z   4672    svc_backup
   2026-03-14 07:19:02Z   4624    svc_backup

   -> "4672 가 먼저" 라고 읽고 "권한 상승 후 로그온" 이라고 답했다. 오답.

   무엇이 틀렸나:
     두 행의 TimeCreated 가 초까지 동일하다.
     Sort-Object TimeCreated 는 동률일 때 원래 순서를 보장하지 않는다.
     CSV 의 시각은 초 단위로 잘려 있어 소수부 비교도 불가능했다.

3. 접근 변경 — EventRecordId 로 정렬
   Import-Csv out\sec.csv |
     Where-Object { $_.EventId -in 4624,4672 -and $_.TimeCreated -like '*07:19:02*' } |
     Sort-Object { [int64]$_.EventRecordId } |
     Format-Table EventRecordId, TimeCreated, EventId, UserName

   EventRecordId TimeCreated            EventId UserName
   1184571       2026-03-14 07:19:02Z   4624    svc_backup
   1184572       2026-03-14 07:19:02Z   4672    svc_backup

   -> 4624 가 1184571, 4672 가 1184572.
      로그온이 먼저이고 그 로그온에 특수 권한이 부여된 것이다. (1) 해결: 로그온 후.

   원본 XML 로 확증:
     RecordId 1184571 SystemTime 2026-03-14T07:19:02.4718235Z
     RecordId 1184572 SystemTime 2026-03-14T07:19:02.4903117Z
   소수부까지 순서가 일치한다.

4. 두 번째 문제 — gap 을 찾는다
   $ids = Import-Csv out\sec.csv | Where-Object { $_.Channel -eq 'Security' } |
            ForEach-Object { [int64]$_.EventRecordId } | Sort-Object
   'span={0} count={1}' -f ($ids[-1]-$ids[0]+1), $ids.Count
   -> span=82364 count=82364

   중간 gap 이 없다. "로그를 안 지웠다" 로 결론? 아니다.

5. 두 번째 실패 — 번호 급락을 안 봤다
   시각순으로 읽으면서 번호가 뒤로 가는 지점을 찾는다.

   $rows = Import-Csv out\sec.csv | Where-Object { $_.Channel -eq 'Security' } |
             Sort-Object { [datetime]$_.TimeCreated }
   for ($i=1; $i -lt $rows.Count; $i++) {
     if ([int64]$rows[$i].EventRecordId -lt [int64]$rows[$i-1].EventRecordId) {
       '{0} : {1} -> {2}' -f $rows[$i].TimeCreated, $rows[$i-1].EventRecordId, $rows[$i].EventRecordId
     }
   }
   -> 아무것도 안 나온다.

   그래서 첫 레코드를 봤다.
   $rows[0] : EventRecordId=1102841  TimeCreated=2026-03-12 22:04:11Z
   -> 첫 번호가 1 이 아니다. 이 파일은 롤오버된 파일이다.
      즉 "지운 흔적"은 이 파일 안에 없고, 이 파일 자체가 삭제 이후의 파일도 아니다.

6. 1102 를 직접 찾는다
   Import-Csv out\sec.csv | Where-Object { $_.EventId -eq 1102 } |
     Select-Object EventRecordId, TimeCreated, UserName

   EventRecordId TimeCreated            UserName
   1185204       2026-03-14 07:45:11Z   svc_backup

   1185204 = LastRecordId. 즉 1102 가 이 파일의 마지막 레코드다.
   => 07:45:11Z 에 로그를 지웠고, 그 이후에 만들어진 새 파일은 첨부에 없다.
      우리가 가진 것은 삭제 직전까지의 파일(백업본)이다.

7. 보존 구간과 삭제 구간 계산
   FirstRecordId 1102841  2026-03-12 22:04:11Z  (= 2026-03-13 07:04:11 KST)
   LastRecordId  1185204  2026-03-14 07:45:11Z  (= 2026-03-14 16:45:11 KST)
   중간 gap 0 -> 이 33.68시간은 온전하다.

   삭제 구간 = 07:45:11Z 이후. 이미지 획득 시각이 08:30:00Z 였다면
   07:45:11Z ~ 08:30:00Z 의 약 45분이 Security 채널에서 소실된 구간이다.
   그 45분은 System 채널의 104, PowerShell/Operational, $J 로 메운다.

정답:
 (1) 로그온(4624, RecId 1184571)이 먼저, 권한 부여(4672, RecId 1184572)가 나중
 (2) 2026-03-14 07:45:11Z(16:45:11 KST) 이후 약 45분이 소실. 근거는 1102 가
     파일의 마지막 레코드이고 그 이후 번호가 이 파일에 없다는 것
```

두 번의 교정이 핵심이다. **① 같은 초는 시각으로 정렬하면 안 된다** — 번호가 유일한 근거다. **② gap이 없다고 삭제가 없는 것은 아니다** — 삭제는 gap이 아니라 번호 재시작 또는 "1102가 마지막 레코드"라는 형태로 나타난다.

## 막혔을 때 다음 체크

1. `[int64]` 캐스팅을 했는가 — 문자열 정렬은 조용히 틀린다
2. `Channel` 로 먼저 그룹핑했는가 — 채널 간 번호 비교는 무효
3. 필터 없는 전체 CSV로 gap을 봤는가
4. 첫 레코드 번호가 1인가 — 아니면 롤오버된 파일이다
5. 마지막 레코드가 1102/104인가 — 삭제 직전 파일이라는 뜻이다
6. 시각순으로 읽을 때 번호가 뒤로 가는 지점이 있는가 — 파일 교체 지점
7. `Get-WinEvent -Path` 에 `-Oldest` 를 붙였는가
8. `span = last - first + 1` 과 실제 행 수가 같은가 — 차이가 사라진 레코드 수
9. 같은 번호가 두 번 나오는가 — CSV 이중 병합 사고
10. 원본 XML의 `SystemTime` 소수부로 확증했는가
11. `wevtutil` XPath에 `EventRecordID`(대문자 ID)를 썼는가
12. 파일 시그니처가 `ElfFile` 인가 — 아니면 EVTX가 아니거나 헤더가 깨졌다
13. 답을 UTC로 낼지 KST(+9시간)로 낼지 지문을 다시 읽었는가
14. 관측 구간 밖의 사건이라면 디스크 artifact로 넘어갔는가

## 출처

- SRC-026 — Libyal libevtx, EVTX 파일 포맷 문서: 파일 헤더(`ElfFile`, 4,096바이트)와 청크(`ElfChnk`, 65,536바이트) 구조, 청크 헤더가 담는 첫/마지막 레코드 번호와 식별자, 이벤트 레코드 시그니처, 레코드 식별자가 파일 단위로 단조 증가한다는 근거
- SRC-022 — Microsoft Learn, 고급 보안 감사 정책 설정: 1102(감사 로그 지움), 104(로그 파일 지움), 1100(이벤트 로깅 서비스 종료), 4719(감사 정책 변경)의 정의
- SRC-004 — Eric Zimmerman 문서: EvtxECmd의 `-f` `-d` `--csv` `--csvf` `--inc` 옵션과 CSV 컬럼(`EventRecordId`, `Channel`, `ChunkNumber`, `SourceFile`, `Payload`) 구성, Timeline Explorer 사용
- CSV 컬럼명(`EventRecordId` vs `RecordNumber`, `ChunkNumber` 존재 여부)은 EvtxECmd 버전에 따라 다르므로 `Get-Member` 로 실제 헤더를 확인할 것
- 채널의 `MaxSize` 기본값은 Windows 버전과 정책에 따라 다르므로 `wevtutil gl <채널>` 또는 `SYSTEM` hive의 실제 값을 읽어서 인용할 것
