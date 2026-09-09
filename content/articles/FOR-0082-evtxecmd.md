---
id: FOR-0082
title: "EvtxECmd 사용법: EVTX를 CSV로 바꾸고 Maps로 페이로드를 정규화한다"
slug: "evtxecmd"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["EVTX", "EvtxECmd Maps", "PayloadData", "MapDescription", "Payload JSON"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "EvtxECmd\\Maps", "EvtxECmd\\Maps\\Microsoft-Windows-Security-Auditing_4624.map"]
registry_paths: []
event_ids: []
protocols: []
tools: ["EvtxECmd", "Timeline Explorer", "PowerShell", "wevtutil", "Event Viewer"]
commands: ["EvtxECmd.exe -f 'C:\\case\\Security.evtx' --csv 'C:\\case\\out' --csvf sec.csv", "EvtxECmd.exe -d 'C:\\case\\Logs' --csv 'C:\\case\\out' --csvf all.csv", "EvtxECmd.exe -f 'C:\\case\\Security.evtx' --inc 4624,4625,4672 --csv 'C:\\case\\out'", "EvtxECmd.exe -f 'C:\\case\\Security.evtx' --sd 2026-03-14T00:00:00 --ed 2026-03-15T00:00:00 --csv 'C:\\case\\out'", "EvtxECmd.exe -d C: --vss --dedupe --csv 'C:\\case\\out'"]
regex_patterns: ["\"TargetUserName\":\"([^\"]+)\"", "\"LogonType\":\"?(\\d+)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "Computer", "UserId", "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo", "Payload", "SourceFile"]
file_formats: ["evtx", "csv", "json", "xml"]
primary_terms: ["EvtxECmd", "evtx CSV 변환", "evtx 파서"]
keywords: ["EvtxECmd", "EVTX", "CSV 변환", "Maps", "MapDescription", "PayloadData", "Payload JSON", "Timeline Explorer", "--inc", "--exc", "--vss", "이벤트 로그 파싱", "손상 EVTX"]
aliases: ["evtxecmd 사용법", "evtx csv로 바꾸기", "이벤트 로그 csv 변환", "evtx 파싱 도구", "evtxecmd 옵션", "evtx 여러 개 합치기", "타임라인 익스플로러로 열기"]
symptom_keywords: ["evtx를 엑셀로 보고 싶다", "PayloadData 컬럼이 무슨 뜻인지 모르겠다", "evtx가 손상되어 안 열린다", "이벤트 로그가 너무 커서 못 본다", "특정 Event ID만 뽑고 싶다", "컬럼 위치가 바뀌었다"]
related: ["FOR-0081", "FOR-0083", "FOR-0107"]
source_ids: ["SRC-004", "SRC-026", "SRC-022"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

EvtxECmd 는 EVTX 를 CSV/JSON/XML 로 변환하는 표준 도구이고, 핵심은 **Maps**다. 맵이 있는 이벤트는 페이로드가 `MapDescription`·`UserName`·`RemoteHost`·`PayloadData1..6` 컬럼으로 정규화되지만, **맵이 없는 이벤트는 `Payload` 원본 JSON 만 채워진다.** 그래서 실전 필터는 컬럼이 아니라 `Payload` JSON 을 정규식으로 긁는 쪽이 안전하다.

## 어떤 문제에서 필요한가

- EVTX 를 Excel/Timeline Explorer 로 열어 정렬·필터해야 한다
- 수십 개 채널 파일을 **하나의 타임라인**으로 합쳐야 한다
- 특정 Event ID 나 시간 범위만 뽑아 파일 크기를 줄여야 한다
- Event Viewer 가 "손상되었다"며 못 여는 EVTX 를 읽어야 한다
- 볼륨 섀도에 남은 이전 시점의 로그를 봐야 한다

Event Viewer 는 정렬·집계·조인이 안 된다. **EVTX 분석은 CSV 로 바꾸는 순간부터 시작된다.**

## 문제에서 처음 볼 단서

1. 첨부가 `.evtx` 하나 → `-f`
2. 첨부가 `winevt\Logs` 폴더 → `-d` (하위 폴더 재귀)
3. 파일이 수백 MB → `--inc` 또는 `--sd/--ed` 로 먼저 줄인다
4. 어느 채널부터 볼지 모르겠다 → 전부 하나의 CSV 로 합쳐 빈도 집계 ([FOR-0081](./evtx-analysis-order.html))
5. CSV 를 열었는데 `PayloadData*`가 비어 있다 → 그 이벤트에 **맵이 없다.** `Payload` 컬럼을 본다

## 30초 절차

```powershell
EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
```

폴더 전체를 하나의 CSV 로:

```powershell
# -d 는 하위 폴더까지 재귀. --csvf 를 주면 모든 채널이 한 파일로 합쳐진다
EvtxECmd.exe -d 'C:\case\Logs' --csv 'C:\case\out' --csvf all.csv
```

큰 파일을 미리 줄이려면:

```powershell
# Event ID 로 좁히기
EvtxECmd.exe -f 'C:\case\Security.evtx' --inc 4624,4625,4634,4647,4648,4672 --csv 'C:\case\out' --csvf logon.csv

# 시간 범위로 좁히기 (UTC 기준으로 준다)
EvtxECmd.exe -f 'C:\case\Security.evtx' --sd 2026-03-14T00:00:00 --ed 2026-03-15T00:00:00 --csv 'C:\case\out' --csvf day.csv
```

## 상세 절차

### 1단계 — 옵션표

| 옵션 | 인자 | 의미 | 실전 메모 |
| --- | --- | --- | --- |
| `-f` | 파일 경로 | 단일 EVTX 처리 | 경로에 공백이 있으면 인용부호 |
| `-d` | 폴더 경로 | 폴더를 **재귀** 처리 | `winevt\Logs` 통째로 넣는 기본 사용법 |
| `--csv` | 출력 **폴더** | CSV 출력 폴더 | 파일명이 아니라 폴더다. 없으면 만든다 |
| `--csvf` | 출력 **파일명** | CSV 파일명 지정 | **`-d`와 함께 쓰면 전 채널이 한 파일로 합쳐진다.** 안 주면 채널별로 따로 생성 |
| `--json` | 출력 폴더 | JSON 출력 | 한 줄에 한 레코드. `jq` 로 다루기 좋다 |
| `--jsonf` | 파일명 | JSON 파일명 지정 | — |
| `--xml` | 출력 폴더 | XML 출력 | 원본 EventData 구조를 그대로 보고 싶을 때 |
| `--xmlf` | 파일명 | XML 파일명 지정 | — |
| `--inc` | ID 목록 | 지정한 Event ID **만** 포함 | 쉼표 구분. `--inc 4624,4625` |
| `--exc` | ID 목록 | 지정한 Event ID **제외** | 노이즈 ID 를 통째로 버릴 때 |
| `--sd` | 날짜/시각 | 이 시각 **이후**만 | UTC 로 해석된다 |
| `--ed` | 날짜/시각 | 이 시각 **이전**만 | `--sd`와 함께 창을 만든다 |
| `--met` | true/false | 처리 통계(메트릭) 출력 | 기본 켜짐. 어떤 Event ID 가 몇 건인지 콘솔에 요약해 준다 — **빈도 집계를 대신할 수 있다** |
| `--maps` | 폴더 경로 | 맵 파일 위치 지정 | 기본은 실행 파일 옆 `Maps` 폴더 |
| `--vss` | (없음) | 볼륨 섀도 사본까지 처리 | 라이브/마운트된 드라이브 대상. 관리자 권한 필요 |
| `--dedupe` | (없음) | 중복 레코드 제거 | `--vss`와 세트로 쓴다. 안 쓰면 섀도 수만큼 중복된다 |

`--inc`/`--exc`, `--sd`/`--ed`는 **파싱 단계에서 걸러내므로** 출력 파일 자체가 작아진다. CSV 로 다 뽑고 나서 필터하는 것보다 훨씬 빠르다.

```powershell
# 볼륨 섀도까지: 삭제 전 시점의 로그가 여기 남아 있을 수 있다
EvtxECmd.exe -d C: --vss --dedupe --csv 'C:\case\out' --csvf all_vss.csv
```

1102(감사 로그 삭제)가 찍혀 있는 사건에서 `--vss`는 **지워진 로그를 되찾는 유일한 수단**인 경우가 많다.

### 2단계 — Maps 개념 (이 글의 핵심)

EVTX 의 `EventData`는 이벤트마다 필드 이름과 개수가 전부 다르다. 4624 는 20개가 넘는 필드를, 7045 는 5개를 갖는다. 이걸 하나의 표로 만들려면 정규화가 필요하고, EvtxECmd 는 그 규칙을 **맵 파일**로 갖고 있다.

| 개념 | 설명 |
| --- | --- |
| 맵 파일 | 공급자+Event ID 단위의 규칙 파일. 기본 위치는 실행 파일 옆 `Maps` 폴더 |
| 하는 일 | 원본 `EventData` 의 특정 필드를 `MapDescription`·`UserName`·`RemoteHost`·`PayloadData1..6`·`ExecutableInfo` 컬럼에 배치 |
| 맵이 있을 때 | 위 컬럼이 채워진다. `MapDescription`에 사람이 읽는 요약이 들어간다 |
| 맵이 없을 때 | **위 컬럼은 전부 빈칸.** `Payload`(원본 JSON)만 채워진다 |
| 맵 갱신 | 도구 배포본에 포함되며 별도로 최신화할 수 있다. 버전이 다르면 **같은 이벤트라도 컬럼 배치가 달라진다** |

즉 EvtxECmd 의 CSV 는 두 층이다.

```text
[정규화 층]  MapDescription / UserName / RemoteHost / PayloadData1..6 / ExecutableInfo
                 ^ 맵이 있는 이벤트만. 편하지만 버전 의존적
[원본 층]    Payload  (EventData 전체를 담은 JSON)
                 ^ 항상 채워진다. 필드 이름이 그대로 들어 있어 버전 무관
```

### 3단계 — 출력 컬럼표

| 컬럼 | 의미 |
| --- | --- |
| `RecordNumber` | 파서가 부여한 순번 |
| `EventRecordId` | **EVTX 원본의 레코드 식별자.** 채널 단위로 단조 증가하고 재사용되지 않는다 |
| `TimeCreated` | 이벤트 발생 시각 (**UTC**) |
| `EventId` | Event ID |
| `Level` | 심각도 (Information / Warning / Error 등) |
| `Provider` | 이벤트를 기록한 공급자 이름 |
| `Channel` | 채널 이름 (`Security`, `Microsoft-Windows-Sysmon/Operational` 등) |
| `Computer` | 기록된 호스트 이름 |
| `UserId` | 레코드 헤더의 SID (EventData 안의 계정과 다를 수 있다) |
| `MapDescription` | 맵이 만든 사람이 읽는 요약. **맵 없으면 빈칸** |
| `UserName` | 맵이 뽑은 계정 (`도메인\계정` 형태가 흔하다) |
| `RemoteHost` | 맵이 뽑은 원격 호스트/IP |
| `PayloadData1` ~ `PayloadData6` | 맵이 배치한 주요 필드 6개. **이벤트마다 의미가 다르다** |
| `ExecutableInfo` | 맵이 뽑은 실행 파일/명령행 관련 정보 |
| `Payload` | **원본 `EventData` 전체 JSON** |
| `SourceFile` | 어느 `.evtx` 에서 나온 레코드인가 |

`PayloadData1`이 4624 에서는 계정 관련 값이지만 7045 에서는 서비스 이름일 수 있다. **컬럼 번호에 의미를 고정해 외우면 안 된다.**

### 4단계 — Payload JSON 을 정규식으로 긁는다 (실전 원칙)

이 글에서 하나만 가져간다면 이것이다. `PayloadData3`에 의존하는 필터는 도구/맵 버전이 바뀌면 조용히 빈 결과를 낸다. **`Payload` 안의 필드 이름은 EVTX 원본 이름이라 절대 바뀌지 않는다.**

```powershell
$csv = Import-Csv 'C:\case\out\sec.csv'

# 원본 EventData 필드 이름으로 값을 뽑는 헬퍼 — 정규식은 항상 작은따옴표
function Get-PayloadField {
  param([string]$Payload, [string]$Name)
  $m = [regex]::Match($Payload, '"' + [regex]::Escape($Name) + '"\s*:\s*"?([^",}]*)')
  if ($m.Success) { $m.Groups[1].Value } else { '' }
}

$csv | Where-Object { $_.EventId -eq '4624' } | ForEach-Object {
  [pscustomobject]@{
    Time    = $_.TimeCreated
    User    = Get-PayloadField $_.Payload 'TargetUserName'
    Type    = Get-PayloadField $_.Payload 'LogonType'
    LogonId = Get-PayloadField $_.Payload 'TargetLogonId'
    Ip      = Get-PayloadField $_.Payload 'IpAddress'
  }
} | Where-Object { $_.User -notmatch '\$$' } | Format-Table -AutoSize
```

같은 원리의 한 줄 버전:

```powershell
# 계정 이름이 attacker 로 시작하는 모든 레코드 — 채널·Event ID 무관
Import-Csv 'C:\case\out\all.csv' |
  Where-Object { $_.Payload -match '"TargetUserName"\s*:\s*"attacker' } |
  Select-Object TimeCreated, Channel, EventId, MapDescription
```

`Payload` 는 JSON 문자열이므로 `ConvertFrom-Json` 으로 객체화해도 된다. 필드가 확실할 때는 정규식보다 이 편이 정확하다.

```powershell
Import-Csv 'C:\case\out\sec.csv' | Where-Object { $_.EventId -eq '4672' } |
  ForEach-Object {
    $p = $_.Payload | ConvertFrom-Json
    [pscustomobject]@{ Time=$_.TimeCreated; User=$p.SubjectUserName; Priv=$p.PrivilegeList }
  }
```

> `Payload` JSON 의 키 구조(중첩 여부, `EventData` 래퍼 유무)는 도구 버전에 따라 다를 수 있다. `ConvertFrom-Json` 을 쓰기 전에 한 레코드를 그대로 출력해 구조를 눈으로 확인한다. 정규식 방식은 구조가 어떻든 동작한다는 것이 장점이다.

### 5단계 — 여러 파일을 하나의 CSV 로 합치기

방법 두 가지다.

| 방법 | 명령 | 특징 |
| --- | --- | --- |
| 도구가 합친다 | `EvtxECmd.exe -d 'C:\case\Logs' --csv out --csvf all.csv` | 컬럼이 자동으로 통일된다. **권장** |
| 나중에 합친다 | 채널별 CSV 를 `Import-Csv`로 읽어 결합 | 컬럼 순서가 다르면 깨진다 |

```powershell
# 채널별로 이미 뽑아 놓은 CSV 들을 하나로 (컬럼이 동일할 때만)
Get-ChildItem 'C:\case\out\*.csv' | ForEach-Object { Import-Csv $_.FullName } |
  Sort-Object TimeCreated |
  Export-Csv 'C:\case\out\merged.csv' -NoTypeInformation -Encoding UTF8
```

합친 뒤에는 반드시 `Channel`과 `Computer`로 먼저 나눠 본다. 여러 호스트가 섞이면 인과가 뒤집힌다.

### 6단계 — Timeline Explorer 로 열기

```text
Timeline Explorer -> File -> Open -> all.csv
  컬럼 헤더 클릭        : 정렬
  헤더 아래 필터 행     : 컬럼별 부분 문자열 필터
  우측 상단 검색창      : 전 컬럼 대상 검색
  컬럼 헤더 우클릭      : 컬럼 숨기기/보이기 (PayloadData 정리에 필수)
  행 좌측 색상 태그     : 관심 행 마킹 (타임라인 후보 표시)
```

Excel 로 열면 `TargetLogonId` 같은 `0x1a2b3c` 값이 문자열/숫자 자동 변환에 망가지고, `PrivilegeList` 처럼 긴 값이 잘린다. **Timeline Explorer 를 쓴다.** 메뉴 구성은 버전에 따라 다를 수 있다.

### 7단계 — 손상 EVTX 처리

| 증상 | 원인 | 대응 |
| --- | --- | --- |
| Event Viewer 가 "손상되었습니다"로 거부 | 더티 플래그(정상 종료되지 않아 헤더가 닫히지 않음) | EvtxECmd 는 대개 그대로 읽는다. **먼저 시도해 본다** |
| 일부 레코드만 나온다 | 청크 하나가 깨져도 나머지 청크는 독립적으로 파싱 가능 | 나온 레코드는 유효하다. `EventRecordId` 의 빈 구간으로 손실 범위를 특정한다 |
| 레코드 수가 0 | 파일이 잘렸거나 헤더만 남았다 | 헥스 편집기로 `ElfFile` 시그니처(`45 6C 66 46 69 6C 65 00`)와 `ElfChnk` 청크 헤더 존재를 확인 |
| 파일 크기가 68KB 근처 | 헤더 4096 + 청크 65,536 = 69,632바이트. 사실상 빈 로그 | 삭제/초기화 의심. 1102 확인 |
| 카빙으로 얻은 조각 | 헤더가 없는 청크 조각 | `ElfChnk` 단위로 잘라 개별 파싱을 시도한다 |

```powershell
# 시그니처 확인 — 정상 EVTX 는 첫 8바이트가 ElfFile
$b = [System.IO.File]::ReadAllBytes('C:\case\Security.evtx')[0..7]
($b | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
# 기대: 45 6C 66 46 69 6C 65 00

# EventRecordId 의 빈 구간 = 손실된 레코드 구간
$ids = (Import-Csv 'C:\case\out\sec.csv' | ForEach-Object { [int64]$_.EventRecordId }) | Sort-Object
[pscustomobject]@{ First=$ids[0]; Last=$ids[-1]; Count=$ids.Count; Missing=($ids[-1]-$ids[0]+1-$ids.Count) }
```

`Missing`이 0 이 아니면 그만큼의 레코드가 사라졌다는 뜻이다. 롤오버로도 생기지만, **중간 구간이 비어 있으면 선택적 삭제**를 의심한다.

## 출력 필드 해석

시각 컬럼만 따로 짚는다.

| 항목 | 값 |
| --- | --- |
| EVTX 내부 `SystemTime` | **UTC** (EVTX 포맷 자체가 UTC 로 저장한다) |
| EvtxECmd CSV `TimeCreated` | **UTC** 그대로 출력 |
| Event Viewer 화면 | 시스템 로컬 시간대로 변환된 값 |
| KST 답이 필요할 때 | **UTC + 9시간** |
| `--sd` / `--ed` 인자 | UTC 로 해석한다. KST 09:00 이후를 원하면 `00:00`을 준다 |

`--sd`/`--ed`에 KST 시각을 그대로 넣어 9시간 어긋난 결과를 얻는 것이 이 도구에서 가장 흔한 실수다. 대상 시스템의 시간대는 [FOR-0054](./system-timezone.html)로 확인한다.

## pivot: 다음에 볼 artifact

| EvtxECmd 출력에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| `Channel, EventId` 빈도표 | [FOR-0081](./evtx-analysis-order.html) | 어느 채널을 깊게 볼지 결정 |
| 4624 행 | [FOR-0083](./event-4624-logon.html) | Logon Type, IP, `TargetLogonId` |
| 4625 행 | [FOR-0084](./event-4625-failed-logon.html) | `Status`/`SubStatus` 로 공격 유형 판정 |
| 4672 행의 `PrivilegeList` | [FOR-0087](./event-4672-special-privileges.html) | `SeDebugPrivilege` 유무 |
| `Payload` 의 `TargetLogonId` | 같은 값으로 전 채널 grep | 세션 단위 활동 전체 |
| `SourceFile` | 원본 `.evtx` | 원본 XML 재확인 (`--xml`) |
| `Computer` | 다른 호스트의 EVTX | 측면 이동의 반대편 |
| 손실된 `EventRecordId` 구간 | `--vss` 재실행 | 섀도 사본에 남은 이전 시점 로그 |

## 흔한 함정

- **`--csv` 에 파일 경로를 주는 것.** `--csv`는 **폴더**다. `--csv 'C:\case\out.csv'`라고 쓰면 `out.csv`라는 이름의 폴더가 만들어진다. 파일명은 `--csvf`로 준다.
- **`PayloadData3` 같은 컬럼 번호에 필터를 고정하는 것.** 맵 버전이 바뀌면 배치가 달라져 필터가 조용히 0건을 반환한다. **`Payload` JSON 의 원본 필드 이름으로 긁는다.**
- **맵이 없는 이벤트를 "정보가 없다"고 판단하는 것.** `MapDescription`이 빈칸이어도 `Payload`에는 모든 필드가 들어 있다. 커스텀 애플리케이션 이벤트는 대부분 맵이 없다.
- **`--sd`/`--ed`에 로컬(KST) 시각을 넣는 것.** UTC 로 해석되어 9시간 어긋난 구간이 잘린다. 사건 시각 앞뒤 여유를 넉넉히 주고 시작한다.
- **`--vss`를 쓰고 `--dedupe`를 빼는 것.** 섀도 사본 개수만큼 같은 레코드가 중복되어 빈도 집계가 전부 부풀려진다.
- **`-d` 에 `--csvf`를 주지 않아 채널별로 흩어진 CSV 를 얻는 것.** 타임라인을 만들려면 한 파일이어야 한다. `--csvf all.csv`를 붙인다.
- **Excel 로 CSV 를 여는 것.** `0x3e7` 같은 16진수 문자열, 긴 `PrivilegeList`, 앞자리 0 이 깨지고 잘린다. Timeline Explorer 를 쓴다.
- **정규식을 큰따옴표로 감싸는 것.** PowerShell 은 큰따옴표 안의 `$`를 변수로 확장한다. `'\$$'`처럼 **항상 작은따옴표**를 쓴다.
- **손상 EVTX 를 포기하는 것.** EVTX 는 64KB 청크 단위로 독립적이라 일부가 깨져도 나머지는 읽힌다. Event Viewer 가 거부해도 EvtxECmd 는 읽는 경우가 많다.
- **여러 호스트의 로그를 합쳐 놓고 `Computer` 를 무시하는 것.** 호스트별 시계 차이 때문에 순서가 뒤집힌다.

## 교차검증

```powershell
# A) --met 콘솔 요약과 CSV 집계가 일치하는지 (파싱 누락 확인)
EvtxECmd.exe -f 'C:\case\Security.evtx' --csv 'C:\case\out' --csvf sec.csv
Import-Csv 'C:\case\out\sec.csv' | Group-Object EventId | Sort-Object Count -Descending |
  Select-Object -First 10 Count, Name

# B) 같은 이벤트를 원본 XML 로 재확인 — 맵이 값을 잘못 배치했는지 검증
EvtxECmd.exe -f 'C:\case\Security.evtx' --inc 4672 --xml 'C:\case\out' --xmlf p.xml

# C) 도구 독립 검증 — wevtutil 로 같은 레코드를 뽑아 대조
wevtutil qe 'C:\case\Security.evtx' /lf:true /c:3 /q:"*[System[(EventID=4672)]]" /f:xml

# D) PowerShell 기본 cmdlet 과 건수 대조
(Get-WinEvent -FilterHashtable @{Path='C:\case\Security.evtx'; Id=4672} -ErrorAction SilentlyContinue).Count
```

A~D 의 건수가 다르면 필터 조건이 아니라 **파싱 자체**를 의심한다. EvtxECmd 는 Windows API 를 쓰지 않고 포맷을 직접 읽으므로, `Get-WinEvent`가 못 읽는 레코드까지 뽑아내 건수가 더 많을 수 있다. 그때는 EvtxECmd 쪽이 맞다.

## mini walkthrough

```text
문제:
"공격자가 사용한 계정을 구하세요. 첨부: Logs 폴더 (evtx 22개, 총 180MB)"

1. 첫 시도 (실패한 접근):
   EvtxECmd.exe -d Logs --csv out
   -> --csvf 를 안 줘서 채널별 CSV 22개가 out 폴더에 흩어졌다.
      Timeline Explorer 로 하나씩 열어 비교하다 시간을 날렸다.
      게다가 채널을 넘나드는 시간 순 정렬이 불가능했다.

   고친 명령:
   EvtxECmd.exe -d Logs --csv out --csvf all.csv
   -> 전 채널이 한 파일(all.csv, 512,388행)로 합쳐졌다. Channel 컬럼으로 구분된다.

2. 두 번째 시도 (또 실패):
   Import-Csv out\all.csv | Where-Object { $_.PayloadData1 -match 'admin' }
   -> 0건.

   왜 틀렸나: PayloadData1 이 계정 이름을 담는다는 보장이 없다.
   한 행을 실제로 찍어 보니 4624 에서 PayloadData1 은 다른 값이었고,
   4104(PowerShell) 행은 PayloadData* 가 전부 빈칸이었다 — 그 이벤트에 맵이 없었다.

3. 방향 전환 — Payload 원본 JSON 을 긁는다:
   Import-Csv out\all.csv |
     Where-Object { $_.Payload -match '"TargetUserName"\s*:\s*"[^"]*admin' } |
     Select-Object TimeCreated, Channel, EventId, MapDescription

   -> 47건. 채널과 Event ID 를 넘나들며 전부 잡혔다.

     TimeCreated            Channel   EventId
     2026-03-14 07:11:02Z   Security  4625
     ...
     2026-03-14 07:18:44Z   Security  4624
     2026-03-14 07:18:44Z   Security  4672

4. 계정별 집계로 좁히기:
   Import-Csv out\all.csv | Where-Object { $_.EventId -eq '4625' } |
     ForEach-Object { [regex]::Match($_.Payload,'"TargetUserName"\s*:\s*"([^"]*)"').Groups[1].Value } |
     Group-Object | Sort-Object Count -Descending | Select-Object -First 5

     Count Name
     ----- ----
       214 svc_backup
        11 administrator
         3 guest

5. 그 계정으로 성공한 4624 가 있는지:
   -> 07:18:44Z svc_backup, LogonType 10, IpAddress 203.0.113.77

6. 시각 변환: 07:18:44Z + 9h = 2026-03-14 16:18:44 KST

정답: svc_backup
```

2단계의 실패가 이 글의 존재 이유다. **`PayloadData*`는 편의 컬럼이고, 신뢰할 수 있는 것은 `Payload` 원본 JSON 이다.** 1단계의 `--csvf` 누락도 실전에서 반복되는 실수다.

## 막혔을 때 다음 체크

1. `--csv`에 폴더를, `--csvf`에 파일명을 주었는가
2. `-d`인데 `--csvf`를 빼먹어 CSV 가 흩어지지 않았는가
3. `PayloadData*`가 비어 있다면 `Payload` 컬럼을 봤는가 — 맵 없는 이벤트다
4. 필터가 0건이면 컬럼 대신 `Payload` JSON 정규식으로 바꿔 봤는가
5. `--sd/--ed`를 UTC 로 주었는가 (KST 를 넣으면 9시간 어긋난다)
6. 정규식을 작은따옴표로 감쌌는가
7. 레코드가 적으면 `--inc/--exc`가 너무 좁지 않은지, 파일이 68KB 짜리 빈 로그가 아닌지
8. 손상되었다는 파일도 EvtxECmd 로 일단 돌려 봤는가
9. 지워진 로그가 필요하면 `--vss --dedupe`를 시도했는가
10. `EventRecordId` 의 빈 구간을 계산해 손실 범위를 파악했는가

## 출처

- SRC-004 — Eric Zimmerman 문서: EvtxECmd 의 CLI 옵션, Maps 개념, CSV 출력 컬럼(`MapDescription`, `PayloadData1..6`, `Payload`), Timeline Explorer 사용
- SRC-026 — libevtx (EVTX) 포맷 문서: `ElfFile` 시그니처(`45 6C 66 46 69 6C 65 00`), 4096바이트 파일 헤더, 65,536바이트 청크(`ElfChnk`), `EventRecordId` 의 단조 증가·비재사용 성질, `SystemTime` 이 UTC 라는 점
- SRC-022 — Microsoft Learn, Advanced security audit policy settings: `--inc` 로 좁힐 대상 Event ID 선정 근거
- 옵션 이름·기본값·CSV 컬럼 순서·Timeline Explorer 메뉴 경로는 도구 버전에 따라 다를 수 있다. 인자 없이 `EvtxECmd.exe`를 실행해 실제 도움말을 확인할 것
</content>
