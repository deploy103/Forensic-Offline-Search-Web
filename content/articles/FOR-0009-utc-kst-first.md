---
id: FOR-0009
title: "분석 시작 전 UTC/KST 시간대 확정 절차"
slug: "utc-kst-first"
category: "트리아지"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["FILETIME", "WebKit timestamp", "PRTime", "Unix epoch", "DOS date-time", "SYSTEMTIME"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "/etc/timezone", "/etc/localtime"]
registry_paths: []
event_ids: []
protocols: []
tools: ["DCode", "Timeline Explorer", "python3", "PowerShell", "sqlite3", "TZ"]
commands: ["TZ=UTC date -d @1773465761 '+%F %T %Z'", "python3 -c \"import datetime;print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=133560000000000000//10))\"", "TZ=Asia/Seoul date -d @1773465761 '+%F %T %Z'"]
regex_patterns: ["^\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeCreated", "SystemTime", "last_visit_time", "last_visit_date", "PreviousTime", "NewTime"]
file_formats: ["evtx", "regf", "sqlite", "csv"]
primary_terms: ["UTC KST 맞추기", "시간대 통일", "시각 보정 절차"]
keywords: ["UTC", "KST", "시간대 통일", "시각 보정", "정규화", "FILETIME", "WebKit", "PRTime", "Unix epoch", "DOS date", "ISO 8601", "syslog", "11644473600", "타임라인", "4616"]
aliases: ["utc kst 맞추기", "시간대 통일", "시각 보정 절차", "시간대 먼저", "타임라인 시간 안 맞음", "시각 정규화", "몇 시간 더해야 하나"]
symptom_keywords: ["여러 artifact 시각이 안 맞는다", "타임라인 순서가 뒤죽박죽이다", "몇 시간을 더해야 할지 모르겠다", "답이 9시간 틀렸다", "로그 연도가 없다", "시각이 미래로 나온다"]
related: ["FOR-0054", "FOR-0010", "FOR-0012", "FOR-0050"]
source_ids: ["SRC-014", "SRC-018", "SRC-075"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

증거물의 시간대를 먼저 확정해 메모지 맨 위에 적고, **모든 artifact 값을 UTC로 정규화해서 한 타임라인에 올린 뒤 최종 답을 낼 때만 한 번 KST(+9)로 변환한다.** artifact마다 즉석에서 +9를 하면 이중 변환과 순서 뒤바뀜이 반드시 생긴다.

## 어떤 문제에서 필요한가

- 여러 artifact(`$MFT`, EVTX, 브라우저 DB, 웹 로그)를 한 타임라인에 합쳐야 하는 문제
- "몇 시에 무엇을 했는가"를 KST로 답해야 하는 문제
- 답을 냈는데 정확히 9시간 또는 18시간 틀린 경우
- 사건 순서(A 다음 B)가 논리적으로 말이 안 되는 경우 — 복사 전에 업로드했다는 식
- 여러 호스트의 로그를 대조해야 하는 경우

시간대 처리는 **문제 종류와 무관하게 항상 붙는 세금**이다. 절차로 고정해 두지 않으면 매번 같은 실수를 반복한다.

시간대 값 자체(레지스트리 `TimeZoneInformation`, `Bias` 부호, `ActiveTimeBias`)는 [FOR-0054](./system-timezone.html)가 전담한다. 이 글은 **그 값을 얻은 다음의 분석 작업 흐름**을 다룬다.

## 문제에서 처음 볼 단서

1. 문제가 요구하는 시간대 표기 — `KST`, `UTC`, `현지 시각`, `+09:00`, 아무 언급 없음
2. 첨부에 `SYSTEM` hive 또는 `/etc/timezone`이 있는가 → 시간대를 확정할 수 있다
3. 도구 출력 시각 끝에 `Z`가 붙어 있는가 → 그 값은 UTC다
4. 로그 문자열에 `+0900` 같은 오프셋이 박혀 있는가 → 이미 로컬이다
5. 로그에 **연도가 없는가** — `Mar 14 16:22:41` 형태의 syslog는 연도를 따로 확정해야 한다
6. 정수 타임스탬프의 **자릿수** — 이것만으로 형식이 거의 결정된다

## 30초 절차

```bash
TZ=UTC date -d @1773465761 '+%F %T %Z'
```

분석을 시작하기 전에 다음 4줄을 메모지 맨 위에 적는다. 이것이 이 글의 전부다.

```text
[TZ NOTE]  case: 2026-CTF-03
  1. 증거물 시간대  : Korea Standard Time (Bias -540) = UTC+9
  2. 문제 요구 시간대: KST
  3. 작업 기준       : 전부 UTC 로 정규화. 표기는 항상 "...Z"
  4. 최종 변환       : 제출 직전 1회만 +9h, 답에 "KST" 명시
```

시간대를 확정할 수 없으면 3번을 `기준=UTC, 미확정`으로 적고 **UTC로만 답한다.** 근거 없이 +9를 하는 것보다 UTC로 답하고 근거를 적는 쪽이 부분 점수에 유리하다.

## 상세 절차

### 1단계 — 증거물의 시간대를 확정한다

| 증거물 | 확인 위치 | 얻는 값 |
| --- | --- | --- |
| Windows 이미지 / `SYSTEM` hive | `SYSTEM\ControlSet00N\Control\TimeZoneInformation` | `TimeZoneKeyName`, `Bias` — [FOR-0054](./system-timezone.html) |
| Linux 이미지 | `/etc/timezone` (문자열), `/etc/localtime` (심볼릭 링크 대상) | `Asia/Seoul` 등 tz 이름 |
| 웹/앱 서버 로그만 있음 | 로그 줄의 오프셋 표기 `+0900` | 그 서버의 로컬 오프셋 |
| pcap만 있음 | 패킷 시각은 **캡처 호스트 기준 Unix epoch(UTC)** | HTTP `Date:` 헤더와 대조 |
| 아무 근거 없음 | — | UTC로 고정하고 그렇게 명시 |

`Bias` 부호는 직관과 반대다. 한 줄만 기억한다.

```text
UTC = 로컬 + Bias      (분 단위)
로컬 = UTC - Bias
KST: Bias = -540  ->  로컬 = UTC + 9h
```

### 2단계 — artifact를 "저장 시간대" 4개 부류로 분류한다

정규화 규칙은 값 하나하나가 아니라 **저장 형식의 부류**로 결정된다. 부류만 판정하면 나머지는 기계적이다.

| 부류 | 판정 방법 | 정규화 규칙 |
| --- | --- | --- |
| A. epoch 정수 = **UTC** | FILETIME / WebKit / Unix / PRTime | 그대로 UTC. **여기에 +9 하면 안 된다** |
| B. 로컬 시각 문자열/워드, 오프셋 없음 | FAT DOS date, EXIF, SYSTEMTIME 구조체 | **변환 금지.** 호스트 시간대를 알면 UTC로 되돌려 기록 |
| C. 오프셋 포함 문자열 | `+0900`, `Z`, `+09:00` | 표기 그대로 신뢰. UTC로 되돌려 정규화 |
| D. 연도/오프셋 없음 | syslog RFC 3164 | 연도와 시간대를 **외부 근거로 보강** |

#### A 부류 — UTC로 저장되는 값 (전부 epoch 정수)

| artifact | 저장 형식 | 기준 시각 |
| --- | --- | --- |
| `$MFT` `$SI`/`$FN` MACB | FILETIME (100ns) | 1601-01-01 UTC |
| `$UsnJrnl` `$J` / `$LogFile` | FILETIME | 1601-01-01 UTC |
| 레지스트리 키 LastWrite | FILETIME | 1601-01-01 UTC |
| EVTX `TimeCreated SystemTime` | FILETIME (XML 렌더는 ISO 8601 `Z`) | 1601-01-01 UTC |
| Prefetch 실행 시각 | FILETIME | 1601-01-01 UTC |
| UserAssist 마지막 실행 시각 | FILETIME | 1601-01-01 UTC |
| BAM/DAM 실행 시각 | FILETIME | 1601-01-01 UTC |
| LNK / Jump List 대상 MAC | FILETIME | 1601-01-01 UTC |
| `$Recycle.Bin` `$I` 삭제 시각 | FILETIME | 1601-01-01 UTC |
| Shimcache / Amcache | FILETIME | 1601-01-01 UTC |
| Chrome/Edge `last_visit_time` | WebKit (마이크로초) | 1601-01-01 UTC |
| Firefox `last_visit_date` | PRTime (마이크로초) | 1970-01-01 UTC |
| SQLite `unixepoch` 정수 | Unix (초/밀리초) | 1970-01-01 UTC |

**자릿수로 형식을 판별한다.** 값을 보자마자 부류가 정해진다.

| 자릿수 | 예시 | 형식 | 초 단위 환산 |
| --- | --- | --- | --- |
| 10 | `1773465761` | Unix 초 | 그대로 |
| 13 | `1773465761000` | Unix 밀리초 | `/1000` |
| 16 | `1773465761000000` | Unix 마이크로초 / PRTime | `/1000000` |
| 17 | `13417139361000000` | WebKit (1601 기준 마이크로초) | `/1000000 - 11644473600` |
| 18 | `133560000000000000` | FILETIME (1601 기준 100ns) | `/10000000 - 11644473600` |

#### B 부류 — 로컬 시각이 그대로 박힌 값 (변환 금지)

| artifact | 저장 형식 | 주의점 |
| --- | --- | --- |
| FAT / exFAT DOS date-time | 날짜 워드 + 시각 워드 | 시간대 정보 없음. 2초 단위 |
| exFAT UTC 오프셋 바이트 | DOS date-time + 오프셋 필드 | 오프셋 필드가 있으면 그것만 적용 |
| ZIP local file header 시각 | DOS date-time | 압축한 PC의 로컬 시각 |
| `NetworkList` `DateCreated`/`DateLastConnected` | `SYSTEMTIME` 구조체(16바이트) | **로컬 시각** — [FOR-0072](./networklist.html) |
| EXIF `DateTimeOriginal` | `YYYY:MM:DD HH:MM:SS` | 촬영 기기의 로컬 시각 |
| 탐색기/Event Viewer 화면 표시 | 렌더링 결과 | **분석 PC**의 로컬 시각 |
| 일부 애플리케이션 텍스트 로그 | 자유 문자열 | 그 호스트의 로컬 시각 |

이 부류를 UTC 타임라인에 올릴 때는 **호스트 시간대를 빼서 UTC로 되돌린다.** KST 호스트라면 `UTC = 로컬 - 9h`다. 되돌릴 근거가 없으면 타임라인에 `(local, tz?)` 표시를 달고 절대 시각 비교에서 제외한다.

#### C 부류 — 오프셋이 표기된 문자열

| 로그 | 표기 예시 | 처리 |
| --- | --- | --- |
| ISO 8601 / RFC 3339 | `2026-03-14T07:04:19Z`, `2026-03-14T16:04:19+09:00` | 표기 그대로. `Z`는 UTC |
| Apache access log (CLF) | `[14/Mar/2026:16:22:41 +0900]` | 이미 로컬. **+9 금지** |
| nginx access log (기본) | `[14/Mar/2026:16:22:41 +0900]` | 동일 |
| journald / RFC 5424 syslog | `2026-03-14T16:22:41.123456+09:00` | 표기 그대로 |
| PDF `/CreationDate` | `D:20260314162241+09'00'` | 표기 그대로 |
| HTTP `Date:` 헤더 | `Sat, 14 Mar 2026 07:04:19 GMT` | GMT = UTC |

`+0900`이 붙은 값은 **이미 KST다.** 여기에 9시간을 더하는 것이 오답 원인 1위다.

#### D 부류 — 연도가 없는 syslog

전통 syslog(RFC 3164) 타임스탬프는 `Mmm dd hh:mm:ss` 형식으로 **연도도 시간대도 없다.**

```text
Mar 14 16:22:41 web01 sshd[2841]: Accepted password for admin from 10.0.0.5
```

| 없는 정보 | 보강 방법 |
| --- | --- |
| 연도 | 파일의 `$MFT`/`stat` mtime, 로테이션 파일명(`auth.log.1`), 로그 안의 연도 표기 줄(재부팅 배너), 문제 지문의 연도 |
| 시간대 | 그 호스트의 `/etc/timezone`, 같은 사건이 찍힌 다른 로그(C 부류)와 대조 |
| 12월→1월 경계 | 연도 증가 지점을 로그 순서로 판정 |

### 3단계 — 전부 UTC로 정규화한다

```text
[원칙]
1) A 부류: 정수 -> UTC datetime. 끝. 더 이상 손대지 않는다
2) B 부류: 로컬 - (호스트 오프셋) -> UTC. 근거 없으면 UTC 칸을 비우고 표시
3) C 부류: 표기 오프셋을 빼서 -> UTC
4) D 부류: 연도/시간대 보강 후 -> UTC
5) 정규화된 값은 항상 "2026-03-14 07:04:19Z" 처럼 Z 를 붙여 적는다
6) 정렬·간격 계산·상관분석은 UTC 값으로만 한다
7) 제출 직전 +9h 한 번, 답에 KST 명시
```

Z 표기를 강제하는 이유는 단순하다. **표기가 없는 시각은 몇 시간 뒤 자신도 어느 시간대인지 모른다.**

### 4단계 — 변환 명령 모음

FILETIME은 1601-01-01 UTC 기준 100ns 단위이고, Unix epoch와의 차이는 `11644473600`초다.

```text
Unix초   = FILETIME / 10000000 - 11644473600
FILETIME = (Unix초 + 11644473600) * 10000000
WebKit   = (Unix초 + 11644473600) * 1000000
PRTime   = Unix초 * 1000000
```

| 도구 | 입력 형식 지정 | 특징 |
| --- | --- | --- |
| DCode | 드롭다운으로 `Windows: 64 bit Hex Value`, `Google Chrome`, `Unix: Numeric` 등 선택 | GUI. 대상 시간대를 KST로 지정하면 한 번에 나온다 |
| Python | 직접 계산 | 대량 변환·스크립트에 유리 |
| PowerShell | `[datetime]::FromFileTimeUtc` | Windows에서 별도 설치 없이 즉시 |
| GNU `date` | `TZ=... date -d @<초>` | Unix 초 전용. 파이프에 넣기 좋다 |
| `sqlite3` | `datetime(..., 'unixepoch')` | 브라우저 DB를 SQL 안에서 변환 |

```python
import datetime

def ft_to_utc(ft):            # FILETIME (18자리)
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)

def webkit_to_utc(wk):        # Chrome/Edge (17자리)
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=wk)

def prtime_to_utc(pr):        # Firefox (16자리)
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=pr)

KST = datetime.timezone(datetime.timedelta(hours=9))
u = ft_to_utc(133560000000000000)
print(u.strftime('%F %T') + 'Z', '->', u.replace(tzinfo=datetime.timezone.utc).astimezone(KST))
```

```powershell
# FILETIME(정수) -> UTC / KST. 작업 기준은 UTC, 표시만 KST
$ft  = 133560000000000000
$utc = [datetime]::FromFileTimeUtc($ft)
"{0}Z" -f $utc.ToString('yyyy-MM-dd HH:mm:ss')
"{0} KST" -f $utc.AddHours(9).ToString('yyyy-MM-dd HH:mm:ss')

# 이미 UTC 인 CSV 컬럼을 KST 컬럼으로 한 번에 추가
Import-Csv .\evtx.csv | Select-Object *, @{
  n = 'TimeKST'
  e = { ([datetime]::Parse($_.TimeCreated)).ToUniversalTime().AddHours(9) }
} | Export-Csv .\evtx_kst.csv -NoTypeInformation -Encoding UTF8
```

```bash
# Unix초 -> UTC / KST
TZ=UTC       date -d @1773465761 '+%F %T %Z'
TZ=Asia/Seoul date -d @1773465761 '+%F %T %Z'

# 오프셋 붙은 로그 시각 -> UTC 로 되돌리기
TZ=UTC date -d '2026-03-14T16:22:41+09:00' '+%F %T %Z'
```

```sql
-- Chrome History (WebKit) : UTC 와 KST 를 나란히
SELECT url,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch')             AS utc,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch', '+9 hours') AS kst
FROM urls ORDER BY last_visit_time DESC LIMIT 20;

-- Firefox places.sqlite (PRTime)
SELECT url,
       datetime(last_visit_date/1000000, 'unixepoch')             AS utc,
       datetime(last_visit_date/1000000, 'unixepoch', '+9 hours') AS kst
FROM moz_places ORDER BY last_visit_date DESC LIMIT 20;
```

`sqlite3`의 `'localtime'` 수정자는 **분석 PC의 시간대**를 쓴다. 증거물 시간대와 다르면 틀린 값이 나오므로 `'+9 hours'`처럼 오프셋을 직접 적는다.

## 출력 필드 해석

| 본 값 | 판정 | 해야 할 일 |
| --- | --- | --- |
| `2026-03-14 07:04:19Z` | UTC 확정 | 그대로 타임라인에 |
| `2026-03-14T16:04:19+09:00` | 로컬(KST) 확정 | 9시간 빼서 UTC로 |
| `2026-03-14 16:04:19` (표기 없음) | **미확정** | 어느 도구·artifact에서 나왔는지 역추적 |
| `133560000000000000` | FILETIME | `/10000000 - 11644473600` |
| `13417139361000000` | WebKit | `/1000000 - 11644473600` |
| `1773465761` | Unix 초 | 그대로 |
| `Mar 14 16:22:41` | 연도·오프셋 없음 | 보강 후 사용 |
| `1980-01-01 00:00:00` | DOS date-time 0값 | 시각 정보 없음. 증거로 못 쓴다 |
| `1601-01-01 00:00:00` | FILETIME 0값 | "설정되지 않음". 삭제·미기록 의미 |
| `1970-01-01 09:00:00` | Unix 0에 +9한 결과 | 값이 0이었다. 변환 오류가 아니다 |

`1601-01-01`과 `1980-01-01`이 보이면 **변환이 틀린 것이 아니라 원본 값이 0**이다. 이 구분을 못 하면 없는 오류를 찾느라 시간을 버린다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 것 | 다음에 할 일 | 확인 사항 |
| --- | --- | --- |
| 증거물 시간대 = UTC+9 | `SYSTEM` hive 재확인 | `TimeZoneKeyName`, 키 LastWrite ([FOR-0054](./system-timezone.html)) |
| UTC 정규화된 통합 타임라인 | 사건 시각 ±5분의 모든 artifact | 순서가 논리적으로 성립하는가 ([FOR-0050](./ntfs-artifact-timeline.html)) |
| `$MFT` MACB (UTC) | `$UsnJrnl` `$J` | 같은 사건이 초 단위로 붙어 있는가 |
| 시간대 키 LastWrite가 사건 이후 | 그 시점 전후 EVTX | 시간대 설정 변경 = 조작 시도인가 |
| 시스템 시각 변경 흔적 | Security 로그의 시각 변경 이벤트 | 변경 전후 구간의 시각 신뢰도 재평가 |
| 웹 로그 오프셋 `+0900` | 서버 호스트 시간대 | 클라이언트 이미지 시간대와 같은가 |
| 자릿수 17 정수 | Chrome History `urls` | WebKit 변환 후 방문 URL ([FOR-0191](./chrome-history.html)) |

## 흔한 함정

- **이미 로컬인 값에 +9를 하는 것.** `[14/Mar/2026:16:22:41 +0900]`, FAT DOS date, EXIF `DateTimeOriginal`, `NetworkList`의 `SYSTEMTIME`은 이미 로컬 시각이다. 여기에 9시간을 더하면 9시간 미래로 간다. 오프셋 표기가 있거나 B 부류면 변환하지 않는다.
- **도구가 이미 변환한 값에 또 +9를 하는 것.** Autopsy 케이스 시간대, Timeline Explorer 표시, Event Viewer 화면은 이미 로컬로 렌더링된 값이다. 여기에 손으로 9시간을 더하면 총 18시간 오차가 난다. **원본 CSV/XML의 raw 값을 기준으로 계산한다.**
- **artifact마다 즉석에서 +9를 하는 것.** 어떤 값은 변환했고 어떤 값은 안 했는지 추적할 수 없게 된다. 30분 뒤 자기 메모를 믿을 수 없다. UTC로 전부 모은 뒤 마지막에 한 번만 변환한다.
- **서머타임 지역에 고정 오프셋을 쓰는 것.** `Eastern Standard Time`은 여름에 UTC-4, 겨울에 UTC-5다. 사건 날짜가 어느 구간인지 보고 `Bias + DaylightBias`를 쓴다. 한국은 서머타임이 없어 이 함정이 안 보이지만, 문제 이미지가 미국/유럽 환경이면 1시간이 틀린다.
- **epoch 단위를 혼동하는 것.** 13자리를 초로 읽으면 서기 58000년대가 나오고, 10자리를 밀리초로 읽으면 1970년 1월 중순이 나온다. **자릿수 표를 먼저 본다.**
- **연도 없는 syslog에 현재 연도를 넣는 것.** 문제 이미지가 2026년에 배포되었어도 로그는 2024년일 수 있다. 파일 mtime과 로테이션 파일명으로 연도를 확정한다.
- **시스템 시각 조작을 고려하지 않는 것.** Security 로그의 시각 변경 이벤트(`4616`)는 `PreviousTime`과 `NewTime`을 함께 기록한다. 이 이벤트가 있으면 **그 구간의 모든 로컬 시각 해석이 흔들린다.** 조작 구간은 절대 시각 대신 `EventRecordID` 같은 단조 증가 값으로 순서를 판정한다.
- **호스트 간 시계 오차를 시간대 문제로 오해하는 것.** 9시간 1분 23초처럼 딱 떨어지지 않는 차이는 NTP 미동기다. 시간대 변환으로 해결되지 않는다. 이 경우 절대 시각을 맞추려 하지 말고 **각 호스트 내부의 순서**로 논증한다.
- **엑셀이 시각 문자열을 다시 해석하게 두는 것.** CSV를 엑셀로 열면 `2026-03-14 07:04:19`가 로컬 서식으로 재해석되고 초가 잘리기도 한다. 대용량 CSV는 Timeline Explorer로 보거나 텍스트로 다룬다.
- **답에 시간대를 안 적는 것.** `2026-03-14 16:04:19`만 제출하면 채점자가 UTC로 읽을 수 있다. `KST` 또는 `+09:00`을 명시한다. 문제가 시각 표기 형식을 지정했으면 그 형식을 글자 그대로 따른다.

## 교차검증

정규화가 맞았는지 값 하나를 두 방향에서 확인한다.

```bash
# 1) FILETIME -> Unix초 -> 다시 FILETIME 왕복
python3 -c "
ft=133560000000000000
u=ft/10000000-11644473600
print(int(u), int((u+11644473600)*10000000)==ft)"
```

```bash
# 2) 같은 사건이 찍힌 두 로그의 차이가 정확히 오프셋만큼인가
TZ=UTC date -d '2026-03-14T16:22:41+09:00' '+%F %T %Z'   # 07:22:41 UTC
```

| 관찰 | 결론 |
| --- | --- |
| 두 artifact 차이가 정확히 9시간 | 한쪽만 변환됐다. 부류 판정을 다시 한다 |
| 정확히 18시간 | 같은 값에 +9를 두 번 했다 |
| 정확히 1시간 | 서머타임 구간 판정 오류 |
| 8시간 / 15시간 등 | 증거물 시간대가 KST가 아니다 |
| 9시간 1분대 어긋남 | 호스트 시계 오차. 순서로 논증 |
| 사건 순서가 인과에 위배 | 변환 방향이 반대다 |
| 시각이 1601년 / 1980년 | 원본 값이 0. 변환 오류가 아니다 |

논리 검사가 가장 강력하다. **파일 생성보다 업로드가 먼저 나오면 변환이 틀린 것이다.**

## mini walkthrough

```text
문제:
"내부 문서가 외부로 유출됐다. 유출 파일이 생성된 시각부터 업로드까지의
 경과 시간(분)과 업로드 시각을 KST로 답하시오."
첨부: SYSTEM, $MFT, access.log, History (Chrome)

1. 첫 시도 (실패):
   각 도구 출력을 그대로 엑셀에 붙여 시각 컬럼으로 정렬했다.

     $MFT      secret.xlsx Created0x10 : 2026-03-14 07:04:19
     access.log POST /upload.php       : 14/Mar/2026:16:22:41 +0900
     History   last_visit_time         : 13417139361000000

   문자열 정렬 결과:
     07:04:19  파일 생성
     16:22:41  업로드
   -> 경과 시간 = 9시간 18분 22초 = 558분 이라고 답했다.  오답.

   왜 틀렸나:
   $MFT 값은 FILETIME = UTC 이고, access.log 값은 이미 KST(+0900) 다.
   서로 다른 시간대의 값을 같은 축에 놓고 뺐다. 9시간이 통째로 섞였다.
   게다가 History 의 17자리 정수는 아예 변환도 하지 않고 정렬에서 빠졌다.

2. 피벗: 부류를 판정하고 전부 UTC 로 되돌린다
   먼저 시간대 확정:
     SYSTEM\ControlSet001\Control\TimeZoneInformation
       TimeZoneKeyName = Korea Standard Time
       Bias            = -540      -> 로컬 = UTC + 9h
       StandardStart / DaylightStart = 전부 00  -> DST 없음

   부류 판정:
     $MFT Created0x10      -> A (FILETIME, UTC)      : 변환 불필요
     access.log +0900      -> C (오프셋 포함)        : -9h 해서 UTC 로
     History last_visit    -> A (WebKit 17자리)      : /1000000-11644473600

3. UTC 정규화
   $MFT       2026-03-14 07:04:19Z
   access.log 16:22:41 +0900 - 9h = 2026-03-14 07:22:41Z
   History    13417139361000000/1000000-11644473600 = 1773465761
              TZ=UTC date -d @1773465761 -> 2026-03-14 07:22:41Z

4. UTC 축에서 정렬
   07:04:19Z  $MFT      secret.xlsx 생성
   07:22:41Z  History   업로드 페이지 방문
   07:22:41Z  access.log POST /upload.php   <- 브라우저 기록과 초 단위 일치

   경과 = 07:22:41 - 07:04:19 = 18분 22초 -> 18분
   History 와 access.log 가 같은 초에 맞물린 것이 정규화가 맞았다는 증거다.

5. 최종 변환 (제출 직전 1회)
   업로드 07:22:41Z + 9h = 2026-03-14 16:22:41 KST

6. 검산
   558분과 18분의 차이는 정확히 540분 = 9시간.
   1차 시도의 오차가 오프셋 하나였음이 확인된다.

정답: 경과 18분 / 업로드 2026-03-14 16:22:41 KST
```

## 막혔을 때 다음 체크

1. `[TZ NOTE]` 4줄을 적었는가 — 안 적었으면 지금 적는다
2. 각 값의 부류(A/B/C/D)를 판정했는가
3. 정수 타임스탬프의 **자릿수**를 세었는가 — 10/13/16/17/18
4. 도구가 이미 시간대를 적용해 출력하고 있지 않은가 (`Z` 유무, 도구 시간대 설정)
5. 오프셋이 표기된 값에 또 변환하지 않았는가
6. 차이가 정확히 9 / 18 / 8 / 1시간인가 — 각각 변환 누락 / 이중 변환 / 다른 시간대 / DST
7. 사건 순서가 인과에 맞는가 — 안 맞으면 변환 방향이 반대다
8. 시각이 `1601-01-01` / `1980-01-01`인가 — 원본 값이 0이다
9. syslog의 연도를 파일 mtime이나 로테이션 파일명으로 확정했는가
10. 시스템 시각 변경 이벤트가 있는가 — 있으면 그 구간은 순서로만 판정
11. 답에 `KST`/`UTC`를 명시했는가, 문제가 지정한 표기 형식과 같은가
12. 시간대를 확정할 근거가 아예 없으면 UTC로 답하고 근거를 함께 적는다

## 출처

- SRC-014 — Microsoft Learn, File Times: FILETIME은 1601-01-01 UTC 기준 100ns 단위이며 Unix epoch와의 차이가 `11644473600`초라는 정의
- SRC-018 — Microsoft Learn, `TIME_ZONE_INFORMATION`: `Bias`가 분 단위이고 **UTC = 로컬 + Bias**라는 부호 정의, `StandardBias`/`DaylightBias`가 `Bias`에 더해진다는 규칙
- SRC-075 — RFC 3339 / ISO 8601: `Z`와 `+09:00` 오프셋 표기의 의미, 오프셋이 없는 시각 표기는 시간대 미확정이라는 점
- 연도 없는 syslog(RFC 3164) 형식은 구현체마다 다를 수 있으므로 실제 로그 헤더로 확인할 것
- 시각 변경 이벤트의 EventData 필드명(`PreviousTime`/`NewTime`)은 Windows 버전에 따라 다를 수 있으므로 실제 EVTX에서 확인할 것
- DCode의 형식 드롭다운 명칭은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- 문제에서 요구하는 정확한 flag/시각 표기 형식은 대회마다 다르다. 이 글은 특정 flag 형식을 가정하지 않는다
