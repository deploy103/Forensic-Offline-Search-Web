---
id: FOR-0202
title: "SQLite 시각 변환: 자릿수로 체계 판정하고 datetime 으로 뽑기"
slug: "sqlite-timestamp-conversion"
category: "브라우저/웹"
type: "guide"
difficulty: "basic"
priority: "high"
platform: [windows, linux]
artifact: ["Unix epoch", "WebKit timestamp", "PRTime", "Cocoa Core Data timestamp", "Julian day"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["sqlite3", "DB Browser for SQLite", "DCode"]
commands: ["sqlite3 app.db \"SELECT datetime(t,'unixepoch','+9 hours') FROM x;\"", "sqlite3 app.db \"SELECT datetime(t/1000000-11644473600,'unixepoch') FROM x;\"", "sqlite3 app.db \"SELECT datetime(t/1000000,'unixepoch') FROM x;\"", "sqlite3 app.db \"SELECT datetime(t+978307200,'unixepoch') FROM x;\"", "sqlite3 app.db \"SELECT typeof(t), length(t), min(t), max(t) FROM x GROUP BY 1;\""]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["unixepoch", "julianday", "strftime", "localtime", "utc"]
file_formats: ["sqlite"]
primary_terms: ["SQLite 시각 변환", "datetime unixepoch", "DB 시각 해석"]
keywords: ["SQLite 시각 변환", "datetime unixepoch", "strftime", "Unix epoch", "WebKit timestamp", "PRTime", "Cocoa timestamp", "978307200", "11644473600", "Julian day", "localtime", "밀리초 타임스탬프", "17자리 숫자"]
aliases: ["sqlite 시간 변환", "13자리 숫자 시간", "17자리 숫자 시간", "unixepoch 사용법", "db 시간 이상함", "1970년으로 나온다", "시간 9시간 차이"]
symptom_keywords: ["시간이 1970년으로 나온다", "숫자가 17자리다", "시간이 9시간 어긋난다", "시간이 미래로 나온다", "datetime 결과가 NULL 이다", "한 컬럼에 시간 형식이 섞여 있다"]
related: ["FOR-0201", "FOR-0197", "FOR-0054"]
source_ids: ["SRC-011", "SRC-014", "SRC-090"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

SQLite 안의 시각은 **먼저 `typeof()` 와 자릿수로 체계를 판정**하고, 그 다음 `datetime()` 에 맞는 나눗셈·상수를 적용한다. 10 자리는 Unix 초, 13 자리는 Unix 밀리초, 16~17 자리는 WebKit(1601 기준 마이크로초) 또는 PRTime(1970 기준 마이크로초)이며, **`'localtime'` 은 분석 PC 의 시간대를 쓰므로 대회에서는 `'+9 hours'` 처럼 시간대를 문자로 못박는다.**

## 어떤 문제에서 필요한가

- 브라우저·메신저·앱 DB 에서 "몇 시에 무엇을 했나"를 답해야 하는 모든 문제
- `datetime(t,'unixepoch')` 결과가 `1970-01-01` 이나 `1601-01-01`, 또는 5 만 년 뒤로 나올 때
- 여러 artifact 를 하나의 타임라인에 합칠 때 (기준 시각을 UTC 로 통일해야 한다)
- 답이 9 시간 어긋나 오답 처리될 때
- 한 DB 안에서 테이블마다 시각 체계가 다를 때

## 문제에서 처음 볼 단서

1. **`typeof()`** — `integer` 인가 `text` 인가 `real` 인가. 이것으로 절반이 갈린다.
2. **자릿수** — `length(t)` 를 세는 것이 가장 빠른 판정법이다.
3. **컬럼 이름** — `_time`, `_at`, `date`, `ts`, `msec`, `usec`, `nanos` 에 단위가 적혀 있는 경우가 많다.
4. **min / max 범위** — 최대값이 오늘보다 미래면 나눗셈을 덜 했다는 뜻이다.
5. **문제 지문의 시간대** — "KST" 라고 적혀 있는가, 아니면 UTC 인가. 적혀 있지 않으면 **UTC 로 답하고 KST 를 괄호로 병기**한다.

```sql
SELECT typeof(t) AS ty, length(t) AS len, count(*) AS n, min(t), max(t)
FROM mytable GROUP BY ty, len;
```

```text
ty       len  n     min(t)            max(t)
integer  17   1842  13350000000000000 13391842211913000
```

17 자리 정수 → WebKit 또는 FILETIME 계열 확정.

## 30초 절차

```bash
sqlite3 app.db "SELECT typeof(t), length(t), min(t), max(t) FROM x GROUP BY 1,2;"
```

자릿수를 보고 아래 한 줄을 고른다.

```sql
SELECT datetime(t,'unixepoch','+9 hours')                        FROM x;  -- 10자리
SELECT datetime(t/1000,'unixepoch','+9 hours')                   FROM x;  -- 13자리
SELECT datetime(t/1000000-11644473600,'unixepoch','+9 hours')    FROM x;  -- 17자리 WebKit
SELECT datetime(t/1000000,'unixepoch','+9 hours')                FROM x;  -- 16자리 PRTime
SELECT datetime(t+978307200,'unixepoch','+9 hours')              FROM x;  -- 9~10자리 Cocoa
SELECT datetime(t/10000000-11644473600,'unixepoch','+9 hours')   FROM x;  -- 18자리 FILETIME
SELECT datetime(t)                                               FROM x;  -- ISO 문자열
SELECT datetime(t)                                               FROM x;  -- Julian day (실수)
```

체계를 모를 때 **여섯 후보를 한꺼번에 뽑아 사람이 눈으로 고르는 것**이 가장 빠르다.

```sql
SELECT t,
  datetime(t,'unixepoch')                      AS as_unix_s,
  datetime(t/1000,'unixepoch')                 AS as_unix_ms,
  datetime(t/1000000,'unixepoch')              AS as_prtime,
  datetime(t/1000000-11644473600,'unixepoch')  AS as_webkit,
  datetime(t+978307200,'unixepoch')            AS as_cocoa,
  datetime(t/10000000-11644473600,'unixepoch') AS as_filetime
FROM mytable LIMIT 3;
```

**사건 기간에 들어맞는 컬럼 하나만 남는다.** 나머지는 1601 년, 1970 년, 또는 수만 년 뒤가 나온다.

## 상세 절차

### 1단계 — 값 형태로 체계를 판정한다

| 관측 | 자릿수 / 형태 | 체계 | 기준시각(epoch) | 단위 |
| --- | --- | --- | --- | --- |
| `1773540902` | 정수 10 | **Unix 초** | 1970-01-01 UTC | 초 |
| `1773540902113` | 정수 13 | **Unix 밀리초** | 1970-01-01 UTC | ms |
| `1773540902113000` | 정수 16 | **PRTime** (Firefox) | 1970-01-01 UTC | µs |
| `13391842211913000` | 정수 17 | **WebKit** (Chrome/Edge) | 1601-01-01 UTC | µs |
| `133918422119130000` | 정수 18 | **FILETIME** | 1601-01-01 UTC | 100ns |
| `795180902` | 정수 9~10 | **Cocoa / Core Data** (Apple) | 2001-01-01 UTC | 초 |
| `795180902.113` | 실수 | Cocoa (소수 초) | 2001-01-01 UTC | 초 |
| `2461114.8`  | 실수 7 자리 + 소수 | **Julian day** | -4713-11-24 12:00 UTC | 일 |
| `2026-03-14 07:15:02` | 문자열 | **ISO-8601 문자열** | 그 자체 | - |
| `2026-03-14T07:15:02.113Z` | 문자열 + `T`/`Z` | ISO-8601 UTC | 그 자체 | - |

자릿수 판정을 잊지 않는 요령: **오늘 날짜의 Unix 초는 10 자리**이고, 마이크로초는 거기에 0 이 6 개 더 붙어 16 자리다. 1601 년 기준은 1970 년 기준보다 369 년 더 세므로 한 자리가 더 늘어 17 자리다.

`length()` 는 정수에도 통한다(문자열로 변환해 센다). 다만 값이 작으면 자릿수가 줄어드니 `max(t)` 로 판정한다.

### 2단계 — 상수 세 개만 외운다

| 상수 | 의미 | 어디에 쓰나 |
| --- | --- | --- |
| **11644473600** | 1601-01-01 부터 1970-01-01 까지의 **초** | WebKit, FILETIME |
| **978307200** | 1970-01-01 부터 2001-01-01 까지의 **초** | Cocoa / Core Data |
| **2440587.5** | 1970-01-01 00:00 UTC 의 Julian day | Julian ↔ Unix |

방향을 틀리지 않는 법: **기준시각이 1970 보다 과거면(1601) 빼고, 미래면(2001) 더한다.**

```text
WebKit  -> unix = t/1000000 - 11644473600      (1601 -> 1970: 빼기)
Cocoa   -> unix = t + 978307200                (2001 -> 1970: 더하기)
```

### 3단계 — 변환 SQL 표 (복붙용)

`t` 를 실제 컬럼명으로 바꿔 쓴다. `'+9 hours'` 를 붙이면 KST, 빼면 UTC 다.

| 체계 | UTC 로 | KST 로 |
| --- | --- | --- |
| Unix 초 | `datetime(t,'unixepoch')` | `datetime(t,'unixepoch','+9 hours')` |
| Unix 밀리초 | `datetime(t/1000,'unixepoch')` | `datetime(t/1000,'unixepoch','+9 hours')` |
| Unix 마이크로초 | `datetime(t/1000000,'unixepoch')` | `datetime(t/1000000,'unixepoch','+9 hours')` |
| **WebKit** (Chrome/Edge) | `datetime(t/1000000-11644473600,'unixepoch')` | `datetime(t/1000000-11644473600,'unixepoch','+9 hours')` |
| **PRTime** (Firefox) | `datetime(t/1000000,'unixepoch')` | `datetime(t/1000000,'unixepoch','+9 hours')` |
| **Cocoa** (Apple) | `datetime(t+978307200,'unixepoch')` | `datetime(t+978307200,'unixepoch','+9 hours')` |
| **FILETIME** (100ns) | `datetime(t/10000000-11644473600,'unixepoch')` | `datetime(t/10000000-11644473600,'unixepoch','+9 hours')` |
| ISO 문자열 | `datetime(t)` | `datetime(t,'+9 hours')` |
| Julian day (실수) | `datetime(t)` | `datetime(t,'+9 hours')` |
| Unix 초 → Julian | `julianday(t,'unixepoch')` | - |

**Julian day 는 `datetime()` 의 기본 입력 형식**이다. 변환자를 아무것도 붙이지 않고 `datetime(2461114.8)` 이라고 쓰면 SQLite 가 Julian 으로 해석한다. 그래서 실수형 시각 컬럼에 `'unixepoch'` 를 빼먹으면 조용히 엉뚱한 날짜가 나온다.

밀리초까지 살리려면 정수 나눗셈이 잘라내는 소수부를 따로 붙인다.

```sql
-- Unix 밀리초에서 소수점 3자리까지 유지
SELECT strftime('%Y-%m-%d %H:%M:%f', t/1000.0, 'unixepoch') FROM x;
-- 2026-03-14 07:15:02.113

-- WebKit 에서 마이크로초까지
SELECT strftime('%Y-%m-%d %H:%M:%f', (t-11644473600000000)/1000000.0, 'unixepoch') FROM x;
```

`t/1000` 은 정수 나눗셈이라 밀리초가 버려진다. `t/1000.0` 처럼 **실수로 나눠야** 소수부가 남는다.

### 4단계 — 역방향: 시각으로 범위를 걸러낸다

"3월 14일 16시 이후"만 보려면 컬럼 전체를 변환해 문자열 비교하는 것보다 **원시 정수 범위로 비교하는 것이 정확하고 빠르다**(인덱스도 탄다).

```sql
-- 사람이 읽는 시각 -> WebKit 정수
SELECT (strftime('%s','2026-03-14 07:00:00') + 11644473600) * 1000000;
-- 13391827200000000

-- 그 값으로 직접 필터
SELECT url FROM urls WHERE last_visit_time >= 13391827200000000;
```

| 방향 | SQL |
| --- | --- |
| 문자열 → Unix 초 | `strftime('%s','2026-03-14 07:00:00')` |
| 문자열 → Unix ms | `strftime('%s','...') * 1000` |
| 문자열 → WebKit | `(strftime('%s','...') + 11644473600) * 1000000` |
| 문자열 → PRTime | `strftime('%s','...') * 1000000` |
| 문자열 → Cocoa | `strftime('%s','...') - 978307200` |
| 문자열 → FILETIME | `(strftime('%s','...') + 11644473600) * 10000000` |

`strftime('%s', ...)` 는 입력 문자열을 **UTC 로 해석**한다. KST 로 적은 시각을 넣으려면 `strftime('%s','2026-03-14 16:00:00','-9 hours')` 처럼 되돌린다.

### 5단계 — 시간대: `'localtime'` 을 쓰지 않는다

`datetime()` 의 변환자 중 시간대와 관련된 것은 두 개다.

| 변환자 | 동작 | 대회에서 |
| --- | --- | --- |
| `'unixepoch'` | 앞의 숫자를 **Unix 초로 해석**한다. 시간대와 무관 | 항상 필요 |
| `'localtime'` | UTC 값을 **이 SQLite 가 돌아가는 PC 의 시간대**로 변환 | **쓰지 않는다** |
| `'utc'` | 로컬 시각으로 해석된 값을 UTC 로 되돌린다 | 거의 안 씀 |
| `'+9 hours'` | 결과에 9 시간을 더한다 | **KST 가 필요하면 이것** |

`'localtime'` 이 위험한 이유는 세 겹이다.

1. 분석 PC 의 시간대가 UTC 인 리눅스 VM 이면 아무 일도 일어나지 않아 **변환한 줄 알고 UTC 를 답한다.**
2. 증거물 PC 의 시간대는 `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` 에 있고([FOR-0054](./system-timezone.html)), 분석 PC 와 다를 수 있다.
3. `'localtime'` 은 **그 시각의 DST 규칙**을 적용한다. 한국은 DST 가 없지만 다른 시간대 증거물에서는 여름/겨울에 1 시간이 달라져 재현되지 않는다.

```sql
-- 나쁨: 분석 PC 의 시간대에 결과가 의존한다
SELECT datetime(t/1000000-11644473600,'unixepoch','localtime') FROM urls;

-- 좋음: 어느 PC 에서 돌려도 같은 값이 나온다
SELECT datetime(t/1000000-11644473600,'unixepoch')             AS utc,
       datetime(t/1000000-11644473600,'unixepoch','+9 hours')  AS kst
FROM urls;
```

**보고서에는 UTC 와 KST 를 나란히 적는다.** 어느 쪽을 묻는 문제든 그 자리에서 답할 수 있다.

### 6단계 — `strftime` 서식

| 서식 | 의미 | 예 |
| --- | --- | --- |
| `%Y` | 연 4 자리 | `2026` |
| `%m` | 월 2 자리 | `03` |
| `%d` | 일 2 자리 | `14` |
| `%H` `%M` `%S` | 시 분 초 | `16` `35` `40` |
| `%f` | **초.밀리초** (`SS.SSS`) | `40.113` |
| `%j` | 연중 일수 | `073` |
| `%s` | **Unix 초** | `1773540902` |
| `%w` | 요일 (0=일요일) | `6` |
| `%W` | 연중 주차 | `10` |
| `%J` | Julian day | `2461114.8` |

```sql
-- 시간대별 방문 분포 (KST 기준 몇 시에 활동했나)
SELECT strftime('%H', last_visit_time/1000000-11644473600, 'unixepoch', '+9 hours') AS hh,
       count(*) AS n
FROM urls GROUP BY hh ORDER BY hh;

-- 일자별 집계
SELECT strftime('%Y-%m-%d', t/1000000-11644473600,'unixepoch','+9 hours') AS d,
       count(*) FROM visits GROUP BY d ORDER BY d;
```

### 7단계 — 0, NULL, 음수

| 값 | `datetime()` 결과 | 해석 |
| --- | --- | --- |
| `0` (Unix 초) | `1970-01-01 00:00:00` | **시각이 없다는 뜻.** 1970 년에 방문한 것이 아니다 |
| `0` (WebKit) | `1601-01-01 00:00:00` | 같다. "설정되지 않음" |
| `NULL` | `NULL` | 컬럼 자체가 비었다. 계산에서 제외된다 |
| 음수 (Unix) | 1970 년 이전 | Cocoa 컬럼을 Unix 로 잘못 읽었을 때도 나온다 |
| 음수 (Cocoa) | 2001 년 이전 | Apple DB 에서는 **정상 값**일 수 있다 |
| 매우 큰 값 | 수천~수만 년 뒤 | 나눗셈을 덜 했다 |
| `-1` | 1969-12-31 23:59:59 | 오류 표식으로 쓰이는 경우 |

**0 을 타임라인에 넣지 않는다.** 1970-01-01 또는 1601-01-01 행이 수백 개 나오면 그것은 사건이 아니라 빈 값이다.

```sql
-- 빈 값을 명시적으로 걸러낸다
SELECT datetime(end_time/1000000-11644473600,'unixepoch','+9 hours') AS ended, target_path
FROM downloads
WHERE end_time > 0
ORDER BY end_time;

-- 빈 값을 표시로 남기고 싶으면
SELECT CASE WHEN end_time IS NULL OR end_time = 0 THEN '(없음)'
            ELSE datetime(end_time/1000000-11644473600,'unixepoch','+9 hours') END AS ended
FROM downloads;
```

### 8단계 — 한 DB 안에 여러 체계가 섞였을 때

실제로 흔하다. 원인은 세 가지다.

| 원인 | 예 | 대응 |
| --- | --- | --- |
| 테이블마다 다른 체계 | Firefox `places.sqlite`: `moz_places.last_visit_date` 는 PRTime(µs), `moz_bookmarks.dateAdded` 도 µs 이지만 `moz_annos` 등 일부는 다르게 저장되는 컬럼이 있다 | **컬럼마다** `min/max` 로 판정 |
| 앱이 버전 업하며 단위를 바꿈 | 옛 행은 초, 새 행은 밀리초 | `length(t)` 로 GROUP BY 해 두 무리로 나눠 처리 |
| affinity 때문에 문자열이 섞임 | `INTEGER` 컬럼에 ISO 문자열 3 건 | `typeof()` 분기 |

전부를 한 번에 정규화하는 표현식을 만든다.

```sql
-- 자릿수/타입에 따라 자동 분기해 UTC 문자열로 통일
SELECT t,
  CASE
    WHEN t IS NULL OR t = 0            THEN NULL
    WHEN typeof(t) = 'text'            THEN datetime(t)
    WHEN t > 130000000000000000        THEN datetime(t/10000000-11644473600,'unixepoch')  -- FILETIME
    WHEN t > 13000000000000000         THEN datetime(t/1000000-11644473600,'unixepoch')   -- WebKit
    WHEN t > 1000000000000000          THEN datetime(t/1000000,'unixepoch')               -- PRTime(µs)
    WHEN t > 1000000000000             THEN datetime(t/1000,'unixepoch')                  -- Unix ms
    WHEN t > 1000000000                THEN datetime(t,'unixepoch')                       -- Unix s
    ELSE datetime(t+978307200,'unixepoch')                                                -- Cocoa
  END AS utc
FROM mytable;
```

이 `CASE` 는 **판정을 자동화한 것이지 판정을 대신하는 것이 아니다.** 결과가 사건 기간에 들어오는지 반드시 눈으로 확인하고, 컬럼별 체계를 보고서에 명시한다.

## 출력 필드 해석

`datetime()` 계열 함수의 결과 형태.

| 함수 | 반환 | 예 |
| --- | --- | --- |
| `datetime(...)` | `YYYY-MM-DD HH:MM:SS` 문자열 | `2026-03-14 07:15:02` |
| `date(...)` | `YYYY-MM-DD` | `2026-03-14` |
| `time(...)` | `HH:MM:SS` | `07:15:02` |
| `julianday(...)` | 실수 (일) | `2461114.80210` |
| `strftime(fmt,...)` | 서식대로 문자열 | 지정한 대로 |
| `unixepoch(...)` | Unix 초 정수 (SQLite 3.38 이상) | `1773540902` |

`unixepoch()` **함수**(3.38 이상)와 `'unixepoch'` **변환자**(오래전부터 존재)는 다른 것이다. 대회장 sqlite3 가 구버전이면 함수는 없고 변환자만 있으므로 `strftime('%s',...)` 를 쓴다.

결과를 읽을 때의 판정표.

| 결과가 이렇게 나오면 | 원인 |
| --- | --- |
| `1970-01-01 00:00:00` | 값이 0 이거나, 큰 값에 `'unixepoch'` 없이 그대로 넣었다 |
| `1601-01-01 00:00:00` | WebKit 값이 0 |
| `1969-12-31 ...` | 음수. 체계를 잘못 골랐다 |
| `2026-03-14` 인데 시각만 9 시간 어긋남 | UTC/KST 혼동. `'+9 hours'` 유무 확인 |
| `+55000-01-01` 같은 미래 | 나눗셈 누락 (µs 를 초로 취급) |
| `NULL` | 입력이 NULL, 또는 문자열을 산술 연산해 0/NULL 이 됐다 |
| `4713-11-25` 부근 | 실수를 Julian 으로 해석했다 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 컬럼별 시각 체계 확정 | 스키마 재확인 ([FOR-0201](./sqlite-schema.html)) — 다른 시각 컬럼도 같은 절차로 |
| UTC 로 정규화한 방문 시각 | pcap 절대 UTC 와 대조 ([FOR-0207](./browser-history-vs-pcap.html)) |
| 다운로드 완료 시각 (UTC) | `$MFT` `$SI` 생성시각 ([FOR-0021](./mft-basics.html)) |
| 방문 시각 (KST) | EVTX 4624 로그온 세션 ([FOR-0083](./event-4624-logon.html)) |
| 증거물 PC 의 시간대 | `TimeZoneInformation` ([FOR-0054](./system-timezone.html)) — 로컬 기록의 기준 |
| WebKit 값 전반 | Chrome History 쿼리 ([FOR-0191](./chrome-history.html)) |
| 변환이 의심스러운 단일 값 | DCode GUI 로 교차확인 |

## 흔한 함정

- **`'unixepoch'` 를 빼먹는 것.** `datetime(1773540902)` 는 그 숫자를 **Julian day** 로 해석해 5 만 년 뒤를 반환한다. 에러가 아니라 조용히 틀린 값이 나오므로 가장 위험하다.
- **`'localtime'` 으로 답을 만드는 것.** 분석 PC 시간대에 결과가 의존한다. UTC 인 VM 에서는 아무 변환도 일어나지 않아 UTC 를 KST 라고 답하게 된다. **`'+9 hours'` 로 명시**한다.
- **11644473600 을 빼지 않는 것.** WebKit 값을 초로만 나누면 1601 년 기준이 그대로 남아 `+52xx` 년이 나온다. 반대로 나누기 1000000 을 빼먹으면 값이 너무 커서 미래로 튄다.
- **정수 나눗셈으로 밀리초를 잃는 것.** `t/1000` 은 소수부를 버린다. 순서 판정이 초 단위로 뭉개져 두 이벤트의 선후가 뒤집힐 수 있다. `t/1000.0` 과 `%f` 를 쓴다.
- **0 을 실제 시각으로 취급하는 것.** `1970-01-01` / `1601-01-01` 행은 "값 없음"이다. 타임라인의 맨 앞을 이 행들이 채우면 잘못된 시작점을 보고하게 된다. `WHERE t > 0`.
- **문자열 시각에 산술을 하는 것.** `INTEGER` 로 선언됐어도 `'2026-03-14 07:15:02'` 가 들어 있을 수 있다. `t/1000000` 은 그 문자열을 0 으로 만들어 조용히 1601 년을 반환한다. `typeof()` 로 먼저 분기한다.
- **`length(t)` 를 최소값으로 판정하는 것.** 아주 이른 시각의 값은 자릿수가 짧다. `max(t)` 로 판정한다.
- **PRTime 과 WebKit 을 혼동하는 것.** 둘 다 마이크로초지만 기준이 1970 과 1601 로 다르다. 자릿수가 16 대 17 로 갈리고, 잘못 고르면 정확히 369 년 어긋난다.
- **Cocoa 를 Unix 로 읽는 것.** 2001 기준 값을 1970 기준으로 읽으면 31 년 과거로 나온다. 애플 DB(`ios`, `macOS`)에서 1994~1996 년이 나오면 이것을 의심한다.
- **DB 안의 시각과 파일시스템 시각을 같은 기준으로 가정하는 것.** DB 값은 대개 UTC, NTFS `$SI` 도 UTC 이지만 도구가 로컬로 표시해 준다. 한쪽만 변환하면 9 시간 차이가 생긴다.
- **문제 지문의 시간대를 확인하지 않는 것.** "KST" 라고 적혀 있는데 UTC 로 답하면 오답이다. 지문에 없으면 UTC 로 답하고 KST 를 병기한다.
- **한 컬럼의 체계로 DB 전체를 단정하는 것.** 테이블마다, 컬럼마다 다시 판정한다.

## 교차검증

```bash
# 1) 한 값을 여섯 체계로 동시에 뽑아 사건 기간에 맞는 것을 고른다
sqlite3 -header -column app.db "
SELECT t,
  datetime(t,'unixepoch')                      AS unix_s,
  datetime(t/1000,'unixepoch')                 AS unix_ms,
  datetime(t/1000000,'unixepoch')              AS prtime,
  datetime(t/1000000-11644473600,'unixepoch')  AS webkit,
  datetime(t+978307200,'unixepoch')            AS cocoa,
  datetime(t/10000000-11644473600,'unixepoch') AS filetime
FROM mytable LIMIT 5;"

# 2) 역변환으로 왕복 검증 — 원래 정수로 돌아오는가
sqlite3 app.db "SELECT (strftime('%s','2026-03-14 07:15:02')+11644473600)*1000000;"

# 3) 타입/자릿수 분포 — 섞여 있는지 확인
sqlite3 -header -column app.db "
SELECT typeof(t) ty, length(t) len, count(*) n, min(t), max(t)
FROM mytable GROUP BY ty, len;"
```

```powershell
# 4) PowerShell 로 같은 값을 교차확인 (FILETIME 은 100ns 단위)
# WebKit 마이크로초 -> 10 을 곱해 100ns 로 맞춘다
[datetime]::FromFileTimeUtc(13391842211913000 * 10)
# Unix 초
[datetimeoffset]::FromUnixTimeSeconds(1773540902).UtcDateTime
```

```python
# 5) Python 교차확인
from datetime import datetime, timedelta, timezone
webkit = 13391842211913000
print(datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=webkit))
print(datetime.fromtimestamp(1773540902, timezone.utc))
print(datetime(2001,1,1,tzinfo=timezone.utc) + timedelta(seconds=795180902))
```

GUI 만 쓸 수 있으면 **DCode** 에 값을 붙여 형식 목록을 훑는다. 세 경로(SQL / PowerShell 또는 Python / DCode)가 같은 값을 주면 변환은 확정이다.

## mini walkthrough

```text
문제:
"메신저 앱 DB 에서 피의자가 마지막으로 메시지를 보낸 시각을 KST 로 답하세요."
첨부: chat.db (SQLite), 사건 기간은 2026-03-14

1. 스키마와 시각 컬럼 찾기
   $ sqlite3 chat.db ".tables"
   android_metadata  attachments  messages  threads

   $ sqlite3 -header -column chat.db "PRAGMA table_info(messages);"
   cid  name       type     notnull dflt pk
   0    _id        INTEGER  0            1
   1    thread_id  INTEGER  0            0
   2    body       TEXT     0            0
   3    date       INTEGER  0            0
   4    date_sent  INTEGER  0            0
   5    read       INTEGER  0            0

   -> date 와 date_sent 두 개가 있다.

2. 첫 시도 (실패)
   $ sqlite3 chat.db "SELECT max(date), datetime(max(date)) FROM messages;"
   1773540902113|+58147-05-27 21:15:13

   58147 년. 'unixepoch' 를 빼먹어 SQLite 가 이 숫자를 Julian day 로
   해석했다. 에러가 나지 않고 그럴듯한 형식의 값이 나오는 것이 함정이다.

3. 두 번째 시도 (또 실패)
   $ sqlite3 chat.db "SELECT datetime(max(date),'unixepoch') FROM messages;"
   +58147-05-27 21:15:13

   여전히 미래다. 'unixepoch' 를 붙였는데도 틀렸다는 것은
   단위가 초가 아니라는 뜻이다. 자릿수를 세지 않고 던진 것이 원인이다.

4. 접근 변경 — 판정부터
   $ sqlite3 -header -column chat.db "
     SELECT typeof(date) ty, length(date) len, count(*) n, min(date), max(date)
     FROM messages GROUP BY ty, len;"

   ty       len  n     min(date)      max(date)
   integer  13   4118  1773502244000  1773540902113
   text     9    9     (없음)          미확인

   -> 13 자리 = Unix 밀리초. 그리고 typeof 가 text 인 행이 9 건 섞여 있다.
      선언 타입은 INTEGER 인데 문자열이 들어 있다 (affinity).

5. 밀리초로 변환
   $ sqlite3 -header -column chat.db "
     SELECT datetime(max(date)/1000,'unixepoch')            AS utc,
            datetime(max(date)/1000,'unixepoch','+9 hours') AS kst
     FROM messages WHERE typeof(date)='integer';"

   utc                  kst
   2026-03-14 07:35:02  2026-03-14 16:35:02

6. 섞여 있던 text 행 9 건을 확인 — 여기에 더 늦은 시각이 있으면 답이 바뀐다
   $ sqlite3 -header -column chat.db "
     SELECT date, body FROM messages WHERE typeof(date)='text' ORDER BY date DESC LIMIT 3;"
   date                 body
   2026-03-14T18:02:41Z  ...
   2026-03-14T09:11:03Z  ...

   -> ISO 문자열이고, 18:02:41Z(UTC) 는 4 단계의 07:35:02 UTC 보다 늦다.
      정수 행만 보고 답했다면 틀렸다.

   $ sqlite3 -header -column chat.db "
     SELECT datetime(date)            AS utc,
            datetime(date,'+9 hours') AS kst
     FROM messages WHERE typeof(date)='text' ORDER BY date DESC LIMIT 1;"
   utc                  kst
   2026-03-14 18:02:41  2026-03-15 03:02:41

7. 두 무리를 하나로 합쳐 최종 확인
   $ sqlite3 -header -column chat.db "
     SELECT CASE WHEN typeof(date)='text' THEN datetime(date)
                 ELSE datetime(date/1000,'unixepoch') END AS utc,
            CASE WHEN typeof(date)='text' THEN datetime(date,'+9 hours')
                 ELSE datetime(date/1000,'unixepoch','+9 hours') END AS kst,
            body
     FROM messages WHERE date IS NOT NULL AND date <> 0
     ORDER BY utc DESC LIMIT 1;"

   utc                  kst                  body
   2026-03-14 18:02:41  2026-03-15 03:02:41  자료 넘겼다

8. 시간대 검증
   증거물 레지스트리 TimeZoneInformation = Korea Standard Time (Bias -540)
   -> KST 표기가 유효하다. 'localtime' 을 쓰지 않았으므로
      분석 VM(UTC) 에서 돌려도 같은 값이 나온다.

정답: 2026-03-15 03:02:41 KST (2026-03-14 18:02:41 UTC)
```

두 번의 실패가 각각 다른 교훈이다. 2 단계는 **`'unixepoch'` 누락이 에러가 아니라 그럴듯한 오답을 만든다**는 것, 3 단계는 **자릿수를 세지 않고 단위를 추측하면 안 된다**는 것이다. 그리고 6 단계가 진짜 함정이다 — `typeof()` 로 분포를 보지 않았다면 정수 행 4,118 건만 보고 **9 건에 숨은 최종 답을 놓쳤을 것이다.**

## 막혔을 때 다음 체크

1. `'unixepoch'` 를 붙였는가 — 빼먹으면 Julian 으로 해석된다
2. `length(max(t))` 로 자릿수를 셌는가 — 10/13/16/17/18 중 무엇인가
3. `typeof(t)` 를 GROUP BY 해 봤는가 — 문자열이 섞여 있지 않은가
4. 나눗셈과 상수를 동시에 적용했는가 — WebKit 은 `/1000000` **과** `-11644473600` 둘 다 필요하다
5. 결과가 사건 기간(문제 지문의 날짜)에 들어오는가
6. `'localtime'` 을 쓰지 않았는가 — `'+9 hours'` 로 바꿨는가
7. `WHERE t > 0` 로 빈 값을 걸렀는가
8. UTC 와 KST 를 나란히 뽑아 놓았는가
9. 여섯 체계 동시 변환 쿼리로 후���를 좁혔는가
10. 밀리초 정밀도가 필요한가 — `t/1000.0` 과 `%f` 를 썼는가
11. 다른 테이블의 시각 컬럼도 **따로** 판정했는가
12. PowerShell/Python/DCode 중 하나로 교차확인했는가

## 출처

- SRC-011 — SQLite 공식 문서 Date And Time Functions: `datetime`/`date`/`time`/`julianday`/`strftime`/`unixepoch`, `'unixepoch'`·`'localtime'`·`'utc'`·`'+N hours'` 변환자, 기본 입력 형식이 Julian day 인 점, `%f` 서식, type affinity
- SRC-014 — Microsoft Learn, File Times: FILETIME 이 1601-01-01 UTC 기준 100ns 단위라는 정의와 Unix epoch 와의 11644473600 초 차이
- SRC-090 — Digital Detective DCode: WebKit / PRTime / Cocoa(2001-01-01, 978307200) / Unix / FILETIME 등 타임스탬프 형식별 기준시각과 단위 정리, 단일 값 교차확인용 GUI
- `unixepoch()` 함수는 SQLite 3.38 이상, `pragma_table_info()` 테이블 함수는 3.16 이상에서만 쓸 수 있다. 대회장 도구는 `sqlite3 --version` 으로 먼저 확인할 것
- Firefox `places.sqlite` 의 컬럼별 단위는 스키마 버전에 따라 다를 수 있으므로 `.schema` 와 `min/max` 로 실제 값에서 확인할 것
