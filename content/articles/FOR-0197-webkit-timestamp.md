---
id: FOR-0197
title: "WebKit timestamp 변환하기: 1601년 기준 마이크로초 완전 정리"
slug: "webkit-timestamp"
category: "브라우저/웹"
type: "guide"
difficulty: "basic"
priority: "high"
platform: [windows, linux, macos]
artifact: ["WebKit timestamp", "Chrome timestamp", "1601 epoch"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["sqlite3", "DCode", "Python", "PowerShell"]
commands: ["python3 -c \"import datetime;print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=13391842211913000))\"", "sqlite3 x.db \"SELECT datetime(t/1000000-11644473600,'unixepoch');\"", "[datetime]::FromFileTimeUtc(13391842211913000 * 10)"]
regex_patterns: ["^1[0-9]{16}$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["last_visit_time", "visit_time", "start_time", "end_time", "last_access_time"]
file_formats: ["sqlite"]
primary_terms: ["WebKit timestamp", "웹킷 타임스탬프"]
keywords: ["WebKit timestamp", "웹킷 타임스탬프", "Chrome timestamp", "1601년 기준", "마이크로초", "17자리 숫자", "unixepoch 변환", "FromFileTimeUtc", "timedelta microseconds", "크롬 시간 변환"]
aliases: ["웹킷 시간 변환", "크롬 시간 변환", "17자리 시간", "1601년으로 나온다", "webkit time convert", "크롬 타임스탬프 계산"]
symptom_keywords: ["시간이 17자리 숫자다", "1601년이라고 나온다", "크롬 시간이 이상하게 크다", "다운로드 시각을 변환해야 한다", "webkit 시간을 unix로 바꿔야 한다"]
related: ["FOR-0191", "FOR-0202", "FOR-0014"]
source_ids: ["SRC-008", "SRC-011", "SRC-014", "SRC-090"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

WebKit timestamp는 **1601-01-01 00:00:00 UTC를 기준으로 센 마이크로초**이며, Unix epoch(1970-01-01)와의 차이는 **11,644,473,600초(=11,644,473,600,000,000마이크로초)**이므로 변환식은 `unix_seconds = webkit_value / 1000000 - 11644473600` 하나로 끝난다.

## 어떤 문제에서 필요한가

- Chrome/Edge/Brave/Whale 등 Chromium 계열 브라우저의 `History`, `Cookies`, `Web Data`, `Login Data`의 시각 컬럼을 읽어야 할 때
- 어떤 정수 컬럼을 `datetime()`에 넣었더니 결과가 **1601년** 또는 **먼 미래**로 나올 때
- 값이 **17자리 정수**(예: `13391842211913000`)로 보일 때
- CTF 문제 지문이 "다운로드 시각", "마지막 방문 시각"을 UTC/KST로 답하라고 요구할 때
- DCode 없이 Python/SQL/PowerShell만으로 손 계산해야 하는 상황

## 문제에서 처음 볼 단서

1. **자릿수 17** — 오늘 날짜의 Unix 초는 10자리, 마이크로초는 16자리다. 1601년 기준은 1970년 기준보다 369년 더 세므로 자릿수가 하나 더 늘어 **17자리**가 된다.
2. **컬럼 이름** — `last_visit_time`, `visit_time`, `start_time`, `end_time`, `last_access_time`, `date_created`, `date_modified` (Chromium 계열 브라우저 DB 공통).
3. **`datetime(t)`를 그냥 넣었을 때 5만 년대 미래가 나온다** — WebKit 값을 변환 없이 Julian day로 해석했다는 신호다.
4. **파일이 `History`, `Cookies`, `Web Data`, `Login Data`, `Bookmarks`처럼 확장자가 없다** — Chromium 계열 SQLite DB일 가능성이 높다.

```text
13391842211913000
^^^^^^^^^^^^^^^^^  17자리 정수 -> WebKit timestamp 후보
```

## 30초 절차

```bash
python3 -c "import datetime;print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=13391842211913000))"
```

세 줄로 UTC/KST를 동시에 뽑는다.

```bash
python3 - <<'EOF'
import datetime
webkit = 13391842211913000
utc = datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=webkit)
print("UTC", utc)
print("KST", utc + datetime.timedelta(hours=9))
EOF
```

## 상세 절차

### 1단계 — 기준 상수와 변환식

| 항목 | 값 |
| --- | --- |
| WebKit epoch | 1601-01-01 00:00:00 UTC |
| Unix epoch | 1970-01-01 00:00:00 UTC |
| 두 epoch의 차이 | **11,644,473,600 초** |
| 두 epoch의 차이(마이크로초) | 11,644,473,600,000,000 |
| WebKit 값의 단위 | **마이크로초 (µs)** |

```text
unix_seconds      = webkit_value / 1,000,000 - 11,644,473,600
webkit_value      = (unix_seconds + 11,644,473,600) * 1,000,000
```

11644473600이라는 값 자체가 근거다. 1601년부터 1970년까지 369년이고, 그중 윤년이 89회 들어 있어 총 134,774일이며, 134,774 × 86400초 = 11,644,473,600초가 정확히 맞아떨어진다. **암기가 아니라 계산으로도 검산할 수 있는 상수다.**

### 2단계 — SQL(SQLite)로 변환

```sql
-- UTC
SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls;

-- KST (문자열로 시간대 고정 — 대회에서 가장 안전)
SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','+9 hours') FROM urls;
```

```text
sqlite> SELECT datetime(13391842211913000/1000000-11644473600,'unixepoch');
2026-03-14 07:35:11
sqlite> SELECT datetime(13391842211913000/1000000-11644473600,'unixepoch','+9 hours');
2026-03-14 16:35:11
```

**`'localtime'`을 쓰지 않는다.** 분석 PC의 시간대에 결과가 좌우된다. KST가 필요하면 항상 `'+9 hours'`로 명시한다.

### 3단계 — Python으로 변환

```python
from datetime import datetime, timedelta, timezone

def webkit_to_utc(value: int) -> datetime:
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)

webkit = 13391842211913000
utc = webkit_to_utc(webkit)
kst = utc + timedelta(hours=9)
print(utc, "UTC")
print(kst, "KST")
```

```text
2026-03-14 07:35:11.913000+00:00 UTC
2026-03-14 16:35:11.913000+09:00 KST
```

역방향(사람이 읽는 시각 -> WebKit 정수)도 자주 필요하다.

```python
from datetime import datetime, timezone

def utc_to_webkit(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 1_000_000)

target = datetime(2026, 3, 14, 7, 35, 11, tzinfo=timezone.utc)
print(utc_to_webkit(target))
```

### 4단계 — PowerShell로 변환

PowerShell의 `[datetime]::FromFileTimeUtc()`는 **100나노초(100ns) 단위**를 받는다. WebKit은 마이크로초이므로 **10을 곱해야** 100ns 단위로 맞는다.

```powershell
# WebKit(마이크로초) -> FILETIME(100ns) -> DateTime
$webkit = 13391842211913000
[datetime]::FromFileTimeUtc($webkit * 10)
```

```text
2026년 3월 14일 토요일 오전 7:35:11
```

KST로 보고 싶으면 `AddHours(9)`를 더한다.

```powershell
[datetime]::FromFileTimeUtc($webkit * 10).AddHours(9)
```

역방향(사람이 읽는 시각 -> WebKit)도 같은 원리로 10으로 나눈다.

```powershell
$dt = [datetime]::new(2026,3,14,7,35,11,[DateTimeKind]::Utc)
$filetime = $dt.ToFileTimeUtc()
$webkit = $filetime / 10
$webkit
```

### 5단계 — GUI 도구(DCode)로 교차확인

DCode에 정수를 그대로 붙여넣고 형식 목록에서 `Google Chrome Value`(또는 `WebKit/Chrome Timestamp`)를 선택하면 즉시 변환된다. 손 계산 결과와 다르면 계산 실수를 의심한다.

## 출력 필드 해석

| 관측값 | 의미 |
| --- | --- |
| 정수, 17자리 | WebKit timestamp일 가능성이 높다 (Unix 마이크로초는 16자리) |
| 나눗셈만 하고 상수를 안 뺀 결과가 `+5xxx`년 | `-11644473600`을 빼먹었다 |
| 결과가 `1601-01-01 00:00:00` | 값이 0이다. "시각 없음"을 의미하며 실제 사건 시각이 아니다 |
| 결과가 `1970-01-01` 근처 | 마이크로초를 초로 착각해 `/1000000`을 빼먹었거나 이미 Unix 값이었다 |
| `%f`가 필요한 밀리초 정밀도 | 정수 나눗셈(`/1000000`)이 소수부를 버리므로 실수로 나눠야 한다 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 변환된 UTC 방문/다운로드 시각 | Chrome History의 `urls`/`visits`/`downloads` 쿼리 ([FOR-0191](./chrome-history.html)) |
| 다른 자릿수의 정수 컬럼 발견 | 자릿수별 전체 판정표 ([FOR-0202](./sqlite-timestamp-conversion.html)) |
| KST로 정규화한 시각 | pcap의 절대 시각과 대조 ([FOR-0207](./browser-history-vs-pcap.html)) |
| 증거물 PC의 시간대 확인 필요 | `TimeZoneInformation`(SYSTEM hive) |
| FILETIME(18자리, 100ns)과 혼동됨 | FILETIME은 나눗셈이 `/10000000`으로 다르다 — 별도로 판정 |

## 흔한 함정

- **`/1000000`만 하고 `-11644473600`을 빼지 않는 것.** 결과가 5000년대 이후로 튄다. 두 연산은 항상 세트다.
- **`-11644473600`을 초 단위가 아니라 마이크로초 단위 값에서 빼는 것.** 반드시 먼저 `/1000000`으로 초 단위를 만든 뒤 빼야 한다. 순서를 바꾸면 값이 완전히 틀어진다.
- **PowerShell `FromFileTimeUtc`에 마이크로초 값을 그대로 넣는 것.** `FromFileTimeUtc`는 100ns 단위다. **10을 곱하지 않으면** 실제 시각의 1/10로 계산되어 완전히 다른 연대가 나온다.
- **`'localtime'`으로 KST를 만드는 것.** 분석 PC 시간대에 의존한다. `'+9 hours'`로 명시한다.
- **값이 0인 행을 실제 시각으로 계산하는 것.** WebKit 0은 1601-01-01이며 "값 없음"을 뜻한다. 타임라인에서 제외한다.
- **FILETIME(1601 기준 100ns, 18자리)과 WebKit(1601 기준 마이크로초, 17자리)을 같은 나눗셈으로 처리하는 것.** 단위가 다르다. FILETIME은 `/10000000`, WebKit은 `/1000000`.
- **정수 나눗셈으로 밀리초 정밀도를 잃는 것.** `t/1000000`은 소수부를 버린다. 여러 이벤트의 선후 관계가 필요하면 `t/1000000.0`처럼 실수 나눗셈을 쓴다.
- **문제 지문의 시간대를 확인하지 않고 UTC/KST 중 하나로 단정하는 것.** 지문에 명시가 없으면 UTC로 답하고 KST를 괄호로 병기한다.

## 교차검증

세 가지 방법으로 같은 값을 계산해 일치하는지 확인한다.

```bash
# 1) SQL
sqlite3 :memory: "SELECT datetime(13391842211913000/1000000-11644473600,'unixepoch');"
```

```python
# 2) Python
from datetime import datetime, timedelta, timezone
print(datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=13391842211913000))
```

```powershell
# 3) PowerShell (100ns 단위로 10배)
[datetime]::FromFileTimeUtc(13391842211913000 * 10)
```

세 값이 모두 `2026-03-14 07:35:11` (UTC)로 일치해야 한다. 하나라도 다르면 계산 실수다. GUI가 있으면 DCode로 네 번째 확인을 더한다.

## mini walkthrough

```text
문제:
"Chrome History의 downloads 테이블에서 마지막으로 완료된
 다운로드 시각을 KST로 답하세요."
첨부: 값만 주어짐 — start_time = 13391842211913000

1. 첫 시도 (실패)
   $ python3 -c "import datetime; print(datetime.datetime.fromtimestamp(13391842211913000))"
   OverflowError: signed integer is greater than maximum

   Unix epoch 기준 fromtimestamp()에 마이크로초 단위 대형 정수를
   그대로 넣어서 오버플로가 났다. 값의 기준(1601)과 단위(마이크로초)를
   먼저 판정하지 않고 함수부터 돌린 것이 원인이다.

2. 접근 변경 — 자릿수와 컬럼 이름으로 판정
   17자리, 컬럼명 start_time -> WebKit timestamp 확정.

3. 변환식 적용
   unix_seconds = 13391842211913000 / 1000000 - 11644473600
                = 13391842211.913   - 11644473600
                = 1747738611.913 (근사)

   $ python3 -c "
   import datetime
   webkit = 13391842211913000
   utc = datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc) + \
         datetime.timedelta(microseconds=webkit)
   print(utc)
   print(utc + datetime.timedelta(hours=9))
   "
   2026-03-14 07:35:11.913000+00:00
   2026-03-14 16:35:11.913000+09:00

4. 검증 — SQL로 재확인
   $ sqlite3 :memory: "SELECT datetime(13391842211913000/1000000-11644473600,'unixepoch','+9 hours');"
   2026-03-14 16:35:11

   Python과 SQL 결과가 초 단위까지 일치한다.

정답: 2026-03-14 16:35:11 KST (2026-03-14 07:35:11 UTC)
```

1단계의 실패가 핵심이다. **기준 epoch를 확인하지 않고 표준 라이브러리 함수에 값을 바로 넣으면 오버플로나 엉뚱한 연대가 나온다.** 자릿수와 컬럼명으로 체계를 먼저 판정하는 습관이 필요하다.

## 막혔을 때 다음 체크

1. 값이 17자리인가 — 16자리면 PRTime(1970 기준 µs), 18자리면 FILETIME(1601 기준 100ns)일 수 있다
2. `/1000000`과 `-11644473600`을 **둘 다** 적용했는가
3. PowerShell을 쓴다면 100ns 단위로 맞추기 위해 **10을 곱했는가**
4. `'localtime'`이 아니라 `'+9 hours'`로 KST를 명시했는가
5. 값이 0인 행을 결과에서 제외했는가
6. Python/SQL/PowerShell 세 가지로 같은 값이 나오는가
7. 문제 지문에 UTC/KST 지정이 있는지 다시 확인했는가
8. DCode 같은 GUI로 마지막 교차확인을 했는가

## 출처

- SRC-008 — Chromium source, `components/history/core/browser`: History DB의 시각 컬럼이 WebKit(1601 기준 마이크로초)임을 정의
- SRC-011 — SQLite Date And Time Functions: `datetime(...,'unixepoch')` 변환자와 `'+N hours'` 시간대 이동 문법
- SRC-014 — Microsoft Learn, File Times: 1601-01-01 UTC 기준 시각 체계와 Unix epoch와의 11644473600초 차이의 근거
- SRC-090 — Digital Detective DCode: WebKit/Chrome Timestamp 형식 정의와 GUI 교차확인 방법
