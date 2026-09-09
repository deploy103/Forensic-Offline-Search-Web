---
id: FOR-0139
title: "ISO 8601 / RFC 3339 timestamp regex와 UTC 정규화"
slug: "iso-timestamp-regex"
category: "로그/Regex"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["JSON log", "journal", "IIS log", "EVTX SystemTime", "audit.log", "Sysmon UtcTime"]
file_paths: ["/var/log/journal", "C:\\inetpub\\logs\\LogFiles"]
registry_paths: []
event_ids: []
protocols: []
tools: ["grep", "ripgrep", "Python", "PowerShell", "jq", "awk"]
commands: ["grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}' app.log", "python3 -c \"from datetime import datetime;print(datetime.fromisoformat('2026-03-14T07:19:02+09:00'))\"", "TZ=UTC date -d '2026-03-14T07:19:02+09:00' --iso-8601=seconds"]
regex_patterns: ["\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}", "\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d{1,9})?(?:Z|[+-]\\d{2}:?\\d{2})?", "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})", "\\d{8}T\\d{6}(?:Z|[+-]\\d{4})?", "\\d{4}-W\\d{2}(?:-\\d)?", "\\d{4}-\\d{3}(?:T|$)", "(?:Z|[+-]\\d{2}:?\\d{2})$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["@timestamp", "time", "timestamp", "SystemTime", "UtcTime", "date"]
file_formats: ["json", "log", "csv", "jsonl"]
primary_terms: ["ISO timestamp regex", "8601 정규식", "ISO 시각 추출"]
keywords: ["ISO 8601", "RFC 3339", "timestamp regex", "타임스탬프 정규식", "UTC 정규화", "오프셋", "KST", "+09:00", "fromisoformat", "DateTimeOffset", "Z 접미", "시간대 변환"]
aliases: ["iso 8601 정규식", "타임스탬프 정규식", "시간 정규식", "utc 변환", "kst 변환", "z 시간", "+09:00 무슨 뜻", "시간 왜 다름"]
symptom_keywords: ["로그 시각을 어떻게 파싱하는지 모르겠다", "Z 가 붙은 시간이 무슨 뜻인지 모르겠다", "로그 두 개 시각이 9시간 차이난다", "fromisoformat 이 에러난다", "시간대 오프셋이 없다", "여러 로그를 시간순으로 합치고 싶다"]
related: ["FOR-0140", "FOR-0054", "FOR-0107", "FOR-0145"]
source_ids: ["SRC-075", "SRC-057"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?` 하나로 실전 ISO 8601/RFC 3339 변형을 거의 다 잡되, **끝의 오프셋 그룹이 매칭되지 않은 타임스탬프는 시간대를 알 수 없는 값**이므로 UTC라고 가정하지 말고 그 로그의 시간대를 별도로 확정해야 한다.

## 개념

ISO 8601은 넓고 RFC 3339는 그중 인터넷용으로 좁힌 프로파일이다. **로그에서 만나는 것은 대부분 RFC 3339**이지만, 도구가 뱉는 변형은 ISO 8601 쪽까지 퍼져 있다.

| 구성요소 | RFC 3339 | ISO 8601 추가 변형 |
| --- | --- | --- |
| 날짜 | `2026-03-14` (확장 형식만) | `20260314` (기본 형식), `2026-W11-6`(주), `2026-073`(서수) |
| 구분자 | `T` (대문자). 관례적으로 공백도 허용 | `T` 또는 생략(기본 형식) |
| 시각 | `07:19:02` | `071902`, `07:19`(초 생략), `07`(분 생략) |
| 소수 초 | `.123`, `.123456` (자리수 제한 없음) | `,123` (쉼표도 소수점) |
| 오프셋 | `Z` 또는 `+09:00` / `-07:00` **필수** | `+0900`, `+09`, 생략 가능 |
| `-00:00` | "오프셋을 모른다"는 별도 의미 | 규정 없음 |

핵심 사실 세 가지다.

1. **RFC 3339는 오프셋을 필수로 요구한다.** 오프셋이 없는 `2026-03-14T07:19:02`는 RFC 3339가 아니라 "지역 시간(local)" ISO 8601이고, **어느 시간대인지 문자열만으로는 알 수 없다.**
2. `Z`는 `+00:00`과 같은 순간을 가리킨다. Zulu의 Z다.
3. `-00:00`은 `+00:00`과 순간은 같지만 **"실제 오프셋을 모른다"** 는 뜻으로 RFC 3339가 따로 정의한다. 로그에서 보이면 생성기가 시간대 정보를 잃었다는 신호다.

### 같은 순간의 여러 표기

| 표기 | 순간(UTC) | KST |
| --- | --- | --- |
| `2026-03-13T22:19:02Z` | 2026-03-13 22:19:02 | 2026-03-14 07:19:02 |
| `2026-03-14T07:19:02+09:00` | 2026-03-13 22:19:02 | 2026-03-14 07:19:02 |
| `2026-03-14T07:19:02+0900` | 동일 | 동일 |
| `20260314T071902+0900` | 동일 | 동일 |
| `2026-03-13T15:19:02-07:00` | 동일 | 동일 |
| `2026-03-13T22:19:02.123456Z` | 동일 + 0.123456초 | |
| `2026-03-14 07:19:02` | **알 수 없다** | **알 수 없다** |

마지막 줄이 이 글의 존재 이유다. 문자열 다섯 개는 같은 순간이고 여섯 번째는 순간이 아니라 "벽시계 표시"다.

KST는 `+09:00`이며 현재 대한민국은 서머타임을 시행하지 않으므로 연중 고정이다. Unix epoch와의 관계는 `epoch = UTC초`이고, Windows FILETIME은 1601-01-01 UTC 기준 100ns 단위여서 Unix와 **11644473600초** 차이가 난다.

## 파일 / 경로

ISO 형식 타임스탬프가 나오는 자리다.

| 대상 | 필드 | 형태 | 시간대 |
| --- | --- | --- | --- |
| EVTX `System/TimeCreated` | `SystemTime` | `2026-03-13T22:19:02.1234567Z` | **UTC 고정** (100ns 7자리) |
| Sysmon EventData | `UtcTime` | `2026-03-13 22:19:02.123` | **UTC 고정**, `T` 없음 |
| IIS W3C 로그 | `date` + `time` (별 컬럼) | `2026-03-14` / `07:19:02` | **UTC 고정** |
| systemd journal JSON | `__REALTIME_TIMESTAMP` | epoch 마이크로초(숫자) | UTC |
| `journalctl -o short-iso-precise` | | `2026-03-14T07:19:02.123456+0900` | 로컬 + 오프셋 |
| rsyslog `RSYSLOG_FileFormat` | | `2026-03-14T07:19:02.123456+09:00` | 로컬 + 오프셋 |
| auditd `audit.log` | `msg=audit(1773... .123:456)` | epoch 초.밀리 | UTC |
| nginx `$time_iso8601` | | `2026-03-14T07:19:02+09:00` | 로컬 + 오프셋 |
| Elastic/OpenSearch, 대부분의 JSON 로그 | `@timestamp` | `2026-03-13T22:19:02.123Z` | UTC 관례 |
| Zeek TSV | `ts` | epoch 초.소수 | UTC |
| EvtxECmd CSV | `TimeCreated` | 도구 옵션에 따라 UTC 또는 로컬 | 옵션 확인 필요 |
| Chrome/Edge 히스토리 | `visit_time` | 1601 기준 마이크로초(숫자) | UTC |

**EVTX의 `SystemTime`과 Sysmon의 `UtcTime`은 UTC 고정**이고, Sysmon의 다른 시각 필드(`CreationUtcTime` 등)도 UTC다. 반면 이벤트 뷰어 GUI는 로컬 시간으로 보여주므로 화면 값과 XML 값이 9시간 다르다.

## 주요 필드

### 패턴 1 — 느슨한 후보 수집 (가장 많이 쓴다)

```text
\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `2026-03-14T07:19:02`, `2026-03-14 07:19:02`, `2026-03-13T22:19:02.123Z`(앞부분만) |
| 매칭 안 됨 | `20260314T071902`, `14/Mar/2026:07:19:02`, `Mar 14 07:19:02` |
| 용도 | "이 로그에 시각이 있나" 확인, 시간 창 좁히기 |

소수와 오프셋을 잘라버리므로 **정렬·병합에는 쓰지 않는다.** 존재 확인용이다.

### 패턴 2 — 실전 통합 패턴 (권장)

```text
\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `2026-03-14T07:19:02+09:00`, `2026-03-14 07:19:02`, `2026-03-13T22:19:02.1234567Z`, `2026-03-14T07:19:02,123+0900` |
| 매칭 안 됨 | 기본 형식(`20260314T071902`), 주/서수 날짜 |
| 캡처 버전 | `(?P<date>...)-...`처럼 명명 그룹을 붙여 쓴다 |

명명 그룹으로 조각을 분해하는 버전이다.

```text
(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ](?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})(?:[.,](?P<frac>\d{1,9}))?(?P<off>Z|[+-]\d{2}:?\d{2})?
```

`off` 그룹이 `None`이면 **그 로그의 시간대를 알아내야 한다.** 그것이 이 패턴을 쓰는 이유다.

### 패턴 3 — 엄격한 RFC 3339 (오프셋 필수)

```text
\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})
```

| 항목 | 값 |
| --- | --- |
| 매칭됨 | `2026-03-14T07:19:02+09:00`, `2026-03-13T22:19:02Z` |
| 매칭 안 됨 | `2026-03-14 07:19:02+09:00`(공백 구분자), `...+0900`(콜론 없음), 오프셋 없는 것 |
| 용도 | "이 로그는 시간대가 명시되어 있다"를 기계적으로 보증할 때 |

### 패턴 4 — ISO 8601 변형들

| 변형 | 예 | 정규식 |
| --- | --- | --- |
| 기본 형식(구분자 없음) | `20260314T071902Z` | `\d{8}T\d{6}(?:Z\|[+-]\d{4})?` |
| 날짜만 | `2026-03-14` | `\d{4}-\d{2}-\d{2}(?![\d-])` |
| 주 날짜 | `2026-W11`, `2026-W11-6` | `\d{4}-W\d{2}(?:-\d)?` |
| 서수 날짜 | `2026-073` | `\d{4}-\d{3}(?![\d-])` |
| 기간(duration) | `PT1H30M`, `P3DT4H` | `P(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?` |
| 구간(interval) | `2026-03-14T00:00Z/2026-03-15T00:00Z` | 두 타임스탬프를 `/`로 이은 것 |

주/서수 날짜와 기간은 **로그에서는 드물다.** 자동화 도구 설정, CI 로그, 백업 정책 파일에서 나온다. `2026-073`은 패턴 1로는 잡히지 않으므로, "날짜가 있어야 하는데 안 잡힌다"면 이 변형을 의심한다.

### 오프셋 표기와 의미

| 오프셋 | 의미 | 주의 |
| --- | --- | --- |
| `Z` | UTC (`+00:00`) | 대문자. 소문자 `z`는 RFC 3339 위반이지만 실물이 존재하므로 `(?i)`로 받아둔다 |
| `+09:00` | KST | RFC 3339 표기 |
| `+0900` | KST | ISO 8601 기본 형식. `strptime %z`가 받는다 |
| `+09` | KST | 시만 있는 표기. 파서가 거부하는 경우가 많다 |
| `-07:00` | PDT (미국 서부 서머타임) | 여름 |
| `-08:00` | PST | 겨울. **같은 서버 로그에서 3월/11월에 바뀐다** |
| `+05:45` | 네팔 | 분 단위 오프셋이 존재한다. `\d{2}:00`으로 가정하면 안 된다 |
| `-00:00` | 순간은 UTC, **오프셋 미상** | 생성기가 시간대를 잃었다는 신호 |
| (없음) | 알 수 없음 | 로그 자체의 시간대를 별도 확정 |

## 빠른 명령

```bash
grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}' app.log | head
```

```bash
# 1) 이 로그에 ISO 시각이 있는지 + 형태 확인
grep -Eom3 '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([.,][0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})?' app.log

# 2) 오프셋이 붙어 있는 줄이 몇 %인지 (시간대 확정의 근거)
total=$(grep -Ec '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:' app.log)
withtz=$(grep -Ec '[0-9]{2}:[0-9]{2}:[0-9]{2}([.,][0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})' app.log)
echo "$withtz / $total"

# 3) 로그에 등장하는 오프셋 종류 (여러 개면 서버가 여러 대다)
grep -Eo '[0-9]{2}:[0-9]{2}:[0-9]{2}([.,][0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})' app.log |
  grep -Eo '(Z|[+-][0-9]{2}:?[0-9]{2})$' | sort | uniq -c

# 4) 특정 시간 창만 (문자열 비교로 충분하다 -- ISO 는 사전순 = 시간순)
awk '$0 >= "2026-03-14T07:00:00" && $0 <= "2026-03-14T08:00:00"' app.log
grep -E '2026-03-14T07:(1[5-9]|2[0-9]):' app.log

# 5) 시간순 정렬 (ISO 확장 형식 + 동일 오프셋이면 sort 로 끝난다)
sort app.log | less

# 6) 한 줄의 시각을 UTC 로 변환 (GNU date)
TZ=UTC date -d '2026-03-14T07:19:02+09:00' --iso-8601=seconds
# -> 2026-03-13T22:19:02+00:00
TZ=Asia/Seoul date -d '2026-03-13T22:19:02Z' --iso-8601=seconds
# -> 2026-03-14T07:19:02+09:00

# 7) 오프셋 없는 로그를 KST 로 간주해 UTC 로 붙여 다시 쓰기
awk '{ if (match($0, /^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}/))
         printf "%s+09:00%s\n", substr($0, RSTART, RLENGTH), substr($0, RSTART+RLENGTH)
       else print }' app.log > app.tz.log

# 8) JSON 로그는 jq 로 (정규식 불필요)
jq -r '[.["@timestamp"], .user, .msg] | @tsv' app.jsonl | sort
```

**ISO 8601 확장 형식은 사전순 정렬이 곧 시간순 정렬이다.** 오프셋이 모두 같거나 전부 `Z`라면 `sort` 한 번으로 병합이 끝난다. 오프셋이 섞여 있으면 반드시 UTC로 변환한 뒤 정렬한다.

```python
import re
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))
UTC = timezone.utc

TS = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
    r'(?:[.,]\d{1,9})?(?P<off>Z|[+-]\d{2}:?\d{2})?)'
)

def parse(s, assume=KST):
    """ISO 문자열 -> aware datetime. 오프셋이 없으면 assume 을 붙인다."""
    t = s.replace(' ', 'T', 1).replace(',', '.')
    # Python 3.11 미만은 'Z' 와 콜론 없는 오프셋을 못 읽는다
    if t.endswith(('Z', 'z')):
        t = t[:-1] + '+00:00'
    m = re.search(r'([+-]\d{2})(\d{2})$', t)
    if m:
        t = t[:m.start()] + f'{m.group(1)}:{m.group(2)}'
    # 소수 초 7자리(EVTX 100ns)는 6자리로 자른다
    t = re.sub(r'\.(\d{6})\d+', r'.\1', t)
    dt = datetime.fromisoformat(t)
    if dt.tzinfo is None:                 # naive -> 가정한 시간대를 붙인다
        dt = dt.replace(tzinfo=assume)    # replace: 벽시계 유지, 시간대 부여
    return dt

# 병합: 어떤 로그든 UTC aware 로 만들고 정렬한다
rows = []
for src, path, assume in [('web', 'access.log', KST), ('auth', 'auth.log', UTC)]:
    for line in open(path, encoding='utf-8', errors='replace'):
        m = TS.search(line)
        if not m:
            continue
        dt = parse(m.group('ts'), assume).astimezone(UTC)   # astimezone: 순간 유지
        rows.append((dt, src, line.rstrip()))

for dt, src, line in sorted(rows):
    print(dt.isoformat(), dt.astimezone(KST).strftime('%H:%M:%S'), src, line[:90])
```

**`replace(tzinfo=)`와 `astimezone()`을 혼동하면 9시간이 틀어진다.**

| 메서드 | 하는 일 | 쓰는 곳 |
| --- | --- | --- |
| `dt.replace(tzinfo=KST)` | 벽시계 숫자를 그대로 두고 시간대 라벨만 붙인다 | naive 값에 "이건 KST였다"를 선언할 때 |
| `dt.astimezone(UTC)` | 순간을 유지하며 숫자를 바꾼다 | 표시 시간대를 바꿀 때 |
| `dt.replace(tzinfo=UTC)` (KST 값에) | **버그.** 07:19 KST를 07:19 UTC로 만들어 9시간 어긋난다 | 없음 |

```powershell
# 오프셋이 있는 문자열: DateTimeOffset 을 쓴다 (오프셋을 보존한다)
$o = [datetimeoffset]::Parse('2026-03-14T07:19:02+09:00')
$o.UtcDateTime            # 2026-03-13 22:19:02
$o.Offset                 # 09:00:00

# 오프셋 없는 문자열은 로컬로 해석된다 -- 명시적으로 가정을 적는다
$kst  = [timezoneinfo]::FindSystemTimeZoneById('Korea Standard Time')
$naive = [datetime]::ParseExact('2026-03-14 07:19:02', 'yyyy-MM-dd HH:mm:ss', $null)
$utc  = [timezoneinfo]::ConvertTimeToUtc($naive, $kst)     # 2026-03-13 22:19:02Z

# UTC -> KST
[timezoneinfo]::ConvertTimeFromUtc([datetime]::Parse('2026-03-13T22:19:02Z').ToUniversalTime(), $kst)

# 라운드트립으로 안전하게 파싱 (Z/오프셋 보존)
[datetime]::Parse('2026-03-13T22:19:02Z', $null, [System.Globalization.DateTimeStyles]::RoundtripKind)

# 항상 ISO 로 출력 (정렬·병합 가능한 형태)
(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')

# EVTX 를 CSV 로 뽑을 때는 UTC 로 고정해 두고 KST 컬럼을 따로 만든다
Import-Csv .\evtx.csv | Select-Object *,
  @{n='KST'; e={ [datetimeoffset]::Parse($_.TimeCreated).ToOffset('09:00').ToString('yyyy-MM-dd HH:mm:ss') }} |
  Sort-Object TimeCreated
```

### 로그 병합 절차 (이 글의 실사용 목적)

| 단계 | 하는 일 | 실패하면 |
| --- | --- | --- |
| 1 | 로그마다 첫 3줄로 **형식과 오프셋 유무**를 확정한다 | 이후 전부 어긋난다 |
| 2 | 오프셋이 없는 로그는 **시간대를 근거로 확정**한다 (아래 표) | 9시간 오차 |
| 3 | 모든 시각을 **UTC aware 값**으로 변환한다 | 정렬이 뒤섞인다 |
| 4 | UTC 기준으로 정렬·병합한다 | |
| 5 | 최종 보고는 **KST로 표시하고 UTC를 괄호로 병기**한다 | 검증 불가 |
| 6 | 소수 초를 버리지 않는다 (같은 초 안의 순서) | 인과관계가 뒤집힌다 |

오프셋 없는 로그의 시간대를 확정하는 근거다.

| 근거 | 확인 방법 |
| --- | --- |
| 시스템 시간대 설정 | Linux `/etc/timezone`, `/etc/localtime` 심링크, `timedatectl` |
| Windows 시간대 | 레지스트리 `TimeZoneKeyName` ([FOR-0054](./system-timezone.html)) |
| 같은 사건이 두 로그에 있다 | 오프셋 있는 로그의 그 줄과 대조해 차이를 계산 |
| 로그 파일 mtime | 마지막 줄의 시각과 mtime 차이 |
| 컨테이너 로그 | 대부분 UTC (이미지 기본 TZ) |
| IIS·EVTX·Sysmon | **UTC 고정.** 확인 불필요 |

## 함께 보는 artifact

| 시각을 확정한 뒤 | 다음 목표 |
| --- | --- |
| 사건 시각 (UTC) | 다른 로그를 그 UTC ±5분으로 재검색 |
| 시스템 시간대 | 레지스트리 `TimeZoneKeyName` ([FOR-0054](./system-timezone.html)) |
| EVTX/Sysmon 시각 | `SystemTime`은 UTC. GUI 표시값과 다름을 명시 |
| 여러 로그를 합쳐야 한다 | CSV 병합 ([FOR-0107](./merge-evtx-csv.html)) |
| 파일시스템 시각과 대조 | `$MFT` MACB ([FOR-0023](./mft-macb.html)) — FILETIME은 UTC |
| 웹 로그 형식이 다르다 | Apache/nginx 시각 형식 해부 |
| 오프셋이 여러 종류다 | 서버가 여러 대. 호스트별로 분리해 처리 |

## 흔한 실수

- **오프셋이 없는 값을 UTC로 가정하는 것.** 가장 비싼 실수다. 한국 서버 로그는 대개 KST이고, 컨테이너는 UTC다. 9시간을 틀린 상태로 상관분석하면 인과관계가 완전히 사라진다. 오프셋이 없으면 시간대를 **먼저 확정**한다.
- **`Z`를 `+00:00`으로 변환하지 않고 `fromisoformat`에 넣는 것.** Python 3.11 미만은 `2026-03-13T22:19:02Z`를 `ValueError`로 거부한다. 3.11 이상은 받아준다. 버전 의존을 피하려면 `Z`를 `+00:00`으로 치환한다.
- **EVTX의 7자리 소수 초를 `fromisoformat`에 그대로 넣는 것.** `22:19:02.1234567`은 100ns 단위 7자리인데 Python `datetime`은 마이크로초 6자리까지다. 3.11 미만에서 실패하고, 자릿수를 잘라야 한다.
- **`replace(tzinfo=)`로 시간대를 "변환"하려는 것.** `replace`는 라벨만 바꾼다. 순간을 바꾸려면 `astimezone()`이다. 반대로 naive 값에 `astimezone()`을 쓰면 실행 머신의 로컬 시간대가 조용히 가정된다.
- **소수 초를 버리고 초 단위로 정렬하는 것.** 같은 초에 여러 이벤트가 있으면 순서가 뒤집혀 "결과가 원인보다 먼저"인 타임라인이 나온다.
- **`+0900`을 콜론 있는 표기로만 처리하는 것.** `strptime`의 `%z`는 `+0900`, `+09:00`, `Z`를 모두 받지만(Python 3.7+), `fromisoformat`은 3.11 미만에서 `+0900`을 거부한다. 파서별 지원 범위가 다르다.
- **`-00:00`을 `+00:00`과 같게 취급해 넘기는 것.** 순간은 같지만 "오프셋 미상"이라는 정보를 잃는다. 그 로그의 생성 환경을 의심해야 한다.
- **로컬 시간에서 서머타임 전환을 무시하는 것.** `-07:00`/`-08:00`처럼 오프셋이 계절마다 바뀌는 서버는 3월/11월 로그에서 같은 벽시계 시각이 두 번 나타나거나 아예 없다. 미국·유럽 서버 로그를 다룰 때 반드시 확인한다.
- **정규식으로 날짜 유효성을 검증하려는 것.** `2026-02-31T25:99:99`도 패턴 2에 매칭된다. 느슨하게 뽑고 `fromisoformat`/`DateTimeOffset.TryParse`에 넘겨 걸러내는 것이 짧고 정확하다.
- **`\d{4}-\d{2}-\d{2}`에 경계를 안 붙이는 것.** `2026-073`(서수 날짜)이나 버전 문자열 `1.2026-03-14`의 일부가 잡힌다. 앞뒤에 `(?<![\d-])` / `(?![\d-])`를 붙인다.
- **기본 형식(`20260314T071902`)을 놓치는 것.** 파일명·백업 이름·일부 도구 출력에서 쓰인다. 확장 형식 패턴으로는 절대 안 잡힌다.
- **보고서에 시간대를 안 적는 것.** `07:19:02`만 쓰면 검증할 수 없다. `2026-03-14 07:19:02 KST (2026-03-13 22:19:02 UTC)` 형태로 병기한다.

## mini example

```text
문제:
"애플리케이션 로그(app.jsonl)와 웹 로그(access.log)를 시간순으로 합쳐
 웹셸 요청 직후 애플리케이션이 무엇을 실행했는지 구하세요."

1. 형식 확인
   $ head -1 app.jsonl
   {"@timestamp":"2026-03-13T22:20:15.412Z","level":"WARN","msg":"exec: id"}
   $ head -1 access.log
   203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] "GET /admin/ HTTP/1.1" 403 199

   app.jsonl 은 ISO + Z (UTC), access.log 는 Apache 형식 + +0900 (KST).

2. 첫 시도 (실패):
   $ cat app.jsonl access.log | sort | head -3
   {"@timestamp":"2026-03-13T22:20:15.412Z",...
   {"@timestamp":"2026-03-13T22:21:07.883Z",...
   203.0.113.77 - - [14/Mar/2026:07:19:02 +0900] ...

   이유: 두 로그의 형식이 다르므로 사전순 정렬이 시간순이 아니다.
        게다가 access.log 는 줄 맨 앞이 IP 라서 시각이 정렬 키가 되지 못한다.
        그리고 22:20Z 과 07:19+0900 중 어느 쪽이 먼저인지 눈으로는 알 수 없다.

3. 두 번째 시도 (실패) -- 벽시계 숫자만 보고 맞추려 했다
   웹 요청 07:19:02, 앱 로그 22:20:15 -> "15시간 차이? 관련 없음" 이라고 결론.

   이유: +0900 과 Z 를 무시했다.
        07:19:02+09:00 = 2026-03-13T22:19:02Z 이므로
        앱 로그 22:20:15Z 는 **웹 요청 73초 후**다. 밀접하게 관련된다.

4. 접근 변경 -- 전부 UTC aware 로 만들고 병합
   >>> import re, json
   >>> from datetime import datetime, timezone, timedelta
   >>> KST, UTC = timezone(timedelta(hours=9)), timezone.utc
   >>> rows = []
   >>> for line in open('app.jsonl'):
   ...     o = json.loads(line)
   ...     t = o['@timestamp'].replace('Z', '+00:00')
   ...     rows.append((datetime.fromisoformat(t), 'app', o['msg']))
   >>> ap = re.compile(r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]')
   >>> MON = {m: i+1 for i, m in enumerate(
   ...     'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}
   >>> for line in open('access.log'):
   ...     m = ap.search(line)
   ...     if not m: continue
   ...     d, mo, y, H, M, S, off = m.groups()
   ...     tz = timezone(timedelta(hours=int(off[:3]), minutes=int(off[0]+off[3:])))
   ...     dt = datetime(int(y), MON[mo], int(d), int(H), int(M), int(S), tzinfo=tz)
   ...     rows.append((dt, 'web', line.split('"')[1]))
   >>> for dt, src, msg in sorted(rows)[:6]:
   ...     print(dt.astimezone(UTC).strftime('%H:%M:%S'),
   ...           dt.astimezone(KST).strftime('%H:%M:%S'), src, msg)
   22:19:02 07:19:02 web GET /admin/ HTTP/1.1
   22:19:44 07:19:44 web POST /upload.php HTTP/1.1
   22:20:15 07:20:15 web GET /uploads/av4tar.php?cmd=id HTTP/1.1
   22:20:15 07:20:15 app exec: id
   22:20:31 07:20:31 web GET /uploads/av4tar.php?cmd=whoami HTTP/1.1
   22:20:31 07:20:31 app exec: whoami

5. 소수 초까지 보고 인과 순서 확정
   web  2026-03-13T22:20:15.318Z  GET /uploads/av4tar.php?cmd=id
   app  2026-03-13T22:20:15.412Z  exec: id
   -> 요청이 94ms 먼저다. 웹 요청이 원인, 앱 실행이 결과.
      초 단위로만 봤다면 두 줄의 순서를 보장할 수 없었다.

6. 교차검증
   $ TZ=UTC date -d '14 Mar 2026 07:19:44 +0900' --iso-8601=seconds
   2026-03-13T22:19:44+00:00
   업로드 성공(POST 200) 시각이 UTC 로 일치한다.

정답: 2026-03-14 07:20:15 KST (2026-03-13 22:20:15 UTC) 에
      /uploads/av4tar.php?cmd=id 요청 -> 94ms 후 앱이 `id` 실행
```

3단계가 이 글의 핵심이다. **오프셋을 읽지 않으면 73초 차이를 15시간 차이로 오독하고, 관련 있는 두 로그를 무관하다고 결론 내린다.**

## 출처

- SRC-075 — RFC 3339: `date-time` ABNF, `T` 구분자와 공백 허용에 관한 note, 소수 초 자리수 무제한, 오프셋 필수 규정, `Z`와 `-00:00`("오프셋 미상")의 구분
- SRC-057 — Python 문서, `re` 및 `datetime`: `fromisoformat`/`strptime %z` 지원 범위, `replace(tzinfo=)`와 `astimezone()`의 의미 차이, 마이크로초 6자리 제한
- ISO 8601 기본 형식·주 날짜·서수 날짜·기간(duration) 표기는 유료 표준 원문이 아니라 RFC 3339의 대비 서술과 실물 로그를 근거로 정리했으므로, 규격 세부(예: 소수점으로 쉼표 사용 허용 범위)는 표준 원문에서 확인할 것
- `fromisoformat`의 `Z`·콜론 없는 오프셋 지원은 Python 3.11에서 확장되었으므로 실행 환경의 버전을 확인할 것
- EvtxECmd 등 도구의 CSV 출력 시간대(UTC/로컬)는 버전과 옵션에 따라 다르므로 실제 출력 헤더에서 확인할 것
