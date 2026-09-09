---
id: FOR-0054
title: "SYSTEM hive 시간대(TimeZoneInformation)와 UTC/KST 보정"
slug: "system-timezone"
category: "Registry"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["TimeZoneInformation", "SYSTEM hive", "FILETIME", "Bias", "ActiveTimeBias"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM"]
registry_paths: ["SYSTEM\\ControlSet001\\Control\\TimeZoneInformation", "SYSTEM\\Select"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "DCode", "rla"]
commands: ["rip.exe -r SYSTEM -p timezone", "python3 -c \"import datetime;print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=133560000000000000//10))\""]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["TimeZoneKeyName", "Bias", "StandardBias", "DaylightBias", "ActiveTimeBias", "StandardName", "DaylightName", "DynamicDaylightTimeDisabled"]
file_formats: ["regf"]
primary_terms: ["TimeZoneInformation", "시간대", "timezone", "Bias", "시간 왜 다름", "utc kst 변환"]
keywords: ["시간대", "TimeZoneInformation", "TimeZoneKeyName", "Bias", "ActiveTimeBias", "KST", "UTC", "FILETIME", "9시간", "11644473600", "Korea Standard Time", "DaylightBias"]
aliases: ["시간 왜 다름", "시간대 확인", "utc kst 변환", "9시간 차이", "타임존 레지스트리", "bias 값", "시각 보정", "korea standard time"]
symptom_keywords: ["시간이 9시간 차이난다", "시각이 안 맞는다", "KST로 답해야 한다", "어느 시간대인지 모르겠다", "로그 시각과 레지스트리 시각이 다르다", "타임스탬프를 어떻게 변환하나"]
related: ["FOR-0051", "FOR-0053", "FOR-0021", "FOR-0191"]
source_ids: ["SRC-018", "SRC-014", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SYSTEM\ControlSet001\Control\TimeZoneInformation`의 `TimeZoneKeyName`과 `Bias`(분 단위, **UTC = 로컬 + Bias**)를 가장 먼저 읽어 두고, 대부분의 Windows artifact가 UTC로 기록된다는 전제하에 답을 요구하는 시간대로 한 번만 변환한다. KST는 `Bias = -540`, 즉 **UTC + 9시간**이다.

## 어떤 문제에서 필요한가

시간대는 별도 문제가 아니라 **모든 타임스탬프 문제의 전제**다.

- "파일이 언제 삭제됐는가(KST)" — `$MFT`/`$UsnJrnl`은 UTC로 기록된다
- "언제 로그인했는가(현지 시각)" — EVTX는 UTC로 저장되고 Event Viewer는 로컬로 표시한다
- 웹 로그의 `+0900`과 레지스트리 LastWrite가 9시간 벌어져 보인다
- 여러 artifact의 시각을 한 타임라인에 올려야 한다
- 답을 제출했는데 정확히 9시간(또는 8/15시간) 틀렸다

## 문제에서 처음 볼 단서

1. 문제 지문이 `KST`, `한국 시간`, `현지 시각`, `UTC+9`를 명시한다
2. 두 artifact의 같은 사건 시각이 정확히 9시간 차이난다
3. 첨부에 `SYSTEM` hive가 있다 → 시간대를 확정할 수 있다
4. 웹/시스템 로그의 시각 표기에 `+0900`이나 오프셋이 붙어 있다
5. 도구 출력 시각 끝에 `Z`가 붙어 있다 → 그 값은 UTC다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -p timezone
```

```text
TimeZoneInformation key
ControlSet001\Control\TimeZoneInformation
LastWrite Time 2026-03-10 04:19:52Z

  DaylightName   -> @tzres.dll,-612
  StandardName   -> @tzres.dll,-611
  Bias           -> -540 (-9 hours)
  ActiveTimeBias -> -540 (-9 hours)
  TimeZoneKeyName-> Korea Standard Time
```

`Bias = -540` 확인 → **모든 UTC 시각에 +9시간**하면 로컬(KST) 시각이다. GUI라면 RegistryExplorer로 `SYSTEM`을 열고 아래 경로로 이동한다(`001`은 `Select\Current` 값으로 정한다 — [FOR-0053](./system-controlset.html)).

```text
SYSTEM\ControlSet001\Control\TimeZoneInformation
```

## 상세 절차

### 1단계 — 값 읽기

| 값 이름 | 타입 | 의미 |
| --- | --- | --- |
| `TimeZoneKeyName` | `REG_SZ` | 시간대의 영문 식별자. **가장 먼저 읽을 값** (예: `Korea Standard Time`) |
| `Bias` | `REG_DWORD` | 표준시의 UTC 오프셋(분). **UTC = 로컬 + Bias** |
| `StandardBias` | `REG_DWORD` | 표준시 구간에 `Bias`에 더할 보정. 보통 `0` |
| `DaylightBias` | `REG_DWORD` | 서머타임 구간에 `Bias`에 더할 보정. 보통 `-60` |
| `ActiveTimeBias` | `REG_DWORD` | **현재 실제로 적용 중인 총 오프셋(분)**. `Bias + (Standard 또는 Daylight)Bias` |
| `StandardName` | `REG_SZ` | 표준시 표시 이름. `@tzres.dll,-611` 같은 리소스 참조일 수 있다 |
| `DaylightName` | `REG_SZ` | 서머타임 표시 이름 |
| `StandardStart` | `REG_BINARY` | 표준시 전환 시점(구조체). DST 없는 지역은 전부 `00` |
| `DaylightStart` | `REG_BINARY` | 서머타임 전환 시점(구조체) |
| `DynamicDaylightTimeDisabled` | `REG_DWORD` | `1`이면 자동 서머타임 조정을 끔 |

`StandardName`/`DaylightName`이 `@tzres.dll,-611` 형태로 나오면 그것은 언어 리소스 참조다. **시간대 판정은 `TimeZoneKeyName`으로 한다.**

### 2단계 — `Bias` 부호를 헷갈리지 않는 법

공식 정의는 다음 한 줄이다.

```text
UTC = 로컬 시각 + Bias        (Bias 단위: 분)
따라서
로컬 시각 = UTC - Bias
```

KST는 `Bias = -540`이므로 `로컬 = UTC - (-540분) = UTC + 9시간`이다. **부호가 직관과 반대**라서 이 한 줄만 외운다.

`REG_DWORD`는 부호 없는 32비트로 저장되므로 음수는 2의 보수로 보인다.

| 시간대 | `Bias`(10진) | 저장된 hex | 실제 오프셋 |
| --- | --- | --- | --- |
| `Korea Standard Time` | `-540` | `0xFFFFFDE4` | UTC+9 |
| `Tokyo Standard Time` | `-540` | `0xFFFFFDE4` | UTC+9 |
| `China Standard Time` | `-480` | `0xFFFFFE20` | UTC+8 |
| `UTC` | `0` | `0x00000000` | UTC+0 |
| `GMT Standard Time` | `0` | `0x00000000` | UTC+0 (여름 UTC+1) |
| `Eastern Standard Time` | `300` | `0x0000012C` | UTC-5 (여름 UTC-4) |
| `Pacific Standard Time` | `480` | `0x000001E0` | UTC-8 (여름 UTC-7) |
| (서머타임 보정) `DaylightBias` | `-60` | `0xFFFFFFC4` | 1시간 앞당김 |

RegRipper는 `-540 (-9 hours)`처럼 부호와 시간을 함께 풀어 준다. RegistryExplorer/hex로 볼 때는 `0xFFFFFDE4`를 부호 있는 정수로 읽어야 `-540`이 나온다.

### 3단계 — 서머타임이 있는 지역

한국은 서머타임이 없으므로 `Bias == ActiveTimeBias == -540`이고 고민할 것이 없다. 서머타임이 있는 지역이면 **사건 날짜가 어느 구간인지**에 따라 오프셋이 달라진다.

| 상황 | 사용할 오프셋 |
| --- | --- |
| DST 없는 지역 (KST 등) | `Bias` |
| 사건이 표준시 구간 | `Bias + StandardBias` |
| 사건이 서머타임 구간 | `Bias + DaylightBias` |
| hive를 만든 시점의 상태 | `ActiveTimeBias` (그 순간의 값일 뿐, 과거 사건에는 못 쓴다) |

**`ActiveTimeBias`는 hive가 마지막으로 기록된 시점의 활성 오프셋이다.** 3월 사건을 8월에 수집한 이미지의 `ActiveTimeBias`로 변환하면 1시간 틀린다. 서머타임 지역에서는 `Bias`와 사건 날짜로 직접 판단한다.

### 4단계 — artifact별 기록 시간대 표

**이 표가 이 글의 핵심이다.** "이미 UTC인 값에 또 +9"를 하거나, "이미 로컬인 값에 +9"를 하는 것이 오답의 대부분이다.

| artifact / 로그 | 저장 형식 | 저장 시간대 | 변환 |
| --- | --- | --- | --- |
| `$MFT` `$SI`/`$FN` MACB | FILETIME (100ns, 1601 기준) | **UTC** | +9h → KST |
| `$UsnJrnl` `$J` 레코드 | FILETIME | **UTC** | +9h |
| `$LogFile` | FILETIME | **UTC** | +9h |
| 레지스트리 키 LastWrite | FILETIME | **UTC** | +9h |
| `Control\Windows\ShutdownTime` | FILETIME (이진 8바이트) | **UTC** | +9h |
| EVTX `TimeCreated SystemTime` | FILETIME (XML은 ISO 8601 Z) | **UTC** | +9h |
| Prefetch 최근 실행 시각 | FILETIME | **UTC** | +9h |
| LNK 대상 MAC 시각 | FILETIME | **UTC** | +9h |
| Jump List | FILETIME | **UTC** | +9h |
| `$Recycle.Bin` `$I` 삭제 시각 | FILETIME | **UTC** | +9h |
| Amcache 대부분 필드 | FILETIME | **UTC** | +9h |
| Shimcache (AppCompatCache) | FILETIME | **UTC** | +9h |
| Chrome/Edge History, Cookies | WebKit (마이크로초, 1601 기준) | **UTC** | +9h ([FOR-0191](./chrome-history.html)) |
| Firefox `places.sqlite` | PRTime (마이크로초, 1970 기준) | **UTC** | +9h |
| SQLite `unixepoch` 정수 | Unix 초 (1970 기준) | **UTC** | +9h |
| SRUM (`SRUDB.dat`) | FILETIME / OLE | **UTC** | +9h |
| Apache / nginx access log | `[14/Mar/2026:16:22:41 +0900]` | **로컬 + 오프셋 표기** | 이미 로컬. 변환 금지 |
| syslog 전통 형식 (`Mar 14 16:22:41`) | 문자열 | **로컬, 오프셋 없음** | 그 호스트의 시간대를 따로 확인 |
| journald / RFC 5424 syslog | ISO 8601 (오프셋 포함) | 표기된 오프셋 | 표기 그대로 |
| IIS W3C Extended log | `date`, `time` 필드 | **UTC (기본 설정)** | +9h |
| FAT / DOS date-time | DOS 날짜·시간 워드 | **로컬, 시간대 정보 없음** | 변환 금지 |
| exFAT | DOS date-time + UTC 오프셋 바이트 | 오프셋 필드가 있으면 그것을 적용 | 필드 유무 확인 |
| EXIF `DateTimeOriginal` | `YYYY:MM:DD HH:MM:SS` | **촬영 기기 로컬, 시간대 없음** | 변환 금지 |
| EXIF GPS 시각 태그 | 날짜/시각 | **UTC** | +9h |
| ZIP local file header 시각 | DOS date-time | **압축한 PC의 로컬** | 변환 금지 |
| PDF `/CreationDate` | `D:20260314162241+09'00'` | 표기된 오프셋 | 표기 그대로 |
| Event Viewer 화면 표시 | (렌더링 결과) | **분석 PC의 로컬 시각** | 이미 변환된 값 |

원칙 두 개로 압축된다.

```text
1) FILETIME / WebKit / Unix epoch 로 저장된 값은 전부 UTC다  -> KST 답이면 +9h
2) 문자열로 로컬 시각이 박혀 있는 값(로그, DOS date, EXIF)은 변환하지 않는다
```

### 5단계 — 변환 실습

FILETIME은 1601-01-01 UTC 기준 100ns 단위, Unix epoch와의 차이는 `11644473600`초다.

```text
Unix초  = FILETIME / 10000000 - 11644473600
FILETIME = (Unix초 + 11644473600) * 10000000
```

```python
import datetime
ft = 133560000000000000                      # 예시 FILETIME 값
utc = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
kst = utc + datetime.timedelta(hours=9)
print(utc, "UTC ->", kst, "KST")
```

```powershell
# PowerShell — FILETIME(정수) -> UTC / KST
$ft = 133560000000000000
$utc = [datetime]::FromFileTimeUtc($ft)
"$($utc.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
"$($utc.AddHours(9).ToString('yyyy-MM-dd HH:mm:ss')) KST"
```

```bash
# Unix초 -> KST (GNU date)
TZ=Asia/Seoul date -d @1773465761 '+%F %T %Z'
```

GUI로는 DCode에 값과 형식(Windows FILETIME / Google Chrome / Unix)을 넣고 대상 시간대를 KST로 지정하면 한 번에 나온다.

### 6단계 — 절차로 고정

```text
[1] SYSTEM\Select -> Current 값으로 ControlSet 번호 결정
[2] ControlSet00N\Control\TimeZoneInformation -> TimeZoneKeyName, Bias 기록
[3] 문제가 요구하는 시간대 확인 (UTC / KST / "현지 시각")
[4] 각 artifact가 UTC 저장인지 로컬 저장인지 위 표로 판정
[5] UTC 저장 + KST 요구 -> +9h 한 번만 적용
[6] 도구 출력 시각에 이미 시간대가 적용됐는지 확인 (Z 표기, 도구 설정)
[7] 최종 답에 시간대를 명시 (2026-03-14 16:04:19 KST)
```

## 출력 필드 해석

| 필드 | 값 예시 | 결론 |
| --- | --- | --- |
| `TimeZoneKeyName` | `Korea Standard Time` | 시스템이 KST로 설정되어 있었다 |
| `Bias` | `-540` / `0xFFFFFDE4` | 표준시 오프셋 UTC+9 |
| `StandardBias` | `0` | 표준시 구간 추가 보정 없음 |
| `DaylightBias` | `0` (KST) / `-60` (DST 지역) | 서머타임 보정치 |
| `ActiveTimeBias` | `-540` | hive 기록 시점의 실제 오프셋. `Bias`와 같으면 DST 미적용 |
| `StandardStart` / `DaylightStart` | 전부 `00` | 서머타임 전환 규칙 없음 = DST 없는 지역 |
| `DynamicDaylightTimeDisabled` | `1` | 자동 서머타임 조정을 사용자가 껐다 |
| 키 LastWrite | `2026-03-10 04:19:52Z` | **시간대 설정이 마지막으로 변경된 시각(UTC)** |

키의 LastWrite도 증거다. **사건 직전에 시간대가 변경되었다면 반포렌식(타임스탬프 혼란 유발) 가능성**을 검토하고, 그 시점 전후의 시각 해석에 주의한다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 할 일 | 확인 사항 |
| --- | --- | --- |
| `Bias = -540` | `$MFT` CSV 전체 | 모든 MACB에 +9h ([FOR-0021](./mft-basics.html)) |
| `Bias` | EVTX CSV | `TimeCreated`에 +9h. Event Viewer 화면값과 비교 |
| `Bias` | 브라우저 History | WebKit/PRTime 변환 후 +9h ([FOR-0191](./chrome-history.html)) |
| `TimeZoneKeyName` | 웹 서버 access log | 로그 오프셋(`+0900`)과 일치하는가 |
| 시간대 키 LastWrite | 그 시각 전후 EVTX/레지스트리 | 시간대 변경 = 조작 시도인가 |
| 활성 ControlSet 번호 | `SYSTEM` 나머지 키 | 서비스·USB·컴퓨터 이름 ([FOR-0053](./system-controlset.html)) |
| hive 목록 | 다른 hive의 LastWrite | 전부 UTC라는 전제 확정 ([FOR-0051](./registry-hive-map.html)) |

## 흔한 함정

- **UTC 값에 +9를 두 번 하는 것.** 도구 설정(Autopsy의 케이스 시간대, Timeline Explorer, EvtxECmd)이 이미 KST로 변환해 출력하고 있는데 손으로 또 +9시간을 더한다. **출력 시각에 `Z`가 없거나 도구 시간대 설정이 KST면 이미 변환된 값이다.**
- **로컬 시각에 +9를 하는 것.** Apache/nginx 로그의 `[14/Mar/2026:16:22:41 +0900]`, FAT/DOS date, EXIF `DateTimeOriginal`은 이미 로컬이다. 변환하면 9시간 미래로 간다.
- **`Bias` 부호를 반대로 적용하는 것.** `-540`을 보고 UTC-9로 읽어 9시간을 빼면 총 18시간 오차가 난다. `UTC = 로컬 + Bias` 한 줄로 확인한다.
- **`REG_DWORD`를 부호 없는 값으로 읽는 것.** `0xFFFFFDE4`를 4294966756분으로 해석하면 아무 의미도 안 나온다. 부호 있는 32비트로 읽는다.
- **`StandardName`/`DaylightName`으로 시간대를 판정하는 것.** `@tzres.dll,-611` 같은 리소스 참조라 지역명이 아니다. `TimeZoneKeyName`을 쓴다.
- **`ActiveTimeBias`를 과거 사건에 적용하는 것.** 그 값은 hive 기록 시점의 상태다. 서머타임 지역이면 사건 날짜로 표준시/서머타임 구간을 따져 `Bias + StandardBias` 또는 `Bias + DaylightBias`를 쓴다.
- **`CurrentControlSet` 경로를 그대로 입력하는 것.** 오프라인 hive에는 없다. `Select\Current`로 `ControlSet00N`을 정한다.
- **시스템 시간대가 사건 당시와 같다고 가정하는 것.** 시간대 키의 LastWrite가 사건보다 나중이면 그 사이에 변경됐을 수 있다. 변경 전 시각 해석은 재검토가 필요하다.
- **답에 시간대를 안 적는 것.** `2026-03-14 16:04:19`만 쓰면 채점자가 UTC로 볼 수 있다. `KST`를 명시한다.
- **여러 호스트의 로그를 합칠 때 각 호스트의 시간대를 확인하지 않는 것.** syslog 전통 형식은 오프셋이 없어서 그 호스트 설정을 따로 확인해야 한다.

## 교차검증

시간대 판정이 맞는지 두 방향에서 확인한다.

```powershell
# 1) 레지스트리
rip.exe -r SYSTEM -p timezone

# 2) 같은 사건이 기록된 두 artifact의 시각 차이를 본다
#    EVTX 4624 (UTC) 와 웹 서버 access log (+0900) 가 같은 사건이면
#    차이가 정확히 Bias 만큼이어야 한다
```

| 관찰 | 결론 |
| --- | --- |
| EVTX(UTC)와 웹 로그(`+0900`) 차이가 정확히 9시간 | `Bias = -540` 확정 |
| 차이가 8시간 | UTC+8 환경. `TimeZoneKeyName` 재확인 |
| 차이가 0 | 웹 로그도 UTC로 기록되도록 설정된 서버 |
| 차이가 9시간 1분 등 어긋난 값 | 호스트 간 시계 오차(NTP 미동기). 절대값보다 순서로 판단 |
| `$MFT` 생성 시각이 사건보다 9시간 미래 | 이미 KST로 변환된 출력에 또 +9를 했다 |

## mini walkthrough

```text
문제:
"사용자가 USB에 파일을 복사한 시각을 KST로 답하세요.
 첨부: SYSTEM, $MFT, access.log"

1. 첫 시도 (실패):
   MFTECmd 로 $MFT 를 파싱해 secret.xlsx 의 Created0x10 을 읽었다.
     Created0x10 = 2026-03-14 07:04:19
   문제가 KST를 요구하니 +9h 해서 16:04:19 KST 라고 답했다... 는 맞지만,
   같은 문제의 두 번째 칸(웹 업로드 시각)에서 access.log 를 이렇게 처리했다.
     [14/Mar/2026:16:22:41 +0900] "POST /upload.php"
     -> +9h 해서 2026-03-15 01:22:41 KST 로 답했다.
   채점 결과 오답.

   왜 틀렸나:
   access.log 의 시각은 이미 로컬(+0900)이다. 문자열에 오프셋이 박혀 있으면
   그 값은 이미 그 시간대의 시각이므로 추가 변환을 하지 않는다.
   "모든 시각에 +9" 라는 습관이 오답의 원인이었다.

2. 피벗: 시간대를 먼저 확정하고, artifact별 저장 시간대를 분류한다
   SYSTEM\Select -> Current = 1
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time
     Bias            = -540 (0xFFFFFDE4)
     ActiveTimeBias  = -540
     StandardStart / DaylightStart = 전부 00  -> DST 없음
   -> 로컬 = UTC + 9h

   분류:
     $MFT MACB   : FILETIME  = UTC   -> +9h 필요
     access.log  : +0900 표기 = 로컬 -> 변환 금지

3. 값 재계산
   $MFT   Created0x10 2026-03-14 07:04:19 UTC -> 16:04:19 KST
   access.log         2026-03-14 16:22:41 (+0900) -> 그대로 16:22:41 KST

4. 교차검증 (같은 사건인지)
   두 시각 차이가 18분 22초. 순서도 파일 생성 -> 업로드 로 자연스럽다.
   만약 access.log 를 또 +9 했다면 업로드가 파일 생성보다 9시간 뒤가 되어
   "복사 전에 업로드했다"는 모순이 생긴다. 이 모순 검사가 검증 장치다.

5. 세 번째 확인 — 도구가 이미 변환했는지
   Timeline Explorer 로 CSV를 열었더니 시각이 16:04:19 로 보였다.
   MFTECmd 는 UTC로 출력하므로 이 화면값은 도구/OS 시간대 설정의 결과다.
   원본 CSV 값(07:04:19)을 기준으로 계산해야 이중 변환을 피한다.

정답: 2026-03-14 16:04:19 KST (파일 생성) / 2026-03-14 16:22:41 KST (업로드)
```

## 막혔을 때 다음 체크

1. **`Bias`를 읽었는가** — `-540`이면 UTC+9
2. `UTC = 로컬 + Bias` 방향을 맞게 적용했는가 (로컬 = UTC − Bias)
3. 그 artifact가 **UTC 저장인지 로컬 저장인지** 표에서 확인했는가
4. 도구가 이미 시간대를 적용해 출력하고 있지 않은가 (`Z` 표기, 도구 시간대 설정)
5. +9를 두 번 하거나, 로컬 값에 +9를 하지 않았는가
6. 서머타임 지역인가 → `DaylightBias`와 사건 날짜 구간 확인
7. 시간대 키의 LastWrite가 사건 이후인가 → 설정 변경 가능성
8. 답에 `KST`/`UTC`를 명시했는가
9. `Select\Current`로 올바른 ControlSet을 열었는가
10. 시각이 정확히 9시간 또는 18시간 어긋나면 변환 횟수·부호 문제다

## 출처

- SRC-018 — Microsoft Learn, `TIME_ZONE_INFORMATION` 구조체: `Bias`는 분 단위이며 **UTC = 로컬 시각 + Bias**, `StandardBias`/`DaylightBias`가 `Bias`에 더해진다는 정의, `StandardDate`/`DaylightDate` 전환 규칙
- SRC-014 — Microsoft Learn, File Times: FILETIME은 1601-01-01 UTC 기준 100ns 단위, Unix epoch와의 차이 `11644473600`초
- SRC-004 — Eric Zimmerman 문서: `rla`로 hive 로그 반영, RegistryExplorer/Timeline Explorer의 시간대 표시 옵션
- `TimeZoneKeyName` 문자열 목록과 `@tzres.dll` 리소스 인덱스는 Windows 버전·언어에 따라 다르므로 실제 hive에서 확인할 것
- IIS·웹 서버 로그의 기록 시간대는 서버 설정으로 변경 가능하므로 로그 헤더와 오프셋 표기로 확인할 것
