---
id: FOR-0192
title: "Chrome downloads 테이블 심화: state / danger_type / interrupt_reason 와 출처 추적"
slug: "chrome-downloads"
category: "브라우저/웹"
type: "guide"
difficulty: "basic"
priority: "high"
platform: [windows]
artifact: ["Chrome downloads", "downloads_url_chains", "downloads_slices", ".crdownload", "Unconfirmed"]
file_paths: ["C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "C:\\Users\\<user>\\Downloads", "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\History", "%LocalAppData%\\Naver\\Naver Whale\\User Data\\Default\\History"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "HTTPS"]
tools: ["sqlite3", "DB Browser for SQLite", "FTK Imager", "MFTECmd", "NTFS Log Tracker", "strings"]
commands: ["sqlite3 History \"SELECT target_path, state, opened, tab_url FROM downloads;\"", "sqlite3 History \"SELECT hex(hash) FROM downloads;\"", "sqlite3 History \"SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index;\"", "strings -a History | grep -Eo 'https?://[^ \"]+\\.(exe|zip|dll|ps1)'"]
regex_patterns: ["https?://[^\\s\"'<>]+\\.(?:exe|dll|zip|rar|7z|ps1|js|hta|scr)"]
wireshark_filters: ["http.response.code == 302"]
tshark_fields: ["http.host", "http.location"]
log_fields: ["current_path", "target_path", "state", "danger_type", "interrupt_reason", "hash", "opened", "last_access_time", "referrer", "tab_url", "tab_referrer_url", "site_url", "chain_index", "received_bytes", "total_bytes", "etag", "last_modified", "by_ext_id", "http_method"]
file_formats: ["sqlite"]
primary_terms: ["Chrome Downloads", "다운로드 기록", "어디서 받았나", "downloads 테이블"]
keywords: ["Chrome downloads", "downloads 테이블", "downloads_url_chains", "downloads_slices", "crdownload", "state", "danger_type", "interrupt_reason", "opened", "리다이렉트 체인", "다운로드 출처", "Edge 다운로드"]
aliases: ["크롬 다운로드 기록", "다운로드 어디서 받았나", "crdownload", "다운로드 중단 원인", "받은 파일 목록", "다운로드 해시", "엣지 다운로드 기록", "다운로드 리다이렉트"]
symptom_keywords: ["파일을 어디서 받았는지 모르겠다", "다운로드가 중단된 이유를 알고 싶다", "다운로드 기록이 지워졌다", "받은 파일이 디스크에 없다", "crdownload 파일만 남았다", "다운로드 해시가 안 보인다"]
related: ["FOR-0191", "FOR-0197", "FOR-0200", "FOR-0028"]
source_ids: ["SRC-008", "SRC-110", "SRC-011"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

"이 파일을 어디서 받았는가"의 답은 `History` DB의 `downloads.target_path` 가 아니라 **`tab_url` + `downloads_url_chains` 조합**에 있고, `state`·`interrupt_reason`·`opened`·`hash` 네 컬럼이 "온전히 받았는가 / 왜 끊겼는가 / 열어봤는가 / 무슨 파일인가"를 각각 확정한다.

## 어떤 문제에서 필요한가

- 악성 파일의 **최초 유입 경로**를 특정해야 하는 경우
- Downloads 폴더에 파일이 없는데 받은 흔적만 찾아야 하는 경우 (받고 삭제·이동)
- `.crdownload` 조각만 남아 있고 원본 URL을 복원해야 하는 경우
- 다운로드가 중단된 원인(용량 부족 / Safe Browsing 차단 / 사용자 취소)을 구분해야 하는 경우
- 브라우저 기록의 파일 해시와 디스크의 파일 해시를 대조해 **동일 파일인지** 증명해야 하는 경우

테이블 구조 전반과 `urls`/`visits` 조인, WebKit 시각 변환은 [FOR-0191](./chrome-history.html)이 담당한다. 이 글은 `downloads` 계열 3개 테이블만 파고든다.

## 문제에서 처음 볼 단서

1. 첨부에 확장자 없는 `History` 파일이 있는가 → `file History` 로 SQLite 확인
2. `History-wal` 이 같이 있는가 → **있으면 반드시 함께 복사한다.** 마지막 다운로드 1건이 WAL에만 있는 경우가 흔하다
3. `Downloads` 폴더에 `*.crdownload` 또는 `Unconfirmed *.crdownload` 가 있는가 → 미완료 다운로드
4. 문제 지문에 "리다이렉트", "실제 서버", "진짜 출처" 같은 단어가 있는가 → `downloads_url_chains` 가 정답
5. 지문이 "몇 바이트 받았나"를 묻는가 → `received_bytes` vs `total_bytes` 불일치를 노린 문제

## 30초 절차

```bash
sqlite3 -header -column History "SELECT id, target_path, state, opened, tab_url FROM downloads ORDER BY start_time DESC;"
```

```bash
# 0) 사본으로 작업. -wal 을 반드시 같이 복사한다
cp History History.cp; cp History-wal History.cp-wal 2>/dev/null

# 1) 스키마 먼저. Chrome 버전마다 컬럼이 늘어난다
sqlite3 History.cp ".schema downloads"

# 2) 핵심 한 줄 — 무엇을, 어디서, 완료했는가, 열었는가
sqlite3 -header -column History.cp "
SELECT d.id,
       datetime(d.start_time/1000000-11644473600,'unixepoch','+9 hours') AS start_kst,
       d.target_path, d.received_bytes AS got, d.total_bytes AS total,
       d.state, d.danger_type AS danger, d.interrupt_reason AS irsn,
       d.opened, d.tab_url
FROM downloads d ORDER BY d.start_time DESC;"

# 3) 진짜 출처 — 리다이렉트 체인 전체
sqlite3 -header -column History.cp "
SELECT c.id, c.chain_index, c.url FROM downloads_url_chains c ORDER BY c.id, c.chain_index;"
```

## 상세 절차

### 1단계 — `downloads` 전체 컬럼을 의미별로 갈라 본다

컬럼이 30개 가까이 되지만 역할은 5묶음뿐이다.

| 묶음 | 컬럼 | 무엇을 답하는가 |
| --- | --- | --- |
| 식별 | `id`, `guid` | 다른 테이블과의 조인 키 |
| 파일 | `current_path`, `target_path`, `received_bytes`, `total_bytes`, `hash`, `mime_type`, `original_mime_type` | 디스크에 무엇이 남았는가 |
| 상태 | `state`, `danger_type`, `interrupt_reason`, `transient` | 온전히 받았는가 |
| 시각 | `start_time`, `end_time`, `last_access_time` | 언제 받고 언제 열었는가 |
| 출처 | `referrer`, `tab_url`, `tab_referrer_url`, `site_url`, `http_method`, `etag`, `last_modified`, `by_ext_id`, `by_ext_name` | 누가·어디서 시작했는가 |

`opened` 는 상태도 시각도 아닌 **행위** 컬럼이다: `1` 이면 사용자가 브라우저 UI(다운로드 바 / `chrome://downloads`)에서 그 파일을 열었다.

### 2단계 — `state` 해석

`state` 는 Chromium 이 History DB 에 저장하는 전용 정수다.

| `state` | 의미 | 실무 판단 |
| --- | --- | --- |
| 0 | 진행 중 (IN_PROGRESS) | 브라우저가 종료될 때까지 끝나지 않았다. `.crdownload` 가 남는다 |
| 1 | **완료 (COMPLETE)** | 파일이 온전히 `target_path` 에 저장됐다 |
| 2 | 취소 (CANCELLED) | 사용자가 취소. `interrupt_reason` 40 과 함께 나오는 경우가 많다 |
| 3 | 레거시 값 | 과거 버전이 쓰던 자리. 현행 브라우저에서는 사실상 나오지 않는다 |
| 4 | **중단 (INTERRUPTED)** | 원인은 `interrupt_reason` 에 있다 |

`state = 1` 이 아닌 행을 "다운로드 실패"로 뭉개면 안 된다. **`state = 4` 이면서 `received_bytes` 가 0보다 크면 부분 파일이 디스크에 남아 있다.**

### 3단계 — `danger_type` 해석

Safe Browsing 이 그 파일을 어떻게 판정했는지, 그리고 사용자가 경고를 무시했는지가 들어 있다.

| `danger_type` | 이름 | 의미 |
| --- | --- | --- |
| 0 | NOT_DANGEROUS | 판정 없음 |
| 1 | DANGEROUS_FILE | 확장자 자체가 위험군(`.exe`, `.dll`, `.scr` 등) |
| 2 | DANGEROUS_URL | URL 이 Safe Browsing 블랙리스트 |
| 3 | DANGEROUS_CONTENT | 내용이 악성으로 판정 |
| 4 | MAYBE_DANGEROUS_CONTENT | 악성 의심 |
| 5 | UNCOMMON_CONTENT | 드문 파일. 평판 정보 부족 |
| 6 | **USER_VALIDATED** | **사용자가 "유지"를 눌러 경고를 무시했다** |
| 7 | DANGEROUS_HOST | 호스트가 악성 배포 이력 |
| 8 | POTENTIALLY_UNWANTED | PUP/애드웨어류 |

`danger_type = 6` 은 포렌식에서 가치가 매우 크다. **브라우저가 경고를 띄웠고 사용자가 의도적으로 무시했다**는 증거다. 9 이상의 값은 딥스캔·정책 차단 등으로 버전마다 추가되므로 단정하지 말고 `.schema` 와 함께 Chromium 소스로 확인한다.

### 4단계 — `interrupt_reason` 해석

번호대가 그대로 원인 계열이다. 이것만 기억하면 대부분 판단이 된다.

| 번호대 | 계열 | 대표 값 |
| --- | --- | --- |
| 0 | 없음 | 0 NONE (정상) |
| 1~19 | **로컬 파일 계열** | 1 FILE_FAILED, 2 FILE_ACCESS_DENIED, 3 **FILE_NO_SPACE**, 5 FILE_NAME_TOO_LONG, 6 FILE_TOO_LARGE, 7 **FILE_VIRUS_INFECTED**, 10 FILE_TRANSIENT_ERROR, 11 **FILE_BLOCKED**, 12 FILE_SECURITY_CHECK_FAILED, 13 FILE_TOO_SHORT, 14 FILE_HASH_MISMATCH |
| 20~29 | 네트워크 계열 | 20 NETWORK_FAILED, 21 NETWORK_TIMEOUT, 22 NETWORK_DISCONNECTED, 23 NETWORK_SERVER_DOWN, 24 NETWORK_INVALID_REQUEST |
| 30~39 | 서버 계열 | 30 SERVER_FAILED, 31 SERVER_NO_RANGE, 33 SERVER_BAD_CONTENT, 34 SERVER_UNAUTHORIZED, 35 SERVER_CERT_PROBLEM, 36 SERVER_FORBIDDEN, 37 SERVER_UNREACHABLE, 38 SERVER_CONTENT_LENGTH_MISMATCH |
| 40~49 | **사용자 계열** | 40 **USER_CANCELED**, 41 USER_SHUTDOWN |
| 50 | 크래시 | 50 CRASH |

판단 요령:

- `7 FILE_VIRUS_INFECTED` / `11 FILE_BLOCKED` → **백신 또는 정책이 막았다.** 파일은 디스크에 없다
- `40 USER_CANCELED` → 사용자가 스스로 멈췄다. 의도 증거
- `41 USER_SHUTDOWN` / `50 CRASH` → 브라우저가 죽었다. `.crdownload` 가 남아 있을 확률이 높다
- `3 FILE_NO_SPACE` → 디스크가 꽉 찼다. 사건과 무관한 노이즈일 때가 많다

### 5단계 — `opened` 와 `last_access_time`

| 컬럼 | 의미 | 주의 |
| --- | --- | --- |
| `opened` | 브라우저 UI 를 통해 파일을 **열었는가** (0/1) | 탐색기에서 직접 더블클릭한 것은 잡히지 않는다 |
| `last_access_time` | 마지막 접근 시각 (WebKit µs) | `0` 이면 접근 기록 없음 |

`opened = 1` 이면서 `last_access_time > 0` 인 행은 **다운로드 → 실행/열기까지 이어졌다**는 직접 증거다. 여기서 바로 실행 흔적(UserAssist, Prefetch)으로 pivot 한다.

`opened = 0` 이라고 실행하지 않았다고 단정하면 안 된다. 탐색기에서 연 경우는 이 값이 0으로 남는다.

### 6단계 — `hash` 는 BLOB 이다

`hash` 컬럼은 완료된 다운로드의 **SHA-256 원시 32바이트**다. 그냥 `SELECT hash` 하면 깨진 바이너리가 출력된다.

```bash
sqlite3 -header -column History.cp "
SELECT id, target_path, length(hash) AS hlen, hex(hash) AS sha256 FROM downloads;"
```

```text
id  target_path                                    hlen  sha256
7   C:\Users\jhkim\Downloads\setup_v3.exe          32    9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
9   C:\Users\jhkim\Downloads\report.pdf            0
```

| `length(hash)` | 의미 |
| --- | --- |
| 32 | SHA-256 이 기록됐다. `hex()` 로 꺼내 디스크 파일 해시와 대조한다 |
| 0 | 빈 BLOB. 완료되지 않았거나 해시를 계산하지 않은 다운로드 |

`hex()` 출력은 대문자다. 대조할 때는 양쪽을 같은 대소문자로 정규화한다.

### 7단계 — `referrer` vs `tab_url` vs `site_url` 의 차이

이 세 컬럼을 같은 것으로 취급하는 것이 이 테이블에서 가장 흔한 오독이다.

| 컬럼 | 채워지는 값 | 언제 비어 있나 |
| --- | --- | --- |
| `referrer` | HTTP `Referer` 헤더로 실제 전송된 참조 URL | Referrer-Policy 로 축약/제거되면 도메인만 남거나 빈 문자열 |
| `tab_url` | **다운로드를 시작한 탭에 떠 있던 페이지 URL** | 새 탭이 즉시 닫히는 다운로드, 링크를 새 창으로 여는 경우, 확장/외부 프로그램이 유발한 다운로드 |
| `tab_referrer_url` | 그 탭이 어디서 왔는지 | 탭이 첫 페이지일 때 |
| `site_url` | 사이트 단위(scheme + eTLD+1) 로 축약된 값 | 구버전 또는 사이트 격리 정보가 없을 때 |

우선순위는 **`tab_url` > `referrer` > `site_url`** 이다. `referrer` 는 정책으로 잘려 있을 수 있고, `site_url` 은 애초에 경로가 없다. 세 개가 모두 비어 있으면 `by_ext_id`(확장이 유발한 다운로드)와 `downloads_url_chains` 로 넘어간다.

최신 Chromium 은 `site_url` 대신 `embedder_download_data` 를 쓰는 버전도 있다. 컬럼이 없다고 나오면 `.schema downloads` 로 확인한다.

### 8단계 — `downloads_url_chains` 로 리다이렉트 체인 복원

```sql
-- 스키마: downloads_url_chains(id, chain_index, url)
SELECT d.target_path, c.chain_index, c.url
FROM downloads d JOIN downloads_url_chains c ON c.id = d.id
ORDER BY d.id, c.chain_index;
```

| `chain_index` | 의미 |
| --- | --- |
| 0 | **사용자가 클릭/입력한 최초 URL** |
| 1..n-1 | 3xx 또는 JS 리다이렉트 중간 단계 |
| 마지막 | 실제로 바이트를 내려준 URL |

`downloads` 테이블 어디에도 "최종 URL" 컬럼은 없다. 체인의 마지막 항목이 그것이다. **단축 URL·CDN·클라우드 스토리지를 거친 배포는 0번과 마지막이 완전히 다른 도메인**이므로, 하나만 보면 결론이 뒤집힌다.

체인 길이로 바로 의심 대상을 뽑는다.

```bash
sqlite3 -header -column History.cp "
SELECT d.id, count(*) AS hops, min(c.url) AS one_of
FROM downloads d JOIN downloads_url_chains c ON c.id=d.id
GROUP BY d.id HAVING hops > 1;"
```

### 9단계 — `downloads_slices`

병렬 다운로드(구간 분할 수신)를 쓰면 구간별 진행 상황이 별 테이블에 들어간다.

| 컬럼 | 의미 |
| --- | --- |
| `download_id` | `downloads.id` 참조 |
| `offset` | 이 조각의 시작 오프셋 |
| `received_bytes` | 이 조각이 받은 바이트 |
| `finished` | 이 조각이 끝났는가 |

```bash
sqlite3 -header -column History.cp "
SELECT download_id, offset, received_bytes, finished FROM downloads_slices ORDER BY download_id, offset;"
```

행이 여럿이고 `finished = 0` 이 섞여 있으면 **파일 중간에 구멍이 있는 부분 파일**이다. 그 파일의 해시가 원본과 다른 이유가 여기서 설명된다. 테이블이 비어 있는 것은 정상이다(병렬 다운로드를 안 쓴 경우).

### 10단계 — `.crdownload` 와 `$UsnJrnl` RENAME 쌍

Chrome 은 다운로드 중에는 최종 이름을 쓰지 않는다.

| 단계 | 디스크의 이름 | DB 의 값 |
| --- | --- | --- |
| 수신 중 (대상 확정) | `report.pdf.crdownload` | `current_path` = `...report.pdf.crdownload`, `target_path` = `...report.pdf` |
| 수신 중 (대상 미확정 / 위험 판정 대기) | `Unconfirmed 481203.crdownload` | `current_path` 가 `Unconfirmed ...` |
| 완료 | `report.pdf` | `current_path` = `target_path`, `state` = 1 |

완료 순간 파일은 **rename** 된다. NTFS 에서 rename 은 `$UsnJrnl:$J` 에 **한 파일에 대한 두 개의 레코드 쌍**으로 남는다.

| USN Reason | 파일명 필드 | 의미 |
| --- | --- | --- |
| `RENAME_OLD_NAME` (0x00001000) | `report.pdf.crdownload` | 바뀌기 전 이름 |
| `RENAME_NEW_NAME` (0x00002000) | `report.pdf` | 바뀐 뒤 이름 |

두 레코드는 **같은 File Reference Number(MFT 엔트리)** 를 가지며 USN 이 연속한다. 이것이 왜 중요한가:

- `History` 가 지워졌어도 `$J` 에 `*.crdownload` → 최종 이름 쌍이 남으면 **다운로드가 있었다는 사실과 파일명·시각을 복원**할 수 있다
- 반대로 `$J` 에 `.crdownload` 쌍이 없는 파일은 브라우저 다운로드가 아니라 복사·압축해제·USB 유입일 가능성이 크다
- `Unconfirmed NNNNNN.crdownload` 이름이 `$J` 에 있으면 **Safe Browsing 대기 중이던 위험 판정 다운로드**였다는 뜻이다

Reason 플래그 값과 파싱 방법은 [FOR-0028](./usn-reason-flags.html), `$J` 추출은 [FOR-0027](./usnjrnl-basics.html)을 본다.

```powershell
# $J 를 파싱한 뒤 crdownload 쌍만 뽑기 (경로는 반드시 작은따옴표)
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv 'C:\case\out' --csvf usn.csv
Import-Csv 'C:\case\out\usn.csv' |
  Where-Object { $_.Name -like '*.crdownload' -or $_.UpdateReasons -match 'Rename' } |
  Select-Object UpdateTimestamp, Name, UpdateReasons, EntryNumber |
  Sort-Object UpdateTimestamp
```

### 11단계 — 삭제된 다운로드 기록 복구

`chrome://downloads` 에서 항목을 지우면 `downloads` 행이 DELETE 되지만, SQLite 는 그 바이트를 즉시 0으로 덮지 않는다. 지워진 행은 **freelist 페이지 또는 페이지 내부의 미사용 영역**에 그대로 남는다.

```bash
# 1) 가장 빠른 방법 — strings 로 URL·경로 잔존 문자열 긁기
strings -a History | grep -Eo 'https?://[^ "]+\.(exe|dll|zip|rar|7z|ps1|js|hta|iso|pdf)' | sort -u
strings -a History | grep -Eo 'C:\\\\Users\\\\[^ "]+\\\\Downloads\\\\[^ "]+' | sort -u

# 2) -wal 에도 따로 긁는다. 커밋 전 데이터가 여기에만 있다
strings -a History-wal | grep -Eo 'https?://[^ "]+' | sort -u

# 3) freelist 가 실제로 남아 있는지 확인
sqlite3 History.cp "PRAGMA freelist_count; PRAGMA page_size; PRAGMA page_count;"

# 4) 구조까지 살리고 싶으면 .recover
sqlite3 History.cp ".recover" > recovered.sql
grep -i -E 'downloads|crdownload' recovered.sql | head -40
```

| 방법 | 얻는 것 | 한계 |
| --- | --- | --- |
| `strings` | URL, 저장 경로, 파일명 문자열 | 시각·`state` 등 정수는 못 얻는다 |
| `PRAGMA freelist_count` | 삭제 흔적이 남았을 가능성 판단 | 값 자체는 증거가 아니다 |
| `.recover` | 살아 있는 페이지에서 재구성한 INSERT 문 | 이미 덮인 행은 못 살린다 |
| `$UsnJrnl` `.crdownload` 쌍 | DB 가 통째로 없어도 파일명 + 시각 | 볼륨이 NTFS 여야 한다 |
| 캐시 폴더 URL 목록 | 방문/수신 URL 잔존 | 큰 파일은 캐시에 없다 |

`PRAGMA secure_delete` 가 켜진 DB 는 삭제 바이트를 0으로 덮으므로 잔존 문자열이 없다. `strings` 가 아무것도 못 뽑아도 "다운로드가 없었다"는 결론이 아니다.

### 12단계 — Edge / Whale / Brave 는 같은 쿼리가 그대로 통한다

| 브라우저 | `History` 경로 | 스키마 |
| --- | --- | --- |
| Chrome | `%LocalAppData%\Google\Chrome\User Data\<프로필>\History` | 기준 |
| Edge | `%LocalAppData%\Microsoft\Edge\User Data\<프로필>\History` | 동일 (Edge 전용 컬럼이 추가될 수 있다) |
| Whale | `%LocalAppData%\Naver\Naver Whale\User Data\<프로필>\History` | 동일 |
| Brave | `%LocalAppData%\BraveSoftware\Brave-Browser\User Data\<프로필>\History` | 동일 |
| Opera | `%AppData%\Opera Software\Opera Stable\History` | 동일 (경로가 Roaming 이다) |

`<프로필>` 은 `Default`, `Profile 1`, `Profile 2` … 다. **전부 확인한다.**

```powershell
Get-ChildItem 'C:\Users\*\AppData\*\*\*\User Data\*\History' -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime
```

## 출력 필드 해석

한 행을 읽는 순서를 고정해 두면 오독이 줄어든다.

| 읽는 순서 | 컬럼 | 뽑아내는 결론 |
| --- | --- | --- |
| 1 | `state` | 온전한 파일인가 (1 이어야 한다) |
| 2 | `received_bytes` / `total_bytes` | 같은가. 다르면 부분 파일 |
| 3 | `interrupt_reason` | 다르다면 왜 끊겼나 |
| 4 | `target_path` | 디스크의 어디에 있어야 하나 |
| 5 | `hex(hash)` | 그 파일이 정말 이 파일인가 |
| 6 | `tab_url` → `chain_index` 0 → 마지막 | 어디서 시작해 어디서 실제로 받았나 |
| 7 | `danger_type` | 브라우저가 경고했나, 사용자가 무시했나 |
| 8 | `opened`, `last_access_time` | 열었나, 언제 |
| 9 | `start_time` / `end_time` 차이 | 파일 크기에 비해 시간이 말이 되나 |

`end_time = 0` 이면서 `state = 0` 은 "브라우저가 끝을 보지 못했다"는 뜻이다. 시각 컬럼은 모두 WebKit 마이크로초이므로 변환 규칙은 [FOR-0197](./webkit-timestamp.html)을 따른다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 여는 것 | 무엇을 확인하나 |
| --- | --- | --- |
| `target_path` | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일이 실제로 생성/삭제된 시각, 현재 존재 여부 |
| `current_path` 의 `.crdownload` | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) | RENAME_OLD/NEW 쌍으로 완료 시각 확정 |
| `target_path` + `opened = 1` | UserAssist / Prefetch / Amcache | 다운로드한 파일을 **실행**했는가 |
| `hex(hash)` | 디스크 파일의 SHA-256 | 동일 파일 증명, 치환 여부 |
| `chain_index` 마지막 URL | pcap `http.host` / TLS SNI | 실제 트래픽이 있었는가 |
| `tab_url` | `visits` 조인 ([FOR-0191](./chrome-history.html)) | 그 탭에 어떻게 도달했나 (TYPED / LINK) |
| `by_ext_id` | `Extensions\<id>\manifest.json` | 어떤 확장이 다운로드를 유발했나 |
| `etag` / `last_modified` | 서버 응답 헤더 | 같은 파일을 받은 다른 PC 와 대조 |
| `danger_type = 6` | 사용자 행위 판단 | 경고를 무시한 고의성 |

## 흔한 함정

- **`target_path` 만 보고 출처를 결론 내는 것.** `target_path` 는 저장 위치일 뿐 출처가 아니다. 출처는 `tab_url` → `downloads_url_chains` 순으로 본다.
- **`downloads_url_chains` 를 건너뛰는 것.** 이 테이블을 안 보면 리다이렉트로 감춰진 실제 배포 서버를 놓친다. `downloads` 안에는 최종 URL 컬럼이 아예 없다.
- **`referrer` 가 비어 있으면 출처가 없다고 판단하는 것.** Referrer-Policy 로 잘린 것일 뿐이다. `tab_url`, `tab_referrer_url`, `site_url`, `chain_index 0` 을 차례로 본다.
- **`state != 1` 을 전부 "실패"로 묶는 것.** `state = 4` + `received_bytes > 0` 은 부분 파일이 디스크에 남았다는 뜻이고, 그 조각이 문제의 답인 경우가 있다.
- **`interrupt_reason` 을 무시하는 것.** 40(사용자 취소)과 7/11(백신·정책 차단)은 사건 해석이 정반대다. 전자는 사용자 의도, 후자는 시스템 개입이다.
- **`hash` 를 문자열로 읽는 것.** BLOB 32바이트다. `hex(hash)` 없이는 깨진 출력만 본다. `length(hash) = 0` 이면 해시가 애초에 없다.
- **`opened = 0` 을 "실행 안 함"으로 읽는 것.** 탐색기에서 더블클릭한 실행은 이 컬럼에 반영되지 않는다. 실행 여부는 UserAssist/Prefetch 로 판단한다.
- **`History` 만 복사하고 `History-wal` 을 두고 오는 것.** 마지막 다운로드 1건이 통째로 사라진다. 문제의 답이 "마지막에 받은 파일"이면 치명적이다.
- **`Default` 프로필만 확인하는 것.** `Profile 1`, `Profile 2` 에 답이 있는 문제가 흔하다.
- **삭제된 기록을 포기하는 것.** `strings History`, `strings History-wal`, `.recover`, `$J` 의 `.crdownload` 쌍 네 갈래가 남아 있다.
- **시각을 그대로 읽는 것.** 17자리 WebKit 값이다. `/1000000 - 11644473600` 을 빼먹으면 1601년, 나누기를 빼먹으면 먼 미래가 나온다. KST 답이 필요하면 `'+9 hours'` 를 명시한다.
- **`Unconfirmed NNNNNN.crdownload` 를 임시 쓰레기로 넘기는 것.** 그 이름 자체가 "위험 판정 대기 상태였다"는 정보다.

## 교차검증

| 주장 | 뒷받침할 다른 흔적 |
| --- | --- |
| "이 URL 에서 받았다" | pcap 의 해당 호스트 세션, DNS 질의 기록 |
| "다운로드가 완료됐다" | `$MFT` 에 `target_path` 파일 존재 + 크기 일치 |
| "받은 직후 이름이 바뀌었다" | `$J` 의 RENAME_OLD_NAME/NEW_NAME 쌍, 동일 EntryNumber |
| "받고 실행했다" | Prefetch `<NAME>-<HASH>.pf`, UserAssist Run Count, Amcache |
| "이 파일이 그 파일이다" | `hex(hash)` == 디스크 파일 SHA-256 |
| "백신이 막았다" | `interrupt_reason` 7/11 + Defender 이벤트 로그 / 격리 폴더 |
| "사용자가 경고를 무시했다" | `danger_type = 6` + 파일이 실제로 존재 |

브라우저 DB 한 곳에서만 나오는 사실은 반드시 파일시스템 또는 네트워크 흔적으로 한 번 더 확인한다.

## mini walkthrough

```text
문제:
"사용자가 받은 실행 파일의 실제 배포 서버와 SHA-256 을 제출하시오.
 Downloads 폴더에는 해당 파일이 없다."
첨부: History, History-wal, $J (파싱본 usn.csv), Downloads 폴더 덤프

1. 파일 확인
   $ file History
   History: SQLite 3.x database
   $ ls
   History  History-wal  usn.csv  Downloads/
   $ ls Downloads/
   Unconfirmed 481203.crdownload
   -> 완료된 exe 가 없다. crdownload 조각만 있다.

2. 첫 시도 (실패):
   $ sqlite3 History "SELECT target_path, tab_url FROM downloads;"
   Error: database is locked

   그리고 -wal 을 두고 History 만 복사해 열었더니 최근 행이 안 나왔다.

3. 접근 변경 — 사본 + wal 동반
   $ cp History History.cp && cp History-wal History.cp-wal
   $ sqlite3 History.cp "PRAGMA wal_checkpoint(TRUNCATE);"
   $ sqlite3 -header -column History.cp "
     SELECT id, datetime(start_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
            current_path, target_path, received_bytes, total_bytes,
            state, danger_type, interrupt_reason, opened, tab_url
     FROM downloads ORDER BY start_time DESC;"

   id kst                  current_path                           target_path                    got     total   state danger irsn opened tab_url
   12 2026-04-02 21:14:07  ...\Unconfirmed 481203.crdownload      ...\Downloads\update_x64.exe   1048576 4194304 4     1      41   0
   11 2026-04-02 21:09:55  ...\Downloads\notice.html              ...\Downloads\notice.html      8213    8213    1     0      0    1      https://board.example.co.kr/view?id=771

   -> id 12: state=4(중단), irsn=41(USER_SHUTDOWN) = 브라우저가 닫혀 끊겼다.
      danger=1(DANGEROUS_FILE), tab_url 이 비어 있다. 출처를 모른다.

4. 두 번째 시도 (불충분):
   referrer 와 site_url 을 봤지만 둘 다 빈 문자열이었다.
   Referrer-Policy 로 잘린 것이라 여기서는 답이 안 나온다.

5. 접근 변경 — downloads_url_chains
   $ sqlite3 -header -column History.cp "
     SELECT c.id, c.chain_index, c.url FROM downloads_url_chains c
     WHERE c.id = 12 ORDER BY c.chain_index;"

   id  chain_index  url
   12  0            https://board.example.co.kr/dl?f=update
   12  1            https://short.example.io/9Kd2
   12  2            https://cdn-e7.storage.example.net/pkg/update_x64.exe
                      ^^^ 실제 바이트를 내려준 서버

   chain_index 0 만 봤다면 게시판이 배포처라고 오답을 냈을 것이다.

6. 해시 — 첫 시도가 또 틀렸다
   $ sqlite3 History.cp "SELECT hash FROM downloads WHERE id=12;"
   (깨진 바이너리 출력)
   $ sqlite3 History.cp "SELECT length(hash), hex(hash) FROM downloads WHERE id=12;"
   0|
   -> 중단된 다운로드라 해시가 비어 있다. DB 에서는 답을 얻을 수 없다.

7. 접근 변경 — 조각 파일에서 직접 계산 + 구멍 확인
   $ sqlite3 -header -column History.cp "
     SELECT download_id, offset, received_bytes, finished
     FROM downloads_slices WHERE download_id=12 ORDER BY offset;"

   download_id  offset   received_bytes  finished
   12           0        1048576         0

   -> 4MB 중 앞 1MB 만 받았다. 조각 파일의 해시는 원본과 다르다.
      제출할 해시는 "부분 파일의 해시"임을 명시해야 한다.

   $ sha256sum "Downloads/Unconfirmed 481203.crdownload"

8. 완료 시각·이름 확정 — $J 쌍 확인
   $ grep -i crdownload usn.csv | head
   2026-04-02 21:09:55  notice.html.crdownload  RenameOldName  EntryNumber 91422
   2026-04-02 21:09:55  notice.html             RenameNewName  EntryNumber 91422
   -> id 11 은 rename 쌍이 있다 = 완료. id 12 는 쌍이 없다 = 미완료 확정.

정답: 실제 배포 서버 cdn-e7.storage.example.net (chain_index 2),
      update_x64.exe 는 4,194,304 바이트 중 1,048,576 바이트만 수신 후
      브라우저 종료(interrupt_reason 41)로 중단, DB 해시 없음 →
      Unconfirmed 481203.crdownload 의 SHA-256 을 부분 파일 해시로 제출
```

3단계(`-wal` 동반)와 5단계(`downloads_url_chains`)가 승부처였다. **`downloads` 테이블 한 개만 보면 이 문제는 풀리지 않는다.**

## 막혔을 때 다음 체크

1. `.schema downloads` 를 먼저 찍었는가. 컬럼이 없다는 오류는 대부분 버전 차이다
2. `History-wal` 을 같이 복사했는가. `PRAGMA wal_checkpoint(TRUNCATE)` 를 돌렸는가
3. `Profile 1`, `Profile 2`, 그리고 Edge/Whale/Brave 경로까지 훑었는가
4. `downloads` 가 비었으면 `downloads_url_chains` 만 남아 있지 않은가 (부모 행이 삭제된 경우)
5. `strings History`, `strings History-wal` 로 URL·경로 잔존 문자열을 긁었는가
6. `PRAGMA freelist_count` 가 0 이 아니면 `.recover` 를 시도했는가
7. DB 가 아예 없으면 `$J` 에서 `.crdownload` RENAME 쌍을 찾았는가
8. 캐시 폴더(`Cache\Cache_Data`)에 같은 URL 항목이 남아 있지 않은가
9. 시각을 `/1000000 - 11644473600` 로 변환했는가, KST 로 명시했는가
10. `state`/`interrupt_reason` 숫자를 표로 대조했는가. 그냥 "실패"로 적지 않았는가

## 출처

- SRC-008 — Chromium source, `components/history/core/browser`: `downloads` / `downloads_url_chains` / `downloads_slices` 스키마와 DB 에 저장되는 `state`·`danger_type` 정수값 정의
- SRC-110 — Chromium `components/download`: `.crdownload` / `Unconfirmed NNNNNN.crdownload` 중간 파일명 동작과 `DownloadInterruptReason` 값 계열
- SRC-011 — SQLite 문서: `datetime(..., 'unixepoch')` 변환, `hex()`, `PRAGMA freelist_count`, `.recover`
- 컬럼 구성은 Chrome/Edge 버전에 따라 추가·개명된다(`site_url` ↔ `embedder_download_data` 등). **쿼리를 쓰기 전에 반드시 `.schema downloads` 로 실제 컬럼을 확인할 것.**
- `danger_type` 9 이상, `interrupt_reason` 의 전체 목록은 버전마다 늘어나므로 이 글의 표에 없는 값은 Chromium 소스에서 직접 확인할 것
