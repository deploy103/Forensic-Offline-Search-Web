---
id: FOR-0191
title: "Chrome History DB 구조: urls / visits / downloads 읽기"
slug: "chrome-history"
category: "브라우저/웹"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux, macos]
artifact: ["Chrome History", "urls", "visits", "downloads", "keyword_search_terms", "WebKit timestamp"]
file_paths: ["C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\History", "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\History", "~/.config/google-chrome/Default/History"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "HTTPS"]
tools: ["sqlite3", "DB Browser for SQLite", "DCode", "ChromeCacheView", "FTK Imager"]
commands: ["sqlite3 History \".tables\"", "sqlite3 History \"SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 20;\"", "sqlite3 History \"SELECT target_path, tab_url FROM downloads;\""]
regex_patterns: ["https?://[^\\s\"'<>]+"]
wireshark_filters: ["http.host", "tls.handshake.extensions_server_name"]
tshark_fields: ["http.host", "dns.qry.name"]
log_fields: ["url", "title", "visit_count", "typed_count", "last_visit_time", "visit_time", "from_visit", "transition", "target_path", "tab_url", "received_bytes"]
file_formats: ["sqlite"]
keywords: ["Chrome History", "urls 테이블", "visits 테이블", "downloads 테이블", "WebKit timestamp", "11644473600", "방문 기록", "다운로드 기록", "검색어", "transition"]
aliases: ["크롬 히스토리", "chrome history", "방문 기록", "브라우저 기록", "다운로드 기록", "어디서 받았나", "크롬 sqlite", "webkit 시간 변환"]
symptom_keywords: ["방문한 사이트를 알고 싶다", "파일을 어디서 받았는지", "검색어를 알고 싶다", "시간이 13자리 숫자다", "1601년으로 나온다", "History 파일이 잠겨있다", "sqlite로 열리지 않는다"]
related: ["FOR-0146", "FOR-0021"]
source_ids: ["SRC-008", "SRC-011", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Chrome의 `History`는 확장자 없는 SQLite DB이며, **`urls`**(방문한 주소), **`visits`**(방문 1건씩의 시각과 유입 경로), **`downloads`**(내려받은 파일과 출처 URL) 세 테이블에 답이 들어 있고 모든 시각은 **1601년 기준 마이크로초(WebKit)** 이다.

## 개념

Chrome은 프로필별로 여러 개의 SQLite DB를 둔다. 포렌식에서 쓰는 것은 다음이다.

| 파일명 | 내용 | 확장자 |
| --- | --- | --- |
| `History` | 방문 기록, 다운로드, 검색어 | 없음 (SQLite) |
| `Cookies` | 쿠키 (값은 DPAPI 암호화) | 없음 |
| `Login Data` | 저장된 계정 (비밀번호는 DPAPI 암호화) | 없음 |
| `Web Data` | 자동완성, 신용카드 | 없음 |
| `Bookmarks` | 북마크 | 없음 (**JSON**) |
| `Preferences` | 설정 | 없음 (JSON) |
| `Top Sites` | 자주 방문 | 없음 (SQLite) |
| `Favicons` | 파비콘 | 없음 (SQLite) |

확장자가 없으므로 `file`로 확인한다 ([FOR-0001](./30sec-triage.html)).

```bash
$ file History
History: SQLite 3.x database, last written using SQLite version 3045000
```

Edge, Brave, Opera, Whale은 모두 Chromium 기반이라 **스키마가 거의 동일하다.** 이 글의 쿼리가 그대로 통한다.

## 파일 / 경로

| 브라우저 / OS | 경로 |
| --- | --- |
| Chrome (Windows) | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History` |
| Edge (Windows) | `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History` |
| Whale (Windows) | `C:\Users\<user>\AppData\Local\Naver\Naver Whale\User Data\Default\History` |
| Chrome (Linux) | `~/.config/google-chrome/Default/History` |
| Chrome (macOS) | `~/Library/Application Support/Google/Chrome/Default/History` |

**프로필 폴더가 `Default`만이 아니다.** 계정을 여러 개 쓰면 `Profile 1`, `Profile 2`가 생긴다. 반드시 전부 확인한다.

```powershell
Get-ChildItem "C:\Users\*\AppData\Local\*\*\User Data\*\History" -Force |
  Select-Object FullName, Length, LastWriteTime
```

### 함께 반드시 꺼낼 파일

| 파일 | 왜 필요한가 |
| --- | --- |
| `History-journal` | 롤백 저널. 커밋되지 않은 변경이 들어 있다 |
| `History-wal` | **WAL 모드의 최신 데이터.** 이것 없이 열면 최근 방문이 누락된다 |
| `History-shm` | 공유 메모리 인덱스 |

`History`만 복사하고 `-wal`을 두고 오면 **가장 최근 방문 기록이 사라진다.** 문제의 답이 "마지막 방문"이면 치명적이다. FTK Imager로 추출할 때 같은 폴더에서 `History*` 전부 선택한다.

## 주요 필드

### `urls` — 방문한 주소 (URL 1개당 1행)

| 컬럼 | 타입 | 의미 |
| --- | --- | --- |
| `id` | INTEGER | URL 고유 ID. `visits.url`이 이 값을 참조 |
| `url` | TEXT | 전체 URL |
| `title` | TEXT | 페이지 제목 |
| `visit_count` | INTEGER | **총 방문 횟수** |
| `typed_count` | INTEGER | **주소창에 직접 입력한 횟수** |
| `last_visit_time` | INTEGER | 마지막 방문 (WebKit 마이크로초) |
| `hidden` | INTEGER | 1이면 자동완성 후보에서 숨김 |

`typed_count > 0`은 **사용자가 URL을 직접 타이핑했다**는 뜻이다. 링크를 눌러 들어간 것과 의도적으로 접속한 것을 구분하는 핵심 지표다.

### `visits` — 방문 1건씩 (같은 URL을 3번 방문하면 3행)

| 컬럼 | 타입 | 의미 |
| --- | --- | --- |
| `id` | INTEGER | 방문 고유 ID |
| `url` | INTEGER | `urls.id` 참조 |
| `visit_time` | INTEGER | **이 방문의 시각** (WebKit) |
| `from_visit` | INTEGER | **직전 방문의 `visits.id`.** 유입 경로 추적의 핵심 |
| `transition` | INTEGER | 어떻게 이동했는지 (아래 표) |
| `visit_duration` | INTEGER | 머문 시간 (마이크로초) |
| `segment_id` | INTEGER | 사이트 묶음 ID |
| `opener_visit` | INTEGER | 새 탭을 연 방문의 id |

`urls`는 "무엇을 봤나", `visits`는 "언제·어떻게 봤나"다. **타임라인을 만들 때는 반드시 `visits`를 쓴다.**

### `transition` 값 해석

`transition`은 하위 8비트가 이동 유형, 상위 비트가 부가 정보인 비트필드다.

```sql
transition & 0xFF     -- 핵심 유형
transition & 0xFF000000  -- 한정자(qualifier)
```

| `& 0xFF` | 이름 | 의미 |
| --- | --- | --- |
| 0 | LINK | 링크 클릭 |
| 1 | TYPED | **주소창에 직접 입력** |
| 2 | AUTO_BOOKMARK | 북마크에서 이동 |
| 3 | AUTO_SUBFRAME | iframe 자동 로드 |
| 4 | MANUAL_SUBFRAME | iframe 안에서 클릭 |
| 5 | GENERATED | 주소창 자동완성/검색 제안 |
| 6 | AUTO_TOPLEVEL | 시작 페이지/홈 |
| 7 | FORM_SUBMIT | **폼 제출 (로그인·검색 등)** |
| 8 | RELOAD | 새로고침 |
| 9 | KEYWORD | 주소창 키워드 검색 |
| 10 | KEYWORD_GENERATED | 키워드로 생성된 URL |

| 한정자 마스크 | 의미 |
| --- | --- |
| `0x01000000` | 앞으로/뒤로 버튼 |
| `0x02000000` | 주소창에서 시작 |
| `0x08000000` | 확장/API가 유발 |
| `0x10000000` | 리다이렉트 체인 시작 |
| `0x20000000` | 리다이렉트 체인 끝 |
| `0x40000000` | **클라이언트 리다이렉트** (JS/meta) |
| `0x80000000` | **서버 리다이렉트** (3xx) |

`AUTO_SUBFRAME`(3)은 사용자 의도가 아니라 광고/추적 iframe이다. **의도적 방문만 보려면 3과 4를 걸러낸다.**

### `downloads` — 내려받은 파일

| 컬럼 | 의미 |
| --- | --- |
| `id` / `guid` | 다운로드 ID |
| `current_path` | 실제 저장 경로 (`.crdownload` 중간 상태 포함) |
| `target_path` | **최종 저장 경로** |
| `start_time` / `end_time` | 시작/종료 (WebKit) |
| `received_bytes` / `total_bytes` | 받은 크기 / 전체 크기 |
| `state` | 0 진행중, 1 **완료**, 2 취소, 4 중단 |
| `danger_type` | Safe Browsing 위험 판정 |
| `interrupt_reason` | 중단 원인 코드 |
| `hash` | 파일 SHA-256 (BLOB) |
| `referrer` | **참조 페이지 URL** |
| `tab_url` | **다운로드를 시작한 탭의 URL** |
| `tab_referrer_url` | 그 탭의 참조 URL |
| `site_url` | 사이트 단위 URL |
| `mime_type` / `original_mime_type` | 선언된 MIME |
| `opened` | 1이면 **사용자가 파일을 열었다** |
| `last_access_time` | 마지막 접근 (WebKit) |
| `etag` / `last_modified` | 서버가 준 HTTP 헤더 값 |

`downloads_url_chains` 테이블에는 **리다이렉트 체인 전체**가 `chain_index` 순서로 들어 있다. 최종 URL만 보면 진짜 출처를 놓친다.

### `keyword_search_terms` — 검색어

| 컬럼 | 의미 |
| --- | --- |
| `keyword_id` | 검색 엔진 ID |
| `url_id` | `urls.id` 참조 |
| `term` | **사용자가 입력한 검색어 (원문)** |
| `lower_term` | 소문자 정규화 |

주소창에서 검색한 내용이 그대로 남는다. "무엇을 찾으려 했는가"의 직접 증거다.

### WebKit timestamp 변환

Chrome의 시각은 **1601-01-01 00:00:00 UTC 기준 마이크로초**다. Unix epoch와의 차이는 **11,644,473,600초**다.

```text
unix_seconds = webkit_microseconds / 1000000 - 11644473600
webkit       = (unix_seconds + 11644473600) * 1000000
```

| 언어 | 변환 |
| --- | --- |
| SQLite | `datetime(t/1000000 - 11644473600, 'unixepoch')` |
| SQLite (로컬) | `datetime(t/1000000 - 11644473600, 'unixepoch', 'localtime')` |
| SQLite (KST 고정) | `datetime(t/1000000 - 11644473600, 'unixepoch', '+9 hours')` |
| Python | `datetime(1601,1,1) + timedelta(microseconds=t)` |
| PowerShell | `[datetime]::FromFileTimeUtc($t * 10)` |
| GUI | DCode에서 `Google Chrome Value` 선택 |

PowerShell의 `FromFileTimeUtc`는 100ns 단위를 받으므로 마이크로초에 **10을 곱한다.**

## 빠른 명령

```bash
# 스키마 확인 — Chrome 버전마다 컬럼이 다르므로 먼저 본다
sqlite3 History ".tables"
sqlite3 History ".schema urls"
sqlite3 History ".schema downloads"

# 1) 최근 방문 20개
sqlite3 -header -column History "
SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
       visit_count AS cnt, typed_count AS typed, url, title
FROM urls ORDER BY last_visit_time DESC LIMIT 20;"

# 2) 방문 타임라인 (visits 기준, 광고 iframe 제외)
sqlite3 -header -column History "
SELECT datetime(v.visit_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
       (v.transition & 255) AS tr, u.url, u.title
FROM visits v JOIN urls u ON u.id = v.url
WHERE (v.transition & 255) NOT IN (3,4)
ORDER BY v.visit_time;"

# 3) 주소창에 직접 입력한 URL만 = 의도적 접속
sqlite3 -header -column History "
SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
       typed_count, url
FROM urls WHERE typed_count > 0 ORDER BY last_visit_time DESC;"

# 4) 다운로드 + 출처 (핵심 쿼리)
sqlite3 -header -column History "
SELECT datetime(d.start_time/1000000-11644473600,'unixepoch','+9 hours') AS started,
       d.target_path, d.received_bytes, d.state, d.opened,
       d.tab_url, d.referrer
FROM downloads d ORDER BY d.start_time DESC;"

# 5) 다운로드 리다이렉트 체인 전체
sqlite3 -header -column History "
SELECT d.target_path, c.chain_index, c.url
FROM downloads d JOIN downloads_url_chains c ON c.id = d.id
ORDER BY d.id, c.chain_index;"

# 6) 검색어
sqlite3 -header -column History "
SELECT datetime(u.last_visit_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
       k.term, u.url
FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id
ORDER BY u.last_visit_time DESC;"

# 7) 유입 경로 추적 — from_visit 자기조인
sqlite3 -header -column History "
SELECT datetime(v.visit_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
       pu.url AS came_from, u.url AS went_to, (v.transition & 255) AS tr
FROM visits v
JOIN urls u  ON u.id = v.url
LEFT JOIN visits pv ON pv.id = v.from_visit
LEFT JOIN urls   pu ON pu.id = pv.url
ORDER BY v.visit_time;"

# 8) 특정 키워드가 들어간 URL 전부
sqlite3 History "SELECT url FROM urls WHERE url LIKE '%upload%' OR url LIKE '%.exe';"
```

WAL이 있는 상태에서 열면 SQLite가 자동으로 병합한다. 파일이 잠겨 있다는 오류가 나면 사본으로 작업한다.

```bash
cp History History.copy && cp History-wal History.copy-wal 2>/dev/null
sqlite3 History.copy "PRAGMA wal_checkpoint(TRUNCATE);"
```

Windows GUI만 쓸 수 있으면 **DB Browser for SQLite**로 열고 `Execute SQL` 탭에 위 쿼리를 붙인다.

## 함께 보는 artifact

| Chrome History에서 얻은 것 | 다음 목표 |
| --- | --- |
| `downloads.target_path` | `$MFT` ([FOR-0021](./mft-basics.html)) — 디스크 생성/삭제 시각 |
| `downloads.target_path` | Prefetch / Amcache — 그 파일을 **실행**했는가 |
| `downloads.tab_url` | pcap의 `http.host` ([FOR-0146](./wireshark-30sec-triage.html)) — 실제 트래픽 |
| 방문 도메인 | DNS 질의 기록, `hosts` 파일 |
| 방문 시각 | EVTX 4624 ([FOR-0083](./event-4624-logon.html)) — 그 시각 로그온 세션 |
| 검색어 | `WordWheelQuery`(탐색기 검색), Windows Search DB |
| `opened = 1` | RecentDocs, LNK, Jump List |
| Cache 항목 | `Cache\` 폴더 → ChromeCacheView |
| 로그인 흔적 | `Login Data`, `Cookies` (DPAPI 복호화 필요) |

## 흔한 실수

- **`History-wal`을 빼고 복사하는 것.** 최신 방문·다운로드가 통째로 누락된다. `History*` 전부 가져온다.
- **`Default` 프로필만 보는 것.** `Profile 1`, `Profile 2`에 답이 있을 수 있다.
- **`urls.last_visit_time`으로 타임라인을 만드는 것.** 그것은 **마지막** 방문 1건이다. 전체 방문은 `visits.visit_time`에 있다.
- **11644473600을 잊는 것.** 안 빼면 1601년대 날짜가 나오고, `1000000`으로 안 나누면 미래 날짜가 나온다.
- **UTC/KST 혼동.** `'unixepoch'`만 쓰면 UTC다. KST 답이 필요하면 `'+9 hours'`. `'localtime'`은 **분석 PC의** 시간대를 쓰므로 증거물의 시간대와 다를 수 있다 — 대회에서는 `'+9 hours'`처럼 명시하는 편이 안전하다.
- **`transition`의 하위 8비트를 마스킹하지 않는 것.** `transition = 1`로 비교하면 상위 한정자 비트가 붙은 TYPED 방문을 놓친다. 반드시 `& 255`.
- **`AUTO_SUBFRAME`을 사용자 방문으로 세는 것.** 광고/추적 iframe이 대량으로 섞인다.
- **`downloads.target_path`만 보고 출처를 결론 내는 것.** 진짜 출처는 `tab_url`과 `downloads_url_chains`에 있다.
- **`state`를 확인하지 않는 것.** `state = 1`(완료)이 아니면 파일이 온전히 저장되지 않았다.
- **`hash` 컬럼이 BLOB인 것을 놓치는 것.** `SELECT hex(hash) FROM downloads;`로 봐야 SHA-256 문자열이 나온다.
- **삭제된 기록을 포기하는 것.** SQLite는 삭제 행을 즉시 지우지 않는다. `strings History | grep -Eo 'https?://[^ ]+'` 또는 freelist 카빙으로 복구되는 경우가 많다.
- **Bookmarks를 SQLite로 열려는 것.** `Bookmarks`는 **JSON**이다. `jq`로 읽는다.

## mini example

```text
문제:
"직원 PC의 Chrome 기록에서 악성 파일을 어디서 받았고 실행했는지 확인하세요."
첨부: History, History-wal

1. 파일 확인
   $ file History
   History: SQLite 3.x database
   $ ls
   History  History-wal        <- wal이 있다. 함께 써야 한다.

2. 스키마 먼저 (Chrome 버전에 따라 컬럼이 다르다)
   $ sqlite3 History ".schema downloads" | head -5

3. 다운로드 목록
   $ sqlite3 -header -column History "
     SELECT datetime(start_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
            target_path, received_bytes, state, opened, tab_url
     FROM downloads ORDER BY start_time DESC;"

   kst                  target_path                                  bytes   state opened tab_url
   2026-03-14 16:33:12  C:\Users\jhkim\Downloads\invoice_0314.zip     284113  1     1      https://mail.example.co.kr/mail/read?id=88213
   2026-03-14 16:35:40  C:\Users\jhkim\Downloads\invoice_0314.exe     198656  1     1      (null)

   -> zip을 받아 열고(opened=1), 그 안의 exe가 Downloads에 나왔다.
      메일에서 시작된 흐름이다.

4. 첫 시도 (불충분했던 접근):
   tab_url만 보고 "메일에서 받았다"로 끝내려 했다.
   그런데 exe의 tab_url이 null이었다. 실제 다운로드 서버를 모른다.

5. 접근 변경 — 리다이렉트 체인 확인
   $ sqlite3 -header -column History "
     SELECT d.target_path, c.chain_index, c.url
     FROM downloads d JOIN downloads_url_chains c ON c.id = d.id
     ORDER BY d.id, c.chain_index;"

   target_path                chain_index  url
   ...invoice_0314.zip        0            https://cdn.example-mail.co.kr/att/88213/invoice_0314.zip
   ...invoice_0314.zip        1            https://d1x9k.blob.core.windows.example/tmp/i.zip
                                            ^^^ 리다이렉트된 실제 다운로드 위치

   최종 URL만 봤다면 정상 CDN으로 오해했을 것이다.

6. 방문 흐름 — 어떻게 그 메일에 도달했나
   $ sqlite3 -header -column History "
     SELECT datetime(v.visit_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
            (v.transition & 255) AS tr, u.url
     FROM visits v JOIN urls u ON u.id=v.url
     WHERE (v.transition & 255) NOT IN (3,4)
     ORDER BY v.visit_time DESC LIMIT 5;"

   kst                  tr  url
   2026-03-14 16:32:05  0   https://mail.example.co.kr/mail/read?id=88213   (LINK)
   2026-03-14 16:31:58  1   https://mail.example.co.kr/                     (TYPED)

   tr=1(TYPED) = 사용자가 직접 메일 사이트에 접속 -> 링크 클릭 -> 첨부 다운로드

7. pivot — 실제로 실행했는가
   UserAssist 확인 (FOR-0061)
   -> C:\Users\jhkim\Downloads\invoice_0314.exe  Run Count 1
      Last Executed 2026-03-14 16:36:21 (KST)

   $MFT 확인 -> 같은 시각에 %TEMP%에 추가 파일 3개 생성

정답: 메일(mail.example.co.kr) 첨부 → cdn 리다이렉트 →
      d1x9k.blob.core.windows.example/tmp/i.zip 에서 실제 수신,
      invoice_0314.exe 를 2026-03-14 16:36:21 KST에 1회 실행
```

5단계가 핵심이었다. **`downloads_url_chains`를 보지 않으면 진짜 다운로드 출처를 놓친다.**

## 출처

- SRC-008 — Chromium source, `components/history/core/browser`: `urls`/`visits`/`downloads` 스키마와 `PageTransition` 상수 정의
- SRC-011 — SQLite 날짜/시간 함수: `datetime(..., 'unixepoch')` 사용법
- SRC-014 — Microsoft Learn, File Times: 1601-01-01 기준 시각과 11644473600초 차이의 근거
