---
id: FOR-0200
title: "SQLite 기본 조회 명령: sqlite3 CLI로 SELECT 던지기"
slug: "sqlite-basics"
category: "브라우저/웹"
type: "reference"
difficulty: "basic"
priority: "high"
platform: [windows, linux, macos]
artifact: ["SQLite CLI", "SELECT", "WHERE", "ORDER BY", "LIMIT"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["sqlite3", "DB Browser for SQLite"]
commands: ["sqlite3 app.db", "sqlite3 -header -column app.db \"SELECT * FROM tablename LIMIT 10;\"", "sqlite3 app.db \".tables\"", "sqlite3 app.db \".mode csv\"", "sqlite3 app.db \".output out.csv\""]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["SELECT", "WHERE", "ORDER BY", "LIMIT", "GROUP BY", "JOIN", "COUNT", "LIKE"]
file_formats: ["sqlite"]
primary_terms: ["sqlite3 기본 조회", "SELECT FROM 기본"]
keywords: ["sqlite3", "SELECT", "WHERE", "ORDER BY", "LIMIT", "GROUP BY", "JOIN", "sqlite3 CLI", "DB Browser for SQLite", "COUNT", "LIKE 검색", "sqlite 기본 명령"]
aliases: ["sqlite3 사용법", "sqlite 쿼리 기본", "sqlite 여는법", "select 문 작성", "db 파일 조회", "sqlite cli 명령어"]
symptom_keywords: ["sqlite3 명령을 처음 써본다", "쿼리 문법을 모르겠다", "결과가 한 줄로 붙어 나온다", "csv로 저장하고 싶다", "테이블 이름을 모르겠다"]
related: ["FOR-0201", "FOR-0202", "FOR-0191"]
source_ids: ["SRC-011"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`sqlite3 파일명`으로 DB를 열고 `.tables`로 목록을 본 뒤, `SELECT 컬럼 FROM 테이블 WHERE 조건 ORDER BY 컬럼 LIMIT N;`이라는 한 줄 문형만 알면 대회장에서 필요한 조회의 90%가 끝난다.

## 개념

`sqlite3`는 SQLite DB 파일을 명령행에서 직접 여는 CLI다. 서버가 없고 파일 하나가 DB 전체이므로 **오프라인 환경에 최적**이다. 명령은 두 종류로 나뉜다.

| 종류 | 시작 문자 | 예 | 세미콜론 필요 |
| --- | --- | --- | --- |
| **도트 명령** (CLI 전용) | `.` | `.tables`, `.schema`, `.mode`, `.quit` | 불필요 |
| **SQL 문** | 없음 | `SELECT`, `INSERT`, `PRAGMA` | **필요** |

도트 명령은 sqlite3 CLI에서만 통한다. DB Browser for SQLite 같은 GUI의 `Execute SQL` 탭에서는 SQL 문만 쓸 수 있다.

## 파일 / 경로

이 글은 특정 artifact가 아니라 **명령 사용법**을 다룬다. 실제 대상 파일 예시는 다음과 같다.

| 파일명 | 확장자 | 어디서 나오나 |
| --- | --- | --- |
| `History`, `Cookies`, `Web Data`, `Login Data` | 없음 | Chrome/Edge 계열 ([FOR-0191](./chrome-history.html)) |
| `places.sqlite` | `.sqlite` | Firefox |
| `*.db`, `*.sqlite3` | 임의 | 모바일 앱, CTF 커스텀 DB |

파일이 SQLite인지 먼저 `file` 명령으로 확인한다. 헤더 16바이트는 `SQLite format 3\0`이다.

```bash
file History
xxd -l 16 History
```

## 주요 필드

SQL 문형에서 자주 쓰는 키워드다.

| 절 | 역할 | 예 |
| --- | --- | --- |
| `SELECT` | 뽑을 컬럼 | `SELECT url, title` |
| `FROM` | 대상 테이블 | `FROM urls` |
| `WHERE` | 행 필터 | `WHERE typed_count > 0` |
| `ORDER BY` | 정렬 | `ORDER BY last_visit_time DESC` |
| `LIMIT` | 결과 개수 제한 | `LIMIT 20` |
| `GROUP BY` | 집계 묶음 | `GROUP BY url` |
| `JOIN ... ON` | 테이블 결합 | `JOIN urls u ON u.id = v.url` |
| `LIKE '%pattern%'` | 부분 문자열 검색 | `WHERE url LIKE '%flag%'` |
| `COUNT(*)`, `MIN()`, `MAX()` | 집계 함수 | `SELECT COUNT(*) FROM urls` |
| `DISTINCT` | 중복 제거 | `SELECT DISTINCT url` |

문장 순서는 항상 `SELECT ... FROM ... WHERE ... GROUP BY ... ORDER BY ... LIMIT ...`이며, 이 순서를 바꾸면 문법 오류가 난다.

## 빠른 명령

```bash
sqlite3 app.db
```

실전에서 가장 자주 쓰는 한 줄들이다.

```bash
# 1) DB 열기 (파일이 없으면 새로 만들어버리므로 오탈자 주의)
sqlite3 app.db

# 2) 테이블 목록
sqlite3 app.db ".tables"

# 3) 헤더와 컬럼 정렬을 켜고 조회 (가장 많이 쓰는 형태)
sqlite3 -header -column app.db "SELECT * FROM urls LIMIT 5;"

# 4) 조건 + 정렬 + 개수 제한
sqlite3 -header -column app.db \
  "SELECT url, visit_count FROM urls WHERE typed_count > 0 ORDER BY visit_count DESC LIMIT 10;"

# 5) 집계
sqlite3 app.db "SELECT COUNT(*) FROM urls;"
sqlite3 -header -column app.db "SELECT url, COUNT(*) n FROM visits GROUP BY url ORDER BY n DESC LIMIT 5;"

# 6) 부분 문자열 검색 (대소문자 무시는 LIKE가 기본, 별도 옵션 불필요)
sqlite3 app.db "SELECT url FROM urls WHERE url LIKE '%flag%';"

# 7) 두 테이블 조인
sqlite3 -header -column app.db \
  "SELECT u.url, v.visit_time FROM visits v JOIN urls u ON u.id = v.url LIMIT 5;"

# 8) CLI 안에서 대화형으로 여러 도트 명령 실행
sqlite3 app.db
sqlite> .headers on
sqlite> .mode column
sqlite> SELECT * FROM urls LIMIT 3;
sqlite> .quit

# 9) 결과를 CSV 파일로 저장
sqlite3 app.db <<'EOF'
.headers on
.mode csv
.output out.csv
SELECT * FROM urls;
.output stdout
EOF

# 10) 한 줄 명령으로 파일 대신 즉시 출력 형식 지정
sqlite3 -csv app.db "SELECT * FROM urls;" > out.csv
sqlite3 -json app.db "SELECT * FROM urls LIMIT 3;"
```

| 도트 명령 | 역할 |
| --- | --- |
| `.tables` | 테이블 목록 |
| `.schema [table]` | DDL(CREATE 문) 출력 |
| `.headers on` | 컬럼명 헤더 표시 |
| `.mode column\|csv\|json\|line` | 출력 형식 |
| `.output file.csv` | 결과를 파일로 리다이렉트 (`stdout`으로 복귀) |
| `.width N N N` | column 모드에서 열 너비 고정 |
| `.quit` | 종료 |

`-header -column`처럼 CLI 실행 시 옵션으로 바로 줄 수도 있고, 대화형 세션 안에서 `.headers on` / `.mode column`으로 켤 수도 있다. **둘 중 하나를 켜지 않으면 결과가 파이프로 이어진 값만 한 줄씩 나와 어느 컬럼인지 알 수 없다.**

## 함께 보는 artifact

| 상황 | 다음에 볼 글 |
| --- | --- |
| 테이블/컬럼 이름을 모른다 | 스키마 확인 ([FOR-0201](./sqlite-schema.html)) |
| 시각 컬럼이 숫자로만 나온다 | 시각 변환 절차 ([FOR-0202](./sqlite-timestamp-conversion.html)) |
| 대상이 Chrome History다 | 전용 쿼리 세트 ([FOR-0191](./chrome-history.html)) |
| GUI만 쓸 수 있다 | DB Browser for SQLite의 `Execute SQL` 탭에 같은 SQL을 붙인다 |
| DB가 잠겨 있거나 열리지 않는다 | 사본으로 작업, `PRAGMA integrity_check;` |

## 흔한 실수

- **세미콜론을 빼먹는 것.** SQL 문은 `;`으로 끝나야 실행된다. 도트 명령은 필요 없어 혼동하기 쉽다.
- **존재하지 않는 DB 파일명을 입력하는 것.** `sqlite3 app.db`는 파일이 없으면 **자동으로 새 빈 DB를 만든다.** 증거 파일명을 오탈자로 치면 엉뚱한 빈 DB를 조회하며 결과가 없다고 착각한다.
- **`-header`/`.headers on` 없이 결과를 읽는 것.** 어느 값이 어느 컬럼인지 알 수 없어 오독하기 쉽다.
- **컬럼 이름을 확인하지 않고 `SELECT *`만 반복하는 것.** 컬럼이 많은 테이블은 줄바꿈되어 읽기 어렵다. 필요한 컬럼만 명시한다.
- **원본 파일을 직접 열어 쓰기 잠금을 유발하는 것.** `sqlite3`로 원본을 열면 WAL 체크포인트 등으로 파일이 변경될 수 있다. 항상 사본에서 작업한다.
- **`LIKE` 패턴에서 `%`를 빼먹는 것.** `WHERE url LIKE 'flag'`는 정확히 `flag`인 행만 찾는다. 부분 일치는 `'%flag%'`.
- **문자열 비교에서 큰따옴표를 쓰는 것.** SQLite는 문자열 리터럴에 **작은따옴표**를 쓴다. 큰따옴표는 식별자(컬럼/테이블명) 취급이다. `WHERE url = "flag"`는 `flag`라는 이름의 컬럼을 찾으려다 오류가 난다.
- **`.output` 후 원상복구를 잊는 것.** `.output out.csv` 이후 계속 CSV로만 저장되어 화면에 아무것도 안 보인다. `.output stdout`으로 되돌린다.

## mini example

```text
문제:
"messages.db 에서 'flag' 라는 단어가 들어간 메시지를 찾아
가장 최근 3건을 출력하세요."

1. file messages.db
   messages.db: SQLite 3.x database

2. 테이블 확인
   $ sqlite3 messages.db ".tables"
   messages  threads

3. 컬럼을 몰라 우선 5행만 눈으로 확인
   $ sqlite3 -header -column messages.db "SELECT * FROM messages LIMIT 5;"
   _id  thread_id  body        date
   1    1          hi          1773500000000
   2    1          ok          1773500100000
   ...

4. 조건 조회
   $ sqlite3 -header -column messages.db \
     "SELECT _id, date, body FROM messages WHERE body LIKE '%flag%' ORDER BY date DESC LIMIT 3;"

   _id  date            body
   482  1773540902113   flag{sqlite_is_easy}
   401  1773480011000   found the flag file
   399  1773470005000   looking for flag

정답 후보: flag{sqlite_is_easy}
```

`SELECT *`로 먼저 컬럼을 확인한 뒤 필요한 컬럼만 골라 조건을 붙이는 순서가 실전에서 가장 빠르다.

## 출처

- SRC-011 — SQLite 공식 문서 Date And Time Functions 페이지 및 CLI 관련 문서: `sqlite3` 커맨드라인 셸의 도트 명령(`.tables`, `.schema`, `.mode`, `.headers`, `.output`)과 표준 SQL 문형
- 도트 명령의 정확한 옵션 목록은 `sqlite3` 버전에 따라 달라질 수 있으므로 `.help`로 실제 버전에서 확인할 것
