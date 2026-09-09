---
id: FOR-0201
title: "SQLite 스키마 확인: sqlite_master 와 PRAGMA 로 테이블 구조 읽기"
slug: "sqlite-schema"
category: "브라우저/웹"
type: "guide"
difficulty: "basic"
priority: "high"
platform: [windows, linux]
artifact: ["sqlite_master", "PRAGMA table_info", "PRAGMA foreign_key_list", "PRAGMA index_list", "SQLite schema"]
file_paths: ["%LocalAppData%\\Google\\Chrome\\User Data\\Default\\History", "%AppData%\\Mozilla\\Firefox\\Profiles"]
registry_paths: []
event_ids: []
protocols: []
tools: ["sqlite3", "DB Browser for SQLite", "file", "strings"]
commands: ["sqlite3 app.db \".tables\"", "sqlite3 app.db \".schema urls\"", "sqlite3 app.db \"SELECT type,name,tbl_name FROM sqlite_master;\"", "sqlite3 app.db \"PRAGMA table_info(urls);\"", "sqlite3 app.db \"PRAGMA foreign_key_list(visits);\"", "sqlite3 app.db \"PRAGMA index_list(urls);\""]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["type", "name", "tbl_name", "rootpage", "sql", "cid", "notnull", "dflt_value", "pk"]
file_formats: ["sqlite"]
primary_terms: ["SQLite schema", "테이블 구조 확인", "sqlite_master"]
keywords: ["SQLite schema", "sqlite_master", "PRAGMA table_info", "PRAGMA foreign_key_list", "PRAGMA index_list", "테이블 구조 확인", "no such column", "type affinity", "뷰", "트리거", "스키마 덤프"]
aliases: ["sqlite 스키마", "테이블 목록 보기", "컬럼 이름 모름", "no such column", "sqlite 테이블 구조", "schema 확인", "알 수 없는 db"]
symptom_keywords: ["no such column 오류가 난다", "테이블 이름을 모르겠다", "컬럼 이름을 모르겠다", "이 DB가 무엇에 쓰이는지 모르겠다", "쿼리를 복사했는데 안 된다", "no such table 이라고 나온다"]
related: ["FOR-0200", "FOR-0202", "FOR-0191"]
source_ids: ["SRC-011", "SRC-008"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

낯선 SQLite DB 는 쿼리부터 던지지 말고 **`.tables` → `.schema <table>` → `PRAGMA table_info(<table>)`** 순서로 실제 컬럼을 확인한 뒤 쿼리를 조립한다. 브라우저와 앱은 버전마다 컬럼을 추가·삭제·개명하므로 **남의 블로그 SQL 을 그대로 붙이면 `no such column` 으로 실패**하고, 그것은 DB 의 문제가 아니라 절차를 건너뛴 결과다.

## 어떤 문제에서 필요한가

- 첨부가 확장자 없는 파일(`History`, `Cookies`, `places.sqlite`, `mmssms.db`)이고 구조를 모를 때
- 인터넷에서 찾은 쿼리가 `no such column: tab_url` / `no such table: downloads_slices` 로 죽을 때
- 모바일 앱 DB 처럼 **공개 문서가 없는 DB** 를 받아 "무엇이 들어 있는 DB 인가"부터 판정해야 할 때
- 시각 컬럼이 어떤 체계인지 판정하기 전에, 그 컬럼의 **선언 타입**을 확인해야 할 때
- 조인 관계(어느 컬럼이 어느 테이블을 참조하는가)를 몰라 타임라인을 못 만들 때

**스키마 확인은 30초가 걸리고, 스키마를 건너뛰면 30분을 잃는다.**

## 문제에서 처음 볼 단서

1. **`file` 출력** — SQLite 인지부터 확정한다. 확장자는 아무 의미가 없다.
2. **동반 파일** — 같은 폴더의 `<name>-wal`, `<name>-shm`, `<name>-journal`. **`-wal` 을 빼고 복사하면 최신 커밋이 누락된다.**
3. **파일 크기** — 몇 KB 면 빈 껍데기이거나 스키마만 있는 DB 다.
4. **파일명** — `History`, `Web Data`, `Login Data`, `places.sqlite`, `cookies.sqlite` 는 이미 알려진 스키마다.
5. **`strings` 첫 출력** — 헤더 근처에 `CREATE TABLE ...` 원문이 평문으로 들어 있어, 열지 못해도 스키마를 읽을 수 있다.

```bash
file History
# History: SQLite 3.x database, last written using SQLite version 3045000

ls -la History*
# History  History-wal  History-shm
```

## 30초 절차

```bash
sqlite3 app.db ".tables"
```

전체 4줄:

```bash
cp app.db /tmp/w.db; cp app.db-wal /tmp/w.db-wal 2>/dev/null   # 1) 사본 + wal
sqlite3 /tmp/w.db ".tables"                                    # 2) 테이블 목록
sqlite3 /tmp/w.db ".schema urls"                               # 3) 관심 테이블 DDL
sqlite3 /tmp/w.db "PRAGMA table_info(urls);"                   # 4) 컬럼을 표로
```

한 방에 전체 스키마를 파일로 떨어뜨리려면:

```bash
sqlite3 /tmp/w.db ".schema" > schema.sql
wc -l schema.sql && grep -c "CREATE TABLE" schema.sql
```

## 상세 절차

### 1단계 — 사본을 만들고 동반 파일을 같이 가져온다

원본을 직접 열면 SQLite 가 `-wal` 을 원본에 체크포인트하며 **증거물을 수정**한다. 항상 사본에서 작업한다.

| 동반 파일 | 무엇이 들어 있나 | 빼먹으면 |
| --- | --- | --- |
| `<db>-wal` | WAL 모드의 **아직 본체에 병합되지 않은 최신 트랜잭션** | 가장 최근 기록이 통째로 사라진다 |
| `<db>-shm` | WAL 인덱스(공유 메모리). 없으면 재생성된다 | 대개 무해 |
| `<db>-journal` | 롤백 저널. 롤백된 이전 이미지 | 삭제 직전 값을 놓친다 |

```powershell
# Windows: 같은 이름으로 시작하는 파일을 전부 가져온다
Copy-Item 'C:\case\Default\History*' 'C:\case\work\' -Force
Get-ChildItem 'C:\case\work\' | Select-Object Name, Length
```

```bash
sqlite3 /tmp/w.db "PRAGMA journal_mode;"   # wal 이면 -wal 이 필수다
sqlite3 /tmp/w.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

### 2단계 — 테이블 목록: `.tables` 와 `sqlite_master`

`.tables` 는 sqlite3 CLI 의 도트 명령이다. 이름만 간단히 보여준다.

```text
sqlite3> .tables
android_metadata          downloads_url_chains      segment_usage
clusters                  keyword_search_terms      segments
content_annotations        meta                      typed_url_sync_metadata
downloads                 sqlite_sequence           urls
downloads_slices          visit_source              visits
```

`.tables` 는 **뷰와 테이블을 구분하지 않고, 인덱스와 트리거를 아예 보여주지 않는다.** 전체 목록은 `sqlite_master` 로 본다.

```sql
SELECT type, name, tbl_name FROM sqlite_master ORDER BY type, name;
```

```text
type    name                         tbl_name
index   urls_url_index               urls
index   visits_from_index            visits
table   downloads                    downloads
table   downloads_url_chains         downloads_url_chains
table   sqlite_sequence              sqlite_sequence
table   urls                         urls
table   visits                       visits
trigger urls_cleanup                 urls
view    v_recent                     v_recent
```

`sqlite_master` 는 **모든 스키마 객체가 들어 있는 진짜 목차**이며, DB 파일 안에 실제로 저장된 테이블이다. `sql` 컬럼에 `CREATE ...` 원문이 문자열로 그대로 있다.

```sql
-- 특정 테이블의 DDL 원문만
SELECT sql FROM sqlite_master WHERE name = 'downloads';

-- 컬럼 이름으로 테이블을 역추적 (어느 테이블에 그 컬럼이 있나)
SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE '%target_path%';

-- 인덱스만
SELECT name, tbl_name FROM sqlite_master WHERE type='index';
```

### 3단계 — `.schema` 로 DDL 을 읽는다

```bash
sqlite3 History ".schema downloads"
```

```sql
CREATE TABLE downloads (
  id INTEGER PRIMARY KEY,
  guid VARCHAR NOT NULL,
  current_path LONGVARCHAR NOT NULL,
  target_path LONGVARCHAR NOT NULL,
  start_time INTEGER NOT NULL,
  received_bytes INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  state INTEGER NOT NULL,
  danger_type INTEGER NOT NULL,
  interrupt_reason INTEGER NOT NULL,
  hash BLOB NOT NULL,
  end_time INTEGER NOT NULL,
  opened INTEGER NOT NULL,
  last_access_time INTEGER NOT NULL,
  referrer VARCHAR NOT NULL,
  tab_url VARCHAR NOT NULL,
  ...
);
```

DDL 원문에서 얻는 것: 컬럼 이름과 선언 타입, `PRIMARY KEY`, `NOT NULL`, `DEFAULT`, `REFERENCES`, `CHECK` 제약. **`REFERENCES` 가 적혀 있으면 조인 관계가 문서 없이도 확정된다.**

`.schema` 에 인수를 주지 않으면 전체 DDL 이 나온다. LIKE 패턴도 받는다.

```bash
sqlite3 History ".schema"              # 전부
sqlite3 History ".schema download%"    # 이름이 download 로 시작하는 것만
```

### 4단계 — `PRAGMA table_info()`: 컬럼을 표로

DDL 은 사람이 읽는 형식이고, `PRAGMA table_info()` 는 **기계가 읽는 표**다. 스크립트로 컬럼 존재를 판정할 때 이것을 쓴다.

```sql
PRAGMA table_info(urls);
```

```text
cid  name             type       notnull  dflt_value  pk
0    id               INTEGER    0                    1
1    url              LONGVARCHAR 0                   0
2    title            LONGVARCHAR 0                   0
3    visit_count      INTEGER    1        0           0
4    typed_count      INTEGER    1        0           0
5    last_visit_time  INTEGER    1        0           0
6    hidden           INTEGER    1        0           0
```

`PRAGMA` 는 테이블 함수 형태로도 쓸 수 있어 **컬럼 존재 여부를 SQL 한 줄로 판정**할 수 있다(SQLite 3.16 이상).

```sql
-- tab_url 컬럼이 이 버전에 있는가
SELECT count(*) FROM pragma_table_info('downloads') WHERE name='tab_url';

-- 모든 테이블 x 모든 컬럼을 한 번에 나열 (전체 스키마 맵)
SELECT m.name AS tbl, p.cid, p.name AS col, p.type
FROM sqlite_master m
JOIN pragma_table_info(m.name) p
WHERE m.type = 'table'
ORDER BY m.name, p.cid;
```

`pragma_table_xinfo()` 는 숨은 컬럼(가상 테이블, `WITHOUT ROWID`, FTS 등)까지 보여준다. `table_info` 에 아무것도 안 나오면 이것을 써 본다.

### 5단계 — 조인 관계: `PRAGMA foreign_key_list()`

```sql
PRAGMA foreign_key_list(visits);
```

```text
id  seq  table  from       to    on_update  on_delete  match
0   0    urls   url        id    NO ACTION  NO ACTION  NONE
```

`from` 이 내 컬럼, `table`+`to` 가 참조 대상이다. 위 출력은 `visits.url → urls.id` 를 뜻하며, 이것이 `JOIN urls u ON u.id = v.url` 의 근거다.

**주의**: Chrome History 처럼 `FOREIGN KEY` 를 선언하지 않고 애플리케이션 코드에서만 관계를 유지하는 DB 가 많다. `foreign_key_list` 가 비어 있어도 관계가 없다는 뜻이 아니다. 그때는 컬럼 이름(`url_id`, `keyword_id`, `parent`)과 값의 범위로 추정하고, 조인 결과 건수로 검증한다.

```sql
-- 이름으로 추정한 조인이 맞는지 검증: 매칭되지 않는 행이 몇 개인가
SELECT count(*) FROM keyword_search_terms k
LEFT JOIN urls u ON u.id = k.url_id
WHERE u.id IS NULL;
-- 0 이면 url_id -> urls.id 관계가 맞다
```

### 6단계 — `PRAGMA index_list()` / `index_info()`

```sql
PRAGMA index_list(urls);
```

```text
seq  name                    unique  origin  partial
0    urls_url_index          0       c       0
1    sqlite_autoindex_urls_1 1       pk      0
```

| `origin` | 의미 |
| --- | --- |
| `c` | `CREATE INDEX` 로 만든 인덱스 |
| `pk` | PRIMARY KEY 로 자동 생성 |
| `u` | UNIQUE 제약으로 자동 생성 |

```sql
PRAGMA index_info('urls_url_index');   -- 그 인덱스가 어느 컬럼을 덮는가
```

포렌식에서 인덱스가 중요한 이유는 두 가지다. 첫째, **인덱스가 걸린 컬럼은 그 앱이 자주 검색하는 값**이므로 그 DB 의 용도를 알려준다. 둘째, 인덱스 페이지에는 **본체에서 삭제된 행의 키 값이 남아 있는 경우**가 있어 카빙 대상이 된다.

### 7단계 — 뷰와 트리거를 놓치지 않는다

```sql
SELECT name, sql FROM sqlite_master WHERE type IN ('view','trigger');
```

- **뷰**: 앱 개발자가 이미 만들어 둔 조인이다. `v_recent`, `combined_view` 같은 이름이 보이면 **그 SQL 을 그대로 읽어 조인 조건을 배운다.** 우리가 풀어야 할 관계를 이미 풀어 놓은 정답지다.
- **트리거**: `AFTER DELETE` 트리거가 있으면 행 삭제 시 다른 테이블도 함께 지워졌다는 뜻이다. 데이터가 왜 사라졌는지 설명해 준다.

```sql
-- 뷰의 정의를 읽어 조인 조건을 그대로 가져온다
SELECT sql FROM sqlite_master WHERE type='view';
```

### 8단계 — 타입이 없다: affinity 때문에 시각이 섞인다

SQLite 는 **컬럼 타입이 값의 형식을 강제하지 않는다.** 선언 타입은 "affinity"(권고)일 뿐이고, `INTEGER` 로 선언한 컬럼에 문자열이 들어갈 수 있다. 그래서 같은 시각 컬럼 안에 정수와 ISO 문자열이 섞이는 DB 가 실제로 존재한다.

선언 타입 대신 **실제 저장된 타입**을 `typeof()` 로 확인한다.

```sql
-- 이 컬럼에 실제로 어떤 타입이 몇 건씩 들어 있나
SELECT typeof(last_visit_time) AS t, count(*), min(last_visit_time), max(last_visit_time)
FROM urls GROUP BY t;
```

```text
t        count(*)  min              max
integer  1842      13350000000000   13391842211913
text     3         2026-03-14 07:15:02  2026-03-14 09:02:11
```

**정수 1,842 건과 문자열 3 건이 한 컬럼에 섞여 있다.** 이 3 건을 정수 산술로 변환하면 조용히 0 이나 NULL 이 되어 타임라인에서 사라진다. 변환 규칙은 [FOR-0202](./sqlite-timestamp-conversion.html) 에서 다룬다.

| 선언 타입 | affinity | 실제로 들어올 수 있는 것 |
| --- | --- | --- |
| `INTEGER` | INTEGER | 정수, 실수, 그리고 **숫자로 안 보이는 문자열은 문자열로 그대로** |
| `VARCHAR` / `LONGVARCHAR` / `TEXT` | TEXT | 문자열. 숫자를 넣으면 문자열로 변환 |
| `REAL` / `DOUBLE` | REAL | 실수 |
| `BLOB` / 타입 없음 | BLOB(none) | **변환 없이 그대로.** `hex()` 로 봐야 한다 |
| `NUMERIC` / `DATETIME` | NUMERIC | 정수/실수/문자열 전부 |

`DATETIME` 은 SQLite 의 진짜 타입이 아니다. `NUMERIC` affinity 를 갖는 이름일 뿐이며, 안에 무엇이 들었는지는 열어 봐야 안다.

### 9단계 — 알 수 없는 DB 의 용도를 스키마만으로 추정한다

공개 문서가 없는 앱 DB 를 받았을 때 순서.

| 신호 | 추정 |
| --- | --- |
| 테이블에 `android_metadata` 가 있다 | **안드로이드 앱 DB** (`locale` 컬럼에 `ko_KR`) |
| `meta` 테이블에 `key`/`value` | 스키마 **버전 번호**가 있다. 컬럼 차이의 원인 |
| `sqlite_sequence` 가 있다 | `AUTOINCREMENT` 사용. `seq` 값 = 지금까지 발급된 최대 ID → **삭제된 행 수를 추정**(`seq` - 실제 행 수) |
| 컬럼명에 `_id` 접미 | 다른 테이블 참조. 이름 앞부분이 대상 테이블 |
| 컬럼명에 `date`, `time`, `_at`, `ts`, `stamp` | 시각 컬럼. 자릿수로 체계 판정 |
| 10~13 자리 정수 컬럼 | Unix 초/밀리초 |
| 16~17 자리 정수 컬럼 | WebKit(1601 기준 마이크로초) 또는 FILETIME |
| `body`, `text`, `message`, `content` | **메시지 본문.** 최우선 확인 대상 |
| `path`, `uri`, `url`, `filename` | 파일/네트워크 경로 |
| `deleted`, `is_deleted`, `trashed` 플래그 | **논리 삭제.** 삭제된 항목이 행으로 남아 있다 |
| `BLOB` 컬럼이 큰 DB | 썸네일/첨부/protobuf. `hex()` 로 매직 바이트 확인 |
| FTS 관련 테이블(`*_content`, `*_segdir`) | 전문 검색 인덱스. **본체에서 지운 텍스트가 여기 남는다** |

행 수를 한 번에 세어 "어느 테이블에 데이터가 있는가"를 먼저 좁힌다.

```bash
# 모든 테이블의 행 수를 세는 SQL 을 자동 생성해서 실행
sqlite3 unknown.db "SELECT 'SELECT '''||name||''', count(*) FROM \"'||name||'\";'
                    FROM sqlite_master WHERE type='table';" > count.sql
sqlite3 -header -column unknown.db < count.sql
```

```text
'android_metadata'  1
'messages'          4127     <- 여기다
'threads'           38
'attachments'       61
'meta'              3
```

## 출력 필드 해석

### `sqlite_master` 컬럼

| 컬럼 | 의미 | 포렌식 활용 |
| --- | --- | --- |
| `type` | `table` \| `index` \| `view` \| `trigger` | 뷰/트리거를 놓치지 않기 위해 필수 |
| `name` | 객체 이름 | `.tables` 가 안 보여주는 것까지 |
| `tbl_name` | 그 객체가 붙어 있는 테이블 | 인덱스/트리거의 소속 |
| `rootpage` | B-tree 루트 **페이지 번호** | 헥스 에디터로 직접 페이지를 찾아갈 때. 뷰/트리거는 0 |
| `sql` | `CREATE ...` **원문 문자열** | 컬럼 검색, 뷰 정의 재사용, `strings` 로 복구 가능 |

### `PRAGMA table_info(t)` 컬럼

| 컬럼 | 의미 |
| --- | --- |
| `cid` | 0 부터의 컬럼 순서. `SELECT *` 의 출력 순서와 같다 |
| `name` | 컬럼 이름 |
| `type` | **선언 타입**(affinity 근거). 실제 값의 타입이 아니다 |
| `notnull` | 1 이면 NOT NULL |
| `dflt_value` | 기본값. `NULL` 이면 기본값 없음 |
| `pk` | 0 이 아니면 PRIMARY KEY 의 몇 번째 컬럼인가 |

### `PRAGMA foreign_key_list(t)` 컬럼

| 컬럼 | 의미 |
| --- | --- |
| `id` / `seq` | 제약 번호 / 복합 키 안의 순서 |
| `table` | 참조 대상 테이블 |
| `from` | **내 테이블의 컬럼** |
| `to` | 대상 테이블의 컬럼. NULL 이면 대상의 PK |
| `on_delete` | `CASCADE` 면 부모 삭제 시 자식도 삭제된다 |

## pivot: 다음에 볼 artifact

| 스키마에서 얻은 것 | 다음 목표 |
| --- | --- |
| 시각 컬럼 이름과 자릿수 | 시각 체계 판정과 변환 ([FOR-0202](./sqlite-timestamp-conversion.html)) |
| `urls` / `visits` / `downloads` 확인 | Chrome History 전용 쿼리 ([FOR-0191](./chrome-history.html)) |
| `moz_places` / `moz_historyvisits` | Firefox `places.sqlite` (PRTime 마이크로초) |
| `sqlite_sequence.seq` 와 실제 행 수 차이 | 삭제된 행 개수 → freelist 카빙, `strings` 복구 |
| `android_metadata` 존재 | 모바일 앱 DB 라인으로 전환 |
| `path` / `filename` 컬럼의 값 | `$MFT` ([FOR-0021](./mft-basics.html)) 에서 그 파일 존재 확인 |
| `BLOB` 컬럼의 `hex()` 앞 8바이트 | 매직 바이트 판정 ([FOR-0001](./30sec-triage.html)) |
| 뷰 정의의 조인 조건 | 그대로 복사해 타임라인 쿼리로 |

## 흔한 함정

- **`.tables` 만 보고 전체를 봤다고 생각하는 것.** `.tables` 는 인덱스·트리거를 안 보여주고 뷰를 테이블과 섞어 보여준다. `SELECT type,name FROM sqlite_master` 가 진짜 목차다.
- **블로그 쿼리를 그대로 붙이는 것.** Chrome 은 `downloads` 에 `tab_url`, `site_url`, `last_access_time`, `by_ext_id` 등을 버전에 따라 추가해 왔다. 오래된 DB 에는 없다. `no such column` 이 나오면 즉시 `PRAGMA table_info()` 로 실제 컬럼을 확인하고 쿼리에서 그 컬럼을 뺀다.
- **`SELECT *` 로 시작하는 것.** 컬럼이 40 개인 테이블에서 출력이 화면을 넘겨 아무것도 못 읽는다. `table_info` 로 필요한 컬럼만 골라 명시한다.
- **선언 타입을 값의 타입으로 믿는 것.** SQLite 는 타입을 강제하지 않는다. `INTEGER` 컬럼에 ISO 문자열이 섞여 있으면 산술 변환이 조용히 NULL 이 된다. `typeof(col)` 로 GROUP BY 해서 먼저 확인한다.
- **`-wal` 을 빼고 스키마만 보는 것.** 스키마 변경(새 컬럼 추가)이 `-wal` 안에만 있으면 본체만 열었을 때 구버전 스키마가 보인다. 동반 파일을 전부 가져온다.
- **원본 파일을 직접 여는 것.** sqlite3 가 원본에 WAL 을 체크포인트하고 `-shm` 을 새로 만들어 **증거물의 해시가 바뀐다.** 반드시 사본.
- **뷰를 테이블로 착각해 UPDATE 를 시도하는 것.** 그리고 뷰의 정의를 읽지 않아 개발자가 이미 만들어 둔 조인을 다시 발명하는 것.
- **`foreign_key_list` 가 비었다고 관계가 없다고 결론 내는 것.** 브라우저 DB 대부분이 FK 를 선언하지 않는다. 컬럼 이름으로 추정하고 `LEFT JOIN ... WHERE 대상 IS NULL` 건수로 검증한다.
- **`sqlite_sequence` 를 무시하는 것.** `seq` 가 5,000 인데 행이 40 개면 **4,960 건이 삭제됐다**는 강력한 신호다.
- **DB 가 열리지 않으면 포기하는 것.** `strings` 로 `CREATE TABLE` 원문과 텍스트 값이 그대로 나온다. 스키마만이라도 먼저 확보한다.
- **FTS(전문 검색) 보조 테이블을 건너뛰는 것.** 본체에서 삭제한 메시지 본문이 `*_content` 테이블에 남아 있는 경우가 많다.

## 교차검증

```bash
# 1) 파일이 정말 SQLite 인가 + 버전
file app.db
xxd -l 16 app.db          # 53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00  = "SQLite format 3\0"

# 2) 무결성 — 손상된 DB 를 붙잡고 씨름하지 않기 위해 먼저
sqlite3 app.db "PRAGMA integrity_check;"     # ok 가 아니면 카빙 라인으로

# 3) 스키마 전체를 파일로 (도구 없이 눈으로 비교)
sqlite3 app.db ".schema" > schema.sql

# 4) DB 를 열 수 없을 때 — 스키마를 strings 로 복구
strings -n 12 app.db | grep -E "^CREATE (TABLE|INDEX|VIEW|TRIGGER)" | sort -u

# 5) GUI 교차확인 — DB Browser for SQLite 의 Database Structure 탭
#    같은 DDL 이 트리로 보인다. Execute SQL 탭에 PRAGMA 도 그대로 통한다
```

`PRAGMA integrity_check` 가 `ok` 가 아니면 SQL 결과를 신뢰하지 말고, `.recover`(sqlite3 3.29 이상) 나 문자열 카빙으로 전환한다.

```bash
sqlite3 broken.db ".recover" | sqlite3 recovered.db
sqlite3 recovered.db ".tables"
```

## mini walkthrough

```text
문제:
"압수된 노트북의 브라우저 DB 에서 마지막으로 다운로드한 파일의
 저장 경로와 출처 URL 을 구하세요."
첨부: History, History-wal  (확장자 없음, 4.2 MB)

1. 정체 확인
   $ file History
   History: SQLite 3.x database, last written using SQLite version 3029000
   $ ls
   History  History-wal        <- wal 이 있다. 함께 복사한다.

   $ cp History History-wal /tmp/ && cd /tmp

2. 첫 시도 (실패) — 인터넷에서 찾은 쿼리를 그대로 붙였다
   $ sqlite3 History "SELECT target_path, tab_url, site_url,
                             datetime(start_time/1000000-11644473600,'unixepoch')
                      FROM downloads ORDER BY start_time DESC LIMIT 1;"
   Error: no such column: site_url

   컬럼을 하나 빼고 다시 던졌다.
   $ sqlite3 History "SELECT target_path, tab_url FROM downloads ...;"
   Error: no such column: tab_url

   -> 두 번 연속 실패. 컬럼을 하나씩 빼며 맞히는 것은 도박이다.
      이 DB 는 SQLite 3.029 시절의 구버전 Chrome 이고,
      최신 스키마 기준 쿼리가 맞을 이유가 없었다.
      순서를 되돌려 스키마부터 본다.

3. 접근 변경 — 스키마 먼저
   $ sqlite3 History ".tables"
   downloads             keyword_search_terms  urls
   downloads_url_chains  meta                  visit_source
   segments              sqlite_sequence       visits

   $ sqlite3 -header -column History "PRAGMA table_info(downloads);"
   cid  name              type         notnull  dflt_value  pk
   0    id                INTEGER      0                    1
   1    current_path      LONGVARCHAR  1                    0
   2    target_path       LONGVARCHAR  1                    0
   3    start_time        INTEGER      1                    0
   4    received_bytes    INTEGER      1                    0
   5    total_bytes       INTEGER      1                    0
   6    state             INTEGER      1                    0
   7    danger_type       INTEGER      1                    0
   8    interrupt_reason  INTEGER      1                    0
   9    end_time          INTEGER      1                    0
   10   opened            INTEGER      1                    0
   11   referrer          VARCHAR      1                    0
   12   by_ext_id         VARCHAR      1                    0
   13   by_ext_name       VARCHAR      1                    0
   14   etag              VARCHAR      1                    0
   15   last_modified     VARCHAR      1                    0
   16   mime_type         VARCHAR(255) 1                    0

   -> tab_url 도 site_url 도 이 버전에는 없다. 출처는 referrer 뿐이다.
      실제 컬럼 목록을 봤으니 이제 쿼리를 조립할 수 있다.

4. 조립한 쿼리
   $ sqlite3 -header -column History "
     SELECT datetime(start_time/1000000-11644473600,'unixepoch','+9 hours') AS kst,
            target_path, received_bytes, state, opened, referrer
     FROM downloads ORDER BY start_time DESC LIMIT 3;"

   kst                  target_path                              bytes   state opened referrer
   2026-03-14 16:35:40  C:\Users\jhkim\Downloads\setup_v2.exe    198656  1     1      https://share.example.net/d/9f2
   2026-03-14 16:33:12  C:\Users\jhkim\Downloads\invoice.zip     284113  1     1      https://mail.example.co.kr/read?id=88213

5. referrer 만으로는 부족하다 — 참조 관계를 스키마에서 확인
   $ sqlite3 History "PRAGMA foreign_key_list(downloads_url_chains);"
   (빈 출력)                  <- FK 선언이 없다

   $ sqlite3 History ".schema downloads_url_chains"
   CREATE TABLE downloads_url_chains (
     id INTEGER NOT NULL, chain_index INTEGER NOT NULL,
     url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index));

   -> id 가 downloads.id 를 가리킨다고 추정. 검증한다.
   $ sqlite3 History "SELECT count(*) FROM downloads_url_chains c
                      LEFT JOIN downloads d ON d.id=c.id WHERE d.id IS NULL;"
   0                          <- 매칭 안 되는 행이 없다. 추정이 맞다.

   $ sqlite3 -header -column History "
     SELECT d.target_path, c.chain_index, c.url
     FROM downloads d JOIN downloads_url_chains c ON c.id=d.id
     WHERE d.id=(SELECT id FROM downloads ORDER BY start_time DESC LIMIT 1)
     ORDER BY c.chain_index;"

   target_path                chain_index  url
   ...\setup_v2.exe           0            https://share.example.net/d/9f2/get
   ...\setup_v2.exe           1            https://cdn7.example-dl.top/f/setup_v2.exe

6. 삭제된 기록이 있는지 확인
   $ sqlite3 History "SELECT * FROM sqlite_sequence;"
   downloads|41
   $ sqlite3 History "SELECT count(*) FROM downloads;"
   6
   -> 발급된 ID 는 41, 남은 행은 6. 35 건이 삭제됐다.
      strings/freelist 카빙 대상이다.

정답: C:\Users\jhkim\Downloads\setup_v2.exe
      실제 출처 cdn7.example-dl.top (share.example.net 경유 리다이렉트)
      다운로드 기록 35 건이 삭제된 상태
```

2 단계의 실패가 이 글의 요지다. **컬럼 이름을 추측해 하나씩 빼는 것은 절차가 아니다.** `PRAGMA table_info()` 한 줄이 두 번의 실패와 그 뒤의 모든 추측을 없앤다. 그리고 5 단계처럼 FK 선언이 없어도 **`LEFT JOIN` 미매칭 건수 0** 으로 관계를 검증할 수 있다.

## 막혔을 때 다음 체크

1. `file` 로 정말 SQLite 인지 확인했는가 — 앞 16바이트가 `SQLite format 3\0` 인가
2. `-wal` / `-shm` / `-journal` 을 함께 복사했는가
3. 원본이 아니라 **사본**에서 작업하고 있는가
4. `SELECT type,name FROM sqlite_master` 로 뷰·트리거·인덱스까지 봤는가
5. `PRAGMA table_info()` 로 **실제 컬럼**을 확인했는가 — 쿼리를 추측으로 고치지 않았는가
6. `PRAGMA integrity_check` 가 `ok` 인가 — 아니면 `.recover` 로 전환
7. `typeof(시각컬럼)` 을 GROUP BY 해 봤는가 — 정수와 문자열이 섞여 있지 않은가
8. 뷰 정의(`SELECT sql FROM sqlite_master WHERE type='view'`)를 읽었는가
9. `sqlite_sequence.seq` 와 실제 행 수를 비교했는가 — 삭제된 행이 있는가
10. FTS 보조 테이블(`*_content`, `*_data`)에 본문이 남아 있는가
11. DB 가 안 열리면 `strings -n 12 | grep '^CREATE'` 로 스키마라도 확보했는가
12. `meta` 테이블의 스키마 버전을 확인했는가 — 컬럼 차이의 원인이다

## 출처

- SRC-011 — SQLite 공식 문서: `sqlite_master` 스키마 테이블, `PRAGMA table_info` / `foreign_key_list` / `index_list` / `integrity_check`, type affinity 규칙, WAL 모드와 `-wal`/`-shm` 동반 파일
- SRC-008 — Chromium source, `components/history/core/browser`: `downloads` / `urls` / `visits` / `downloads_url_chains` 의 실제 DDL 과 버전에 따른 컬럼 추가 이력(`tab_url`, `site_url`, `last_access_time` 등이 후기 버전에서 추가된 근거)
- `.tables`, `.schema`, `.recover` 는 sqlite3 **CLI 의 도트 명령**이며 SQL 이 아니다. DB Browser for SQLite 같은 GUI 에서는 통하지 않고, 메뉴(Database Structure 탭)로 같은 정보를 본다. `.recover` 는 sqlite3 3.29 이상, `pragma_table_info()` 테이블 함수는 3.16 이상에서만 쓸 수 있으므로 대회장 도구의 버전(`sqlite3 --version`)을 먼저 확인할 것
- `PRAGMA table_xinfo` 의 출력 컬럼은 SQLite 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
