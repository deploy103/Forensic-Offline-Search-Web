---
id: FOR-0193
title: "Chrome Cookies DB: 복호화 없이 읽어내는 정보와 encrypted_value 의 한계"
slug: "chrome-cookies"
category: "브라우저/웹"
type: "reference"
difficulty: "basic"
priority: "high"
platform: [windows]
artifact: ["Chrome Cookies", "cookies 테이블", "encrypted_value", "Local State", "os_crypt"]
file_paths: ["C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "HTTPS"]
tools: ["sqlite3", "DB Browser for SQLite", "FTK Imager", "Wireshark", "tshark"]
commands: ["sqlite3 Cookies \"SELECT DISTINCT host_key FROM cookies ORDER BY host_key;\"", "sqlite3 Cookies \".schema cookies\"", "sqlite3 Cookies \"SELECT host_key, name, length(encrypted_value) FROM cookies;\"", "tshark -r x.pcap -Y http.cookie -T fields -e http.host -e http.cookie"]
regex_patterns: ["^v1[01]"]
wireshark_filters: ["http.cookie", "http.set_cookie", "http.cookie contains \"session\""]
tshark_fields: ["http.cookie", "http.set_cookie", "http.host"]
log_fields: ["creation_utc", "host_key", "name", "value", "encrypted_value", "path", "expires_utc", "is_secure", "is_httponly", "last_access_utc", "has_expires", "is_persistent", "priority", "samesite", "source_scheme", "source_port"]
file_formats: ["sqlite"]
primary_terms: ["Chrome Cookies", "쿠키 DB", "cookies 테이블"]
keywords: ["Chrome Cookies", "cookies 테이블", "encrypted_value", "DPAPI", "os_crypt", "Local State", "host_key", "세션 쿠키", "samesite", "쿠키 복호화", "쿠키 만료", "AES-GCM"]
aliases: ["크롬 쿠키", "쿠키 db 위치", "쿠키 복호화", "encrypted_value", "쿠키 값이 비어있다", "접속한 사이트 목록", "쿠키 sqlite"]
symptom_keywords: ["쿠키 value 가 비어 있다", "쿠키 값이 깨져 보인다", "쿠키를 복호화할 수 없다", "접속한 사이트 목록이 필요하다", "로그인 세션이 있었는지 알고 싶다", "쿠키 파일이 어디 있나"]
related: ["FOR-0191", "FOR-0194", "FOR-0197", "FOR-0200"]
source_ids: ["SRC-008", "SRC-011"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Chrome 의 `Cookies` DB 는 `value` 가 **빈 문자열**이고 실제 값은 `encrypted_value` 에 DPAPI + Local State 의 AES 키로 이중 암호화되어 있어 **원 사용자 컨텍스트 없이는 복호화가 불가능**하지만, `host_key`·`creation_utc`·`last_access_utc`·`is_persistent` 는 평문이므로 "어느 사이트에 언제 접속했고 로그인 세션이 있었는가"는 복호화 없이 그대로 답할 수 있다.

## 개념

쿠키 DB 는 두 계층으로 나뉜다.

| 계층 | 내용 | 접근 가능성 |
| --- | --- | --- |
| **메타데이터** (`host_key`, `name`, `path`, 각종 시각, 플래그) | 어느 도메인의 어떤 이름의 쿠키가 언제 생겼는가 | **평문. 그냥 SELECT 하면 나온다** |
| **값** (`encrypted_value`) | 세션 토큰, 사용자 식별자 등 | 암호화. 사실상 불가 |

암호화 사슬은 이렇게 걸려 있다.

```text
encrypted_value  ("v10" 또는 "v11" 접두 + nonce + ciphertext + tag)
        ^ AES-256-GCM 키
        |
Local State (JSON) -> os_crypt.encrypted_key  (base64, 앞에 "DPAPI" 태그)
        ^ DPAPI
        |
원 사용자의 Windows 로그인 자격증명 (또는 도메인/로컬 마스터키)
```

즉 **Cookies 파일만 가져와도 값은 못 읽는다.** `Local State` 를 함께 가져와도 못 읽는다. DPAPI 단계를 풀려면 그 사용자로 로그인한 라이브 시스템이거나, 사용자 비밀번호 + DPAPI 마스터키 + SID 를 모두 확보해야 한다.

| 플랫폼 | 값 보호 방식 (접두) |
| --- | --- |
| Windows | `v10` — AES-256-GCM. 키는 `Local State` 의 `os_crypt.encrypted_key`, 그 키는 DPAPI 로 보호 |
| Windows (최신 Chrome) | `v20` — App-Bound Encryption 이 추가된 버전에서 관측된다. 브라우저 프로세스 컨텍스트를 추가로 요구한다 |
| Linux | `v11` — OS 키링(GNOME Keyring/KWallet)에서 키를 얻는다. 키링이 없으면 고정 문자열 기반 `v10` |
| macOS | `v10` — Keychain 항목 `Chrome Safe Storage` 에서 키를 얻는다 |

`v20` 은 버전에 따라 동작이 다르므로 실제 접두 바이트를 직접 확인하고 단정하지 않는다.

접두 확인은 SQL 한 줄로 끝난다.

```bash
sqlite3 Cookies "SELECT DISTINCT substr(hex(encrypted_value),1,6) FROM cookies;"
```

| hex 앞 6자리 | ASCII | 의미 |
| --- | --- | --- |
| `763130` | `v10` | AES-GCM (Windows/macOS 기본) |
| `763131` | `v11` | Linux 키링 기반 |
| `763230` | `v20` | App-Bound Encryption 계열 |
| 그 외 | - | 암호화 없이 저장된 구버전 데이터 가능. `value` 컬럼도 확인 |

Edge, Whale, Brave, Opera 는 모두 Chromium 이라 **테이블 구조와 암호화 방식이 동일**하다. `Local State` 의 위치만 다르다.

## 파일 / 경로

| 브라우저 / 상황 | 경로 |
| --- | --- |
| Chrome (현행) | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies` |
| Chrome (구버전) | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies` |
| Chrome 키 파일 | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State` |
| Edge | `%LocalAppData%\Microsoft\Edge\User Data\Default\Network\Cookies` |
| Whale | `%LocalAppData%\Naver\Naver Whale\User Data\Default\Network\Cookies` |
| Chrome (Linux) | `~/.config/google-chrome/Default/Cookies` |
| Chrome (macOS) | `~/Library/Application Support/Google/Chrome/Default/Cookies` |

**`Cookies` 는 어느 시점부터 프로필 폴더 아래 `Network\` 하위로 옮겨졌다.** 두 위치를 모두 확인한다. `Local State` 는 프로필 폴더가 아니라 그 **상위 `User Data\` 에 있다** — 프로필별이 아니라 설치 단위다.

### 함께 반드시 꺼낼 파일

| 파일 | 왜 필요한가 |
| --- | --- |
| `Cookies-wal` | **WAL 의 최신 데이터.** 이것 없이 열면 마지막 접속 쿠키가 누락된다 |
| `Cookies-journal` | 롤백 저널 (구버전) |
| `Local State` | `os_crypt.encrypted_key`. 라이브 환경에서 복호화를 시도할 때 필수 |
| `Network\` 폴더 전체 | `Network Persistent State`, `TransportSecurity` 등 접속 도메인 흔적이 추가로 나온다 |

`Cookies` 만 복사하고 `-wal` 을 두고 오면 **가장 최근 세션이 사라진다.** FTK Imager 로는 `Cookies*` 를 전부 선택한다 ([FOR-0016](./ftk-imager-open-image.html)).

```powershell
Get-ChildItem 'C:\Users\*\AppData\Local\*\*\User Data\*\Network\Cookies*' -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime
```

## 주요 필드

### `cookies` 테이블

| 컬럼 | 타입 | 의미 | 평문? |
| --- | --- | --- | --- |
| `creation_utc` | INTEGER | **쿠키가 만들어진 시각** (WebKit µs). 기본 PK | O |
| `host_key` | TEXT | **쿠키의 도메인.** 앞에 `.` 이 붙으면 서브도메인 포함 | O |
| `top_frame_site_key` | TEXT | 파티션 키(상위 프레임 사이트). 서드파티 쿠키 격리용 | O |
| `name` | TEXT | 쿠키 이름 (`SID`, `PHPSESSID`, `_ga` …) | O |
| `value` | TEXT | **암호화 사용 시 빈 문자열** | O (비어 있음) |
| `encrypted_value` | BLOB | **실제 값.** `v10`/`v11`/`v20` 접두 + 암호문 | X |
| `path` | TEXT | 쿠키 유효 경로 (`/`, `/admin` …) | O |
| `expires_utc` | INTEGER | 만료 시각 (WebKit µs). `0` 이면 세션 쿠키 | O |
| `is_secure` | INTEGER | 1 이면 HTTPS 전용 | O |
| `is_httponly` | INTEGER | 1 이면 JS 접근 불가 | O |
| `last_access_utc` | INTEGER | **마지막으로 전송된 시각** (WebKit µs) | O |
| `has_expires` | INTEGER | 만료가 지정됐는가 | O |
| `is_persistent` | INTEGER | **0 이면 세션 쿠키** (브라우저 종료 시 소멸 예정) | O |
| `priority` | INTEGER | 0 LOW / 1 MEDIUM / 2 HIGH | O |
| `samesite` | INTEGER | -1 UNSPECIFIED / 0 NONE / 1 LAX / 2 STRICT | O |
| `source_scheme` | INTEGER | 0 Unset / 1 NonSecure(http) / 2 Secure(https) | O |
| `source_port` | INTEGER | 쿠키를 설정한 포트. `-1` 이면 불명 | O |
| `last_update_utc` | INTEGER | 값이 마지막으로 갱신된 시각 | O |

구버전은 `secure` / `httponly` / `persistent` / `firstpartyonly` 같은 다른 컬럼명을 쓴다. **`.schema cookies` 를 먼저 찍고 컬럼명을 확인한다.**

### 시각 3종의 차이 — 이것이 이 DB 의 핵심 가치

| 컬럼 | 답하는 질문 |
| --- | --- |
| `creation_utc` | **그 사이트에 처음(또는 재로그인 시점에) 접촉한 시각** |
| `last_access_utc` | **그 쿠키가 마지막으로 서버에 전송된 시각 = 마지막 활동 시각** |
| `expires_utc` | 발급 서버가 정한 유효기간. 발급 시점 추정에 쓴다 |

세 값은 모두 **1601-01-01 UTC 기준 마이크로초(WebKit)** 다. 변환은 `/1000000 - 11644473600` ([FOR-0197](./webkit-timestamp.html)).

`creation_utc` 를 오름차순으로 정렬하면 **History 가 지워진 뒤에도 접속 사이트의 시간순 목록**이 나온다. 이것이 실전에서 쿠키 DB 를 여는 가장 큰 이유다.

### `is_persistent` / `has_expires` / `expires_utc` 조합

| `is_persistent` | `has_expires` | `expires_utc` | 해석 |
| --- | --- | --- | --- |
| 1 | 1 | 미래 값 | 정상 영속 쿠키 (로그인 유지 등) |
| 1 | 1 | 과거 값 | 만료됐지만 아직 정리되지 않았다. 과거 활동의 증거 |
| 0 | 0 | 0 | **세션 쿠키.** 원래 디스크에 안 남는다 |

**세션 쿠키가 디스크 DB 에 있는 것 자체가 정보다.** "종료 시 세션 복원"(계속하기 설정)이 켜져 있거나 브라우저가 비정상 종료된 경우에 남는다. 즉 그 행이 있으면 **마지막 브라우징 세션이 정상적으로 닫히지 않았을 가능성**을 의심한다.

### 복호화 없이 확정할 수 있는 것 / 없는 것

| 질문 | 답 가능? | 근거 컬럼 |
| --- | --- | --- |
| 어느 사이트에 접속했나 | **O** | `host_key` |
| 언제 처음 접촉했나 | **O** | `creation_utc` |
| 언제까지 활동했나 | **O** | `last_access_utc` |
| 로그인 상태였을 가능성이 있나 | **O (정황)** | 인증성 쿠키 이름 + `is_httponly=1` + `is_secure=1` |
| 세션이 비정상 종료됐나 | **O (정황)** | `is_persistent=0` 행의 존재 |
| 어떤 계정으로 로그인했나 | X | 값 안에 있다. 복호화 필요 |
| 세션 토큰 문자열 | X | `encrypted_value` |
| 그 토큰으로 재접속 가능한가 | X | 복호화 + 만료 미도과 필요 |

계정 자체를 알고 싶으면 쿠키가 아니라 `Login Data` 의 `username_value` 로 간다 ([FOR-0194](./chrome-login-data.html)). 그쪽은 **아이디가 평문**이다.

### 쿠키 이름으로 서비스 성격 추정

값을 못 봐도 `name` 은 평문이므로 무슨 종류의 쿠키인지는 판단할 수 있다.

| `name` 패턴 | 성격 |
| --- | --- |
| `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session` | 서버 세션 식별자. **로그인 세션의 강한 정황** |
| `SID`, `SSID`, `HSID`, `APISID`, `SAPISID`, `__Secure-*` | Google 계열 인증 |
| `_ga`, `_gid`, `_gat`, `_fbp`, `_gcl_au` | 분석/광고 추적. 사용자 행위 증거로는 약하다 |
| `csrftoken`, `XSRF-TOKEN` | 폼 제출이 있었다는 정황 |
| `remember_token`, `auth`, `access_token`, `refresh_token` | 장기 인증. `expires_utc` 가 멀다 |

`__Host-` / `__Secure-` 접두는 브라우저가 강제하는 보안 접두이므로 HTTPS 로 발급됐다는 것이 확정된다.

## 빠른 명령

```bash
sqlite3 -header -column Cookies "SELECT DISTINCT host_key FROM cookies ORDER BY host_key;"
```

```bash
# 0) 사본 + wal 동반. 원본을 직접 열지 않는다
cp Cookies Cookies.cp; cp Cookies-wal Cookies.cp-wal 2>/dev/null

# 1) 스키마 확인 — 컬럼명이 버전마다 다르다
sqlite3 Cookies.cp ".schema cookies"

# 2) 접속 도메인 목록 + 쿠키 개수 + 활동 구간
sqlite3 -header -column Cookies.cp "
SELECT host_key,
       count(*) AS n,
       datetime(min(creation_utc)/1000000-11644473600,'unixepoch','+9 hours') AS first_kst,
       datetime(max(last_access_utc)/1000000-11644473600,'unixepoch','+9 hours') AS last_kst
FROM cookies GROUP BY host_key ORDER BY max(last_access_utc) DESC;"

# 3) 시간순 접촉 타임라인 (History 대체용)
sqlite3 -header -column Cookies.cp "
SELECT datetime(creation_utc/1000000-11644473600,'unixepoch','+9 hours') AS created_kst,
       host_key, name, is_secure, is_httponly, is_persistent
FROM cookies ORDER BY creation_utc;"

# 4) 세션 쿠키만 = 정상 종료되지 않았을 가능성
sqlite3 -header -column Cookies.cp "
SELECT datetime(creation_utc/1000000-11644473600,'unixepoch','+9 hours') AS created_kst,
       host_key, name FROM cookies WHERE is_persistent = 0 ORDER BY creation_utc;"

# 5) 인증성 쿠키 후보만 추리기
sqlite3 -header -column Cookies.cp "
SELECT host_key, name, is_httponly, is_secure,
       datetime(expires_utc/1000000-11644473600,'unixepoch','+9 hours') AS expires_kst
FROM cookies
WHERE name LIKE '%SESS%' OR name LIKE '%sid%' OR name LIKE '%auth%'
   OR name LIKE '%token%' OR name LIKE '%remember%'
ORDER BY host_key;"

# 6) 값이 정말 암호화되어 있는지 확인 (value 는 비어 있어야 한다)
sqlite3 -header -column Cookies.cp "
SELECT host_key, name, length(value) AS plain_len,
       length(encrypted_value) AS enc_len,
       substr(hex(encrypted_value),1,6) AS tag
FROM cookies LIMIT 10;"

# 7) 잠겨 있다는 오류가 날 때
sqlite3 Cookies.cp "PRAGMA wal_checkpoint(TRUNCATE);"

# 8) Local State 에서 암호화 키 존재 여부만 확인 (복호화는 별개)
python3 -c "import json;print(json.load(open('Local State'))['os_crypt']['encrypted_key'][:24])"
```

`length(value) = 0` 이고 `length(encrypted_value) > 0` 이면 예상대로 암호화된 DB 다. `tag` 가 `763130`(`v10`)으로 나오는지 확인한다. 도트 명령과 `PRAGMA` 용법 전반은 [FOR-0200](./sqlite-basics.html)에 정리해 두었다.

### pcap 의 `http.cookie` 와 대조

디스크의 쿠키 값은 암호화되어 있지만, **평문 HTTP 트래픽이 캡처되어 있으면 값이 그대로 보인다.** 두 증거를 이름 단위로 이어 붙인다.

```text
http.cookie
http.set_cookie
http.cookie contains "PHPSESSID"
```

```bash
tshark -r capture.pcap -Y http.cookie -T fields -e frame.time -e http.host -e http.cookie
tshark -r capture.pcap -Y http.set_cookie -T fields -e http.host -e http.set_cookie
```

| 디스크 (Cookies DB) | pcap | 결합해서 얻는 것 |
| --- | --- | --- |
| `host_key`, `name`, 시각 | `http.host`, `http.cookie` 의 이름=값 | **암호화된 값의 평문**을 트래픽에서 획득 |
| `creation_utc` | `http.set_cookie` 프레임 시각 | 발급 시점 상호 검증 |
| `is_secure = 1` | HTTPS 라 값이 안 보임 | TLS 구간은 값 획득 불가. SNI 로 도메인만 확인 |

HTTPS 세션은 값이 안 보인다. 그때는 `tls.handshake.extensions_server_name` 으로 도메인만 확인하고 값은 포기한다. pcap 진입 절차는 [FOR-0146](./wireshark-30sec-triage.html)을 본다.

## 함께 보는 artifact

| 쿠키에서 얻은 것 | 다음에 여는 것 |
| --- | --- |
| `host_key` 도메인 목록 | `History` 의 `urls` ([FOR-0191](./chrome-history.html)) — 실제 방문 URL 과 제목 |
| `host_key` | DNS 질의 기록, pcap TLS SNI, `hosts` 파일 |
| 인증성 쿠키가 있는 도메인 | `Login Data` 의 `origin_url` / `username_value` ([FOR-0194](./chrome-login-data.html)) |
| `creation_utc` 구간 | EVTX 4624 로그온 세션, `$MFT` 파일 활동 |
| 세션 쿠키 존재 | `Sessions\` 폴더의 `Session_*` / `Tabs_*` — 마지막 열린 탭 |
| `host_key` | `Cache\Cache_Data` 항목 URL — 캐시에 남은 방문 흔적 |
| `Local State` | `os_crypt.encrypted_key`, 프로필 목록(`profile.info_cache`) |
| 값 복호화가 필요할 때 | 라이브 시스템에서 그 사용자 컨텍스트 확보 |

## 흔한 실수

- **`value` 가 비었다고 DB 가 손상됐다고 판단하는 것.** 정상이다. 암호화 사용 시 `value` 는 빈 문자열이고 실제 값은 `encrypted_value` 에 있다.
- **`Cookies` 만 복사하는 것.** `Cookies-wal` 이 없으면 가장 최근 접속 흔적이 빠진다. `Local State` 도 함께 확보해야 나중에 복호화 시도가 가능하다.
- **`Local State` 를 프로필 폴더에서 찾는 것.** `Default\` 가 아니라 그 상위 `User Data\` 에 있다.
- **`Network\Cookies` 를 놓치는 것.** 어느 시점부터 위치가 바뀌었다. `Default\Cookies` 만 보고 "쿠키가 없다"고 결론 내면 안 된다.
- **`encrypted_value` 를 base64 나 hex 로 풀어서 값을 읽으려는 것.** 인코딩이 아니라 **암호화**다. `v10` 접두 뒤는 AES-GCM 암호문이다. 키 없이는 어떤 디코더로도 안 나온다.
- **오프라인 이미지에서 복호화를 시도하다 시간을 버리는 것.** DPAPI 단계는 사용자 자격증명·마스터키·SID 가 전부 있어야 풀린다. 대회에서 이 세 가지가 주어지지 않았다면 값은 **문제의 답이 아니다.** 메타데이터로 답하도록 설계된 문제다.
- **`expires_utc = 0` 을 "1601년 만료"로 읽는 것.** `0` 은 만료 없음(세션 쿠키)이라는 뜻이다. 변환식을 그대로 적용하면 1601-01-01 이 나와 표가 오염된다. `has_expires = 0` 인 행은 시각 계산에서 제외한다.
- **`last_access_utc` 를 방문 시각으로 단정하는 것.** 그 쿠키가 **전송된** 시각이다. 백그라운드 요청, 서드파티 광고 요청으로도 갱신된다. 사용자의 능동적 방문은 `visits` 로 확인한다.
- **추적 쿠키(`_ga`, `_fbp`)를 사용자 행위 증거로 쓰는 것.** 광고 iframe 만으로도 생긴다. 사용자가 그 사이트를 봤다는 증거가 아니다.
- **`host_key` 앞의 점을 무시하는 것.** `.example.com` 은 서브도메인 전체에 유효한 쿠키다. `example.com` 과 다른 행으로 존재할 수 있어 `GROUP BY host_key` 시 중복처럼 보인다.
- **`samesite = -1` 을 오류로 보는 것.** UNSPECIFIED 를 뜻하는 정상 값이다.
- **KST 변환을 명시하지 않는 것.** `'unixepoch'` 만 쓰면 UTC 다. 답을 제출할 때는 `'+9 hours'` 로 명시하거나 UTC 임을 적는다.

## mini example

```text
문제:
"History 파일이 삭제된 PC 다. 사용자가 2026-05-11 에 접속한 웹메일 도메인과
 그 세션이 정상 종료되었는지 판단하시오."
첨부: User Data 폴더 덤프 (History 없음)

1. 무엇이 남았는지 확인
   $ find "User Data" -maxdepth 3 -type f | sort
   User Data/Local State
   User Data/Default/Network/Cookies
   User Data/Default/Network/Cookies-wal
   User Data/Default/Login Data
   -> History 는 정말 없다. Cookies 로 간다.

2. 첫 시도 (실패):
   $ sqlite3 "User Data/Default/Network/Cookies" \
       "SELECT host_key, name, value FROM cookies LIMIT 5;"

   accounts.example.co.kr|SESSIONID|
   mail.example.co.kr|EX_SID|
   .example.co.kr|_ga|

   value 가 전부 비어 있다. "DB 가 깨졌다"고 판단해 다른 파일로 넘어가려 했다.

3. 왜 틀렸나 — 컬럼을 잘못 봤다
   $ sqlite3 "User Data/Default/Network/Cookies" ".schema cookies" | tr ',' '\n' | grep -i value
     value TEXT NOT NULL
     encrypted_value BLOB DEFAULT ''

   $ sqlite3 "User Data/Default/Network/Cookies" \
       "SELECT name, length(value), length(encrypted_value),
               substr(hex(encrypted_value),1,6) FROM cookies LIMIT 3;"
   SESSIONID|0|156|763130
   EX_SID|0|132|763130
   _ga|0|84|763130

   763130 = "v10". 정상이다. 값은 암호화됐고 키는 Local State + DPAPI 다.
   이미지만 있으므로 복호화는 포기한다. 메타데이터로 답한다.

4. 접근 변경 — 사본 + wal 로 다시 열고 도메인·시각을 뽑는다
   $ cp "User Data/Default/Network/Cookies" c.db
   $ cp "User Data/Default/Network/Cookies-wal" c.db-wal
   $ sqlite3 -header -column c.db "
     SELECT host_key, count(*) AS n,
            datetime(min(creation_utc)/1000000-11644473600,'unixepoch','+9 hours') AS first_kst,
            datetime(max(last_access_utc)/1000000-11644473600,'unixepoch','+9 hours') AS last_kst
     FROM cookies GROUP BY host_key ORDER BY max(last_access_utc) DESC;"

   host_key                  n   first_kst            last_kst
   mail.example.co.kr        6   2026-05-11 09:41:22  2026-05-11 18:07:55
   accounts.example.co.kr    3   2026-05-11 09:41:05  2026-05-11 09:41:31
   .doubleclick.example      2   2026-05-11 10:02:13  2026-05-11 17:58:40

   -> accounts 에서 인증 -> mail 로 이동. 활동 구간 09:41 ~ 18:07 KST.
      doubleclick 은 광고 추적이므로 사용자 행위 증거에서 제외한다.

5. 세션 정상 종료 여부
   $ sqlite3 -header -column c.db "
     SELECT host_key, name, has_expires, is_persistent,
            datetime(creation_utc/1000000-11644473600,'unixepoch','+9 hours') AS created_kst
     FROM cookies WHERE is_persistent = 0;"

   host_key             name       has_expires  is_persistent  created_kst
   mail.example.co.kr   EX_SID     0            0              2026-05-11 18:05:12

   -> 세션 쿠키가 디스크에 남아 있다. 원래 종료 시 사라지는 쿠키다.
      = 브라우저가 정상적으로 닫히지 않았거나 세션 복원 설정이 켜져 있었다.

6. 교차검증
   $ sqlite3 "User Data/Default/Login Data" \
       "SELECT origin_url, username_value FROM logins;"
   https://accounts.example.co.kr/login|jhkim@example.co.kr
   -> 계정은 Login Data 에서 평문으로 확인된다 (비밀번호는 암호화).

정답: 웹메일 도메인 mail.example.co.kr (인증은 accounts.example.co.kr),
      활동 구간 2026-05-11 09:41:22 ~ 18:07:55 KST,
      is_persistent=0 세션 쿠키가 디스크에 남아 정상 종료되지 않은 것으로 판단.
      쿠키 값은 v10 (DPAPI+AES-GCM) 이라 이미지만으로는 복호화 불가.
```

2단계의 오판이 핵심이다. **`value` 가 비어 있는 것은 손상이 아니라 설계**이며, 그것을 알면 `encrypted_value` 를 건드리지 않고 메타데이터만으로 답이 나온다.

## 출처

- SRC-008 — Chromium source: `cookies` 테이블 스키마, `value`/`encrypted_value` 이원 저장, `CookieSameSite`·`CookiePriority`·`CookieSourceScheme` 정수값, `os_crypt` 키 보관 구조
- SRC-011 — SQLite 문서: `datetime(..., 'unixepoch')`, `hex()`, `length()`, `PRAGMA wal_checkpoint`
- `cookies` 테이블 컬럼명과 개수는 Chrome/Edge 버전마다 바뀐다(`secure` → `is_secure`, `firstpartyonly` → `samesite`, `top_frame_site_key`·`source_port`·`last_update_utc` 추가 등). **쿼리 전에 반드시 `.schema cookies` 로 실제 컬럼을 확인할 것.**
- `Cookies` 파일이 `Default\` 에서 `Default\Network\` 로 이동한 시점과 `v20`(App-Bound Encryption)의 정확한 도입 버전은 배포 버전에 따라 다르므로 실제 파일 위치와 접두 바이트를 직접 확인할 것
