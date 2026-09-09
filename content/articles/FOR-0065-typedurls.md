---
id: FOR-0065
title: "TypedURLs와 TypedURLsTime으로 직접 입력한 URL과 그 시각 구하기"
slug: "typedurls"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["TypedURLs", "TypedURLsTime", "NTUSER.DAT", "WebCacheV01.dat", "typed_count"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat", "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"]
registry_paths: ["NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLs", "HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs", "NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLsTime", "HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLsTime"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "DB Browser for SQLite", "FTK Imager", "KAPE"]
commands: ["rip.exe -r NTUSER.DAT -p typedurls", "rip.exe -r NTUSER.DAT -p typedurlstime", "sqlite3 History \"SELECT url, typed_count FROM urls WHERE typed_count > 0;\""]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["url1", "TypedURLsTime", "typed_count", "visit_count", "last_visit_time", "transition"]
file_formats: ["regf", "sqlite", "ese"]
primary_terms: ["TypedURLs", "IE 주소창 입력", "TypedURLsTime"]
keywords: ["TypedURLs", "TypedURLsTime", "url1", "IE 주소창", "직접 입력한 URL", "typed_count", "FILETIME", "Internet Explorer", "Edge Chromium", "브라우저 히스토리 교차검증"]
aliases: ["typedurls", "직접 입력한 url", "주소창에 친 주소", "ie 주소창 기록", "typedurlstime", "url 입력 시각", "타이핑한 url"]
symptom_keywords: ["사용자가 직접 입력한 URL을 알고 싶다", "URL을 언제 입력했는지 알고 싶다", "레지스트리에 크롬 기록이 없다", "주소를 타이핑한 증거가 필요하다", "url1이 무슨 값인지", "링크 클릭인지 직접 입력인지 구분해야 한다"]
related: ["FOR-0057", "FOR-0064", "FOR-0062", "FOR-0191"]
source_ids: ["SRC-017", "SRC-014", "SRC-008"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`Software\Microsoft\Internet Explorer\TypedURLs`의 `url1`..`urlN`은 사용자가 **IE 주소창에 직접 타이핑한 URL**이고, Windows 8/IE10 이후에는 같은 이름의 값을 가진 `TypedURLsTime` 서브키가 각 항목의 8바이트 FILETIME을 담아 **항목별 시각까지** 알려준다. 단 Chrome은 여기에 전혀 남지 않는다.

## 어떤 문제에서 필요한가

- "사용자가 주소를 직접 입력해 접속한 사이트는 무엇인가" — 링크 클릭이 아니라 **의도적 접속**
- "그 URL을 입력한 시각은 언제인가" — `TypedURLsTime`이 있으면 항목별로 확정된다
- "브라우저 프로필이 지워졌는데 접속 흔적이 필요하다" — 레지스트리는 브라우저 캐시 정리와 별개로 남는다
- "피싱 사이트에 스스로 들어간 것인가 링크를 타고 간 것인가"

`TypedPaths`([FOR-0064](./typedpaths.html))가 파일 경로 입력을 담당하는 것과 정확히 대칭이다. `TypedPaths`는 탐색기 주소창, `TypedURLs`는 IE 주소창이다.

## 문제에서 처음 볼 단서

1. 첨부에 `NTUSER.DAT`이 있고 지문에 "직접 입력", "주소를 쳐서", "타이핑한 URL"
2. 브라우저 프로필·히스토리 DB가 없거나 비워져 있는데 웹 접속 증거가 필요한 상황
3. 레지스트리 값 이름이 `url1`, `url2`이고 데이터가 `http://`로 시작한다
4. 그 옆에 `TypedURLsTime` 서브키가 보인다 → **항목별 시각을 확보할 수 있다**

## 30초 절차

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p typedurls
```

GUI라면 RegistryExplorer로 `NTUSER.DAT`을 열고 두 키를 나란히 본다.

```text
NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs
NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLsTime
```

Chrome이 문제라면 레지스트리를 볼 필요가 없다. 곧바로 History SQLite로 간다.

```powershell
sqlite3 "C:\case\History" "SELECT url, typed_count FROM urls WHERE typed_count > 0;"
```

## 상세 절차

### 1단계 — hive 확보와 로그 반영

```powershell
rla.exe -f "C:\case\NTUSER.DAT" --out "C:\case\clean"
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedurls > typedurls.txt
```

`NTUSER.DAT.LOG1`/`.LOG2`를 같은 폴더에 함께 두고 replay한다. 마지막 입력이 로그에만 남아 있는 경우가 흔하다.

### 2단계 — 두 키의 구조

| 항목 | `TypedURLs` | `TypedURLsTime` |
| --- | --- | --- |
| 경로 | `Software\Microsoft\Internet Explorer\TypedURLs` | `Software\Microsoft\Internet Explorer\TypedURLsTime` |
| 값 이름 | `url1`, `url2`, `url3` ... | 같은 이름(`url1`, `url2` ...)으로 대응 |
| 값 타입 | `REG_SZ` (읽을 수 있는 문자열) | `REG_BINARY` 8바이트 |
| 데이터 | 입력한 URL 전체 | **FILETIME (1601 기준 100ns, UTC)** |
| 순서 | `url1`이 가장 최근 | 값 이름이 `TypedURLs`와 1:1 대응 |
| 존재 조건 | IE 전 버전 | **Windows 8 / IE10 이후** |

`TypedURLsTime`이 있으면 `url3`을 입력한 시각까지 특정할 수 있다. 없으면 얻을 수 있는 시각은 **`TypedURLs` 키의 LastWrite 하나**이고 그것은 `url1`에만 대응한다.

이 두 키 외에 다른 형제 키가 보이면 이름만 기록하고 **의미를 추측하지 말고 파서 출력으로 확인한다.** 신뢰할 수 있는 것은 `TypedURLs`와 `TypedURLsTime` 두 개다.

### 3단계 — TypedURLsTime의 8바이트를 읽는다

`REG_BINARY` 8바이트를 **리틀엔디언**으로 붙여 FILETIME 정수로 읽는다.

```text
TypedURLsTime\url1 (8 바이트, 리틀엔디언):
00 06 08 86 84 B3 DC 01

리틀엔디언 -> 0x01DCB38486080600 = 134179470680000000
FILETIME(100ns) -> 초 = 134179470680000000 / 10000000 = 13417947068
Unix epoch 로 = 13417947068 - 11644473600 = 1773473468
-> 2026-03-14 07:31:08 UTC
-> KST 로 = 2026-03-14 16:31:08
```

| 상수 | 값 | 용도 |
| --- | --- | --- |
| FILETIME 단위 | 100ns | 1초 = `10000000` |
| FILETIME 기준 | 1601-01-01 UTC | Windows 계열 공통 |
| Unix epoch 차이 | `11644473600`초 | FILETIME초 − 이 값 = Unix time |
| KST 보정 | +9시간 (`32400`초) | UTC 기준값에 더한다 |

DCode나 Timeline Explorer에 8바이트를 넣으면 바로 변환되지만, 위 산식을 알고 있으면 계산기만으로도 검증된다.

### 4단계 — 출력 읽기

```powershell
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedurls > typedurls.txt
```

```text
TypedURLs
Software\Microsoft\Internet Explorer\TypedURLs
LastWrite Time: 2026-03-14 07:31:08Z

  url1 -> http://filehost.example/upload
  url2 -> https://mail.example.co.kr
  url3 -> http://192.168.10.55:8080/
  url4 -> https://www.naver.com/
```

`TypedURLsTime`까지 있으면 항목별 시각이 붙는다.

```text
TypedURLsTime
Software\Microsoft\Internet Explorer\TypedURLsTime
LastWrite Time: 2026-03-14 07:31:08Z

  url1 -> 2026-03-14 07:31:08Z
  url2 -> 2026-03-14 06:58:44Z
  url3 -> 2026-03-13 22:15:03Z
  url4 -> 2026-03-10 01:02:19Z
```

이 조합이 있으면 **입력 URL의 완전한 타임라인**이 만들어진다. 레지스트리 artifact 중에서 항목별 시각이 있는 것은 드물다.

### 5단계 — Chrome은 여기에 없다: History DB로 간다

이것이 이 글에서 가장 자주 오답을 만드는 지점이다. **Chrome은 입력 URL을 레지스트리에 쓰지 않는다.** `TypedURLs`는 IE와 레거시 Edge 계열 전용이다.

Chrome의 "직접 입력했는가"는 History SQLite의 `urls.typed_count`가 답한다.

```sql
SELECT id,
       url,
       title,
       typed_count,
       visit_count,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS last_visit_utc
FROM urls
WHERE typed_count > 0
ORDER BY last_visit_time DESC;
```

```text
id   url                                    typed_count  visit_count  last_visit_utc
41   http://filehost.example/upload         3            9            2026-03-14 07:31:08
17   https://mail.example.co.kr             12           88           2026-03-14 06:58:44
9    http://192.168.10.55:8080/             1            2            2026-03-13 22:15:03
```

방문 단위로 더 정확히 보려면 `visits.transition`의 하위 8비트(core type)를 본다.

| core transition | 값 | 의미 |
| --- | --- | --- |
| `LINK` | `0` | 링크 클릭 |
| `TYPED` | `1` | **주소창에 직접 입력** |
| `AUTO_BOOKMARK` | `2` | 북마크 |
| `AUTO_SUBFRAME` | `3` | 프레임 자동 로드 |
| `MANUAL_SUBFRAME` | `4` | 프레임 수동 |
| `GENERATED` | `5` | 주소창 제안/검색으로 생성 |
| `FORM_SUBMIT` | `7` | 폼 전송 |
| `RELOAD` | `8` | 새로고침 |
| `KEYWORD` | `9` | 검색 키워드 |

```sql
SELECT datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS visit_utc,
       u.url,
       v.transition & 0xFF AS core_transition
FROM visits v JOIN urls u ON u.id = v.url
WHERE (v.transition & 0xFF) = 1
ORDER BY v.visit_time DESC;
```

Chrome/Edge의 시각은 **WebKit 시각**으로 1601-01-01 기준 **마이크로초**다. 초로 바꿀 때 `1000000`으로 나눈 뒤 `11644473600`을 빼면 Unix time이 된다. 자세한 스키마는 [FOR-0191](./chrome-history.html)에서 다룬다.

### 6단계 — 브라우저별로 어디를 볼 것인가

| 브라우저 | 입력 URL 증거 위치 | 형식 |
| --- | --- | --- |
| Internet Explorer (전 버전) | `HKCU\Software\Microsoft\Internet Explorer\TypedURLs` | REG_SZ |
| IE 10+ / Windows 8+ | 위 + `TypedURLsTime` (8바이트 FILETIME) | REG_BINARY |
| IE 10+ 방문 이력 전체 | `%LocalAppData%\Microsoft\Windows\WebCache\WebCacheV01.dat` | ESE 데이터베이스 |
| Edge (Chromium 기반, 현행) | `%LocalAppData%\Microsoft\Edge\User Data\Default\History` | SQLite. Chrome과 **같은 스키마** |
| Edge 레거시 (Spartan) | `%LocalAppData%\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\...` 아래 ESE DB | 경로가 빌드마다 달라 실제 이미지에서 확인 |
| Chrome | `%LocalAppData%\Google\Chrome\User Data\Default\History` | SQLite (`urls.typed_count`) |
| Firefox | `%AppData%\Mozilla\Firefox\Profiles\<프로필>\places.sqlite` | SQLite (`moz_places`) |

현행 Edge는 Chromium 기반이므로 **레지스트리 `TypedURLs`가 아니라 Chrome과 동일한 History SQLite**를 본다. `TypedURLs`에 값이 있다는 것은 그 시스템에서 IE(또는 IE 엔진을 쓰는 프로그램)가 실제로 사용됐다는 뜻이기도 하다.

## 출력 필드 해석

| 필드 | 해석 | 주의 |
| --- | --- | --- |
| `TypedURLs\url1` | 가장 최근에 입력한 URL | 숫자가 클수록 오래됨 |
| `TypedURLsTime\urlN` | 그 항목의 입력 시각(FILETIME, UTC) | 8바이트 리틀엔디언 |
| `TypedURLs` 키 LastWrite | `url1` 입력 시각 | `TypedURLsTime`이 없을 때의 유일한 시각 |
| Chrome `typed_count` | 그 URL을 주소창에 입력한 **누적 횟수** | 0이면 링크·리다이렉트로만 방문 |
| Chrome `visit_count` | 총 방문 횟수 | `typed_count`보다 항상 크거나 같다 |
| Chrome `visits.transition & 0xFF` | 방문 단위 유입 경로 | `1`(TYPED)이 직접 입력 |
| Chrome `last_visit_time` | WebKit 마이크로초(1601 기준) | `/1000000 - 11644473600` |

## pivot: 다음에 볼 artifact

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 입력한 도메인/URL | 브라우저 History (`urls`/`visits`) | 실제 방문 여부, 방문 횟수, 유입 경로 |
| 입력한 URL | 브라우저 `downloads` 테이블 | 그 사이트에서 받은 파일과 저장 경로 |
| 도메인 | DNS 캐시·PCAP | 실제 이름 질의와 통신 발생 |
| URL의 IP:포트 | PCAP·프록시 로그 | 업로드/다운로드 트래픽 |
| 입력 시각 | UserAssist ([FOR-0061](./userassist.html)) | 그 시각 전후에 어떤 프로그램을 실행했는가 |
| 다운로드 파일명 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일 생성 시각과 현재 존재 여부 |
| 업로드 의심 URL | HTTP POST 추적 | 실제 전송 본문 |
| 사용자 식별 | `ProfileList`·SAM ([FOR-0052](./sam-user-accounts.html)) | 어느 계정의 `NTUSER.DAT`인가 |

## 흔한 함정

- **Chrome 기록을 `TypedURLs`에서 찾는다.** 가장 흔한 오답 경로다. Chrome은 레지스트리에 입력 URL을 남기지 않는다 → Chrome은 `History` SQLite의 `urls.typed_count`와 `visits.transition & 0xFF = 1`로 간다.
- **현행 Edge를 IE와 같이 취급한다.** Chromium 기반 Edge는 Chrome과 같은 SQLite 스키마를 쓴다 → `%LocalAppData%\Microsoft\Edge\User Data\Default\History`를 본다.
- **`url1`을 최초 입력으로 읽는다.** `url1`이 **가장 최근**이다 → 시간 순서를 물으면 역순으로 나열한다.
- **`TypedURLsTime`이 없는데 항목별 시각을 적는다.** Windows 7/IE9 이하 환경에는 이 서브키가 없다. 그때 얻을 수 있는 시각은 키 LastWrite 하나이고 `url1`에만 대응한다 → 나머지는 History DB나 `WebCacheV01.dat`로 채운다.
- **8바이트를 빅엔디언으로 읽는다.** 리틀엔디언이다. `00 06 08 86 84 B3 DC 01`은 `0x01DCB38486080600`이다 → 바이트를 역순으로 붙인다.
- **FILETIME을 초 단위로 착각한다.** 100ns 단위다. `10000000`으로 나눠야 초가 되고, 거기서 `11644473600`을 빼야 Unix time이다 → WebKit(마이크로초)과 단위가 다르다는 점도 함께 기억한다.
- **`typed_count > 0`을 "마지막 방문이 입력이었다"로 읽는다.** `typed_count`는 누적 횟수다. 마지막 방문이 링크 클릭이었을 수도 있다 → 방문 단위 판단은 `visits.transition`으로 한다.
- **비어 있으면 "웹 접속 없음"으로 단정한다.** IE를 안 썼으면 당연히 비어 있다. 항목은 상한을 넘으면 밀려 나가고 "인터넷 사용 기록 삭제"로도 지워진다 → 브라우저별 위치 표를 전부 훑는다.
- **`TypedURLs`가 곧 방문 성공을 뜻한다고 본다.** 입력 사실의 기록이므로, 접속 실패·오타 URL도 남을 수 있다 → 실제 방문은 History·PCAP로 확인한다.
- **사용자를 하나만 본다.** `NTUSER.DAT`은 사용자별이다. 모든 프로필을 파싱한다.
- **시간대를 안 맞춘다.** FILETIME과 WebKit 모두 UTC다. KST 답을 요구하면 +9시간. 시스템 시간대는 [FOR-0054](./system-timezone.html)로 확인한다.

## 교차검증

"직접 입력했다"를 최소 두 곳에서 확인한다.

```powershell
# 1) 레지스트리 — IE 주소창 입력과 항목별 시각
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedurls
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedurlstime

# 2) Chrome / Edge(Chromium) — typed_count 로 같은 질문
sqlite3 "C:\case\History" "SELECT url, typed_count, visit_count FROM urls WHERE typed_count > 0 ORDER BY last_visit_time DESC LIMIT 20;"

# 3) 방문 단위 유입 경로 (TYPED = 1)
sqlite3 "C:\case\History" "SELECT u.url, v.transition & 255 FROM visits v JOIN urls u ON u.id=v.url WHERE (v.transition & 255)=1;"

# 4) 다운로드 흔적
sqlite3 "C:\case\History" "SELECT target_path, tab_url, total_bytes FROM downloads;"
```

| 조합 결과 | 해석 |
| --- | --- |
| `TypedURLs` O, History O | IE로 입력 후 방문 확정 |
| `TypedURLs` O, History X | IE 히스토리가 정리되었거나 `WebCacheV01.dat`을 확보하지 못했다 |
| `TypedURLs` X, Chrome `typed_count` > 0 | Chrome 사용자다. 레지스트리에는 원래 안 남는다 |
| `TypedURLs` X, History X, PCAP에 통신 O | 브라우저 흔적이 정리됨(반포렌식) 또는 브라우저가 아닌 도구의 통신 |
| `typed_count` 0인데 방문 다수 | 링크·리다이렉트 유입. 고의성 주장은 약해진다 |

## mini walkthrough

```text
문제:
"사용자가 자료를 업로드한 사이트의 URL과, 그 URL을 주소창에 입력한
 시각(KST)을 구하세요.
 첨부: NTUSER.DAT (+ .LOG1/.LOG2), Chrome User Data\Default 폴더"

1. 첫 시도 (실패)
   rip.exe -r NTUSER.DAT -p typedurls
   -> TypedURLs 키가 존재하지 않는다는 출력.
      "직접 입력한 URL 없음" 이라고 결론.

   왜 틀렸는가:
   TypedURLs 는 Internet Explorer 전용 키다.
   이 시스템의 브라우저는 Chrome 이므로 레지스트리에는 애초에 남지 않는다.
   첨부에 Chrome User Data 폴더가 함께 온 것이 이미 힌트였다.

2. 피벗 1 — Chrome History 로 이동
   sqlite3 History "SELECT url, typed_count, visit_count,
     datetime(last_visit_time/1000000 - 11644473600,'unixepoch')
     FROM urls WHERE typed_count > 0 ORDER BY last_visit_time DESC;"

   http://filehost.example/upload   3   9   2026-03-14 07:31:08
   https://mail.example.co.kr      12  88   2026-03-14 06:58:44

3. 두 번째 실수
   typed_count 3 을 보고 "마지막 방문도 직접 입력" 이라고 단정했다.
   typed_count 는 누적 횟수이므로 마지막 방문의 유입 경로는 알 수 없다.

4. 피벗 2 — 방문 단위 transition 으로 확정
   sqlite3 History "SELECT datetime(v.visit_time/1000000 - 11644473600,'unixepoch'),
     u.url, v.transition & 255
     FROM visits v JOIN urls u ON u.id=v.url
     WHERE u.url LIKE '%filehost.example%' ORDER BY v.visit_time;"

   2026-03-13 22:41:10  http://filehost.example/upload  1   <- TYPED
   2026-03-14 06:12:55  http://filehost.example/upload  0   <- LINK
   2026-03-14 07:31:08  http://filehost.example/upload  1   <- TYPED

   -> 마지막 방문도 TYPED(1) 이 맞았다. 다만 근거가 typed_count 가 아니라
      transition 이어야 했다.

5. 업로드 증거 보강
   sqlite3 History "SELECT target_path, tab_url FROM downloads;"
   -> 다운로드는 없음. 업로드는 History 에 남지 않는다.
      PCAP 이 있으면 HTTP POST 로, 없으면 $MFT/LNK 로 원본 파일 접근을 본다.

6. 시간대 변환
   07:31:08 UTC + 9h = 2026-03-14 16:31:08 KST

정답: http://filehost.example/upload / 2026-03-14 16:31:08 KST

참고 (IE 환경이었다면):
   TypedURLs\url1        = http://filehost.example/upload
   TypedURLsTime\url1    = 00 06 08 86 84 B3 DC 01
                         = 0x01DCB38486080600 = 134179470680000000
                         = 2026-03-14 07:31:08 UTC = 16:31:08 KST
   같은 답에 도달한다.
```

## 막혔을 때 다음 체크

1. **브라우저를 먼저 확정했는가** — Chrome/현행 Edge면 레지스트리가 아니라 History SQLite다
2. **`TypedURLsTime` 서브키가 있는가** — 있으면 항목별 시각을 그대로 쓴다
3. **8바이트를 리틀엔디언으로 읽었는가**
4. **`url1`이 최근이라는 방향을 맞게 잡았는가**
5. **`rla`로 `.LOG1`/`.LOG2`를 반영했는가**
6. `TypedURLs`가 비어 있다 → `WebCacheV01.dat`(IE10+) → Chrome/Edge `History` → Firefox `places.sqlite` 순으로 이동
7. 링크 유입인지 직접 입력인지가 쟁점이다 → Chrome은 `visits.transition & 0xFF`, IE는 `TypedURLs` 존재 자체
8. 업로드가 쟁점이다 → History에는 업로드가 남지 않는다. PCAP의 HTTP POST와 원본 파일 접근 흔적으로 간다
9. 사용자가 여러 명인가 → 모든 프로필의 `NTUSER.DAT`과 브라우저 프로필. hive 위치는 [FOR-0051](./registry-hive-map.html)

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `NTUSER.DAT`의 위치와 `HKCU` 매핑, hive가 사용자별이라는 근거
- SRC-014 — Microsoft Learn, File Times: `TypedURLsTime`의 8바이트 해석 기준(1601-01-01 UTC, 100ns 단위)과 `11644473600` 보정
- SRC-008 — Chromium source, components/history/core/browser: `urls.typed_count`, `visits.transition`의 core PageTransition 값과 WebKit 시각(1601 기준 마이크로초) 스키마
- 레거시 Edge(Spartan)의 데이터베이스 경로는 Windows 빌드마다 달라 여기서 단정하지 않았다. 실제 이미지에서 확인할 것
- `TypedURLs`가 보관하는 항목 수의 상한은 버전에 따라 다르므로 실제 키의 값 개수로 확인할 것
- `TypedURLs`/`TypedURLsTime` 외의 형제 키가 관측되면 의미를 추측하지 말고 파서 출력으로 확인할 것
- 플러그인 이름은 배포 버전에 따라 다르므로 `rip.exe -l`로 확인할 것
