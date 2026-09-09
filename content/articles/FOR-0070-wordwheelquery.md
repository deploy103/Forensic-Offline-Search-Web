---
id: FOR-0070
title: "WordWheelQuery로 탐색기 검색창에 입력한 검색어 복원"
slug: "wordwheelquery"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["WordWheelQuery", "MRUListEx", "NTUSER.DAT", "Windows.edb", "keyword_search_terms"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb", "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"]
registry_paths: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "RECmd", "rla", "HxD", "FTK Imager", "KAPE"]
commands: ["rip.exe -r NTUSER.DAT -p wordwheelquery", "rla.exe -f NTUSER.DAT --out .", "RegistryExplorer.exe"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["MRUListEx", "MRU Position", "LastWrite"]
file_formats: ["regf"]
primary_terms: ["WordWheelQuery", "탐색기 검색어", "윈도우 검색 기록"]
keywords: ["WordWheelQuery", "탐색기 검색어", "검색 기록", "MRUListEx", "UTF-16LE", "NTUSER.DAT", "Windows Search", "Windows.edb", "keyword_search_terms", "사용자 의도"]
aliases: ["wordwheelquery", "탐색기에서 검색한 단어", "윈도우 검색 기록", "무엇을 검색했나", "검색창 입력 기록", "파일 검색 흔적", "검색어 복원"]
symptom_keywords: ["사용자가 무엇을 검색했는지 알고 싶다", "탐색기 검색 기록을 찾아야 한다", "검색어가 이진값으로 보인다", "어떤 파일을 찾으려 했는지", "브라우저 검색어와 구분해야 한다", "고의성을 검색어로 증명해야 한다"]
related: ["FOR-0057", "FOR-0062", "FOR-0064", "FOR-0068"]
source_ids: ["SRC-017", "SRC-099", "SRC-083"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`WordWheelQuery`의 값 `0`, `1`, `2` ... 는 사용자가 **탐색기(파일 탐색기) 검색창에 입력한 검색 문자열**을 UTF-16LE 이진값으로 담고, `MRUListEx`가 그 순서를 앞에서부터 최신순으로 알려준다. "무엇을 찾으려 했는가" = 사용자 의도를 그대로 보여주는 직접 증거다.

## 어떤 문제에서 필요한가

- "피의자가 무엇을 찾으려 했는가" — 검색어 자체가 목적의 진술이다
- "특정 인물·계좌·파일명을 알고 있었는가" — 그 문자열을 검색했다면 알고 있었다
- "자료를 어떻게 특정해 수집했는가" — 검색어가 수집 기준을 드러낸다
- "삭제한 파일의 원래 이름은 무엇이었나" — 검색어에 파일명이 남는 경우가 있다

`RecentDocs`는 열어본 결과를, ShellBags는 탐색한 경로를 보여준다. `WordWheelQuery`만이 **행위 이전의 의도**를 보여준다. 검색어는 반박이 어려운 진술성 증거라 배점이 큰 문제에 자주 나온다.

## 문제에서 처음 볼 단서

1. 첨부에 `NTUSER.DAT`이 있고 지문에 "검색", "찾으려", "무엇을 찾았는가", "키워드"
2. 지문에 사람 이름·계좌번호·프로젝트명이 등장하고 그 인지 여부가 쟁점인 상황
3. 레지스트리 값 이름이 `0`, `1`, `2`이고 데이터가 이진값인데 `MRUListEx`가 함께 있다
4. hex 뷰에서 글자 사이에 `00`이 규칙적으로 끼어 있다 → UTF-16LE 문자열이다

## 30초 절차

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p wordwheelquery
```

GUI라면 RegistryExplorer로 `NTUSER.DAT`을 열고 다음 경로로 이동한다.

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```

RegistryExplorer는 값을 선택하면 하단에 hex와 함께 문자열 해석을 보여준다. 값이 이진값이라 **RegRipper 출력이나 파서 해석을 보는 것이 가장 빠르다.**

## 상세 절차

### 1단계 — hive 확보와 로그 반영

```powershell
rla.exe -f "C:\case\NTUSER.DAT" --out "C:\case\clean"
rip.exe -r "C:\case\clean\NTUSER.DAT" -p wordwheelquery > wwq.txt
```

`NTUSER.DAT`, `NTUSER.DAT.LOG1`, `NTUSER.DAT.LOG2`를 같은 폴더에 함께 꺼낸 뒤 replay한다. 검색은 세션 중 수시로 발생하므로 **마지막 검색어가 트랜잭션 로그에만 남기 쉽다.**

### 2단계 — 키 구조

| 항목 | 내용 |
| --- | --- |
| 키 | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` |
| 값 이름 | `0`, `1`, `2` ... (등록 순번) |
| 값 타입 | `REG_BINARY` |
| 값 데이터 | **UTF-16LE 널종료 문자열** = 검색어 |
| `MRUListEx` | `REG_BINARY`. 4바이트 리틀엔디언 DWORD 배열. 앞이 최신, 끝은 `FF FF FF FF` |
| 시각 | 개별 값에는 없음. **키 LastWrite 하나뿐** |
| 대상 | 파일 탐색기 검색창 입력 (Windows 7 이후) |

값 이름의 숫자는 **등록 순번**이고 최근순이 아니다. 순서는 오직 `MRUListEx`가 정한다. [FOR-0062](./recentdocs.html)의 `RecentDocs`와 완전히 같은 MRU 구조다.

### 3단계 — MRUListEx 읽기

```text
MRUListEx (16 바이트):
02 00 00 00  00 00 00 00  01 00 00 00  FF FF FF FF

해석: 2 -> 0 -> 1 -> (끝)
      값 이름 "2" 의 검색어가 가장 최근
```

| 바이트 | 값 | 의미 |
| --- | --- | --- |
| `0x00`–`0x03` | `02 00 00 00` | MRU 1위 = 값 이름 `2` |
| `0x04`–`0x07` | `00 00 00 00` | MRU 2위 = 값 이름 `0` |
| `0x08`–`0x0B` | `01 00 00 00` | MRU 3위 = 값 이름 `1` |
| `0x0C`–`0x0F` | `FF FF FF FF` | 배열 종료 표시 |

항목 개수는 `(MRUListEx 전체 길이 − 4) / 4`다. 마지막 4바이트는 데이터가 아니다.

### 4단계 — 값 데이터 수동 hex 확인

파서 출력을 신뢰하되, hex로도 직접 확인할 수 있어야 한다. UTF-16LE는 ASCII 글자마다 뒤에 `00`이 붙고, 문자열 끝은 `00 00`이다.

```text
값 이름: 2
데이터:
73 00 61 00 6C 00 61 00 72 00 79 00 00 00
s     a     l     a     r     y     (종료)

-> 검색어 "salary"
```

한글은 2바이트 코드 유닛이 그대로 리틀엔디언으로 들어간다.

```text
값 이름: 0
데이터:
00 B3 78 C6 44 BE 00 00

00 B3 -> U+B300 대
78 C6 -> U+C678 외
44 BE -> U+BE44 비
00 00 -> 종료

-> 검색어 "대외비"
```

```text
값 이름: 1
데이터:
40 AE A0 CC 18 C2 00 00

40 AE -> U+AE40 김
A0 CC -> U+CCA0 철
18 C2 -> U+C218 수

-> 검색어 "김철수"
```

| 확인 절차 | 방법 |
| --- | --- |
| 1. hex 확보 | RegistryExplorer에서 값 선택 → 하단 hex 패널, 또는 HxD로 hive 직접 열기 |
| 2. 인코딩 지정 | 1바이트가 아니라 **UTF-16LE(UTF-16 Little Endian)** 로 표시 전환 |
| 3. 종료 위치 | `00 00`(2바이트 널)까지가 한 문자열 |
| 4. 한글 검증 | 2바이트를 역순으로 붙여 코드포인트를 만든 뒤 문자 대조 |
| 5. 순서 확정 | `MRUListEx`의 DWORD 순서로 값 이름을 나열 |

### 5단계 — 출력 읽기

```powershell
rip.exe -r "C:\case\clean\NTUSER.DAT" -p wordwheelquery
```

```text
WordWheelQuery
Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
LastWrite Time: 2026-03-14 07:29:51Z

MRUListEx = 2,0,1,3
  2 = salary
  0 = 대외비
  1 = 김철수
  3 = 110-234-567890
```

읽는 순서는 이렇다.

1. `MRUListEx` 1위가 `2` → **가장 최근 검색어는 `salary`**
2. 키 LastWrite `2026-03-14 07:29:51Z`는 그 마지막 검색의 시각에 대응한다
3. 나머지 검색어의 시각은 알 수 없다
4. `110-234-567890` 같은 계좌 형태 문자열, 인명, `대외비` 같은 분류 표시는 **그 자체로 목적의 진술**이다

### 6단계 — 검색어를 사건과 연결한다

검색어의 형태만으로 무엇을 노렸는지 분류할 수 있다.

| 검색어 형태 | 예 | 시사점 | 다음에 볼 것 |
| --- | --- | --- | --- |
| 분류 표시 | `대외비`, `비밀`, `confidential`, `내부용` | 등급이 높은 문서를 표적 수집 | 그 문자열을 포함한 파일명 `$MFT` 검색 |
| 인명 | `김철수`, `홍길동` | 특정인 관련 자료 수집 | 인사·급여 폴더 접근 흔적 |
| 계좌·번호 | `110-234-567890`, `주민번호` | 금융/개인정보 수집 | 개인정보 파일 존재와 반출 경로 |
| 확장자 | `*.pst`, `.xlsx`, `*.pdf` | 형식 단위 대량 수집 | 압축·업로드 흔적 |
| 파일명 조각 | `급여`, `단가표`, `계약서` | 문서 표적 확인 | `RecentDocs`·LNK 대조 |
| 도구·기법 | `password`, `mimikatz`, `dump` | 공격 도구 탐색 | MUICache·Prefetch |
| 경로/공유명 | `backup`, `share` | 반출 대상 위치 탐색 | `TypedPaths`·`MountPoints2` |

검색어 하나가 답인 경우도 있고, 검색어 목록 전체가 **타임라인의 동기 구간**을 만들어 주는 경우도 있다.

### 7단계 — 어느 검색창이었는지 구분한다

`WordWheelQuery`는 **파일 탐색기 검색창** 입력을 대상으로 한다. 같은 "검색어"라도 입력 위치가 다르면 남는 곳이 다르다.

| 어디에 입력했나 | 남는 곳 | 형식 | 확인 방법 |
| --- | --- | --- | --- |
| **파일 탐색기 검색창** | `HKCU\...\Explorer\WordWheelQuery` | REG_BINARY (UTF-16LE) + `MRUListEx` | `rip.exe -p wordwheelquery` |
| 브라우저 검색창/검색엔진 | Chrome `History`의 `keyword_search_terms` 테이블 | SQLite | `SELECT term FROM keyword_search_terms` |
| 브라우저 주소창 URL 직접 입력 | Chrome `urls.typed_count` / IE `TypedURLs` | SQLite / REG_SZ | [FOR-0065](./typedurls.html) |
| 탐색기 주소창에 경로 입력 | `HKCU\...\Explorer\TypedPaths` | REG_SZ (`url1`...) | [FOR-0064](./typedpaths.html) |
| 실행(Win+R) 대화상자 | `HKCU\...\Explorer\RunMRU` | REG_SZ + `MRUList` | `rip.exe -p runmru` |
| Windows Search 색인 자체 | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | ESE 데이터베이스 | ESE 파서 |

Windows Search 색인(`Windows.edb`)은 **검색어 기록이 아니라 색인된 파일·속성의 저장소**다. "무엇을 검색했는가"의 답은 `WordWheelQuery`에 있고, "그 시점에 어떤 파일이 색인되어 있었는가"의 답이 `Windows.edb`에 있다. 두 역할을 혼동하면 엉뚱한 데이터베이스를 파싱하며 시간을 버린다.

시작 메뉴·작업 표시줄 검색은 Windows 버전에 따라 저장 위치가 달라 여기서 단정하지 않는다. **탐색기 검색창 이외의 입력이 쟁점이면 위 표의 다른 경로를 함께 확인한다.**

```powershell
# 브라우저 검색어는 레지스트리가 아니라 History DB 다
sqlite3 "C:\case\History" "SELECT term FROM keyword_search_terms ORDER BY rowid DESC LIMIT 20;"
```

## 출력 필드 해석

| 필드 | 해석 | 주의 |
| --- | --- | --- |
| 값 이름 (`0`,`1`,`2`...) | 등록 순번 | 숫자 크기가 최신순이 아니다 |
| 값 데이터 | UTF-16LE 검색어 | `00 00`까지가 한 문자열 |
| `MRUListEx` | 실제 검색 순서. 앞이 최신 | 마지막 `FF FF FF FF`는 종료 표시 |
| 키 `LastWrite` | 마지막 검색 시각(FILETIME, UTC) | MRU 1위 항목에만 대응 |
| 항목 수 | `(MRUListEx 길이 − 4) / 4` | 값 개수와 일치해야 정상 |

키 LastWrite는 FILETIME이므로 1601-01-01 UTC 기준 100ns 단위다. Unix epoch 차이는 `11644473600`초, KST는 +9시간이다. 시스템 시간대는 [FOR-0054](./system-timezone.html)의 `TimeZoneInformation`으로 확인한다.

## pivot: 다음에 볼 artifact

검색어는 "찾으려 했다"까지만 말한다. "찾았다"와 "가져갔다"는 다음 artifact가 답한다.

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 검색어 문자열 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 문자열을 포함한 파일명이 실제로 존재했는가 |
| 검색어와 일치하는 파일명 | `RecentDocs` | 검색 후 실제로 열었는가 |
| 검색어와 일치하는 파일명 | `%AppData%\Microsoft\Windows\Recent`의 LNK | 전체 경로와 접근 시각 |
| 검색 시각(LastWrite) | ShellBags ([FOR-0068](./shellbags.html)) | 같은 시각대에 어떤 폴더를 탐색했는가 |
| 검색 시각 | UserAssist ([FOR-0061](./userassist.html)) | 그 전후에 어떤 프로그램을 실행했는가 |
| 검색 대상 폴더 | `TypedPaths`·`MountPoints2` | 검색 후 어디로 이동/복사했는가 |
| 검색어가 개인정보 형태 | 개인정보 파일 존재·압축·업로드 흔적 | 반출 완료 여부 |
| 검색어가 도구명 | MUICache·Prefetch·Amcache | 그 도구를 실제로 받아 실행했는가 |
| 브라우저 검색어 | Chrome `keyword_search_terms` ([FOR-0191](./chrome-history.html)) | 외부 검색과의 연결 |

## 흔한 함정

- **값 이름 숫자를 최근순으로 읽는다.** `0`이 가장 오래된 것도, 가장 최근인 것도 아니다. 등록 순번일 뿐이다 → 순서는 반드시 `MRUListEx`로 정한다.
- **`FF FF FF FF`를 항목으로 센다.** 배열 종료 표시다 → 항목 수는 `(길이 − 4) / 4`다.
- **모든 검색어에 LastWrite 시각을 붙인다.** 개별 값에는 타임스탬프가 없다. 키 LastWrite 하나가 있을 뿐이고 MRU 1위에만 대응한다 → 나머지 검색 시각은 ShellBags·EVTX·`$MFT`로 간접 추정한다.
- **브라우저 검색어를 여기서 찾는다.** 구글·네이버 검색어는 `WordWheelQuery`에 없다. Chrome은 `History`의 `keyword_search_terms`다 → 어느 검색창이었는지부터 확정한다.
- **`Windows.edb`를 검색어 기록으로 오해한다.** `Windows.edb`는 색인된 **파일과 속성**의 저장소다. 검색어 기록이 아니다 → 검색어는 `WordWheelQuery`, 색인 내용은 `Windows.edb`다.
- **값 데이터를 ANSI로 읽어 깨진 문자로 판단한다.** UTF-16LE다. 1바이트 인코딩으로 보면 글자 사이에 `00`이 끼어 보인다 → 인코딩 표시를 UTF-16LE로 바꾸거나 파서를 쓴다.
- **한글 검색어의 바이트를 순서대로 붙인다.** 리틀엔디언이므로 `00 B3`은 `U+B300`이다 → 2바이트를 역순으로 붙인다.
- **비어 있으면 "검색하지 않았다"고 단정한다.** 항목은 상한을 넘으면 밀려 나가고, 검색 기록 삭제·정리 도구로 지워진다. 키는 있는데 값이 없으면 **삭제 정황**으로 본다 → 키 LastWrite, hive 슬랙, `$UsnJrnl`의 hive 변경을 확인한다.
- **검색어가 곧 결과를 뜻한다고 본다.** 검색은 실패할 수 있다. 아무 파일도 안 나왔을 수 있다 → 결과 확인은 `RecentDocs`·LNK·`$MFT`다. 다만 **실패한 검색도 의도의 증거**로서는 충분히 강하다.
- **사용자를 하나만 본다.** `NTUSER.DAT`은 사용자별이다. 누가 검색했는지가 답이면 모든 프로필을 파싱한다.
- **hive 로그를 반영하지 않는다.** `rla` 없이 파싱하면 마지막 검색어가 빠진다.
- **시간대를 안 맞춘다.** LastWrite는 UTC다. KST 답을 요구하면 +9시간.

## 교차검증

```powershell
# 1) WordWheelQuery — 탐색기 검색어와 순서
rip.exe -r "C:\case\clean\NTUSER.DAT" -p wordwheelquery

# 2) 검색어와 일치하는 파일이 실제로 있었나 (메타파일 경로는 반드시 작은따옴표)
MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
Import-Csv 'C:\case\out\mft.csv' | Where-Object { $_.FileName -match 'salary|대외비|김철수' }

# 3) 검색 후 실제로 열었나
rip.exe -r "C:\case\clean\NTUSER.DAT" -p recentdocs | Select-String 'salary'

# 4) 같은 시각대의 폴더 탐색
SBECmd.exe -d "C:\case\Users\jhkim" --csv "C:\case\out"

# 5) 브라우저 검색어 (레지스트리 아님)
sqlite3 "C:\case\History" "SELECT term FROM keyword_search_terms ORDER BY rowid DESC LIMIT 20;"
```

| 조합 결과 | 해석 |
| --- | --- |
| 검색어 O, 일치 파일 O, `RecentDocs` O | 검색 → 발견 → 열람. 완전한 사슬 |
| 검색어 O, 일치 파일 O, `RecentDocs` X | 찾았지만 열지는 않았다. 복사만 했을 수 있다. `$UsnJrnl` 확인 |
| 검색어 O, 일치 파일 X | 검색 실패, 또는 그 파일이 이미 삭제됨. `$UsnJrnl`·`$Recycle.Bin` 확인 |
| 검색어 X, `RecentDocs` O | 검색 없이 직접 접근. 경로를 이미 알고 있었다는 뜻 → `TypedPaths` 확인 |
| 검색어가 브라우저 쪽에만 O | 외부 검색만 했고 로컬 파일 검색은 없었다 |

## mini walkthrough

```text
문제:
"내부 자료 유출자가 자료를 특정하기 위해 사용한 검색어 중 가장 마지막
 검색어와 그 검색 시각(KST)을 구하세요.
 첨부: NTUSER.DAT(+LOG1/2), UsrClass.dat, $MFT"

1. 첫 시도 (실패)
   RegistryExplorer 로 NTUSER.DAT 을 열고
   Explorer\WordWheelQuery 의 값 목록을 확인.
   값 이름: 0, 1, 2, 3, MRUListEx
   -> 이름이 가장 큰 "3" 의 데이터를 읽어 "110-234-567890" 을 답으로 냈다. 오답.

   왜 틀렸는가:
   값 이름 숫자는 등록 순번이다. 최근순은 MRUListEx 만이 정한다.

2. 두 번째 실수
   값 "2" 의 데이터를 hex 로 보고 1바이트 인코딩으로 읽었다.
   73 00 61 00 6C 00 61 00 72 00 79 00 00 00
   -> "s.a.l.a.r.y." 처럼 점이 섞여 보여 "깨진 값" 이라고 판단했다.

   왜 틀렸는가:
   UTF-16LE 다. ASCII 글자마다 뒤에 00 이 붙는 것이 정상이다.
   인코딩을 UTF-16LE 로 바꾸면 "salary" 로 바로 읽힌다.

3. 피벗 1 — 로그 반영 후 파서로
   rla.exe -f NTUSER.DAT --out clean\
   rip.exe -r clean\NTUSER.DAT -p wordwheelquery

   LastWrite Time: 2026-03-14 07:29:51Z
   MRUListEx = 2,0,1,3
     2 = salary            <- MRU 1위 = 마지막 검색어
     0 = 대외비
     1 = 김철수
     3 = 110-234-567890    <- 이름은 최대지만 MRU 4위

4. 검증 — MRUListEx 원본 hex 를 직접 확인
   02 00 00 00  00 00 00 00  01 00 00 00  03 00 00 00  FF FF FF FF
   -> 20바이트. 항목 수 = (20-4)/4 = 4개. 값 개수와 일치.
      1위가 2 인 것이 확정.

5. 교차검증 — 검색어와 일치하는 파일이 있었나
   MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
   Import-Csv 'C:\case\out\mft.csv' |
     Where-Object { $_.FileName -match 'salary' }
   -> salary_2026Q1.xlsx  Created 2026-02-02  (현재 존재)
      salary.docx         삭제됨 -> $UsnJrnl 로 삭제 시각 추적 대상

6. 사슬 완성 — 검색 후 열었는가
   rip.exe -r clean\NTUSER.DAT -p recentdocs | Select-String 'salary'
   -> .xlsx 서브키 MRU 1위 = salary_2026Q1.xlsx
      RecentDocs\.xlsx LastWrite 2026-03-14 07:31:44Z
      검색(07:29:51) -> 열람(07:31:44). 2분 차이. 인과가 성립한다.

7. 시간대 변환
   07:29:51Z (UTC) + 9h = 2026-03-14 16:29:51 KST

정답: salary / 2026-03-14 16:29:51 KST
```

## 막혔을 때 다음 체크

1. **`MRUListEx`를 읽었는가** — 값 이름 숫자로 순서를 판단하지 않았는가
2. **`FF FF FF FF`를 항목에서 제외했는가** — 항목 수 = `(길이 − 4) / 4`
3. **인코딩을 UTF-16LE로 봤는가** — 글자 사이 `00`은 정상이다
4. **한글을 리틀엔디언으로 조립했는가** — `00 B3` = `U+B300`
5. **`rla`로 `.LOG1`/`.LOG2`를 반영했는가** — 마지막 검색어 누락의 주원인
6. **LastWrite를 MRU 1위에만 적용했는가**
7. 검색창 종류가 쟁점이다 → 브라우저는 `keyword_search_terms`, 탐색기 주소창은 `TypedPaths`, 실행 대화상자는 `RunMRU`
8. 비어 있다 → `RecentDocs` → ShellBags → LNK/Jump List → `Windows.edb` 순으로 이동
9. 검색어와 일치하는 파일이 없다 → `$UsnJrnl`·`$Recycle.Bin`으로 삭제 추적
10. 사용자가 여러 명인가 → 모든 프로필의 `NTUSER.DAT`. hive 위치는 [FOR-0051](./registry-hive-map.html)

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `NTUSER.DAT`의 위치와 `HKCU` 매핑, hive가 사용자별이라는 근거
- SRC-099 — RegRipper 3.0 repository: `wordwheelquery` 플러그인과 `rip.exe -r ... -p ...` 사용법, MRU 계열 플러그인의 출력 형식
- SRC-083 — Microsoft Learn, Windows Search / `Windows.edb`: 색인 데이터베이스의 역할과 위치(검색어 기록이 아니라 색인 저장소라는 구분 근거)
- 시작 메뉴·작업 표시줄 검색의 저장 위치는 Windows 버전에 따라 달라 여기서 단정하지 않았다. 탐색기 검색창 이외의 입력이 쟁점이면 실제 이미지에서 확인할 것
- `WordWheelQuery`가 보관하는 항목 수의 상한은 버전에 따라 다르므로 실제 키의 값 개수로 확인할 것
- 플러그인 이름은 배포 버전에 따라 다르므로 `rip.exe -l`로 확인할 것
