---
id: FOR-0059
title: "RegistryExplorer로 hive 열기: 북마크·플러그인·삭제 레코드"
slug: "registry-explorer"
category: "Registry"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["Registry hive", "dirty hive", "transaction log", "deleted record", "value slack"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE"]
registry_paths: []
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RECmd", "rla", "RegRipper", "Timeline Explorer"]
commands: ["RegistryExplorer.exe", "RECmd.exe -d C:\\case\\hives --bn BatchExamples\\Kroll_Batch.reb --csv C:\\case\\out", "rla.exe -d C:\\case\\hives --out C:\\case\\clean"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Value Name", "Value Type", "Data", "Value Slack", "Last Write Timestamp"]
file_formats: ["regf", "reb", "csv"]
primary_terms: ["RegistryExplorer", "레지스트리 익스플로러", "hive GUI 탐색"]
keywords: ["RegistryExplorer", "Registry Explorer", "RECmd", "Eric Zimmerman", "dirty hive", "트랜잭션 로그", "Available Bookmarks", "플러그인", "Deleted Records", "value slack", "batch", "reb", "hive GUI"]
aliases: ["레지스트리 익스플로러", "registry explorer 사용법", "hive 어떻게 여나", "레지스트리 뷰어", "recmd", "북마크로 찾기", "삭제된 레지스트리 값"]
symptom_keywords: ["hive 파일을 열 도구가 필요하다", "dirty hive 경고가 뜬다", "레지스트리 값이 인코딩되어 보인다", "어느 키를 봐야 할지 모르겠다", "삭제된 레지스트리 값을 복구하고 싶다", "regedit로 hive 파일이 안 열린다"]
related: ["FOR-0051", "FOR-0057", "FOR-0060", "FOR-0061"]
source_ids: ["SRC-004", "SRC-027", "SRC-017"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

RegistryExplorer는 `regf` hive 파일을 **트리로 직접 열어 보는** GUI 도구로, 트랜잭션 로그 반영·포렌식 키 북마크·플러그인 자동 디코딩·삭제 레코드 복구를 한 화면에서 처리한다. "어느 키를 봐야 할지 모를 때" 북마크 목록이 답을 대신 알려주는 것이 이 도구의 가장 큰 가치다.

## 어떤 문제에서 필요한가

- 확장자 없는 hive 파일(`SYSTEM`, `NTUSER.DAT`, `Amcache.hve`)이 첨부로 주어졌다
- RegRipper 플러그인이 없는 키, 또는 **문제 출제자가 임의로 만들어 넣은 키**를 찾아야 한다
- 값이 이진 데이터라 사람 눈으로는 못 읽는다 (UserAssist, AppCompatCache 등)
- 공격자가 지운 레지스트리 값을 복구해야 한다
- 키 하나의 LastWrite와 값의 원문 바이트를 직접 확인해 근거로 삼아야 한다

`regedit`는 hive **파일**을 열지 못한다(`파일 > 하이브 로드`로 마운트하면 라이브 레지스트리를 오염시키고 관리자 권한이 필요하다). 오프라인 hive는 전용 파서로 읽는다.

## 문제에서 처음 볼 단서

1. 첨부 파일 선두 4바이트가 `72 65 67 66`(`regf`) → hive다. 확장자와 무관하게 RegistryExplorer로 열린다
2. `.LOG1`/`.LOG2`가 hive와 같이 왔다 → dirty일 가능성이 높으니 로드 시 경고를 반드시 처리한다
3. 파일 이름이 뭉개졌거나 `unknown.dat` 형태 → 로드하면 트리 루트에 원래 hive 경로가 보여 정체가 드러난다
4. 지문이 "삭제된 설정", "지운 자동실행" → 삭제 레코드 복구가 답이다

## 30초 절차

```text
RegistryExplorer.exe → hive 파일을 창에 드래그앤드롭 → 좌측 트리에서 Available Bookmarks
```

1. hive와 `.LOG1`/`.LOG2`를 **같은 폴더에** 둔 상태로 hive를 드래그앤드롭한다(`File` 메뉴의 hive 로드와 동일)
2. dirty hive 경고가 뜨면 **트랜잭션 로그를 반영하는 쪽을 택한다.** 무시하면 최신 변경이 빠진다
3. 좌측의 북마크 목록에서 필요한 항목(UserAssist, Run, TypedPaths 등)을 골라 해당 키로 점프한다
4. 우측 값 목록에서 값을 클릭하고, 플러그인이 붙는 키라면 아래쪽에 디코딩된 표가 나온다
5. 결과를 CSV/TSV로 내보내 Timeline Explorer나 Excel로 넘긴다

CLI로 여러 hive를 한 번에 처리할 때는 자매 도구 RECmd를 쓴다.

```powershell
RECmd.exe -d 'C:\case\hives' --bn 'BatchExamples\Kroll_Batch.reb' --csv 'C:\case\out'
```

## 상세 절차

### 1단계 — hive 로드

| 방법 | 설명 |
| --- | --- |
| 드래그앤드롭 | 창에 파일을 끌어다 놓는다. 가장 빠르다 |
| `File` 메뉴의 hive 로드 | 파일 선택 대화상자로 고른다 |
| 여러 개 동시 로드 | hive를 여러 개 열면 트리에 루트가 여러 개 생긴다. `SYSTEM` + `SOFTWARE` + `NTUSER.DAT`을 함께 열고 비교하는 것이 실전 패턴 |

로드된 루트 노드에는 그 hive가 원래 있던 경로(base block `0x30`의 UTF-16LE 문자열)가 함께 보인다. **이름을 잃어버린 파일의 정체를 이걸로 확정한다.**

### 2단계 — dirty hive 경고와 트랜잭션 로그

hive의 base block에는 primary sequence number(`0x04`)와 secondary(`0x08`)가 있고, 두 값이 다르면 그 hive는 정상 종료되지 않은 **dirty** 상태다. 미반영 변경은 `.LOG1`/`.LOG2`에만 존재한다.

| 상황 | 도구의 반응 | 해야 할 일 |
| --- | --- | --- |
| dirty + 같은 폴더에 로그 있음 | dirty임을 알리고 로그를 반영할지 묻는다 | 반영을 택한다. 정리된 hive를 저장해 두면 재작업이 없다 |
| dirty + 로그 없음 | 로그가 없어 반영할 수 없다고 경고한다 | 이미지로 돌아가 `.LOG1`/`.LOG2`를 다시 추출한다 |
| clean | 경고 없이 열린다 | 그대로 진행 |

경고를 지나쳐 버렸거나 여러 hive를 일괄 처리해야 하면 CLI 도구 `rla`로 먼저 반영한다.

```powershell
# 폴더에 있는 모든 hive + 로그를 한 번에 반영해 clean hive 를 만든다
rla.exe -d 'C:\case\hives' --out 'C:\case\clean'
```

**이 단계를 건너뛰면 "마지막 실행", "마지막 입력", "마지막 마운트" 류의 답이 조용히 틀린다.** 값이 아예 안 보이는 것이 아니라 한 세대 이전 값이 보이기 때문에 눈치채기 어렵다.

### 3단계 — 트리 탐색과 값 목록

| 화면 영역 | 내용 |
| --- | --- |
| 좌측 트리 | 키 계층. 하위 키/값 개수와 키의 LastWrite를 함께 보여준다 |
| 우측 값 목록 | 선택한 키의 값들. 값 이름 / 타입(`RegSz`, `RegBinary`, `RegDword` 등) / 데이터 / **값 slack** |
| 값 상세 | 선택한 값의 원시 바이트를 hex와 문자열로 함께 보여준다 |
| 하단 플러그인 패널 | 그 키에 전용 플러그인이 있으면 디코딩 결과가 표로 나온다 |

**값 slack**은 값 데이터가 이전에 더 길었을 때 남는 잔여 바이트다. 값이 짧게 덮어써진 경우 이전 문자열의 뒷부분이 slack에 남아 있을 수 있어, 지워진 경로·URL의 단서가 된다. 다른 파서들은 대부분 보여주지 않는 정보다.

### 4단계 — 플러그인 (자동 디코딩)

포렌식적으로 중요한 키는 값이 이진 인코딩이라 눈으로 못 읽는다. 해당 키를 선택하면 플러그인이 이를 표로 풀어 준다.

| 대상 | 플러그인이 해주는 일 |
| --- | --- |
| UserAssist | ROT13 해제, Run Count / Focus Time / Last Executed 컬럼화 ([FOR-0061](./userassist.html)) |
| AppCompatCache (Shimcache) | 캐시 엔트리를 경로 + 순서 + 시각으로 분해 |
| RecentDocs, TypedURLs 류 MRU 키 | `MRUListEx` 순서를 풀어 최신순 정렬 |
| 계정/서비스 관련 키 | 이진 값(`F`/`V` 등)을 필드로 분해 |

플러그인이 붙는 키 목록은 배포 버전마다 늘어난다. 사용 중인 버전에서 무엇이 지원되는지는 프로그램 안의 플러그인 목록으로 확인한다. **ShellBags(`BagMRU`)는 구조가 커서 같은 제작자의 전용 도구(ShellBags Explorer)를 쓰는 것이 정석**이므로, RegistryExplorer에서 `BagMRU` 트리를 눈으로 훑어 위치만 확인하고 파싱은 전용 도구나 RegRipper로 넘긴다([FOR-0058](./usrclass-dat.html)).

### 5단계 — 북마크 (이 도구의 핵심 기능)

RegistryExplorer에는 **포렌식적으로 중요한 키를 미리 등록해 둔 북마크 목록**이 들어 있다. 좌측에서 북마크 목록을 열면 hive 종류별로 분류된 항목이 나오고, 항목을 고르면 그 키로 바로 이동한다. 트리에서도 북마크된 키는 표시가 되어 눈에 띈다.

| 왜 중요한가 | 설명 |
| --- | --- |
| 경로를 외울 필요가 없다 | `Software\Microsoft\Windows\CurrentVersion\Explorer\...`를 타이핑하지 않는다 |
| 체크리스트가 된다 | 그 hive에서 볼 만한 키가 목록으로 나오므로 빠뜨림이 줄어든다 |
| 처음 보는 hive에 유용하다 | `SECURITY`, `Amcache.hve` 처럼 익숙하지 않은 hive에서 시작점을 준다 |
| 사용자 북마크 추가 | 문제에서 반복해 보는 키를 직접 등록해 재사용한다 |

시간에 쫓기는 상황에서는 **북마크 목록을 위에서 아래로 훑는 것**이 가장 빠른 트리아지다.

### 6단계 — 검색 (Find)

키 이름을 모를 때 쓴다. 검색 대상을 고를 수 있다.

| 검색 대상 | 쓰는 상황 |
| --- | --- |
| 키 이름 | `USBSTOR`, `Run`, `BagMRU` 처럼 키 이름을 아는 경우 |
| 값 이름 | `MRUListEx`, `UserChoice` 등 |
| 값 데이터 | 경로·파일명·URL 문자열로 역추적. **가장 많이 쓴다** |
| 값 slack | 지워진 흔적 찾기 |

`AppData\Roaming`, `Temp`, `.ps1`, `http` 같은 문자열로 값 데이터를 검색하면 어느 키에 무엇이 박혀 있는지 한 번에 드러난다. 유니코드 문자열은 hive 안에서 UTF-16LE로 저장되므로, 문자열 검색이 안 잡히면 hex 검색으로 바꿔 시도한다.

### 7단계 — 삭제 레코드 복구 (Deleted Records)

레지스트리에서 키/값을 지워도 hive 파일의 셀은 즉시 재사용되지 않는다. RegistryExplorer는 이 미할당 셀에서 `nk`/`vk` 레코드를 복구해 별도로 보여준다.

| 복구 대상 | 얻을 수 있는 것 |
| --- | --- |
| 삭제된 키 | 키 이름과 LastWrite. 부모를 못 찾으면 부모 없는 항목으로 분류된다 |
| 삭제된 값 | 값 이름, 타입, 데이터 |

공격자가 자동실행 값을 지운 경우, 지운 사실 자체와 지워진 값의 내용이 여기서 나온다. 복구된 항목은 **부모 경로가 불확실할 수 있으므로** 결론을 낼 때는 "삭제 레코드에서 복구됨"을 명시하고 다른 아티팩트로 뒷받침한다.

### 8단계 — 내보내기와 RECmd

값 목록/플러그인 결과는 표 형태이므로 CSV·TSV로 내보내 Timeline Explorer나 Excel에서 정렬·필터한다. 자동화가 필요하면 CLI 자매 도구 RECmd를 쓴다.

| 항목 | RegistryExplorer | RECmd |
| --- | --- | --- |
| 형태 | GUI | CLI |
| 대상 | hive 1개 이상을 눈으로 탐색 | 폴더 안의 hive를 일괄 처리 |
| 무엇을 뽑을지 지정 | 사람이 트리에서 클릭 | **배치 파일**(`.reb`)에 미리 적어 둔다 |
| 출력 | 화면 + CSV/TSV 내보내기 | CSV 파일 |

**배치 파일**은 "어떤 hive의 어떤 키/값을 뽑아 어떤 이름의 컬럼으로 낼지"를 적어 둔 텍스트(YAML) 파일이다. 배포판의 `BatchExamples` 폴더에 기본 배치가 함께 들어 있고, 그것을 지정하면 북마크에 해당하는 키들을 한 번에 CSV로 떨어뜨린다.

```powershell
# 폴더 안의 모든 hive 에 기본 배치를 적용
RECmd.exe -d 'C:\case\hives' --bn 'BatchExamples\Kroll_Batch.reb' --csv 'C:\case\out'

# hive 1개, 특정 키만
RECmd.exe -f 'C:\case\NTUSER.DAT' --sk 'TypedPaths' --csv 'C:\case\out'
```

옵션 이름은 버전에 따라 달라질 수 있으므로 `RECmd.exe`를 인자 없이 실행해 실제 도움말을 먼저 본다.

## 출력 필드 해석

| 필드 | 의미 | 주의 |
| --- | --- | --- |
| 키의 LastWrite | 그 키의 값이 마지막으로 추가/변경/삭제된 시각. FILETIME **UTC** | 값 단위 시각이 아니다. 값이 여러 개면 어느 값 때문인지 모른다 |
| 값 타입 | `RegSz`(문자열), `RegExpandSz`(환경변수 포함), `RegBinary`, `RegDword`, `RegMultiSz` | `RegBinary`인데 사람이 읽을 문자열이 보이면 UTF-16LE다 |
| Data | 값 데이터. 문자열이면 그대로, 이진이면 hex | 이진 값의 앞 8바이트가 FILETIME인 경우가 많다 |
| Value Slack | 값 데이터 뒤의 잔여 바이트 | 이전 값의 조각. 단정 근거로는 약하지만 단서로 강하다 |
| 플러그인 표의 시각 컬럼 | 값 데이터 안에서 뽑아낸 자체 타임스탬프 | 키 LastWrite보다 **정확하다.** 우선 채택 |
| 삭제 레코드 표시 | 미할당 셀에서 복구된 항목 | 부모 경로가 추정일 수 있다 |

모든 시각은 UTC다. KST 답을 요구하면 +9시간, Unix epoch와의 차이는 `11644473600`초다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| hive 루트에 찍힌 원래 경로 | 어느 hive인지 확정 ([FOR-0051](./registry-hive-map.html)) | `NTUSER.DAT`인지 `UsrClass.dat`인지 |
| `NTUSER.DAT`의 사용자 활동 키 | 키 인덱스 ([FOR-0057](./ntuser-dat.html)) | 다음에 볼 키 목록 |
| `BagMRU` 위치 | `UsrClass.dat` ShellBags ([FOR-0058](./usrclass-dat.html)) | 탐색기로 방문한 폴더 |
| UserAssist 플러그인 표 | Prefetch, `Amcache.hve` | 실행 사실·해시 교차검증 |
| 실행 파일 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일 생성·삭제 시각 |
| 시간대(`SYSTEM`) | 모든 시각 보정 ([FOR-0054](./system-timezone.html)) | UTC ↔ 로컬 변환 기준 |
| CSV로 내보낸 결과 | Timeline Explorer / `Import-Csv` | 다른 아티팩트와 통합 타임라인 |

## 흔한 함정

- **dirty hive 경고를 지나치는 것.** 가장 자주 나오는 실수다. 반영하지 않으면 값이 "없는" 게 아니라 **한 세대 이전 값이 정상처럼 보인다.** 로드할 때마다 경고 문구를 읽는다.
- **hive만 복사해 놓고 `.LOG1`/`.LOG2`를 두고 오는 것.** 도구가 반영해 주려 해도 로그가 없으면 못 한다. 추출은 항상 hive + 로그 세트로 한다.
- **`regedit`의 하이브 로드로 증거 hive를 마운트하는 것.** 라이브 레지스트리를 건드리고 hive 파일이 수정될 수 있다. 오프라인 파서로만 읽는다.
- **키 LastWrite를 값의 시각으로 쓰는 것.** 키 단위·마지막 1회다. 플러그인이 값 안에서 뽑아 준 시각이 있으면 그쪽이 정답이다.
- **`CurrentControlSet` 경로를 트리에서 찾는 것.** 부팅 시 만들어지는 링크라 오프라인 hive에 없다. `Select\Current`로 `ControlSet001` 같은 실제 이름을 확인한다([FOR-0053](./system-controlset.html)).
- **플러그인 표만 보고 원본 값을 확인하지 않는 것.** 표는 해석 결과다. 답으로 제출할 값은 원시 데이터에서 한 번 더 확인한다. 특히 시각은 UTC/로컬 표기 혼동이 잦다.
- **삭제 레코드에서 복구된 항목을 확정 사실처럼 쓰는 것.** 부모 키를 못 찾은 항목은 경로가 추정이다. "삭제 레코드 복구"임을 명시하고 다른 아티팩트로 뒷받침한다.
- **문자열 검색이 안 잡히면 없다고 결론내는 것.** hive 내부 문자열은 UTF-16LE다. ASCII 검색으로 안 나오면 hex 검색이나 값 slack 검색으로 바꾼다.
- **hive 하나만 열고 판단하는 것.** 사용자 활동은 `NTUSER.DAT` + `UsrClass.dat`, 시스템 사실은 `SYSTEM` + `SOFTWARE`가 쌍이다. 한쪽만 보면 절반이 빈다.
- **원본 hive를 직접 열어 쓰기 가능 상태로 두는 것.** 작업용 복사본에서 작업하고, 원본 해시를 먼저 기록한다.

## 교차검증

같은 사실을 GUI와 CLI 양쪽에서 확인하면 해석 실수를 잡을 수 있다.

```powershell
# 1) GUI: 북마크로 UserAssist 로 점프해 플러그인 표 확인 (사람 눈)

# 2) CLI: 같은 키를 RegRipper 로 덤프해 대조
rip.exe -r 'C:\case\clean\NTUSER.DAT' -p userassist > 'C:\case\ua_rr.txt'

# 3) CLI: RECmd 배치로 CSV 산출
RECmd.exe -f 'C:\case\clean\NTUSER.DAT' --bn 'BatchExamples\Kroll_Batch.reb' --csv 'C:\case\out'

# 4) 두 결과의 항목 수와 시각이 같은지 확인
Select-String -Path 'C:\case\ua_rr.txt' -Pattern 'dump_tool'
```

세 결과가 어긋나면 원인은 대개 **한쪽만 트랜잭션 로그를 반영했기 때문**이다. 어느 hive 파일을 먹였는지부터 확인한다.

## mini walkthrough

```text
문제:
"감염 PC에서 뽑은 NTUSER.DAT, ntuser.dat.LOG1, ntuser.dat.LOG2 가 주어진다.
 사용자가 실행한 악성 실행 파일의 경로와, 공격자가 등록했다가 지운
 자동실행 값의 내용을 구하세요."

1. 첫 시도 (실패):
   NTUSER.DAT 을 드래그앤드롭.
   "dirty hive" 경고 창이 떴지만 로그 반영을 하지 않고 그냥 열었다.

   - 북마크로 UserAssist 로 점프 -> 플러그인 표의 최신 항목이 사건 전날이다
   - Software\Microsoft\Windows\CurrentVersion\Run -> 값이 하나도 없다
   -> "자동실행 등록 없음, 실행 흔적도 없음" 이라고 결론냈다. 둘 다 오답.

   왜 틀렸나:
   primary(0x04)=0x51, secondary(0x08)=0x53 로 불일치하는 dirty hive 였고,
   사건 당일 변경분 전체가 ntuser.dat.LOG1 에만 있었다.

2. 피벗 1: 트랜잭션 로그 반영 후 재로드
   rla.exe -f NTUSER.DAT --out clean\
   clean\NTUSER.DAT 을 다시 로드 -> 경고 없이 열린다(clean)

   UserAssist 플러그인 표:
     Program Name                                        Run Count  Last Executed (UTC)
     C:\Users\jhkim\AppData\Roaming\svc\updater.exe             2   2026-03-14 08:12:47

3. 피벗 2: Run 키는 여전히 비어 있다 -> 삭제 레코드를 본다
   Deleted Records 목록에서 복구된 값:
     Key  : Software\Microsoft\Windows\CurrentVersion\Run  (복구, 부모 확인됨)
     Value: SvcUpdater
     Type : RegSz
     Data : C:\Users\jhkim\AppData\Roaming\svc\updater.exe
   -> 등록했다가 지운 자동실행 값이 그대로 남아 있었다.

4. 보강: Find 로 값 데이터 검색
   검색 대상 = 값 데이터, 검색어 = AppData\Roaming\svc
   -> Run(삭제), UserAssist, MuiCache 후보 등 3곳에서 히트.
      같은 경로가 여러 키에서 나오므로 우연이 아니다.

5. 교차검증
   rip.exe -r clean\NTUSER.DAT -p userassist | Select-String 'updater'
   -> 같은 경로, Run Count 2, 같은 UTC 시각

6. 시간 보정
   2026-03-14 08:12:47 UTC + 9h = 2026-03-14 17:12:47 KST

정답: C:\Users\jhkim\AppData\Roaming\svc\updater.exe
      삭제된 자동실행 값 = Run\SvcUpdater (같은 경로), 2026-03-14 17:12:47 KST 마지막 실행
```

## 막혔을 때 다음 체크

1. **dirty hive 경고를 처리했는가** — 안 했으면 `rla`로 반영해 다시 로드한다
2. **`.LOG1`/`.LOG2`를 같이 가져왔는가** — 없으면 이미지로 돌아간다
3. 찾는 키가 안 보이는가 → 북마크 목록을 위에서 아래로 훑는다
4. 키 이름을 모르는가 → **값 데이터 검색**으로 문자열부터 찾는다
5. 문자열 검색이 안 잡히는가 → UTF-16LE 이므로 hex 검색 또는 값 slack 검색으로 전환
6. 값이 지워진 것 같은가 → 삭제 레코드 목록 확인
7. 값이 이진이라 못 읽는가 → 플러그인 지원 여부 확인, 없으면 RegRipper로 넘긴다([FOR-0060](./regripper.html))
8. hive가 여러 개인가 → 동시에 로드해 `SYSTEM`/`SOFTWARE`/사용자 hive를 나란히 비교한다
9. 결과가 많아 정리가 안 되는가 → CSV로 내보내 Timeline Explorer에서 정렬한다
10. GUI가 실행되지 않는가(.NET 런타임 문제) → RECmd 또는 RegRipper로 CLI 경로를 택한다

## 출처

- SRC-004 — Eric Zimmerman 도구 문서: RegistryExplorer의 hive 로드, 트랜잭션 로그 처리, 플러그인 자동 디코딩, 북마크, 삭제 레코드 복구, 자매 도구 RECmd와 배치 파일 개념
- SRC-027 — Libyal libregf, REGF 포맷 문서: base block의 sequence number로 dirty 판정, 값 타입, 삭제된 `nk`/`vk` 셀이 즉시 재사용되지 않는다는 점, hive 내부 문자열이 UTF-16LE라는 점
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: hive 파일과 루트키 대응, `regedit`의 하이브 로드가 라이브 레지스트리에 마운트된다는 점
- **메뉴 이름, 창 배치, 경고 문구, 북마크·플러그인 목록, RECmd 스위치는 도구 버전에 따라 다르다.** 이 글은 기능 단위로 서술했으므로 실제 화면과 `RECmd.exe` 도움말에서 이름을 확인할 것
- 배치 파일 이름(`BatchExamples` 폴더의 기본 배치)은 배포판마다 다르므로 실제 폴더를 열어 확인할 것
