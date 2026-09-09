---
id: FOR-0044
title: "Autopsy Timeline로 시각 축 좁히기 (Counts/Details/List)"
slug: "autopsy-timeline"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["Timeline", "Counts View", "Details View", "List View", "event cluster", "Histogram"]
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["Autopsy", "Sleuth Kit", "MFTECmd", "EvtxECmd", "Timeline Explorer", "mactime"]
commands: ["fls -o 2048 -r -m /C: image.dd > body.txt", "mactime -b body.txt -d -z UTC"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["File Modified", "File Accessed", "File Created", "File Changed", "Web History", "Web Downloads", "Web Searches", "Recent Documents", "Installed Programs", "Devices Attached", "Log Entry", "Registry"]
file_formats: ["e01", "raw", "dd", "vmdk", "vhd"]
primary_terms: ["Autopsy Timeline", "autopsy 타임라인"]
keywords: ["Autopsy", "Timeline", "Counts View", "Details View", "List View", "Hide Known Files", "Text Filter", "Description Detail", "event cluster", "타임라인", "Zoom"]
aliases: ["autopsy 타임라인", "타임라인 보기", "autopsy timeline", "언제 무슨 일이 있었나", "시각 순서대로 보기", "타임라인 필터", "이벤트 클러스터"]
symptom_keywords: ["언제 무슨 일이 있었는지 알고 싶다", "타임라인이 너무 많아서 못 본다", "타임라인이 비어 있다", "특정 시각 전후를 보고 싶다", "타임라인이 느리다", "$FN 시각이 안 보인다"]
related: ["FOR-0018", "FOR-0021", "FOR-0041"]
source_ids: ["SRC-033", "SRC-005", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Autopsy Timeline은 `Tools > Timeline`으로 열고 **Counts View로 활동이 몰린 구간을 찾은 뒤 그 구간만 남기고 Details/List View로 내려가는** 순서로 써야 하며, 시각 축을 좁히지 않고 상세 뷰를 열면 UI가 멈춘다.

## 어떤 문제에서 필요한가

- 지문이 "언제 무슨 일이 있었나", "사건 시각 전후에 무엇이 일어났나"를 요구하는 경우
- 시각 하나(로그온 시각, 파일 생성 시각)를 잡았고 그 주변을 훑어야 하는 경우
- 파일시스템 시각 + 웹 활동 + 최근문서 + 레지스트리를 **하나의 축**에서 봐야 하는 경우
- 컴퓨터가 마지막으로 사용된 시점, 사용 빈도를 재야 하는 경우
- ingest 결과가 흩어져 있어 인과 순서를 세우기 어려운 경우

반대로 **artifact 하나의 정밀 시각이 목표라면 Timeline을 쓰지 않는다.** `$MFT`/`$J`/EVTX를 꺼내 전용 파서로 보는 편이 컬럼이 풍부하고 빠르다.

## 문제에서 처음 볼 단서

1. ingest가 끝났고 `Results`에 항목이 쌓여 있다 → Timeline이 의미 있다 ([FOR-0018](./autopsy-ingest.html))
2. Timeline이 **비어 있다** → ingest가 진행 중이거나, 케이스가 Autopsy 4.13 이전에 만들어졌다
3. Counts View의 막대 하나가 압도적으로 크다 → 그 구간에 사용자 활동 또는 대량 파일 조작이 있었다
4. 특정 날짜만 이벤트가 있고 나머지가 비었다 → 이미지 제작 시점의 일괄 복사. 그 날짜는 노이즈다
5. `Hide Known Files`를 켰는데 아무것도 줄지 않는다 → Hash Lookup을 Known 해시셋으로 돌리지 않았다

## 30초 절차

```text
Tools > Timeline
```

```text
1. Tools > Timeline 로 창을 연다
2. 좌상단 Zoom 의 Time Units 를 사건 규모에 맞춘다 (년 -> 월 -> 일 -> 시)
3. Counts View 에서 막대가 큰 구간을 찾는다
4. 그 구간을 시간 범위 슬라이더 또는 시작/끝 날짜 입력으로 남긴다
5. 좌측 Event Types 에서 필요한 유형만 체크 (예: Web Activity + File Created)
6. Hide Known Files 체크 (Hash Lookup 을 돌렸다면)
7. Details View 로 전환해 클러스터를 [+] 로 펼친다
8. 개별 이벤트 우클릭 -> 파일로 점프
```

**3→4 순서를 뒤집지 않는다.** 범위를 안 좁히고 Details View나 List View를 열면 수만 건이 한 화면에 들어가 실질적으로 못 쓴다.

## 상세 절차

### 1단계 — 세 가지 뷰의 용도

화면 상단 가운데 버튼으로 전환한다.

| 뷰 | 형태 | 언제 쓰는가 | 한계 |
| --- | --- | --- | --- |
| **Counts View** | 시간 축 × 이벤트 개수의 누적 막대. **시작 시 기본 뷰** | "활동이 언제 몰렸나", "마지막 사용 시점", "사용 빈도" | 개별 이벤트를 볼 수 없다 |
| **Details View** | 관련 이벤트를 묶은 클러스터를 시간 축에 배치. 세로축은 의미 없음 | 좁은 구간의 **인과 순서** 파악 | 범위가 넓으면 UI가 느려진다 |
| **List View** | 전 이벤트를 시간순 목록으로 | "그 이벤트 직전·직후에 무엇이 있었나" | 이벤트가 많으면 압도적이다 (문서도 이를 명시) |

실전 순서는 **Counts → 범위 축소 → Details → List**다. Counts에서 "어디"를, Details에서 "무엇과 무엇이 붙어 있나"를, List에서 "정확한 순서"를 얻는다.

이벤트는 유형별로 **색과 아이콘**이 부여되며, 좌측 Event Types 트리가 그 **범례** 역할을 겸한다.

### 2단계 — 시간 범위 좁히기 (Zoom과 범위 컨트롤)

좌상단 Zoom 패널에는 세 가지 축이 있다.

| Zoom 항목 | 조절하는 것 | 실전 |
| --- | --- | --- |
| **Time Units** | X축의 시간 단위 (년/월/일/시/분 규모) | 넓게 잡고 시작해 좁혀 간다 |
| **Event Type** | 이벤트 유형 계층의 **표시 깊이** (상위 유형만 vs 하위 유형까지) | 처음엔 상위, 후보가 좁혀지면 하위 |
| **Description Detail** | 설명 문자열의 상세도. **비슷한 설명끼리 묶는 정도** | 완전히 축소하면 파일시스템 이벤트가 공통 루트 폴더 단위로 뭉친다 |

`Description Detail`은 Autopsy Timeline의 가장 특징적인 기능이다. 축소하면 `/Users/kim/...` 수천 건이 폴더 단위 한 덩어리로 보이고, 확대하면 개별 파일까지 펼쳐진다. **문서가 명시적으로 경고하듯, 범위를 좁히거나 필터를 걸지 않은 상태에서 최대 상세로 올리면 UI가 심하게 느려진다.**

시간 범위는 여러 방법으로 지정한다.

| 컨트롤 | 사용법 |
| --- | --- |
| 시작/끝 날짜·시각 입력칸 | 값을 직접 편집 |
| 날짜/시각 선택기 | 달력에서 고르기 |
| 돋보기 `-` / `+` 버튼 | 현재 중심에서 범위 확대/축소 |
| 미리 정의된 범위 드롭다운 | 자주 쓰는 기간 |
| 양끝 범위 슬라이더 | 끝을 끌면 범위 변경, **파란 구간 자체를 끌면 크기 유지하며 이동** |
| 차트 빈 공간에서 우클릭 드래그 | 연한 파란 구간 표시 → 더블클릭하면 그 구간으로 확대, 우클릭하면 해제 |
| `Alt` + `←` / `→` | 확대·축소 이력 되돌리기/앞으로 |

범위 슬라이더 뒤에는 **Histogram**이 깔려 있다. 케이스 전체 기간을 균등 구간으로 나눈 것으로, **필터와 확대에 영향받지 않는다**(문서 명시). 즉 Histogram은 "전체 대비 상대적인 활동량"을 보는 용도이며 정확한 수치로 읽지 않는다.

시간대는 **local time 또는 UTC** 중에서 고른다.

| 판단 | 권장 |
| --- | --- |
| 최종 답을 KST로 요구 | 표시를 local(KST)로 두되, 근거 값은 UTC로 한 번 더 확인 |
| 여러 artifact를 대조 | **UTC로 고정**한다. 파서 CSV가 대개 UTC이므로 축이 맞는다 |
| 시차가 의심된다 | Data Source 추가 시 지정한 시간대를 `Case Properties`에서 확인 |

FILETIME 기반 값은 1601-01-01 UTC 기준이고 Unix 시각과의 차이는 `11644473600`초다. KST는 UTC+9다.

### 3단계 — 필터: Event Types, Text Filter, Hide Known Files

좌측 패널의 필터 세 종류가 실질적인 노이즈 제거 수단이다.

| 필터 | 동작 | 실전 |
| --- | --- | --- |
| **Event Types** | 유형 체크박스 트리. 유형을 우클릭하면 유형 묶음을 한 번에 선택하는 메뉴가 나온다 | 목표에 맞는 유형만 남긴다 |
| **Text Filter** | 이벤트 **설명(description)에 그 문자열이 포함된** 이벤트만 남긴다. 화면에 설명이 보이지 않아도 전체 설명을 검색한다 | 사용자명·폴더명·파일명·도메인 |
| **Hide Known Files** | 알려진 해시의 파일을 타임라인 전체에서 제외한다 (Histogram은 예외로 전부 표시) | OS 기본 파일 대량 제거 |

`Hide Known Files`는 **Hash Lookup ingest 모듈을 Known 해시셋으로 미리 돌려야 효과가 있다.** 돌리지 않았다면 체크해도 아무 변화가 없다(문서 명시). 해시셋이 없는 CTF 환경에서는 기대하지 않는 편이 낫다.

Details View에서는 **설명(description)으로 탐색하는 탭이 추가로 제공된다.**

### 4단계 — 이벤트 유형 계층

문서가 정의하는 유형 분류다.

| 상위 | 하위 유형 |
| --- | --- |
| **File System** | Modified, Access, Created, Changed |
| **Web Activity** | Web Downloads, Web Cookies, Web Bookmarks(생성), Web History, Web Searches, Web Form Auto Fill, Web Form Address |
| **Miscellaneous** | Messages, GPS Routes, Location History, Calls, Email, Recent Documents, Installed Programs, Exif metadata, Devices Attached, Log Entry, Registry |

목표별 유형 조합이다.

| 목표 | 남길 유형 |
| --- | --- |
| 파일 유입 경로 | Web Downloads + File Created + Recent Documents |
| USB 사용 | Devices Attached + File Created + File Modified |
| 검색·열람 행위 | Web Searches + Web History + Recent Documents |
| 프로그램 설치·실행 | Installed Programs + Registry + File Created |
| 사진 촬영·이동 | Exif metadata + File Created |
| 데이터 반출 | Web Downloads + Email + Messages + File Accessed |
| 파일 대량 조작 | File Modified + File Changed **만** (나머지 끄기) |

`Miscellaneous`의 하위 유형은 **Recent Activity / EXIF Parser 같은 ingest 모듈이 만들어 준 결과**에서 나온다. 해당 모듈을 돌리지 않았다면 그 유형은 애초에 존재하지 않는다 ([FOR-0018](./autopsy-ingest.html)).

### 5단계 — 클러스터를 펼쳐 개별 파일로 내려가기

Details View의 이벤트 묶음(클러스터)은 작은 초록색 `[+]` 버튼으로 하위 클러스터로 펼쳐지고, 빨간 `[-]`로 접힌다. 선택한 클러스터는 X축에 투영되어 시간 관계를 보여 준다.

Details View의 설정 네 가지다.

| 설정 | 효과 | 언제 켜나 |
| --- | --- | --- |
| **Band by Type** | 유형별로 가로 띠를 따로 배정(섞이지 않는다) | 유형 간 순서를 비교할 때 |
| **One event per Row** | 세로 겹침 없이 한 줄에 하나. Gantt 차트처럼 보이지만 공간을 많이 쓴다 | 이벤트 수가 적은 좁은 구간 |
| **Truncate Descriptions** | 라벨 길이를 픽셀 단위로 제한 | 경로가 길어 화면이 밀릴 때 |
| **Description Visibility** | `show`(기본) / `counts only` / `hide` | 밀도가 높으면 `counts only` |

Counts View의 설정은 하나, **세로 축 스케일**이다.

| 스케일 | 특성 | 주의 |
| --- | --- | --- |
| Linear | Y축에 수치 라벨이 붙고, 이벤트가 있는 날짜 라벨이 굵게 표시된다 | 값 차이가 크면 작은 막대가 안 보인다 |
| Logarithmic | 작은 막대도 보인다. **Y축 라벨이 의도적으로 표시되지 않는다** | 유형별로 개별 적용되어 누적 막대 높이가 직관적이지 않다 |

문서는 로그 스케일에서 "한 유형의 시간에 따른 비교" 또는 "한 시점의 유형 간 비교" 중 **하나만** 하라고 명시한다. 두 축을 동시에 비교하면 잘못 읽는다. 막대가 여전히 안 보이면 창을 키우거나, 큰 막대가 있는 기간을 범위에서 빼거나, 필터를 거는 것이 답이다.

### 6단계 — 결과에서 파일로 점프

관심 이벤트를 잡으면 그 파일로 이동해 실제 내용을 확인한다. 하단 좌측 표에는 노드를 찾는 **UI Quick Search**가 있다.

```text
이벤트 선택 -> 하단 표에서 해당 파일 확인
             -> 우클릭 -> 파일 위치로 이동 / 내용 보기 / 추출
             -> Extract File(s) 로 꺼내 file / strings / 전용 파서로 검증
```

메뉴 항목 이름은 Autopsy 버전에 따라 다르다. 이벤트나 표 행을 우클릭해 나오는 항목을 직접 확인한다.

### 7단계 — Autopsy Timeline의 한계와 대안

| 한계 | 내용 | 대안 |
| --- | --- | --- |
| **$FILE_NAME 시각이 없다** | Autopsy의 파일시스템 이벤트는 TSK 메타데이터 시각(`$STANDARD_INFORMATION` 계열) 기반이다. `$SI`/`$FN` 8개 비교가 불가능하다 | `$MFT`를 꺼내 MFTECmd로 파싱 ([FOR-0021](./mft-basics.html)) |
| timestomp 탐지 불가 | 위와 같은 이유 | MFTECmd CSV의 `Created0x10` vs `Created0x30` |
| `$UsnJrnl` 미반영 | 삭제·이름변경 이력이 축에 올라오지 않는다 | `$J` 파싱 후 별도 타임라인 ([FOR-0027](./usnjrnl-basics.html)) |
| EVTX 상세 부족 | `Log Entry`로 뭉쳐 EventData 필드를 못 본다 | EvtxECmd CSV ([FOR-0083](./event-4624-logon.html)) |
| 초 이하 정밀도 | UI 단위가 초 수준이다 | 파서 CSV의 원본 타임스탬프 |
| 4.13 이전 케이스 | 이벤트를 ingest 중에 케이스 DB에 만들므로 **이전에 만든 케이스는 Timeline이 동작하지 않는다**(문서 명시) | 케이스를 새로 만들어 다시 ingest |
| ingest 중 불완전 | Timeline을 ingest 중에 열 수 있지만 데이터가 계속 늘어난다 | 진행률 100% 후 결론 |

정밀 타임라인이 필요하면 **CSV를 모아 Timeline Explorer에서 합치는 편**이 낫다.

```bash
# 파일시스템 (Sleuth Kit 만으로도 가능)
fls -o 2048 -r -m /C: image.dd > body.txt
mactime -b body.txt -d -z UTC 2026-03-14 > fs_timeline.csv
```

```powershell
# $MFT ($SI + $FN 양쪽 시각)
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv

# $UsnJrnl:$J (삭제·이름변경 이력)
MFTECmd.exe -f 'C:\case\$J' --csv "C:\case\out" --csvf usn.csv

# EVTX (로그온·프로세스 생성)
EvtxECmd.exe -d "C:\case\winevt" --csv "C:\case\out" --csvf evtx.csv
```

세 CSV를 Timeline Explorer에 각각 열고 시각 컬럼으로 정렬하면 Autopsy Timeline보다 훨씬 촘촘한 축을 얻는다. **단 시간대를 UTC로 통일해야 한다.**

## 출력 필드 해석

Timeline 하단 표와 이벤트에서 읽는 값이다.

| 보이는 것 | 의미 | 함정 |
| --- | --- | --- |
| 이벤트 유형 색/아이콘 | 좌측 Event Types 트리가 범례 | 상위 유형만 표시 중이면 하위 구분이 안 보인다 |
| 이벤트 설명(description) | Description Detail 수준에 따라 뭉친 문자열 | **Text Filter는 화면에 안 보이는 전체 설명까지 검색한다** |
| 클러스터의 이벤트 개수 | 묶인 이벤트 수 | 개수만 보고 "파일 N개"로 단정하지 않는다. 한 파일이 M/A/C/B 4개 이벤트를 만든다 |
| Counts View 막대 높이 | 구간 내 이벤트 개수 | 로그 스케일에서는 높이를 절대 비교하지 않는다 |
| Histogram 모양 | 전체 기간 대비 활동 분포 | **필터·확대에 반응하지 않는다.** 현재 필터 결과가 아니다 |
| 시각 | local 또는 UTC 표시 | 어느 쪽인지 먼저 확인한다 |

**한 파일이 여러 이벤트를 만든다**는 점이 개수 해석의 핵심이다. File System 유형은 Modified / Access / Created / Changed 각각이 별도 이벤트이므로, 파일 1000개가 이벤트 4000건이 될 수 있다.

## pivot: 다음에 볼 artifact

| Timeline에서 얻은 것 | 다음 목표 |
| --- | --- |
| 활동이 몰린 시각 구간 | 그 구간의 로그온 이벤트 대조 ([FOR-0083](./event-4624-logon.html)) |
| Web Downloads 이벤트 | 브라우저 History/Downloads DB 직접 질의 ([FOR-0191](./chrome-history.html)) |
| Devices Attached 이벤트 | `SYSTEM` hive의 USBSTOR, `MountedDevices` |
| Recent Documents / Installed Programs | UserAssist·Prefetch 교차검증 ([FOR-0061](./userassist.html)) |
| File Created 폭증 구간 | 압축 해제·대량 복사 흔적. 그 폴더를 직접 확인 |
| 관심 파일 하나 | Extract 후 `file`/`strings`/전용 파서 ([FOR-0001](./30sec-triage.html)) |
| 파일시스템 시각 정밀 비교 필요 | `$MFT` → MFTECmd ($SI vs $FN) ([FOR-0021](./mft-basics.html)) |
| 삭제 이력이 필요 | `$UsnJrnl:$J` ([FOR-0027](./usnjrnl-basics.html)) |
| Timeline이 비었다 | ingest 상태 확인, 케이스 재생성 ([FOR-0018](./autopsy-ingest.html)) |
| CLI로 대조 | `fls -m` + `mactime` ([FOR-0041](./tsk-fls.html)) |

## 흔한 함정

- **범위를 좁히지 않고 Details View를 여는 것.** 문서가 명시적으로 경고한다. Description Detail을 최대로 올린 상태와 겹치면 UI가 사실상 멈춘다. → Counts View에서 구간을 먼저 확정한다.
- **Histogram을 현재 필터 결과로 읽는 것.** Histogram은 필터와 확대에 반응하지 않는다. 상대 비교용이며 수치로 쓰지 않는다.
- **로그 스케일 막대 높이를 절대 비교하는 것.** 유형별로 개별 적용되므로 누적 높이가 직관과 다르다. 시간축 비교와 유형 비교를 동시에 하지 않는다.
- **`Hide Known Files`가 켜지면 자동으로 걸러진다고 믿는 것.** Hash Lookup을 Known 해시셋으로 돌리지 않으면 아무 효과가 없다.
- **이벤트 개수를 파일 개수로 읽는 것.** File System 유형은 한 파일이 Modified/Access/Created/Changed 최대 4개 이벤트를 만든다.
- **시간대를 확인하지 않고 시각을 답으로 쓰는 것.** local과 UTC를 전환할 수 있으므로 지금 어느 쪽인지 먼저 본다. 여러 artifact를 대조할 때는 UTC로 통일한다.
- **`$FN` 시각을 Timeline에서 찾는 것.** Autopsy의 파일시스템 시각은 `$SI` 계열 하나뿐이다. timestomp 판정은 `$MFT` 파서의 일이다.
- **Timeline이 비었을 때 이미지를 의심하는 것.** ingest 미완료이거나 4.13 이전에 만든 케이스일 가능성이 먼저다.
- **Event Types를 전부 켜 둔 채 답을 찾는 것.** File System 이벤트가 나머지를 수치로 압도해 웹 활동이 안 보인다. **목표 유형만 남기는 것이 이 도구의 핵심 조작이다.**
- **Text Filter를 파일명 전체 일치로 기대하는 것.** 설명 문자열의 **부분 문자열** 검색이다. 정규식이 아니다.
- **Zoom 되돌리기를 몰라 처음부터 다시 잡는 것.** `Alt` + `←`/`→`로 확대 이력을 오간다.
- **List View를 첫 화면으로 쓰는 것.** 구간당 수천 건이면 문서 표현대로 "압도적"이다. 필터를 먼저 건다.

## 교차검증

```bash
# 1) Autopsy 의 File Created 폭증 구간 vs Sleuth Kit 타임라인
fls -o 2048 -r -m /C: image.dd > body.txt
mactime -b body.txt -d -z UTC 2026-03-14 | wc -l
mactime -b body.txt -d -z UTC 2026-03-14 | head -30

# 2) 시간대 검증 — UTC 로 뽑아 Autopsy 표시와 9시간 차이가 맞는지
mactime -b body.txt -d -z UTC 2026-03-14T07:00:00..2026-03-14T08:00:00
```

```powershell
# 3) Autopsy 의 파일시스템 이벤트 vs $MFT 파서 ($SI/$FN 양쪽)
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv
Import-Csv C:\case\out\mft.csv |
  Where-Object { $_.Created0x10 -like '2026-03-14*' } |
  Select-Object FileName, Created0x10, Created0x30 | Format-Table

# 4) Autopsy 의 Log Entry vs EvtxECmd
EvtxECmd.exe -d "C:\case\winevt" --csv "C:\case\out" --csvf evtx.csv
```

Autopsy 표시 시각과 `mactime -z UTC` 결과가 정확히 9시간 차이면 local(KST) 표시 중인 것이다. 차이가 다르면 Data Source 시간대 지정이 잘못되었다.

## mini walkthrough

```text
문제:
"직원이 반출한 파일의 유입 경로와 반출 시각을 특정하세요."
첨부: laptop.E01 (120 GB), 지문에 "3월 중순"만 명시

1. ingest 완료 후 Tools > Timeline

2. 첫 시도 (실패):
   - 바로 Details View 로 전환
   - Description Detail 을 최대로 올림
   - Event Types 는 전부 체크된 기본 상태

   결과: 진행 표시가 돌고 화면이 5분 넘게 응답하지 않았다.
         강제로 되돌리고 다시 시작.

   왜 틀렸나:
   범위가 케이스 전체 기간(2년)인 상태에서 최대 상세로 개별 이벤트를
   전부 펼치려 했다. 문서도 이 조합을 경고한다.

3. 접근 변경 — Counts View 로 되돌아가 구간을 먼저 찾는다
   - Counts View, Time Units = 월
   - 2년 구간 중 2026-03 막대가 다른 달의 8배

   -> Time Units = 일 로 내리고 3월만 남긴다
   -> 2026-03-14 하루가 압도적

4. 유형을 줄인다
   Event Types 에서 File System 하위를 모두 끄고
   Web Activity + Recent Documents 만 남긴다

   -> 이벤트가 4만 건에서 62건으로 줄었다.
      비로소 Details View 가 즉시 뜬다.

5. Details View 로 인과 순서 확인
   범위: 2026-03-14 (시간대 표시는 local/KST)

   09:41  Web Searches      "sample dataset download"
   09:43  Web History       cdn.example.org/files/
   09:44  Web Downloads     customer_list.xlsx     <- 유입
   10:12  Recent Documents  customer_list.xlsx     <- 열람

   [+] 로 09:44 클러스터를 펼쳐 개별 이벤트로 내려가고
   하단 표에서 파일을 선택 -> 우클릭 -> 파일 위치로 이동

6. 두 번째 확인 — 반출 시각은 이 축에 없었다
   File System 유형을 다시 켜고 Text Filter 에 'customer_list' 입력
   -> 11:58 File Accessed 가 하나 더 나왔다.
      경로가 E:\ 로 시작한다 = 외부 매체

   Miscellaneous 의 Devices Attached 를 켠다
   -> 11:55 Devices Attached (USB) 가 잡힌다.
      순서: USB 연결(11:55) -> 파일 접근(11:58) = 복사 반출

7. 정밀 검증 — Timeline 만으로는 부족하다
   Autopsy 는 $SI 시각만 보여 준다. 조작 여부를 확인해야 한다.

   $MFT 를 추출해 MFTECmd 로 파싱:
     Created0x10 = 2026-03-14 09:44:21
     Created0x30 = 2026-03-14 09:44:21   -> 일치, timestomp 아님

   $J 파싱: 12:03 에 FILE_DELETE (원본 삭제 시도)
   -> Autopsy Timeline 에는 없던 이벤트다.

정답: 유입 2026-03-14 09:44 (웹 다운로드), 반출 11:58 (USB 복사),
      원본 삭제 12:03 ($UsnJrnl 기준)
```

2→3단계가 이 글의 요지다. **Details View를 먼저 열면 도구가 멈추고, Counts View로 구간을 먼저 자르면 62건으로 끝난다.** 그리고 7단계처럼 **Timeline의 결론은 항상 전용 파서로 보강해야 한다** — `$J`의 삭제 이벤트는 Autopsy Timeline 축에 올라오지 않았다.

## 막혔을 때 다음 체크

1. ingest 진행률이 100%인가
2. 케이스를 Autopsy 4.13 이후 버전에서 만들었는가 (이전 케이스는 Timeline이 동작하지 않는다)
3. Counts View에서 구간을 먼저 좁혔는가 — Details/List를 먼저 열지 않았는가
4. Event Types에서 **불필요한 유형을 껐는가** (특히 File System 하위)
5. Zoom의 `Time Units`를 사건 규모에 맞췄는가
6. `Description Detail`을 필요 이상으로 올리지 않았는가
7. Text Filter에 사용자명·폴더명·파일명 일부를 넣어 봤는가
8. `Hide Known Files`를 쓰려면 Hash Lookup을 Known 해시셋으로 돌렸는가
9. 시간대 표시가 local인지 UTC인지 확인했는가
10. 찾는 유형이 애초에 존재하는가 — 해당 ingest 모듈을 돌렸는가 ([FOR-0018](./autopsy-ingest.html))
11. Histogram을 필터 결과로 오해하고 있지 않은가
12. 이벤트 개수를 파일 개수로 세고 있지 않은가
13. `$FN` 시각·삭제 이력이 필요하면 `$MFT`/`$J`를 꺼냈는가 ([FOR-0021](./mft-basics.html))
14. CLI로 대조했는가 — `fls -m` + `mactime` ([FOR-0041](./tsk-fls.html))

## 출처

- SRC-033 — Autopsy User Documentation (Timeline): 세 뷰(Counts View / Details View / List View)의 정의와 기본 뷰, Zoom의 `Time Units` / `Event Type` / `Description Detail`, 필터(`Hide Known Files`, `Text Filter`, `Event Types`)의 동작, 이벤트 유형 계층(File System / Web Activity / Miscellaneous), Histogram이 필터·확대에 영향받지 않는다는 명시, Details View 설정 4종(`Band by Type`, `One event per Row`, `Truncate Descriptions`, `Description Visibility`), Counts View의 선형/로그 스케일 주의사항, 클러스터의 `[+]`/`[-]` 펼침, `Alt`+`←`/`→` 이력 이동, 4.13부터 이벤트를 ingest 중 생성하므로 이전 케이스는 동작하지 않는다는 명시
- SRC-005 — Microsoft Learn, Master File Table: Autopsy의 파일시스템 시각이 `$STANDARD_INFORMATION` 계열이라는 점과 `$FILE_NAME` 세트가 별도로 존재한다는 근거
- SRC-004 — Eric Zimmerman 문서: MFTECmd / EvtxECmd의 CSV 출력과 Timeline Explorer로 여러 CSV를 합치는 대안
- **메뉴 경로와 UI 라벨은 Autopsy 버전에 따라 다르다.** 위 라벨은 4.23.0 기준 문서에서 확인한 것이며, 우클릭 메뉴 항목명(파일로 점프, Extract File(s) 등)은 문서에 라벨이 명시되지 않아 단정하지 않았다. **실제 화면에서 확인할 것**
- 시간대 표시(local / UTC)의 전환 위치와 라벨은 버전 차이가 있으므로 화면에서 확인할 것
