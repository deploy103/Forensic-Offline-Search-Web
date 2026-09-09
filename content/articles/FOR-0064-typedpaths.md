---
id: FOR-0064
title: "TypedPaths로 탐색기 주소창에 직접 입력한 경로 찾기"
slug: "typedpaths"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["TypedPaths", "url1", "NTUSER.DAT", "UNC 경로", "RunMRU"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "%UserProfile%\\NTUSER.DAT"]
registry_paths: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "RECmd", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r NTUSER.DAT -p typedpaths", "rip.exe -r NTUSER.DAT -p runmru", "rla.exe -f NTUSER.DAT --out ."]
regex_patterns: ["^\\\\\\\\[A-Za-z0-9._-]+\\\\[^\\\\]+"]
wireshark_filters: []
tshark_fields: []
log_fields: ["url1", "url2", "LastWrite"]
file_formats: ["regf"]
primary_terms: ["TypedPaths", "탐색기 주소창 입력", "url1"]
keywords: ["TypedPaths", "url1", "주소창", "탐색기 주소창", "직접 입력한 경로", "UNC 경로", "원격 공유 접근", "NTUSER.DAT", "사용자 의도", "RunMRU"]
aliases: ["typedpaths", "주소창에 입력한 경로", "탐색기 경로 입력 기록", "url1 url2", "unc 경로 흔적", "원격 공유 접근 기록", "직접 타이핑한 폴더"]
symptom_keywords: ["사용자가 직접 입력한 경로를 알고 싶다", "네트워크 공유에 접근했는지", "폴더 경로를 타이핑한 기록이 필요하다", "고의성을 증명해야 한다", "url1이 무슨 값인지", "숨긴 폴더에 어떻게 갔는지"]
related: ["FOR-0057", "FOR-0062", "FOR-0067", "FOR-0068"]
source_ids: ["SRC-017", "SRC-099", "SRC-079"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`TypedPaths`의 `url1`, `url2` ... 값은 사용자가 **탐색기 주소창에 손으로 타이핑해 넣은 경로**이고 `url1`이 가장 최근이다. 클릭으로 탐색한 흔적이 아니라 **입력한** 흔적이므로 고의성을 증명하는 가장 강한 사용자 의도 증거다.

## 어떤 문제에서 필요한가

- "피의자가 그 폴더의 존재를 알고 있었는가" — 경로를 타이핑했다면 알고 있었다
- "네트워크 공유에 접근했는가" — `\\server\share` 형태가 남으면 원격 접근 증거
- "숨겨진 폴더나 링크 없는 경로에 어떻게 도달했는가"
- "마지막으로 입력한 경로는 무엇인가"

`ShellBags`는 "폴더 창을 열었다"를, `RecentDocs`는 "파일을 열었다"를 알려준다. `TypedPaths`만이 **"경로 문자열을 직접 쳤다"** 를 알려준다. 아이콘을 눌러 우연히 들어간 것과 경로를 외워 타이핑한 것은 고의성 판단에서 무게가 다르다.

## 문제에서 처음 볼 단서

1. 첨부에 `NTUSER.DAT`이 있고 지문에 "직접 입력", "주소창", "타이핑", "고의로"
2. 지문에 네트워크 공유·서버명·IP가 등장하고 그 접근 증거를 찾는 상황
3. 다른 artifact에는 없는 경로가 답이어야 하는 경우(링크·바로가기 없이 접근)
4. 레지스트리 값 이름이 `url1`, `url2`, `url3` 이고 데이터가 사람이 읽을 수 있는 문자열이다

## 30초 절차

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p typedpaths
```

GUI라면 RegistryExplorer로 `NTUSER.DAT`을 열고 다음 경로로 이동한다.

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

값이 `REG_SZ`(문자열)라서 **파서 없이 눈으로 바로 읽힌다.** 디코딩·이진 해석이 필요 없다는 점이 이 artifact의 최대 장점이다.

## 상세 절차

### 1단계 — hive 확보와 로그 반영

```powershell
rla.exe -f "C:\case\NTUSER.DAT" --out "C:\case\clean"
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedpaths > typedpaths.txt
```

`NTUSER.DAT`, `NTUSER.DAT.LOG1`, `NTUSER.DAT.LOG2`를 같은 폴더에 함께 꺼낸 뒤 `rla`로 replay한다. 주소창 입력은 로그오프 시점에 flush되는 경우가 있어 **가장 최근 입력이 트랜잭션 로그에만 남기 쉽다.**

### 2단계 — 키 구조

| 항목 | 내용 |
| --- | --- |
| 키 | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` |
| 값 이름 | `url1`, `url2`, `url3` ... |
| 값 타입 | `REG_SZ` (UTF-16LE 문자열, 사람이 읽을 수 있음) |
| 순서 | **`url1`이 가장 최근**, 숫자가 커질수록 오래됨 |
| 시각 | 개별 값에는 없음. **키 LastWrite 하나뿐** |
| 범위 | 실무 관측상 수십 개까지 쌓인다. 상한은 Windows 빌드에 따라 다르므로 실제 키에서 값 개수를 확인한다 |

`MRUListEx` 같은 별도 순서 배열이 **없다.** 순서는 값 이름의 숫자 자체가 나타낸다. 이 점이 `RecentDocs`·`WordWheelQuery` 계열과 근본적으로 다르다.

### 3단계 — 값 데이터에 무엇이 들어오는가

주소창에 입력해 이동이 성공한 대상이 그대로 문자열로 들어간다.

| 데이터 예 | 의미 | 포렌식 가치 |
| --- | --- | --- |
| `C:\Users\jhkim\Documents\대외비` | 로컬 경로 타이핑 | 그 폴더를 알고 있었다 |
| `D:\` | 드라이브 루트 | 외장매체·추가 볼륨 접근 |
| `\\192.168.10.55\backup` | **UNC 경로(IP)** | 원격 공유 접근. 대상 호스트 확보 |
| `\\FILESRV01\HR$` | UNC 경로(호스트명 + 관리 공유) | 관리 공유 `$` 접근은 강한 신호 |
| `ftp://ftp.example.com` | 주소창에 URL 입력 | 탐색기를 통한 외부 전송 시도 |
| `%TEMP%` | 환경변수 표기 | 확장 전 문자열이 그대로 남을 수 있다 |
| `Control Panel\...` | 쉘 위치 | 설정 접근 |

UNC 경로 표기 규칙(`\\server\share\path`)은 Windows 경로 규칙 문서에 정의된 형태 그대로다. 서버 부분이 IP면 그 IP가, 호스트명이면 그 이름이 **다음 조사 대상**이 된다.

### 4단계 — 출력 읽기

```powershell
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedpaths
```

```text
TypedPaths
Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
LastWrite Time: 2026-03-14 07:44:31Z

  url1 -> \\192.168.10.55\backup
  url2 -> D:\usb_backup
  url3 -> C:\Users\jhkim\AppData\Local\Temp
  url4 -> C:\대외비\인사자료
  url5 -> \\FILESRV01\HR$
```

읽는 순서는 이렇다.

1. `url1` = `\\192.168.10.55\backup` → **가장 마지막에 입력한 경로.** 키 LastWrite `2026-03-14 07:44:31Z`가 이 항목의 입력 시각에 대응한다
2. `url2` 이하는 그 이전 입력들이지만 **각각의 시각은 알 수 없다**
3. `url5`의 `HR$`는 관리 공유다. 일반 사용자가 우연히 타이핑할 문자열이 아니다

### 5단계 — 수동 확인 절차 (파서가 없을 때)

RegistryExplorer의 값 목록에서 그대로 읽으면 끝이지만, hive를 텍스트로만 다뤄야 할 때는 문자열 검색으로도 충분히 잡힌다.

```text
1. FTK Imager 또는 KAPE 로 C:\Users\<user>\NTUSER.DAT 추출
2. RegistryExplorer 로 열기 -> 좌측 트리에서
   Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths 선택
3. 우측 값 목록에서 url1..urlN 을 순서대로 기록
4. 키를 선택한 상태에서 하단/속성의 Last Write Timestamp 를 기록 (UTC)
5. url1 = 최근. LastWrite 는 url1 에만 대응한다고 적어 둔다
```

UNC 경로만 빠르게 뽑으려면 정규식으로 훑는다. PowerShell에서는 정규식을 **항상 작은따옴표**로 감싼다.

```powershell
# UNC 시작 형태만 추출 (\\host\share)
Select-String -Path .\typedpaths.txt -Pattern '\\\\[A-Za-z0-9._-]+\\[^\\]+'
```

### 6단계 — 비슷한 키와 헷갈리지 않기

주소창 입력과 **실행 대화상자 입력**은 다른 키다.

| 키 | 무엇을 기록하나 | 값 이름 | 순서 배열 |
| --- | --- | --- | --- |
| `Explorer\TypedPaths` | **탐색기 주소창**에 입력한 경로 | `url1`, `url2` ... | 없음(이름이 순서) |
| `Explorer\RunMRU` | **실행(Win+R) 대화상자**에 입력한 명령 | `a`, `b`, `c` ... | `MRUList` 값(문자 나열) |
| `Internet Explorer\TypedURLs` | IE 주소창에 입력한 URL | `url1`, `url2` ... | 없음 |

`RunMRU`는 값 데이터 끝에 `\1`이 붙고 순서는 `MRUList` 값의 문자 나열로 표현된다. 이름이 `url1`이면 `TypedPaths` 또는 `TypedURLs`이고, 어느 쪽인지는 **부모 키가 `Explorer`인지 `Internet Explorer`인지**로 구분한다.

## 출력 필드 해석

| 필드 | 해석 | 주의 |
| --- | --- | --- |
| `url1` | 가장 최근에 입력한 경로 | 키 LastWrite에 대응하는 유일한 항목 |
| `url2`..`urlN` | 그 이전 입력. 숫자가 클수록 오래됨 | 개별 시각 없음 |
| 데이터가 `\\`로 시작 | UNC = 원격 공유 접근 | 서버/IP가 다음 pivot 대상 |
| 데이터에 `$` 로 끝나는 공유명 | 관리 공유(`C$`, `ADMIN$`, `HR$`) | 우연히 입력되지 않는다 |
| 데이터가 드라이브 루트만 | 외장매체·추가 볼륨 | `MountPoints2`·USBSTOR로 pivot |
| 키 `LastWrite` | `url1` 입력 시각(FILETIME, UTC) | 나머지 항목에는 적용 불가 |

`LastWrite`는 FILETIME이므로 1601-01-01 UTC 기준 100ns 단위다. Unix epoch 차이는 `11644473600`초, KST는 +9시간이다. 시스템 시간대는 [FOR-0054](./system-timezone.html)의 `TimeZoneInformation`으로 확인한다.

## pivot: 다음에 볼 artifact

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| UNC 서버명/IP | EVTX Security 4624 Type 3 ([FOR-0083](./event-4624-logon.html)) | 네트워크 로그온 성공 여부와 시각 |
| UNC 공유명 | Security 5140 / 5145 | 공유 접근과 개별 파일 접근 |
| UNC 경로 | `HKCU\...\Explorer\MountPoints2`의 `##server#share` | 그 공유가 실제로 마운트되었는가 |
| 로컬 폴더 경로 | ShellBags ([FOR-0068](./shellbags.html)) | 그 폴더 창을 실제로 열었는가, 언제 |
| 로컬 폴더 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 폴더의 파일 목록과 시각 |
| 드라이브 문자 | USBSTOR([FOR-0066](./usbstor.html)) / `MountedDevices`([FOR-0067](./mounteddevices.html)) | 어떤 장치가 그 문자를 썼는가 |
| 입력 시각(LastWrite) | 같은 시각대의 UserAssist ([FOR-0061](./userassist.html)) | 그 시각에 무엇을 실행했는가 |
| `ftp://`·`http://` 입력 | PCAP·프록시 로그 | 실제 전송 발생 여부 |

## 흔한 함정

- **`url1`을 "첫 번째로 입력한 경로"로 읽는다.** 정반대다. **`url1`이 가장 최근**이고 숫자가 커질수록 오래된 입력이다 → 시간 순서를 물으면 역순으로 나열한다.
- **모든 항목에 LastWrite 시각을 붙인다.** 개별 값에는 타임스탬프가 없다. 키 LastWrite 하나가 있을 뿐이고 그것은 `url1`에만 대응한다 → `url2` 이하의 시각은 ShellBags·EVTX·`$MFT`로 별도 확보한다.
- **탐색기로 클릭해 들어간 폴더가 여기 남는다고 생각한다.** `TypedPaths`는 **주소창에 입력한 것만** 기록한다. 트리·아이콘 클릭 탐색은 ShellBags에 남는다 → "폴더를 봤는가"는 ShellBags, "경로를 쳤는가"는 `TypedPaths`다.
- **실행 대화상자 입력을 `TypedPaths`에서 찾는다.** Win+R 입력은 `Explorer\RunMRU`다. 값 이름이 `a`,`b`,`c`이고 `MRUList`가 순서를 담는다 → 두 키를 모두 본다.
- **IE `TypedURLs`와 혼동한다.** 이름이 똑같이 `url1`이지만 키가 `Software\Microsoft\Internet Explorer\TypedURLs`다 → 부모 키를 확인한다.
- **비어 있으면 "주소창을 안 썼다"고 단정한다.** 항목은 상한을 넘으면 밀려 나가고, 사용자가 탐색기 주소창 기록을 지우거나 정리 도구를 돌리면 사라진다. 키는 남아 있는데 값이 없다면 **삭제 정황**으로 본다 → 키 LastWrite와 hive 슬랙, `$UsnJrnl`의 hive 변경을 확인한다.
- **사용자를 하나만 본다.** `NTUSER.DAT`은 사용자별이다. UNC 경로를 입력한 사용자가 누구인지가 답인 문제라면 모든 프로필을 파싱해야 한다.
- **hive 로그를 반영하지 않는다.** `rla` 없이 파싱하면 마지막 입력이 빠진다. `url1`이 답인 문제에서 치명적이다.
- **경로 문자열이 존재를 보장한다고 생각한다.** `TypedPaths`에는 이동이 성공한 경로가 들어가지만, 그 이후 폴더가 삭제·이름 변경되었을 수 있다 → `$MFT`로 실제 존재와 시각을 확인한다.
- **시간대를 안 맞춘다.** LastWrite는 UTC다. KST 답을 요구하면 +9시간.

## 교차검증

`TypedPaths`는 "입력했다"만 말한다. "실제로 들어갔다"와 "무엇을 했다"는 다른 artifact가 답한다.

| artifact | 답하는 질문 | 근거의 성격 |
| --- | --- | --- |
| `TypedPaths` | 경로를 **입력**했는가 | 사용자 의도(가장 강함) |
| `RunMRU` | 명령을 **실행 대화상자에 입력**했는가 | 사용자 의도 |
| ShellBags | 폴더 창을 **열었는가** | 탐색 행위 |
| `RecentDocs` | 파일을 **열었는가** | 열람 행위 |
| `MountPoints2` | 볼륨/공유가 **마운트**되었는가 | 시스템 상태 |
| USBSTOR / `MountedDevices` | 어떤 **장치**가 연결되었는가 | 하드웨어 |
| Security 4624 Type 3 / 5140 | 원격 공유에 **로그온·접근**했는가 | 네트워크 사실 |

```powershell
# 1) TypedPaths — 입력한 경로
rip.exe -r "C:\case\clean\NTUSER.DAT" -p typedpaths

# 2) RunMRU — 실행 대화상자 입력
rip.exe -r "C:\case\clean\NTUSER.DAT" -p runmru

# 3) MountPoints2 — 공유/볼륨 마운트 흔적 (##server#share 형태 확인)
rip.exe -r "C:\case\clean\NTUSER.DAT" -p mp2

# 4) ShellBags — 실제로 창을 열었는가
SBECmd.exe -d "C:\case\Users\jhkim" --csv "C:\case\out"

# 5) $MFT — 그 경로가 언제 존재했는가 (메타파일 경로는 반드시 작은따옴표)
MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
```

| 조합 결과 | 해석 |
| --- | --- |
| `TypedPaths` O, ShellBags O | 입력 + 실제 탐색. 결론 확정 |
| `TypedPaths` O, ShellBags X | 입력은 했으나 창 기록이 없다. `UsrClass.dat` 확보 여부부터 확인 |
| `TypedPaths` UNC O, 4624 Type 3 O | 원격 접근 성립. 대상 호스트·계정 확정 |
| `TypedPaths` UNC O, 로그 없음 | 대상 호스트의 로그를 못 받았거나 접근 실패. 실패도 "시도"의 증거다 |
| `TypedPaths` X, ShellBags O | 클릭으로만 탐색. 고의성 주장은 약해진다 |

## mini walkthrough

```text
문제:
"내부 직원이 자료를 외부로 옮기기 전에 접근한 '네트워크 공유 경로'와
 그 경로를 입력한 시각(KST)을 구하세요.
 첨부: NTUSER.DAT, NTUSER.DAT.LOG1, NTUSER.DAT.LOG2, UsrClass.dat, Security.evtx"

1. 첫 시도 (실패)
   ShellBags 부터 열었다.
   SBECmd.exe -d Users\jhkim --csv out\
   -> 로컬 폴더(C:\대외비\인사자료 등)만 잔뜩. 네트워크 공유가 안 보인다.
      "공유 접근 없음" 이라고 판단.

   왜 틀렸는가:
   ShellBags 는 탐색기 창으로 '탐색한' 흔적이다.
   주소창에 UNC 를 타이핑해 바로 들어간 경우 ShellBags 항목이
   남지 않거나 다른 형태로 들어가 눈에 띄지 않는다.
   '입력' 증거는 TypedPaths 가 전담한다.

2. 두 번째 실수
   rip.exe -r NTUSER.DAT -p typedpaths   (원본 hive, rla 미적용)
   LastWrite Time: 2026-03-14 06:02:11Z
     url1 -> D:\usb_backup
   -> UNC 가 없다. 여기서 또 "없음" 으로 갈 뻔했다.

3. 피벗 1 — 트랜잭션 로그 반영
   rla.exe -f NTUSER.DAT --out clean\
   rip.exe -r clean\NTUSER.DAT -p typedpaths

   LastWrite Time: 2026-03-14 07:44:31Z
     url1 -> \\192.168.10.55\backup      <- 최근 입력. 원본 hive 에 없던 항목
     url2 -> D:\usb_backup
     url3 -> C:\Users\jhkim\AppData\Local\Temp
     url4 -> C:\대외비\인사자료
     url5 -> \\FILESRV01\HR$

   -> 마지막 입력이 UNC 였다. rla 를 건너뛴 것이 실패의 원인이었다.

4. 피벗 2 — 마운트 흔적으로 실제 접근 확인
   rip.exe -r clean\NTUSER.DAT -p mp2
   -> ##192.168.10.55#backup  서브키 존재
      입력만 한 것이 아니라 실제로 연결됐다.

5. 교차검증 — Security.evtx 네트워크 로그온
   EvtxECmd.exe -f Security.evtx --csv out\
   Import-Csv out\*Security*.csv |
     Where-Object { $_.EventId -eq 4624 -and $_.PayloadData1 -match 'Type 3' }
   -> 2026-03-14 07:44:29Z  TargetUserName jhkim  IpAddress 192.168.10.55
      TypedPaths LastWrite(07:44:31Z) 와 2초 차이. 같은 행위로 확정.

6. url5 도 확인
   \\FILESRV01\HR$ 는 관리 공유. 우연한 입력이 아니다.
   -> 별건으로 기록. FILESRV01 로그 확보 요청 대상.

7. 시간대 변환
   07:44:31Z (UTC) + 9h = 2026-03-14 16:44:31 KST

정답: \\192.168.10.55\backup / 2026-03-14 16:44:31 KST
```

## 막혔을 때 다음 체크

1. **`rla`로 `.LOG1`/`.LOG2`를 반영했는가** — 마지막 입력 누락의 대부분이 이것이다
2. **`url1`이 최근이라는 방향을 맞게 잡았는가**
3. **LastWrite를 `url1`에만 적용했는가** — 다른 항목에 시각을 붙이지 않았는가
4. **`RunMRU`도 봤는가** — 실행 대화상자 입력은 별도 키다
5. **`MountPoints2`의 `##server#share` 서브키를 봤는가** — 입력이 실제 연결로 이어졌는지의 근거
6. `TypedPaths`가 비어 있다 → ShellBags → `RecentDocs` → LNK/Jump List → EVTX 5140/5145 순으로 이동
7. UNC가 나왔다 → 서버 IP/호스트명으로 4624 Type 3, 5140, DNS 캐시, PCAP까지 확장
8. 사용자가 여러 명인가 → 모든 프로필의 `NTUSER.DAT`. hive 위치는 [FOR-0051](./registry-hive-map.html)
9. 키는 있는데 값이 없다 → 정리 도구·수동 삭제 정황. 키 LastWrite와 hive 슬랙 확인

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `NTUSER.DAT`의 위치와 `HKCU` 매핑, hive가 사용자별이라는 근거
- SRC-099 — RegRipper 3.0 repository: `typedpaths`, `runmru`, `mp2` 계열 플러그인과 `rip.exe -r ... -p ...` 사용법
- SRC-079 — Microsoft Learn, Naming Files, Paths, and Namespaces: UNC 경로 표기(`\\server\share`)와 Windows 경로 문법 정의
- `TypedPaths`가 보관하는 항목 수의 상한은 Windows 빌드에 따라 다르므로 실제 키의 값 개수로 확인할 것. 여기서 특정 숫자를 단정하지 않았다
- 플러그인 이름은 배포 버전에 따라 다르므로 `rip.exe -l`로 확인할 것
