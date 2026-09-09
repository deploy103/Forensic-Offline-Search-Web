---
id: FOR-0062
title: "RecentDocs로 최근 열어본 문서와 확장자별 MRU 순서 확인"
slug: "recentdocs"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["RecentDocs", "MRUListEx", "NTUSER.DAT", "shell item", "Folder"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "%AppData%\\Microsoft\\Windows\\Recent", "%UserProfile%\\NTUSER.DAT"]
registry_paths: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.docx", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pdf", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\Folder", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "HxD", "FTK Imager", "KAPE"]
commands: ["rip.exe -r NTUSER.DAT -p recentdocs", "rla.exe -f NTUSER.DAT --out .", "RegistryExplorer.exe"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["MRUListEx", "MRU Position", "Extension", "LastWrite"]
file_formats: ["regf", "lnk"]
primary_terms: ["RecentDocs", "최근 문서", "최근 열어본 파일"]
keywords: ["RecentDocs", "MRUListEx", "최근 문서", "최근 열어본 파일", "확장자별 MRU", "NTUSER.DAT", "shell item", "UTF-16LE", "Folder 서브키", "OpenSavePidlMRU"]
aliases: ["recentdocs", "최근 문서 목록", "어떤 파일을 열었나", "최근 열어본 문서", "mrulistex", "문서 열람 흔적", "최근 파일 순서"]
symptom_keywords: ["어떤 문서를 열었는지 알고 싶다", "가장 최근에 열어본 파일이 뭔지", "파일을 열람한 순서가 필요하다", "레지스트리 값이 이진값으로 보인다", "MRUListEx가 무슨 뜻인지", "파일은 삭제됐는데 열었던 기록이 필요하다"]
related: ["FOR-0057", "FOR-0061", "FOR-0068", "FOR-0070"]
source_ids: ["SRC-017", "SRC-099", "SRC-029"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`RecentDocs`는 사용자가 쉘(Explorer·파일 열기 대화상자)을 통해 열어본 문서의 **파일명과 열람 순서**를 확장자별 서브키에 이진값으로 남기며, 순서는 `MRUListEx`의 4바이트 리틀엔디언 배열이 앞에서부터 최신순으로 알려준다.

## 어떤 문제에서 필요한가

- "피의자가 마지막으로 열어본 문서는 무엇인가"
- "이 파일을 열어본 적이 있는가" (파일 자체가 이미 삭제된 경우에도 이름이 남는다)
- "어떤 순서로 문서를 열었는가"
- "몇 개의 `.docx`를 다뤘는가" — 확장자별 서브키가 그대로 답이다

[FOR-0061](./userassist.html)의 UserAssist가 "무엇을 **실행**했는가"를 답하는 반면, RecentDocs는 "무엇을 **열었는가**"를 답한다. 유출·문서 위조·개인정보 열람 유형 문제에서 가장 먼저 열어야 하는 사용자 키다.

## 문제에서 처음 볼 단서

1. 첨부에 `NTUSER.DAT`이 있고 지문에 "문서", "열어본", "최근", "마지막으로 본" 이 있다
2. `$MFT`에 있어야 할 파일이 삭제되어 없는데 **파일명만이라도** 필요한 상황
3. 확장자를 지정한 질문("가장 최근에 열어본 PDF") — 확장자 서브키를 직접 찍으면 된다
4. 레지스트리 값 이름이 `0`, `1`, `2`, ... 이고 데이터가 이진값이며 옆에 `MRUListEx`가 있다 → RecentDocs 계열 MRU 구조다

## 30초 절차

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p recentdocs > recentdocs.txt
```

GUI라면 RegistryExplorer로 `NTUSER.DAT`을 열고 다음 경로로 이동한다.

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

루트 키에는 전체 문서의 MRU가, 그 아래 `.docx` `.pdf` `.xlsx` `.jpg` 같은 **확장자 이름의 서브키**와 폴더 전용 `Folder` 서브키가 있다. RegistryExplorer는 이 키에 전용 플러그인이 있어 하단 패널에 파일명과 MRU 순위를 표로 풀어 준다.

## 상세 절차

### 1단계 — hive와 트랜잭션 로그를 함께 확보

```powershell
# NTUSER.DAT.LOG1 / .LOG2 를 같은 폴더에 두고 replay 해야 최신 항목이 반영된다
rla.exe -f "C:\case\NTUSER.DAT" --out "C:\case\clean"
```

RecentDocs는 문서를 열 때마다 갱신되므로 **가장 최근 항목이 트랜잭션 로그에만 있는** 경우가 흔하다. "마지막으로 열어본 파일"을 묻는 문제에서 `rla`를 건너뛰면 오답이 나온다.

### 2단계 — 키 구조 파악

| 키 | 내용 |
| --- | --- |
| `RecentDocs` (루트) | 확장자와 무관한 **전체 문서 MRU**. 값 이름 `0`,`1`,`2`... + `MRUListEx` |
| `RecentDocs\.docx` | `.docx` 문서만의 MRU. 확장자마다 서브키가 따로 생긴다 |
| `RecentDocs\.pdf` | `.pdf` 문서만의 MRU |
| `RecentDocs\Folder` | **폴더**를 열어본 기록. 확장자가 없으므로 별도 서브키 |
| `MRUListEx` (각 키의 값) | 그 키 안에서의 사용 순서. 4바이트 DWORD 배열 |

확장자 서브키는 실제로 그 확장자를 열었을 때만 생성된다. **`.docx` 서브키가 없다는 것 자체가 "Word 문서를 쉘로 열지 않았다"는 정보다.**

### 3단계 — MRUListEx 읽기

`MRUListEx`는 REG_BINARY이고 4바이트 리틀엔디언 정수를 나열한 배열이다. **가장 앞이 가장 최근**이고, 끝은 `FF FF FF FF`로 닫힌다.

```text
MRUListEx (16 바이트):
02 00 00 00  00 00 00 00  01 00 00 00  FF FF FF FF

해석: 2 -> 0 -> 1 -> (끝)
      값 이름 "2" 가 가장 최근, 그다음 "0", 그다음 "1"
```

| 바이트 | 값 | 의미 |
| --- | --- | --- |
| `0x00`–`0x03` | `02 00 00 00` | MRU 1위 = 값 이름 `2` |
| `0x04`–`0x07` | `00 00 00 00` | MRU 2위 = 값 이름 `0` |
| `0x08`–`0x0B` | `01 00 00 00` | MRU 3위 = 값 이름 `1` |
| `0x0C`–`0x0F` | `FF FF FF FF` | 배열 종료 표시 |

**값 이름의 숫자는 등록 순서(생성 순번)일 뿐 최근순이 아니다.** 순서는 오직 `MRUListEx`로만 결정된다. 이 구조는 WordWheelQuery([FOR-0070](./wordwheelquery.html))와 `ComDlg32` MRU 계열에도 그대로 쓰인다.

### 4단계 — 값 데이터 구조: UTF-16LE 파일명 + shell item

각 번호 값의 데이터는 두 부분이다.

| 부분 | 내용 |
| --- | --- |
| 앞부분 | **UTF-16LE 널종료 문자열**. 표시용 파일명(대개 확장자 포함) |
| 뒷부분 | **shell item / IDList** 구조. LNK의 `LinkTargetIDList`와 같은 계열로 원본 경로 정보가 인코딩되어 있다 |

```text
값 이름: 2
데이터 (앞부분):
73 00 61 00 6C 00 61 00 72 00 79 00 2E 00 64 00   s.a.l.a.r.y...d.
6F 00 63 00 78 00 00 00 ...                       o.c.x...

-> 파일명 "salary.docx" (UTF-16LE, 마지막 00 00 이 널종료)
-> 그 뒤부터가 shell item. 여기서 원래 폴더/볼륨 정보가 나온다
```

shell item 내부 오프셋은 항목 종류(볼륨·폴더·파일)마다 다르므로 **손으로 세지 말고 파서에 맡긴다.** 필요한 것이 파일명뿐이라면 앞부분 UTF-16LE 문자열만 읽으면 끝난다.

### 5단계 — RegRipper 출력 읽기

```powershell
rip.exe -r "C:\case\clean\NTUSER.DAT" -p recentdocs > recentdocs.txt
```

```text
RecentDocs
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time: 2026-03-14 07:52:19Z

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx
LastWrite Time: 2026-03-14 07:52:19Z
MRUListEx = 2,0,1
  2 = salary.docx
  0 = 사업계획_v3.docx
  1 = 공지사항.docx

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf
LastWrite Time: 2026-03-13 21:04:55Z
MRUListEx = 0
  0 = 계약서_스캔.pdf

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder
LastWrite Time: 2026-03-14 07:41:02Z
MRUListEx = 1,0
  1 = usb_backup
  0 = 대외비
```

`.docx` 서브키의 LastWrite `2026-03-14 07:52:19Z`가 루트 LastWrite와 같다 → **전체 문서 중 가장 최근에 열린 것이 `salary.docx`** 라는 뜻이다.

### 6단계 — 확장자 서브키만 콕 집어 보기

문제가 특정 확장자를 물으면 RegistryExplorer에서 그 서브키만 선택하고 LastWrite를 읽는다. 명령행으로 여러 사용자를 훑을 때는 다음처럼 필터한다([FOR-0121](./powershell-select-string.html)).

```powershell
# 특정 확장자 블록만 남기기
Select-String -Path recentdocs.txt -Pattern 'RecentDocs\\\.pdf' -Context 0,8
```

## 출력 필드 해석

| 필드 | 해석 | 주의 |
| --- | --- | --- |
| 값 이름 (`0`,`1`,`2`...) | 그 키에 등록된 **순번**. 재사용될 수 있다 | 숫자가 크다고 최신이 아니다 |
| `MRUListEx` | 실제 사용 순서. 앞 = 최신 | `FF FF FF FF`는 데이터가 아니라 종료 표시 |
| 데이터 앞부분 | UTF-16LE 파일명 | 확장자가 표시 설정에 따라 빠져 있을 수 있다 |
| 데이터 뒷부분 | shell item(원본 경로 단서) | 오프셋을 추측하지 말고 파서로 확인 |
| 확장자 서브키 이름 | 열었던 파일 형식 | 서브키 자체가 존재 증거 |
| 서브키 `LastWrite` | 그 확장자의 **가장 최근 열람 시각** | 개별 항목별 시각은 없다 |
| 루트 `LastWrite` | 전체 중 가장 최근 열람 시각 | 위와 같은 값이면 그 확장자가 최신 |

`LastWrite`는 레지스트리 키의 FILETIME이므로 1601-01-01 UTC 기준 100ns 단위, **UTC**다. Unix epoch와의 차이는 `11644473600`초이고 KST 답을 요구하면 +9시간 한다. 시스템 시간대는 [FOR-0054](./system-timezone.html)의 `TimeZoneInformation`으로 확인한다.

## pivot: 다음에 볼 artifact

RecentDocs에서 얻은 것은 **파일명**과 **가장 최근 시각 1개**뿐이다. 나머지는 다른 artifact로 채운다.

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 파일명 | `%AppData%\Microsoft\Windows\Recent\<name>.lnk` | LNK 내부의 **전체 경로·볼륨 시리얼·타깃 MAC 시각** |
| 파일명 | Jump List (`AutomaticDestinations-ms`) | 앱별 열람 이력과 접근 횟수 |
| 파일명 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일 생성·수정·삭제 시각, 현재 존재 여부 |
| `Folder` 항목 | ShellBags ([FOR-0068](./shellbags.html)) | 폴더 탐색 시각과 창 위치까지 |
| 파일 저장 흔적 | `ComDlg32\OpenSavePidlMRU` | 열기/저장 대화상자로 다룬 파일과 폴더 |
| 대화상자 방문 폴더 | `ComDlg32\LastVisitedPidlMRU` | 어떤 프로그램이 어느 폴더를 마지막으로 봤는가 |
| 문서를 연 프로그램 | UserAssist ([FOR-0061](./userassist.html)) | WINWORD.EXE 등의 실행 횟수·시각 |
| 열었던 폴더가 외장매체 | USBSTOR / MountPoints2 | 어떤 USB에 있던 파일인가 |

## 흔한 함정

- **값 이름 숫자를 최근순으로 착각한다.** `0`이 가장 오래된 것도, 가장 최근인 것도 아니다. 등록 순번일 뿐이다 → 순서가 답이라면 반드시 `MRUListEx`를 읽는다.
- **`MRUListEx`의 `FF FF FF FF`를 항목으로 센다.** 이것은 배열 종료 표시다 → 마지막 4바이트는 세지 않는다. 항목 수는 `(전체 길이 - 4) / 4`다.
- **RecentDocs에 없으면 열지 않았다고 단정한다.** RecentDocs는 **쉘(Explorer, 파일 열기 대화상자)을 통한 열람만** 기록한다. 스크립트·명령행·서비스가 읽은 파일, `type`·`copy`로 처리한 파일은 남지 않는다 → 없으면 LNK·Jump List·`$MFT`·프로그램별 최근 파일 목록으로 이동한다.
- **항목마다 시각이 있다고 기대한다.** 개별 값에는 타임스탬프가 없다. 있는 것은 **키 단위 LastWrite 하나**뿐이고, 그것은 그 키에 마지막으로 추가된 항목의 시각이다 → 항목별 시각이 필요하면 `Recent` 폴더의 LNK 파일 시각으로 간다.
- **LastWrite를 "그 파일을 연 시각"으로 전부 적용한다.** MRU 2위·3위 항목의 열람 시각은 알 수 없다. LastWrite는 **1위 항목**에만 대응한다고 봐야 한다 → 나머지는 LNK/Jump List로 개별 확인한다.
- **전체 경로가 있다고 생각한다.** 표시용 문자열은 파일명뿐인 경우가 많다. 경로는 뒤쪽 shell item에 인코딩되어 있어 파서 없이는 읽기 어렵다 → 경로가 답이면 LNK나 `OpenSavePidlMRU`를 쓴다.
- **사용자를 하나만 본다.** `NTUSER.DAT`은 사용자별이다. 프로필이 여러 개면 모두 파싱해야 한다. SID와 폴더 매핑은 [FOR-0052](./sam-user-accounts.html)와 `ProfileList`로 확인한다.
- **hive 로그를 반영하지 않는다.** `rla` 없이 파싱하면 최신 항목이 빠진다. "마지막으로 열어본 문서"가 답인 문제에서 치명적이다.
- **`Folder` 서브키를 빼먹는다.** 폴더 열람은 확장자 서브키가 아니라 `Folder`에 들어간다. "어떤 폴더를 봤는가" 질문의 1차 답이 여기 있다.
- **한글 파일명을 ANSI로 읽는다.** 데이터는 UTF-16LE다. hex 뷰어에서 1바이트 인코딩으로 보면 글자 사이에 `00`이 끼어 깨져 보인다 → HxD에서 UTF-16 표시로 바꾸거나 파서를 쓴다.

## 교차검증

같은 "이 문서를 열었다"를 최소 두 곳에서 확인한다.

```powershell
# 1) RecentDocs — 파일명과 MRU 순서
rip.exe -r "C:\case\clean\NTUSER.DAT" -p recentdocs | Select-String 'salary'

# 2) Recent 폴더의 LNK — 전체 경로와 타깃 MAC 시각
LECmd.exe -d "C:\case\Users\jhkim\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\case\out"

# 3) Jump List — 앱별 열람 이력
JLECmd.exe -d "C:\case\Users\jhkim\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\case\out"

# 4) $MFT — 그 파일이 디스크에 언제 있었나 (메타파일 경로는 반드시 작은따옴표)
MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
```

| 조합 결과 | 해석 |
| --- | --- |
| RecentDocs O, LNK O, `$MFT` O | 파일이 존재하고 열람도 확인. 결론 확정 |
| RecentDocs O, LNK O, `$MFT` X | 열람 후 **삭제**됨. `$UsnJrnl`·`$Recycle.Bin`으로 삭제 시각 추적 |
| RecentDocs O, LNK X | `Recent` 폴더가 정리(반포렌식)되었거나 정책으로 LNK 생성이 꺼져 있다 |
| RecentDocs X, LNK O | LNK가 다른 경로로 생성됨. 루트 MRU와 확장자 서브키를 다시 확인 |
| RecentDocs X, `$MFT`에 접근 흔적만 | 쉘을 거치지 않은 접근(스크립트·명령행) |

## mini walkthrough

```text
문제:
"사용자 jhkim이 가장 마지막에 열어본 문서의 파일명과 그 시각(KST)을 구하세요.
 첨부: NTUSER.DAT, NTUSER.DAT.LOG1, NTUSER.DAT.LOG2, UsrClass.dat"

1. 첫 시도 (실패)
   RegistryExplorer로 NTUSER.DAT 을 그대로 열고
   RecentDocs\.docx 의 값 목록에서 이름이 가장 큰 "5" 를 최근 항목이라고 판단.
   -> "5 = 회의록.docx" 를 답으로 냈으나 오답.

   왜 틀렸는가:
   값 이름의 숫자는 등록 순번이지 최근순이 아니다.
   순서를 결정하는 것은 MRUListEx 하나뿐이다.

2. 두 번째 문제 (또 실패)
   로그를 반영하지 않고 원본 hive 만 파싱했다.
   -> RecentDocs 루트 LastWrite 가 2026-03-14 06:10:33Z 로 나왔는데
      다른 artifact(LNK)에는 07:52 대 항목이 있어 모순.

3. 피벗 1 — 트랜잭션 로그 반영
   rla.exe -f NTUSER.DAT --out clean\
   -> clean\NTUSER.DAT 재파싱
      루트 LastWrite = 2026-03-14 07:52:19Z 로 갱신. LNK 와 모순 해소.

4. 피벗 2 — MRUListEx 로 순서 확정
   rip.exe -r clean\NTUSER.DAT -p recentdocs > rd.txt

   RecentDocs                     LastWrite 2026-03-14 07:52:19Z
   RecentDocs\.docx               LastWrite 2026-03-14 07:52:19Z
     MRUListEx = 2,0,1,5
       2 = salary.docx        <- MRU 1위 = 가장 최근
       0 = 사업계획_v3.docx
       1 = 공지사항.docx
       5 = 회의록.docx        <- 이름은 최대지만 MRU 4위

   RecentDocs\.pdf                LastWrite 2026-03-13 21:04:55Z

5. 루트와 확장자 LastWrite 비교
   루트 07:52:19Z == .docx 07:52:19Z
   -> 전체 최근 문서는 .docx 계열의 MRU 1위, 즉 salary.docx

6. 교차검증 — Recent 폴더 LNK
   LECmd.exe -d Recent\ --csv out\
   -> salary.docx.lnk
      SourceAccessed  2026-03-14 07:52:18
      TargetPath      D:\대외비\salary.docx
      -> 볼륨이 D: = 외장매체 가능성 -> USBSTOR 로 pivot 대상 확보

7. 시간대 변환
   07:52:19Z (UTC) + 9h = 2026-03-14 16:52:19 KST

정답: salary.docx / 2026-03-14 16:52:19 KST
```

## 막혔을 때 다음 체크

1. **`MRUListEx`를 읽었는가** — 값 이름 숫자로 순서를 판단하지 않았는가
2. **`rla`로 `.LOG1`/`.LOG2`를 반영했는가** — 최신 항목 누락의 90%가 이것이다
3. **루트 `RecentDocs`와 확장자 서브키를 모두 봤는가** — 루트 LastWrite가 어느 확장자와 같은지가 "전체 최신"의 근거다
4. **`Folder` 서브키를 봤는가** — 폴더 질문은 여기에 답이 있다
5. RecentDocs가 비어 있다 → `Recent` 폴더 LNK → Jump List → `ComDlg32\OpenSavePidlMRU` → ShellBags 순으로 이동
6. 전체 경로가 필요한가 → RecentDocs 대신 LNK 또는 `OpenSavePidlMRU`
7. 항목별 시각이 필요한가 → LNK 파일의 MAC 시각과 내부 타깃 시각
8. 사용자가 여러 명인가 → 모든 프로필의 `NTUSER.DAT` 파싱. hive 위치는 [FOR-0051](./registry-hive-map.html) 참고
9. 값 데이터가 글자 사이에 `00`이 끼어 보이는가 → UTF-16LE다. 인코딩 표시를 바꾼다

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `NTUSER.DAT`의 위치와 `HKCU` 매핑, hive가 사용자별이라는 근거
- SRC-099 — RegRipper 3.0 repository: `recentdocs` 플러그인과 `rip.exe -r ... -p ...` 사용법, 플러그인 출력 형식
- SRC-029 — Libyal liblnk 문서: 값 데이터 뒷부분에 들어가는 shell item / IDList 구조와 LNK 교차검증 근거
- 플러그인 목록은 `rip.exe -l`로, RegistryExplorer의 패널 구성과 컬럼명은 실제 화면에서 확인할 것. 도구 버전에 따라 다를 수 있다
- shell item 내부 오프셋은 항목 종류마다 달라 여기서 단정하지 않았다. 원본 경로가 답이면 파서 출력을 근거로 쓸 것
