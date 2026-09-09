---
id: FOR-0061
title: "UserAssist로 사용자가 직접 실행한 프로그램 찾기"
slug: "userassist"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["UserAssist", "NTUSER.DAT", "Count"]
file_paths: ["C:\\Users\\<user>\\NTUSER.DAT", "%UserProfile%\\NTUSER.DAT"]
registry_paths: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r NTUSER.DAT -p userassist", "rla.exe -f NTUSER.DAT --out .", "RegistryExplorer.exe"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Run Count", "Focus Count", "Focus Time", "Last Executed"]
file_formats: ["regf"]
primary_terms: ["UserAssist", "ROT13", "실행 횟수", "run count", "rla"]
keywords: ["UserAssist", "실행 횟수", "run count", "ROT13", "NTUSER.DAT", "프로그램 실행", "GUI 실행", "마지막 실행 시간"]
aliases: ["userassist", "유저어시스트", "프로그램 실행", "실행 흔적", "몇 번 실행했는지", "누가 무엇을 실행했나", "실행 횟수 확인"]
symptom_keywords: ["프로그램을 실행했는지 알고 싶다", "실행 횟수가 필요하다", "언제 실행했는지", "사용자가 직접 켰는지", "rot13으로 보인다", "레지스트리 값이 암호처럼 보인다"]
related: ["FOR-0021", "FOR-0083"]
source_ids: ["SRC-009", "SRC-004", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`NTUSER.DAT`의 UserAssist 키에는 **사용자가 Explorer에서 직접 실행한** 프로그램의 이름·실행 횟수·마지막 실행 시각이 ROT13으로 인코딩되어 남으며, RegistryExplorer나 RegRipper가 자동 디코딩해 준다.

## 어떤 문제에서 필요한가

- "피의자가 어떤 도구를 사용했는가"
- "이 프로그램을 몇 번 실행했는가"
- "언제 마지막으로 실행했는가"
- "누가 실행했는가" (사용자별 `NTUSER.DAT`이므로 사용자가 자동으로 특정된다)

Prefetch·Amcache·Shimcache가 "실행되었다"는 사실을 알려주는 반면, UserAssist는 **사람이 아이콘을 눌러 실행했다**는 사실을 알려준다. 자동화·스크립트 실행과 사용자 의도를 구분하는 데 결정적이다.

## 문제에서 처음 볼 단서

1. 첨부에 `NTUSER.DAT`이 있다 → UserAssist는 반드시 확인 대상
2. 문제 지문에 "직접", "사용자가", "실행 횟수", "몇 번" 같은 표현
3. 다른 artifact에서 프로그램 이름은 나왔는데 **횟수와 마지막 시각**이 필요한 상황
4. 레지스트리 값 이름이 `Zvpebfbsg.Jvaqbjf` 처럼 자음이 뒤틀린 문자열로 보이면 ROT13이다

## 30초 절차

```powershell
rip.exe -r "C:\case\NTUSER.DAT" -p userassist
```

GUI라면 RegistryExplorer로 `NTUSER.DAT`을 열고 좌측 트리에서 다음 경로로 이동한다.

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count
```

RegistryExplorer는 이 키에 전용 플러그인이 있어 하단 패널에 **디코딩된 프로그램명 / Run Count / Last Executed**를 표로 보여준다. ROT13을 수동으로 풀 필요가 없다.

## 상세 절차

### 1단계 — hive 확보와 정리

`NTUSER.DAT`은 실행 중인 시스템에서 잠겨 있고, 트랜잭션 로그(`NTUSER.DAT.LOG1`, `.LOG2`)에 최신 변경이 남아 있을 수 있다.

```powershell
# 트랜잭션 로그를 hive에 반영(replay) — 최신 값을 놓치지 않으려면 필수
rla.exe -f "C:\case\NTUSER.DAT" --out "C:\case\clean"
```

`rla`(Registry Log Aggregator)를 거치지 않으면 마지막 실행 기록이 누락되는 경우가 있다. 이미지에서 추출할 때 `NTUSER.DAT`, `NTUSER.DAT.LOG1`, `NTUSER.DAT.LOG2`를 **같은 폴더에** 함께 꺼낸다.

### 2단계 — GUID로 무엇이 실행됐는지 구분

`UserAssist` 아래의 GUID 서브키는 "실행 방식"을 뜻한다.

| GUID | 의미 |
| --- | --- |
| `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` | **실행 파일(EXE) 직접 실행** |
| `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` | **바로가기(LNK) 통한 실행** |
| `{75048700-EF1F-11D0-9888-006097DEACF9}` | 구형 시스템의 실행 항목 |
| `{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}` | Windows 8+ UI 항목 |
| `{B267E3AD-A825-4A09-82B9-EEC22AA3B847}` | Windows 8+ 검색/실행 |

두 개만 기억하면 된다. **`CEBFF5CD` = exe, `F4E57C4B` = lnk.** 같은 프로그램이 두 GUID에 모두 있으면 사용자가 직접 exe로도, 바로가기로도 실행했다는 뜻이다.

### 3단계 — 값 이름 = ROT13 인코딩된 실행 경로

`Count` 서브키 아래의 각 **값 이름**이 실행된 대상이다. ROT13(알파벳 13칸 회전)이 적용되어 있다.

```text
저장된 값 이름:
{P:\\Jvaqbjf\\flfgrz32\\pzq.rkr

ROT13 디코딩:
{C:\Windows\system32\cmd.exe
```

숫자와 기호는 변하지 않고 알파벳만 회전한다. 앞의 `{...}` 는 Known Folder GUID인 경우가 있다.

| Known Folder GUID | 실제 경로 |
| --- | --- |
| `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}` | `C:\Windows\System32` |
| `{6D809377-6AF0-444B-8957-A3773F02200E}` | `C:\Program Files` (64비트) |
| `{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}` | `C:\Program Files (x86)` |
| `{F38BF404-1D43-42F2-9305-67DE0B28FC23}` | `C:\Windows` |
| `{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}` | `C:\Windows\System32` (SysWOW 대응) |
| `{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}` | `C:\ProgramData\...\Programs` |
| `{9E3995AB-1F9C-4F13-B827-48B24B6C7174}` | 작업 표시줄 고정 항목 |

### 4단계 — 값 데이터 72바이트 해석 (Windows 7 이후)

수동으로 읽어야 할 때의 바이트 오프셋이다.

| 오프셋 | 크기 | 필드 |
| --- | --- | --- |
| `0x00` | 4 | Session ID |
| `0x04` | 4 | **Run Count (실행 횟수)** |
| `0x08` | 4 | Focus Count (포커스 획득 횟수) |
| `0x0C` | 4 | Focus Time (누적 포커스 시간, ms) |
| `0x10`–`0x3B` | 44 | 사용 통계용 float 배열 |
| `0x3C` | 8 | **Last Executed (FILETIME, UTC)** |
| `0x44` | 4 | 예약/패딩 |

전체 **72바이트(0x48)**. `0x3C`의 8바이트 FILETIME은 1601-01-01 UTC 기준 100ns 단위다 — DCode에 넣으면 바로 변환된다.

> Windows XP는 구조가 다르다. 값 데이터가 16바이트이고 실행 횟수가 **5부터 시작**하므로 `Run Count - 5`가 실제 횟수다.

### 5단계 — RegRipper로 일괄 추출

```powershell
rip.exe -r "C:\case\clean\NTUSER.DAT" -p userassist > userassist.txt
```

출력은 시간 역순으로 정렬되어 나온다.

```text
UserAssist
Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}
LastWrite Time 2026-03-14 07:41:22Z

2026-03-14 07:38:05Z
  C:\Users\jhkim\Downloads\dump_tool.exe (3)
2026-03-14 07:22:41Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe (12)
2026-03-13 22:10:59Z
  {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\7-Zip\7zFM.exe (5)
```

괄호 안 숫자가 Run Count다.

## 출력 필드 해석

| 필드 | 해석 방법 | 주의 |
| --- | --- | --- |
| 프로그램 경로 | ROT13 해제 후의 값. Known Folder GUID는 표로 치환 | 경로가 `Downloads`/`Temp`/`AppData`면 강한 의심 신호 |
| Run Count | 사용자가 실행한 횟수 | XP는 −5 보정 필요 |
| Last Executed | **마지막 1회**의 시각 (UTC) | 이전 실행 시각은 남지 않는다 |
| Focus Time | 실제로 창을 사용한 누적 시간 | 0이면 실행 즉시 종료 = 오류/콘솔 프로그램 가능 |
| 키의 LastWrite | 이 GUID 키가 마지막 갱신된 시각 | 개별 값의 시각과 다르다 |

Focus Time이 크면 사람이 그 프로그램을 실제로 붙잡고 작업했다는 뜻이고, Run Count는 큰데 Focus Time이 0이면 배치성 실행이거나 즉시 종료였다는 뜻이다.

## pivot: 다음에 볼 artifact

UserAssist에서 프로그램 이름과 시각을 얻었다면 그 값으로 다음을 연다.

| 얻은 정보 | 다음 목표 | 무엇을 확인하나 |
| --- | --- | --- |
| 실행 파일 경로 | Prefetch (`C:\Windows\Prefetch\<NAME>-<HASH>.pf`) | 실행 횟수·최초 실행·참조 파일 |
| 실행 파일 경로 | Amcache (`Amcache.hve`) | SHA-1 해시, 최초 등록 시각 |
| 실행 시각 | EVTX Security 4688 ([FOR-0083](./event-4624-logon.html) 인접) | 명령행 인자, 부모 프로세스 |
| 실행 파일이 있던 폴더 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일 생성/삭제 시각, 삭제 여부 |
| `Downloads` 경로 | 브라우저 Downloads ([FOR-0191](./chrome-history.html)) | 어디서 받았는지 |
| LNK GUID 항목 | Jump List, RecentDocs | 어떤 문서를 열었는지 |

## 흔한 함정

- **UserAssist에 없다 = 실행되지 않았다, 는 아니다.** UserAssist는 **Explorer를 통한 실행만** 기록한다. `cmd.exe`에서 타이핑해 실행한 프로그램, 스케줄러·서비스·스크립트가 띄운 프로세스는 **남지 않는다.** 이 경우 Prefetch/Amcache/4688로 가야 한다.
- **명령행 인자가 없다.** UserAssist는 경로만 기록한다. `powershell.exe -enc ...` 같은 인자는 4688이나 4104에서 찾아야 한다.
- **Last Executed는 1개뿐이다.** "3번 실행했다"는 것은 알지만 1·2번째 시각은 UserAssist에 없다. 전체 타임라인은 Prefetch(최근 8회)와 EVTX로 보완한다.
- **`NTUSER.DAT`은 사용자별이다.** 사용자가 여러 명이면 각 프로필의 hive를 모두 봐야 한다. 어느 SID가 누구인지는 `SAM` 또는 `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`로 확인한다.
- **ROT13은 암호가 아니다.** 값이 이상해 보인다고 복호화 툴을 찾을 필요 없다. 툴이 자동으로 풀거나, 최악의 경우 손으로 13칸 돌리면 된다.
- **트랜잭션 로그 미반영.** `rla` 없이 hive만 파싱하면 가장 최근 실행이 빠질 수 있다. 문제의 답이 "마지막 실행"이면 치명적이다.
- **시간대.** FILETIME은 UTC다. RegRipper 출력의 `Z`가 그 뜻이다. KST 답을 요구하면 +9시간.

## 교차검증

같은 "실행" 사실을 최소 두 곳에서 확인한다.

```powershell
# 1) UserAssist — 사용자가 직접 실행했는가 + 횟수
rip.exe -r NTUSER.DAT -p userassist | Select-String 'dump_tool'

# 2) Prefetch — 실행 사실 + 최근 실행 시각 8개 + 로드한 파일
# (WinPrefetchView로 열거나 PECmd 사용)
PECmd.exe -f "C:\case\Prefetch\DUMP_TOOL.EXE-1A2B3C4D.pf"

# 3) Amcache — 파일 해시와 최초 등록
rip.exe -r Amcache.hve -p amcache | Select-String 'dump_tool'

# 4) $MFT — 파일이 언제 디스크에 생겼는가
Import-Csv mft.csv | Where-Object { $_.FileName -like '*dump_tool*' }
```

네 값이 모두 같은 시간대를 가리키면 결론이 단단해진다. UserAssist에만 있고 Prefetch에 없다면 Prefetch가 삭제됐거나(반포렌식) SSD에서 비활성된 환경이다.

## mini walkthrough

```text
문제:
"사용자 jhkim이 자료 유출에 사용한 도구의 이름과 실행 횟수를 구하세요.
 첨부: NTUSER.DAT, NTUSER.DAT.LOG1, NTUSER.DAT.LOG2"

1. 로그 반영
   rla.exe -f NTUSER.DAT --out clean\
   -> clean\NTUSER.DAT 생성

2. 첫 시도: RegRipper 전체
   rip.exe -r clean\NTUSER.DAT -p userassist > ua.txt
   -> 항목이 60개. 너무 많다.

3. 필터: 시스템 기본 프로그램 제외, 사용자 폴더/임시 폴더만
   Select-String -Path ua.txt -Pattern 'Users\\|Temp|Downloads|AppData'

   2026-03-14 07:38:05Z
     C:\Users\jhkim\Downloads\dump_tool.exe (3)
   2026-03-14 07:35:12Z
     C:\Users\jhkim\AppData\Local\Temp\7zS8A1\setup.exe (1)

4. 잘못된 접근이었던 것:
   처음에 {F4E57C4B...}(LNK) 키만 보고 "없다"고 판단했다.
   실제 기록은 {CEBFF5CD...}(EXE) 키에 있었다. 두 GUID를 모두 봐야 한다.

5. 교차검증 — Prefetch
   PECmd.exe -d Prefetch\ --csv .
   -> DUMP_TOOL.EXE  Run Count 3  Last Run 2026-03-14 07:38:05
   UserAssist와 횟수·시각이 일치

6. pivot — 어디서 받았는가
   Chrome History의 downloads 테이블에서 dump_tool.exe 검색
   -> target_path = C:\Users\jhkim\Downloads\dump_tool.exe
      tab_url     = http://filehost.example/dump_tool.exe

정답: dump_tool.exe, 3회
```

## 막혔을 때 다음 체크

1. **두 GUID를 모두 봤는가** — `CEBFF5CD`(exe)와 `F4E57C4B`(lnk)
2. **`rla`로 트랜잭션 로그를 반영했는가**
3. UserAssist가 비어 있다면 → **Prefetch → Amcache → Shimcache → BAM/DAM** 순서로 이동
4. 사용자가 여러 명인가 → 모든 프로필의 `NTUSER.DAT` 확인
5. 값 이름이 GUID로 시작하는가 → Known Folder 표로 치환
6. Run Count가 5 근처의 어색한 값인가 → XP 환경(−5 보정) 의심
7. 명령행 인자가 필요한가 → 4688(Security), 4104(PowerShell ScriptBlock)로 전환
8. Focus Time이 0인가 → 콘솔 프로그램이거나 즉시 종료. 실제 사용 증거는 다른 곳에서

## 출처

- SRC-009 — Forensics Wiki, UserAssist: GUID 목록, ROT13 인코딩, 값 구조
- SRC-004 — Eric Zimmerman 문서: RegistryExplorer UserAssist 플러그인, `rla` 사용법
- SRC-014 — Microsoft Learn, File Times: 오프셋 `0x3C` FILETIME 해석 기준
