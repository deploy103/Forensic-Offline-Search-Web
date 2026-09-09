---
id: FOR-0076
title: "프로그램 실행 흔적 교차검증: 12개 증거원 비교표"
slug: "recent-execution-crosscheck"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["UserAssist", "Prefetch", "Amcache", "Shimcache", "AppCompatCache", "BAM", "DAM", "MUICache", "SRUM", "Jump List", "LNK", "$MFT"]
file_paths: ["C:\\Windows\\Prefetch", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "C:\\Windows\\System32\\sru\\SRUDB.dat", "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent", "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations", "C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt", "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive"]
registry_paths: ["SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache", "SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings", "SYSTEM\\ControlSet001\\Services\\dam\\State\\UserSettings", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", "UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", "NTUSER.DAT\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "AppCompatCacheParser", "AmcacheParser", "PECmd", "WinPrefetchView", "EvtxECmd", "Timeline Explorer", "rla"]
commands: ["PECmd.exe -d C:\\case\\Prefetch --csv C:\\case\\out", "AppCompatCacheParser.exe -f C:\\case\\SYSTEM --csv C:\\case\\out", "rip.exe -r NTUSER.DAT -p userassist"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["Run Count", "Last Executed", "LastRun", "SourceCreated", "LastModifiedTimeUTC", "Executed", "FileId", "LinkDate", "SubjectUserSid", "CommandLine"]
file_formats: ["regf", "pf", "hve", "lnk"]
primary_terms: ["실행 흔적 교차검증", "프로그램 실행 증거 비교", "실행했는지 확인"]
keywords: ["실행 흔적", "교차검증", "UserAssist", "Prefetch", "Amcache", "Shimcache", "BAM", "MUICache", "SRUM", "Jump List", "실행 증거", "실행 횟수", "안티포렌식"]
aliases: ["실행했는지 확인", "프로그램 실행 증거", "실행 흔적 비교", "어디서 실행 확인", "실행 안 했다고 주장", "실행 증거 교차검증"]
symptom_keywords: ["이 프로그램을 실행했는지 알고 싶다", "실행 흔적이 하나도 없다", "artifact마다 시각이 다르다", "Shimcache에만 있다", "실행 횟수가 서로 다르다", "실행 시각을 확정해야 한다"]
related: ["FOR-0061", "FOR-0071", "FOR-0079", "FOR-0088"]
source_ids: ["SRC-031", "SRC-030", "SRC-017", "SRC-021"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

"이 프로그램이 실행되었는가"는 단일 artifact로 답하지 않는다 — **기록 주체가 서로 다른 증거원 최소 2개(가능하면 3개)가 같은 방향을 가리킬 때만** 실행을 단정하고, Shimcache처럼 실행을 보장하지 않는 것은 확증 카운트에 넣지 않는다.

## 어떤 문제에서 필요한가

- "피의자가 이 도구를 실행했는가" — 실행 부인에 대한 반박
- "언제 실행했는가" — 여러 artifact의 시각이 서로 다르다
- "몇 번 실행했는가" — UserAssist와 Prefetch의 횟수가 다르다
- Shimcache나 Amcache에만 이름이 있고 다른 곳엔 없다
- 실행 흔적이 하나도 없는데 실행되었다고 봐야 할 근거가 필요하다
- 반포렌식(Prefetch 삭제, 로그 소거)이 의심된다

## 문제에서 처음 볼 단서

1. 지문이 "실행"이라는 단어를 쓴다 → 무엇을 실행 증거로 인정할지부터 정한다
2. 지문이 "사용자가 직접"이라고 한다 → UserAssist·Jump List 쪽으로 무게가 간다
3. 지문이 "몇 번"이라고 한다 → 실행 횟수를 가진 artifact는 UserAssist와 Prefetch뿐이다
4. 지문이 "명령행 인자"를 묻는다 → 레지스트리에는 없다. 4688·Sysmon 1·4104로 간다
5. 첨부에 Prefetch 폴더가 없다 → 삭제됐는지, 애초에 비활성이었는지부터 판정한다

## 30초 절차

```powershell
PECmd.exe -d "C:\case\Prefetch" --csv "C:\case\out" --csvf pf.csv
```

세 줄로 1차 스캔을 끝낸다.

```powershell
# 1) 실행 사실 + 횟수 + 최근 8회 시각
PECmd.exe -d "C:\case\Prefetch" --csv "C:\case\out" --csvf pf.csv
# 2) 사용자가 직접 실행했는가 + 횟수
rip.exe -r "C:\case\NTUSER.DAT" -p userassist
# 3) 사용자별 최근 실행 시각 (BAM)
rip.exe -r "C:\case\SYSTEM" -p bam
```

## 상세 절차

### 1단계 — 증거원 비교표 (이 글의 본체)

| artifact | 기록 주체 | 실행 횟수 | 시각 개수 | 사용자 특정 | "실행"을 보장하나 | 보존 특성 |
| --- | --- | --- | --- | --- | --- | --- |
| **UserAssist** | Explorer (셸) | **있음** | 마지막 1개 | **가능** (사용자 hive) | 실행 보장. 단 **Explorer 경유만** | 프로필이 남는 동안 계속 |
| **Prefetch** | 커널 (Superfetch/Sysmain) | **있음** | Win8+ **최근 8개**, Win7은 1개 | 불가 | **실행 보장** (가장 강한 단독 증거) | Win8+ 최대 1024개 파일, 넘으면 오래된 것부터 삭제 |
| **Amcache** | Appraiser 예약 작업 | 없음 | 등록 시각(키 LastWrite) + `LinkDate` | 불가 | **보장 안 됨** — 디스크에 있는 파일을 목록화 | hive가 살아 있는 동안. 삭제된 파일도 남는다 |
| **Shimcache / AppCompatCache** | 커널 (shim 엔진) | 없음 | 1개 — **파일의 수정 시각** | 불가 | **보장 안 됨** — 존재/호환성 검사일 수 있다 | 엔트리 상한 존재. **종료 시 디스크에 기록** |
| **BAM / DAM** | 백그라운드 활동 조절 서비스 | 없음 | 마지막 1개 | **가능** (키 이름이 SID) | 실행 보장 | **약 1주 단위로 정리**된다. 오래된 것은 없다 |
| **MUICache** | Explorer (셸) | 없음 | **없음** | **가능** (사용자 hive) | 강한 연관. 단독으로는 약하다 | 사용자 hive가 남는 동안 |
| **SRUM** | 진단 정책 서비스 | 없음 | 시간 단위 사용량 레코드 다수 | **가능** (사용자 SID) | 실행 + 자원 사용 보장 | 약 30~60일. 주기적으로 DB에 기록 |
| **EVTX 4688** | 감사 정책 | 없음 (건별) | **모든 실행이 1건씩** | **가능** (`SubjectUserSid`) | **실행 보장 + 명령행** | 감사 정책이 켜져 있어야 존재. 로그 크기만큼 |
| **Sysmon Event ID 1** | Sysmon 드라이버 | 없음 (건별) | **모든 실행이 1건씩** | **가능** | **실행 보장 + 해시 + 부모** | Sysmon이 설치된 환경에서만 |
| **$MFT** | 파일시스템 | 없음 | 파일의 MACB | 불가 | **실행과 무관** — 존재와 시각만 | 볼륨이 있는 동안 |
| **Jump List** | Explorer (셸) | 항목별 접근 횟수 | 항목별 접근 시각 | **가능** | 앱 **사용** 보장 (문서 단위) | 사용자 프로필 안 |
| **LNK (Recent)** | Explorer (셸) | 없음 | 대상 파일의 MACB + LNK 자체 MACB | **가능** | **파일 열기** 보장. 프로그램 실행 증거는 아니다 | 사용자 프로필 안 |

**기록 주체 칼럼이 이 표의 핵심이다.** 같은 주체(예: Explorer)에서 나온 세 가지는 서로를 확증하지 못한다. 하나의 원인(사용자가 Explorer를 썼다)에서 파생된 세 흔적이기 때문이다. **주체가 다른 두 개**를 골라야 진짜 교차검증이다.

| 주체 계열 | 여기 속한 artifact |
| --- | --- |
| 셸(Explorer) | UserAssist, MUICache, Jump List, LNK, `Compatibility Assistant\Store` |
| 커널 | Prefetch, Shimcache |
| 서비스/예약 작업 | Amcache, BAM/DAM, SRUM, PCA 로그 |
| 감사/모니터링 | 4688, Sysmon 1, 4104 |
| 파일시스템 | `$MFT`, `$UsnJrnl` |

### 2단계 — "실행"을 의미하지 않는 경우

이 단계를 건너뛰면 오답이 된다.

| artifact | 실행 없이도 생기는 경우 | 그래서 어떻게 쓰나 |
| --- | --- | --- |
| **Shimcache** | 파일이 **존재**하기만 해도 shim 엔진이 검사하며 엔트리가 생길 수 있다. 폴더를 탐색기로 열어 실행 파일이 나열되는 것만으로도 등록되는 사례가 보고된다 | "그 경로에 그 파일이 **있었다**"는 증거로만 쓴다. 실행 확증 카운트에 넣지 않는다 |
| **Amcache** | Appraiser가 디스크를 스캔해 목록화한다. 압축을 풀어 놓기만 한 파일도 등록된다 | 파일의 **존재·해시·경로** 증거. 실행은 다른 곳에서 |
| **MUICache** | 셸이 그 실행 파일의 표시 이름을 조회할 때 등록된다. 실행 외 경로로 생길 수 있다 | 보조 근거. 시각이 없어 단독으로는 시점을 못 준다 |
| **LNK / RecentDocs** | **문서를 열었다**는 기록이다. 그 문서를 연 프로그램의 실행은 간접 증거 | 파일 접근 증거로 쓰고, 프로그램 실행은 따로 확증 |
| **`$MFT`** | 파일이 디스크에 있다는 것뿐이다 | 실행 파일이 언제 생겼는지(다운로드 시각)에 쓴다 |
| **Prefetch** | `.pf`가 있으면 실행됐다고 봐도 된다. 다만 **다른 경로의 동명 파일은 별개 `.pf`** 이고, 파일명 해시는 경로에서 계산된다 | 강한 증거. 단 `.pf` 하나가 어느 경로의 실행인지는 내부 참조 목록으로 확인 |
| **Amcache `LinkDate`** | PE 헤더의 컴파일 시각이다. **공격자가 조작할 수 있다** | 실행 시각이 아니다. 동일 도구 식별용 |
| **Shimcache의 시각** | 파일의 `$SI` 수정 시각이다 | 실행 시각으로 쓰면 오답이다. `$MFT`와 대조해 확인 |

**한 문장으로: Shimcache와 Amcache는 "있었다"의 증거, Prefetch·UserAssist·BAM·4688은 "실행됐다"의 증거다.**

### 3단계 — 확증 절차

```text
1. 대상 실행 파일 이름/경로를 확정한다 (부분 문자열이라도)
2. "실행 보장" 열이 참인 것부터 본다:
     Prefetch -> UserAssist -> BAM -> 4688/Sysmon 1 -> SRUM
3. 주체가 다른 2개에서 나오면 실행 확정
4. 3개가 같은 시각대를 가리키면 시각까지 확정
5. Shimcache/Amcache/MUICache 는 "존재/등록" 증거로 별도 기술
6. 시각은 전부 UTC 로 모은 뒤 마지막에 한 번만 KST 보정한다
```

```powershell
# 대상 이름으로 4개 CSV 를 동시에 훑는다
$t = 'dump_tool'
Import-Csv "C:\case\out\pf.csv"  | Where-Object { $_.ExecutableName -match $t } |
  Format-Table SourceFilename, RunCount, LastRun, SourceCreated
Import-Csv "C:\case\out\appcompat.csv" | Where-Object { $_.Path -match $t } |
  Format-Table ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC, Executed
Import-Csv "C:\case\out\amcache_associated.csv" | Where-Object { $_.FullPath -match $t } |
  Format-Table FullPath, SHA1, FileSize, LinkDate
Import-Csv "C:\case\out\evt.csv" | Where-Object { $_.Payload -match $t } |
  Format-Table TimeCreated, EventId, UserName, Payload
```

### 4단계 — 시각이 서로 어긋날 때

각 artifact의 시각은 **서로 다른 사건의 시각**이다. 어긋나는 것이 정상이고, 어긋나는 방향이 정보다.

| 관측 | 해석 |
| --- | --- |
| Prefetch `LastRun` > UserAssist `Last Executed` | 마지막 실행이 Explorer 경유가 아니었다 (콘솔·스케줄러·스크립트) |
| UserAssist `Run Count` > Prefetch `Run Count` | Prefetch가 삭제·순환되었거나 다른 경로의 `.pf`로 분리됐다 |
| Prefetch `Run Count` > UserAssist `Run Count` | 자동 실행이 섞여 있다. 사용자 의도와 자동화를 분리해야 한다 |
| Shimcache 시각 < Prefetch 최초 실행 | 정상이다. Shimcache는 **파일 수정 시각**이므로 실행보다 앞선다 |
| Shimcache 시각 > 모든 실행 시각 | 파일이 실행 이후 교체되었거나 타임스탬프가 조작됐다 |
| Amcache 등록 시각 ≫ 실행 시각 | Appraiser가 나중에 스캔한 것이다. 실행 시각으로 쓰지 않는다 |
| BAM에는 있고 Prefetch에는 없다 | Prefetch가 삭제되었거나 비활성. **BAM은 약 1주만 남으므로 최근 실행이라는 뜻** |
| Prefetch에는 있고 BAM에는 없다 | 1주보다 오래된 실행이다 |
| 4688은 있는데 Prefetch가 없다 | Prefetch 비활성/삭제, 또는 매우 짧은 실행 |
| Prefetch `.pf` 생성 시각이 실행보다 몇 초 늦다 | 정상이다. `.pf` 쓰기가 실행 직후 잠깐 지연된다 |

**Prefetch 파일 자체의 `$MFT` 생성 시각 ≈ 최초 실행 시각**, **`.pf`의 수정 시각 ≈ 마지막 실행 시각**이다. 파서 출력이 의심스러울 때 `$MFT`로 검증하는 우회로다 ([FOR-0021](./mft-basics.html)).

### 5단계 — 하나도 없을 때

| 확인 | 방법 | 판정 |
| --- | --- | --- |
| Prefetch가 애초에 켜져 있었나 | `SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters`의 `EnablePrefetcher` | `0`이면 비활성. 부재가 반증이 아니다 |
| Prefetch가 삭제됐나 | `$UsnJrnl`에서 `C:\Windows\Prefetch` 하위의 `FileDelete` | 대량 삭제면 반포렌식 ([FOR-0028](./usn-reason-flags.html)) |
| 다른 사용자 프로필인가 | 모든 `NTUSER.DAT`/`UsrClass.dat` | 사용자를 놓쳤을 수 있다 |
| 볼륨 섀도 카피가 있나 | 이전 시점의 hive·Prefetch | 삭제 전 상태 회수 |
| 메모리 덤프가 있나 | 프로세스 목록·명령행 ([FOR-0214](./volatility-pslist.html)) | 실행 중이었다면 결정적 |
| 파일 자체는 남아 있나 | `$MFT`, 카빙 | 존재만이라도 증명 |
| 실행 파일이 삭제됐나 | `$UsnJrnl`, `$Recycle.Bin` | 삭제 시각이 실행 이후임을 보이면 정황 확보 |
| 부수 흔적이 있나 | WER 크래시 보고서, 프로그램이 만든 로그·설정 파일·레지스트리 키 | 프로그램이 **동작한 결과물**이 실행의 증거가 된다 |

**부재를 실행하지 않았다는 증거로 쓰지 않는다.** 각 artifact의 비활성 조건·보존 기간·삭제 가능성을 먼저 배제한 뒤에만 "흔적 없음"을 주장한다.

## 출력 필드 해석

각 도구에서 실제로 읽어야 하는 칼럼만 모았다.

| 도구 / 출처 | 실행 판정에 쓰는 필드 | 주의 |
| --- | --- | --- |
| `PECmd` | `ExecutableName`, `RunCount`, `LastRun`, `PreviousRun0~6`, `SourceCreated`, `Directories`, `FilesLoaded` | 시각은 UTC. Win7은 `PreviousRun*`이 비어 있다 |
| `rip -p userassist` | 경로, 괄호 안 실행 횟수, 항목별 시각 | ROT13 자동 해제. `CEBFF5CD`(exe)와 `F4E57C4B`(lnk) 둘 다 볼 것 ([FOR-0061](./userassist.html)) |
| `rip -p bam` | 값 이름의 `\Device\HarddiskVolumeN\...` 경로, 값 데이터 앞 8바이트 FILETIME | 볼륨 번호를 드라이브 문자로 환산해야 한다 ([FOR-0067](./mounteddevices.html)) |
| `AppCompatCacheParser` | `CacheEntryPosition`, `Path`, `LastModifiedTimeUTC`, `Executed` | `Executed`는 Win10에서 의미 없는 값이 된다 ([FOR-0079](./appcompatcache.html)) |
| `AmcacheParser` | `FullPath`, `SHA1`, `FileSize`, `LinkDate`, `ProductName` | `SHA1`이 해시 대조의 핵심. 등록 시각은 실행 시각이 아니다 |
| `EvtxECmd` (4688) | `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName` | 명령행은 별도 정책이 켜져 있어야 기록된다 ([FOR-0088](./event-4688-process-creation.html)) |
| Sysmon 1 | `Image`, `CommandLine`, `Hashes`, `ParentImage`, `User` | 설치 환경에서만 |
| `SRUM` | 앱 경로, 사용자 SID, 시간대별 송수신 바이트 | "실행 + 네트워크 사용"을 함께 준다 |

## pivot: 다음에 볼 artifact

| 확보한 것 | 다음에 열 것 | 무엇을 얻나 |
| --- | --- | --- |
| 실행 파일 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일이 언제 생겼는가 = 유입 시각 |
| 실행 파일 해시 (Amcache) | 다른 이미지·위협 인텔 | 동일 도구의 다른 감염 지점 |
| 실행 시각 | EVTX 4688/Sysmon 1 | 명령행 인자와 부모 프로세스 |
| 실행 시각 | 4624 세션 ([FOR-0083](./event-4624-logon.html)) | 어느 로그온 세션 안의 행위인가 |
| 사용자 SID (BAM/SRUM) | `ProfileList` ([FOR-0074](./sid-user-mapping.html)) | 실행 주체의 이름 |
| Prefetch 참조 파일 목록 | 그 경로들의 `$MFT` | 프로그램이 무엇을 건드렸는가 |
| SRUM 송수신량 | PCAP·방화벽 로그 | 외부 전송 여부 |
| 실행 파일이 있던 폴더 | ShellBags ([FOR-0068](./shellbags.html)) | 사용자가 그 폴더를 탐색했는가 |

## 흔한 함정

- **Shimcache 항목을 실행 증거로 제시하는 것** → 존재/호환성 검사만으로도 등록될 수 있고 시각은 파일 수정 시각이다 → "그 경로에 그 파일이 있었다"까지만 주장하고 실행은 Prefetch·UserAssist·BAM으로 확증한다.
- **Amcache 등록 시각을 실행 시각으로 쓰는 것** → Appraiser 예약 작업이 스캔한 시각이다 → 실행 시각은 다른 artifact에서 가져오고 Amcache는 해시·경로·크기에만 쓴다.
- **`LinkDate`를 실행 시각이나 다운로드 시각으로 읽는 것** → PE 컴파일 타임스탬프이며 조작 가능하다 → 동일 바이너리 식별용으로만 쓴다.
- **같은 주체의 artifact 2개로 "교차검증했다"고 말하는 것** → UserAssist + MUICache는 둘 다 셸 기록이라 하나의 원인에서 파생된다 → 주체가 다른 것(커널/서비스/감사)을 섞는다.
- **artifact가 없으면 실행하지 않았다고 결론 내는 것** → Prefetch 비활성, BAM의 1주 한계, 로그 순환, 반포렌식이 모두 같은 "부재"를 만든다 → 부재의 원인을 먼저 배제한다.
- **실행 횟수를 하나의 숫자로 합치는 것** → UserAssist는 Explorer 경유만, Prefetch는 경로별로 센다 → 각각을 별도로 제시하고 차이를 해석한다.
- **`.pf` 파일명의 해시를 무시하고 이름만 보는 것** → 같은 이름의 실행 파일이 다른 경로에 있으면 `.pf`가 따로 생긴다 → `.pf` 두 개가 나오면 경로가 둘이라는 뜻이다.
- **BAM의 `\Device\HarddiskVolumeN` 경로를 그대로 답으로 쓰는 것** → 드라이브 문자가 아니다 → `MountedDevices`로 환산한다.
- **4688이 없는데 감사 정책을 확인하지 않는 것** → 기본 설정에서는 4688이 기록되지 않는다 → `SECURITY\Policy\PolAdtEv`나 4688의 존재 자체로 정책 상태를 판정한다.
- **시각을 artifact마다 따로 KST로 바꿔 비교하는 것** → 변환 실수가 섞인다 → 전부 UTC로 모아 정렬한 뒤 최종 답에서만 +9시간 한다. FILETIME은 1601-01-01 UTC 기준 100ns, Unix와의 차이는 `11644473600`초다 ([FOR-0054](./system-timezone.html)).
- **키 LastWrite를 실행 시각으로 쓰는 것** → 값 단위 시각이 아니다 → 값 안에 자체 FILETIME이 있는 UserAssist `0x3C`·BAM 앞 8바이트를 쓴다 ([FOR-0077](./registry-lastwrite-caveats.html)).

## 교차검증

```powershell
# 1) 커널 계열 — Prefetch
PECmd.exe -d "C:\case\Prefetch" --csv "C:\case\out" --csvf pf.csv
```

```powershell
# 2) 셸 계열 — UserAssist
rip.exe -r "C:\case\clean\NTUSER.DAT" -p userassist | Select-String 'dump_tool'
```

```powershell
# 3) 서비스 계열 — BAM (사용자 SID 별)
rip.exe -r "C:\case\clean\SYSTEM" -p bam | Select-String 'dump_tool'
```

```powershell
# 4) 감사 계열 — 4688 명령행
Import-Csv "C:\case\out\evt.csv" |
  Where-Object { $_.EventId -eq 4688 -and $_.Payload -match 'dump_tool' } |
  Format-Table TimeCreated, UserName, Payload
```

| 확보한 조합 | 결론 강도 |
| --- | --- |
| Prefetch + UserAssist + BAM | **실행·주체·시각 모두 확정.** 최상 |
| Prefetch + 4688 | 실행 확정 + 명령행 확보. 주체는 4688의 SID로 |
| UserAssist + BAM | 사용자 확정. 실행 횟수는 UserAssist만 |
| Shimcache + Amcache만 | **실행 미확정.** "파일이 존재했다"로만 기술 |
| MUICache만 | 매우 약하다. 다른 증거를 더 찾는다 |

## mini walkthrough

```text
문제:
"피의자는 'mimi.exe 를 실행한 적이 없다'고 주장합니다. 실행 여부와 시각(KST),
 실행 주체를 판정하시오.
 첨부: SYSTEM, SOFTWARE, SAM, NTUSER.DAT(hjlee), Amcache.hve, Prefetch 폴더 없음,
       Security.evtx"

1. 첫 시도 (실패):
   AppCompatCacheParser.exe -f SYSTEM --csv out\
   -> CacheEntryPosition 3 | C:\Users\hjlee\Downloads\mimi.exe
      LastModifiedTimeUTC 2026-04-07 02:11:09 | Executed: NA

   "Shimcache 에 있고 시각도 나왔으니 2026-04-07 11:11 KST 에 실행했다"고 결론 낼 뻔했다.

   왜 틀렸나:
   (1) Shimcache 는 실행을 보장하지 않는다. Executed 가 NA 인 것이 그 신호다.
   (2) 그 시각은 실행 시각이 아니라 파일의 수정 시각($SI mtime)이다.
   => 두 가지를 동시에 틀렸다.

2. 접근 변경 — "실행 보장" 열이 참인 것부터
   Prefetch 폴더가 첨부에 없다. 먼저 비활성인지 삭제인지 판정한다.
     SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
       EnablePrefetcher = 3   -> 활성이었다. 즉 파일이 있었어야 한다.
   -> 부재의 원인이 "비활성"이 아니다. 삭제 가능성을 기록해 둔다.

3. BAM 확인
   rip.exe -r SYSTEM -p bam
     S-1-5-21-3623811015-3361044348-30300820-1002
       \Device\HarddiskVolume3\Users\hjlee\Downloads\mimi.exe
         2026-04-09 07:52:30Z
   -> 실행 확정. 주체는 SID -1002.
      BAM 은 약 1주만 남으므로 이 실행은 최근이다.

4. 두 번째로 틀린 판단:
   "\Device\HarddiskVolume3 는 D: 겠지"라고 적었다.
   -> MountedDevices 를 보니 HarddiskVolume3 = C: 였다.
      경로는 C:\Users\hjlee\Downloads\mimi.exe. 볼륨 번호는 추측하지 않는다.

5. 주체 이름 확정
   rip.exe -r SOFTWARE -p profilelist
     S-1-5-21-...-1002 -> C:\Users\hjlee
   NTUSER.DAT(hjlee) 의 UserAssist:
     rip.exe -r NTUSER.DAT -p userassist | Select-String 'mimi'
     -> 항목 없음

6. 세 번째 판단 지점 — UserAssist 부재를 어떻게 읽을까
   UserAssist 에 없다 = Explorer 를 통해 실행하지 않았다는 뜻이다.
   실행 자체를 부정하지 않는다. 콘솔/스크립트 실행을 의심하고 4688 로 간다.

     Import-Csv evt.csv | Where-Object { $_.EventId -eq 4688 -and $_.Payload -match 'mimi' }
       2026-04-09 07:52:29Z  4688  hjlee
         NewProcessName  C:\Users\hjlee\Downloads\mimi.exe
         ParentProcessName C:\Windows\System32\cmd.exe
         CommandLine     mimi.exe privilege::debug sekurlsa::logonpasswords
   -> 주체가 다른 세 계열(서비스=BAM, 감사=4688)에서 확증. 명령행까지 확보.
      cmd.exe 가 부모이므로 UserAssist 에 없는 것이 일관된다.

7. Amcache 로 파일 동일성 확인
   AmcacheParser.exe -f Amcache.hve -i --csv out\
     FullPath  C:\Users\hjlee\Downloads\mimi.exe
     SHA1      da39a3ee5e6b4b0d3255bfef95601890afd80709
     LinkDate  2021-06-15 09:00:00
   -> LinkDate 는 컴파일 시각이므로 실행 시각과 무관. 해시는 도구 식별용으로 기록.

8. Prefetch 부재의 원인 확정
   $UsnJrnl 에서 C:\Windows\Prefetch 하위 FileDelete 다수 (2026-04-09 08:05Z)
   -> 실행 13분 뒤 Prefetch 일괄 삭제 = 반포렌식. 부재 자체가 증거가 되었다.

9. 시간대 보정 (마지막에 한 번만)
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time, ActiveTimeBias = -540분
   2026-04-09 07:52:29Z -> 2026-04-09 16:52:29 KST

정답:
  실행됨. 2026-04-09 16:52:29 KST, 주체 hjlee (S-1-5-21-...-1002),
  cmd.exe 에서 인자와 함께 실행. 근거는 BAM(서비스) + 4688(감사) 2계열 확증.
  Shimcache 항목은 "파일이 존재했다"의 증거로만 인용.
  Prefetch 폴더는 실행 13분 후 삭제됨.
```

1단계·4단계·6단계가 요점이다. **Shimcache를 실행 증거로 쓰는 것, 볼륨 번호를 추측하는 것, UserAssist 부재를 실행 부정으로 읽는 것**이 세 가지 대표 오답이다.

## 막혔을 때 다음 체크

1. "실행 보장" 열이 참인 artifact부터 봤는가 — Prefetch, UserAssist, BAM, 4688, Sysmon 1, SRUM
2. 확증에 쓴 두 artifact의 **기록 주체가 다른가**
3. Shimcache/Amcache/MUICache를 실행 증거 카운트에서 뺐는가
4. Prefetch 부재의 원인을 판정했는가 — `EnablePrefetcher`, `$UsnJrnl` 삭제 기록
5. BAM에 없다면 → 1주보다 오래된 실행일 수 있다. Prefetch·Amcache로 이동
6. UserAssist에 없다면 → 콘솔·스케줄러·서비스 실행 의심. 4688·7045로 이동
7. 모든 사용자 프로필의 hive를 봤는가
8. 볼륨 번호(`HarddiskVolumeN`)를 드라이브 문자로 환산했는가
9. 시각을 전부 UTC로 모아 정렬했는가 — 마지막에 한 번만 KST 보정
10. 흔적이 전무하다면 → VSS·메모리 덤프·WER·프로그램 산출물(로그·설정·레지스트리 키)로 우회

## 출처

- SRC-031 — Microsoft Learn, Application Compatibility / Shim infrastructure: shim 엔진이 실행 파일을 검사하는 시점과 AppCompatCache의 목적. **실행이 아니라 호환성 검사가 기록 계기**라는 판단의 근거
- SRC-030 — Libyal libscca, Prefetch 파일 포맷 문서: 실행 횟수 필드, 마지막 실행 시각 배열(버전에 따라 1개 또는 8개), 파일명 해시가 경로에서 계산된다는 점
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: UserAssist·BAM·MUICache·Shimcache가 어느 hive의 어느 키에 있는지
- SRC-021 — Microsoft Learn, Event 4688: 프로세스 생성 이벤트의 필드(`NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserSid`)와 명령행 기록에 별도 설정이 필요하다는 점
- **SRUM·Sysmon·UserAssist 항목은 각각 SRC-082(SRUM), SRC-024(Sysmon), SRC-009(UserAssist)에 근거가 있으며, 이 글은 비교표와 확증 절차만 제공한다.** 각 필드의 정의는 해당 전담 글을 참조할 것
- **BAM의 정리 주기(약 1주), SRUM의 보존 기간(약 30~60일), Prefetch 파일 개수 상한(Win8 이후 1024)은 OS 버전과 구성에 따라 달라지므로 실제 환경에서 확인할 것.** 이 글은 "짧다/길다"의 상대 비교를 위해 통상값을 제시한다
- `PcaAppLaunchDic.txt`와 `Compatibility Assistant\Store`는 Windows 11 계열에서 주로 관측되며 존재 여부가 환경에 따라 다르므로, 있으면 보조 증거로만 쓸 것
- 각 파서의 CSV 컬럼명은 도구 버전에 따라 다를 수 있으므로 실제 출력 헤더에서 확인할 것
- mini walkthrough의 시각·해시·SID는 설명을 위한 예시 값이다
