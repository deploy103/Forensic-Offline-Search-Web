---
id: FOR-0101
title: "Sysmon Event ID 11 FileCreate: 누가 이 파일을 만들었는가"
slug: "sysmon-event-11-file-create"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["Sysmon", "FileCreate", "TargetFilename", "CreationUtcTime", "FileCreateStreamHash", "FileDelete"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "C:\\Sysmon", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"]
registry_paths: []
event_ids: ["11", "15", "23", "26", "2"]
protocols: []
tools: ["Sysmon", "EvtxECmd", "MFTECmd", "PowerShell", "Timeline Explorer"]
commands: ["Get-WinEvent -Path sysmon.evtx -FilterXPath '*[System[EventID=11]]'", "MFTECmd.exe -f 'C:\\case\\$J' -m 'C:\\case\\$MFT' --csv out --csvf usn.csv"]
regex_patterns: ["TargetFilename:\\s*(.+\\.(?:exe|dll|ps1|bat|vbs|js|hta|scr))"]
wireshark_filters: []
tshark_fields: []
log_fields: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "User", "Hash", "IsExecutable", "Archived"]
file_formats: ["evtx"]
primary_terms: ["Sysmon 11", "Sysmon FileCreate", "sysmon 파일 생성"]
keywords: ["Sysmon", "Event ID 11", "FileCreate", "TargetFilename", "CreationUtcTime", "FileCreateStreamHash", "Zone.Identifier", "FileDelete", "FileDeleteDetected", "timestomp", "드롭퍼", "파일 생성 주체", "evtx"]
aliases: ["sysmon 파일 생성", "sysmon 11", "누가 파일을 만들었나", "드롭된 파일 찾기", "sysmon 파일 삭제", "sysmon 15 ads", "파일 생성 프로세스"]
symptom_keywords: ["누가 이 파일을 만들었는지 알고 싶다", "MFT로는 생성 주체를 모른다", "삭제된 파일을 누가 지웠는지", "다운로드한 파일의 출처를 알고 싶다", "생성 시각이 이상하다", "드롭퍼를 찾아야 한다"]
related: ["FOR-0099", "FOR-0100", "FOR-0102"]
source_ids: ["SRC-024", "SRC-013", "SRC-081"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Sysmon Event ID 11은 파일 생성마다 **만든 프로세스(`Image`, `ProcessGuid`)와 대상 경로(`TargetFilename`)** 를 남긴다. `$MFT`와 `$UsnJrnl`은 "생성됐다"까지만 알고 **주체를 모르므로**, "누가 만들었는가"에 답하는 로그는 이것뿐이다.

## 어떤 문제에서 필요한가

- "이 악성 파일을 드롭한 프로세스는 무엇인가"
- "Word 문서가 실행 파일을 떨어뜨렸는가" — 드롭퍼 판정
- "다운로드된 파일인가" — Event 15의 `Zone.Identifier`
- "이 파일을 지운 것은 누구인가" — Event 23/26
- "생성 시각이 조작됐는가" — `CreationUtcTime` vs `UtcTime`, Event 2
- `$UsnJrnl`에는 있는데 주체를 모를 때

프로세스의 명령행·부모·해시는 Sysmon 1 전담 글(FOR-0099)에서 얻는다.

## 문제에서 처음 볼 단서

1. 지문에 "누가", "어떤 프로세스가" + 파일 이름 → Event 11
2. 파일 경로가 `\Temp\`, `\AppData\`, `Startup` → 드롭 흔적
3. 지문에 "다운로드" → Event 15와 `Zone.Identifier`
4. 지문에 "삭제" → Event 23/26, `Archived`
5. `$MFT`의 생성 시각과 다른 시각이 나온다 → `CreationUtcTime` 대조

## 30초 절차

```powershell
# 원본: Microsoft-Windows-Sysmon%4Operational.evtx -> sysmon.evtx
Get-WinEvent -Path 'C:\case\sysmon.evtx' -FilterXPath '*[System[EventID=11]]' | Format-List
```

객체로 뽑아 두고 시작한다.

```powershell
$sm = 'C:\case\sysmon.evtx'

$p11 = Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=11]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime  = [datetime]::Parse($d['UtcTime'])
      CreateT  = [datetime]::Parse($d['CreationUtcTime'])
      Image    = $d['Image']
      Guid     = $d['ProcessGuid']
      Target   = $d['TargetFilename']
      User     = $d['User']
      RuleName = $d['RuleName']
    }
  } | Sort-Object UtcTime

# 실행 가능 확장자만
$p11 | Where-Object { $_.Target -match '\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|jar|lnk)$' } |
  Select-Object UtcTime, Image, Target, User | Format-Table -AutoSize
```

출력 예시:

```text
UtcTime             Image                                 Target                                                    User
-------             -----                                 ------                                                    ----
2026-03-14 07:19:58 C:\...\Office16\WINWORD.EXE            C:\Users\jhkim\AppData\Local\Temp\stage1.ps1              WIN10\jhkim
2026-03-14 07:22:01 C:\...\v1.0\powershell.exe             C:\Windows\Temp\svchost.exe                               WIN10\jhkim
2026-03-14 07:31:44 C:\Windows\Temp\svchost.exe            C:\Users\jhkim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\upd.lnk  WIN10\jhkim
```

세 줄로 감염 → 드롭 → 지속성 등록이 끝난다. `WINWORD.EXE`가 `.ps1`을 만드는 것은 정상 환경에서 일어나지 않는다.

## 상세 절차

### 1단계 — 필드표

| 필드 | 의미 | 실전 활용 |
| --- | --- | --- |
| `RuleName` | 매칭된 설정 규칙 태그 | 설정에서 지정했을 때만 값이 있다 |
| `UtcTime` | **이벤트 발생 시각(UTC)** = 실제로 만든 순간 | 타임라인의 기준 |
| `ProcessGuid` | 만든 프로세스의 GUID | **Sysmon 1과 잇는 키** |
| `ProcessId` | PID | 재사용됨. 단독 사용 금지 |
| `Image` | **만든 프로세스의 실행 파일 경로** | "누가"의 답 |
| `TargetFilename` | **만들어진 파일의 전체 경로** | "무엇을"의 답 |
| `CreationUtcTime` | 그 파일에 기록된 생성 시각(UTC) | `UtcTime`과 다르면 신호 |
| `User` | 만든 프로세스의 실행 계정 | 서비스 계정이 사용자 폴더에 쓰면 이상 |

`Image`와 `TargetFilename` 두 필드가 이 로그의 전부이자 핵심이다.

### 2단계 — $MFT / $UsnJrnl 과의 결정적 차이

| 질문 | `$MFT` | `$UsnJrnl` | **Sysmon 11** |
| --- | --- | --- | --- |
| 파일이 존재했나 | 답한다 | 답한다 | 생성 시점만 |
| 언제 만들어졌나 | 답한다(`$SI`/`$FN`) | 답한다(USN 시각) | 답한다(`UtcTime`) |
| **누가 만들었나** | **모른다** | **모른다** | **답한다** |
| 삭제 후에도 남나 | 레코드 재사용 전까지 | 저널 순환 전까지 | **로그에 영구 기록** |
| 파일 내용/해시 | 없음 | 없음 | 11에는 없음(15에 일부) |
| 조작 저항성 | 타임스탬프 조작 가능 | 저널 삭제 가능 | 로그 삭제 가능 |

`$MFT`는 파일 시스템의 상태이고 Sysmon 11은 **행위 기록**이다. 그래서 파일이 지워져 `$MFT` 레코드가 재사용된 뒤에도 Sysmon 11에는 그 파일이 만들어진 사실과 주체가 남는다. 반대로 Sysmon 설치 이전에 만들어진 파일은 Event 11이 없으므로 `$MFT`로 가야 한다. **둘은 대체재가 아니라 상호 보완재다.** `$MFT` 해석은 [FOR-0021](./mft-basics.html), `$UsnJrnl`은 [FOR-0027](./usnjrnl-basics.html)을 본다.

### 3단계 — CreationUtcTime vs UtcTime

새로 만들어지는 파일은 두 값이 사실상 같다(밀리초 차이). 다르면 이유가 있다.

| 관계 | 의미 | 판정 |
| --- | --- | --- |
| `CreationUtcTime` ≈ `UtcTime` | 정상적인 신규 생성 | 이상 없음 |
| `CreationUtcTime` < `UtcTime` (과거) | 생성 시각을 물려받았다 | 같은 볼륨 내 **이동/이름 변경**, 생성 시각을 보존하는 복사 도구, 또는 **timestomp** |
| `CreationUtcTime` > `UtcTime` (미래) | 존재할 수 없는 조합 | **timestomp 확정** |
| 차이가 수년 단위 | 정품 시스템 파일의 시각을 베꼈다 | `\System32\` 파일 시각을 그대로 옮겨 심는 전형적 위장 |

```powershell
$p11 | Where-Object { [Math]::Abs((($_.UtcTime) - ($_.CreateT)).TotalSeconds) -gt 60 } |
  Select-Object UtcTime, CreateT, Image, Target |
  Sort-Object UtcTime | Format-Table -AutoSize
```

출력:

```text
UtcTime             CreateT             Image                        Target
-------             -------             -----                        ------
2026-03-14 07:22:01 2019-03-19 12:07:44 C:\...\powershell.exe        C:\Windows\Temp\svchost.exe
2026-03-14 07:26:10 2026-03-14 07:24:55 C:\Windows\explorer.exe      C:\Users\jhkim\Desktop\bk.zip
```

첫 줄은 2019년 생성 시각을 가진 파일이 2026년에 만들어졌다. 정품 `svchost.exe`의 시각을 베낀 timestomp다. 둘째 줄은 1분 15초 차이로, 같은 볼륨 안에서 옮긴 것에 가깝다 — 이 정도 차이는 조작으로 단정하지 않는다.

**직접 탐지는 Event 2가 더 확실하다.**

| Event 2 필드 | 의미 |
| --- | --- |
| `TargetFilename` | 시각이 변경된 파일 |
| `CreationUtcTime` | **변경 후** 생성 시각 |
| `PreviousCreationUtcTime` | **변경 전** 생성 시각 |
| `Image` / `ProcessGuid` | 시각을 바꾼 프로세스 |

```powershell
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=2]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime = $d['UtcTime']
      Image   = $d['Image']
      Target  = $d['TargetFilename']
      Before  = $d['PreviousCreationUtcTime']
      After   = $d['CreationUtcTime']
    }
  } | Format-Table -AutoSize
```

Event 2가 있으면 **누가 언제 어떤 값으로 바꿨는지**가 전부 나온다. `$STANDARD_INFORMATION`과 `$FILE_NAME`의 불일치로 추정하는 방식([FOR-0038](./timestomp-detection.html))보다 직접적이다.

### 4단계 — 관련 이벤트

| ID | 이름 | 무엇을 알려주는가 |
| --- | --- | --- |
| 11 | FileCreate | 파일 생성 주체와 경로 |
| 15 | FileCreateStreamHash | **ADS(대체 데이터 스트림) 생성**. 다운로드 흔적 |
| 2 | FileCreateTime | 생성 시각 변경 = timestomp 직접 탐지 |
| 23 | FileDelete (archived) | 삭제 주체 + **파일을 아카이브 폴더에 보존** |
| 26 | FileDeleteDetected | 삭제 주체만 기록(아카이브 없음) |

#### Event 15 — 다운로드 판정

브라우저·메일 클라이언트·일부 압축 도구는 다운로드한 파일에 `Zone.Identifier`라는 ADS를 붙인다. Event 15는 그 스트림 생성을 기록한다.

| Event 15 필드 | 의미 |
| --- | --- |
| `TargetFilename` | `C:\...\a.dat:Zone.Identifier` 형태 |
| `CreationUtcTime` | 스트림 생성 시각 |
| `Hash` | 스트림 내용의 해시 |
| `Image` / `ProcessGuid` | 붙인 프로세스(브라우저 등) |

```powershell
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=15]]' |
  Where-Object { $_.Message -match 'Zone.Identifier' } |
  Select-Object -First 20 TimeCreated, Message
```

ADS의 실제 내용은 마운트한 이미지에서 직접 읽는다.

```powershell
Get-Content -Path 'C:\case\mount\Users\jhkim\Downloads\a.dat' -Stream Zone.Identifier
```

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=http://cdn-update.example.net:8080/
HostUrl=http://cdn-update.example.net:8080/pkg/a7f2.dat
```

`ZoneId=3`은 인터넷 영역이다. **`HostUrl`이 다운로드 원본 URL**이므로 이 한 줄이 유입 경로의 답이 되는 경우가 많다. ADS 자체의 구조와 다루는 법은 [FOR-0035](./alternate-data-streams.html)를 본다.

#### Event 23 / 26 — 삭제 주체와 아카이빙

| 항목 | 23 (FileDelete) | 26 (FileDeleteDetected) |
| --- | --- | --- |
| 삭제 사실 기록 | 기록 | 기록 |
| 삭제 주체(`Image`) | 기록 | 기록 |
| **파일 사본 보존** | **아카이브 폴더에 저장** | 저장하지 않음 |
| `Archived` 필드 | 아카이브 성공 여부 | 해당 없음 |

23이 켜져 있으면 삭제된 파일의 **실체가 남는다.** 아카이브 위치는 설정의 `ArchiveDirectory`로 정하며 기본값은 `C:\Sysmon`이다. 문제에서 "삭제된 파일의 내용"을 물으면 카빙 전에 이 폴더를 먼저 확인한다.

```powershell
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=23 or EventID=26]]' |
  Select-Object -First 20 TimeCreated, Id, Message

# 아카이브 폴더 (이미지 마운트 후)
Get-ChildItem 'C:\case\mount\Sysmon' -Recurse | Select-Object Length, Name
```

아카이브 파일 이름은 해시 기반이라 원래 이름이 아니다. Event 23의 `TargetFilename`과 `Hashes`로 짝을 맞춘다.

### 5단계 — 드롭퍼 탐지 실전 필터

```powershell
# 문서/브라우저/메일 프로세스가 실행 가능 파일을 만든 경우
$dropper = 'winword|excel|powerpnt|outlook|acrord32|msaccess|visio|' +
           'chrome|firefox|msedge|iexplore|' +
           'winrar|7z|zip|thunderbird|hwp'

$p11 | Where-Object {
  $_.Image -match $dropper -and
  $_.Target -match '\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|lnk|jar|iso|img)$'
} | Select-Object UtcTime, Image, Target, User | Format-Table -AutoSize

# 자동 실행 위치에 만들어진 파일
$p11 | Where-Object {
  $_.Target -match '\\Start Menu\\Programs\\Startup\\|\\Windows\\Tasks\\|\\System32\\Tasks\\|\\Windows\\System32\\drivers\\'
} | Select-Object UtcTime, Image, Target | Format-Table -AutoSize

# 사용자 쓰기 가능 경로의 실행 파일
$p11 | Where-Object {
  $_.Target -match '\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\|\\ProgramData\\' -and
  $_.Target -match '\.(exe|dll|ps1|scr)$'
} | Select-Object UtcTime, Image, Target, User | Format-Table -AutoSize
```

| 패턴 | 해석 |
| --- | --- |
| Office 프로세스 → `.exe`/`.ps1` | 매크로 드롭퍼. 문서가 최초 유입 경로 |
| 브라우저 → `.exe` in `Downloads` | 사용자 다운로드. Event 15로 URL 확보 |
| 압축 도구 → `\Temp\` `.exe` | 첨부 압축파일 안에서 실행 |
| `powershell.exe` → `\Windows\Temp\` `.exe` | 2단계 페이로드 드롭 |
| 임의 프로세스 → `Startup\*.lnk` | 지속성 등록 |
| `w3wp.exe` → `.aspx`/`.jsp` | **웹셸 설치** |

### 6단계 — $UsnJrnl 과 시각 대조

```powershell
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv 'C:\case\out' --csvf usn.csv
```

CSV를 열어 같은 파일 이름의 USN 레코드 시각과 Sysmon 11의 `UtcTime`을 비교한다.

| 대조 결과 | 해석 |
| --- | --- |
| 두 시각이 초 단위 일치 | 정합. 파일 생성 사실 확정 |
| Sysmon 11만 있다 | 저널이 순환해 밀려났다. 또는 파일이 즉시 삭제됐다 |
| `$UsnJrnl`만 있다 | Sysmon 설정에서 제외된 경로이거나 Sysmon 설치 이전 |
| 시각이 크게 어긋난다 | 두 개의 다른 사건을 같은 이름으로 착각한 것. 경로 전체로 다시 비교 |

`$UsnJrnl`은 `FileCreate` 이후 `DataExtend`/`DataTruncation`/`Close` 등 여러 레코드를 연속으로 남긴다. Sysmon 11의 `UtcTime`은 그 중 **최초 생성 시점**과 맞춰야 한다.

## 출력 필드 해석

`UtcTime`과 `CreationUtcTime` 모두 **이미 UTC**다. Event Viewer 상단 시각은 EVTX `SystemTime`(UTC)을 로컬 시간대로 변환한 값이라 다르게 보인다. 답이 KST면 +9시간.

| 상황 | 해석 |
| --- | --- |
| `TargetFilename`에 `:` 뒤 스트림 이름 | ADS다. Event 15와 함께 본다 |
| `TargetFilename`이 `\Device\HarddiskVolumeN\...` | 볼륨 장치 경로 표기. 드라이브 문자로 정규화해 비교 |
| 같은 파일이 여러 번 11에 나온다 | 임시 파일로 만들고 이름을 바꾸는 저장 패턴(Office 등) |
| `.tmp` → 최종 이름 순서 | 정상적인 원자적 저장. 최종 이름으로 추적한다 |
| `Image`가 `System` | 커널/드라이버 수준 생성 |
| Event 11이 하나도 없다 | 설정에서 대량 제외됨. 경로 기준 포함 규칙만 켜 두는 것이 일반적 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| `ProcessGuid` | Sysmon 1 (FOR-0099) | 만든 프로세스의 명령행·부모·해시 |
| `ProcessGuid` | Sysmon 3 | 파일 생성 직전의 다운로드 통신 |
| `TargetFilename` | Sysmon 1의 `Image` | 그 파일이 이후 실행됐는가 |
| `TargetFilename` | `$MFT` ([FOR-0021](./mft-basics.html)) | 파일의 MACB와 현재 존재 여부 |
| `TargetFilename` | `$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html)) | 이름 변경·삭제 이력 |
| Event 15 `Zone.Identifier` | ADS 내용 ([FOR-0035](./alternate-data-streams.html)) | `HostUrl` = 다운로드 원본 URL |
| Event 23 `Hashes` | 아카이브 폴더 `C:\Sysmon` | 삭제된 파일의 실체 |
| Event 2 `Previous...` | `$STANDARD_INFORMATION` 대조 ([FOR-0038](./timestomp-detection.html)) | 조작 전 원래 시각 |
| `Startup`/`Tasks` 경로 | Sysmon 13 · Run 키 | 지속성 등록 전체 그림 |
| 파일 생성 시각 | 그 시각의 4624 세션 | 어느 로그온 세션의 행위인가 |

## 흔한 함정

- **`$MFT`만 보고 "누가 만들었는지 모른다"고 결론 내리는 것.** `$MFT`에는 주체 정보가 없다 → Sysmon 11의 `Image`/`ProcessGuid`가 그 답이다.
- **`CreationUtcTime`을 이벤트 시각으로 읽는 것.** 실제로 만들어진 순간은 `UtcTime`이다 → `CreationUtcTime`은 파일에 기록된 값이며 조작·상속될 수 있다.
- **두 시각 차이를 곧바로 timestomp로 단정하는 것.** 같은 볼륨 내 이동/이름 변경은 생성 시각을 그대로 물려받는다 → 차이가 수년 단위이거나 미래 시각일 때만 조작으로 판정하고, 가능하면 Event 2로 확증한다.
- **`.tmp` 파일만 보고 최종 파일을 놓치는 것.** Office 등은 임시 이름으로 쓰고 이름을 바꾼다 → `$UsnJrnl`의 `RenameOldName`/`RenameNewName`으로 최종 이름을 잇는다.
- **Event 11이 없어서 파일이 생성되지 않았다고 보는 것.** Sysmon 11은 노이즈가 커서 설정에서 확장자·경로 기준으로만 켜는 경우가 많다 → 설정을 확인하고 `$UsnJrnl`로 보완한다.
- **Event 26을 보고 파일 사본을 찾으려는 것.** 26은 탐지만 하고 아카이브하지 않는다 → 사본은 23의 `Archived`가 있을 때만 존재한다.
- **ADS 이벤트를 파일 생성으로 세는 것.** `TargetFilename`에 `:`가 있으면 스트림이다 → 파일 개수 집계에서 제외한다.
- **PID로 프로세스를 특정하는 것.** PID는 재사용된다 → `ProcessGuid`로 Sysmon 1과 잇는다.
- **`UtcTime`에 다시 9시간을 더하는 것.** 이미 UTC다 → KST 답에만 한 번 +9시간.
- **`\Device\HarddiskVolume2\` 경로를 다른 파일로 보는 것.** 드라이브 문자 표기만 다르다 → 볼륨 매핑을 확인해 정규화한 뒤 비교한다.

## 교차검증

```powershell
$sm = 'C:\case\sysmon.evtx'

# 1) 관심 파일을 만든 이벤트
$p11 | Where-Object { $_.Target -match 'svchost\.exe' } |
  Select-Object UtcTime, CreateT, Image, Guid, Target

# 2) 그 프로세스의 Sysmon 1 (명령행과 부모)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=1]]' |
  Where-Object { $_.Message -match 'powershell' } | Select-Object -First 3 TimeCreated, Message

# 3) 그 파일이 나중에 실행됐는가 (Sysmon 1 의 Image 로 등장)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=1]]' |
  Where-Object { $_.Message -match 'C:\\Windows\\Temp\\svchost\.exe' } |
  Select-Object TimeCreated, Message

# 4) 삭제됐는가 (23/26)
Get-WinEvent -Path $sm -FilterXPath '*[System[EventID=23 or EventID=26]]' |
  Where-Object { $_.Message -match 'svchost\.exe' } | Select-Object TimeCreated, Id

# 5) 파일시스템 측 대조
MFTECmd.exe -f 'C:\case\$MFT' --csv 'C:\case\out' --csvf mft.csv
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv 'C:\case\out' --csvf usn.csv
```

Sysmon 11(생성) → Sysmon 1(실행) → Sysmon 3(통신) → Sysmon 23(삭제)가 같은 파일 경로로 이어지면 전체 생애주기가 완성된다.

## mini walkthrough

```text
문제:
"C:\Windows\Temp\svchost.exe 의 다운로드 원본 URL 과 이 파일을 떨어뜨린 프로세스를 답하시오.
 첨부: Microsoft-Windows-Sysmon%4Operational.evtx, 디스크 이미지"

1. 첫 시도 (실패):
   MFTECmd 로 $MFT 를 파싱해 svchost.exe 를 찾았다.

     FileName            C:\Windows\Temp\svchost.exe
     Created0x10         2019-03-19 12:07:44
     LastModified0x10    2019-03-19 12:07:44
     Created0x30         2026-03-14 07:22:01

   Created0x10 이 2019년이라 "2019년에 설치된 정상 파일" 이라고 판단했다. 오답.
   그리고 "누가 만들었는지" 는 $MFT 로는 알 수 없어 답을 못 냈다.

   왜 틀렸나:
   $SI(0x10) 의 생성 시각은 조작 가능하다. $FN(0x30) 은 2026년이었는데 무시했다.
   그리고 $MFT 에는 생성 주체 정보가 아예 없다.

2. 피벗 — Sysmon Event 11 을 열었다.
     UtcTime         2026-03-14 07:22:01.338
     CreationUtcTime 2019-03-19 12:07:44.000
     Image           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
     TargetFilename  C:\Windows\Temp\svchost.exe
     User            WIN10\jhkim

   - UtcTime(2026) != CreationUtcTime(2019), 차이 7년 -> timestomp 확정
   - 만든 주체는 powershell.exe -> $MFT 로는 절대 알 수 없던 값

3. 시각 조작을 직접 확인 (Event 2):
     UtcTime 2026-03-14 07:22:02
     Image   C:\Windows\...\powershell.exe
     Target  C:\Windows\Temp\svchost.exe
     PreviousCreationUtcTime 2026-03-14 07:22:01
     CreationUtcTime         2019-03-19 12:07:44
   -> 만든 1초 뒤에 자기가 만든 파일의 생성 시각을 2019년으로 바꿨다.

4. 다운로드 원본 찾기 — 먼저 Event 15 를 svchost.exe 로 검색했다. 0건.
   (PowerShell 의 WebClient 는 Zone.Identifier 를 붙이지 않는다.)
   대신 그 이전 단계의 다운로드 산물을 찾았다.

     Event 15  07:20:12  chrome.exe
       TargetFilename C:\Users\jhkim\Downloads\a7f2.dat:Zone.Identifier

   ADS 내용:
     [ZoneTransfer]
     ZoneId=3
     HostUrl=http://cdn-update.example.net:8080/pkg/a7f2.dat

5. 계보 확인 (같은 ProcessGuid 로 Sysmon 1):
   07:20:08  powershell.exe -nop -w hidden -enc SQBFAFgA...
     Parent -> 07:19:58  WINWORD.EXE "C:\Users\jhkim\Downloads\invoice.doc"

6. 시간대: UtcTime 은 이미 UTC. 07:22:01 UTC = 16:22:01 KST (+9h)

정답: 원본 URL http://cdn-update.example.net:8080/pkg/a7f2.dat,
      드롭한 프로세스 powershell.exe (부모 WINWORD.EXE)
```

1단계의 실패가 이 글의 요지다. **`$MFT`의 생성 시각은 거짓말할 수 있고, 주체는 아예 말하지 않는다.** Sysmon 11은 둘 다 해결한다.

## 막혔을 때 다음 체크

1. `Image`를 확인했는가 → "누가"의 답은 이 필드다
2. `UtcTime`과 `CreationUtcTime`을 비교했는가 → 차이가 크면 timestomp
3. Event 2가 있는가 → 조작을 직접 증명한다
4. Event 15가 있는가 → `Zone.Identifier`의 `HostUrl`이 유입 URL
5. Event 11이 없는가 → 설정 제외 가능성. `$UsnJrnl`·`$MFT`로 보완
6. 삭제된 파일 내용이 필요한가 → Event 23의 아카이브 폴더(`C:\Sysmon`)
7. 임시 파일 이름만 보이는가 → `$UsnJrnl`의 rename 레코드로 최종 이름을 잇는다
8. 만든 프로세스의 유입 경로가 필요한가 → `ProcessGuid`로 Sysmon 1의 부모를 거슬러 올라간다
9. 그 파일이 실제로 실행됐는지 확인이 필요하면 → 같은 경로가 Sysmon 1의 `Image`로 나오는지 본다

## 출처

- SRC-024 — Microsoft Learn, Sysmon: Event ID 11 FileCreate의 필드 목록, 관련 이벤트 2/15/23/26과 아카이브 디렉터리 설정
- SRC-013 — Microsoft Learn, Change Journals: `$UsnJrnl`이 기록하는 정보 범위(생성 사실은 있으나 주체 정보는 없음)
- SRC-081 — Microsoft Learn, Alternate Data Streams / File Streams: `Zone.Identifier` ADS와 스트림 경로 표기
- Event 23/26의 필드 구성(`Archived`, `IsExecutable`, `Hashes`)과 아카이브 디렉터리 기본값은 **Sysmon 버전에 따라 다르다.** 실제 이벤트와 설정 파일에서 확인할 것
- Event 15의 `Contents` 필드는 최신 버전에서만 존재할 수 있으므로 이 글에서는 필수 필드로 다루지 않았다
- `\Device\HarddiskVolumeN\` 형태의 경로 표기가 나오는 조건은 환경에 따라 다르다. 드라이브 문자 매핑은 실제 이미지에서 확인할 것
