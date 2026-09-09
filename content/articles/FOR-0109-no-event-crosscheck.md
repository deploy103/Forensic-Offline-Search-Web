---
id: FOR-0109
title: "있어야 할 이벤트가 없을 때: 원인 8가지 판별과 대체 artifact 매핑"
slug: "no-event-crosscheck"
category: "Event Log"
type: "troubleshooting"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["EVTX", "Prefetch", "Amcache.hve", "BAM", "UserAssist", "ShellBags", "ConsoleHost_history.txt", "$MFT"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs", "C:\\Windows\\Prefetch", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache"]
registry_paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"]
event_ids: []
protocols: []
tools: ["EvtxECmd", "PECmd", "AmcacheParser", "RegistryExplorer", "PowerShell", "wevtutil"]
commands: ["EvtxECmd.exe -d 'C:\\case\\winevt' --csv 'C:\\case\\out' --csvf all.csv --inc 1102,104,4719,1100", "wevtutil gl Security", "PECmd.exe -d 'C:\\case\\Prefetch' --csv 'C:\\case\\out'"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["EventRecordId", "TimeCreated", "Channel", "MaxSize", "AuditPolicyChanges", "SubcategoryGuid"]
file_formats: ["evtx", "csv", "hve"]
primary_terms: ["이벤트가 없을 때", "로그가 없다", "감사 미설정"]
keywords: ["이벤트 없음", "로그 없음", "감사 정책", "audit policy", "롤오버", "rollover", "1102", "104", "4719", "1100", "대체 artifact", "Prefetch", "Amcache", "BAM", "ShellBags", "없음의 증거"]
aliases: ["이벤트가 안 보인다", "4688이 없다", "로그가 비어 있다", "감사 안 켜져 있었다", "로그 지워졌나", "로그 범위 밖", "대체 흔적"]
symptom_keywords: ["있어야 할 이벤트가 없다", "4688이 하나도 없다", "4104가 안 남았다", "로그가 특정 시각부터 없다", "감사가 꺼져 있었는지 알고 싶다", "없다는 것을 증거로 쓸 수 있나"]
related: ["FOR-0103", "FOR-0108", "FOR-0050"]
source_ids: ["SRC-022", "SRC-026", "SRC-031"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

이벤트가 없는 이유는 **① 감사 미설정 ② 롤오버 ③ 삭제(1102/104) ④ 정책 변경(4719) ⑤ 서비스 중지(1100) ⑥ 다른 채널 ⑦ 파일 손상 ⑧ 그 행위가 애초에 이벤트를 남기지 않음** 중 하나이며, 원인을 확정하기 전에는 "없음"을 증거로 쓸 수 없다 — 원인이 확정되면 대체 artifact(Prefetch·Amcache·BAM·`$MFT`·ShellBags)로 그 구간을 메운다.

## 증상

- Security.evtx는 있는데 4688(프로세스 생성)이 **한 건도** 없다
- PowerShell 채널은 있는데 4104가 없다
- 사건 시각 전후의 이벤트가 통째로 비어 있다
- 로그의 마지막 이벤트가 사건보다 이르다
- 특정 계정의 로그온 기록이 없는데 그 계정의 프로필 폴더는 갱신되어 있다
- 파서가 오류를 뱉고 일부만 읽는다

이 상태에서 "그 행위는 일어나지 않았다"고 답하는 것이 가장 흔한 오답이다. **없음의 원인을 먼저 확정한다.**

## 가장 가능성 높은 원인

확률이 높은 순서다. 위에서부터 확인한다.

| 순위 | 원인 | 대표 신호 | 즉시 확인 |
| --- | --- | --- | --- |
| 1 | **해당 감사 정책이 애초에 꺼져 있었다** | 그 Event ID가 **전 구간에서 0건** | 다른 시각에도 0건인지 |
| 2 | **롤오버로 밀려났다** | 첫 `EventRecordId` > 1, 첫 이벤트 시각이 사건보다 나중 | 첫 레코드 번호와 시각 |
| 3 | **1102 / 104 로 삭제됐다** | 번호가 1로 재시작, 또는 1102가 마지막 레코드 | 1102/104 검색 |
| 4 | **4719 로 감사 정책이 변경됐다** | 특정 시각 이후(또는 이전)만 0건 | 4719의 시각과 대상 하위 범주 |
| 5 | **1100 으로 로깅 서비스가 중지됐다** | 특정 시각 이후 전 채널이 조용하다 | 1100, 6005/6006 |
| 6 | **이벤트가 다른 채널에 있다** | 그 채널 파일이 첨부에 없거나 안 봤다 | 채널 목록과 건수 |
| 7 | **파일이 손상됐다** | 파서 오류, `ChunkNumber` 불연속 | 시그니처와 파서 경고 |
| 8 | **그 행위가 이벤트를 남기지 않는다** | 정책도 켜져 있고 로그도 온전한데 없다 | 그 행위의 감사 대상 여부 |

기본으로 꺼져 있어 1번에 자주 해당하는 것들이다.

| Event ID | 무엇 | 켜져 있어야 기록되는 것 |
| --- | --- | --- |
| 4688 | 프로세스 생성 | 감사 하위 범주 "프로세스 만들기" |
| 4688의 `CommandLine` | 명령행 | **별도 정책.** 하위 범주만 켜도 필드는 빈다 |
| 4689 | 프로세스 종료 | "프로세스 종료" |
| 4104 / 4103 | PowerShell 스크립트·모듈 | 스크립트 블록 로깅 / 모듈 로깅 |
| 5145 | 상세 파일 공유 | "상세 파일 공유" |
| 4663 | 객체 접근 | "파일 시스템" + 대상 객체의 SACL |
| 4673 / 4674 | 특권 사용 | "중요한 권한 사용" |
| Sysmon 전 이벤트 | Sysmon 설치와 config | 애초에 설치돼 있어야 한다 |

**정책이 꺼져 있었다면 그 이벤트의 부재는 아무 정보도 주지 않는다.** 반대로 정책이 켜져 있었음을 입증하면 부재가 강한 증거가 된다.

## 1차 확인

```powershell
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf all.csv --inc 1102,104,4719,1100
```

원인 3·4·5를 한 번에 배제하거나 확정한다. 하나라도 나오면 그 시각이 답의 축이 된다.

```powershell
Import-Csv 'C:\case\out\all.csv' |
  Sort-Object { [datetime]$_.TimeCreated } |
  Format-Table TimeCreated, Channel, EventId, UserName, MapDescription -AutoSize
```

그다음 **필터 없는 전체 CSV**로 네 가지를 순서대로 본다.

```powershell
EvtxECmd.exe -d 'C:\case\winevt' --csv 'C:\case\out' --csvf full.csv
$csv = Import-Csv 'C:\case\out\full.csv'

# (1) 그 Event ID 가 전 구간에서 몇 건인가 -> 0 이면 정책 미설정 유력
$csv | Where-Object { $_.EventId -eq 4688 } | Measure-Object | Select-Object Count

# (2) 채널 목록과 건수 -> 다른 채널에 있는지
$csv | Group-Object Channel | Sort-Object Count -Descending | Select-Object Name, Count

# (3) 채널별 보존 구간 (첫/마지막 레코드) -> 롤오버 판정
$csv | Group-Object Channel | ForEach-Object {
  $g = $_.Group | Sort-Object { [int64]$_.EventRecordId }
  [pscustomobject]@{
    Channel   = $_.Name
    Count     = $_.Count
    FirstId   = $g[0].EventRecordId
    FirstTime = $g[0].TimeCreated
    LastId    = $g[-1].EventRecordId
    LastTime  = $g[-1].TimeCreated
  }
} | Format-Table -AutoSize

# (4) 첨부에 없는 채널 파일이 있는지 (파일 목록과 대조)
Get-ChildItem 'C:\case\winevt\*.evtx' | Select-Object Name, Length | Sort-Object Length -Descending
```

판정표:

| 관찰 | 확정되는 원인 |
| --- | --- |
| 그 Event ID가 전 구간 0건 | 1 (감사 미설정) — 단, 4719로 중간에 켜졌다 꺼졌을 수도 있으므로 4719 확인 |
| `FirstId` > 1 이고 `FirstTime` 이 사건보다 나중 | 2 (롤오버) |
| 1102/104 존재 + 번호 1 재시작 또는 1102가 마지막 | 3 (삭제) |
| 4719 존재 + 그 시각 전후로 건수가 갈린다 | 4 (정책 변경) |
| 1100 존재 + 그 이후 전 채널 조용 | 5 (서비스 중지) |
| 그 이벤트가 다른 채널에 있다 | 6 |
| 파서 오류 / `ChunkNumber` 불연속 | 7 (손상) |
| 위 전부 아님 | 8 (원래 안 남는다) |

## 2차 확인

### 감사 정책이 켜져 있었는지 입증

라이브 시스템이라면 정책을 직접 읽는다.

```powershell
# 하위 범주별 감사 설정 (라이브)
auditpol /get /category:*

# 특정 하위 범주만
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"Detailed File Share"

# 채널의 최대 크기와 보존 정책
wevtutil gl Security
wevtutil gl System
```

오프라인 이미지라면 간접 증거를 모은다.

| 근거 | 무엇을 보나 | 강도 |
| --- | --- | --- |
| **4719** | `SubcategoryGuid` 와 `AuditPolicyChanges` 로 어떤 감사가 언제 켜지고 꺼졌는지 | 가장 직접적 |
| 그 이벤트가 **다른 시각에는 존재** | 정책이 켜져 있었음을 증명 | 강하다 |
| 같은 하위 범주의 **다른 Event ID**가 존재 | 예: 4689가 있으면 프로세스 감사가 켜져 있었다 | 중간 |
| `SYSTEM` hive의 `Services\EventLog\<채널>` `MaxSize` | 롤오버 속도 추정 | 보조 |
| `SECURITY` hive의 감사 정책 값 | 정책 상태의 원본 | 중간 (해석에 주의) |
| 4608(시스템 시작) 직후 감사 관련 이벤트 | 부팅 시점의 정책 상태 | 보조 |

```powershell
# 4719 로 감사 정책 변경 이력을 확정
Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest -FilterXPath '*[System[(EventID=4719)]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUTC        = $x.Event.System.TimeCreated.SystemTime
      RecordId       = $_.RecordId
      Subject        = $d['SubjectUserName']
      SubcategoryId  = $d['SubcategoryId']
      Subcategory    = $d['SubcategoryGuid']
      Changes        = $d['AuditPolicyChanges']
    }
  } | Format-Table -AutoSize
```

### 로그 보존 구간을 계산해 "이 시각은 로그 범위 밖"임을 입증

이것이 "없음"을 증거로 바꾸는 유일한 절차다.

```powershell
$ch = 'Security'
$g = Import-Csv 'C:\case\out\full.csv' |
  Where-Object { $_.Channel -eq $ch } |
  Sort-Object { [int64]$_.EventRecordId }

$firstT = [datetime]$g[0].TimeCreated
$lastT  = [datetime]$g[-1].TimeCreated

[pscustomobject]@{
  Channel      = $ch
  FirstRecord  = $g[0].EventRecordId
  FirstUTC     = $firstT.ToString('yyyy-MM-dd HH:mm:ss')
  FirstKST     = $firstT.AddHours(9).ToString('yyyy-MM-dd HH:mm:ss')
  LastRecord   = $g[-1].EventRecordId
  LastUTC      = $lastT.ToString('yyyy-MM-dd HH:mm:ss')
  LastKST      = $lastT.AddHours(9).ToString('yyyy-MM-dd HH:mm:ss')
  Records      = $g.Count
  SpanHours    = [math]::Round(($lastT - $firstT).TotalHours, 2)
  Missing      = ([int64]$g[-1].EventRecordId - [int64]$g[0].EventRecordId + 1) - $g.Count
} | Format-List
```

출력 예시와 서술 전환:

```text
Channel     : Security
FirstRecord : 1102841
FirstUTC    : 2026-03-12 22:04:11
FirstKST    : 2026-03-13 07:04:11
LastRecord  : 1185204
LastUTC     : 2026-03-14 07:45:11
LastKST     : 2026-03-14 16:45:11
Records     : 82364
SpanHours   : 33.68
Missing     : 0
```

이 표에서 나오는 문장이 답이다.

```text
Security 채널의 관측 가능 구간은 2026-03-13 07:04:11 ~ 2026-03-14 16:45:11 KST 이다.
첫 레코드 번호가 1102841 로 1 이 아니므로 그 이전 구간은 롤오버로 소실되었고,
번호 누락(Missing)이 0 이므로 구간 내부는 온전하다.
따라서 "2026-03-12 이전에 로그온이 없었다"는 주장은 성립하지 않는다 —
그 시각은 로그 범위 밖이다.
```

`Missing` 이 0이 아니면 그만큼의 레코드가 사라진 것이다. 그 판정 절차는 FOR-0103에 있다.

### 파일 손상 확인

```powershell
# EVTX 시그니처 (ElfFile 이 보여야 정상)
Format-Hex -Path 'C:\case\Security.evtx' -Count 64

# 총 청크 수 추정 (헤더 4096바이트 제외, 청크 65536바이트)
$len = (Get-Item 'C:\case\Security.evtx').Length
[math]::Floor(($len - 4096) / 65536)
```

파서가 중간에 멈췄다면 마지막으로 읽힌 `EventRecordId` 와 위 청크 수를 비교해 어디까지 읽혔는지 본다. 청크 단위 구조라 **손상 구간 이후의 청크에도 유효한 레코드가 남아 있을 수 있다.**

## 다른 방법

원인이 확정됐고 그 구간이 정말 없다면, 다른 artifact로 메운다. **이 표가 이 글의 실전 가치다.**

| 없는 이벤트 | 무엇을 알려는가 | 대체 artifact | 얻는 것 / 한계 |
| --- | --- | --- | --- |
| **4688 없음** | 무엇이 실행됐나 | Prefetch (`C:\Windows\Prefetch\*.pf`) | 실행 파일명, 최근 실행 시각들, `RunCount`. **개수 제한으로 오래된 것이 밀려난다** |
| | | Amcache (`C:\Windows\AppCompat\Programs\Amcache.hve`) | 실행 파일 경로·크기·SHA-1. **"실행"이 아니라 "존재"를 뜻할 수 있다** |
| | | BAM (`SYSTEM\...\Services\bam\State\UserSettings\<SID>`) | 사용자별 실행 파일과 마지막 실행 시각. 보존 기간이 짧다 |
| | | UserAssist (`NTUSER.DAT`) | **GUI로 실행한 것만.** 실행 횟수와 마지막 시각 |
| | | AppCompatCache / ShimCache | 경로와 크기. 시각은 파일 수정 시각이며 실행 증거가 아니다 |
| | | SRUM (`SRUDB.dat`) | 앱별 네트워크·CPU 사용량. 실행 사실의 강한 보조 |
| **4624 없음** | 누가 로그온했나 | `$MFT` 의 사용자 프로필 폴더 시각 | 프로필 폴더·`NTUSER.DAT` 갱신 시각 = 로그온 구간 추정 |
| | | RDP 비트맵 캐시 (`...\Terminal Server Client\Cache`) | 화면 조각. **RDP 클라이언트 측** 흔적 |
| | | 브라우저 히스토리 / 다운로드 | 그 시각에 사람이 앉아 있었다는 증거 |
| | | `NTUSER.DAT` LastWrite, ProfileList | 프로필 로드 시각 |
| | | TerminalServices 채널 21/24/25, 1149 | Security가 없어도 RDP 채널은 남아 있을 수 있다 |
| **4104 없음** | 어떤 스크립트가 돌았나 | `ConsoleHost_history.txt` | **대화형으로 입력한 명령 전문.** 시각이 없다 |
| | | 디스크의 `.ps1` 파일 | 본문. `$MFT` 로 생성 시각 확보 |
| | | 메모리 덤프 | 실행 중이던 스크립트 블록·명령행 |
| | | `Windows PowerShell` 클래식 채널 (400/403/600) | 엔진 시작·공급자 이벤트. 본문은 없지만 **실행 사실과 시각** |
| | | PowerShell 전사(transcript) 파일 | 켜져 있었다면 입출력 전문 |
| **5145 없음** | 어떤 파일에 접근했나 | `$MFT` / `$UsnJrnl:$J` | 파일 생성·수정·삭제 사실과 시각 |
| | | LNK / Jump List | 사용자가 연 파일의 경로와 볼륨 정보 |
| | | ShellBags (`NTUSER.DAT`, `USRCLASS.DAT`) | **탐색한 폴더**. 파일 접근의 정황 |
| | | RecentDocs | 최근 열어본 문서 |
| | | 5140 (있으면) | 공유 접근 자체는 남을 수 있다 |

각 대체 artifact의 파싱 절차는 해당 전담 글에 있다. `$MFT`/`$J` 축을 EVTX와 한 타임라인에 올리는 방법은 [FOR-0050](./ntfs-artifact-timeline.html), `$MFT` 자체는 [FOR-0021](./mft-basics.html), UserAssist는 [FOR-0061](./userassist.html)이다.

### 없다는 사실 자체를 증거로 쓰는 방법과 그 한계

다음 세 조건을 **모두** 만족하면 "없음"을 증거로 쓸 수 있다.

| 조건 | 입증 방법 |
| --- | --- |
| ① 그 이벤트를 남기는 감사가 **켜져 있었다** | 같은 이벤트가 다른 시각에 존재, 또는 4719로 정책 상태 확인 |
| ② 그 시각이 **보존 구간 안**이다 | 첫/마지막 레코드의 번호와 시각 |
| ③ 그 구간에 **레코드 누락이 없다** | `Missing = 0` (번호 연속성) |

세 조건이 갖춰졌을 때 쓸 수 있는 서술:

```text
Security 채널의 관측 구간(2026-03-13 07:04 ~ 2026-03-14 16:45 KST)에는
번호 누락이 없고, 4688 이 같은 구간의 다른 시각에 12,844건 존재하므로
프로세스 생성 감사가 켜져 있었음이 확인된다.
그 구간 안의 16:35~16:40 에 4688 이 한 건도 없다는 것은
그 5분간 새 프로세스가 생성되지 않았음을 의미한다.
```

한계도 함께 써야 한다.

| 한계 | 내용 |
| --- | --- |
| 감사 범위 밖의 행위 | 정책이 켜져 있어도 감사 대상이 아닌 행위는 안 남는다 |
| 커널·드라이버 수준 우회 | 감사 자체를 우회하는 기법이 있다 |
| 선택적 레코드 제거 | 번호 연속성이 이것까지 완벽히 잡아 준다고 단정할 수 없다 |
| 다른 채널의 기록 | "Security에 없음"과 "어디에도 없음"은 다르다 |
| 시간 동기화 | 시스템 시각이 변경됐다면 구간 계산 자체가 흔들린다 (4616 확인) |

**"관측되지 않았다"와 "일어나지 않았다"를 문장에서 구분한다.** 전자는 항상 안전하고, 후자는 위 세 조건이 갖춰졌을 때만 쓴다.

## 실제 예시

```text
문제:
"공격자가 실행한 프로그램의 이름을 구하세요.
 지문: '2026-03-14 16:20 KST 경에 악성 실행이 있었습니다.'
 첨부: winevt/ (Security, System), Prefetch/, $MFT, NTUSER.DAT"

1. 첫 시도 (실패):
   4688 을 찾았다.
   Get-WinEvent -Path 'C:\case\Security.evtx' -Oldest `
     -FilterXPath '*[System[(EventID=4688)]]' | Measure-Object
   -> Count : 0

   "프로세스 생성 기록이 없으므로 실행되지 않았다" 로 답했다. 오답.

   무엇이 틀렸나:
     0건이라는 것은 "실행되지 않았다"가 아니라
     "이 시스템에서 프로세스 생성 감사가 켜져 있지 않았다" 는 뜻일 수 있다.
     원인을 확정하지 않고 부재를 결론으로 썼다.

2. 원인 확정 절차
   (1) 전 구간 0건인가 -> 4688 은 전 구간 0건
   (2) 같은 하위 범주의 4689 는? -> 역시 0건
   (3) 4719 가 있는가? -> 없음
   (4) 1102 / 104 / 1100 이 있는가? -> 없음
   (5) 채널별 보존 구간
       Security : FirstId 1102841 (2026-03-12 22:04:11Z) ~ LastId 1185204 (2026-03-14 09:12:40Z)
                  Missing 0
       System   : FirstId 8102 ~ LastId 12844, Missing 0

   => 삭제도 롤오버도 아니고, 정책 변경 이력도 없다.
      4688 이 전 구간 0건이고 4689 도 0건이므로
      원인 ① "프로세스 생성 감사가 애초에 꺼져 있었다" 로 확정.

3. 두 번째 시도 (실패):
   대체 artifact 로 Amcache 를 먼저 봤다.
   AmcacheParser 결과에 C:\Users\Public\svc.exe 가 있었다.
   "svc.exe 가 실행된 프로그램" 이라고 답했다. 부분 오답.

   무엇이 틀렸나:
     Amcache 는 "그 파일이 이 시스템에 있었다"를 강하게 말해 주지만
     실행 사실과 실행 시각을 확정해 주지는 않는다.
     지문이 요구한 것은 16:20 KST 에 실행된 프로그램이다.

4. 접근 변경 — 실행과 시각을 함께 주는 artifact 로 간다
   시간 축을 먼저 UTC 로 환산한다.
     지문 16:20 KST = 07:20 UTC

   Prefetch:
   PECmd.exe -d 'C:\case\Prefetch' --csv 'C:\case\out'
   -> POWERSHELL.EXE-*.pf  LastRun 2026-03-14 07:20:08Z  RunCount 4
      SVC.EXE-*.pf         LastRun 2026-03-14 07:28:30Z  RunCount 1

   07:20:08Z = 16:20:08 KST -> 지문의 시각과 일치.
   => 16:20 에 실행된 것은 powershell.exe 다.

5. 교차 확증
   - BAM (SYSTEM hive, 사용자 SID 아래): powershell.exe 항목의 마지막 실행 시각이
     07:20 대와 일치
   - $MFT: C:\Users\Public\svc.exe 의 Created0x10 = 2026-03-14 07:27:51Z
     -> svc.exe 는 07:28 에 실행된 두 번째 단계다
   - ConsoleHost_history.txt: IEX (New-Object Net.WebClient).DownloadString(...)
     -> powershell 로 실행한 명령의 본문 확보 (시각은 없다)
   - Prefetch 의 POWERSHELL.EXE-*.pf 참조 파일 목록에 svc.exe 경로가 있는지 확인

6. 서술로 정리
   "이 시스템은 프로세스 생성 감사(4688)가 활성화되어 있지 않았다.
    근거: Security 채널의 관측 구간(2026-03-13 07:04 ~ 2026-03-14 18:12 KST)에
    번호 누락이 없고 1102/104/4719/1100 이 모두 부재하는데도
    4688/4689 가 전 구간 0건이다.
    따라서 실행 흔적은 Prefetch·BAM·Amcache 로 대체 확인했다.
    2026-03-14 16:20:08 KST 에 powershell.exe 가 실행되었고
    (Prefetch LastRun, BAM 일치),
    16:28:30 KST 에 C:\Users\Public\svc.exe 가 실행되었다
    (Prefetch RunCount 1, $MFT 생성 07:27:51Z)."

정답: powershell.exe (16:20:08 KST), 이어서 svc.exe (16:28:30 KST)
```

두 번의 교정이 핵심이다. **① 부재를 원인 확정 없이 결론으로 쓰면 오답이다** — 0건은 "안 했다"가 아니라 "안 남았다"일 수 있다. **② 대체 artifact는 "무엇을 말해 주는지"가 다르다** — Amcache는 존재를, Prefetch/BAM은 실행과 시각을 말한다. 문제가 시각을 요구하면 후자로 가야 한다.

## 막혔을 때 다음 체크

1. 그 Event ID가 **전 구간에서** 0건인가 — 그렇다면 정책 미설정 유력
2. 같은 감사 하위 범주의 **다른 Event ID**가 있는가 (4688 없음 ↔ 4689 있음)
3. 1102 / 104 / 4719 / 1100 을 모두 검색했는가
4. 채널별 첫 `EventRecordId` 가 1인가 — 아니면 롤오버다
5. 번호 누락(`Missing`)이 0인가
6. 사건 시각이 관측 구간 **안**인가 — KST/UTC 환산을 확인했는가
7. 첨부에 없는 채널 파일이 있는가 (파일 목록과 채널 목록 대조)
8. 그 이벤트가 다른 채널에 있는가 (4697↔7045, 4104↔클래식 400/403/600)
9. EVTX 시그니처가 `ElfFile` 인가, 파서가 오류를 뱉었는가
10. `Archive-*.evtx` 백업 파일이 있는가 — 지워진 구간이 여기 남아 있을 수 있다
11. 대체 artifact 매핑표에서 **시각까지 주는** 것을 골랐는가
12. 대체 artifact의 한계를 서술에 반영했는가 (Amcache = 존재, ShimCache ≠ 실행)
13. 4616(시스템 시각 변경)이 있는가 — 있으면 구간 계산 자체를 재검토
14. "관측되지 않았다"와 "일어나지 않았다"를 문장에서 구분했는가
15. 답 시각을 KST(+9시간)로 낼지 확인했는가

## 출처

- SRC-022 — Microsoft Learn, 고급 보안 감사 정책 설정: 감사 하위 범주와 각 Event ID의 대응, 4719(감사 정책 변경)의 `SubcategoryGuid`/`AuditPolicyChanges` 필드, 1100(로깅 서비스 종료), 1102(감사 로그 지움), 104(로그 파일 지움), 4688/4689/5145/4663/4673 등이 어떤 하위 범주에 속하는지
- SRC-026 — Libyal libevtx, EVTX 포맷 문서: 파일 헤더(`ElfFile`, 4,096바이트)와 청크(`ElfChnk`, 65,536바이트) 구조, 레코드 식별자가 파일 단위로 단조 증가한다는 근거 — 보존 구간과 누락 계산의 기반
- SRC-031 — Microsoft Learn, 애플리케이션 호환성/Shim 인프라: AppCompatCache(ShimCache)와 Amcache가 애플리케이션 호환성 목적의 기록이라는 근거. **실행 증거로 직접 쓸 수 없다**는 해석의 출처
- 각 감사 하위 범주의 기본 활성/비활성 상태는 Windows 버전과 적용된 정책에 따라 다르므로, "기본으로 꺼져 있다"를 단정하지 않고 대상 시스템의 실제 정책(4719, `auditpol`, `SECURITY` hive)으로 확인할 것
- Prefetch / Amcache / BAM / UserAssist / ShellBags / SRUM / `ConsoleHost_history.txt` 의 상세 구조와 파싱 절차는 각 전담 글과 해당 도구 문서에서 확인할 것. 이 글은 "무엇을 대신 볼 수 있는가"의 매핑만 제공한다
- `auditpol` 과 `wevtutil` 은 라이브 시스템 전용이다. 오프라인 이미지에서는 hive와 이벤트로 간접 확인해야 한다
