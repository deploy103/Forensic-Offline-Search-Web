---
id: FOR-0032
title: "삭제된 파일이 휴지통에 없을 때: 원인 8가지와 확인 순서"
slug: "deleted-file-not-in-recycle-bin"
category: "디스크/NTFS"
type: "troubleshooting"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$Recycle.Bin", "$UsnJrnl", "$J", "$LogFile", "$MFT", "Prefetch", "NukeOnDelete"]
file_paths: ["C:\\$Recycle.Bin", "C:\\$Extend\\$UsnJrnl:$J", "C:\\$LogFile", "C:\\$MFT", "C:\\Windows\\Prefetch", "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"]
registry_paths: ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]
event_ids: []
protocols: []
tools: ["MFTECmd", "RBCmd", "NTFS Log Tracker", "photorec", "foremost", "WinPrefetchView", "RegistryExplorer", "Sleuth Kit"]
commands: ["Import-Csv usn.csv | Where-Object {$_.UpdateReasons -match 'FileDelete'}", "blkls -o 2048 image.dd > unalloc.raw", "photorec unalloc.raw", "Get-ChildItem -Force -Recurse 'C:\\$Recycle.Bin'"]
regex_patterns: ["File_?Delete", "sdelete|cipher|bleachbit|ccleaner|eraser", "Remove-Item|del\\s|rd\\s+/s"]
wireshark_filters: []
tshark_fields: []
log_fields: ["UpdateReasons", "Usn", "UpdateTimestamp", "FileName", "ParentPath", "InUse", "SequenceNumber", "NukeOnDelete", "MaxCapacity"]
file_formats: ["ntfs"]
primary_terms: ["휴지통에 없다", "shift delete", "쉬프트 딜리트", "완전삭제"]
keywords: ["휴지통에 없다", "Shift+Delete", "완전 삭제", "NukeOnDelete", "MaxCapacity", "휴지통 우회", "이동식 매체", "안티포렌식", "sdelete", "카빙", "삭제 도구"]
aliases: ["휴지통에 없는 삭제 파일", "shift delete 흔적", "완전삭제 확인", "휴지통 우회", "usb 파일 삭제", "지운 파일 복구 안 됨", "휴지통 비웠을 때"]
symptom_keywords: ["삭제된 파일이 휴지통에 없다", "$I 파일이 하나도 없다", "RBCmd가 0건이다", "완전삭제인지 알고 싶다", "휴지통을 비운 것 같다", "USB에서 지운 파일을 찾고 싶다", "누가 삭제 도구를 썼는지"]
related: ["FOR-0028", "FOR-0030", "FOR-0031"]
source_ids: ["SRC-013", "SRC-005", "SRC-086"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

휴지통이 비어 있는 것은 **삭제가 없었다는 뜻이 아니라 삭제 경로가 휴지통을 지나지 않았다는 뜻**이다 — `$J`에서 `$Recycle.Bin`으로의 rename 유무를 먼저 확인하면 "우회 삭제"와 "휴지통 비우기"가 즉시 갈리고, 거기서 원인 8가지가 두 갈래로 나뉜다.

## 증상

- 문제 지문은 "삭제된 파일"을 말하는데 `$Recycle.Bin`에 `$I`/`$R`가 없다
- `RBCmd.exe -d ...`가 `0 files` 또는 빈 CSV를 낸다
- `$Recycle.Bin` 폴더 자체가 없거나 SID 폴더만 있고 내용이 없다
- `$R` 파일은 있는데 `$I`가 없다 (또는 그 반대)
- `$J`에는 `FileDelete`가 잔뜩 있는데 휴지통 기록은 하나도 없다
- USB/네트워크 드라이브에서 지운 파일을 찾는데 휴지통이 아예 없다

## 가장 가능성 높은 원인

**확률 높은 순.** 위에서부터 확인하면 대부분 3번 안에 끝난다.

| 순위 | 원인 | `$J`에 남는 모양 | 결정적 판별점 |
| --- | --- | --- | --- |
| 1 | **Shift+Delete** (탐색기에서 즉시 삭제) | `FileDelete\|Close`. `$Recycle.Bin` rename **없음** | 사용자 폴더의 개별 파일 1~수건. 시각이 사용자 활동 시간대 |
| 2 | **명령줄/스크립트 삭제** (`del`, `Remove-Item`, `rd /s /q`) | `FileDelete\|Close`가 **짧은 시간에 다발** | 같은 폴더의 여러 파일이 초 단위로 연속 삭제. 부모 폴더까지 삭제되면 폴더 `FileDelete`도 함께 |
| 3 | **휴지통 우회 설정** (`NukeOnDelete`) | 모든 삭제가 `FileDelete`. 휴지통 기록이 **기간 전체에 걸쳐 0건** | 레지스트리 `NukeOnDelete = 1`. 사용자가 오래 그렇게 써 왔다 |
| 4 | **휴지통 용량 초과** | 큰 파일만 `FileDelete`, 작은 파일은 rename | `MaxCapacity`보다 큰 파일에서만 발생. 크기 상관관계가 보인다 |
| 5 | **이동식 매체 / 네트워크 드라이브** | 그 볼륨의 `$J`가 있으면 `FileDelete`, FAT32/exFAT면 **기록 자체 없음** | 대상 경로가 `C:` 이외의 이동식 볼륨 또는 UNC 경로 |
| 6 | **애플리케이션이 직접 삭제** (설치 제거, 캐시 정리, 임시파일 삭제, 동기화 클라이언트) | `FileDelete` 대량. `ParentPath`가 `AppData`/`Temp`/`Cache` | 삭제 대상이 사용자 문서가 아니라 프로그램 관리 영역 |
| 7 | **안티포렌식 도구** (`sdelete`, `cipher /w`, 와이핑 유틸리티) | `DataOverwrite` 다수 반복 → `Rename`(무의미한 이름) → `FileDelete` | 같은 엔트리에 `DataOverwrite`가 비정상적으로 많다. 도구 실행 흔적이 Prefetch에 남는다 |
| 8 | **휴지통을 비웠다** | `RenameOldName`/`RenameNewName`(→`$R...`)이 **먼저** 있고, 나중에 `$I`/`$R`의 `FileDelete` | **휴지통을 거친 흔적이 남아 있다.** 위 1~7과 근본적으로 다르다 |

**1~7은 "휴지통을 지나지 않았다", 8은 "지났지만 지워졌다"다.** 이 이분법이 첫 갈림길이다.

## 1차 확인

### ① `$Recycle.Bin`이 정말 비어 있는지 (도구 문제 배제)

```powershell
Get-ChildItem -Force -Recurse 'C:\case\$Recycle.Bin' | Select-Object FullName, Length
```

`-Force`가 없으면 숨김+시스템 속성 때문에 **아무것도 안 보인다.** RBCmd가 0건인 이유의 절반은 이것과 PowerShell 이중 인용부호의 `$` 확장이다 ([FOR-0031](./rbcmd.html)).

다른 볼륨도 확인한다.

```powershell
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
  Test-Path (Join-Path $_.Root '$Recycle.Bin')
}
```

### ② `$J`에서 휴지통 경유 여부를 판정한다 (가장 중요한 한 단계)

```powershell
Import-Csv usn.csv | Where-Object { $_.ParentPath -match '\$Recycle\.Bin' } |
  Sort-Object {[uint64]$_.Usn} |
  Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath
```

| 결과 | 판정 | 다음 |
| --- | --- | --- |
| 아무 것도 없다 | **휴지통을 지나지 않았다.** 원인 1~7 | ③으로 |
| `RenameNewName`으로 `$R...`이 나온다, 이후 `FileDelete` 없음 | 휴지통에 있어야 하는데 파일이 없다 → **추출 누락** 또는 복원됨 | `$Recycle.Bin` 재추출 |
| `$R.../$I...`의 `FileDelete`가 있다 | **원인 8: 휴지통을 비웠다.** 그 시각이 답이다 | `$I`의 `FileDelete` 시각을 보고 |

### ③ 삭제 시각과 밀도로 1·2·6을 가른다

```powershell
# 관심 파일의 삭제 레코드
Import-Csv usn.csv | Where-Object { $_.UpdateReasons -match 'File_?Delete' -and
                                     $_.FileName -match 'contract' } |
  Format-Table Usn, UpdateTimestamp, FileName, ParentPath

# 그 시각 ±60초의 모든 삭제 — 단발인가 다발인가
Import-Csv usn.csv |
  Where-Object { $_.UpdateReasons -match 'File_?Delete' -and
                 [datetime]$_.UpdateTimestamp -ge '2026-04-08 23:46:15' -and
                 [datetime]$_.UpdateTimestamp -le '2026-04-08 23:48:15' } |
  Sort-Object {[uint64]$_.Usn} | Format-Table UpdateTimestamp, FileName, ParentPath
```

| 관측 | 원인 후보 |
| --- | --- |
| 삭제 1~3건, 사용자 문서 폴더 | **1. Shift+Delete** |
| 같은 폴더 파일이 수십 건, 1~2초 내 연속 | **2. 명령줄/스크립트** |
| `ParentPath`가 `AppData`/`Temp`/`Cache`/`INetCache` | **6. 애플리케이션** |
| 같은 엔트리에 `DataOverwrite`가 여러 번 선행 | **7. 와이핑 도구** |

### ④ 휴지통 설정을 확인한다 (원인 3·4)

NTUSER.DAT를 RegistryExplorer로 열고 다음 키를 본다.

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{볼륨GUID}
  ├ NukeOnDelete = 1        -> 휴지통을 쓰지 않고 즉시 삭제 (원인 3)
  └ MaxCapacity  = <MB>     -> 이 크기를 넘는 파일은 휴지통에 못 들어간다 (원인 4)

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket
  └ UseGlobalSettings       -> 볼륨별 설정 대신 전역 설정 사용 여부

HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
  └ NoRecycleFiles = 1      -> 정책으로 휴지통 사용 금지 (원인 3)
```

`NukeOnDelete = 1`이면 **그 볼륨의 모든 탐색기 삭제가 즉시 삭제**다. 이 경우 "Shift+Delete를 눌렀는가"는 물을 필요가 없다 — 일반 Delete도 같은 결과다. 답변에서 "고의성"을 주장할 근거가 사라지므로 반드시 확인한다.

원인 4의 판별은 크기 상관관계다. `MaxCapacity`보다 큰 파일만 `FileDelete`로 나타나고 작은 파일은 정상적으로 휴지통 rename이 있으면 용량 초과다.

## 2차 확인

### ⑤ `$LogFile`로 삭제 자체를 독립 확증

```text
NTFS Log Tracker 에 $LogFile + $J + $MFT 로드 -> 대상 EntryNumber 로 필터
```

| 오퍼레이션 | 뜻 |
| --- | --- |
| `DeleteIndexEntryAllocation` / `DeleteIndexEntryRoot` | 부모 폴더 인덱스에서 이름 제거 |
| `DeallocateFileRecordSegment` | **MFT 레코드 해제 = 실제 삭제** |

두 개가 짝으로 있으면 삭제 확정이다. `$LogFile`에 없으면 보존 창(수십 분~수 시간) 밖일 뿐 반증이 아니다. 판정 절차는 [FOR-0029](./logfile-usnjrnl-crosscheck.html)에 있다.

### ⑥ `$MFT`로 복구 가능성을 판정

```powershell
Import-Csv mft.csv | Where-Object { $_.EntryNumber -eq 204118 } |
  Format-Table EntryNumber, SequenceNumber, InUse, FileName, ParentPath
```

| 관측 | 의미 | 복구 |
| --- | --- | --- |
| `InUse = False`, `SequenceNumber`가 `$J`와 동일 | 레코드 생존 | 데이터런이 남아 있으면 `icat`으로 추출 가능 |
| `SequenceNumber`가 `$J`보다 큼 | 레코드 재사용 | 메타데이터 소실. **카빙만 남았다** |
| 엔트리에 다른 파일 이름 | 재사용 확정 | 위와 동일 |

```bash
# 레코드가 살아 있으면 바로 추출
istat -o 2048 image.dd 204118
icat  -o 2048 image.dd 204118 > recovered.pdf
```

### ⑦ 카빙 (원인 1~8 공통의 마지막 수단)

```bash
# 비할당 영역만 뽑아 카빙 — 전체 이미지를 카빙하는 것보다 훨씬 빠르다
blkls -o 2048 image.dd > unalloc.raw
photorec unalloc.raw
# 또는 시그니처 지정
foremost -t pdf,doc,xls,zip,jpg -i unalloc.raw -o carved/
```

카빙 결과는 **파일명과 경로가 없다.** `$J`에서 얻은 원본 크기와 카빙된 파일 크기를 대조해 특정한다.

### ⑧ 삭제 도구 실행 흔적 (원인 2·7)

| artifact | 경로 / 확인 방법 | 얻는 것 |
| --- | --- | --- |
| Prefetch | `C:\Windows\Prefetch\*.pf` — WinPrefetchView로 열기 | `SDELETE.EXE-*.pf`, `CIPHER.EXE-*.pf`, `CMD.EXE-*.pf`, `POWERSHELL.EXE-*.pf`의 마지막 실행 시각과 실행 횟수 |
| UserAssist | NTUSER.DAT ([FOR-0061](./userassist.html)) | GUI로 실행한 삭제/청소 유틸리티와 실행 횟수 |
| PowerShell 콘솔 히스토리 | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | **입력한 명령 원문.** `Remove-Item`, `del`이 그대로 남는다 |
| EVTX 4688 | Security.evtx ([FOR-0083](./event-4624-logon.html)) | 프로세스 생성 명령행 (감사 정책이 켜져 있었다면) |
| EVTX 4104 | Microsoft-Windows-PowerShell/Operational | 스크립트 블록 원문 |
| Amcache / Shimcache | SYSTEM hive, Amcache.hve | 실행 파일의 존재 이력 (삭제된 도구도 남는다) |

```powershell
# 삭제 도구 이름을 Prefetch 파일명에서 한 번에
Get-ChildItem 'C:\case\Prefetch' -Filter '*.pf' |
  Where-Object { $_.Name -match 'SDELETE|CIPHER|ERASER|BLEACHBIT|CCLEANER|WIPE' } |
  Select-Object Name, LastWriteTime
```

```powershell
# 콘솔 히스토리에서 삭제 명령
Select-String -Path 'C:\case\ConsoleHost_history.txt' -Pattern 'Remove-Item|del\s|rd\s+/s|sdelete|cipher\s+/w'
```

## 다른 방법

원본 볼륨에서 아무것도 안 나올 때 파일의 **존재 자체**를 다른 곳에서 증명한다.

| 목표 | 볼 곳 |
| --- | --- |
| 파일이 존재했다 | LNK, Jump List, RecentDocs, Office `MRU`, 썸네일 캐시(`thumbcache_*.db`) |
| 파일 내용의 일부 | Windows Search DB(`Windows.edb`), 브라우저 캐시, `$LogFile`의 `UpdateResidentValue` |
| 파일이 다른 곳으로 갔다 | 브라우저 업로드 기록, `USBSTOR`, Shellbag, 클라우드 동기화 로그, VSS 스냅숏 |
| USB에서 삭제된 경우 | USB 볼륨이 NTFS면 그 볼륨의 `$J`·`$MFT`. FAT32/exFAT면 **디렉터리 엔트리 카빙** |
| 삭제 파일 목록을 GUI로 | Autopsy의 Deleted Files 뷰 ([FOR-0018](./autopsy-ingest.html)) |

FAT32/exFAT USB는 저널이 없으므로 접근이 완전히 다르다. 삭제된 파일의 디렉터리 엔트리는 첫 바이트가 `0xE5`로 바뀐 채 남아 있는 경우가 많고, Autopsy나 PhotoRec이 이를 회수한다.

## 흔한 함정

- **`Get-ChildItem`을 `-Force` 없이 돌려 "휴지통이 비었다"고 판정하는 것** → `$Recycle.Bin`과 그 하위 항목은 숨김+시스템 속성이다 → `-Force -Recurse`를 항상 붙이거나 FTK Imager로 본다.
- **PowerShell 이중 인용부호로 `"C:\$Recycle.Bin"`을 쓰는 것** → `$Recycle`이 변수로 확장되어 경로가 망가진다 → 단일 인용부호를 쓴다.
- **`FileDelete` 필터만으로 삭제를 찾는 것** → 휴지통 이동은 `FileDelete`가 아니라 rename으로 기록된다 → 원인 8을 통째로 놓친다. `ParentPath`에 `$Recycle.Bin`이 들어간 레코드를 반드시 함께 본다 ([FOR-0028](./usn-reason-flags.html)).
- **`NukeOnDelete`를 확인하지 않고 "Shift+Delete로 은폐를 시도했다"고 결론 내는 것** → 설정이 켜져 있으면 일반 Delete도 즉시 삭제된다 → 고의성 주장 전에 레지스트리를 본다.
- **USB/네트워크 드라이브에서 휴지통을 찾는 것** → 이동식 매체와 네트워크 드라이브는 기본적으로 휴지통을 쓰지 않는다 → 그 볼륨의 파일시스템 종류를 먼저 확인한다.
- **`$Recycle.Bin`이 비었으니 `$J`도 볼 필요 없다고 판단하는 것** → 인과가 뒤집혔다. `$J`가 휴지통이 왜 비었는지 설명해 주는 유일한 출처다 → 순서는 항상 `$J` → 휴지통이다.
- **시간대 혼동** → `$J`의 `UpdateTimestamp`, `$I`의 삭제 시각, Prefetch의 마지막 실행 시각 모두 FILETIME(1601-01-01 UTC 기준 100ns)이며 파서는 보통 UTC로 출력한다 → KST 답이면 +9시간. Unix 환산은 `-11644473600`초.
- **여러 원인이 동시에 성립할 수 있음을 놓치는 것** → 예: 일부는 Shift+Delete, 일부는 휴지통 비우기, 일부는 와이핑 도구 → 파일별로 판정하고 원인을 하나로 강제하지 않는다.

## 실제 예시

```text
문제:
"직원이 퇴사 직전 자료를 삭제했다는 신고입니다. 휴지통에는 아무것도 없습니다.
 무엇이 언제 어떤 방식으로 삭제되었는지 판정하세요."
첨부: disk.E01

1. 첫 시도 (실패):
   RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv 'C:\case\out' --csvf rb.csv
   -> Found 0 files

   "휴지통이 비어 있으니 완전삭제(Shift+Delete)다"라고 결론 낼 뻔했다.  <-- 근거 부족

   왜 틀렸나: 0건의 원인이 최소 8가지다. 추출 실패·설정·용량·이동식 매체·
   휴지통 비우기 모두 같은 0건을 만든다. 0건 자체는 어떤 원인도 지목하지 않는다.

2. 접근 변경 — $J 에서 '휴지통을 지났는가'를 먼저 묻는다
   MFTECmd.exe -f 'C:\case\J' -m 'C:\case\MFT' --csv 'C:\case\out' --csvf usn.csv

   Import-Csv out\usn.csv | Where-Object { $_.ParentPath -match '\$Recycle\.Bin' } |
     Sort-Object {[uint64]$_.Usn} |
     Format-Table UpdateTimestamp, UpdateReasons, FileName, ParentPath

   UpdateTimestamp        UpdateReasons          FileName        ParentPath
   2026-04-08 14:30:22Z   RenameNewName|Close    $R3PB7QW.xlsx   .\$Recycle.Bin\S-1-5-21-...-1002
   2026-04-08 14:30:22Z   FileCreate|Close       $I3PB7QW.xlsx   .\$Recycle.Bin\S-1-5-21-...-1002
   2026-04-09 08:02:41Z   FileDelete|Close       $I3PB7QW.xlsx   .\$Recycle.Bin\S-1-5-21-...-1002
   2026-04-09 08:02:41Z   FileDelete|Close       $R3PB7QW.xlsx   .\$Recycle.Bin\S-1-5-21-...-1002

   -> 휴지통을 지났다. 그리고 다음 날 08:02:41 에 비워졌다.  = 원인 8
      1단계 결론(Shift+Delete)은 틀렸다.

3. 원래 이름 복원 — $R3PB7QW 의 rename 짝
   Import-Csv out\usn.csv | Where-Object { $_.FileName -match '3PB7QW|salary' } |
     Sort-Object {[uint64]$_.Usn} | Format-Table Usn, UpdateTimestamp, UpdateReasons, FileName, ParentPath

   0x9a41200  2026-04-08 14:30:22Z  RenameOldName        salary_2026.xlsx  .\Users\hjlee\Documents
   0x9a41290  2026-04-08 14:30:22Z  RenameNewName|Close  $R3PB7QW.xlsx     .\$Recycle.Bin\S-1-5-21-...-1002
   -> 원래 경로 C:\Users\hjlee\Documents\salary_2026.xlsx

4. 두 번째 판정 — 다른 파일들은 어땠나 (원인이 하나라고 가정하지 않는다)
   Import-Csv out\usn.csv |
     Where-Object { $_.UpdateReasons -match 'File_?Delete' -and
                    $_.ParentPath -match 'Users\\hjlee\\(Documents|Desktop|Downloads)' } |
     Sort-Object {[uint64]$_.Usn} | Format-Table UpdateTimestamp, FileName, ParentPath

   2026-04-09 08:11:03Z  client_list.xlsx   .\Users\hjlee\Desktop
   2026-04-09 08:11:03Z  pricing_2026.xlsx  .\Users\hjlee\Desktop
   2026-04-09 08:11:04Z  memo.docx          .\Users\hjlee\Desktop
   ... 총 23건이 08:11:03~08:11:05 사이

   1초에 20건 이상. 사람이 탐색기로 하나씩 지운 속도가 아니다.
   그리고 이 23건은 $Recycle.Bin rename 이 없다.  = 원인 2 (명령줄/스크립트)

5. 설정 배제 (원인 3·4 제외)
   RegistryExplorer 로 hjlee 의 NTUSER.DAT ...\Explorer\BitBucket\Volume\{...} 확인
   -> NukeOnDelete 값 없음, MaxCapacity = 12800 (MB). 우회 설정 아님, 용량 초과도 아님.

6. 도구 흔적 (원인 2 확증)
   ConsoleHost_history.txt:
     Get-ChildItem C:\Users\hjlee\Desktop -Include *.xlsx,*.docx,*.txt -Recurse | Remove-Item -Force
   Prefetch: POWERSHELL.EXE-*.pf 마지막 실행 2026-04-09 08:10:57Z, 실행 횟수 4
   -> 08:11:03 의 다발 삭제와 6초 차이. 명령 원문까지 확보.

7. 복구 판정
   client_list.xlsx: $MFT SequenceNumber 가 $J 와 동일, InUse=False -> 레코드 생존
     icat -o 2048 disk.dd <엔트리번호> > client_list.xlsx   -> 정상 오픈
   salary_2026.xlsx: $R·$I 모두 삭제됨 -> blkls + photorec 로 카빙

정답:
  ① 2026-04-08 14:30:22Z (= 04-08 23:30:22 KST)
     C:\Users\hjlee\Documents\salary_2026.xlsx 를 휴지통으로 삭제
  ② 2026-04-09 08:02:41Z (= 04-09 17:02:41 KST) 휴지통 비우기
  ③ 2026-04-09 08:11:03~05Z (= 04-09 17:11 KST) PowerShell Remove-Item -Force 로
     Desktop 파일 23건 일괄 우회 삭제
  => 원인은 하나가 아니다. 원인 8(휴지통 비우기) + 원인 2(스크립트 삭제)의 조합.
```

1단계와 4단계가 이 글의 요점이다. **"휴지통이 비었다 → Shift+Delete"는 가장 흔한 오답이고, 원인을 하나로 확정하려는 태도가 두 번째 오답이다.** `$J`의 `ParentPath` 한 줄 필터가 방향을 바로잡았다.

## 막혔을 때 다음 체크

1. `Get-ChildItem -Force -Recurse`와 단일 인용부호로 다시 확인했는가 — 도구/셸 문제 배제가 최우선
2. 모든 볼륨의 `$Recycle.Bin`을 확인했는가
3. `$J`에서 `ParentPath`에 `$Recycle.Bin`이 들어간 레코드를 검색했는가 — 원인 8 판별의 유일한 방법
4. 삭제 시각 ±60초의 삭제 건수를 셌는가 — 단발(1) vs 다발(2·6)
5. `NukeOnDelete`와 `MaxCapacity`를 봤는가 — 고의성 판단의 전제
6. 대상 볼륨이 이동식/네트워크였는가, 파일시스템이 NTFS였는가
7. 같은 엔트리에 `DataOverwrite`가 반복되지 않는가 — 와이핑 도구 신호
8. Prefetch·UserAssist·`ConsoleHost_history.txt`·4688에서 삭제 도구/명령을 찾았는가
9. `$MFT`의 `SequenceNumber`가 `$J`와 같은가 — 복구 가능성 판정
10. 원인을 하나로 강제하지 않았는가 — 파일별로 다른 원인일 수 있다
11. 여전히 안 되면 → `blkls` + 카빙, 그리고 파일 존재 자체를 LNK·`Windows.edb`·썸네일 캐시로 증명한다

## 출처

- SRC-013 — Microsoft Learn, Change Journals: `USN_REASON_FILE_DELETE`/`RENAME_*` 의미와 `$J`의 보존 특성. 삭제 방식별 기록 차이의 근거
- SRC-005 — Microsoft Learn, Master File Table: MFT 레코드의 해제·재사용과 시퀀스 개념, 삭제 후 메타데이터 소실의 원리
- SRC-086 — MITRE ATT&CK: Indicator Removal on Host(T1070) 및 File Deletion(T1070.004) — 명령줄 삭제·와이핑 도구의 관측 지점
- `BitBucket\Volume\{GUID}` 하위 `NukeOnDelete`/`MaxCapacity`와 `Policies\Explorer\NoRecycleFiles`의 존재 여부·자료형은 OS 버전과 정책 적용 상태에 따라 다르므로 실제 NTUSER.DAT에서 키를 열어 확인할 것. 값이 없으면 기본값(휴지통 사용)이다
- Prefetch 파일명, 콘솔 히스토리 경로, 파서 CSV 컬럼명은 OS/도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- 실제 예시의 시각·엔트리 번호·6문자 식별자는 설명을 위한 예시 값이다
