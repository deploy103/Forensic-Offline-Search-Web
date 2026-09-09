---
id: FOR-0039
title: "파일명 변경 흔적 추적: $UsnJrnl RENAME 쌍으로 원래 이름 찾기"
slug: "filename-change-traces"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["$UsnJrnl", "$J", "$LogFile", "$FILE_NAME", "LNK", "Jump List", "RecentDocs", "Prefetch", "$I"]
file_paths: ["C:\\$Extend\\$UsnJrnl", "C:\\$LogFile", "C:\\$MFT", "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent", "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations", "C:\\Windows\\Prefetch"]
registry_paths: ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"]
event_ids: []
protocols: []
tools: ["MFTECmd", "NTFS Log Tracker", "LECmd", "JLECmd", "RegistryExplorer", "WinPrefetchView", "Timeline Explorer", "sqlite3", "Autopsy"]
commands: ["MFTECmd.exe -f C:\\case\\$J --csv C:\\case\\out --csvf j.csv", "MFTECmd.exe -f C:\\case\\$MFT --csv C:\\case\\out --csvf mft.csv", "rg -i 'RenameOldName|RenameNewName' j.csv", "sqlite3 History \"SELECT target_path, tab_url FROM downloads;\""]
regex_patterns: ["Rename(Old|New)Name"]
wireshark_filters: []
tshark_fields: []
log_fields: ["UpdateReasons", "UpdateTimestamp", "EntryNumber", "ParentEntryNumber", "Name", "Extension", "UpdateSequenceNumber", "target_path", "current_path"]
file_formats: ["ntfs", "lnk", "sqlite"]
primary_terms: ["파일명 변경", "이름 바꾼 기록", "원래 이름 찾기", "이름 변경 흔적"]
keywords: ["파일명 변경", "rename", "RENAME_OLD_NAME", "RENAME_NEW_NAME", "$UsnJrnl", "$J", "원래 이름", "확장자 변경", "파일 이동", "ParentEntryNumber", "$LogFile"]
aliases: ["파일 이름 바뀐 흔적", "원래 파일명 찾기", "rename 추적", "확장자만 바꾼 파일", "이름 변경 시각", "usnjrnl rename", "파일 이동 흔적"]
symptom_keywords: ["파일의 원래 이름을 알고 싶다", "이름이 언제 바뀌었는지 모르겠다", "MFT에는 최종 이름만 있다", "이동인지 이름변경인지 구분이 안 된다", "확장자만 바꾼 파일을 찾고 싶다"]
related: ["FOR-0027", "FOR-0021", "FOR-0038"]
source_ids: ["SRC-013", "SRC-005", "SRC-029"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`$MFT`는 최종 이름만 보관하므로 원래 이름은 `$UsnJrnl`(`$Extend\$UsnJrnl:$J`)의 `RENAME_OLD_NAME`/`RENAME_NEW_NAME` **레코드 쌍**에서 찾는다. 두 레코드는 같은 파일 참조 번호를 갖고 같은 시각에 연속으로 찍히며, 이름이 같고 부모만 다르면 이름변경이 아니라 **이동**이다.

## 어떤 문제에서 필요한가

- 지문이 "이 파일의 원래 이름", "언제 이름이 바뀌었는가"를 묻는 경우
- 확장자만 바꿔 위장한 파일의 원래 확장자를 확인해야 하는 경우 ([FOR-0036](./signature-extension-mismatch.html))
- 자료 유출 시나리오에서 "어떤 파일을 무슨 이름으로 바꿔 어디로 옮겼는가"를 재구성해야 하는 경우
- `$MFT`에는 없는 파일 이름이 다른 artifact(LNK, RecentDocs, 브라우저)에서만 보이는 경우
- 이동과 이름변경을 구분해 사건 흐름을 시간순으로 서술해야 하는 경우

## 문제에서 처음 볼 단서

1. `$J` CSV의 `UpdateReasons`에 `RenameOldName`/`RenameNewName`이 있는 행
2. `$MFT`의 최종 이름과 LNK/RecentDocs의 이름이 **다른** 경우
3. 브라우저 `downloads` 테이블의 `target_path`와 현재 파일 이름이 다른 경우
4. Prefetch에 **현재 존재하지 않는 실행 파일 이름**의 `.pf`가 있는 경우
5. 같은 `EntryNumber`에 대해 `$J`에 여러 개의 서로 다른 이름이 등장하는 경우
6. `$Recycle.Bin`의 `$I` 파일에 적힌 원래 경로가 현재 이름과 다른 경우

## 30초 절차

```powershell
MFTECmd.exe -f 'C:\case\$J' --csv "C:\case\out" --csvf j.csv
```

```bash
# RENAME 쌍만 시간순으로
rg -i 'RenameOldName|RenameNewName' out/j.csv | head -40

# 특정 파일의 전체 이력
rg -i 'secret' out/j.csv
```

```powershell
# 같은 EntryNumber 에서 이름이 두 개 이상 등장한 항목 = 이름이 바뀐 파일
Import-Csv .\out\j.csv |
  Where-Object { $_.UpdateReasons -match 'Rename' } |
  Group-Object EntryNumber |
  Where-Object { ($_.Group.Name | Sort-Object -Unique).Count -gt 1 } |
  ForEach-Object {
    [pscustomobject]@{
      EntryNumber = $_.Name
      Names       = ($_.Group.Name | Sort-Object -Unique) -join ' -> '
      FirstSeen   = ($_.Group.UpdateTimestamp | Sort-Object)[0]
    }
  }
```

## 상세 절차

### 1단계 — RENAME 쌍이 1차 증거다

이름을 바꾸면 NTFS는 `$UsnJrnl`에 **두 개의 레코드**를 연속으로 쓴다.

| 순서 | Reason | 값 | `Name` 필드에 들어가는 것 |
| --- | --- | --- | --- |
| 1 | `USN_REASON_RENAME_OLD_NAME` | `0x00001000` | **변경 전 이름** |
| 2 | `USN_REASON_RENAME_NEW_NAME` | `0x00002000` | **변경 후 이름** |
| 3 | `USN_REASON_CLOSE` | `0x80000000` | 마지막 레코드에 함께 표시 |

두 레코드를 짝지우는 조건:

| 조건 | 확인 방법 |
| --- | --- |
| 같은 파일이다 | `EntryNumber`(파일 참조 번호)와 `SequenceNumber`가 같다 |
| 같은 사건이다 | `UpdateTimestamp`가 같거나 수 밀리초 이내, `UpdateSequenceNumber`(USN)가 연속 |
| 이름이 다르다 | `Name` 필드 비교 |

```text
$ rg -i 'report_final' out/j.csv
UpdateTimestamp,Name,Extension,EntryNumber,ParentEntryNumber,UpdateReasons,UpdateSequenceNumber
2026-03-14 07:41:09.2210048,고객명단_2026.xlsx,.xlsx,88420,71204,RenameOldName,412839240
2026-03-14 07:41:09.2210048,report_final.jpg,.jpg,88420,71204,RenameNewName,412839328
2026-03-14 07:41:09.2210048,report_final.jpg,.jpg,88420,71204,RenameNewName|Close,412839416
```

읽는 법:

- `EntryNumber` 88420이 동일 → **같은 파일**
- `ParentEntryNumber` 71204이 동일 → 폴더는 그대로. **이름변경**이다
- `고객명단_2026.xlsx` → `report_final.jpg`
- 시각 `2026-03-14 07:41:09 UTC` = **`2026-03-14 16:41:09 KST`**
- 확장자가 `.xlsx` → `.jpg`로 바뀌었다 → 위장 목적. 내용은 여전히 XLSX다 ([FOR-0036](./signature-extension-mismatch.html))

### 2단계 — $MFT의 한계

`$MFT`의 `$FILE_NAME`(`0x30`) 속성은 **현재 이름만** 담는다. 이름을 바꾸면 이전 `$FN`은 새 값으로 대체된다 ([FOR-0021](./mft-basics.html)).

| `$MFT`에서 알 수 있는 것 | `$MFT`로 알 수 없는 것 |
| --- | --- |
| 현재 이름과 현재 부모 폴더 | 이전 이름 |
| 8.3 DOS 단축 이름 (있으면) | 이름이 몇 번 바뀌었는지 |
| `$SI`의 C(MFT Changed) — 마지막 엔트리 변경 시각 | 그 변경이 이름변경인지 속성변경인지 |
| 하드링크가 여러 개면 `$FN`이 여러 개 | 이동 이력 |

그래서 `$MFT` 단독으로는 "이름이 바뀌었다"까지도 확정할 수 없다. 다만 두 가지 보조 단서가 있다.

- **8.3 단축 이름의 잔재**: 이름을 바꿀 때 8.3 이름이 이전 이름의 흔적을 남기는 경우가 있다. `MFTECmd` CSV의 short name 계열 컬럼을 본다
- **MFT 레코드 여유 공간**: 속성이 교체되면서 이전 `$FN` 바이트가 레코드의 사용하지 않는 부분에 남을 수 있다. HxD로 레코드(`EntryNumber × 1024`)를 열어 이전 이름 문자열을 UTF-16LE로 찾는다 ([FOR-0034](./file-slack.html), [FOR-0037](./hxd-header-check.html))

### 3단계 — 이름변경 vs 이동 구분

같은 볼륨 안에서의 이동도 `RENAME_OLD_NAME`/`RENAME_NEW_NAME` 쌍을 만든다. **구분 기준은 `Name`과 `ParentEntryNumber`의 조합**이다.

| `Name` | `ParentEntryNumber` | 판정 |
| --- | --- | --- |
| 다르다 | 같다 | **이름변경** (제자리) |
| 같다 | 다르다 | **이동** (같은 볼륨 내) |
| 다르다 | 다르다 | **이동 + 이름변경** (한 번의 작업으로) |
| — | 소스 볼륨에 `FILE_DELETE`, 대상 볼륨에 `FILE_CREATE` | **다른 볼륨으로 이동** (`$J`가 볼륨별로 따로 있다) |

```powershell
# RENAME 쌍을 붙여서 판정까지 한 번에
$j = Import-Csv .\out\j.csv | Where-Object { $_.UpdateReasons -match 'Rename' }
$j | Group-Object EntryNumber, UpdateTimestamp | ForEach-Object {
  $old = $_.Group | Where-Object { $_.UpdateReasons -match 'RenameOldName' } | Select-Object -First 1
  $new = $_.Group | Where-Object { $_.UpdateReasons -match 'RenameNewName' } | Select-Object -First 1
  if ($old -and $new) {
    [pscustomobject]@{
      Time    = $old.UpdateTimestamp
      Entry   = $old.EntryNumber
      OldName = $old.Name
      NewName = $new.Name
      OldPar  = $old.ParentEntryNumber
      NewPar  = $new.ParentEntryNumber
      Kind    = if ($old.Name -ne $new.Name -and $old.ParentEntryNumber -eq $new.ParentEntryNumber) { '이름변경' }
                elseif ($old.Name -eq $new.Name) { '이동' }
                else { '이동+이름변경' }
    }
  }
} | Sort-Object Time | Format-Table -AutoSize
```

```text
Time                         Entry OldName              NewName          OldPar NewPar Kind
----                         ----- -------              -------          ------ ------ ----
2026-03-14 07:41:09.2210048  88420 고객명단_2026.xlsx   report_final.jpg 71204  71204  이름변경
2026-03-14 07:43:22.8830464  88420 report_final.jpg     report_final.jpg 71204  90118  이동
```

`ParentEntryNumber`를 실제 경로로 바꾸려면 `$MFT` CSV에서 그 `EntryNumber`를 찾는다.

```powershell
Import-Csv .\out\mft.csv |
  Where-Object { $_.EntryNumber -in '71204','90118' } |
  Select-Object EntryNumber, ParentPath, FileName
```

```text
EntryNumber ParentPath                    FileName
----------- ----------                    --------
71204       .\Users\jhkim\Documents       work
90118       .\Users\jhkim\Pictures        2026-03
```

이제 사건이 문장이 된다: **"`Documents\work\고객명단_2026.xlsx`를 07:41:09 UTC에 `report_final.jpg`로 이름을 바꾸고, 07:43:22 UTC에 `Pictures\2026-03`으로 옮겼다."**

### 4단계 — $UsnJrnl이 없거나 잘렸을 때: $LogFile

`$J`는 순환 버퍼라 오래된 레코드가 밀려 사라진다. 그때 `$LogFile`이 대안이다.

| 항목 | `$UsnJrnl:$J` | `$LogFile` |
| --- | --- | --- |
| 목적 | 변경 사유 요약 저널 | 트랜잭션 복구용 로그 |
| 보존 기간 | 길다 (수 GB까지 설정 가능) | **짧다** (기본 크기가 작아 수 시간~수일) |
| 이름 정보 | `Name` 필드에 직접 | **인덱스 엔트리 변경 레코드 안에** |
| 파싱 도구 | `MFTECmd -f $J` | NTFS Log Tracker |

이름변경은 부모 디렉터리의 인덱스(`$INDEX_ROOT`/`$INDEX_ALLOCATION`)에서 **옛 엔트리를 지우고 새 엔트리를 추가**하는 형태로 나타난다. `$LogFile`에는 이 인덱스 엔트리 추가/삭제 오퍼레이션이 redo/undo 데이터와 함께 남으므로, **undo 데이터에서 이전 파일 이름을 복원**할 수 있다.

| `$LogFile`에서 찾을 것 | 의미 |
| --- | --- |
| 인덱스 엔트리 삭제 오퍼레이션의 undo 데이터 | **이전 이름** (지워진 엔트리의 내용) |
| 인덱스 엔트리 추가 오퍼레이션의 redo 데이터 | 새 이름 |
| `$FILE_NAME` 속성 갱신 레코드 | 이름 변경 자체 |
| 같은 LSN 구간에 두 오퍼레이션이 묶여 있음 | 한 번의 rename 트랜잭션 |

오퍼레이션 이름 표기는 파서에 따라 다르므로 도구 출력의 라벨을 그대로 확인한다. `$J`와 `$LogFile`의 시각이 일치하면 결론이 두 출처로 확정된다.

### 5단계 — 과거 이름이 남는 다른 artifact

`$J`가 없어도 **과거 이름이 그대로 화석화된 곳**들이 있다. 이쪽이 실전에서 결정타가 되는 경우가 많다.

| artifact | 경로 | 무엇이 남나 | 왜 남나 |
| --- | --- | --- | --- |
| **LNK** | `...\AppData\Roaming\Microsoft\Windows\Recent\*.lnk` | 대상 파일의 **당시 경로·이름**, 크기, MAC 시각, 볼륨 시리얼 | LNK는 만들어진 시점의 값을 복사해 두고, 대상 이름이 바뀌어도 **자동 갱신되지 않는다** |
| **Jump List** | `...\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` | 앱별 최근 파일 경로·이름 (내부에 LNK 스트림) | 위와 동일 |
| **RecentDocs** | `HKCU\...\Explorer\RecentDocs\.<ext>` | 확장자별 최근 문서 이름 (UTF-16), `MRUListEx` 순서 | 열었던 시점의 이름이 그대로 |
| **ComDlg32 MRU** | `HKCU\...\Explorer\ComDlg32\OpenSavePidlMRU`, `LastVisitedPidlMRU` | 열기/저장 대화상자로 다룬 파일·폴더 | 위와 동일 |
| **브라우저 Downloads** | Chrome `History` DB의 `downloads` | `target_path`(저장하려던 경로), `current_path`(당시 실제 경로), `tab_url` | 다운로드 시점의 이름 |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | `.pf` 파일 이름 = **실행 파일 이름** + 경로 해시, 내부에 **참조 파일 전체 경로 목록** | 실행 시점의 이름으로 만들어지고 이후에도 남는다 |
| **`$Recycle.Bin` `$I`** | `C:\$Recycle.Bin\<SID>\$I*` | 삭제 당시의 **원래 전체 경로와 이름**, 삭제 시각, 크기 | 삭제 시점의 값 |
| **Shellbags** | `HKCU\...\Shell\BagMRU` 등 | 탐색한 **폴더** 이름 구조 | 폴더 이름변경 추적에 유용 |
| **Windows Search** | `Windows.edb` | 색인된 파일 경로·이름·속성 | 색인 시점의 값이 남아 있을 수 있다 |
| **Office/앱 MRU** | 앱별 레지스트리 키 | 최근 문서 이름 | 위와 동일 |

핵심 원리는 하나다. **이 artifact들은 "그 시점의 이름"을 복사해 저장하고, 원본 이름이 바뀌어도 갱신되지 않는다.** 그래서 `$MFT`의 현재 이름과 이들이 불일치하면 그 자체가 이름변경의 증거다.

```powershell
# LNK 일괄 파싱 (LECmd)
LECmd.exe -d "C:\case\Recent" --csv "C:\case\out" --csvf lnk.csv
Import-Csv .\out\lnk.csv |
  Select-Object SourceFile, LocalPath, TargetCreated, TargetModified, FileSize

# Jump List 일괄 파싱 (JLECmd)
JLECmd.exe -d "C:\case\AutomaticDestinations" --csv "C:\case\out" --csvf jl.csv
```

```bash
# 브라우저 다운로드의 당시 경로
sqlite3 History "SELECT id, current_path, target_path, tab_url,
                        datetime(start_time/1000000-11644473600,'unixepoch') AS start_utc
                 FROM downloads ORDER BY start_time DESC LIMIT 20;"
```

```text
41|C:\Users\jhkim\Downloads\고객명단_2026.xlsx|C:\Users\jhkim\Downloads\고객명단_2026.xlsx|https://intra.example/dl/9f2a|2026-03-14 07:12:33
```

Chrome/Edge의 `start_time`은 WebKit 시각(1601-01-01 UTC 기준 마이크로초)이므로 `/1000000 - 11644473600`으로 Unix 초로 바꾼다 ([FOR-0191](./chrome-history.html)).

Prefetch는 실행 파일 이름변경 추적에 특히 강하다.

| 관찰 | 해석 |
| --- | --- |
| 현재 없는 이름의 `.pf`가 있다 | 그 이름으로 실행된 뒤 이름이 바뀌거나 삭제되었다 |
| 같은 경로 해시를 가진 `.pf`가 이름만 다르게 두 개 | **같은 자리의 파일이 이름을 바꿔가며 실행되었다** |
| `.pf` 내부 참조 목록에 현재 없는 파일 경로 | 실행 당시 그 경로에 그 이름으로 존재했다 |

### 6단계 — 확장자만 바꾼 경우 vs 이름 전체를 바꾼 경우

| 구분 | `$J`에서의 모습 | 의도 | 함께 볼 것 |
| --- | --- | --- | --- |
| **확장자만 변경** (`a.xlsx` → `a.jpg`) | `Name`의 앞부분이 같고 `Extension`만 다르다 | 형식 위장, 필터 회피, 첨부 제한 회피 | 헤더가 원래 형식 그대로다 ([FOR-0036](./signature-extension-mismatch.html)) |
| **이름 전체 변경** (`고객명단.xlsx` → `IMG_0417.jpg`) | 앞부분과 확장자가 모두 다르다 | 내용 은닉, 탐지 회피 | 주변 파일의 이름 규칙을 모방했는지 |
| **점 추가/제거** (`a.exe` → `a.exe.txt`) | 확장자만 추가 | 실행 차단 우회 준비 또는 격리 | 이후 다시 되돌린 rename 쌍이 있는지 |
| **대소문자만 변경** | `Name`이 대소문자만 다르다 | 대개 무의미. 앱 동작 | 오탐 주의 |
| **임시 이름 경유** (`a.xlsx` → `~tmp` → `b.jpg`) | rename 쌍이 **연속 2회** | 저장 프로그램의 정상 동작인 경우가 많다 | Office/에디터의 원자적 저장 패턴 |

**임시 파일 경유 rename이 가장 큰 오탐원이다.** Office·에디터·다운로드 관리자는 "임시 파일에 쓰고 → 원본을 백업 이름으로 rename → 임시를 원본 이름으로 rename"을 수행한다. Chrome은 `*.crdownload`를 최종 이름으로 rename한다. 이 패턴은 다음으로 걸러낸다.

| 정상 패턴의 특징 | 예 |
| --- | --- |
| 이름에 임시 표식이 있다 | `~$`, `.tmp`, `.crdownload`, `.part`, 8.3 난수 이름 |
| 두 rename이 1초 이내 연속 | 프로그램이 자동 수행 |
| 확장자가 최종적으로 **동일** | `a.xlsx` → `~tmp` → `a.xlsx` |
| 같은 폴더 안에서만 발생 | `ParentEntryNumber` 동일 |

반대로 **위장 의도**의 신호:

| 위장 신호 | 근거 |
| --- | --- |
| 확장자가 다른 형식으로 바뀌고 되돌아오지 않는다 | 최종 상태가 위장 상태 |
| 이름변경 후 바로 다른 폴더로 이동 | 두 개의 rename 쌍이 수초~수분 간격 |
| 이름변경 후 압축/전송/업로드 흔적 | 브라우저 업로드, 메일 첨부, USB 연결 |
| 헤더와 확장자 불일치 | `file`/헤더 확인 결과 |
| 대상 폴더의 기존 파일 이름 규칙을 모방 | `IMG_0417.jpg`처럼 이웃과 같은 형식 |

### 7단계 — 사건 흐름 재구성 절차

```text
1. $Extend\$UsnJrnl:$J 와 $MFT 를 추출해 각각 CSV 로 변환한다.
2. $J 에서 UpdateReasons 에 Rename 이 포함된 행만 뽑는다.
3. EntryNumber + UpdateTimestamp 로 OLD/NEW 쌍을 붙인다.
4. Name/ParentEntryNumber 비교로 이름변경 / 이동 / 둘 다를 판정한다.
5. ParentEntryNumber 를 $MFT CSV 로 실제 경로로 치환한다.
6. 임시 파일 경유 패턴을 제외한다 (~$, .tmp, .crdownload, 1초 이내 왕복).
7. 남은 항목을 시간순으로 정렬해 한 파일의 이력을 한 줄씩 쓴다.
8. 다른 artifact 로 각 지점을 보강한다:
     - 원래 이름의 출처: 브라우저 downloads / LNK / RecentDocs
     - 실행 여부: Prefetch / Amcache
     - 최종 행방: USB 연결, 업로드, 압축, $Recycle.Bin
9. 시각은 전부 UTC 로 맞춰 비교하고, 답만 KST(+9)로 변환한다.
```

시간표 형식으로 정리한다.

```text
시각(UTC)             시각(KST)            사건                                   출처
2026-03-14 07:12:33   2026-03-14 16:12:33  고객명단_2026.xlsx 다운로드            Chrome downloads
2026-03-14 07:20:44   2026-03-14 16:20:44  Documents\work 로 이동                 $J (이동)
2026-03-14 07:41:09   2026-03-14 16:41:09  report_final.jpg 로 이름변경           $J (RENAME 쌍)
2026-03-14 07:43:22   2026-03-14 16:43:22  Pictures\2026-03 으로 이동             $J (이동)
2026-03-14 07:51:07   2026-03-14 16:51:07  E:\ (USB) 로 복사                      $J + USBSTOR
```

## 출력 필드 해석

`MFTECmd`의 `$J` CSV 주요 컬럼이다.

| 컬럼 | 의미 | 이 글에서의 용도 |
| --- | --- | --- |
| `UpdateTimestamp` | 레코드 시각 (FILETIME, UTC) | 쌍 매칭과 타임라인의 축 |
| `Name` | 그 레코드 시점의 **파일 이름** | OLD/NEW 이름 |
| `Extension` | 이름에서 잘라낸 확장자 | 확장자만 바뀐 경우 판별 |
| `EntryNumber` | 파일의 MFT 엔트리 번호 | 같은 파일임을 확정 |
| `SequenceNumber` | 슬롯 재사용 횟수 | 다르면 **다른 파일**이다 |
| `ParentEntryNumber` | 부모 폴더의 엔트리 번호 | **이동 판정의 핵심** |
| `UpdateSequenceNumber` (USN) | 저널 내 순서 값 | 연속성 확인 |
| `UpdateReasons` | 변경 사유 플래그 목록 | `RenameOldName`/`RenameNewName` 등 |
| `FileAttributes` | 속성 (디렉터리 여부 포함) | 폴더 이름변경 구분 |

관련 USN Reason 값:

| Reason | 값 | 의미 |
| --- | --- | --- |
| `USN_REASON_RENAME_OLD_NAME` | `0x00001000` | 변경 전 이름 |
| `USN_REASON_RENAME_NEW_NAME` | `0x00002000` | 변경 후 이름 |
| `USN_REASON_FILE_CREATE` | `0x00000100` | 생성 (다른 볼륨 이동의 도착 측) |
| `USN_REASON_FILE_DELETE` | `0x00000200` | 삭제 (다른 볼륨 이동의 출발 측) |
| `USN_REASON_BASIC_INFO_CHANGE` | `0x00008000` | 시각/속성 변경 ([FOR-0038](./timestomp-detection.html)) |
| `USN_REASON_INDEXABLE_CHANGE` | `0x00004000` | 색인 대상 여부 변경 |
| `USN_REASON_CLOSE` | `0x80000000` | 핸들 닫힘 |

시간대 처리: `$J`의 시각은 FILETIME(1601-01-01 UTC 기준 100ns)이며 `MFTECmd`는 기본적으로 UTC로 출력한다. Chrome `downloads.start_time`은 WebKit(1601 기준 마이크로초), 레지스트리 `RecentDocs`의 키 LastWrite는 FILETIME이다. Unix epoch와의 차이는 **11644473600초**. 전부 UTC로 정규화한 뒤 비교하고, 최종 답만 KST(+9)로 쓴다.

## pivot: 다음에 볼 artifact

| 여기서 얻은 것 | 다음 목표 |
| --- | --- |
| 원래 이름 | 그 이름으로 모든 artifact 전수 검색 (LNK, RecentDocs, 브라우저, EVTX) |
| 이름변경 시각 | 그 시각 ±5분의 프로세스 실행 기록 — **무엇이 이름을 바꿨나** |
| 확장자가 바뀌었다 | 실제 헤더 확인 ([FOR-0036](./signature-extension-mismatch.html)) |
| 이동 대상 폴더 | 그 폴더의 다른 파일도 같은 시각에 들어왔는지 |
| 원래 이름의 다운로드 출처 | 브라우저 `downloads`, `Zone.Identifier` ADS ([FOR-0035](./alternate-data-streams.html)) |
| 이름변경과 함께 시각도 바뀜 | timestomp 병행 여부 ([FOR-0038](./timestomp-detection.html)) |
| 최종 행방이 USB | `SYSTEM` hive의 USBSTOR, 대상 볼륨의 `$J` |
| 최종 행방이 업로드 | pcap의 HTTP POST ([FOR-0158](./http-post-find.html)) |
| `$J`가 잘렸다 | `$LogFile` (NTFS Log Tracker), VSS 내부의 이전 `$MFT`/`$J` |
| 파일이 삭제됐다 | `$Recycle.Bin`의 `$I`, 비할당 카빙 ([FOR-0033](./unallocated-space.html)) |
| 실행 파일 이름이 바뀌었다 | Prefetch의 `.pf` 이름과 내부 참조 목록 |

## 흔한 함정

- **`$MFT`에서 원래 이름을 찾으려는 것.** `$FN`은 현재 이름만 담는다. 왜 틀리는가: 이름변경 시 이전 `$FN`이 대체된다. 어떻게: `$UsnJrnl:$J`의 RENAME 쌍을 본다.
- **`RENAME_NEW_NAME`만 보고 이전 이름을 놓치는 것.** 두 레코드는 서로 다른 행이다. `RenameOldName` 행을 함께 뽑아 시각·`EntryNumber`로 짝지운다.
- **이름이 같은 rename 쌍을 이름변경으로 세는 것.** `Name`이 같고 `ParentEntryNumber`만 다르면 **이동**이다. 판정 로직에 부모 비교를 반드시 넣는다.
- **`EntryNumber`만으로 같은 파일이라고 단정하는 것.** 슬롯은 재사용된다. `SequenceNumber`가 다르면 완전히 다른 파일이다.
- **임시 파일 경유 rename을 위장으로 보고하는 것.** Office의 `~$`, Chrome의 `.crdownload`, 에디터의 원자적 저장이 대량의 rename 쌍을 만든다. 1초 이내 왕복·최종 확장자 동일·임시 표식으로 걸러낸다.
- **`$J`에 기록이 없으면 이름변경이 없었다고 결론 내리는 것.** `$J`는 순환 버퍼다. 오래된 사건은 밀려 사라진다. `$LogFile`·LNK·RecentDocs·Prefetch로 이어간다.
- **`ParentEntryNumber`를 경로로 치환하지 않고 보고하는 것.** 숫자만으로는 아무 의미가 없다. `$MFT` CSV에서 그 엔트리의 `ParentPath`/`FileName`을 찾아 경로로 바꾼다.
- **LNK의 대상 경로를 현재 상태로 읽는 것.** LNK는 **만들어진 시점**의 이름·크기·시각을 담고 있다. 현재 그 경로에 그 파일이 없는 것이 정상이며, 그 불일치가 바로 증거다.
- **시간대를 섞는 것.** `$J`는 UTC, 브라우저 WebKit은 1601 기준 마이크로초, 레지스트리 LastWrite는 FILETIME이다. 전부 UTC로 정규화한 뒤 비교한다.
- **폴더 이름변경을 파일과 같게 다루는 것.** 폴더 이름이 바뀌면 하위 파일의 `$J` 레코드는 생기지 않는다(부모 엔트리 번호는 그대로다). 폴더 자체의 rename 쌍과 Shellbags를 본다.
- **한 번의 rename만 확인하고 끝내는 것.** 이름은 여러 번 바뀐다. 같은 `EntryNumber`의 모든 rename을 시간순으로 뽑아 이력 전체를 만든다.
- **다른 볼륨 이동을 rename으로 찾으려는 것.** 볼륨 간 이동은 rename이 아니라 출발 볼륨의 `FILE_DELETE`와 도착 볼륨의 `FILE_CREATE`다. `$J`는 볼륨마다 따로 있으므로 양쪽을 모두 파싱한다.

## 교차검증

```bash
# 1) 같은 파일의 rename 이력을 두 번 확인 ($J 전체 vs 이름 검색)
rg -i '88420' out/j.csv | head -30
rg -i '고객명단' out/j.csv

# 2) $LogFile 로 2차 확인 (NTFS Log Tracker 출력에서 같은 시각의 인덱스 변경)

# 3) 원래 이름이 다른 artifact 에도 있는가
rg -i '고객명단' out/lnk.csv out/jl.csv out/recentdocs.csv

# 4) 브라우저 다운로드의 당시 이름과 일치하는가
sqlite3 History "SELECT target_path FROM downloads WHERE target_path LIKE '%고객명단%';"

# 5) 현재 파일의 헤더가 원래 확장자와 맞는가
icat -o 2048 image.dd 88420 | head -c 8 | xxd
#  -> 50 4B 03 04  (XLSX = ZIP 컨테이너. .jpg 가 거짓임이 확정)

# 6) 이름변경 시각에 $SI 의 C 도 갱신되었는가 (같은 사건의 다른 흔적)
istat -o 2048 image.dd 88420 | head -20
```

`$J`의 RENAME 시각과 `$SI`의 `LastRecordChange`(C)가 일치하면 같은 사건이 두 출처에 기록된 것이다. 다르면 그 이후에 또 다른 엔트리 변경(속성 변경, timestomp)이 있었다는 뜻이므로 `$J`를 더 읽는다.

## mini walkthrough

```text
문제:
"직원이 고객 자료를 사진으로 위장해 유출했습니다.
 위장된 파일의 원래 이름과 이름을 바꾼 시각(KST)을 답하세요."
첨부: pc01.E01

1. Autopsy Extension Mismatch 로 위장 파일 후보 확보
   -> Users/jhkim/Pictures/2026-03/report_final.jpg
      MIME Type: application/zip
   icat 로 헤더 확인 -> 50 4B 03 04 (ZIP/XLSX 계열)

2. 첫 시도 (실패한 접근):
   $MFT 를 파싱해 그 파일의 원래 이름을 찾으려 했다.
   Import-Csv mft.csv | Where-Object { $_.FileName -eq 'report_final.jpg' } |
     Select-Object FileName, ParentPath, Created0x10, LastRecordChange0x10

   FileName          ParentPath                        Created0x10
   --------          ----------                        -----------
   report_final.jpg  .\Users\jhkim\Pictures\2026-03    2026-03-14 07:12:33...

   원래 이름이 어디에도 없다. "MFT 에 남지 않는다"고 판단해
   비할당 카빙으로 넘어갔고 30 분을 썼다.

   무엇이 틀렸나: $MFT 의 $FILE_NAME 은 최종 이름만 보관한다.
   구조적으로 원래 이름이 있을 수 없는 곳을 계속 뒤졌다.
   이름의 이력은 $UsnJrnl 에 있다.

3. 접근 변경 — $J 를 파싱한다
   FTK Imager 로 C:\$Extend\$UsnJrnl 추출 ($J 스트림 포함)
   MFTECmd.exe -f 'C:\case\$J' --csv "C:\case\out" --csvf j.csv

   먼저 EntryNumber 를 확보 (2단계 mft.csv 에서)
   -> report_final.jpg = EntryNumber 88420, SequenceNumber 2

   rg '88420' out\j.csv | rg -i rename

   2026-03-14 07:41:09.2210048,고객명단_2026.xlsx,.xlsx,88420,71204,RenameOldName
   2026-03-14 07:41:09.2210048,report_final.jpg,.jpg,88420,71204,RenameNewName
   2026-03-14 07:43:22.8830464,report_final.jpg,.jpg,88420,71204,RenameOldName
   2026-03-14 07:43:22.8830464,report_final.jpg,.jpg,88420,90118,RenameNewName

   1~2 행: 부모 동일(71204), 이름 다름 -> 이름변경
   3~4 행: 이름 동일, 부모 다름(71204 -> 90118) -> 이동

4. 부모 엔트리를 경로로 치환
   71204 -> .\Users\jhkim\Documents\work
   90118 -> .\Users\jhkim\Pictures\2026-03

5. 임시 파일 패턴이 아닌지 확인
   - 이름에 ~$ / .tmp / .crdownload 없음
   - 두 rename 간격 2 분 13 초 (자동 저장 패턴 아님)
   - 최종 확장자가 원래와 다름(.xlsx -> .jpg) 이고 되돌아오지 않음
   -> 위장 의도 확정

6. 교차검증 — 원래 이름이 다른 곳에도 있는가
   (a) 브라우저 다운로드
       sqlite3 History "SELECT target_path, datetime(start_time/1000000-11644473600,
                        'unixepoch') FROM downloads;"
       -> C:\Users\jhkim\Downloads\고객명단_2026.xlsx | 2026-03-14 07:12:33
   (b) RecentDocs
       HKCU\...\Explorer\RecentDocs\.xlsx -> 고객명단_2026.xlsx
   (c) LNK
       Recent\고객명단_2026.lnk -> LocalPath: C:\Users\jhkim\Documents\work\고객명단_2026.xlsx
       (현재 그 경로에 그 파일은 없다. LNK 가 갱신되지 않은 것 자체가 증거)
   세 출처가 원래 이름을 독립적으로 뒷받침한다.

7. 시간대 변환
   이름변경 2026-03-14 07:41:09 UTC + 9h = 2026-03-14 16:41:09 KST

8. 이후 행방 (부가)
   07:51:07 UTC  E:\ 로 복사 ($J of E: + USBSTOR)

정답: 원래 이름 = 고객명단_2026.xlsx
      이름변경 시각 = 2026-03-14 16:41:09 KST (07:41:09 UTC)
      경로: Documents\work -> Pictures\2026-03 (16:43:22 KST 이동)
```

2→3단계가 이 글의 요지다. **`$MFT`에 원래 이름을 찾는 것은 구조적으로 불가능하다.** 그 30분은 "어느 artifact가 어떤 정보를 보관하는가"를 몰라서 잃은 시간이고, `$J`의 RENAME 쌍 한 번의 조회로 답이 나왔다. 6단계처럼 LNK·RecentDocs·브라우저로 보강하면 `$J`가 없는 문제에서도 같은 답에 도달할 수 있다.

## 막혔을 때 다음 체크

1. `$Extend\$UsnJrnl`을 `$J` 스트림까지 추출했는가 (ADS이므로 스트림 지정이 필요하다 — [FOR-0035](./alternate-data-streams.html))
2. `UpdateReasons`에서 `RenameOldName` **행**을 별도로 뽑았는가
3. `EntryNumber` + `SequenceNumber`로 같은 파일임을 확인했는가
4. `ParentEntryNumber`를 비교해 이동/이름변경을 구분했는가
5. `ParentEntryNumber`를 `$MFT` CSV로 실제 경로로 치환했는가
6. 임시 파일 경유 패턴을 제외했는가 (`~$`, `.tmp`, `.crdownload`, 1초 이내 왕복)
7. 같은 파일의 rename이 **여러 번** 있는지 전부 뽑았는가
8. `$J`가 잘렸다면 `$LogFile`(NTFS Log Tracker)을 봤는가
9. LNK / Jump List / RecentDocs / ComDlg32 MRU를 파싱했는가
10. 브라우저 `downloads`의 `target_path`/`current_path`를 봤는가
11. 실행 파일이라면 Prefetch의 `.pf` 이름과 내부 참조 목록을 봤는가
12. 삭제되었다면 `$Recycle.Bin`의 `$I`에서 원래 경로를 확인했는가
13. 폴더 이름변경이라면 Shellbags를 봤는가
14. 다른 볼륨으로의 이동이라면 **양쪽 볼륨의 `$J`**를 모두 파싱했는가
15. 시각을 전부 UTC로 정규화하고 답만 KST로 변환했는가

## 출처

- SRC-013 — Microsoft Learn, Change Journals: `USN_REASON_RENAME_OLD_NAME`(`0x00001000`)/`USN_REASON_RENAME_NEW_NAME`(`0x00002000`)의 의미와 값, `FILE_CREATE`/`FILE_DELETE`/`BASIC_INFO_CHANGE`/`CLOSE` 플래그, USN 레코드가 파일 참조 번호·부모 참조 번호·이름·시각을 담는다는 구조
- SRC-005 — Microsoft Learn, Master File Table: `$FILE_NAME`(`0x30`) 속성이 현재 이름과 부모 참조 번호를 보관한다는 구조. `$MFT`가 이름 이력을 보존하지 않는 이유
- SRC-029 — Libyal liblnk, Windows Shortcut File (LNK) 포맷: LNK가 생성 시점의 대상 경로(LocalBasePath), 파일 크기, 대상 MAC 시각, 볼륨 시리얼을 복사해 저장한다는 구조. Jump List 내부의 LNK 스트림
- `MFTECmd`의 `$J` CSV 컬럼 이름(`UpdateReasons`, `UpdateTimestamp`, `ParentEntryNumber` 등)과 Reason 플래그 표기 문자열(`RenameOldName` 등)은 버전에 따라 다를 수 있으므로 실제 CSV 헤더에서 확인할 것
- `$LogFile`의 인덱스 엔트리 추가/삭제 오퍼레이션 명칭은 파서(NTFS Log Tracker 등)마다 표기가 다르므로 도구 출력의 라벨을 그대로 확인할 것
- Chrome `downloads` 테이블의 컬럼 구성은 Chromium 버전에 따라 달라질 수 있으므로 `PRAGMA table_info(downloads);`로 확인할 것
- 이름변경/이동이 `$FILE_NAME` 타임스탬프에 미치는 영향은 Windows 버전과 작업 방식에 따라 다르므로, 대상 이미지에서 직접 비교해 확인할 것
- `MFTECmd`·`LECmd`·`JLECmd`·`Timeline Explorer`는 `tools/manifest.json`에 등재되어 있지 않다. 등재된 도구로는 `analyzeMFT`, `NTFS Log Tracker`, `RegistryExplorer`, `WinPrefetchView`, Autopsy로 대체할 수 있다
