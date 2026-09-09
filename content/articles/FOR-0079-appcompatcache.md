---
id: FOR-0079
title: "AppCompatCache(Shimcache)와 Amcache: 실행 파일 캐시 두 개 정리"
slug: "appcompatcache"
category: "Registry"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["AppCompatCache", "Shimcache", "Amcache", "InventoryApplicationFile", "InventoryApplication", "InventoryDriverBinary", "Session Manager"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve.LOG1", "C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf"]
registry_paths: ["SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatCache", "SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCompatibility", "Amcache.hve\\Root\\InventoryApplicationFile", "Amcache.hve\\Root\\InventoryApplication", "Amcache.hve\\Root\\InventoryDriverBinary", "Amcache.hve\\Root\\File"]
event_ids: []
protocols: []
tools: ["AppCompatCacheParser", "AmcacheParser", "RegistryExplorer", "RegRipper", "rla", "Timeline Explorer", "HxD"]
commands: ["AppCompatCacheParser.exe -f C:\\case\\SYSTEM --csv C:\\case\\out", "AmcacheParser.exe -f C:\\case\\Amcache.hve -i --csv C:\\case\\out", "rip.exe -r SYSTEM -p appcompatcache"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed", "Duplicate", "FileId", "LowerCaseLongPath", "LinkDate", "Size", "ProductName", "Publisher", "BinFileVersion", "BinaryType", "ProgramId"]
file_formats: ["regf", "hve"]
primary_terms: ["AppCompatCache", "Shimcache", "Amcache", "실행 파일 캐시"]
keywords: ["AppCompatCache", "Shimcache", "Amcache", "Amcache.hve", "InventoryApplicationFile", "FileId", "SHA-1", "LinkDate", "AppCompatCacheParser", "AmcacheParser", "실행 파일 캐시", "존재 증거"]
aliases: ["shimcache", "appcompatcache", "amcache", "실행 파일 캐시", "shimcache 실행 증거", "amcache 해시", "appcompatcacheparser"]
symptom_keywords: ["Shimcache가 실행 증거인지 모르겠다", "Shimcache 시각이 무슨 시각인지", "Amcache에서 해시를 얻고 싶다", "삭제된 실행 파일의 흔적을 찾고 싶다", "라이브 시스템에 최신 항목이 없다", "Executed 컬럼이 NA다"]
related: ["FOR-0076", "FOR-0051", "FOR-0053", "FOR-0024"]
source_ids: ["SRC-031", "SRC-017", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Shimcache(`AppCompatCache`)와 Amcache는 둘 다 **"그 경로에 그 실행 파일이 있었다"의 증거이고 실행을 보장하지 않는다** — Shimcache는 경로 + 파일 수정 시각을 종료 시점에 레지스트리에 기록하고, Amcache는 경로 + SHA-1 + 크기 + 버전 정보를 예약 작업이 목록화하므로, 삭제된 실행 파일을 추적하는 데 쓰고 실행 시각은 다른 artifact에서 가져온다.

## 개념

| 구분 | Shimcache (AppCompatCache) | Amcache |
| --- | --- | --- |
| 무엇을 위한 것인가 | 애플리케이션 호환성(shim) 적용 여부를 빨리 판단하기 위한 커널 캐시 | 설치·실행된 프로그램의 인벤토리 수집 |
| 기록 주체 | 커널의 shim 엔진 | Microsoft Compatibility Appraiser 예약 작업 |
| 저장 위치 | `SYSTEM` hive의 이진 값 하나 | 별도 hive 파일 `Amcache.hve` |
| 기록 시점 | 캐시는 메모리에 있고 **시스템 종료 시 디스크에 기록** | 예약 작업 실행 시(주기적) |
| 실행 보장 | **없음** | **없음** |
| 해시 | 없음 | **SHA-1 있음** |
| 사용자 특정 | 불가 | 불가 |
| 시각의 의미 | 파일의 `$SI` 수정 시각 | 키 LastWrite = 목록화 시각, `LinkDate` = PE 컴파일 시각 |

**"라이브 시스템에서는 최신 항목이 없을 수 있다"**는 Shimcache의 성질이 실무에서 가장 자주 문제가 된다. 캐시가 메모리에 있다가 종료 시 기록되므로, 전원을 켠 상태로 hive를 `reg save`하면 **그 부팅 세션의 실행 파일이 빠진다.** 라이브 대응에서는 메모리 덤프를 함께 확보한다.

### 순서의 의미

Shimcache 엔트리는 **대략 최근순**으로 배열된다. `CacheEntryPosition`이 작을수록 최근에 삽입된 항목이다. 다만 삽입 규칙이 버전마다 다르고 중복 처리·재배치가 일어나므로 **위치를 절대 시각처럼 쓰지 않는다.** "이 항목이 저 항목보다 나중에 캐시에 들어왔을 가능성이 높다"까지만 말한다.

## 파일 / 경로

### Shimcache

```text
SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache
  AppCompatCache = (REG_BINARY)      <- 전체 캐시가 이 값 하나 안에 들어 있다

(XP 계열 레거시)
SYSTEM\ControlSet001\Control\Session Manager\AppCompatibility
  AppCompatCache = (REG_BINARY)
```

| 주의 | 내용 |
| --- | --- |
| ControlSet | `ControlSet001`과 `ControlSet002`에 **각각 다른 캐시**가 있다. 둘 다 파싱한다 ([FOR-0053](./system-controlset.html)) |
| `CurrentControlSet` | 오프라인 hive에 없다. 실제 세트 번호로 들어간다 |
| 값이 하나 | 키 LastWrite는 캐시가 기록된 시각(대개 마지막 종료 시각)이다. 개별 엔트리 시각이 아니다 |
| 엔트리 상한 | 버전에 따라 다르다(XP 96개, 이후 대략 1024개). 넘으면 오래된 것이 밀려 나간다 |

이진 값의 선두에 버전 서명이 있고 파서가 이것으로 구조를 판정한다.

| 서명 값 | 대응 계열 |
| --- | --- |
| `0xDEADBEEF` | Windows XP |
| `0xBADC0FEE` | Windows 7 / 2008 R2 계열 |
| `0x00000080` | Windows 8 / 8.1 계열 |
| `0x00000030` / `0x00000034` | Windows 10 계열 (빌드에 따라 다름) |

**이 표는 파서가 무엇을 보고 판단하는지 이해하기 위한 것이다.** 엔트리 내부의 바이트 오프셋은 버전마다 다르므로 수동 파싱하지 않는다.

### Amcache

```text
C:\Windows\AppCompat\Programs\Amcache.hve        <- regf 형식. RegistryExplorer 로 그냥 열린다
C:\Windows\AppCompat\Programs\Amcache.hve.LOG1
C:\Windows\AppCompat\Programs\Amcache.hve.LOG2
C:\Windows\AppCompat\Programs\RecentFileCache.bcf   <- Win7 초기의 전신. 형식이 다르다
```

| 주요 키 | 무엇이 들어 있나 |
| --- | --- |
| `Root\InventoryApplicationFile` | **실행 파일 단위 인벤토리.** 경로·SHA-1·크기·버전. 가장 많이 쓴다 |
| `Root\InventoryApplication` | 설치된 프로그램 단위. 이름·게시자·설치 시각·설치 경로 |
| `Root\InventoryApplicationShortcut` | 바로가기 인벤토리 |
| `Root\InventoryDriverBinary` | **드라이버 파일** 인벤토리. 서명 여부 포함. 루트킷 조사에 유용 |
| `Root\InventoryDeviceContainer` | 장치 컨테이너 |
| `Root\File\{볼륨GUID}\...` | **Win8/8.1 시절의 구조.** 값 이름이 숫자·16진 문자라 사람이 읽을 수 없다 |

`Root\File` 형식이 나오면 값 이름 대응을 추측하지 않고 **AmcacheParser에 맡긴다.** 이 글은 그 구조의 필드 대응을 단정하지 않는다.

## 주요 필드

### Shimcache — AppCompatCacheParser 출력

| 컬럼 | 의미 | 해석 주의 |
| --- | --- | --- |
| `ControlSet` | 어느 ControlSet에서 나온 항목인가 | 001/002를 구분해 기록 |
| `CacheEntryPosition` | 캐시 안의 위치 (0이 최근) | 대략적 순서. 시각 대체물이 아니다 |
| `Path` | 실행 파일 경로 | `\??\C:\...` 형태로 나올 수 있다 |
| `LastModifiedTimeUTC` | **파일의 `$SI` 수정 시각** (FILETIME, UTC) | **실행 시각이 아니다.** `$MFT`와 대조하면 타임스탬프 조작이 보인다 ([FOR-0024](./si-vs-fn-timestamps.html)) |
| `Executed` | 실행 플래그 해석 결과 | Win7 계열까지의 삽입 플래그에서 유래. **Win10 계열은 플래그가 없어 의미 없는 값(`NA`)이 된다** |
| `Duplicate` | 두 ControlSet에 중복 등장하는가 | 중복 제거용 |
| `SourceFile` | 파싱 대상 hive | 여러 이미지를 다룰 때 필수 |

`Executed`가 `NA`이거나 비어 있으면 **그 OS 버전에는 실행 여부 정보가 아예 없다는 뜻**이다. "실행되지 않았다"가 아니다.

### Amcache — `InventoryApplicationFile` 하위 값

| 값 이름 | 내용 | 활용 |
| --- | --- | --- |
| `FileId` | **`0000` 4자리 + SHA-1 40자리 = 44자 문자열** | 앞 4자리를 떼면 그대로 SHA-1이다. 해시 대조의 핵심 |
| `LowerCaseLongPath` | 소문자로 정규화된 전체 경로 | 경로 검색은 소문자로 한다 |
| `Name` | 파일 이름 | — |
| `Size` | 파일 크기 (바이트) | 카빙 결과와 대조 |
| `LinkDate` | **PE 헤더의 컴파일 시각** | 실행·설치 시각이 아니다. **조작 가능** |
| `BinaryType` | `pe32` / `pe64` | 비트수 |
| `ProductName` / `ProductVersion` | 제품명·제품 버전 | 도구 식별 |
| `Publisher` | 게시자 문자열 | 서명 주체가 아니다. 리소스 문자열이다 |
| `BinFileVersion` / `BinProductVersion` | 바이너리 파일/제품 버전 | 동일 도구의 버전 구분 |
| `ProgramId` | `InventoryApplication`의 키와 연결되는 식별자 | 설치 프로그램과 파일을 잇는다 |
| `IsPeFile` / `IsOsComponent` | PE 여부 / OS 구성요소 여부 | OS 파일 노이즈 제거 |
| 키의 LastWrite | **Appraiser가 이 항목을 기록한 시각** | 실행 시각이 아니다 |

**`FileId`에서 앞 4개의 `0`을 떼면 SHA-1이다.** 이것이 Amcache의 가장 큰 가치다 — 실행 파일이 이미 삭제되어도 해시가 남아 다른 이미지·다른 사건과 대조할 수 있다.

### 두 artifact 비교표 (결론용)

| 질문 | Shimcache | Amcache |
| --- | --- | --- |
| 그 파일이 그 경로에 있었나 | **예** | **예** |
| 실행됐나 | 보장 안 됨 | 보장 안 됨 |
| 언제 실행됐나 | 알 수 없음 | 알 수 없음 |
| 파일의 수정 시각 | **있음** (`LastModifiedTimeUTC`) | 없음 (`LinkDate`는 컴파일 시각) |
| 해시 | 없음 | **SHA-1** |
| 크기 | 버전에 따라 일부 | **있음** |
| 삭제된 파일도 남나 | **남는다** | **남는다** |
| 사용자 특정 | 불가 | 불가 |
| 최신 항목 누락 위험 | **높음** (종료 시 기록) | 낮음 (주기 작업) |
| 엔트리 상한 | 있음 | 사실상 넉넉함 |

## 빠른 명령

```powershell
AppCompatCacheParser.exe -f "C:\case\SYSTEM" --csv "C:\case\out" --csvf shimcache.csv
```

```powershell
# 두 ControlSet 을 모두 뽑고, 중복도 남긴다
AppCompatCacheParser.exe -f "C:\case\SYSTEM" -c 1 --csv "C:\case\out" --csvf shim_cs1.csv
AppCompatCacheParser.exe -f "C:\case\SYSTEM" -c 2 --csv "C:\case\out" --csvf shim_cs2.csv
```

```powershell
# Amcache — -i 로 프로그램에 연결되지 않은 파일 항목까지 포함
AmcacheParser.exe -f "C:\case\Amcache.hve" -i --csv "C:\case\out"
```

```powershell
# 키트 안 도구만으로 갈 때
rip.exe -r "C:\case\SYSTEM" -p appcompatcache > shimcache.txt
rip.exe -r "C:\case\Amcache.hve" -p amcache > amcache.txt
```

```powershell
# Amcache.hve 도 트랜잭션 로그를 반영한다
rla.exe -f "C:\case\Amcache.hve" --out "C:\case\clean"
```

### 출력 예시

```text
AppCompatCacheParser 출력 (shimcache.csv)

ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate
1,0,C:\Users\hjlee\Downloads\dump_tool.exe,2026-04-07 02:11:09,NA,False
1,1,C:\Windows\System32\cmd.exe,2025-11-02 12:00:31,NA,False
1,2,C:\Users\hjlee\AppData\Local\Temp\7zS8A1\setup.exe,2026-04-06 22:41:55,NA,False
```

```text
AmcacheParser 출력 (*_AssociatedFileEntries.csv 일부)

FullPath                                       SHA1                                      FileSize  LinkDate
c:\users\hjlee\downloads\dump_tool.exe         3a1f9c...(40자)                            284160    2021-06-15 09:00:00
c:\windows\system32\cmd.exe                    b9f4a2...(40자)                            289792    2025-10-30 07:12:44
```

```powershell
# 관심 이름으로 두 CSV 를 동시에 훑는다
$t = 'dump_tool'
Import-Csv "C:\case\out\shimcache.csv" | Where-Object { $_.Path -match $t } |
  Format-Table ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC, Executed
Get-ChildItem "C:\case\out\*AssociatedFileEntries.csv" | ForEach-Object {
  Import-Csv $_.FullName | Where-Object { $_.FullPath -match $t } |
    Format-Table FullPath, SHA1, FileSize, LinkDate
}
```

## 함께 보는 artifact

| 이 글에서 얻은 것 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 실행 파일 경로 | Prefetch, UserAssist, BAM, 4688 | **실행 여부와 시각** ([FOR-0076](./recent-execution-crosscheck.html)) |
| `LastModifiedTimeUTC` | `$MFT`의 `$SI`/`$FN` ([FOR-0021](./mft-basics.html)) | 두 값이 다르면 파일이 교체됐거나 타임스탬프 조작 |
| SHA-1 (`FileId`) | 다른 이미지의 Amcache, 위협 인텔 | 같은 도구가 쓰인 다른 지점 |
| 삭제된 실행 파일 경로 | `$UsnJrnl`, `$Recycle.Bin` | 언제 어떻게 사라졌는가 |
| `ProgramId` | `Root\InventoryApplication` | 설치 프로그램 이름·설치 시각·설치 경로 |
| 드라이버 경로 | `Root\InventoryDriverBinary`, `Services` | 서명되지 않은 드라이버·악성 서비스 |
| `Temp`/`AppData` 경로 항목 | 브라우저 다운로드, 메일 첨부 | 유입 경로 |
| 캐시 기록 시각(키 LastWrite) | 마지막 종료 시각 | Shimcache가 어느 시점까지를 담고 있는가 |

## 흔한 실수

- **Shimcache 항목을 실행 증거로 제시하는 것** → shim 엔진은 파일을 **검사**할 때도 엔트리를 만든다 → "그 경로에 그 파일이 있었다"까지만 주장하고 실행은 Prefetch·UserAssist·BAM·4688으로 확증한다.
- **`LastModifiedTimeUTC`를 실행 시각으로 읽는 것** → 그것은 파일의 `$SI` 수정 시각이다 → 실행 시각은 다른 artifact에서 가져오고, 이 값은 `$MFT`와 대조해 파일 교체·조작을 본다.
- **`Executed`가 `NA`인 것을 "실행되지 않음"으로 읽는 것** → Win10 계열 엔트리에는 실행 플래그가 없다 → `NA`는 정보 없음이다.
- **라이브 시스템에서 `reg save`한 `SYSTEM`으로 최신 실행을 찾는 것** → 캐시는 종료 시 기록되므로 현재 부팅 세션의 항목이 빠진다 → 메모리 덤프를 함께 확보하거나 정상 종료 후 이미지를 쓴다.
- **`ControlSet001`만 파싱하는 것** → 세트마다 캐시가 다르다 → `-c 1`, `-c 2`를 각각 돌려 합집합을 본다.
- **`CacheEntryPosition`을 시각처럼 정렬해 타임라인을 만드는 것** → 삽입 규칙이 버전마다 다르고 재배치가 일어난다 → 순서는 참고용이며 절대 시각으로 쓰지 않는다.
- **Amcache의 키 LastWrite를 실행/설치 시각으로 쓰는 것** → Appraiser가 목록화한 시각이다 → 설치 시각은 `InventoryApplication`의 `InstallDate`나 `Uninstall` 키를 본다.
- **`LinkDate`를 다운로드·실행 시각으로 쓰는 것** → PE 컴파일 타임스탬프이고 조작 가능하다 → 동일 바이너리 식별용으로만 쓴다.
- **`FileId`를 그대로 SHA-1로 대조하는 것** → 앞에 `0000` 4자리가 붙어 있다 → 4자리를 떼고 대조한다.
- **`Amcache.hve`의 트랜잭션 로그를 반영하지 않는 것** → 다른 hive와 똑같이 `.LOG1`/`.LOG2`가 있다 → `rla`를 거친다.
- **`Publisher`를 디지털 서명 주체로 읽는 것** → PE 리소스의 문자열이다 → 서명 검증은 별도로 한다.
- **Amcache에 있으면 실행됐다고 단정하는 것** → 압축을 풀어 놓기만 한 파일도 인벤토리에 들어간다 → 존재 증거로만 쓴다.

## mini example

```text
문제:
"공격자가 사용한 도구의 SHA-1 해시와, 그 파일이 있던 경로를 구하시오.
 도구 파일 자체는 이미 삭제되었습니다.
 첨부: SYSTEM(+LOG1/2), Amcache.hve(+LOG1/2), $MFT 파싱 CSV, Prefetch 폴더"

1. 첫 시도 (실패):
   AppCompatCacheParser.exe -f SYSTEM --csv out\ --csvf shim.csv
   -> 1,0,C:\Users\hjlee\AppData\Local\Temp\pw.exe,2026-04-08 13:55:02,NA,False

   "Shimcache 에 2026-04-08 13:55:02 로 나오니 그때 실행했고, 해시는 Shimcache 에서
    구한다"고 적으려 했다. 두 가지가 동시에 틀렸다.

   왜 틀렸나:
   (1) Shimcache 에는 해시가 없다. 해시는 Amcache 의 FileId 다.
   (2) 그 시각은 파일의 $SI 수정 시각이다. 실행 시각이 아니다.

2. 접근 변경 — Amcache 에서 해시를 얻는다
   rla.exe -f Amcache.hve --out clean\
   AmcacheParser.exe -f clean\Amcache.hve -i --csv out\
   -> *_AssociatedFileEntries.csv
      FullPath  c:\users\hjlee\appdata\local\temp\pw.exe
      SHA1      0000da39a3ee5e6b4b0d3255bfef95601890afd80709
      FileSize  1204224
      LinkDate  2019-03-04 11:22:33

3. 두 번째로 틀린 판단:
   SHA1 컬럼 값을 그대로 해시로 적었다.
   -> 44자다. FileId 형식은 "0000" + SHA-1(40자) 이므로 앞 4자리를 떼야 한다.
      정답 해시: da39a3ee5e6b4b0d3255bfef95601890afd80709
   (파서 버전에 따라 이미 떼고 출력하는 경우도 있으므로 길이를 세어 확인한다)

4. 세 번째로 틀린 판단:
   LinkDate 2019-03-04 를 "파일이 만들어진 시각"으로 적었다.
   -> PE 컴파일 시각이다. $MFT 의 pw.exe 엔트리를 보니
      $SI Created 2026-04-08 13:55:02, $FN Created 2026-04-08 13:55:02
      => 디스크에 생긴 시각은 2026-04-08 13:55:02Z 다.
      Shimcache 의 LastModifiedTimeUTC 와 일치하므로 타임스탬프 조작 신호는 없다.

5. 실행 여부는 별도로 확증
   Prefetch: PW.EXE-3F2A1B9C.pf  RunCount 2  LastRun 2026-04-08 14:07:19Z
   -> 실행 확정. 실행 시각은 Prefetch 에서 나왔다.
      Shimcache/Amcache 는 "존재"의 증거로만 인용한다.

6. ControlSet 확인
   AppCompatCacheParser.exe -f SYSTEM -c 2 --csv out\ --csvf shim_cs2.csv
   -> ControlSet002 에는 pw.exe 항목이 없다. 001 에만 있다.
      두 세트를 모두 확인했음을 기록한다.

7. 시간대 보정
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time  (ActiveTimeBias -540분)
   2026-04-08 14:07:19Z -> 2026-04-08 23:07:19 KST

정답:
  경로  C:\Users\hjlee\AppData\Local\Temp\pw.exe
  SHA-1 da39a3ee5e6b4b0d3255bfef95601890afd80709  (FileId 앞 0000 제거)
  파일 생성 2026-04-08 22:55:02 KST / 실행 2026-04-08 23:07:19 KST (근거: Prefetch)
  Shimcache·Amcache 는 파일의 존재·경로·해시 증거로만 인용
```

## 출처

- SRC-031 — Microsoft Learn, Application Compatibility / Shim infrastructure: shim 엔진이 실행 파일을 검사하며 캐시를 채운다는 점, 즉 **AppCompatCache 항목의 계기가 실행이 아니라 호환성 검사일 수 있다**는 판단의 근거
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM` hive의 `Control\Session Manager` 위치, `Amcache.hve`가 별도 hive 파일이라는 점
- SRC-004 — Eric Zimmerman 문서: AppCompatCacheParser·AmcacheParser의 옵션과 CSV 컬럼(`CacheEntryPosition`, `LastModifiedTimeUTC`, `Executed`, `Duplicate`, `FileId`/SHA-1, `LinkDate` 등), `rla`의 로그 반영
- **이진 값 안의 엔트리 구조와 바이트 오프셋은 OS 버전마다 다르므로 이 글은 단정하지 않고 파서에 맡긴다.** 버전 서명 값 표(`0xDEADBEEF`/`0xBADC0FEE`/`0x00000080`/`0x00000030`·`0x00000034`)는 파서가 무엇으로 버전을 판정하는지 이해하기 위한 것이며, 빌드에 따라 다른 값이 나올 수 있으므로 수동 판정에 쓰지 말 것
- **엔트리 개수 상한(XP 96개, 이후 대략 1024개)과 Win7 계열 삽입 플래그의 실행 의미는 환경·버전에 따라 다르고 신뢰도가 낮다는 보고가 있으므로, `Executed` 컬럼을 단독 근거로 쓰지 않을 것**
- **`Root\File\{볼륨GUID}` 형식(Win8/8.1 계열)의 숫자 값 이름 대응은 이 글에서 단정하지 않는다.** AmcacheParser의 출력을 쓸 것
- 파서의 출력 파일 이름(`*_AssociatedFileEntries.csv` 등)과 `FileId`의 앞 `0000` 처리 여부는 도구 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
- mini example의 해시·시각·경로는 설명을 위한 예시 값이다
