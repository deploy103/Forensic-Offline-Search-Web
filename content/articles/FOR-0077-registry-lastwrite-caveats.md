---
id: FOR-0077
title: "Registry LastWrite 시각을 믿으면 안 되는 7가지 경우"
slug: "registry-lastwrite-caveats"
category: "Registry"
type: "troubleshooting"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["LastWrite", "nk record", "vk record", "MRUListEx", "트랜잭션 로그", "regf"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE", "C:\\Users\\<user>\\NTUSER.DAT", "C:\\Users\\<user>\\NTUSER.DAT.LOG1"]
registry_paths: ["NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", "SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings", "NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLsTime", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", "SAM\\Domains\\Account\\Users"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "RegRipper", "rla", "DCode", "Timeline Explorer", "HxD"]
commands: ["rla.exe -d C:\\case\\config --out C:\\case\\clean", "xxd -l 16 SYSTEM", "rip.exe -r NTUSER.DAT -p userassist"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["LastWrite", "primary sequence number", "secondary sequence number", "MRUListEx", "Last Executed"]
file_formats: ["regf"]
primary_terms: ["LastWrite", "레지스트리 시각 주의점", "키 마지막 쓰기 시각"]
keywords: ["LastWrite", "레지스트리 시각", "키 마지막 쓰기", "MRU", "트랜잭션 로그", "시각 불일치", "FILETIME", "값 시각 없음", "일괄 갱신", "시스템 시각 조작"]
aliases: ["lastwrite 신뢰", "레지스트리 시각 이상", "키 시각 안 맞음", "레지스트리 시간 틀림", "값 시각 어디", "mru 시각"]
symptom_keywords: ["레지스트리 시각이 다른 artifact와 안 맞는다", "값이 언제 만들어졌는지 모르겠다", "여러 키의 시각이 똑같다", "LastWrite가 너무 과거다", "MRU 시각이 하나뿐이다", "시각으로 결론을 못 내겠다"]
related: ["FOR-0051", "FOR-0054", "FOR-0078", "FOR-0076"]
source_ids: ["SRC-027", "SRC-014", "SRC-017"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

레지스트리 LastWrite는 **키 단위 시각이고 값 단위 시각은 존재하지 않는다** — 값 10개인 키에서 어느 값이 언제 바뀌었는지 알 수 없으므로, 시각을 근거로 쓸 때는 값 데이터 안에 자체 FILETIME을 담은 키(UserAssist `0x3C`, BAM 앞 8바이트, `TypedURLsTime`, NetworkList)를 우선한다.

## 증상

- 레지스트리 LastWrite로 "이 프로그램을 이때 실행했다"고 결론 냈는데 Prefetch·EVTX와 몇 시간에서 며칠까지 어긋난다
- 한 키의 LastWrite가 그 키에 있는 값 여러 개 중 무엇의 시각인지 설명할 수 없다
- `RecentDocs`·`TypedPaths` 같은 MRU 키의 시각이 **하나뿐**인데 문제는 항목별 시각을 요구한다
- 수십 개 키의 LastWrite가 **초 단위로 동일**하다
- LastWrite가 OS 설치 시각이나 마지막 부팅 시각과 같다
- LastWrite가 사건 시각보다 훨씬 **과거**다 (최신 변경이 보이지 않는다)
- 같은 키인데 도구마다 다른 시각을 보여 준다

## 가장 가능성 높은 원인

**확률 높은 순.** 위에서부터 배제하면 대부분 3번 안에 끝난다.

| 순위 | 원인 | 어떤 증상으로 보이나 | 결정적 판별점 |
| --- | --- | --- | --- |
| 1 | **LastWrite는 키 단위이고 값 단위 시각은 없다** | "어느 값의 시각인지" 답할 수 없다 | 그 키의 값 개수가 2개 이상이다 |
| 2 | **값 하나만 바뀌어도 키 전체 시각이 갱신된다** | 관심 없는 값 때문에 시각이 최신이다 | 키 안에 자주 바뀌는 값(카운터·플래그)이 섞여 있다 |
| 3 | **MRU 키는 항목 추가마다 갱신된다** | 시각이 1개뿐이고 최신 항목만 설명된다 | 키에 `MRUListEx`나 `MRUList`가 있다 |
| 4 | **하이브 로드/언로드, 무관한 값 변경으로 갱신** | 로그온·로그오프·종료 시각과 일치한다 | 시각이 부팅/로그온/종료 시각과 같다 |
| 5 | **트랜잭션 로그 미반영** | LastWrite가 과거이고 최신 항목이 없다 | 헤더의 primary ≠ secondary sequence number (dirty) |
| 6 | **정책 적용·업데이트로 일괄 갱신** | 수십~수백 키가 동일 시각 | 같은 시각을 가진 키가 무리를 이룬다 |
| 7 | **시스템 시각 자체가 조작됨** | 순서가 역전되거나 미래 시각이 나온다 | 다른 artifact와 **일관되게** 어긋난다 |

**1·2·3은 구조적 한계**여서 없앨 수 없고, **4·5·6은 확인해서 배제**할 수 있으며, **7은 별도 조사 대상**이다.

## 1차 확인

### ① 그 키의 값이 몇 개인지 센다 (원인 1·2)

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xlsx"
```

오프라인 hive라면 RegistryExplorer로 키를 선택하고 **우측 상단 값 목록의 개수**를 센다.

| 관측 | 판정 | 어떻게 쓰나 |
| --- | --- | --- |
| 값이 1개 | LastWrite ≈ 그 값의 시각 | 시각 근거로 쓸 수 있다. 예: `USBSTOR` 인스턴스 키 |
| 값이 2개 이상 | **어느 값의 시각인지 알 수 없다** | "그 키에서 마지막으로 어떤 변경이 있었다"까지만 주장 |
| 값 데이터에 자체 FILETIME이 있다 | **그쪽을 쓴다** | 아래 "다른 방법" 표 참조 |

레지스트리 포맷에서 시각은 키 레코드(`nk`)에만 있고 값 레코드(`vk`)에는 필드 자체가 없다. **도구가 값 시각을 보여 주지 않는 것은 도구의 한계가 아니라 포맷의 사실이다.**

### ② `MRUListEx`가 있는지 본다 (원인 3)

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xlsx
  MRUListEx = 03 00 00 00  01 00 00 00  00 00 00 00  FF FF FF FF
  0 = (항목)   1 = (항목)   3 = (항목)
  LastWrite  2026-04-09 08:11:03Z
```

`MRUListEx`의 첫 4바이트 인덱스가 **가장 최근 항목**이다. 그러므로 이 키의 LastWrite는 **`MRUListEx`의 첫 항목이 추가된 시각**이라고만 말할 수 있다. 나머지 항목의 시각은 이 키에 없다.

| 요구 | 가능한가 | 대안 |
| --- | --- | --- |
| 가장 최근 항목의 시각 | **가능** | 키 LastWrite |
| 2번째·3번째 항목의 시각 | 불가 | LNK/Jump List의 대상 파일 MACB, `$MFT`, `$UsnJrnl` |
| 항목의 추가 순서 | **가능** | `MRUListEx` 순서 |

### ③ hive가 dirty인지 본다 (원인 5)

```bash
xxd -l 16 SYSTEM
```

```text
00000000: 7265 6766 2900 0000 2800 0000 ....
                    ^primary=0x29   ^secondary=0x28   -> 다르다 = dirty
```

primary(`0x04`)와 secondary(`0x08`)가 다르면 최신 변경이 `.LOG1`/`.LOG2`에만 있다. 반영하지 않으면 **LastWrite가 과거로 보인다.**

```powershell
# config 폴더 전체를 한 번에 반영
rla.exe -d "C:\case\config" --out "C:\case\clean"
```

```powershell
# 사용자 hive 개별 반영
rla.exe -f "C:\case\NTUSER.DAT" --out "C:\case\clean"
```

반영 전후의 같은 키 LastWrite를 비교한다. **값이 달라지면 그 차이가 곧 놓칠 뻔한 활동이다.**

### ④ 일괄 갱신인지 본다 (원인 6)

같은 시각을 가진 키가 몇 개인지 세는 것이 판별법이다.

```powershell
# RegRipper 전체 플러그인 출력에서 LastWrite 시각의 빈도를 센다
rip.exe -r "C:\case\clean\SOFTWARE" -a > software_all.txt
Select-String -Path software_all.txt -Pattern '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}' |
  ForEach-Object { $_.Matches.Value } | Group-Object |
  Where-Object { $_.Count -gt 3 } | Sort-Object Count -Descending
```

| 관측 | 해석 |
| --- | --- |
| 한 시각에 키 수십 개 | 정책 적용·Windows 업데이트·프로그램 설치. **개별 행위의 시각이 아니다** |
| 한 시각에 키 2~3개 | 같은 프로그램이 관련 키를 함께 쓴 것. 정상 |
| 시각이 전부 흩어져 있다 | 일괄 갱신 아님. 개별 해석 가능 |
| 시각이 부팅/로그온/종료 시각과 같다 | 원인 4. hive 로드/언로드에 따른 갱신 |

## 2차 확인

### ⑤ 다른 artifact와 방향을 대조한다 (원인 7 판별)

시스템 시각 조작은 **레지스트리 하나만 어긋나는 것이 아니라 그 시각 이후의 모든 기록이 함께 어긋난다.**

| 대조 대상 | 무엇을 보나 | 조작 신호 |
| --- | --- | --- |
| `$MFT`·`$UsnJrnl` | hive 파일 자체의 수정 시각과 USN 번호 | USN 번호는 증가하는데 시각이 역행한다 |
| EVTX | 시각 변경 감사 이벤트, `EventRecordID` 순서 | 레코드 번호는 증가하는데 시각이 역행한다 ([FOR-0103](./event-record-id-tracking.html)) |
| Prefetch | 실행 시각 | 레지스트리와 일정한 오프셋만큼 차이난다 |
| 브라우저 히스토리 | 방문 시각 | 같은 방향으로 어긋난다 |

**단조 증가하는 카운터(USN, `EventRecordID`)와 시각의 순서가 어긋나면 시각 조작이다.** 레지스트리만 어긋나면 원인 1~6이다.

### ⑥ 값 데이터 안의 시각으로 갈아탄다

이것이 이 글의 결론이다. **키 LastWrite보다 값 안의 FILETIME이 항상 우선한다.**

| 키 | 값 안의 시각 | 형식 / 위치 |
| --- | --- | --- |
| `...\Explorer\UserAssist\{GUID}\Count` | **Last Executed** | 값 데이터 오프셋 `0x3C`의 8바이트 FILETIME (Win7 이후, 전체 72바이트) ([FOR-0061](./userassist.html)) |
| `SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID>` | **마지막 실행 시각** | 각 값 데이터 **앞 8바이트** FILETIME ([FOR-0071](./bam-dam.html)) |
| `...\Internet Explorer\TypedURLsTime` | URL 입력 시각 | `url1`, `url2`... 각각 8바이트 FILETIME ([FOR-0065](./typedurls.html)) |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` | `DateCreated` / `DateLastConnected` | 16바이트 SYSTEMTIME (연·월·요일·일·시·분·초·밀리초 각 2바이트) ([FOR-0072](./networklist.html)) |
| `SAM\Domains\Account\Users\<RID>` | 마지막 로그온·비밀번호 변경 등 | `F` 값 안의 FILETIME들 ([FOR-0052](./sam-user-accounts.html)) |
| `SOFTWARE\...\ProfileList\<SID>` | 프로필 로드/언로드 시각 | `...TimeHigh`/`...TimeLow` 두 DWORD를 합쳐 FILETIME (버전에 따라 존재) ([FOR-0074](./sid-user-mapping.html)) |
| `SYSTEM\ControlSet001\Enum\USBSTOR\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}` | 최초 설치·마지막 연결·마지막 제거 | 하위 `0064`/`0065`/`0066`/`0067` 키의 값에 FILETIME ([FOR-0066](./usbstor.html)) |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `InstallDate` | Unix epoch 초 (DWORD) |

| 시각 종류 | 기준 | KST 보정 |
| --- | --- | --- |
| FILETIME | 1601-01-01 UTC 기준 100ns | **UTC → +9시간** |
| Unix epoch | 1970-01-01 UTC 기준 초 | **UTC → +9시간**. FILETIME과 `11644473600`초 차이 |
| SYSTEMTIME (NetworkList) | 구조체에 연·월·일·시·분·초가 그대로 | **로컬 시각으로 기록되는 것이 통상**이므로 무조건 더하지 않고 다른 artifact와 대조해 확정 |
| DOS date/time (shell item) | 2초 단위 | **로컬 시각.** 더하지 않는다 ([FOR-0068](./shellbags.html)) |

**같은 표에 UTC와 로컬 시각을 섞어 쓰면 9시간짜리 오답이 나온다.** 컬럼마다 기준을 적는다 ([FOR-0054](./system-timezone.html)).

## 다른 방법

키 LastWrite로 답할 수 없을 때의 우회로다.

| 원래 알고 싶던 것 | LastWrite 대신 볼 것 |
| --- | --- |
| 이 값이 언제 만들어졌나 | 값 안의 FILETIME → 없으면 트랜잭션 로그(`.LOG1`)의 해당 레코드 → `$UsnJrnl`의 hive 파일 변경 시각 |
| 이 키가 언제 삭제됐나 | 부모 키 LastWrite + `$UsnJrnl`의 hive 변경 ([FOR-0078](./registry-deleted-keys.html)) |
| MRU 2번째 항목의 시각 | LNK·Jump List의 대상 MACB, `$MFT`, `$UsnJrnl` |
| 프로그램 실행 시각 | Prefetch·4688·BAM ([FOR-0076](./recent-execution-crosscheck.html)) |
| USB 연결 시각 | `USBSTOR`의 `0066`/`0067`, `setupapi.dev.log`, EVTX |
| 과거 시점의 값 | 볼륨 섀도 카피의 hive, `RegBack`, 메모리 덤프의 hive |
| 값 변경 이력 | 감사 정책이 켜져 있었다면 4657, Sysmon 12/13/14 |

시각 조작이 확인되면 **모든 시각을 상대 순서로만 다룬다.** 절대 시각 대신 "A가 B보다 먼저"만 주장하고, 단조 증가 카운터(USN, `EventRecordID`)로 순서를 세운다.

## 흔한 함정

- **키 LastWrite를 "값이 생성된 시각"으로 쓰는 것** → 키 단위 시각이고 값이 여러 개면 어느 것인지 알 수 없다 → 값 개수를 세고, 2개 이상이면 결론을 약화하거나 값 안의 FILETIME으로 갈아탄다.
- **MRU 키의 LastWrite를 모든 항목의 시각으로 쓰는 것** → 최신 항목이 추가된 시각 하나뿐이다 → 나머지 항목은 순서만 주장하고 시각은 다른 artifact에서 가져온다.
- **`rla` 없이 파싱하는 것** → dirty hive의 최신 변경이 로그에만 있어 LastWrite가 과거로 보인다 → 반영 전후를 비교한다.
- **하위 키가 바뀌면 부모 LastWrite도 갱신된다고 가정하는 것** → 손자 키의 값 변경은 조상 키 시각을 건드리지 않는다 → 관심 있는 키 자체의 시각을 본다.
- **동일 시각을 가진 키 무리를 개별 행위로 해석하는 것** → 정책 적용·업데이트·설치가 일괄 갱신한다 → 같은 시각의 키 개수를 세어 일괄 갱신을 먼저 배제한다.
- **LastWrite를 로컬 시각으로 읽는 것** → FILETIME이므로 항상 UTC다 → KST는 +9시간. NetworkList의 SYSTEMTIME과 shell item의 DOS 시각은 반대로 더하지 않는다.
- **도구가 다른 시각을 보여 줄 때 한쪽을 임의로 믿는 것** → 한쪽은 로그 반영 후, 다른 쪽은 반영 전 hive를 읽고 있을 수 있다 → 같은 파일(반영 후 hive)로 두 도구를 다시 돌린다.
- **시각 조작 가능성을 검토하지 않는 것** → 조작이 있으면 모든 절대 시각이 무효다 → USN·`EventRecordID` 같은 단조 카운터와 순서를 대조한다.
- **"LastWrite가 사건 시각과 같다"를 인과로 읽는 것** → 로그온·종료 때 hive가 일괄 갱신될 수 있다 → 부팅/로그온/종료 시각 목록과 대조해 배제한다.
- **hive 헤더의 시각(`0x0C`)을 키 시각으로 혼동하는 것** → 그것은 hive가 마지막으로 정리된 시각이다 → 키 시각과 별개로 취급한다 ([FOR-0051](./registry-hive-map.html)).

## 실제 예시

```text
문제:
"USB 연결 시각을 근거로 자료 반출 시점을 특정하시오.
 첨부: SYSTEM(+LOG1/2), SOFTWARE, NTUSER.DAT(+LOG1/2), Prefetch, Security.evtx"

1. 첫 시도 (실패):
   RegistryExplorer 로 SYSTEM 을 열고
   ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\
     4C530001231205117495&0
   -> 키 LastWrite 2026-03-02 01:44:07Z
   "2026-03-02 10:44 KST 에 USB 를 꽂았다"고 답을 적었다.

   그런데 Prefetch 와 4624 로그온 기록은 2026-04-08 저녁에 몰려 있고,
   그날 USB 관련 활동이 분명히 있었다. 한 달 넘게 어긋난다.

2. 원인 후보 배제 — 순서대로
   (원인 1·2) 그 인스턴스 키의 값 개수를 센다
     -> 값이 여러 개(FriendlyName, ContainerID, Capabilities 등).
        어느 값 때문에 갱신된 시각인지 알 수 없다. 이미 근거가 약하다.

   (원인 5) hive 가 dirty 인지 확인
     xxd -l 16 SYSTEM
     00000000: 7265 6766 3f01 0000 3e01 0000 ....
     primary 0x13f != secondary 0x13e  -> dirty 다.

3. 접근 변경 — 트랜잭션 로그 반영 후 재확인
   rla.exe -d config\ --out clean\
   clean\SYSTEM 의 같은 키 LastWrite -> 2026-04-08 14:01:58Z
   => 원인 5 였다. 반영 전 값은 한 달 전 상태였다.

4. 두 번째로 틀린 판단:
   "반영했으니 이제 LastWrite 가 연결 시각"이라고 결론 낼 뻔했다.
   -> 여전히 원인 1·2 가 살아 있다. 값이 여러 개인 키의 시각이다.
      값 안에 자체 FILETIME 이 있는 곳으로 갈아탄다:

      ...\4C530001231205117495&0\Properties\
        {83da6326-97a6-4088-9453-a1923f573b29}\0066   -> 마지막 연결(Arrival)
        {83da6326-97a6-4088-9453-a1923f573b29}\0067   -> 마지막 제거(Removal)
      0066 = 2026-04-08 14:01:58Z
      0067 = 2026-04-08 14:52:33Z
   => 연결과 제거 시각이 각각 확보됐다. 키 LastWrite 가 아니라 값이 근거다.

5. 일괄 갱신 배제 (원인 6)
   같은 시각(14:01:58Z)을 가진 키가 몇 개인지 센다 -> 3개(USBSTOR 인스턴스,
   DeviceClasses, MountedDevices 관련). 장치 연결 하나가 만든 무리로 설명된다.
   정책 일괄 갱신이 아니다.

6. 시각 조작 배제 (원인 7)
   Security.evtx 의 EventRecordID 는 단조 증가하고 시각도 증가한다.
   $UsnJrnl 의 USN 번호와 시각도 순서가 일치한다. 조작 신호 없음.

7. 교차검증
   Prefetch: EXPLORER.EXE 참조 목록에 E:\ 경로 등장
   4624:     2026-04-08 13:58:02Z 로컬 로그온 (연결 4분 전)
   ShellBags: E:\proj_backup 2026-04-08 14:02:19Z
   -> 연결 21초 뒤 폴더 탐색. 순서가 자연스럽다.

8. 시간대 보정 (마지막에 한 번)
   SYSTEM\ControlSet001\Control\TimeZoneInformation
     TimeZoneKeyName = Korea Standard Time, ActiveTimeBias = -540분
   2026-04-08 14:01:58Z -> 2026-04-08 23:01:58 KST
   2026-04-08 14:52:33Z -> 2026-04-08 23:52:33 KST

정답:
  USB 연결 2026-04-08 23:01:58 KST / 제거 23:52:33 KST
  근거는 인스턴스 키의 LastWrite 가 아니라 Properties 하위 값의 FILETIME.
  최초 답(2026-03-02)은 트랜잭션 로그 미반영 hive 를 읽은 결과였다.
```

2단계와 4단계가 이 글의 요점이다. **`rla`를 돌리면 끝난다고 생각하는 것이 두 번째 함정이다** — 로그를 반영해도 "키 단위 시각"이라는 한계는 그대로 남는다.

## 막혔을 때 다음 체크

1. 그 키의 **값 개수**를 셌는가 — 2개 이상이면 시각의 귀속이 불가능하다
2. 값 데이터 안에 자체 FILETIME이 있는 키인가 — UserAssist `0x3C`, BAM 앞 8바이트, `TypedURLsTime`, NetworkList, `USBSTOR` Properties
3. `rla`로 `.LOG1`/`.LOG2`를 반영했는가 — 반영 전후 시각을 비교했는가
4. hive 헤더의 primary/secondary sequence number가 같은가
5. `MRUListEx`가 있는 키인가 — 그렇다면 시각은 최신 항목 것 하나뿐이다
6. 같은 시각을 가진 키가 몇 개인가 — 일괄 갱신 배제
7. 그 시각이 부팅·로그온·종료 시각과 같지 않은가
8. 다른 artifact와 **일관되게** 어긋나는가 — 그렇다면 시각 조작을 의심한다
9. USN·`EventRecordID` 같은 단조 카운터로 순서를 확인했는가
10. FILETIME(UTC)과 SYSTEMTIME·DOS 시각(로컬)을 섞지 않았는가
11. 그래도 시각이 필요하면 → VSS의 과거 hive, `RegBack`, 메모리 덤프, 4657/Sysmon 13

## 출처

- SRC-027 — Libyal libregf, REGF 포맷 문서: **키 레코드(`nk`)에만 마지막 쓰기 시각 필드가 있고 값 레코드(`vk`)에는 시각 필드가 존재하지 않는다는 점**, base block의 primary/secondary sequence number로 dirty 판정, 트랜잭션 로그의 역할
- SRC-014 — Microsoft Learn, File Times: FILETIME이 1601-01-01 UTC 기준 100ns 단위라는 점과 UTC 기준이라는 점, Unix epoch와의 `11644473600`초 차이
- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: hive 로드/언로드 구조와 각 키의 위치
- **NetworkList의 `DateCreated`/`DateLastConnected`는 16바이트 SYSTEMTIME 구조체이며 로컬 시각으로 기록되는 것이 통상이지만, 이 글은 그 기준을 단정하지 않는다.** 실제 사건에서는 다른 artifact와 대조해 UTC/로컬을 확정할 것
- **`USBSTOR` 하위 `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` 아래 `0064`/`0065`/`0066`/`0067`의 의미(최초 설치·설치·마지막 연결·마지막 제거)는 Windows 버전에 따라 존재 여부와 대응이 달라질 수 있으므로 실제 hive에서 확인할 것.** 값 자체는 FILETIME이다
- `ProfileList`의 로드/언로드 시각 값은 OS 버전에 따라 없을 수 있다
- 실제 예시의 시각·시리얼·시퀀스 번호는 설명을 위한 예시 값이다
