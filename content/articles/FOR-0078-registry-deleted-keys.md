---
id: FOR-0078
title: "있어야 할 레지스트리 키가 없을 때: 삭제된 키 복구 6가지 접근"
slug: "registry-deleted-keys"
category: "Registry"
type: "troubleshooting"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["deleted registry key", "hive slack", "unallocated cell", "트랜잭션 로그", "RegBack", "VSS", "nk record", "vk record"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM.LOG1", "C:\\Windows\\System32\\config\\SYSTEM.LOG2", "C:\\Windows\\System32\\config\\RegBack", "C:\\Users\\<user>\\NTUSER.DAT.LOG1", "C:\\Windows\\System32\\config"]
registry_paths: ["SYSTEM\\ControlSet001\\Control\\Session Manager\\Configuration Manager", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "SYSTEM\\ControlSet001\\Services"]
event_ids: []
protocols: []
tools: ["RegistryExplorer", "rla", "RegRipper", "Volatility 3", "Arsenal Image Mounter", "strings", "HxD", "FTK Imager"]
commands: ["rla.exe -d C:\\case\\config --out C:\\case\\clean", "strings -el SYSTEM | grep -i -n 'Run'", "vol -f mem.raw windows.registry.hivelist"]
regex_patterns: ["nk[\\x20-\\x7e]{0,2}", "[Ss]oftware\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Deleted Records", "primary sequence number", "secondary sequence number", "cell size", "LastWrite"]
file_formats: ["regf"]
primary_terms: ["삭제된 레지스트리 키", "레지스트리 슬랙", "unallocated hive"]
keywords: ["삭제된 레지스트리", "deleted key", "hive slack", "미할당 셀", "트랜잭션 로그", "RegBack", "볼륨 섀도 카피", "hivelist", "regf 카빙", "키가 없다", "EnablePeriodicBackup"]
aliases: ["레지스트리 키 없다", "삭제된 키 복구", "레지스트리 슬랙", "regback", "hive 카빙", "지워진 레지스트리 값"]
symptom_keywords: ["있어야 할 키가 없다", "Run 키가 비어 있다", "레지스트리 값이 사라졌다", "공격자가 키를 지운 것 같다", "플러그인 출력이 비어 있다", "삭제된 레지스트리를 복구하고 싶다"]
related: ["FOR-0051", "FOR-0077", "FOR-0063", "FOR-0027"]
source_ids: ["SRC-027", "SRC-004", "SRC-013"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

레지스트리 키가 안 보이는 원인은 삭제·제거·정책·애초에 없었음 4가지이고, 복구는 **트랜잭션 로그 반영 → hive 내부 미할당 셀 스캔 → hive 문자열 검색 → VSS/`RegBack` → 메모리 hive** 순으로 시도한다 — 그리고 **삭제 사실 자체가 증거**가 되는 경우가 많다.

## 증상

- RegRipper 플러그인 출력이 `Key not found` 또는 빈 결과다
- `Run`/`RunOnce`처럼 반드시 있어야 할 키가 아예 없거나 값이 0개다
- 서비스가 실행된 흔적은 있는데 `Services\<name>` 키가 없다
- `USBSTOR`에 장치가 있는데 `MountedDevices`에 대응 항목이 없다
- 다른 사용자 hive에는 있는 키가 이 사용자 hive에만 없다
- RegistryExplorer 하단에 "deleted records" 개수가 0이 아닌 숫자로 표시된다
- EVTX·Prefetch는 활동을 말하는데 레지스트리만 조용하다

## 가장 가능성 높은 원인

| 순위 | 원인 | 어떤 모양으로 보이나 | 결정적 판별점 |
| --- | --- | --- | --- |
| 1 | **도구/경로 문제** (삭제가 아니다) | 플러그인 이름 오타, 잘못된 hive, `CurrentControlSet` 입력 | 다른 도구로 열면 키가 있다. **가장 먼저 배제** |
| 2 | **트랜잭션 로그 미반영** | 최근 생성된 키가 안 보인다 | hive 헤더의 primary ≠ secondary (dirty) |
| 3 | **공격자/사용자가 삭제** | 부모 키의 LastWrite가 사건 시각. 미할당 셀에 잔존 | `$UsnJrnl`에 그 시각의 hive 파일 변경, 4657/Sysmon 13 |
| 4 | **프로그램 제거 / 정리 도구** | 관련 키가 무리로 사라졌다 | `Uninstall` 키 부재, 제거 로그, 같은 시각의 일괄 변경 |
| 5 | **정책/구성으로 비활성** | 키가 아니라 **값**만 없다 | 그룹 정책 관련 키 존재, `Policies` 하위 값 |
| 6 | **애초에 없었다** | OS 버전이 그 키를 안 쓴다 | 다른 정상 이미지·다른 사용자 hive와 대조 |

**1과 2를 배제하기 전에 "삭제됐다"고 결론 내지 않는다.** 실전에서 "키가 없다"의 절반 이상이 1·2다.

## 1차 확인

### ① 도구·경로 문제 배제

```powershell
# 플러그인 이름을 눈으로 확인한다 — 이름 오타가 빈 출력의 최대 원인
rip.exe -l | Select-String 'run|usb|shell|bam'
```

| 확인 | 방법 |
| --- | --- |
| 플러그인 이름이 맞는가 | `rip.exe -l`로 목록 확인. `shellbag`(X) / `shellbags`(O) |
| hive를 맞게 골랐는가 | `userassist`는 `NTUSER.DAT`, `usbstor`는 `SYSTEM` |
| `CurrentControlSet`을 쓰지 않았는가 | 오프라인 hive에는 없다. `Select\Current`로 `ControlSet001` 확인 ([FOR-0053](./system-controlset.html)) |
| hive가 손상되지 않았는가 | 선두 4바이트가 `regf`인지, 체크섬 오류가 없는지 |
| 사용자를 맞게 골랐는가 | 모든 프로필의 hive를 확인 |

### ② 트랜잭션 로그를 반영한다

```bash
xxd -l 16 SYSTEM
```

```text
00000000: 7265 6766 3f01 0000 3e01 0000 ....
                    ^primary        ^secondary   -> 다르면 dirty
```

```powershell
# hive + .LOG1 + .LOG2 를 같은 폴더에 두고 반영
rla.exe -d "C:\case\config" --out "C:\case\clean"
```

**트랜잭션 로그는 "최근 삭제 전 상태"를 담고 있을 수 있다.** 로그에는 아직 hive 본체에 반영되지 않은 변경이 들어 있으므로, 반영 전 hive와 반영 후 hive를 **둘 다 보관하고 비교**한다.

| 비교 결과 | 해석 |
| --- | --- |
| 반영 후에 키가 생겼다 | 원인 2. 삭제가 아니었다 |
| 반영 후에 키가 사라졌다 | **로그에 삭제 연산이 담겨 있었다.** 반영 전 hive가 삭제 이전 스냅숏이다 |
| 둘 다 없다 | 원인 3~6으로 진행 |

### ③ hive 내부 미할당(deleted) 셀을 스캔한다

hive는 파일 안에서 셀 단위로 공간을 관리하고, **키를 삭제하면 셀이 해제될 뿐 내용이 즉시 지워지지 않는다.** 그 영역이 레지스트리 슬랙이다.

```text
RegistryExplorer -> hive 로드 -> 좌측 하단 "Deleted Records" 노드
  Recovered keys / Recovered values 를 확인
  Options 에서 삭제 레코드 복구 기능이 켜져 있는지 본다
```

셀 헤더의 크기 값이 **음수면 사용 중, 양수면 해제된 셀**이다. 파서는 이 부호로 삭제 레코드를 찾아낸다. 손으로 카빙할 때도 같은 규칙을 쓴다.

| 복구 가능성 | 조건 |
| --- | --- |
| 높다 | 삭제 직후 이미지를 떴고, 그 hive에 이후 쓰기가 적었다 |
| 중간 | 삭제 후 시간이 지났지만 hive가 작다 |
| 낮다 | 삭제 후 hive에 대량 쓰기가 있었다. 셀이 재사용됐다 |
| 없다 | hive가 압축·재구성(정상 종료 시 정리)되었다 |

복구된 레코드는 **부모 관계가 끊겨 있는 경우가 많다.** 키 이름과 값은 나와도 전체 경로를 알 수 없으므로, 값 이름/데이터의 특징으로 원래 위치를 추정하고 그 근거를 함께 적는다.

## 2차 확인

### ④ hive 파일에 직접 문자열·패턴 검색

파서가 못 살린 조각을 찾는 마지막 수단이다. **키 이름은 hive 안에서 ASCII 또는 UTF-16LE 중 하나로 저장되므로 두 인코딩을 모두 돌린다.**

```bash
# ASCII 로 저장된 이름
strings -a -t d SYSTEM | grep -i -n 'svchost\|Run\|Services'

# UTF-16LE 로 저장된 이름
strings -el -t d SYSTEM | grep -i -n 'svchost\|Run\|Services'

# nk/vk 레코드 시그니처 주변을 직접 본다
grep -a -b -o 'nk' SYSTEM | head -40
```

```powershell
# Windows 만 있을 때
Select-String -Path "C:\case\SYSTEM" -Pattern 'suspicious_name' -Encoding unicode
Select-String -Path "C:\case\SYSTEM" -Pattern 'suspicious_name' -Encoding ascii
```

| 결과 | 해석 |
| --- | --- |
| 이름이 나오고 주변에 `nk`가 있다 | 삭제된 키 레코드의 잔존. HxD로 오프셋을 열어 구조 확인 |
| 이름만 나오고 구조가 없다 | 다른 값의 데이터 안에 문자열로 들어 있을 수 있다. 오해하지 않도록 문맥 확인 |
| 아무것도 없다 | 그 hive에는 흔적이 없다. ⑤·⑥으로 |

문자열이 나왔다는 것만으로 "그 키가 있었다"고 단정하지 않는다. **`nk` 레코드 구조가 함께 확인될 때만 키의 존재를 주장한다.**

### ⑤ 볼륨 섀도 카피 / 백업 hive

| 소스 | 경로 / 방법 | 성공 조건 |
| --- | --- | --- |
| 볼륨 섀도 카피 | Arsenal Image Mounter로 이미지를 마운트하고 섀도 카피 선택 ([FOR-0017](./arsenal-image-mounter.html)) | 사건 시각 이전의 스냅숏이 존재 |
| `RegBack` | `C:\Windows\System32\config\RegBack` | **Windows 10 1803 이후 기본 비활성**이라 파일 크기가 0바이트인 경우가 많다 |
| `RegBack` 활성 여부 | `SYSTEM\ControlSet001\Control\Session Manager\Configuration Manager`의 `EnablePeriodicBackup` | `1`이면 다시 켜 둔 환경. 백업이 실제로 존재할 수 있다 |
| 시스템 복원 지점 | VSS 안의 `config` 폴더 | 복원 지점이 남아 있어야 한다 |
| 백업 소프트웨어 | 백업 이미지·`.vhdx` 등 | 사건과 무관하게 존재해야 한다 |

```powershell
# RegBack 이 실제로 내용을 담고 있는지 크기로 판정한다
Get-ChildItem "C:\case\mount\Windows\System32\config\RegBack" |
  Select-Object Name, Length, LastWriteTimeUtc
```

크기가 0이면 그 경로는 포기하고 VSS로 간다.

### ⑥ 메모리 덤프의 hive

메모리에는 **로드된 hive의 최신 상태**가 있고, 디스크에 기록되기 전의 내용도 포함한다.

```bash
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

| 장점 | 한계 |
| --- | --- |
| 디스크에 없는 최신 값이 있을 수 있다 | 메모리 덤프가 있어야 한다 |
| 휘발성 hive(`HKLM\HARDWARE`)도 볼 수 있다 | 삭제된 키는 대체로 이미 사라졌다 |
| 종료 시 기록되는 Shimcache의 최신 상태 | 페이지 아웃된 부분은 결손 |

프로세스 목록 등 다른 메모리 분석과 함께 진행한다 ([FOR-0214](./volatility-pslist.html)).

## 다른 방법

### 삭제 사실 자체를 증거로 쓴다

키를 못 살려도 **"그 시각에 이 hive에서 무언가 지워졌다"**는 것은 증명할 수 있다.

| 근거 | 무엇을 보나 | 무엇을 말할 수 있나 |
| --- | --- | --- |
| **부모 키의 LastWrite** | 삭제된 키가 있어야 했던 부모 키의 시각 | 서브키 목록이 그 시각에 변경됐다. 삭제 시각의 후보 |
| **`$UsnJrnl`** | hive 파일·`.LOG1`의 `DataOverwrite`/`DataExtend`/`DataTruncation` | hive가 언제 수정됐는가 ([FOR-0027](./usnjrnl-basics.html)) |
| **`$MFT`** | hive 파일의 `$SI` 수정 시각 | 마지막 수정 시각 (조작 가능) |
| **`$LogFile`** | hive 파일에 대한 쓰기 연산 | 짧은 보존 창 안이면 상세 기록 |
| **EVTX 4657** | 레지스트리 값 변경 감사 | 감사 정책이 켜져 있었다면 삭제 주체까지 |
| **Sysmon 12/13/14** | 키 생성/삭제, 값 설정, 키 이름 변경 | Sysmon 환경이면 가장 명확 |
| **미할당 셀의 잔존** | 복구된 키 이름 | 무엇이 지워졌는지 |

부모 키 LastWrite는 **삭제 외의 원인으로도 갱신되므로 단독 근거로 쓰지 않는다.** `$UsnJrnl`의 hive 파일 변경 시각과 시각이 일치할 때만 삭제 시각으로 제시한다 ([FOR-0077](./registry-lastwrite-caveats.html)).

### 각 방법의 성공 조건 요약

| 방법 | 성공 조건 | 얻는 것 |
| --- | --- | --- |
| ① 도구/경로 재확인 | — | 대부분 여기서 끝난다 |
| ② 트랜잭션 로그 | hive가 dirty, `.LOG1`/`.LOG2` 확보 | 삭제 직전 상태 |
| ③ 미할당 셀 스캔 | 셀이 재사용되지 않았다 | 키 이름·값 (경로는 불확실) |
| ④ 문자열 검색 | 이름 문자열이 덮이지 않았다 | 이름 조각 |
| ⑤ VSS / `RegBack` | 스냅숏·백업이 존재 | **완전한 과거 hive** (가장 좋다) |
| ⑥ 메모리 hive | 덤프 존재 | 최신 상태 |
| 삭제 사실 증명 | `$UsnJrnl` 또는 감사 로그 | 삭제 시각·주체 |

## 실제 예시

```text
문제:
"악성 프로그램이 자동실행으로 등록되었다는 신고입니다. 그런데 Run 키에 항목이
 없습니다. 등록된 항목의 이름과 등록·삭제 시각을 구하시오.
 첨부: NTUSER.DAT(+LOG1/LOG2), SYSTEM, $MFT, $UsnJrnl 파싱 CSV, Security.evtx"

1. 첫 시도 (실패):
   rip.exe -r NTUSER.DAT -p runkey
   -> 빈 출력.
   "공격자가 Run 키를 삭제했다"고 결론 낼 뻔했다.

   왜 성급했나:
   플러그인 이름부터 확인하지 않았다.
     rip.exe -l | Select-String 'run'
     -> 목록에 있는 이름은 run 이었다. runkey 는 존재하지 않는 이름이었다.
   rip.exe -r NTUSER.DAT -p run
   -> 이번엔 키는 나오지만 값이 0개다. 키는 있고 항목만 없다.

2. 두 번째 시도 (실패):
   "값이 0개니 원래 아무것도 없었다"고 판단했다.
   -> hive 헤더 확인:
      xxd -l 16 NTUSER.DAT
      00000000: 7265 6766 8a02 0000 8902 0000
      primary 0x28a != secondary 0x289  -> dirty.
      트랜잭션 로그를 반영하지 않은 상태로 판단했다.

   rla.exe -f NTUSER.DAT --out clean\
   rip.exe -r clean\NTUSER.DAT -p run
   -> 여전히 값 0개. 다만 Run 키의 LastWrite 가 2026-04-09 08:31:12Z 로 갱신됐다.
      (반영 전에는 2026-02-11 이었다)
   => 로그 안에 그 시각의 변경이 담겨 있었다. 값이 삭제된 연산일 가능성이 높다.

3. 세 번째 시도 (부분 실패):
   미할당 셀을 본다.
     RegistryExplorer 로 clean\NTUSER.DAT 로드 -> Deleted Records
     -> 복구된 값 1개: 이름 "OneDriveHelper", 데이터 일부만 남음
        (데이터의 앞부분만 살아 있어 전체 경로가 잘렸다)
   경로가 잘려 답으로 쓰기 부족하다. 다음 방법으로 보강한다.

4. 문자열 검색으로 데이터 보강
   strings -el -t d clean/NTUSER.DAT | grep -i 'onedrivehelper'
   -> 1179648  OneDriveHelper
      1179700  C:\Users\hjlee\AppData\Roaming\OneDriveHelper\odhelper.exe
   HxD 로 오프셋 1179648 주변을 열어 vk 레코드 구조 확인 -> 값 레코드 잔존 확정.

5. 삭제 시각 확정
   Run 키 LastWrite            2026-04-09 08:31:12Z   (단독 근거로는 부족)
   $UsnJrnl 에서 NTUSER.DAT 관련:
     2026-04-09 08:31:12Z  DataOverwrite|DataExtend  NTUSER.DAT   .\Users\hjlee
   -> 두 시각이 일치. 삭제 시각으로 제시할 근거가 생겼다.

6. 등록 시각은 어디서?
   Run 키 LastWrite 는 마지막 변경(삭제) 시각이므로 등록 시각이 아니다.
   $UsnJrnl 에서 odhelper.exe 의 FileCreate: 2026-04-07 23:14:50Z
   Prefetch: ODHELPER.EXE-*.pf 최초 실행 2026-04-08 00:02:11Z
   -> 등록은 파일 생성 시각 이후 ~ 첫 실행 시각 사이로 범위 제시.
      정확한 등록 시각은 이 증거들로는 확정 불가. 그렇게 적는다.

7. VSS 확인 (더 좋은 근거를 찾는다)
   이미지를 Arsenal Image Mounter 로 마운트 -> 섀도 카피 2026-04-08 존재
   그 안의 NTUSER.DAT 을 꺼내 rip -p run
   -> OneDriveHelper = C:\Users\hjlee\AppData\Roaming\OneDriveHelper\odhelper.exe
   => 완전한 값 확보. 4번의 추정이 확증됐다.

정답:
  삭제된 자동실행 항목: OneDriveHelper
    -> C:\Users\hjlee\AppData\Roaming\OneDriveHelper\odhelper.exe
  삭제 시각: 2026-04-09 08:31:12Z = 2026-04-09 17:31:12 KST
    (근거: Run 키 LastWrite + $UsnJrnl 의 NTUSER.DAT 쓰기 일치)
  등록 시각: 2026-04-07 23:14:50Z ~ 2026-04-08 00:02:11Z 사이 (확정 불가, 범위로 제시)
```

1·2단계가 요점이다. **플러그인 이름과 트랜잭션 로그를 배제하기 전에 "공격자가 지웠다"고 결론 내면 두 번 틀린다.** 그리고 7단계처럼 **VSS가 있으면 다른 모든 방법보다 먼저 확인하는 것이 이득**이다.

## 막혔을 때 다음 체크

1. `rip.exe -l`로 플러그인 이름을 확인했는가 — 빈 출력의 최대 원인
2. hive를 맞게 골랐는가, `CurrentControlSet`을 입력하지 않았는가
3. `rla`로 로그를 반영했는가 — **반영 전 hive도 보관했는가**
4. 헤더의 primary/secondary sequence number를 봤는가
5. RegistryExplorer의 Deleted Records를 봤는가
6. hive에 ASCII와 UTF-16LE **두 인코딩으로** 문자열 검색을 했는가
7. VSS·`RegBack`·백업 이미지를 확인했는가 — `RegBack`은 크기 0인지 먼저 본다
8. 메모리 덤프가 있는가 — `windows.registry.hivelist`
9. 다른 사용자 hive·다른 이미지와 대조해 "애초에 없었다"를 배제했는가
10. 복구가 실패했다면 → 삭제 사실 자체를 `$UsnJrnl`·부모 키 LastWrite·4657·Sysmon 13으로 증명했는가
11. 복구된 레코드의 **경로가 불확실하면** 그 한계를 답에 함께 적었는가

## 출처

- SRC-027 — Libyal libregf, REGF 포맷 문서: hive의 셀 구조와 **셀 크기가 음수면 할당·양수면 해제**라는 판정 기준, `nk`/`vk` 레코드 시그니처, 키 이름이 ASCII 또는 UTF-16LE로 저장된다는 점, 트랜잭션 로그의 역할과 sequence number
- SRC-004 — Eric Zimmerman 문서: RegistryExplorer의 삭제 레코드 복구 기능과 `rla`의 트랜잭션 로그 반영 동작
- SRC-013 — Microsoft Learn, Change Journals: hive 파일 자체의 변경을 `$UsnJrnl`의 `DataOverwrite`/`DataExtend`/`DataTruncation`으로 관측하는 근거
- **`RegBack`이 Windows 10 1803 이후 기본적으로 채워지지 않는다는 점과 `EnablePeriodicBackup` 값으로 다시 활성화할 수 있다는 점은 환경에 따라 다르므로, 실제 이미지에서 폴더 안 파일의 크기가 0인지 먼저 확인할 것**
- RegistryExplorer의 메뉴/노드 이름(Deleted Records, 복구 옵션 위치)은 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- Volatility 3의 레지스트리 플러그인은 SRC-006(Volatility 3 문서)에 근거가 있으며, 이 글은 사용 위치만 제시한다
- 4657·Sysmon 12/13/14의 필드 정의는 Event Log 전담 글의 몫이다
- 실제 예시의 오프셋·시각·항목명은 설명을 위한 예시 값이다
