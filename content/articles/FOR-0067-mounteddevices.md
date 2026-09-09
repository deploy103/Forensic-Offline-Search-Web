---
id: FOR-0067
title: "MountedDevices로 드라이브 문자와 볼륨을 매핑하기"
slug: "mounteddevices"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["MountedDevices", "disk signature", "partition offset", "Volume GUID", "device instance path", "MBR"]
file_paths: ["C:\\Windows\\System32\\config\\SYSTEM"]
registry_paths: ["SYSTEM\\MountedDevices", "HKLM\\SYSTEM\\MountedDevices"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "HxD", "FTK Imager", "Sleuth Kit"]
commands: ["rip.exe -r SYSTEM -p mountdev", "xxd -s 0x1b8 -l 4 disk.dd", "mmls disk.dd"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["\\DosDevices\\C:", "\\??\\Volume{GUID}", "disk signature", "partition starting offset"]
file_formats: ["regf"]
primary_terms: ["MountedDevices", "드라이브 문자 매핑", "\\DosDevices"]
keywords: ["MountedDevices", "DosDevices", "드라이브 문자", "drive letter", "Volume GUID", "disk signature", "디스크 시그니처", "파티션 오프셋", "0x1B8", "SYSTEM hive", "UTF-16LE", "device instance path"]
aliases: ["mounteddevices", "드라이브 문자 매핑", "e 드라이브가 뭐였나", "dosdevices", "볼륨 guid 드라이브", "디스크 시그니처 확인", "usb 드라이브 문자"]
symptom_keywords: ["E 드라이브가 무엇이었는지 알고 싶다", "드라이브 문자와 장치를 연결하고 싶다", "MountedDevices 값이 hex라 못 읽는다", "볼륨 GUID가 어느 디스크인지 모르겠다", "ControlSet 아래에 MountedDevices가 없다", "디스크 시그니처를 대조하고 싶다"]
related: ["FOR-0066", "FOR-0075", "FOR-0053", "FOR-0019"]
source_ids: ["SRC-017", "SRC-098", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SYSTEM\MountedDevices`는 **ControlSet 밖, hive 루트 바로 아래**에 있으며, `\DosDevices\X:` 값의 데이터가 **12바이트 짧은 이진(디스크 시그니처 4바이트 + 파티션 시작 오프셋 8바이트)이면 고정 디스크**, **UTF-16LE 문자열이면 착탈식/특수 볼륨**이고 그 문자열 안에 USB 시리얼이 들어 있어 드라이브 문자와 장치를 잇는다.

## 어떤 문제에서 필요한가

LNK·ShellBags·Prefetch·BAM은 모두 `E:\...` 또는 `\Device\HarddiskVolume3\...` 같은 표기로 경로를 남긴다. 그 표기가 **어느 물리 장치**였는지를 답하는 유일한 레지스트리 키가 여기다.

- "E: 드라이브는 무엇이었나 — 내장 파티션인가 USB인가"
- "USBSTOR에서 찾은 그 USB는 어느 드라이브 문자로 붙었나"
- "`\??\Volume{GUID}`가 어느 디스크의 몇 번째 파티션인가"
- "이 hive가 이 디스크 이미지의 것인지 확인하고 싶다" (디스크 시그니처 대조)
- "`\Device\HarddiskVolume3`을 드라이브 문자로 바꾸고 싶다"

## 문제에서 처음 볼 단서

1. 어떤 artifact에 낯선 드라이브 문자(`D:`~`Z:`)가 나오는데 그 정체를 모른다
2. `\??\Volume{...}` GUID만 있는 항목을 발견했다
3. `ControlSet001` 아래를 다 뒤졌는데 `MountedDevices`가 없다 → **루트에 있다**
4. USBSTOR에서 시리얼은 얻었는데 드라이브 문자가 없어 파일 접근 흔적과 연결되지 않는다

## 30초 절차

```powershell
rip.exe -r "C:\case\SYSTEM" -p mountdev
```

```text
MountedDevices
LastWrite Time 2026-03-14 07:04:22Z

Device: \??\STORAGE#Volume#{c8f2c7d1-...}#...4C530001120521105424&0#{53f5630d-...}
  \DosDevices\E:
  \??\Volume{9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}

Device: 3EEE3EED (disk signature), offset 0x100000
  \DosDevices\C:
  \??\Volume{6b8d0f11-2f4a-11f0-9b31-806e6f6e6963}
```

GUI라면 RegistryExplorer에서 트리 최상단을 본다.

```text
SYSTEM
  ControlSet001
  ControlSet002
  MountedDevices      <- ControlSet 안이 아니라 여기
  Select
  Setup
  WPA
```

## 상세 절차

### 1단계 — 위치를 먼저 못 박는다

```text
SYSTEM\MountedDevices        (O)  hive 루트 바로 아래
SYSTEM\ControlSet001\MountedDevices   (X)  존재하지 않는다
```

`Select`와 마찬가지로 ControlSet 밖에 있다. 즉 **이 키는 ControlSet 판정과 무관하게 단 하나뿐이며, 활성 세트를 고를 필요가 없다.** 라이브 시스템에서는 `HKLM\SYSTEM\MountedDevices`다. 이 키는 값만 있고 서브키가 없다.

### 2단계 — 값 이름의 두 형식

| 값 이름 형식 | 의미 |
| --- | --- |
| `\DosDevices\C:` | **드라이브 문자 배정.** 문자 하나가 값 하나 |
| `\??\Volume{9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}` | **볼륨 GUID 배정.** 드라이브 문자가 없는 볼륨도 여기에는 있다 |
| `#{GUID}` 로 시작하는 기타 항목 | 특수 장치. 대개 결론에 쓰지 않는다 |

같은 볼륨이 두 형식에 **동일한 데이터**로 등장한다. 그래서 데이터를 키로 삼아 두 형식을 서로 이을 수 있다.

```text
\DosDevices\E:                                   -> 데이터 X
\??\Volume{9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02} -> 데이터 X   (같다)
=> Volume{9f3a7c10-...} 이 E: 였다
```

이 대응은 LNK·ShellBags·`MountPoints2`가 볼륨 GUID로만 기록한 항목을 드라이브 문자로 되돌릴 때 결정적이다.

`\DosDevices\`에는 드라이브 문자뿐 아니라 매핑된 네트워크 드라이브가 남는 경우가 있으나, 사용자별 네트워크 드라이브는 사용자 hive 쪽이 정본이므로 여기서 단정하지 않는다.

### 3단계 — 값 데이터 형태 ①: 고정 디스크 (12바이트)

```text
\DosDevices\C:
  ED 3E EE 3E 00 00 10 00 00 00 00 00
  \_________/ \_____________________/
   시그니처 4B      시작 오프셋 8B
```

| 오프셋 | 크기 | 필드 | 읽는 법 |
| --- | --- | --- | --- |
| `0x00` | 4 | **디스크 시그니처** (MBR의 NT 디스크 서명) | 리틀엔디언 32비트. `ED 3E EE 3E` → `0x3EEE3EED` |
| `0x04` | 8 | **파티션 시작 오프셋 (바이트)** | 리틀엔디언 64비트. `00 00 10 00 00 00 00 00` → `0x100000` = 1048576 |

오프셋을 섹터로 바꾸면 파티션 테이블과 바로 대조된다.

```text
1048576 / 512 = 2048   -> 섹터 2048 에서 시작하는 파티션
```

`mmls`(Sleuth Kit) 출력의 Start 섹터와 이 값이 일치해야 한다([FOR-0040](./tsk-mmls.html)).

```text
$ mmls disk.dd
      Slot      Start        End          Length       Description
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0062912511   0062705664   NTFS / exFAT (0x07)
```

`Start = 2048`인 파티션이 `\DosDevices\C:`가 가리키는 파티션이다. 두 번째 파티션(섹터 206848 = `0x19000000` 바이트)이 있으면 그 값을 가진 `\DosDevices\D:`가 별도로 존재한다.

### 4단계 — 값 데이터 형태 ②: 착탈식/특수 볼륨 (UTF-16LE 문자열)

착탈식 장치는 디스크 시그니처가 아니라 **장치 인스턴스 경로를 담은 UTF-16LE 문자열**이 들어간다. 길이가 수십~수백 바이트라 hex 보기에서 12바이트 항목과 즉시 구분된다.

```text
\DosDevices\E:
  5F 00 3F 00 3F 00 5F 00 55 00 53 00 42 00 53 00   _ ? ? _ U S B S
  54 00 4F 00 52 00 23 00 44 00 69 00 73 00 6B 00   T O R # D i s k
  ...

UTF-16LE 디코딩:
_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001120521105424&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
                                                        ^^^^^^^^^^^^^^^^^^^^^^
                                                        USBSTOR 인스턴스 ID (시리얼)
```

**이 문자열 안에 `Enum\USBSTOR`에서 얻은 시리얼이 그대로 들어 있다는 것이 USB ↔ 드라이브 문자 연결의 원리다** ([FOR-0066](./usbstor.html)). 문자열의 접두 형태는 Windows 버전과 볼륨 종류에 따라 여러 가지가 관찰된다.

| 관찰되는 접두 | 대개의 의미 |
| --- | --- |
| `_??_USBSTOR#Disk&Ven_...#<시리얼>&0#{53f56307-...}` | USB 대용량 저장장치의 디스크 인터페이스 |
| `\??\STORAGE#Volume#...` | 볼륨 인터페이스 경로 |
| `DMIO:ID:` + 이진 GUID | 동적 디스크/GPT 계열 항목 |
| `DBCC` 로 시작하는 문자열 | Windows 10 이후 일부 볼륨에서 관찰되는 형태 |

**접두 문자열의 정확한 목록과 의미는 버전 의존이므로 외운 것으로 판정하지 않는다.** 판정의 불변량은 두 개뿐이다.

1. **데이터 길이가 12바이트면 고정 디스크**, 그보다 훨씬 길면 문자열형이다
2. 문자열형이면 **그 안에 장치 인스턴스 경로(그리고 대개 시리얼)가 들어 있다**

### 5단계 — hex를 직접 읽는 절차

파서가 없거나 파서 출력이 의심스러울 때의 수동 절차다.

라이브 시스템 / 마운트된 hive를 레지스트리에 로드한 경우:

```powershell
# 1) 값 이름과 데이터 길이만 먼저 훑는다 (12바이트 = 고정 디스크)
$md = Get-ItemProperty 'HKLM:\SYSTEM\MountedDevices'
$md.PSObject.Properties |
  Where-Object { $_.Name -like '\DosDevices\*' -or $_.Name -like '\??\Volume*' } |
  ForEach-Object { '{0,-58} {1,4} bytes' -f $_.Name, $_.Value.Length }
```

```text
\DosDevices\C:                                               12 bytes
\DosDevices\D:                                               12 bytes
\DosDevices\E:                                              228 bytes
\??\Volume{6b8d0f11-2f4a-11f0-9b31-806e6f6e6963}             12 bytes
\??\Volume{9f3a7c10-4b21-11f0-8a44-c8d3ffb17a02}            228 bytes
```

```powershell
# 2) 12바이트 항목: 시그니처와 오프셋을 숫자로 뽑는다
$d = $md.'\DosDevices\C:'
'signature = 0x{0:X8}' -f [BitConverter]::ToUInt32($d, 0)
'offset    = {0} bytes = sector {1}' -f [BitConverter]::ToUInt64($d, 4), ([BitConverter]::ToUInt64($d, 4) / 512)

# 3) 긴 항목: UTF-16LE 로 디코딩한다
[Text.Encoding]::Unicode.GetString($md.'\DosDevices\E:')
```

```text
signature = 0x3EEE3EED
offset    = 1048576 bytes = sector 2048
_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001120521105424&0#{53f56307-...}
```

오프라인 hive 파일만 있을 때는 RegistryExplorer로 값을 선택해 하단 hex 패널을 읽거나, 값 데이터를 파일로 내보낸 뒤 CLI로 처리한다.

```bash
# 내보낸 값 데이터 파일에서 UTF-16LE 문자열만 추출
strings -e l mounteddev_E.bin
xxd -l 12 mounteddev_C.bin
```

```powershell
rip.exe -r "C:\case\SYSTEM" -p mountdev > mountdev.txt
Select-String -Path mountdev.txt -Pattern '4C530001120521105424'
```

### 6단계 — MBR `0x1B8`과 대조해 디스크를 확정한다

디스크 시그니처는 MBR의 **오프셋 `0x1B8`에서 4바이트**에 들어 있다. 레지스트리 값과 이미지의 이 4바이트가 일치하면 "이 hive는 이 디스크의 것"이 증명된다.

```text
MBR (섹터 0, 512바이트) 배치
  0x000 - 0x1B7   부트 코드
  0x1B8 - 0x1BB   디스크 시그니처 (NT drive serial number)   <- 여기
  0x1BC - 0x1BD   보통 0x0000
  0x1BE - 0x1FD   파티션 테이블 (16바이트 * 4)
  0x1FE - 0x1FF   55 AA
```

```bash
xxd -s 0x1b8 -l 4 disk.dd
```

```text
000001b8: ed3e ee3e                                .>.>
```

```powershell
$fs  = [IO.File]::OpenRead('C:\case\disk.dd')
$buf = New-Object byte[] 4
$fs.Seek(0x1B8, 'Begin') | Out-Null
$fs.Read($buf, 0, 4) | Out-Null
$fs.Close()
'MBR signature = 0x{0:X8}' -f [BitConverter]::ToUInt32($buf, 0)
```

```text
MBR signature = 0x3EEE3EED
```

| 결과 | 해석 |
| --- | --- |
| 레지스트리 값과 MBR `0x1B8`이 일치 | 그 hive와 그 디스크가 같은 시스템의 것 |
| 불일치 | 다른 디스크의 hive이거나, 디스크를 클론/재서명(리시그니처)했다 |
| 이미지가 GPT다 (`0x1BE`~ 가 protective MBR) | 시그니처 대조가 성립하지 않는다. GUID 기반 항목을 봐야 한다 ([FOR-0019](./mbr-gpt.html)) |

디스크 이미지가 아니라 **파티션 이미지**만 받았으면 섹터 0이 MBR이 아니라 VBR이므로 `0x1B8`에는 시그니처가 없다. 이때는 대조를 포기하고 파티션 시작 오프셋만 사용한다.

## 출력 필드 해석

| 값 | 데이터 모양 | 결론 |
| --- | --- | --- |
| `\DosDevices\C:` | 12바이트 | 고정 디스크. 시그니처 + 오프셋으로 어느 파티션인지 확정 |
| `\DosDevices\E:` | 긴 문자열 | 착탈식. 문자열의 시리얼로 장치 확정 |
| `\??\Volume{GUID}` | 12바이트 또는 문자열 | 같은 데이터를 가진 `\DosDevices\X:`를 찾아 문자로 환산 |
| 데이터 앞 4바이트 | 리틀엔디언 32비트 | 디스크 시그니처. MBR `0x1B8`과 대조 |
| 데이터 `0x04`부터 8바이트 | 리틀엔디언 64비트 | 파티션 시작 **바이트** 오프셋. 512로 나누면 섹터 |
| 키 LastWrite | 키 하나뿐 | **개별 값의 변경 시각이 아니다.** 마지막으로 어떤 매핑이든 바뀐 시각 |

`MountedDevices`에는 값별 타임스탬프가 없다. 키 LastWrite 하나만 존재하므로 **"E:가 언제 붙었나"를 이 키로 답할 수 없다.** 시각은 `Enum\USBSTOR`, `setupapi.dev.log`, EVTX에서 가져온다.

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| 문자열 안의 USBSTOR 시리얼 | `SYSTEM\ControlSet001\Enum\USBSTOR` ([FOR-0066](./usbstor.html)) | 모델·제조사·연결 시각 |
| 확정된 드라이브 문자 `E:` | LNK, Jump List, ShellBags, RecentDocs | 그 드라이브에서 열린 파일 |
| 확정된 드라이브 문자 | BAM/DAM의 `\Device\HarddiskVolumeN` ([FOR-0071](./bam-dam.html)) | 그 볼륨에서 실행된 프로그램 |
| `\??\Volume{GUID}` | `NTUSER.DAT\...\Explorer\MountPoints2\{GUID}` | **어느 사용자**가 마운트했나 |
| 디스크 시그니처 | 이미지의 MBR `0x1B8` ([FOR-0019](./mbr-gpt.html)) | hive와 이미지의 동일성 |
| 파티션 시작 오프셋 | `mmls` ([FOR-0040](./tsk-mmls.html)), `fsstat` | 파티션 번호와 파일시스템 |
| 전체 조립이 필요할 때 | [FOR-0075](./usb-serial-drive-letter.html) | 시리얼 → 문자 → 사용자 → 시각 |

## 흔한 함정

- **`ControlSet001` 아래에서 `MountedDevices`를 찾는 것.** 이 키는 hive 루트에 있다 → "키가 없다 = hive 손상"으로 오판해 시간을 버린다 → 루트에 있는 키(`Select`, `MountedDevices`, `Setup`, `WPA`)를 따로 외운다.
- **12바이트 앞 4바이트를 빅엔디언으로 읽는 것.** `ED 3E EE 3E`를 `0xED3EEE3E`로 읽으면 MBR 대조가 영원히 실패한다 → 리틀엔디언으로 `0x3EEE3EED`.
- **오프셋 8바이트를 섹터 수로 착각하는 것.** 단위는 **바이트**다 → `2048`을 기대했는데 `1048576`이 나와 당황한다 → 512(또는 실제 섹터 크기)로 나눈다. 4Kn 디스크는 4096으로 나눈다([FOR-0048](./partition-offset-problems.html)).
- **문자열형 데이터를 그냥 hex로만 보고 "깨진 값"이라고 넘기는 것.** UTF-16LE라 hex에서 `00`이 한 칸씩 끼어 보인다 → 사람이 못 읽는다고 판단해 버린다 → `strings -e l` 또는 `[Text.Encoding]::Unicode.GetString()`으로 디코딩한다.
- **`MountedDevices`로 연결 시각을 답하는 것.** 값별 타임스탬프가 없다 → 키 LastWrite를 "USB 꽂은 시각"으로 쓰면 틀린다 → 시각은 `Enum\USBSTOR`·`setupapi.dev.log`·EVTX에서 가져온다.
- **드라이브 문자를 유일한 식별자로 취급하는 것.** 문자는 재사용된다 → 서로 다른 USB 두 개가 시간을 달리해 모두 `E:`였다면 `MountedDevices`에는 **마지막 것만** 남는다 → 문자만으로 장치를 특정하지 않고 시리얼과 시각을 함께 제시한다.
- **`\??\Volume{GUID}`를 볼륨 시리얼 번호와 혼동하는 것.** 볼륨 GUID는 마운트 매니저가 부여한 128비트 식별자이고, LNK가 담는 볼륨 시리얼 번호는 파일시스템이 포맷 때 만든 32비트 값이다 → 두 값을 대조하려다 영원히 실패한다 → 서로 다른 필드로 분리해 다룬다.
- **GPT 디스크에서 `0x1B8` 대조를 시도하는 것.** protective MBR이라 의미 있는 시그니처가 없다 → 불일치를 "조작"으로 오해한다 → GPT는 파티션 GUID 기반 항목으로 판정한다.
- **`rla`로 트랜잭션 로그를 반영하지 않는 것.** 마지막 마운트 결과가 `.LOG1`/`.LOG2`에만 있을 수 있다 → 최근 꽂은 USB가 안 보인다 → `SYSTEM`과 두 로그를 함께 꺼내 `rla`를 돌린다.
- **파티션 이미지를 디스크 이미지로 착각하는 것.** 섹터 0이 VBR이면 `0x1B8`은 부트 코드의 일부다 → 엉뚱한 4바이트를 시그니처로 비교한다 → `mmls`가 파티션 테이블을 못 읽으면 파티션 이미지로 간주한다.

## 교차검증

```powershell
# 1) MountedDevices 전체 덤프
rip.exe -r "C:\case\SYSTEM" -p mountdev > mountdev.txt

# 2) USBSTOR 시리얼이 MountedDevices 문자열에 있는지
rip.exe -r "C:\case\SYSTEM" -p usbstor > usbstor.txt
Select-String -Path mountdev.txt -Pattern '4C530001120521105424'

# 3) 고정 디스크: 레지스트리 시그니처 vs 이미지 MBR 0x1B8
$fs  = [IO.File]::OpenRead('C:\case\disk.dd')
$buf = New-Object byte[] 4
$fs.Seek(0x1B8, 'Begin') | Out-Null
$fs.Read($buf, 0, 4) | Out-Null
$fs.Close()
'MBR signature = 0x{0:X8}' -f [BitConverter]::ToUInt32($buf, 0)

# 4) 파티션 시작 오프셋 vs mmls
#    mmls disk.dd  ->  Start 섹터가 (오프셋 / 512) 와 같아야 한다
```

세 값(레지스트리 시그니처, MBR `0x1B8`, `mmls` 시작 섹터)이 모두 맞아떨어지면 드라이브 문자 매핑을 결론으로 쓸 수 있다.

## mini walkthrough

```text
문제:
"SYSTEM hive 와 디스크 이미지가 첨부됩니다. ShellBags 에 남은 F:\report 폴더가
 어느 장치의 것인지 밝히고, 그 장치의 시리얼 번호를 구하세요."

1. 첫 시도 (실패):
   RegistryExplorer 로 SYSTEM 을 열고
   SYSTEM\ControlSet001\MountedDevices 를 찾았다. 없다.
   ControlSet002 아래도 없다. "hive 가 잘렸나" 하고 다시 추출했다.

   왜 틀렸나:
   MountedDevices 는 ControlSet 안이 아니라 hive 루트 바로 아래에 있다.
   Select 와 같은 계층이다. 추출 문제가 아니었고 5분을 날렸다.

2. 위치를 바로잡고 값 목록을 본다
   SYSTEM\MountedDevices
     \DosDevices\C:    12 bytes
     \DosDevices\D:    12 bytes
     \DosDevices\F:   228 bytes      <- 길다. 착탈식 후보
     \??\Volume{6b8d0f11-...}  12 bytes
     \??\Volume{2c71ea44-...} 228 bytes

3. 두 번째 실수 — hex 를 그대로 읽으려 함
   \DosDevices\F: 의 hex 를 보고 "5F 00 3F 00 3F 00 ..." 를
   의미 없는 이진으로 판단해 넘어갔다.

   왜 틀렸나:
   UTF-16LE 다. 바이트마다 00 이 끼어 있어서 그렇게 보이는 것이고,
   디코딩하면 장치 인스턴스 경로가 평문으로 나온다.

   [Text.Encoding]::Unicode.GetString($md.'\DosDevices\F:')
   -> _??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP#
      0018F30D9B21EFB0A9331B27&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}

4. 시리얼 확정
   인스턴스 ID = 0018F30D9B21EFB0A9331B27&0
   두 번째 문자 = '0' (＆ 아님) -> 장치가 보고한 실제 시리얼
   답으로 쓸 시리얼 = 0018F30D9B21EFB0A9331B27

5. 볼륨 GUID 도 같은 데이터인지 확인
   \??\Volume{2c71ea44-...} 의 데이터가 \DosDevices\F: 와 동일
   -> Volume{2c71ea44-...} = F:  (MountPoints2 대조에 쓸 값)

6. 내장 디스크와 혼동하지 않았는지 검증
   \DosDevices\C: = ED 3E EE 3E | 00 00 10 00 00 00 00 00
     signature 0x3EEE3EED, offset 1048576 = sector 2048
   xxd -s 0x1b8 -l 4 disk.dd  ->  ed3e ee3e   (일치)
   mmls disk.dd               ->  002: Start 2048   (일치)
   -> C: 는 이미지의 첫 NTFS 파티션. F: 는 이미지에 없는 외부 장치다.

7. 장치 정보 보강
   SYSTEM\ControlSet001\Enum\USBSTOR
     Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP
       0018F30D9B21EFB0A9331B27&0   LastWrite 2026-03-13 23:51:07Z
         FriendlyName = Kingston DataTraveler 3.0 USB Device

정답: F: 는 Kingston DataTraveler 3.0 USB 저장장치,
      시리얼 0018F30D9B21EFB0A9331B27
```

## 막혔을 때 다음 체크

1. `MountedDevices`를 **hive 루트**에서 찾았는가
2. `rla`로 `SYSTEM.LOG1`/`.LOG2`를 반영했는가
3. 데이터 길이를 먼저 봤는가 — 12바이트면 고정 디스크, 길면 문자열형
4. 4바이트 시그니처를 **리틀엔디언**으로 읽었는가
5. 8바이트 오프셋을 섹터가 아니라 **바이트**로 해석하고 512로 나눴는가
6. 긴 데이터를 `strings -e l` 또는 `Unicode.GetString`으로 디코딩했는가
7. 같은 데이터를 가진 `\??\Volume{GUID}` 항목을 찾아 짝을 지었는가
8. 찾는 드라이브 문자가 없다면 → 나중에 다른 장치가 그 문자를 덮어썼을 수 있다. 시리얼로 역방향 검색하고 `MountPoints2`·LNK·ShellBags로 보완
9. 시각이 필요하면 이 키가 아니라 [FOR-0066](./usbstor.html)과 `setupapi.dev.log`로 이동
10. GPT/동적 디스크라면 `0x1B8` 대조를 포기하고 GUID 기반으로 판정([FOR-0019](./mbr-gpt.html))

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SYSTEM` hive가 `HKLM\SYSTEM`으로 마운트되며 `MountedDevices`가 ControlSet 밖 루트 계층에 있다는 구조
- SRC-098 — Microsoft Learn, USB 장치 레지스트리 항목: 장치 인스턴스 경로 표기(`USBSTOR#Disk&Ven_...#<인스턴스 ID>#{인터페이스 GUID}`)와 그 문자열이 볼륨 매핑 정보에 포함되는 방식
- SRC-099 — RegRipper 3.0 저장소: `mountdev`, `usbstor` 플러그인과 `rip.exe` 옵션
- 값 데이터 문자열의 **접두 형태 목록(`_??_USBSTOR#`, `\??\STORAGE#Volume#`, `DMIO:ID:`, `DBCC` 등)은 Windows 버전과 볼륨 종류에 따라 다르다.** 이 글은 관찰되는 형태만 나열하고 단정하지 않으며, 실제 판정은 데이터 길이와 디코딩 결과로 할 것
- MBR 시그니처 위치(`0x1B8`, 4바이트)와 파티션 테이블 배치는 이미지가 디스크 전체 이미지일 때만 유효하다. 파티션 이미지·GPT 디스크에서는 대조 방법이 달라지므로 실제 이미지 구조를 먼저 확인할 것
- RegRipper 플러그인 이름과 출력 형식은 버전에 따라 다를 수 있으므로 `rip.exe -l`로 확인할 것
