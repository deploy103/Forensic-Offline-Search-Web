---
id: FOR-0017
title: "Arsenal Image Mounter로 이미지를 실제 디스크처럼 마운트하기"
slug: "arsenal-image-mounter"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["E01", "RAW", "VHD", "VHDX", "VMDK", "VDI", "mounted volume"]
file_paths: ["C:\\Windows\\System32\\config", "C:\\Users"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Arsenal Image Mounter", "FTK Imager", "RegistryExplorer", "KAPE", "EvtxECmd"]
commands: []
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["e01", "ex01", "raw", "dd", "vhd", "vhdx", "vmdk", "vdi"]
primary_terms: ["Arsenal Image Mounter", "arsenal", "이미지 마운트"]
keywords: ["Arsenal Image Mounter", "이미지 마운트", "write temporary", "read only", "드라이브 문자", "VMDK 열기", "VHD 열기", "가상 디스크"]
aliases: ["arsenal", "arsenal image mounter", "이미지 마운트", "이미지 마운트하기", "vmdk 열기", "vhd 열기", "디스크 마운트", "드라이브로 붙이기"]
symptom_keywords: ["VMDK를 못 연다", "VHD를 열 수 없다", "이미지를 탐색기에서 보고 싶다", "툴이 이미지를 직접 못 읽는다", "마운트가 안 된다", "쓰기가 안 된다고 나온다", "원본이 변경될까 걱정된다"]
related: ["FOR-0016", "FOR-0019", "FOR-0021"]
source_ids: ["SRC-005", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

Arsenal Image Mounter는 이미지를 **볼륨이 아니라 디스크 장치 수준으로** 마운트해 드라이브 문자를 붙여 주므로, 이미지 형식을 직접 못 읽는 도구(RegistryExplorer, ChromeCacheView, WinPrefetchView 등)에 그대로 경로를 넘길 수 있게 해 준다 — 반드시 **Read only** 또는 **Write temporary**로 마운트한다.

## 어떤 문제에서 필요한가

- `.VMDK` / `.VHD` / `.VHDX` / `.VDI` 가 첨부되어 FTK Imager로 바로 열기 어려운 경우
- 분석 도구가 이미지 형식을 모르고 **폴더 경로만 받는** 경우
- KAPE로 이미지에서 artifact를 일괄 수집하고 싶은 경우
- 탐색기로 파일 구조를 직접 둘러봐야 하는 경우
- 파티션 테이블·볼륨 구성을 Windows 디스크 관리 화면에서 확인하고 싶은 경우

FTK Imager도 `File > Image Mounting` 기능이 있지만, Arsenal은 **가상 SCSI 디스크 어댑터 드라이버**로 붙기 때문에 Windows가 진짜 디스크로 인식한다. 이 차이가 도구 호환성을 크게 벌린다.

## 문제에서 처음 볼 단서

1. 확장자가 `.vmdk`, `.vhd`, `.vhdx`, `.vdi` — 가상 머신 디스크
2. `.E01` / `.raw` 인데 쓰려는 도구가 이미지를 못 읽는다
3. 파일이 `disk-flat.vmdk` + `disk.vmdk` 처럼 **디스크립터와 데이터가 분리**되어 있다 → 디스크립터(`disk.vmdk`)를 지정한다
4. VM 스냅샷 체인(`disk-000001.vmdk`)이 있다 → 최신 스냅샷을 지정해야 최종 상태가 보인다

## 30초 절차

```text
1. Arsenal Image Mounter 실행 (관리자 권한)
2. Mount disk image... 클릭
3. 이미지 파일 선택
4. 마운트 옵션에서 Read only 또는 Write temporary 선택
5. OK -> 드라이브 문자 확인 (예: E:)
6. 작업 종료 후 목록에서 선택 > Remove
```

관리자 권한이 필요하다. 드라이버를 로드하기 때문이다.

## 상세 절차

### 1단계 — 마운트 모드 세 가지의 차이 (가장 중요)

| 모드 | 원본 이미지 | 쓰기 결과 | 언제 쓰나 |
| --- | --- | --- | --- |
| **Read only** | 변경 없음 | 쓰기 자체가 거부됨 | **기본값. 대부분 이것** |
| **Write temporary** | 변경 없음 | 별도 차이(differencing) 파일에 저장, 언마운트 시 폐기 | Windows가 볼륨에 쓰려 할 때 (아래 참고) |
| Write original | **원본이 변경됨** | 이미지 파일에 직접 기록 | 증거물에는 **절대 사용하지 않는다** |

**`Write temporary`가 실무의 기본값이 되는 경우가 많다.** Windows는 NTFS 볼륨을 붙일 때 저널 복구·`$LogFile` 처리 등으로 볼륨에 쓰려고 시도하는데, `Read only`에서는 이 때문에 마운트가 실패하거나 볼륨이 인식되지 않을 수 있다. `Write temporary`는 원본을 건드리지 않으면서 이 쓰기를 흡수한다.

증거물 원본 보존이 최우선이면 다음 순서로 시도한다.

```text
Read only 로 시도
  └ 볼륨이 안 붙거나 오류 -> Write temporary 로 재시도
      └ 그래도 안 되면 이미지가 손상되었거나 파일시스템이 손상된 상태
```

`Write original`은 선택 화면에서 눈에 보이는 곳에 있으므로 **잘못 누르지 않도록 주의한다.** 이미지 사본으로 작업하는 습관이 안전장치가 된다.

### 2단계 — 마운트되는 형식

| 형식 | 확장자 | 지정할 파일 |
| --- | --- | --- |
| EnCase | `.E01`, `.Ex01` | 첫 조각(`.E01`)만 |
| RAW / dd | `.raw`, `.dd`, `.001`, `.img`, `.bin` | 첫 조각만 |
| VMware | `.vmdk` | **디스크립터** `.vmdk` (`-flat.vmdk`가 아니라) |
| Hyper-V | `.vhd`, `.vhdx` | 해당 파일 |
| VirtualBox | `.vdi` | 해당 파일 |

VMware 스냅샷 체인이 있을 때는 **가장 최신 스냅샷의 `.vmdk`** 를 지정한다. 부모 디스크는 자동으로 따라 붙는다. 원본 상태를 보려면 최초 `.vmdk`를 지정한다.

### 3단계 — 마운트 후 확인

마운트가 끝나면 Arsenal 창에 디스크 목록이 나온다.

```text
Disk #  Size      Image file            Mode              Volumes
2       237 GB    C:\case\pc01.E01      Write temporary   E: (NTFS, 236 GB), F: (FAT32, 100 MB)
```

여러 파티션이 있으면 **파티션마다 드라이브 문자**가 붙는다. 어느 것이 Windows 볼륨인지는 크기와 파일시스템으로 판단한다.

드라이브 문자가 안 붙었다면:

| 증상 | 원인과 대응 |
| --- | --- |
| 디스크는 붙었는데 드라이브 문자가 없다 | `diskmgmt.msc`(디스크 관리)에서 수동으로 드라이브 문자 할당 |
| 볼륨이 "RAW"로 표시된다 | 파일시스템이 손상됐거나 암호화(BitLocker). FTK Imager로 직접 파싱 |
| 파티션이 아예 안 보인다 | 파티션 테이블 손상. `mmls`로 오프셋을 찾아 다른 경로로 접근 ([FOR-0019](./mbr-gpt.html)) |
| BitLocker 잠금 | 복구 키/암호가 있으면 `manage-bde -unlock` |

### 4단계 — 마운트한 볼륨으로 무엇을 하나

여기가 Arsenal을 쓰는 이유다.

| 도구 | 마운트 없이는 | 마운트 후 |
| --- | --- | --- |
| RegistryExplorer | hive를 미리 추출해야 함 | `E:\Windows\System32\config\SYSTEM` 직접 열기 |
| RegRipper | 동일 | `rip.exe -r E:\Users\jhkim\NTUSER.DAT -p userassist` |
| EvtxECmd | 동일 | `EvtxECmd.exe -d E:\Windows\System32\winevt\Logs --csv out` |
| WinPrefetchView | 동일 | `E:\Windows\Prefetch` 폴더 지정 |
| ChromeCacheView | 동일 | `E:\Users\jhkim\...\Cache` 폴더 지정 |
| KAPE | 이미지 대상 불가 | `kape.exe --tsource E: --target !SANS_Triage --tdest C:\out` |
| exiftool / rg / 7-Zip | 경로 필요 | 볼륨 전체 재귀 스캔 |
| yara | 동일 | `yara -r rules.yar E:\` |

KAPE 조합이 특히 강력하다. 이미지를 마운트하고 KAPE 타깃 하나로 주요 artifact 전체를 한 번에 수집할 수 있다.

```powershell
# 마운트된 E: 에서 주요 artifact 일괄 수집
kape.exe --tsource E: --tdest C:\case\kape_out --target !SANS_Triage --vhdx case01
```

### 5단계 — 마운트해도 못 꺼내는 파일 (반드시 알아야 할 한계)

**마운트된 볼륨에서 탐색기나 `copy`로 다음 파일을 복사할 수 없다.** Windows NTFS 드라이버가 잠근다.

```text
$MFT, $MFTMirr, $LogFile, $Extend\$UsnJrnl:$J, $Bitmap, $Secure, $Boot
```

해결책은 **마운트된 볼륨을 FTK Imager로 `Logical Drive`로 다시 여는 것**이다.

```text
FTK Imager > File > Add Evidence Item > Logical Drive > E:
  -> [root] 에서 $MFT / $Extend\$UsnJrnl:$J Export 가능
```

또는 애초에 원본 이미지를 FTK Imager의 `Image File`로 열어 꺼낸다 ([FOR-0016](./ftk-imager-open-image.html)). **NTFS 메타파일이 필요하면 Arsenal 마운트를 우회하는 편이 빠르다.**

정리하면 역할 분담은 이렇다.

| 필요한 것 | 도구 |
| --- | --- |
| NTFS 메타파일(`$MFT`, `$J`, `$LogFile`) | FTK Imager (`Image File`) |
| 일반 파일·폴더, 도구에 경로 넘기기 | Arsenal 마운트 |
| VMDK/VHD/VDI 형식 | Arsenal 마운트 → 필요하면 FTK Imager로 `Logical Drive` |

### 6단계 — 언마운트

```text
Arsenal 창에서 해당 디스크 선택 > Remove
```

언마운트하지 않고 프로그램을 닫으면 드라이버가 디스크를 계속 붙들고 있을 수 있다. `Write temporary`의 차이 파일도 이때 정리된다. **작업이 끝나면 반드시 Remove한다.**

## 출력 필드 해석

Arsenal 메인 창의 컬럼이다.

| 컬럼 | 의미 | 확인 포인트 |
| --- | --- | --- |
| `Disk #` | Windows가 부여한 디스크 번호 | `diskmgmt.msc`에서 같은 번호로 보인다 |
| `Size` | 디스크 전체 크기 | 원본 디스크 크기와 일치해야 한다 |
| `Image file` | 마운트한 이미지 경로 | 여러 개 마운트 시 구분 |
| `Mode` | 마운트 모드 | **`Write original`이면 즉시 Remove** |
| `Volumes` | 붙은 드라이브 문자와 파일시스템 | 비어 있으면 4단계의 문제 해결로 |

`diskmgmt.msc`를 함께 열어 두면 파티션 배치와 미할당 영역을 시각적으로 확인할 수 있다 — 숨긴 파티션 탐지에 유용하다.

## pivot: 다음에 볼 artifact

| 마운트 후 확인한 것 | 다음 목표 |
| --- | --- |
| 사용자 폴더 목록 | 각 프로필의 `NTUSER.DAT` → UserAssist ([FOR-0061](./userassist.html)) |
| `Windows\System32\winevt\Logs` | EvtxECmd로 일괄 변환 → 4624/4688 ([FOR-0083](./event-4624-logon.html)) |
| `Windows\Prefetch` | 실행 이력 |
| 브라우저 프로필 폴더 | `History*` → sqlite3 ([FOR-0191](./chrome-history.html)) |
| 파티션이 예상보다 적다 | `mmls` / 디스크 관리로 미할당 영역 확인 ([FOR-0019](./mbr-gpt.html)) |
| 볼륨이 RAW로 보인다 | BitLocker/암호화 또는 파일시스템 손상 |
| NTFS 메타파일 필요 | FTK Imager `Logical Drive` 재오픈 ([FOR-0016](./ftk-imager-open-image.html)) |
| 전체 파일 목록 필요 | `$MFT` 파싱 ([FOR-0021](./mft-basics.html)) |

## 흔한 함정

- **`Write original`로 마운트하는 것.** 원본 이미지가 변경되어 해시가 깨지고 증거 가치를 잃는다. 실수 방지를 위해 항상 이미지 **사본**으로 작업한다.
- **`Read only`가 실패했을 때 원인을 오해하는 것.** 이미지 문제가 아니라 Windows가 볼륨에 쓰려는 것이 원인인 경우가 많다. `Write temporary`로 재시도한다.
- **마운트된 볼륨에서 `$MFT`를 복사하려는 것.** 잠겨서 실패한다. FTK Imager로 우회한다. **이것이 가장 자주 겪는 막힘 지점이다.**
- **`-flat.vmdk`를 지정하는 것.** 디스크립터인 `.vmdk`를 지정해야 한다.
- **스냅샷 체인에서 부모 디스크를 지정하는 것.** 최신 상태가 아니라 스냅샷 이전 상태가 보인다. 목적에 따라 골라야 한다.
- **관리자 권한 없이 실행하는 것.** 드라이버를 못 로드해 마운트가 실패한다.
- **작업 후 Remove하지 않는 것.** 디스크가 붙어 있어 이미지 파일이 잠기고, 다른 도구가 접근하지 못한다.
- **마운트된 드라이브에 백신·인덱싱이 붙는 것.** Windows Search나 백신이 볼륨을 스캔하면 `Write temporary`의 차이 파일이 커지고 접근 시각이 바뀔 수 있다. 분석용 시스템에서는 미리 비활성화한다.
- **마운트한 볼륨의 파일 시각을 그대로 신뢰하는 것.** 탐색기는 로컬 시간대로 표시한다. 증거물의 시간대와 다르므로 `$MFT` 파서의 UTC 값으로 재확인한다.
- **여러 이미지를 동시에 마운트하고 드라이브 문자를 혼동하는 것.** `Image file` 컬럼으로 매번 확인한다.

## 교차검증

```text
1) Arsenal 로 마운트 후 탐색기에서 파일 개수/크기 확인
2) 같은 이미지를 FTK Imager 의 Image File 로 열어 비교
3) $MFT 를 꺼내 MFTECmd 로 파싱한 전체 목록과 대조
4) 디스크 관리(diskmgmt.msc)의 파티션 배치와 mmls 출력 대조
```

1)과 3)의 파일 개수가 크게 다르면 **삭제 파일**(마운트에서는 안 보이고 `$MFT`에는 남음) 때문이다. 이것은 정상이며, 오히려 그 차이가 조사 대상이다.

4)에서 파티션 개수가 다르면 파��션 테이블에만 존재하고 실제로는 붙지 않는 볼륨이 있다는 뜻이다 — 암호화나 손상을 의심한다.

## mini walkthrough

```text
문제:
"VM 이미지에서 사용자가 실행한 프로그램 목록과 마지막 실행 시각을 구하세요."
첨부: win10.vmdk (디스크립터), win10-flat.vmdk (60 GB)

1. FTK Imager 로 시도 (실패한 접근)
   File > Add Evidence Item > Image File > win10.vmdk
   -> 형식을 인식하지 못했다.

2. 접근 변경 — Arsenal 로 마운트
   관리자 권한으로 Arsenal Image Mounter 실행
   Mount disk image... > win10.vmdk (flat 이 아니라 디스크립터)
   모드: Read only
   -> "볼륨을 마운트할 수 없습니다" 오류

3. Write temporary 로 재시도
   -> 성공. E: (NTFS, 59 GB) 붙음
      Windows 가 $LogFile 복구를 위해 쓰기를 시도하던 것이 원인이었다.

4. Prefetch 로 실행 이력
   WinPrefetchView 실행 > Options > Advanced Options
     Prefetch 폴더: E:\Windows\Prefetch
   -> 142개 .pf 파일. 실행 파일명 / Run Count / Last Run Time 확인

   또는 CLI:
   PECmd.exe -d E:\Windows\Prefetch --csv C:\case\out --csvf pf.csv

5. UserAssist 로 "사용자가 직접 실행한" 것만 (FOR-0061)
   rla.exe -f E:\Users\jhkim\NTUSER.DAT --out C:\case\clean
   rip.exe -r C:\case\clean\NTUSER.DAT -p userassist

   2026-03-14 07:38:05Z
     C:\Users\jhkim\Downloads\dump_tool.exe (3)

6. 교차검증 — $MFT 로 파일 생성 시각
   여기서 막혔다: E:\$MFT 를 복사하려니 "다른 프로세스가 사용 중"

7. 우회 — FTK Imager 로 마운트된 볼륨을 Logical Drive 로 열기
   FTK Imager > Add Evidence Item > Logical Drive > E:
   -> [root] > $MFT 를 Export 성공

   MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv
   -> dump_tool.exe  Created0x10 = 2026-03-14 07:36:44Z
      (다운로드 시각. 실행보다 81초 앞선다)

8. 시간대 보정
   rip.exe -r C:\case\clean\SYSTEM -p timezone -> Korea Standard Time
   07:38:05 UTC = 16:38:05 KST

정답: dump_tool.exe 등 3회 실행, 마지막 2026-03-14 16:38:05 KST
```

2→3단계(`Read only` 실패 → `Write temporary` 성공)와 6→7단계(마운트로는 `$MFT`를 못 꺼내 FTK Imager로 우회)가 Arsenal 사용의 두 가지 핵심 함정이다.

## 막혔을 때 다음 체크

1. **관리자 권한**으로 실행했는가
2. `Read only`가 실패했다면 **`Write temporary`로 재시도**했는가
3. VMDK인 경우 `-flat.vmdk`가 아니라 **디스크립터 `.vmdk`** 를 지정했는가
4. 스냅샷 체인에서 의도한 시점의 파일을 지정했는가
5. 드라이브 문자가 안 붙었는가 → `diskmgmt.msc`에서 수동 할당
6. 볼륨이 RAW로 보이는가 → BitLocker/암호화/파일시스템 손상 확인
7. `$MFT`가 잠겨 있는가 → **FTK Imager로 `Logical Drive` 재오픈**
8. 파티션이 예상보다 적은가 → `mmls`로 미할당 영역 확인
9. 이미지 파일이 잠겨 다른 도구가 못 여는가 → Arsenal에서 `Remove`
10. 파일 시각이 이상한가 → 탐색기는 로컬 시간대. `$MFT` 파서의 UTC로 재확인
11. 원본이 변경되었을까 우려되는가 → 이미지 해시를 재계산해 마운트 전 값과 비교

## 출처

- SRC-005 — Microsoft Learn, Master File Table: NTFS 메타파일이 볼륨 마운트 시 잠기는 이유의 배경
- SRC-004 — Eric Zimmerman 문서: 마운트된 볼륨을 입력으로 받는 도구들(RegistryExplorer, EvtxECmd, PECmd, KAPE)의 사용법
- 마운트 모드 명칭과 화면 구성은 Arsenal Image Mounter 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것. 일부 고급 기능은 유료 버전 전용이다
