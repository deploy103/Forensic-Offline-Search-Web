---
id: FOR-0021
title: "$MFT 기본 구조와 포렌식 활용"
slug: "mft-basics"
category: "디스크/NTFS"
type: "reference"
difficulty: "basic"
priority: "critical"
platform: [windows]
artifact: ["$MFT", "MFT record", "$STANDARD_INFORMATION", "$FILE_NAME", "$DATA", "$BITMAP"]
file_paths: ["C:\\$MFT", "\\.\\C:\\$MFT", "$MFT", "$MFTMirr"]
registry_paths: []
event_ids: []
protocols: []
tools: ["FTK Imager", "MFTECmd", "analyzeMFT", "Autopsy", "Sleuth Kit", "HxD", "Arsenal Image Mounter"]
commands: ["MFTECmd.exe -f $MFT --csv .", "analyzeMFT.py -f $MFT -o mft.csv", "fls -o 2048 -r image.dd", "istat -o 2048 image.dd 0"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["EntryNumber", "SequenceNumber", "ParentEntryNumber", "FileName", "InUse", "IsDirectory", "FileSize"]
file_formats: ["ntfs"]
primary_terms: ["$MFT", "MFT", "Master File Table", "마스터 파일 테이블", "MFT 레코드"]
keywords: ["MFT", "$MFT", "Master File Table", "NTFS", "파일 목록", "MFT 레코드", "resident", "non-resident", "MACB"]
aliases: ["mft", "엠에프티", "마스터 파일 테이블", "NTFS 파일 목록", "파일 전체 목록 뽑기", "master file table"]
symptom_keywords: ["파일이 언제 만들어졌는지", "전체 파일 목록이 필요하다", "삭제된 파일 이름을 알고 싶다", "파일 크기가 이상하다", "디스크에 뭐가 있었는지"]
related: ["FOR-0001", "FOR-0061"]
source_ids: ["SRC-005", "SRC-014", "SRC-004"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`$MFT`는 NTFS 볼륨의 모든 파일과 디렉터리를 1개 레코드씩 기록한 색인이며, 삭제된 파일의 이름·크기·타임스탬프까지 남아 있기 때문에 "이 디스크에 무엇이 있었는가"를 한 번에 답해 주는 첫 번째 artifact다.

## 개념

NTFS는 자기 자신을 파일로 관리한다. `$MFT` 역시 파일이고, 그 자신이 MFT의 0번 레코드다.

- 레코드 1개 크기는 보통 **1024바이트** (부트섹터의 `clusters per MFT record` 값으로 결정)
- 레코드는 `FILE` (`46 49 4C 45`) 시그니처로 시작한다
- 레코드 = 헤더 + **속성(attribute) 목록**
- 파일을 삭제해도 레코드는 즉시 지워지지 않는다. 헤더의 flag에서 `in use` 비트만 내려간다 → **삭제 파일 정보가 그대로 남는다**

예약된 앞부분 레코드(0~15번)는 NTFS 메타파일이다.

| 레코드 번호 | 파일 | 용도 |
| --- | --- | --- |
| 0 | `$MFT` | MFT 자신 |
| 1 | `$MFTMirr` | MFT 앞부분 백업 (MFT 손상 시 사용) |
| 2 | `$LogFile` | 트랜잭션 로그 |
| 3 | `$Volume` | 볼륨 이름/버전 |
| 5 | `.` (루트) | 볼륨 루트 디렉터리 |
| 6 | `$Bitmap` | 클러스터 할당 비트맵 |
| 7 | `$Boot` | 부트섹터 |
| 9 | `$Secure` | 보안 기술자 |

## 파일 / 경로

`$MFT`는 볼륨 루트에 있지만 실행 중인 Windows에서는 일반 복사가 불가능하다.

| 상황 | 추출 방법 |
| --- | --- |
| 디스크 이미지 (E01/RAW) | FTK Imager로 열고 볼륨 루트 → `$MFT` → Export Files |
| 이미지 마운트 | Arsenal Image Mounter로 마운트 후 FTK Imager로 추출 |
| 라이브 시스템 | KAPE, 또는 FTK Imager의 `Add Physical Drive` |
| Linux/Sleuth Kit | `icat -o <offset> image.dd 0 > \$MFT` |

CTF에서는 대개 `$MFT` 파일 하나만 따로 첨부된다. 이때 파일 시그니처는 `FILE`로 시작한다 ([FOR-0001](./30sec-triage.html)).

## 주요 필드

파서(MFTECmd / analyzeMFT)가 CSV로 뱉는 컬럼 중 실전에서 쓰는 것만 정리한다.

| 컬럼 | 의미 | 왜 중요한가 |
| --- | --- | --- |
| `EntryNumber` | MFT 레코드 번호 | 파일의 고유 ID. `fls`/`icat`에 그대로 넣는다 |
| `SequenceNumber` | 레코드 재사용 횟수 | 값이 크면 그 슬롯이 여러 번 재사용됨 = 삭제/생성 반복 |
| `InUse` | 사용 중 여부 | `False` = **삭제된 파일** |
| `ParentEntryNumber` | 부모 디렉터리 레코드 번호 | 전체 경로 재구성의 핵심 |
| `ParentPath` / `FileName` | 경로와 이름 | 검색 대상 |
| `IsDirectory` | 디렉터리 여부 | 필터링용 |
| `FileSize` | 논리 크기 | 0인데 이름이 있으면 resident 또는 잘린 파일 |
| `Created0x10` / `Created0x30` | $SI / $FN 생성 시각 | **불일치 = timestomp 의심** |
| `LastModified0x10` / `0x30` | 수정 시각 | 위와 동일 |
| `LastRecordChange0x10` / `0x30` | MFT 엔트리 변경 시각 | 사용자가 조작하기 가장 어려운 값 |
| `LastAccess0x10` / `0x30` | 접근 시각 | Win7+ 기본 갱신 비활성인 경우 많음 |
| `HasAds` / `si<fn` | ADS 존재 / 타임스탬프 역전 | 은닉·조작 신호 |

### 핵심 속성

| 속성 타입 | 이름 | 내용 |
| --- | --- | --- |
| `0x10` | `$STANDARD_INFORMATION` | MACB 타임스탬프, 파일 속성, USN |
| `0x30` | `$FILE_NAME` | 파일 이름 + **두 번째 MACB 세트** + 부모 레코드 번호 |
| `0x80` | `$DATA` | 실제 내용. 작으면 레코드 안에 들어간다(resident) |
| `0x90` / `0xA0` | `$INDEX_ROOT` / `$INDEX_ALLOCATION` | 디렉터리 색인 |
| `0xB0` | `$BITMAP` | 색인 할당 비트맵 |

`0x10`과 `0x30`이 **각각 4개씩, 총 8개의 타임스탬프**를 가진다는 점이 timestomp 탐지의 근거다. 흔한 조작 도구는 `$SI`만 바꾸고 `$FN`은 그대로 둔다.

### resident vs non-resident

- **resident**: `$DATA`가 레코드 내부에 저장됨. 대략 700바이트 이하 파일. → `$MFT` 하나만 있어도 **파일 내용을 복구할 수 있다**
- **non-resident**: `$DATA`가 클러스터 런(data run) 목록으로 저장됨. 내용 복구에는 볼륨 전체가 필요하다

작은 텍스트 파일에 flag가 들어 있는 문제는 `$MFT`만으로 풀린다.

## 빠른 명령

```powershell
# Eric Zimmerman MFTECmd — 가장 빠르고 컬럼이 풍부하다
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv

# 특정 파일만 보기
MFTECmd.exe -f 'C:\case\$MFT' --csv "C:\case\out" --csvf mft.csv --de 12345
```

```bash
# analyzeMFT (Python)
analyzeMFT.py -f '$MFT' -o mft.csv

# Sleuth Kit — 이미지에서 직접, 삭제 파일 포함 전체 목록
mmls image.dd                       # 파티션 오프셋 확인
fls -o 2048 -r -p image.dd          # -r 재귀, -p 전체 경로
istat -o 2048 image.dd 12345        # 레코드 12345 상세
icat -o 2048 image.dd 12345 > out   # 내용 추출
```

CSV가 나오면 검색은 텍스트 도구로 한다.

```powershell
# 삭제된 xlsx만
Import-Csv mft.csv | Where-Object { $_.InUse -eq 'False' -and $_.Extension -eq '.xlsx' } |
  Select-Object FileName, ParentPath, Created0x10, FileSize
```

```bash
# 특정 시각대(2026-03-14)에 생성된 항목
rg '2026-03-14' mft.csv | rg -v 'True,True'

# 확장자별 개수
awk -F, '{print $NF}' mft.csv | sort | uniq -c | sort -nr | head
```

## 함께 보는 artifact

| 목적 | 함께 볼 것 |
| --- | --- |
| 삭제 시각과 이유 | `$UsnJrnl` (USN_REASON_FILE_DELETE), `$LogFile` |
| 휴지통 경유 삭제 | `$Recycle.Bin` 의 `$I`/`$R` 파일 |
| 실행 여부 | Prefetch, Amcache, Shimcache |
| 사용자가 열었는지 | UserAssist, RecentDocs, LNK, Jump List ([FOR-0061](./userassist.html)) |
| 다운로드 출처 | 브라우저 History/Downloads ([FOR-0191](./chrome-history.html)) |
| Zone.Identifier ADS | `HasAds = True` 인 항목 |

## 흔한 실수

- **`FileSize`가 0인 것을 빈 파일로 단정하는 것.** resident 파일이거나 파서가 `$DATA`를 못 읽은 경우가 있다. `istat`으로 속성을 직접 확인한다.
- **`$SI` 타임스탬프만 보는 것.** MFTECmd CSV에서 `0x10`만 보고 결론 내리면 timestomp에 그대로 속는다. `0x30`과 항상 비교한다.
- **시간대를 UTC로 두고 KST 문제를 푸는 것.** MFT 타임스탬프는 FILETIME(UTC 기준)이다. 파서는 보통 UTC로 출력한다. 문제가 KST를 요구하면 +9시간 한다.
- **`InUse=False`를 "복구 가능"으로 착각하는 것.** 레코드는 남았지만 데이터 클러스터는 재할당되었을 수 있다. 내용이 필요하면 카빙으로 넘어간다.
- **`$MFTMirr`를 무시하는 것.** `$MFT` 앞부분이 손상된 경우 `$MFTMirr`에서 레코드 0~3을 복구할 수 있다.
- **레코드 번호 재사용을 놓치는 것.** `SequenceNumber`가 다르면 같은 `EntryNumber`라도 **다른 파일**이다.

## mini example

```text
문제:
"$MFT만 제공됩니다. 삭제된 텍스트 파일의 내용을 찾으세요."

1. file '$MFT'
   -> data          (매직 없음. 하지만 xxd로 확인)
   xxd -l 16 '$MFT'
   -> 00000000: 4649 4c45 ...   ("FILE" = MFT 레코드 확인)

2. MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv

3. 삭제 + txt 검색
   Import-Csv out\mft.csv |
     Where-Object { $_.InUse -eq 'False' -and $_.Extension -eq '.txt' } |
     Select-Object EntryNumber, FileName, FileSize, Created0x10

   EntryNumber FileName      FileSize Created0x10
   ----------- --------      -------- -----------
   84213       secret.txt    118      2026-03-14 07:22:41

4. FileSize 118바이트 = resident 확실 -> 레코드 안에 내용이 있다

5. MFTECmd.exe -f "$MFT" --csv out --csvf one.csv --de 84213
   또는 HxD로 오프셋 계산: 84213 * 1024 = 86,234,112 (0x52 4E 00 0)
   해당 위치에서 $DATA(0x80) 속성 뒤의 118바이트를 읽는다

6. 내용: flag{res1dent_d4ta_in_mft}

정답: flag{res1dent_d4ta_in_mft}
```

레코드 오프셋 = `EntryNumber × 레코드 크기(보통 1024)`. 이 계산 하나로 HxD에서 바로 점프할 수 있다.

## 출처

- SRC-005 — Microsoft Learn, Master File Table: 레코드 구조와 예약 레코드
- SRC-014 — Microsoft Learn, File Times: FILETIME은 1601-01-01 UTC 기준 100ns 단위
- SRC-004 — Eric Zimmerman 문서: MFTECmd 옵션 및 CSV 컬럼 정의
