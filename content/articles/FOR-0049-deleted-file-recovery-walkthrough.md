---
id: FOR-0049
title: "삭제 파일 복구 실전: 휴지통 → $UsnJrnl → $MFT → 카빙 판정 트리"
slug: "deleted-file-recovery-walkthrough"
category: "디스크/NTFS"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["$Recycle.Bin", "$I", "$R", "$UsnJrnl", "$MFT", "unallocated space", "slack space", "data run"]
file_paths: ["C:\\$Recycle.Bin", "C:\\$Extend\\$UsnJrnl", "C:\\$MFT"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "icat", "istat", "blkstat", "ifind", "MFTECmd", "RBCmd", "FTK Imager", "foremost", "PhotoRec", "HxD"]
commands: ["icat -o 2048 -r image.raw 84213 > recovered.bin", "fls -o 2048 -r -d -p image.raw", "istat -o 2048 image.raw 84213", "blkstat -o 2048 image.raw 1180160", "ifind -o 2048 -d 1180160 image.raw", "RBCmd.exe -d \"C:\\case\\$Recycle.Bin\" --csv ."]
regex_patterns: ["flag\\{[^}]*\\}"]
wireshark_filters: []
tshark_fields: []
log_fields: ["InUse", "SequenceNumber", "EntryNumber", "FileSize", "UpdateReasons", "DeletedOn"]
file_formats: ["ntfs", "zip", "xlsx", "e01", "raw"]
primary_terms: ["삭제 파일 복구", "파일 복구"]
keywords: ["삭제 파일 복구", "undelete", "휴지통", "$Recycle.Bin", "$I", "$R", "icat", "recover", "카빙", "재할당", "부분 복구", "슬랙"]
aliases: ["삭제 파일 복구", "지운 파일 복구", "휴지통 복구", "undelete", "파일 되살리기", "icat 복구", "복구 순서", "삭제된 파일 어떻게"]
symptom_keywords: ["삭제된 파일을 복구하고 싶다", "복구했는데 열리지 않는다", "휴지통에 없다", "카빙했는데 못 찾겠다", "파일이 잘려서 나온다", "복구한 파일이 다른 내용이다", "MFT에 레코드가 없다"]
related: ["FOR-0046", "FOR-0047", "FOR-0021"]
source_ids: ["SRC-005", "SRC-013", "SRC-032", "SRC-035"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

삭제 파일 복구는 도구 선택 문제가 아니라 **순서 문제**다 — 휴지통 → `$UsnJrnl`로 이름·시각 확정 → `$MFT`에서 레코드 생존(`InUse=False`) 확인 → 레코드가 있으면 `icat`/FTK Imager로 직접 추출 → 레코드가 없거나 클러스터가 재할당되었으면 카빙 → 마지막으로 슬랙/비할당 `strings`. 카빙부터 시작하면 거의 항상 시간을 잃는다.

## 어떤 문제에서 필요한가

- "삭제된 파일을 복구하세요" / "지워진 문서의 내용을 제출하세요" 유형 전부
- 유출 사고 시나리오에서 유출물의 **원래 이름과 내용**을 둘 다 요구하는 문제
- 카빙으로 파일은 뽑았는데 그중 어느 것이 문제의 파일인지 특정해야 하는 상황
- 복구했지만 열리지 않는 파일을 부분 복구해야 하는 상황

## 문제에서 처음 볼 단서

1. 첨부가 이미지 전체인가, `$MFT`/`$J` 같은 artifact 몇 개인가 — 후자면 판정 트리의 일부 단계가 애초에 불가능하다
2. 지문의 "휴지통을 비웠다", "Shift+Delete", "포맷했다" — 어느 단계부터 시작할지 결정된다
3. 대상 파일의 **형식** — ZIP/Office/PDF는 푸터가 있어 카빙 성공률이 높고, 텍스트는 카빙이 무의미하다
4. 지문이 요구하는 것이 **이름/시각**인가 **내용**인가 — 전자는 `$J`, 후자는 `icat`/카빙
5. 삭제 시각이 주어졌는가 — 주어졌으면 그 시각 ±5분의 `$J`만 봐도 된다

## 30초 절차

```bash
icat -o 2048 -r image.raw 84213 > recovered.bin
```

레코드 번호를 아직 모를 때의 최단 경로:

```bash
mmls image.raw                                  # 오프셋 확정 (FOR-0048)
fls -o 2048 -r -d -p image.raw | head -40       # -d = 삭제된 항목만
fls -o 2048 -r -d -p image.raw | grep -i 'secret\|budget\|\.xlsx'
icat -o 2048 -r image.raw <레코드번호> > out.bin
file out.bin && xxd -l 16 out.bin
```

Windows GUI만 있다면 FTK Imager에서 볼륨을 열고 삭제 항목(빨간 X 아이콘)을 우클릭 → `Export Files` ([FOR-0016](./ftk-imager-open-image.html)).

## 상세 절차

### 판정 트리

```text
[삭제 파일 복구 시작]
  |
  1. $Recycle.Bin 에 $I / $R 이 있는가?
  |    예 -> $I 로 원래 경로·크기·삭제 시각 확정, $R 이 곧 파일 내용. [완료]
  |    아니오 (Shift+Delete 또는 휴지통 비움)
  v
  2. $UsnJrnl($J) 에 FileDelete 가 있는가?
  |    예 -> 이름 / 삭제 시각 / EntryNumber / ParentEntryNumber 확보
  |    아니오 -> 저널이 순환됐거나 꺼져 있다. 3번으로 그냥 진행
  v
  3. $MFT 의 그 EntryNumber 레코드가 살아 있는가? (InUse=False 로 남아 있는가)
  |    예 -> 4번
  |    아니오 (레코드 재사용됨: SequenceNumber 불일치) -> 5번
  v
  4. icat / FTK Imager 로 직접 추출
  |    성공 (헤더·크기·열림 모두 정상) -> [완료]
  |    실패 (0바이트 / 다른 파일 내용 / 깨짐)
  |       -> istat 로 런리스트 확인, blkstat 으로 재할당 여부 판정 -> 5번
  v
  5. 카빙 (blkls 비할당 + foremost / PhotoRec)
  |    성공 -> 크기·내부 메타데이터로 그 파일인지 특정 -> [완료]
  |    실패 -> 6번
  v
  6. 슬랙 / 비할당 strings — 파일 전체가 아니라 "내용의 일부"를 노린다
       flag 문자열만 필요한 문제는 여기서 끝나는 경우가 많다
```

각 단계의 판정 기준을 표로 고정한다.

| 단계 | 성공 판정 | 실패 판정 | 실패 시 이동 |
| --- | --- | --- | --- |
| 1 휴지통 | `$I` 파싱 성공 + `$R` 크기가 `$I`의 크기와 일치 | `$Recycle.Bin` 하위가 비었다 | 2 |
| 2 `$J` | `FileDelete` 레코드에 대상 파일명 존재 | 대상 이름이 없다 | 3 (이름은 나중에) |
| 3 `$MFT` | `InUse=False`이고 `SequenceNumber`가 `$J`의 값과 일치 | 레코드가 다른 파일로 채워졌다 | 5 |
| 4 `icat` | 출력 크기 = `FileSize`, 헤더/푸터 정상, 열린다 | 0바이트 / 다른 내용 / 헤더 불일치 | 5 |
| 5 카빙 | 헤더+푸터가 온전한 파일이 나오고 크기가 근사 | 후보 없음, 전부 잘림 | 6 |
| 6 `strings` | 요구된 문자열이 나온다 | 아무것도 없다 | 덮어쓰기 완료. 복구 불가 |

### 1단계 — 휴지통 ($Recycle.Bin)

휴지통 삭제는 **파일을 지우지 않고 이름만 바꿔 옮긴다.** 가장 쉬운 복구 경로다.

```text
C:\$Recycle.Bin\S-1-5-21-...-1001\
├── $I8KP2QX.xlsx      <- 메타데이터 (원래 경로, 크기, 삭제 시각)
└── $R8KP2QX.xlsx      <- 실제 파일 내용 (이름만 바꿔 그대로 있다)
```

| 요소 | 내용 |
| --- | --- |
| `$I` | 헤더 8바이트 = 버전(구형 `0x01`, Windows 10 이후 `0x02`), 이어서 파일 크기 8바이트, **삭제 시각 FILETIME 8바이트**, 그 뒤 원래 전체 경로(UTF-16LE) |
| `$R` | 삭제된 파일의 원본 바이트. **확장자를 붙여 그대로 열면 된다** |
| SID 폴더 | `S-1-5-21-...-1001` — 누가 지웠는지 알려 준다 |

```powershell
RBCmd.exe -d 'C:\case\$Recycle.Bin' --csv "C:\case\out"
```

```text
SourceName            FileType  FileName                              FileSize   DeletedOn
$I8KP2QX.xlsx         Recycler  C:\Users\jhkim\Documents\budget.xlsx  1245184    2026-03-14 07:39:52
```

- `DeletedOn`은 **FILETIME(UTC)** 이다. KST 답이 필요하면 +9시간 → `16:39:52`
- `$R` 파일을 원래 이름으로 복사하면 복구 완료다

```bash
cp '$R8KP2QX.xlsx' budget.xlsx && file budget.xlsx
```

휴지통이 비었으면 `$I`/`$R`도 삭제된 상태이므로, **`$Recycle.Bin` 하위의 삭제 항목까지 `fls -d`로 확인**한다. `$I`만 카빙으로 살려도 원래 경로와 삭제 시각은 얻는다.

```bash
fls -o 2048 -r -d -p image.raw | grep -i 'Recycle'
```

### 2단계 — $UsnJrnl($J)로 사건과 원래 이름 확정

`$J`는 "무슨 일이 있었나"에 답한다. 여기서 얻는 것이 뒤 단계의 입력이 된다.

```powershell
MFTECmd.exe -f 'C:\case\$J' -m 'C:\case\$MFT' --csv "C:\case\out" --csvf usn.csv
```

```powershell
Import-Csv out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'FileDelete' } |
  Select-Object Usn, UpdateTimestamp, FileName, ParentPath, EntryNumber, SequenceNumber |
  Sort-Object Usn
```

| `$J`에서 얻는 것 | 다음 단계에서 쓰는 곳 |
| --- | --- |
| `FileName` | 카빙 결과 특정, 이름이 답인 문제 |
| `UpdateTimestamp` | 사건 시각(UTC). 같은 시간대의 다른 artifact |
| `EntryNumber` | `$MFT` 조회, `icat`/`istat`의 인자 |
| `SequenceNumber` | **레코드 재사용 판정** — `$MFT` 값과 다르면 그 레코드는 이미 남의 것 |
| `RenameOldName` | 위장 전 원래 이름 |

플래그 값과 사건 유형별 패턴은 [FOR-0027](./usnjrnl-basics.html)에 정리되어 있다. 여기서는 `FileDelete`와 `RenameOldName` 두 개만 쓴다.

### 3단계 — $MFT에서 레코드 생존 확인

```powershell
Import-Csv out\mft.csv |
  Where-Object { $_.EntryNumber -eq 128441 } |
  Select-Object EntryNumber, SequenceNumber, InUse, FileName, ParentPath, FileSize, Created0x10
```

| 관찰 | 의미 | 행동 |
| --- | --- | --- |
| `InUse=False` + `SequenceNumber`가 `$J`와 일치 | **레코드가 살아 있다.** 이름·크기·런리스트가 그대로 | 4단계로 |
| `InUse=False`이지만 `FileName`이 다른 파일 | 레코드가 재사용됐다 | 5단계(카빙)로 |
| `InUse=True`이고 다른 이름 | 레코드가 이미 다른 파일에 배정됐다 | 5단계로 |
| 해당 `EntryNumber`가 CSV에 없다 | `$MFT`가 축소됐거나 이미지가 잘렸다 | 5단계로 |
| `FileSize`가 0인데 이름이 있다 | resident이거나 파서가 `$DATA`를 못 읽었다 | `istat`으로 직접 확인 |

`FileSize`는 뒤에서 **복구 성공 판정의 기준**이 되므로 반드시 적어 둔다.

Sleuth Kit만으로 하는 같은 작업:

```bash
fls -o 2048 -r -d -p image.raw | grep -i 'budget'
# -/r * 128441-128-1:  Users/jhkim/Documents/budget_2026.xlsx
#      ^ * = 삭제됨   ^ 레코드-속성타입-속성ID
```

`128441-128-1` 형식은 `레코드번호-속성타입(128=0x80=$DATA)-속성ID`다. ADS가 있는 파일은 `-128-2`처럼 여러 개가 나오며, **그중 어느 것을 뽑는지에 따라 결과가 완전히 달라진다.**

### 4단계 — 레코드가 있으면 직접 추출

```bash
# 기본
icat -o 2048 image.raw 128441 > recovered.xlsx

# 삭제 항목을 강제로 복구 모드로
icat -o 2048 -r image.raw 128441 > recovered.xlsx

# 특정 속성만 (ADS 포함 파일)
icat -o 2048 image.raw 128441-128-1 > recovered.xlsx

# 슬랙까지 포함해 뽑는다 (뒷부분에 이전 파일 잔재가 붙는다)
icat -o 2048 -s image.raw 128441 > with_slack.bin
```

추출 직후 **크기부터 본다.**

```bash
ls -l recovered.xlsx        # $MFT 의 FileSize 와 같아야 한다
file recovered.xlsx
xxd -l 16 recovered.xlsx
```

실패했다면 원인을 `istat`로 확정한다.

```bash
istat -o 2048 image.raw 128441
```

```text
MFT Entry Header Values:
Entry: 128441        Sequence: 7
$LogFile Sequence Number: 0x0000000047a2b1c0
Not Allocated
Links: 0

$STANDARD_INFORMATION Attribute Values:
Created:        2026-03-14 07:31:04 (UTC)
File Modified:  2026-03-14 07:33:18 (UTC)

Attributes:
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 90
Type: $DATA (128-1)   Name: N/A   Non-Resident   size: 1245184  init_size: 1245184
1180160 1180161 1180162 1180163 1180164 1180165 1180166 1180167
1180168 1180169 ...
```

마지막 숫자 목록이 **데이터 런(클러스터 번호)** 이다. 이 클러스터가 다른 파일에 다시 배정됐는지 확인한다.

```bash
blkstat -o 2048 image.raw 1180160
# Allocated      -> 누군가에게 배정됨. 내용이 덮였을 가능성 높다
# Not Allocated  -> 아직 비어 있다. 내용이 남아 있을 가능성 높다

ifind -o 2048 -d 1180160 image.raw
# 그 클러스터를 현재 소유한 MFT 레코드 번호를 알려 준다
```

| `blkstat` 결과 | `ifind` 결과 | 해석 | 행동 |
| --- | --- | --- | --- |
| `Not Allocated` | 없음 | 데이터가 살아 있다 | `icat`을 신뢰. 크기/헤더 재확인 |
| `Allocated` | 다른 레코드 번호 | **재할당됨.** `icat`은 남의 데이터를 준다 | 카빙으로 전환 |
| `Allocated` | 같은 레코드 번호 | 아직 자기 것 | `icat`을 신뢰 |

이것이 "`icat`은 성공했는데 파일이 안 열린다"의 진짜 원인 판정법이다.

### 5단계 — 카빙으로 전환

레코드가 죽었거나 데이터가 재할당된 경우다. **이미지 전체를 카빙하지 않는다.** 비할당만 잘라 형식을 좁힌다.

```bash
blkls -o 2048 image.raw > unalloc.blkls
foremost -t zip,pdf,doc,jpg -i unalloc.blkls -o carved
cat carved/audit.txt
```

옵션·`audit.txt` 해석은 [FOR-0046](./foremost.html), 조각화 대응은 [FOR-0047](./photorec.html)에 있다.

카빙 결과에서 **어느 것이 문제의 파일인가**를 특정하는 방법:

| 특정 근거 | 방법 |
| --- | --- |
| 크기 | `$MFT`/`$I`의 `FileSize`와 ±1 클러스터 이내인 후보 |
| 내부 파일 이름 | ZIP 계열은 `unzip -l`의 항목 이름, Office는 `docProps/core.xml` |
| 내부 시각 | `docProps/core.xml`의 `dcterms:created`(UTC), EXIF `DateTimeOriginal` |
| 위치 | `audit.txt`의 `File Offset` → `blkcalc`로 원본 블록 → `$MFT` 런리스트와 비교 |
| 내용 | `strings`로 지문에 등장한 고유 명사 검색 |

```bash
# 크기로 후보 좁히기 ($MFT FileSize = 1245184)
find carved -type f -size +1100k -size -1400k -ls

# ZIP 계열 내부 이름 확인
for f in carved/zip/*.zip; do echo "== $f"; unzip -l "$f" | head -8; done
```

### 6단계 — 슬랙과 비할당 strings

파일 전체가 아니라 **내용 일부**만 필요한 문제는 여기서 끝난다.

```bash
# 슬랙 공간만
blkls -s -o 2048 image.raw > slack.raw
strings -n 6 slack.raw | grep -Eo 'flag\{[^}]*\}'

# 비할당 전체에서 문자열
strings -n 6 unalloc.blkls | grep -i 'budget\|flag{' | head

# UTF-16LE (Windows 문자열은 이쪽인 경우가 많다)
strings -el -n 6 unalloc.blkls | grep -i 'flag{' | head

# 특정 클러스터 하나만 직접 읽기 (클러스터 4096 가정)
dd if=image.raw bs=4096 skip=$((1180160)) count=1 2>/dev/null | xxd | head
```

`strings -el`을 빼먹는 것이 흔한 누락이다. Windows 애플리케이션이 남긴 경로·파일명은 UTF-16LE로 저장되는 경우가 많다.

### 7단계 — 부분 복구 (잘린 파일 다루기)

카빙물이 최대 크기까지 잘려 왔거나 뒷부분이 덮인 경우다.

| 형식 | 부분 복구 방법 |
| --- | --- |
| ZIP / OOXML | 뒤에서 EOCD(`50 4B 05 06`)를 찾아 그 지점 + 22바이트에서 절단. 개별 파일은 local header(`50 4B 03 04`)마다 분리 가능 |
| PDF | 마지막 `%%EOF` 뒤를 잘라낸다. 앞쪽 `xref`가 깨졌으면 뷰어의 복구 기능에 맡긴다 |
| JPEG | `FF D9`까지 절단. 없으면 뷰어가 보여 주는 만큼이 전부 |
| PNG | `IEND` 청크까지. 청크 CRC는 `pngcheck`로 검증 |
| Office 구형(OLE) | 헤더 `D0 CF 11 E0`부터 최소 섹터 구조만 살아 있으면 텍스트 추출 가능 |
| 텍스트/로그 | 절단이 문제가 되지 않는다. 그대로 `strings` |

```bash
# ZIP 끝(EOCD)을 찾아 그 뒤를 잘라낸다
grep -abo $'\x50\x4b\x05\x06' carved/zip/00031002.zip | tail -1
# 출력이 1245140 이면
dd if=carved/zip/00031002.zip of=fixed.zip bs=1 count=$((1245140+22))
unzip -t fixed.zip

# 헤더 앞에 쓰레기가 붙은 경우 앞쪽을 잘라낸다
grep -abo $'\x50\x4b\x03\x04' broken.zip | head -1
dd if=broken.zip of=fixed.zip bs=1 skip=<첫 헤더 오프셋>
```

부분 복구물은 "일부만 복구했다"는 사실을 답안에 명시한다. 완전 복구를 주장하려면 다음 절의 검증을 전부 통과해야 한다.

## 출력 필드 해석

복구물 검증 4단계다. **네 개를 다 통과해야 복구다.**

| # | 검증 | 명령 | 통과 기준 |
| --- | --- | --- | --- |
| 1 | 크기 | `ls -l recovered.xlsx` | `$MFT`/`$I`의 `FileSize`와 정확히 일치 (카빙물은 클러스터 단위 오차 허용) |
| 2 | 헤더/푸터 | `xxd -l 16` / `tail -c 32 \| xxd` | 형식 매직 바이트가 앞뒤 모두 맞다 |
| 3 | 해시 | `md5sum` / `sha256sum` | 문제가 기준 해시를 줬다면 일치 |
| 4 | 열림 | 전용 도구로 실제 파싱 | 에러 없이 내용이 보인다 |

```bash
ls -l recovered.xlsx
xxd -l 16 recovered.xlsx            # 50 4b 03 04 = ZIP/OOXML
tail -c 32 recovered.xlsx | xxd     # 50 4b 05 06 = EOCD
md5sum recovered.xlsx
unzip -t recovered.xlsx             # ZIP 계열 무결성 검사
unzip -p recovered.xlsx docProps/core.xml   # 작성자·시각
```

| 관찰 | 해석 |
| --- | --- |
| 크기는 맞는데 헤더가 다르다 | 클러스터가 재할당됐다. 남의 데이터를 뽑았다 |
| 헤더는 맞고 크기가 더 크다 | 슬랙까지 포함됐거나 카빙이 최대 크기까지 긁었다 |
| 헤더는 맞고 크기가 작다 | 이미지가 잘렸거나 뒷부분 클러스터가 덮였다 |
| `unzip -t`가 일부 항목만 실패 | 부분 복구. 성공한 항목만 꺼낸다 (`unzip -p`) |
| 전부 통과 | 완전 복구. 해시를 기록해 둔다 |

**시각 처리.** `$I`의 삭제 시각, `$MFT`의 MACB, `$J`의 `UpdateTimestamp`는 모두 FILETIME이며 **1601-01-01 UTC 기준 100ns 단위**다. 파서는 보통 UTC로 출력한다. Unix epoch와의 차이는 `11644473600`초다.

```powershell
[datetime]::FromFileTimeUtc(133545600000000000).ToString('yyyy-MM-dd HH:mm:ss')
```

```bash
python3 -c "import datetime;print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=133545600000000000//10))"
```

KST 답이 필요하면 UTC에 **+9시간**. 반대로 복구된 파일의 파일시스템 타임스탬프(mtime)는 **추출 시각**이므로 절대 증거 시각으로 쓰지 않는다.

## pivot: 다음에 볼 artifact

| 얻은 것 | 다음 목표 |
| --- | --- |
| 원래 파일 이름 | Prefetch / LNK / RecentDocs / UserAssist ([FOR-0061](./userassist.html)) — 누가 열었나 |
| 삭제 시각 | 그 시각 ±5분의 `$J` 전체, EVTX 4688/4624 ([FOR-0083](./event-4624-logon.html)) |
| 휴지통 SID 폴더 | `SOFTWARE\...\ProfileList`로 사용자 이름 확정 |
| 복구한 문서 | 내부 메타데이터(작성자, 회사, 마지막 저장자) |
| 복구한 실행 파일 | 해시 → Amcache/Shimcache/Prefetch로 실행 여부 |
| 재할당된 클러스터 | `ifind -d`로 지금 그 클러스터를 가진 파일 → 덮어쓴 주체 |
| 복구 실패 | `$LogFile`(NTFS Log Tracker)로 삭제 트랜잭션 상세 |
| 다운로드였다면 | 브라우저 History/Downloads ([FOR-0191](./chrome-history.html)) |

## 흔한 함정

- **카빙부터 시작하는 것.** 이 글의 핵심이다. `$MFT` 레코드가 살아 있으면 `icat` 한 줄로 이름·크기·내용이 모두 정확하게 나온다. 카빙은 그것이 실패한 뒤의 수단이며, 이름과 시각을 영구히 잃는다.
- **`icat`이 파일을 냈다고 성공으로 판단하는 것.** 클러스터가 재할당됐으면 크기는 맞고 내용은 남의 것이다. **헤더까지 확인**해야 한다.
- **`InUse=False`를 "복구 가능"으로 읽는 것.** 레코드 생존과 데이터 생존은 별개다. `blkstat`/`ifind`로 클러스터를 확인한다.
- **`SequenceNumber`를 대조하지 않는 것.** `EntryNumber`가 같아도 `SequenceNumber`가 다르면 **완전히 다른 파일**이다. 재사용된 레코드를 원래 파일로 착각하는 사고가 잦다.
- **`fls`의 `128441-128-1` 표기에서 속성 ID를 무시하는 것.** ADS가 있는 파일은 속성이 여러 개다. 번호만 넣으면 기본 `$DATA`가 나오고, 정작 답이 ADS에 있으면 못 찾는다.
- **`$Recycle.Bin`에서 `$R`만 챙기는 것.** 원래 경로와 삭제 시각은 `$I`에만 있다. 반대로 `$I`만 보고 내용을 못 찾는 것도 같은 실수다.
- **휴지통이 비었으니 휴지통을 건너뛰는 것.** `$I`/`$R` 자체가 삭제된 상태로 남아 있을 수 있다. `fls -d`로 `$Recycle.Bin` 하위를 확인한다.
- **복구 파일의 mtime을 삭제/생성 시각으로 쓰는 것.** 추출 시각이다. 시각은 `$MFT`/`$I`/`$J`에서만 얻는다.
- **`strings`에서 `-el`(UTF-16LE)을 빼먹는 것.** Windows 경로·파일명·문서 내용이 UTF-16으로 저장된 경우 ASCII 검색으로는 안 걸린다.
- **원본 이미지를 쓰기 가능 상태로 마운트해 복구를 시도하는 것.** 비할당 영역이 갱신되어 아직 못 찾은 데이터가 파괴된다. 항상 `-o ro` 또는 읽기 전용 마운트다.
- **카빙 결과를 크기만 보고 특정하는 것.** 클러스터 단위 오차가 있으므로 내부 메타데이터(내부 파일명, 작성 시각)로 교차 확인한다.
- **부분 복구를 완전 복구로 제출하는 것.** `unzip -t`가 일부 실패하면 그 사실을 명시하고, 성공한 항목에서 답을 찾는다.
- **`$J`가 없으니 삭제 기록이 없다고 결론 내리는 것.** 저널은 순환되며 볼륨별로 꺼져 있을 수도 있다. "기록이 잘려 나갔다"와 "일어나지 않았다"는 다르다.

## 교차검증

```bash
# 1) 같은 파일을 세 경로로 뽑아 해시를 비교한다
icat -o 2048 image.raw 128441 > a.bin
icat -o 2048 -r image.raw 128441 > b.bin
# (FTK Imager 로 Export 한 결과를 c.bin 으로)
md5sum a.bin b.bin c.bin

# 2) 런리스트를 직접 읽어 dd 로 재조립 (icat 결과 검증)
istat -o 2048 image.raw 128441 | tail -20        # 클러스터 목록
dd if=image.raw bs=4096 skip=$((2048*512/4096 + 1180160)) count=304 of=manual.bin
# 주의: skip 은 이미지 시작 기준이므로 파티션 오프셋을 더해야 한다 (FOR-0048)

# 3) 클러스터 소유권 확인
blkstat -o 2048 image.raw 1180160
ifind -o 2048 -d 1180160 image.raw

# 4) 카빙 결과와 대조
blkls -o 2048 image.raw > unalloc.blkls
foremost -t zip -i unalloc.blkls -o carved && cat carved/audit.txt

# 5) 이름·시각을 다른 artifact로 확인
#    $J 의 FileDelete, $I 의 DeletedOn, $LogFile 의 트랜잭션이 같은 시각을 가리키는가
```

세 경로의 해시가 같으면 복구물을 신뢰할 수 있다. 다르면 `istat` 런리스트를 기준으로 판단한다.

## mini walkthrough

```text
문제:
"내부 재무 자료가 유출된 뒤 흔적을 지운 것으로 보입니다.
 삭제된 파일을 복구하고 그 안의 flag 를 제출하세요.
 휴지통은 이미 비워져 있습니다."
첨부: case.E01 (8 GB)

=== 0. 판 읽기 ===
$ ewfinfo case.E01 | head -12
Acquired: 2026-03-15 02:11:40
MD5 hash in file: 3f2a...  (검증 통과)

$ mkdir /mnt/ewf && ewfmount case.E01 /mnt/ewf
$ mmls /mnt/ewf/ewf1
DOS Partition Table / Units are in 512-byte sectors
002:  000:000   0000002048   0016777215   0016775168   NTFS / exFAT (0x07)

$ fsstat -o 2048 /mnt/ewf/ewf1 | grep -i 'type\|size'
File System Type: NTFS
Sector Size: 512
Cluster Size: 4096

오프셋 2048(섹터), 클러스터 4096 확정.

=== 1. 첫 시도 (실패 #1) — 순서를 거꾸로 밟았다 ===
$ foremost -t all -i /mnt/ewf/ewf1 -o carved
... 21분 후
$ tail -12 carved/audit.txt
5,417 FILES EXTRACTED
jpg:= 3102
zip:= 411
pdf:= 288
htm:= 964
...

$ find carved -name '*.zip' | wc -l
411

411개의 ZIP 중 어느 것이 "재무 자료"인가?
크기도 이름도 모르는 상태에서 411개를 열어 볼 수는 없다.
게다가 이미지 전체를 돌렸으므로 살아 있는 파일까지 섞였다.

무엇이 틀렸나:
  - 대상의 "이름"과 "크기"를 먼저 확정하지 않고 카빙부터 했다
  - 카빙은 판정 트리의 5번인데 2~4번을 건너뛰었다
  - $MFT 레코드가 살아 있었다면 icat 한 줄로 끝났을 일이다
카빙 결과는 버리지 않고 남겨 둔다. 나중에 특정에 쓴다.

=== 2. 휴지통 (판정 트리 1번) ===
$ fls -o 2048 -r -d -p /mnt/ewf/ewf1 | grep -i 'Recycle'
d/d 96612:  $Recycle.Bin/S-1-5-21-2103847-1001
-/r * 96790: $Recycle.Bin/S-1-5-21-2103847-1001/$IF3K1LM.pdf
-/r * 96791: $Recycle.Bin/S-1-5-21-2103847-1001/$RF3K1LM.pdf

$I/$R 한 쌍이 삭제된 상태로 남아 있다. 지문("비워져 있습니다")대로다.
$ icat -o 2048 -r /mnt/ewf/ewf1 96790 > I.bin
$ RBCmd.exe -f I.bin --csv .
  FileName: C:\Users\jhkim\Downloads\manual_v3.pdf   FileSize: 88214
  DeletedOn: 2026-03-13 05:02:11

manual_v3.pdf — 재무 자료가 아니다. 이 경로는 답이 아니다.
(하지만 이 사용자 SID 가 S-1-5-21-2103847-1001 임을 확보했다)

=== 3. $UsnJrnl (판정 트리 2번) ===
$ fls -o 2048 -r -p /mnt/ewf/ewf1 | grep -i 'UsnJrnl'
r/r 90-128-2:  $Extend/$UsnJrnl:$J
$ icat -o 2048 /mnt/ewf/ewf1 90-128-2 > J.bin
$ icat -o 2048 /mnt/ewf/ewf1 0 > MFT.bin

  (ADS 이므로 90-128-2 를 지정해야 한다. 90 만 주면 빈 파일이 나온다)

$ MFTECmd.exe -f J.bin -m MFT.bin --csv out --csvf usn.csv
-> 388,214 레코드

$ Import-Csv out\usn.csv |
    Where-Object { $_.UpdateReasons -match 'FileDelete' -and
                   $_.ParentPath -match 'jhkim' } |
    Select-Object Usn, UpdateTimestamp, FileName, EntryNumber, SequenceNumber |
    Sort-Object Usn

Usn        UpdateTimestamp        FileName              EntryNumber SequenceNumber
0x51a2100  2026-03-14 07:39:52Z   budget_2026Q1.xlsx    128441      7
0x51a2340  2026-03-14 07:40:03Z   ~$budget_2026Q1.xlsx  128442      3
0x51a4b80  2026-03-14 07:41:19Z   notes.txt             131002      2

budget_2026Q1.xlsx / 삭제 07:39:52 UTC (= 16:39:52 KST)
EntryNumber 128441, SequenceNumber 7.

여기서 얻은 이름과 레코드 번호가 1단계에서 필요했던 정보다.

=== 4. $MFT (판정 트리 3번) ===
$ MFTECmd.exe -f MFT.bin --csv out --csvf mft.csv
$ Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq 128441 } |
    Select-Object EntryNumber, SequenceNumber, InUse, FileName, FileSize

EntryNumber SequenceNumber InUse FileName            FileSize
128441      7              False budget_2026Q1.xlsx  1245184

InUse=False, SequenceNumber 7 이 $J 와 일치한다.
레코드가 살아 있다. FileSize = 1,245,184 (= 304 클러스터).
-> 판정 트리 4번으로

=== 5. 두 번째 시도 (실패 #2) — icat 은 성공했지만 내용이 남의 것 ===
$ icat -o 2048 /mnt/ewf/ewf1 128441 > recovered.xlsx
$ ls -l recovered.xlsx
-rw-r--r-- 1 user user 1245184 recovered.xlsx        <- 크기는 정확히 일치

$ file recovered.xlsx
recovered.xlsx: data                                  <- ???
$ xxd -l 16 recovered.xlsx
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR

PNG 다. xlsx(=ZIP, 50 4B 03 04)가 아니다.
크기가 맞았기 때문에 "성공"으로 착각하기 쉬운 지점이다.

원인 판정:
$ istat -o 2048 /mnt/ewf/ewf1 128441 | tail -8
Type: $DATA (128-1)  Non-Resident  size: 1245184  init_size: 1245184
1180160 1180161 1180162 1180163 1180164 1180165 1180166 1180167
...

$ blkstat -o 2048 /mnt/ewf/ewf1 1180160
Allocated
$ ifind -o 2048 -d 1180160 /mnt/ewf/ewf1
131521

클러스터 1180160 은 지금 레코드 131521 의 것이다.
$ Import-Csv out\mft.csv | Where-Object { $_.EntryNumber -eq 131521 } |
    Select-Object FileName, FileSize
FileName          FileSize
screenshot_02.png 1102336

삭제 후 저장된 PNG 가 그 클러스터를 재사용했다.
=> 레코드는 살아 있지만 데이터는 죽었다. 판정 트리 5번(카빙)으로.

=== 6. 접근 변경 — 비할당만, 크기와 이름으로 특정 ===
1단계의 411개 ZIP 이 이제는 쓸 수 있다. 특정 근거가 생겼다.
크기 1,245,184 (±1 클러스터 = ±4096) 인 후보만 본다.

$ find carved -name '*.zip' -size +1200k -size -1260k -ls
  ... 00204800.zip   1245184
  ... 00318442.zip   1249280

2개로 줄었다.
$ for f in carved/zip/00204800.zip carved/zip/00318442.zip; do
>   echo "== $f"; unzip -l "$f" | head -6; done
== carved/zip/00204800.zip
   [Content_Types].xml
   xl/workbook.xml
   xl/worksheets/sheet1.xml
   docProps/core.xml
== carved/zip/00318442.zip
   word/document.xml
   docProps/core.xml

첫 번째가 xl/ 구조 = xlsx 다. 두 번째는 docx.

$ unzip -p carved/zip/00204800.zip docProps/core.xml
<dc:creator>jhkim</dc:creator>
<dcterms:created xsi:type="dcterms:W3CDTF">2026-03-14T07:12:40Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2026-03-14T07:33:18Z</dcterms:modified>

modified 07:33:18Z 가 $MFT 의 File Modified 와 일치한다. 이 파일이다.

=== 7. 검증 4단계 ===
(1) 크기: 1,245,184 = $MFT FileSize 와 일치                    OK
(2) 헤더/푸터:
    $ xxd -l 4 carved/zip/00204800.zip
    00000000: 504b 0304                               PK..            OK
    $ tail -c 22 carved/zip/00204800.zip | xxd | head -1
    00000000: 504b 0506 0000 0000 ...                 PK.. (EOCD)     OK
(3) 무결성:
    $ unzip -t carved/zip/00204800.zip
    No errors detected in compressed data                            OK
(4) 열림:
    $ unzip -p carved/zip/00204800.zip xl/sharedStrings.xml | grep -o 'flag{[^}]*}'
    flag{c4rv3d_wh3n_clust3rs_w3r3_r34ll0c4t3d}                      OK

$ md5sum carved/zip/00204800.zip
e91c... (기록해 둔다)

=== 8. 사건 서술 ===
07:12:40Z  budget_2026Q1.xlsx 생성 (docProps)
07:33:18Z  마지막 저장 ($MFT File Modified 와 일치)
07:39:52Z  삭제 ($J FileDelete)                  = 16:39:52 KST
07:41:19Z  notes.txt 삭제 ($J)
이후       screenshot_02.png 이 같은 클러스터를 재사용 (ifind)

정답: flag{c4rv3d_wh3n_clust3rs_w3r3_r34ll0c4t3d}
      원래 이름 budget_2026Q1.xlsx, 삭제 2026-03-14 16:39:52 KST
```

두 실패가 각각 다른 교훈이다.

**실패 #1 — 순서를 건너뛰면 결과를 해석할 수 없다.** 411개의 ZIP은 정보가 아니라 잡음이었다. 같은 카빙 결과가 6단계에서는 3분 만에 답이 됐다. 달라진 것은 도구가 아니라 **`$J`와 `$MFT`에서 확보한 이름과 크기**다. 카빙은 "무엇을 찾는지 아는 상태"에서만 힘을 쓴다.

**실패 #2 — 크기가 맞아도 복구가 아니다.** `icat`은 런리스트대로 클러스터를 읽어 주므로 그 클러스터가 남의 것이 됐다면 남의 데이터를 정확한 크기로 준다. `file`/`xxd`로 헤더를 확인하고, `blkstat` + `ifind`로 재할당을 판정하는 두 줄이 이 함정을 막는다.

## 막혔을 때 다음 체크

1. 판정 트리의 **1번(휴지통)부터** 밟았는가 — 카빙부터 하지 않았는가
2. `$Recycle.Bin` 하위의 **삭제된** `$I`/`$R`까지 `fls -d`로 확인했는가
3. `$J`의 `FileDelete`에서 이름·`EntryNumber`·`SequenceNumber`를 확보했는가
4. `$J`에 `RenameOldName`이 있는가 — 위장된 이름을 쫓고 있지 않은가
5. `$MFT`의 `SequenceNumber`가 `$J`의 값과 **일치**하는가
6. `$MFT`의 `FileSize`를 적어 뒀는가 — 이후 모든 검증의 기준이다
7. `icat` 결과의 **헤더**를 확인했는가 (크기만 보고 판단하지 않았는가)
8. `istat`로 런리스트를 봤는가, `blkstat`/`ifind`로 재할당을 확인했는가
9. ADS가 있는 파일인가 → `fls` 표기의 `-128-2` 같은 속성 ID를 지정했는가
10. `icat -s`(슬랙 포함)로 뒷부분에 무엇이 붙어 있는지 봤는가
11. 카빙을 `blkls` **비할당 스트림**에 대해 했는가, 형식을 좁혔는가
12. 카빙 후보를 `$MFT`의 `FileSize`로 좁혔는가, 내부 메타데이터로 특정했는가
13. `strings -el`(UTF-16LE)을 시도했는가
14. `blkls -s`로 **슬랙만** 뽑아 문자열을 찾아봤는가
15. resident 파일인가 → `$MFT` 하나로 내용이 나온다 ([FOR-0021](./mft-basics.html))
16. 부분 복구물을 EOCD/`%%EOF`/`FF D9` 기준으로 절단해 봤는가
17. PhotoRec의 brute force로 조각화 재조립을 시도했는가 ([FOR-0047](./photorec.html))
18. 시각을 UTC로 통일했는가, KST 답에 +9시간을 적용했는가

## 출처

- SRC-005 — Microsoft Learn, Master File Table: 레코드 in-use 플래그와 삭제 시 레코드가 남는 동작, resident/non-resident `$DATA`
- SRC-013 — Microsoft Learn, Change Journals: `USN_REASON_FILE_DELETE`/`RENAME_OLD_NAME`과 `USN_RECORD`의 파일 참조(레코드 번호 + 시퀀스 번호) 구조
- SRC-032 — The Sleuth Kit 도구 문서: `fls -d`(삭제 항목), `icat -r`/`-s`, `레코드-속성타입-속성ID` 표기, `istat` 런리스트, `blkstat`(블록 할당 여부), `ifind -d`(블록 → 레코드), `blkls`
- SRC-035 — foremost 매뉴얼: 카빙 단계에서 쓴 `-t`/`-i`/`-o`와 `audit.txt`
- `$I` 파일의 버전별 레이아웃(구형 고정 544바이트 vs Windows 10 이후 가변 파일명)과 RBCmd/MFTECmd의 CSV 컬럼명은 버전에 따라 다를 수 있으므로 실제 출력에서 확인할 것
