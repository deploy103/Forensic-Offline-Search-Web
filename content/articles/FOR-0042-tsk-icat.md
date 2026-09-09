---
id: FOR-0042
title: "icat으로 파일 내용·ADS·삭제 파일 추출"
slug: "tsk-icat"
category: "디스크/NTFS"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [linux, windows]
artifact: ["metadata address", "$DATA", "alternate data stream", "Zone.Identifier", "file slack", "deleted file"]
file_paths: ["setup.exe:Zone.Identifier", "$Extend\\$UsnJrnl:$J"]
registry_paths: []
event_ids: []
protocols: []
tools: ["Sleuth Kit", "icat", "istat", "fls", "tsk_recover", "file", "strings", "md5sum", "xxd"]
commands: ["icat -o 2048 image.dd 9188", "icat -o 2048 image.dd 9188-128-5", "icat -o 2048 -r image.dd 9188", "icat -o 2048 -s image.dd 9188", "istat -o 2048 image.dd 9188", "icat -o 2048 image.dd 0 > MFT.bin", "tsk_recover -o 2048 image.dd out/"]
regex_patterns: ["[0-9]+-[0-9]+-[0-9]+"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Type", "Resident", "Non-Resident", "size", "init_size"]
file_formats: ["ntfs", "raw", "dd", "e01"]
primary_terms: ["icat"]
keywords: ["icat", "Sleuth Kit", "파일 추출", "ADS", "alternate data stream", "Zone.Identifier", "slack", "메타주소", "속성 ID", "삭제 파일 복구", "tsk_recover"]
aliases: ["icat", "icat 사용법", "이미지에서 파일 꺼내기", "삭제 파일 복구 icat", "ads 추출", "슬랙 추출", "$MFT 뽑기", "icat 결과가 이상하다"]
symptom_keywords: ["이미지에서 파일 하나만 꺼내고 싶다", "icat 결과가 깨져 나온다", "숨은 데이터 스트림을 추출하고 싶다", "삭제 파일 내용이 필요하다", "슬랙 공간을 보고 싶다", "파일을 한꺼번에 다 뽑고 싶다"]
related: ["FOR-0041", "FOR-0045", "FOR-0021"]
source_ids: ["SRC-032", "SRC-005", "SRC-081"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`icat -o <오프셋> image.dd <메타주소>`는 지정한 파일의 내용을 표준출력으로 뱉으므로 반드시 리다이렉트해서 받고, ADS나 특정 속성을 노릴 때는 `fls`가 보여 준 `<주소>-<속성타입>-<ID>` 세 토막 주소를 그대로 넣는다.

## 어떤 문제에서 필요한가

- 이미지 전체를 마운트하지 않고 **파일 하나만** 꺼내야 하는 경우
- `$MFT`, `$LogFile`, `$UsnJrnl:$J`, EVTX, 레지스트리 hive 등 **잠긴 시스템 파일**을 꺼내야 하는 경우
- 삭제된 파일의 내용을 복구해야 하는 경우
- **ADS(대체 데이터 스트림)** 에 숨긴 데이터를 꺼내야 하는 경우
- 파일 슬랙에 남은 잔여 데이터를 봐야 하는 경우
- 목록에서 골라낸 수십~수백 개를 스크립트로 일괄 추출해야 하는 경우

## 문제에서 처음 볼 단서

1. `fls` 출력에 목표 파일의 메타주소가 보인다 → 바로 `icat` ([FOR-0041](./tsk-fls.html))
2. 같은 메타주소에 속성 ID가 다른 줄이 두 개 있다 → **ADS 문제다**
3. 파일 이름에 `:`가 들어 있다 (`notes.txt:hidden`) → ADS
4. 삭제 항목인데 `(realloc)` 표시가 있다 → 내용 복구 기대치 낮음. 카빙 준비 ([FOR-0045](./carving-strategy.html))
5. `istat`에서 `$DATA`가 `Resident`다 → 레코드 안에 내용이 있어 추출이 거의 확실하다

## 30초 절차

```bash
icat -o 2048 image.dd 9188 > out.bin
```

```bash
fls -o 2048 -r -p image.dd | grep -i 'flag'      # 1) 주소 찾기
istat -o 2048 image.dd 9188                      # 2) 속성·크기 확인
icat -o 2048 image.dd 9188 > out.bin             # 3) 추출
file out.bin && md5sum out.bin && xxd -l 32 out.bin   # 4) 검증
```

**리다이렉트를 잊으면 바이너리가 터미널을 망가뜨린다.** 실수했으면 `reset`으로 되돌린다.

## 상세 절차

### 1단계 — 인자 형식: 메타주소의 세 가지 형태

| 형태 | 의미 | 예 |
| --- | --- | --- |
| `<주소>` | 기본 `$DATA` 스트림 | `icat -o 2048 image.dd 9188` |
| `<주소>-<속성타입>` | 속성 타입 지정 | `icat -o 2048 image.dd 9188-128` |
| `<주소>-<속성타입>-<ID>` | 같은 타입이 여러 개일 때 ID까지 지정 | `icat -o 2048 image.dd 9188-128-5` |

`fls`/`istat`의 출력이 이미 이 형식이므로 **복붙하면 된다.**

자주 쓰는 속성 타입 번호:

| 10진 | 16진 | 속성 | 의미 |
| --- | --- | --- | --- |
| `16` | `0x10` | `$STANDARD_INFORMATION` | MACB 타임스탬프 |
| `48` | `0x30` | `$FILE_NAME` | 이름 + 두 번째 MACB 세트 |
| `128` | `0x80` | **`$DATA`** | 실제 내용. **ADS도 여기 들어간다** |
| `144` | `0x90` | `$INDEX_ROOT` | 디렉터리 색인 |
| `160` | `0xA0` | `$INDEX_ALLOCATION` | 디렉터리 색인(비상주) |

NTFS 파일시스템 메타파일도 같은 방식으로 꺼낸다.

```bash
icat -o 2048 image.dd 0  > MFT.bin        # $MFT
icat -o 2048 image.dd 2  > LogFile.bin    # $LogFile
icat -o 2048 image.dd 6  > Bitmap.bin     # $Bitmap
icat -o 2048 image.dd 7  > Boot.bin       # $Boot (부트섹터)
```

`$UsnJrnl`의 `$J`는 `$Extend\$UsnJrnl`의 ADS다. `fls`로 주소와 속성 ID를 먼저 확인하고 세 토막 주소로 꺼낸다 ([FOR-0027](./usnjrnl-basics.html)).

```bash
fls -o 2048 -r -p image.dd | grep -i 'UsnJrnl'
# r/r 42-128-2:   $Extend/$UsnJrnl:$Max
# r/r 42-128-4:   $Extend/$UsnJrnl:$J
icat -o 2048 image.dd 42-128-4 > UsnJrnl_J.bin
```

`$J`는 앞부분이 sparse(0으로 채워진 구멍)라 파일 크기가 매우 크게 나온다. 실제 내용만 필요하면 뒤에서 다룰 `-h`를 고려한다.

### 2단계 — 옵션 전체

| 옵션 | 의미 | 실전 용도 |
| --- | --- | --- |
| `-o offset` | 파일시스템 시작 **섹터** 오프셋 | `mmls`의 `Start` |
| `-s` | **슬랙 공간을 출력에 포함** | 파일 끝 잔여 데이터 확인 |
| `-r` | 파일이 삭제된 경우 **복구 기법 사용** | 삭제 파일 추출 시 |
| `-h` | sparse 파일의 구멍을 건너뛴다 (절대 위치 정보가 사라진다) | `$J`처럼 앞이 비어 있는 거대 파일 |
| `-f fstype` | 파일시스템 타입 강제. `-f list` | 자동탐지 실패 시 |
| `-i imgtype` | 이미지 형식 강제. `-i list` | E01/split |
| `-b size` | 하부 장치 섹터 크기 | 4Kn = `4096` |
| `-v` / `-V` | 디버그 출력 / 버전 | 진단 |

`-s`와 `-h`의 차이를 헷갈리지 않는다.

| 옵션 | 출력 크기 | 쓰는 상황 |
| --- | --- | --- |
| (없음) | 논리 크기 그대로 | 정상 추출. **해시 비교는 이 상태로 한다** |
| `-s` | 논리 크기 + 슬랙 | 파일 끝에 이전 파일의 잔재가 있는지 볼 때 |
| `-h` | 구멍을 뺀 크기 | sparse 파일의 실제 데이터만 |

```bash
# 슬랙에 다른 파일의 흔적이 있는지
icat -o 2048 image.dd 9188 > logical.bin
icat -o 2048 -s image.dd 9188 > with_slack.bin
ls -l logical.bin with_slack.bin
cmp -l logical.bin with_slack.bin | head          # 차이가 시작되는 지점 = 슬랙 시작
strings -n 6 with_slack.bin | tail -20            # 슬랙 쪽 문자열
```

### 3단계 — fls → istat → icat 워크플로

```bash
IMG=image.dd; OFF=2048

# 1) 목록에서 후보 찾기
fls -o $OFF -r -p $IMG | grep -iE 'flag|secret|password'

# 2) 주소 확정 후 속성 구조 확인 (이 단계를 건너뛰면 ADS 를 놓친다)
istat -o $OFF $IMG 9188

# 3) 추출
icat -o $OFF $IMG 9188 > out.bin

# 4) 검증
file out.bin
ls -l out.bin
md5sum out.bin
xxd -l 32 out.bin
strings -n 6 out.bin | head
```

`istat` 출력에서 확인할 것:

| 보이는 것 | 의미 |
| --- | --- |
| `$DATA ... Resident` | 내용이 MFT 레코드 안에 있다. **삭제되어도 추출 성공 가능성이 높다** |
| `$DATA ... Non-Resident` + data run 목록 | 클러스터에 있다. 그 클러스터가 재할당되지 않았는지가 관건 |
| `$DATA`가 **두 개 이상** | ADS 존재. 각각의 `(128-N)` ID를 확인한다 |
| `size` vs `init_size` | 초기화된 크기가 더 작으면 뒷부분은 0으로 읽힌다 |
| `Flags: Compressed` / `Sparse` | 압축·희소 파일. TSK 처리 결과를 반드시 `file`로 검증 |

### 4단계 — ADS 추출

`fls`는 ADS를 같은 메타주소의 다른 속성 ID로 보여 준다.

```text
$ fls -o 2048 -r -p image.dd | grep -i 'notes.txt'
r/r 49-128-1:   Users/kim/notes.txt
r/r 49-128-5:   Users/kim/notes.txt:hidden
```

```bash
icat -o 2048 image.dd 49        > notes.txt        # 기본 스트림 (= 49-128-1)
icat -o 2048 image.dd 49-128-5  > hidden.bin       # ADS
file hidden.bin
```

**메타주소만 주면 항상 기본 `$DATA` 스트림이 나온다.** ADS를 꺼내려면 세 토막 주소가 필수다.

실전에서 자주 만나는 ADS:

| 스트림 | 내용 | 포렌식 의미 |
| --- | --- | --- |
| `<파일>:Zone.Identifier` | `[ZoneTransfer]` 섹션의 `ZoneId` | `ZoneId=3` = 인터넷에서 다운로드됨. `HostUrl`/`ReferrerUrl`이 있으면 출처까지 나온다 |
| `<파일>:SmartScreen` | SmartScreen 판정 결과 | 실행 파일 다운로드 흔적 |
| 임의 이름 스트림 | 사용자가 숨긴 데이터 | **CTF의 전형적인 은닉 위치** |

```bash
# 다운로드 출처 확인
fls -o 2048 -r -p image.dd | grep -i 'Zone.Identifier'
# r/r 8123-128-3:  Users/kim/Downloads/setup.exe:Zone.Identifier
icat -o 2048 image.dd 8123-128-3
```

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.org/download
HostUrl=https://cdn.example.org/setup.exe
```

Zone.Identifier가 붙은 파일은 브라우저 다운로드 기록과 대조한다 ([FOR-0191](./chrome-history.html)).

ADS 후보를 한 번에 훑는 방법:

```bash
# 이름에 콜론이 있는 항목 = ADS
fls -o 2048 -r -p image.dd | grep ':.*:' | grep -v '^d'

# 같은 메타주소가 두 번 이상 나오는 항목 = 스트림이 여러 개
fls -o 2048 -r -p image.dd | grep -oE '^[a-z-]/[a-z-] \*? *[0-9]+' \
  | grep -oE '[0-9]+$' | sort | uniq -d
```

### 5단계 — 삭제 파일 추출과 그 한계

```bash
fls -o 2048 -r -p -d image.dd | grep -i '\.docx$'
# -/r * 9188-128-1:  Users/kim/Documents/report.docx

icat -o 2048 -r image.dd 9188 > recovered.docx
file recovered.docx
```

`-r`은 "파일이 삭제된 경우 복구 기법을 사용한다"는 옵션이다. **성공을 보장하지 않는다.**

| 삭제 파일의 상태 | 추출 결과 | 대응 |
| --- | --- | --- |
| resident (약 700바이트 이하) | 거의 항상 정상 | 그대로 사용 |
| non-resident, 클러스터 미재할당 | 정상 | 해시·`file`로 검증 |
| non-resident, **클러스터 일부 재할당** | 앞부분만 맞고 뒤가 다른 파일 내용 | 헤더는 살아 있으니 카빙과 병행 |
| non-resident, 전부 재할당 | 전혀 다른 데이터 또는 0 | 카빙으로 전환 ([FOR-0045](./carving-strategy.html)) |
| `(realloc)` 표시 | 메타데이터부터 다른 파일의 것 | 이름만 증거로 쓰고 내용은 카빙 |
| data run이 없다 | 크기 0 또는 파서가 못 읽음 | `istat`으로 확인, `$MFT` resident 여부 재확인 ([FOR-0021](./mft-basics.html)) |

**추출했다고 복구된 것이 아니다.** 반드시 다음을 확인한다.

```bash
# 1) 형식이 맞는가
file recovered.docx

# 2) 크기가 fls/istat 의 논리 크기와 같은가
ls -l recovered.docx
istat -o 2048 image.dd 9188 | grep -i size

# 3) 헤더 매직이 맞는가
xxd -l 8 recovered.docx        # docx 라면 50 4B 03 04 (PK..)

# 4) 실제로 열리는가 (형식별 구조 검사)
unzip -t recovered.docx        # OOXML 은 ZIP
```

`file`이 `data`라고 하거나 헤더 매직이 안 맞으면 그 추출은 실패다. 시간을 더 쓰지 말고 카빙으로 넘어간다.

### 6단계 — 대량 추출 스크립트

목록에서 골라낸 항목을 한꺼번에 뽑는다.

```bash
#!/bin/bash
IMG=image.dd; OFF=2048; OUT=extracted
mkdir -p "$OUT"

# 삭제된 문서·이미지만 추출한다
fls -o "$OFF" -r -p -d "$IMG" \
  | grep -iE '\.(docx|xlsx|pdf|jpg|png|zip|txt)$' \
  | while IFS= read -r line; do
      addr=$(printf '%s' "$line" | grep -oE '[0-9]+-[0-9]+-[0-9]+' | head -1)
      name=$(printf '%s' "$line" | awk -F'\t' '{print $2}' | tr '/' '_')
      [ -z "$addr" ] && continue
      [ -z "$name" ] && name="unknown"
      icat -o "$OFF" -r "$IMG" "$addr" > "$OUT/${addr}__${name}" 2>/dev/null
    done

# 결과 요약
for f in "$OUT"/*; do printf '%-40s %8s  %s\n' \
  "$(basename "$f")" "$(stat -c%s "$f")" "$(file -b "$f" | cut -c1-40)"; done
```

| 스크립트의 포인트 | 이유 |
| --- | --- |
| 주소를 `grep -oE`로 뽑는다 | 삭제 항목의 `*`가 컬럼을 밀어 `awk '{print $2}'`가 틀린다 |
| 파일명에 주소를 접두로 붙인다 | 같은 이름이 여러 개 나와도 덮어쓰지 않는다 |
| 경로의 `/`를 `_`로 치환 | 하위 디렉터리 생성 없이 평평하게 저장 |
| `2>/dev/null` | 복구 불가 항목의 에러로 루프가 지저분해지는 것을 막는다 |
| 마지막에 `file`로 일괄 검증 | **`data`나 크기 0인 것은 실패한 추출이다** |

`fls` 출력에서 주소와 이름 사이는 탭이다. 구현·버전에 따라 다를 수 있으니 한 번 확인한다.

```bash
fls -o 2048 -r -p -d image.dd | head -3 | cat -A
```

전체를 한 번에 복구하려면 `tsk_recover`가 더 간단하다.

```bash
tsk_recover -o 2048 image.dd out/          # 기본: 비할당(삭제) 파일 복구
tsk_recover -o 2048 -a image.dd out_alloc/ # 할당된 파일만
tsk_recover -o 2048 -e image.dd out_all/   # 전부
```

단 `tsk_recover`는 **기본 `$DATA` 스트림만** 처리한다. ADS가 목표라면 `icat`을 직접 써야 한다.

## 출력 필드 해석

`icat`은 필드가 없는 도구다. 판단은 **추출된 바이트**로 한다.

| 확인 | 명령 | 정상 판정 |
| --- | --- | --- |
| 형식 | `file out.bin` | 기대한 형식 이름이 나온다 |
| 헤더 매직 | `xxd -l 16 out.bin` | `50 4B 03 04`(ZIP/OOXML), `FF D8 FF`(JPEG), `89 50 4E 47`(PNG), `25 50 44 46`(PDF), `4D 5A`(PE) ([FOR-0001](./30sec-triage.html)) |
| 크기 | `ls -l` vs `istat`의 `size` | 일치 |
| 내용 | `strings -n 6 out.bin \| head` | 의미 있는 문자열 |
| UTF-16 문자열 | `strings -el out.bin \| head` | Windows 문서·레지스트리 |
| 무결성 | `md5sum` / `sha256sum` | 문제에서 준 해시와 대조 |
| 크기 0 | `ls -l` | **추출 실패다.** `istat`으로 원인 확인 |

## pivot: 다음에 볼 artifact

| icat으로 얻은 것 | 다음 목표 |
| --- | --- |
| `$MFT` (주소 0) | MFTECmd / analyzeMFT로 전체 파일 타임라인 ([FOR-0021](./mft-basics.html)) |
| `$UsnJrnl:$J` | 삭제·이름변경 이력 ([FOR-0027](./usnjrnl-basics.html)) |
| `Zone.Identifier` ADS | 다운로드 출처 URL → 브라우저 기록 ([FOR-0191](./chrome-history.html)) |
| EVTX 파일 | EvtxECmd → 로그온 분석 ([FOR-0083](./event-4624-logon.html)) |
| 레지스트리 hive | RegistryExplorer / RegRipper ([FOR-0061](./userassist.html)) |
| 추출 실패(`data`, 크기 0) | 카빙 전략 재수립 ([FOR-0045](./carving-strategy.html)) |
| 슬랙에서 나온 문자열 | 이전 파일의 잔재 → 카빙 대상 확정 |
| 추출한 ZIP/문서 | 내부 재귀 확인(`7z l`, `binwalk`) |
| 크기·형식이 이상하다 | `istat`으로 속성·data run 재확인 |

## 흔한 함정

- **리다이렉트를 잊는 것.** `icat`은 표준출력으로 바이너리를 쏟는다. 터미널이 깨지면 `reset`. → 항상 `> 파일`을 붙인다.
- **메타주소만 주고 ADS를 놓치는 것.** 주소만 주면 기본 `$DATA`만 나온다. `fls`에서 같은 주소의 다른 속성 ID가 있는지 반드시 확인한다. **CTF에서 가장 자주 놓치는 지점이다.**
- **추출 성공을 복구 성공으로 착각하는 것.** `icat`은 에러 없이 쓰레기를 뱉을 수 있다. → `file` + 헤더 매직 + 크기 비교 세 개를 항상 돌린다.
- **`-r`이 마법이라고 믿는 것.** 클러스터가 재할당되었으면 무슨 옵션을 줘도 원본은 없다. `(realloc)` 표시를 보면 즉시 카빙으로 전환한다.
- **`-s`로 뽑은 파일을 해시 비교에 쓰는 것.** 슬랙이 붙어 크기와 해시가 원본과 달라진다. → 해시는 옵션 없이 뽑은 것으로 비교한다.
- **`-b`(섹터 크기)와 `-i`(이미지 형식)를 `mmls`에만 주는 것.** TSK는 명령마다 독립이다. 4Kn·E01이면 `icat`에도 같이 준다 ([FOR-0040](./tsk-mmls.html)).
- **`awk '{print $2}'`로 주소를 뽑아 루프를 돌리는 것.** 삭제 항목의 `*` 때문에 `*`가 주소 자리에 들어가 전부 실패한다.
- **크기 0으로 나온 결과를 "빈 파일"로 결론 내는 것.** resident 파일을 파서가 못 읽었거나 오프셋이 틀린 경우가 많다. `istat`으로 속성을 직접 본다.
- **sparse 파일(`$J` 등)을 그대로 받아 디스크를 채우는 것.** 논리 크기가 수십 GB일 수 있다. `istat`으로 크기를 먼저 확인하고 `-h`를 고려한다.
- **압축(Compressed) NTFS 파일의 추출 결과를 검증 없이 쓰는 것.** 처리 결과가 형식에 맞는지 `file`로 확인한다.
- **대량 추출에서 파일명 충돌을 방치하는 것.** 같은 이름이 여러 경로에 있으면 서로 덮어쓴다. → 주소를 파일명 접두로 붙인다.
- **`tsk_recover`로 ADS까지 나왔다고 가정하는 것.** 기본 스트림만 처리한다.

## 교차검증

```bash
# 1) 논리 크기 일치 확인
istat -o 2048 image.dd 9188 | grep -iE 'size|resident'
ls -l out.bin

# 2) 형식·매직 확인
file out.bin
xxd -l 16 out.bin

# 3) 같은 파일을 다른 경로로 꺼내 비교
#    (Arsenal 로 마운트한 볼륨에서 일반 복사한 것과 해시 대조)
md5sum out.bin
md5sum /mnt/case/Users/kim/Documents/report.docx

# 4) 슬랙 포함 여부에 따른 차이
icat -o 2048    image.dd 9188 | wc -c
icat -o 2048 -s image.dd 9188 | wc -c

# 5) 스트림이 몇 개인지 두 방법으로
istat -o 2048 image.dd 49 | grep -c 'DATA'
fls -o 2048 -r -p image.dd | grep -c '49-128-'
```

`icat` 결과와 마운트 후 일반 복사본의 해시가 같으면 추출 경로가 검증된 것이다 ([FOR-0017](./arsenal-image-mounter.html)).

## mini walkthrough

```text
문제:
"사용자의 메모 파일에 아무것도 없어 보입니다. 숨겨진 내용을 찾으세요."
첨부: ws01.dd (10 GB)

1. 오프셋과 목록
   $ mmls -a ws01.dd
   002:  000:000   0000206848   0020971519   0020764672   NTFS / exFAT (0x07)
   $ fsstat -o 206848 ws01.dd | head -3
   File System Type: NTFS
   -> 오프셋 확정

   $ fls -o 206848 -r -p ws01.dd | grep -i 'notes'
   r/r 49-128-1:   Users/kim/Documents/notes.txt
   r/r 49-128-5:   Users/kim/Documents/notes.txt:hidden

2. 첫 시도 (실패):
   $ icat -o 206848 ws01.dd 49 > notes.txt
   $ cat notes.txt
   회의 일정 정리
   - 월: 주간보고
   - 수: 코드리뷰

   평범한 메모다. 여기서 "이 파일은 관계없다"고 판단하고
   다른 파일을 뒤지기 시작했다.  -> 30분을 버렸다.

3. 왜 틀렸나
   fls 출력에 같은 메타주소 49 가 두 줄 있었다.
     49-128-1  기본 $DATA
     49-128-5  두 번째 $DATA  = ADS
   icat 에 주소(49)만 주면 항상 기본 스트림만 나온다.

4. 접근 변경 — istat 으로 속성 구조를 먼저 본다
   $ istat -o 206848 ws01.dd 49
   MFT Entry Header Values:
   Entry: 49        Sequence: 2
   ...
   Attributes:
   Type: $STANDARD_INFORMATION (16-0)   Resident   size: 72
   Type: $FILE_NAME (48-2)              Resident   size: 90
   Type: $DATA (128-1)                  Resident   size: 61
   Type: $DATA (128-5)   Name: hidden   Non-Resident  size: 4096

   -> $DATA 가 두 개. 두 번째가 4096바이트다.

5. ADS 추출
   $ icat -o 206848 ws01.dd 49-128-5 > hidden.bin
   $ file hidden.bin
   hidden.bin: PNG image data, 320 x 96, 8-bit/color RGBA, non-interlaced
   $ xxd -l 8 hidden.bin
   00000000: 8950 4e47 0d0a 1a0a                      .PNG....

   -> 메모 파일 뒤에 PNG 를 숨겨 두었다.
   $ cp hidden.bin hidden.png    # 열어 보면 플래그 이미지

6. 같은 방법으로 다른 은닉도 훑는다
   $ fls -o 206848 -r -p ws01.dd | grep ':.*:'
   r/r 8123-128-3:  Users/kim/Downloads/setup.exe:Zone.Identifier

   $ icat -o 206848 ws01.dd 8123-128-3
   [ZoneTransfer]
   ZoneId=3
   HostUrl=https://cdn.example.org/setup.exe
   -> setup.exe 는 인터넷 다운로드. 출처 URL 확보 (부가 점수)

7. 검증
   $ md5sum hidden.bin
   $ ls -l hidden.bin        # 4096 = istat 의 size 와 일치

정답: hidden.png 안의 flag{4ds_1s_th3_r34l_str34m}
```

핵심은 2→4단계다. **`icat`에 주소만 주면 기본 스트림만 나온다.** `fls`에서 같은 주소가 두 번 보이거나 이름에 `:`가 있으면 무조건 `istat`으로 속성 목록을 먼저 확인한다.

## 막혔을 때 다음 체크

1. 리다이렉트(`> 파일`)를 했는가
2. `-o` 값이 `fsstat`으로 검증된 값인가 ([FOR-0043](./tsk-fsstat.html))
3. 4Kn·E01이면 `-b` / `-i`를 `icat`에도 주었는가
4. `istat`으로 속성 목록을 확인했는가 — `$DATA`가 몇 개인가
5. 같은 메타주소에 속성 ID가 다른 줄이 있는가 → ADS를 세 토막 주소로 추출
6. 이름에 `:`가 포함된 항목을 전부 훑었는가
7. `file`과 헤더 매직으로 형식을 검증했는가
8. 크기가 `istat`의 논리 크기와 일치하는가
9. 크기 0이 나왔다면 resident 여부와 오프셋을 재확인했는가
10. 삭제 파일이면 `-r`을 주었는가, 그리고 `(realloc)` 표시가 없었는가
11. 파일 끝 잔재를 봐야 하면 `-s`를 시도했는가
12. sparse 파일이면 논리 크기를 먼저 확인했는가 (`-h` 고려)
13. 추출이 계속 실패하면 카빙으로 전환할 시점인가 ([FOR-0045](./carving-strategy.html))
14. 대량 추출에서 파일명이 서로 덮어쓰이지 않았는가

## 출처

- SRC-032 — The Sleuth Kit 도구 문서(icat / istat / fls man page): `-h` "sparse 파일의 구멍을 건너뛴다", `-r` "파일이 삭제된 경우 복구 기법 사용", `-s` "슬랙 공간을 출력에 포함", `-o`가 섹터 단위라는 정의
- SRC-005 — Microsoft Learn, Master File Table: 속성 타입 번호(`0x10`/`0x30`/`0x80`/`0x90`)와 resident / non-resident `$DATA`의 의미
- SRC-081 — Microsoft Learn, File Streams / Alternate Data Streams: 하나의 파일이 여러 `$DATA` 스트림을 가질 수 있다는 정의와 `파일명:스트림명` 표기, `Zone.Identifier`의 존재
- `<주소>-<속성타입>-<ID>` 형태의 메타주소 지정은 man page가 명시하지 않지만 `fls`/`istat` 출력이 그 형식이며 모든 TSK 도구가 받아들인다. 실제 이미지에서 `istat`으로 속성 ID를 확인한 뒤 사용할 것
- `tsk_recover`의 옵션과 ADS 처리 범위는 버전에 따라 다를 수 있으므로 `tsk_recover -V`와 도움말로 확인할 것
