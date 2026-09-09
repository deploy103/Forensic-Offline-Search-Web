---
id: FOR-0010
title: "해시로 분석 전후 무결성 확인 (MD5/SHA1/SHA256)"
slug: "hash-integrity"
category: "트리아지"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["E01 digest", "acquisition log", "hash manifest"]
file_paths: ["C:\\case\\original", "C:\\case\\work", "C:\\case\\notes\\hash_before.txt"]
registry_paths: []
event_ids: []
protocols: []
tools: ["HashCalc", "FTK Imager", "certutil", "Get-FileHash", "sha256sum", "md5sum", "ewfverify", "ewfinfo"]
commands: ["sha256sum evidence.dd", "certutil -hashfile evidence.dd SHA256", "Get-FileHash .\\evidence.dd -Algorithm SHA256", "ewfverify evidence.E01"]
regex_patterns: ["^[a-fA-F0-9]{32}$", "^[a-fA-F0-9]{40}$", "^[a-fA-F0-9]{64}$"]
wireshark_filters: []
tshark_fields: []
log_fields: ["Hash", "Algorithm", "Path", "MD5", "SHA1", "SHA256"]
file_formats: ["e01", "raw", "txt", "csv"]
primary_terms: ["해시 무결성", "분석 전후 해시", "무결성 검증"]
keywords: ["해시", "hash", "MD5", "SHA1", "SHA256", "무결성", "integrity", "Get-FileHash", "certutil", "sha256sum", "HashCalc", "ewfverify", "E01 verify", "해시 대조"]
aliases: ["해시 무결성", "분석 전후 해시", "무결성 검증", "해시 계산 방법", "해시 다름", "get-filehash", "certutil 해시", "e01 검증"]
symptom_keywords: ["해시가 달라졌다", "원본이 변경된 것 같다", "무결성을 어떻게 증명하나", "E01 검증이 실패한다", "해시를 어떻게 계산하나", "추출한 파일이 원본과 같은지 모르겠다"]
related: ["FOR-0011", "FOR-0016", "FOR-0017", "FOR-0001"]
source_ids: ["SRC-078", "SRC-007"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

분석을 시작하기 전에 원본 파일의 SHA-256을 계산해 케이스 폴더 밖에 기록하고, **작업은 사본에서만 하고**, 분석이 끝난 뒤 원본을 다시 계산해 그 값과 문자 단위로 일치하는지 확인한다. 해시는 "원본을 안 건드렸다"는 유일한 증명 수단이다.

## 어떤 문제에서 필요한가

- 디스크 이미지·메모리 덤프를 받아 분석을 시작할 때 (항상)
- 문제가 파일의 해시값 자체를 답으로 요구할 때
- 이미지에서 파일을 추출(export)했는데 그 추출물이 원본과 같은지 확인해야 할 때
- 마운트했던 이미지가 변경되지 않았는지 확인해야 할 때
- 여러 첨부 중 같은 파일이 중복으로 들어 있는지 확인할 때
- 제출한 답이 틀렸는데 "내가 분석한 파일이 원본과 다른가?"를 배제해야 할 때

## 문제에서 처음 볼 단서

1. 첨부와 함께 온 `*.txt`, `*.md5`, `hashes.txt`, `readme` — **취득 시 계산된 해시가 들어 있다**
2. 이미지가 `.E01`이면 해시가 **파일 내부에 저장되어 있다**
3. 문제 지문에 `MD5`, `SHA-256`, `무결성`, `해시값을 제출` 같은 단어
4. 답으로 요구하는 문자열 길이 — 32자면 MD5, 40자면 SHA-1, 64자면 SHA-256
5. 첨부 파일 크기가 어중간하게 잘려 있는가 — 다운로드 중단이면 해시부터 안 맞는다

## 30초 절차

```bash
sha256sum evidence.dd | tee ~/case_notes/hash_before.txt
```

```powershell
# Windows. 결과를 케이스 폴더 "밖"에 기록한다
Get-FileHash .\evidence.dd -Algorithm SHA256 |
  Select-Object Algorithm, Hash, Path |
  Tee-Object -FilePath D:\notes\hash_before.txt
```

E01이면 파일 해시가 아니라 **내장 해시 검증**을 돌린다.

```bash
ewfverify evidence.E01
```

## 상세 절차

### 1단계 — 해시 알고리즘 선택

| 알고리즘 | 출력 길이 | hex 문자 수 | 포렌식에서의 용도 |
| --- | --- | --- | --- |
| MD5 | 128비트 | 32 | 레거시 해시셋 대조, 중복 파일 식별 **전용** |
| SHA-1 | 160비트 | 40 | 구형 도구 호환(Amcache의 파일 SHA-1 등) |
| SHA-256 | 256비트 | 64 | **무결성 증명의 기본값** |
| SHA-512 | 512비트 | 128 | 필요할 때만. 대용량에서 SHA-256보다 빠른 경우도 있다 |

원칙은 두 줄이다.

```text
무결성을 "증명"할 때        -> SHA-256 (또는 SHA-256 + MD5 병기)
파일을 "식별/대조"할 때만   -> MD5 도 무방 (해시셋, 중복 제거)
```

빈 파일의 해시는 외워 두면 즉시 사고를 잡는다. 복사 실패·0바이트 추출을 한눈에 알 수 있다.

| 대상 | MD5 | SHA-256 |
| --- | --- | --- |
| 0바이트 파일 | `d41d8cd98f00b204e9800998ecf8427e` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

### 2단계 — 계산 방법 4가지

| 방법 | 환경 | 명령/조작 | 특징 |
| --- | --- | --- | --- |
| HashCalc | Windows GUI | 파일 선택 → 알고리즘 체크 → Calculate | 여러 알고리즘 동시 계산. 파일 하나씩 |
| `Get-FileHash` | PowerShell | `Get-FileHash <path> -Algorithm SHA256` | 파이프라인·재귀·CSV에 강하다. 기본값 SHA-256 |
| `certutil -hashfile` | cmd/PowerShell | `certutil -hashfile <path> SHA256` | PowerShell 없는 구형 환경에서도 동작 |
| `sha256sum` / `md5sum` | Linux/WSL | `sha256sum <path>` | `-c`로 목록 검증까지 한 번에 |

```powershell
# 1) 단일 파일
Get-FileHash .\evidence.dd -Algorithm SHA256

# 2) 여러 알고리즘 병기
'MD5','SHA1','SHA256' | ForEach-Object {
  Get-FileHash .\evidence.dd -Algorithm $_
} | Format-Table Algorithm, Hash -AutoSize

# 3) NTFS 메타파일은 반드시 작은따옴표. 큰따옴표는 변수로 확장돼 경로가 잘린다
Get-FileHash 'C:\case\original\$MFT' -Algorithm SHA256
Get-FileHash 'C:\case\original\$J'   -Algorithm SHA256
```

```text
Algorithm  Hash                                                             Path
---------  ----                                                             ----
SHA256     9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08 C:\case\evidence.dd
```

`Get-FileHash`는 **대문자 hex**를 낸다. `sha256sum`은 **소문자**다. 비교할 때는 한쪽을 맞춘다.

```cmd
certutil -hashfile C:\case\evidence.dd SHA256
```

```text
SHA256 hash of C:\case\evidence.dd:
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
CertUtil: -hashfile command completed successfully.
```

`certutil` 출력은 **3줄**이다. 해시만 필요하면 가운데 줄을 뽑는다. 구형 Windows에서는 hex 사이에 공백이 들어가므로 공백을 제거해야 비교가 된다.

```powershell
# certutil 출력에서 해시만 추출 (공백 제거 포함)
(certutil -hashfile C:\case\evidence.dd SHA256)[1] -replace '\s',''
```

```bash
# Linux
sha256sum evidence.dd
md5sum    evidence.dd
sha1sum   evidence.dd
```

```text
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  evidence.dd
```

### 3단계 — 분석 전후 절차로 고정

```text
[1] 원본 도착      -> SHA-256 계산 -> hash_before.txt 에 기록 (케이스 폴더 밖)
[2] 취득 로그/E01 내장 해시가 있으면 [1] 값과 대조
[3] 사본 생성      -> 사본의 SHA-256 이 [1] 과 같은지 확인
[4] 원본은 읽기 전용으로 잠그고 손대지 않는다
[5] 모든 작업은 사본에서 한다
[6] 분석 종료      -> 원본 SHA-256 재계산 -> hash_after.txt
[7] before == after 확인. 다르면 무엇이 원본을 건드렸는지 규명
[8] 추출물(export)마다 해시를 기록. 원본 내 해당 파일 해시와 대조
```

핵심은 [3]과 [7]이다. **[3]은 사본이 제대로 만들어졌음을, [7]은 원본이 그대로임을 증명한다.** 둘 중 하나만 하면 반쪽이다. 사본 생성과 원본 보존의 구체적 방법은 별도 글에서 다룬다.

### 4단계 — E01 내장 해시와 FTK Imager Verify

E01(EWF) 컨테이너는 **취득한 미디어 데이터의 해시를 파일 내부에 저장한다.** 이것이 RAW 이미지와의 결정적인 차이다.

| 대상 | 무엇을 해시하는가 | 값이 같은가 |
| --- | --- | --- |
| `sha256sum evidence.E01` | **컨테이너 파일**의 바이트 (헤더·압축 포함) | E01 내장 해시와 **다르다** |
| `ewfverify evidence.E01` | 압축을 풀어 복원한 **미디어 데이터** | 내장 해시와 **같아야 한다** |
| FTK Imager `Verify Drive/Image` | 동일하게 미디어 데이터 | 내장 해시와 **같아야 한다** |
| `sha256sum evidence.dd` (RAW) | 미디어 데이터 자체 | E01의 내장 해시와 같아야 한다 |

```bash
# E01 내장 해시 확인
ewfinfo evidence.E01

# 실제로 다시 읽어 계산하고 내장값과 비교
ewfverify evidence.E01
```

```text
ewfverify 20140608

Verify started at: Mar 14, 2026 07:10:22
...
MD5 hash stored in file:      3f1c8a0e6b2d47c9a1e5b73d0c9f4a12
MD5 hash calculated over data: 3f1c8a0e6b2d47c9a1e5b73d0c9f4a12

ewfverify: SUCCESS
```

FTK Imager에서는 이미지를 추가한 뒤 `File > Verify Drive/Image`를 실행한다. 결과 창에 저장된 해시와 계산된 해시가 나란히 표시되고 일치 여부를 알려 준다 ([FOR-0016](./ftk-imager-open-image.html)).

**분할 E01(`.E01`, `.E02`, ...)은 개별 파일 해시를 비교하지 말고 `ewfverify`나 FTK Imager Verify를 쓴다.** 세그먼트 분할 방식이 다르면 파일 단위 해시는 달라도 데이터는 같을 수 있다.

### 5단계 — 폴더 전체 해시 목록 만들기와 비교

파일 하나가 아니라 수집 폴더 전체를 검증할 때는 **목록(manifest)** 을 만든다.

```bash
# 생성 — 경로 순으로 정렬해야 diff 가 의미를 가진다
cd /case/original
find . -type f -print0 | sort -z | xargs -0 sha256sum > /notes/manifest_before.txt

# 나중에 같은 위치에서 검증 (내용까지 다시 읽어 비교)
cd /case/original && sha256sum -c /notes/manifest_before.txt
```

```text
./Windows/System32/config/SYSTEM: OK
./Windows/System32/winevt/Logs/Security.evtx: OK
./Users/kim/NTUSER.DAT: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
```

```bash
# 두 목록 비교 (원본 vs 사본). 경로 접두사를 맞춘 뒤 diff
diff <(sort /notes/manifest_before.txt) <(sort /notes/manifest_after.txt)
```

```powershell
# PowerShell — 상대 경로로 정규화해서 만들어야 원본/사본 비교가 된다
$root = 'C:\case\original'
Get-ChildItem -LiteralPath $root -Recurse -File |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Hash, @{ n='Rel'; e={ $_.Path.Substring($root.Length).TrimStart('\') } } |
  Sort-Object Rel |
  Export-Csv D:\notes\manifest_before.csv -NoTypeInformation -Encoding UTF8

# 비교 — Hash 와 상대 경로 조합이 다른 항목만 나온다
Compare-Object `
  (Import-Csv D:\notes\manifest_before.csv) `
  (Import-Csv D:\notes\manifest_after.csv) `
  -Property Hash, Rel | Format-Table -AutoSize
```

| `Compare-Object` `SideIndicator` | 의미 |
| --- | --- |
| `<=` | before에만 있다 → 파일이 삭제됐거나 내용이 변경됐다 |
| `=>` | after에만 있다 → 파일이 추가됐거나 내용이 변경됐다 |
| 같은 `Rel`이 양쪽에 각각 | **그 파일의 내용이 바뀌었다** |
| 출력 없음 | 완전 일치 |

**절대 경로를 그대로 넣으면 `C:\case\original`과 `C:\case\work` 차이 때문에 전 항목이 불일치로 나온다.** 반드시 상대 경로로 정규화한다.

### 6단계 — 추출물과 원본 대조

이미지에서 파일을 export한 뒤에는 **그 추출물이 이미지 안의 원본과 같은지** 확인해야 한다. 도구가 조용히 잘라내거나 슬랙을 붙이는 경우가 있다.

| 확인 방법 | 명령 | 무엇을 잡아내는가 |
| --- | --- | --- |
| 크기 우선 확인 | `ls -l` / `Get-Item` | 0바이트, 잘린 추출 |
| 추출물 해시 | `sha256sum extracted.xlsx` | 기록해 두면 이후 변조 감지 |
| 다른 도구로 재추출 후 대조 | Autopsy export vs FTK Imager export | 도구 버그·슬랙 포함 여부 |
| Sleuth Kit으로 직접 뽑아 대조 | `icat -o <offset> image.dd <inode> \| sha256sum` | GUI 추출의 신뢰도 검증 |

```bash
# 같은 파일을 두 경로로 뽑아 해시가 같은지 확인
icat -o 2048 image.dd 12345 | sha256sum
sha256sum ./autopsy_export/secret.xlsx
```

두 값이 다르면 **최소 한쪽 도구가 잘못 뽑았다.** 크기를 먼저 비교하면 원인이 대부분 즉시 보인다.

## 출력 필드 해석

| 관찰 | 판정 | 조치 |
| --- | --- | --- |
| before == after | 원본 무결성 유지 | 그대로 진행 |
| before != after | 원본이 변경됐다 | 아래 원인 표로 규명. 사본으로 재작업 |
| 취득 로그 해시 != 내 계산값 | 전송 중 손상 또는 다른 파일 | 파일 크기부터 비교 |
| `ewfverify: SUCCESS` | E01 데이터 무결 | 마운트/파싱 진행 |
| `ewfverify: FAILURE` | 세그먼트 손상/누락 | `.E02` 이후 파일이 다 있는지 확인 |
| `sha256sum -c` 결과 `FAILED` | 그 파일만 변경됨 | 어느 도구가 그 파일을 열었는지 추적 |
| 해시가 `e3b0c442...` | **0바이트** | 복사·추출이 실패했다 |
| 해시는 같은데 타임스탬프가 다름 | **정상** | 해시는 내용만 본다. 무결성 판정에 영향 없음 |
| 크기가 같은데 해시가 다름 | 내용의 일부가 바뀌었다 | 마운트 쓰기·백신 치료 의심 |

**타임스탬프가 바뀌어도 해시는 바뀌지 않는다.** 반대로 해시가 바뀌었다면 내용이 실제로 바뀐 것이다. 이 구분이 원인 추적의 출발점이다.

### 해시가 달라졌을 때의 원인

| 원인 | 어떻게 일어나는가 | 예방 |
| --- | --- | --- |
| 쓰기 가능 마운트 | 마운트 시 OS가 저널을 재생(replay)하고 `$LogFile`·메타데이터를 갱신한다 | 읽기 전용 마운트 ([FOR-0017](./arsenal-image-mounter.html)) |
| 백신 치료/격리 | 이미지 안이나 추출물에서 악성코드를 탐지해 파일을 변경·삭제한다 | 케이스 폴더 실시간 검사 예외 등록 |
| 검색 인덱싱 | 인덱서가 파일을 열고 ADS(`Zone.Identifier` 등)를 붙인다. 이름 없는 데이터 스트림은 보통 그대로지만 컨테이너 파일은 영향을 받을 수 있다 | 케이스 볼륨 인덱싱 해제 |
| 복사 중단 | 대용량 복사가 끝나기 전에 계산했다 | 크기 확인 후 해시 |
| 도구의 "복구" 동작 | 일부 도구가 손상 헤더를 자동 수정해 저장한다 | 원본 열기 금지, 사본에서만 |
| 압축 해제 후 재압축 | ZIP을 풀고 다시 묶으면 컨테이너 해시가 달라진다 | 내부 파일 단위로 해시 비교 |
| 네트워크/USB 전송 오류 | 드물지만 존재 | 전송 후 해시 재확인 |

### 충돌 내성 — MD5는 어디까지 쓸 수 있는가

| 성질 | MD5 | SHA-1 | SHA-256 |
| --- | --- | --- | --- |
| 충돌 저항 (서로 다른 두 파일이 같은 해시) | **깨졌다** | **깨졌다** | 유효 |
| 원상 복원(preimage) 저항 | 실용적으로 유효 | 유효 | 유효 |
| "이 파일이 그 파일인가" 식별 | 쓸 수 있다 | 쓸 수 있다 | 쓸 수 있다 |
| "누가 바꿔치기하지 않았다"는 증명 | **못 쓴다** | **못 쓴다** | 쓸 수 있다 |

즉 MD5가 같으면 **우연히 다른 파일일 가능성은 사실상 없지만, 의도적으로 같게 만든 파일일 가능성은 있다.** 그래서 MD5는 해시셋 대조·중복 제거 같은 식별 용도로만 쓰고, 무결성 주장에는 SHA-256을 병기한다. 취득 로그가 MD5만 남겼다면 MD5로 대조하되 **자기 기록에는 SHA-256을 함께 남긴다.**

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 할 일 | 확인 사항 |
| --- | --- | --- |
| 원본 SHA-256 | 사본 생성 후 재계산 | 사본이 원본과 동일한가 |
| `ewfverify: SUCCESS` | 이미지 마운트 / 파티션 확인 | 읽기 전용으로 마운트했는가 ([FOR-0017](./arsenal-image-mounter.html)) |
| 취득 로그의 MD5 | 내 계산 MD5와 대조 | 전송 손상 배제 |
| 추출물 해시 | 다른 도구로 재추출해 대조 | 도구가 잘라내지 않았는가 |
| 폴더 manifest | 분석 종료 후 `-c` 검증 | 어느 파일이 변경됐는가 |
| 해시가 0바이트 값 | 추출 절차 재실행 | 파일 크기·경로 오타 |
| 파일 형식 미확정 | 매직 바이트 확인 | 해시만으로는 형식을 알 수 없다 ([FOR-0001](./30sec-triage.html)) |

## 흔한 함정

- **E01 컨테이너 파일의 해시를 내장 해시와 비교하는 것.** `sha256sum evidence.E01`은 압축·헤더를 포함한 컨테이너 바이트의 해시다. E01 안에 저장된 해시는 **복원된 미디어 데이터**의 해시라서 절대 같지 않다. 반드시 `ewfverify`나 FTK Imager `Verify Drive/Image`를 쓴다.
- **원본을 직접 열어 놓고 나중에 해시를 계산하는 것.** 이미 변경됐으면 before 값이 없어 무결성을 증명할 방법이 사라진다. **해시는 아무것도 하기 전에 계산한다.**
- **대소문자를 무시하고 문자열 비교하는 것.** `Get-FileHash`는 대문자, `sha256sum`은 소문자를 낸다. 육안 비교는 통과하지만 스크립트 비교(`-eq`, `diff`)는 불일치로 나온다. 한쪽을 `.ToLower()`로 맞춘다.
- **`certutil` 출력을 통째로 비교하는 것.** 출력은 헤더 줄과 완료 메시지를 포함한 3줄이고, 구형 Windows는 hex 사이에 공백을 넣는다. 가운데 줄만 뽑고 공백을 제거한다.
- **폴더 manifest를 절대 경로로 만들어 비교하는 것.** `C:\case\original\...`과 `C:\case\work\...`는 해시가 같아도 전 항목이 불일치로 나온다. 상대 경로로 정규화한다.
- **타임스탬프가 바뀌었으니 무결성이 깨졌다고 판단하는 것.** 해시는 내용만 본다. 타임스탬프·ADS·속성 변경은 파일 내용 해시를 바꾸지 않는다. 반대로 **해시가 바뀌었으면 내용이 실제로 바뀐 것**이므로 그때는 원인을 반드시 규명한다.
- **MD5 일치만으로 무결성을 주장하는 것.** MD5는 충돌 저항이 깨져 있다. 식별에는 쓰고 증명에는 SHA-256을 병기한다.
- **해시 기록을 케이스 폴더 안에 두는 것.** 케이스 폴더가 통째로 오염되면 기준값도 함께 오염된다. 별도 위치(다른 드라이브, 메모 파일)에 남긴다.
- **크기를 확인하지 않고 해시부터 계산하는 것.** 해시가 `e3b0c442...`(0바이트)나 예상과 완전히 다르면 대개 크기 문제다. `ls -l` 한 줄이 더 빠르다.
- **분할 E01의 세그먼트를 개별 비교하는 것.** 분할 크기가 다르면 파일 단위 해시가 달라도 데이터는 동일하다. 데이터 단위로 검증한다.
- **분석 종료 후 재계산을 생략하는 것.** [7]단계를 빼면 "작업 중 원본을 건드렸는지"를 아무도 모른다. 30초짜리 작업이다.

## 교차검증

같은 파일을 두 도구로 계산해서 값이 같아야 한다. 도구 오류·잘못된 경로를 즉시 잡는다.

```bash
# 1) Linux 두 방법
sha256sum evidence.dd
openssl dgst -sha256 evidence.dd
```

```powershell
# 2) Windows 두 방법 — 값이 다르면 경로/스트림을 잘못 지정한 것이다
(Get-FileHash .\evidence.dd -Algorithm SHA256).Hash.ToLower()
(certutil -hashfile .\evidence.dd SHA256)[1] -replace '\s',''
```

| 관찰 | 결론 |
| --- | --- |
| 두 도구 값이 일치 | 계산 신뢰 가능 |
| 한쪽만 0바이트 해시 | 경로 오타 또는 권한 문제 |
| GUI(HashCalc)와 CLI가 다름 | GUI가 다른 파일/다른 스트림을 읽고 있다 |
| E01 내장 해시와 RAW 변환 결과가 일치 | 변환 무손실 확인 |
| `-c` 검증에서 특정 파일만 `FAILED` | 그 파일을 연 도구를 추적 |

## mini walkthrough

```text
문제:
"제공된 E01 이미지의 무결성을 검증하고, 이미지에서 추출한
 secret.xlsx 의 SHA-256 을 제출하시오."
첨부: case01.E01 (2.1 GB), case01.E01.txt (취득 로그), case01.E02

1. 첫 시도 (실패):
   취득 로그를 열었다.
     Acquisition MD5: 3f1c8a0e6b2d47c9a1e5b73d0c9f4a12
   그래서 컨테이너 파일의 MD5 를 계산해 비교했다.
     $ md5sum case01.E01
       8b44f0c1d9e27a3b5c6f018d4e2a91bb  case01.E01
   값이 전혀 달랐다. "이미지가 손상됐다"고 판단하고 문제를 넘겼다.  오답.

   왜 틀렸나:
   취득 로그의 MD5 는 "취득한 미디어 데이터" 의 해시다.
   반면 md5sum 이 계산한 것은 압축·헤더를 포함한 E01 컨테이너 파일의 해시다.
   대상이 다르므로 애초에 같을 수 없다.
   게다가 .E02 세그먼트가 있는 분할 이미지였는데 .E01 만 계산했다.

2. 피벗: E01 은 전용 검증 도구로 데이터 단위로 검증한다
   $ ewfinfo case01.E01
     Digest hash information
       MD5: 3f1c8a0e6b2d47c9a1e5b73d0c9f4a12     <- 로그와 동일
     Media size: 2147483648 bytes

   $ ewfverify case01.E01
     MD5 hash stored in file:       3f1c8a0e6b2d47c9a1e5b73d0c9f4a12
     MD5 hash calculated over data: 3f1c8a0e6b2d47c9a1e5b73d0c9f4a12
     ewfverify: SUCCESS
   -> 무결성 확인. 손상이 아니었다.
   ewfverify 는 .E01 을 지정하면 .E02 이후 세그먼트를 자동으로 따라간다.

3. 분석 전 기록 (원본 기준값)
   $ sha256sum case01.E01 case01.E02 > /notes/hash_before.txt
   -> 컨테이너 해시도 별개로 남긴다. "내가 이 파일들을 안 건드렸다" 의 증명용.

4. 읽기 전용 마운트 후 추출
   추출한 파일이 0바이트가 아닌지 크기부터 본다.
   $ ls -l export/secret.xlsx
     -rw-r--r-- 1 u u 18452 Mar 14 07:31 export/secret.xlsx
   $ sha256sum export/secret.xlsx
     4c9f2a7e1b8d05c3a6e4f27b9d013c8a5f6e2b40c7d19a83e5f0b6c2d4a89173

5. 교차검증 — 다른 경로로 뽑아 같은 값인지 확인
   $ icat -o 2048 case01.dd 74213 | sha256sum
     4c9f2a7e1b8d05c3a6e4f27b9d013c8a5f6e2b40c7d19a83e5f0b6c2d4a89173
   -> 일치. 추출 과정에서 잘리거나 슬랙이 붙지 않았다.

6. 분석 종료 후 원본 재계산
   $ sha256sum -c /notes/hash_before.txt
     case01.E01: OK
     case01.E02: OK
   -> 읽기 전용 마운트였으므로 원본 불변. 무결성 사슬 완성.

정답: 4c9f2a7e1b8d05c3a6e4f27b9d013c8a5f6e2b40c7d19a83e5f0b6c2d4a89173
      (E01 무결성: ewfverify SUCCESS, 내장 MD5 = 취득 로그 MD5 일치)
```

4단계에서 **크기를 먼저 본 것**이 결정적이었다. 0바이트 추출은 해시가 `e3b0c442...`로 나오는데, 그것을 정답으로 제출하는 사고가 흔하다.

## 막혔을 때 다음 체크

1. 파일 **크기**를 먼저 확인했는가 — 0바이트/잘림이면 해시는 의미 없다
2. E01이면 `ewfverify` 또는 FTK Imager `Verify Drive/Image`를 썼는가 (컨테이너 해시가 아니다)
3. 분할 이미지의 세그먼트가 전부 있는가 (`.E02`, `.E03`, ...)
4. 대소문자를 맞추고 비교했는가
5. `certutil` 출력에서 가운데 줄만 뽑고 공백을 제거했는가
6. manifest를 상대 경로로 만들었는가
7. 해시가 `d41d8cd9...` / `e3b0c442...`인가 → 0바이트다
8. 취득 로그가 MD5만 남겼는가 → MD5로 대조하고 SHA-256을 추가로 기록
9. 원본을 읽기 전용으로 잠갔는가, 작업을 사본에서 했는가
10. 백신·인덱싱 예외를 등록했는가
11. 분석 종료 후 재계산을 했는가
12. 문제가 요구하는 알고리즘(32/40/64자)이 내가 계산한 것과 같은가

## 출처

- SRC-078 — NIST FIPS 180-4(Secure Hash Standard) / RFC 1321(MD5): SHA-1 160비트, SHA-256 256비트, MD5 128비트라는 출력 길이와 알고리즘 정의
- SRC-007 — Microsoft Learn, PowerShell Utility 모듈 문서: 파이프라인·`Select-Object`·`Export-Csv` 조합의 동작. **`Get-FileHash`의 `-Algorithm` 허용값 목록은 PowerShell 버전에 따라 다르므로 `Get-Help Get-FileHash -Full`로 확인할 것**
- `certutil -hashfile` 출력 형식(줄 수, hex 사이 공백 유무)은 Windows 버전에 따라 다르므로 실제 화면에서 확인할 것
- `ewfinfo`/`ewfverify` 출력 라벨과 FTK Imager의 `Verify Drive/Image` 메뉴 경로는 도구 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
- 본문의 해시값 예시(`9f86d081...`, `3f1c8a0e...` 등)는 절차를 보여주기 위한 가상 값이다. 0바이트 파일 해시 두 개만 실제 상수다
- 문제에서 요구하는 flag/해시 제출 형식은 대회마다 다르다. 이 글은 특정 flag 형식을 가정하지 않는다
