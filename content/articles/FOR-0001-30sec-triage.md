---
id: FOR-0001
title: "포렌식 문제 파일을 받았을 때 30초 트리아지"
slug: "30sec-triage"
category: "트리아지"
type: "troubleshooting"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: []
file_paths: []
registry_paths: []
event_ids: []
protocols: []
tools: ["file", "HxD", "strings", "exiftool", "binwalk", "DIE", "7-Zip"]
commands: ["file target.bin", "xxd -l 64 target.bin", "strings -n 8 target.bin", "binwalk target.bin"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: []
file_formats: ["pcap", "pcapng", "evtx", "regf", "sqlite", "e01", "zip", "png", "jpeg", "pdf"]
keywords: ["트리아지", "triage", "파일 식별", "매직 바이트", "magic byte", "파일 시그니처", "첫 단계", "무엇부터"]
aliases: ["30초 트리아지", "문제 파일 받았을 때", "뭐부터 해야 하나", "파일 종류 모를 때", "처음 시작", "first look"]
symptom_keywords: ["확장자가 없다", "파일이 뭔지 모르겠다", "열리지 않는다", "무엇부터 봐야 할지 모르겠다", "시간이 없다"]
related: ["FOR-0021", "FOR-0146", "FOR-0191"]
source_ids: ["SRC-005", "SRC-014"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

확장자를 믿지 말고 `file` + 첫 64바이트 hex + `strings` 세 가지를 먼저 돌려서 "무슨 파일인가"를 확정한 뒤, 그 파일 종류에 맞는 전용 툴 한 개만 연다.

## 어떤 문제에서 필요한가

- 첨부파일이 `evidence`, `dump`, `challenge.bin` 처럼 확장자가 없거나 거짓인 경우
- 첨부가 여러 개라서 어느 것부터 볼지 결정해야 하는 경우
- 문제 지문이 "분석하시오" 한 줄뿐이라 방향이 없는 경우

CTF 포렌식에서 가장 많이 낭비되는 시간은 잘못된 툴을 여는 데 쓰는 시간이다. 30초를 써서 파일 종류를 확정하면 나머지 절차가 전부 결정된다.

## 문제에서 처음 볼 단서

1. **파일 크기** — 수 MB면 문서/이미지/pcap, 수백 MB~수 GB면 디스크 이미지 또는 메모리 덤프
2. **파일 이름** — `*.E01`, `*.raw`, `*.mem`, `*.pcapng`, `Security.evtx`, `NTUSER.DAT` 처럼 이름 자체가 정답인 경우가 많다
3. **첫 4~8바이트** — 이름과 확장자가 모두 거짓이어도 매직 바이트는 거짓말하지 않는다
4. **문제 지문의 명사** — "사용자", "USB", "접속", "다운로드" 같은 단어가 어떤 artifact를 봐야 하는지 알려준다

## 30초 절차

```bash
file target.bin
xxd -l 64 target.bin
strings -n 8 target.bin | head -40
```

Windows에서 `file`/`xxd`가 없을 때:

```powershell
Format-Hex -Path .\target.bin -Count 64
Select-String -Path .\target.bin -Pattern 'flag|http|\.exe' -Encoding Byte -AllMatches | Select-Object -First 20
```

GUI만 쓸 수 있으면 HxD로 열어 좌상단 16바이트만 읽는다. Detect It Easy(DIE)는 실행 파일/패커 판정에 특히 빠르다.

## 상세 절차

### 1단계 — 매직 바이트로 종류 확정

| 매직 바이트 (hex) | ASCII | 종류 | 다음에 열 툴 |
| --- | --- | --- | --- |
| `D4 C3 B2 A1` / `A1 B2 C3 D4` | — | pcap (libpcap) | Wireshark |
| `4D 3C B2 A1` | — | pcap, 나노초 정밀도 | Wireshark |
| `0A 0D 0D 0A` | — | pcapng | Wireshark |
| `45 6C 66 46 69 6C 65 00` | `ElfFile\0` | Windows EVTX | EvtxECmd |
| `72 65 67 66` | `regf` | Registry hive | RegistryExplorer |
| `53 51 4C 69 74 65 20 66` | `SQLite f` | SQLite DB | DB Browser / sqlite3 |
| `46 49 4C 45` | `FILE` | NTFS MFT 레코드 | analyzeMFT / MFTECmd |
| `45 56 46 09 0D 0A FF 00` | `EVF` | EnCase E01 이미지 | FTK Imager / Arsenal |
| `50 4B 03 04` | `PK..` | ZIP (docx/xlsx/apk/jar 포함) | 7-Zip |
| `D0 CF 11 E0 A1 B1 1A E1` | — | 구형 Office (doc/xls/msi) | oledump / Metadata++ |
| `25 50 44 46` | `%PDF` | PDF | pdf 도구 / HxD |
| `89 50 4E 47 0D 0A 1A 0A` | `.PNG` | PNG | zsteg / pngcheck |
| `FF D8 FF` | — | JPEG | exiftool / steghide |
| `4D 5A` | `MZ` | Windows PE (exe/dll) | DIE / strings |
| `7F 45 4C 46` | `.ELF` | Linux 실행 파일 | file / strings |
| `1F 8B` | — | gzip | gunzip |
| `37 7A BC AF 27 1C` | `7z` | 7-Zip 아카이브 | 7-Zip |
| `52 61 72 21 1A 07` | `Rar!` | RAR | 7-Zip |
| 매직 없음, 크기 수 GB | — | RAW 디스크/메모리 덤프 | mmls → Autopsy / Volatility 3 |

### 2단계 — 종류가 정해지면 그 라인만 판다

- **pcap/pcapng** → Wireshark: Statistics > Protocol Hierarchy 부터 ([FOR-0146](./wireshark-30sec-triage.html))
- **디스크 이미지** → FTK Imager로 열고 파티션·사용자 폴더 확인
- **메모리 덤프** → `windows.info` 로 프로파일 확인 후 `windows.pslist` ([FOR-0214](./volatility-pslist.html))
- **Registry hive** → RegistryExplorer, 사용자 활동이면 NTUSER.DAT의 UserAssist ([FOR-0061](./userassist.html))
- **EVTX** → EvtxECmd로 CSV 변환 후 4624/4688/7045 검색
- **이미지/오디오 단독** → 스테가노 라인 (exiftool → strings → zsteg/steghide)

### 3단계 — `strings`로 공짜 단서 회수

`strings` 결과에서 다음이 보이면 바로 방향이 정해진다.

```bash
strings -n 8 target.bin | grep -Ei 'flag|password|http://|https://|\.php|C:\\\\Users|/home/'
```

- `C:\Users\<이름>\` → Windows 사용자 이름 확보
- `http://...` → 네트워크/브라우저 라인
- `flag{`, `FLAG{` → 운이 좋으면 여기서 끝난다
- Base64처럼 보이는 긴 문자열 → 디코딩 후보

## 출력 필드 해석

`file` 출력에서 실제로 쓸 정보는 다음이다.

```text
$ file evidence
evidence: pcapng capture file - version 1.0

$ file dump.bin
dump.bin: data
```

- 구체적인 포맷명이 나오면 그대로 신뢰한다.
- `data`라고만 나오면 **매직 바이트가 없는 RAW**라는 뜻이다. 디스크 이미지, 메모리 덤프, 암호화된 파일, 잘린 파일 중 하나다. 크기로 1차 판단하고 `mmls`/`windows.info`를 각각 시도한다.
- `file`이 확장자와 다른 답을 주면 **확장자가 거짓**이다. 이것 자체가 문제의 정답인 경우도 있다.

## pivot: 다음에 볼 artifact

| 1단계에서 확인된 것 | 다음 목표 |
| --- | --- |
| Windows 사용자 이름 | `NTUSER.DAT` → UserAssist / RecentDocs |
| URL / 도메인 | 브라우저 History → pcap 대조 |
| 실행 파일 이름 | Prefetch → Amcache → EVTX 4688 |
| 삭제 파일 언급 | `$UsnJrnl` → `$Recycle.Bin` |
| 시간 값 하나 | 그 시각 ±5분의 모든 artifact |

## 흔한 함정

- **확장자를 믿는 것.** `.jpg`인데 실제로는 ZIP인 경우가 CTF에서 매우 흔하다. 항상 hex를 본다.
- **큰 파일을 GUI로 먼저 여는 것.** 4 GB 덤프를 HxD로 열면 시간만 잃는다. `file`/`xxd -l 64`는 크기와 무관하게 즉시 끝난다.
- **매직 바이트가 파일 중간에 있는 경우를 놓치는 것.** 앞에 패딩이나 다른 파일이 붙어 있을 수 있다. `binwalk target.bin`으로 내부 시그니처를 전체 스캔한다.
- **pcap의 엔디언 혼동.** `D4 C3 B2 A1`과 `A1 B2 C3 D4`는 같은 pcap의 엔디언 차이일 뿐이다. 둘 다 Wireshark로 열린다.
- **`strings` 기본값이 ASCII만이라는 점.** 한글/UTF-16 문자열은 `strings -el`(16비트 리틀엔디언)을 추가로 돌려야 보인다.

## 교차검증

같은 결론을 두 가지 방법으로 확인한다.

```bash
# 1) 시그니처 기반
file target.bin

# 2) 내부 시그니처 전체 스캔 — 앞부분이 위조되어도 잡힌다
binwalk target.bin

# 3) 엔트로피 — 0.99에 가까우면 암호화/압축, 낮으면 평문 구조
binwalk -E target.bin
```

GUI에서는 DIE(Detect It Easy)가 `file`과 다른 판정을 내리는지 비교하면 위조 여부를 빠르게 안다.

## mini walkthrough

```text
문제:
"직원 PC에서 수집한 자료입니다. 유출된 파일 이름을 찾으세요."
첨부: artifact_01 (확장자 없음, 12 MB)

1. file artifact_01
   -> "artifact_01: data"          (매직 없음. RAW 후보)

2. xxd -l 64 artifact_01
   -> 00000000: 0a0d 0d0a ...      (0A 0D 0D 0A = pcapng!)
   file이 못 잡은 이유: 헤더 앞에 4바이트 쓰레기가 붙어 있었음

3. binwalk artifact_01
   -> 4  0x4  pcapng capture file  (오프셋 4에서 시작 확인)

4. dd if=artifact_01 of=fixed.pcapng bs=1 skip=4
   -> Wireshark로 정상 오픈

5. Statistics > Protocol Hierarchy
   -> FTP 존재 확인

6. 필터: ftp.request.command == "STOR"
   -> STOR 고객명단_2026.xlsx

정답: 고객명단_2026.xlsx
```

핵심은 2단계였다. `file`이 `data`라고 답했을 때 포기하지 않고 hex를 직접 본 것이 결정적이었다.

## 막혔을 때 다음 체크

1. `binwalk target.bin` — 파일 안에 다른 파일이 숨어 있는가
2. `strings -el target.bin` — UTF-16 문자열을 놓쳤는가
3. 파일 **끝** 64바이트도 본다 (`xxd | tail -4`) — 뒤에 붙은 ZIP/주석이 흔하다
4. 크기가 512 또는 4096의 배수인가 — 디스크 이미지/섹터 단위 데이터 신호
5. 엔트로피가 0.99 부근인가 — 암호나 패스워드를 찾는 문제로 방향 전환
6. 여러 첨부 중 **가장 작은 파일**을 먼저 본다 — 설명/힌트 파일인 경우가 많다

## 출처

- SRC-005 — Microsoft Learn, Master File Table (NTFS 시그니처 `FILE`)
- SRC-014 — Microsoft Learn, File Times (FILETIME 기준 시각)
- 매직 바이트 값은 대상 파일을 HxD/`xxd`로 직접 열어 재확인할 것
