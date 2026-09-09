---
id: FOR-0184
title: "tshark 옵션 레퍼런스: -r -Y -T fields -z 를 한 장에"
slug: "tshark-basics"
category: "Network/PCAP"
type: "reference"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng"]
file_paths: ["C:\\Program Files\\Wireshark\\tshark.exe", "/usr/bin/tshark"]
registry_paths: []
event_ids: []
protocols: ["HTTP", "DNS", "TCP", "UDP", "TLS"]
tools: ["tshark", "Wireshark", "capinfos", "editcap", "mergecap"]
commands: ["tshark -r capture.pcapng -c 20", "tshark -r capture.pcapng -q -z io,phs", "tshark -r capture.pcapng -T fields -e ip.src -e ip.dst -E header=y", "tshark -r capture.pcapng -V -O http", "tshark -r capture.pcapng -d tcp.port==8080,http", "tshark -r capture.pcapng -o tcp.desegment_tcp_streams:TRUE", "tshark -r capture.pcapng --export-objects http,out/", "tshark -G protocols"]
regex_patterns: []
wireshark_filters: ["http.request", "dns.flags.response == 0", "tcp.stream eq 4"]
tshark_fields: ["frame.number", "frame.time", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream", "_ws.col.Info", "_ws.col.Protocol"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["tshark", "tshark 기본", "tshark 옵션"]
keywords: ["tshark", "tshark 옵션", "-T fields", "-z 통계", "Decode As", "preference 설정", "two-pass", "tshark.exe", "명령줄 패킷 분석", "CLI Wireshark"]
aliases: ["tshark 옵션", "tshark 사용법", "tshark 명령어", "티샤크", "wireshark cli", "tshark exe 경로", "tshark 안됨"]
symptom_keywords: ["tshark 옵션이 기억나지 않는다", "tshark 명령을 찾을 수 없다", "GUI 결과와 tshark 결과가 다르다", "비표준 포트가 파싱되지 않는다", "통계를 CLI로 뽑고 싶다"]
related: ["FOR-0185", "FOR-0186", "FOR-0146"]
source_ids: ["SRC-010", "SRC-002"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

tshark 는 `-r`(입력) `-Y`(디스플레이 필터) `-T fields -e`(컬럼 추출) `-q -z`(통계) 네 축으로 쓴다. 나머지 옵션은 이 네 축을 보정하는 장치이며, GUI 와 결과가 다르면 거의 항상 `-2`(2-pass) 또는 `-o`(preference) 가 원인이다.

## 개념

tshark 는 Wireshark 와 **같은 dissector 엔진**을 쓰는 CLI 프론트엔드다. 따라서 GUI 에서 보이는 필드 이름을 그대로 `-e` 에 넣을 수 있고, GUI 의 디스플레이 필터를 그대로 `-Y` 에 넣을 수 있다.

세 가지 계층을 구분해야 옵션이 헷갈리지 않는다.

| 계층 | 옵션 | 언제 적용되나 | 문법 |
| --- | --- | --- | --- |
| 캡처 필터 | `-f` | **캡처하는 순간** 커널에서 버린다 | pcap-filter (BPF), `tcp port 80` |
| 읽기 필터 | `-R` | 1차 패스에서 걸러 이후 패스에 넘기지 않는다. `-2` 필요 | 디스플레이 필터 문법 |
| 디스플레이 필터 | `-Y` | 해석 후 출력 직전 | 디스플레이 필터 문법 |
| 출력 형식 | `-T`, `-e`, `-E`, `-V`, `-x`, `-O` | 통과한 패킷을 어떻게 찍을까 | — |
| 통계 | `-z` | 읽기가 끝난 뒤 한 번 | `-z <subtype>[,filter]` |

이미 저장된 pcap 을 분석할 때 `-f` 는 의미가 없다. **저장 파일에는 `-Y` 를 쓴다.**

## 파일 / 경로

| 플랫폼 | 실행 파일 |
| --- | --- |
| Windows (기본 설치) | `C:\Program Files\Wireshark\tshark.exe` |
| Windows (32bit 설치) | `C:\Program Files (x86)\Wireshark\tshark.exe` |
| Linux (deb/rpm) | `/usr/bin/tshark` |
| macOS (Wireshark.app) | `/Applications/Wireshark.app/Contents/MacOS/tshark` |

Windows 설치 시 `tshark.exe` 가 있는 디렉터리가 **PATH 에 자동으로 추가되지 않는 경우가 많다.** `tshark : 용어가 cmdlet ... 인식되지 않습니다` 가 뜨면 경로 문제다.

```powershell
# 현재 세션에만 PATH 추가
$env:Path += ';C:\Program Files\Wireshark'
tshark -v

# 또는 별칭으로
Set-Alias tshark 'C:\Program Files\Wireshark\tshark.exe'
```

```bash
# Linux: 비루트로 저장 파일만 읽을 때는 권한 설정이 필요 없다
which tshark && tshark -v | head -1
```

같은 디렉터리에 함께 설치되는 형제 도구도 같은 PATH 문제를 공유한다.

| 도구 | 용도 |
| --- | --- |
| `capinfos` | 패킷 수, 시간 범위, 파일 해시 — GUI 의 Capture File Properties |
| `editcap` | 자르기, 분할, 시간 범위 추출, 포맷 변환 |
| `mergecap` | 여러 캡처 파일을 하나로 병합 |
| `text2pcap` | hex 덤프를 pcap 으로 되돌리기 |
| `dumpcap` | 실제 캡처 엔진 |

## 주요 필드

### 입출력

| 옵션 | 의미 | 주의 |
| --- | --- | --- |
| `-r <file>` | 저장 파일 읽기. gzip 압축 파일도 그대로 읽는다 | `-` 로 stdin 도 되지만 되감기가 필요한 포맷은 실패 |
| `-w <file>` | **원시 패킷 데이터**를 파일로 쓴다 | 텍스트가 아니다. 텍스트를 저장하려면 셸 리다이렉션(`> out.txt`) |
| `-c <n>` | 최대 n 패킷만 읽는다 | **필터에 걸러진 패킷도 개수에 포함된다** |
| `-F <format>` | `-w` 출력 포맷 지정 | `-F pcap` 로 구형 도구 호환 |

### 필터

| 옵션 | 의미 |
| --- | --- |
| `-Y <filter>` | 디스플레이 필터. 단일 패스 분석의 기본 선택 |
| `-f <filter>` | 캡처 필터(BPF). 라이브 캡처에만 의미 |
| `-2` | 2-pass 분석. 미래 정보가 필요한 필드를 채운다. 되감기 가능한 입력만 |
| `-R <filter>` | 1차 패스 읽기 필터. **`-2` 와 함께만 의미가 있다** |

`-2` 아래에서는 `-R` 를 통과한 패킷만 `-Y` 검사를 받는다. `http.response_in`, `http.time` 처럼 **뒤 패킷을 봐야 알 수 있는 필드는 `-2` 없이는 비어 나온다.**

### 출력 형식

| 옵션 | 의미 |
| --- | --- |
| `-T text` | 기본. GUI 의 패킷 목록 한 줄 요약 |
| `-T fields` | `-e` 로 고른 필드만. **CSV/TSV 를 만드는 모드** |
| `-T json` | 전체 트리를 JSON 으로 |
| `-T jsonraw` | JSON + 원시 hex 바이트 |
| `-T ek` | Elasticsearch 용 줄단위 JSON |
| `-T pdml` | 전체 트리를 XML 로 (GUI 의 Export Packet Dissections > PDML) |
| `-T psml` | 요약을 XML 로 |
| `-T tabs` | 텍스트 요약을 탭으로 구분 |
| `-T ps` | PostScript |

`-T` 의 유효값 전체는 `ek|fields|json|jsonraw|pdml|ps|psml|tabs|text` 이다.

| 옵션 | 의미 |
| --- | --- |
| `-e <field>` | 출력할 필드. **반복해서 컬럼을 늘린다.** `-T fields` 에서는 최소 1개 필수 |
| `-V` | 패킷 상세 트리 전체 출력 |
| `-x` | hex + ASCII 덤프 |
| `-O <proto,...>` | 지정 프로토콜만 상세하게, 나머지는 한 줄로 |
| `-q` | 패킷 정보를 출력하지 않는다. `-z` 통계만 볼 때 |
| `-Q` | `-q` 보다 조용하다. 진짜 오류만 stderr 로 |
| `-l` | 패킷마다 stdout 을 flush. 파이프로 실시간 처리할 때 |

`-e` 에는 프로토콜 필드 외에 **GUI 컬럼**도 넣을 수 있다.

| `-e` 값 | 내용 |
| --- | --- |
| `_ws.col.Protocol` | GUI 의 Protocol 컬럼(최종 판정 프로토콜) |
| `_ws.col.Info` | GUI 의 Info 컬럼 요약 문자열 |
| `_ws.col.Source` / `_ws.col.Destination` | GUI 의 주소 컬럼 |

### `-E` — `-T fields` 의 출력 제어

| `-E` 옵션 | 유효값 | 기본값 | 용도 |
| --- | --- | --- | --- |
| `header=` | `y` \| `n` | `n` | 첫 줄에 필드 이름 |
| `separator=` | `/t` \| `/s` \| 임의 문자 | `/t`(탭) | `separator=,` 로 CSV |
| `quote=` | `d` \| `s` \| `n` | `n` | `d` 는 큰따옴표, `s` 는 작은따옴표 |
| `occurrence=` | `f` \| `l` \| `a` | `a` | 한 패킷에 같은 필드가 여러 번일 때 first/last/all |
| `aggregator=` | `,` \| `/s` \| 임의 문자 | `,` | `occurrence=a` 일 때 값들을 묶는 구분자 |
| `bom=` | `y` \| `n` | `n` | UTF-8 BOM 부착. Excel 한글 깨짐 방지 |
| `escape=` | `y` \| `n` | `y` | 제어문자를 C 스타일 이스케이프로 |

CSV 를 만드는 표준 조합은 `-E header=y -E separator=, -E quote=d -E occurrence=a` 다. 자세한 레시피는 [FOR-0186](./tshark-extract-fields.html).

### 해석 보정 — `-d`, `-o`, `-n`, `-N`

| 옵션 | 문법 | 예시 |
| --- | --- | --- |
| `-d` | `<layer type>==<selector>,<protocol>` | `-d tcp.port==8080,http` |
| `-d` (범위) | `<layer>==<from>-<to>,<proto>` | `-d tcp.port==8000-8010,http` |
| `-d` (목록 보기) | `-d .` 로 selector 목록, `-d tcp.port==8080,.` 로 프로토콜 목록 | — |
| `-o` | `<preference>:<value>` | `-o tcp.desegment_tcp_streams:TRUE` |
| `-n` | 이름 변환 전부 끔 | 포트가 `http` 대신 `80` 으로 |
| `-N <flags>` | 선택적 변환만 켬 | `-N t` 는 포트 이름만 |

`-N` 의 플래그는 다음과 같다.

| 플래그 | 켜는 변환 |
| --- | --- |
| `m` | MAC 주소 → 벤더 이름 |
| `n` | 네트워크 주소 → 호스트 이름 (내부 테이블) |
| `N` | 외부 리졸버(DNS) 사용. `n` 과 함께 써야 한다 |
| `d` | 캡처된 DNS 패킷으로부터 이름 변환 |
| `t` | 전송 계층 포트 번호 → 서비스 이름 |
| `s` | 캡처된 핸드셰이크의 SNI 로 주소 변환 |
| `v` | VLAN ID → 이름 |
| `g` | MaxMind DB 로 지리 정보 조회 |

**포렌식에서는 `-n` 을 기본으로 켠다.** 이름 변환이 켜져 있으면 외부 DNS 질의가 나가고(증거 오염), 출력에 IP 대신 도메인이 들어와 grep 이 어긋난다.

자주 쓰는 `-o` preference:

| preference | 값 | 효과 |
| --- | --- | --- |
| `tcp.desegment_tcp_streams` | `TRUE` / `FALSE` | 여러 세그먼트에 걸친 페이로드 재조립. `http.file_data` 가 비면 이것을 본다 |
| `tcp.check_checksum` | `FALSE` | 체크섬 오류로 패킷이 버려지는 것을 막는다 (TSO 캡처에서 흔하다) |
| `tcp.reassemble_out_of_order` | `TRUE` | 순서가 뒤바뀐 캡처 재조립 |
| `tcp.calculate_timestamps` | `TRUE` | `tcp.time_delta` 를 계산해 준다 (비콘 간격 판정용) |
| `http.decompress_body` | `TRUE` | gzip 응답 본문을 풀어 `http.file_data` 에 넣는다 |
| `tls.keylog_file` | 파일 경로 | SSLKEYLOGFILE 로 TLS 복호화 |
| `gui.column.format` | `"Time","%Aut"` 등 | 텍스트 출력의 컬럼 구성 변경 |

### 시각 표기 — `-t`

`-t` 의 문법은 `-t (a|ad|adoy|d|dd|e|r|u|ud|udoy)[.[N]]` 다.

| 값 | 표기 |
| --- | --- |
| `r` | **기본값.** 첫 패킷 기준 상대 초 |
| `a` | 로컬 시각 (날짜 없음) |
| `ad` | 로컬 **날짜 + 시각** |
| `adoy` | 로컬 날짜(연중 일수) + 시각 |
| `u` | UTC 시각 (날짜 없음) |
| `ud` | **UTC 날짜 + 시각** — 로그 대조의 정답 |
| `udoy` | UTC 날짜(연중 일수) + 시각 |
| `d` | 직전 캡처 패킷과의 델타 |
| `dd` | 직전 **표시된** 패킷과의 델타 |
| `e` | Unix epoch 초 |

pcap 의 타임스탬프는 **파일 안에 UTC(epoch) 로 저장된다.** 화면에 로컬 시각으로 보이는 것은 표기 변환일 뿐이다. `-t ad` 는 분석 PC 의 타임존을 타므로, 보고서와 타임라인에는 `-t ud`(UTC) 또는 `-t e`(epoch) 를 쓰고 KST 는 명시적으로 +9시간 계산해 병기한다.

```bash
# UTC 절대시각으로 출력 — EVTX/access.log 와 대조 가능
tshark -r capture.pcapng -n -t ud -c 5

# epoch 로 뽑아 스크립트에서 변환
tshark -r capture.pcapng -T fields -e frame.time_epoch -e ip.src -c 3
```

```text
1773645302.418221	10.0.0.15
1773645302.601884	203.0.113.77
1773645302.734550	10.0.0.15
```

`1773645302` → UTC `2026-03-16 09:55:02` → KST `2026-03-16 18:55:02`. Unix epoch 는 1970-01-01 UTC 기준 초이며, FILETIME(1601 기준 100ns) 과의 차이는 `11644473600`초다.

### 통계 — `-z`

`-z` 는 항상 `-q` 와 함께 쓴다. 유효한 subtype 전체 목록은 `tshark -z help` 로 확인한다.

| `-z` 값 | 출력 | GUI 동등물 |
| --- | --- | --- |
| `io,phs` | 프로토콜 계층 비중 | Statistics > Protocol Hierarchy |
| `conv,tcp` / `conv,udp` / `conv,ip` | 대화 목록 (패킷/바이트) | Statistics > Conversations |
| `endpoints,ip` / `endpoints,tcp` | 종점 목록 | Statistics > Endpoints |
| `io,stat,<간격>,<필터>` | 시간 구간별 카운트 | Statistics > I/O Graph |
| `http,tree` | 상태 코드/요청 통계 | Statistics > HTTP > Packet Counter |
| `http_req,tree` | 요청 URI 별 카운트 | Statistics > HTTP > Requests |
| `dns,tree` | DNS 질의/응답 통계 | Statistics > DNS |
| `smb,srt` / `smb2,srt` | SMB 응답 시간 | Statistics > Service Response Time |
| `expert` | 전문가 정보(재전송, 오류) | Analyze > Expert Information |
| `follow,tcp,ascii,<stream>` | 스트림 내용 | Follow > TCP Stream |
| `credentials` | 평문 자격증명 후보 목록 | — ([FOR-0187](./pcap-credentials.html)) |

```bash
# 10초 구간별 HTTP 요청 수와 DNS 질의 수를 동시에
tshark -r capture.pcapng -q -z io,stat,10,'http.request','dns.flags.response==0'
```

### 파일에서 객체 뽑기

```bash
tshark -r capture.pcapng --export-objects help
tshark -r capture.pcapng --export-objects http,out_http/
```

`--export-objects <protocol>,<destdir>` 는 디렉터리에 파일을 저장하며, **이름이 겹치면 덮어쓰지 않고 확장자 앞에 번호를 붙인다.** 그래서 `report(1).pdf` 같은 파일이 생긴다. 자세한 것은 [FOR-0189](./pcap-file-extraction.html).

### 필드 이름·프로토콜 이름을 모를 때

| 명령 | 출력 |
| --- | --- |
| `tshark -G protocols` | 프로토콜 약칭 목록 (`-O` 에 넣을 이름) |
| `tshark -G fields` | **전체 필드 이름 목록** (수십만 줄. grep 필수) |
| `tshark -G values` | 필드별 값 이름 매핑 |
| `tshark -z help` | `-z` subtype 전체 |
| `tshark -d .` | `-d` 에 쓸 수 있는 selector 목록 |

```bash
# ftp 로 시작하는 필드만 찾는다
tshark -G fields | grep -P '^F\tftp' | cut -f2,3 | head -20
```

```powershell
tshark -G fields | Select-String -Pattern '\tftp\.' | Select-Object -First 20
```

## 빠른 명령

```bash
tshark -r capture.pcapng -n -t ud -c 20
```

```bash
# 프로토콜 비중 (가장 먼저)
tshark -r capture.pcapng -q -z io,phs

# TCP 대화 — 바이트 큰 순서가 목표
tshark -r capture.pcapng -q -z conv,tcp

# HTTP 요청을 CSV 로
tshark -r capture.pcapng -n -Y 'http.request' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e http.host -e http.request.uri \
  -E header=y -E separator=, -E quote=d

# 특정 패킷 하나만 상세히, HTTP 만
tshark -r capture.pcapng -Y 'frame.number == 842' -V -O http

# 비표준 포트 8080 을 HTTP 로 강제 + 재조립 켜기
tshark -r capture.pcapng -d tcp.port==8080,http -o tcp.desegment_tcp_streams:TRUE \
  -Y 'http.request' -T fields -e http.request.uri

# 2-pass 로만 채워지는 필드 (응답 시간, 응답 프레임 번호)
tshark -r capture.pcapng -2 -R 'http' -Y 'http.request' \
  -T fields -e http.request.uri -e http.time -e http.response_in

# 스트림 4 의 내용을 텍스트로
tshark -r capture.pcapng -q -z follow,tcp,ascii,4

# HTTP 로 전송된 파일 전부 추출
tshark -r capture.pcapng --export-objects http,out_http/ && file out_http/*
```

```powershell
# PowerShell — 필터는 작은따옴표로 감싼다
tshark -r capture.pcapng -Y 'http.request.method == "POST"' -T fields -e http.request.uri

# 결과를 CSV 로 받아 바로 집계
tshark -r capture.pcapng -n -Y 'dns.flags.response == 0' -T fields -e dns.qry.name |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 10 Count, Name
```

```bash
# capinfos / editcap / mergecap
capinfos capture.pcapng
mergecap -w merged.pcapng part1.pcapng part2.pcapng
editcap -c 20000 big.pcapng chunk.pcapng
editcap -r capture.pcapng picked.pcapng 100-200
```

## 함께 보는 artifact

| tshark 로 얻은 것 | 다음에 볼 것 |
| --- | --- |
| `-z io,phs` 의 이상한 프로토콜 | 그 프로토콜 전담 필터 ([FOR-0146](./wireshark-30sec-triage.html)) |
| `-z conv,tcp` 의 최대 바이트 대화 | `tcp.stream eq <n>` 으로 Follow, 파일 추출 ([FOR-0189](./pcap-file-extraction.html)) |
| POST 요청 목록 | 본문·자격증명 ([FOR-0158](./http-post-find.html)) |
| 평문 자격증명 | EVTX 4624/4625 로 실제 로그온 확인 ([FOR-0083](./event-4624-logon.html)) |
| `frame.time_epoch` | 디스크 artifact 타임라인 ([FOR-0050](./ntfs-artifact-timeline.html)) |
| 추출한 실행 파일 해시 | Amcache / Prefetch / `$MFT` ([FOR-0021](./mft-basics.html)) |

## 흔한 실수

- **저장 파일에 `-f` 를 쓰는 것.** `-f 'tcp port 80'` 은 캡처 필터(BPF)이고 이미 저장된 파일에는 적용되지 않는다. `-Y 'tcp.port == 80'` 을 써야 한다. 문법도 다르다 — BPF 는 `port 80`, 디스플레이 필터는 `tcp.port == 80`.
- **`-R` 를 `-2` 없이 쓰는 것.** `-R` 는 1차 패스 필터이므로 단일 패스에서는 의미가 없고, 버전에 따라 `-R without -2` 경고 또는 오류가 난다. 단일 패스에서는 항상 `-Y`.
- **`-w out.txt` 로 텍스트를 저장하려는 것.** `-w` 는 원시 패킷을 쓴다. 텍스트는 `> out.txt` 리다이렉션으로 받는다.
- **`-c` 를 "필터에 걸린 패킷 n개"로 이해하는 것.** `-c` 는 **읽은 패킷** 수를 센다. `-Y` 로 걸러진 것도 포함되므로 `-c 10` 이 결과 10줄을 보장하지 않는다. 결과 줄 수를 제한하려면 `| head -10` 을 쓴다.
- **`-z` 를 `-q` 없이 쓰는 것.** 패킷 요약 수만 줄이 통계 앞에 쏟아져 통계를 못 찾는다. `-q -z ...` 가 정답이다.
- **`-e` 없이 `-T fields` 를 쓰는 것.** `-T fields` 는 `-e` 를 최소 하나 요구한다. 빈 줄만 나오거나 오류가 난다.
- **`-o` 값의 대소문자.** boolean preference 는 `TRUE`/`FALSE` 로 쓴다. `true`/`1` 이 통하는 버전도 있으나 일관되지 않으므로 대문자로 고정한다.
- **`-n` 없이 분석하는 것.** 이름 변환이 켜져 있으면 분석 PC 에서 **외부 DNS 질의가 나간다.** 증거 처리 원칙에도 어긋나고, 출력에 `example.com` 이 들어와 IP 기준 grep 이 어긋난다.
- **`-d` 의 selector 를 프로토콜 이름으로 착각하는 것.** `-d http==8080` 이 아니라 `-d tcp.port==8080,http` 다. 좌변은 **선택자 필드**, 우변은 붙일 프로토콜이다.
- **GUI 와 결과가 다를 때 필터를 의심하는 것.** 필터보다 먼저 볼 것은 아래 세 가지다.

| GUI 와 tshark 가 다를 때 | 확인 |
| --- | --- |
| 필드가 비어 나온다 (`http.time`, `http.response_in`, `tcp.analysis.*` 일부) | `-2` 를 붙인다. 미래 정보가 필요한 필드다 |
| 본문/재조립 필드가 비어 나온다 (`http.file_data`) | `-o tcp.desegment_tcp_streams:TRUE`, `-o http.decompress_body:TRUE` |
| 프로토콜이 `TCP` 로만 나온다 | `-d tcp.port==<포트>,<프로토콜>` |
| 패킷 자체가 사라졌다 | `-o tcp.check_checksum:FALSE` — 체크섬 오프로드 캡처 |
| GUI 에서 켜둔 설정이 반영되지 않는다 | GUI 는 프로필의 `preferences` 파일을 쓴다. tshark 는 같은 프로필을 읽지만 GUI 에서 저장하지 않은 변경은 모른다. `-o` 로 명시한다 |

## mini example

```text
문제:
"이 캡처에서 서버가 응답하는 데 가장 ���래 걸린 HTTP 요청의 URI 를 구하세요."
첨부: web.pcapng (9,120 packets)

1. 첫 시도 (실패)
   $ tshark -r web.pcapng -Y 'http.request' -T fields -e http.request.uri -e http.time
   /index.html
   /login
   /admin/report.php
   ...
   -> http.time 컬럼이 전부 비어 있다.

   원인: http.time 은 "요청 → 응답까지 걸린 시간" 이다.
        요청 패킷을 읽는 시점에는 응답이 아직 오지 않았으므로
        단일 패스에서는 계산할 수 없다.
        같은 이유로 http.response_in, http.request_in 도 비어 나온다.

2. 접근 변경 — -2 (2-pass) 를 붙인다
   $ tshark -r web.pcapng -2 -Y 'http.request' \
       -T fields -e frame.number -e http.request.uri -e http.time -e http.response_in \
       -E header=y

   frame.number  http.request.uri     http.time  http.response_in
   210           /index.html          0.014221   214
   488           /login               0.102885   495
   1902          /admin/report.php    4.871004   1955     <-- 가장 느리다
   3771          /export.php?all=1    0.220118   3780

3. 정렬로 확정 (컬럼 3번이 http.time)
   $ tshark -r web.pcapng -2 -Y 'http.request' \
       -T fields -e http.request.uri -e http.time | sort -k2 -g -r | head -3
   /admin/report.php	4.871004
   /export.php?all=1	0.220118
   /login	0.102885

4. 응답 내용 확인 — 왜 느렸나
   $ tshark -r web.pcapng -2 -Y 'frame.number == 1955' -V -O http | head -20
     Content-Length: 4194304
   -> 4 MB 응답. 대량 데이터 반출 후보다.

정답: /admin/report.php (4.871초)
```

`http.time` 이 비어 있는 것을 "필드 이름이 틀렸다"로 오해하면 `tshark -G fields | grep http.time` 만 반복하게 된다. **비어 나오는 필드는 이름 문제가 아니라 패스 문제일 때가 많다.**

## 출처

- SRC-010 — Wireshark tshark man page: `-r` `-w` `-c` `-Y` `-f` `-2` `-R` `-T`(ek/fields/json/jsonraw/pdml/ps/psml/tabs/text) `-e` `-E`(bom/header/separator/occurrence/aggregator/quote/escape) `-z` `-q` `-Q` `-V` `-x` `-O` `-n` `-N`(d/g/m/n/N/s/t/v) `-d` `-o` `-l` `-t`(a/ad/adoy/d/dd/e/r/u/ud/udoy) `--export-objects` 의 문법과 기본값
- SRC-002 — Wireshark Display Filter Reference: `-e` / `-Y` 에 넣는 필드 이름(`http.time`, `http.response_in`, `frame.time_epoch`, `_ws.col.*`)
- `-z` subtype 목록과 `-o` preference 이름은 Wireshark 버전에 따라 추가·변경된다. 실제 환경에서 `tshark -z help`, `tshark -G currentprefs` 로 확인할 것
- `-z credentials` 는 비교적 최근에 추가된 subtype이므로 구버전에는 없을 수 있다. `tshark -z help` 출력에 없으면 [FOR-0187](./pcap-credentials.html) 의 필터 방식을 쓴다
- Windows/macOS 의 설치 경로는 설치 옵션에 따라 다를 수 있으므로 실제 경로를 확인할 것
