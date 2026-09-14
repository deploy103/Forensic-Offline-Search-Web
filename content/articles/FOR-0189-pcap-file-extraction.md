---
id: FOR-0189
title: "pcap에서 전송된 파일 복원하기"
slug: "pcap-file-extraction"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP object", "FTP-DATA", "SMB file", "TFTP file", "IMF attachment"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "FTP", "SMB", "SMTP", "TFTP"]
tools: ["Wireshark", "tshark", "HxD", "binwalk", "foremost"]
commands: ["tshark -r cap.pcapng --export-objects http,out_http", "tshark -r cap.pcapng --export-objects smb,out_smb", "tshark -r cap.pcapng --export-objects imf,out_mail", "foremost -i cap.pcapng -o carved"]
regex_patterns: []
wireshark_filters: ["http.request", "http.response", "ftp-data", "smb2.cmd == 5", "tcp.stream eq 4", "imf"]
tshark_fields: ["http.file_data", "http.content_type", "tcp.stream"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["pcap 파일 카빙", "패킷에서 파일 복원"]
keywords: ["Export Objects", "Follow TCP Stream", "HTTP 파일 추출", "FTP-DATA", "SMB 파일", "IMF 첨부", "청크 전송", "gzip 압축", "패킷 카빙"]
aliases: ["pcap에서 파일 뽑기", "패킷에서 파일 추출", "다운로드한 파일 복원", "export objects 안됨", "pcap 파일 카빙", "패킷에서 이미지 꺼내기"]
symptom_keywords: ["Export Objects에 아무것도 안 나온다", "다운로드한 파일을 찾아야 한다", "추출한 파일이 열리지 않는다", "파일이 잘려서 나온다", "압축이 풀리지 않는다"]
related: ["FOR-0165", "FOR-0146", "FOR-0188", "FOR-0168"]
source_ids: ["SRC-003", "SRC-002", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`File > Export Objects`(HTTP/SMB/IMF/TFTP)로 먼저 시도하고, 목록이 비거나 항목이 없으면 `Follow > TCP Stream`에서 `Show data as: Raw`로 저장하는 두 단계면 pcap에서 전송된 파일 대부분을 복원할 수 있다 — **Export Objects가 비어 있다고 파일이 없는 것은 아니다.**

## 어떤 문제에서 필요한가

- "전송된 파일을 찾아 그 안의 flag를 구하라"는 지문
- Protocol Hierarchy에서 HTTP/FTP-DATA/SMB의 `Bytes`가 크게 잡힌다
- 파일이 여러 조각(청크 전송, TCP 세그먼트)으로 나뉘어 있다
- 이메일 첨부파일을 SMTP 캡처에서 꺼내야 한다

## 문제에서 처음 볼 단서

1. Protocol Hierarchy에서 `Bytes`가 큰 프로토콜 — HTTP/FTP-DATA/SMB2가 후보 ([FOR-0146](./wireshark-30sec-triage.html))
2. `Content-Type`, `Content-Disposition: attachment; filename=...` 헤더
3. `STOR`/`RETR`(FTP), `WRITE`(SMB) 커맨드
4. 파일 크기와 무관하게 패킷 수가 비정상적으로 많은 TCP 스트림 하나
5. `.zip`, `.exe`, `.docx`, `.jpg` 같은 확장자가 URI나 파일명에 보인다

## 30초 절차

```bash
tshark -r cap.pcapng --export-objects http,out_http
```

1. `File > Export Objects > HTTP` (또는 SMB/IMF/TFTP) 확인
2. 비어 있으면 `Statistics > Conversations > TCP`에서 Bytes 1위 스트림 확인
3. 그 스트림 `Follow > TCP Stream` → `Show data as: Raw` → Save As
4. 저장한 파일에 `file`/`binwalk` 적용

## 상세 절차

### 1단계 — Export Objects로 먼저 시도

`File > Export Objects >` 뒤에 오는 하위 메뉴는 캡처에 실제로 있는 프로토콜만 활성화된다.

| 메뉴 | 대상 | 비고 |
| --- | --- | --- |
| HTTP | GET/POST 응답 본문, 업로드된 multipart 파일 | 가장 흔하게 성공 |
| SMB / SMB2 | 공유 폴더로 전송된 파일 | `smb2.cmd == 5`(Create) 전후 확인 |
| IMF | SMTP로 보낸 메일 원문(`.eml`), MIME 첨부 포함 | 첨부는 메일 본문 안에서 Base64로 인코딩되어 있을 수 있다 |
| TFTP | TFTP 전송 파일 | UDP 기반, 컨트롤러/부트 관련 캡처에서 자주 등장 |
| DICOM | 의료 영상 | CTF에서는 드묾 |

목록 창에서 항목을 우클릭 → `Save As` 또는 `Save All`.

```bash
# CLI 로 동일 작업 (여러 프로토콜을 한 번에)
tshark -r cap.pcapng --export-objects http,out_http
tshark -r cap.pcapng --export-objects smb,out_smb
tshark -r cap.pcapng --export-objects imf,out_mail
tshark -r cap.pcapng --export-objects tftp,out_tftp
ls -la out_http/ && file out_http/*
```

FTP-DATA는 **Export Objects 메뉴에 없다.** FTP는 항상 Follow Stream이나 아래 2단계로 처리한다.

### 2단계 — Export Objects가 실패하는 경우와 대안

| 실패 원인 | 왜 | 대안 |
| --- | --- | --- |
| Passive mode FTP | 데이터 채널이 별도 포트로 열려 Wireshark가 FTP-DATA로 연결 못 함 | Conversations에서 Bytes 큰 스트림을 수동으로 찾아 Follow |
| TCP 재조립 실패 | 캡처가 스트림 중간부터 시작 | `Analyze > Expert Information`에서 확인, 잘린 데이터로 부분 복구 시도 |
| Chunked transfer encoding | 청크 크기 줄이 파서를 혼동시킴 | Wireshark가 대개 자동 처리하지만 실패하면 `http.file_data` raw로 수동 재조립 |
| gzip/deflate 압축 응답 | Export Objects는 압축 해제된 상태로 주는 경우가 많지만, 설정에 따라 원본 그대로 나올 수 있다 | `file`로 gzip 여부 확인 후 `gunzip` |
| 비표준 포트의 HTTP | `Protocol` 컬럼이 `TCP`로만 보여 HTTP로 파싱 안 됨 | 패킷 우클릭 `Decode As > HTTP` 후 재시도 |
| 암호화(TLS) | 페이로드 자체가 안 보인다 | 개인키가 주어졌다면 `Preferences > Protocols > TLS`에 등록 후 복호화 |

### 3단계 — Follow Stream으로 직접 저장 (만능 대안)

```text
1. 대상 스트림 패킷 우클릭 > Follow > TCP Stream (또는 UDP Stream)
2. 좌하단 방향 선택: <- 서버->클라이언트 방향만 (파일 다운로드는 이쪽)
3. 우하단 Show data as: Raw
4. Save as... 로 저장
```

FTP 능동/수동 모드 모두 이 방법으로 파일이 복원된다. 단, **TCP 헤더/HTTP 헤더가 앞에 붙어 있으면 파일 시그니처가 깨진다.** HTTP 응답이면 본문 시작 위치(빈 줄 `\r\n\r\n` 다음)부터 잘라야 한다.

```bash
# HTTP 헤더를 제거하고 본문만 저장 (raw 캡처를 hex로 export한 경우)
python3 -c "
data = open('raw_stream.bin','rb').read()
idx = data.find(b'\r\n\r\n')
open('body.bin','wb').write(data[idx+4:])
"
file body.bin
```

### 4단계 — CLI로 스트림 단위 일괄 재조립

```bash
# 특정 tcp.stream 의 서버->클라이언트 payload 만 순서대로 이어붙인다
tshark -r cap.pcapng -q -z follow,tcp,raw,4 | \
  sed -n '/^[0-9a-f]/p' > stream4_hex.txt
tr -d '\n' < stream4_hex.txt | xxd -r -p > stream4.bin
file stream4.bin
```

`follow,tcp,raw,<stream번호>` 출력은 방향이 섞여 있으므로(`tshark` 버전에 따라 접두 문자로 방향 구분), 실제 사용 전 짧은 스트림으로 형식을 먼저 확인한다.

### 5단계 — 카빙으로 보강

파일 경계를 못 찾을 때는 시그니처 기반 카빙을 pcap 전체에 바로 돌려도 된다. pcap 자체가 일종의 컨테이너이므로 안의 파일이 연속된 바이트로 들어 있으면 걸린다.

```bash
foremost -i cap.pcapng -o carved
ls carved/*/
```

## 출력 필드 해석

| 필드/컬럼 | 의미 | 확인할 점 |
| --- | --- | --- |
| Export Objects `Filename` | HTTP `Content-Disposition`이나 URI에서 유추 | 없으면 `(No filename)`으로 표시 |
| Export Objects `Content Type` | MIME 타입 | 확장자와 불일치하면 위장 가능성 |
| Export Objects `Size` | 재조립된 크기 | pcap 안 실제 전송 바이트와 대조 |
| Follow Stream 좌하단 | 스트림 번호, 총 바이트 | `tcp.stream eq N` 필터에 재사용 |
| `Content-Encoding: gzip` | 본문이 압축됨 | 저장 후 `file`로 gzip 확인, 필요시 `gunzip` |

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 것 | 다음 목표 |
| --- | --- |
| 추출한 실행 파일 | 해시 계산 → Amcache/Prefetch 대조, `strings`/`binwalk` |
| 추출한 문서(zip/docx/pdf) | 메타데이터 확인, 내부 콘텐츠에 flag 은닉 여부 |
| 추출한 이미지 | 스테가노 도구로 재확인 |
| 메일 원문(.eml) | 헤더의 `Received`, 첨부 재추출 |
| 전송 시각 | EVTX/디스크 타임라인과 대조 ([FOR-0108](./attack-timeline-from-eventlog.html)) |
| 인코딩되어 보이는 본문 | Base64/hex 디코딩으로 전환 ([FOR-0188](./pcap-base64-hex-payload.html)) |

## 흔한 함정

- **Export Objects가 비었다고 파일이 없다고 결론짓는 것** → passive FTP, 비표준 포트, gzip 등 여러 이유로 목록이 안 뜬다 → Conversations의 Bytes와 Follow Stream을 항상 대안으로 시도한다.
- **HTTP 헤더째로 저장해 파일이 안 열리는 것** → 헤더와 본문 경계(`\r\n\r\n`)를 안 자르고 저장했다 → Export Objects는 자동으로 분리해 주므로 우선 사용하고, Raw 저장 시 직접 분리한다.
- **Passive FTP 데이터 채널을 FTP-DATA 필터로 찾는 것** → 별도 포트라 필터에 안 걸린다 → Conversations에서 Bytes로 대화를 찾는다.
- **gzip 압축을 확인하지 않고 텍스트 에디터로 여는 것** → 바이너리가 깨진 것처럼 보인다 → `file`로 gzip 여부를 먼저 확인한다.
- **양방향 데이터를 한꺼번에 저장하는 것** → 클라이언트 요청과 서버 응답이 섞여 파일 시그니처가 깨진다 → Follow Stream에서 방향을 선택해 저장한다.
- **`Decode As`를 시도하지 않는 것** → 비표준 포트의 HTTP/FTP는 자동 인식이 안 된다 → 우클릭 `Decode As`로 강제 지정한다.
- **재조립이 안 된 상태로 저장하는 것** → 캡처 시작이 스트림 중간이면 Follow Stream이 앞부분 없이 시작한다 → `Analyze > Expert Information`에서 `[TCP Previous segment not captured]`를 확인한다.
- **확장자를 URI만 보고 단정하는 것** → 실제 바이트는 다른 형식일 수 있다 → 저장 후 항상 `file`/매직 바이트로 재확인한다.

## 교차검증

```bash
# 1) GUI Export Objects 와 동일한 결과인지
tshark -r cap.pcapng --export-objects http,out_http
tshark -r cap.pcapng --export-objects smb,out_smb

# 2) 스트림 재조립 방식으로 같은 파일이 나오는지
tshark -r cap.pcapng -q -z follow,tcp,raw,4 | sed -n '/^[0-9a-f]/p' | tr -d '\n' | xxd -r -p > cli_stream4.bin
diff out_http/some_extracted_file cli_stream4.bin

# 3) 카빙으로도 같은 파일이 나오는지 (독립 경로)
foremost -i cap.pcapng -o carved -t zip,jpg,pdf,exe
ls carved/*/

# 4) 추출 파일 해시 대조
sha256sum out_http/* carved/*/*.* 2>/dev/null | sort
```

세 가지 경로(Export Objects, Follow Stream 수동 저장, 카빙) 중 최소 두 개가 같은 해시를 내면 재조립이 정확했다고 볼 수 있다.

## mini walkthrough

```text
문제:
"직원이 외부로 유출한 파일을 pcap 에서 찾아 flag 를 구하세요."
첨부: leak.pcapng (9,204 packets)

1. Protocol Hierarchy
   FTP Data 6.2% (3.4 MB)  |  FTP 0.4%  |  나머지 TCP/DNS

2. 첫 시도 (실패):
   File > Export Objects > FTP-DATA 메뉴 자체가 비활성화되어 있었다.
   ("메뉴가 없으니 FTP 파일 전송이 없나?" 라고 잘못 판단할 뻔함)
   실제로는 Wireshark Export Objects 메뉴에 FTP-DATA 항목이 애초에 없다.
   (HTTP/SMB/IMF/TFTP/DICOM 뿐)

3. 접근 변경 — ftp 필터로 커맨드 확인
   필터: ftp
   USER anonymous
   PASS guest@
   PASV
   RETR payroll_backup.zip
   -> 전송 방향은 서버->클라이언트(다운로드)

4. Conversations 에서 데이터 채널 확인
   Statistics > Conversations > TCP, Bytes 내림차순
   10.0.0.22:20 <-> 10.0.0.77:51044   2,214 packets   3,405,880 bytes   stream 6

5. Follow > TCP Stream (stream 6), Show data as: Raw, Save as extracted.zip
   $ file extracted.zip
   extracted.zip: Zip archive data
   $ unzip -l extracted.zip
   Archive:  extracted.zip
     Length      Date    Time    Name
   ---------  ---------- -----   ----
      182300  2026-05-02 03:11   payroll.xlsx
        512   2026-05-02 03:11   flag.txt

6. flag 확인
   $ unzip -p extracted.zip flag.txt
   flag{ftp_data_channel_via_follow_stream}

정답: payroll_backup.zip 내부 flag.txt / flag{ftp_data_channel_via_follow_stream}
```

2단계의 착각이 핵심이다. **Wireshark Export Objects 메뉴는 애초에 FTP-DATA를 지원 목록에 넣지 않는다.** 메뉴가 없다고 전송이 없는 것이 아니라, FTP는 원래부터 Follow Stream으로 처리하는 프로토콜이라는 점을 기억해야 한다.

## 막혔을 때 다음 체크

1. `File > Export Objects`의 HTTP/SMB/IMF/TFTP를 모두 확인했는가
2. FTP-DATA는 Export Objects에 없다는 것을 알고 Follow Stream으로 넘어갔는가
3. `Statistics > Conversations`에서 Bytes로 정렬해 큰 대화를 찾았는가
4. Passive mode 가능성을 염두에 두었는가
5. `Analyze > Expert Information`에서 재조립 실패 여부를 확인했는가
6. Follow Stream 저장 시 방향(클라이언트/서버)을 올바르게 선택했는가
7. HTTP 헤더가 본문에 섞여 저장되지 않았는가
8. 저장한 파일에 `file`/`binwalk`/`strings`를 돌렸는가
9. 압축(gzip)이나 청크 인코딩 가능성을 확인했는가
10. 카빙(foremost)으로 독립 경로 검증을 했는가

## 출처

- SRC-003 — Wireshark User's Guide: Export Objects(HTTP/SMB/IMF/TFTP/DICOM), Follow Stream 사용법과 `Show data as` 옵션
- SRC-002 — Wireshark Display Filter Reference: `ftp-data`, `smb2.cmd`, `tcp.stream` 필드
- SRC-010 — tshark man page: `--export-objects`, `-z follow,tcp,raw` 옵션
- Export Objects 메뉴 항목 구성은 Wireshark 버전에 따라 추가/변경될 수 있으므로 실제 화면에서 확인할 것
