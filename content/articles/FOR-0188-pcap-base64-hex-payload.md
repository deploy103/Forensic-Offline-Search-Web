---
id: FOR-0188
title: "pcap 안 Base64/hex로 인코딩된 페이로드 찾기"
slug: "pcap-base64-hex-payload"
category: "Network/PCAP"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "DNS query name", "HTTP body", "ICMP payload"]
file_paths: []
registry_paths: []
event_ids: []
protocols: ["DNS", "HTTP", "ICMP", "TCP"]
tools: ["Wireshark", "tshark", "CyberChef", "Base64encoder", "HxD"]
commands: ["tshark -r cap.pcapng -Y \"dns\" -T fields -e dns.qry.name", "echo BASE64STR | base64 -d | xxd | head", "python3 -c \"import base64,sys;print(base64.b64decode(sys.argv[1]))\" STR", "xxd -r -p hex.txt out.bin"]
regex_patterns: ["[A-Za-z0-9+/]{20,}={0,2}", "[A-Fa-f0-9]{32,}"]
wireshark_filters: ["frame matches \"[A-Za-z0-9+/]{20,}={0,2}\"", "dns.qry.name.len > 40", "http.request.method == \"POST\"", "tcp contains \"==\""]
tshark_fields: ["dns.qry.name", "http.file_data", "data.data"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["pcap base64", "pcap hex payload"]
keywords: ["Base64 디코딩", "hex 디코딩", "DNS 터널링", "인코딩된 페이로드", "패딩", "CyberChef", "RFC 4648", "data exfiltration", "인코딩 후보 탐지"]
aliases: ["pcap 안에 base64", "패킷에서 base64 찾기", "dns 안에 hex", "pcap 인코딩 데이터", "패딩 등호", "패킷 디코딩", "숨겨진 문자열 디코딩"]
symptom_keywords: ["문자열이 알파벳과 숫자로만 되어 있다", "등호로 끝나는 이상한 문자열이 보인다", "16진수만 잔뜩 있다", "디코딩해도 깨진다", "flag가 인코딩되어 있는 것 같다"]
related: ["FOR-0155", "FOR-0146", "FOR-0189", "FOR-0180"]
source_ids: ["SRC-074", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`[A-Za-z0-9+/]{20,}={0,2}`(Base64) 또는 `[A-Fa-f0-9]{32,}`(hex) 패턴에 걸리는 긴 문자열을 `frame contains`/`dns.qry.name`/Follow Stream에서 찾은 뒤 `base64 -d`나 `xxd -r -p`로 바로 디코딩해 본다 — **틀린 인코딩으로 추측해서 시간을 버리는 것이 가장 흔한 실수**이므로 문자 집합만으로 먼저 후보를 좁힌다.

## 어떤 문제에서 필요한가

- HTTP 요청/응답 본문, DNS 쿼리 이름, ICMP 페이로드에 평문이 아닌 이상한 문자열이 반복된다
- "flag가 pcap 안에 인코딩되어 숨겨져 있다"는 지문
- Export Objects/Follow Stream으로 텍스트를 봤는데 읽을 수 없다
- 여러 패킷에 나눠서 조각조각 인코딩된 데이터를 이어 붙여야 한다

## 문제에서 처음 볼 단서

1. **문자 집합이 좁다** — `A-Za-z0-9+/=`만 있으면 Base64, `0-9a-fA-F`만 있으면 hex
2. **길이가 4의 배수(Base64)** — 패딩(`=`, `==`)이 끝에 있으면 거의 확정
3. **DNS 쿼리 이름의 서브도메인이 비정상적으로 길고 무작위처럼 보인다** — DNS 터널링과 겹친다 ([FOR-0155](./dns-tunneling.html))
4. **HTTP 헤더에 `Content-Transfer-Encoding: base64`, 쿠키/파라미터 값이 `=`로 끝난다**
5. **hex 문자열 길이가 짝수** — 홀수면 hex가 아니거나 앞뒤가 잘렸다

## 30초 절차

```bash
tshark -r cap.pcapng -Y "http.request or dns" -T fields -e frame.number -e dns.qry.name -e http.file_data
```

1. `frame matches "[A-Za-z0-9+/]{20,}={0,2}"`로 Base64 후보 패킷을 필터링
2. 해당 스트림을 Follow TCP Stream으로 열어 전체 문자열 확보
3. 문자 집합 확인 → Base64면 `base64 -d`, hex면 `xxd -r -p`
4. 디코딩 결과에 `file`/`strings` 적용

## 상세 절차

### 1단계 — 인코딩 종류 판별

| 특징 | Base64 | hex(Base16) | Base32 |
| --- | --- | --- | --- |
| 문자 집합 | `A-Za-z0-9+/` (URL-safe는 `-_`) | `0-9A-Fa-f` | `A-Z2-7` |
| 패딩 | `=` 0~2개, 길이가 4의 배수 | 없음. 길이가 항상 짝수 | `=` 0~6개, 길이가 8의 배수 |
| 예 | `ZmxhZ3s...` | `666c6167...` | `NBSWY3DP...` |
| 3바이트 → 문자 수 | 4자 | 6자 | 8자(5바이트 단위) |

RFC 4648(SRC-074)이 세 인코딩의 알파벳과 패딩 규칙을 정의한다. **`+`나 `/`가 보이면 hex가 아니라 Base64다.** `-`나 `_`가 섞여 있으면 URL-safe Base64(RFC 4648 §5)이므로 표준 디코더가 그대로 실패할 수 있다.

```bash
# URL-safe -> 표준 Base64로 치환 후 디코딩
echo "ZmxhZ3sxMjM0-Cg_" | tr '_-' '/+' | base64 -d
```

### 2단계 — Wireshark에서 후보 찾기

```text
frame matches "[A-Za-z0-9+/]{20,}={0,2}"
frame matches "[A-Fa-f0-9]{32,}"
dns.qry.name.len > 40
http.request.method == "POST" && http.content_length > 0
```

`matches`는 Wireshark가 PCRE를 사용한다(SRC-002). 대소문자를 구분하므로 필요하면 `(?i)`를 붙인다.

```text
frame matches "(?i)[a-z0-9+/]{20,}={0,2}"
```

### 3단계 — 데이터를 뽑아 파일로 저장

Follow Stream 창에서 `Show data as`를 `ASCII`로 두고 인코딩된 부분만 복사하거나, tshark로 필드째 뽑는다.

```bash
# HTTP 본문만 모아 파일로
tshark -r cap.pcapng -Y "http.request.method==\"POST\"" -T fields -e http.file_data > body_hex.txt

# tshark의 -e 필드는 기본이 hex 문자열이다. 그대로 xxd -r -p 로 바이너리 복원 가능
tr -d '\n:' < body_hex.txt | xxd -r -p > body.bin
```

DNS 서브도메인을 이어 붙이는 경우 순서(시퀀스 번호나 프레임 번호)를 지켜야 한다.

```bash
tshark -r cap.pcapng -Y "dns.flags.response==0" -T fields -e frame.number -e dns.qry.name |
  sort -k1 -n |
  awk -F'.' '{print $1}' |
  cut -f2- > pieces.txt
```

### 4단계 — 실제 디코딩

```bash
# Base64
cat piece.txt | base64 -d > out.bin

# 패딩이 깨졌을 때 (길이를 4의 배수로 맞춘다)
python3 -c "
import base64, sys
s = sys.stdin.read().strip()
s += '=' * (-len(s) % 4)
sys.stdout.buffer.write(base64.b64decode(s))
" < piece.txt > out.bin

# hex
cat hex.txt | tr -d ' \n' | xxd -r -p > out.bin
```

```powershell
# PowerShell 에서 Base64 디코딩
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('ZmxhZ3sxMjM0Cg=='))

# hex 디코딩
$bytes = [byte[]] -split ('66 6c 61 67' -replace '..', '0x$& ')
[System.Text.Encoding]::UTF8.GetString($bytes)
```

```python
import base64
data = "ZmxhZ3sxMjM0Cg=="
print(base64.b64decode(data))
# b'flag{1234\n'

data_hex = "666c61677b31323334"
print(bytes.fromhex(data_hex))
# b'flag{1234'
```

## 출력 필드 해석

| 관찰 | 해석 |
| --- | --- |
| 디코딩 결과가 매직 바이트(예: `PK\x03\x04`, `\x89PNG`)로 시작 | 인코딩된 것은 파일 전체다. `file`로 확인 후 확장자 부여 |
| 디코딩 결과가 다시 Base64/hex처럼 보인다 | **다중 인코딩(레이어링).** 한 번 더 디코딩 |
| `base64 -d`가 "invalid input" 에러 | 패딩 누락, 개행/공백 혼입, URL-safe 문자 혼입 중 하나 |
| `xxd -r -p` 결과가 의미 없는 바이트 | hex가 아니라 실제로 Base64였을 가능성. 문자 집합 재확인 |
| 서브도메인마다 길이가 다르다 | 마지막 조각에 패딩. 순서대로 이어 붙여야 정상 디코딩 |

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 것 | 다음 목표 |
| --- | --- |
| 디코딩된 바이너리 | `file`/`strings`/`binwalk`로 형식 판정, 필요시 카빙 ([FOR-0189](./pcap-file-extraction.html)) |
| 반복되는 인코딩된 DNS 서브도메인 | DNS 터널링 전체 흐름 분석 ([FOR-0155](./dns-tunneling.html)) |
| 디코딩된 문자열이 명령어 | 공격자 C2 명령 이력 재구성 |
| 인코딩 위치가 HTTP 헤더/쿠키 | 그 값이 세션·인증 토큰인지 확인 |
| 여러 스트림에 걸친 조각 | `tcp.stream`별로 순서 재조립 ([FOR-0164](./tcp-stream-filter.html)) |

## 흔한 함정

- **`+`/`/`가 있는데 hex로 시도하는 것** → hex는 0-9a-f만 허용한다 → 문자 집합을 먼저 확인한다.
- **패딩을 무시하고 자르는 것** → Base64 길이가 4의 배수가 아니면 디코더가 에러를 내거나 마지막 바이트를 깨뜨린다 → `=` 개수를 세어 맞춘다.
- **URL-safe Base64(`-`, `_`)를 표준 디코더에 그대로 넣는 것** → 문자가 알파벳에 없어 실패한다 → `tr '_-' '/+'` 후 디코딩한다.
- **개행이나 청크 구분자를 그대로 포함시키는 것** → HTTP chunked encoding의 청크 크기 줄이 문자열 중간에 섞여 디코딩이 깨진다 → Wireshark의 재조립된 `http.file_data`를 쓴다.
- **한 번만 디코딩하고 포기하는 것** → 다중 레이어(Base64 안에 hex, hex 안에 Base64)가 CTF에서 흔하다 → 결과가 다시 인코딩 문자 집합이면 반복한다.
- **조각을 프레임 순서가 아니라 알파벳 순으로 이어 붙이는 것** → DNS 응답은 도착 순서가 보장되지 않는다 → 시퀀스 번호나 `frame.number`로 정렬한다.
- **tshark `-e` 필드가 이미 hex 문자열이라는 것을 모르고 다시 hex로 취급하는 것** → 이중 디코딩이 되어 깨진다 → 필드 출력 형식을 먼저 확인한다(`-e http.file_data`는 hex, `-Y` 매칭 텍스트는 문자열).
- **디코딩 결과를 UTF-8로만 강제하는 것** → 결과가 실제로 바이너리(이미지/zip)면 텍스트 디코딩이 예외를 낸다 → 항상 바이트로 먼저 저장하고 `file`로 판정한다.

## 교차검증

```bash
# 1) Wireshark 필터와 strings 결과 대조
strings -n 20 cap.pcapng | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'

# 2) CyberChef 없이 여러 인코딩을 한 번에 시도 (오프라인)
for f in base64 base32; do
  echo "== $f =="
  python3 -c "
import base64, sys
s = open('piece.txt').read().strip()
try:
    print(getattr(base64, 'b64decode' if '$f'=='base64' else 'b32decode')(s + '=' * (-len(s) % 4)))
except Exception as e:
    print('fail:', e)
"
done

# 3) 디코딩 결과 형식 확인
file out.bin
xxd out.bin | head -3
```

두 경로(Wireshark UI와 CLI)에서 뽑은 원문 문자열이 바이트 단위로 같은지 `diff`로 확인한다. 다르면 재조립(청크/개행 처리)이 어느 한쪽에서 틀렸다는 뜻이다.

## mini walkthrough

```text
문제:
"pcap 안에 flag가 인코딩되어 숨겨져 있습니다."
첨부: hidden.pcapng (612 packets)

1. Protocol Hierarchy 확인 -> HTTP 43건, 나머지는 TCP 핸드셰이크/ACK
   http.request 필터 -> GET /api/beacon?d=... 요청이 반복

2. 첫 시도 (실패):
   쿼리 파라미터 d 값을 hex로 간주하고 xxd -r -p 시도
   $ echo "aGVsbG8=" | xxd -r -p
   -> 깨진 바이트만 나옴. hex 알파벳(0-9a-f) 범위를 벗어난 문자(g,l,o,=)가 있는데
      무시하고 강행한 것이 원인이었다.

3. 문자 집합 재확인
   값: aGVsbG8=  -> A-Za-z 와 마지막 '=' 뿐. Base64 확정 (패딩 1개, 길이 8 = 4의 배수)

4. 디코딩
   $ echo "aGVsbG8=" | base64 -d
   hello
   -> 첫 요청은 헬로 비콘. flag 는 아니다. 43건을 모두 훑어야 한다.

5. 43건을 전부 추출해 순서대로 디코딩
   $ tshark -r hidden.pcapng -Y 'http.request.uri contains "/api/beacon"' \
       -T fields -e frame.number -e http.request.uri.query.parameter |
     sort -n -k1 |
     cut -f2 |
     sed 's/^d=//' > all_d.txt

   $ while read -r line; do
       pad=$(( (4 - ${#line} % 4) % 4 ))
       printf '%s%s\n' "$line" "$(printf '=%.0s' $(seq 1 $pad))" | base64 -d
     done < all_d.txt | tr -d '\n'
   flag{b4se64_1n_query_str1ng_2026}

정답: flag{b4se64_1n_query_str1ng_2026}
```

3단계에서 hex와 Base64를 헷갈린 것이 실패 원인이었다. **알파벳 범위를 벗어난 문자가 하나라도 있으면 그 인코딩이 아니다** — 강행하지 않고 문자 집합부터 다시 본다.

## 막혔을 때 다음 체크

1. 문자 집합을 눈으로 확인했는가 (`+`, `/`, `=` 있으면 Base64. `0-9a-f`만이면 hex)
2. 길이가 인코딩 규칙(Base64는 4배수, hex는 짝수)에 맞는가
3. 패딩(`=`)이 누락되지 않았는가
4. URL-safe 문자(`-`, `_`)가 섞여 있지 않은가
5. 여러 패킷에 걸쳐 조각나 있지는 않은가 — 순서를 프레임 번호로 정렬했는가
6. 한 번 디코딩한 결과가 또 인코딩된 것처럼 보이지 않는가 (다중 레이어)
7. 디코딩 결과를 텍스트로 강제하기 전에 `file`로 바이너리 여부를 확인했는가
8. tshark `-e` 필드가 이미 hex라는 점을 감안했는가

## 출처

- SRC-074 — RFC 4648: Base16(hex)/Base32/Base64 알파벳, 패딩 규칙, URL-safe 변형
- SRC-002 — Wireshark Display Filter Reference: `matches`(PCRE) 연산자
- SRC-003 — Wireshark User's Guide: Follow Stream, 필드 값 표시 형식
- CyberChef는 도구 목록에 없어 예시에서 제외했다. 오프라인 환경에서는 `base64`/`xxd`/Python `base64` 모듈로 동일한 작업이 가능하다
