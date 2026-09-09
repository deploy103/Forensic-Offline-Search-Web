---
id: FOR-0168
title: "SMB2 공유 파일 접근 흔적: smb2.cmd로 읽은 파일과 계정 특정"
slug: "smb-file-access"
category: "Network/PCAP"
type: "guide"
difficulty: "basic"
priority: "critical"
platform: [windows, linux]
artifact: ["pcap", "pcapng", "SMB share", "named pipe"]
file_paths: ["\\\\server\\C$", "\\\\server\\ADMIN$", "\\\\server\\IPC$"]
registry_paths: []
event_ids: []
protocols: ["SMB", "SMB2", "NTLM", "NBSS", "TCP"]
tools: ["Wireshark", "tshark", "file", "strings"]
commands: ["tshark -r capture.pcapng -Y 'smb2.cmd == 5 && smb2.flags.response == 0' -T fields -e frame.number -e smb2.tree -e smb2.filename", "tshark -r capture.pcapng --export-objects smb,out_smb/", "tshark -r capture.pcapng -Y 'smb2.cmd == 1' -T fields -e smb2.acct -e smb2.domain -e smb2.host"]
regex_patterns: []
wireshark_filters: ["smb2", "smb2.cmd == 3", "smb2.cmd == 5 && smb2.flags.response == 0", "smb2.cmd == 8 || smb2.cmd == 9", "smb2.filename contains \"flag\"", "smb2.tree contains \"$\"", "smb2.nt_status != 0", "tcp.port == 445 || tcp.port == 139", "smb || smb2"]
tshark_fields: ["smb2.cmd", "smb2.filename", "smb2.tree", "smb2.acct", "smb2.host", "smb2.domain", "smb2.nt_status", "smb2.sesid", "smb2.tid", "smb2.read_length", "smb2.write_length", "smb2.flags.response", "smb2.dialect"]
log_fields: []
file_formats: ["pcap", "pcapng"]
primary_terms: ["SMB 분석", "smb2 필터", "공유 파일 접근 흔적"]
keywords: ["SMB", "SMB2", "smb2.cmd", "smb2.filename", "TreeConnect", "관리 공유", "C$", "IPC$", "445 포트", "Export Objects SMB", "NTLM 인증", "측면 이동", "파일 공유 접근"]
aliases: ["smb 필터", "smb2 필터", "공유 폴더 접근 기록", "smb 파일 추출", "445 포트 분석", "누가 어떤 파일을 열었나", "관리 공유 접속"]
symptom_keywords: ["공유 폴더에서 어떤 파일을 가져갔는지 모르겠다", "smb 계정 이름을 찾고 싶다", "445 트래픽이 많다", "smb로 전송된 파일을 추출하고 싶다", "측면 이동 흔적을 찾고 싶다", "Protocol이 SMB2인데 뭘 봐야 하나"]
related: ["FOR-0146", "FOR-0189", "FOR-0190"]
source_ids: ["SRC-073", "SRC-002", "SRC-003"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

SMB 문제는 `smb2.cmd == 3`(TreeConnect)으로 **접속한 공유 이름**을, `smb2.cmd == 5`(Create)의 `smb2.filename`으로 **손댄 파일 목록**을, `smb2.cmd == 1`(SessionSetup)의 `smb2.acct`로 **계정 이름**을 각각 확정한 뒤 `File > Export Objects > SMB`로 파일 본문을 꺼낸다.

## 어떤 문제에서 필요한가

- "공유 폴더에서 어떤 파일을 가져갔는가", "누가 접속했는가"를 답하는 문제
- Protocol Hierarchy에 `SMB2` 또는 `SMB`가 보이는 pcap
- 445번 포트 트래픽이 대화 바이트 1위인 pcap
- 측면 이동(lateral movement) 판정 — 관리 공유(`C$`, `ADMIN$`, `IPC$`) 접속 여부
- EVTX의 5140/5145 이벤트와 pcap을 맞춰 "실제로 어떤 파일이 열렸는가"를 확정하는 문제

## 문제에서 처음 볼 단서

1. **포트 445** — SMB2/SMB3의 기본. 이것 하나만 봐도 SMB 문제다
2. **`Info` 컬럼의 `Tree Connect Request Tree: \\...`** — 공유 이름이 그대로 보인다
3. **`Info` 컬럼의 `Create Request File: ...`** — 파일 경로가 그대로 보인다
4. **공유 이름 끝의 `$`** — `C$`, `ADMIN$`, `IPC$`는 **숨겨진 관리 공유**다. 일반 사용자는 쓰지 않는다
5. **`Session Setup Request, NTLMSSP_AUTH`** — 이 패킷에 계정명·도메인·클라이언트 호스트명이 있다
6. **`Error: STATUS_...`가 반복되는 패턴** — 권한 없는 경로를 훑은 정찰 흔적

## 30초 절차

```text
smb2.cmd == 5 && smb2.flags.response == 0
```

Create 요청만 남으므로 **접근한 파일 목록이 그대로 나온다.** 이어서 세 줄:

```text
smb2.cmd == 3
smb2.cmd == 1
smb2.cmd == 8 || smb2.cmd == 9
```

순서대로 **공유 이름 → 계정 → 실제 읽기/쓰기**다.

CLI로 파일 목록을 한 번에:

```bash
tshark -r capture.pcapng -Y 'smb2.cmd == 5 && smb2.flags.response == 0' \
  -T fields -e frame.number -e smb2.tree -e smb2.filename -E header=y
```

파일 추출:

```bash
tshark -r capture.pcapng --export-objects smb,out_smb/ && file out_smb/*
```

## 상세 절차

### 1단계 — 프로토콜과 포트 확정: `smb`인가 `smb2`인가

| 버전 | 표시 필터 | 포트 | 캡슐화 |
| --- | --- | --- | --- |
| SMB1 (CIFS) | `smb` | 139 또는 445 | 139는 NetBIOS Session Service(`nbss`)로 한 겹 감싸인다 |
| SMB2 / SMB3 | `smb2` | 445 | TCP 위에 직접 |

**`smb2` 필터는 SMB1 패킷을 잡지 못한다.** 어느 쪽인지 모르면 항상 둘 다 쓴다.

```text
smb || smb2
tcp.port == 445 || tcp.port == 139
```

협상된 방언(dialect)은 `smb2.dialect`로 확인한다. `0x0202`=2.0.2, `0x0210`=2.1, `0x0300`=3.0, `0x0311`=3.1.1. **3.1.1은 암호화(SMB3 encryption)가 협상되었을 수 있고, 그 경우 파일명과 본문이 보이지 않는다.** 이때 `Info` 컬럼에 `Encrypted SMB3 data`가 나타난다.

### 2단계 — `smb2.cmd`: 명령 번호로 흐름을 읽는다

`smb2.cmd`는 정수 필드다. 알아야 하는 값만 정리한다.

| `smb2.cmd` | 명령 | 이 명령에서 얻는 것 |
| --- | --- | --- |
| `0` | Negotiate | `smb2.dialect` — 프로토콜 버전, 암호화 여부 |
| `1` | Session Setup | **`smb2.acct`(계정), `smb2.domain`, `smb2.host`(클라이언트 이름)** |
| `2` | Logoff | 세션 종료. 세션 경계 |
| `3` | Tree Connect | **`smb2.tree` — 접속한 공유 UNC 경로** |
| `4` | Tree Disconnect | 공유 접속 해제 |
| `5` | Create | **`smb2.filename` — 열기/생성한 파일 경로.** 가장 중요 |
| `6` | Close | 핸들 닫기. 작업 완료 시점 |
| `8` | Read | **`smb2.read_length` — 실제로 읽어간 바이트** |
| `9` | Write | **`smb2.write_length` — 실제로 쓴 바이트** |
| `11` | Ioctl | 명명 파이프 제어. 원격 서비스 조작에 쓰인다 |
| `14` | Find (Query Directory) | **디렉터리 목록 조회 = 정찰.** 응답에 파일명 나열 |
| `16` | Get Info | 파일 메타데이터(크기, 타임스탬프) 조회 |
| `17` | Set Info | 메타데이터 변경. **타임스탬프 조작·이름 변경·삭제 표시** |

**`5`(Create)와 `8`/`9`(Read/Write)를 구분하는 것이 결정적이다.** Create는 "열었다"는 뜻이고 실제 데이터 이동은 Read/Write에서 일어난다. 디렉터리를 열 때도 Create가 발생하므로, Create만 세면 "가져간 파일"을 과대 계상한다.

```text
smb2.cmd == 5 && smb2.flags.response == 0
```

`smb2.flags.response == 0`을 붙이는 이유: 요청과 응답이 같은 `smb2.cmd` 값을 가지므로, 붙이지 않으면 모든 항목이 두 번 나온다.

### 3단계 — `smb2.tree`: 공유 이름이 곧 판정이다

```bash
tshark -r capture.pcapng -Y 'smb2.cmd == 3 && smb2.flags.response == 0' \
  -T fields -e frame.number -e ip.src -e ip.dst -e smb2.tree
```

```text
118   10.0.0.15   10.0.0.40   \\FS01\IPC$
131   10.0.0.15   10.0.0.40   \\FS01\Shared
902   10.0.0.15   10.0.0.40   \\FS01\C$
```

| 공유 이름 | 의미 | 판정 |
| --- | --- | --- |
| `\\server\Share` 같은 일반 이름 | 업무용 공유 | 정상 접근 가능. 접근 파일이 문제 |
| `\\server\IPC$` | 명명 파이프용 공유 | 원격 관리·인증 협상에 자동으로 붙는다. 단독으로는 노이즈 |
| `\\server\C$` | **C 드라이브 전체를 노출하는 관리 공유** | **관리자 권한 필요. 측면 이동의 강한 신호** |
| `\\server\ADMIN$` | `C:\Windows` 관리 공유 | 원격 서비스 설치·도구 반입 경로 |
| `\\server\D$`, `\\server\E$` | 다른 드라이브 관리 공유 | 같음. 드라이브 문자별 전수 조사 흔적 |
| `\\server\PRINT$`, `\\server\SYSVOL`, `\\server\NETLOGON` | 인쇄 드라이버 / 도메인 공유 | 도메인 환경 신호 |

**`IPC$` 접속 후 `ADMIN$`에 파일을 `Write`하고, 이어 `IPC$`의 명명 파이프에 `Ioctl`이 나가는 조합**은 원격 서비스 생성을 통한 실행의 전형적 순서다. 이 조합을 보면 대상 호스트의 EVTX 7045(서비스 설치)와 4624 Logon Type 3을 함께 확인한다.

`$`로 끝나는 공유만 골라내는 필터:

```text
smb2.tree contains "$"
```

### 4단계 — 계정 이름 확보

`smb2.cmd == 1`(Session Setup)의 마지막 요청 패킷에 인증 정보가 들어 있다. Wireshark는 그 값을 SMB2 계층 필드로도 노출한다.

```bash
tshark -r capture.pcapng -Y 'smb2.cmd == 1' \
  -T fields -e frame.number -e ip.src -e smb2.acct -e smb2.domain -e smb2.host -E header=y
```

```text
frame.number   ip.src      smb2.acct    smb2.domain   smb2.host
104            10.0.0.15   svc_backup   CORP          WKS-DEV-07
```

| 필드 | 내용 | 활용 |
| --- | --- | --- |
| `smb2.acct` | 인증에 쓴 계정 이름 | EVTX 4624의 `TargetUserName`과 대조 |
| `smb2.domain` | 도메인 또는 워크그룹 | 도메인 계정인지 로컬 계정인지 판정 |
| `smb2.host` | **클라이언트가 스스로 보고한 컴퓨터 이름** | EVTX 4624의 `WorkstationName`과 대조 |
| `smb2.sesid` | 세션 ID (64비트) | 같은 세션의 모든 작업을 묶는 키 |
| `smb2.tid` | Tree ID | 어느 공유에 대한 작업인지 연결하는 키 |

`smb2.host`는 클라이언트가 자기 이름을 적어 보내는 값이므로 **위조 가능하지만, 실제 사고에서는 공격자 PC의 진짜 이름이 그대로 남는 경우가 많다.** 도구 기본값(예: 도구가 넣는 임의 문자열)이 들어 있으면 그 자체가 도구 사용의 흔적이다.

인증 교환 자체를 보려면 `ntlmssp` 프로토콜 필터로 좁힌다.

```text
ntlmssp
```

NTLM 협상은 3단계다.

| 순서 | 방향 | 내용 | SMB2 응답 상태 |
| --- | --- | --- | --- |
| 1 | 클라이언트 → 서버 | Negotiate (지원 기능 광고) | `0xc0000016` STATUS_MORE_PROCESSING_REQUIRED |
| 2 | 서버 → 클라이언트 | Challenge (서버 난수, 서버 이름/도메인 노출) | 같음 |
| 3 | 클라이언트 → 서버 | Authenticate (**계정·도메인·호스트명 평문**, 응답 해시) | `0x00000000` 성공 또는 `0xc000006d` 실패 |

**계정 이름·도메인·클라이언트 호스트명은 평문으로 흐른다.** 비밀번호 자체는 흐르지 않는다(챌린지-응답 방식). 그러므로 pcap에서 얻을 수 있는 것은 "누가"이고, "무엇으로"는 얻을 수 없다.

### 5단계 — `smb2.nt_status`로 성공/실패 판정

`smb2.nt_status`는 32비트 정수다. 필터에서는 16진수로 쓴다.

| 값 | 이름 | 해석 |
| --- | --- | --- |
| `0x00000000` | STATUS_SUCCESS | 성공 |
| `0xc0000016` | STATUS_MORE_PROCESSING_REQUIRED | NTLM 협상 중간 단계. **실패가 아니다** |
| `0xc0000022` | STATUS_ACCESS_DENIED | **권한 없음.** 접근 시도는 있었다 |
| `0xc0000034` | STATUS_OBJECT_NAME_NOT_FOUND | 파일/경로 없음. **경로 추측 정찰의 흔적** |
| `0xc000006d` | STATUS_LOGON_FAILURE | **인증 실패.** 반복되면 무차별 대입 |
| `0xc000006a` | STATUS_WRONG_PASSWORD | 비밀번호 오류 |
| `0xc00000cc` | STATUS_BAD_NETWORK_NAME | **존재하지 않는 공유 이름.** 공유 이름 열거의 흔적 |
| `0x80000006` | STATUS_NO_MORE_FILES | 디렉터리 목록 끝. 정상 |

실패만 골라 보는 필터가 정찰 판정에 가장 빠르다.

```text
smb2.nt_status != 0 && smb2.nt_status != 0xc0000016 && smb2.nt_status != 0x80000006
```

`0xc0000034`(경로 없음)가 수십 건 연속이면 공격자가 파일 경로를 추측하며 훑은 것이고, `0xc00000cc`(공유 없음)가 연속이면 공유 이름을 열거한 것이다. **실패 목록이 곧 공격자의 시도 목록이다.**

### 6단계 — 파일 추출

```text
File > Export Objects > SMB...
  Packet   Hostname   Content Type       Size       Filename
  1204     FS01       (unknown)          2317540    \Shared\reports\internal_report.pdf
  1888     FS01       (unknown)             12288    \C$\Users\admin\Desktop\notes.txt
```

```bash
tshark -r capture.pcapng --export-objects smb,out_smb/
ls -lR out_smb/ && file out_smb/*
```

Export Objects가 비면 `smb2.cmd == 8`(Read)/`9`(Write) 응답의 바이트를 직접 꺼낸다.

```text
1. smb2.cmd == 8 필터
2. 응답 패킷 상세창에서 데이터 노드 선택
3. 우클릭 > Export Packet Bytes...
```

여러 Read로 쪼개진 파일은 `Follow > TCP Stream > Raw` 저장 후 SMB 헤더를 잘라내야 하므로, 우선 Export Objects를 신뢰하고 실패 시 크기를 검증한다. `smb2.read_length`의 합이 파일 크기와 맞아야 온전한 추출이다.

```bash
# 읽어간 총 바이트 — 유출량 산정
tshark -r capture.pcapng -Y 'smb2.cmd == 8 && smb2.flags.response == 1' \
  -T fields -e smb2.read_length | awk '{s+=$1} END {print s" bytes"}'
```

### 7단계 — EVTX 5140 / 5145와 대조

pcap과 대상 서버의 보안 이벤트 로그를 맞추면 판정이 확정된다.

| pcap 쪽 | EVTX 쪽 | 대조 항목 |
| --- | --- | --- |
| `smb2.tree` (`\\FS01\C$`) | 5140 (네트워크 공유 개체 접근)의 `ShareName` | 공유 이름 일치 |
| `smb2.filename` | 5145 (상세 파일 공유)의 `RelativeTargetName` | 파일 경로 일치 |
| `smb2.acct` | 5140/5145의 `SubjectUserName`, 4624의 `TargetUserName` | 계정 일치 |
| 클라이언트 IP | 5140의 `IpAddress`, 4624의 `IpAddress` | 출발지 일치 |
| `smb2.host` | 4624의 `WorkstationName` | 단말 이름 일치 |
| 패킷 시각 (UTC) | 이벤트 `TimeCreated` (UTC) | 시각 일치 |

5145는 기본적으로 감사가 꺼져 있어 없는 경우가 많다. **pcap에 있고 EVTX에 없다면 감사 미설정이지 사건의 부재가 아니다.** 반대로 5140만 있고 5145가 없으면 "공유에 붙은 것은 확실하나 어떤 파일인지는 pcap만이 안다"는 뜻이다.

Wireshark의 시각 표시를 UTC 절대시각으로 먼저 바꾼다(`View > Time Display Format > UTC Date and Time of Day`). EVTX는 UTC로 기록되므로 KST(UTC+9)로 환산해 대조하면 9시간 오차가 난다.

## 출력 필드 해석

```bash
tshark -r capture.pcapng -Y 'smb2' -T fields \
  -e frame.number -e smb2.sesid -e smb2.tid -e smb2.cmd \
  -e smb2.tree -e smb2.filename -e smb2.nt_status -E header=y | head -20
```

```text
frame.number  smb2.sesid          smb2.tid    smb2.cmd  smb2.tree      smb2.filename        smb2.nt_status
100                                           0                                             0x00000000
104           0x0000c00000000021              1                                             0xc0000016
108           0x0000c00000000021              1                                             0x00000000
118           0x0000c00000000021  0x00000001  3         \\FS01\IPC$                          0x00000000
131           0x0000c00000000021  0x00000005  3         \\FS01\Shared                        0x00000000
140           0x0000c00000000021  0x00000005  5                        reports              0x00000000
146           0x0000c00000000021  0x00000005  14                       reports              0x00000000
158           0x0000c00000000021  0x00000005  5                        reports\internal.pdf 0x00000000
162           0x0000c00000000021  0x00000005  8                        reports\internal.pdf 0x00000000
```

읽는 법:

- `smb2.sesid`가 같은 행은 **한 인증 세션**이다. 계정이 하나로 묶인다
- `smb2.tid`가 같은 행은 **한 공유**에 대한 작업이다. `tid`로 파일과 공유를 연결한다
- `smb2.filename`은 **공유 루트 기준 상대 경로**다. `\\FS01\Shared` + `reports\internal.pdf` = `\\FS01\Shared\reports\internal.pdf`
- `smb2.cmd == 14`(Find)가 `5`(Create) 뒤에 오면 그 Create는 **디렉터리**를 연 것이다. 파일이 아니다
- `smb2.cmd == 8`(Read)이 붙은 파일만 실제로 내용이 이동했다

## pivot: 다음에 볼 artifact

| SMB에서 얻은 값 | 다음에 볼 것 |
| --- | --- |
| `smb2.acct` 계정명 | EVTX 4624 Logon Type 3 ([FOR-0083](./event-4624-logon.html)) — 원격 로그온 성공 여부 |
| `smb2.host` 클라이언트 이름 | 4624의 `WorkstationName`, DHCP `option 12` 호스트명 |
| `smb2.tree`가 `ADMIN$`/`C$` | 대상 호스트의 7045(서비스 설치), 4697, 4688 ([FOR-0088](./event-4688-process-creation.html)) |
| `smb2.filename` 파일 경로 | 서버 디스크의 `$MFT` ([FOR-0021](./mft-basics.html)) — 접근 시각과 존재 확인 |
| `smb2.cmd == 9`(Write)한 파일 | 그 파일의 실행 흔적(Prefetch, Amcache), 해시 대조 |
| 추출한 바이너리 | `file`/`strings`/`binwalk` ([FOR-0001](./30sec-triage.html)) |
| `0xc000006d` 반복 | 4625 실패 로그온 폭발 구간, 계정 잠금 이벤트 |
| 클라이언트 IP | 그 IP의 다른 프로토콜 트래픽, Sysmon Event 3 ([FOR-0100](./sysmon-event-3-network-connect.html)) |

## 흔한 함정

- **`smb` 필터로 SMB2를 찾는 것.** `smb`는 SMB1(CIFS) 전용 필터다. SMB2/SMB3는 `smb2`로 완전히 별개다. 반대로 `smb2`는 SMB1을 못 잡는다. 모르면 `smb || smb2`로 시작한다.
- **`smb2.flags.response == 0`을 빼고 세는 것.** 요청과 응답이 같은 `smb2.cmd` 값을 가지므로 모든 파일명이 두 번 나온다. "파일 20개"가 실제로는 10개다.
- **`smb2.cmd == 5`(Create) 개수를 곧 접근 파일 수로 세는 것.** 디렉터리를 열 때도 Create가 나간다. `smb2.cmd == 8`(Read)이나 `9`(Write)가 뒤따르지 않는 Create는 실제 데이터 이동이 없다.
- **`smb2.filename`을 전체 경로로 착각하는 것.** 공유 루트 기준 **상대 경로**다. `smb2.tid`로 대응하는 `smb2.tree`를 찾아 앞에 붙여야 UNC 전체 경로가 된다.
- **`0xc0000016`을 인증 실패로 읽는 것.** STATUS_MORE_PROCESSING_REQUIRED는 NTLM 3단계 협상의 정상적인 중간 응답이다. 실제 실패는 `0xc000006d`다.
- **`IPC$` 접속만 보고 측면 이동이라 단정하는 것.** `IPC$`는 원격 관리·인증 협상 과정에서 자동으로 붙는 노이즈에 가깝다. 판정 근거는 `C$`/`ADMIN$` 같은 드라이브 관리 공유와 그 뒤의 Write/Ioctl 조합이다.
- **SMB3 암호화를 놓치는 것.** `smb2.dialect`가 `0x0300` 이상이고 `Info`에 `Encrypted SMB3 data`가 보이면 파일명도 본문도 없다. 이때는 세션 개설 전의 Negotiate/SessionSetup 평문 구간(계정명까지)만 얻는다.
- **139번 포트를 무시하는 것.** SMB1 over NetBIOS는 139다. `tcp.port == 445`만 걸면 SMB1 트래픽 전체를 놓친다.
- **Export Objects의 파일 크기를 검증하지 않는 것.** 여러 Read로 쪼개진 전송이 일부만 캡처되면 잘린 파일이 나온다. `smb2.read_length` 합계와 비교한다.
- **NTLM에서 비밀번호를 찾으려 하는 것.** 챌린지-응답 방식이므로 비밀번호 평문은 와이어에 없다. pcap이 답하는 것은 "누가"까지다.
- **`smb2.nt_status`를 10진수로 필터하는 것.** 값이 크고 표시가 16진수이므로 `smb2.nt_status == 0xc0000022` 형태로 쓴다.
- **EVTX 5145가 없는 것을 근거로 접근이 없었다고 결론내는 것.** 5145는 기본 감사가 꺼져 있다. pcap이 더 신뢰할 수 있는 증거다.

## 교차검증

```bash
# 1) 접속한 공유 목록
tshark -r capture.pcapng -Y 'smb2.cmd == 3 && smb2.flags.response == 0' \
  -T fields -e frame.number -e ip.src -e ip.dst -e smb2.tree

# 2) 접근한 파일 목록 (중복 제거)
tshark -r capture.pcapng -Y 'smb2.cmd == 5 && smb2.flags.response == 0' \
  -T fields -e smb2.filename | sort -u

# 3) 실제로 읽은 파일과 바이트
tshark -r capture.pcapng -Y 'smb2.cmd == 8 && smb2.flags.response == 1' \
  -T fields -e smb2.filename -e smb2.read_length

# 4) 실제로 쓴 파일과 바이트 (도구 반입 판정)
tshark -r capture.pcapng -Y 'smb2.cmd == 9 && smb2.flags.response == 0' \
  -T fields -e smb2.filename -e smb2.write_length

# 5) 계정 / 도메인 / 클라이언트 호스트명
tshark -r capture.pcapng -Y 'smb2.cmd == 1' \
  -T fields -e smb2.acct -e smb2.domain -e smb2.host | sort -u

# 6) 실패 응답 집계 — 정찰 판정
tshark -r capture.pcapng -Y 'smb2.nt_status != 0 && smb2.nt_status != 0xc0000016' \
  -T fields -e smb2.nt_status | sort | uniq -c | sort -nr

# 7) 협상된 방언 — 암호화 여부
tshark -r capture.pcapng -Y 'smb2.cmd == 0 && smb2.flags.response == 1' \
  -T fields -e smb2.dialect

# 8) 파일 추출
tshark -r capture.pcapng --export-objects smb,out_smb/ && file out_smb/*

# 9) 파서 우회 — 공유/파일명은 UTF-16LE 로 흐른다
strings -e l -n 5 capture.pcapng | grep -Ei '\\\\|\.pdf|\.xlsx|\.exe' | head -20
```

9번의 `strings -e l`(little-endian 16비트)이 중요하다. **SMB의 파일명과 공유명은 UTF-16LE 문자열이므로 기본 `strings`로는 걸리지 않는다.**

## mini walkthrough

```text
문제:
"내부 파일 서버에서 자료가 유출되었다. 유출된 파일 이름과 그 안의 flag,
 그리고 사용된 계정 이름을 답하시오."
첨부: smb_case.pcapng (9,880 packets, 4.4 MB)

1. Statistics > Protocol Hierarchy
   TCP 99.6%  |  SMB2 41.2% (4,071 packets, 3.9 MB)
   -> SMB2 확정. 바이트가 크므로 실제 파일이 흘렀다.

2. 첫 시도 (실패):
   필터: smb
   -> 결과 0건. "SMB 트래픽이 없다"는 결론이 나온다.

   원인: smb 는 SMB1(CIFS) 전용 필터다. 이 캡처는 SMB2 이므로
        전혀 다른 디섹터인 smb2 로 걸어야 한다.
        Protocol Hierarchy 에는 "SMB2" 로 적혀 있었는데 필터를 smb 로
        쓴 것이 실수였다.

   교훈: Protocol Hierarchy 의 표기와 필터 이름은 다르다.
        SMB1 = smb, SMB2/SMB3 = smb2. 모르면 smb || smb2 로 시작한다.

3. 필터 수정: smb2
   Info 컬럼에 Tree Connect / Create / Read 가 줄줄이 보인다.

4. 공유 확인
   $ tshark -r smb_case.pcapng -Y 'smb2.cmd == 3 && smb2.flags.response == 0' \
       -T fields -e smb2.tree
   \\FS01\IPC$
   \\FS01\Finance
   \\FS01\C$              <- 관리 공유. 측면 이동 신호

5. 계정 확인
   $ tshark -r smb_case.pcapng -Y 'smb2.cmd == 1' \
       -T fields -e smb2.acct -e smb2.domain -e smb2.host | sort -u
   svc_backup   CORP   WKS-DEV-07
   -> 계정 = CORP\svc_backup, 접속 단말 = WKS-DEV-07

6. 두 번째 실패 — Create 만 세었다
   $ tshark -r smb_case.pcapng -Y 'smb2.cmd == 5' -T fields -e smb2.filename | wc -l
   88
   -> "파일 88개 접근"? 과대 계상이다. 이유 두 가지:
      (a) 요청과 응답이 모두 잡혀 정확히 2배가 되었다
      (b) 디렉터리를 여는 Create 가 섞여 있다

   수정:
   $ tshark -r smb_case.pcapng -Y 'smb2.cmd == 8 && smb2.flags.response == 1' \
       -T fields -e smb2.filename -e smb2.read_length | sort -u
   Finance\2026\payroll_q1.xlsx   1048576
   Finance\2026\payroll_q1.xlsx   1048576
   Finance\2026\payroll_q1.xlsx    220388
   -> 실제로 읽어간 파일은 단 하나. 총 2,317,540 bytes.

7. 추출
   File > Export Objects > SMB... > payroll_q1.xlsx 저장
   $ ls -l payroll_q1.xlsx
   -rw-r--r-- 1 user user 2317540 payroll_q1.xlsx   <- read_length 합계와 일치
   $ file payroll_q1.xlsx
   payroll_q1.xlsx: Microsoft Excel 2007+
   $ unzip -p payroll_q1.xlsx | strings | grep -i 'flag{'
   flag{smb2_n0t_smb_r34d_length}

8. EVTX 대조
   pcap 시각 2026-03-14 07:22:41 UTC = 16:22:41 KST
   FS01 의 보안 로그: 5140 ShareName=\\*\Finance, SubjectUserName=svc_backup,
   IpAddress=10.0.0.15  -> 일치
   5145 는 없음 (상세 파일 공유 감사 미설정) -> 파일명은 pcap 만이 안다

정답: payroll_q1.xlsx / flag{smb2_n0t_smb_r34d_length} / CORP\svc_backup
```

두 번의 실패가 이 글의 요지다. **필터는 `smb`가 아니라 `smb2`이고, 접근 파일 수는 Create가 아니라 `smb2.flags.response`로 방향을 고정한 Read/Write로 센다.**

## 막혔을 때 다음 체크

1. `smb`인가 `smb2`인가 — Protocol Hierarchy 표기와 필터 이름은 다르다
2. `smb2.flags.response == 0`으로 방향을 고정했는가 — 안 하면 개수가 2배
3. `smb2.cmd == 3`으로 공유 이름을 봤는가 — `$`로 끝나면 관리 공유
4. `smb2.cmd == 1`의 `smb2.acct`로 계정을 확보했는가
5. `smb2.cmd == 8`/`9`가 있는가 — Create만 있으면 데이터는 안 움직였다
6. `smb2.filename`에 `smb2.tree`를 앞에 붙였는가 — 상대 경로다
7. `smb2.nt_status != 0` 목록을 봤는가 — 실패 목록이 공격자의 시도 목록
8. `smb2.dialect`가 `0x0300` 이상이고 `Encrypted SMB3 data`가 보이는가 — 그러면 본문 없음
9. `tcp.port == 139`도 확인했는가 — SMB1 트래픽
10. `File > Export Objects > SMB`를 시도했는가
11. 추출 파일 크기가 `smb2.read_length` 합계와 같은가
12. `strings -e l`(UTF-16LE)로 파일명을 직접 찾아봤는가
13. 시각을 UTC 절대시각으로 바꿔 EVTX 5140/5145/4624와 대조했는가

## 출처

- SRC-073 — Microsoft MS-SMB2 프로토콜 문서: SMB2 명령 번호(`SMB2 NEGOTIATE`=0x0000, `SESSION_SETUP`=0x0001, `LOGOFF`=0x0002, `TREE_CONNECT`=0x0003, `TREE_DISCONNECT`=0x0004, `CREATE`=0x0005, `CLOSE`=0x0006, `READ`=0x0008, `WRITE`=0x0009, `IOCTL`=0x000B, `QUERY_DIRECTORY`=0x000E, `QUERY_INFO`=0x0010, `SET_INFO`=0x0011), 방언 리비전 값(0x0202/0x0210/0x0300/0x0311), 세션·트리 식별자 구조, NTLM 협상 중 STATUS_MORE_PROCESSING_REQUIRED 반환 규칙
- SRC-002 — Wireshark Display Filter Reference: `smb2` 항목에서 `smb2.cmd` `smb2.filename` `smb2.tree` `smb2.acct` `smb2.host` `smb2.domain` `smb2.nt_status` `smb2.sesid` `smb2.tid` `smb2.read_length` `smb2.write_length` `smb2.flags.response` `smb2.dialect` `smb2.share_type` `smb2.fid` 확인
- SRC-003 — Wireshark User's Guide: `File > Export Objects > SMB`, `Export Packet Bytes`, `Statistics > Protocol Hierarchy`, `View > Time Display Format`
- NTLMSSP 계층의 개별 필드 이름(예: 인증 메시지의 계정/도메인/호스트 필드)은 이 글에서 확인하지 못해 쓰지 않았다. 같은 정보를 SMB2 계층의 `smb2.acct` / `smb2.domain` / `smb2.host` 로 얻을 수 있으므로 그것을 사용했다. NTLMSSP 세부 필드가 필요하면 dfref의 `ntlmssp` 항목에서 직접 확인할 것
- EVTX 5140/5145 는 이 글의 주제가 아니라 대조 대상이며, 5145 는 "상세 파일 공유" 감사 정책이 켜져 있을 때만 기록된다. 감사 설정 여부는 대상 시스템에서 확인할 것
- `Export Objects` 의 `SMB` 항목명은 Wireshark 버전에 따라 다를 수 있으므로 실제 화면에서 확인할 것
