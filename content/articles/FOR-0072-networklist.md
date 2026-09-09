---
id: FOR-0072
title: "NetworkList로 접속한 네트워크와 SSID·게이트웨이 MAC 찾기"
slug: "networklist"
category: "Registry"
type: "guide"
difficulty: "intermediate"
priority: "critical"
platform: [windows]
artifact: ["NetworkList", "Profiles", "Signatures", "DefaultGatewayMac", "SYSTEMTIME", "Wlansvc profile"]
file_paths: ["C:\\Windows\\System32\\config\\SOFTWARE", "C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles"]
registry_paths: ["SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged"]
event_ids: []
protocols: []
tools: ["RegRipper", "RegistryExplorer", "rla", "FTK Imager", "KAPE"]
commands: ["rip.exe -r SOFTWARE -p networklist", "rip.exe -r SOFTWARE -p profilelist"]
regex_patterns: []
wireshark_filters: []
tshark_fields: []
log_fields: ["ProfileName", "Description", "NameType", "Category", "Managed", "DateCreated", "DateLastConnected", "DefaultGatewayMac", "DnsSuffix", "FirstNetwork", "ProfileGuid"]
file_formats: ["regf", "xml"]
primary_terms: ["NetworkList", "연결한 네트워크", "SSID 흔적", "무선 접속 기록"]
keywords: ["NetworkList", "SSID", "연결한 네트워크", "ProfileName", "DateLastConnected", "DateCreated", "DefaultGatewayMac", "SYSTEMTIME", "Signatures", "Unmanaged", "Managed", "DnsSuffix", "Wlansvc", "무선 프로파일"]
aliases: ["networklist", "연결한 wifi", "ssid 흔적", "무선 접속 기록", "어느 공유기에 붙었나", "네트워크 접속 시각", "wifi 이름 찾기"]
symptom_keywords: ["어떤 Wi-Fi에 접속했는지 알고 싶다", "네트워크 접속 시각이 필요하다", "DateLastConnected가 이상한 값으로 나온다", "게이트웨이 MAC으로 위치를 특정하고 싶다", "SSID 목록을 뽑고 싶다", "타임스탬프 변환이 안 된다"]
related: ["FOR-0054", "FOR-0055", "FOR-0051", "FOR-0075"]
source_ids: ["SRC-017", "SRC-077", "SRC-099"]
last_verified: "2026-09-10"
status: "verified"
---

## 한 줄 결론

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`의 `Profiles\{GUID}`에서 SSID(`ProfileName`)와 접속 시각을, `Signatures\{Managed,Unmanaged}\<hash>`에서 `DefaultGatewayMac`을 얻는다. 함정은 시각이다 — **`DateCreated`/`DateLastConnected`는 FILETIME이 아니라 16바이트 `SYSTEMTIME` 구조이고 로컬 시각으로 저장**되므로 FILETIME 변환기에 넣으면 반드시 틀린 값이 나온다.

## 어떤 문제에서 필요한가

`SOFTWARE` hive만 있으면 "이 PC가 어디에 있었나"를 답할 수 있다. 물리적 위치 추정의 근거가 되는 유일한 레지스트리 artifact다.

- "어떤 Wi-Fi(SSID)에 접속했나, 목록 전체를 뽑고 싶다"
- "그 네트워크에 **처음 접속한 시각**과 **마지막 접속 시각**은 언제인가"
- "회사망인가 집인가 공용 와이파이인가" (`Category`, `Managed`, `DnsSuffix`)
- "어느 공유기였나" — `DefaultGatewayMac`은 특정 공유기 하드웨어를 지목한다
- "노트북이 사고 시각에 어느 네트워크에 있었나"

## 문제에서 처음 볼 단서

1. 첨부에 `SOFTWARE`가 있고 지문에 "네트워크", "Wi-Fi", "SSID", "접속", "위치"가 있다
2. 지문이 MAC 주소를 주고 "이 공유기에 접속했는지" 묻는다 → `Signatures` 쪽부터 본다
3. 타임스탬프를 FILETIME으로 변환했는데 1601년이나 30827년 같은 값이 나온다 → **SYSTEMTIME이다**
4. `C:\ProgramData\Microsoft\Wlansvc\Profiles`가 함께 첨부됐다 → 무선 프로파일 XML까지 요구하는 문제다

## 30초 절차

```powershell
rip.exe -r "C:\case\SOFTWARE" -p networklist
```

```text
NetworkList
Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles

{A3B1C4D0-77E2-4C1B-9F3A-1D2E5B6C8A90}
  ProfileName         : CTF-OFFICE-5G
  Description         : CTF-OFFICE-5G
  NameType            : 0x47 (71) - wireless
  Category            : 1 (Private)
  Managed             : 0
  DateCreated         : 2026-02-11 09:24:37 (local)
  DateLastConnected   : 2026-03-14 16:12:05 (local)

Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged

010103000F0000F0080000000F0000F0E1CFE0...
  ProfileGuid       : {A3B1C4D0-77E2-4C1B-9F3A-1D2E5B6C8A90}
  Description       : CTF-OFFICE-5G
  FirstNetwork      : CTF-OFFICE-5G
  DefaultGatewayMac : 8C:1A:BF:03:D4:E7
  DnsSuffix         : ctf.local
```

## 상세 절차

### 1단계 — 두 갈래를 함께 본다

```text
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
  Profiles\{GUID}                    <- 네트워크 이름과 시각
  Signatures\Managed\<hash>          <- 도메인 인증 네트워크의 물리 정보
  Signatures\Unmanaged\<hash>        <- 그 외 네트워크의 물리 정보
  Nla\...                            <- 위치 인식 캐시 (존재 여부가 환경에 따라 다르다)
```

두 갈래는 `ProfileGuid` 값으로 이어진다.

```text
Signatures\Unmanaged\<hash>\ProfileGuid  =  {A3B1C4D0-...}
                                            ||
Profiles\{A3B1C4D0-...}\ProfileName      =  CTF-OFFICE-5G
```

**이름은 `Profiles`에, 물리 정보(게이트웨이 MAC·DNS 접미사)는 `Signatures`에** 있다. 한쪽만 보면 절반만 나온다.

| 갈래 | 서브키 이름 | 들어 있는 것 |
| --- | --- | --- |
| `Profiles` | 네트워크 프로파일 GUID | `ProfileName`, `Description`, `NameType`, `Category`, `Managed`, `DateCreated`, `DateLastConnected` |
| `Signatures\Managed` | 네트워크 시그니처 해시(긴 hex 문자열) | 도메인 인증을 받은 네트워크. `DefaultGatewayMac`, `DnsSuffix`, `FirstNetwork`, `ProfileGuid` |
| `Signatures\Unmanaged` | 같은 형식 | 가정·카페·핫스팟 등 도메인 인증이 없는 네트워크 |

### 2단계 — `Profiles\{GUID}`의 값

| 값 이름 | 타입 | 의미 |
| --- | --- | --- |
| `ProfileName` | `REG_SZ` | **무선이면 SSID, 유선이면 "네트워크"·도메인 이름 등 표시 이름** |
| `Description` | `REG_SZ` | 대개 `ProfileName`과 같다. 사용자가 이름을 바꾸면 달라진다 |
| `NameType` | `REG_DWORD` | 연결 종류 (아래 표) |
| `Category` | `REG_DWORD` | 방화벽 프로파일 분류 (아래 표) |
| `Managed` | `REG_DWORD` | `1`이면 도메인이 관리하는 네트워크 |
| `DateCreated` | `REG_BINARY` 16바이트 | **처음 접속한 시각. SYSTEMTIME, 로컬 시각** |
| `DateLastConnected` | `REG_BINARY` 16바이트 | **마지막 접속 시각. SYSTEMTIME, 로컬 시각** |
| `NameSource` 등 기타 | `REG_DWORD` | 환경에 따라 존재. 결론에 쓰지 않는다 |

`Category` 값:

| 값 | 의미 | 실무 해석 |
| --- | --- | --- |
| `0` | 공용(Public) | 카페·공항·핫스팟. 기본값이므로 "그냥 붙였다"는 뜻이기도 하다 |
| `1` | 개인(Private) | 사용자가 "신뢰"를 선택했다. **집·개인 사무실일 확률이 높다** |
| `2` | 도메인(Domain) | 도메인 컨트롤러 인증에 성공했다. 회사 내부망 |

`Category = 1`이나 `2`는 사용자가 그 네트워크를 반복적으로/의도적으로 썼다는 강한 신호다.

`NameType` 값 중 실무에서 자주 보는 것:

| 값 (hex) | 값 (dec) | 의미 |
| --- | --- | --- |
| `0x06` | 6 | 유선(이더넷) |
| `0x17` | 23 | VPN·광대역 연결 계열 |
| `0x47` | 71 | **무선(Wi-Fi)** |

다른 값도 존재하며 빌드에 따라 추가된다. **표에 없는 값이 나오면 값으로 종류를 단정하지 말고 `Signatures`의 `DefaultGatewayMac` 유무와 Wlansvc 프로파일 XML의 존재로 유·무선을 판정한다.**

### 3단계 — 결정적 함정: SYSTEMTIME 16바이트

`DateCreated`와 `DateLastConnected`는 **FILETIME이 아니다.** Windows API의 `SYSTEMTIME` 구조를 그대로 덤프한 128비트(16바이트)이고, 각 필드가 2바이트 `WORD`(리틀엔디언)다.

| 오프셋 | 크기 | 필드 | 비고 |
| --- | --- | --- | --- |
| `0x00` | 2 | `wYear` | `2026` = `0x07EA` |
| `0x02` | 2 | `wMonth` | 1~12 |
| `0x04` | 2 | `wDayOfWeek` | **0 = 일요일** ~ 6 = 토요일. 검산용 |
| `0x06` | 2 | `wDay` | 1~31 |
| `0x08` | 2 | `wHour` | 0~23 |
| `0x0A` | 2 | `wMinute` | 0~59 |
| `0x0C` | 2 | `wSecond` | 0~59 |
| `0x0E` | 2 | `wMilliseconds` | 0~999 |

**그리고 이 값은 로컬 시각이다.** UTC가 아니다. FILETIME(UTC)만 다루던 습관으로 +9시간을 또 더하면 9시간 미래의 답이 나온다.

```text
hex:  EA 07 03 00 06 00 0E 00 10 00 1F 00 02 00 7B 00
      \___/ \___/ \___/ \___/ \___/ \___/ \___/ \___/
      Year  Month  DoW   Day   Hour   Min   Sec    ms
      07EA  0003  0006  000E  0010  001F  0002  007B
      2026    3     6    14    16    31     2    123

=> 2026-03-14 16:31:02.123  (로컬 시각, 요일 = 6 = 토요일)
```

`wDayOfWeek`가 **검산 도구**다. 계산한 날짜의 실제 요일과 이 값이 다르면 바이트를 잘못 잘랐다는 뜻이다. 2026-03-14는 토요일이므로 `6`이 맞다.

```powershell
# 라이브 시스템에서 SYSTEMTIME 을 사람이 읽는 문자열로
$guid = '{A3B1C4D0-77E2-4C1B-9F3A-1D2E5B6C8A90}'
$key  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\$guid"
$p    = Get-ItemProperty $key
foreach ($name in 'DateCreated', 'DateLastConnected') {
    $b  = $p.$name
    $st = 0..7 | ForEach-Object { [BitConverter]::ToUInt16($b, $_ * 2) }
    '{0} = {1:d4}-{2:d2}-{3:d2} {4:d2}:{5:d2}:{6:d2}.{7:d3} (local, dow={8})' -f `
        $name, $st[0], $st[1], $st[3], $st[4], $st[5], $st[6], $st[7], $st[2]
}
```

```text
DateCreated = 2026-02-11 09:24:37.812 (local, dow=3)
DateLastConnected = 2026-03-14 16:31:02.123 (local, dow=6)
```

오프라인 hive만 있으면 RegistryExplorer로 값의 hex를 읽고 위 표대로 2바이트씩 자른다. **로컬 시각이므로 시간대를 답에 함께 적어야 한다.** 시간대는 `SYSTEM\ControlSet001\Control\TimeZoneInformation`에서 확인한다([FOR-0054](./system-timezone.html)).

| 이 글의 시각 | 기준 |
| --- | --- |
| `DateCreated` / `DateLastConnected` | **로컬 시각** (SYSTEMTIME) |
| 레지스트리 키 LastWrite | UTC (FILETIME) |
| 대부분의 다른 Windows artifact | UTC (FILETIME) |

같은 표에 넣을 때는 반드시 한쪽으로 통일하고 열 이름에 `(KST)` 또는 `(UTC)`를 붙인다.

### 4단계 — `Signatures`의 `DefaultGatewayMac`

`Signatures\Managed` 또는 `Signatures\Unmanaged` 아래 서브키 이름은 네트워크 시그니처 해시(긴 hex 문자열)다. 그 안의 값들이 물리적 특정의 근거다.

| 값 이름 | 의미 | 활용 |
| --- | --- | --- |
| `DefaultGatewayMac` | `REG_BINARY`. **앞 6바이트가 기본 게이트웨이(공유기)의 MAC** | 특정 공유기 하드웨어 지목. 위치 추정의 핵심 |
| `DnsSuffix` | DNS 접미사 (`ctf.local`, `lan` 등) | 조직 내부망 판별 |
| `FirstNetwork` | 처음 인식된 네트워크 이름 | 대개 SSID와 같다 |
| `ProfileGuid` | `Profiles\{GUID}`로 가는 링크 | 이름·시각과 연결 |
| `Description` | 설명 문자열 | 이름 확인 보조 |
| `Source` | 숫자 값 | 의미가 공개되어 있지 않다. **결론에 쓰지 않는다** |

```powershell
$sig = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\010103000F0000F0080000000F0000F0E1CFE0'
($sig.DefaultGatewayMac[0..5] | ForEach-Object { $_.ToString('X2') }) -join ':'
```

```text
8C:1A:BF:03:D4:E7
```

`DefaultGatewayMac`은 6바이트보다 길게(패딩 포함) 저장될 수 있다. **앞 6바이트만 MAC이다.** 나머지 바이트를 MAC의 일부로 읽으면 존재하지 않는 주소가 만들어진다.

MAC 앞 3바이트(`8C:1A:BF`)는 OUI로, 제조사 등록 블록이다. 공유기 제조사 추정에 쓸 수 있지만 **오프라인 환경에서는 OUI 목록이 없으므로 외운 값으로 제조사를 단정하지 않는다.** 같은 MAC이 서로 다른 PC의 hive에서 발견되면 **두 PC가 같은 공유기 아래에 있었다**는 강력한 정황이 된다.

### 5단계 — 무선 프로파일 XML로 보강

```text
C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{인터페이스 GUID}\{프로파일 GUID}.xml
```

```xml
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>CTF-OFFICE-5G</name>
  <SSIDConfig>
    <SSID>
      <hex>435446...</hex>
      <name>CTF-OFFICE-5G</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
      </authEncryption>
    </security>
  </MSM>
</WLANProfile>
```

| 얻는 것 | 의미 |
| --- | --- |
| `<name>` / `<SSID><name>` | SSID. `ProfileName`과 교차 확인 |
| `<SSID><hex>` | SSID의 hex 표현. 비ASCII SSID나 숨김 SSID일 때 유용 |
| `<connectionMode>auto` | **자동 접속 설정. 반복 사용 네트워크라는 신호** |
| `<authentication>` / `<encryption>` | 보안 방식. 개방망(`open`)이면 공용 핫스팟 정황 |
| `<keyMaterial>` | 존재하면 자격 정보. 평문이 아닐 수 있고 보호되어 있으므로 **복호 가능성을 전제하지 않는다** |
| 파일 자체의 `$MFT` 타임스탬프 | 프로파일 생성/수정 시각 |

레지스트리에는 프로파일 GUID가, XML 파일 이름에는 같은 GUID가 들어 있어 서로 매칭된다. `SOFTWARE` hive가 손상됐을 때 이 XML만으로 SSID 목록을 복원할 수 있다.

### 6단계 — 목록 전체를 시간순으로 만든다

```powershell
rip.exe -r "C:\case\SOFTWARE" -p networklist > netlist.txt

# 무선만 추리기 (NameType 71) / 마지막 접속 시각 순으로 보기
Select-String -Path netlist.txt -Pattern 'ProfileName|DateLastConnected|NameType|Category|DefaultGatewayMac'
```

결과를 표로 정리하면 사건의 이동 경로가 보인다.

| ProfileName | NameType | Category | DateCreated (local) | DateLastConnected (local) | DefaultGatewayMac |
| --- | --- | --- | --- | --- | --- |
| `CTF-OFFICE-5G` | 71 (무선) | 1 (개인) | 2026-02-11 09:24:37 | 2026-03-14 16:31:02 | `8C:1A:BF:03:D4:E7` |
| `Network` | 6 (유선) | 0 (공용) | 2026-01-08 21:02:11 | 2026-02-27 08:41:55 | `00:1B:44:11:3A:B7` |
| `FREE_WIFI_CAFE` | 71 (무선) | 0 (공용) | 2026-03-13 19:52:40 | 2026-03-13 21:10:04 | `44:D9:E7:0C:22:81` |

## 출력 필드 해석

| 필드 | 어디서 | 결론에 어떻게 쓰나 |
| --- | --- | --- |
| `ProfileName` | `Profiles\{GUID}` | SSID/네트워크 이름 답안 |
| `NameType` | `Profiles\{GUID}` | 유선/무선/VPN 구분. 71이 무선 |
| `Category` | `Profiles\{GUID}` | 0 공용 / 1 개인 / 2 도메인 |
| `DateCreated` | `Profiles\{GUID}` | **최초 접속 시각. SYSTEMTIME, 로컬** |
| `DateLastConnected` | `Profiles\{GUID}` | **마지막 접속 시각. SYSTEMTIME, 로컬** |
| `DefaultGatewayMac` 앞 6바이트 | `Signatures\...` | 공유기 MAC. 물리적 위치·장치 특정 |
| `DnsSuffix` | `Signatures\...` | 조직 내부망 판별 |
| `ProfileGuid` | `Signatures\...` | 두 갈래를 잇는 키 |
| 프로파일 키 LastWrite | REGF `nk` | UTC. `DateLastConnected`(로컬)와 9시간 차이가 나면 정상이다 |

프로파일 키의 LastWrite(UTC)를 KST로 바꾼 값이 `DateLastConnected`(로컬)와 거의 같아야 한다. **이 대조가 SYSTEMTIME 해석이 맞았는지 확인하는 가장 빠른 검산이다.**

## pivot: 다음에 볼 artifact

| 이 글에서 얻은 값 | 다음에 열 것 | 무엇을 확인하나 |
| --- | --- | --- |
| SSID | `C:\ProgramData\Microsoft\Wlansvc\Profiles` | 보안 방식, 자동 접속 여부, SSID hex |
| `DefaultGatewayMac` | 다른 PC의 `SOFTWARE` hive | 같은 공유기 아래 있었는지 |
| `DefaultGatewayMac` | pcap의 ARP·DHCP ([FOR-0146](./wireshark-30sec-triage.html)) | 캡처와 이 PC가 같은 망인지 |
| `DateLastConnected` 시각 | EVTX System/보안 로그, BAM ([FOR-0071](./bam-dam.html)) | 그 시각의 사용자 활동 |
| `DnsSuffix` | DNS 캐시, 브라우저 기록 | 내부망 호스트 접근 |
| `Category = 2` | `SOFTWARE\...\ProfileList`, 도메인 SID | 도메인 가입 여부 |
| 시간대 확인이 필요할 때 | `SYSTEM\Control\TimeZoneInformation` ([FOR-0054](./system-timezone.html)) | 로컬 ↔ UTC 변환 기준 |
| 이동식 장치와 함께 볼 때 | [FOR-0075](./usb-serial-drive-letter.html) | 같은 시각대의 USB 연결 |

## 흔한 함정

- **`DateLastConnected`를 FILETIME으로 변환하는 것.** 이 값은 SYSTEMTIME 16바이트다 → 1601년이나 30827년 같은 값이 나오거나 도구가 오류를 낸다 → 2바이트씩 8개 필드로 자른다.
- **SYSTEMTIME 값을 UTC로 취급해 +9시간 하는 것.** 이미 로컬 시각이다 → 9시간 미래의 답을 낸다 → 답안에 `(로컬/KST)`이라고 명시하고 추가 변환하지 않는다.
- **`wDayOfWeek`를 날짜(일)로 읽는 것.** 오프셋 `0x04`가 요일, `0x06`이 날짜다 → 3월 6일과 3월 14일을 뒤바꾼다 → 요일 값으로 날짜 계산을 **검산**한다.
- **`DefaultGatewayMac`을 전체 길이로 읽는 것.** 앞 6바이트만 MAC이고 뒤는 패딩이다 → 8바이트 "MAC"을 만들어 대조에 실패한다 → `[0..5]`만 쓴다.
- **`Profiles`만 보고 끝내는 것.** 게이트웨이 MAC과 `DnsSuffix`는 `Signatures` 쪽에 있다 → 위치 특정 근거를 놓친다 → `ProfileGuid`로 두 갈래를 반드시 잇는다.
- **`ProfileName`을 항상 SSID로 단정하는 것.** 유선(`NameType = 6`)이면 `Network`, `네트워크 2`, 도메인 이름 등이 들어간다 → 유선 연결을 Wi-Fi로 보고한다 → `NameType`과 `DefaultGatewayMac`/Wlansvc XML로 유·무선을 확정한다.
- **`Category = 0`(공용)을 "한 번만 붙었다"로 읽는 것.** 공용은 기본값일 뿐이다 → 반복 접속을 놓친다 → `DateCreated`와 `DateLastConnected`의 간격으로 판단한다.
- **프로파일이 지워진 네트워크를 없다고 결론하는 것.** 사용자가 "네트워크 삭제"를 하면 키가 지워진다 → 접속 이력 자체를 부정하게 된다 → Wlansvc XML의 잔존 파일, `$MFT`·`$UsnJrnl`의 XML 삭제 레코드, EVTX로 보완한다.
- **OUI로 제조사를 단정하는 것.** 오프라인에서는 등록 목록을 조회할 수 없다 → 근거 없는 브랜드 주장이 된다 → OUI는 "제조사 등록 블록"이라고만 서술하고 확인 가능한 출처를 명시한다.
- **`SOFTWARE` hive의 트랜잭션 로그를 반영하지 않는 것.** 마지막 접속이 `.LOG1`/`.LOG2`에만 있을 수 있다 → 최신 접속을 놓친다 → `rla`로 반영한다([FOR-0051](./registry-hive-map.html)).
- **`Signatures` 서브키 이름의 해시를 시각·SSID로 해석하려 드는 것.** 네트워크 식별용 해시일 뿐이다 → 무의미한 해독 시도로 시간을 버린다 → 내부 값만 읽는다.

## 교차검증

```powershell
# 1) NetworkList 전체
rip.exe -r "C:\case\SOFTWARE" -p networklist > netlist.txt

# 2) 시간대 확인 (SYSTEMTIME 이 로컬이므로 반드시 필요)
rip.exe -r "C:\case\SYSTEM" -p timezone

# 3) 프로파일 키 LastWrite(UTC) vs DateLastConnected(로컬) 검산
#    RegistryExplorer 에서 Profiles\{GUID} 의 LastWrite 를 읽고 +9h 해서 비교

# 4) 무선 프로파일 XML 과 SSID 대조
Select-String -Path 'C:\case\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*\*.xml' -Pattern '<name>'

# 5) 사고 시각의 사용자 활동
rip.exe -r "C:\case\SYSTEM" -p bam > bam.txt
```

`DateLastConnected`(로컬)를 UTC로 되돌린 값이 프로파일 키 LastWrite와 몇 초 이내로 맞으면 SYSTEMTIME 해석이 옳다는 뜻이다. 크게 벗어나면 바이트를 잘못 자른 것이다.

## mini walkthrough

```text
문제:
"SOFTWARE hive 가 첨부됩니다. 피의자 노트북이 마지막으로 접속한 무선 네트워크의
 SSID 와 접속 시각(KST), 그 공유기의 MAC 주소를 구하세요."

1. 첫 시도 (실패):
   RegistryExplorer 로 Profiles\{A3B1C4D0-...} 를 열고
   DateLastConnected 의 16바이트를 그대로 DCode 의 FILETIME 에 넣었다.

     EA 07 03 00 06 00 0E 00 10 00 1F 00 02 00 7B 00
     -> DCode 결과: 1601 년대의 말도 안 되는 시각

   "값이 손상됐다" 고 판단하고 다른 artifact 를 찾으러 갔다.

   왜 틀렸나:
   NetworkList 의 DateCreated/DateLastConnected 는 FILETIME 이 아니다.
   16바이트 SYSTEMTIME 이고, WORD 8개(년/월/요일/일/시/분/초/밀리초)로 잘라야 한다.
   FILETIME 은 8바이트 단일 정수이므로 애초에 구조가 다르다.

2. 올바른 해석
     07EA=2026  0003=3  0006=토요일  000E=14
     0010=16    001F=31 0002=2       007B=123ms
   -> 2026-03-14 16:31:02.123
   요일 검산: 2026-03-14 는 토요일 -> wDayOfWeek=6 과 일치. OK

3. 두 번째 실수 — 시각을 또 변환함
   습관적으로 "레지스트리 시각은 UTC" 라고 생각해 +9시간 해서
   2026-03-15 01:31:02 KST 라고 답을 적었다.

   왜 틀렸나:
   SYSTEMTIME 으로 저장된 이 두 값은 이미 로컬 시각이다.
   시간대가 Korea Standard Time 이므로 16:31:02 자체가 KST 다.

   검산: Profiles\{A3B1C4D0-...} 의 키 LastWrite = 2026-03-14 07:31:05Z (UTC)
        +9h = 16:31:05 KST  -> DateLastConnected 16:31:02 와 3초 차이. 정합.

4. SSID 와 종류 확인
   ProfileName = CTF-OFFICE-5G
   NameType    = 0x47 (71) -> 무선
   Category    = 1 -> 개인(신뢰) 네트워크

5. 공유기 MAC — Signatures 로 이동
   Signatures\Unmanaged\<hash>\ProfileGuid = {A3B1C4D0-...}  (일치)
     DefaultGatewayMac (REG_BINARY) = 8C 1A BF 03 D4 E7 00 00
   앞 6바이트만 MAC -> 8C:1A:BF:03:D4:E7
   (뒤 00 00 을 포함해 8바이트로 읽으면 오답이 된다)

6. 보강
   C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{...}\{...}.xml
     <name>CTF-OFFICE-5G</name>
     <connectionMode>auto</connectionMode>
     <authentication>WPA2PSK</authentication>
   -> 자동 접속으로 등록된 반복 사용 네트워크

정답: SSID CTF-OFFICE-5G, 2026-03-14 16:31:02 KST,
      게이트웨이 MAC 8C:1A:BF:03:D4:E7
```

## 막혔을 때 다음 체크

1. `Profiles`와 `Signatures`를 **둘 다** 봤는가. `ProfileGuid`로 이었는가
2. 시각을 SYSTEMTIME(16바이트, WORD 8개)으로 잘랐는가 — FILETIME이 아니다
3. `wDayOfWeek`로 날짜를 검산했는가
4. SYSTEMTIME이 **로컬 시각**임을 반영했는가. 추가 변환을 하지 않았는가
5. 키 LastWrite(UTC)와 `DateLastConnected`(로컬)를 대조해 검산했는가
6. `DefaultGatewayMac`을 **앞 6바이트만** 읽었는가
7. `NameType`으로 유·무선을 구분했는가 — 71이 무선
8. `rla`로 `SOFTWARE.LOG1`/`.LOG2`를 반영했는가
9. 프로파일이 안 보이면 → `C:\ProgramData\Microsoft\Wlansvc\Profiles`의 XML, `$UsnJrnl`의 XML 삭제 레코드로 보완
10. 시간대 값을 `SYSTEM\Control\TimeZoneInformation`에서 확인했는가 ([FOR-0054](./system-timezone.html))

## 출처

- SRC-017 — Microsoft Learn, Windows Registry hives and file locations: `SOFTWARE` hive의 위치와 `Microsoft\Windows NT\CurrentVersion` 계층 구조, 오프라인 hive 경로 표기
- SRC-077 — IEEE 등록 기관(MAC 주소 표기와 OUI): `DefaultGatewayMac` 앞 6바이트를 MAC으로 읽는 표기 규칙과 앞 3바이트가 제조사 등록 블록(OUI)이라는 근거
- SRC-099 — RegRipper 3.0 저장소: `networklist`, `timezone`, `bam` 플러그인의 존재와 `rip.exe` 옵션
- `SYSTEMTIME` 구조(각 필드 2바이트 WORD, 총 16바이트, `wDayOfWeek`는 0=일요일)는 Windows API 정의를 따른다. **`DateCreated`/`DateLastConnected`가 로컬 시각으로 저장된다는 점은 이 키에 한정된 특징이므로, 사건에서는 키 LastWrite(UTC)와 대조해 검산할 것**
- `NameType` 값의 전체 목록과 `Signatures\...\Source` 값의 의미는 공개 문서로 확정되지 않았다. 이 글은 자주 관찰되는 값만 제시하고 나머지는 단정하지 않는다
- `C:\ProgramData\Microsoft\Wlansvc\Profiles` 하위 경로와 XML 스키마는 Windows 버전에 따라 다를 수 있으므로 실제 파일에서 확인할 것
- RegRipper 플러그인 이름과 출력 형식은 버전에 따라 다를 수 있으므로 `rip.exe -l`로 확인할 것
