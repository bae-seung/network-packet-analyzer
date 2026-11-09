# 공통 인터페이스 v1

이 문서는 팀원들이 독립적으로 구현할 때 따를 **목표 계약**입니다.
현재 Python 파일은 TODO 상태이며 아래 함수·기능은 아직 구현되지 않았습니다.
Python 3.12 / Ubuntu 24.04 LTS / Linux AF_PACKET을 기준으로 합니다.
키 이름·타입·지원 범위 변경은 관련 담당자와 먼저 합의하고 이 문서와 테스트를 같은 PR에서 수정합니다.

## 1. 담당과 데이터 흐름

| 담당 | 파일 | 공개 함수 |
|---|---|---|
| 이수호 | `capture/capture.py` | `capture_packets(interface: str) -> Iterator[dict]` |
| 구본준 | `parsers/packet_parser.py` | `parse_packet(raw_data: bytes) -> dict \| None` |
| 배승준 | `parsers/http_parser.py` | `parse_http(payload: bytes) -> dict \| None` |
| 배승준(선택) | `parsers/smtp_parser.py` | `parse_smtp(payload: bytes) -> dict \| None` |
| 박수빈 | `parsers/dns_parser.py` | `parse_dns(payload: bytes) -> dict \| None` |
| 이수호(초기), 공동 | `main.py` | 캡처 → 헤더 분석 → 응용 파서 선택 → 출력 |
| 박수빈 | `tests/test_packets.py` | 통합 검증; 각 담당자도 자신의 단위 검증 제공 |

`Iterator`는 `collections.abc.Iterator`입니다. `dict`는 아래 스키마를 뜻합니다.
파서는 소켓을 열거나 출력·파일 저장을 하지 않는 순수 분석 함수로 작성합니다.
입력 `bytes`를 수정하지 않으며, 주소·시각·방향을 payload에 덧붙이지 않습니다.

## 2. 공통 반환·오류 규칙

- 성공 시 아래에 명시된 키를 **전부** 포함합니다. 임의의 키 추가·이름 변경은 하지 않습니다.
- 해당하지 않는 값은 키를 생략하거나 빈 문자열을 쓰지 않고 `None`으로 둡니다.
  목록에 항목이 없으면 `[]`, HTTP 헤더가 없으면 `{}`입니다.
- 포트·길이·코드·식별자는 `int`, 플래그는 `bool`, 바이너리 데이터는 `bytes`입니다.
  네트워크 바이트 순서의 정수는 파서에서 호스트 정수로 변환합니다.
- 파서는 미지원 프로토콜, 불완전 입력, 잘못된 길이·형식에 `None`을 반환합니다.
  v1에서는 `None`의 세부 원인을 구분하지 않습니다.
- `bytes`가 아닌 입력은 `TypeError`입니다. 빈 `b""`는 `None`입니다.
- 잘못된 외부 데이터 때문에 `struct.error`, `IndexError`, `UnicodeDecodeError`가
  호출자에게 새어 나오지 않도록 경계 검사합니다. 모든 예외를 무조건 숨기지는 않습니다.
- `NotImplementedError`는 개발 중 미구현 표시로만 사용합니다. 미지원 패킷의 반환값이 아닙니다.
  통합 시 이 예외를 잡아 정상 분석 완료처럼 표시하지 않습니다.

## 3. 캡처 → 헤더 파서

```python
def capture_packets(interface: str) -> Iterator[dict]: ...
```

호출자가 지정한 **단일 Ethernet 인터페이스**에서 프레임을 차례로 yield합니다.
빈 인터페이스는 `ValueError`, 문자열이 아니면 `TypeError`입니다.
Linux/AF_PACKET 미지원 환경은 `RuntimeError`, 권한 부족은 `PermissionError`,
그 밖의 소켓·인터페이스 오류는 `OSError`로 전달합니다.
iterator 구현에 따라 초기 오류는 첫 `next()` 시점에 발생할 수 있습니다.

| 키 | 타입 | 의미 |
|---|---|---|
| `raw_data` | `bytes` | Ethernet II 헤더부터 시작하는 전체 수신 프레임; FCS 포함을 가정하지 않음 |
| `interface` | `str` | 실제 수신한 인터페이스 이름 |
| `timestamp` | `float` | 수신 직후 기록한 Unix epoch 초; 사용자 공간 시각이며 하드웨어 시각이 아님 |
| `direction` | `str` | `"OUTGOING"` 또는 `"INCOMING"` |
| `packet_type` | `int` | AF_PACKET 주소 정보의 원래 `pkttype` |

방향은 `recvfrom()` 주소의 `pkttype`로 판단합니다.
`PACKET_OUTGOING`은 `OUTGOING`, `PACKET_HOST`·`PACKET_BROADCAST`·
`PACKET_MULTICAST`는 `INCOMING`입니다. `PACKET_OTHERHOST`와 알 수 없는 타입은
v1에서 건너뜁니다. IP 주소나 TCP 포트로 방향을 추측하지 않습니다.
이는 로컬 캡처 인터페이스 기준이며 클라이언트/서버, 요청/응답과 독립적입니다.

`AF_PACKET` + `SOCK_RAW`를 사용해 링크 헤더를 보존하고, Ethernet이 아닌 링크는
지원하지 않습니다. loopback·무선 monitor·가상 환경 특유의 방향/중복은 v1 보장 범위 밖입니다.
수신 버퍼 절단이 확인된 프레임은 전달하지 않습니다. promiscuous mode는 기본 사용하지 않습니다.
소켓은 iterator 종료·예외·`close()` 시 정리되도록 `finally`를 사용합니다.
`main.py`는 Ctrl+C뿐 아니라 조기 종료 시에도 iterator를 닫아야 합니다.

```python
# raw_data는 실제로 Ethernet 헤더를 포함해야 함. 아래 bytes는 형태 설명용.
frame = {
    "raw_data": b"...",
    "interface": "eth0",
    "timestamp": 1730000000.0,
    "direction": "OUTGOING",
    "packet_type": 4,
}
packet = parse_packet(frame["raw_data"])
```

## 4. 헤더 파서 → 응용 파서

```python
def parse_packet(raw_data: bytes) -> dict | None: ...
```

Ethernet II → IPv4 → TCP 또는 UDP만 반환합니다.
성공 결과는 TCP와 UDP 모두 다음 키를 갖습니다.

| 키 | 타입 | 의미 |
|---|---|---|
| `src_mac`, `dst_mac` | `str` | 소문자 콜론 구분 MAC, 예: `02:00:00:00:00:01` |
| `ethertype` | `int` | v1 성공 결과는 `0x0800` |
| `src_ip`, `dst_ip` | `str` | IPv4 점 표기 |
| `ttl` | `int` | IPv4 TTL |
| `ip_protocol` | `int` | TCP=6, UDP=17 |
| `ip_header_length` | `int` | IPv4 헤더 길이(바이트), 20~60 |
| `ip_total_length` | `int` | IPv4 헤더+데이터 길이(바이트) |
| `transport` | `str` | `"TCP"` 또는 `"UDP"` |
| `src_port`, `dst_port` | `int` | 0~65535 |
| `transport_header_length` | `int` | TCP는 data offset × 4, UDP는 8 |
| `seq`, `ack` | `int \| None` | TCP의 원시 32비트 번호; UDP는 `None` |
| `tcp_flags` | `dict \| None` | TCP는 아래 9개 bool 키, UDP는 `None` |
| `udp_length` | `int \| None` | UDP 헤더+데이터 길이; TCP는 `None` |
| `payload` | `bytes` | TCP/UDP 헤더를 제외한 데이터; 없으면 `b""` |

`tcp_flags`의 필수 키는 `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`, `cwr`, `ns`입니다.
숫자 필드 `ack`는 ACK 플래그가 꺼져 있어도 원시 값을 반환합니다.
연결 성립/종료 판정 자체는 하지 않고 SYN·ACK·FIN·RST와 번호를 제공합니다.

경계 처리:
- Ethernet 헤더 최소 14바이트. VLAN(802.1Q/QinQ), ARP, IPv6, 802.3 LLC는 `None`.
- IPv4 version=4, IHL≥5, 전체 길이≥IP 헤더 길이, 수신 데이터 길이 충분 여부 검사.
- IPv4 옵션은 IHL만큼 건너뜁니다. MF=1 또는 fragment offset≠0이면 첫 조각도 `None`.
- TCP 최소 20바이트, data offset≥5, TCP 헤더가 IP 데이터 경계를 넘지 않는지 검사.
  TCP 옵션은 data offset으로 건너뜁니다.
- UDP length≥8이고 v1에서는 IP 데이터 길이와 같아야 합니다. 불일치는 `None`.
- Ethernet 패딩·후행 바이트는 IPv4 total length로 잘라 payload에서 제외합니다.
- 체크섬 검증과 TCP 재조립은 v1 범위 밖입니다. 성공 반환은 체크섬이 유효하다는 뜻이 아닙니다.

## 5. main.py의 응용 파서 선택

헤더 분석 결과가 `None`이면 그 프레임은 건너뜁니다. 성공하면 메타데이터는 원래
`frame`에 유지하고 `packet["payload"]`만 응용 파서에 전달합니다.

| 조건 (src_port 또는 dst_port) | 호출 |
|---|---|
| TCP, 80 또는 8000 | `parse_http(payload)` |
| UDP, 53 | `parse_dns(payload)` |
| TCP, 25 또는 2525 | `parse_smtp(payload)` — 선택 기능 구현 후만 연결 |
| 그 밖의 경우 | 응용 파서 호출 없이 헤더 결과만 사용 |

payload가 비면 응용 파서를 호출하지 않습니다. 두 서비스 포트가 동시에 걸리는
모호한 TCP 조합(예: 80 → 25)은 응용 분석을 건너뜁니다.
포트는 후보 선택 기준이며 실제 내용 검증은 파서가 담당합니다.
응용 파서가 `None`을 반환해도 헤더 결과는 보존합니다. 방향으로 요청/응답을 결정하지 않습니다.
기본 출력은 요약 필드만 사용하고 원시 payload, 인증 헤더, 본문은 출력하지 않습니다.
외부 문자열을 출력할 때 터미널 제어문자를 이스케이프합니다.

## 6. HTTP/1.1 — 헤더 분석

```python
def parse_http(payload: bytes) -> dict | None: ...
```

v1은 TCP payload **시작 위치**에서 시작한 HTTP/1.1 시작 줄과 전체 헤더만 분석합니다.
시작 줄·헤더가 한 세그먼트에 있고 `\r\n\r\n`으로 끝나야 합니다.
본문이 없어도, 일부만 있어도 헤더 분석은 가능합니다. 성공 반환은 전체 HTTP 메시지의
수신 완료를 의미하지 않습니다. 본문·Content-Length 충족 여부·chunked decoding은 분석하지 않습니다.

| 키 | 타입 | 의미 |
|---|---|---|
| `kind` | `str` | `"request"` 또는 `"response"` |
| `version` | `str` | `"HTTP/1.1"` |
| `method` | `str \| None` | 요청의 대문자 메서드 토큰(GET/POST 필수, 그 외 유효 토큰 허용); 응답은 `None` |
| `target` | `str \| None` | 요청 대상 원문, URL decode하지 않음; 응답은 `None` |
| `status_code` | `int \| None` | 응답의 100~599 코드; 요청은 `None` |
| `reason` | `str \| None` | 응답 사유 문구(빈 문자열 허용); 요청은 `None` |
| `headers` | `dict[str, list[str]]` | 소문자 헤더 이름 → 등장 순서대로 값 목록 |
| `host` | `str \| None` | 요청의 Host 값(포트 포함 원문); 응답은 `None` |

요청 줄의 method·target은 ASCII, 헤더 값·응답 사유는 ISO-8859-1로 손실 없이 디코딩합니다.
헤더 값 양끝 SP/HTAB은 제거하고 중복 헤더는 쉼표로 합치지 않습니다.
요청에는 비어 있지 않은 Host가 정확히 1개 필요하며 없거나 중복이면 `None`입니다.
잘못된 시작 줄·헤더 이름·콜론 없는 헤더, 접힌 헤더(obs-fold), LF만 쓰는 줄바꿈,
HTTP/1.0·2·3, TLS 데이터는 `None`입니다.
첫 헤더 블록 이후 바이트는 무시합니다. 여러 HTTP 메시지가 한 payload에 있어도 첫 헤더만 반환합니다.
세그먼트 중간부터 시작하는 메시지를 검색하거나 연결별 상태를 저장하지 않습니다.

```python
parse_http(b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n")
# 기대 결과:
{
    "kind": "request", "version": "HTTP/1.1",
    "method": "GET", "target": "/hello", "status_code": None, "reason": None,
    "headers": {"host": ["example.test"]}, "host": "example.test",
}
```

## 7. DNS — UDP 메시지 분석

```python
def parse_dns(payload: bytes) -> dict | None: ...
```

입력은 UDP 헤더를 제외한 DNS 메시지 전체입니다. TCP용 2바이트 길이 접두사는 없습니다.
12바이트 DNS 헤더와 선언된 모든 question/RR을 경계 검사합니다.
표준 query(opcode=0)만 지원하며 다른 opcode는 `None`입니다.

| 키 | 타입 | 의미 |
|---|---|---|
| `transaction_id` | `int` | 0~65535 |
| `kind` | `str` | QR=0이면 `"query"`, QR=1이면 `"response"` |
| `flags` | `int` | DNS 헤더의 원시 16비트 flags |
| `opcode` | `int` | v1에서는 0 |
| `rcode` | `int` | 헤더의 하위 4비트 응답 코드; EDNS 확장 코드는 해석하지 않음 |
| `truncated` | `bool` | TC 비트 |
| `questions` | `list[dict]` | 아래 question 스키마, wire 순서 |
| `answers` | `list[dict]` | answer RR 목록, wire 순서 |
| `authorities` | `list[dict]` | authority RR 목록, wire 순서 |
| `additionals` | `list[dict]` | additional RR 목록, wire 순서 |

question은 정확히 `{"name": str, "qtype": int, "qclass": int}`입니다.
RR은 정확히 `{"name": str, "rtype": int, "rclass": int, "ttl": int,
"rdata": bytes, "address": str | None}`입니다.
- `rdata`는 RDLENGTH만큼의 원본 바이트입니다. 압축 포인터도 원문 그대로 보존합니다.
- IN(class=1) A(type=1, 길이 4)는 IPv4 주소, IN AAAA(type=28, 길이 16)는
  소문자 축약 IPv6 주소를 `address`에 넣습니다. 이는 IPv6 패킷 캡처 지원과 별개입니다.
- 그 외 RR은 원본 rdata를 유지하고 `address=None`으로 둡니다.
  CNAME 등의 rdata 내부 이름 해석과 EDNS 옵션 해석은 v1 범위 밖입니다.
- IN A/AAAA의 잘못된 RDLENGTH는 `None`입니다. 알 수 없는 RR 타입 자체는 오류가 아닙니다.
- question 및 RR 소유자 이름의 압축 포인터를 처리합니다. 포인터 기준은 DNS payload 첫 바이트입니다.
  범위 밖 포인터·순환 참조·잘린 라벨·63바이트 초과 라벨·255바이트 초과 확장 이름은 `None`.
- 이름은 wire의 대소문자를 보존하고 마지막 점을 생략합니다. 루트는 `"."`입니다.
  라벨 내부 점·역슬래시·비출력/비ASCII 바이트는 `\DDD`(3자리 십진수)로 이스케이프합니다.
  IDNA 변환은 하지 않습니다.
- TC=1이라도 선언된 모든 항목을 읽을 수 있으면 반환합니다. 데이터가 잘렸으면 `None`.
  선언 항목 뒤 여분의 바이트가 남는 메시지도 v1에서는 `None`입니다.
- 수신 길이에서 가능한 항목 수와 포인터 방문 수를 제한해 무한 반복·과도한 할당을 막습니다.

## 8. SMTP — 선택 확장

```python
def parse_smtp(payload: bytes) -> dict | None: ...
```

TCP payload 시작부터 **정확히 한 줄**의 평문 ASCII 명령 또는 응답을 분석합니다.
끝은 `\r\n`이며 추가 줄·불완전 줄·비ASCII·다중행 응답(`250-...`)은 `None`입니다.

| 키 | 타입 | 의미 |
|---|---|---|
| `kind` | `str` | `"command"` 또는 `"response"` |
| `command` | `str \| None` | `EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT` 중 하나; 응답은 `None` |
| `argument` | `str \| None` | 명령 인자 원문(양끝 SP/HTAB 제거), 없으면 `""`; 응답은 `None` |
| `code` | `int \| None` | 응답의 200~599 3자리 코드; 명령은 `None` |
| `text` | `str \| None` | 응답 코드와 한 칸 공백 이후 문구(빈 값 허용); 명령은 `None` |

명령어는 대소문자 구분 없이 인식하고 대문자로 반환합니다.
`MAIL FROM:<a@example.test>`는 command=`"MAIL FROM"`, argument=`"<a@example.test>"`입니다.
EHLO/HELO/MAIL FROM/RCPT TO의 빈 인자는 `None`입니다.
DATA/RSET/QUIT의 인자는 없어야 하고 NOOP는 선택 인자를 허용합니다.
응답은 3자리 코드 다음 한 칸 공백이 있어야 합니다.
AUTH·STARTTLS·DATA 본문·메일 주소의 상세 문법·세션 상태는 분석하지 않습니다.
미지원 명령은 `None`이며, DATA 본문을 구별할 상태가 없으므로
이 함수의 반환은 세션 수준에서 검증된 SMTP 이벤트가 아닌 한 줄 문법 분석 결과입니다.

## 9. 공통 지원 한계

IPv6 패킷, VLAN, IP 단편 재조립, TCP 스트림 재조립, DNS over TCP,
HTTPS/TLS 복호화, HTTP/2·3은 지원하지 않습니다.
TCP 순서 복원·재전송 제거·연결 상태 추적을 하지 않아 결과가 누락되거나 중복될 수 있습니다.
HTTP 헤더 분할은 분석 실패, SMTP 줄 분할/병합은 분석 실패입니다.
이 제한을 정상 메시지 전체를 분석한 것처럼 출력하거나 보고하지 않습니다.

## 10. 테스트·통합 완료 기준

`tests/test_packets.py`에서 표준 라이브러리 `unittest`를 사용합니다.
fixture는 테스트 코드 안의 합성 bytes로 만들고 실제 캡처·민감 데이터는 커밋하지 않습니다.
테스트를 통과시키려고 미구현 예외를 성공으로 취급하지 않습니다.

| 대상 | 필수 사례와 확인 항목 |
|---|---|
| 공통 | 빈 입력→None, 잘린 입력→None, 잘못된 입력 타입→TypeError, 정확한 키 집합과 값 타입 |
| 캡처 | 소켓 mock으로 방향별 매핑, OTHERHOST/미지 타입 제외, 권한 오류, 종료·예외 시 close |
| Ethernet/IP | TCP/UDP 정상 프레임, IPv4 옵션, 패딩 제외, 짧은 헤더, 잘못된 IHL/total length, VLAN/IPv6/단편→None |
| TCP/UDP | SYN·ACK·FIN·RST, 빈 payload, TCP 옵션, 잘못된 offset, UDP 길이 불일치, 사용하지 않는 필드의 None |
| HTTP | GET/POST/응답, 중복 헤더 목록, Host 누락·중복, 헤더 분할→None, 본문 분할 시 헤더만 반환, 첫 헤더 이후 무시 |
| DNS | 질의/응답, 다중 question/RR, A/AAAA, 압축 이름, 순환/범위 초과 포인터, NXDOMAIN, TC, 알 수 없는 RR, 길이 오류 |
| SMTP(선택) | EHLO/MAIL FROM/RCPT TO/DATA 및 응답, 분할/병합 줄, 다중행 응답, 미지원 명령 |
| 통합 | 합성 캡처→패킷→응용 파서 연결, 포트별 선택, 응용 None이어도 헤더 유지, 방향과 요청/응답의 독립성 |

실행 예정: `python3.12 -m unittest discover -s tests -v`.
현재 테스트는 TODO이므로 테스트 0개 실행은 기능 검증 완료가 아닙니다.
구현 후 Ubuntu 24.04 LTS에서 허가된 별도 실습 호스트와 양방향 HTTP/UDP DNS를
발생시키고 Wireshark와 주소·포트·플래그·응용 필드를 대조합니다.
사용한 Python/OS 버전, 인터페이스, 테스트 명령, 기대/실제 결과, 알려진 제한을 PR에 기록합니다.
단위 테스트 통과와 Raw Socket 실환경 검증은 별도로 보고합니다.

## 참고

- [Python 3.12 socket: AF_PACKET 주소 구조](https://docs.python.org/3.12/library/socket.html)
- [Linux packet(7): packet type와 Raw Socket](https://man7.org/linux/man-pages/man7/packet.7.html)
