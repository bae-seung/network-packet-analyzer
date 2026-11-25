# network-packet-analyzer
Python-based Network Packet Capture and Analysis Project

Python 3.12 / Ubuntu 24.04 LTS / Linux AF_PACKET Raw Socket 기반
네트워크 패킷 캡처·분석 팀 프로젝트입니다.
HTTP/1.1과 DNS를 필수로 분석하고, SMTP는 선택 확장으로 진행합니다.

캡처 모듈과 실행 진입점이 준비되어 있습니다. 각 분석 파서는 담당자가 구현한 뒤 통합합니다.

## 역할 분담
| 팀원 | 담당 파일 |
|---|---|
| 이수호 | `capture/capture.py`, `main.py` 초기 골격 |
| 구본준 | `parsers/packet_parser.py` |
| 배승준 | `parsers/http_parser.py`, `parsers/smtp_parser.py`(선택) |
| 박수빈 | `parsers/dns_parser.py`, `tests/test_packets.py`(통합 검증) |
| 공동 | `main.py` 통합, `docs/INTERFACE.md` 합의 |

## 개발 안내
- 담당 파일에서 TODO를 구현합니다.
- 모듈 연결 전 [공통 인터페이스](docs/INTERFACE.md)를 함께 확정합니다.
- 외부 Python 의존성 없이 Ubuntu 24.04 LTS와 Python 3.12에서 실행합니다.
- 기능별 브랜치에서 작업하고 PR로 검토 후 병합합니다.

## Ubuntu에서 캡처 확인

저장소 루트에서 실행합니다. `ip -br link` 출력에서 테스트 통신이 지나는 Ethernet 인터페이스를 확인한 뒤 아래의 `enp0s3`를 실제 이름으로 바꿉니다.

```bash
python3.12 --version
ip -br link
sudo python3.12 main.py -i enp0s3 --capture-only
```

캡처가 실행 중일 때 별도 Ubuntu 터미널에서 허가된 실습 서버로 HTTP 요청 또는 UDP DNS 질의를 보냅니다. 예를 들어 `curl -4 --http1.1 http://<실습-서버-IP>:8000/`에서 IP를 실제 값으로 바꿔 실행합니다. 터미널에서 `OUTGOING`과 `INCOMING`을 확인하고 Ctrl+C로 종료합니다. 이 모드의 출력에는 인터페이스, 시각, 방향, 패킷 유형, 프레임 길이가 포함됩니다.

필수 파서 구현이 합쳐지면 `--capture-only`를 빼고 실행해 헤더와 응용 프로토콜 요약을 확인합니다. 캡처 모의 테스트는 `python3.12 -m unittest discover -s tests -v`로 실행합니다.

## 현재 검증 결과

- 사용자 Ubuntu 24.04 VM의 `enp0s3`에서 위 캡처 명령을 실행하고, 별도 터미널에서 `wget -4 --spider --timeout=5 --tries=1 https://example.com`을 실행했습니다. 요청의 `200 OK`와 캡처 출력의 `OUTGOING`(packet_type=4), `INCOMING`(packet_type=0)을 확인했습니다.
- 이 실행으로 Raw Socket 프레임 캡처와 송수신 방향 출력의 기본 동작을 확인했습니다. 각 출력 프레임과 테스트 요청의 대응, 헤더 필드의 정확성은 추가 대조가 필요합니다.
- 개발 PC의 Windows Python 환경에서 소켓 모의 객체를 사용하는 캡처 단위 테스트 6개가 통과했습니다. Ubuntu VM에서의 단위 테스트 결과는 아직 확인되지 않았습니다.
- 헤더·HTTP·DNS 파서는 현재 로컬 코드에서 TODO 상태입니다. 파서 통합과 HTTP·UDP DNS 실환경 분석, Wireshark 필드 대조는 통합 단계에서 검증합니다.

## 주의사항
본인 소유 또는 허가된 네트워크에서만 캡처합니다.
실제 패킷 파일, 로그, 비밀번호, 인증 정보는 저장소에 올리지 않습니다.
