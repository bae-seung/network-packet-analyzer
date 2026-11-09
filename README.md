# network-packet-analyzer
Python-based Network Packet Capture and Analysis Project

Python 3.12 / Ubuntu 24.04 LTS / Linux AF_PACKET Raw Socket 기반
네트워크 패킷 캡처·분석 팀 프로젝트입니다.
HTTP/1.1과 DNS를 필수로 분석하고, SMTP는 선택 확장으로 진행합니다.

현재는 폴더 구조와 TODO만 준비되어 있으며 캡처·분석·테스트는 아직 구현되지 않았습니다.

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
- 외부 Python 의존성은 현재 없습니다. 설치·실행 절차는 구현 후 추가합니다.
- 기능별 브랜치에서 작업하고 PR로 검토 후 병합합니다.

## 주의사항
본인 소유 또는 허가된 네트워크에서만 캡처합니다.
실제 패킷 파일, 로그, 비밀번호, 인증 정보는 저장소에 올리지 않습니다.
실환경 동작 검증은 아직 수행하지 않았습니다.
