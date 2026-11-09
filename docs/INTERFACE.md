# 공통 인터페이스

아래는 팀원 간 협의를 위한 기본 함수 형태입니다. 현재 코드는 TODO만 있으며,
정확한 반환 dict와 예외 처리 규칙은 구현 전에 팀원들이 합의합니다.

| 담당 | 함수 형태 | 역할 |
|---|---|---|
| 이수호 | `capture_packets(interface: str)` | 캡처한 원시 패킷과 메타데이터 전달 |
| 구본준 | `parse_packet(raw_data: bytes) -> dict \| None` | Ethernet/IPv4/TCP/UDP 분석 및 payload 추출 |
| 배승준 | `parse_http(payload: bytes) -> dict \| None` | HTTP/1.1 분석 |
| 배승준(선택) | `parse_smtp(payload: bytes) -> dict \| None` | SMTP 분석 |
| 박수빈 | `parse_dns(payload: bytes) -> dict \| None` | DNS 분석 |

- 데이터 흐름: 캡처 → 패킷 헤더 분석 → 응용계층 payload 분석 → 출력.
- `main.py`는 이수호가 초기 골격을 작성하고 함께 통합합니다.
- 송·수신 방향은 캡처 인터페이스 기준이며 HTTP 요청·응답 구분과 다릅니다.
- 반환 키, 미지원 패킷 처리, 메시지 분할 처리 범위는 팀에서 확정 후 이 문서에 기록합니다.
