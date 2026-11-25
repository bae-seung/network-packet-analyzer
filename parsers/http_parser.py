
import re

# HTTP 헤더 이름에 사용할 수 있는 문자
TOKEN_PATTERN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")

# 프로젝트 규칙에 따라 대문자 HTTP 메서드만 허용
METHOD_PATTERN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Z]+")


def valid_field_value(value: bytes) -> bool:
    """
    HTTP 헤더 값이나 응답 사유 문구에서
    허용되지 않는 제어 문자가 있는지 검사한다.
    """
    return all(
        byte == 9 or 32 <= byte <= 126 or 128 <= byte <= 255
        for byte in value
    )


def parse_http(payload: bytes) -> dict | None:
    # 1. 입력 타입 및 빈 데이터 검사
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    if not payload:
        return None

    # 2. HTTP 헤더가 완전히 수신되었는지 검사
    header_block, separator, _ = payload.partition(b"\r\n\r\n")

    if not separator:
        return None

    lines = header_block.split(b"\r\n")

    # LF 단독 줄바꿈이나 잘못된 CR 처리
    for line in lines:
        if b"\r" in line or b"\n" in line:
            return None

    first_line = lines[0]

    # 3. HTTP 응답 분석
    if first_line.startswith(b"HTTP/1.1 "):
        parts = first_line.split(b" ", 2)

        if len(parts) != 3:
            return None

        version_bytes, code_bytes, reason_bytes = parts

        if len(code_bytes) != 3 or not code_bytes.isdigit():
            return None

        status_code = int(code_bytes)

        if not 100 <= status_code <= 599:
            return None

        if not valid_field_value(reason_bytes):
            return None

        kind = "response"
        version = "HTTP/1.1"
        method = None
        target = None
        reason = reason_bytes.decode("iso-8859-1")

    # 4. HTTP 요청 분석
    else:
        parts = first_line.split(b" ")

        if len(parts) != 3:
            return None

        method_bytes, target_bytes, version_bytes = parts

        if version_bytes != b"HTTP/1.1":
            return None

        if not METHOD_PATTERN.fullmatch(method_bytes):
            return None

        if not target_bytes:
            return None

        # 요청 대상은 출력 가능한 ASCII 문자만 허용
        if any(byte < 33 or byte > 126 for byte in target_bytes):
            return None

        kind = "request"
        version = "HTTP/1.1"
        method = method_bytes.decode("ascii")
        target = target_bytes.decode("ascii")
        status_code = None
        reason = None

    # 5. HTTP 헤더 분석
    headers = {}

    for line in lines[1:]:
        # 접힌 헤더(obs-fold)는 지원하지 않음
        if not line or line.startswith((b" ", b"\t")):
            return None

        if b":" not in line:
            return None

        key_bytes, value_bytes = line.split(b":", 1)

        # 잘못된 헤더 이름 검사
        if not TOKEN_PATTERN.fullmatch(key_bytes):
            return None

        if not valid_field_value(value_bytes):
            return None

        key = key_bytes.decode("ascii").lower()
        value = value_bytes.decode("iso-8859-1").strip(" \t")

        # 중복 헤더도 리스트에 순서대로 저장
        headers.setdefault(key, []).append(value)

    # 6. Host 헤더 검증
    host = None

    if kind == "request":
        host_values = headers.get("host", [])

        if len(host_values) != 1:
            return None

        if not host_values[0]:
            return None

        host = host_values[0]

    # 7. 팀 공통 인터페이스에 맞춰 반환
    return {
        "kind": kind,
        "version": version,
        "method": method,
        "target": target,
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "host": host
    }
