def parse_http(payload: bytes) -> dict | None:
    if b"\r\n\r\n" not in payload:
          return None
    
    lines = payload.split(b"\r\n")

    # HTTP 요청 라인 분석
    first_line = lines[0].decode("ascii")
    if first_line.startswith("HTTP/1.1 "):
        #HTTP 응답
        parts = first_line.split(" ",2)
        if len(parts) < 2 or not parts[1].isdigit():
                return None
        kind = "response"
        version = parts[0]
        status_code = int(parts[1])
        reason = parts[2] if len(parts) == 3 else ""
        method = None
        target = None
    else:
         #HTTP request
        parts = first_line.split(" ")
        
        if len(parts) != 3:
              return None
        method , target , version = parts
        if method not in ("GET", "POST"):
                 return None
        if version != "HTTP/1.1":
                return None
        kind = "request"
        status_code = None
        reason = None
        
    
    

    

    headers = {}

    for line in lines[1:]:
        if line == b"":
            break

        text = line.decode("ascii")
        #예외 처리 : 불완전한 TCP 데이터: HTTP 헤더가 여러 TCP 세그먼트로 나뉘어 전달되어 일부 일때 : 가 빠질수도 있음
        if ":" not in text:
              return None
        key, value = text.split(":", 1)

        key = key.strip()
        value = value.strip()

        headers[key] = value

    return {
    "kind": kind,
    "version": version,
    "method": method,
    "target": target,
    "status_code": status_code,
    "reason": reason,
    "headers": headers,
    "host": headers.get("Host")
    }

'''
GET 메서드
# 테스트용 데이터
payload = (
    b"GET /hello HTTP/1.1\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: keep-alive\r\n"
    b"Host: localhost\r\n"
    b"\r\n"
)
'''
# HTTP 요청 테스트
request = (
    b"GET /hello HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"\r\n"
)

# HTTP 응답 테스트
response = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

print("=== REQUEST ===")
print(parse_http(request))

print("=== RESPONSE ===")
print(parse_http(response))

invalid_request = (
    b"GET /hello HTTP/1.1\r\n"
    b"Host localhost\r\n"
    b"\r\n"
)

print(parse_http(invalid_request))


incomplete_request = (
    b"GET /hello HTTP/1.1\r\n"
    b"Host: localhost\r\n"
)

print(parse_http(incomplete_request))