def parse_http(payload: bytes) -> dict | None:
    if b"\r\n\r\n" not in payload:
          return None
    
    lines = payload.split(b"\r\n")

    # HTTP 요청 라인 분석
    # 정상적인 ASCII가 아닌 바이트가 들어오면 UnicodeDecodeError가 발생하면서 함수가 중단 -> try-except 문으로 해결
    # 패킷 분석 프로그램은 다양한 데이터를 받는다 -> 분석할 수 없는 데이터 하나 때문에 전체 프로그램이 종료되면 안된다.
    try:
        first_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
          return None

    if first_line.startswith("HTTP/1.1 "):
        #HTTP 응답
        parts = first_line.split(" ",2)
        if len(parts) < 2:
                return None
        if not parts[1].isdigit() or len(parts[1]) != 3:
                return None
        if not 100 <= int(parts[1]) <= 599:
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


        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            return None
        
        #예외 처리 : 불완전한 TCP 데이터: HTTP 헤더가 여러 TCP 세그먼트로 나뉘어 전달되어 일부 일때 : 가 빠질수도 있음
        if ":" not in text:
              return None
        key, value = text.split(":", 1)

        key = key.strip()
        value = value.strip()

        headers[key] = value

    #1. HTTP 헤더의 대소문자가 달라도 정상적으로 분석하기
    normalized_headers = {
         key.lower() : value for key,value in headers.items()
    }
    #2. Content-Length를 이용해 POST 요청의 본문이 잘리지 않았는지 확인하기
    content_length = normalized_headers.get("content-length")
    if content_length is not None:
         if not content_length.isdigit():
              return None
         if kind == "request":
            expected_length = int(content_length)
            body = payload.split(b"\r\n\r\n", 1)[1]
            if len(body) < expected_length:
                 return None


    host = normalized_headers.get("host")
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
