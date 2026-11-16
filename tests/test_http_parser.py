import unittest

from parsers.http_parser import parse_http


class TestHTTPParser(unittest.TestCase):

    def test_get_request(self):
        payload = (
            b"GET /hello HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], "request")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["target"], "/hello")
        self.assertEqual(result["host"], "localhost")

    def test_post_request(self):
        payload = (
            b"POST /login HTTP/1.1\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "POST")

    def test_http_response(self):
        payload = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], "response")
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["reason"], "Not Found")

    def test_lowercase_host(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"host: localhost\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "localhost")

    def test_invalid_header(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host localhost\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_incomplete_message(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_incomplete_body(self):
        payload = (
            b"POST /login HTTP/1.1\r\n"
            b"Content-Length: 10\r\n"
            b"\r\n"
            b"{}"
        )

        self.assertIsNone(parse_http(payload))

    def test_invalid_encoding(self):
        payload = (
            b"GET /\xff HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))
    
    def test_invalid_status_code(self):
        payload = (
            b"HTTP/1.1 99 Invalid\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        self.assertIsNone(parse_http(payload))

if __name__ == "__main__":
    unittest.main()