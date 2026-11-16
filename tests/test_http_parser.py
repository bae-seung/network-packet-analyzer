
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
        self.assertEqual(result["version"], "HTTP/1.1")
        self.assertEqual(result["host"], "localhost")
        self.assertEqual(result["headers"]["host"], ["localhost"])
        self.assertIsNone(result["status_code"])
        self.assertIsNone(result["reason"])

        self.assertEqual(
            set(result),
            {
                "kind", "version", "method", "target",
                "status_code", "reason", "headers", "host"
            }
        )

    def test_post_request(self):
        payload = (
            b"POST /login HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["target"], "/login")
        self.assertEqual(result["headers"]["content-length"], ["2"])

    def test_other_http_method(self):
        payload = (
            b"PUT /users/1 HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "PUT")

    def test_http_response(self):
        payload = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: text/html\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], "response")
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["reason"], "Not Found")
        self.assertEqual(
            result["headers"]["content-type"],
            ["text/html"]
        )
        self.assertIsNone(result["method"])
        self.assertIsNone(result["target"])
        self.assertIsNone(result["host"])

    def test_empty_reason(self):
        payload = b"HTTP/1.1 204 \r\n\r\n"

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["reason"], "")
        self.assertEqual(result["headers"], {})

    def test_lowercase_host(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"host: localhost\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "localhost")
        self.assertEqual(result["headers"]["host"], ["localhost"])

    def test_duplicate_headers(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Accept: text/html\r\n"
            b"Accept: application/json\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["headers"]["accept"],
            ["text/html", "application/json"]
        )

    def test_response_host_is_none(self):
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Host: example.test\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertIsNone(result["host"])

    def test_iso_8859_1_header(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"X-Name: caf\xe9\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["headers"]["x-name"], ["café"])

    def test_missing_host(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Accept: text/html\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_duplicate_host(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_empty_host(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host:   \r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_invalid_header(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host localhost\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_invalid_header_name(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Bad Name: value\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_folded_header(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\tcontinued-value\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_incomplete_header(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_incomplete_body_allowed(self):
        payload = (
            b"POST /login HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 100\r\n"
            b"\r\n"
            b"{}"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "POST")
        self.assertEqual(
            result["headers"]["content-length"],
            ["100"]
        )

    def test_first_header_only(self):
        payload = (
            b"GET /first HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
            b"GET /second HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"\r\n"
        )

        result = parse_http(payload)

        self.assertIsNotNone(result)
        self.assertEqual(result["target"], "/first")
        self.assertEqual(result["host"], "localhost")

    def test_invalid_status_code(self):
        payload = b"HTTP/1.1 99 Invalid\r\n\r\n"

        self.assertIsNone(parse_http(payload))

    def test_out_of_range_status_code(self):
        payload = b"HTTP/1.1 600 Invalid\r\n\r\n"

        self.assertIsNone(parse_http(payload))

    def test_http_10_not_supported(self):
        payload = (
            b"GET / HTTP/1.0\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_lf_only(self):
        payload = (
            b"GET / HTTP/1.1\n"
            b"Host: localhost\n"
            b"\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_invalid_binary_data(self):
        payload = b"\xff\xfe\xfd\r\n\r\n"

        self.assertIsNone(parse_http(payload))

    def test_lowercase_method(self):
        payload = (
            b"get / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))

    def test_empty_input(self):
        self.assertIsNone(parse_http(b""))

    def test_invalid_input_type(self):
        with self.assertRaises(TypeError):
            parse_http("GET / HTTP/1.1")

    def test_invalid_header_control_character(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"X-Test: hello\x00world\r\n"
            b"\r\n"
        )

        self.assertIsNone(parse_http(payload))


if __name__ == "__main__":
    unittest.main()
