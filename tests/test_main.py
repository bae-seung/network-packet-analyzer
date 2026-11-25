"""main.py가 파서 결과에서 응용 헤더와 IPv4 TTL을 출력에 담는지 확인한다."""

import json
import struct
import unittest

import main


def frame(proto, sport, dport, payload, ttl=64):
    eth = bytes(6) + bytes(6) + b"\x08\x00"
    if proto == 6:
        l4 = struct.pack("!HHLLBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0x4000, ttl, proto, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip + l4


def summarize(raw):
    summary = main.summarize_frame(
        {"raw_data": raw, "interface": "eth0", "timestamp": 1.0,
         "direction": "OUTGOING", "packet_type": 4},
        capture_only=False,
    )
    json.dumps(summary)  # main.py가 그대로 JSON으로 내보낼 수 있어야 한다
    return summary


class TestSummaryFields(unittest.TestCase):
    def test_ipv4_ttl(self):
        self.assertEqual(summarize(frame(6, 40000, 443, b"", ttl=57))["ttl"], 57)

    def test_http_request_headers(self):
        app = summarize(frame(6, 40000, 80, b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"))["application"]
        self.assertEqual(app["method"], "GET")
        self.assertEqual(app["target"], "/a")
        self.assertEqual(app["version"], "HTTP/1.1")
        self.assertEqual(app["host"], "example.com")
        self.assertIsNone(app["content_type"])

    def test_http_response_headers(self):
        app = summarize(frame(6, 80, 40000, b"HTTP/1.1 404 Not Found\r\n"
                              b"Content-Type: text/plain\r\nContent-Length: 9\r\n\r\n"))["application"]
        self.assertEqual((app["status_code"], app["reason"]), (404, "Not Found"))
        self.assertEqual((app["content_type"], app["content_length"]), ("text/plain", "9"))

    def test_dns_response_question_and_answers(self):
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04" + bytes([104, 20, 23, 154])
        payload = struct.pack("!6H", 0x375E, 0x8180, 1, 1, 0, 0) + question + answer
        app = summarize(frame(17, 53, 50505, payload))["application"]
        self.assertEqual(app["questions"], [{"name": "example.com", "qtype": 1}])
        self.assertEqual(app["answers"], [
            {"name": "example.com", "rtype": 1, "ttl": 300, "address": "104.20.23.154"},
        ])

    def test_smtp_argument_and_text(self):
        cmd = summarize(frame(6, 40000, 2525, b"RCPT TO:<bob@test.smtp.local>\r\n"))["application"]
        self.assertEqual((cmd["command"], cmd["argument"]), ("RCPT TO", "<bob@test.smtp.local>"))
        resp = summarize(frame(6, 2525, 40000, b"250 OK\r\n"))["application"]
        self.assertEqual((resp["code"], resp["text"]), (250, "OK"))


if __name__ == "__main__":
    unittest.main()
