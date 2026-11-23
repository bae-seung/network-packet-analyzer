import io
import json
import unittest

from tools import pretty

CLIENT = ("172.26.251.191", 33592)
SERVER = ("172.66.147.243", 80)


def tcp(direction, src, dst, seq, ack, flags, app=None):
    f = {k: False for k in ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ns")}
    f.update({k: True for k in flags})
    return json.dumps({
        "interface": "eth0", "timestamp": 1795419366.0, "direction": direction,
        "packet_type": 4 if direction == "OUTGOING" else 0, "frame_length": 66,
        "src_ip": src[0], "dst_ip": dst[0], "transport": "TCP",
        "src_port": src[1], "dst_port": dst[1], "seq": seq, "ack": ack,
        "tcp_flags": f, "udp_length": None, "application": app,
    })


def udp(direction, src, dst, app=None):
    return json.dumps({
        "interface": "eth0", "timestamp": 1795419366.0, "direction": direction,
        "packet_type": 4 if direction == "OUTGOING" else 0, "frame_length": 80,
        "src_ip": src[0], "dst_ip": dst[0], "transport": "UDP",
        "src_port": src[1], "dst_port": dst[1], "seq": None, "ack": None,
        "tcp_flags": None, "udp_length": 40, "application": app,
    })


def render(lines, **kwargs):
    out = io.StringIO()
    count = pretty.render(lines, out, **kwargs)
    return count, out.getvalue()


class TestTcpStages(unittest.TestCase):
    def test_handshake_data_and_teardown(self):
        lines = [
            tcp("OUTGOING", CLIENT, SERVER, 100, 0, ["syn"]),
            tcp("INCOMING", SERVER, CLIENT, 500, 101, ["syn", "ack"]),
            tcp("OUTGOING", CLIENT, SERVER, 101, 501, ["ack"]),
            tcp("OUTGOING", CLIENT, SERVER, 101, 501, ["psh", "ack"],
                {"protocol": "HTTP", "kind": "request", "method": "GET", "status_code": None}),
            tcp("INCOMING", SERVER, CLIENT, 501, 179, ["psh", "ack"],
                {"protocol": "HTTP", "kind": "response", "method": None, "status_code": 200}),
            tcp("OUTGOING", CLIENT, SERVER, 179, 900, ["fin", "ack"]),
            tcp("INCOMING", SERVER, CLIENT, 900, 180, ["fin", "ack"]),
            tcp("OUTGOING", CLIENT, SERVER, 180, 901, ["ack"]),
        ]
        count, text = render(lines)
        self.assertEqual(count, 8)
        for expected in (
            "① 연결 요청", "② 연결 수락", "③ 연결 확립", "HTTP 요청: GET",
            "HTTP 응답: 200", "연결 해제 요청 (FIN 1)", "상대도 해제 (FIN 2)",
            "연결 해제 완료 (마지막 ACK)", "송신 5, 수신 3",
        ):
            self.assertIn(expected, text)

    def test_seq_ack_and_flags_shown(self):
        _, text = render([tcp("INCOMING", SERVER, CLIENT, 139529485, 79598137, ["syn", "ack"])])
        self.assertIn("SYN,ACK", text)
        self.assertIn("139529485", text)
        self.assertIn("79598137", text)

    def test_rst(self):
        _, text = render([tcp("INCOMING", SERVER, CLIENT, 1, 2, ["rst", "ack"])])
        self.assertIn("강제 종료 (RST)", text)


class TestApplicationAndFilter(unittest.TestCase):
    def test_dns_query_and_response(self):
        lines = [
            udp("OUTGOING", ("172.26.251.191", 38239), ("8.8.8.8", 53),
                {"protocol": "DNS", "kind": "query", "transaction_id": 60160, "rcode": 0}),
            udp("INCOMING", ("8.8.8.8", 53), ("172.26.251.191", 38239),
                {"protocol": "DNS", "kind": "response", "transaction_id": 60160, "rcode": 0}),
        ]
        _, text = render(lines)
        self.assertIn("DNS 질의 (ID 0xeb00)", text)
        self.assertIn("DNS 응답 (ID 0xeb00, rcode 0)", text)
        self.assertIn("UDP/DNS", text)

    def test_smtp(self):
        server = ("10.0.0.2", 25)
        _, text = render([
            tcp("OUTGOING", CLIENT, server, 1, 1, ["psh", "ack"],
                {"protocol": "SMTP", "kind": "command", "command": "EHLO", "code": None}),
            tcp("INCOMING", server, CLIENT, 1, 2, ["psh", "ack"],
                {"protocol": "SMTP", "kind": "response", "command": None, "code": 250}),
        ])
        self.assertIn("SMTP 명령: EHLO", text)
        self.assertIn("SMTP 응답: 250", text)

    def test_other_ports_hidden_by_default(self):
        ssdp = udp("INCOMING", ("172.26.240.1", 57010), ("239.255.255.250", 1900))
        self.assertEqual(render([ssdp])[0], 0)
        count, text = render([ssdp], show_all=True)
        self.assertEqual(count, 1)
        self.assertIn("UDP 데이터", text)

    def test_ignores_non_json_and_capture_only_lines(self):
        capture_only = json.dumps({"interface": "eth0", "timestamp": 1.0, "direction": "INCOMING",
                                   "packet_type": 0, "frame_length": 60})
        count, _ = render(["^C", "not json {", "{broken", capture_only])
        self.assertEqual(count, 0)

    def test_no_color_codes_by_default(self):
        _, text = render([tcp("OUTGOING", CLIENT, SERVER, 1, 0, ["syn"])])
        self.assertNotIn("\033[", text)

    def test_korean_columns_align(self):
        header = pretty.format_row([c[0] for c in pretty.COLUMNS])
        row = pretty.format_row(["1", "16:36:06.312", "송신", "1.2.3.4:5", "→",
                                 "5.6.7.8:80", "TCP", "SYN", "1", "0", "설명"])
        self.assertEqual(pretty.display_width(header.split("설명")[0]),
                         pretty.display_width(row.split("설명")[0]))


if __name__ == "__main__":
    unittest.main()
