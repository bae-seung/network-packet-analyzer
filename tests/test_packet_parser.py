"""구본준: parsers/packet_parser.py 단위 테스트 (합성 bytes만 사용)."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.packet_parser import parse_packet  # noqa: E402

DST_MAC = bytes.fromhex("020000000002")
SRC_MAC = bytes.fromhex("020000000001")
SRC_IP = bytes([192, 168, 0, 10])
DST_IP = bytes([93, 184, 216, 34])

EXPECTED_KEYS = {
    "src_mac", "dst_mac", "ethertype", "src_ip", "dst_ip", "ttl", "ip_protocol",
    "ip_header_length", "ip_total_length", "transport", "src_port", "dst_port",
    "transport_header_length", "seq", "ack", "tcp_flags", "udp_length", "payload",
}
FLAG_KEYS = {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ns"}


def make_ethernet(ethertype=0x0800):
    return DST_MAC + SRC_MAC + struct.pack("!H", ethertype)


def make_ipv4(protocol, data, options=b"", flags_fragment=0, version=4, ihl=None,
              total_length=None, ttl=64):
    header_len = 20 + len(options)
    if ihl is None:
        ihl = header_len // 4
    if total_length is None:
        total_length = header_len + len(data)
    header = struct.pack(
        "!BBHHHBBH4s4s", (version << 4) | ihl, 0, total_length, 0x1234,
        flags_fragment, ttl, protocol, 0, SRC_IP, DST_IP)
    return header + options + data


def make_tcp(src_port=51000, dst_port=80, seq=1000, ack=0, flags=0x02, options=b"",
             payload=b"", data_offset=None, ns=False):
    if data_offset is None:
        data_offset = (20 + len(options)) // 4
    offset_byte = (data_offset << 4) | (1 if ns else 0)
    header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, offset_byte,
                         flags, 65535, 0, 0)
    return header + options + payload


def make_udp(src_port=40000, dst_port=53, payload=b"", length=None):
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def tcp_frame(**kwargs):
    ip_kwargs = {k: kwargs.pop(k) for k in
                 ("options", "flags_fragment", "version", "ihl", "total_length", "ttl")
                 if k in kwargs and k != "options"}
    ip_options = kwargs.pop("ip_options", b"")
    return make_ethernet() + make_ipv4(6, make_tcp(**kwargs), options=ip_options, **ip_kwargs)


def udp_frame(payload=b"", length=None, **ip_kwargs):
    return make_ethernet() + make_ipv4(17, make_udp(payload=payload, length=length), **ip_kwargs)


class CommonTests(unittest.TestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(parse_packet(b""))

    def test_non_bytes_raises_type_error(self):
        for bad in ("text", None, 123, [1, 2, 3], bytearray(b"abc")):
            with self.assertRaises(TypeError):
                parse_packet(bad)

    def test_truncated_returns_none(self):
        frame = tcp_frame(payload=b"hello")
        for n in range(len(frame)):  # 한 바이트라도 모자라면 IP total length 검사에 걸린다
            self.assertIsNone(parse_packet(frame[:n]), msg=f"len={n}")

    def test_exact_key_set(self):
        for frame in (tcp_frame(), udp_frame()):
            self.assertEqual(set(parse_packet(frame)), EXPECTED_KEYS)


class TcpTests(unittest.TestCase):
    def test_syn_basic_fields(self):
        r = parse_packet(tcp_frame(seq=4000000000, ack=0, flags=0x02))
        self.assertEqual(r["src_mac"], "02:00:00:00:00:01")
        self.assertEqual(r["dst_mac"], "02:00:00:00:00:02")
        self.assertEqual(r["ethertype"], 0x0800)
        self.assertEqual(r["src_ip"], "192.168.0.10")
        self.assertEqual(r["dst_ip"], "93.184.216.34")
        self.assertEqual(r["ttl"], 64)
        self.assertEqual(r["ip_protocol"], 6)
        self.assertEqual(r["ip_header_length"], 20)
        self.assertEqual(r["ip_total_length"], 40)
        self.assertEqual(r["transport"], "TCP")
        self.assertEqual((r["src_port"], r["dst_port"]), (51000, 80))
        self.assertEqual(r["transport_header_length"], 20)
        self.assertEqual(r["seq"], 4000000000)
        self.assertEqual(r["ack"], 0)
        self.assertIsNone(r["udp_length"])
        self.assertEqual(r["payload"], b"")
        self.assertEqual(set(r["tcp_flags"]), FLAG_KEYS)
        self.assertTrue(all(isinstance(v, bool) for v in r["tcp_flags"].values()))

    def test_flag_combinations(self):
        cases = {
            "syn": (0x02, {"syn"}),
            "syn+ack": (0x12, {"syn", "ack"}),
            "ack": (0x10, {"ack"}),
            "psh+ack": (0x18, {"psh", "ack"}),
            "fin+ack": (0x11, {"fin", "ack"}),
            "rst": (0x04, {"rst"}),
            "all8": (0xFF, {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}),
        }
        for name, (byte, on) in cases.items():
            r = parse_packet(tcp_frame(flags=byte))
            actual = {k for k, v in r["tcp_flags"].items() if v}
            self.assertEqual(actual, on, msg=name)

    def test_ns_flag(self):
        r = parse_packet(tcp_frame(flags=0, ns=True))
        self.assertTrue(r["tcp_flags"]["ns"])

    def test_ack_number_returned_even_if_ack_flag_off(self):
        r = parse_packet(tcp_frame(flags=0x02, ack=777))
        self.assertFalse(r["tcp_flags"]["ack"])
        self.assertEqual(r["ack"], 777)

    def test_payload(self):
        r = parse_packet(tcp_frame(payload=b"GET / HTTP/1.1\r\n\r\n", flags=0x18))
        self.assertEqual(r["payload"], b"GET / HTTP/1.1\r\n\r\n")

    def test_tcp_options_skipped(self):
        options = bytes([2, 4, 5, 180, 1, 1, 1, 0])  # MSS + NOP*3 + EOL = 8바이트
        r = parse_packet(tcp_frame(options=options, payload=b"abc"))
        self.assertEqual(r["transport_header_length"], 28)
        self.assertEqual(r["payload"], b"abc")

    def test_bad_data_offset_returns_none(self):
        self.assertIsNone(parse_packet(tcp_frame(data_offset=4)))
        self.assertIsNone(parse_packet(tcp_frame(data_offset=15)))  # 60바이트인데 20바이트뿐

    def test_tcp_shorter_than_20_bytes_returns_none(self):
        frame = make_ethernet() + make_ipv4(6, b"\x00" * 19)
        self.assertIsNone(parse_packet(frame))


class UdpTests(unittest.TestCase):
    def test_basic_fields(self):
        r = parse_packet(udp_frame(payload=b"dnsdata"))
        self.assertEqual(r["transport"], "UDP")
        self.assertEqual(r["ip_protocol"], 17)
        self.assertEqual((r["src_port"], r["dst_port"]), (40000, 53))
        self.assertEqual(r["transport_header_length"], 8)
        self.assertEqual(r["udp_length"], 15)
        self.assertEqual(r["payload"], b"dnsdata")
        self.assertIsNone(r["seq"])
        self.assertIsNone(r["ack"])
        self.assertIsNone(r["tcp_flags"])

    def test_empty_payload(self):
        r = parse_packet(udp_frame())
        self.assertEqual(r["payload"], b"")
        self.assertEqual(r["udp_length"], 8)

    def test_length_mismatch_returns_none(self):
        self.assertIsNone(parse_packet(udp_frame(payload=b"abcd", length=20)))
        self.assertIsNone(parse_packet(udp_frame(payload=b"abcd", length=9)))
        self.assertIsNone(parse_packet(udp_frame(payload=b"abcd", length=7)))

    def test_udp_shorter_than_8_bytes_returns_none(self):
        frame = make_ethernet() + make_ipv4(17, b"\x00" * 7)
        self.assertIsNone(parse_packet(frame))


class EthernetIpTests(unittest.TestCase):
    def test_padding_excluded_from_payload(self):
        frame = tcp_frame(payload=b"hi", flags=0x18) + b"\x00" * 10
        r = parse_packet(frame)
        self.assertEqual(r["payload"], b"hi")
        self.assertEqual(r["ip_total_length"], 42)

    def test_ip_options_skipped(self):
        r = parse_packet(tcp_frame(ip_options=b"\x01\x01\x01\x00", payload=b"x"))
        self.assertEqual(r["ip_header_length"], 24)
        self.assertEqual(r["ip_total_length"], 45)
        self.assertEqual(r["payload"], b"x")
        self.assertEqual(r["src_port"], 51000)

    def test_ethertype_not_ipv4_returns_none(self):
        body = make_ipv4(6, make_tcp())
        for ethertype in (0x0806, 0x86DD, 0x8100, 0x88A8, 0x0100):
            self.assertIsNone(parse_packet(make_ethernet(ethertype) + body), msg=hex(ethertype))

    def test_vlan_tagged_frame_returns_none(self):
        frame = DST_MAC + SRC_MAC + struct.pack("!HH", 0x8100, 5) + struct.pack("!H", 0x0800) \
            + make_ipv4(6, make_tcp())
        self.assertIsNone(parse_packet(frame))

    def test_short_ethernet_returns_none(self):
        self.assertIsNone(parse_packet(b"\x00" * 13))
        self.assertIsNone(parse_packet(make_ethernet()))  # IP 헤더 없음

    def test_wrong_version_returns_none(self):
        self.assertIsNone(parse_packet(tcp_frame(version=6)))

    def test_bad_ihl_returns_none(self):
        self.assertIsNone(parse_packet(tcp_frame(ihl=4)))
        self.assertIsNone(parse_packet(tcp_frame(ihl=15)))  # 60바이트인데 헤더 20바이트뿐

    def test_bad_total_length_returns_none(self):
        self.assertIsNone(parse_packet(tcp_frame(total_length=10)))   # 헤더보다 작음
        self.assertIsNone(parse_packet(tcp_frame(total_length=500)))  # 수신 데이터보다 큼

    def test_fragments_return_none(self):
        self.assertIsNone(parse_packet(tcp_frame(flags_fragment=0x2000)))  # MF=1
        self.assertIsNone(parse_packet(tcp_frame(flags_fragment=0x0010)))  # offset != 0
        self.assertIsNotNone(parse_packet(tcp_frame(flags_fragment=0x4000)))  # DF만 켜짐은 정상

    def test_other_ip_protocol_returns_none(self):
        frame = make_ethernet() + make_ipv4(1, b"\x08\x00\x00\x00\x00\x00\x00\x00")  # ICMP
        self.assertIsNone(parse_packet(frame))

    def test_ttl_value(self):
        self.assertEqual(parse_packet(tcp_frame(ttl=7))["ttl"], 7)

    def test_input_not_modified(self):
        frame = tcp_frame(payload=b"abc")
        copy = bytes(frame)
        parse_packet(frame)
        self.assertEqual(frame, copy)


if __name__ == "__main__":
    unittest.main()
