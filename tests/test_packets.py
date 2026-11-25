
import ipaddress
import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from parsers.dns_parser import parse_dns  # noqa: E402


# ---------- 합성 DNS 패킷 도우미 ----------

def header(tid=0x1234, flags=0x0100, qd=0, an=0, ns=0, ar=0):
    return struct.pack("!6H", tid, flags, qd, an, ns, ar)


def name(*labels):
    """라벨(bytes)들로 wire 형식 이름을 만든다. 끝에 루트(0)가 붙는다."""
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def question(qname, qtype=1, qclass=1):
    return qname + struct.pack("!HH", qtype, qclass)


def rr(owner, rtype, rclass, ttl, rdata):
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


EXAMPLE = name(b"example", b"com")
PTR_TO_FIRST_NAME = b"\xc0\x0c"  # 헤더(12바이트) 바로 뒤의 첫 이름을 가리킴
IPV4 = bytes([93, 184, 216, 34])

TOP_KEYS = {
    "transaction_id", "kind", "flags", "opcode", "rcode", "truncated",
    "questions", "answers", "authorities", "additionals",
}
QUESTION_KEYS = {"name", "qtype", "qclass"}
RR_KEYS = {"name", "rtype", "rclass", "ttl", "rdata", "address"}


def a_response():
    """example.com A 응답 (소유자 이름은 압축 포인터)."""
    return (header(flags=0x8180, qd=1, an=1)
            + question(EXAMPLE)
            + rr(PTR_TO_FIRST_NAME, 1, 1, 300, IPV4))


# ---------- 공통 규칙 ----------

class DnsCommonTests(unittest.TestCase):
    def test_empty_input_returns_none(self):
        self.assertIsNone(parse_dns(b""))

    def test_input_shorter_than_header_returns_none(self):
        for length in range(1, 12):
            with self.subTest(length=length):
                self.assertIsNone(parse_dns(b"\x00" * length))

    def test_non_bytes_input_raises_type_error(self):
        for value in ("abc", None, 123, [1, 2], bytearray(b"abc"),
                      memoryview(b"abc")):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    parse_dns(value)

    def test_header_only_message_is_valid(self):
        result = parse_dns(header())
        self.assertIsNotNone(result)
        for key in ("questions", "answers", "authorities", "additionals"):
            self.assertEqual(result[key], [])

    def test_exact_key_sets_and_value_types(self):
        packet = (header(flags=0x8180, qd=1, an=1, ns=1, ar=1)
                  + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 1, 1, 60, IPV4)
                  + rr(PTR_TO_FIRST_NAME, 2, 1, 60, name(b"ns", b"example", b"com"))
                  + rr(PTR_TO_FIRST_NAME, 1, 1, 60, IPV4))
        result = parse_dns(packet)
        self.assertEqual(set(result), TOP_KEYS)
        self.assertIsInstance(result["transaction_id"], int)
        self.assertIsInstance(result["kind"], str)
        self.assertIsInstance(result["flags"], int)
        self.assertIsInstance(result["opcode"], int)
        self.assertIsInstance(result["rcode"], int)
        self.assertIsInstance(result["truncated"], bool)
        for key in ("questions", "answers", "authorities", "additionals"):
            self.assertIsInstance(result[key], list)

        q = result["questions"][0]
        self.assertEqual(set(q), QUESTION_KEYS)
        self.assertIsInstance(q["name"], str)
        self.assertIsInstance(q["qtype"], int)
        self.assertIsInstance(q["qclass"], int)

        for section in ("answers", "authorities", "additionals"):
            record = result[section][0]
            self.assertEqual(set(record), RR_KEYS)
            self.assertIsInstance(record["name"], str)
            self.assertIsInstance(record["rtype"], int)
            self.assertIsInstance(record["rclass"], int)
            self.assertIsInstance(record["ttl"], int)
            self.assertIs(type(record["rdata"]), bytes)
            self.assertTrue(record["address"] is None
                            or isinstance(record["address"], str))

    def test_every_strict_prefix_of_valid_message_returns_none(self):
        packet = a_response()
        for cut in range(len(packet)):
            with self.subTest(cut=cut):
                self.assertIsNone(parse_dns(packet[:cut]))


# ---------- 정상 분석 ----------

class DnsParseTests(unittest.TestCase):
    def test_query(self):
        result = parse_dns(header(flags=0x0100, qd=1) + question(EXAMPLE))
        self.assertEqual(result["transaction_id"], 0x1234)
        self.assertEqual(result["kind"], "query")
        self.assertEqual(result["flags"], 0x0100)
        self.assertEqual(result["opcode"], 0)
        self.assertEqual(result["rcode"], 0)
        self.assertIs(result["truncated"], False)
        self.assertEqual(result["questions"],
                         [{"name": "example.com", "qtype": 1, "qclass": 1}])
        self.assertEqual(result["answers"], [])

    def test_a_response_with_compressed_owner_name(self):
        result = parse_dns(a_response())
        self.assertEqual(result["kind"], "response")
        self.assertEqual(result["flags"], 0x8180)
        self.assertEqual(result["answers"], [{
            "name": "example.com", "rtype": 1, "rclass": 1, "ttl": 300,
            "rdata": IPV4, "address": "93.184.216.34",
        }])

    def test_transaction_id_range(self):
        for tid in (0, 1, 65535):
            with self.subTest(tid=tid):
                result = parse_dns(header(tid=tid, qd=1) + question(EXAMPLE))
                self.assertEqual(result["transaction_id"], tid)

    def test_multiple_questions_and_records_keep_wire_order(self):
        other = name(b"www", b"example", b"org")
        aaaa = ipaddress.IPv6Address("2001:db8::1").packed
        packet = (
            header(flags=0x8180, qd=2, an=2, ns=1, ar=1)
            + question(EXAMPLE, 1, 1)
            + question(other, 28, 1)
            + rr(PTR_TO_FIRST_NAME, 1, 1, 10, IPV4)
            + rr(PTR_TO_FIRST_NAME, 28, 1, 20, aaaa)
            + rr(PTR_TO_FIRST_NAME, 2, 1, 30, name(b"ns", b"example", b"com"))
            + rr(PTR_TO_FIRST_NAME, 1, 1, 40, bytes([1, 2, 3, 4]))
        )
        result = parse_dns(packet)
        self.assertEqual([q["name"] for q in result["questions"]],
                         ["example.com", "www.example.org"])
        self.assertEqual([q["qtype"] for q in result["questions"]], [1, 28])
        self.assertEqual([r["ttl"] for r in result["answers"]], [10, 20])
        self.assertEqual([r["address"] for r in result["answers"]],
                         ["93.184.216.34", "2001:db8::1"])
        self.assertEqual([r["ttl"] for r in result["authorities"]], [30])
        self.assertEqual([r["ttl"] for r in result["additionals"]], [40])
        self.assertEqual(result["additionals"][0]["address"], "1.2.3.4")

    def test_aaaa_address_is_lowercase_and_compressed(self):
        cases = {
            "2001:0DB8:0:0:0:0:0:1": "2001:db8::1",
            "FE80:0:0:0:0:0:1:2": "fe80::1:2",
            "0:0:0:0:0:0:0:1": "::1",
            "2606:2800:220:1:248:1893:25C8:1946":
                "2606:2800:220:1:248:1893:25c8:1946",
        }
        for text, expected in cases.items():
            with self.subTest(address=text):
                packet = (header(flags=0x8180, qd=1, an=1)
                          + question(EXAMPLE, 28)
                          + rr(PTR_TO_FIRST_NAME, 28, 1, 60,
                               ipaddress.IPv6Address(text).packed))
                self.assertEqual(parse_dns(packet)["answers"][0]["address"],
                                 expected)

    def test_label_followed_by_pointer(self):
        owner = b"\x03www" + PTR_TO_FIRST_NAME
        packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                  + rr(owner, 1, 1, 60, IPV4))
        self.assertEqual(parse_dns(packet)["answers"][0]["name"],
                         "www.example.com")

    def test_pointer_to_pointer(self):
        first_rr_offset = 12 + len(question(EXAMPLE))
        pointer_to_first_rr = bytes([0xC0 | (first_rr_offset >> 8),
                                     first_rr_offset & 0xFF])
        packet = (header(flags=0x8180, qd=1, an=2) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 1, 1, 60, IPV4)
                  + rr(pointer_to_first_rr, 1, 1, 60, IPV4))
        result = parse_dns(packet)
        self.assertEqual([r["name"] for r in result["answers"]],
                         ["example.com", "example.com"])

    def test_nxdomain_response(self):
        result = parse_dns(header(flags=0x8183, qd=1) + question(EXAMPLE))
        self.assertEqual(result["kind"], "response")
        self.assertEqual(result["rcode"], 3)
        self.assertEqual(result["answers"], [])

    def test_truncated_flag_with_complete_items_is_returned(self):
        packet = (header(flags=0x8380, qd=1, an=1) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 1, 1, 60, IPV4))
        result = parse_dns(packet)
        self.assertIs(result["truncated"], True)
        self.assertEqual(len(result["answers"]), 1)

    def test_truncated_flag_with_cut_data_returns_none(self):
        packet = (header(flags=0x8380, qd=1, an=1) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 1, 1, 60, IPV4))
        self.assertIsNone(parse_dns(packet[:-2]))

    def test_unknown_rr_type_is_kept_not_an_error(self):
        packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 999, 1, 5, b"abc"))
        record = parse_dns(packet)["answers"][0]
        self.assertEqual(record["rtype"], 999)
        self.assertEqual(record["rdata"], b"abc")
        self.assertIsNone(record["address"])

    def test_unknown_rr_with_empty_rdata(self):
        packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 999, 1, 5, b""))
        self.assertEqual(parse_dns(packet)["answers"][0]["rdata"], b"")

    def test_cname_rdata_is_preserved_raw_with_compression_pointer(self):
        rdata = b"\x03www" + PTR_TO_FIRST_NAME
        packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 5, 1, 60, rdata))
        record = parse_dns(packet)["answers"][0]
        self.assertEqual(record["rtype"], 5)
        self.assertEqual(record["rdata"], rdata)
        self.assertIsNone(record["address"])

    def test_non_in_class_a_record_has_no_address(self):
        for rdlength_data in (IPV4, b"abc"):
            with self.subTest(rdata=rdlength_data):
                packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                          + rr(PTR_TO_FIRST_NAME, 1, 3, 60, rdlength_data))
                record = parse_dns(packet)["answers"][0]
                self.assertEqual(record["rclass"], 3)
                self.assertIsNone(record["address"])


# ---------- 이름 처리 ----------

class DnsNameTests(unittest.TestCase):
    def _question_name(self, qname):
        result = parse_dns(header(qd=1) + question(qname))
        return None if result is None else result["questions"][0]["name"]

    def test_root_name(self):
        self.assertEqual(self._question_name(b"\x00"), ".")

    def test_case_is_preserved(self):
        self.assertEqual(self._question_name(name(b"ExAmPle", b"COM")),
                         "ExAmPle.COM")

    def test_escapes(self):
        cases = [
            (name(b"a.b", b"com"), "a\\046b.com"),
            (name(b"a\\b", b"com"), "a\\092b.com"),
            (name(b"\xff", b"com"), "\\255.com"),
            (name(b"\x01x", b"com"), "\\001x.com"),
            (name(b"a\x7fb", b"com"), "a\\127b.com"),
        ]
        for wire, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self._question_name(wire), expected)

    def test_max_length_name_is_accepted(self):
        wire = name(b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61)
        self.assertEqual(len(wire), 255)
        self.assertEqual(self._question_name(wire),
                         ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61]))

    def test_name_over_255_bytes_returns_none(self):
        wire = name(b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 62)
        self.assertEqual(len(wire), 256)
        self.assertIsNone(self._question_name(wire))

    def test_expanded_name_over_255_bytes_via_pointer_returns_none(self):
        long_name = name(b"a" * 63, b"b" * 63, b"c" * 63)  # 193바이트
        owner = b"\x3f" + b"x" * 63 + PTR_TO_FIRST_NAME    # 확장 시 257바이트
        packet = (header(flags=0x8180, qd=1, an=1) + question(long_name)
                  + rr(owner, 1, 1, 60, IPV4))
        self.assertIsNone(parse_dns(packet))

    def test_label_over_63_bytes_returns_none(self):
        for prefix in (b"\x40", b"\x80"):
            with self.subTest(prefix=prefix):
                wire = prefix + b"a" * 64 + b"\x00"
                self.assertIsNone(self._question_name(wire))

    def test_truncated_label_returns_none(self):
        self.assertIsNone(parse_dns(header(qd=1) + b"\x0aabc"))

    def test_name_without_terminator_returns_none(self):
        self.assertIsNone(parse_dns(header(qd=1) + b"\x03abc"))

    def test_self_pointer_loop_returns_none(self):
        packet = header(qd=1) + PTR_TO_FIRST_NAME + struct.pack("!HH", 1, 1)
        self.assertIsNone(parse_dns(packet))

    def test_two_pointer_loop_returns_none(self):
        packet = (header(qd=1) + b"\xc0\x0e" + b"\xc0\x0c"
                  + struct.pack("!HH", 1, 1))
        self.assertIsNone(parse_dns(packet))

    def test_pointer_out_of_range_returns_none(self):
        packet = header(qd=1) + b"\xc3\xff" + struct.pack("!HH", 1, 1)
        self.assertIsNone(parse_dns(packet))

    def test_pointer_exactly_at_end_returns_none(self):
        size = 12 + 2 + 4  # 헤더 + 포인터(2) + qtype/qclass(4)
        packet = (header(qd=1)
                  + bytes([0xC0 | (size >> 8), size & 0xFF])
                  + struct.pack("!HH", 1, 1))
        self.assertEqual(len(packet), size)
        self.assertIsNone(parse_dns(packet))  # 가리키는 위치가 메시지 끝 바깥

    def test_truncated_pointer_returns_none(self):
        self.assertIsNone(parse_dns(header(qd=1) + b"\xc0"))


# ---------- 잘못된 메시지 ----------

class DnsMalformedTests(unittest.TestCase):
    def test_non_zero_opcode_returns_none(self):
        for opcode in (1, 2, 4, 5):
            with self.subTest(opcode=opcode):
                flags = 0x0100 | (opcode << 11)
                self.assertIsNone(
                    parse_dns(header(flags=flags, qd=1) + question(EXAMPLE)))

    def test_invalid_a_rdlength_returns_none(self):
        for bad in (b"", b"abc", b"abcde"):
            with self.subTest(length=len(bad)):
                packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                          + rr(PTR_TO_FIRST_NAME, 1, 1, 60, bad))
                self.assertIsNone(parse_dns(packet))

    def test_invalid_aaaa_rdlength_returns_none(self):
        for length in (0, 4, 15, 17):
            with self.subTest(length=length):
                packet = (header(flags=0x8180, qd=1, an=1) + question(EXAMPLE)
                          + rr(PTR_TO_FIRST_NAME, 28, 1, 60, b"x" * length))
                self.assertIsNone(parse_dns(packet))

    def test_rdlength_beyond_message_returns_none(self):
        bad_rr = (PTR_TO_FIRST_NAME
                  + struct.pack("!HHIH", 999, 1, 60, 10) + b"abc")
        packet = header(flags=0x8180, qd=1, an=1) + question(EXAMPLE) + bad_rr
        self.assertIsNone(parse_dns(packet))

    def test_truncated_question_returns_none(self):
        packet = header(qd=1) + EXAMPLE + b"\x00\x01"  # qclass 누락
        self.assertIsNone(parse_dns(packet))

    def test_declared_more_records_than_present_returns_none(self):
        packet = (header(flags=0x8180, qd=1, an=2) + question(EXAMPLE)
                  + rr(PTR_TO_FIRST_NAME, 1, 1, 60, IPV4))
        self.assertIsNone(parse_dns(packet))

    def test_trailing_bytes_return_none(self):
        self.assertIsNone(parse_dns(a_response() + b"\x00"))

    def test_huge_declared_counts_return_none(self):
        self.assertIsNone(parse_dns(header(qd=65535, an=65535,
                                           ns=65535, ar=65535)))
        self.assertIsNone(parse_dns(header(qd=1000) + question(EXAMPLE)))


if __name__ == "__main__":
    unittest.main()