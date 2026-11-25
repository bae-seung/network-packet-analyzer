"""Unit tests for parsers.smtp_parser based on docs/INTERFACE.md SMTP v1."""

import unittest

from parsers.smtp_parser import parse_smtp


class TestSMTPParser(unittest.TestCase):
    def assert_command(self, payload: bytes, command: str, argument: str):
        self.assertEqual(
            parse_smtp(payload),
            {
                "kind": "command",
                "command": command,
                "argument": argument,
                "code": None,
                "text": None,
            },
        )

    def assert_response(self, payload: bytes, code: int, text: str):
        self.assertEqual(
            parse_smtp(payload),
            {
                "kind": "response",
                "command": None,
                "argument": None,
                "code": code,
                "text": text,
            },
        )

    def test_ehlo(self):
        self.assert_command(b"EHLO mail.example.test\r\n", "EHLO", "mail.example.test")

    def test_helo(self):
        self.assert_command(b"HELO mail.example.test\r\n", "HELO", "mail.example.test")

    def test_mail_from(self):
        self.assert_command(b"MAIL FROM:<alice@example.test>\r\n", "MAIL FROM", "<alice@example.test>")

    def test_rcpt_to(self):
        self.assert_command(b"RCPT TO:<bob@example.test>\r\n", "RCPT TO", "<bob@example.test>")

    def test_data(self):
        self.assert_command(b"DATA\r\n", "DATA", "")

    def test_rset(self):
        self.assert_command(b"RSET\r\n", "RSET", "")

    def test_noop(self):
        self.assert_command(b"NOOP\r\n", "NOOP", "")

    def test_quit(self):
        self.assert_command(b"QUIT\r\n", "QUIT", "")

    def test_lowercase_ehlo(self):
        self.assert_command(b"ehlo Client.Example\r\n", "EHLO", "Client.Example")

    def test_mixed_case_mail_from(self):
        self.assert_command(b"mAiL fRoM:<X@Example.test>\r\n", "MAIL FROM", "<X@Example.test>")

    def test_mixed_case_rcpt_to(self):
        self.assert_command(b"rCpT tO:<X@Example.test>\r\n", "RCPT TO", "<X@Example.test>")

    def test_argument_trimmed(self):
        self.assert_command(b"EHLO \t example.test  \t\r\n", "EHLO", "example.test")

    def test_mail_argument_trimmed(self):
        self.assert_command(b"MAIL FROM: \t<alice@example.test> \t\r\n", "MAIL FROM", "<alice@example.test>")

    def test_rcpt_argument_trimmed(self):
        self.assert_command(b"RCPT TO: \t<bob@example.test> \t\r\n", "RCPT TO", "<bob@example.test>")

    def test_noop_with_argument(self):
        self.assert_command(b"NOOP arbitrary text\r\n", "NOOP", "arbitrary text")

    def test_noop_with_empty_argument(self):
        self.assert_command(b"NOOP   \r\n", "NOOP", "")

    def test_helo_tab_separator(self):
        self.assert_command(b"HELO\texample.test\r\n", "HELO", "example.test")

    def test_response_250(self):
        self.assert_response(b"250 OK\r\n", 250, "OK")

    def test_response_220(self):
        self.assert_response(b"220 smtp.example.test ready\r\n", 220, "smtp.example.test ready")

    def test_response_354(self):
        self.assert_response(b"354 Start mail input\r\n", 354, "Start mail input")

    def test_response_550(self):
        self.assert_response(b"550 Mailbox unavailable\r\n", 550, "Mailbox unavailable")

    def test_response_599(self):
        self.assert_response(b"599 Some response\r\n", 599, "Some response")

    def test_response_empty_text(self):
        self.assert_response(b"250 \r\n", 250, "")

    def test_response_text_case_preserved(self):
        self.assert_response(b"250 AbC TaG\r\n", 250, "AbC TaG")

    def test_empty_payload(self):
        self.assertIsNone(parse_smtp(b""))

    def test_wrong_input_type(self):
        for value in (None, "EHLO x\r\n", bytearray(b"EHLO x\r\n"), 123):
            with self.subTest(value=value), self.assertRaises(TypeError):
                parse_smtp(value)

    def test_missing_crlf(self):
        self.assertIsNone(parse_smtp(b"EHLO example.test"))

    def test_lf_only(self):
        self.assertIsNone(parse_smtp(b"EHLO example.test\n"))

    def test_cr_only(self):
        self.assertIsNone(parse_smtp(b"EHLO example.test\r"))

    def test_multiple_lines(self):
        self.assertIsNone(parse_smtp(b"EHLO example.test\r\nQUIT\r\n"))

    def test_additional_crlf(self):
        self.assertIsNone(parse_smtp(b"NOOP\r\n\r\n"))

    def test_split_command_line(self):
        self.assertIsNone(parse_smtp(b"MAIL FROM:<alice@exa"))

    def test_split_response_line(self):
        self.assertIsNone(parse_smtp(b"250 OK"))

    def test_multiline_response(self):
        self.assertIsNone(parse_smtp(b"250-First line\r\n250 Second line\r\n"))

    def test_multiline_response_prefix_alone(self):
        self.assertIsNone(parse_smtp(b"250-First line\r\n"))

    def test_response_without_space(self):
        self.assertIsNone(parse_smtp(b"250OK\r\n"))

    def test_response_tab_separator(self):
        self.assertIsNone(parse_smtp(b"250\tOK\r\n"))

    def test_response_below_range(self):
        self.assertIsNone(parse_smtp(b"199 Reserved\r\n"))

    def test_response_above_range(self):
        self.assertIsNone(parse_smtp(b"600 Invalid\r\n"))

    def test_response_two_digits(self):
        self.assertIsNone(parse_smtp(b"25 OK\r\n"))

    def test_response_four_digits(self):
        self.assertIsNone(parse_smtp(b"2500 OK\r\n"))

    def test_response_non_digits(self):
        self.assertIsNone(parse_smtp(b"2A0 OK\r\n"))

    def test_non_ascii(self):
        self.assertIsNone(parse_smtp(b"EHLO \xff\r\n"))

    def test_null_byte(self):
        self.assertIsNone(parse_smtp(b"EHLO test\x00\r\n"))

    def test_del_character(self):
        self.assertIsNone(parse_smtp(b"250 OK\x7f\r\n"))

    def test_unknown_command(self):
        self.assertIsNone(parse_smtp(b"STARTTLS\r\n"))

    def test_auth_unsupported(self):
        self.assertIsNone(parse_smtp(b"AUTH LOGIN\r\n"))

    def test_data_with_argument(self):
        self.assertIsNone(parse_smtp(b"DATA unexpected\r\n"))

    def test_rset_with_argument(self):
        self.assertIsNone(parse_smtp(b"RSET unexpected\r\n"))

    def test_quit_with_argument(self):
        self.assertIsNone(parse_smtp(b"QUIT unexpected\r\n"))

    def test_ehlo_empty_arg(self):
        self.assertIsNone(parse_smtp(b"EHLO\r\n"))

    def test_helo_spaces_only(self):
        self.assertIsNone(parse_smtp(b"HELO   \r\n"))

    def test_mail_from_empty(self):
        self.assertIsNone(parse_smtp(b"MAIL FROM:\r\n"))

    def test_mail_from_spaces_only(self):
        self.assertIsNone(parse_smtp(b"MAIL FROM: \t\r\n"))

    def test_rcpt_to_empty(self):
        self.assertIsNone(parse_smtp(b"RCPT TO:\r\n"))

    def test_mail_without_colon(self):
        self.assertIsNone(parse_smtp(b"MAIL FROM <alice@example.test>\r\n"))

    def test_rcpt_without_colon(self):
        self.assertIsNone(parse_smtp(b"RCPT TO <bob@example.test>\r\n"))

    def test_partial_command_token(self):
        self.assertIsNone(parse_smtp(b"EHLOOO x\r\n"))

    def test_data_body_not_parsed(self):
        self.assertIsNone(parse_smtp(b"hello world\r\n"))

    def test_command_contract_keys_and_types(self):
        result = parse_smtp(b"NOOP\r\n")
        self.assertEqual(set(result), {"kind", "command", "argument", "code", "text"})
        self.assertIsInstance(result["command"], str)
        self.assertIsInstance(result["argument"], str)
        self.assertIsNone(result["code"])
        self.assertIsNone(result["text"])

    def test_response_contract_keys_and_types(self):
        result = parse_smtp(b"250 OK\r\n")
        self.assertEqual(set(result), {"kind", "command", "argument", "code", "text"})
        self.assertIsInstance(result["code"], int)
        self.assertIsInstance(result["text"], str)
        self.assertIsNone(result["command"])
        self.assertIsNone(result["argument"])


if __name__ == "__main__":
    unittest.main()
