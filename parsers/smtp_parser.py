"""Stateless, single-line SMTP command/reply parser for the team's v1 contract.

Only exactly one complete, plaintext ASCII line in a TCP payload is handled.
This parser does not validate SMTP sessions, addresses, or DATA content.
"""

import re


_SIMPLE_COMMAND = re.compile(r"([A-Za-z]+)(?:[ \t]+(.*))?\Z")
_REQUIRED_ARGUMENT = frozenset({"EHLO", "HELO"})
_NO_ARGUMENT = frozenset({"DATA", "RSET", "QUIT"})
_OPTIONAL_ARGUMENT = frozenset({"NOOP"})
_ADDRESS_PREFIXES = (("MAIL FROM:", "MAIL FROM"), ("RCPT TO:", "RCPT TO"))


def _command_result(command: str, argument: str) -> dict:
    return {
        "kind": "command",
        "command": command,
        "argument": argument,
        "code": None,
        "text": None,
    }


def parse_smtp(payload: bytes) -> dict | None:
    """Parse one complete ASCII SMTP command or single-line server response.

    Args:
        payload: Raw TCP payload beginning at the SMTP message line.

    Returns:
        Five-field dict as defined in docs/INTERFACE.md, or None for unsupported,
        incomplete, or invalid input.

    Raises:
        TypeError: If payload is not bytes (including bytearray/memoryview).
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    if not payload or not payload.endswith(b"\r\n"):
        return None

    # Precisely one line: no extra SMTP commands/replies or line fragments.
    raw_line = payload[:-2]
    if b"\r" in raw_line or b"\n" in raw_line:
        return None

    # Printable ASCII (SP..~), with HTAB allowed as whitespace.
    if any(byte != 9 and not (32 <= byte <= 126) for byte in raw_line):
        return None

    line = raw_line.decode("ascii")

    # Server replies: exactly three ASCII digits, one SP, then response text.
    if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
        code = int(line[:3])
        if not 200 <= code <= 599:
            return None
        return {
            "kind": "response",
            "command": None,
            "argument": None,
            "code": code,
            "text": line[4:],
        }

    upper = line.upper()

    # Commands containing the required FROM:/TO: marker.
    for prefix, command in _ADDRESS_PREFIXES:
        if upper.startswith(prefix):
            argument = line[len(prefix):].strip(" \t")
            return _command_result(command, argument) if argument else None

    # One-word commands, matched on token boundaries.
    match = _SIMPLE_COMMAND.fullmatch(line)
    if match is None:
        return None

    command = match.group(1).upper()
    raw_arg = match.group(2)
    argument = "" if raw_arg is None else raw_arg.strip(" \t")

    if command in _REQUIRED_ARGUMENT:
        return _command_result(command, argument) if argument else None

    if command in _NO_ARGUMENT:
        return _command_result(command, "") if raw_arg is None else None

    if command in _OPTIONAL_ARGUMENT:
        return _command_result(command, argument)

    return None
