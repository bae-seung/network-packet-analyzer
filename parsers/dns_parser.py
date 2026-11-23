

import ipaddress
import struct

_HEADER_LEN = 12
_MIN_QUESTION_LEN = 5   # 루트 이름(1) + qtype(2) + qclass(2)
_MIN_RR_LEN = 11        # 루트 이름(1) + type/class/ttl/rdlength(10)
_MAX_NAME_WIRE_LEN = 255
_MAX_POINTER_JUMPS = 128

_TYPE_A = 1
_TYPE_AAAA = 28
_CLASS_IN = 1


class _Malformed(Exception):
    """잘못되었거나 불완전한 DNS 메시지 (내부 전용)."""


def _escape_label(raw: bytes) -> str:
    """라벨 안의 '.', '\\', 비출력/비ASCII 바이트를 \\DDD(3자리 십진수)로 바꾼다."""
    out = []
    for c in raw:
        if c == 0x2E or c == 0x5C or c < 0x20 or c > 0x7E:
            out.append("\\%03d" % c)
        else:
            out.append(chr(c))
    return "".join(out)


def _read_name(data: bytes, offset: int):
    """offset에서 시작하는 이름을 읽어 (이름, 다음 읽기 위치)를 반환한다.

    압축 포인터의 기준은 DNS payload 첫 바이트이다.
    범위 밖 포인터, 순환 참조, 잘린 라벨, 예약된 라벨 형식,
    255바이트를 넘는 확장 이름은 _Malformed.
    """
    size = len(data)
    labels = []
    pos = offset
    next_offset = None
    visited = set()
    wire_len = 1  # 끝의 루트 라벨

    while True:
        if pos >= size:
            raise _Malformed
        first = data[pos]

        if first == 0:  # 이름 끝
            if next_offset is None:
                next_offset = pos + 1
            break

        label_type = first & 0xC0
        if label_type == 0xC0:  # 압축 포인터
            if pos + 1 >= size:
                raise _Malformed
            target = ((first & 0x3F) << 8) | data[pos + 1]
            if next_offset is None:
                next_offset = pos + 2
            if target >= size or target in visited:
                raise _Malformed
            visited.add(target)
            if len(visited) > _MAX_POINTER_JUMPS:
                raise _Malformed
            pos = target
            continue

        if label_type != 0:  # 0x40, 0x80은 63바이트 초과/예약 형식
            raise _Malformed

        start = pos + 1
        end = start + first
        if end > size:
            raise _Malformed
        wire_len += first + 1
        if wire_len > _MAX_NAME_WIRE_LEN:
            raise _Malformed
        labels.append(_escape_label(data[start:end]))
        pos = end

    name = ".".join(labels) if labels else "."
    return name, next_offset


def _read_question(data: bytes, offset: int):
    name, offset = _read_name(data, offset)
    if offset + 4 > len(data):
        raise _Malformed
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    return {"name": name, "qtype": qtype, "qclass": qclass}, offset + 4


def _read_rr(data: bytes, offset: int):
    name, offset = _read_name(data, offset)
    if offset + 10 > len(data):
        raise _Malformed
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    end = offset + rdlength
    if end > len(data):
        raise _Malformed
    rdata = data[offset:end]

    address = None
    if rclass == _CLASS_IN and rtype == _TYPE_A:
        if rdlength != 4:
            raise _Malformed
        address = ".".join(str(b) for b in rdata)
    elif rclass == _CLASS_IN and rtype == _TYPE_AAAA:
        if rdlength != 16:
            raise _Malformed
        address = ipaddress.IPv6Address(rdata).compressed

    rr = {
        "name": name,
        "rtype": rtype,
        "rclass": rclass,
        "ttl": ttl,
        "rdata": rdata,
        "address": address,
    }
    return rr, end


def parse_dns(payload: bytes) -> dict | None:
    """UDP DNS 메시지를 분석한다.

    - bytes가 아니면 TypeError
    - 빈 입력, 불완전/잘못된 형식, 표준 query(opcode=0)가 아닌 메시지는 None
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    size = len(payload)
    if size < _HEADER_LEN:
        return None

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!6H", payload, 0
    )
    opcode = (flags >> 11) & 0xF
    if opcode != 0:
        return None

    # 선언된 항목이 남은 길이에 들어갈 수 있는지 먼저 확인 (과도한 반복 방지)
    min_needed = (qdcount * _MIN_QUESTION_LEN
                  + (ancount + nscount + arcount) * _MIN_RR_LEN)
    if min_needed > size - _HEADER_LEN:
        return None

    try:
        offset = _HEADER_LEN
        questions = []
        for _ in range(qdcount):
            q, offset = _read_question(payload, offset)
            questions.append(q)

        sections = []
        for count in (ancount, nscount, arcount):
            records = []
            for _ in range(count):
                rr, offset = _read_rr(payload, offset)
                records.append(rr)
            sections.append(records)
    except _Malformed:
        return None

    if offset != size:  # 선언 항목 뒤에 여분의 바이트가 남음
        return None

    answers, authorities, additionals = sections
    return {
        "transaction_id": tid,
        "kind": "response" if flags & 0x8000 else "query",
        "flags": flags,
        "opcode": opcode,
        "rcode": flags & 0xF,
        "truncated": bool(flags & 0x0200),
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }