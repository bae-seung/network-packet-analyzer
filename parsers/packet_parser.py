"""담당: 구본준.

Ethernet, IPv4, TCP, UDP 헤더 분석.
공통 규칙은 docs/INTERFACE.md 4번을 따른다.
"""

import struct

ETHERNET_HEADER_LEN = 14  # 도착지 MAC 6 + 출발지 MAC 6 + 타입 2
ETHERTYPE_IPV4 = 0x0800

IPV4_MIN_HEADER_LEN = 20
IP_PROTOCOL_TCP = 6
IP_PROTOCOL_UDP = 17
IP_FLAG_MF = 0x2000  # More Fragments 비트 (flags/fragment 필드 기준)
IP_FRAGMENT_OFFSET_MASK = 0x1FFF

TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8


def _format_mac(mac_bytes: bytes) -> str:
    """6바이트 MAC 주소를 '02:00:00:00:00:01' 형태의 소문자 문자열로 바꾼다."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _format_ipv4(ip_bytes: bytes) -> str:
    """4바이트 IPv4 주소를 '192.168.0.1' 형태의 문자열로 바꾼다."""
    return ".".join(str(b) for b in ip_bytes)


def _parse_ethernet(raw_data: bytes) -> dict | None:
    """Ethernet II 헤더(맨 앞 14바이트)를 읽는다. 14바이트보다 짧으면 None."""
    if len(raw_data) < ETHERNET_HEADER_LEN:
        return None
    # "!"  : 네트워크 바이트 순서(큰 값이 앞)
    # "6s" : 6바이트 덩어리 (도착지 MAC)
    # "6s" : 6바이트 덩어리 (출발지 MAC)
    # "H"  : 2바이트 정수 (ethertype)
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw_data[:ETHERNET_HEADER_LEN])
    return {
        "dst_mac": _format_mac(dst_mac),
        "src_mac": _format_mac(src_mac),
        "ethertype": ethertype,
    }


def _parse_ipv4(ip_packet: bytes) -> dict | None:
    """Ethernet 헤더 뒤의 bytes에서 IPv4 헤더를 읽는다.

    반환 dict의 "data"는 IP 헤더를 뺀, IP total length까지의 데이터(TCP/UDP 세그먼트)다.
    잘못된 헤더, 조각난 패킷(fragment), TCP/UDP가 아닌 프로토콜이면 None.
    """
    if len(ip_packet) < IPV4_MIN_HEADER_LEN:
        return None
    # "!"  : 네트워크 바이트 순서
    # "B"  : version(상위 4비트) + IHL(하위 4비트)
    # "B"  : TOS (사용하지 않음)
    # "H"  : 전체 길이(total length)
    # "H"  : identification (사용하지 않음)
    # "H"  : flags(상위 3비트) + fragment offset(하위 13비트)
    # "B"  : TTL
    # "B"  : protocol
    # "H"  : checksum (검증하지 않음)
    # "4s" : 출발지 IP
    # "4s" : 목적지 IP
    (version_ihl, _tos, total_length, _ident, flags_fragment, ttl, protocol,
     _checksum, src_ip, dst_ip) = struct.unpack("!BBHHHBBH4s4s", ip_packet[:IPV4_MIN_HEADER_LEN])

    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    if version != 4 or ihl < 5:
        return None
    header_len = ihl * 4  # IHL은 4바이트 단위
    if total_length < header_len or len(ip_packet) < total_length:
        return None
    # MF=1 이거나 fragment offset이 0이 아니면 조각난 패킷이므로 지원하지 않는다.
    if flags_fragment & IP_FLAG_MF or flags_fragment & IP_FRAGMENT_OFFSET_MASK:
        return None
    if protocol not in (IP_PROTOCOL_TCP, IP_PROTOCOL_UDP):
        return None

    return {
        "src_ip": _format_ipv4(src_ip),
        "dst_ip": _format_ipv4(dst_ip),
        "ttl": ttl,
        "ip_protocol": protocol,
        "ip_header_length": header_len,
        "ip_total_length": total_length,
        # 이더넷 패딩 같은 후행 바이트는 total_length로 잘라 버린다.
        "data": ip_packet[header_len:total_length],
    }


def _parse_tcp(segment: bytes) -> dict | None:
    """TCP 세그먼트(IP 데이터)에서 TCP 헤더를 읽는다. 잘못된 헤더면 None."""
    if len(segment) < TCP_MIN_HEADER_LEN:
        return None
    # "H" "H" : 출발지/목적지 포트
    # "L" "L" : 시퀀스 번호 / 확인 응답 번호 (각 32비트)
    # "B"     : data offset(상위 4비트) + NS 플래그(마지막 비트)
    # "B"     : CWR ECE URG ACK PSH RST SYN FIN 플래그
    # "H" "H" "H" : window, checksum, urgent pointer (사용하지 않음)
    (src_port, dst_port, seq, ack, offset_byte, flags_byte,
     _window, _checksum, _urgent) = struct.unpack("!HHLLBBHHH", segment[:TCP_MIN_HEADER_LEN])

    data_offset = offset_byte >> 4
    if data_offset < 5:
        return None
    header_len = data_offset * 4  # data offset은 4바이트 단위 (옵션 포함)
    if header_len > len(segment):
        return None

    flags = {
        "fin": bool(flags_byte & 0x01),
        "syn": bool(flags_byte & 0x02),
        "rst": bool(flags_byte & 0x04),
        "psh": bool(flags_byte & 0x08),
        "ack": bool(flags_byte & 0x10),
        "urg": bool(flags_byte & 0x20),
        "ece": bool(flags_byte & 0x40),
        "cwr": bool(flags_byte & 0x80),
        "ns": bool(offset_byte & 0x01),
    }
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "transport_header_length": header_len,
        "seq": seq,
        "ack": ack,
        "tcp_flags": flags,
        "udp_length": None,
        "payload": segment[header_len:],
    }


def _parse_udp(segment: bytes) -> dict | None:
    """UDP 데이터그램(IP 데이터)에서 UDP 헤더를 읽는다. 길이가 맞지 않으면 None."""
    if len(segment) < UDP_HEADER_LEN:
        return None
    # "H" "H" : 출발지/목적지 포트, "H" : UDP 길이(헤더+데이터), "H" : checksum(사용 안 함)
    src_port, dst_port, length, _checksum = struct.unpack("!HHHH", segment[:UDP_HEADER_LEN])
    # v1에서는 UDP 길이가 IP 데이터 길이와 정확히 같아야 한다.
    if length < UDP_HEADER_LEN or length != len(segment):
        return None
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "transport_header_length": UDP_HEADER_LEN,
        "seq": None,
        "ack": None,
        "tcp_flags": None,
        "udp_length": length,
        "payload": segment[UDP_HEADER_LEN:],
    }


def parse_packet(raw_data: bytes) -> dict | None:
    """원시 프레임 bytes를 공통 dict로 바꾼다. (docs/INTERFACE.md 4번)

    Ethernet II → IPv4 → TCP 또는 UDP만 지원한다.
    bytes가 아니면 TypeError, 빈 입력·미지원·잘못된 패킷이면 None.
    """
    if not isinstance(raw_data, bytes):
        raise TypeError("raw_data는 bytes여야 합니다")
    if not raw_data:
        return None

    ethernet = _parse_ethernet(raw_data)
    # VLAN(0x8100), ARP(0x0806), IPv6(0x86DD), 802.3 LLC(길이값) 등은 모두 IPv4가 아니므로 None.
    if ethernet is None or ethernet["ethertype"] != ETHERTYPE_IPV4:
        return None

    ip = _parse_ipv4(raw_data[ETHERNET_HEADER_LEN:])
    if ip is None:
        return None

    if ip["ip_protocol"] == IP_PROTOCOL_TCP:
        transport_name = "TCP"
        transport = _parse_tcp(ip["data"])
    else:
        transport_name = "UDP"
        transport = _parse_udp(ip["data"])
    if transport is None:
        return None

    return {
        "src_mac": ethernet["src_mac"],
        "dst_mac": ethernet["dst_mac"],
        "ethertype": ethernet["ethertype"],
        "src_ip": ip["src_ip"],
        "dst_ip": ip["dst_ip"],
        "ttl": ip["ttl"],
        "ip_protocol": ip["ip_protocol"],
        "ip_header_length": ip["ip_header_length"],
        "ip_total_length": ip["ip_total_length"],
        "transport": transport_name,
        "src_port": transport["src_port"],
        "dst_port": transport["dst_port"],
        "transport_header_length": transport["transport_header_length"],
        "seq": transport["seq"],
        "ack": transport["ack"],
        "tcp_flags": transport["tcp_flags"],
        "udp_length": transport["udp_length"],
        "payload": transport["payload"],
    }
