"""Linux AF_PACKET을 이용한 Ethernet 프레임 캡처."""

from collections.abc import Iterator
import errno
import socket
import sys
import time


ARPHRD_ETHER = 1
RECEIVE_BUFFER_SIZE = 262_144


def capture_packets(interface: str) -> Iterator[dict]:
    """지정한 인터페이스에서 프레임과 캡처 정보를 반환한다."""
    if not isinstance(interface, str):
        raise TypeError("interface must be a string")
    if not interface.strip():
        raise ValueError("interface must not be empty")
    if sys.platform != "linux" or not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("AF_PACKET capture requires Linux")

    directions = {
        socket.PACKET_HOST: "INCOMING",
        socket.PACKET_BROADCAST: "INCOMING",
        socket.PACKET_MULTICAST: "INCOMING",
        socket.PACKET_OUTGOING: "OUTGOING",
    }
    buffer = memoryview(bytearray(RECEIVE_BUFFER_SIZE))
    # 프로토콜 0으로 열어 지정 인터페이스에 bind할 때부터 수신한다.
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    try:
        raw_socket.bind((interface, socket.ETH_P_ALL))
        if raw_socket.getsockname()[3] != ARPHRD_ETHER:
            raise OSError(errno.EPROTONOSUPPORT, "Ethernet interface required", interface)

        while True:
            # Linux의 MSG_TRUNC는 복사한 길이 대신 원래 프레임 길이를 돌려준다.
            length, address = raw_socket.recvfrom_into(buffer, len(buffer), socket.MSG_TRUNC)
            timestamp = time.time()
            if length > len(buffer):
                continue

            actual_interface, _, packet_type, _, _ = address
            direction = directions.get(packet_type)
            if direction is None:
                continue

            yield {
                "raw_data": bytes(buffer[:length]),
                "interface": actual_interface,
                "timestamp": timestamp,
                "direction": direction,
                "packet_type": packet_type,
            }
    finally:
        raw_socket.close()
