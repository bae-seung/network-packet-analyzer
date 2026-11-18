"""공통 인터페이스 v1의 캡처 계약을 합성 프레임으로 확인한다."""

import errno
import socket
import unittest
from unittest.mock import Mock, patch

from capture import capture


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.raw_socket = Mock()
        self.raw_socket.getsockname.return_value = ("eth0", 3, 0, 1, b"")
        fake_socket = Mock(
            AF_PACKET=17, SOCK_RAW=socket.SOCK_RAW, ETH_P_ALL=3,
            PACKET_HOST=0, PACKET_BROADCAST=1, PACKET_MULTICAST=2,
            PACKET_OUTGOING=4, MSG_TRUNC=32,
            socket=Mock(return_value=self.raw_socket),
        )
        self.enterContext(patch.object(capture, "socket", fake_socket))
        self.enterContext(patch.object(capture.sys, "platform", "linux"))
        self.fake_socket = fake_socket

    def test_direction_filtering_and_frame_bytes(self):
        frame_bytes = bytes.fromhex("ffffffffffff0200000000010800") + bytes(46)
        packet_types = iter((3, 99, 4, 0, 1, 2))

        def receive(buffer, capacity, flags):
            self.assertEqual(flags, self.fake_socket.MSG_TRUNC)
            buffer[:len(frame_bytes)] = frame_bytes
            return len(frame_bytes), ("eth0", 0x0800, next(packet_types), 1, b"")

        self.raw_socket.recvfrom_into.side_effect = receive
        frames = capture.capture_packets("eth0")
        with patch.object(capture.time, "time", return_value=123.5):
            try:
                outgoing, *incoming = [next(frames) for _ in range(4)]
            finally:
                frames.close()

        self.assertEqual(outgoing, {
            "raw_data": frame_bytes, "interface": "eth0", "timestamp": 123.5,
            "direction": "OUTGOING", "packet_type": 4,
        })
        self.assertEqual(
            [(f["direction"], f["packet_type"]) for f in incoming],
            [("INCOMING", 0), ("INCOMING", 1), ("INCOMING", 2)],
        )
        self.fake_socket.socket.assert_called_once_with(17, socket.SOCK_RAW, 0)
        self.raw_socket.bind.assert_called_once_with(("eth0", 3))
        self.raw_socket.close.assert_called_once()

    def test_truncated_frame_is_skipped(self):
        frame_bytes = bytes(60)
        address = ("eth0", 0x0800, 0, 1, b"")
        first_receive = True

        def receive(buffer, capacity, flags):
            nonlocal first_receive
            if first_receive:
                first_receive = False
                return capacity + 1, address
            buffer[:len(frame_bytes)] = frame_bytes
            return len(frame_bytes), address

        self.raw_socket.recvfrom_into.side_effect = receive
        frames = capture.capture_packets("eth0")
        try:
            self.assertEqual(next(frames)["raw_data"], frame_bytes)
            self.assertEqual(self.raw_socket.recvfrom_into.call_count, 2)
        finally:
            frames.close()

    def test_permission_error_propagates(self):
        self.fake_socket.socket.side_effect = PermissionError(errno.EPERM, "denied")
        with self.assertRaises(PermissionError):
            next(capture.capture_packets("eth0"))

    def test_socket_closed_on_receive_error(self):
        self.raw_socket.recvfrom_into.side_effect = OSError(errno.ENETDOWN, "down")
        with self.assertRaises(OSError):
            next(capture.capture_packets("eth0"))
        self.raw_socket.close.assert_called_once()

    def test_non_ethernet_interface_is_rejected(self):
        self.raw_socket.getsockname.return_value = ("lo", 3, 0, 772, b"")
        with self.assertRaises(OSError):
            next(capture.capture_packets("lo"))
        self.raw_socket.close.assert_called_once()

    def test_invalid_arguments_and_platform(self):
        with self.assertRaises(TypeError):
            next(capture.capture_packets(None))
        with self.assertRaises(ValueError):
            next(capture.capture_packets(""))
        with patch.object(capture.sys, "platform", "win32"):
            with self.assertRaises(RuntimeError):
                next(capture.capture_packets("eth0"))
        self.fake_socket.socket.assert_not_called()
