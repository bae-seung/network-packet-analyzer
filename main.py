"""캡처와 분석 모듈을 연결하는 실행 진입점."""

import argparse
from contextlib import closing
from itertools import islice
import json
import sys

from capture.capture import capture_packets
from parsers import dns_parser, http_parser, packet_parser, smtp_parser


def summarize_application(packet: dict) -> dict | None:
    payload = packet["payload"]
    if not payload:
        return None

    ports = {packet["src_port"], packet["dst_port"]}
    if packet["transport"] == "UDP" and 53 in ports:
        result = dns_parser.parse_dns(payload)
        if result is not None:
            return {
                "protocol": "DNS",
                "kind": result["kind"],
                "transaction_id": result["transaction_id"],
                "rcode": result["rcode"],
            }
    elif packet["transport"] == "TCP":
        is_http = bool(ports & {80, 8000})
        is_smtp = bool(ports & {25, 2525})
        if is_http and is_smtp:
            return None
        if is_http:
            result = http_parser.parse_http(payload)
            if result is not None:
                return {
                    "protocol": "HTTP",
                    "kind": result["kind"],
                    "method": result["method"],
                    "status_code": result["status_code"],
                }
        elif is_smtp:
            parse_smtp = getattr(smtp_parser, "parse_smtp", None)
            if callable(parse_smtp):
                result = parse_smtp(payload)
                if result is not None:
                    return {
                        "protocol": "SMTP",
                        "kind": result["kind"],
                        "command": result["command"],
                        "code": result["code"],
                    }
    return None


def summarize_frame(frame: dict, *, capture_only: bool) -> dict | None:
    raw_data = frame["raw_data"]
    summary = {
        "interface": frame["interface"],
        "timestamp": frame["timestamp"],
        "direction": frame["direction"],
        "packet_type": frame["packet_type"],
        "frame_length": len(raw_data),
    }
    if capture_only:
        return summary

    packet = packet_parser.parse_packet(raw_data)
    if packet is None:
        return None
    for key in (
        "src_ip", "dst_ip", "transport", "src_port", "dst_port",
        "seq", "ack", "tcp_flags", "udp_length",
    ):
        summary[key] = packet[key]
    summary["application"] = summarize_application(packet)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--interface", required=True, help="캡처할 Ethernet 인터페이스")
    parser.add_argument("--capture-only", action="store_true", help="캡처 메타데이터만 출력")
    parser.add_argument("--count", type=int, help="이 프레임 수만큼 캡처한 뒤 종료")
    args = parser.parse_args(argv)
    if args.count is not None and args.count <= 0:
        parser.error("--count는 양수여야 합니다.")
    if not args.capture_only:
        for module, name in (
            (packet_parser, "parse_packet"),
            (http_parser, "parse_http"),
            (dns_parser, "parse_dns"),
        ):
            if not callable(getattr(module, name, None)):
                parser.error(f"{name} 함수가 아직 없습니다. 캡처만 확인하려면 --capture-only를 사용하세요.")

    try:
        with closing(capture_packets(args.interface)) as frames:
            for frame in islice(frames, args.count):
                summary = summarize_frame(frame, capture_only=args.capture_only)
                if summary is not None:
                    print(json.dumps(summary, ensure_ascii=True), flush=True)
    except KeyboardInterrupt:
        return 130
    except PermissionError:
        print("캡처에 필요한 권한이 없습니다. sudo로 실행하세요.", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print(f"실행 오류 {str(error)!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
