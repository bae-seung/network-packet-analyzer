"""main.py가 출력하는 JSON 줄을 사람이 읽기 쉬운 표로 바꿔 보여준다.

main.py와 파서는 바꾸지 않고, 출력(JSON Lines)만 읽어 표로 만든다.

사용법 (저장소 루트에서)
  실시간:  sudo python3.12 main.py -i eth0 | tee result.jsonl | python3.12 tools/pretty.py
  저장본:  python3.12 tools/pretty.py result.jsonl
옵션
  --all       HTTP·DNS·SMTP 포트(53, 80, 8000, 25, 2525)가 아닌 패킷도 표시
  --no-color  색 없이 출력
"""

from __future__ import annotations

import json
import sys
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Iterable, TextIO

KST = timezone(timedelta(hours=9))
APP_PORTS = {53, 80, 8000, 25, 2525}

COLUMNS = [
    ("No", 4, True), ("시각", 12, False), ("방향", 4, False),
    ("출발지", 21, False), ("", 1, False), ("목적지", 21, False),
    ("계층", 9, False), ("플래그", 8, False), ("SEQ", 10, True),
    ("ACK", 10, True), ("설명", 0, False),
]


def display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def pad(text: str, width: int, right: bool = False) -> str:
    gap = " " * max(0, width - display_width(text))
    return gap + text if right else text + gap


def format_row(values: list[str]) -> str:
    return "  ".join(
        pad(v, w, r) if w else v for v, (_, w, r) in zip(values, COLUMNS)
    )


def flag_text(flags: dict | None) -> str:
    if not flags:
        return ""
    return ",".join(
        k.upper() for k in ("syn", "fin", "rst", "psh", "ack", "urg") if flags.get(k)
    )


def app_text(app: dict) -> str:
    proto = app.get("protocol")
    if proto == "HTTP":
        if app.get("kind") == "request":
            return f"HTTP 요청: {app.get('method')}"
        return f"HTTP 응답: {app.get('status_code')}"
    if proto == "DNS":
        tid = app.get("transaction_id")
        tid = f"0x{tid:04x}" if isinstance(tid, int) else str(tid)
        if app.get("kind") == "query":
            return f"DNS 질의 (ID {tid})"
        return f"DNS 응답 (ID {tid}, rcode {app.get('rcode')})"
    if proto == "SMTP":
        if app.get("kind") == "command":
            return f"SMTP 명령: {app.get('command')}"
        return f"SMTP 응답: {app.get('code')}"
    return json.dumps(app, ensure_ascii=False)


class TcpTracker:
    """연결(양 끝점 쌍)별로 3-way handshake와 FIN 해제 단계를 붙인다."""

    def __init__(self) -> None:
        self.conns: dict[tuple, dict] = {}

    def describe(self, p: dict) -> str:
        f = p.get("tcp_flags") or {}
        key = tuple(sorted([(p["src_ip"], p["src_port"]), (p["dst_ip"], p["dst_port"])]))
        st = self.conns.setdefault(key, {
            "no": len(self.conns) + 1, "synack": False,
            "established": False, "fins": 0, "closed": False,
        })
        tag = f"[연결{st['no']}] "
        app = p.get("application")
        if f.get("rst"):
            return tag + "강제 종료 (RST)"
        if f.get("syn") and not f.get("ack"):
            return tag + "① 연결 요청 (3-way handshake 1/3)"
        if f.get("syn") and f.get("ack"):
            st["synack"] = True
            return tag + "② 연결 수락 (3-way handshake 2/3)"
        if f.get("fin"):
            st["fins"] += 1
            return tag + ("연결 해제 요청 (FIN 1)" if st["fins"] == 1 else "상대도 해제 (FIN 2)")
        if st["fins"] >= 2 and not st["closed"]:
            st["closed"] = True
            return tag + "연결 해제 완료 (마지막 ACK)"
        if st["synack"] and not st["established"] and not app:
            st["established"] = True
            return tag + "③ 연결 확립 (3-way handshake 3/3)"
        if app:
            return tag + app_text(app)
        if f.get("psh"):
            return tag + "데이터 전송 (이어지는 조각)"
        return tag + "수신 확인 (ACK)"


def layer(p: dict) -> str:
    app = p.get("application")
    if app and app.get("protocol"):
        return f"{p['transport']}/{app['protocol']}"
    return p.get("transport") or "-"


def describe(p: dict, tracker: TcpTracker) -> str:
    if p.get("transport") == "TCP":
        return tracker.describe(p)
    if p.get("application"):
        return app_text(p["application"])
    return f"UDP 데이터 (길이 {p.get('udp_length')})"


def build_row(p: dict, no: int, tracker: TcpTracker) -> list[str]:
    t = datetime.fromtimestamp(p["timestamp"], KST).strftime("%H:%M:%S.%f")[:-3]
    return [
        str(no), t, "송신" if p["direction"] == "OUTGOING" else "수신",
        f"{p['src_ip']}:{p['src_port']}", "→", f"{p['dst_ip']}:{p['dst_port']}",
        layer(p), flag_text(p.get("tcp_flags")),
        "" if p.get("seq") is None else str(p["seq"]),
        "" if p.get("ack") is None else str(p["ack"]),
        describe(p, tracker),
    ]


def iter_packets(lines: Iterable[str], show_all: bool = False):
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            p = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "src_ip" not in p:  # --capture-only 출력은 건너뜀
            continue
        if not show_all and not ({p.get("src_port"), p.get("dst_port")} & APP_PORTS):
            continue
        yield p


def render(lines: Iterable[str], out: TextIO, *, show_all: bool = False, color: bool = False) -> int:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    tracker = TcpTracker()
    print(paint(format_row([c[0] for c in COLUMNS]), "1"), file=out)
    print("-" * 150, file=out)
    sent = received = 0
    try:
        for no, p in enumerate(iter_packets(lines, show_all), start=1):
            values = build_row(p, no, tracker)
            outgoing = values[2] == "송신"
            sent += outgoing
            received += not outgoing
            text = format_row(values)
            if color:
                label = values[2]
                text = text.replace(label, paint(label, "32" if outgoing else "36"), 1)
            print(text, file=out, flush=True)
    except KeyboardInterrupt:
        pass
    print("-" * 150, file=out)
    print(f"표시한 패킷 {sent + received}개 (송신 {sent}, 수신 {received})", file=out)
    return sent + received


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    files = [a for a in argv if not a.startswith("--")]
    color = "--no-color" not in argv and sys.stdout.isatty()
    if files:
        with open(files[0], encoding="utf-8", errors="replace") as src:
            render(src, sys.stdout, show_all="--all" in argv, color=color)
    else:
        render(sys.stdin, sys.stdout, show_all="--all" in argv, color=color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
