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
    ("TTL", 3, True), ("계층", 9, False), ("플래그", 8, False),
    ("SEQ", 10, True), ("ACK", 10, True), ("설명", 0, False),
]
RULE_WIDTH = 160
MAX_FIELD = 60  # 설명 칸에 넣는 외부 문자열 한 개의 최대 길이

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 64: "SVCB", 65: "HTTPS",
}


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


def safe(value) -> str:
    """패킷에서 온 문자열을 터미널에 안전하게 표시한다.

    제어 문자(ESC 등)는 \\xNN 형태로 바꿔 터미널 조작을 막고, 너무 긴 값은 줄인다.
    """
    def escape(c: str) -> str:
        if not unicodedata.category(c).startswith("C"):
            return c
        return f"\\x{ord(c):02x}" if ord(c) < 0x100 else f"\\u{ord(c):04x}"

    text = "".join(escape(c) for c in str(value))
    return text if len(text) <= MAX_FIELD else text[: MAX_FIELD - 1] + "…"


def dns_type(code) -> str:
    return DNS_TYPES.get(code, f"TYPE{code}")


def dns_answers_text(answers: list) -> str:
    parts = []
    for rr in answers:
        rtype = dns_type(rr.get("rtype"))
        if rr.get("address"):
            parts.append(f"{rtype} {safe(rr['address'])}")
        else:
            parts.append(rtype)  # A/AAAA 외 레코드 내용은 파서 범위 밖
    ttls = {rr.get("ttl") for rr in answers}
    if len(ttls) == 1:
        return ", ".join(parts) + f" (TTL {ttls.pop()})"
    return ", ".join(f"{p} (TTL {rr.get('ttl')})" for p, rr in zip(parts, answers))


def http_text(app: dict) -> str:
    if app.get("kind") == "request":
        text = f"HTTP 요청: {app.get('method')}"
        if app.get("target") is not None:
            text += f" {safe(app['target'])}"
        if app.get("version"):
            text += f" {app['version']}"
        if app.get("host"):
            text += f" (Host: {safe(app['host'])})"
    else:
        text = f"HTTP 응답: {app.get('status_code')}"
        if app.get("reason"):
            text += f" {safe(app['reason'])}"
    extras = []
    if app.get("content_type"):
        extras.append(safe(app["content_type"]))
    if app.get("content_length") is not None:
        extras.append(f"{safe(app['content_length'])}바이트")
    return text + (" · " + " · ".join(extras) if extras else "")


def dns_text(app: dict) -> str:
    tid = app.get("transaction_id")
    tid = f"0x{tid:04x}" if isinstance(tid, int) else str(tid)
    questions = app.get("questions") or []
    question = " ".join(
        f"{safe(q.get('name'))} {dns_type(q.get('qtype'))}" for q in questions
    )
    if app.get("kind") == "query":
        return f"DNS 질의 (ID {tid})" + (f" {question}" if question else "")
    text = f"DNS 응답 (ID {tid}, rcode {app.get('rcode')})"
    if question:
        text += f" {question}"
    answers = app.get("answers")
    if answers:
        text += " → " + dns_answers_text(answers)
    elif answers is not None:
        text += " → 답 없음"
    return text


def smtp_text(app: dict) -> str:
    if app.get("kind") == "command":
        command = app.get("command")
        text = f"SMTP 명령: {command}"
        if app.get("argument"):
            # MAIL FROM·RCPT TO는 원문처럼 콜론 뒤에 주소를 붙인다.
            sep = ":" if command in ("MAIL FROM", "RCPT TO") else " "
            text += f"{sep}{safe(app['argument'])}"
        return text
    text = f"SMTP 응답: {app.get('code')}"
    if app.get("text"):
        text += f" {safe(app['text'])}"
    return text


def app_text(app: dict) -> str:
    proto = app.get("protocol")
    if proto == "HTTP":
        return http_text(app)
    if proto == "DNS":
        return dns_text(app)
    if proto == "SMTP":
        return smtp_text(app)
    return safe(json.dumps(app, ensure_ascii=False))


class DnsMatcher:
    """같은 트랜잭션 ID와 클라이언트 주소로 DNS 응답을 앞선 질의 행과 짝짓는다."""

    def __init__(self) -> None:
        self.queries: dict[tuple, int] = {}

    def note(self, p: dict, no: int) -> str:
        app = p.get("application") or {}
        if app.get("protocol") != "DNS":
            return ""
        tid = app.get("transaction_id")
        if app.get("kind") == "query":
            self.queries[(tid, p["src_ip"], p["src_port"], p["dst_ip"])] = no
            return ""
        query_no = self.queries.pop((tid, p["dst_ip"], p["dst_port"], p["src_ip"]), None)
        return f" ← {query_no}번 질의의 응답" if query_no is not None else ""


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


def build_row(p: dict, no: int, tracker: TcpTracker, dns: DnsMatcher | None = None) -> list[str]:
    t = datetime.fromtimestamp(p["timestamp"], KST).strftime("%H:%M:%S.%f")[:-3]
    text = describe(p, tracker)
    if dns is not None:
        text += dns.note(p, no)
    return [
        str(no), t, "송신" if p["direction"] == "OUTGOING" else "수신",
        f"{p['src_ip']}:{p['src_port']}", "→", f"{p['dst_ip']}:{p['dst_port']}",
        "" if p.get("ttl") is None else str(p["ttl"]),
        layer(p), flag_text(p.get("tcp_flags")),
        "" if p.get("seq") is None else str(p["seq"]),
        "" if p.get("ack") is None else str(p["ack"]),
        text,
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
    dns = DnsMatcher()
    print(paint(format_row([c[0] for c in COLUMNS]), "1"), file=out)
    print("-" * RULE_WIDTH, file=out)
    sent = received = 0
    try:
        for no, p in enumerate(iter_packets(lines, show_all), start=1):
            values = build_row(p, no, tracker, dns)
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
    print("-" * RULE_WIDTH, file=out)
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
