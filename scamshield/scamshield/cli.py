from __future__ import annotations

import argparse
import logging
import sys

from . import config as config_mod
from .engine import Engine
from .models import Channel, Message


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scamshield")
    p.add_argument("--config", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check one message (reads stdin if no text given)")
    c.add_argument("text", nargs="?")
    c.add_argument("--channel", choices=[ch.value for ch in Channel], default="sms")
    c.add_argument("--sender", default="")
    c.add_argument("--subject", default="")
    sub.add_parser("email-guard", help="watch configured inboxes forever")
    s = sub.add_parser("serve", help="run the web page + API")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = config_mod.load(args.config)

    if args.cmd == "check":
        text = args.text if args.text is not None else sys.stdin.read()
        v = Engine(cfg).check(Message(Channel(args.channel), body=text, sender=args.sender, subject=args.subject))
        print(f"{v.level.value.upper()} ({v.score}) - {v.headline}\n{v.advice}")
        for r in v.reasons:
            print(f"  - {r}")
        return 0
    if args.cmd == "email-guard":
        from .email_guard import run_forever
        run_forever(cfg)
    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("scamshield.api:app", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
