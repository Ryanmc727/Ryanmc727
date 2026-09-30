"""Watches IMAP inboxes and moves scams to a quarantine folder. Set and forget.

Works with Gmail, Outlook, Yahoo, iCloud, AOL, etc. using an app password, so
nothing needs to be installed on grandma's phone or computer: her mail app just
stops showing the scams.
"""

from __future__ import annotations

import email
import html
import imaplib
import json
import logging
import re
import time
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import parseaddr
from pathlib import Path

from .alerts import notify_guardian
from .config import Config, EmailAccount
from .engine import Engine
from .models import Channel, Level, Message

log = logging.getLogger(__name__)
STATE = Path("state/email_state.json")


def _text_of(em: EmailMessage) -> str:
    part = em.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    text = part.get_content()
    if part.get_content_type() == "text/html":
        # Keep hrefs visible so link checks still see where buttons really go.
        text = re.sub(r"(?is)<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", r"\2 (\1)", text)
        text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return re.sub(r"\s+", " ", text).strip()


def parse_email(raw: bytes) -> Message:
    em = email.message_from_bytes(raw, policy=default_policy)
    name, addr = parseaddr(str(em.get("From", "")))
    _, reply = parseaddr(str(em.get("Reply-To", "")))
    return Message(
        channel=Channel.EMAIL,
        body=_text_of(em),
        sender=addr,
        sender_name=name,
        subject=str(em.get("Subject", "")),
        reply_to=reply,
    )


def _load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def _save_state(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state))


def _move(conn: imaplib.IMAP4_SSL, uid: bytes, folder: str) -> None:
    conn.create(f'"{folder}"')  # harmless error if it already exists
    typ, _ = conn.uid("MOVE", uid, f'"{folder}"')
    if typ != "OK":  # servers without MOVE
        conn.uid("COPY", uid, f'"{folder}"')
        conn.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
        conn.expunge()


def scan_account(acct: EmailAccount, engine: Engine, cfg: Config, state: dict) -> None:
    key = f"{acct.username}@{acct.host}/{acct.folder}"
    with imaplib.IMAP4_SSL(acct.host, acct.port) as conn:
        conn.login(acct.username, acct.password)
        conn.select(f'"{acct.folder}"')
        validity = conn.response("UIDVALIDITY")[1][0].decode()
        seen = state.get(key, {})
        if seen.get("validity") != validity:
            # First run (or mailbox reset): only look at the last day, don't re-judge years of mail.
            since = time.strftime("%d-%b-%Y", time.gmtime(time.time() - 86400))
            _, data = conn.uid("SEARCH", None, "SINCE", since)
        else:
            _, data = conn.uid("SEARCH", None, "UID", f"{seen['last_uid'] + 1}:*")
        uids = [u for u in data[0].split() if int(u) > seen.get("last_uid", 0)] if data and data[0] else []
        last = seen.get("last_uid", 0)
        for uid in uids:
            _, parts = conn.uid("FETCH", uid, "(BODY.PEEK[])")  # PEEK: don't mark as read
            raw = next((p[1] for p in parts if isinstance(p, tuple)), None)
            if raw:
                msg = parse_email(raw)
                v = engine.check(msg)
                log.info("%s | %s | %s", v.level.value, msg.sender, msg.subject[:60])
                if v.level is Level.SCAM:
                    _move(conn, uid, acct.quarantine_folder)
                    notify_guardian(cfg, msg, v)
                elif v.level is Level.SUSPICIOUS:
                    conn.uid("STORE", uid, "+FLAGS", r"(\Flagged)")
            last = max(last, int(uid))
        state[key] = {"validity": validity, "last_uid": last}


def run_forever(cfg: Config) -> None:
    engine = Engine(cfg)
    state = _load_state()
    log.info("Email guard watching %d account(s)", len(cfg.email_accounts))
    while True:
        for acct in cfg.email_accounts:
            try:
                scan_account(acct, engine, cfg, state)
                _save_state(state)
            except (imaplib.IMAP4.error, OSError) as e:
                log.warning("Could not check %s: %s", acct.username, e)
        time.sleep(cfg.poll_seconds)
