"""Heads-up notifications to a trusted family member ("guardian")."""

from __future__ import annotations

import logging
import smtplib
import urllib.request
from email.message import EmailMessage

from .config import Config
from .models import Message, Verdict

log = logging.getLogger(__name__)


def _summary(msg: Message, v: Verdict) -> tuple[str, str]:
    who = msg.sender_name or msg.sender or "unknown sender"
    title = f"ScamShield caught a likely scam ({msg.channel.value})"
    lines = [f"From: {who}"]
    if msg.subject:
        lines.append(f"Subject: {msg.subject}")
    lines.append("")
    lines += [f"- {r}" for r in v.reasons[:4]]
    lines += ["", "It was moved out of the way. You may want to check in and make sure they didn't respond."]
    return title, "\n".join(lines)


def notify_guardian(cfg: Config, msg: Message, v: Verdict) -> None:
    title, body = _summary(msg, v)
    if cfg.guardian_ntfy_topic:
        try:
            req = urllib.request.Request(
                f"{cfg.ntfy_server.rstrip('/')}/{cfg.guardian_ntfy_topic}",
                data=body.encode(),
                headers={"Title": title, "Tags": "warning", "Priority": "high"},
            )
            urllib.request.urlopen(req, timeout=10).close()
        except OSError as e:
            log.warning("ntfy alert failed: %s", e)
    if cfg.guardian_email and cfg.smtp_host:
        em = EmailMessage()
        em["Subject"], em["From"], em["To"] = title, cfg.smtp_username, cfg.guardian_email
        em.set_content(body)
        try:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=20) as s:
                s.starttls()
                s.login(cfg.smtp_username, cfg.smtp_password)
                s.send_message(em)
        except (OSError, smtplib.SMTPException) as e:
            log.warning("email alert failed: %s", e)
