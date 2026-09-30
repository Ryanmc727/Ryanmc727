from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class EmailAccount:
    host: str
    username: str
    password: str  # app password, never the real account password
    port: int = 993
    folder: str = "INBOX"
    quarantine_folder: str = "ScamShield Quarantine"


@dataclass
class Config:
    # People the user trusts. Messages from these never get flagged unless they
    # ask for money or codes (accounts get hacked).
    trusted_senders: list[str] = field(default_factory=list)
    # Family member / helper who gets a heads-up when a scam is caught.
    guardian_ntfy_topic: str = ""
    ntfy_server: str = "https://ntfy.sh"
    guardian_email: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    # AI second opinion. Off automatically when no API key is present.
    ai_enabled: bool = True
    ai_model: str = "claude-opus-5-5"
    email_accounts: list[EmailAccount] = field(default_factory=list)
    poll_seconds: int = 120
    api_token: str = ""  # shared secret for phone/shortcut calls to /api/check


def load(path: str | os.PathLike | None = None) -> Config:
    path = Path(path or os.environ.get("SCAMSHIELD_CONFIG", "config.yaml"))
    raw: dict = (yaml.safe_load(path.read_text()) or {}) if path.exists() else {}
    accounts = [EmailAccount(**a) for a in raw.pop("email_accounts", []) or []]
    cfg = Config(**raw, email_accounts=accounts)
    cfg.trusted_senders = [s.strip().lower() for s in cfg.trusted_senders]
    cfg.api_token = os.environ.get("SCAMSHIELD_API_TOKEN", cfg.api_token)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        cfg.ai_enabled = False
    return cfg
