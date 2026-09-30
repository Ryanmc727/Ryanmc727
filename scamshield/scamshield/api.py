"""HTTP API + a dead-simple web page.

- The page: family bookmarks it on grandma's phone/tablet. Paste anything, get a
  big green / yellow / red answer.
- /api/check: for an iPhone Shortcut automation ("When I get a text, check it")
  or an Android SMS-forwarder app, so texts are vetted automatically.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import config as config_mod
from .alerts import notify_guardian
from .engine import Engine
from .models import Channel, Level, Message

app = FastAPI(title="ScamShield")
PAGE = Path(__file__).with_name("static").joinpath("index.html")


@lru_cache
def get_cfg():
    return config_mod.load()


@lru_cache
def get_engine() -> Engine:
    return Engine(get_cfg())


def require_token(
    x_scamshield_token: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> None:
    expected = get_cfg().api_token
    given = x_scamshield_token or token or ""
    if expected and not secrets.compare_digest(given, expected):
        raise HTTPException(status_code=401, detail="Bad or missing token")


class CheckIn(BaseModel):
    channel: Channel = Channel.SMS
    body: str = ""
    sender: str = ""
    sender_name: str = ""
    subject: str = ""
    alert_guardian: bool = True


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE.read_text()


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/api/check", dependencies=[Depends(require_token)])
def check(inp: CheckIn) -> dict:
    msg = Message(channel=inp.channel, body=inp.body, sender=inp.sender,
                  sender_name=inp.sender_name, subject=inp.subject)
    v = get_engine().check(msg)
    if v.level is Level.SCAM and inp.alert_guardian:
        notify_guardian(get_cfg(), msg, v)
    out = v.to_dict()
    # One line an iPhone Shortcut / Android app can drop straight into a notification.
    out["notification"] = f"{v.headline} {v.advice}"
    return out
