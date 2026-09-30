"""Combines rule signals and the optional AI opinion into one plain-English verdict."""

from __future__ import annotations

import re

from . import rules
from .ai import AIChecker
from .config import Config
from .models import Level, Message, Signal, Verdict

SCAM_AT = 60
SUSPICIOUS_AT = 25
# Signals that stay serious even from a trusted sender (their account may be hacked).
ALWAYS_SERIOUS = {"pay_gift_card", "pay_crypto", "pay_wire", "ask_code", "ask_ssn", "remote_access", "secrecy"}

HEADLINES = {
    Level.SAFE: "This looks safe.",
    Level.SUSPICIOUS: "Be careful with this one.",
    Level.SCAM: "This is very likely a scam.",
}
ADVICE = {
    Level.SAFE: "No warning signs found. As always, never share passwords or codes.",
    Level.SUSPICIOUS: "Don't click links or call numbers in it. If it's about an account, call the company using the number on your card or statement.",
    Level.SCAM: "Don't reply, click, or call back. Delete it. If you already responded, call a family member or your bank right away.",
}


def _normalize_sender(s: str) -> str:
    s = s.strip().lower()
    return re.sub(r"\D", "", s)[-10:] if "@" not in s else s.strip("<>")


def _is_trusted(msg: Message, cfg: Config) -> bool:
    if not msg.sender:
        return False
    me = _normalize_sender(msg.sender)
    return any(_normalize_sender(t) == me for t in cfg.trusted_senders if t)


def _level(score: int) -> Level:
    if score >= SCAM_AT:
        return Level.SCAM
    if score >= SUSPICIOUS_AT:
        return Level.SUSPICIOUS
    return Level.SAFE


class Engine:
    def __init__(self, cfg: Config, ai: AIChecker | None = None):
        self.cfg = cfg
        self.ai = ai if ai is not None else (AIChecker(cfg.ai_model) if cfg.ai_enabled else None)

    def check(self, msg: Message) -> Verdict:
        signals: list[Signal] = rules.all_signals(msg)
        if _is_trusted(msg, self.cfg):
            signals = [s for s in signals if s.code in ALWAYS_SERIOUS]
        score = min(100, sum(s.weight for s in signals))
        level = _level(score)
        verdict = Verdict(
            level=level,
            score=score,
            headline=HEADLINES[level],
            advice=ADVICE[level],
            reasons=[s.reason for s in sorted(signals, key=lambda s: -s.weight)],
            signals=signals,
        )

        # Rules are confident at the extremes; ask the AI about the gray zone and
        # about anything with a link or sender we couldn't pin down.
        gray = 0 < score < 80 or (score == 0 and len(msg.body) > 40 and not _is_trusted(msg, self.cfg))
        if self.ai and gray:
            opinion = self.ai.check(msg, verdict.reasons)
            if opinion:
                verdict = self._merge(verdict, opinion)
        return verdict

    @staticmethod
    def _merge(v: Verdict, opinion) -> Verdict:
        ai_level = Level(opinion.verdict)
        hard = any(s.code in ALWAYS_SERIOUS for s in v.signals)
        order = [Level.SAFE, Level.SUSPICIOUS, Level.SCAM]
        if order.index(ai_level) > order.index(v.level):
            # AI sees something the rules missed: escalate.
            level = ai_level if opinion.confidence >= 70 else order[order.index(v.level) + 1]
        elif order.index(ai_level) < order.index(v.level) and not hard and opinion.confidence >= 85:
            # AI is confident it's fine and no hard red flag fired: step down one notch.
            level = order[order.index(v.level) - 1]
        else:
            level = v.level
        reasons = v.reasons if level is Level.SAFE and ai_level is Level.SAFE else [opinion.explanation, *v.reasons]
        return Verdict(
            level=level,
            score=v.score,
            headline=HEADLINES[level],
            advice=opinion.advice if ai_level is level else ADVICE[level],
            reasons=reasons,
            signals=v.signals,
            ai_used=True,
        )
