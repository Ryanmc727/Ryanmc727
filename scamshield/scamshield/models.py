from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Channel(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    CALL = "call"


class Level(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    SCAM = "scam"


@dataclass
class Message:
    channel: Channel
    body: str = ""
    sender: str = ""  # email address or phone number
    sender_name: str = ""  # display name ("Chase Bank")
    subject: str = ""
    reply_to: str = ""
    # For calls this can hold a voicemail transcript in `body`.


@dataclass
class Signal:
    code: str
    weight: int
    reason: str  # plain-English, shown to the user


@dataclass
class Verdict:
    level: Level
    score: int
    headline: str
    advice: str
    reasons: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    ai_used: bool = False

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "score": self.score,
            "headline": self.headline,
            "advice": self.advice,
            "reasons": self.reasons,
            "ai_used": self.ai_used,
        }
