"""Heuristic scam signals. Fast, offline, explainable.

Each rule is (code, weight, regex, plain-English reason). Reasons are written for
someone who is not technical: they're read aloud / shown in big text.
"""

from __future__ import annotations

import re

from . import urls
from .models import Channel, Message, Signal

Rule = tuple[str, int, str, str]

TEXT_RULES: list[Rule] = [
    # How they want to be paid: the single strongest tell.
    ("pay_gift_card", 45, r"\b(gift ?cards?|google play cards?|itunes cards?|apple cards?|steam cards?|target cards?)\b",
     "It asks for gift cards. Real companies and government offices never want gift cards."),
    ("pay_crypto", 40, r"\b(bitcoin|btc|crypto(currency)?|usdt|tether|bitcoin atm|coin ?atm)\b",
     "It mentions Bitcoin or crypto. Scammers use it because it can't be traced or refunded."),
    ("pay_wire", 30, r"\b(wire (the )?(money|funds|transfer)|western union|moneygram)\b",
     "It asks you to wire money, which is almost impossible to get back."),
    ("pay_p2p", 20, r"\b(zelle|venmo|cash ?app)\b.{0,60}\b(send|refund|verify|reverse|pay)\b",
     "It asks you to send money by Zelle, Venmo, or Cash App, which scammers love because there's no refund."),

    # Asking for secrets.
    ("ask_code", 60, r"\b(verification|security|one[- ]time|6[- ]digit|confirmation) code\b.{0,80}\b(send|tell|give|read|share|reply)\b|\b(send|tell|give|read|share|reply)\b.{0,80}\b(verification|security|one[- ]time|6[- ]digit) code\b",
     "It asks you to share a security code. That code is the key to your account. Never give it to anyone."),
    ("ask_ssn", 40, r"\b(social security (number|#)|ssn)\b.{0,60}\b(confirm|verify|provide|update|enter)\b|\b(confirm|verify|provide|update|enter)\b.{0,60}\b(social security (number|#)|ssn)\b",
     "It asks for your Social Security number."),
    ("ask_login", 30, r"\b(verify|confirm|update|validate|re-?enter)\b.{0,40}\b(password|login|account (details|information)|card (number|details)|banking (details|information)|pin)\b",
     "It asks you to confirm a password, PIN, or card number. Real companies don't ask this way."),
    ("remote_access", 45, r"\b(anydesk|teamviewer|any ?desk|ultraviewer|logmein|remote (access|desktop|support session)|screen ?share)\b",
     "It wants remote access to your computer. That lets a stranger control it."),

    # Pressure and fear.
    ("urgent", 15, r"\b(act now|immediately|urgent(ly)?|within (24|48) hours|today only|final (notice|warning)|last chance|expires? (today|soon)|right away)\b",
     "It rushes you. Scammers create panic so you don't stop to think."),
    ("threat", 25, r"\b(arrest(ed)?|warrant|lawsuit|legal action|police|deport(ed|ation)?|suspend(ed)?|locked|frozen|disabled|terminated|jail)\b",
     "It threatens you with arrest, a locked account, or legal trouble."),
    ("secrecy", 30, r"\b(don'?t tell (anyone|your (family|kids|bank))|keep (this|it) (secret|confidential|between us)|do not (discuss|tell))\b",
     "It tells you to keep it secret. Honest people don't ask you to hide things from family or your bank."),

    # Classic scripts.
    ("grandparent", 35, r"\b(grand(ma|pa|mother|father)|it'?s me|your grandson|your granddaughter)\b.{0,120}\b(jail|bail|accident|hospital|lawyer|trouble|arrested)\b",
     "It sounds like the 'grandchild in trouble' scam. Hang up and call your grandchild on their usual number."),
    ("new_number", 15, r"\b(new (phone|number)|lost my phone|this is my new number|changed my number)\b",
     "Someone says they have a 'new number'. Check by calling their old number first."),
    ("tech_support", 35, r"\b(virus|malware|infected|hacked|compromised)\b.{0,80}\b(call|contact|dial)\b",
     "It claims your computer or account is hacked and tells you to call. That's the tech-support scam."),
    ("prize", 30, r"\b(you('ve| have)? won|winner|lottery|sweepstakes|claim your (prize|reward)|selected to receive)\b",
     "It says you won something you never entered."),
    ("refund_overpay", 25, r"\b(refund|overpaid|overpayment|reimburs\w*)\b.{0,80}\b(send (back|the difference)|return the (extra|excess))\b",
     "It says you were 'overpaid' and must send money back. That's a common refund scam."),
    ("package", 20, r"\b(package|parcel|shipment|delivery)\b.{0,80}\b(held|on hold|failed|unable to deliver|redeliver|address (issue|incomplete))\b",
     "It says there's a problem with a package. Fake delivery texts are one of the most common scams."),
    ("toll", 25, r"\b(unpaid|outstanding) (toll|tolls|balance)\b",
     "It says you owe an unpaid toll. Fake toll texts are everywhere right now."),
    ("investment", 30, r"\b(guaranteed (returns?|profit)|double your money|risk[- ]free investment|trading platform|mining pool)\b",
     "It promises guaranteed profits. Real investments never guarantee returns."),
    ("callback", 10, r"\bcall (us|now|back|this number|the number below)\b",
     "It pushes you to call a number it gives you. Use the number on your card or statement instead."),
    ("gov_impersonation", 20, r"\b(irs|social security administration|ssa|medicare|internal revenue|department of (justice|treasury)|federal agent)\b",
     "It claims to be from the government. Agencies contact you by mail first and never demand payment by phone or text."),
]

COMPILED = [(code, w, re.compile(rx, re.I | re.S), reason) for code, w, rx, reason in TEXT_RULES]

# Real 2FA texts say "Your code is 123456. Don't share it" - that's the opposite of a scam.
SUPPRESS = {
    "ask_code": re.compile(r"\b(don'?t|do not|never|won'?t ever|will never) (share|give|tell)|\bwill never ask\b|\bnever ask (you )?for\b", re.I),
}


def text_signals(text: str) -> list[Signal]:
    text = text or ""
    return [
        Signal(code, w, reason)
        for code, w, rx, reason in COMPILED
        if rx.search(text) and not (code in SUPPRESS and SUPPRESS[code].search(text))
    ]


def link_signals(text: str) -> list[Signal]:
    seen: set[str] = set()
    out: list[Signal] = []
    for url in urls.extract_urls(text):
        for code, w, reason in urls.link_findings(url):
            if code not in seen:
                seen.add(code)
                out.append(Signal(code, w, reason))
    return out


def sender_signals(msg: Message) -> list[Signal]:
    out: list[Signal] = []
    if msg.channel is Channel.EMAIL:
        sender_dom = urls.domain_of_email(msg.sender)
        brand = urls.brand_mentioned(f"{msg.sender_name} {msg.subject}")
        if brand and sender_dom and urls.registrable_domain(sender_dom) not in urls.BRANDS[brand]:
            out.append(Signal("sender_brand_mismatch", 40,
                              f"It says it's from {brand.title()}, but it really came from '{sender_dom}'."))
        reply_dom = urls.domain_of_email(msg.reply_to)
        if reply_dom and sender_dom and urls.registrable_domain(reply_dom) != urls.registrable_domain(sender_dom):
            out.append(Signal("reply_to_mismatch", 20,
                              "Replies would go to a different address than the one it came from."))
        if sender_dom in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"} and brand:
            out.append(Signal("free_mail_brand", 25,
                              f"A company like {brand.title()} would not email you from a free {sender_dom} account."))
    if msg.channel is Channel.SMS:
        # Texts from email addresses or odd long numbers are a strong spam tell.
        if "@" in msg.sender:
            out.append(Signal("sms_from_email", 20, "This text came from an email address, not a phone number."))
        digits = re.sub(r"\D", "", msg.sender)
        if digits and not digits.startswith("1") and len(digits) > 11:
            out.append(Signal("sms_foreign_number", 15, "This text came from an overseas number."))
    return out


def all_signals(msg: Message) -> list[Signal]:
    text = "\n".join(p for p in (msg.subject, msg.body) if p)
    return text_signals(text) + link_signals(text) + sender_signals(msg)
