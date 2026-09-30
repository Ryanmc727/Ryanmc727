import pytest

from scamshield.config import Config
from scamshield.email_guard import parse_email
from scamshield.engine import Engine
from scamshield.models import Channel, Level, Message


@pytest.fixture
def engine():
    return Engine(Config(ai_enabled=False, trusted_senders=["daughter@example.com", "+1 555 123 4567"]), ai=None)


def sms(body, sender="+15559998888"):
    return Message(Channel.SMS, body=body, sender=sender)


SCAMS = [
    "USPS: Your package is on hold due to an incomplete address. Update now: https://usps-redelivery.top/track",
    "Grandma it's me, I was in a car accident and I'm in jail. I need bail money, please don't tell mom. Can you get Google Play cards?",
    "This is the Social Security Administration. Your SSN has been suspended. Press 1 to avoid arrest. Payment by Bitcoin ATM.",
    "We sent you a verification code. Please reply with the 6-digit code to confirm your identity.",
    "Your computer is infected with a virus! Call Microsoft support at 1-888-555-0100 immediately. We will connect by AnyDesk.",
    "You have an unpaid toll balance of $6.99. Pay within 24 hours to avoid fees: https://ezpass-pay.xyz",
    "Congratulations! You've won the Publishers sweepstakes. Pay the $250 processing fee with a gift card to claim your prize.",
]

SAFE = [
    "Hi Mom, are we still on for dinner Sunday? I'll bring the pie.",
    "Your appointment with Dr. Patel is tomorrow at 10:30 AM. Reply C to confirm.",
    "Your order has shipped and will arrive Thursday. Thanks for shopping with us!",
    "Your Chase verification code is 482913. Don't share this code with anyone. We will never call to ask for it.",
]


@pytest.mark.parametrize("body", SCAMS)
def test_scams_flagged(engine, body):
    assert engine.check(sms(body)).level is Level.SCAM


@pytest.mark.parametrize("body", SAFE)
def test_safe_messages_pass(engine, body):
    assert engine.check(sms(body)).level is Level.SAFE


def test_trusted_sender_not_flagged_for_mild_stuff(engine):
    v = engine.check(sms("Call me back right away, urgent news about the house!", sender="(555) 123-4567"))
    assert v.level is Level.SAFE


def test_trusted_sender_still_flagged_for_gift_cards(engine):
    v = engine.check(Message(Channel.EMAIL, body="Can you buy 4 Apple gift cards and send me the codes? Don't tell anyone.",
                             sender="daughter@example.com"))
    assert v.level is Level.SCAM


def test_email_brand_spoof(engine):
    v = engine.check(Message(Channel.EMAIL, sender="security@chase-alerts.info", sender_name="Chase Bank",
                             subject="Your account is locked",
                             body="Verify your account details to restore access: http://chase-secure-verify.com/login"))
    assert v.level is Level.SCAM
    assert any("really came from" in r for r in v.reasons)


def test_real_brand_email_not_flagged(engine):
    v = engine.check(Message(Channel.EMAIL, sender="no-reply@paypal.com", sender_name="PayPal",
                             subject="Receipt for your payment", body="You sent $20.00 to Jane. View at https://www.paypal.com/activity"))
    assert v.level is Level.SAFE


def test_parse_html_email_keeps_link_targets():
    raw = (b"From: \"Amazon\" <alerts@amaz0n-billing.support>\r\nSubject: Problem with your order\r\n"
           b"Content-Type: text/html\r\n\r\n<p>Your order is on hold.</p><a href=\"http://amaz0n-billing.click/x\">View order</a>")
    msg = parse_email(raw)
    assert msg.sender_name == "Amazon"
    assert "amaz0n-billing.click" in msg.body


class FakeAI:
    def __init__(self, verdict, confidence=90):
        from scamshield.ai import AIVerdict
        self.v = AIVerdict(verdict=verdict, confidence=confidence, explanation="AI says so.", advice="Do the thing.")

    def check(self, msg, found):
        return self.v


def test_ai_escalates_gray_zone():
    eng = Engine(Config(ai_enabled=False), ai=FakeAI("scam"))
    v = eng.check(sms("Hi, this is Linda from the benefits office. Call me back about your account."))
    assert v.level is Level.SCAM and v.ai_used


def test_ai_cannot_clear_hard_red_flag():
    eng = Engine(Config(ai_enabled=False), ai=FakeAI("safe", 99))
    v = eng.check(sms("Please pay with gift cards today."))
    assert v.level is not Level.SAFE
