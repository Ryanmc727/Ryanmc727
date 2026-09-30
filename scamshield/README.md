# ScamShield

Set-and-forget scam protection for email, texts, and calls, built for grandparents, parents, and anyone who
doesn't want to become a tech expert just to avoid getting robbed.

Businesses get Proofpoint, Mimecast, and security awareness training. Regular people get nothing. ScamShield
is the consumer version: a family member sets it up once, and after that it quietly works.

## What works today (v0.1)

| Piece | What it does |
|---|---|
| **Email guard** | Watches Gmail / Outlook / Yahoo / iCloud / AOL over IMAP with an app password. Scams get moved to a `ScamShield Quarantine` folder, sketchy ones get flagged, and a family member gets a push alert. Nothing gets installed on the person's device. |
| **"Is this a scam?" page** | Huge text and buttons. Paste anything and get a green / yellow / red answer in plain English. Bookmark it on their home screen. |
| **`/api/check`** | Hook it up to an iPhone Shortcuts automation or an Android SMS forwarder so texts get checked automatically (see `docs/PLAN.md`). |
| **Detection engine** | ~30 offline rules (gift cards, crypto, code requests, remote access, grandparent script, toll/package texts, brand look-alike links, spoofed senders) plus an optional Claude second opinion for the gray-zone stuff. Every verdict says *why* in words a 10-year-old gets. |
| **Guardian alerts** | Free push notifications through [ntfy](https://ntfy.sh), or email. |

## Quick start

```bash
cp config.example.yaml config.yaml   # fill in inbox + trusted contacts + ntfy topic
export ANTHROPIC_API_KEY=...          # optional, turns on the AI second opinion
docker compose up -d                  # web page on :8080 + email guard
```

Or without Docker:

```bash
pip install -e '.[dev]'
scamshield check "USPS: package on hold, update address at https://usps-redelivery.top"
scamshield serve          # http://localhost:8080
scamshield email-guard    # runs forever
pytest
```

## How a verdict gets made

1. **Rules** score the message (0–100). Anything asking for gift cards, crypto, wires, codes, your SSN, or remote access is a hard red flag.
2. **Trusted senders** (family, doctor) skip the soft rules, but the hard red flags still fire, because hacked accounts are a thing.
3. **Claude** (optional) weighs in on the gray zone. It can escalate a verdict, and it can step a soft one down a notch, but it can never clear a hard red flag.
4. The output is always **headline + what to do + why**, never a bare score.

See [`docs/PLAN.md`](docs/PLAN.md) for the product plan, the platform limits, and the roadmap.
