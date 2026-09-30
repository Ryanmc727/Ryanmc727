# ScamShield product plan

## Who it's for

- **The protected person:** 65+ or just not techy. They never open a settings screen. Their whole experience is:
  fewer scams show up, and when something sketchy does get through, they see a big red "this is a scam" with one
  sentence telling them what to do.
- **The guardian:** the adult kid or grandkid who sets it up and gets the heads-up. Honestly, *this* is the buyer.
  Make the product for them, and make the protected person's side feel like nothing at all.

## The platform reality check (read this before promising "installs and vets everything")

| Channel | iPhone | Android | Plan |
|---|---|---|---|
| **Email** | Can't read mail from an app | Same | **Server-side over IMAP (done)** or Gmail/Graph APIs. This is the easiest win and it works for every device. |
| **Texts** | Apps **cannot** read your texts. The only hooks are an *SMS Filter extension* (iOS sorts unknown senders into Junk using our verdict), which only covers unknown senders, and *Shortcuts automations*. | You can read SMS if you're the default SMS app or use a notification listener, but Google Play restricts SMS permissions hard. | iOS: Message Filter extension → `/api/check`. Android: notification-listener app → `/api/check`. |
| **Calls** | *Call Directory extension*: we can block or label numbers ahead of time, but we can't see calls live. | `CallScreeningService` can screen calls in real time. | Phase 2: conditional call forwarding to a Twilio number that answers unknown callers, asks who they are, transcribes, runs the transcript through `/api/check`, and only rings the person if it's legit. Works on **any** phone, landlines too. That's the killer feature for this crowd. |

Big picture: no app can "just install and vet everything" on an iPhone. Apple won't let it. The set-and-forget
version runs **in the cloud** (email via IMAP/API, calls via carrier forwarding) plus thin phone extensions. Build
it that way on purpose instead of fighting the OS.

## Roadmap

**Phase 0 (this repo):** detection engine, IMAP email guard, web checker, guardian alerts, Docker. Self-hostable, so you can dogfood it on your own family.

**Phase 1: make it real for 10 families**
- Hosted multi-tenant backend (Postgres, per-family accounts, encrypted creds)
- Gmail API + Microsoft Graph OAuth ("Sign in with Google" beats app passwords for grandma). Heads up: Gmail's restricted scopes need Google's CASA security assessment, so budget time and money for it.
- Weekly "here's what we caught" email to the guardian (it's the retention hook, the proof the thing is working)
- iOS Message Filter extension + Android notification listener
- Reputation data: phone-number lookups (carrier/line type, spam reports), URL reputation (Google Safe Browsing, URLhaus), domain age

**Phase 2: calls**
- Twilio call screening line (answer, ask for name and reason, transcribe, check, ring through or send to voicemail)
- Voicemail transcripts checked and summarized
- "Family code word" prompt for voice-clone / grandparent calls

**Phase 3: go past filtering**
- "Pause before you pay": bank / card alerts for unusual gift-card or wire activity (Plaid, or bank partnerships)
- Caregiver dashboard for multiple parents
- Sell through AARP-style partners, Medicare Advantage plans, credit unions, and elder-law attorneys

## Business notes

- **Pricing:** ~$8–12/mo per protected person, paid by the guardian. Aura, Norton, and carrier add-ons are the competition, and they're built for identity theft rather than the scam conversation itself. Being built for seniors *and* telling the family is the angle.
- **AI cost:** only gray-zone messages hit the model, at low effort. That's roughly a fraction of a cent to a cent per message checked, so a heavy month still comes in under $1 per user. Pull `ai_model` down to a cheaper model if margins get tight, and measure accuracy before and after.
- **Privacy is the product:** you're reading grandma's email. Keep bodies only as long as needed to judge, publish a clear policy, and never train on their mail. One breach and the company is done.
- **False positives kill trust faster than misses.** A quarantined pharmacy refill reminder means a call to the kid. That's why there's a trusted-sender list, why quarantine moves mail instead of deleting it, and why the guardian can release it.
