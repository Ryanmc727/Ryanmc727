"""Link and sender-domain checks. Pure functions, no network calls."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"')]+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|click|link|site|online|live|shop|co|us|io|me|cc|ru|cn)(?:/[^\s<>\"')]*)?)")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

# Cheap TLDs heavily abused by SMS/email phishing kits.
RISKY_TLDS = {"xyz", "top", "click", "link", "site", "online", "live", "shop", "icu", "cc", "buzz", "rest"}

# Brand -> the domains that brand actually sends from / links to.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amazonses.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "irs": {"irs.gov"},
    "medicare": {"medicare.gov", "cms.gov"},
    "ssa": {"ssa.gov"},
    "ezpass": {"e-zpassny.com", "ezpassnj.com", "e-zpassiag.com"},
    "geeksquad": {"geeksquad.com", "bestbuy.com"},
    "norton": {"norton.com"},
    "mcafee": {"mcafee.com"},
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def extract_urls(text: str) -> list[str]:
    return [m.group(1).rstrip(".,;:!?") for m in URL_RE.finditer(text or "")]


def host_of(url: str) -> str:
    if not re.match(r"(?i)^https?://", url):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def registrable_domain(host: str) -> str:
    """Good-enough eTLD+1 without pulling in the public suffix list."""
    parts = host.strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_of_email(addr: str) -> str:
    addr = (addr or "").strip().strip("<>").lower()
    return addr.rsplit("@", 1)[-1] if "@" in addr else ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# How a brand shows up in normal writing ("Wells Fargo", "E-ZPass", "Social Security").
BRAND_ALIASES: dict[str, str] = {
    "paypal": r"pay\s?pal", "amazon": r"amazon", "apple": r"apple(?:\s?id)?", "microsoft": r"microsoft",
    "netflix": r"netflix", "chase": r"chase(?:\s?bank)?", "wellsfargo": r"wells\s?fargo",
    "bankofamerica": r"bank\s?of\s?america", "usps": r"usps|postal\s?service", "fedex": r"fed\s?ex",
    "ups": r"ups", "irs": r"irs|internal\s?revenue", "medicare": r"medicare",
    "ssa": r"social\s?security", "ezpass": r"e-?z\s?pass", "geeksquad": r"geek\s?squad",
    "norton": r"norton", "mcafee": r"mcafee",
}


def brand_mentioned(text: str) -> str | None:
    for brand, pattern in BRAND_ALIASES.items():
        if re.search(rf"(?i)\b(?:{pattern})\b", text or ""):
            return brand
    return None


def impersonated_brand(host: str) -> str | None:
    """Return the brand a host is pretending to be, if it isn't really that brand.

    Catches paypal-secure-login.com, amaz0n.support, apple.com.verify-id.co, etc.
    """
    reg = registrable_domain(host)
    deleeted = host.translate(LEET)
    labels = set(re.split(r"[.-]", deleeted))
    for brand, real in BRANDS.items():
        if reg in real:
            return None
        # Whole-word match, or prefix for longer names ("chaseonline"), so that
        # groups.io / pineapple.com / purchase.com don't trip it.
        if brand in labels or (len(brand) >= 5 and any(lbl.startswith(brand) for lbl in labels)):
            return brand
    return None


def link_findings(url: str) -> list[tuple[str, int, str]]:
    host = host_of(url)
    if not host:
        return []
    out: list[tuple[str, int, str]] = []
    reg = registrable_domain(host)
    if reg in SHORTENERS:
        out.append(("link_shortener", 15, "It uses a shortened link that hides where it really goes."))
    if is_ip(host):
        out.append(("link_raw_ip", 30, "The link goes to a bare number address instead of a real website name."))
    if host.startswith("xn--") or ".xn--" in host:
        out.append(("link_punycode", 30, "The link uses look-alike characters to imitate a real website."))
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        out.append(("link_risky_tld", 15, f"The link goes to a '.{host.rsplit('.', 1)[-1]}' address, which scammers use a lot."))
    brand = impersonated_brand(host)
    if brand:
        out.append(("link_brand_lookalike", 40, f"The link pretends to be {brand.title()} but goes to '{reg}', which is not {brand.title()}."))
    return out
