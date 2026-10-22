"""URL feature extraction: shortener, punycode/IDN, IP host, suspicious TLD, typosquat.

Uses tldextract + rapidfuzz per TECHNOLOGY.md §4. Never fetches URLs.
"""

import ipaddress
import re
from urllib.parse import urlparse

import rapidfuzz
import tldextract

_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "shorturl.at",
    "rb.ge",
    "isg.to",
    "cutt.ly",
}

# Brand list for typosquat detection. Extend via config; keep in sync with app assets.
_BRANDS = [
    "paytm",
    "amazon",
    "flipkart",
    "sbi",
    "hdfc",
    "icici",
    "kotak",
    "axis",
    "upi",
    "whatsapp",
]

_SUSPICIOUS_TLDS = {"xyz", "top", "icu", "click", "link", "rest", "shop"}

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    return _URL_RE.findall(text)


def url_signals(text: str) -> list[tuple[str, str]]:
    """Return (signal_type, detail) pairs for all URLs found in text."""
    out: list[tuple[str, str]] = []
    for url in extract_urls(text):
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            out.append(("ip_host", host))
        except ValueError:
            pass
        if host in _SHORTENERS:
            out.append(("url_shortener", host))
        ext = tldextract.extract(host)
        if ext.suffix in _SUSPICIOUS_TLDS:
            out.append(("suspicious_tld", f".{ext.suffix}"))
        try:
            host.encode("ascii")
        except UnicodeEncodeError:
            out.append(("non_ascii_domain", host))
        if host.startswith("xn--") or ".xn--" in host:
            out.append(("punycode", host))
        domain = ext.domain
        if domain:
            for brand in _BRANDS:
                if domain != brand:
                    ratio = rapidfuzz.fuzz.ratio(domain, brand)
                    if 70 <= ratio < 100 and len(domain) >= 3:
                        out.append(("typosquat", f"{domain} ~ {brand} ({ratio:.0f})"))
                        break
    return out
