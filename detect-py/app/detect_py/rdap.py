"""Domain age via RDAP (preferred over WHOIS per TECHNOLOGY.md §4).

On ANY failure: return no signal, never fail the request.
"""

import time
from datetime import UTC

import httpx

_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_CACHE: dict[str, str] = {}  # suffix -> base URL
_BOOTSTRAP_TS = 0.0
_TTL = 86400  # refresh bootstrap daily


async def _base_for(suffix: str, client: httpx.AsyncClient) -> str | None:
    global _BOOTSTRAP_TS
    now = time.monotonic()
    if not _CACHE or now - _BOOTSTRAP_TS > _TTL:
        try:
            r = await client.get(_RDAP_BOOTSTRAP_URL)
            r.raise_for_status()
            services = r.json().get("services", [])
            _CACHE.clear()
            for entry in services:
                bases, suffixes = entry[0], entry[1]
                if bases:
                    for s in suffixes:
                        _CACHE[s] = bases[0]
            _BOOTSTRAP_TS = now
        except Exception:
            return None
    return _CACHE.get(suffix)


async def domain_age_days(domain: str, timeout_s: float = 3.0) -> int | None:
    """Return age in days, or None on any failure (never raises)."""
    parts = domain.lower().rsplit(".", 1)
    if len(parts) != 2:
        return None
    base = await _base_for(parts[1], httpx.AsyncClient(timeout=timeout_s))
    if base is None:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
            r = await client.get(f"{base}domain/{domain}")
            if r.status_code != 200:
                return None
            events = r.json().get("events", [])
            reg = next(
                (e["eventDate"] for e in events if e.get("eventAction") == "registration"),
                None,
            )
            if not reg:
                return None
            from datetime import datetime

            ts = reg.replace("%(z)", "+00:00").replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return max(0, (datetime.now(UTC) - dt).days)
    except Exception:
        return None
