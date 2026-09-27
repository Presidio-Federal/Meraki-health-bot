#!/usr/bin/env python3
"""Minimal GET-only Meraki Dashboard API v1 client.

- Key lookup order: env MERAKI_API_KEY, then the box secrets file
  (/home/box/agent-data/box-secrets.json) at top level or under "card".
- Never prints, logs, or writes the key.
- Rate limited to <= 4 req/s; honors 429 Retry-After.
- Only GET is implemented. There is no code path for PUT/POST/DELETE.
"""
import json, os, re, time, urllib.request, urllib.error, urllib.parse

BASE = os.environ.get("MERAKI_BASE_URL", "https://api.meraki.com/api/v1").rstrip("/")
SECRETS_FILE = os.environ.get("MERAKI_SECRETS_FILE", "/home/box/agent-data/box-secrets.json")
MIN_INTERVAL = 0.25  # seconds between requests (4 req/s, under Meraki's 10 req/s/org limit)


class MissingKey(Exception):
    pass


class AuthError(Exception):
    pass


def _load_key():
    k = os.environ.get("MERAKI_API_KEY", "").strip()
    if k:
        return k
    try:
        with open(SECRETS_FILE) as f:
            d = json.load(f)
        k = (d.get("MERAKI_API_KEY") or (d.get("card") or {}).get("MERAKI_API_KEY") or "").strip()
    except (OSError, ValueError, AttributeError):
        k = ""
    if not k:
        raise MissingKey("MERAKI_API_KEY not found in environment or box secrets file")
    return k


_KEY = None
_last = [0.0]


def key_available():
    try:
        _get_key()
        return True
    except MissingKey:
        return False


def _get_key():
    global _KEY
    if _KEY is None:
        _KEY = _load_key()
    return _KEY


def get(path, params=None, allpages=False, max_pages=50):
    """GET a Dashboard API path. Returns parsed JSON, or {"_error": code, "_msg": text}
    on a non-auth error. Raises AuthError on 401/403 and MissingKey if there is no key."""
    key = _get_key()
    url = BASE + path + (("?" + urllib.parse.urlencode(params, doseq=True)) if params else "")
    out, tries, pages = [], 0, 0
    while url:
        wait = MIN_INTERVAL - (time.time() - _last[0])
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.time()
        req = urllib.request.Request(url, method="GET", headers={
            "Authorization": "Bearer " + key,
            "Accept": "application/json",
            "User-Agent": "MerakiHealthBot/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read().decode() or "null"
                data = json.loads(body)
                link = r.headers.get("Link", "") or ""
        except urllib.error.HTTPError as e:
            if e.code == 429 and tries < 6:
                tries += 1
                time.sleep(float(e.headers.get("Retry-After", "2") or 2))
                continue
            try:
                msg = e.read().decode()[:400]
            except Exception:
                msg = ""
            # 401 = bad key. 403 on the org list/org itself = no access. Other 403s can be
            # feature-specific (e.g. a product not licensed), so they are returned as skips.
            if e.code == 401 or (e.code == 403 and re.fullmatch(r"/organizations(/[^/]+)?", path)):
                raise AuthError(f"HTTP {e.code} on GET {path}: {msg[:200].strip()}")
            return {"_error": e.code, "_msg": msg}
        except Exception as e:  # network error / timeout
            return {"_error": "exception", "_msg": str(e)[:300]}
        tries = 0
        if not allpages:
            return data
        if not isinstance(data, list):
            return data
        out.extend(data)
        pages += 1
        m = re.search(r'<([^>]+)>;\s*rel=next', link)
        url = m.group(1) if (m and pages < max_pages) else None
    return out


def ok(d):
    return not (isinstance(d, dict) and "_error" in d)
