"""
Small, dependency-free implementations of the analytical algorithms used
to upgrade MailTrace's detection quality:

- levenshtein / typosquat_match: edit-distance brand-impersonation
  detection, replacing a hardcoded lookalike-spelling dictionary with a
  general algorithm that catches *any* close misspelling of a protected
  brand, not just the handful someone thought to enumerate.
- shannon_entropy: flags algorithmically-generated / randomized domains
  and paths (a classic DGA and phishing-kit-hosting signal).
- normalize_homoglyphs: collapses common look-alike character
  substitutions (0/o, 1/l/i, rn/m ...) before comparison, so
  "micr0soft" and "microsoft" are recognized as near-identical.
- haversine_km / implausible_travel: geometric "impossible travel"
  check across relay hops using real coordinates, instead of just
  eyeballing a map.
"""
import math
import re

# Brands most commonly impersonated in phishing/BEC; extend as needed.
PROTECTED_BRANDS = [
    'microsoft', 'office365', 'outlook', 'google', 'gmail', 'apple', 'icloud',
    'paypal', 'amazon', 'netflix', 'dropbox', 'docusign', 'adobe', 'facebook',
    'instagram', 'linkedin', 'bankofamerica', 'wellsfargo', 'chase', 'coinbase',
]

_HOMOGLYPHS = str.maketrans({
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's',
})


def normalize_homoglyphs(s: str) -> str:
    s = s.lower().translate(_HOMOGLYPHS)
    s = s.replace('rn', 'm').replace('vv', 'w')
    return s


def levenshtein(a: str, b: str) -> int:
    """Classic O(n*m) edit distance, single-row DP (O(min(n,m)) memory)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def typosquat_match(domain: str, brands=None, max_distance_ratio=0.24):
    """
    Compare each hyphen/underscore/digit-delimited *token* of a domain's
    registrable label against a brand list using edit distance (both the
    raw token and its homoglyph-normalized form). Returns the closest
    match if a token is suspiciously close to — but not an exact,
    correctly-spelled instance of — a protected brand.

    Tokenizing (rather than comparing the whole label at once) is what
    lets this catch real-world compound phishing domains like
    "micr0soft-support.xyz" or "secure-paypaI-login.com", where the
    brand name is only one part of a hyphenated label; comparing the
    full label against the bare brand name would almost never be within
    a small edit distance once extra words are appended.

    Distance tolerance is scaled by brand length so short and long
    brands both get a sensible allowance (e.g. 1 edit on 'apple' is
    significant; 1 edit on 'docusign' is proportionally smaller).
    """
    brands = brands or PROTECTED_BRANDS
    labels = domain.lower().split('.')
    if len(labels) < 2:
        return None
    registrable_label = labels[-2]  # e.g. "micr0soft-support.xyz" -> "micr0soft-support"
    tokens = [t for t in re.split(r'[^a-z0-9]+', registrable_label) if t]
    best = None
    for token in tokens:
        norm_token = normalize_homoglyphs(token)
        for brand in brands:
            if token == brand:
                continue  # correctly-spelled brand token — not a spelling trick
            dist_raw = levenshtein(token, brand)
            dist_norm = levenshtein(norm_token, brand)
            dist = min(dist_raw, dist_norm)
            tolerance = max(1, math.ceil(len(brand) * max_distance_ratio))
            if dist <= tolerance:
                if best is None or dist < best['distance']:
                    via_homoglyph = dist_norm < dist_raw
                    best = {'brand': brand, 'distance': dist, 'compared': token, 'via_homoglyph': via_homoglyph}
    return best


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character; random/DGA strings score high (>3.8),
    natural-language words score low (~2.5-3.2)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# A generous ceiling: fastest commercial flights + margin. Anything that
# would require exceeding this speed between two relay hops is not
# physically consistent with a single mail server relaying in sequence
# within the observed time window (accounting for missing/garbled hops,
# this is intentionally conservative rather than a hard "impossible").
MAX_PLAUSIBLE_KMH = 1200


def implausible_travel(hops_with_geo):
    """
    hops_with_geo: ordered list of dicts with 'lat','lon','minutes_since_prev'
    (minutes_since_prev may be None if timestamps couldn't be parsed).
    Returns list of flagged hop-pairs with computed speed.
    """
    flags = []
    for prev, cur in zip(hops_with_geo, hops_with_geo[1:]):
        if None in (prev.get('lat'), prev.get('lon'), cur.get('lat'), cur.get('lon')):
            continue
        minutes = cur.get('minutes_since_prev')
        if not minutes or minutes <= 0:
            continue
        dist = haversine_km(prev['lat'], prev['lon'], cur['lat'], cur['lon'])
        speed_kmh = dist / (minutes / 60.0)
        if speed_kmh > MAX_PLAUSIBLE_KMH:
            flags.append({
                'from_ip': prev.get('ip'), 'to_ip': cur.get('ip'),
                'distance_km': round(dist, 1), 'minutes': round(minutes, 1),
                'implied_speed_kmh': round(speed_kmh, 1),
            })
    return flags
