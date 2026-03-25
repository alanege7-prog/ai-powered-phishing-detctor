"""
url_features.py
---------------
Extracts hand-crafted numerical features from a URL string.

Why hand-crafted features instead of raw text?
URLs don't tokenise well with TF-IDF (every URL is nearly unique), so we
extract specific red-flag signals that phishing researchers have identified
as reliable indicators.  These features are used both by the model and by
the explainability layer to tell the user *why* a URL looks suspicious.

References
----------
- "Phishing Websites Features" (UCI ML Repository)
- OWASP guidance on malicious URL patterns
"""

import re
from urllib.parse import urlparse


# Domains that are frequently spoofed in phishing campaigns
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"}

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "facebook", "instagram", "bank", "secure", "login", "verify",
    "account", "update", "confirm", "ebay", "dhl", "fedex",
]


def extract_url_features(url: str) -> dict:
    """
    Parse a URL and return a dictionary of numerical / boolean features.

    Parameters
    ----------
    url : str
        The raw URL string submitted by the user.

    Returns
    -------
    dict
        Feature name → value pairs.  All numeric features are ints or floats
        so they can be concatenated with the TF-IDF vector if needed in future.
    """

    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # ensure urlparse works correctly

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        domain = path = full = ""

    features = {
        # --- Length signals ---
        "url_length":          len(url),
        "domain_length":       len(domain),
        "path_length":         len(path),

        # --- Structural red flags ---
        "has_ip_address":      1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0,
        "has_at_symbol":       1 if "@" in url else 0,
        "double_slash_redirect": 1 if url.count("//") > 1 else 0,
        "hyphen_in_domain":    1 if "-" in domain else 0,
        "dot_count":           url.count("."),
        "subdomain_count":     max(0, domain.count(".") - 1),

        # --- Protocol ---
        "uses_https":          1 if parsed.scheme == "https" else 0,

        # --- Suspicious TLD ---
        "suspicious_tld":      1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0,

        # --- Brand impersonation ---
        "brand_in_domain":     1 if any(b in domain for b in BRAND_KEYWORDS) else 0,
        "brand_in_path":       1 if any(b in path   for b in BRAND_KEYWORDS) else 0,

        # --- Special character counts ---
        "num_special_chars":   len(re.findall(r"[!$%^&*()+=\[\]{};':|,.<>?]", full)),
        "num_digits_in_domain": sum(c.isdigit() for c in domain),

        # --- Query string ---
        "has_query_string":    1 if parsed.query else 0,
        "query_length":        len(parsed.query),
    }

    return features


def get_url_risk_flags(url: str) -> list[str]:
    """
    Return a human-readable list of specific reasons a URL looks suspicious.
    Used by the explainability layer in the API response.

    Parameters
    ----------
    url : str

    Returns
    -------
    list[str]
        Plain-English flag descriptions (empty list if no flags triggered).
    """

    feats = extract_url_features(url)
    flags = []

    if feats["has_ip_address"]:
        flags.append("URL uses a raw IP address instead of a domain name")
    if feats["has_at_symbol"]:
        flags.append("URL contains '@' symbol — browsers ignore everything before it")
    if feats["double_slash_redirect"]:
        flags.append("URL contains double-slash redirect pattern")
    if feats["suspicious_tld"]:
        flags.append("Domain uses a TLD commonly associated with phishing (.tk, .ml, etc.)")
    if feats["brand_in_domain"] or feats["brand_in_path"]:
        flags.append("URL contains a well-known brand name — possible impersonation")
    if feats["hyphen_in_domain"]:
        flags.append("Domain contains hyphens — common in lookalike domains")
    if feats["url_length"] > 75:
        flags.append(f"URL is unusually long ({feats['url_length']} characters)")
    if feats["subdomain_count"] > 2:
        flags.append(f"URL has {feats['subdomain_count']} subdomains — excessive nesting is a red flag")
    if not feats["uses_https"]:
        flags.append("URL uses HTTP (not HTTPS) — no encryption")
    if feats["num_special_chars"] > 5:
        flags.append("URL contains an unusual number of special characters")

    return flags


# ---------------------------------------------------------------------------
# Quick sanity check – run `python url_features.py` to verify
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=phishing",
        "http://192.168.1.1/paypal/login@verify",
        "http://amaz0n-secure-update.tk/account/confirm?id=abc123!!",
    ]
    for u in test_urls:
        print(f"\nURL   : {u}")
        print(f"Flags : {get_url_risk_flags(u)}")
