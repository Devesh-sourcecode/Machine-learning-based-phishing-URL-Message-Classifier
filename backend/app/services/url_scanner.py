import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "signin",
    "bank",
]


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
}


def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent analysis.
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    path = parsed.path or ""

    normalized = f"{scheme}://{hostname}{path}"

    return normalized


def analyze_url(url: str) -> dict:
    """
    Perform basic rule-based phishing analysis.

    This is intentionally a baseline detector.
    The ML model will be integrated later.
    """

    normalized_url = normalize_url(url)

    parsed = urlparse(normalized_url)

    score = 0
    indicators = []

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # 1. HTTP instead of HTTPS
    if parsed.scheme == "http":
        score += 15
        indicators.append("URL does not use HTTPS")

    # 2. IP address instead of domain
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname):
        score += 30
        indicators.append("URL uses an IP address instead of a domain")

    # 3. Suspicious keywords
    url_lower = normalized_url.lower()

    found_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    if found_keywords:
        score += min(len(found_keywords) * 10, 30)
        indicators.append(
            f"Suspicious keywords detected: {', '.join(found_keywords)}"
        )

    # 4. URL length
    if len(normalized_url) > 100:
        score += 15
        indicators.append("Unusually long URL")

    # 5. Too many subdomains
    if hostname.count(".") >= 3:
        score += 10
        indicators.append("Unusually high number of subdomains")

    # 6. URL shortener
    if hostname in SHORTENER_DOMAINS:
        score += 20
        indicators.append("URL shortening service detected")

    # Keep score between 0 and 100
    score = min(score, 100)

    if score >= 60:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "normalized_url": normalized_url,
        "risk_score": score,
        "verdict": verdict,
        "detection_method": "rule_based",
        "indicators": indicators,
    }