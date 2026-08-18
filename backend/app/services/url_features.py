import math
import re
from collections import Counter
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """Normalize a URL before feature extraction."""

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def has_ip_address(hostname: str) -> int:
    """Check whether hostname is an IPv4 address."""

    if not hostname:
        return 0

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return 1 if re.match(pattern, hostname) else 0


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def extract_url_features(url: str) -> dict:
    """
    Extract lexical and structural features from a URL.

    These features will later be used by the ML model.
    """

    normalized_url = normalize_url(url)

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_lower = normalized_url.lower()

    # -----------------------------
    # Basic features
    # -----------------------------

    url_length = len(normalized_url)

    domain_length = len(hostname)

    path_length = len(path)

    query_length = len(query)

    # -----------------------------
    # Character features
    # -----------------------------

    digit_count = sum(
        character.isdigit()
        for character in normalized_url
    )

    letter_count = sum(
        character.isalpha()
        for character in normalized_url
    )

    dot_count = normalized_url.count(".")

    hyphen_count = normalized_url.count("-")

    underscore_count = normalized_url.count("_")

    slash_count = normalized_url.count("/")

    question_mark_count = normalized_url.count("?")

    equal_count = normalized_url.count("=")

    ampersand_count = normalized_url.count("&")

    at_symbol_count = normalized_url.count("@")

    percent_count = normalized_url.count("%")

    # -----------------------------
    # Security features
    # -----------------------------

    has_https = 1 if parsed.scheme == "https" else 0

    has_http = 1 if parsed.scheme == "http" else 0

    has_ip = has_ip_address(hostname)

    has_port = 1 if parsed.port else 0

    has_at_symbol = 1 if "@" in normalized_url else 0

    has_double_slash = (
        1 if "//" in path else 0
    )

    # -----------------------------
    # Domain structure
    # -----------------------------

    if has_ip:
        subdomain_count = 0
        tld_length = 0
    else:
        subdomain_count = max(
            hostname.count(".") - 1,
            0,
        )

        tld = ""

        if "." in hostname:
            tld = hostname.split(".")[-1]

        tld_length = len(tld)

    # -----------------------------
    # Suspicious keywords
    # -----------------------------

    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "bank",
        "payment",
        "wallet",
        "security",
    ]

    suspicious_keyword_count = sum(
        1
        for keyword in suspicious_keywords
        if keyword in url_lower
    )

    # -----------------------------
    # Entropy
    # -----------------------------

    domain_entropy = calculate_entropy(hostname)

    # -----------------------------
    # Special character count
    # -----------------------------

    special_character_count = sum(
        1
        for character in normalized_url
        if not character.isalnum()
    )

    # -----------------------------
    # Final feature dictionary
    # -----------------------------

    features = {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,

        "digit_count": digit_count,
        "letter_count": letter_count,

        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "question_mark_count": question_mark_count,
        "equal_count": equal_count,
        "ampersand_count": ampersand_count,
        "at_symbol_count": at_symbol_count,
        "percent_count": percent_count,

        "has_https": has_https,
        "has_http": has_http,
        "has_ip": has_ip,
        "has_port": has_port,
        "has_at_symbol": has_at_symbol,
        "has_double_slash": has_double_slash,

        "subdomain_count": subdomain_count,
        "tld_length": tld_length,

        "suspicious_keyword_count": suspicious_keyword_count,

        "domain_entropy": domain_entropy,

        "special_character_count": special_character_count,
    }

    return features