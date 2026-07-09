"""
ThreatLens AI - Intelligent Feature Extractor
=============================================
Architecture:
  Layer 1 - Pre-check (Rule-Based Intelligence):
      Handles known-safe and known-malicious patterns
      with high confidence BEFORE touching the ML model.
      This prevents false positives on legitimate sites
      and catches obvious threats instantly.

  Layer 2 - ML Feature Extraction:
      Feeds the original 10 features the model was trained on.
      Only reached if Layer 1 doesn't make a confident decision.

Return values:
  extract_features(url) -> list[10 floats]  (standard path)
  pre_check(url)        -> dict | None      (fast path override)
"""

import re
from urllib.parse import urlparse, unquote

# ──────────────────────────────────────────────
# LAYER 1 — RULE-BASED INTELLIGENCE
# ──────────────────────────────────────────────

# Tier-1: Major trusted domains (will ALWAYS be benign regardless of path)
TRUSTED_DOMAINS = {
    # Search & Productivity
    "google.com", "gmail.com", "google.com.eg", "docs.google.com",
    "drive.google.com", "calendar.google.com", "meet.google.com",
    "outlook.com", "live.com", "hotmail.com", "office.com",
    "microsoft.com", "sharepoint.com", "onedrive.com", "teams.microsoft.com",

    # AI Platforms
    "claude.ai", "anthropic.com",
    "chatgpt.com", "openai.com", "chat.openai.com",
    "gemini.google.com", "bard.google.com",
    "copilot.microsoft.com", "bing.com",
    "perplexity.ai", "you.com", "poe.com",
    "huggingface.co", "colab.research.google.com",

    # Social & Communication
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "pinterest.com", "tumblr.com",
    "tiktok.com", "snapchat.com", "discord.com", "telegram.org",
    "whatsapp.com", "signal.org", "slack.com", "zoom.us",

    # Tech & Dev
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com", "npmjs.com", "pypi.org", "docker.com",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "heroku.com", "vercel.com", "netlify.com", "cloudflare.com",

    # Media & Entertainment
    "youtube.com", "youtu.be", "netflix.com", "spotify.com",
    "twitch.tv", "vimeo.com", "soundcloud.com", "flickr.com",
    "imgur.com", "giphy.com",

    # E-Commerce & Finance
    "amazon.com", "amazon.eg", "ebay.com", "etsy.com",
    "paypal.com", "stripe.com", "shopify.com",

    # News & Knowledge
    "wikipedia.org", "wikimedia.org", "britannica.com",
    "bbc.com", "cnn.com", "reuters.com", "techcrunch.com",
    "medium.com", "substack.com",

    # Security & Tools
    "virustotal.com", "shodan.io", "haveibeenpwned.com",
    "1password.com", "lastpass.com", "bitwarden.com",

    # Other Common
    "apple.com", "yahoo.com", "mozilla.org", "firefox.com",
    "adobe.com", "canva.com", "notion.so", "trello.com",
    "dropbox.com", "box.com", "figma.com",
}

# Tier-2: Suspicious TLDs — heavily used in phishing campaigns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom — #1 phishing TLDs
    ".xyz", ".top", ".click", ".link",
    ".work", ".party", ".loan", ".win",
    ".download", ".stream", ".science",
    ".date", ".faith", ".racing", ".review",
    ".cricket", ".accountant", ".trade",
    ".country", ".gdn", ".bid",
}

# Tier-3: Keywords strongly associated with phishing in domain names
# (only checked in the DOMAIN part, not the path)
PHISHING_DOMAIN_KEYWORDS = [
    "secure-login", "account-verify", "signin-confirm",
    "update-account", "verify-identity", "confirm-payment",
    "paypal-", "-paypal", "apple-id", "icloud-verify",
    "microsoft-", "-microsoft", "google-verify",
    "amazon-security", "netflix-billing",
    "bank-secure", "banking-verify",
]

# Tier-4: Data exfiltration / redirection patterns in full URL
MALICIOUS_URL_PATTERNS = [
    r"@.+\.",                         # user@domain trick: http://legit.com@evil.com
    r"//[^/]*//",                     # double slash after domain
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # raw IP address
    r"[a-z0-9]{30,}\.",               # extremely long random subdomain
    r"(\.php\?id=|\.asp\?|\.aspx\?).{0,20}(=|%3D).{10,}",  # SQLi-like params
]

# Tier-5: URL shorteners — unknown destination, treated as suspicious
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
    "t.co", "buff.ly", "rebrand.ly", "short.io",
    "cutt.ly", "rb.gy", "is.gd", "v.gd",
}


def _extract_domain_info(url: str):
    """Parse URL and return (base_domain, tld, full_domain, path)."""
    original = url.lower().strip()

    # Ensure parseable
    if not original.startswith(("http://", "https://")):
        original = "http://" + original

    try:
        parsed = urlparse(original)
        full_domain = parsed.netloc.replace("www.", "")
        path = parsed.path + ("?" + parsed.query if parsed.query else "")

        parts = full_domain.split(".")
        tld = "." + parts[-1] if len(parts) >= 2 else ""
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else full_domain

        return base_domain, tld, full_domain, path, original
    except Exception:
        return url, "", url, "", url


def pre_check(url: str):
    """
    Layer 1: Rule-based fast-path decision.

    Returns a dict with override result if confident, or None to
    fall through to the ML model.

    Return format:
        {
            "override": True,
            "prediction": "benign" | "phishing",
            "confidence": float,   # 0.0 - 1.0
            "reason": str
        }
    """
    base_domain, tld, full_domain, path, clean = _extract_domain_info(url)

    # ── CHECK 1: Trusted domain whitelist ─────────────────────────────
    # Walk up the domain hierarchy (handles subdomains like mail.google.com)
    domain_parts = full_domain.split(".")
    for i in range(len(domain_parts) - 1):
        candidate = ".".join(domain_parts[i:])
        if candidate in TRUSTED_DOMAINS:
            return {
                "override": True,
                "prediction": "benign",
                "confidence": 0.98,
                "reason": f"Trusted domain: {candidate}"
            }

    # ── CHECK 2: URL shortener ─────────────────────────────────────────
    if base_domain in URL_SHORTENERS or full_domain in URL_SHORTENERS:
        return {
            "override": True,
            "prediction": "phishing",
            "confidence": 0.75,
            "reason": "URL shortener — destination unknown"
        }

    # ── CHECK 3: Raw IP address used as host ───────────────────────────
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", full_domain):
        return {
            "override": True,
            "prediction": "phishing",
            "confidence": 0.92,
            "reason": "Raw IP address used as host — strong phishing indicator"
        }

    # ── CHECK 4: Suspicious TLD ────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        return {
            "override": True,
            "prediction": "phishing",
            "confidence": 0.85,
            "reason": f"High-risk TLD: {tld}"
        }

    # ── CHECK 5: Phishing keywords in domain ──────────────────────────
    for keyword in PHISHING_DOMAIN_KEYWORDS:
        if keyword in full_domain:
            return {
                "override": True,
                "prediction": "phishing",
                "confidence": 0.90,
                "reason": f"Phishing keyword in domain: '{keyword}'"
            }

    # ── CHECK 6: Malicious URL structural patterns ─────────────────────
    for pattern in MALICIOUS_URL_PATTERNS:
        if re.search(pattern, clean):
            return {
                "override": True,
                "prediction": "phishing",
                "confidence": 0.88,
                "reason": f"Malicious URL pattern detected"
            }

    # ── CHECK 7: Extreme URL length (300+ chars = almost always malicious)
    if len(url) > 300:
        return {
            "override": True,
            "prediction": "phishing",
            "confidence": 0.80,
            "reason": "Abnormally long URL (>300 chars)"
        }

    # ── CHECK 8: Too many subdomains (4+) — evasion technique ─────────
    subdomain_count = max(len(full_domain.split(".")) - 2, 0)
    if subdomain_count >= 4:
        return {
            "override": True,
            "prediction": "phishing",
            "confidence": 0.82,
            "reason": f"Excessive subdomains ({subdomain_count}) — evasion indicator"
        }

    # No confident override — let the ML model decide
    return None


# ──────────────────────────────────────────────
# LAYER 2 — ML FEATURE EXTRACTION
# (Same 10 features the model was trained on)
# ──────────────────────────────────────────────

def extract_features(url: str) -> list:
    """
    Extract the 10 numerical features the Random Forest model expects.
    This function is only called when pre_check() returns None.
    """
    original_url = url.lower()

    has_https = 1 if original_url.startswith("https://") else 0

    clean_url = original_url
    clean_url = clean_url.replace("http://", "")
    clean_url = clean_url.replace("https://", "")
    clean_url = clean_url.replace("www.", "")

    base_domain = clean_url.split("/")[0].split("?")[0]

    url_length        = len(clean_url)
    num_dots          = clean_url.count(".")
    num_digits        = sum(c.isdigit() for c in clean_url)
    num_hyphens       = clean_url.count("-")
    num_slashes       = clean_url.count("/")
    num_questionmarks = clean_url.count("?")
    num_equals        = clean_url.count("=")
    has_ip            = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", clean_url) else 0

    parts = base_domain.split(".")
    num_subdomains = max(len(parts) - 2, 0)

    return [
        url_length,
        num_dots,
        num_digits,
        num_hyphens,
        num_slashes,
        num_questionmarks,
        num_equals,
        has_ip,
        num_subdomains,
        has_https,
    ]