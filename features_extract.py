import re
import math
from urllib.parse import urlparse
from collections import Counter

def calculate_entropy(text):
    """Shannon entropy"""
    if not text:
        return 0
    counts = Counter(text.lower())
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def extract_features(url):
    """Extract 30+ essential lexical features for URL threat detection"""
    
    # Ensure URL has scheme
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    full = url.lower()

    features = {}

    # BASIC LENGTH FEATURES
    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # DOMAIN LEVEL
    parts = domain.split(".")
    features["subdomain_count"] = len(parts) - 2 if len(parts) > 2 else 0
    features["tld"] = parts[-1] if len(parts) > 1 else "none"
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", domain) else 0

    # CHARACTER COUNTS
    features["dot_count"] = full.count(".")
    features["hyphen_count"] = full.count("-")
    features["slash_count"] = full.count("/")
    features["question_count"] = full.count("?")
    features["equal_count"] = full.count("=")
    features["percent_count"] = full.count("%")
    features["at_count"] = full.count("@")

    # RATIOS
    digits = sum(c.isdigit() for c in full)
    letters = sum(c.isalpha() for c in full)

    features["digit_ratio"] = digits / len(full)
    features["letter_ratio"] = letters / len(full)
    features["special_char_ratio"] = sum(not c.isalnum() for c in full) / len(full)

    # PATH DEPTH
    features["path_depth"] = len([p for p in path.split("/") if p])

    # ENTROPY
    features["url_entropy"] = calculate_entropy(full)
    features["domain_entropy"] = calculate_entropy(domain)

    # KEYWORDS
    keywords = [
        "login","secure","account","verify","update","confirm","bank","payment",
        "signin","free","click","credential","admin","ebay","amazon"
    ]
    features["keyword_hits"] = sum(k in full for k in keywords)

    # SUSPICIOUS TLD
    bad_tlds = ["tk","ml","ga","cf","gq"]
    features["suspicious_tld"] = 1 if features["tld"] in bad_tlds else 0

    # EXTENSIONS
    features["has_php"] = int(".php" in full)
    features["has_html"] = int(".html" in full)
    features["has_exe"] = int(".exe" in full)

    # SHORTENER CHECK
    shorteners = ["bit.ly","t.co","tinyurl","goo.gl","ow.ly","is.gd","buff.ly"]
    features["is_shortened"] = int(any(s in full for s in shorteners))

    # HTTPS CHECK
    features["is_https"] = int(full.startswith("https"))

    return features
