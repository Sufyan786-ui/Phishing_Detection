import re
import socket
import logging
import os
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
import numpy as np
import xgboost as xgb

logger = logging.getLogger("URLFeatures")
URL_SCORE_VERSION = 3
ML_SCORE_WEIGHT = 0.80
HEURISTIC_SCORE_WEIGHT = 0.20

# List of keywords commonly used in phishing campaigns
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "account", "banking",
    "signin", "support",
    "service", "recover", "wallet", "crypto", "auth", "credential", "free",
    "pay", "farma", "digital", "card", "billing", "web", "online", "rewards", "claim"
}

BRAND_KEYWORDS = {
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "amaz0n": "amazon.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "info", "live", "support", 
    "vip", "work", "cc", "fit", "gq", "cf", "tk", "ml", "ga", 
    "country", "tokyo", "bid", "gdn", "stream", "tech", "download",
    "shop", "store", "app", "site", "click", "link", "pages"
}

FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "subdomain_count", "count_dot", "count_hyphen", "count_underscore",
    "count_slash", "count_question", "count_equal", "count_at", "count_percent",
    "is_https", "is_ip_address", "keyword_count", "is_suspicious_tld"
]

# Load pre-trained XGBoost model
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "detector", "url_classifier.json")

model = None
try:
    if os.path.exists(MODEL_PATH):
        model = xgb.XGBClassifier()
        model.load_model(MODEL_PATH)
        logger.info("XGBoost model loaded successfully from %s", MODEL_PATH)
    else:
        logger.warning("XGBoost model file not found at %s. Running with heuristic fallback.", MODEL_PATH)
except Exception as e:
    logger.error("Failed to load XGBoost model: %s. Falling back to heuristics.", e)
    model = None

def is_ip_address(domain: str) -> bool:
    """Checks if the domain is a raw IP address (IPv4 or IPv6)."""
    # Simple IPv4 check
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return True
    # IPv6 check
    try:
        socket.inet_pton(socket.AF_INET6, domain)
        return True
    except (socket.error, ValueError):
        return False

def get_domain_age_days(domain: str) -> int:
    """Queries WHOIS database to find domain age in days. Returns -1 if lookup fails."""
    try:
        # Perform WHOIS lookup
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if not creation_date:
            return -1
            
        # WHOIS can return list of dates or single date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not isinstance(creation_date, datetime):
            return -1
            
        # Coerce timezone-aware datetime to naive
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)
            
        age = (datetime.utcnow() - creation_date).days
        return max(0, age)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return -1

def extract_flat_features(url: str) -> list:
    """Extracts a flat list of numeric features for the ML model."""
    parsed_url = url
    if not url.startswith(("http://", "https://")):
        parsed_url = "http://" + url
        
    try:
        parsed = urlparse(parsed_url)
        extracted = tldextract.extract(parsed_url)
    except Exception:
        return [0] * len(FEATURE_NAMES)

    domain = extracted.registered_domain
    subdomain = extracted.subdomain
    fqdn = parsed.netloc
    tld = extracted.suffix.lower()

    # 1. Lengths
    url_len = len(url)
    domain_len = len(fqdn)
    path_len = len(parsed.path)
    query_len = len(parsed.query)

    # 2. Subdomains
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    # 3. Special characters
    count_dot = url.count(".")
    count_hyphen = url.count("-")
    count_underscore = url.count("_")
    count_slash = url.count("/")
    count_question = url.count("?")
    count_equal = url.count("=")
    count_at = url.count("@")
    count_percent = url.count("%")

    # 4. Flags
    is_https = 1 if parsed.scheme.lower() == "https" else 0
    uses_ip = 1 if is_ip_address(fqdn) else 0

    # 5. Keywords
    found_keywords_count = 0
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            found_keywords_count += 1
    for brand_kw, official_domain in BRAND_KEYWORDS.items():
        if brand_kw in url_lower and domain != official_domain:
            found_keywords_count += 1

    # 6. TLD
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    return [
        url_len, domain_len, path_len, query_len,
        subdomain_count, count_dot, count_hyphen, count_underscore,
        count_slash, count_question, count_equal, count_at, count_percent,
        is_https, uses_ip, found_keywords_count, is_suspicious_tld
    ]

def extract_url_features(url: str) -> dict:
    """Extracts lexical, structural and network features from a URL."""
    # Ensure scheme exists (default to http for parsing if none exists)
    parsed_url = url
    if not url.startswith(("http://", "https://")):
        parsed_url = "http://" + url
        
    try:
        parsed = urlparse(parsed_url)
        extracted = tldextract.extract(parsed_url)
    except Exception as e:
        logger.error("Failed to parse URL %s: %s", url, e)
        return {"error": "Invalid URL formatting"}

    domain = extracted.registered_domain
    subdomain = extracted.subdomain
    fqdn = parsed.netloc
    tld = extracted.suffix.lower()

    # Get flat features
    flat_features = extract_flat_features(url)

    # Extract human-readable details for database and logging
    url_len = flat_features[0]
    domain_len = flat_features[1]
    path_len = flat_features[2]
    query_len = flat_features[3]
    subdomain_count = flat_features[4]
    
    char_counts = {
        "count_dot": flat_features[5],
        "count_hyphen": flat_features[6],
        "count_underscore": flat_features[7],
        "count_slash": flat_features[8],
        "count_question": flat_features[9],
        "count_equal": flat_features[10],
        "count_at": flat_features[11],
        "count_percent": flat_features[12]
    }
    
    is_https = bool(flat_features[13])
    uses_ip = bool(flat_features[14])
    is_suspicious_tld = bool(flat_features[16])

    # Find suspicous keywords matched in the URL
    found_keywords = []
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            found_keywords.append(kw)
    for brand_kw, official_domain in BRAND_KEYWORDS.items():
        if brand_kw in url_lower and domain != official_domain:
            found_keywords.append(brand_kw)
            
    # WHOIS Domain Age (avoid querying raw IPs)
    domain_age = -1
    if domain and not uses_ip:
        domain_age = get_domain_age_days(domain)

    # Calculate Score
    url_feature_score = 0
    heuristic_score = 0
    raw_ml_score = None
    ml_used = False

    url_risk_points = 0

    # URL length > 75 is suspicious
    if url_len > 75:
        url_risk_points += 15
    elif url_len > 54:
        url_risk_points += 8

    # Subdomains depth > 2
    if subdomain_count > 2:
        url_risk_points += 15

    # Count dots > 3
    if char_counts["count_dot"] > 3:
        url_risk_points += 10

    # Hyphens are common in phishing domains
    if char_counts["count_hyphen"] > 1:
        url_risk_points += 10

    # IP address instead of domain is highly suspicious
    if uses_ip:
        url_risk_points += 35

    # Non-HTTPS
    if not is_https:
        url_risk_points += 20

    # Suspicious keywords in domain/path
    if found_keywords:
        url_risk_points += min(30, len(found_keywords) * 15)

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        url_risk_points += 15

    # New domain (< 30 days) or WHOIS missing
    if domain_age >= 0 and domain_age < 30:
        url_risk_points += 25
    elif domain_age == -1 and not uses_ip: # WHOIS failed/hidden
        url_risk_points += 10

    heuristic_score = min(100, url_risk_points)

    # Attempt XGBoost prediction
    if model is not None:
        try:
            features_array = np.array([flat_features])
            prob_phish = model.predict_proba(features_array)[0][1]
            raw_ml_score = int(round(prob_phish * 100))
            url_feature_score = int(round(
                (raw_ml_score * ML_SCORE_WEIGHT)
                + (heuristic_score * HEURISTIC_SCORE_WEIGHT)
            ))
            # The current model can be overconfident on short, well-known URLs.
            # Strong clean signals should prevent that confidence from becoming
            # a misleading high phishing-risk score.
            if (
                heuristic_score <= 10
                and domain_age >= 365
                and not found_keywords
                and not is_suspicious_tld
                and not uses_ip
            ):
                url_feature_score = min(url_feature_score, 20)
            elif heuristic_score <= 20 and raw_ml_score >= 95:
                url_feature_score = min(url_feature_score, 35)
            ml_used = True
            logger.info(
                "XGBoost URL classification score for %s: raw=%d/100 heuristic=%d/100 calibrated=%d/100",
                url,
                raw_ml_score,
                heuristic_score,
                url_feature_score
            )
        except Exception as e:
            logger.error("XGBoost classification failed: %s. Using heuristic backup.", e)

    # Heuristic fallback (if ML fails or isn't loaded)
    if not ml_used:
        url_feature_score = heuristic_score

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "query_length": query_len,
        "subdomain_count": subdomain_count,
        "char_counts": char_counts,
        "is_https": is_https,
        "is_ip_address": uses_ip,
        "found_keywords": found_keywords,
        "domain_age_days": domain_age,
        "is_suspicious_tld": is_suspicious_tld,
        "feature_score": url_feature_score,
        "heuristic_score": heuristic_score,
        "raw_ml_score": raw_ml_score,
        "ml_used": ml_used,
        "score_version": URL_SCORE_VERSION,
        "ml_weight": ML_SCORE_WEIGHT,
        "heuristic_weight": HEURISTIC_SCORE_WEIGHT
    }
