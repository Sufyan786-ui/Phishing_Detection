import os
import re
import logging
import urllib.parse
from urllib.parse import urlparse
import requests
import tldextract
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainModel")

# Suspicious TLDs and Keywords lists
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "info", "live", "support", 
    "vip", "work", "cc", "fit", "gq", "cf", "tk", "ml", "ga", 
    "country", "tokyo", "bid", "gdn", "stream", "tech", "download",
    "shop", "store", "app", "site", "click", "link", "pages"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "account", "banking",
    "signin", "support",
    "service", "recover", "wallet", "crypto", "auth", "credential", "free",
    "pay", "farma", "digital", "card", "billing", "web", "online"
}

BRAND_KEYWORDS = {
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
}

FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "subdomain_count", "count_dot", "count_hyphen", "count_underscore",
    "count_slash", "count_question", "count_equal", "count_at", "count_percent",
    "is_https", "is_ip_address", "keyword_count", "is_suspicious_tld"
]

def extract_flat_features(url: str) -> list:
    """Extracts a flat list of numeric features for the ML model."""
    if not isinstance(url, str):
        url = ""
    # Standardize URL
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
    is_ip_address = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", fqdn) else 0

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
        is_https, is_ip_address, found_keywords_count, is_suspicious_tld
    ]

def train_model():
    """Main training routine. Loads dataset, extracts features, trains XGBoost, and saves the model."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # backend/
    csv_path = os.path.join(base_dir, "PhiUSIIL_Phishing_URL_Dataset.csv")
    model_path = os.path.join(base_dir, "detector", "url_classifier.json")

    urls = []
    labels = []

    # Case A: Local PhiUSIIL dataset CSV is present
    if os.path.exists(csv_path):
        logger.info("Local PhiUSIIL dataset CSV found at %s. Loading...", csv_path)
        try:
            # Load a subset to make training fast and prevent out-of-memory errors
            df = pd.read_csv(csv_path, usecols=["URL", "label"])
            logger.info("Loaded %d rows from CSV. Sampling for balanced training...", len(df))
            
            # Extract phishing (label 0 in PhiUSIIL) and legitimate (label 1 in PhiUSIIL)
            phish_subset = df[df["label"] == 0].sample(n=15000, random_state=42, replace=True)
            legit_subset = df[df["label"] == 1].sample(n=15000, random_state=42, replace=True)
            
            # Invert label: our model predicts phishing = 1, legitimate = 0
            phish_subset["target"] = 1
            legit_subset["target"] = 0
            
            balanced_df = pd.concat([phish_subset, legit_subset]).sample(frac=1, random_state=42)
            urls = balanced_df["URL"].tolist()
            labels = balanced_df["target"].tolist()
            logger.info("Prepared balanced dataset of %d samples.", len(urls))
        except Exception as e:
            logger.error("Failed to load local CSV dataset: %s. Falling back to internet sources...", e)

    # Case B: Download dataset dynamically (URLhaus + Legitimate domains)
    if not urls:
        logger.info("Fetching malicious URLs from URLhaus...")
        try:
            r = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=10)
            if r.status_code == 200:
                # Find all URLs in URLhaus response (ignoring comments)
                malicious_urls = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
                # Sample 2,000 malicious URLs
                if len(malicious_urls) > 2000:
                    malicious_urls = malicious_urls[:2000]
                logger.info("Fetched %d malicious URLs from URLhaus.", len(malicious_urls))
            else:
                malicious_urls = []
        except Exception as e:
            logger.warning("Failed to fetch from URLhaus: %s", e)
            malicious_urls = []

        # Fetch/Compile Legitimate URLs
        logger.info("Compiling legitimate domains list...")
        legit_domains = [
            "google.com", "youtube.com", "facebook.com", "instagram.com", "wikipedia.org", 
            "amazon.com", "apple.com", "microsoft.com", "netflix.com", "yahoo.com", 
            "reddit.com", "twitter.com", "linkedin.com", "github.com", "stackoverflow.com",
            "cloudflare.com", "zoom.us", "tumblr.com", "vimeo.com", "pinterest.com",
            "medium.com", "salesforce.com", "imdb.com", "nytimes.com", "bbc.co.uk",
            "cnn.com", "forbes.com", "nih.gov", "cdc.gov", "nasa.gov", "mit.edu", "harvard.edu"
        ]
        
        # Expand legit list with subpages to generate realistic URLs
        legitimate_urls = []
        for d in legit_domains:
            legitimate_urls.append(f"https://{d}")
            legitimate_urls.append(f"https://www.{d}")
            legitimate_urls.append(f"https://{d}/about")
            legitimate_urls.append(f"https://{d}/contact")
            legitimate_urls.append(f"https://{d}/login")
            legitimate_urls.append(f"https://{d}/search?q=security")
            legitimate_urls.append(f"https://{d}/feed/posts")
            
        # Sample more if we have a top 1000 list available
        try:
            top_domains_r = requests.get("https://raw.githubusercontent.com/danielmiessler/top-domains/master/top-1000.txt", timeout=5)
            if top_domains_r.status_code == 200:
                additional_domains = [line.strip() for line in top_domains_r.text.splitlines() if line.strip()]
                for d in additional_domains[:500]:
                    legitimate_urls.append(f"https://{d}")
                    legitimate_urls.append(f"https://www.{d}")
                    legitimate_urls.append(f"https://{d}/home")
        except Exception as e:
            logger.warning("Failed to download additional top domains: %s", e)

        # Balance dataset
        min_size = min(len(malicious_urls), len(legitimate_urls))
        if min_size == 0:
            # Create a tiny mock fallback list in case of total offline failure
            logger.error("No URLs compiled. Creating tiny mock dataset.")
            malicious_urls = [
                "http://login-verify-paypal.com/update", "http://netflix-login-update.com",
                "http://verify-apple-secure.com", "http://elshadaydigital.online/farmapay",
                "http://danger-credential-harvester.net/collect.php"
            ]
            legitimate_urls = ["https://www.google.com", "https://www.paypal.com", "https://www.apple.com"]
            min_size = min(len(malicious_urls), len(legitimate_urls))

        urls = malicious_urls[:min_size] + legitimate_urls[:min_size]
        labels = [1] * min_size + [0] * min_size
        logger.info("Compiled dynamic dataset of %d samples (balanced).", len(urls))

    # Feature extraction
    logger.info("Extracting features from %d URLs...", len(urls))
    X_list = []
    for i, url in enumerate(urls):
        if i % 5000 == 0 and i > 0:
            logger.info("Processed %d URLs...", i)
        X_list.append(extract_flat_features(url))
        
    X = np.array(X_list)
    y = np.array(labels)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train XGBoost model
    logger.info("Training XGBoost classifier...")
    # Using parameters suitable for quick training and binary classification
    model = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42
    )
    model.fit(X_train, y_train)

    # Evaluate model
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    logger.info("Model training completed.")
    logger.info("Accuracy: %.4f", accuracy)
    logger.info("Classification Report:\n%s", classification_report(y_test, predictions, target_names=["Legitimate", "Phishing"]))

    # Save trained model to json
    model.save_model(model_path)
    logger.info("Saved model file to %s", model_path)

if __name__ == "__main__":
    train_model()
