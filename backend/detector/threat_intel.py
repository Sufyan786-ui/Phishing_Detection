import requests
import logging
from backend import config

logger = logging.getLogger("ThreatIntel")

# Local lists of test domains for demo and verification without API keys
TEST_MALICIOUS_DOMAINS = {
    "testsafebrowsing.appspot.com",
    "phishtank-test.com",
    "phishing-test.com",
    "malicious-test.com",
    "login-verify-paypal.com",
    "verify-apple-secure.com",
    "netflix-login-update.com"
}

def query_google_safe_browsing(url: str) -> dict:
    """Queries the Google Safe Browsing API (v4). Returns status and details."""
    api_key = config.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        # Check simulation list
        for test_domain in TEST_MALICIOUS_DOMAINS:
            if test_domain in url:
                return {
                    "is_malicious": True,
                    "provider": "Google Safe Browsing (Simulated)",
                    "threat_type": "SOCIAL_ENGINEERING",
                    "details": "Simulated match: URL contains a domain registered in the test signature list."
                }
        return {
            "is_malicious": False,
            "provider": "Google Safe Browsing",
            "details": "API Key not configured. Simulated lookup returned Safe."
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishing-detector-app",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code == 200:
            res_data = response.json()
            if "matches" in res_data and len(res_data["matches"]) > 0:
                match = res_data["matches"][0]
                return {
                    "is_malicious": True,
                    "provider": "Google Safe Browsing",
                    "threat_type": match.get("threatType", "UNKNOWN"),
                    "details": f"Flagged as {match.get('threatType')} on platform {match.get('platformType')}."
                }
            return {"is_malicious": False, "provider": "Google Safe Browsing", "details": "No matches found. URL is clean."}
        else:
            logger.warning("Google Safe Browsing API returned status %d: %s", response.status_code, response.text)
            return {"is_malicious": False, "provider": "Google Safe Browsing (Error)", "details": f"API returned status {response.status_code}."}
    except Exception as e:
        logger.error("Google Safe Browsing request failed: %s", e)
        return {"is_malicious": False, "provider": "Google Safe Browsing (Error)", "details": f"Request failed: {str(e)}"}

def query_phishtank(url: str) -> dict:
    """Queries the PhishTank API. Returns status and details."""
    # PhishTank allows checking URLs via checkurl API
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    
    # Simulation check
    for test_domain in TEST_MALICIOUS_DOMAINS:
        if test_domain in url:
            return {
                "is_malicious": True,
                "provider": "PhishTank (Simulated)",
                "phish_detail_page": "https://www.phishtank.com/",
                "verified": True,
                "details": "Simulated match: Domain matches test signature list."
            }
            
    payload = {
        "url": url,
        "format": "json"
    }
    if config.PHISHTANK_API_KEY:
        payload["app_key"] = config.PHISHTANK_API_KEY
        
    try:
        # Send POST request
        headers = {"User-Agent": "phish-detector-app"}
        response = requests.post(endpoint, data=payload, headers=headers, timeout=5)
        
        if response.status_code == 200:
            res_data = response.json()
            # PhishTank returns meta info. Check if url is in the database.
            results = res_data.get("results", {})
            if results and results.get("in_database") is True:
                is_valid_phish = results.get("valid") is True
                return {
                    "is_malicious": is_valid_phish,
                    "provider": "PhishTank",
                    "phish_detail_page": results.get("phish_detail_page"),
                    "verified": results.get("verified") is True,
                    "details": "URL found in PhishTank database. " + ("Confirmed Phishing." if is_valid_phish else "Pending verification.")
                }
            return {"is_malicious": False, "provider": "PhishTank", "details": "URL not found in PhishTank database."}
        else:
            logger.warning("PhishTank API returned status %d: %s", response.status_code, response.text)
            return {"is_malicious": False, "provider": "PhishTank (Error)", "details": f"API returned status {response.status_code}."}
    except Exception as e:
        logger.error("PhishTank request failed: %s", e)
        return {"is_malicious": False, "provider": "PhishTank (Error)", "details": f"Request failed: {str(e)}"}

def check_threat_intel(url: str) -> dict:
    """Aggregates threat intelligence lookup results."""
    gsb_res = query_google_safe_browsing(url)
    pt_res = query_phishtank(url)
    
    is_flagged = gsb_res["is_malicious"] or pt_res["is_malicious"]
    
    # Scoring: 100 points if flagged by either API, 0 if clean
    threat_score = 100 if is_flagged else 0
    
    return {
        "google_safe_browsing": gsb_res,
        "phishtank": pt_res,
        "is_flagged": is_flagged,
        "feature_score": threat_score
    }
