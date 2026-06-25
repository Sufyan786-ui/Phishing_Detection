import logging
from backend import config

logger = logging.getLogger("ScoringEngine")

def calculate_confidence_score(
    url_res: dict, 
    threat_res: dict, 
    content_res: dict, 
    similarity_res: dict,
    final_score: int
) -> int:
    """
    Estimates a confidence percentage (45% - 98%) representing
    the system's certainty in its calculated risk verdict.
    """
    # If confirmed malicious by threat intel, certainty is near 100%
    if threat_res.get("is_flagged"):
        return 99

    confidence = 50  # Start with a base of 50%

    # 1. Data completeness signals
    if url_res.get("domain_age_days") != -1:
        confidence += 10  # We have active WHOIS age
    if content_res.get("status") == "success":
        confidence += 15  # We successfully fetched and parsed HTML

    # 2. ML classifier certainty
    if url_res.get("ml_used"):
        raw_ml = url_res.get("raw_ml_score", 50)
        # The closer raw_ml is to the extremes (0 or 100), the more certain the ML model is.
        certainty_margin = abs(raw_ml - 50)
        if certainty_margin >= 40:  # ML is highly certain (e.g. score <= 10 or >= 90)
            confidence += 18
        elif certainty_margin >= 25:  # ML is moderately certain (e.g. score 11-25 or 75-89)
            confidence += 10

    # 3. Consensus/impersonation signals
    if similarity_res.get("impersonation_detected"):
        confidence += 10  # Visual brand mismatch is a highly confident signal

    # 4. Score polarization booster
    if final_score >= 85 or final_score < 15:
        confidence += 5  # Polarized aggregate results are more statistically stable

    # Cap confidence between 45% and 98%
    return max(45, min(98, confidence))

def calculate_risk_score(
    url_res: dict, 
    threat_res: dict, 
    content_res: dict, 
    similarity_res: dict
) -> tuple[int, str, list[str], int]:
    """
    Aggregates module scores, applies critical risk overrides,
    and returns (final_score, verdict, list_of_warnings, confidence_score).

    Threat intelligence is authoritative only when it finds a match.
    A clean/not-found reputation lookup is not treated as evidence of safety,
    so it is excluded from normal weighted scoring.
    """
    url_score = url_res.get("feature_score", 0)
    content_score = content_res.get("feature_score", 0)
    threat_flagged = threat_res.get("is_flagged", False)

    warnings = []

    # Redirect chain penalty: +10 per redirect beyond 2
    redirect_count = content_res.get("redirect_count", 0)
    if redirect_count > 2:
        redirect_penalty = (redirect_count - 2) * 10
        content_score = min(100, content_score + redirect_penalty)

    if threat_flagged:
        if threat_res.get("google_safe_browsing", {}).get("is_malicious"):
            warnings.append("Google Safe Browsing has blacklisted this URL for social engineering or malware.")
        if threat_res.get("phishtank", {}).get("is_malicious"):
            warnings.append("PhishTank community database has confirmed this URL as an active phishing page.")
            
        # Add brand similarity and lexical warnings if they exist
        if similarity_res.get("impersonation_detected"):
            warnings.append(similarity_res.get("reason"))
        if url_res.get("is_ip_address"):
            warnings.append("URL uses a raw IP address instead of a domain name (common for temporary phishing hosting).")
        if not url_res.get("is_https"):
            warnings.append("Unsecured connection: Website does not use HTTPS (data sent in plaintext).")
        if url_res.get("found_keywords"):
            kws = ", ".join(f"'{k}'" for k in url_res["found_keywords"])
            warnings.append(f"Suspicious phishing-related keywords found in URL: {kws}.")
            
        return 100, "High Risk", warnings, 99

    # 1. Base Weighted Score Calculation for URLs not found in reputation databases.
    weighted_score = (
        (url_score * config.WEIGHT_URL_FEATURES) +
        (content_score * config.WEIGHT_CONTENT_ANALYSIS)
    )

    final_score = int(round(weighted_score))

    # 2. Risk Indicators and Warnings Extraction
    if url_res.get("is_ip_address"):
        warnings.append("URL uses a raw IP address instead of a domain name (common for temporary phishing hosting).")
    if not url_res.get("is_https"):
        warnings.append("Unsecured connection: Website does not use HTTPS (data sent in plaintext).")
    if url_res.get("found_keywords"):
        kws = ", ".join(f"'{k}'" for k in url_res["found_keywords"])
        warnings.append(f"Suspicious phishing-related keywords found in URL: {kws}.")
    if url_res.get("domain_age_days") != -1 and url_res.get("domain_age_days") < 30:
        warnings.append(f"Very young domain: registered only {url_res['domain_age_days']} days ago.")

    if redirect_count > 2:
        warnings.append(f"Deep redirect chain detected: {redirect_count} redirects followed. Phishing websites often redirect through multiple domains to evade detection.")

    if content_res.get("ssl_error"):
        warnings.append("SSL certificate verification failed (expired, self-signed, or hostname mismatch). Legitimate sites rarely have misconfigured SSL.")

    if content_res.get("status") == "success":
        if content_res.get("external_forms"):
            warnings.append("HTML forms post data to a completely different registered domain (credential harvesting technique).")
        if content_res.get("empty_forms"):
            warnings.append("Form has empty action attribute, potentially trapping user input.")
        if content_res.get("hidden_iframes_count", 0) > 0:
            warnings.append("Hidden iframe(s) detected, which can run malicious background scripts or overlays.")
        if content_res.get("obfuscation_signals") and (
            content_res.get("credential_forms_count", 0) > 0
            or content_res.get("external_forms")
        ):
            warnings.append("Obfuscated or packed JavaScript code detected, indicating attempts to hide logic.")
    else:
        # Fetching page failed
        warnings.append("Failed to fetch webpage source. Could be offline, blocking automated scanners, or redirecting.")

    if similarity_res.get("impersonation_detected"):
        warnings.append(similarity_res.get("reason"))

    # 3. Standalone WHOIS domain age + HTTPS forms check (+20 points)
    domain_age = url_res.get("domain_age_days", -1)
    if (
        domain_age != -1 
        and domain_age < 30 
        and url_res.get("is_https") 
        and content_res.get("forms_count", 0) > 0
        and content_res.get("status") == "success"
    ):
        final_score += 20
        warnings.append("High-risk zero-day indicator: This site is hosted on a very young domain (< 30 days) using an HTTPS certificate and hosting interactive web forms (often used for credential harvesting).")

    # 4. Critical Overrides for unknown URLs.
    # Rule A: If brand impersonation is detected (e.g. title is PayPal but domain is fake), force score to >= 85.
    if similarity_res.get("impersonation_detected"):
        final_score = max(final_score, 85)
        
    # Rule B: If the domain is young/WHOIS missing AND forms post to external servers, force score to >= 80.
    elif (url_res.get("domain_age_days") != -1 and url_res.get("domain_age_days") < 45) and content_res.get("external_forms"):
        final_score = max(final_score, 80)
        
    # Rule C: If no HTTPS and external forms, elevate score to Suspicious or High Risk.
    elif not url_res.get("is_https") and content_res.get("external_forms"):
        final_score = max(final_score, 75)

    # Rule D: If SSL certificate is invalid/mismatched AND we have suspicious URL features (score >= 30), elevate to High Risk (75).
    elif content_res.get("ssl_error") and url_score >= 30:
        final_score = max(final_score, 75)
        
    # Rule E: If SSL certificate is invalid/mismatched but URL risk is low, elevate to Suspicious (45).
    elif content_res.get("ssl_error"):
        final_score = max(final_score, 45)

    # Rule F: If XGBoost is highly confident (url_score >= 90) AND the TLD is suspicious AND domain is young/missing WHOIS, elevate to High Risk (70).
    elif url_score >= 90 and url_res.get("is_suspicious_tld") and (url_res.get("domain_age_days") == -1 or url_res.get("domain_age_days") < 90):
        final_score = max(final_score, 70)

    # Cap final score between 0 and 100
    final_score = max(0, min(100, final_score))

    # 5. Categorize Verdict
    if final_score < 30:
        verdict = "Safe"
    elif final_score < 50:
        verdict = "Low Suspicious"
    elif final_score < 70:
        verdict = "High Suspicious"
    else:
        verdict = "High Risk"

    confidence = calculate_confidence_score(url_res, threat_res, content_res, similarity_res, final_score)

    return final_score, verdict, warnings, confidence

def get_recommendations(verdict: str, score: int) -> str:
    """Generates detailed, actionable instructions for the user based on verdict."""
    if verdict == "Safe":
        return (
            "✅ This website appears to be SAFE.\n\n"
            "Our multi-layered detection engine scanned this URL and found no significant security threats:\n"
            "• The URL structure does not match any known phishing templates.\n"
            "• The site is not listed on Google Safe Browsing or PhishTank.\n"
            "• The webpage's HTML forms and scripts show standard, secure behaviors.\n"
            "• Visual identity check confirmed no attempt to impersonate legitimate brand assets.\n\n"
            "Recommendation: You can browse this website safely. As a general security practice, always check the address bar to verify you are on the correct website before submitting any passwords or credit card details."
        )
    elif verdict == "Low Suspicious":
        return (
            "⚠️ Warning: This website is LOW SUSPICIOUS.\n\n"
            "Our analysis engine identified a few minor risk indicators:\n"
            "• A minor structural anomaly in the URL or slightly young domain age.\n"
            "• No brand impersonation or malicious database hits were detected.\n"
            "• Standard connection security is active but proceed with careful observation.\n\n"
            "Recommendation: Exercise basic caution. Double-check that the sender of the link is trusted, and avoid entering sensitive credentials if the site asks for unexpected actions."
        )
    elif verdict == "High Suspicious":
        return (
            "⚠️ High Alert: This website is HIGH SUSPICIOUS.\n\n"
            "Our analysis engine identified several notable risk indicators:\n"
            "• URL structure matches common typo-squatting or lexical warning patterns.\n"
            "• Anomalous HTML content detected (e.g., redirect loops, invalid SSL, or hidden forms).\n"
            "• The domain is young or lacks a mail server configuration.\n\n"
            "Recommendation: DO NOT submit login credentials, PINs, or financial details. Verify the source of the link. If you received this URL via an unsolicited message, close the tab immediately and navigate to the official service directly."
        )
    else:
        return (
            "🚨 CRITICAL WARNING: HIGH RISK Phishing Site Detected!\n\n"
            "This URL has been flagged with severe risk indicators and is highly likely to be a fraudulent site:\n"
            "• Reputation databases have confirmed it is blacklisted OR\n"
            "• Brand impersonation analysis detected visual, typo-squatting, or favicon spoofing OR\n"
            "• HTML analysis found login forms designed to harvest credentials and send them to external servers.\n\n"
            "Recommendation: LEAVE THIS WEBSITE IMMEDIATELY. Do not click any links, do not download files, and under no circumstances enter any passwords, credit card numbers, or personal identity details. If you have already entered information, change your credentials on the official platform immediately."
        )

def generate_verdict_summary(
    url_res: dict, 
    threat_res: dict, 
    content_res: dict, 
    similarity_res: dict,
    score: int,
    verdict: str
) -> str:
    """Generates a natural-language description of why this verdict was reached."""
    if threat_res.get("is_flagged"):
        providers = []
        if threat_res.get("google_safe_browsing", {}).get("is_malicious"):
            providers.append("Google Safe Browsing")
        if threat_res.get("phishtank", {}).get("is_malicious"):
            providers.append("PhishTank")
        providers_str = " and ".join(providers) if providers else "threat intelligence feeds"
        
        brand_impersonation_text = ""
        if similarity_res.get("impersonation_detected"):
            brand = similarity_res.get("matched_brand") or "a trusted brand"
            brand_impersonation_text = f" Additionally, potential impersonation of {brand} was detected."
            
        return f"This URL is classified as High Risk because it was flagged by {providers_str}.{brand_impersonation_text} Secondary checks like HTML content scraping were skipped because a confirmed blacklist match is already decisive."

    # Zero-day analysis summary
    reasons = []
    url_score = url_res.get("feature_score", 0)
    content_score = content_res.get("feature_score", 0)
    
    # Check brand impersonation
    if similarity_res.get("impersonation_detected"):
        brand = similarity_res.get("matched_brand") or "a trusted brand"
        reasons.append(f"the brand impersonation check detected potential spoofing of {brand}")
    
    # Check URL ML score
    if url_score >= 50:
        reasons.append(f"the ML URL score is high ({url_score}/100)")
    elif url_res.get("found_keywords"):
        reasons.append("suspicious phishing keywords were found in the URL")
        
    # Check HTML content
    if content_score >= 40:
        if content_res.get("external_forms"):
            reasons.append("the page contains a login form")
        else:
            reasons.append("suspicious HTML structures (like hidden forms or scripts) were found")
    elif content_res.get("ssl_error"):
        reasons.append("the website has an invalid or self-signed SSL certificate")
        
    if not reasons:
        if score >= 30:
            reasons.append("of a combination of minor domain age, WHOIS anomalies, or layout features")
        else:
            reasons.append("all security layers returned low risk indicators")

    # Join reasons nicely
    if len(reasons) == 1:
        reasons_str = reasons[0]
    elif len(reasons) == 2:
        reasons_str = f"{reasons[0]} and {reasons[1]}"
    else:
        reasons_str = f"{', '.join(reasons[:-1])}, and {reasons[-1]}"

    verdict_lower = verdict.lower()
    if verdict == "Safe":
        return f"This URL is safe mainly because threat intelligence did not list the URL, and {reasons_str}. The verdict is based on zero-day analysis."
    else:
        return f"This URL is {verdict_lower} mainly because {reasons_str}. Threat intelligence did not list the URL, so the verdict is based on zero-day analysis."
