# Verification Script for Phishing Detection Engine
import sys
from sqlalchemy.orm import Session

# Add current folder to path
sys.path.append(".")

from backend import database, models
from backend.main import seed_brands
from backend.detector.url_features import extract_url_features
from backend.detector.threat_intel import check_threat_intel
from backend.detector.content_analysis import analyze_html_content
from backend.detector.similarity import analyze_brand_similarity
from backend.detector.scoring import calculate_risk_score

def run_test_scan(url: str, db: Session):
    print(f"\n==========================================")
    print(f"Scanning URL: {url}")
    print(f"==========================================")
    
    # 1. Lexical features
    url_res = extract_url_features(url)
    print(f"[1] Lexical Score: {url_res['feature_score']}/100")
    print(f"    Keywords found: {url_res['found_keywords']}")
    print(f"    Domain age: {url_res['domain_age_days']} days")
    
    # 2. Threat Intel
    threat_res = check_threat_intel(url)
    print(f"[2] Threat Intel Flagged: {threat_res['is_flagged']}")
    
    # 3. Content Analysis
    content_res = analyze_html_content(url)
    print(f"[3] HTML Content Score: {content_res['feature_score']}/100")
    print(f"    Forms found: {content_res['forms_count']}")
    print(f"    External Forms: {content_res.get('external_forms', [])}")
    print(f"    Obfuscation signals: {content_res.get('obfuscation_signals', False)}")
    
    # 4. Brand Impersonation Similarity
    title = content_res.get("title", "")
    favicon_url = content_res.get("favicon_url", "")
    similarity_res = analyze_brand_similarity(url, title, favicon_url, db)
    print(f"[4] Impersonation Detected: {similarity_res['impersonation_detected']}")
    print(f"    Details: {similarity_res['reason']}")
    
    # 5. Combined Score
    score, verdict, warnings, confidence = calculate_risk_score(url_res, threat_res, content_res, similarity_res)
    print(f"\n>>> FINAL REPORT <<<")
    print(f"    Score: {score}/100")
    print(f"    Verdict: {verdict}")
    print(f"    Confidence: {confidence}%")
    print(f"    Warnings Flagged:")
    for w in warnings:
        print(f"      - {w}")

if __name__ == "__main__":
    db = next(database.get_db())
    # Seed brands if not seeded
    seed_brands(db)
    
    # Run scans
    run_test_scan("https://distribuidora-bebidasentrega.shop/", db)
    run_test_scan("http://login-verify-paypal.com/update", db)
