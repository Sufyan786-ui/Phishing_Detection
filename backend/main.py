import logging
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from datetime import datetime
import os

from backend import config, models, database
from backend.database import get_db, engine
from backend.detector.url_features import extract_url_features, URL_SCORE_VERSION
from backend.detector.threat_intel import check_threat_intel
from backend.detector.content_analysis import analyze_html_content
from backend.detector.similarity import analyze_brand_similarity
from backend.detector.scoring import calculate_risk_score, get_recommendations, generate_verdict_summary, calculate_confidence_score

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MainApp")

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Phishing Detection System",
    description="Multi-layered, intelligent phishing URL analysis engine.",
    version="1.0.0"
)

# Enable CORS for frontend flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Seed Database with brand references
def seed_brands(db: Session):
    logger.info("Verifying brand references database...")
    default_brands = [
        models.BrandReference(
            name="PayPal",
            domain="paypal.com",
            title_keywords="paypal,pay-pal,pay pal,paypal secure,paypal login",
            favicon_hash="003c7e7e3c180000"
        ),
        models.BrandReference(
            name="Netflix",
            domain="netflix.com",
            title_keywords="netflix,netflix login,netflix payment,nflx",
            favicon_hash="e0e0e0e0e0e0e0e0"
        ),
        models.BrandReference(
            name="Google",
            domain="google.com",
            title_keywords="google,gmail,google account,g-mail,google drive",
            favicon_hash="ffc3c3c3c3c3c3c3"
        ),
        models.BrandReference(
            name="Microsoft",
            domain="microsoft.com",
            title_keywords="microsoft,outlook,office 365,microsoft login,live mail,hotmail,sharepoint",
            favicon_hash="f0f0f0f00f0f0f0f"
        ),
        models.BrandReference(
            name="Apple",
            domain="apple.com",
            title_keywords="apple,apple id,icloud,appleid,itunes,apple support",
            favicon_hash="183c7e7e3c3c1800"
        ),
        models.BrandReference(
            name="Facebook",
            domain="facebook.com",
            title_keywords="facebook,meta,fb login,messenger",
            favicon_hash="0f0f0f0f0f0f0f0f"
        ),
        models.BrandReference(
            name="Ze Delivery",
            domain="ze.delivery",
            title_keywords="ze delivery,ze express,zedelivery,zédelivery,zé delivery",
            favicon_hash=""
        )
    ]
    
    for brand in default_brands:
        existing = db.query(models.BrandReference).filter(models.BrandReference.name == brand.name).first()
        if not existing:
            logger.info("Adding missing brand reference: %s", brand.name)
            db.add(brand)
            
    db.commit()
    logger.info("Successfully verified brand references database.")

# Run seeding and check/train XGBoost model on startup
@app.on_event("startup")
def startup_event():
    db = next(get_db())
    seed_brands(db)
    
    # Check if XGBoost model is trained
    model_path = os.path.join(os.path.dirname(__file__), "detector", "url_classifier.json")
    if not os.path.exists(model_path):
        logger.info("XGBoost model not found on startup. Training model...")
        try:
            from backend.detector.train_model import train_model
            train_model()
            logger.info("XGBoost model trained successfully on startup.")
            
            # Reload the model in url_features
            from backend.detector import url_features
            import xgboost as xgb
            url_features.model = xgb.XGBClassifier()
            url_features.model.load_model(model_path)
            logger.info("Reloaded newly trained XGBoost model in url_features.")
        except Exception as e:
            logger.error("Failed to train XGBoost model on startup: %s", e)

# Pydantic schemas for request validation
class ScanRequest(BaseModel):
    url: str

@app.post("/api/scan")
def scan_url(request: ScanRequest, db: Session = Depends(get_db)):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
        
    # Standardize URL formatting
    if not url.startswith(("http://", "https://")):
        # Check if it looks like a hostname or IP
        url = "https://" + url

    logger.info("Initiating scan for URL: %s", url)

    try:
        # Step 1: Reputation database queries.
        # If a URL is already confirmed by threat intelligence, classify it
        # immediately instead of spending time on secondary analysis layers.
        threat_res = check_threat_intel(url)

        if threat_res.get("is_flagged"):
            url_res = extract_url_features(url)
            content_res = {
                "status": "skipped",
                "message": "HTML content analysis skipped because threat intelligence already confirmed this URL as malicious.",
                "feature_score": 0
            }
            similarity_res = analyze_brand_similarity(url, "", "", db)
            score, verdict, warnings, confidence = calculate_risk_score(url_res, threat_res, content_res, similarity_res)
            recommendations = get_recommendations(verdict, score)
            verdict_summary = generate_verdict_summary(url_res, threat_res, content_res, similarity_res, score, verdict)

            # Embed confidence in similarity metadata to save to DB
            similarity_res["confidence_score"] = confidence

            scan_log = models.ScanHistory(
                url=url,
                score=score,
                verdict=verdict,
                url_features=url_res,
                threat_intel=threat_res,
                content_analysis=content_res,
                similarity=similarity_res,
                recommendations=recommendations
            )

            db.add(scan_log)
            db.commit()
            db.refresh(scan_log)

            return {
                "id": scan_log.id,
                "url": url,
                "score": score,
                "verdict": verdict,
                "confidence_score": confidence,
                "scanned_at": scan_log.scanned_at,
                "warnings": warnings,
                "recommendations": recommendations,
                "verdict_summary": verdict_summary,
                "details": {
                    "url_features": url_res,
                    "threat_intel": threat_res,
                    "content_analysis": content_res,
                    "similarity": similarity_res
                }
            }

        # Step 2: Lexical URL feature analysis
        url_res = extract_url_features(url)
        if "error" in url_res:
            raise HTTPException(status_code=400, detail=url_res["error"])

        # Step 3: Source HTML scraping and checks
        content_res = analyze_html_content(url)

        # Step 4: Brand impersonation similarity analysis
        # Extract title and favicon URL retrieved by content analyzer
        title = content_res.get("title", "")
        favicon_url = content_res.get("favicon_url", "")
        similarity_res = analyze_brand_similarity(url, title, favicon_url, db)

        # Step 5: Risk Scoring Aggregation
        score, verdict, warnings, confidence = calculate_risk_score(url_res, threat_res, content_res, similarity_res)
        recommendations = get_recommendations(verdict, score)
        verdict_summary = generate_verdict_summary(url_res, threat_res, content_res, similarity_res, score, verdict)

        # Embed confidence in similarity metadata to save to DB
        similarity_res["confidence_score"] = confidence

        # Step 6: Log scan result to Database
        scan_log = models.ScanHistory(
            url=url,
            score=score,
            verdict=verdict,
            url_features=url_res,
            threat_intel=threat_res,
            content_analysis=content_res,
            similarity=similarity_res,
            recommendations=recommendations
        )
        
        db.add(scan_log)
        db.commit()
        db.refresh(scan_log)

        # Return full structural report
        return {
            "id": scan_log.id,
            "url": url,
            "score": score,
            "verdict": verdict,
            "confidence_score": confidence,
            "scanned_at": scan_log.scanned_at,
            "warnings": warnings,
            "recommendations": recommendations,
            "verdict_summary": verdict_summary,
            "details": {
                "url_features": url_res,
                "threat_intel": threat_res,
                "content_analysis": content_res,
                "similarity": similarity_res
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("An error occurred during URL scanning:")
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")

@app.get("/api/history")
def get_scan_history(limit: int = 50, db: Session = Depends(get_db)):
    """Fetches recent scan history sorted by date descending."""
    scans = db.query(models.ScanHistory).order_by(models.ScanHistory.scanned_at.desc()).limit(limit).all()
    
    result = []
    for s in scans:
        url_features = s.url_features or {}
        is_legacy = (
            bool(url_features)
            and url_features.get("status") != "skipped"
            and url_features.get("score_version") != URL_SCORE_VERSION
        )
        result.append({
            "id": s.id,
            "url": s.url,
            "score": s.score,
            "verdict": s.verdict,
            "scanned_at": s.scanned_at,
            "is_legacy": is_legacy
        })
    return result

@app.get("/api/history/{scan_id}")
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """Retrieves full detail reports of a specific historical scan."""
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
        
    url_features = dict(scan.url_features or {})
    if (
        url_features
        and url_features.get("status") != "skipped"
        and url_features.get("score_version") != URL_SCORE_VERSION
    ):
        url_features["legacy_feature_score"] = url_features.get("feature_score")
        url_features["feature_score"] = None
        url_features["status"] = "legacy"
        url_features["message"] = (
            "This scan used an older URL scoring model. Run a new scan to get "
            "a score that is comparable with the current analysis."
        )

    verdict_summary = generate_verdict_summary(
        url_features,
        scan.threat_intel or {},
        scan.content_analysis or {},
        scan.similarity or {},
        scan.score,
        scan.verdict
    )

    similarity_dict = dict(scan.similarity or {})
    confidence = similarity_dict.get("confidence_score")
    if confidence is None:
        confidence = calculate_confidence_score(
            url_features,
            scan.threat_intel or {},
            scan.content_analysis or {},
            similarity_dict,
            scan.score
        )
        
    return {
        "id": scan.id,
        "url": scan.url,
        "score": scan.score,
        "verdict": scan.verdict,
        "confidence_score": confidence,
        "scanned_at": scan.scanned_at,
        "recommendations": scan.recommendations,
        "verdict_summary": verdict_summary,
        # We collect warnings dynamically from the saved states
        "details": {
            "url_features": url_features,
            "threat_intel": scan.threat_intel,
            "content_analysis": scan.content_analysis,
            "similarity": similarity_dict
        }
    }

@app.get("/api/brands")
def get_monitored_brands(db: Session = Depends(get_db)):
    """Returns database list of all brands currently monitored for brand impersonation."""
    brands = db.query(models.BrandReference).all()
    return [{
        "id": b.id,
        "name": b.name,
        "domain": b.domain,
        "title_keywords": b.title_keywords
    } for b in brands]

@app.get("/api/status")
def get_api_status(db: Session = Depends(get_db)):
    """Returns database and threat intelligence API connectivity status."""
    # Google Safe Browsing API status
    gsb_key = config.GOOGLE_SAFE_BROWSING_API_KEY
    gsb_status = "Connected" if gsb_key else "Simulated"
    
    # PhishTank API status
    pt_key = config.PHISHTANK_API_KEY
    pt_status = "Connected" if pt_key else "Simulated"
    
    # Check DB type from backend.database
    from backend.database import db_type
    
    return {
        "database": db_type.upper(),
        "google_safe_browsing": gsb_status,
        "phishtank": pt_status
    }

# Mount the static frontend directory. Must be mounted at the end
# to prevent static route matching overriding API endpoints.
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
else:
    logger.warning("Frontend static directory not found at %s. API will run, but frontend UI will not be served.", static_dir)
