from sqlalchemy import Column, Integer, String, DateTime, JSON, Text
from datetime import datetime
from backend.database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False)
    score = Column(Integer, nullable=False)
    verdict = Column(String(50), nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    
    # Store detailed module outputs as JSON
    url_features = Column(JSON, nullable=True)
    threat_intel = Column(JSON, nullable=True)
    content_analysis = Column(JSON, nullable=True)
    similarity = Column(JSON, nullable=True)
    
    # Actionable advice for the user
    recommendations = Column(Text, nullable=True)


class BrandReference(Base):
    __tablename__ = "brand_reference"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    domain = Column(String(255), nullable=False)
    title_keywords = Column(Text, nullable=False)  # JSON or comma-separated keywords
    favicon_hash = Column(String(64), nullable=True)  # Perceptual hash of brand favicon
