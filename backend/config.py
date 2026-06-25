import os
from pathlib import Path
from dotenv import load_dotenv

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(dotenv_path=BASE_DIR / ".env")

# Database Configuration
# Default credentials for local MySQL server.
# We will dynamically fall back to SQLite if MySQL is unavailable.
MYSQL_USER = os.getenv("DB_USER", "root")
MYSQL_PASSWORD = os.getenv("DB_PASSWORD", "")
MYSQL_HOST = os.getenv("DB_HOST", "localhost")
MYSQL_PORT = os.getenv("DB_PORT", "3306")
MYSQL_DB = os.getenv("DB_NAME", "phishing_detector")

# SQLite fallback path
SQLITE_DB_PATH = BASE_DIR / "phishing_detector.db"
SQLITE_URL = f"sqlite:///{SQLITE_DB_PATH}"

# Threat Intelligence APIs
# Users can supply these keys in their environment. If empty, the system will use realistic mock data.
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")

# Risk Scoring Engine Weights
# Threat intelligence is treated as a confirmation layer:
# if a URL is blacklisted, it is immediately high risk. If it is not
# blacklisted, it does not reduce the final score.
WEIGHT_URL_FEATURES = 0.60
WEIGHT_CONTENT_ANALYSIS = 0.40

# Port for backend
PORT = 8000
