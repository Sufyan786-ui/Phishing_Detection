import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend import config

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Database")

Base = declarative_base()

SessionLocal = None
engine = None
db_type = "sqlite"

def init_db():
    global engine, SessionLocal, db_type
    
    # Try connecting to MySQL
    mysql_url = f"mysql+pymysql://{config.MYSQL_USER}:{config.MYSQL_PASSWORD}@{config.MYSQL_HOST}:{config.MYSQL_PORT}/{config.MYSQL_DB}"
    
    try:
        # Check if we can connect to MySQL (without the database first to see if MySQL is running)
        import pymysql
        conn = pymysql.connect(
            host=config.MYSQL_HOST,
            user=config.MYSQL_USER,
            password=config.MYSQL_PASSWORD,
            port=int(config.MYSQL_PORT)
        )
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config.MYSQL_DB}")
        conn.close()
        
        # Now create the SQLAlchemy engine for MySQL
        engine = create_engine(mysql_url, echo=False)
        # Test connection
        with engine.connect() as connection:
            pass
            
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db_type = "mysql"
        logger.info("Successfully connected to MySQL database: %s", config.MYSQL_DB)
    except Exception as e:
        logger.warning("Could not connect to MySQL server (%s). Falling back to SQLite.", e)
        # Fall back to SQLite
        engine = create_engine(config.SQLITE_URL, connect_args={"check_same_thread": False})
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db_type = "sqlite"
        logger.info("Using SQLite database at %s", config.SQLITE_DB_PATH)

# Initialize database components immediately
init_db()

# Dependency to get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
