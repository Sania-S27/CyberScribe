import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

# Suppress verbose SQLAlchemy query logs unless SQL_ECHO is explicitly True
if not getattr(settings, "SQL_ECHO", False):
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)

# Create engine for MySQL connection
engine = create_engine(
    settings.MYSQL_URL,
    pool_pre_ping=True,  # Ensures disconnected sessions automatically reconnect
    echo=getattr(settings, "SQL_ECHO", False)  # Controlled via SQL_ECHO environment variable
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# FastAPI Dependency to yield a database session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()