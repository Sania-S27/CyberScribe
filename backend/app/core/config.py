import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load .env explicitly from backend directory, fallback to current dir
backend_env = BASE_DIR / ".env"
if backend_env.exists():
    load_dotenv(dotenv_path=backend_env)
else:
    load_dotenv()


def _resolve_chroma_path() -> str:
    env_path = os.getenv("CHROMADB_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_absolute() and p.exists():
            return str(p)
        backend_relative = (BASE_DIR / env_path).resolve()
        if backend_relative.exists():
            return str(backend_relative)
        if p.exists():
            return str(p.resolve())
        return str(backend_relative)
    
    local_path = (BASE_DIR / "chroma_storage").resolve()
    if local_path.exists():
        return str(local_path)
    return str(local_path)

class Settings:
    PROJECT_NAME: str = os.getenv("APP_NAME", "Cyber Threat Intelligence Agent")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1")
    SQL_ECHO: bool = os.getenv("SQL_ECHO", "False").lower() in ("true", "1")
    MYSQL_URL: str = os.getenv("MYSQL_DATABASE_URL", "mysql+pymysql://root:password@localhost:3306/cyberscribe")
    CHROMADB_PATH: str = _resolve_chroma_path()
    CHROMA_PATH: str = CHROMADB_PATH
    
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "cyber_scribe_super_secret_jwt_key_change_in_production")
    SECRET_KEY: str = JWT_SECRET_KEY
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    MODEL_NAME: str = os.getenv("model_name", "gemini-1.5-flash")

    # Containment Adapter & Fedora 44 nftables Executor Configuration
    CONTAINMENT_ADAPTER_MODE: str = os.getenv("CONTAINMENT_ADAPTER_MODE", "simulated").strip().lower()
    FEDORA_EXECUTOR_URL: str = os.getenv("FEDORA_EXECUTOR_URL", "http://127.0.0.1:8088").rstrip("/")
    FEDORA_EXECUTOR_TOKEN: str = os.getenv("FEDORA_EXECUTOR_TOKEN", "")
    FEDORA_NFTABLES_TABLE: str = os.getenv("FEDORA_NFTABLES_TABLE", "cyberscribe")

    # Email & Brevo Configuration
    EMAIL_PROVIDER: str = os.getenv("EMAIL_PROVIDER", "brevo").strip().lower()
    EMAIL_ENABLED: bool = os.getenv("EMAIL_ENABLED", "false").strip().lower() in ("true", "1", "yes")
    BREVO_API_KEY: str = os.getenv("BREVO_API_KEY", "").strip()
    BREVO_API_URL: str = os.getenv("BREVO_API_URL", "https://api.brevo.com/v3/smtp/email").strip()
    SMTP_HOST: str = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "").strip()
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "").strip()
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "alerts@cyberscribe.local").strip()
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "CyberScribe Security").strip()
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").strip().lower() in ("true", "1", "yes")
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")

settings = Settings()