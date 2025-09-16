# core/settings.py
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    MONGO_URI: str = "mongodb://127.0.0.1:27017"
    MONGO_DB: str = "cyber_threat_platform"

    # API Keys
    OTX_API_KEY: Optional[str] = None
    THREATFOX_API_KEY: Optional[str] = None   # ✅ now matches .env exactly

    # AI artifacts
    AI_MODEL_PATH: str = "models/priority_model.joblib"
    AI_VECT_PATH: str = "models/tfidf_vectorizer.joblib"

    # Alerting integrations
    ALERT_EMAIL: Optional[str] = None
    SLACK_WEBHOOK: Optional[str] = None
    WEBHOOK_URL: Optional[str] = None

    # App settings
    FETCH_TIMEOUT: int = 60

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
