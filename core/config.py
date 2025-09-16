import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Database
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.getenv("MONGO_DB", "cyber_threat_platform")

# API Keys
OTX_API_KEY = os.getenv("OTX_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_Auth-Key")  # matches your .env key

# AI model paths
AI_MODEL_PATH = os.getenv("AI_MODEL_PATH", "models/priority_model.joblib")
AI_VECT_PATH = os.getenv("AI_VECT_PATH", "models/tfidf_vectorizer.joblib")

# Alerts
ALERT_EMAIL = os.getenv("ALERT_EMAIL")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
