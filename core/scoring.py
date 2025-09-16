import joblib
import pandas as pd
from datetime import datetime
from core.settings import settings
from core.db import save_threat, get_all_threats, save_alert
from core.ws import manager as ws_manager  # for WebSocket broadcasting
from core.queries import serialize_doc      # ✅ import serializer

# Weighted fallback weights (rule-based backup)
WEIGHTS = {
    "malware": 40,
    "phishing": 30,
    "ransomware": 50,
    "exploit": 40,
    "critical": 30,
    "high": 20,
    "kev_exploited": 50,
    "cvss": 2,    # multiplier
    "epss": 100,  # multiplier
}

# Try loading AI model (pipeline)
MODEL = None
try:
    MODEL = joblib.load(settings.AI_MODEL_PATH)
    print("✅ AI model loaded for scoring.")
except Exception as e:
    MODEL = None
    print(f"⚠️ AI model not loaded, using rule-based scoring: {e}")


def prepare_ai_features(threat: dict) -> pd.DataFrame:
    """
    Prepare features for the AI model.
    Adjust this to match the feature set your model was trained on.
    """
    return pd.DataFrame([{
        "title": threat.get("title", ""),
        "description": threat.get("description", ""),
        "cvss_score": threat.get("cvss_score", 0.0),
        "epss_score": threat.get("epss_score", 0.0),
        "kev_exploited": int(threat.get("kev_exploited", False)),
        "percentile": threat.get("percentile", 0.0),   # ✅ added missing feature
    }])


async def analyze_threats(threat: dict, role: str | None = None):
    """
    Score a threat using AI model if available, else rule-based heuristics.
    Role-specific modifiers are applied in both cases.
    Generates & broadcasts alerts if severity is high/critical.
    """
    summary = (threat.get("description") or "") + " " + (threat.get("title") or "")
    cvss = threat.get("cvss_score") or 0
    epss = threat.get("epss_score") or 0
    kev = threat.get("kev_exploited", False)

    score = 0
    priority = "low"

    # ================================
    # 1. AI-based scoring
    # ================================
    if MODEL:
        try:
            X = prepare_ai_features(threat)
            pred_label = MODEL.predict(X)[0]

            if pred_label == "high":
                score = 90
            elif pred_label == "medium":
                score = 70
            else:
                score = 40

            threat["ai_label"] = pred_label
        except Exception as e:
            print(f"⚠️ AI prediction failed, fallback to rules: {e}")
            score = 0
            threat["ai_label"] = "low"

    # ================================
    # 2. Rule-based scoring (if no AI or AI failed)
    # ================================
    if not MODEL or score == 0:
        text = summary.lower()
        for keyword, w in WEIGHTS.items():
            if keyword in text:
                score += w
        score += cvss * WEIGHTS.get("cvss", 2)
        score += epss * WEIGHTS.get("epss", 100)
        if kev:
            score += WEIGHTS.get("kev_exploited", 50)

    # ================================
    # 3. Role-based modifiers
    # ================================
    text = summary.lower()
    if role == "security":
        if kev:
            score += 30
        if cvss >= 9:
            score += 20
    elif role == "financial":
        if "ransomware" in text or "phishing" in text:
            score += 40
    elif role == "operational":
        if cvss >= 7:
            score += 25
        if "supply chain" in text:
            score += 30

    # ================================
    # 4. Priority assignment
    # ================================
    if score >= 120:
        priority = "critical"
    elif score >= 90:
        priority = "high"
    elif score >= 60:
        priority = "medium"
    else:
        priority = "low"

    # Attach analysis metadata
    threat["score"] = float(score)
    threat["priority"] = priority
    threat["analyzed_at"] = datetime.utcnow()

    # Save updated threat
    await save_threat(threat)

    # ================================
    # 5. Generate alerts for high/critical
    # ================================
    try:
        if priority in ("high", "critical"):
            alert = {
                "title": f"High-priority threat detected: {priority.upper()}",
                "description": threat.get("description") or threat.get("title") or "",
                "severity": priority,
                "source": threat.get("source"),
                "threat_ref": threat.get("cve_id") or threat.get("indicator") or str(threat.get("_id")),
                "created_at": datetime.utcnow(),
            }
            alert_id = await save_alert(alert)
            alert["id"] = alert_id

            # ✅ Serialize before broadcasting
            alert_out = serialize_doc(alert)

            try:
                await ws_manager.broadcast({"type": "alert", "alert": alert_out})
            except Exception as e:
                print(f"⚠️ Failed to broadcast alert: {e}")
    except Exception as e:
        print(f"⚠️ Failed to save/broadcast alert: {e}")

    return threat


async def get_scored_threats(limit: int = 50, role: str | None = None):
    """
    Retrieve and score threats, sorted by score.
    """
    data = await get_all_threats(limit=limit)
    scored = []
    for t in data:
        analyzed = await analyze_threats(t, role)
        scored.append(analyzed)
    scored = sorted(scored, key=lambda x: x.get("score", 0), reverse=True)
    return scored[:limit]
