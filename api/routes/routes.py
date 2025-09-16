from fastapi import APIRouter, Query
from core.db import save_alert, get_alerts

router = APIRouter()

@router.get("/")
async def list_alerts(limit: int = 10, role: str | None = Query(None)):
    """
    Get recent alerts (optionally filtered by role).
    """
    alerts = await get_alerts(limit=limit)
    if role:
        alerts = [a for a in alerts if a.get("role") == role]
    return {"status": "success", "alerts": alerts}

@router.post("/")
async def create_alert(alert: dict):
    """
    Create a new alert (manual or triggered).
    """
    alert_id = await save_alert(alert)
    return {"status": "success", "id": alert_id}
