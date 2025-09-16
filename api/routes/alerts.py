# api/routes/alerts.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Body, Query
from core.db import save_alert, get_alerts
from core.ws import manager
from core.queries import serialize_doc

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for clients to receive real-time alerts.
    Clients connect to: ws://host:port/alerts/ws
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, optionally handle pings from clients
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.post("/")
async def create_alert(alert: dict = Body(...)):
    """
    Create an alert (persist to DB) and broadcast it to all WebSocket clients.

    Example body:
    {
      "title": "Suspicious IP blocked",
      "description": "IP 1.2.3.4 triggered X rule",
      "severity": "high",
      "meta": {...}
    }
    """
    try:
        # Save alert to DB
        alert_id = await save_alert(alert)

        # ✅ Serialize alert so ObjectId + datetime are JSON-safe
        alert_out = serialize_doc(alert)
        alert_out["id"] = str(alert_id)

        # ✅ Broadcast alert to all connected WebSocket clients
        try:
            await manager.broadcast({"type": "alert", "alert": alert_out})
        except Exception as be:
            # We don’t want broadcast failures to block DB save
            print(f"⚠️ Failed to broadcast alert: {be}")

        return {"status": "ok", "id": str(alert_id), "alert": alert_out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save alert: {e}")


@router.get("/")
async def list_alerts(
    limit: int = Query(20, description="Max number of alerts to return"),
    role: str | None = Query(None, description="Filter alerts by role"),
):
    """
    List alerts stored in DB, optionally filtered by role.
    """
    try:
        docs = await get_alerts(limit=limit, role=role)
        # ✅ Ensure all docs are JSON safe
        return {"alerts": [serialize_doc(d) for d in docs]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {e}")
