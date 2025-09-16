# core/alerts.py
import httpx
import smtplib
from email.message import EmailMessage
from datetime import datetime
from core.db import save_alert
from core.settings import settings
from core.queries import serialize_doc
from core.ws import manager


async def send_slack(text: str):
    """Send alert text to Slack via webhook."""
    if not settings.SLACK_WEBHOOK:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(settings.SLACK_WEBHOOK, json={"text": text})
            return resp.status_code == 200
    except Exception as e:
        print("⚠️ Slack send failed:", e)
        return False


async def send_webhook(payload: dict):
    """Send full alert payload to a generic webhook."""
    if not settings.WEBHOOK_URL:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(settings.WEBHOOK_URL, json=payload)
            return resp.status_code in (200, 202)
    except Exception as e:
        print("⚠️ Webhook send failed:", e)
        return False


def send_email(subject: str, body: str, to_addr: str | None = None):
    """Send alert via SMTP email (sync)."""
    if not settings.ALERT_EMAIL or not to_addr:
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.ALERT_EMAIL
        msg["To"] = to_addr
        msg.set_content(body)
        with smtplib.SMTP("localhost") as s:
            s.send_message(msg)
        return True
    except Exception as e:
        print("⚠️ Failed to send email:", e)
        return False


async def create_and_dispatch_alert(threat: dict, role: str | None = None):
    """
    Create an alert in DB, then dispatch to Slack, webhook, email, and WebSocket clients.
    Ensures ObjectId + datetime are JSON serializable before broadcasting.
    """
    priority = threat.get("priority", "low")
    alert = {
        "threat_id": threat.get("cve_id") or threat.get("indicator"),
        "priority": priority,
        "title": threat.get("title") or threat.get("cve_id") or threat.get("indicator"),
        "details": threat.get("description") or "",
        "role": role or "general",
        "created_at": datetime.utcnow(),
    }

    # ✅ Save in DB
    alert_id = await save_alert(alert)

    # ✅ Always use serializer (datetime → str, ObjectId → str)
    alert_out = serialize_doc(alert)
    alert_out["id"] = str(alert_id)

    # ✅ Send to integrations
    text = f"[{priority.upper()}] {alert_out['title']} ({alert_out['threat_id']})"
    await send_slack(text)
    await send_webhook(alert_out)
    # Email optional
    # send_email(f"{priority.upper()} ALERT: {alert_out['title']}", alert_out["details"], settings.ALERT_EMAIL)

    # ✅ WebSocket broadcast (safe JSON)
    try:
        await manager.broadcast({"type": "alert", "alert": alert_out})
    except Exception as e:
        print(f"⚠️ Failed to broadcast alert: {e}")

    return alert_id
