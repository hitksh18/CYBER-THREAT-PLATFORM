# core/dashboard.py
from core.db import get_data
from core.scoring import get_scored_threats

async def get_dashboard_data(role: str | None = None):
    """
    Aggregate key dashboard metrics for threats:
    - Total threats
    - High/Critical risk counts
    - Cluster breakdown
    - Role-specific top threats
    """

    # Get scored threats (AI / rule-based scoring applied)
    scored = await get_scored_threats(limit=500, role=role) or []

    # Get clustered threats (if clustering pipeline was executed)
    clustered = await get_data("clustered_threats") or []

    # Compute summary metrics
    total = len(scored)
    high_risk = sum(1 for t in scored if t.get("priority") in ["high", "critical"])
    critical_risk = sum(1 for t in scored if t.get("priority") == "critical")

    # Build cluster stats
    cluster_summary = {}
    for c in clustered:
        cluster_name = c.get("cluster", "unknown")
        cluster_summary[cluster_name] = cluster_summary.get(cluster_name, 0) + 1

    # Ensure top threats are serializable (avoid ObjectId/datetime issues)
    def safe_threat(t: dict):
        return {
            "id": str(t.get("_id", "")),
            "cve_id": t.get("cve_id"),
            "indicator": t.get("indicator"),
            "description": t.get("description", "")[:200],  # trim long text
            "score": t.get("score"),
            "priority": t.get("priority"),
            "source": t.get("source"),
        }

    top_threats = [safe_threat(t) for t in scored[:10]]

    # Return structured dashboard summary
    return {
        "total_threats": total,
        "high_risk_threats": high_risk,
        "critical_threats": critical_risk,
        "clusters": cluster_summary,
        "top_threats": top_threats
    }
