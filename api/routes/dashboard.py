# api/routes/dashboard.py
from fastapi import APIRouter, Query, HTTPException
from core import queries
from core.dashboard import get_dashboard_data

router = APIRouter()


@router.get("/sample_cves")
async def sample_cves(limit: int = 5):
    """
    Return a sample set of CVEs from the database.
    Default limit = 5.
    """
    try:
        data = await queries.get_sample_cves(limit=limit)
        return {"status": "success", "sample": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching sample CVEs: {str(e)}")


@router.get("/sources_count")
async def sources_count():
    """
    Count number of threats ingested per source (NVD, OTX, ThreatFox, etc.).
    """
    try:
        data = await queries.count_by_source()
        return {"status": "success", "counts": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching source counts: {str(e)}")


@router.get("/top_iocs")
async def top_iocs(limit: int = 10, role: str | None = Query(None)):
    """
    Return top IOCs (Indicators of Compromise) ranked by confidence.
    Role filter modifies scoring:
    - security: confidence >= 80
    - financial: phishing/fraud-focused
    - operational: system-impacting indicators
    """
    try:
        data = await queries.get_top_iocs(limit=limit, role=role)
        return {"status": "success", "iocs": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching top IOCs: {str(e)}")


@router.get("/trending_cves")
async def trending_cves(limit: int = 10, role: str | None = Query(None)):
    """
    Return trending CVEs sorted by EPSS/score.
    Role filter modifies scoring:
    - security: KEV exploited CVEs
    - financial: ransomware/phishing impact
    - operational: CVSS >= 7.0
    """
    try:
        data = await queries.get_trending_cves(limit=limit, role=role)
        return {"status": "success", "trending": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching trending CVEs: {str(e)}")


@router.get("/overview")
async def dashboard_overview(role: str | None = Query(None)):
    """
    High-level dashboard overview.
    Includes:
    - total threats
    - high / critical counts
    - clusters summary
    - top 10 threats (AI-enhanced + role scoring)
    """
    try:
        data = await get_dashboard_data(role=role)
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating dashboard overview: {str(e)}")
