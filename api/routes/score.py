# api/routes/score.py
from fastapi import APIRouter, Query, Body, HTTPException
from core.scoring import get_scored_threats, analyze_threats
from core.queries import serialize_doc

router = APIRouter()

@router.get("/")
async def scored_threats(limit: int = 50, role: str | None = Query(None)):
    """
    Get a list of scored threats from the database.
    """
    try:
        data = await get_scored_threats(limit=limit, role=role)
        return {"status": "success", "data": serialize_doc(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching scored threats: {e}")


@router.post("/analyze")
async def analyze_single_threat(threat: dict = Body(...), role: str | None = Query(None)):
    """
    Analyze a single threat document (via POST body).
    """
    try:
        analyzed = await analyze_threats(threat, role=role)
        return {"status": "success", "data": serialize_doc(analyzed)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing threat: {e}")


@router.get("/analyze")
async def analyze_threat_query(
    title: str = Query("Test threat"),
    description: str = Query("No description"),
    cvss_score: float = Query(5.0),
    epss_score: float = Query(0.5),
    kev_exploited: bool = Query(False),
    role: str | None = Query(None)
):
    """
    Analyze a single threat using query parameters (GET).
    Example:
    /score/analyze?title=RCE&cvss_score=9.0&epss_score=0.8&kev_exploited=true
    """
    try:
        threat = {
            "title": title,
            "description": description,
            "cvss_score": cvss_score,
            "epss_score": epss_score,
            "kev_exploited": kev_exploited,
        }
        analyzed = await analyze_threats(threat, role=role)
        return {"status": "success", "data": serialize_doc(analyzed)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing threat: {e}")
