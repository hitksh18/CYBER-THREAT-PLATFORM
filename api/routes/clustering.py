# api/routes/clustering.py
from fastapi import APIRouter, Query, HTTPException
from core.clustering import run_clustering

router = APIRouter()

@router.get("/run")
@router.post("/run")
async def clustering_run(n_clusters: int = Query(5, ge=2, le=20), limit: int = Query(500, le=5000)):
    """
    Run clustering on threat descriptions.
    - n_clusters: number of clusters (default 5, max 20)
    - limit: number of threats to cluster (default 500, max 5000)
    """
    try:
        result = await run_clustering(n_clusters=n_clusters, limit=limit)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running clustering: {str(e)}")
