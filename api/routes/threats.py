from fastapi import APIRouter, HTTPException
from core.extractor import fetch_and_store_all
from core.settings import settings

router = APIRouter()

@router.get("/fetch_all")
async def fetch_all_threats():
    try:
        result = await fetch_and_store_all()
        return {"status": "success", "fetched": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threats: {str(e)}")
