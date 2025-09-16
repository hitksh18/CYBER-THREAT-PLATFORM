# models/score_model.py
from pydantic import BaseModel
from typing import Optional

class ScoredThreat(BaseModel):
    id: Optional[str]
    summary: Optional[str]
    cvss: Optional[float]
    score: int
    priority: str
    cluster: Optional[str] = None
