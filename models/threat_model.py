# models/threat_model.py
from pydantic import BaseModel
from typing import Optional

class Threat(BaseModel):
    id: Optional[str]
    cve_id: Optional[str]
    indicator: Optional[str]
    title: Optional[str]
    description: Optional[str]
    cvss_score: Optional[float]
    epss_score: Optional[float]
    source: Optional[str]
    fetched_at: Optional[str]
