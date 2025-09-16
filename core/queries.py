# core/queries.py
from core.db import threats_collection, alerts_collection
from datetime import datetime
from bson import ObjectId

def serialize_doc(doc):
    """
    Recursively convert MongoDB documents into JSON-safe dicts.
    Handles ObjectId and datetime for all fields, including nested dicts/lists.
    """
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        out = {}
        for k, v in doc.items():
            if isinstance(v, ObjectId):
                out[k] = str(v)
            elif isinstance(v, datetime):
                out[k] = v.isoformat()
            elif isinstance(v, (dict, list)):
                out[k] = serialize_doc(v)
            else:
                out[k] = v
        return out
    return doc


# ------------------------
# Queries
# ------------------------

async def get_sample_cves(limit: int = 5):
    cursor = threats_collection.find({"cve_id": {"$exists": True}}).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [serialize_doc(d) for d in docs]


async def count_by_source():
    pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    docs = await threats_collection.aggregate(pipeline).to_list(length=50)
    return [serialize_doc(d) for d in docs]


async def get_top_iocs(limit: int = 10, role: str | None = None):
    query = {"indicator": {"$exists": True}}

    # Role-specific filtering
    if role == "security":
        query.update({"confidence": {"$gte": 80}})
    elif role == "financial":
        query.update({"tags": {"$in": ["phishing", "fraud", "scam"]}})
    elif role == "operational":
        query.update({"type": {"$in": ["ip", "domain", "url"]}})

    cursor = threats_collection.find(query).sort("confidence", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [serialize_doc(d) for d in docs]


async def get_trending_cves(limit: int = 10, role: str | None = None):
    query = {"cve_id": {"$exists": True}}

    # Role-specific filtering
    if role == "security":
        query.update({"kev_exploited": True})
    elif role == "financial":
        query.update({"description": {"$regex": "financial|ransomware|phishing", "$options": "i"}})
    elif role == "operational":
        query.update({"cvss_score": {"$gte": 7}})

    cursor = threats_collection.find(query).sort("epss_score", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [serialize_doc(d) for d in docs]


async def get_alerts(limit: int = 10, role: str | None = None):
    query = {}
    if role:
        query["role"] = role
    cursor = alerts_collection.find(query).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [serialize_doc(d) for d in docs]
