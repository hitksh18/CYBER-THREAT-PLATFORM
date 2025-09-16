# core/db.py
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
from core.settings import settings
from datetime import datetime

client = AsyncIOMotorClient(settings.MONGO_URI)
db = client[settings.MONGO_DB]

# Collections
threats_collection = db["threats"]
alerts_collection = db["alerts"]
users_collection = db["users"]
roles_collection = db["roles"]
clustered_collection = db["clustered_threats"]  # ✅ for clustering results


async def ensure_indexes():
    """Create necessary indexes once on startup."""
    # unique on CVE and indicator (sparse so both can coexist)
    await threats_collection.create_index([("cve_id", ASCENDING)], unique=True, sparse=True)
    await threats_collection.create_index([("indicator", ASCENDING)], unique=True, sparse=True)
    await threats_collection.create_index([("fetched_at", DESCENDING)])
    # alerts indexes
    await alerts_collection.create_index([("created_at", DESCENDING)])
    # users/roles
    await users_collection.create_index([("username", ASCENDING)], unique=True)
    # clustered threats
    await clustered_collection.create_index([("cluster", ASCENDING)])


# ----------------------
# Threat operations
# ----------------------
async def save_threat(data: dict):
    """
    Upsert threat document using cve_id or indicator as unique key.
    Returns the upserted key/object id.
    """
    doc = data.copy()
    # ensure fetched_at
    if "fetched_at" not in doc:
        doc["fetched_at"] = datetime.utcnow()
    key = {}
    if doc.get("cve_id"):
        key = {"cve_id": doc["cve_id"]}
    elif doc.get("indicator"):
        key = {"indicator": doc["indicator"]}
    else:
        # fallback: generate doc as new record
        result = await threats_collection.insert_one(doc)
        return str(result.inserted_id)

    await threats_collection.update_one(key, {"$set": doc}, upsert=True)
    return key


async def get_all_threats(limit: int = 100):
    cursor = threats_collection.find({}).sort("fetched_at", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_threats_by_source(source: str, limit: int = 50):
    cursor = threats_collection.find({"source": source}).sort("fetched_at", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_trending_cves(limit: int = 10):
    cursor = threats_collection.find({"cve_id": {"$exists": True}}).sort(
        [("cvss_score", -1), ("fetched_at", -1)]
    ).limit(limit)
    return await cursor.to_list(length=limit)


async def get_top_iocs(limit: int = 10):
    pipeline = [
        {"$match": {"indicator": {"$exists": True}}},
        {"$group": {"_id": "$indicator", "count": {"$sum": 1}, "latest": {"$max": "$fetched_at"}}},
        {"$sort": {"count": -1, "latest": -1}},
        {"$limit": limit}
    ]
    return await threats_collection.aggregate(pipeline).to_list(length=limit)


# ----------------------
# Alerts operations
# ----------------------
async def save_alert(alert: dict):
    if "created_at" not in alert:
        alert["created_at"] = datetime.utcnow()
    result = await alerts_collection.insert_one(alert)
    return str(result.inserted_id)


async def get_alerts(limit: int = 50):
    cursor = alerts_collection.find({}).sort("created_at", -1).limit(limit)
    return await cursor.to_list(length=limit)


# ----------------------
# Role-based helpers
# ----------------------
async def get_role_filtered_threats(role: str, limit: int = 50):
    query = {}
    if role == "security":
        query = {"$or": [{"cve_id": {"$exists": True}}, {"indicator": {"$exists": True}}]}
    elif role == "financial":
        query = {"$or": [{"tags": "fraud"}, {"tags": "ransomware"}, {"tags": "phishing"}]}
    elif role == "operational":
        query = {"$or": [{"tags": "ddos"}, {"tags": "malware"}, {"tags": "infrastructure"}]}

    cursor = threats_collection.find(query).sort("fetched_at", -1).limit(limit)
    return await cursor.to_list(length=limit)


# ----------------------
# Users / roles CRUD
# ----------------------
async def save_user(user: dict):
    await users_collection.update_one({"username": user["username"]}, {"$set": user}, upsert=True)
    return user["username"]


async def get_user_role(username: str):
    u = await users_collection.find_one({"username": username})
    return u.get("role") if u else None


# ----------------------
# Generic data accessor
# ----------------------
async def get_data(collection_name: str, limit: int = 100):
    """
    Generic fetch for any collection by name.
    Example: await get_data("clustered_threats")
    """
    collection = db[collection_name]
    cursor = collection.find({}).limit(limit)
    return await cursor.to_list(length=limit)
