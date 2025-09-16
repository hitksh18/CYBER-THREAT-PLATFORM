# core/extractor.py
import httpx
from datetime import datetime
from core.db import threats_collection
from core.settings import settings

# ========================
# Utility: Safe Fetch
# ========================
async def safe_fetch(fetch_func, *args, **kwargs):
    """Wrapper to safely fetch data from sources without crashing the pipeline."""
    try:
        return await fetch_func(*args, **kwargs)
    except Exception as e:
        print(f"❌ Error fetching from {fetch_func.__name__}: {e}")
        return [] if "fetch_" in fetch_func.__name__ else {}

# ========================
# 1. NVD CVE Data
# ========================
async def fetch_nvd_data(limit=100):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={limit}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=settings.FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        desc = ""
        if "descriptions" in cve and cve["descriptions"]:
            desc = cve["descriptions"][0].get("value", "")

        published = cve.get("published")
        if published:
            published = datetime.fromisoformat(published.replace("Z", "+00:00"))

        base_score = None
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            base_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        cves.append({
            "cve_id": cve_id,
            "description": desc,
            "published": published,
            "cvss_score": base_score,
            "source": "NVD"
        })
    return cves

# ========================
# 2. EPSS Scores
# ========================
async def fetch_epss_scores(limit=1000):
    url = f"https://api.first.org/data/v1/epss?limit={limit}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=settings.FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

    epss_data = {}
    for row in data.get("data", []):
        epss_data[row["cve"]] = {
            "epss_score": float(row["epss"]),
            "percentile": float(row["percentile"])
        }
    return epss_data

# ========================
# 3. CISA KEV
# ========================
async def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=settings.FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    return {item["cveID"]: item for item in data.get("vulnerabilities", [])}

# ========================
# 4. AlienVault OTX
# ========================
async def fetch_otx(limit=10):
    if not settings.OTX_API_KEY:
        print("⚠️ No OTX API Key configured.")
        return []

    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={limit}"
    headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers, timeout=settings.FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

    iocs = []
    for pulse in data.get("results", []):
        for indicator in pulse.get("indicators", []):
            iocs.append({
                "indicator": indicator.get("indicator"),
                "type": indicator.get("type"),
                "title": pulse.get("name"),
                "source": "OTX"
            })
    return iocs

# ========================
# 5. Abuse.ch ThreatFox
# ========================
async def fetch_threatfox(limit=50):
    if not settings.THREATFOX_API_KEY:
        print("⚠️ No ThreatFox API Key configured.")
        return []

    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "limit": limit}
    headers = {"Auth-Key": settings.THREATFOX_API_KEY}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, headers=headers, timeout=settings.FETCH_TIMEOUT)
            resp.raise_for_status()

            # Try parsing JSON safely
            try:
                data = resp.json()
            except Exception:
                print(f"❌ ThreatFox returned non-JSON response: {resp.text[:200]}...")
                return []

        # Ensure data is dict
        if not isinstance(data, dict):
            print(f"❌ Unexpected ThreatFox response type: {type(data)}, value: {str(data)[:200]}")
            return []

        # Handle API errors
        if "error" in data:
            print(f"❌ ThreatFox API error: {data['error']}")
            return []

        iocs = []
        for ioc in data.get("data", []):
            iocs.append({
                "indicator": ioc.get("ioc"),
                "type": ioc.get("ioc_type"),
                "malware": ioc.get("malware"),
                "confidence": ioc.get("confidence_level"),
                "source": "ThreatFox"
            })
        print(f"✅ Fetched {len(iocs)} IOCs from ThreatFox")
        return iocs

    except Exception as e:
        print(f"❌ Error fetching from ThreatFox: {e}")
        return []

# ========================
# 6. MITRE ATT&CK
# ========================
async def fetch_mitre_attack():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=settings.FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            techniques.append({
                "technique_id": obj.get("external_references", [{}])[0].get("external_id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "source": "MITRE"
            })
    return techniques

# ========================
# 7. Reddit Cybersecurity
# ========================
async def fetch_reddit():
    url = "https://www.reddit.com/r/cybersecurity/top/.json?limit=10&t=day"
    headers = {"User-Agent": "Mozilla/5.0 (CyberThreatBot)"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers, timeout=settings.FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

    posts = []
    for post in data["data"]["children"]:
        pd = post["data"]
        posts.append({
            "title": pd["title"],
            "url": pd["url"],
            "score": pd["score"],
            "source": "Reddit"
        })
    return posts

# ========================
# 8. Master Fetcher
# ========================
async def fetch_and_store_all():
    nvd_data = await safe_fetch(fetch_nvd_data)
    epss_scores = await safe_fetch(fetch_epss_scores)
    kev_data = await safe_fetch(fetch_cisa_kev)
    otx_data = await safe_fetch(fetch_otx)
    threatfox_data = await safe_fetch(fetch_threatfox)
    mitre_data = await safe_fetch(fetch_mitre_attack)
    reddit_data = await safe_fetch(fetch_reddit)

    # Merge NVD + EPSS + KEV
    for cve in nvd_data:
        cve_id = cve["cve_id"]
        if cve_id in epss_scores:
            cve.update(epss_scores[cve_id])
        if cve_id in kev_data:
            cve["kev_exploited"] = True
            cve["kev_details"] = kev_data[cve_id]
        else:
            cve["kev_exploited"] = False
        cve["fetched_at"] = datetime.utcnow()

        await threats_collection.update_one(   # ✅ must await motor
            {"cve_id": cve_id},
            {"$set": cve},
            upsert=True
        )

    # Store other sources (prevent duplicates by using unique keys)
    async def bulk_insert_safe(data, unique_field):
        for item in data:
            if not item.get(unique_field):
                continue
            await threats_collection.update_one(   # ✅ must await motor
                {unique_field: item[unique_field]},
                {"$set": item},
                upsert=True
            )

    await bulk_insert_safe(otx_data, "indicator")
    await bulk_insert_safe(threatfox_data, "indicator")
    await bulk_insert_safe(mitre_data, "technique_id")
    await bulk_insert_safe(reddit_data, "url")

    return {
        "nvd": len(nvd_data),
        "epss": len(epss_scores),
        "kev": len(kev_data),
        "otx": len(otx_data),
        "threatfox": len(threatfox_data),
        "mitre": len(mitre_data),
        "reddit": len(reddit_data)
    }
