# core/clustering.py
import asyncio
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from core.db import threats_collection, save_threat

async def run_clustering(n_clusters: int = 5, limit: int = 500):
    """
    Cluster threats based on their textual description using KMeans.
    """
    cursor = threats_collection.find({}).limit(limit)
    threats = await cursor.to_list(length=limit)

    if not threats:
        return {"status": "no_data", "clusters": []}

    df = pd.DataFrame(threats)

    # Ensure description field
    if "description" not in df.columns:
        df["description"] = ""
    df["description"] = df["description"].fillna("").astype(str)

    # TF-IDF vectorization
    vectorizer = TfidfVectorizer(max_features=2000, stop_words="english")
    X = vectorizer.fit_transform(df["description"])

    # KMeans clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    df["cluster"] = kmeans.fit_predict(X)

    results = []
    for idx, row in df.iterrows():
        threat = threats[idx]
        threat["cluster"] = int(row["cluster"])
        await save_threat(threat)  # update with cluster assignment
        results.append({
            "id": str(threat.get("_id")),
            "description": threat.get("description"),
            "cluster": int(row["cluster"]),
        })

    return {
        "status": "success",
        "n_clusters": n_clusters,
        "count": len(results),
        "clusters": results[:20],  # preview first 20
    }

# Run standalone for testing
if __name__ == "__main__":
    asyncio.run(run_clustering())
