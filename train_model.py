# train_model.py
import asyncio
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import RandomOverSampler
from imblearn.pipeline import Pipeline as ImbPipeline

from core.db import threats_collection
from core.settings import settings


# ===============================
# Load Data
# ===============================
async def load_data():
    cursor = threats_collection.find({})
    data = await cursor.to_list(length=10000)  # pull more samples if available
    return data


# ===============================
# Preprocess Data
# ===============================
def preprocess(data):
    df = pd.DataFrame(data)

    # Ensure description column
    if "description" not in df.columns:
        df["description"] = ""
    df["description"] = df["description"].fillna("").astype(str)

    # Ensure numeric features
    for col in ["cvss_score", "epss_score", "percentile"]:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = df[col].fillna(0).astype(float)

    # Boolean kev_exploited
    if "kev_exploited" not in df.columns:
        df["kev_exploited"] = False
    df["kev_exploited"] = df["kev_exploited"].fillna(False).astype(int)

    # Label strategy
    if "severity" in df.columns:
        df["label"] = df["severity"].fillna("low")
    else:
        df["label"] = pd.cut(
            df["cvss_score"].fillna(0),
            bins=[-1, 4, 7, 10],
            labels=["low", "medium", "high"]
        )

    # Clean dataset
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(str)
    df = df[df["description"].str.strip() != ""]

    print("Label distribution:")
    print(df["label"].value_counts())

    return df


# ===============================
# Train Model
# ===============================
async def train_model():
    data = await load_data()
    if not data:
        print("No data found in MongoDB. Run /threats/fetch_all first.")
        return

    df = preprocess(data)

    X = df[["description", "cvss_score", "epss_score", "percentile", "kev_exploited"]]
    y = df["label"]

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Feature transformer
    preprocessor = ColumnTransformer([
        ("text", TfidfVectorizer(max_features=5000, stop_words="english"), "description"),
        ("num", StandardScaler(), ["cvss_score", "epss_score", "percentile", "kev_exploited"])
    ])

    # Pipeline with oversampling
    pipeline = ImbPipeline([
        ("preprocessor", preprocessor),
        ("oversample", RandomOverSampler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])

    # Train model
    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model
    joblib.dump(pipeline, settings.AI_MODEL_PATH)
    print(f"Model saved to {settings.AI_MODEL_PATH}")


if __name__ == "__main__":
    asyncio.run(train_model())
