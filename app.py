# app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import the router objects directly
from api.routes.threats import router as threats_router
from api.routes.score import router as score_router
from api.routes.clustering import router as clustering_router
from api.routes.dashboard import router as dashboard_router

# Optional routers (alerts, commands)
try:
    from api.routes.alerts import router as alerts_router
    HAS_ALERTS = True
except ImportError:
    HAS_ALERTS = False

try:
    from api.routes.commands import router as commands_router
    HAS_COMMANDS = True
except ImportError:
    HAS_COMMANDS = False

from core.db import ensure_indexes
from core.settings import settings


# ------------------------
# FastAPI app
# ------------------------
app = FastAPI(
    title="AI-Powered Cyber Threat Intelligence Platform",
    version="1.0.0"
)

# ------------------------
# CORS
# ------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 🔒 restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------
# Routers
# ------------------------
app.include_router(threats_router, prefix="/threats", tags=["Threats"])
app.include_router(score_router, prefix="/score", tags=["Scoring"])
app.include_router(clustering_router, prefix="/clustering", tags=["Clustering"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])

if HAS_ALERTS:
    app.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
if HAS_COMMANDS:
    app.include_router(commands_router, prefix="/commands", tags=["Commands"])


# ------------------------
# Startup Event
# ------------------------
@app.on_event("startup")
async def startup_event():
    await ensure_indexes()  # Ensure DB indexes
    print("✅ Startup complete. Using database:", settings.MONGO_DB)


# ------------------------
# Root + Health
# ------------------------
@app.get("/")
async def root():
    return {
        "message": "Cyber Threat Intelligence Platform is running",
        "docs": "/docs"
    }

@app.get("/health")
async def health():
    return {"status": "ok", "database": settings.MONGO_DB}
