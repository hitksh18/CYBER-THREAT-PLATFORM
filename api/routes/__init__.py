# api/routes/__init__.py
from .threats import router as threats
from .score import router as score
from .clustering import router as clustering
from .dashboard import router as dashboard
from .alerts import router as alerts
from .commands import router as commands  # if commands exists
