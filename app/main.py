"""FastAPI application initialization for DATACAT Tier 2 SaaS."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes_analytics import router as analytics_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_health import router as health_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_ml import router as ml_router
from app.api.routes_statistical import router as statistical_router
from app.api.routes_unified_aiops import router as unified_aiops_router
from app.config import BASE_DIR, PROJECT_NAME, VERSION
from app.core.registry import registry
from app.db.database import get_db_connection, init_db
from app.db.queries import sync_collector_to_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("datacat")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager handling database schema initialization and collector sync."""
    logger.info("Initializing DATACAT Tier 2 Database...")
    await init_db()

    # Load YAML collector registry
    registry.reload()

    # Sync registered collectors to SQLite
    now_utc = datetime.now(timezone.utc).isoformat()
    db = await get_db_connection()
    try:
        for c in registry.list_all():
            await sync_collector_to_db(
                db=db,
                collector_id=c.collector_id,
                tenant_id=c.tenant_id,
                public_key_path=str(c.public_key_path),
                status="ACTIVE" if c.active else "SUSPENDED",
                now_utc=now_utc,
            )
        logger.info("Synchronized %d collectors with database", len(registry.list_all()))
    finally:
        await db.close()

    yield
    logger.info("Shutting down DATACAT Tier 2 application...")


app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    lifespan=lifespan,
)

# CORS middleware for prospective frontend consumption
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = BASE_DIR / "app" / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Register API routers
app.include_router(health_router)
app.include_router(ingest_router)
app.include_router(dashboard_router)
app.include_router(analytics_router)
app.include_router(statistical_router)
app.include_router(ml_router)
app.include_router(unified_aiops_router)


@app.get("/")
@app.get("/dashboard")
async def dashboard_page():
    """Serves the DATACAT central monitoring dashboard single-page interface."""
    template_path = BASE_DIR / "app" / "templates" / "index.html"
    return FileResponse(str(template_path))


@app.get("/api")
async def api_root():
    return {
        "service": PROJECT_NAME,
        "version": VERSION,
        "docs": "/docs",
        "health": "/api/v1/health",
        "ingest": "/api/v1/ingest",
        "dashboard": "/api/v1/dashboard/overview",
    }
