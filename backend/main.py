"""
TLS Inspector — FastAPI Application Entry Point
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import init_pg_db
from routers import scan, report
from routers import auth as auth_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: create all tables on startup."""
    logger.info("🚀 Starting TLS Inspector...")
    await init_pg_db()
    logger.info("✅ PostgreSQL (Neon) tables created/verified")
    yield
    logger.info("👋 Shutting down TLS Inspector")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Web-Based Certificate & TLS Security Assessment Portal",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)
app.include_router(report.router)
app.include_router(auth_router.router)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
