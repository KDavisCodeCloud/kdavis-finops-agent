"""kdavis-finops-agent -- FastAPI application entry point.

Run locally:
    uvicorn api.main:app --reload --port 8001
"""

# ruff: noqa: E402  -- load_dotenv() must run before any os.environ read below

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

import asyncpg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.db import register_jsonb_codec
from api.routes import tenants, scans, hitl

log = logging.getLogger(__name__)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise EnvironmentError("DATABASE_URL not set")

    asyncpg_url = database_url.replace("postgresql+asyncpg://", "postgresql://")

    # statement_cache_size=0: same fix as kdavis-agentic-platform/api/main.py --
    # this DATABASE_URL points at Supabase's transaction-mode pooler, which
    # doesn't pin a client to one server-side connection across statements.
    app.state.db_pool = await asyncpg.create_pool(
        asyncpg_url,
        min_size=1,
        max_size=5,
        command_timeout=60,
        statement_cache_size=0,
        init=register_jsonb_codec,
    )
    log.info("[API] Database pool created")

    yield

    await app.state.db_pool.close()
    log.info("[API] Shutdown complete")


app = FastAPI(
    title="FinOps Agent API",
    description="Continuous cloud-cost-and-security monitoring.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_allowed_origins = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "finops-agent-api"}


@app.get("/health/db")
async def health_db() -> dict:
    async with app.state.db_pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    return {"status": "ok", "db": "connected"}


app.include_router(tenants.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(hitl.router, prefix="/api/v1")
