# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio

from app.core.database import get_db, engine, Base
from app.services.osint_collector import fetch_and_process_osint

# Import your routers (including tenants and webhooks)
from app.api import auth, logs, admin, tenants, threats, webhooks

Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    collector_task = asyncio.create_task(fetch_and_process_osint())
    yield
    collector_task.cancel()
    try:
        await collector_task
    except (asyncio.CancelledError, Exception):
        pass

app = FastAPI(
    title="CyberScribe API",
    description="Autonomous Multi-Agent Cyber Threat Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the routers
app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(threats.router)
app.include_router(admin.router)
app.include_router(tenants.router)
app.include_router(webhooks.router)

from app.services.readiness_service import ReadinessService
from fastapi import Depends
from sqlalchemy.orm import Session

@app.get("/health")
def health_check():
    return {"status": "HEALTHY", "service": "CyberScribe API"}

@app.get("/health/readiness")
@app.get("/readiness")
def readiness_check(db: Session = Depends(get_db)):
    return ReadinessService.get_system_readiness(db=db)