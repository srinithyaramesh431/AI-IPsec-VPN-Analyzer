"""
main.py
-------
FastAPI entrypoint. Run with:
    uvicorn app.main:app --reload --port 8000
(from the backend/ directory, with the venv activated)
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_db
from app.config import FRONTEND_ORIGINS
from app.routers import upload, analysis, dashboard

app = FastAPI(
    title="AI-Powered IPsec VPN Protocol Analyzer & Security Assessment",
    description="Capture -> Identify -> Infer -> Assess -> Score -> Recommend",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(analysis.router)
app.include_router(dashboard.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {
        "project": "AI-Powered IPsec VPN Protocol Analyzer & Security Assessment",
        "flow": "Capture -> Identify -> Infer -> Assess -> Score -> Recommend",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
