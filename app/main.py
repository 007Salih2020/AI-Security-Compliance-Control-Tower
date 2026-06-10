from __future__ import annotations

from fastapi import FastAPI

from app import __version__
from app.database import get_db
from app.routes.analysis import router as analysis_router
from app.routes.evaluations import router as evaluations_router
from app.routes.evidence import router as evidence_router
from app.routes.findings import router as findings_router
from app.routes.models_inventory import router as models_router
from app.routes.policies import router as policies_router
from app.routes.sync import router as sync_router

app = FastAPI(title="ControlLens AI", version=__version__)

app.include_router(findings_router)
app.include_router(analysis_router)
app.include_router(evaluations_router)
app.include_router(evidence_router)
app.include_router(models_router)
app.include_router(policies_router)
app.include_router(sync_router)


@app.get("/health")
def health():
    db = get_db()
    return {
        "status": "ok",
        "findings": len(db.get_findings()),
        "models": len(db.get_models()),
        "reports": len(db.get_reports()),
    }
