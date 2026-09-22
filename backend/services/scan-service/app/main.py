"""scan-service entrypoint: orquestacion de escaneres defensivos
(nmap/trivy/nuclei/openvas) en modo SOLO DETECCION. Ver
app/scanners/base.py y docs/architecture.md para el alcance."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from app.schemas import ScanJobCreate, ScanJobOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("scan-service")
scan_jobs_total = Counter("scan_jobs_total", "Jobs de escaneo creados", ["scanner_type"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("scan-service iniciado")
    yield


app = FastAPI(title="SentinelOps Scan Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "scan-service"}


@app.get("/scanners/status")
async def scanners_status(claims: dict = Depends(get_current_claims)):
    return services.scanners_status()


@app.post("/scans", response_model=ScanJobOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.create_scan_job(db, payload, claims.get("sub", ""))
    await db.commit()
    scan_jobs_total.labels(scanner_type=payload.scanner_type.value).inc()
    logger.info("scan job creado", extra={"job_id": job.id, "scanner": payload.scanner_type.value})
    background_tasks.add_task(services.execute_scan_job, SessionLocal, job.id)
    return job


@app.get("/scans", response_model=list[ScanJobOut])
async def list_scans(
    status_filter: str | None = None,
    scanner_type: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_scan_jobs(db, status_filter, scanner_type)


@app.get("/scans/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    job = await services.get_scan_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    return job
