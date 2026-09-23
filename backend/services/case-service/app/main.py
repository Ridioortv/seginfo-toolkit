"""case-service entrypoint: incidentes estilo ITSM/kanban con SLA por
prioridad y timeline de auditoria."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import CaseCreate, CaseUpdate, CaseOut, TimelineEntryCreate, ImportResult
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("case-service")
cases_created_total = Counter("case_created_total", "Casos creados", ["priority", "source"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE cases ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            f"UPDATE cases SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    logger.info("case-service iniciado")
    yield


app = FastAPI(title="SentinelOps Case Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "case-service"}


@app.post("/cases", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(payload: CaseCreate, db: AsyncSession = Depends(get_db)):
    """Sin RBAC estricto en la creacion: soar-service y otros servicios
    internos tambien crean casos (ver app/actions/create_case.py de
    soar-service, que intenta este endpoint antes de encolar como
    PendingCase)."""
    case = await services.create_case(db, payload)
    await db.commit()
    cases_created_total.labels(priority=payload.priority.value, source=payload.source).inc()
    return case


@app.get("/cases", response_model=list[CaseOut])
async def list_cases(
    status_filter: str | None = None,
    priority: str | None = None,
    assignee: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_cases(db, org_id_from_claims(claims), status_filter, priority, assignee)


@app.get("/cases/{case_id}", response_model=CaseOut)
async def get_case(case_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    case = await services.get_case(db, case_id, org_id_from_claims(claims))
    if case is None:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    return case


@app.patch("/cases/{case_id}", response_model=CaseOut)
async def update_case(
    case_id: str,
    payload: CaseUpdate,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    case = await services.get_case(db, case_id, org_id_from_claims(claims))
    if case is None:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    case = await services.update_case(db, case, payload, claims.get("sub", ""))
    await db.commit()
    return case


@app.post("/cases/{case_id}/timeline", response_model=CaseOut)
async def add_timeline_entry(
    case_id: str,
    payload: TimelineEntryCreate,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    case = await services.get_case(db, case_id, org_id_from_claims(claims))
    if case is None:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    case = await services.add_timeline_entry(db, case, payload, claims.get("sub", ""))
    await db.commit()
    return case


@app.post("/import/soar-pending", response_model=ImportResult)
async def import_soar_pending(
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    imported, skipped = await services.import_pending_cases_from_soar(db, org_id_from_claims(claims))
    await db.commit()
    logger.info("importacion de pending-cases de soar-service", extra={"imported": imported, "skipped": skipped})
    return ImportResult(imported=imported, skipped=skipped)
