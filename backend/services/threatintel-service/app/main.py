"""threatintel-service entrypoint: resuelve si una IP es maliciosa conocida
contra fuentes externas (AbuseIPDB, MISP), cacheando el resultado. Lo
consume tanto un usuario final (GET /lookup/{ip}, ej. desde el widget de
busqueda de Siem.tsx) como otro microservicio (POST /internal/lookup-batch,
ej. siem-service enriqueciendo una alerta nueva -- ver
siem-service/app/services.py::_enrich_alert_with_threat_intel)."""
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base, wait_for_database
from backend.shared.logging import configure_logging
from backend.shared import egress
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from app.schemas import IpReputationOut, LookupBatchRequest, LookupBatchResponse
from backend.shared.service_auth import require_service_token
from app.dependencies import get_current_claims
from app import services

logger = configure_logging("threatintel-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await wait_for_database()
    async with engine.begin() as conn:
        # Tabla nueva (no existia antes de este servicio) -- a diferencia
        # del resto de los microservicios, no hace falta ninguna migracion
        # ALTER TABLE para instalaciones existentes: create_all alcanza.
        await conn.run_sync(Base.metadata.create_all)
    logger.info("threatintel-service iniciado")
    yield


app = FastAPI(title="TERO Security Threat Intel Service", version="0.1.0", lifespan=lifespan)
egress.install("threatintel-service", app)
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
    return {"status": "ok", "service": "threatintel-service"}


@app.get("/lookup/{ip}", response_model=IpReputationOut)
async def lookup(ip: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    # Cualquier rol autenticado alcanza -- es una consulta de solo lectura/
    # enriquecimiento, no hay ninguna accion sensible que proteger con un
    # RBAC mas granular (a diferencia de, por ejemplo, activar/desactivar
    # un activo en asset-service).
    async with httpx.AsyncClient() as http_client:
        result = await services.lookup_ip(db, ip, http_client)
    await db.commit()
    return result


@app.post("/internal/lookup-batch", response_model=LookupBatchResponse)
async def internal_lookup_batch(
    payload: LookupBatchRequest,
    claims: dict = Depends(require_service_token),
    db: AsyncSession = Depends(get_db),
):
    """Endpoint interno servicio-a-servicio: exige JWT de servicio (antes
    anonimo, y sin tope de IPs: cualquiera con acceso al puerto podia gastar
    la cuota de AbuseIPDB). El tamaño del lote esta acotado en el schema."""
    results = await services.lookup_batch(db, payload.ips)
    return LookupBatchResponse(results=results)
