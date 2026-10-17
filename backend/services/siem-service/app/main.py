"""siem-service entrypoint: ingesta de logs, normalizacion ECS-lite,
evaluacion de reglas Sigma y generacion de alertas. Ver app/sigma.py para
el motor de deteccion y app/opensearch_client.py para el almacen de logs."""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.ingest_auth import ingest_token_valid, org_ingest_token
from backend.shared.service_auth import require_service_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import (
    IngestLogsRequest, IngestLogsResponse, SigmaRuleCreate, SigmaRuleUpdate, SigmaRuleOut,
    AlertUpdate, AlertOut,
)
from app.dependencies import get_current_claims, require_role
from app import services, opensearch_client

logger = configure_logging("siem-service")
logs_ingested_total = Counter("siem_logs_ingested_total", "Eventos de log ingeridos")
alerts_created_total = Counter("siem_alerts_created_total", "Alertas generadas", ["severity"])

os_client = opensearch_client.build_client()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            f"UPDATE sigma_rules SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE alerts SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        # Migracion para instalaciones existentes -- mismo patron que
        # organization_id arriba: create_all no altera una tabla que ya
        # existia antes de esta version. threat_intel default 'null'::json
        # a nivel SQL no es lo mismo que el default={} de la app (JSON
        # NULL en la columna, no un objeto vacio), asi que las filas viejas
        # se backfillean explicitamente a '{}' para que el frontend
        # (que chequea Object.keys(alert.threat_intel).length) nunca vea
        # null.
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_intel JSON"))
        await conn.execute(text(
            "UPDATE alerts SET threat_intel = '{}' WHERE threat_intel IS NULL"
        ))
    # OpenSearch (con el plugin de seguridad) tarda en arrancar: se reintenta en
    # segundo plano hasta que el indice quede creado, sin bloquear el arranque.
    index_task = asyncio.create_task(_ensure_index_with_retry())
    logger.info("siem-service iniciado")
    yield
    index_task.cancel()
    await os_client.close()


async def _ensure_index_with_retry(attempts: int = 60, delay_seconds: float = 5.0) -> None:
    for attempt in range(1, attempts + 1):
        try:
            await opensearch_client.ensure_index(os_client)
            logger.info("indice de OpenSearch listo", extra={"attempt": attempt})
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "OpenSearch todavia no esta listo, se reintenta",
                extra={"error": str(exc), "attempt": attempt},
            )
            await asyncio.sleep(delay_seconds)
    logger.error("no se pudo asegurar el indice de OpenSearch tras varios intentos")


app = FastAPI(title="TERO Security SIEM Service", version="0.1.0", lifespan=lifespan)
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
    return {"status": "ok", "service": "siem-service"}


@app.post("/logs/ingest", response_model=IngestLogsResponse, status_code=status.HTTP_201_CREATED)
async def ingest_logs(
    payload: IngestLogsRequest,
    x_ingest_token: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    # El token maestro (servicios internos) escribe en cualquier org; un token
    # derivado (forwarder externo de un tenant) solo en SU organizacion.
    if not ingest_token_valid(x_ingest_token, payload.organization_id or DEFAULT_ORGANIZATION_ID):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de ingesta invalido")
    indexed, alerts_created = await services.ingest_events(db, os_client, payload)
    await db.commit()
    logs_ingested_total.inc(indexed)
    return IngestLogsResponse(indexed=indexed, alerts_created=alerts_created)


@app.get("/logs/ingest-token")
async def get_org_ingest_token(claims: dict = Depends(require_role("admin"))):
    """Token de ingesta para forwarders EXTERNOS de la organizacion del admin
    (header X-Ingest-Token, con organization_id en el body). Solo sirve para
    esta organizacion; no es el token maestro de los servicios internos."""
    token = org_ingest_token(org_id_from_claims(claims))
    if token is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SIEM_INGEST_TOKEN no esta configurado")
    return {"organization_id": org_id_from_claims(claims), "header": "X-Ingest-Token", "token": token}


@app.get("/logs/search")
async def search_logs(
    q: str | None = None,
    host: str | None = None,
    size: int = 100,
    claims: dict = Depends(get_current_claims),
):
    return await services.search_logs(os_client, org_id_from_claims(claims), q, host, min(size, 500))


@app.get("/rules", response_model=list[SigmaRuleOut])
async def list_rules(
    enabled_only: bool = False, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)
):
    return await services.list_rules(db, org_id_from_claims(claims), enabled_only)


@app.post("/rules", response_model=SigmaRuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: SigmaRuleCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    rule = await services.create_rule(db, payload, org_id_from_claims(claims))
    await db.commit()
    logger.info("regla sigma creada", extra={"rule_id": rule.id, "actor": claims.get("sub")})
    return rule


@app.patch("/rules/{rule_id}", response_model=SigmaRuleOut)
async def update_rule(
    rule_id: str,
    payload: SigmaRuleUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    rule = await services.get_rule(db, rule_id, org_id_from_claims(claims))
    if rule is None:
        raise HTTPException(status_code=404, detail="Regla no encontrada")
    rule = await services.update_rule(db, rule, payload)
    await db.commit()
    return rule


@app.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    rule = await services.get_rule(db, rule_id, org_id_from_claims(claims))
    if rule is None:
        raise HTTPException(status_code=404, detail="Regla no encontrada")
    await services.delete_rule(db, rule)
    await db.commit()
    logger.info("regla sigma borrada", extra={"rule_id": rule_id, "actor": claims.get("sub")})


@app.post("/rules/seed-defaults", response_model=list[SigmaRuleOut])
async def seed_default_rules(
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    created = await services.seed_default_rules(db, org_id_from_claims(claims))
    await db.commit()
    logger.info("reglas por defecto cargadas", extra={"cantidad": len(created), "actor": claims.get("sub")})
    return created


@app.get("/internal/rule-tags")
async def internal_rule_tags(
    claims: dict = Depends(require_service_token),
    db: AsyncSession = Depends(get_db),
):
    """Endpoint interno servicio-a-servicio (ej. purple-service): exige un JWT
    de servicio y la organizacion sale de SUS claims (org_id), no de un
    query param -- antes era anonimo y aceptaba cualquier organization_id.
    Expone solo id/nombre/tags de reglas habilitadas, para que
    purple-service calcule cobertura contra tecnicas MITRE ATT&CK."""
    rules = await services.list_rules(db, org_id_from_claims(claims), enabled_only=True)
    return [{"id": r.id, "name": r.name, "tags": r.tags} for r in rules]


@app.get("/alerts", response_model=list[AlertOut])
async def list_alerts(
    status_filter: str | None = None,
    severity: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_alerts(db, org_id_from_claims(claims), status_filter, severity)


@app.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    alert = await services.get_alert(db, alert_id, org_id_from_claims(claims))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    return alert


@app.patch("/alerts/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: str,
    payload: AlertUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    alert = await services.get_alert(db, alert_id, org_id_from_claims(claims))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    alert = await services.update_alert(db, alert, payload, claims.get("sub", ""))
    await db.commit()
    alerts_created_total.labels(severity=alert.severity.value).inc(0)  # asegura la serie en /metrics
    return alert
