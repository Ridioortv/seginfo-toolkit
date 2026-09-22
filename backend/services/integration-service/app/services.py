"""Business logic for integration-service: conectores genericos (webhook
REST) de contencion. Por defecto (INTEGRATION_DRY_RUN=true) NUNCA hace una
llamada de red real al 'base_url' configurado por el operador -- solo
registra la accion que se ejecutaria, igual que el patron SOAR_DRY_RUN de
soar-service. Un operador que quiera contencion real primero configura un
conector con su propio endpoint (por ejemplo un webhook intermedio que ya
tenga integrado con su firewall/EDR) y luego pone INTEGRATION_DRY_RUN=false
explicitamente."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import Connector, IntegrationActionLog

logger = configure_logging("integration-service")


def dry_run_enabled() -> bool:
    return os.getenv("INTEGRATION_DRY_RUN", "true").lower() != "false"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_connector(db: AsyncSession, payload) -> Connector:
    connector = Connector(name=payload.name, kind=payload.kind, config=payload.config, enabled=payload.enabled)
    db.add(connector)
    await db.flush()
    return connector


async def list_connectors(db: AsyncSession, kind: str | None = None) -> list[Connector]:
    query = select(Connector)
    if kind:
        query = query.where(Connector.kind == kind)
    result = await db.execute(query.order_by(Connector.created_at.desc()))
    return list(result.scalars().all())


async def _pick_connector(db: AsyncSession, kind: str, connector_id: str | None) -> Connector | None:
    if connector_id:
        result = await db.execute(select(Connector).where(Connector.id == connector_id, Connector.enabled == True))  # noqa: E712
    else:
        result = await db.execute(
            select(Connector).where(Connector.kind == kind, Connector.enabled == True).order_by(Connector.created_at.desc())  # noqa: E712
        )
    return result.scalars().first()


async def _call_connector(connector: Connector, action: str, payload: dict) -> tuple[str, str]:
    base_url = connector.config.get("base_url", "")
    if not base_url:
        return "failed", "el conector no tiene 'base_url' configurado"
    headers = {}
    header_name = connector.config.get("header_name")
    if header_name and connector.config.get("api_key"):
        headers[header_name] = connector.config["api_key"]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{base_url.rstrip('/')}/{action}", json=payload, headers=headers)
            response.raise_for_status()
        return "executed", ""
    except httpx.HTTPError as exc:
        return "failed", str(exc)


async def run_action(db: AsyncSession, action: str, target: str, kind: str, connector_id: str | None) -> IntegrationActionLog:
    connector = await _pick_connector(db, kind, connector_id)
    if connector is None:
        status_, error, cid = "failed", f"no hay un conector de tipo '{kind}' habilitado y configurado", ""
    elif dry_run_enabled():
        status_, error, cid = "simulated", "", connector.id
        logger.info("accion de contencion simulada (dry-run)", extra={"action": action, "target": target, "connector_id": connector.id})
    else:
        status_, error = await _call_connector(connector, action, {"target": target})
        cid = connector.id

    log = IntegrationActionLog(connector_id=cid, action=action, target=target, status=status_, error=error)
    db.add(log)
    await db.flush()
    return log


async def block_ip(db: AsyncSession, ip: str, connector_id: str | None = None) -> IntegrationActionLog:
    return await run_action(db, "block_ip", ip, "firewall", connector_id)


async def isolate_host(db: AsyncSession, hostname: str, connector_id: str | None = None) -> IntegrationActionLog:
    return await run_action(db, "isolate_host", hostname, "edr", connector_id)


async def list_action_logs(db: AsyncSession, limit: int = 100) -> list[IntegrationActionLog]:
    result = await db.execute(select(IntegrationActionLog).order_by(IntegrationActionLog.created_at.desc()).limit(limit))
    return list(result.scalars().all())
