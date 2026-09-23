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
from backend.shared.crypto import encrypt_secret, decrypt_secret
from app.models import Connector, IntegrationActionLog, TicketLog

logger = configure_logging("integration-service")

# Claves de 'config' que son credenciales (no URLs, headers ni otros datos
# de conexion) -- se cifran en la base (ver _encrypt_secret_fields) y se
# ocultan en cualquier respuesta de la API (ver redact_connector_config).
# Antes se guardaban y devolvian en texto plano: cualquier usuario
# autenticado de la organizacion (no solo un admin) podia leer /connectors
# y ver el api_key/api_token real de firewall/EDR/Jira, y cualquiera con
# acceso de lectura a la base podia leerlos de ahi directamente.
_SECRET_CONFIG_KEYS = ("api_key", "api_token")


def _encrypt_secret_fields(config: dict) -> dict:
    out = dict(config)
    for key in _SECRET_CONFIG_KEYS:
        if out.get(key):
            out[key] = encrypt_secret(out[key])
    return out


def _decrypt_secret_fields(config: dict) -> dict:
    out = dict(config)
    for key in _SECRET_CONFIG_KEYS:
        if out.get(key):
            out[key] = decrypt_secret(out[key])
    return out


def redact_connector_config(config: dict) -> dict:
    """Para cualquier respuesta HTTP (ConnectorOut) -- nunca se devuelve el
    valor cifrado ni, mucho menos, el plano. Mismo criterio que
    SsoConfigOut en auth-service (que jamas incluye client_secret)."""
    out = dict(config)
    for key in _SECRET_CONFIG_KEYS:
        if out.get(key):
            out[key] = "••••••••"
    return out


def dry_run_enabled() -> bool:
    return os.getenv("INTEGRATION_DRY_RUN", "true").lower() != "false"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_connector(db: AsyncSession, payload, organization_id: str) -> Connector:
    connector = Connector(
        organization_id=organization_id, name=payload.name, kind=payload.kind,
        config=_encrypt_secret_fields(payload.config), enabled=payload.enabled,
    )
    db.add(connector)
    await db.flush()
    return connector


async def list_connectors(db: AsyncSession, organization_id: str, kind: str | None = None) -> list[Connector]:
    query = select(Connector).where(Connector.organization_id == organization_id)
    if kind:
        query = query.where(Connector.kind == kind)
    result = await db.execute(query.order_by(Connector.created_at.desc()))
    return list(result.scalars().all())


async def _pick_connector(
    db: AsyncSession, kind: str, connector_id: str | None, organization_id: str
) -> Connector | None:
    """organization_id siempre filtra, incluso cuando se pide un
    connector_id especifico -- sin esto, una organizacion podria disparar
    una accion de contencion real usando el conector (firewall/EDR/Jira)
    configurado por OTRA organizacion con solo adivinar/probar un uuid."""
    if connector_id:
        result = await db.execute(
            select(Connector).where(
                Connector.id == connector_id, Connector.organization_id == organization_id,
                Connector.enabled == True,  # noqa: E712
            )
        )
    else:
        result = await db.execute(
            select(Connector)
            .where(Connector.kind == kind, Connector.organization_id == organization_id, Connector.enabled == True)  # noqa: E712
            .order_by(Connector.created_at.desc())
        )
    return result.scalars().first()


async def _call_connector(connector: Connector, action: str, payload: dict) -> tuple[str, str]:
    base_url = connector.config.get("base_url", "")
    if not base_url:
        return "failed", "el conector no tiene 'base_url' configurado"
    headers = {}
    header_name = connector.config.get("header_name")
    if header_name and connector.config.get("api_key"):
        # api_key esta cifrado en la base (ver _encrypt_secret_fields) --
        # se descifra aca, en el momento exacto de uso, sin tocar
        # connector.config (evita persistir el texto plano de vuelta).
        headers[header_name] = decrypt_secret(connector.config["api_key"])
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{base_url.rstrip('/')}/{action}", json=payload, headers=headers)
            response.raise_for_status()
        return "executed", ""
    except httpx.HTTPError as exc:
        return "failed", str(exc)


async def run_action(
    db: AsyncSession, action: str, target: str, kind: str, connector_id: str | None, organization_id: str
) -> IntegrationActionLog:
    connector = await _pick_connector(db, kind, connector_id, organization_id)
    if connector is None:
        status_, error, cid = "failed", f"no hay un conector de tipo '{kind}' habilitado y configurado", ""
    elif dry_run_enabled():
        status_, error, cid = "simulated", "", connector.id
        logger.info("accion de contencion simulada (dry-run)", extra={"action": action, "target": target, "connector_id": connector.id})
    else:
        status_, error = await _call_connector(connector, action, {"target": target})
        cid = connector.id

    log = IntegrationActionLog(
        organization_id=organization_id, connector_id=cid, action=action, target=target, status=status_, error=error
    )
    db.add(log)
    await db.flush()
    return log


async def block_ip(db: AsyncSession, ip: str, organization_id: str, connector_id: str | None = None) -> IntegrationActionLog:
    return await run_action(db, "block_ip", ip, "firewall", connector_id, organization_id)


async def isolate_host(
    db: AsyncSession, hostname: str, organization_id: str, connector_id: str | None = None
) -> IntegrationActionLog:
    return await run_action(db, "isolate_host", hostname, "edr", connector_id, organization_id)


async def list_action_logs(db: AsyncSession, organization_id: str, limit: int = 100) -> list[IntegrationActionLog]:
    result = await db.execute(
        select(IntegrationActionLog)
        .where(IntegrationActionLog.organization_id == organization_id)
        .order_by(IntegrationActionLog.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def _call_jira(connector: Connector, title: str, description: str, priority: str) -> tuple[str, str, str, str]:
    """Devuelve (status, error, external_key, external_url). Usa la API
    v2 de Jira (Cloud o Server/Data Center) porque acepta 'description'
    como texto plano -- la v3 exige Atlassian Document Format, que
    complicaria innecesariamente un conector pensado para ser generico.
    El campo 'priority' de Jira solo se manda si el conector define
    'priority_map': los nombres de prioridad son especificos de cada
    instancia de Jira (varian segun el esquema configurado) y adivinarlos
    puede tirar un 400 -- mejor omitirlo que fallar la creacion del
    ticket por un campo secundario."""
    base_url = connector.config.get("base_url", "").rstrip("/")
    email = connector.config.get("email", "")
    # api_token esta cifrado en la base -- se descifra solo aca, en el
    # momento exacto de uso (ver _encrypt_secret_fields/_decrypt_secret_fields).
    api_token = decrypt_secret(connector.config.get("api_token", ""))
    project_key = connector.config.get("project_key", "")
    issue_type = connector.config.get("issue_type", "Task")
    priority_map = connector.config.get("priority_map", {})

    if not (base_url and email and api_token and project_key):
        return (
            "failed",
            "el conector no tiene 'base_url'/'email'/'api_token'/'project_key' configurados",
            "",
            "",
        )

    fields: dict = {
        "project": {"key": project_key},
        "summary": title,
        "description": description,
        "issuetype": {"name": issue_type},
    }
    jira_priority = priority_map.get(priority)
    if jira_priority:
        fields["priority"] = {"name": jira_priority}

    try:
        async with httpx.AsyncClient(timeout=10.0, auth=(email, api_token)) as client:
            response = await client.post(f"{base_url}/rest/api/2/issue", json={"fields": fields})
            response.raise_for_status()
            data = response.json()
        key = data.get("key", "")
        url = f"{base_url}/browse/{key}" if key else ""
        return "executed", "", key, url
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        return "failed", detail, "", ""
    except httpx.HTTPError as exc:
        return "failed", str(exc), "", ""


async def create_ticket(
    db: AsyncSession, title: str, description: str, priority: str, connector_id: str | None, organization_id: str
) -> TicketLog:
    connector = await _pick_connector(db, "ticketing", connector_id, organization_id)
    if connector is None:
        status_, error, key, url, cid = (
            "failed",
            "no hay un conector de tipo 'ticketing' habilitado y configurado",
            "",
            "",
            "",
        )
    elif dry_run_enabled():
        status_, error, key, url, cid = "simulated", "", "", "", connector.id
        logger.info("apertura de ticket simulada (dry-run)", extra={"title": title, "connector_id": connector.id})
    else:
        status_, error, key, url = await _call_jira(connector, title, description, priority)
        cid = connector.id

    log = TicketLog(
        organization_id=organization_id,
        connector_id=cid, title=title, priority=priority, status=status_,
        external_key=key, external_url=url, error=error,
    )
    db.add(log)
    await db.flush()
    return log


async def list_ticket_logs(db: AsyncSession, organization_id: str, limit: int = 100) -> list[TicketLog]:
    result = await db.execute(
        select(TicketLog)
        .where(TicketLog.organization_id == organization_id)
        .order_by(TicketLog.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
