"""Business logic for siem-service: ingesta -> normalizacion ECS -> indexado
en OpenSearch -> evaluacion de reglas Sigma habilitadas -> creacion de
Alert cuando corresponde -> notificacion best-effort a soar-service para
que evalue playbooks de respuesta. Todo es deteccion/analisis sobre datos
ya ingeridos; no se ejecuta ninguna accion contra el evento de origen."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.ecs import normalize_event
from app.sigma import evaluate_rule
from app.models import SigmaRule, Alert, AlertStatus
from app import opensearch_client

logger = configure_logging("siem-service")

SOAR_SERVICE_URL = os.getenv("SOAR_SERVICE_URL", "http://soar-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def ingest_events(db: AsyncSession, os_client, payload) -> tuple[int, int]:
    indexed = 0
    alerts_created = 0

    rules_result = await db.execute(select(SigmaRule).where(SigmaRule.is_enabled.is_(True)))
    enabled_rules = list(rules_result.scalars().all())

    for event_in in payload.events:
        document = normalize_event(event_in.model_dump())
        await opensearch_client.index_event(os_client, document)
        indexed += 1

        for rule in enabled_rules:
            try:
                matched = evaluate_rule(document, rule.detection)
            except Exception as exc:  # regla mal formada no debe tumbar la ingesta
                logger.warning("regla sigma invalida, se omite", extra={"rule_id": rule.id, "error": str(exc)})
                continue
            if matched:
                alert = await _create_alert(db, rule, document)
                alerts_created += 1
                await _notify_soar(alert)

    await db.flush()
    return indexed, alerts_created


async def _create_alert(db: AsyncSession, rule: SigmaRule, event: dict) -> Alert:
    alert = Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        matched_event=event,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)
    logger.info("alerta generada", extra={"alert_id": alert.id, "rule": rule.name, "severity": rule.severity.value})
    return alert


async def _notify_soar(alert: Alert) -> None:
    """Best-effort: si soar-service no responde, la alerta ya quedo guardada
    igual; esto solo dispara la evaluacion automatica de playbooks."""
    payload = {
        "alert_id": alert.id,
        "rule_name": alert.rule_name,
        "severity": alert.severity.value,
        "event": alert.matched_event,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SOAR_SERVICE_URL}/trigger", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo notificar a soar-service", extra={"alert_id": alert.id, "error": str(exc)})


async def create_rule(db: AsyncSession, payload) -> SigmaRule:
    rule = SigmaRule(**payload.model_dump())
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


async def list_rules(db: AsyncSession, enabled_only: bool = False) -> list[SigmaRule]:
    query = select(SigmaRule)
    if enabled_only:
        query = query.where(SigmaRule.is_enabled.is_(True))
    result = await db.execute(query.order_by(SigmaRule.name))
    return list(result.scalars().all())


async def get_rule(db: AsyncSession, rule_id: str) -> SigmaRule | None:
    return await db.get(SigmaRule, rule_id)


async def update_rule(db: AsyncSession, rule: SigmaRule, payload) -> SigmaRule:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    await db.flush()
    await db.refresh(rule)
    return rule


async def list_alerts(db: AsyncSession, status_filter: str | None = None, severity: str | None = None) -> list[Alert]:
    query = select(Alert)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
    result = await db.execute(query.order_by(Alert.created_at.desc()))
    return list(result.scalars().all())


async def get_alert(db: AsyncSession, alert_id: str) -> Alert | None:
    return await db.get(Alert, alert_id)


async def update_alert(db: AsyncSession, alert: Alert, payload, actor: str) -> Alert:
    alert.status = payload.status
    alert.notes = payload.notes
    if payload.status == AlertStatus.acknowledged:
        alert.acknowledged_by = actor
    await db.flush()
    await db.refresh(alert)
    return alert


async def search_logs(os_client, query_text: str | None, host: str | None, size: int) -> list[dict]:
    must = []
    if query_text:
        must.append({"match": {"message": query_text}})
    if host:
        must.append({"term": {"host.name": host}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    return await opensearch_client.search_events(os_client, query, size)
