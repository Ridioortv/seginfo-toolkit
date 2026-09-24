"""Business logic for notification-service: envio de notificaciones a
canales configurables. Por defecto corre en modo DRY-RUN
(NOTIFICATION_DRY_RUN=true, igual que SOAR_DRY_RUN en soar-service): el
envio se registra como 'simulated' sin hacer ninguna llamada de red real a
la URL/SMTP configurada por el usuario en el canal. Solo si un operador
pone NOTIFICATION_DRY_RUN=false esta plataforma intenta el envio real."""
import base64
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.models import NotificationChannel, NotificationLog

logger = configure_logging("notification-service")


def dry_run_enabled() -> bool:
    return os.getenv("NOTIFICATION_DRY_RUN", "true").lower() != "false"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_channel(db: AsyncSession, payload, organization_id: str) -> NotificationChannel:
    channel = NotificationChannel(
        organization_id=organization_id,
        name=payload.name,
        channel_type=payload.channel_type,
        config=payload.config,
        enabled=payload.enabled,
    )
    db.add(channel)
    await db.flush()
    return channel


async def list_channels(db: AsyncSession, organization_id: str) -> list[NotificationChannel]:
    result = await db.execute(
        select(NotificationChannel)
        .where(NotificationChannel.organization_id == organization_id)
        .order_by(NotificationChannel.created_at.desc())
    )
    return list(result.scalars().all())


async def get_channel(db: AsyncSession, channel_id: str, organization_id: str) -> NotificationChannel | None:
    channel = await db.get(NotificationChannel, channel_id)
    if channel is None or channel.organization_id != organization_id:
        return None
    return channel


async def update_channel(db: AsyncSession, channel: NotificationChannel, payload) -> NotificationChannel:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(channel, field, value)
    await db.flush()
    await db.refresh(channel)
    return channel


async def delete_channel(db: AsyncSession, channel: NotificationChannel) -> None:
    await db.delete(channel)
    await db.flush()


async def _send_email(
    channel: NotificationChannel, subject: str, body: str, attachments: list | None = None
) -> tuple[str, str]:
    """Envia via SMTP configurado por variables de entorno globales
    (SMTP_HOST/PORT/USER/PASSWORD) al destinatario definido en
    channel.config['smtp_to']. Nunca guarda credenciales en la base.
    Si vienen adjuntos (ej. un PDF de reporte programado), se agregan
    como partes MIME aparte -- un adjunto que no decodifica bien en
    base64 se ignora silenciosamente en vez de tumbar el envio del
    resto del mail."""
    smtp_host = os.getenv("SMTP_HOST", "")
    if not smtp_host:
        return "failed", "SMTP_HOST no configurado en el entorno"
    to_addr = channel.config.get("smtp_to", "")
    if not to_addr:
        return "failed", "el canal no tiene 'smtp_to' configurado"
    try:
        if attachments:
            msg = MIMEMultipart()
            msg.attach(MIMEText(body))
            for att in attachments:
                try:
                    raw = base64.b64decode(att.content_base64)
                except Exception:  # noqa: BLE001 -- adjunto invalido no debe tumbar el mail entero
                    continue
                part = MIMEApplication(raw, Name=att.filename)
                part["Content-Disposition"] = f'attachment; filename="{att.filename}"'
                msg.attach(part)
        else:
            msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = os.getenv("SMTP_FROM", "sentinelops@localhost")
        msg["To"] = to_addr
        with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as server:
            if os.getenv("SMTP_USER"):
                server.starttls()
                server.login(os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", ""))
            server.send_message(msg)
        return "sent", ""
    except Exception as exc:  # noqa: BLE001 -- reportamos cualquier fallo de envio, no lo escondemos
        return "failed", str(exc)


async def _send_webhook(channel: NotificationChannel, subject: str, body: str, severity: str) -> tuple[str, str]:
    url = channel.config.get("webhook_url", "")
    if not url:
        return "failed", "el canal no tiene 'webhook_url' configurado"
    payload = {"subject": subject, "body": body, "severity": severity, "source": "sentinelops"}
    if channel.channel_type == "slack_webhook":
        payload = {"text": f"*[{severity.upper()}] {subject}*\n{body}"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
        return "sent", ""
    except httpx.HTTPError as exc:
        return "failed", str(exc)


async def send_notification(
    db: AsyncSession,
    channel: NotificationChannel,
    subject: str,
    body: str,
    severity: str,
    attachments: list | None = None,
) -> NotificationLog:
    if not channel.enabled:
        status_, error = "failed", "canal deshabilitado"
    elif dry_run_enabled():
        status_, error = "simulated", ""
        logger.info("notificacion simulada (dry-run)", extra={"channel_id": channel.id, "subject": subject})
    elif channel.channel_type == "email":
        status_, error = await _send_email(channel, subject, body, attachments)
    else:
        status_, error = await _send_webhook(channel, subject, body, severity)

    log = NotificationLog(
        organization_id=channel.organization_id,
        channel_id=channel.id,
        channel_type=channel.channel_type,
        subject=subject,
        body=body,
        severity=severity,
        status=status_,
        error=error,
    )
    db.add(log)
    await db.flush()
    return log


async def notify(db: AsyncSession, payload) -> list[NotificationLog]:
    organization_id = payload.organization_id or DEFAULT_ORGANIZATION_ID
    query = select(NotificationChannel).where(
        NotificationChannel.enabled == True,  # noqa: E712
        NotificationChannel.organization_id == organization_id,
    )
    if payload.channel_ids:
        query = query.where(NotificationChannel.id.in_(payload.channel_ids))
    result = await db.execute(query)
    channels = list(result.scalars().all())
    logs = []
    for channel in channels:
        log = await send_notification(db, channel, payload.subject, payload.body, payload.severity, payload.attachments)
        logs.append(log)
    return logs


async def list_logs(db: AsyncSession, organization_id: str, limit: int = 100) -> list[NotificationLog]:
    result = await db.execute(
        select(NotificationLog)
        .where(NotificationLog.organization_id == organization_id)
        .order_by(NotificationLog.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
