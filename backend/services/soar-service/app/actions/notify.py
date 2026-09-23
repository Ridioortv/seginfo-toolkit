"""Accion 'notify': manda una alerta a los canales configurados en
notification-service (email/Slack/webhook generico) cuando corre un
playbook -- ej. para avisar por Slack de una alerta critica sin abrir
necesariamente un caso o bloquear nada. Mismo patron dry-run que
block_ip/isolate_host: en SOAR_DRY_RUN=true (default) solo simula; si
esta en false, llama de verdad a notification-service (que a su vez
tiene su PROPIO modo dry-run, NOTIFICATION_DRY_RUN, hasta que un
operador lo desactive tambien) -- llama a POST /internal/notify (sin
auth de usuario, pensado para llamadas servicio-a-servicio dentro de la
red de docker-compose, mismo patron que /internal/actions/* de
integration-service)."""
import os
import httpx
from app.actions.base import ActionExecutor, ActionResult, dry_run_enabled

NOTIFICATION_SERVICE_URL = os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8000")


class NotifyAction(ActionExecutor):
    action_name = "notify"

    async def execute(self, params: dict, context: dict) -> ActionResult:
        alert = context.get("alert", {})
        subject = params.get("subject") or f"SentinelOps - Alerta {alert.get('severity', '')}: {alert.get('rule_name', '')}"
        body = params.get("body") or f"El playbook disparo esta notificacion a partir de la alerta {alert.get('id', '')}."
        channel_ids = params.get("channel_ids")  # None = todos los canales habilitados

        if dry_run_enabled():
            return ActionResult(
                success=True,
                simulated=True,
                message=f"[DRY-RUN] Se simularia la notificacion '{subject}'",
                details={"subject": subject},
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{NOTIFICATION_SERVICE_URL}/internal/notify",
                    json={
                        "subject": subject,
                        "body": body,
                        "severity": alert.get("severity", "info"),
                        "channel_ids": channel_ids,
                    },
                )
                response.raise_for_status()
                result = response.json()
        except httpx.HTTPError as exc:
            return ActionResult(
                success=False,
                simulated=False,
                message=f"No se pudo contactar a notification-service: {exc}",
                details={"subject": subject},
            )

        statuses = [r.get("status") for r in result.get("results", [])]
        return ActionResult(
            success=bool(statuses) and all(s in ("sent", "simulated") for s in statuses),
            simulated=bool(statuses) and all(s == "simulated" for s in statuses),
            message=f"notification-service proceso {len(statuses)} canal(es): {statuses}"
            if statuses
            else "notification-service no proceso ningun canal (sin canales habilitados)",
            details={"subject": subject, "notify_result": result},
        )
