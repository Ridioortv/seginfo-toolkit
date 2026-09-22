"""Accion 'create_case': abre un caso de incidente a partir de una alerta.
case-service (Fase 4) todavia no existe, asi que esta accion primero intenta
notificar a CASE_SERVICE_URL (best-effort, por si en un despliegue ya esta
arriba) y si no responde guarda la solicitud como PendingCase en la propia
base de soar-service, para que case-service la pueda importar cuando se
implemente. Nunca se pierde la solicitud de apertura de caso."""
import os
import httpx
from app.actions.base import ActionExecutor, ActionResult
from app.models import PendingCase
from backend.shared.logging import configure_logging

logger = configure_logging("soar-service.create_case")
CASE_SERVICE_URL = os.getenv("CASE_SERVICE_URL", "")


class CreateCaseAction(ActionExecutor):
    action_name = "create_case"

    async def execute(self, params: dict, context: dict) -> ActionResult:
        alert = context.get("alert", {})
        title = params.get("title") or f"Alerta {alert.get('severity', 'desconocida')}: {alert.get('rule_name', '')}"
        description = params.get("description") or f"Generado automaticamente por playbook a partir de la alerta {alert.get('id', '')}"
        priority = params.get("priority") or alert.get("severity", "medium")

        if CASE_SERVICE_URL:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.post(
                        f"{CASE_SERVICE_URL}/cases",
                        json={"title": title, "description": description, "priority": priority, "alert_id": alert.get("id")},
                    )
                    if resp.status_code < 300:
                        return ActionResult(
                            success=True, simulated=False,
                            message=f"Caso creado en case-service: {title}",
                            details={"title": title, "case_service": True},
                        )
            except httpx.HTTPError as exc:
                logger.info("case-service no disponible, se guarda como PendingCase", extra={"error": str(exc)})

        db = context.get("db")
        if db is not None:
            pending = PendingCase(
                title=title, description=description, priority=priority,
                alert_id=alert.get("id"), playbook_run_id=context.get("playbook_run_id"),
            )
            db.add(pending)
            await db.flush()
            return ActionResult(
                success=True, simulated=True,
                message=f"case-service no disponible todavia: caso guardado como pendiente ({title})",
                details={"title": title, "pending_case_id": pending.id},
            )

        return ActionResult(success=False, message="No se pudo crear ni encolar el caso: sin sesion de base de datos")
