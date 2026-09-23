"""Accion 'create_ticket': abre un ticket en un sistema externo de
ticketing (ej. Jira) a partir de una alerta, via integration-service
(que es quien tiene el conector real configurado -- ver Connector
kind='ticketing' y app/services.py _call_jira de integration-service).
Mismo patron dry-run que block_ip/isolate_host/create_case: en
SOAR_DRY_RUN=true (default) solo simula; si esta en false, delega en
integration-service, que a su vez tiene su propio dry-run
(INTEGRATION_DRY_RUN) hasta que un operador configure un conector de
ticketing real."""
import os
import httpx
from app.actions.base import ActionExecutor, ActionResult, dry_run_enabled

INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://integration-service:8000")


class CreateTicketAction(ActionExecutor):
    action_name = "create_ticket"

    async def execute(self, params: dict, context: dict) -> ActionResult:
        alert = context.get("alert", {})
        title = params.get("title") or f"Alerta {alert.get('severity', 'desconocida')}: {alert.get('rule_name', '')}"
        description = params.get("description") or f"Generado automaticamente por playbook a partir de la alerta {alert.get('id', '')}"
        priority = params.get("priority") or alert.get("severity", "medium")
        connector_id = params.get("connector_id")

        if dry_run_enabled():
            return ActionResult(
                success=True,
                simulated=True,
                message=f"[DRY-RUN] Se simularia la apertura de un ticket: {title}",
                details={"title": title},
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{INTEGRATION_SERVICE_URL}/internal/actions/create-ticket",
                    json={
                        "title": title, "description": description, "priority": priority,
                        "connector_id": connector_id, "organization_id": context.get("organization_id"),
                    },
                )
                response.raise_for_status()
                result = response.json()
        except httpx.HTTPError as exc:
            return ActionResult(
                success=False,
                simulated=False,
                message=f"No se pudo contactar a integration-service para crear el ticket: {exc}",
                details={"title": title},
            )

        extra = f" -- {result.get('external_url')}" if result.get("external_url") else ""
        return ActionResult(
            success=result.get("status") in ("executed", "simulated"),
            simulated=result.get("status") == "simulated",
            message=f"integration-service reporto status='{result.get('status')}' para el ticket '{title}'"
            + (f" ({result.get('error')})" if result.get("error") else "")
            + extra,
            details={"title": title, "integration_result": result},
        )
