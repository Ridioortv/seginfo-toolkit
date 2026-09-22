"""Accion 'isolate_host': aislamiento de red de un host comprometido
(EDR/NAC). Mismo patron dry-run que block_ip, delegando en
integration-service cuando SOAR_DRY_RUN=false (ver app/actions/block_ip.py
y app/actions/base.py)."""
import os
import httpx
from app.actions.block_ip import _resolve_field
from app.actions.base import ActionExecutor, ActionResult, dry_run_enabled

INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://integration-service:8000")


class IsolateHostAction(ActionExecutor):
    action_name = "isolate_host"

    async def execute(self, params: dict, context: dict) -> ActionResult:
        host = params.get("host") or _resolve_field(context, params.get("field", "host.name"))
        if not host:
            return ActionResult(success=False, message="No se encontro un host para aislar en el contexto de la alerta")

        if dry_run_enabled():
            return ActionResult(
                success=True,
                simulated=True,
                message=f"[DRY-RUN] Se simularia el aislamiento de red del host {host}",
                details={"host": host},
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(f"{INTEGRATION_SERVICE_URL}/internal/actions/isolate-host", json={"hostname": host})
                response.raise_for_status()
                result = response.json()
        except httpx.HTTPError as exc:
            return ActionResult(
                success=False,
                simulated=False,
                message=f"No se pudo contactar a integration-service para aislar {host}: {exc}",
                details={"host": host},
            )

        return ActionResult(
            success=result.get("status") in ("executed", "simulated"),
            simulated=result.get("status") == "simulated",
            message=f"integration-service reporto status='{result.get('status')}' para el aislamiento de {host}"
            + (f" ({result.get('error')})" if result.get("error") else ""),
            details={"host": host, "integration_result": result},
        )
