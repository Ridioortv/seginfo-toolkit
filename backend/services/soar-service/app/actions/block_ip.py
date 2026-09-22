"""Accion 'block_ip': bloqueo perimetral de una IP de origen marcada en la
alerta. En modo dry-run (default) solo registra la intencion. Si
SOAR_DRY_RUN=false, delega en integration-service (Fase 5), que a su vez
tiene su propio modo dry-run por defecto (INTEGRATION_DRY_RUN) hasta que un
operador configure un conector de firewall real."""
import os
import httpx
from app.actions.base import ActionExecutor, ActionResult, dry_run_enabled

INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://integration-service:8000")


class BlockIpAction(ActionExecutor):
    action_name = "block_ip"

    async def execute(self, params: dict, context: dict) -> ActionResult:
        ip = params.get("ip") or _resolve_field(context, params.get("field", "source.ip"))
        if not ip:
            return ActionResult(success=False, message="No se encontro una IP para bloquear en el contexto de la alerta")

        if dry_run_enabled():
            return ActionResult(
                success=True,
                simulated=True,
                message=f"[DRY-RUN] Se simularia el bloqueo perimetral de la IP {ip}",
                details={"ip": ip},
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(f"{INTEGRATION_SERVICE_URL}/internal/actions/block-ip", json={"ip": ip})
                response.raise_for_status()
                result = response.json()
        except httpx.HTTPError as exc:
            return ActionResult(
                success=False,
                simulated=False,
                message=f"No se pudo contactar a integration-service para bloquear {ip}: {exc}",
                details={"ip": ip},
            )

        return ActionResult(
            success=result.get("status") in ("executed", "simulated"),
            simulated=result.get("status") == "simulated",
            message=f"integration-service reporto status='{result.get('status')}' para el bloqueo de {ip}"
            + (f" ({result.get('error')})" if result.get("error") else ""),
            details={"ip": ip, "integration_result": result},
        )


def _resolve_field(context: dict, dotted_path: str):
    node = context.get("event", {})
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node
