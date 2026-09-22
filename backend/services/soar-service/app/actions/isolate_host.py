"""Accion 'isolate_host': aislamiento de red de un host comprometido (EDR/NAC).
Mismo patron dry-run que block_ip (ver app/actions/base.py)."""
from app.actions.block_ip import _resolve_field
from app.actions.base import ActionExecutor, ActionResult, dry_run_enabled


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

        return ActionResult(
            success=False,
            simulated=False,
            message=f"No hay un conector de EDR/NAC real configurado para aislar {host}",
            details={"host": host},
        )
