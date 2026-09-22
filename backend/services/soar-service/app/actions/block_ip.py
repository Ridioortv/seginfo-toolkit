"""Accion 'block_ip': bloqueo perimetral de una IP de origen marcada en la
alerta. En modo dry-run (default) solo registra la intencion; un conector
real de firewall se enchufaria aca en el futuro via integration-service."""
from app.actions.base import ActionExecutor, ActionResult, dry_run_enabled


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

        # Sin conector real configurado (integration-service, Fase 5): no se
        # ejecuta ninguna accion contra infraestructura real todavia.
        return ActionResult(
            success=False,
            simulated=False,
            message=f"No hay un conector de firewall real configurado para bloquear {ip}",
            details={"ip": ip},
        )


def _resolve_field(context: dict, dotted_path: str):
    node = context.get("event", {})
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node
