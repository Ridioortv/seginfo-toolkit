"""Registro de acciones de playbook disponibles (todas defensivas/dry-run
por defecto, ver base.py)."""
from app.actions.base import ActionExecutor
from app.actions.block_ip import BlockIpAction
from app.actions.isolate_host import IsolateHostAction
from app.actions.create_case import CreateCaseAction

ACTIONS: dict[str, ActionExecutor] = {
    "block_ip": BlockIpAction(),
    "isolate_host": IsolateHostAction(),
    "create_case": CreateCaseAction(),
}


def get_action(name: str) -> ActionExecutor:
    if name not in ACTIONS:
        raise KeyError(f"Accion de playbook desconocida: {name}")
    return ACTIONS[name]
