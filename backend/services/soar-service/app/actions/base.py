"""Interfaz comun para acciones de playbook. TODAS las acciones son de
CONTENCION/RESPUESTA DEFENSIVA (bloquear una IP en el perimetro, aislar un
host de la red, abrir un caso) -- nunca acciones ofensivas. Ademas, por
defecto corren en modo DRY-RUN (SOAR_DRY_RUN=true): registran la accion que
*se ejecutaria* sin llamar a ningun sistema real, porque los conectores
reales contra firewall/EDR/NAC los provee integration-service (Fase 5, no
implementado todavia). Cuando ese servicio exista, un ActionExecutor real
puede reemplazar el dry-run sin tocar el modelo de playbooks."""
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


def dry_run_enabled() -> bool:
    return os.getenv("SOAR_DRY_RUN", "true").lower() != "false"


@dataclass
class ActionResult:
    success: bool
    message: str
    simulated: bool = True
    details: dict = field(default_factory=dict)


class ActionExecutor(ABC):
    action_name: str

    @abstractmethod
    async def execute(self, params: dict, context: dict) -> ActionResult:
        """`context` trae la alerta que disparo el playbook (ver
        services.trigger_playbooks): permite resolver valores como
        '{{event.source.ip}}' en los params del step."""
        ...
