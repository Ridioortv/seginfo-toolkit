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


def service_auth_headers(organization_id: str | None) -> dict:
    """Headers con un JWT de servicio-a-servicio de corta vida para llamar a
    integration-service/notification-service. Antes, block_ip/isolate_host/
    create_ticket/notify llamaban a los /internal/* del otro lado SIN
    ninguna credencial, y esos endpoints confiaban en el organization_id
    que mandaba este mismo payload sin verificar nada -- cualquiera que
    alcanzara el puerto publicado de integration-service/notification-
    service (ver docker-compose.yml) podia disparar un bloqueo/aislamiento/
    ticket/notificacion real contra el conector de OTRA organizacion.
    Mismo patron ya usado por scan-service -> vuln-service (ver
    scan-service/app/services.py)."""
    from backend.shared.security import create_access_token

    token = create_access_token("system:soar-service", "admin", org_id=organization_id)
    return {"Authorization": f"Bearer {token}"}


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
