"""Interfaz comun para drivers de escaneo. Todos los drivers son de SOLO
DETECCION: descubren puertos/servicios/paquetes/CVEs conocidos, nunca
ejecutan payloads de explotacion contra el objetivo."""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


_PERMISSION_HINT = (
    " | Si un volumen de Docker quedo con dueno root, corre: docker compose exec -u root scan-service "
    "chown -R sentinelops:sentinelops /root/.cache/trivy /root/nuclei-templates /home/sentinelops"
)


def clean_stderr(text: str, limit: int = 2000) -> str:
    """stderr de un scanner listo para guardarse en error_message: sin codigos de
    color ANSI (nuclei los imprime aunque no haya TTY), acotado, y con la receta
    de arreglo cuando es el tipico 'permission denied' de un volumen con dueno
    root (cache de trivy / plantillas de nuclei)."""
    out = _ANSI_RE.sub("", text or "").strip()
    if "permission denied" in out.lower():
        return out[: limit - len(_PERMISSION_HINT)] + _PERMISSION_HINT
    return out[:limit]


@dataclass
class ScanResult:
    raw_output: str
    findings: list[dict] = field(default_factory=list)
    # Solo lo llena TrivyDriver: inventario COMPLETO de paquetes detectados
    # (no solo los que tienen CVE, a diferencia de `findings`). El resto de
    # los drivers lo deja vacio.
    packages: list[dict] = field(default_factory=list)
    error: str | None = None


class ScannerDriver(ABC):
    """Un driver ejecuta el binario del scanner en modo deteccion y normaliza
    la salida a una lista de findings (ver schemas.Finding)."""

    binary_name: str

    def is_available(self) -> bool:
        import shutil

        return shutil.which(self.binary_name) is not None

    @abstractmethod
    async def run(self, target: str, options: dict) -> ScanResult:
        ...
