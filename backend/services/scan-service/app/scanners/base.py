"""Interfaz comun para drivers de escaneo. Todos los drivers son de SOLO
DETECCION: descubren puertos/servicios/paquetes/CVEs conocidos, nunca
ejecutan payloads de explotacion contra el objetivo."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    raw_output: str
    findings: list[dict] = field(default_factory=list)
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
