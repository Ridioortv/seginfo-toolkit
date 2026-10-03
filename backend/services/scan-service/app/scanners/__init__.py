"""Registro de drivers de escaneo disponibles, todos de solo-deteccion."""
from app.models import ScannerType
from app.scanners.base import ScannerDriver
from app.scanners.trivy import TrivyDriver
from app.scanners.nuclei import NucleiDriver

DRIVERS: dict[ScannerType, ScannerDriver] = {
    ScannerType.trivy: TrivyDriver(),
    ScannerType.nuclei: NucleiDriver(),
}


def get_driver(scanner_type: ScannerType) -> ScannerDriver:
    return DRIVERS[scanner_type]
