"""Registro de drivers de escaneo disponibles, todos de solo-deteccion."""
from app.models import ScannerType
from app.scanners.base import ScannerDriver
from app.scanners.nmap import NmapDriver
from app.scanners.trivy import TrivyDriver
from app.scanners.nuclei import NucleiDriver
from app.scanners.openvas import OpenVasDriver

DRIVERS: dict[ScannerType, ScannerDriver] = {
    ScannerType.nmap: NmapDriver(),
    ScannerType.trivy: TrivyDriver(),
    ScannerType.nuclei: NucleiDriver(),
    ScannerType.openvas: OpenVasDriver(),
}


def get_driver(scanner_type: ScannerType) -> ScannerDriver:
    return DRIVERS[scanner_type]
