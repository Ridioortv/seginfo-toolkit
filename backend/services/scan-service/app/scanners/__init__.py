"""Registro de drivers de escaneo disponibles, todos de solo-deteccion.

trivy/nuclei son los originales; zap/semgrep/gitleaks/yara/zeek/falco
se sumaron por directiva explicita de Manu (2026) a partir del
documento de expansion comercial/licencias ("DIRECTIVAS DE EXPANSION
COMERCIAL") -- unicamente herramientas cuya licencia permite venderlas
como parte de este producto sin problema (Apache-2.0/MIT/BSD-3-Clause/
LGPL-2.1-via-subprocess, nunca estaticamente linkeadas). Zeek y Falco
son "jobs de duracion fija" (ver sus docstrings) en vez de escaneos
puntuales -- decision de producto que acepta su complejidad de
despliegue extra (NET_RAW/NET_ADMIN, eBPF/kernel) a cambio de la
cobertura adicional."""
from app.models import ScannerType
from app.scanners.base import ScannerDriver
from app.scanners.trivy import TrivyDriver
from app.scanners.nuclei import NucleiDriver
from app.scanners.zap import ZapDriver
from app.scanners.semgrep import SemgrepDriver
from app.scanners.gitleaks import GitleaksDriver
from app.scanners.yara import YaraDriver
from app.scanners.zeek import ZeekDriver
from app.scanners.falco import FalcoDriver

DRIVERS: dict[ScannerType, ScannerDriver] = {
    ScannerType.trivy: TrivyDriver(),
    ScannerType.nuclei: NucleiDriver(),
    ScannerType.zap: ZapDriver(),
    ScannerType.semgrep: SemgrepDriver(),
    ScannerType.gitleaks: GitleaksDriver(),
    ScannerType.yara: YaraDriver(),
    ScannerType.zeek: ZeekDriver(),
    ScannerType.falco: FalcoDriver(),
}


def get_driver(scanner_type: ScannerType) -> ScannerDriver:
    return DRIVERS[scanner_type]
