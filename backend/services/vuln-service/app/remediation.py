"""Genera pasos de remediacion legibles para un hallazgo, en base a los
datos que ya trae el registro (package/fixed_version, puerto/servicio,
CVE, KEV). Deliberadamente basado en reglas -- nada de IA generativa ni
llamadas externas -- para que sea determinista, explicable y no dependa de
que un servicio de terceros este arriba."""
from typing import Protocol


class RemediationSource(Protocol):
    """Lo minimo que necesitamos leer de una Vulnerability (o de cualquier
    objeto con los mismos atributos, ej. en un test)."""

    cve_id: str | None
    package: str
    installed_version: str
    fixed_version: str
    port: int | None
    service: str
    is_kev: bool
    severity: object  # str o VulnSeverity, se compara como string


def build_remediation_steps(vuln: RemediationSource) -> list[str]:
    steps: list[str] = []

    if vuln.package and vuln.fixed_version:
        installed = vuln.installed_version or "la version instalada actualmente"
        steps.append(
            f"Actualizar el paquete '{vuln.package}' de {installed} a la version corregida "
            f"'{vuln.fixed_version}' (o una mas nueva)."
        )
    elif vuln.package:
        steps.append(
            f"Revisar si el proveedor de '{vuln.package}' publico una version mas nueva que corrija esto "
            "-- el escaner no informo una version corregida especifica."
        )

    if vuln.port:
        service_txt = f" ({vuln.service})" if vuln.service else ""
        steps.append(
            f"Si el puerto {vuln.port}{service_txt} no necesita estar expuesto, cerrarlo o restringirlo "
            "por firewall solo a las IPs/redes que realmente lo necesitan."
        )

    if vuln.cve_id:
        steps.append(
            f"Revisar el aviso oficial de {vuln.cve_id} (NVD/proveedor) y aplicar el parche correspondiente."
        )

    if not steps:
        steps.append(
            "Revisar manualmente el hallazgo con el equipo tecnico y aplicar el hardening que corresponda "
            "segun el tipo de activo."
        )

    if vuln.is_kev:
        steps.insert(
            0,
            "Esta vulnerabilidad figura en el catalogo CISA KEV (explotada activamente en el mundo real) -- "
            "tratarla con prioridad maxima.",
        )

    steps.append(
        "Una vez aplicada la correccion, volver a escanear el activo para confirmar que el hallazgo ya no "
        "aparece, y marcar la vulnerabilidad como 'remediado' en la pestana de triage."
    )
    return steps
