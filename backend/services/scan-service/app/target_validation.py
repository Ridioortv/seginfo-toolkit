"""Validacion del `target` de un escaneo antes de que llegue a cualquier
driver (nmap/nuclei/trivy/openvas) o al agente remoto.

Los drivers ya usan `asyncio.create_subprocess_exec` (nunca `shell=True`),
asi que no hay inyeccion de shell clasica -- pero `target` viaja como un
argumento posicional (nmap, trivy) o interpolado en una query GMP/XML
(openvas), y sin validar:

- Un target que empieza con "-" (ej. "--script=exploit" o "-oN /etc/cron.d/x")
  se puede interpretar como una OPCION de nmap/trivy en vez de como el
  objetivo, permitiendo saltarse las flags fijas (`--script default,safe`)
  o escribir un archivo arbitrario dentro del contenedor.
- openvas.py interpola `target` directo en un string XML
  (`f"<get_vulns filter='rows=200 host={target}'/>"`) -- un target con
  comillas o `<`/`>` rompe ese filtro GMP.

Esta validacion se aplica UNA sola vez, en los schemas Pydantic de
entrada (ScanJobCreate/ScanScheduleCreate/AgentScanJobCreate), asi que
cualquier target que llegue a un driver o al agente remoto ya paso por
aca."""
import re

# Letras/numeros, '.', ':', '/', '@', '_', '-' -- alcanza para hostnames,
# IPv4/IPv6, CIDR, URLs de nuclei y referencias de imagen de trivy
# (registry/repo:tag o repo@sha256:digest). Tiene que empezar y terminar
# con un caracter alfanumerico, asi que un target no puede empezar con
# "-" (se interpretaria como flag) ni terminar en un separador colgante.
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:/@-]{0,498}[A-Za-z0-9])?$")


def validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("el target no puede estar vacio")
    if not _SAFE_TARGET_RE.match(target):
        raise ValueError(
            "target invalido -- solo se permiten letras, numeros, '.', ':', '/', '@', '_' y '-', "
            "y no puede empezar con '-' (se interpretaria como una opcion de linea de comandos)"
        )
    return target
