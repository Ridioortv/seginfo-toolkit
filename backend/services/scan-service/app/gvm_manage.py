"""Operaciones GMP de "gestion" para el dashboard de OpenVAS (configs de
escaneo, credenciales, targets guardados, tasks/reportes) -- separado de
app/scanners/openvas.py, que es el DRIVER que corre un escaneo puntual
(ScannerDriver.run) via la fila generica de scan jobs. Este modulo no
sabe nada de ScanJob/ScanResult: solo habla GMP con gvmd (reusando
gvm_query, ya extraida a nivel de modulo en openvas.py) y devuelve datos
livianos (dicts/tuplas) para que main.py los envuelva en sus propios
schemas Pydantic.

Todas las funciones publicas devuelven (ok: bool, datos, detalle_error:
str) -- nunca levantan por un fallo GMP esperado (gvmd caido, xml
invalido, credenciales vencidas): eso lo decide el endpoint que llama
(404/422/502 segun corresponda), igual que ya hace probe_connection en
openvas.py."""
import base64
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

from app.scanners.openvas import (
    _build_create_target_xml,
    _parse_response_id,
    _response_status_ok,
    gvm_query,
)

# Nombres de los formatos de reporte INCLUIDOS por defecto en toda
# instalacion de gvmd (ver docker-compose.yml, servicio "report-formats"
# -- son parte del feed base, no hace falta instalarlos aparte). Si en el
# futuro se suman mas formatos (ej. "CPE"), alcanza con agregar la entrada
# aca.
_EXPORT_FORMAT_NAMES = {"pdf": "PDF", "xml": "XML", "csv": "CSV Results"}
_EXPORT_FORMAT_EXTENSIONS = {"pdf": "pdf", "xml": "xml", "csv": "csv"}

# Todos los tasks que crea este sistema (ver OpenVasDriver.run) se llaman
# "sentinelops-{target}-{timestamp}" -- filtrar por este prefijo evita
# mostrar en el dashboard tasks que alguien haya creado por fuera (a mano
# con gvm-cli/gvm-tools), que no tienen ningun ScanJob nuestro asociado.
_TASK_NAME_PREFIX = "sentinelops-"


# --- Parseo (funciones puras, testeables sin gvmd real) --------------------

def _parse_named_entities(xml_text: str, item_tag: str, extra_tags: tuple[str, ...] = ()) -> list[dict]:
    """Parsea una respuesta get_X (configs/scanners/port_lists/
    report_formats/credentials) a una lista de {"id", "name", ...
    extra_tags}. extra_tags son sub-elementos de texto plano directos del
    item (ej. "login"/"type" para credenciales)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    items = []
    for item in root.findall(f".//{item_tag}"):
        item_id = item.get("id")
        if not item_id:
            continue
        name_el = item.find("name")
        entry = {"id": item_id, "name": name_el.text if name_el is not None and name_el.text else ""}
        for tag in extra_tags:
            el = item.find(tag)
            entry[tag] = el.text if el is not None and el.text else ""
        items.append(entry)
    return items


def _parse_targets_xml(xml_text: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    targets = []
    for t in root.findall(".//target"):
        target_id = t.get("id")
        if not target_id:
            continue
        name_el = t.find("name")
        hosts_el = t.find("hosts")
        port_list_el = t.find("port_list")
        ssh_el = t.find("ssh_lsc_credential")
        smb_el = t.find("smb_lsc_credential")
        targets.append({
            "id": target_id,
            "name": name_el.text if name_el is not None and name_el.text else "",
            "hosts": hosts_el.text if hosts_el is not None and hosts_el.text else "",
            "port_list_id": port_list_el.get("id") if port_list_el is not None else None,
            "ssh_credential_id": ssh_el.get("id") if ssh_el is not None and ssh_el.get("id") else None,
            "smb_credential_id": smb_el.get("id") if smb_el is not None and smb_el.get("id") else None,
        })
    return targets


def _parse_tasks_xml(xml_text: str, name_prefix: str = _TASK_NAME_PREFIX) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    tasks = []
    for task in root.findall(".//task"):
        task_id = task.get("id")
        if not task_id:
            continue
        name_el = task.find("name")
        name = name_el.text if name_el is not None and name_el.text else ""
        if name_prefix and not name.startswith(name_prefix):
            continue
        status_el = task.find("status")
        progress_el = task.find("progress")
        target_el = task.find("target")
        last_report_el = task.find("last_report/report")
        try:
            progress = int(progress_el.text) if progress_el is not None and progress_el.text else 0
        except (TypeError, ValueError):
            progress = 0
        tasks.append({
            "id": task_id,
            "name": name,
            "status": status_el.text if status_el is not None and status_el.text else "Unknown",
            "progress": progress,
            "target_id": target_el.get("id") if target_el is not None else None,
            "last_report_id": last_report_el.get("id") if last_report_el is not None else None,
        })
    return tasks


def _extract_base64_report(xml_text: str) -> bytes | None:
    """Cuando get_reports se llama CON format_id (ver export_report), gvmd
    corre el reporte por el conversor de ese formato y devuelve el
    resultado en base64 adentro de <report format_id='...'>...</report> --
    a diferencia de get_reports SIN format_id (get_report_xml), que
    devuelve el reporte nativo como XML anidado real."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    report_el = root.find(".//report[@format_id]")
    if report_el is None or not (report_el.text or "").strip():
        return None
    try:
        return base64.b64decode(report_el.text.strip())
    except (ValueError, TypeError):
        return None


# --- Construccion de XML (funciones puras) ----------------------------------

def _build_create_credential_xml(name: str, login: str, password: str) -> str:
    """Tipo 'up' (usuario+contraseña): sirve tanto para login SSH por
    contraseña como para SMB -- el par de credenciales autenticadas mas
    comun para un primer dashboard. GVM soporta otros tipos (clave
    privada SSH, SNMP, certificados de cliente) que quedan para una
    proxima etapa."""
    return (
        "<create_credential>"
        f"<name>{_xml_escape(name)}</name>"
        f"<login>{_xml_escape(login)}</login>"
        f"<password>{_xml_escape(password)}</password>"
        "<type>up</type>"
        "</create_credential>"
    )


# --- Wrappers async sobre GMP (usan gvm_query, ver app/scanners/openvas.py) -

async def list_configs(socket_path: str, user: str, password: str) -> tuple[bool, list[dict], str]:
    rc, out, err = await gvm_query(socket_path, user, password, "<get_configs/>")
    if rc != 0:
        return False, [], (err or out)[:1000]
    return True, _parse_named_entities(out, "config"), ""


async def list_port_lists(socket_path: str, user: str, password: str) -> tuple[bool, list[dict], str]:
    rc, out, err = await gvm_query(socket_path, user, password, "<get_port_lists/>")
    if rc != 0:
        return False, [], (err or out)[:1000]
    return True, _parse_named_entities(out, "port_list"), ""


async def list_report_formats(socket_path: str, user: str, password: str) -> tuple[bool, list[dict], str]:
    rc, out, err = await gvm_query(socket_path, user, password, "<get_report_formats/>")
    if rc != 0:
        return False, [], (err or out)[:1000]
    return True, _parse_named_entities(out, "report_format"), ""


async def list_credentials(socket_path: str, user: str, password: str) -> tuple[bool, list[dict], str]:
    rc, out, err = await gvm_query(socket_path, user, password, "<get_credentials/>")
    if rc != 0:
        return False, [], (err or out)[:1000]
    return True, _parse_named_entities(out, "credential", extra_tags=("login", "type")), ""


async def create_credential(
    socket_path: str, user: str, password: str, name: str, login: str, secret: str,
) -> tuple[bool, str | None, str]:
    xml = _build_create_credential_xml(name, login, secret)
    rc, out, err = await gvm_query(socket_path, user, password, xml)
    if rc != 0 or not _response_status_ok(out):
        return False, None, (err or out)[:1000]
    credential_id = _parse_response_id(out)
    if not credential_id:
        return False, None, "create_credential no devolvio un id de credencial"
    return True, credential_id, ""


async def delete_credential(socket_path: str, user: str, password: str, credential_id: str) -> tuple[bool, str]:
    rc, out, err = await gvm_query(socket_path, user, password, f"<delete_credential credential_id='{credential_id}'/>")
    if rc != 0 or not _response_status_ok(out):
        return False, (err or out)[:1000]
    return True, ""


async def list_targets(socket_path: str, user: str, password: str) -> tuple[bool, list[dict], str]:
    rc, out, err = await gvm_query(socket_path, user, password, "<get_targets/>")
    if rc != 0:
        return False, [], (err or out)[:1000]
    return True, _parse_targets_xml(out), ""


async def create_target(
    socket_path: str, user: str, password: str, name: str, hosts: str, port_list_id: str,
    ssh_credential_id: str | None = None, smb_credential_id: str | None = None,
) -> tuple[bool, str | None, str]:
    xml = _build_create_target_xml(name, hosts, port_list_id, ssh_credential_id, smb_credential_id)
    rc, out, err = await gvm_query(socket_path, user, password, xml)
    if rc != 0 or not _response_status_ok(out):
        return False, None, (err or out)[:1000]
    target_id = _parse_response_id(out)
    if not target_id:
        return False, None, "create_target no devolvio un id de target"
    return True, target_id, ""


async def delete_target(socket_path: str, user: str, password: str, target_id: str) -> tuple[bool, str]:
    rc, out, err = await gvm_query(socket_path, user, password, f"<delete_target target_id='{target_id}'/>")
    if rc != 0 or not _response_status_ok(out):
        return False, (err or out)[:1000]
    return True, ""


async def list_tasks(socket_path: str, user: str, password: str) -> tuple[bool, list[dict], str]:
    rc, out, err = await gvm_query(socket_path, user, password, "<get_tasks/>")
    if rc != 0:
        return False, [], (err or out)[:1000]
    return True, _parse_tasks_xml(out), ""


async def get_report_xml(socket_path: str, user: str, password: str, report_id: str) -> tuple[bool, str, str]:
    """Reporte NATIVO completo (todos los hosts/resultados/metadata de la
    corrida, no solo los findings resumidos que ya guarda ScanJob) -- para
    "ver el reporte completo" en el dashboard sin exportar ningun archivo."""
    rc, out, err = await gvm_query(
        socket_path, user, password, f"<get_reports report_id='{report_id}' details='1'/>", timeout=120,
    )
    if rc != 0:
        return False, "", (err or out)[:2000]
    return True, out, ""


async def export_report(
    socket_path: str, user: str, password: str, report_id: str, fmt: str,
) -> tuple[bool, bytes | None, str | None, str]:
    """Descarga el reporte convertido a un formato exportable (pdf/xml/csv).
    Devuelve (ok, contenido_bytes, nombre_de_archivo_sugerido, detalle_error)."""
    fmt_key = (fmt or "").strip().lower()
    format_name = _EXPORT_FORMAT_NAMES.get(fmt_key)
    if not format_name:
        return False, None, None, f"formato de exportacion no soportado: '{fmt}' (usar pdf, xml o csv)"

    rc, out, err = await gvm_query(socket_path, user, password, "<get_report_formats/>")
    if rc != 0:
        return False, None, None, (err or out)[:1000]
    formats = _parse_named_entities(out, "report_format")
    format_id = next((f["id"] for f in formats if f["name"].strip().lower() == format_name.lower()), None)
    if not format_id:
        return False, None, None, f"gvmd no tiene instalado el formato de reporte '{format_name}'"

    rc, out, err = await gvm_query(
        socket_path, user, password,
        f"<get_reports report_id='{report_id}' format_id='{format_id}' details='1'/>",
        timeout=120,
    )
    if rc != 0:
        return False, None, None, (err or out)[:2000]

    content = _extract_base64_report(out)
    if content is None:
        return False, None, None, "gvmd no devolvio contenido de reporte para este formato"

    ext = _EXPORT_FORMAT_EXTENSIONS[fmt_key]
    filename = f"sentinelops-report-{report_id[:8]}.{ext}"
    return True, content, filename, ""

