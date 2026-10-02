"""Tests de app/gvm_manage.py (configs/credenciales/targets/reportes del
dashboard de OpenVAS) -- sin gvmd real: las funciones de parseo/construccion
de XML se testean con XML fabricado, y los wrappers async mockeando
gvm_query (monkeypatch de app.gvm_manage.gvm_query), igual que
test_openvas_driver.py hace con las funciones que comparte este modulo."""
import asyncio
import base64

import app.gvm_manage as gm


# ---- _parse_named_entities ----

def test_parse_named_entities_configs():
    xml = (
        "<get_configs_response>"
        "<config id='c1'><name>Full and fast</name></config>"
        "<config id='c2'><name>Discovery</name></config>"
        "</get_configs_response>"
    )
    assert gm._parse_named_entities(xml, "config") == [
        {"id": "c1", "name": "Full and fast"},
        {"id": "c2", "name": "Discovery"},
    ]


def test_parse_named_entities_with_extra_tags():
    xml = (
        "<get_credentials_response>"
        "<credential id='x'><name>root-ssh</name><login>root</login><type>up</type></credential>"
        "</get_credentials_response>"
    )
    assert gm._parse_named_entities(xml, "credential", extra_tags=("login", "type")) == [
        {"id": "x", "name": "root-ssh", "login": "root", "type": "up"}
    ]


def test_parse_named_entities_skips_items_without_id():
    xml = "<get_configs_response><config><name>sin id</name></config></get_configs_response>"
    assert gm._parse_named_entities(xml, "config") == []


def test_parse_named_entities_invalid_xml():
    assert gm._parse_named_entities("no es xml", "config") == []


# ---- _parse_targets_xml ----

def test_parse_targets_xml_full():
    xml = (
        "<get_targets_response><target id='t1'>"
        "<name>Oficina</name><hosts>192.168.1.0/24</hosts>"
        "<port_list id='pl1'/><ssh_lsc_credential id='cred1'/>"
        "</target></get_targets_response>"
    )
    assert gm._parse_targets_xml(xml) == [{
        "id": "t1", "name": "Oficina", "hosts": "192.168.1.0/24",
        "port_list_id": "pl1", "ssh_credential_id": "cred1", "smb_credential_id": None,
    }]


def test_parse_targets_xml_no_credentials():
    xml = (
        "<get_targets_response><target id='t2'>"
        "<name>Sin auth</name><hosts>10.0.0.5</hosts><port_list id='pl1'/>"
        "</target></get_targets_response>"
    )
    parsed = gm._parse_targets_xml(xml)
    assert parsed[0]["ssh_credential_id"] is None
    assert parsed[0]["smb_credential_id"] is None


# ---- _parse_tasks_xml ----

def test_parse_tasks_xml_filters_by_prefix_and_parses_report():
    xml = (
        "<get_tasks_response>"
        "<task id='tk1'><name>sentinelops-192.168.1.5-123</name><status>Done</status>"
        "<progress>100</progress><target id='t1'/>"
        "<last_report><report id='rep1'/></last_report></task>"
        "<task id='tk2'><name>otra-task-creada-a-mano</name><status>New</status>"
        "<progress>0</progress></task>"
        "</get_tasks_response>"
    )
    tasks = gm._parse_tasks_xml(xml)
    assert len(tasks) == 1
    assert tasks[0] == {
        "id": "tk1", "name": "sentinelops-192.168.1.5-123", "status": "Done",
        "progress": 100, "target_id": "t1", "last_report_id": "rep1",
    }


def test_parse_tasks_xml_no_prefix_filter_when_empty_string():
    xml = "<get_tasks_response><task id='tk2'><name>manual</name><status>New</status></task></get_tasks_response>"
    assert gm._parse_tasks_xml(xml, name_prefix="") == [
        {"id": "tk2", "name": "manual", "status": "New", "progress": 0, "target_id": None, "last_report_id": None}
    ]


# ---- _extract_base64_report ----

def test_extract_base64_report_decodes_payload():
    payload = base64.b64encode(b"%PDF-1.4 contenido falso").decode()
    xml = f"<get_reports_response><report format_id='fmt1'>{payload}</report></get_reports_response>"
    assert gm._extract_base64_report(xml) == b"%PDF-1.4 contenido falso"


def test_extract_base64_report_native_xml_has_no_format_id():
    # Sin format_id (reporte nativo, ver get_report_xml) no hay nada que
    # decodificar -- eso lo pide get_report_xml, no export_report.
    xml = "<get_reports_response><report id='rep1'><results/></report></get_reports_response>"
    assert gm._extract_base64_report(xml) is None


def test_extract_base64_report_invalid_base64():
    xml = "<get_reports_response><report format_id='fmt1'>no-es-base64!!!</report></get_reports_response>"
    assert gm._extract_base64_report(xml) is None


# ---- _build_create_credential_xml ----

def test_build_create_credential_xml_escapes_special_chars():
    xml = gm._build_create_credential_xml("nombre & raro", "user<1>", "p&ss")
    assert "&amp;" in xml
    assert "&lt;1&gt;" in xml
    assert "p&amp;ss" in xml
    assert "<type>up</type>" in xml


# ---- Wrappers async (gvm_query mockeado) ----

def _patch_gvm_query(monkeypatch_fn):
    original = gm.gvm_query
    gm.gvm_query = monkeypatch_fn
    return original


def _restore_gvm_query(original):
    gm.gvm_query = original


def test_list_credentials_success():
    async def fake(socket_path, user, password, xml, timeout=60):
        assert xml == "<get_credentials/>"
        return 0, (
            "<get_credentials_response><credential id='c1'><name>x</name>"
            "<login>u</login><type>up</type></credential></get_credentials_response>"
        ), ""

    original = _patch_gvm_query(fake)
    try:
        ok, creds, err = asyncio.run(gm.list_credentials("/sock", "admin", "pw"))
    finally:
        _restore_gvm_query(original)
    assert ok is True
    assert creds == [{"id": "c1", "name": "x", "login": "u", "type": "up"}]
    assert err == ""


def test_list_credentials_gvm_error():
    async def fake(socket_path, user, password, xml, timeout=60):
        return 1, "", "gvmd no responde"

    original = _patch_gvm_query(fake)
    try:
        ok, creds, err = asyncio.run(gm.list_credentials("/sock", "admin", "pw"))
    finally:
        _restore_gvm_query(original)
    assert ok is False
    assert creds == []
    assert "gvmd no responde" in err


def test_create_credential_success():
    async def fake(socket_path, user, password, xml, timeout=60):
        assert "<create_credential>" in xml
        return 0, "<create_credential_response status='201' id='newcred'/>", ""

    original = _patch_gvm_query(fake)
    try:
        ok, cred_id, err = asyncio.run(gm.create_credential("/sock", "admin", "pw", "nombre", "user", "secret"))
    finally:
        _restore_gvm_query(original)
    assert ok is True
    assert cred_id == "newcred"
    assert err == ""


def test_create_credential_gvmd_rejects():
    async def fake(socket_path, user, password, xml, timeout=60):
        return 0, "<create_credential_response status='400' status_text='ya existe'/>", ""

    original = _patch_gvm_query(fake)
    try:
        ok, cred_id, err = asyncio.run(gm.create_credential("/sock", "admin", "pw", "nombre", "user", "secret"))
    finally:
        _restore_gvm_query(original)
    assert ok is False
    assert cred_id is None


def test_delete_credential_success():
    async def fake(socket_path, user, password, xml, timeout=60):
        assert xml == "<delete_credential credential_id='c1'/>"
        return 0, "<delete_credential_response status='200'/>", ""

    original = _patch_gvm_query(fake)
    try:
        ok, err = asyncio.run(gm.delete_credential("/sock", "admin", "pw", "c1"))
    finally:
        _restore_gvm_query(original)
    assert ok is True


def test_create_target_with_credentials():
    seen_xml = {}

    async def fake(socket_path, user, password, xml, timeout=60):
        seen_xml["xml"] = xml
        return 0, "<create_target_response status='201' id='newtarget'/>", ""

    original = _patch_gvm_query(fake)
    try:
        ok, target_id, err = asyncio.run(
            gm.create_target("/sock", "admin", "pw", "Oficina", "192.168.1.0/24", "pl1", ssh_credential_id="cred1")
        )
    finally:
        _restore_gvm_query(original)
    assert ok is True
    assert target_id == "newtarget"
    assert "<ssh_lsc_credential id='cred1'/>" in seen_xml["xml"]


def test_list_tasks_only_returns_sentinelops_tasks():
    async def fake(socket_path, user, password, xml, timeout=60):
        return 0, (
            "<get_tasks_response>"
            "<task id='tk1'><name>sentinelops-10.0.0.1-1</name><status>Done</status>"
            "<progress>100</progress></task>"
            "<task id='tk2'><name>manual</name><status>New</status></task>"
            "</get_tasks_response>"
        ), ""

    original = _patch_gvm_query(fake)
    try:
        ok, tasks, err = asyncio.run(gm.list_tasks("/sock", "admin", "pw"))
    finally:
        _restore_gvm_query(original)
    assert ok is True
    assert len(tasks) == 1 and tasks[0]["id"] == "tk1"


def test_export_report_pdf_roundtrip():
    async def fake(socket_path, user, password, xml, timeout=60):
        if xml == "<get_report_formats/>":
            return 0, "<get_report_formats_response><report_format id='fmtpdf'><name>PDF</name></report_format></get_report_formats_response>", ""
        if "format_id='fmtpdf'" in xml:
            payload = base64.b64encode(b"pdf-bytes-here").decode()
            return 0, f"<get_reports_response><report format_id='fmtpdf'>{payload}</report></get_reports_response>", ""
        raise AssertionError(f"comando gmp inesperado: {xml}")

    original = _patch_gvm_query(fake)
    try:
        ok, content, filename, err = asyncio.run(gm.export_report("/sock", "admin", "pw", "rep1", "pdf"))
    finally:
        _restore_gvm_query(original)
    assert ok is True
    assert content == b"pdf-bytes-here"
    assert filename == "sentinelops-report-rep1.pdf"


def test_export_report_unsupported_format_never_calls_gvm():
    async def fake(socket_path, user, password, xml, timeout=60):
        raise AssertionError("no deberia llamar a gvmd con un formato no soportado")

    original = _patch_gvm_query(fake)
    try:
        ok, content, filename, err = asyncio.run(gm.export_report("/sock", "admin", "pw", "rep1", "docx"))
    finally:
        _restore_gvm_query(original)
    assert ok is False
    assert "no soportado" in err


def test_export_report_format_not_installed_in_gvmd():
    async def fake(socket_path, user, password, xml, timeout=60):
        if xml == "<get_report_formats/>":
            return 0, "<get_report_formats_response></get_report_formats_response>", ""
        raise AssertionError("no deberia pedir el reporte si no se encontro el formato")

    original = _patch_gvm_query(fake)
    try:
        ok, content, filename, err = asyncio.run(gm.export_report("/sock", "admin", "pw", "rep1", "pdf"))
    finally:
        _restore_gvm_query(original)
    assert ok is False
    assert "no tiene instalado" in err


# --- Regression: credential_id/target_id/task_id/report_id vienen DIRECTO
# de un path param de la URL (DELETE /openvas/credentials/{id}, etc, ver
# main.py) sin ninguna validacion de formato -- antes se interpolaban sin
# escapar en un atributo XML delimitado por comillas simples, asi que una
# comilla simple en el id cortaba el atributo e inyectaba un comando GMP
# adicional (ver test_gvm_xml_attr_injection.py para el mismo bug del lado
# de app/scanners/openvas.py). Estos tests confirman que lo que
# efectivamente se manda a gvmd via gvm_query queda escapado.

def test_delete_credential_escapes_malicious_id():
    payload = "c1'/><delete_task task_id='victim'/><delete_credential credential_id='"
    seen_xml = {}

    async def fake(socket_path, user, password, xml, timeout=60):
        seen_xml["xml"] = xml
        return 0, "<delete_credential_response status='200'/>", ""

    original = _patch_gvm_query(fake)
    try:
        asyncio.run(gm.delete_credential("/sock", "admin", "pw", payload))
    finally:
        _restore_gvm_query(original)
    assert "<delete_task" not in seen_xml["xml"]
    assert "&apos;" in seen_xml["xml"]


def test_delete_target_escapes_malicious_id():
    payload = "t1'/><get_credentials/><delete_target target_id='"
    seen_xml = {}

    async def fake(socket_path, user, password, xml, timeout=60):
        seen_xml["xml"] = xml
        return 0, "<delete_target_response status='200'/>", ""

    original = _patch_gvm_query(fake)
    try:
        asyncio.run(gm.delete_target("/sock", "admin", "pw", payload))
    finally:
        _restore_gvm_query(original)
    assert "<get_credentials" not in seen_xml["xml"]
    assert "&apos;" in seen_xml["xml"]


def test_delete_task_escapes_malicious_id():
    payload = "tk1'/><delete_target target_id='victim'/><delete_task task_id='"
    seen_xml = {}

    async def fake(socket_path, user, password, xml, timeout=60):
        seen_xml["xml"] = xml
        return 0, "<delete_task_response status='200'/>", ""

    original = _patch_gvm_query(fake)
    try:
        asyncio.run(gm.delete_task("/sock", "admin", "pw", payload))
    finally:
        _restore_gvm_query(original)
    assert "<delete_target" not in seen_xml["xml"]
    assert "&apos;" in seen_xml["xml"]


def test_get_report_xml_escapes_malicious_report_id():
    payload = "rep1'/><delete_task task_id='victim'/><get_reports report_id='"
    seen_xml = {}

    async def fake(socket_path, user, password, xml, timeout=60):
        seen_xml["xml"] = xml
        return 0, "<get_reports_response status='200'></get_reports_response>", ""

    original = _patch_gvm_query(fake)
    try:
        asyncio.run(gm.get_report_xml("/sock", "admin", "pw", payload))
    finally:
        _restore_gvm_query(original)
    assert "<delete_task" not in seen_xml["xml"]
    assert "&apos;" in seen_xml["xml"]
