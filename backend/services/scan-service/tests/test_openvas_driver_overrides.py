"""Tests de OpenVasDriver.run() para los overrides opcionales que agrega
el dashboard de OpenVAS (gvm_target_id/gvm_config_id/gvm_scanner_id/
gvm_port_list_id/gvm_ssh_credential_id/gvm_smb_credential_id, ver
app/gvm_manage.py y los endpoints /openvas/* en main.py) -- sin gvmd real:
se mockea app.scanners.openvas.gvm_query (ahora una funcion de modulo, ya
no un closure, justamente para poder mockearla asi) y se corren
escenarios con y sin overrides para confirmar que:
  1. sin overrides, el comportamiento es EXACTAMENTE el de antes
     (auto-discovery + crear un target nuevo sin autenticar).
  2. con gvm_target_id, NUNCA se llama a get_port_lists ni create_target
     -- se reusa el target tal cual.
  3. con gvm_config_id/gvm_scanner_id, se saltea su descubrimiento.
  4. con credenciales, el create_target incluye ssh_lsc_credential/
     smb_lsc_credential.
  5. el ScanResult final queda "marcado" con gvm_task_id (para que el
     dashboard pueda pedir despues el reporte completo/exportarlo)."""
import asyncio

import pytest

import app.scanners.openvas as openvas


@pytest.fixture(autouse=True)
def _fast_poll_interval():
    """_DEFAULT_POLL_INTERVAL son 15s reales (generoso para gvmd de
    verdad, ver openvas.py) -- sin bajarlo, cada test de este archivo que
    llega a "Done" en la primera consulta de get_tasks igual paga un
    asyncio.sleep(15) real antes de leerlo."""
    original = openvas._DEFAULT_POLL_INTERVAL
    openvas._DEFAULT_POLL_INTERVAL = 0
    yield
    openvas._DEFAULT_POLL_INTERVAL = original


def _patch_gvm_query(fake):
    original = openvas.gvm_query
    openvas.gvm_query = fake
    return original


def _restore_gvm_query(original):
    openvas.gvm_query = original


def _run(coro):
    return asyncio.run(coro)


def test_no_overrides_keeps_previous_autodiscovery_behavior():
    calls = []

    async def fake(socket_path, user, password, xml, timeout=60):
        calls.append(xml)
        if xml == "<get_configs/>":
            return 0, "<r><config id='cfg1'><name>Full and fast</name></config></r>", ""
        if xml == "<get_scanners/>":
            return 0, "<r><scanner id='scn1'><name>OpenVAS Default</name></scanner></r>", ""
        if xml == "<get_port_lists/>":
            return 0, "<r><port_list id='pl1'><name>All IANA assigned TCP</name></port_list></r>", ""
        if "<create_target>" in xml:
            assert "ssh_lsc_credential" not in xml and "smb_lsc_credential" not in xml
            return 0, "<create_target_response status='201' id='tgt1'/>", ""
        if "<create_task>" in xml:
            return 0, "<create_task_response status='201' id='task1'/>", ""
        if xml.startswith("<start_task"):
            return 0, "<start_task_response status='202'/>", ""
        if xml.startswith("<get_tasks"):
            return 0, "<r><task><status>Done</status><progress>100</progress></task></r>", ""
        if xml.startswith("<get_results"):
            return 0, "<r></r>", ""
        raise AssertionError(f"comando gmp inesperado: {xml}")

    driver = openvas.OpenVasDriver()
    driver.is_available = lambda: True
    original = _patch_gvm_query(fake)
    try:
        result = _run(driver.run("10.0.0.5", {"gvm_user": "admin", "gvm_password": "pw"}))
    finally:
        _restore_gvm_query(original)

    assert result.error is None
    assert getattr(result, "gvm_task_id", None) == "task1"
    assert "<get_configs/>" in calls
    assert "<get_scanners/>" in calls
    assert "<get_port_lists/>" in calls


def test_gvm_target_id_override_skips_port_list_and_create_target():
    calls = []

    async def fake(socket_path, user, password, xml, timeout=60):
        calls.append(xml)
        if xml == "<get_configs/>":
            return 0, "<r><config id='cfg1'><name>Full and fast</name></config></r>", ""
        if xml == "<get_scanners/>":
            return 0, "<r><scanner id='scn1'><name>OpenVAS Default</name></scanner></r>", ""
        if "<create_task>" in xml:
            # el target_id usado en create_task tiene que ser el override,
            # nunca uno recien creado
            assert "id='tgt-guardado'" in xml
            return 0, "<create_task_response status='201' id='task1'/>", ""
        if xml.startswith("<start_task"):
            return 0, "<start_task_response status='202'/>", ""
        if xml.startswith("<get_tasks"):
            return 0, "<r><task><status>Done</status><progress>100</progress></task></r>", ""
        if xml.startswith("<get_results"):
            return 0, "<r></r>", ""
        raise AssertionError(f"comando gmp inesperado (no deberia crear ni consultar targets/port_lists): {xml}")

    driver = openvas.OpenVasDriver()
    driver.is_available = lambda: True
    original = _patch_gvm_query(fake)
    try:
        result = _run(driver.run("10.0.0.5", {
            "gvm_user": "admin", "gvm_password": "pw", "gvm_target_id": "tgt-guardado",
        }))
    finally:
        _restore_gvm_query(original)

    assert result.error is None
    assert not any("get_port_lists" in c or "create_target" in c for c in calls)


def test_config_and_scanner_overrides_skip_their_discovery():
    calls = []

    async def fake(socket_path, user, password, xml, timeout=60):
        calls.append(xml)
        if xml == "<get_port_lists/>":
            return 0, "<r><port_list id='pl1'><name>All IANA</name></port_list></r>", ""
        if "<create_target>" in xml:
            return 0, "<create_target_response status='201' id='tgt1'/>", ""
        if "<create_task>" in xml:
            assert "id='cfg-override'" in xml and "id='scn-override'" in xml
            return 0, "<create_task_response status='201' id='task1'/>", ""
        if xml.startswith("<start_task"):
            return 0, "<start_task_response status='202'/>", ""
        if xml.startswith("<get_tasks"):
            return 0, "<r><task><status>Done</status><progress>100</progress></task></r>", ""
        if xml.startswith("<get_results"):
            return 0, "<r></r>", ""
        raise AssertionError(f"no deberia descubrir config/scanner cuando hay override: {xml}")

    driver = openvas.OpenVasDriver()
    driver.is_available = lambda: True
    original = _patch_gvm_query(fake)
    try:
        result = _run(driver.run("10.0.0.5", {
            "gvm_user": "admin", "gvm_password": "pw",
            "gvm_config_id": "cfg-override", "gvm_scanner_id": "scn-override",
        }))
    finally:
        _restore_gvm_query(original)

    assert result.error is None
    assert not any("get_configs" in c or "get_scanners" in c for c in calls)


def test_credentials_attached_when_creating_new_target():
    seen = {}

    async def fake(socket_path, user, password, xml, timeout=60):
        if xml == "<get_configs/>":
            return 0, "<r><config id='cfg1'><name>x</name></config></r>", ""
        if xml == "<get_scanners/>":
            return 0, "<r><scanner id='scn1'><name>x</name></scanner></r>", ""
        if xml == "<get_port_lists/>":
            return 0, "<r><port_list id='pl1'><name>x</name></port_list></r>", ""
        if "<create_target>" in xml:
            seen["create_target_xml"] = xml
            return 0, "<create_target_response status='201' id='tgt1'/>", ""
        if "<create_task>" in xml:
            return 0, "<create_task_response status='201' id='task1'/>", ""
        if xml.startswith("<start_task"):
            return 0, "<start_task_response status='202'/>", ""
        if xml.startswith("<get_tasks"):
            return 0, "<r><task><status>Done</status><progress>100</progress></task></r>", ""
        if xml.startswith("<get_results"):
            return 0, "<r></r>", ""
        raise AssertionError(f"comando gmp inesperado: {xml}")

    driver = openvas.OpenVasDriver()
    driver.is_available = lambda: True
    original = _patch_gvm_query(fake)
    try:
        result = _run(driver.run("10.0.0.5", {
            "gvm_user": "admin", "gvm_password": "pw",
            "gvm_ssh_credential_id": "sshcred1", "gvm_smb_credential_id": "smbcred1",
        }))
    finally:
        _restore_gvm_query(original)

    assert result.error is None
    assert "<ssh_lsc_credential id='sshcred1'/>" in seen["create_target_xml"]
    assert "<smb_lsc_credential id='smbcred1'/>" in seen["create_target_xml"]


def test_gvm_task_id_tagged_even_on_failed_start_task():
    async def fake(socket_path, user, password, xml, timeout=60):
        if xml == "<get_configs/>":
            return 0, "<r><config id='cfg1'><name>x</name></config></r>", ""
        if xml == "<get_scanners/>":
            return 0, "<r><scanner id='scn1'><name>x</name></scanner></r>", ""
        if xml == "<get_port_lists/>":
            return 0, "<r><port_list id='pl1'><name>x</name></port_list></r>", ""
        if "<create_target>" in xml:
            return 0, "<create_target_response status='201' id='tgt1'/>", ""
        if "<create_task>" in xml:
            return 0, "<create_task_response status='201' id='task1'/>", ""
        if xml.startswith("<start_task"):
            return 1, "", "gvmd rechazo el start_task"
        raise AssertionError(f"comando gmp inesperado: {xml}")

    driver = openvas.OpenVasDriver()
    driver.is_available = lambda: True
    original = _patch_gvm_query(fake)
    try:
        result = _run(driver.run("10.0.0.5", {"gvm_user": "admin", "gvm_password": "pw"}))
    finally:
        _restore_gvm_query(original)

    assert result.error is not None
    # Aunque el escaneo no arranco, el task SI se creo en gvmd -- el
    # dashboard puede seguir mostrando/borrando ese task a mano.
    assert getattr(result, "gvm_task_id", None) == "task1"
