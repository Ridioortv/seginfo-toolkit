"""Regression tests para la inyeccion de XML/GMP via atributos sin
escapar en app/scanners/openvas.py y app/gvm_manage.py.

El bug real: _build_create_target_xml y _build_create_task_xml
interpolaban port_list_id/ssh_credential_id/smb_credential_id/target_id/
config_id/scanner_id DIRECTO en atributos XML delimitados por comillas
simples (`id='{valor}'`) sin ningun escape -- a diferencia de name/hosts,
que si pasaban por _xml_escape (seguro ahi porque son texto plano entre
tags, no atributos). Estos ids NO vienen siempre de gvmd: cuando el
usuario manda overrides en ScanJobCreate/ScanScheduleCreate.options
(gvm_config_id, gvm_scanner_id, gvm_port_list_id, gvm_target_id,
gvm_ssh_credential_id, gvm_smb_credential_id -- ver OpenVasDriver.run),
son texto libre sin ninguna validacion de formato. Mismo problema en
app/gvm_manage.py con credential_id/target_id/task_id/report_id, tomados
directo de un path param de la URL (DELETE /openvas/credentials/{id},
etc.) -- un path param puede ser literalmente cualquier string.

Con una comilla simple en cualquiera de esos valores, un usuario
autenticado (con rol analyst, el minimo que ya puede lanzar un escaneo
openvas o pegarle al dashboard) podia cortar el atributo e inyectar
CUALQUIER comando GMP adicional en la sesion ya autenticada contra gvmd
(borrar/crear tasks, leer reportes de otra organizacion, lo que sea que
GMP permita) -- el XML resultante terminaba con una tag GMP extra que
gvm-cli mandaba igual.

El fix: _xml_attr (igual que _xml_escape pero tambien escapa la comilla
simple, la unica que _xml_escape no toca) envuelve todos estos valores
antes de interpolarlos."""
from app.scanners.openvas import _build_create_target_xml, _build_create_task_xml, _xml_attr
import xml.etree.ElementTree as ET


class TestXmlAttrHelper:
    def test_escapes_single_quote(self):
        assert _xml_attr("pl'222") == "pl&apos;222"

    def test_escapes_ampersand_and_angle_brackets_too(self):
        assert _xml_attr("a&b<c>d") == "a&amp;b&lt;c&gt;d"

    def test_noop_for_an_ordinary_gvmd_uuid(self):
        # Los ids que SI vienen de gvmd (UUIDs) no tienen ninguno de estos
        # caracteres -- el escape no les cambia nada (ver los tests de
        # abajo, que siguen pasando con la misma aserción de antes del fix).
        assert _xml_attr("bbb-222") == "bbb-222"


class TestCreateTargetXmlInjection:
    def test_malicious_port_list_id_cannot_break_out_of_the_attribute(self):
        # Intento de inyeccion: cerrar el atributo id='...' con una
        # comilla simple y agregar una tag GMP extra (<delete_task .../>)
        # como si fuera un elemento hermano de <port_list/>.
        payload = "pl1'/><delete_task task_id='victim'/><port_list id='"
        xml = _build_create_target_xml("t1", "10.0.0.1", payload)

        # El payload entero debe seguir siendo el VALOR del atributo
        # port_list -- nunca aparecer como una tag GMP real en el XML.
        root = ET.fromstring(xml)
        assert root.tag == "create_target"
        assert len(root.findall(".//delete_task")) == 0
        assert root.find("port_list").get("id") == payload

    def test_malicious_ssh_credential_id_cannot_break_out(self):
        payload = "c1'/><modify_setting setting_id='x'><value>pwned</value></modify_setting><ssh_lsc_credential id='"
        xml = _build_create_target_xml("t1", "10.0.0.1", "pl-222", ssh_credential_id=payload)

        root = ET.fromstring(xml)
        assert len(root.findall(".//modify_setting")) == 0
        assert root.find("ssh_lsc_credential").get("id") == payload


class TestCreateTaskXmlInjection:
    def test_malicious_config_id_cannot_inject_a_sibling_command(self):
        payload = "cfg1'/><delete_task task_id='victim'/><config id='"
        xml = _build_create_task_xml("t1", "target-1", payload, "scanner-1")

        root = ET.fromstring(xml)
        assert root.tag == "create_task"
        assert len(root.findall(".//delete_task")) == 0
        assert root.find("config").get("id") == payload

    def test_malicious_target_id_override_cannot_inject(self):
        # Caso real: options["gvm_target_id"] llega directo como
        # target_id a _build_create_task_xml cuando el usuario elige un
        # target guardado en vez de que el driver cree uno nuevo.
        payload = "tgt1'/><get_credentials/><target id='"
        xml = _build_create_task_xml("t1", payload, "config-1", "scanner-1")

        root = ET.fromstring(xml)
        assert len(root.findall(".//get_credentials")) == 0
        assert root.find("target").get("id") == payload

    def test_ordinary_ids_round_trip_unchanged(self):
        # Mismo caso que ya cubria test_openvas_driver.py -- sigue
        # funcionando igual para ids sin caracteres especiales.
        xml = _build_create_task_xml("t1", "target-1", "config-1", "scanner-1")
        assert "target id='target-1'" in xml
        assert "config id='config-1'" in xml
        assert "scanner id='scanner-1'" in xml
