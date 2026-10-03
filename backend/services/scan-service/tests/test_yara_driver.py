"""Tests para app/scanners/yara.py -- parseo de la salida de linea de
comandos de yara, sin ejecutar el binario de verdad."""
from app.scanners.yara import parse_yara_output


def test_parse_output_extracts_rule_and_file():
    raw = "SentinelOps_EICAR_Test_File /tmp/uploads/eicar.com\n"
    findings = parse_yara_output(raw)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SentinelOps_EICAR_Test_File"
    assert findings[0]["file_path"] == "/tmp/uploads/eicar.com"
    assert findings[0]["severity"] == "info"


def test_parse_output_known_rule_severity_mapping():
    raw = "SentinelOps_PHP_Obfuscated_Webshell_Pattern /var/www/shell.php\n"
    findings = parse_yara_output(raw)
    assert findings[0]["severity"] == "critical"


def test_parse_output_unknown_rule_defaults_to_medium():
    raw = "AlgunaReglaNoListada /tmp/archivo.bin\n"
    findings = parse_yara_output(raw)
    assert findings[0]["severity"] == "medium"


def test_parse_output_ignores_match_string_detail_lines():
    # Con -s, yara imprime debajo de cada match las cadenas que
    # matchearon, formato real "0xOFFSET:$id: contenido" -- SIN
    # indentacion (bug real encontrado en produccion: el formato real no
    # trae tab/espacio como se asumio originalmente). No son un hallazgo
    # nuevo -- un nombre de regla YARA nunca empieza con un digito, asi
    # que "0x..." es inequivocamente una linea de detalle, nunca un
    # "REGLA archivo".
    raw = "SentinelOps_EICAR_Test_File /tmp/eicar.com\n0x0:$eicar: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR...\n"
    findings = parse_yara_output(raw)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SentinelOps_EICAR_Test_File"


def test_parse_output_ignores_indented_match_strings_too():
    # Por si una version futura de yara SI indenta esa linea -- deberia
    # seguir funcionando igual (el offset de yara -s siempre es hex,
    # "0x...", nunca decimal).
    raw = "SentinelOps_EICAR_Test_File /tmp/eicar.com\n\t0x44:$eicar: X5O!...\n"
    findings = parse_yara_output(raw)
    assert len(findings) == 1


def test_parse_output_multiple_matches():
    raw = "RuleA /tmp/a.txt\nRuleB /tmp/b.txt\n"
    findings = parse_yara_output(raw)
    assert len(findings) == 2


def test_parse_output_empty_returns_empty():
    assert parse_yara_output("") == []
