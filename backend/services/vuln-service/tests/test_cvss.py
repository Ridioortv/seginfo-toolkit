"""Tests para app/cvss.py (calculadora CVSS v3.1 Base Score, pura, sin red).

Los vectores usados son ejemplos de referencia publicos y ampliamente
citados (calculadora oficial de FIRST.org) para poder verificar el score
esperado sin tener que reimplementar la formula en el test:
  - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  -> 9.8  (ej. tipo EternalBlue)
  - AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  -> 10.0 (Log4Shell, CVE-2021-44228)
"""
from app.cvss import compute_base_score


def test_known_vector_9_8_no_scope_change():
    score = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8


def test_known_vector_10_0_scope_changed_capped():
    # Scope:Changed multiplica por 1.08 y el resultado se capea en 10.0.
    score = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score == 10.0


def test_no_impact_vector_scores_zero():
    score = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0


def test_missing_required_metric_returns_none():
    # Falta "A" (Availability) -> vector invalido/incompleto.
    score = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
    assert score is None


def test_unknown_metric_value_returns_none():
    score = compute_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is None


def test_empty_vector_returns_none():
    assert compute_base_score("") is None


def test_higher_privileges_required_lowers_score():
    low_priv = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    high_priv = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
    assert high_priv < low_priv
