"""Tests para app/enrichment.py::compute_priority_score (funcion pura de
priorizacion 0-100, sin llamadas de red -- las llamadas HTTP a NVD/EPSS/KEV
del resto del modulo no se ejercitan aca, ver docs/architecture.md sobre
por que esas fuentes son de solo lectura/best-effort)."""
from app.enrichment import compute_priority_score


def test_no_data_scores_zero():
    assert compute_priority_score(None, None, False, "medium") == 0.0


def test_critical_cvss_high_epss_kev_confirmed_caps_at_100():
    score = compute_priority_score(9.8, 0.9, True, "critical")
    assert score == 100.0


def test_kev_confirmed_always_scores_higher_than_not():
    base_kwargs = dict(cvss_score=5.0, epss_score=0.2, asset_criticality="medium")
    with_kev = compute_priority_score(is_kev=True, **base_kwargs)
    without_kev = compute_priority_score(is_kev=False, **base_kwargs)
    assert with_kev > without_kev
    assert with_kev - without_kev == 25.0  # kev_bonus fijo


def test_asset_criticality_multiplier_orders_scores():
    kwargs = dict(cvss_score=6.0, epss_score=0.3, is_kev=False)
    low = compute_priority_score(asset_criticality="low", **kwargs)
    medium = compute_priority_score(asset_criticality="medium", **kwargs)
    high = compute_priority_score(asset_criticality="high", **kwargs)
    critical = compute_priority_score(asset_criticality="critical", **kwargs)
    assert low < medium < high < critical


def test_unknown_criticality_falls_back_to_neutral_multiplier():
    kwargs = dict(cvss_score=6.0, epss_score=0.3, is_kev=False)
    unknown = compute_priority_score(asset_criticality="not-a-real-value", **kwargs)
    medium = compute_priority_score(asset_criticality="medium", **kwargs)
    assert unknown == medium


def test_score_never_exceeds_100_or_goes_negative():
    high = compute_priority_score(10.0, 1.0, True, "critical")
    low = compute_priority_score(0.0, 0.0, False, "low")
    assert 0.0 <= low <= 100.0
    assert 0.0 <= high <= 100.0
