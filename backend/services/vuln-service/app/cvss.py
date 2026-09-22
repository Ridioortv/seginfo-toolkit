"""Calculadora de CVSS v3.1 Base Score a partir del vector string, sin
dependencias externas ni llamadas de red (pura funcion matematica sobre
datos declarados por el usuario)."""

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # depende de Scope, se resuelve en compute_base_score
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.5},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def compute_base_score(vector: str) -> float | None:
    """Devuelve el CVSS v3.1 Base Score (0.0-10.0) o None si el vector es
    invalido/incompleto. Formula oficial de FIRST.org."""
    metrics = _parse_vector(vector)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics.keys()):
        return None

    scope_changed = metrics["S"] == "C"
    try:
        av = _WEIGHTS["AV"][metrics["AV"]]
        ac = _WEIGHTS["AC"][metrics["AC"]]
        pr = _WEIGHTS["PR"][metrics["PR"]]["C" if scope_changed else "U"]
        ui = _WEIGHTS["UI"][metrics["UI"]]
        c = _WEIGHTS["C"][metrics["C"]]
        i = _WEIGHTS["I"][metrics["I"]]
        a = _WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)

    return _round_up(base)


def _round_up(value: float) -> float:
    """Round-up-to-1-decimal segun la especificacion oficial de CVSS."""
    import math

    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10
