"""Resuelve y acota options.duration_minutes para los drivers de
'duracion fija' (Zeek, Falco) -- los unicos escaneres de esta
plataforma que no terminan solos contra un target puntual, sino que
corren durante una ventana de tiempo fija (decision de producto
explicita, ver docstring de app/scanners/zeek.py) y reportan lo que
detectaron en ese lapso, como si fuera un escaneo mas."""

DEFAULT_DURATION_MINUTES = 5
MIN_DURATION_MINUTES = 1
MAX_DURATION_MINUTES = 60


def resolve_duration_seconds(options: dict | None) -> int:
    """Funcion pura, testeable sin correr ningun binario de verdad."""
    raw = (options or {}).get("duration_minutes", DEFAULT_DURATION_MINUTES)
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        minutes = DEFAULT_DURATION_MINUTES
    minutes = max(MIN_DURATION_MINUTES, min(MAX_DURATION_MINUTES, minutes))
    return minutes * 60
