"""Enriquecimiento de vulnerabilidades con fuentes publicas de inteligencia:
NVD (CVSS), FIRST.org (EPSS) y el catalogo CISA KEV (explotacion conocida).
Todo es de solo LECTURA: se consultan APIs publicas de datos declarados,
nunca se ejecuta ninguna accion contra el activo afectado. Cada llamada es
best-effort con timeout corto: si una fuente no responde (por ejemplo por
falta de salida a internet desde el contenedor), el campo correspondiente
queda en None/False y el resto del enriquecimiento sigue."""
import asyncio
import os
import time
import httpx
from backend.shared.logging import configure_logging
from app.cvss import compute_base_score

logger = configure_logging("vuln-service.enrichment")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
CISA_KEV_URL = os.getenv(
    "CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

_HTTP_TIMEOUT = 8.0

# Cache en memoria del catalogo CISA KEV: es un feed grande (varios cientos
# de KB) que cambia poco durante el dia, asi que se refresca por TTL en vez
# de descargarlo en cada enriquecimiento individual.
_kev_cache: dict[str, dict] = {}
_kev_cache_loaded_at: float = 0.0
_KEV_CACHE_TTL_SECONDS = 6 * 60 * 60
_kev_lock = asyncio.Lock()


async def fetch_cvss(cve_id: str) -> tuple[float | None, str]:
    """Devuelve (score, vector) de CVSS v3.1 (o v3.0 si v3.1 no esta),
    tomado del primer resultado de NVD para ese CVE."""
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("no se pudo consultar NVD", extra={"cve_id": cve_id, "error": str(exc)})
        return None, ""

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None, ""
    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString", "")
            if score is None and vector:
                # NVD a veces expone el vector sin el score precalculado;
                # se recalcula localmente con la formula oficial (app/cvss.py)
                # en vez de descartar el dato.
                score = compute_base_score(vector)
            return score, vector
    return None, ""


async def fetch_epss(cve_id: str) -> float | None:
    """EPSS: probabilidad (0-1) de explotacion en los proximos 30 dias."""
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("no se pudo consultar EPSS", extra={"cve_id": cve_id, "error": str(exc)})
        return None

    rows = data.get("data", [])
    if not rows:
        return None
    try:
        return float(rows[0].get("epss"))
    except (TypeError, ValueError):
        return None


async def _load_kev_catalog() -> dict[str, dict]:
    global _kev_cache, _kev_cache_loaded_at
    async with _kev_lock:
        if _kev_cache and (time.monotonic() - _kev_cache_loaded_at) < _KEV_CACHE_TTL_SECONDS:
            return _kev_cache
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(CISA_KEV_URL)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("no se pudo descargar catalogo CISA KEV", extra={"error": str(exc)})
            return _kev_cache
        by_cve = {row["cveID"]: row for row in data.get("vulnerabilities", []) if row.get("cveID")}
        _kev_cache = by_cve
        _kev_cache_loaded_at = time.monotonic()
        return _kev_cache


async def check_kev(cve_id: str) -> tuple[bool, str]:
    """Devuelve (esta_en_kev, fecha_agregado)."""
    catalog = await _load_kev_catalog()
    entry = catalog.get(cve_id)
    if entry is None:
        return False, ""
    return True, entry.get("dateAdded", "")


def compute_priority_score(
    cvss_score: float | None, epss_score: float | None, is_kev: bool, asset_criticality: str = "medium"
) -> float:
    """Score de priorizacion 0-100 para ordenar la cola de triage. Pondera
    severidad tecnica (CVSS), probabilidad real de explotacion (EPSS),
    explotacion ya confirmada en el mundo real (KEV) y el impacto de negocio
    del activo afectado (criticidad del activo en el CMDB)."""
    cvss_component = (cvss_score or 0.0) * 10  # 0-10 -> 0-100
    epss_component = (epss_score or 0.0) * 100  # 0-1 -> 0-100
    kev_bonus = 25.0 if is_kev else 0.0

    criticality_multiplier = {
        "critical": 1.3,
        "high": 1.15,
        "medium": 1.0,
        "low": 0.85,
        "other": 1.0,
    }.get(asset_criticality, 1.0)

    raw_score = (cvss_component * 0.55 + epss_component * 0.25 + kev_bonus) * criticality_multiplier
    return round(min(100.0, max(0.0, raw_score)), 2)
