"""Proveedores de tickets (Jira y ServiceNow): crear un ticket y leer su estado.

Reglas:
  * Los mensajes de error NUNCA incluyen la URL ni las credenciales (se guardan en la base y se muestran en pantalla).
  * Toda llamada valida la URL contra SSRF justo antes de salir (ver backend/shared/ssrf_guard.py).
  * El estado externo se traduce a tres valores propios: open | resolved | canceled. "Cancelado / no se hara / duplicado" NO se
    trata como corregido: nadie arreglo la vulnerabilidad, asi que TERO no la da por remediada."""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from backend.shared.crypto import decrypt_secret
from backend.shared.ssrf_guard import UnsafeUrlError, validate_outbound_url

TIMEOUT = 10.0
PROVIDERS = ("jira", "servicenow")
# Resoluciones de Jira que significan "no se va a hacer": el ticket se cerro pero la vulnerabilidad sigue ahi.
NO_FIX_RESOLUTIONS = {"won't do", "won't fix", "wont do", "wont fix", "declined", "duplicate", "cannot reproduce",
                      "incomplete", "rejected", "no se hara", "rechazado", "duplicado"}
SNOW_RESOLVED = {"6", "7"}   # 6 Resolved, 7 Closed
SNOW_CANCELED = {"8"}        # 8 Canceled
SNOW_URGENCY = {"critical": ("1", "1"), "high": ("2", "2"), "medium": ("2", "3"), "low": ("3", "3")}  # (impact, urgency)


class ProviderError(Exception):
    """Fallo al hablar con el sistema de tickets; el mensaje es apto para mostrar (sin URL ni credenciales)."""


@dataclass
class Created:
    key: str
    external_id: str
    url: str


@dataclass
class Status:
    state: str  # open | resolved | canceled
    raw: str


def provider_of(config: dict) -> str:
    p = str((config or {}).get("provider") or "jira").lower()
    return p if p in PROVIDERS else "jira"


def _client(auth: tuple[str, str] | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, auth=auth, follow_redirects=False, headers={"Accept": "application/json"})


def _base(config: dict) -> str:
    base = str(config.get("base_url", "")).strip().rstrip("/")
    if not base:
        raise ProviderError("El conector no tiene 'base_url' configurada")
    try:
        validate_outbound_url(base, field_name="base_url")
    except UnsafeUrlError as exc:
        raise ProviderError(str(exc)) from exc
    return base


def _secret(config: dict, key: str) -> str:
    value = config.get(key, "")
    return decrypt_secret(value) if value else ""


def _http_error(exc: httpx.HTTPStatusError, what: str) -> ProviderError:
    code = exc.response.status_code
    if code in (401, 403):
        return ProviderError(f"{what}: el sistema de tickets rechazo las credenciales (HTTP {code})")
    if code == 404:
        return ProviderError(f"{what}: no se encontro el recurso (HTTP 404). Revisa la URL, el proyecto o que el ticket exista")
    if code == 429:
        return ProviderError(f"{what}: el sistema de tickets pidio esperar (HTTP 429)")
    return ProviderError(f"{what}: el sistema de tickets respondio HTTP {code}")


def _net_error(exc: httpx.HTTPError, what: str) -> ProviderError:
    return ProviderError(f"{what}: error de red ({type(exc).__name__})")


# ----------------------------- Jira (API v2, Cloud o Server/Data Center) -----------------------------

def _jira_auth(config: dict) -> tuple[str, str]:
    email, token = str(config.get("email", "")), _secret(config, "api_token")
    if not (email and token):
        raise ProviderError("El conector de Jira necesita 'email' y 'api_token'")
    return email, token


async def _jira_create(config: dict, title: str, description: str, priority: str) -> Created:
    base, auth = _base(config), _jira_auth(config)
    project = str(config.get("project_key", ""))
    if not project:
        raise ProviderError("El conector de Jira necesita 'project_key'")
    fields: dict = {"project": {"key": project}, "summary": title[:250], "description": description,
                    "issuetype": {"name": config.get("issue_type", "Task")}}
    mapped = (config.get("priority_map") or {}).get(priority)
    if mapped:
        fields["priority"] = {"name": mapped}
    try:
        async with _client(auth) as client:
            resp = await client.post(f"{base}/rest/api/2/issue", json={"fields": fields})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise _http_error(exc, "No se pudo crear el ticket en Jira") from exc
    except httpx.HTTPError as exc:
        raise _net_error(exc, "No se pudo crear el ticket en Jira") from exc
    except ValueError as exc:
        raise ProviderError("Jira respondio algo que no se pudo leer") from exc
    key = str(data.get("key", ""))
    if not key:
        raise ProviderError("Jira no devolvio la clave del ticket")
    return Created(key=key, external_id=str(data.get("id", "")), url=f"{base}/browse/{key}")


async def _jira_status(config: dict, key: str, external_id: str) -> Status:
    base, auth = _base(config), _jira_auth(config)
    try:
        async with _client(auth) as client:
            resp = await client.get(f"{base}/rest/api/2/issue/{key}", params={"fields": "status,resolution"})
            resp.raise_for_status()
            fields = resp.json().get("fields", {})
    except httpx.HTTPStatusError as exc:
        raise _http_error(exc, "No se pudo leer el ticket de Jira") from exc
    except httpx.HTTPError as exc:
        raise _net_error(exc, "No se pudo leer el ticket de Jira") from exc
    except ValueError as exc:
        raise ProviderError("Jira respondio algo que no se pudo leer") from exc
    st = fields.get("status") or {}
    raw = str(st.get("name", ""))
    if (st.get("statusCategory") or {}).get("key") == "done":
        resolution = str((fields.get("resolution") or {}).get("name", "")).strip().lower()
        return Status("canceled" if resolution in NO_FIX_RESOLUTIONS else "resolved", raw)
    return Status("open", raw)


# ----------------------------- ServiceNow (Table API) -----------------------------

def _snow_auth(config: dict) -> tuple[str, str]:
    user, password = str(config.get("username", "")), _secret(config, "api_token")
    if not (user and password):
        raise ProviderError("El conector de ServiceNow necesita 'username' y 'api_token' (la contrasena)")
    return user, password


def _snow_table(config: dict) -> str:
    table = str(config.get("table") or "incident")
    if not table.replace("_", "").isalnum():
        raise ProviderError("El nombre de la tabla de ServiceNow no es valido")
    return table


async def _snow_create(config: dict, title: str, description: str, priority: str) -> Created:
    base, auth, table = _base(config), _snow_auth(config), _snow_table(config)
    impact, urgency = SNOW_URGENCY.get(priority, ("2", "3"))
    body = {"short_description": title[:160], "description": description, "impact": impact, "urgency": urgency}
    for opt in ("caller_id", "assignment_group", "category", "cmdb_ci"):
        if config.get(opt):
            body[opt] = config[opt]
    try:
        async with _client(auth) as client:
            resp = await client.post(f"{base}/api/now/table/{table}", json=body)
            resp.raise_for_status()
            result = resp.json().get("result", {})
    except httpx.HTTPStatusError as exc:
        raise _http_error(exc, "No se pudo crear el ticket en ServiceNow") from exc
    except httpx.HTTPError as exc:
        raise _net_error(exc, "No se pudo crear el ticket en ServiceNow") from exc
    except ValueError as exc:
        raise ProviderError("ServiceNow respondio algo que no se pudo leer") from exc
    sys_id, number = str(result.get("sys_id", "")), str(result.get("number", ""))
    if not sys_id:
        raise ProviderError("ServiceNow no devolvio el identificador del ticket")
    return Created(key=number or sys_id, external_id=sys_id, url=f"{base}/nav_to.do?uri={table}.do%3Fsys_id%3D{sys_id}")


async def _snow_status(config: dict, key: str, external_id: str) -> Status:
    base, auth, table = _base(config), _snow_auth(config), _snow_table(config)
    try:
        async with _client(auth) as client:
            if external_id:
                resp = await client.get(f"{base}/api/now/table/{table}/{external_id}", params={"sysparm_fields": "state,number"})
                resp.raise_for_status()
                result = resp.json().get("result", {})
            else:
                resp = await client.get(f"{base}/api/now/table/{table}", params={"sysparm_query": f"number={key}", "sysparm_limit": 1, "sysparm_fields": "state,number"})
                resp.raise_for_status()
                rows = resp.json().get("result", [])
                if not rows:
                    raise ProviderError("No se pudo leer el ticket de ServiceNow: no se encontro el recurso")
                result = rows[0]
    except httpx.HTTPStatusError as exc:
        raise _http_error(exc, "No se pudo leer el ticket de ServiceNow") from exc
    except httpx.HTTPError as exc:
        raise _net_error(exc, "No se pudo leer el ticket de ServiceNow") from exc
    except ValueError as exc:
        raise ProviderError("ServiceNow respondio algo que no se pudo leer") from exc
    state = str(result.get("state", ""))
    return Status("resolved" if state in SNOW_RESOLVED else "canceled" if state in SNOW_CANCELED else "open", f"state={state}")


# ----------------------------- interfaz comun -----------------------------

async def create(config: dict, title: str, description: str, priority: str) -> Created:
    fn = _snow_create if provider_of(config) == "servicenow" else _jira_create
    return await fn(config, title, description, priority)


async def fetch_status(config: dict, key: str, external_id: str = "") -> Status:
    fn = _snow_status if provider_of(config) == "servicenow" else _jira_status
    return await fn(config, key, external_id)


async def check(config: dict) -> str:
    """Prueba de conexion y credenciales sin crear nada. Devuelve un texto de exito o levanta ProviderError."""
    base = _base(config)
    try:
        if provider_of(config) == "servicenow":
            auth, table = _snow_auth(config), _snow_table(config)
            async with _client(auth) as client:
                (await client.get(f"{base}/api/now/table/{table}", params={"sysparm_limit": 1, "sysparm_fields": "number"})).raise_for_status()
            return "Conexion correcta con ServiceNow"
        auth = _jira_auth(config)
        async with _client(auth) as client:
            (await client.get(f"{base}/rest/api/2/myself")).raise_for_status()
            if config.get("project_key"):
                (await client.get(f"{base}/rest/api/2/project/{config['project_key']}")).raise_for_status()
        return "Conexion correcta con Jira"
    except httpx.HTTPStatusError as exc:
        raise _http_error(exc, "La prueba de conexion fallo") from exc
    except httpx.HTTPError as exc:
        raise _net_error(exc, "La prueba de conexion fallo") from exc
