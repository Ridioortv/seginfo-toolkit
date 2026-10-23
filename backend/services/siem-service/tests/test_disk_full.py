"""Disco casi lleno: OpenSearch bloquea las escrituras (flood-stage 95 %) y el SIEM tiene que
contestar 503 con un mensaje claro, no un 500 generico, y avisarlo al panel."""
import asyncio

import pytest
from fastapi.testclient import TestClient
from opensearchpy.exceptions import AuthorizationException, TransportError

from app import opensearch_client as oc
import app.main as m
from app.dependencies import get_current_claims
from backend.shared.database import get_db

MENSAJE = "El disco de la PC está casi lleno: OpenSearch dejó de aceptar logs. Liberá espacio."
BLOQUEO_429 = (
    "index [sentinelops-logs] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded "
    "flood-stage watermark, index has read-only-allow-delete block];"
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_estado():
    oc._disk_full_seen_at = None
    yield
    oc._disk_full_seen_at = None


class FakeIndexClient:
    def __init__(self, error=None):
        self.error = error

    async def index(self, **kwargs):
        if self.error:
            raise self.error
        return {"_id": "abc"}


# --- deteccion del error ---------------------------------------------------------------------
def test_mensaje_exacto():
    assert oc.DISK_FULL_MESSAGE == MENSAJE


@pytest.mark.parametrize(
    "exc",
    [
        TransportError(429, "cluster_block_exception", BLOQUEO_429),
        AuthorizationException(403, "cluster_block_exception", "blocked by: [FORBIDDEN/12/index read-only / allow delete (api)];"),
        TransportError(429, "cluster_block_exception", {"error": {"reason": BLOQUEO_429}}),
    ],
)
def test_reconoce_el_bloqueo_por_disco(exc):
    assert oc.is_disk_full_error(exc) is True


@pytest.mark.parametrize(
    "exc",
    [
        TransportError(429, "es_rejected_execution_exception", "queue capacity reached"),  # 429 normal
        AuthorizationException(403, "security_exception", "no permissions for [indices:data/write/index]"),
        TransportError(500, "cluster_block_exception", BLOQUEO_429),   # solo 403/429
        ConnectionError("cluster_block_exception flood-stage"),         # sin status_code
        ValueError("x"),
    ],
)
def test_no_confunde_otros_errores_con_disco_lleno(exc):
    assert oc.is_disk_full_error(exc) is False


def test_index_event_traduce_el_bloqueo():
    client = FakeIndexClient(TransportError(429, "cluster_block_exception", BLOQUEO_429))
    with pytest.raises(oc.OpenSearchDiskFull) as e:
        run(oc.index_event(client, {"a": 1}))
    assert str(e.value) == MENSAJE
    assert oc._disk_full_seen_at is not None


def test_index_event_deja_pasar_otros_errores():
    client = FakeIndexClient(TransportError(500, "boom", "otro problema"))
    with pytest.raises(TransportError):
        run(oc.index_event(client, {"a": 1}))
    assert oc._disk_full_seen_at is None


def test_una_escritura_exitosa_limpia_el_aviso():
    oc._disk_full_seen_at = 123.0
    assert run(oc.index_event(FakeIndexClient(), {"a": 1})) == "abc"
    assert oc._disk_full_seen_at is None


# --- endpoint de ingesta: 503 ---------------------------------------------------------------
class _Resultado:
    def scalars(self):
        return self

    def all(self):
        return []


class FakeSession:
    async def execute(self, *a, **k):
        return _Resultado()

    async def commit(self):
        pass

    async def flush(self):
        pass


@pytest.fixture
def cliente(monkeypatch):
    monkeypatch.delenv("SIEM_INGEST_TOKEN", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")

    async def fake_db():
        yield FakeSession()

    m.app.dependency_overrides[get_db] = fake_db
    m.app.dependency_overrides[get_current_claims] = lambda: {"sub": "u", "role": "admin", "org_id": "o"}
    yield TestClient(m.app, raise_server_exceptions=False)
    m.app.dependency_overrides.clear()


def test_ingesta_con_disco_lleno_devuelve_503_con_mensaje(cliente, monkeypatch):
    monkeypatch.setattr(m, "os_client", FakeIndexClient(TransportError(429, "cluster_block_exception", BLOQUEO_429)))
    r = cliente.post("/logs/ingest", json={"events": [{"message": "hola"}]})
    assert r.status_code == 503
    assert r.json() == {"detail": MENSAJE, "code": "disk_full"}
    assert r.headers.get("retry-after") == "300"


def test_ingesta_normal_sigue_andando(cliente, monkeypatch):
    monkeypatch.setattr(m, "os_client", FakeIndexClient())
    r = cliente.post("/logs/ingest", json={"events": [{"message": "hola"}]})
    assert r.status_code == 201
    assert r.json()["indexed"] == 1


def test_otro_error_de_opensearch_no_se_disfraza_de_disco_lleno(cliente, monkeypatch):
    monkeypatch.setattr(m, "os_client", FakeIndexClient(TransportError(500, "boom", "otro")))
    r = cliente.post("/logs/ingest", json={"events": [{"message": "hola"}]})
    assert r.status_code == 500
    assert MENSAJE not in r.text


def test_health_no_depende_del_disco(cliente):
    assert cliente.get("/health").status_code == 200


# --- estado para el panel ------------------------------------------------------------------
class FakeStatusClient:
    def __init__(self, bloqueado=False, porcentaje=None, falla_settings=False, falla_cat=False):
        self.bloqueado, self.porcentaje = bloqueado, porcentaje
        self.falla_settings, self.falla_cat = falla_settings, falla_cat
        self.indices = self
        self.cat = self

    async def get_settings(self, index):
        if self.falla_settings:
            raise TransportError(404, "index_not_found_exception", "no existe")
        bloques = {"read_only_allow_delete": "true"} if self.bloqueado else {}
        return {index: {"settings": {"index": {"blocks": bloques}}}}

    async def allocation(self, format):
        if self.falla_cat:
            raise TransportError(500, "x", "y")
        return [] if self.porcentaje is None else [{"node": "n1", "disk.percent": str(self.porcentaje)}]


def test_estado_normal():
    s = run(oc.storage_status(FakeStatusClient(porcentaje=40)))
    assert s == {"writable": True, "disk_full": False, "disk_used_percent": 40.0, "message": None}


def test_estado_con_indice_bloqueado():
    s = run(oc.storage_status(FakeStatusClient(bloqueado=True, porcentaje=96)))
    assert s["disk_full"] is True and s["writable"] is False and s["message"] == MENSAJE


def test_estado_por_porcentaje_aunque_todavia_no_haya_bloqueo():
    assert run(oc.storage_status(FakeStatusClient(porcentaje=95)))["disk_full"] is True
    assert run(oc.storage_status(FakeStatusClient(porcentaje=94.9)))["disk_full"] is False


def test_estado_tras_una_escritura_rechazada():
    oc._disk_full_seen_at = 1.0
    assert run(oc.storage_status(FakeStatusClient()))["disk_full"] is True


def test_estado_si_opensearch_no_responde_no_inventa_un_problema_de_disco():
    s = run(oc.storage_status(FakeStatusClient(falla_settings=True, falla_cat=True)))
    assert s["disk_full"] is False and s["disk_used_percent"] is None


def test_endpoint_storage_status(cliente, monkeypatch):
    monkeypatch.setattr(m, "os_client", FakeStatusClient(bloqueado=True, porcentaje=97))
    r = cliente.get("/logs/storage-status")
    assert r.status_code == 200
    assert r.json()["disk_full"] is True and r.json()["message"] == MENSAJE


def test_endpoint_storage_status_exige_login():
    m.app.dependency_overrides.clear()
    assert TestClient(m.app).get("/logs/storage-status").status_code == 401
