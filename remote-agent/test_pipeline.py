#!/usr/bin/env python3
"""SentinelOps - test end-to-end del pipeline de ESCANEOS REMOTOS.

Que hace
--------
Prueba TODO el ciclo de vida de un escaneo remoto, para los 4 scanners
(nmap / trivy / nuclei / openvas), SIN necesidad de tener los binarios
instalados ni de escanear nada real: simula al agente hablando con
scan-service por HTTP, exactamente como lo hace remote-agent/agent.py.

Verifica, para cada scanner:
  1. POST /agent-scans           -> el job se crea en estado 'pending'
  2. POST /agents/poll           -> el agente se lo lleva y pasa a 'assigned'
  3. POST /agents/results/{id}   -> el agente reporta y pasa a 'completed'
  4. GET  /agent-scans           -> queda 'completed' con el/los hallazgos

Y ademas:
  - que una api key INCORRECTA sea rechazada al lanzar (401)
  - que el poll con una api key INCORRECTA sea rechazado (401)

Si todo esto pasa, el pipeline remoto funciona: un escaneo que "queda en
pending" es simplemente porque no hay un agente real corriendo que haga
el polling (ver remote-agent/agent.py y remote-agent/README.md).

Uso (en la PC donde corre SentinelOps, con el stack levantado):
  Windows (cmd):
    set SENTINEL_EMAIL=tu-email-admin@dominio
    set SENTINEL_PASSWORD=tu-password
    python remote-agent\test_pipeline.py

  Linux/Mac:
    SENTINEL_EMAIL=... SENTINEL_PASSWORD=... python3 remote-agent/test_pipeline.py

Variables opcionales:
  SCAN_SERVICE_URL   default http://localhost:8003
  AUTH_SERVICE_URL   default http://localhost:8001
  SENTINEL_TOTP      codigo TOTP, si tu cuenta admin tiene MFA activado
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

SCAN_URL = os.environ.get("SCAN_SERVICE_URL", "http://localhost:8003").rstrip("/")
AUTH_URL = os.environ.get("AUTH_SERVICE_URL", "http://localhost:8001").rstrip("/")

SCANNERS = [
    ("nmap", "host.docker.internal"),
    ("trivy", "alpine:3.18"),
    ("nuclei", "http://example.com"),
    ("openvas", "host.docker.internal"),
]

_passed = 0
_failed = 0


def _c(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def check(desc: str, ok: bool, detail: str = "") -> bool:
    global _passed, _failed
    if ok:
        _passed += 1
    else:
        _failed += 1
    line = f"  [{_c(ok)}] {desc}"
    if detail and not ok:
        line += f"  -> {detail}"
    print(line, flush=True)
    return ok


def request(method: str, url: str, token: str = "", agent_key: str = "", payload=None):
    """Devuelve (status_code, body_dict_or_text). Nunca lanza por status
    HTTP: los errores 4xx/5xx se devuelven con su codigo para poder
    afirmar sobre ellos."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if agent_key:
        req.add_header("X-Agent-Key", agent_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
        return exc.code, body
    except urllib.error.URLError as exc:
        return -1, f"no se pudo conectar a {url}: {exc.reason}"


def main() -> int:
    email = os.environ.get("SENTINEL_EMAIL", "")
    password = os.environ.get("SENTINEL_PASSWORD", "")
    totp = os.environ.get("SENTINEL_TOTP", "")
    if not email or not password:
        print("Falta SENTINEL_EMAIL y/o SENTINEL_PASSWORD (cuenta admin de SentinelOps).")
        try:
            email = email or input("Email admin: ").strip()
            import getpass
            password = password or getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            return 2

    print(f"\nSentinelOps - test de escaneos remotos")
    print(f"  auth-service: {AUTH_URL}")
    print(f"  scan-service: {SCAN_URL}\n")

    # -- Login ---------------------------------------------------------
    print("1) Login")
    login_payload = {"email": email, "password": password}
    if totp:
        login_payload["totp_code"] = totp
    code, body = request("POST", f"{AUTH_URL}/auth/login", payload=login_payload)
    if not check("login como admin", code == 200 and isinstance(body, dict) and "access_token" in body,
                 f"HTTP {code}: {body}"):
        print("\nNo se pudo iniciar sesion -- revisa email/password (y TOTP si tenes MFA). Abortando.")
        return 1
    token = body["access_token"]

    # -- Registrar un agente de prueba ---------------------------------
    print("\n2) Registrar agente de prueba")
    agent_name = f"test-e2e-{int(time.time())}"
    code, body = request("POST", f"{SCAN_URL}/agents", token=token, payload={"name": agent_name})
    if not check("POST /agents (crear agente) -> 201 + api_key", code == 201 and isinstance(body, dict) and body.get("api_key"),
                 f"HTTP {code}: {body}"):
        print("\nNo se pudo crear el agente (¿tu cuenta es admin?). Abortando.")
        return 1
    agent_id = body["id"]
    api_key = body["api_key"]
    print(f"   agente '{agent_name}' creado (id={agent_id[:8]}...)")

    # -- Ciclo completo por cada scanner -------------------------------
    print("\n3) Ciclo completo (crear -> poll/assigned -> submit/completed) por scanner")
    created_job_ids = []
    for scanner, target in SCANNERS:
        print(f"\n  -- scanner: {scanner} (target {target}) --")
        # a) crear job
        code, body = request("POST", f"{SCAN_URL}/agent-scans", token=token, payload={
            "agent_id": agent_id, "scanner_type": scanner, "name": f"e2e {scanner}",
            "target": target, "api_key": api_key,
        })
        ok = check(f"crear job {scanner} -> 201 pending",
                   code == 201 and isinstance(body, dict) and body.get("status") == "pending"
                   and body.get("scanner_type") == scanner, f"HTTP {code}: {body}")
        if not ok:
            continue
        job_id = body["id"]
        created_job_ids.append(job_id)

        # b) el agente hace polling -> se lo lleva, pasa a assigned
        code, body = request("POST", f"{SCAN_URL}/agents/poll", agent_key=api_key)
        polled = body.get("jobs", []) if isinstance(body, dict) else []
        got = next((j for j in polled if j.get("id") == job_id), None)
        check(f"poll trae el job {scanner} con su scanner_type",
              code == 200 and got is not None and got.get("scanner_type") == scanner, f"HTTP {code}: {body}")

        # c) el agente reporta el resultado -> completed
        finding = {"title": f"[test] hallazgo simulado {scanner}", "description": "generado por test_pipeline.py",
                   "severity": "info"}
        code, body = request("POST", f"{SCAN_URL}/agents/results/{job_id}", agent_key=api_key, payload={
            "status": "completed", "findings": [finding], "raw_output": "test", "error_message": "",
        })
        check(f"submit resultado {scanner} -> 200 completed",
              code == 200 and isinstance(body, dict) and body.get("status") == "completed", f"HTTP {code}: {body}")

    # -- Verificacion final via GET /agent-scans -----------------------
    print("\n4) Verificacion final (GET /agent-scans)")
    code, body = request("GET", f"{SCAN_URL}/agent-scans", token=token)
    rows = body if isinstance(body, list) else []
    for job_id in created_job_ids:
        row = next((r for r in rows if r.get("id") == job_id), None)
        check(f"job {job_id[:8]}... quedo completed con hallazgos",
              row is not None and row.get("status") == "completed" and len(row.get("findings", [])) >= 1,
              f"estado: {row.get('status') if row else 'no encontrado'}")

    # -- Negativos: api key incorrecta ---------------------------------
    print("\n5) Seguridad: api key incorrecta debe ser rechazada")
    code, body = request("POST", f"{SCAN_URL}/agent-scans", token=token, payload={
        "agent_id": agent_id, "scanner_type": "nmap", "name": "e2e badkey",
        "target": "host.docker.internal", "api_key": "key-totalmente-invalida",
    })
    check("lanzar con api key incorrecta -> 401", code == 401, f"HTTP {code}: {body}")

    code, body = request("POST", f"{SCAN_URL}/agents/poll", agent_key="key-totalmente-invalida")
    check("poll con api key incorrecta -> 401", code == 401, f"HTTP {code}: {body}")

    # -- Limpieza ------------------------------------------------------
    print("\n6) Limpieza")
    for job_id in created_job_ids:
        request("DELETE", f"{SCAN_URL}/agent-scans/{job_id}", token=token)
    code, _ = request("DELETE", f"{SCAN_URL}/agents/{agent_id}", token=token)
    check("borrar agente de prueba -> 204", code == 204, f"HTTP {code}")

    # -- Resumen -------------------------------------------------------
    total = _passed + _failed
    print("\n" + "=" * 50)
    print(f"RESULTADO: {_passed}/{total} checks OK, {_failed} fallaron")
    print("=" * 50)
    if _failed == 0:
        print("\nEl pipeline de escaneos remotos funciona de punta a punta para")
        print("los 4 scanners. Si un escaneo real 'queda en pending', es porque")
        print("no hay un agente REAL corriendo que lo levante -- corre")
        print("remote-agent/agent.py en una maquina de la red a escanear.")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        sys.exit(130)
