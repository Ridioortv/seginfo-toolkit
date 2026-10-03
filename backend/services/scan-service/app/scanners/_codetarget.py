"""Resuelve el `target` de un driver que escanea CODIGO FUENTE
(semgrep, gitleaks) a un directorio/archivo local sobre el que correr
el binario.

target puede ser:
  - una URL git clonable (http:// o https://) -> se clona a un
    directorio temporal que este helper borra solo al salir del
    `async with` (ver CodeTarget).
  - un path local que YA existe en el filesystem de quien ejecuta este
    driver (el contenedor de scan-service, o la maquina del agente
    remoto que corre remote-agent/agent.py) -> se usa directo, nunca se
    borra (es del usuario, no nuestro).

NUNCA se ejecuta codigo del repositorio/directorio resuelto -- solo se
lee como texto/archivos para las herramientas de analisis estatico."""
import asyncio
import os
import re
import shutil
import tempfile

_GIT_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_CREDENTIALS_IN_URL_RE = re.compile(r"://[^\s@/]+@")


def is_clonable_url(target: str) -> bool:
    return bool(_GIT_URL_RE.match((target or "").strip()))


def _redact(text: str) -> str:
    """Nunca debe aparecer un token/credencial embebido en una URL de
    clone (ej. "https://x-access-token:TOKEN@github.com/...") en un
    mensaje de error guardado en ScanJob.error_message."""
    return _CREDENTIALS_IN_URL_RE.sub("://***@", text or "")


async def clone_repo(url: str, dest_dir: str, timeout: int = 180, shallow: bool = False) -> str | None:
    """Clona `url` en `dest_dir`. Devuelve None si salio bien, o un
    mensaje de error corto (ya redactado) si fallo."""
    cmd = ["git", "clone", "--single-branch"]
    if shallow:
        cmd += ["--depth", "1"]
    cmd += [url, dest_dir]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except FileNotFoundError:
        return "git no esta instalado en este contenedor/maquina"
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"timeout clonando el repositorio ({timeout}s)"
    if proc.returncode != 0:
        return _redact(stderr.decode(errors="replace"))[:2000]
    return None


class CodeTarget:
    """Context manager async: `ct.path` queda con el directorio/archivo
    local resuelto, o `ct.error` con un mensaje claro si no se pudo
    resolver (target ni es una URL clonable ni un path existente, o el
    clone fallo)."""

    def __init__(self, target: str, clone_timeout: int = 180, shallow: bool = False):
        self.target = target
        self.clone_timeout = clone_timeout
        self.shallow = shallow
        self.path: str | None = None
        self.error: str | None = None
        self._tmpdir: str | None = None

    async def __aenter__(self) -> "CodeTarget":
        target = (self.target or "").strip()
        if is_clonable_url(target):
            self._tmpdir = tempfile.mkdtemp(prefix="sentinelops-clone-")
            err = await clone_repo(target, self._tmpdir, timeout=self.clone_timeout, shallow=self.shallow)
            if err:
                self.error = f"no se pudo clonar '{_redact(target)}': {err}"
            else:
                self.path = self._tmpdir
        elif os.path.isdir(target) or os.path.isfile(target):
            self.path = target
        else:
            self.error = (
                f"target '{target}' no es una URL git clonable (http:// o https://) ni un path "
                "existente en el filesystem de quien ejecuta este escaneo"
            )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._tmpdir is not None:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
