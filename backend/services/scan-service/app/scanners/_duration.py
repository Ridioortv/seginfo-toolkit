"""Resuelve y acota options.duration_minutes para los drivers de
'duracion fija' (Zeek, Falco) -- los unicos escaneres de esta
plataforma que no terminan solos contra un target puntual, sino que
corren durante una ventana de tiempo fija (decision de producto
explicita, ver docstring de app/scanners/zeek.py) y reportan lo que
detectaron en ese lapso, como si fuera un escaneo mas."""

import asyncio

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


async def run_for_fixed_duration(cmd: list[str], duration_seconds: int, grace_seconds: int = 10):
    """Corre `cmd` una ventana FIJA de `duration_seconds`.

    Confiar solo en el flag del propio programa (falco -M) no alcanza: si no se
    corta solo, el escaneo quedaba "corriendo" para siempre (o se mataba a
    destiempo y se perdia lo que habia juntado). Aca el tiempo lo manda este
    codigo: al vencer la ventana (+ unos segundos de margen) se le manda SIGTERM,
    que cierra el programa limpio y deja leer lo capturado, y solo si no
    responde en `grace_seconds` se lo mata.

    Devuelve (returncode, stdout, stderr, cortado_por_nosotros). Si `cmd` no
    existe levanta FileNotFoundError; si lo cancelan, mata el proceso."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out_task = asyncio.create_task(proc.stdout.read())
    err_task = asyncio.create_task(proc.stderr.read())
    stopped_by_us = False
    try:
        try:
            await asyncio.wait_for(proc.wait(), timeout=duration_seconds + 5)
        except asyncio.TimeoutError:
            stopped_by_us = True
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        stdout = await out_task
        stderr = await err_task
    except asyncio.CancelledError:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        out_task.cancel()
        err_task.cancel()
        raise
    return proc.returncode, stdout, stderr, stopped_by_us
