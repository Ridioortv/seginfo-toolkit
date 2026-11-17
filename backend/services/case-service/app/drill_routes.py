"""Prueba firmada de un simulacro de respuesta (case-service).

purple-service deja en la cadena de custodia drill.started y drill.completed (con los tiempos medidos y el puntaje).
Aca se arma, a pedido, un atestado firmado (Ed25519) con el resultado, los umbrales de puntaje, la historia del
simulacro y el estado de la cadena en ese momento. Se verifica sin TERO con verificar_evidencia.py."""
import json

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.tenancy import org_id_from_claims
from app import custody_service as custody
from app.dependencies import require_role

router = APIRouter()
READERS = ("admin", "soc_manager", "analyst")
RESULT_EVENTS = ("drill.completed", "drill.cancelled")


def _summary(entry: dict) -> dict:
    p = entry["payload"]
    return {"seq": entry["seq"], "ts": entry["ts"], "event_type": entry["event_type"], "actor": entry["actor"],
            "status": p.get("status", ""), "score": p.get("score")}


@router.get("/drills/{drill_id}/attestation")
async def drill_attestation(drill_id: str, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    _total, rows = await custody.list_entries(db, org, limit=200, subject_id=drill_id)
    entries = [custody.entry_to_dict(e) for e in rows if e.event_type.startswith("drill.")]
    result = next((e for e in entries if e["event_type"] in RESULT_EVENTS), None)  # el mas reciente
    if result is None:
        raise HTTPException(status_code=404, detail="Este simulacro todavia no termino")
    chain = await custody.verify(db, org)
    body = {
        "drill_id": drill_id, "status": result["payload"].get("status", ""), "recorded_at": result["ts"],
        "result": result["payload"],
        "custody_entry": {k: result[k] for k in ("seq", "ts", "prev_hash", "entry_hash", "signature")},
        "history": [_summary(e) for e in reversed(entries)],
        "chain_ok_at_signing": bool(chain["ok"]), "chain_entries": chain["entries"], "chain_head": chain["head_hash"],
        "meaning": ("Prueba que el sistema registro, en la fecha indicada, un simulacro de respuesta a incidentes: un evento sintetico "
                    "rotulado como simulacro y los tiempos medidos hasta que una persona reconocio y cerro la alerta. "
                    "No ejecuto ninguna tecnica de ataque ni disparo respuestas automaticas reales. No prueba las reglas de deteccion "
                    "reales de la organizacion."),
    }
    doc = core.make_attestation("drill", org, body)
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="prueba-simulacro-{drill_id[:8]}.json"'})
