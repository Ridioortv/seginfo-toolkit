"""Prueba firmada del cierre verificado de una vulnerabilidad (case-service).

vuln-service deja en la cadena de custodia los eventos vuln.closure_requested / closure_verified / closure_failed.
Aca se arma, a pedido, un atestado firmado (Ed25519) con el resultado, la evidencia del re-escaneo, la historia
completa de esa vulnerabilidad y el estado de la cadena en ese momento. Se verifica sin TERO con
verificar_evidencia.py."""
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
RESULT_EVENTS = {"vuln.closure_verified": "verified", "vuln.closure_failed": "failed"}


def _summary(entry: dict) -> dict:
    p = entry["payload"]
    return {"seq": entry["seq"], "ts": entry["ts"], "event_type": entry["event_type"], "actor": entry["actor"],
            "from": p.get("from", ""), "to": p.get("to", ""), "scan_job": p.get("closure_scan_job_id", "")}


@router.get("/closure/{vuln_id}/attestation")
async def closure_attestation(vuln_id: str, claims: dict = Depends(require_role(*READERS)), db: AsyncSession = Depends(get_db)):
    org = org_id_from_claims(claims)
    _total, rows = await custody.list_entries(db, org, limit=200, subject_id=vuln_id)
    entries = [custody.entry_to_dict(e) for e in rows if e.event_type.startswith("vuln.")]
    result = next((e for e in entries if e["event_type"] in RESULT_EVENTS), None)  # el mas reciente (orden descendente)
    if result is None:
        raise HTTPException(status_code=404, detail="Esta vulnerabilidad todavia no tiene un cierre verificado ni fallido")
    chain = await custody.verify(db, org)
    body = {
        "vulnerability_id": vuln_id, "result": RESULT_EVENTS[result["event_type"]], "recorded_at": result["ts"],
        "evidence": result["payload"],
        "custody_entry": {k: result[k] for k in ("seq", "ts", "prev_hash", "entry_hash", "signature")},
        "history": [_summary(e) for e in reversed(entries)],
        "chain_ok_at_signing": bool(chain["ok"]), "chain_entries": chain["entries"], "chain_head": chain["head_hash"],
        "meaning": ("Prueba que el sistema registro, en la fecha indicada, que un re-escaneo completo con el mismo escaner y "
                    "objetivo " + ("ya no detecto" if result["event_type"] == "vuln.closure_verified" else "volvio a detectar")
                    + " la vulnerabilidad. No prueba que el objetivo estuviera encendido durante el escaneo."),
    }
    doc = core.make_attestation("closure", org, body)
    return Response(content=json.dumps(doc, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="prueba-cierre-{vuln_id[:8]}.json"'})
