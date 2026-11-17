"""API de la cadena de custodia (case-service). Lectura: cualquier usuario autenticado de la organizacion.
Exportar evidencia: admin, soc_manager, analyst. Escritura desde otros servicios: solo /internal con JWT de servicio."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared import custody_core as core
from backend.shared.database import get_db
from backend.shared.service_auth import require_service_token
from backend.shared.tenancy import org_id_from_claims
from app import custody_service as custody
from app import services
from app.dependencies import get_current_claims, require_role

router = APIRouter()
WRITERS = ("admin", "soc_manager", "analyst")


class CustodyEventIn(BaseModel):
    event_type: str = Field(min_length=3, max_length=100, pattern=r"^[a-z0-9_.-]+$")
    actor: str = Field(default="", max_length=255)
    source: str = Field(default="", max_length=50)
    subject_type: str = Field(default="", max_length=30)
    subject_id: str = Field(default="", max_length=100)
    refs: list[str] = Field(default_factory=list, max_length=core.MAX_REFS)
    payload: dict = Field(default_factory=dict)


class CustodyEventOut(BaseModel):
    seq: int
    entry_hash: str


def _actor(claims: dict) -> str:
    return claims.get("email") or claims.get("sub", "")


@router.post("/internal/custody/events", response_model=CustodyEventOut, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    payload: CustodyEventIn, claims: dict = Depends(require_service_token), db: AsyncSession = Depends(get_db),
):
    """Otros servicios (siem, soar, scan, vuln...) registran aca lo que hacen. La organizacion sale del JWT de
    servicio, nunca del body. Los tipos case.* y evidence.* estan reservados a case-service."""
    if payload.event_type.startswith(custody.RESERVED_PREFIXES):
        raise HTTPException(status_code=403, detail="Tipo de evento reservado")
    if not payload.event_type.startswith(custody.EXTERNAL_PREFIXES):
        raise HTTPException(status_code=422, detail="Tipo de evento no permitido")
    try:
        entry = await custody.append(
            db, org_id_from_claims(claims), payload.event_type, actor=payload.actor,
            source=payload.source or str(claims.get("sub", "")).removeprefix("system:"),
            subject_type=payload.subject_type, subject_id=payload.subject_id, refs=payload.refs, payload=payload.payload,
        )
    except custody.CustodyError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    await db.commit()
    return CustodyEventOut(seq=entry.seq, entry_hash=entry.entry_hash)


@router.get("/custody/status")
async def custody_status(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    head = await custody.head(db, org_id_from_claims(claims))
    pub = core.public_key_hex()
    return {
        **head, "public_key": pub, "key_fingerprint": core.key_fingerprint(pub),
        "key_derived_from_jwt": core.key_is_derived_from_jwt(), "algorithm": "Ed25519 + SHA-256",
    }


@router.get("/custody/entries")
async def custody_entries(
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), event_type: str | None = None,
    subject_id: str | None = None, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    total, rows = await custody.list_entries(db, org_id_from_claims(claims), limit, offset, event_type, subject_id)
    return {"total": total, "items": [custody.entry_to_dict(e) for e in rows]}


@router.get("/custody/verify")
async def custody_verify(
    expected_count: int | None = Query(None, ge=0), expected_head: str | None = Query(None, min_length=64, max_length=64),
    claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db),
):
    return await custody.verify(db, org_id_from_claims(claims), expected_count, expected_head)


@router.get("/custody/anchor")
async def custody_anchor(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await custody.anchor(db, org_id_from_claims(claims))


@router.get("/custody/verifier")
async def custody_verifier(claims: dict = Depends(get_current_claims)):
    """El mismo verificador independiente que viaja dentro de cada paquete (solo biblioteca estandar de Python)."""
    return Response(content=custody.VERIFIER_PATH.read_text(encoding="utf-8"), media_type="text/x-python",
                    headers={"Content-Disposition": 'attachment; filename="verificar_evidencia.py"'})


@router.post("/custody/cases/{case_id}/package")
async def custody_case_package(
    case_id: str, claims: dict = Depends(require_role(*WRITERS)), db: AsyncSession = Depends(get_db),
):
    """Genera el paquete de evidencia del caso (zip). Queda anotado en la cadena quien lo exporto y la huella de la ficha."""
    case = await services.get_case(db, case_id, org_id_from_claims(claims))
    if case is None:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    data, _manifest = await custody.build_evidence_package(db, case, _actor(claims))
    await db.commit()
    filename = f"evidencia-caso-{case.id[:8]}.zip"
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
