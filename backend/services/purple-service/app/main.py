"""purple-service entrypoint: gap analysis de cobertura MITRE ATT&CK sobre
ejercicios purple team declarados (SOLO calcula metricas a partir de datos: tags de reglas Sigma de siem-service;
no incluye ningun motor de simulacion/ejecucion de tecnicas -- ver docs/architecture.md 'Fuera de alcance
(deliberado)') y simulacros medibles de respuesta (app/drills.py): un unico evento sintetico rotulado en el SIEM y
la medicion de cuanto tardan las personas en reconocer y cerrar la alerta. Tampoco ejecutan ninguna tecnica."""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base, SessionLocal, wait_for_database
from backend.shared.logging import configure_logging
from backend.shared import egress
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.db_errors import install_db_error_handlers
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.models import PurpleDrill
from app.schemas import TechniqueOut, ExerciseCreate, ExerciseOut, CoverageResult
from app.dependencies import get_current_claims, require_role
from app.attack_data import ATTACK_TECHNIQUES
from app import services
from app import drills

logger = configure_logging("purple-service")
exercises_created_total = Counter("purple_exercise_created_total", "Ejercicios purple team creados")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await wait_for_database()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE purple_exercises ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            f"UPDATE purple_exercises SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    drill_task = asyncio.create_task(drills.loop(SessionLocal))
    logger.info("purple-service iniciado")
    yield
    drill_task.cancel()


app = FastAPI(title="TERO Security Purple Team Service", version="0.1.0", lifespan=lifespan)
egress.install("purple-service", app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
install_db_error_handlers(app)  # 409/422 claros en vez de 500 ante datos que la base rechaza
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "purple-service"}


@app.get("/techniques", response_model=list[TechniqueOut])
async def list_techniques(claims: dict = Depends(get_current_claims)):
    """Catalogo de referencia MITRE ATT&CK (subset curado) usado como
    universo para el gap analysis."""
    return ATTACK_TECHNIQUES


@app.get("/coverage/overall", response_model=CoverageResult)
async def overall_coverage(claims: dict = Depends(get_current_claims)):
    """Metrica de dashboard: cobertura de deteccion contra el catalogo
    completo de tecnicas, sin ligarse a un ejercicio particular."""
    return await services.compute_overall_coverage(org_id_from_claims(claims))


@app.post("/exercises", response_model=ExerciseOut, status_code=status.HTTP_201_CREATED)
async def create_exercise(
    payload: ExerciseCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    exercise = await services.create_exercise(db, payload, org_id_from_claims(claims))
    await db.commit()
    exercises_created_total.inc()
    return exercise


@app.get("/exercises", response_model=list[ExerciseOut])
async def list_exercises(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_exercises(db, org_id_from_claims(claims))


@app.get("/exercises/{exercise_id}", response_model=ExerciseOut)
async def get_exercise(exercise_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    exercise = await services.get_exercise(db, exercise_id, org_id_from_claims(claims))
    if exercise is None:
        raise HTTPException(status_code=404, detail="Ejercicio no encontrado")
    return exercise


@app.post("/exercises/{exercise_id}/coverage", response_model=CoverageResult)
async def compute_exercise_coverage(
    exercise_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Recalcula y persiste la cobertura de deteccion para las tecnicas
    declaradas por este ejercicio (gap analysis, nunca ejecucion)."""
    exercise = await services.get_exercise(db, exercise_id, org_id_from_claims(claims))
    if exercise is None:
        raise HTTPException(status_code=404, detail="Ejercicio no encontrado")
    result = await services.compute_coverage_for_exercise(db, exercise)
    await db.commit()
    return result


# ---------------- Simulacros medibles de respuesta (ver app/drills.py) ----------------

class DrillStart(BaseModel):
    scenario: str = Field(min_length=3, max_length=40)


@app.get("/drills/scenarios")
async def drill_scenarios(claims: dict = Depends(get_current_claims)):
    return {"scenarios": [{"key": k, **v} for k, v in drills.SCENARIOS.items()],
            "scoring": {"points": drills.POINTS, "ack_bands": drills.ACK_BANDS, "close_bands": drills.CLOSE_BANDS,
                        "floors": {"ack": drills.ACK_FLOOR, "close": drills.CLOSE_FLOOR},
                        "min_note_chars": drills.MIN_NOTE_CHARS, "expire_hours": drills.EXPIRE_HOURS}}


@app.get("/drills/stats")
async def drill_stats(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await drills.stats(db, org_id_from_claims(claims))


@app.get("/drills")
async def list_drills(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(PurpleDrill).where(PurpleDrill.organization_id == org_id_from_claims(claims))
                             .order_by(PurpleDrill.started_at.desc()).limit(50))).scalars().all()
    return [drills.view(r) for r in rows]


@app.post("/drills", status_code=status.HTTP_201_CREATED)
async def start_drill(payload: DrillStart, claims: dict = Depends(require_role("admin", "soc_manager")),
                      db: AsyncSession = Depends(get_db)):
    try:
        drill = await drills.start(db, org_id_from_claims(claims), claims.get("email") or claims.get("sub", ""), payload.scenario)
    except drills.DrillError as exc:
        await db.rollback()
        code = status.HTTP_409_CONFLICT if "en curso" in str(exc) else status.HTTP_502_BAD_GATEWAY if "SIEM" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc))
    await db.commit()
    return drills.view(drill)


@app.get("/drills/{drill_id}")
async def get_drill(drill_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    drill = await db.get(PurpleDrill, drill_id)
    if drill is None or drill.organization_id != org_id_from_claims(claims):
        raise HTTPException(status_code=404, detail="Simulacro no encontrado")
    await drills.step(db, drill)  # no espera al ciclo de fondo: la pantalla ve el estado al instante
    await db.commit()
    return drills.view(drill)


@app.post("/drills/{drill_id}/cancel")
async def cancel_drill(drill_id: str, claims: dict = Depends(require_role("admin", "soc_manager")),
                       db: AsyncSession = Depends(get_db)):
    drill = await db.get(PurpleDrill, drill_id)
    if drill is None or drill.organization_id != org_id_from_claims(claims):
        raise HTTPException(status_code=404, detail="Simulacro no encontrado")
    await drills.cancel(db, drill, claims.get("email") or claims.get("sub", ""))
    await db.commit()
    return drills.view(drill)
