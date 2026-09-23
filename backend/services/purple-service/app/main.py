"""purple-service entrypoint: gap analysis de cobertura MITRE ATT&CK sobre
ejercicios purple team declarados. SOLO calcula metricas a partir de datos
(tags de reglas Sigma de siem-service); no incluye ningun motor de
simulacion/ejecucion de tecnicas -- ver docs/architecture.md 'Fuera de
alcance (deliberado)'."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import TechniqueOut, ExerciseCreate, ExerciseOut, CoverageResult
from app.dependencies import get_current_claims, require_role
from app.attack_data import ATTACK_TECHNIQUES
from app import services

logger = configure_logging("purple-service")
exercises_created_total = Counter("purple_exercise_created_total", "Ejercicios purple team creados")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE purple_exercises ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
        await conn.execute(text(
            f"UPDATE purple_exercises SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    logger.info("purple-service iniciado")
    yield


app = FastAPI(title="SentinelOps Purple Team Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
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
    claims: dict = Depends(get_current_claims),
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
