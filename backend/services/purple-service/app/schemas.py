"""Pydantic schemas for purple-service."""
import re
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class TechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactic: str


class ExerciseCreate(BaseModel):
    name: str
    description: str = ""
    declared_technique_ids: list[str] = Field(
        default_factory=list,
        # validate_default=True: sin esto, pydantic v2 no corre el
        # validator de abajo cuando el caller omite el campo por completo
        # (usa el default_factory tal cual, sin pasar por
        # _require_at_least_one_technique) -- un caller sin UI que no
        # mande declared_technique_ids se colaria igual con una lista
        # vacia.
        validate_default=True,
        description="IDs de tecnicas ATT&CK declaradas como probadas (datos, nunca ejecucion)",
    )

    @field_validator("declared_technique_ids")
    @classmethod
    def _require_at_least_one_technique(cls, v: list[str]) -> list[str]:
        # El frontend ya bloquea el submit sin tecnicas marcadas (ver
        # PurpleTeam.tsx::onCreateExercise), pero este endpoint tambien lo
        # usa soar-service/otros callers sin UI -- sin este chequeo server
        # side se podia declarar un ejercicio con 0 tecnicas, que despues
        # el gap analysis interpretaba (por un bug ya corregido en
        # _build_coverage) como "sin recorte", calculando la cobertura
        # contra TODO el catalogo ATT&CK en vez de reportar 0 declaradas.
        if not v:
            raise ValueError("declared_technique_ids no puede estar vacio: hay que declarar al menos una tecnica")
        if len(v) > 400:
            raise ValueError("Demasiadas tecnicas declaradas (maximo 400)")
        # Formato ATT&CK (T1566 o T1566.001). Antes se aceptaba cualquier texto
        # ("T9999", "no-tecnica") y la cobertura lo ignoraba en silencio.
        out: list[str] = []
        for raw in v:
            tid = (raw or "").strip().upper()
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
                raise ValueError(f"'{raw}' no es un ID de tecnica ATT&CK valido (ej. T1566 o T1566.001)")
            if tid not in out:
                out.append(tid)
        return out

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("El nombre del ejercicio es obligatorio (hasta 255 caracteres)")
        return v


class TechniqueCoverage(BaseModel):
    technique_id: str
    name: str
    tactic: str
    covered: bool
    matching_rules: list[str] = Field(default_factory=list)


class CoverageResult(BaseModel):
    exercise_id: str | None = None
    total_techniques: int
    covered_count: int
    coverage_pct: float
    by_tactic: dict[str, dict] = Field(default_factory=dict)
    techniques: list[TechniqueCoverage] = Field(default_factory=list)
    gaps: list[TechniqueCoverage] = Field(default_factory=list)


class ExerciseOut(BaseModel):
    id: str
    name: str
    description: str
    declared_technique_ids: list[str]
    last_coverage_result: dict
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
