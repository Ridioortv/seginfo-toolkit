"""Pydantic schemas for purple-service."""
from datetime import datetime
from pydantic import BaseModel, Field


class TechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactic: str


class ExerciseCreate(BaseModel):
    name: str
    description: str = ""
    declared_technique_ids: list[str] = Field(
        default_factory=list,
        description="IDs de tecnicas ATT&CK declaradas como probadas (datos, nunca ejecucion)",
    )


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
