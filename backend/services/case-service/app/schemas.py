"""Pydantic schemas for case-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import CasePriority, CaseStatus


class CaseCreate(BaseModel):
    title: str
    description: str = ""
    priority: CasePriority = CasePriority.medium
    assignee: str = ""
    alert_id: str | None = None
    source: str = "manual"
    # BUG DE SEGURIDAD (corregido aca): este campo existia antes y el
    # endpoint (POST /cases) confiaba en el organization_id que mandaba el
    # propio caller, sin exigir ningun JWT -- cualquiera en internet podia
    # inyectar casos falsos en la cola de SOC de CUALQUIER organizacion con
    # solo adivinar/enumerar un organization_id ajeno (ver infra/k8s/base/
    # ingress.yaml: /api/cases se expone externamente sin distincion de
    # metodo). Ya no es un campo del payload publico: app/main.py::create_case
    # ahora exige un JWT (igual que el resto de los endpoints de este
    # servicio) y resuelve el organization_id SIEMPRE de ese JWT, nunca del
    # body. soar-service (ver app/actions/create_case.py ahi) sigue
    # funcionando igual si manda este campo -- pydantic simplemente lo
    # ignora al no estar declarado, y si el POST sin JWT ahora le devuelve
    # 401 en vez de 2xx, su propio fallback existente guarda la solicitud
    # como PendingCase, que se importa despues por el camino
    # service-to-service autenticado (ver import_pending_cases_from_soar).


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    priority: CasePriority | None = None
    status: CaseStatus | None = None
    assignee: str | None = None


class TimelineEntryOut(BaseModel):
    id: str
    actor: str
    action: str
    notes: str
    created_at: datetime

    class Config:
        from_attributes = True


class CaseOut(BaseModel):
    id: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus
    assignee: str
    alert_id: str | None
    source: str
    sla_due_at: datetime | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    timeline: list[TimelineEntryOut] = Field(default_factory=list)

    class Config:
        from_attributes = True


class TimelineEntryCreate(BaseModel):
    action: str
    notes: str = ""


class ImportResult(BaseModel):
    imported: int
    skipped: int
