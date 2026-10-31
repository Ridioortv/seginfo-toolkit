"""Riesgo de proveedores (terceros): cuestionario de seguridad, puntaje y nivel de riesgo.

Reglas del puntaje (todas deterministas y explicables, nada de cajas negras):

  * El cuestionario lo responde el PROVEEDOR (por un link con vencimiento). Cada respuesta vale: si = 1, parcial = 0,5,
    no = 0; "no aplica" se excluye del calculo. Cada pregunta tiene un peso. Puntaje de controles = suma de puntos / suma
    de pesos aplicables, de 0 a 100.
  * Las preguntas "eliminatorias" (marcadas knockout) son controles basicos: cada "no" en una resta 10 puntos (tope 30).
  * La evidencia vigente (ISO 27001, SOC 2 tipo II, pentest reciente, DPA firmado...) suma hasta 10 puntos. La vencida
    no suma. TERO no valida el contenido de esos documentos: guarda la ficha y el vencimiento.
  * Riesgo residual = criticidad del proveedor (cuanto daño haria una falla) x lo que le falta de controles.
        indice = peso_criticidad x (100 - puntaje_efectivo)       -> 0..100
        >= 50 critico | >= 30 alto | >= 15 medio | < 15 bajo
    Un "no" en un control basico (MFA, cifrado, aviso de brechas) nunca deja el riesgo en "bajo": como minimo "medio".
  * Sin evaluacion completada, o con una evaluacion de mas de 12 meses, el nivel es "sin_evaluar" / "vencida": nunca se
    supone un riesgo bajo por falta de datos.

El puntaje es una ayuda para priorizar; no certifica al proveedor."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

ANSWERS = ("yes", "partial", "no", "na")
POINTS = {"yes": 1.0, "partial": 0.5, "no": 0.0}

CRITICALITY = ("critical", "high", "medium", "low")
CRITICALITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}
CRITICALITY_LABEL = {"critical": "Critico", "high": "Alto", "medium": "Medio", "low": "Bajo"}

DATA_TYPES = ("personal", "financial", "health", "credentials", "intellectual_property", "none")
EVIDENCE_KINDS = ("iso27001", "soc2", "pentest", "dpa", "bcp", "insurance", "other")
EVIDENCE_LABEL = {
    "iso27001": "ISO/IEC 27001", "soc2": "SOC 2 tipo II", "pentest": "Prueba de penetracion",
    "dpa": "Contrato de proteccion de datos (DPA)", "bcp": "Plan de continuidad", "insurance": "Ciberseguro", "other": "Otra",
}
# Cuanto suma cada tipo de evidencia vigente (tope total: EVIDENCE_CAP).
EVIDENCE_BONUS = {"iso27001": 5.0, "soc2": 5.0, "pentest": 3.0, "dpa": 2.0, "bcp": 1.0, "insurance": 1.0, "other": 0.0}
EVIDENCE_CAP = 10.0
KNOCKOUT_PENALTY, KNOCKOUT_CAP = 10.0, 30.0
ASSESSMENT_VALID_DAYS = 365
EVIDENCE_WARN_DAYS = 60
DEFAULT_LINK_DAYS = 30
TEMPLATE_VERSION = "tprm-1"

LEVELS = ("critical", "high", "medium", "low", "unassessed", "stale")
LEVEL_LABEL = {"critical": "Critico", "high": "Alto", "medium": "Medio", "low": "Bajo",
               "unassessed": "Sin evaluar", "stale": "Evaluacion vencida"}

# (id, dominio, pregunta, peso, eliminatoria)
_Q = [
    ("gov-1", "Gobierno", "¿Tienen una politica de seguridad de la informacion aprobada y revisada en los ultimos 12 meses?", 2, False),
    ("gov-2", "Gobierno", "¿Hay una persona o equipo responsable de la seguridad de la informacion?", 2, False),
    ("acc-1", "Accesos", "¿Exigen doble factor de autenticacion (MFA) para el personal que accede a sistemas o a datos de clientes?", 3, True),
    ("acc-2", "Accesos", "¿Los accesos se dan por minimo privilegio y se revisan al menos una vez al año?", 2, False),
    ("acc-3", "Accesos", "¿Dan de baja los accesos el mismo dia que alguien deja la empresa o cambia de funcion?", 2, False),
    ("dat-1", "Datos", "¿Cifran los datos de clientes en transito (TLS) y en reposo?", 3, True),
    ("dat-2", "Datos", "¿Separan los datos de cada cliente y limitan quien puede verlos?", 2, False),
    ("dat-3", "Datos", "¿Tienen definido cuanto tiempo guardan los datos y como los eliminan al terminar el contrato?", 2, False),
    ("dev-1", "Desarrollo seguro", "¿Revisan el codigo y corren pruebas de seguridad antes de publicar cambios?", 2, False),
    ("dev-2", "Desarrollo seguro", "¿Hacen pruebas de penetracion independientes al menos una vez al año?", 2, False),
    ("vul-1", "Vulnerabilidades", "¿Escanean sus sistemas en busca de vulnerabilidades de forma periodica?", 2, False),
    ("vul-2", "Vulnerabilidades", "¿Corrigen las vulnerabilidades criticas dentro de plazos definidos (por ejemplo 15 dias)?", 3, False),
    ("inc-1", "Incidentes", "¿Tienen un plan de respuesta a incidentes probado en los ultimos 12 meses?", 2, False),
    ("inc-2", "Incidentes", "¿Se comprometen por contrato a avisarte de una brecha que te afecte en un plazo definido (por ejemplo 72 horas)?", 3, True),
    ("inc-3", "Incidentes", "¿Registran y conservan logs de seguridad por al menos 6 meses?", 2, False),
    ("bcp-1", "Continuidad", "¿Hacen copias de respaldo y prueban la restauracion al menos una vez al año?", 3, False),
    ("bcp-2", "Continuidad", "¿Tienen un plan de continuidad del negocio y recuperacion ante desastres?", 2, False),
    ("per-1", "Personas", "¿Capacitan en seguridad al personal al menos una vez al año?", 1, False),
    ("per-2", "Personas", "¿Verifican antecedentes del personal con acceso a datos sensibles, cuando la ley lo permite?", 1, False),
    ("sub-1", "Subcontratistas", "¿Evaluan la seguridad de los proveedores que ellos mismos usan para prestarte el servicio?", 2, False),
    ("sub-2", "Subcontratistas", "¿Te informan cuando suman o cambian un subcontratista que toca tus datos?", 2, False),
    ("leg-1", "Legal", "¿Cumplen la normativa de proteccion de datos que les aplica (por ejemplo la Ley 25.326) y pueden mostrarlo?", 2, False),
    ("leg-2", "Legal", "¿Aceptan una clausula de auditoria o de entrega de evidencia de seguridad cuando la pidas?", 1, False),
    ("phy-1", "Fisica", "¿Los equipos y centros de datos donde estan tus datos tienen control de acceso fisico?", 1, False),
]
QUESTIONS = [{"id": i, "domain": d, "text": t, "weight": w, "knockout": k} for i, d, t, w, k in _Q]
QUESTION_BY_ID = {q["id"]: q for q in QUESTIONS}


def public_questions() -> list[dict]:
    """Lo que ve el proveedor: sin pesos ni marcas internas."""
    return [{"id": q["id"], "domain": q["domain"], "text": q["text"]} for q in QUESTIONS]


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class AnswerError(ValueError):
    pass


def validate_answers(raw: object) -> dict[str, dict]:
    """Devuelve {id: {"answer", "comment"}} o levanta AnswerError con un mensaje claro para el proveedor."""
    if not isinstance(raw, dict):
        raise AnswerError("Las respuestas tienen un formato invalido")
    unknown = [k for k in raw if k not in QUESTION_BY_ID]
    if unknown:
        raise AnswerError("Hay respuestas a preguntas que no existen")
    out: dict[str, dict] = {}
    missing = []
    for q in QUESTIONS:
        item = raw.get(q["id"])
        if isinstance(item, str):
            item = {"answer": item}
        if not isinstance(item, dict) or item.get("answer") not in ANSWERS:
            missing.append(q["id"])
            continue
        comment = str(item.get("comment") or "").strip()[:500]
        out[q["id"]] = {"answer": item["answer"], "comment": comment}
    if missing:
        raise AnswerError(f"Faltan responder {len(missing)} pregunta(s)")
    return out


def control_score(answers: dict[str, dict]) -> dict:
    earned = total = 0.0
    knockouts = []
    by_domain: dict[str, list[float]] = {}
    for q in QUESTIONS:
        a = (answers.get(q["id"]) or {}).get("answer")
        if a not in POINTS:
            continue
        earned += q["weight"] * POINTS[a]
        total += q["weight"]
        d = by_domain.setdefault(q["domain"], [0.0, 0.0])
        d[0] += q["weight"] * POINTS[a]
        d[1] += q["weight"]
        if q["knockout"] and a == "no":
            knockouts.append(q["id"])
    base = round(100.0 * earned / total, 1) if total else 0.0
    penalty = min(KNOCKOUT_CAP, KNOCKOUT_PENALTY * len(knockouts))
    return {
        "base": base, "knockouts": knockouts, "knockout_penalty": penalty,
        "domains": {k: round(100.0 * v[0] / v[1], 1) for k, v in by_domain.items() if v[1]},
    }


def evidence_status(valid_until: datetime | None, now: datetime) -> str:
    until = _aware(valid_until)
    if until is None:
        return "vigente"  # sin vencimiento declarado (por ejemplo un DPA firmado)
    if until <= now:
        return "vencida"
    if until <= now + timedelta(days=EVIDENCE_WARN_DAYS):
        return "por_vencer"
    return "vigente"


def evidence_bonus(items: list[dict]) -> float:
    seen: set[str] = set()
    total = 0.0
    for e in items:
        if e["status"] == "vencida" or e["kind"] in seen:
            continue
        seen.add(e["kind"])
        total += EVIDENCE_BONUS.get(e["kind"], 0.0)
    return min(EVIDENCE_CAP, total)


def level_for(index: float) -> str:
    return "critical" if index >= 50 else "high" if index >= 30 else "medium" if index >= 15 else "low"


def assess(criticality: str, assessment: dict | None, evidence: list[dict], now: datetime | None = None) -> dict:
    """Riesgo de un proveedor: `assessment` es la ultima evaluacion completada ({"score_detail", "completed_at"}) o None."""
    now = now or datetime.now(timezone.utc)
    bonus = evidence_bonus(evidence)
    if assessment is None:
        return {"level": "unassessed", "index": None, "effective_score": None, "evidence_bonus": bonus, "stale": False}
    detail = assessment["score_detail"]
    effective = max(0.0, min(100.0, detail["base"] - detail["knockout_penalty"] + bonus))
    idx = round(CRITICALITY_WEIGHT.get(criticality, 0.6) * (100.0 - effective), 1)
    done = _aware(assessment["completed_at"])
    stale = bool(done and now - done > timedelta(days=ASSESSMENT_VALID_DAYS))
    computed = level_for(idx)
    if computed == "low" and detail.get("knockouts"):
        computed = "medium"
    return {"level": "stale" if stale else computed, "index": idx, "effective_score": round(effective, 1),
            "evidence_bonus": bonus, "stale": stale, "computed_level": computed}
