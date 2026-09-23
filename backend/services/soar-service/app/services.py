"""Business logic for soar-service: matching de playbooks contra una alerta
(por severidad minima) y ejecucion secuencial de sus pasos via el registro
de acciones (app/actions/*). Todas las acciones son de contencion defensiva
y corren en dry-run por defecto -- ver app/actions/base.py. No hay ninguna
ruta de codigo aca que ejecute algo contra un objetivo real."""
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import Playbook, PlaybookRun, PendingCase, RunStatus
from app.actions.block_ip import BlockIpAction
from app.actions.isolate_host import IsolateHostAction
from app.actions.create_case import CreateCaseAction
from app.actions.create_ticket import CreateTicketAction
from app.actions.notify import NotifyAction

logger = configure_logging("soar-service")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

ACTIONS = {
    "block_ip": BlockIpAction(),
    "isolate_host": IsolateHostAction(),
    "create_case": CreateCaseAction(),
    "create_ticket": CreateTicketAction(),
    "notify": NotifyAction(),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _severity_meets_minimum(alert_severity: str, min_severity: str) -> bool:
    return _SEVERITY_RANK.get(alert_severity, 0) >= _SEVERITY_RANK.get(min_severity, 0)


async def _run_steps(db: AsyncSession, playbook: Playbook, context: dict, triggered_by: str) -> PlaybookRun:
    run = PlaybookRun(
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        alert_id=context.get("alert", {}).get("id"),
        status=RunStatus.running,
        triggered_by=triggered_by,
    )
    db.add(run)
    await db.flush()
    context["playbook_run_id"] = run.id

    steps_log = []
    overall_ok = True
    for step in playbook.steps:
        action_name = step.get("action")
        executor = ACTIONS.get(action_name)
        if executor is None:
            steps_log.append({"action": action_name, "success": False, "message": f"Accion desconocida: {action_name}"})
            overall_ok = False
            continue
        result = await executor.execute(step.get("params", {}), context)
        steps_log.append({
            "action": action_name,
            "success": result.success,
            "simulated": result.simulated,
            "message": result.message,
            "details": result.details,
        })
        if not result.success:
            overall_ok = False
        logger.info(
            "paso de playbook ejecutado",
            extra={"playbook": playbook.name, "action": action_name, "success": result.success, "simulated": result.simulated},
        )

    run.steps_log = steps_log
    run.status = RunStatus.completed if overall_ok else RunStatus.failed
    run.finished_at = _now()
    await db.flush()
    await db.refresh(run)
    return run


async def trigger_playbooks(db: AsyncSession, payload) -> tuple[int, list[PlaybookRun]]:
    """Llamado por siem-service cuando se genera una alerta (ver
    siem-service/app/services.py _notify_soar). Corre TODOS los playbooks
    habilitados cuyo min_severity sea <= la severidad de la alerta."""
    result = await db.execute(select(Playbook).where(Playbook.is_enabled.is_(True)))
    playbooks = list(result.scalars().all())
    matched = [p for p in playbooks if _severity_meets_minimum(payload.severity, p.min_severity)]

    context_base = {
        "event": payload.event,
        "alert": {"id": payload.alert_id, "severity": payload.severity, "rule_name": payload.rule_name},
        "db": db,
    }

    runs = []
    for playbook in matched:
        run = await _run_steps(db, playbook, dict(context_base), triggered_by="siem-service")
        runs.append(run)

    await db.flush()
    return len(matched), runs


async def run_playbook_manually(db: AsyncSession, playbook: Playbook, payload) -> PlaybookRun:
    context = {
        "event": payload.event,
        "alert": {"id": payload.alert_id, "severity": payload.event.get("severity", "medium"), "rule_name": ""},
        "db": db,
    }
    return await _run_steps(db, playbook, context, triggered_by="manual")


async def list_playbooks(db: AsyncSession) -> list[Playbook]:
    result = await db.execute(select(Playbook).order_by(Playbook.name))
    return list(result.scalars().all())


async def get_playbook(db: AsyncSession, playbook_id: str) -> Playbook | None:
    return await db.get(Playbook, playbook_id)


async def create_playbook(db: AsyncSession, payload) -> Playbook:
    playbook = Playbook(**payload.model_dump())
    db.add(playbook)
    await db.flush()
    await db.refresh(playbook)
    return playbook


async def update_playbook(db: AsyncSession, playbook: Playbook, payload) -> Playbook:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(playbook, field, value)
    await db.flush()
    await db.refresh(playbook)
    return playbook


async def list_runs(db: AsyncSession) -> list[PlaybookRun]:
    result = await db.execute(select(PlaybookRun).order_by(PlaybookRun.created_at.desc()))
    return list(result.scalars().all())


async def get_run(db: AsyncSession, run_id: str) -> PlaybookRun | None:
    return await db.get(PlaybookRun, run_id)


async def list_pending_cases(db: AsyncSession) -> list[PendingCase]:
    result = await db.execute(select(PendingCase).order_by(PendingCase.created_at.desc()))
    return list(result.scalars().all())
