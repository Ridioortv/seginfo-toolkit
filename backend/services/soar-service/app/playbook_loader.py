"""Carga los playbooks YAML del directorio playbooks/ y los sincroniza con
la tabla `playbooks` al arrancar el servicio (si un playbook con el mismo
`name` ya existe, se actualiza su contenido pero se respeta `is_enabled` tal
como haya quedado editado desde la API/UI)."""
import pathlib
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import Playbook

logger = configure_logging("soar-service.playbook_loader")
PLAYBOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "playbooks"


async def sync_playbooks_from_yaml(db: AsyncSession) -> int:
    if not PLAYBOOKS_DIR.exists():
        return 0

    synced = 0
    for yaml_file in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.warning("playbook YAML invalido, se omite", extra={"file": yaml_file.name, "error": str(exc)})
            continue

        name = data.get("name")
        if not name:
            continue

        result = await db.execute(select(Playbook).where(Playbook.name == name))
        existing = result.scalar_one_or_none()
        if existing is None:
            db.add(
                Playbook(
                    name=name,
                    description=data.get("description", ""),
                    min_severity=data.get("min_severity", "high"),
                    rule_tags=data.get("rule_tags", []),
                    steps=data.get("steps", []),
                    source_file=yaml_file.name,
                )
            )
        else:
            existing.description = data.get("description", existing.description)
            existing.min_severity = data.get("min_severity", existing.min_severity)
            existing.rule_tags = data.get("rule_tags", existing.rule_tags)
            existing.steps = data.get("steps", existing.steps)
            existing.source_file = yaml_file.name
        synced += 1

    await db.flush()
    return synced
