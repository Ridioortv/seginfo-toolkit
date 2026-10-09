## Que cambia

## Checklist de seguridad
- [ ] No agrego secretos, tokens ni archivos `.env` (el hook pre-commit y CI los detectan)
- [ ] Los endpoints nuevos usan `require_role(...)` y filtran por `organization_id`
- [ ] Toda entrada externa (URLs, rutas, nombres) esta validada (ver `backend/shared/ssrf_guard.py`)
- [ ] No hay SQL armado con datos del usuario (solo parametros / ORM)
- [ ] Tests nuevos o actualizados y en verde
- [ ] Si toca dependencias: revise el resultado de `pip-audit` / `npm audit`
