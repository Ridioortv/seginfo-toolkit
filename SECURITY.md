# Politica de seguridad

## Reportar una vulnerabilidad

**No abras un issue publico.** Usa el reporte privado de GitHub:
<https://github.com/Ridioortv/seginfo-toolkit/security/advisories/new>

Incluye: componente afectado, pasos para reproducir e impacto estimado.
Respuesta inicial objetivo: 72 horas. Corregimos primero y publicamos despues
(divulgacion coordinada).

## Versiones soportadas

Solo la rama `main` y el ultimo release reciben correcciones de seguridad.

## Practicas del proyecto

- Secretos solo en `.env` local (ignorado por git); hook pre-commit y gitleaks en CI.
- Analisis automatico en cada PR y semanal: CodeQL, Bandit, pip-audit, npm audit, Trivy, Hadolint.
- Dependabot para dependencias, imagenes Docker y GitHub Actions.
- Contenedores sin privilegios extra (`no-new-privileges`, usuario no root) y puertos solo en `127.0.0.1`.
- Control de acceso por rol (`admin`, `soc_manager`, `analyst`) y aislamiento por organizacion.
