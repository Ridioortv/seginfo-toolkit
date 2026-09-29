.PHONY: up down logs test test-openvas lint migrate seed

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	@# Corre pytest dentro de cada microservicio que ya tiene tests/ (ver STATUS.md).
	@# Requiere `docker compose up -d` primero -- las dependencias (sqlalchemy,
	@# httpx, pytest, etc.) ya estan instaladas en cada imagen via requirements.txt.
	@# openvas-orchestrator NO esta en esta lista porque solo corre bajo el
	@# profile opcional "openvas" (ver docker-compose.yml) -- no siempre esta
	@# arriba. Usar `make test-openvas` para correr sus tests.
	@for svc in auth-service vuln-service purple-service scan-service; do \
		echo "== pytest: $$svc =="; \
		docker compose exec -T $$svc pytest -q || exit 1; \
	done

test-openvas:
	@# openvas-orchestrator solo esta arriba con el profile "openvas" activo --
	@# si el `exec` de abajo falla con "service is not running", levantarlo
	@# primero: `docker compose --profile openvas up -d openvas-orchestrator`.
	docker compose exec -T openvas-orchestrator pytest -q

lint:
	docker compose exec auth-service ruff check . || true

migrate:
	docker compose exec auth-service alembic upgrade head || true

seed:
	docker compose exec auth-service python -m app.seed || true
