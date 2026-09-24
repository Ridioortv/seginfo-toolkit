.PHONY: up down logs test lint migrate seed

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
	@for svc in auth-service vuln-service purple-service scan-service; do \
		echo "== pytest: $$svc =="; \
		docker compose exec -T $$svc pytest -q || exit 1; \
	done

lint:
	docker compose exec auth-service ruff check . || true

migrate:
	docker compose exec auth-service alembic upgrade head || true

seed:
	docker compose exec auth-service python -m app.seed || true
