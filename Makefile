.PHONY: up down logs test lint migrate seed

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	docker compose exec auth-service pytest -q || true

lint:
	docker compose exec auth-service ruff check . || true

migrate:
	docker compose exec auth-service alembic upgrade head || true

seed:
	docker compose exec auth-service python -m app.seed || true
