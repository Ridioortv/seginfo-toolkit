.PHONY: up down logs test test-rapido lint migrate seed

# Sin SBOM/provenance de BuildKit (capas extra, build mas lento) y a lo sumo
# 3 imagenes compilandose a la vez.
export BUILDX_NO_DEFAULT_ATTESTATIONS ?= 1
export COMPOSE_PARALLEL_LIMIT ?= 3

# Para desarrollo: COMPILA las imagenes en la PC (docker-compose.dev.yml). El uso normal es
# `docker compose pull && docker compose up -d` con las imagenes ya publicadas (docker-compose.yml).
COMPOSE_DEV = docker compose -f docker-compose.yml -f docker-compose.dev.yml

up:
	$(COMPOSE_DEV) up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	@# Si existe tero-probar.sh (paquete Linux Mint) corre TODAS las pruebas con un veredicto unico
	@# (ver pruebas/LEEME.md). Si no, corre pytest dentro de cada microservicio que ya tiene tests/
	@# (requiere `docker compose up -d` primero: las dependencias ya estan en cada imagen).
	@if [ -x ./tero-probar.sh ]; then \
		./tero-probar.sh; \
	else \
		for svc in auth-service vuln-service purple-service scan-service; do \
			echo "== pytest: $$svc =="; \
			docker compose exec -T $$svc pytest -q || exit 1; \
		done; \
	fi

test-rapido:
	./tero-probar.sh --rapido

lint:
	docker compose exec auth-service ruff check . || true

migrate:
	docker compose exec auth-service alembic upgrade head || true

seed:
	docker compose exec auth-service python -m app.seed || true
