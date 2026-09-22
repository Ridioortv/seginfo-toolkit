# SentinelOps -- launcher para Windows

Codigo fuente (Go) de los dos ejecutables que viven en la raiz del repo:

- `SentinelOps - Iniciar.exe`: revisa que Docker Desktop este instalado y
  corriendo (intenta abrirlo si no lo esta), crea `.env` a partir de
  `.env.example` si es la primera vez, corre
  `docker compose up -d --build`, espera a que auth-service responda en
  `/health`, y abre el dashboard (`http://localhost:5173`) en el
  navegador por defecto.
- `SentinelOps - Detener.exe`: corre `docker compose down` (no borra los
  datos -- los volumenes, como el de Postgres, se conservan).

Ambos asumen que estan ubicados en la raiz del repo, junto a
`docker-compose.yml`, y usan su propia ubicacion para saber en que
carpeta correr Docker Compose -- no dependen de desde donde se los
ejecute.

**Estos dos .exe siguen necesitando Docker Desktop instalado en la PC.**
No empaquetan Postgres/Redis/OpenSearch ni los 12 microservicios dentro
del propio .exe -- eso seria un trabajo de empaquetado mucho mas grande
(y menos mantenible) que no sigue el patron con el que se construyo el
proyecto. Lo que hacen es automatizar el "abrir una terminal y correr
`docker compose up`" para alguien que no quiere usar la linea de
comandos.

## Recompilar

Requiere Go 1.21+. Desde la raiz del repo:

```bash
cd launcher
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "../SentinelOps - Iniciar.exe" ./cmd/iniciar
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "../SentinelOps - Detener.exe" ./cmd/detener
```

Se puede compilar desde Linux/Mac sin instalar nada de Windows (Go
cross-compila de forma nativa) -- por eso se armo en Go y no en un
script de PowerShell empaquetado con alguna herramienta de terceros.

Los `.exe` compilados no se versionan en git (ver `.gitignore` de la
raiz del repo) porque son binarios generados; lo que se versiona es este
codigo fuente.
