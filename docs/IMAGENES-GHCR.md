# Imágenes prearmadas (GHCR) e instalación rápida

Las imágenes de Docker de TERO Security se arman **una vez** en GitHub Actions y se suben a
GitHub Container Registry (privado) como `ghcr.io/<dueño>/tero-<servicio>:<versión>`. Las PCs de
los clientes las **bajan** en lugar de compilarlas.

| Qué | Dónde |
|---|---|
| Versión de las imágenes | archivo `VERSION` (ej. `1.0.0`) |
| Nombre de las imágenes | `ghcr.io/ridioortv/tero-auth-service:1.0.0`, `tero-scan-service`, `tero-frontend`, `tero-base`... (variables `TERO_REGISTRY` y `TERO_VERSION`) |
| Quién las publica | `.github/workflows/publicar-imagenes.yml` |
| Imagen base común | `backend/Dockerfile.base` (13 servicios simples heredan de ella; `scan-service` y `coderepo-service` tienen su propio Dockerfile) |

## Publicar una versión

1. Subir `VERSION` (ej. `1.1.0`) y mergear a `main`.
2. `git tag v1.1.0 && git push origin v1.1.0` (o *Actions → Publicar imagenes → Run workflow* con `1.1.0`).
   El workflow falla si la versión pedida no coincide con `VERSION`.
3. Compose construye primero `tero-base` y después los demás; todo se sube con `docker compose push`.
4. La primera vez, en GitHub → *Packages* → cada paquete → **Package settings**: dejarlo **Private** y, si hace
   falta, conectarlo al repositorio (así `GITHUB_TOKEN` puede publicar las versiones siguientes).

## Dar acceso a un cliente

Crear un **Personal access token (classic)** con el único permiso `read:packages` (y dar acceso de lectura a
los paquetes a esa cuenta). El cliente corre una vez `echo TOKEN | docker login ghcr.io -u USUARIO --password-stdin`.
Si la cuenta es una organización, conviene una cuenta de servicio de solo lectura por cliente para poder revocarlo.

## Windows vs. Linux Mint

* **Windows:** el `.exe` corre `docker compose up -d --build` sobre `docker-compose.yml` del repo, por eso ese archivo
  conserva los bloques `build:` (más el `image:` de cada servicio). Sigue compilando en la PC.
* **Linux Mint:** `tools/generar_linuxmint.py` parte el compose en `docker-compose.yml` (solo `image:`, con la versión
  del archivo `VERSION` como valor por defecto) y `docker-compose.dev.yml` (solo `build:`, para `./tero-iniciar.sh --compilar`).

## Límites conocidos

* El frontend publicado trae las URLs de las APIs **fijadas en el build** (`http://localhost:800X`). Para usar el panel
  desde otra PC de la LAN hay que compilar el frontend con `VITE_*_API_BASE_URL` propias (`--compilar`).
* Los `tests/` de cada servicio siguen dentro de la imagen (`make test` los corre ahí), por eso no están en `.dockerignore`.
* Las imágenes no se firman ni llevan SBOM (se desactivaron las *attestations* de BuildKit a propósito).
