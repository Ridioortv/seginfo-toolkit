# Dependencias de terceros (librerias)

Complementa `THIRD-PARTY-LICENSES.md` (motores de escaneo). Lista las librerias
que usan los servicios de SentinelOps, con la licencia declarada por cada
paquete. Se genero a partir de los `requirements.txt` de los servicios
(resolviendo dependencias transitivas) y del `package-lock.json` del frontend.
Ninguna es GPL/AGPL/SSPL; las unicas con copyleft son `semgrep` (LGPL-2.1, se
invoca como programa externo, ver `licenses/SEMGREP-LGPL-SOURCE-OFFER.txt`) y
`certifi` (MPL-2.0, sin modificar). El texto de cada licencia esta en el
propio paquete instalado y en su sitio oficial (PyPI / npm).

## Imagenes base de Docker

| Imagen | Licencia |
|---|---|
| python:3.11-slim | PSF-2.0 (Python) sobre Debian (licencias libres varias, codigo fuente en debian.org) |
| node:20-slim | MIT (Node.js) sobre Debian |
| postgres:16-alpine | PostgreSQL License (permisiva) |
| redis:7.2-alpine | BSD-3-Clause (version 7.2.x; las 7.4 y posteriores NO son BSD, por eso se fija) |
| opensearchproject/opensearch:2.16.0 | Apache-2.0 |

## Launcher de Windows (`SentinelOps - Iniciar.exe` / `Detener.exe`)

Estan escritos en Go sin librerias externas; incluyen la libreria estandar y el runtime de Go, bajo BSD-3-Clause, Copyright The Go Authors (texto en `licenses/go-BSD-3-Clause.txt`).

## Resumen Python (120 paquetes)

| Licencia | Cantidad |
|---|---|
| MIT | 51 |
| Apache Software | 25 |
| BSD | 13 |
| BSD-3-Clause | 7 |
| Apache-2.0 | 3 |
| Python Software Foundation | 2 |
| BSD-2-Clause | 2 |
| Apache Software; MIT | 2 |
| Apache-2.0 AND MIT | 1 |
| Mozilla Public 2.0 (MPL 2.0) | 1 |
| MIT-0 | 1 |
| 0BSD | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 |
| ISC (ISCL) | 1 |
| The Unlicense (Unlicense) | 1 |
| MIT AND PSF-2.0 | 1 |
| Apache License 2.0 | 1 |
| Apache-2.0 OR BSD-2-Clause | 1 |
| MIT-CMU | 1 |
| 3-Clause BSD License | 1 |
| Apache Software; BSD | 1 |
| GNU Lesser General Public v2 (LGPLv2) | 1 |
| PSF-2.0 | 1 |

## Detalle Python

| Paquete | Version | Licencia |
|---|---|---|
| aiohappyeyeballs | 2.7.1 | Python Software Foundation |
| aiohttp | 3.14.3 | Apache-2.0 AND MIT |
| aiosignal | 1.4.0 | Apache Software |
| alembic | 1.13.2 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| apscheduler | 3.10.4 | MIT |
| async-timeout | 5.0.1 | Apache Software |
| asyncpg | 0.29.0 | Apache Software |
| attrs | 26.1.0 | MIT |
| bcrypt | 4.0.1 | Apache Software |
| boltons | 21.0.0 | BSD |
| boto3 | 1.35.36 | Apache Software |
| botocore | 1.35.99 | Apache Software |
| bracex | 3.0.1 | MIT |
| cachetools | 5.5.2 | MIT |
| certifi | 2026.7.22 | Mozilla Public 2.0 (MPL 2.0) |
| cffi | 2.1.1 | MIT-0 |
| chardet | 7.6.0 | 0BSD |
| charset-normalizer | 3.5.2 | MIT |
| click-option-group | 0.5.9 | BSD |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| defusedxml | 0.7.1 | Python Software Foundation |
| deprecated | 1.3.1 | MIT |
| dnspython | 2.8.0 | ISC (ISCL) |
| ecdsa | 0.19.2 | MIT |
| email_validator | 2.2.0 | The Unlicense (Unlicense) |
| events | 0.5 | BSD |
| exceptiongroup | 1.2.2 | MIT |
| exceptiongroup | 1.3.1 | MIT |
| face | 26.0.1 | BSD-3-Clause |
| fastapi | 0.115.0 | MIT |
| frozenlist | 1.8.0 | Apache-2.0 |
| glom | 22.1.0 | BSD |
| google-auth | 2.34.0 | Apache Software |
| googleapis-common-protos | 1.75.0 | Apache Software |
| greenlet | 3.5.6 | MIT AND PSF-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD |
| httptools | 0.8.0 | MIT |
| httpx | 0.27.2 | BSD |
| idna | 3.20 | BSD-3-Clause |
| importlib_metadata | 7.1.0 | Apache Software |
| iniconfig | 2.3.0 | MIT |
| jmespath | 1.1.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| jsonschema | 4.26.0 | MIT |
| mako | 1.4.3 | MIT |
| markdown-it-py | 4.2.0 | MIT |
| markupsafe | 3.0.4 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT |
| multidict | 6.9.1 | Apache License 2.0 |
| opensearch-py | 2.7.1 | Apache Software |
| opentelemetry-api | 1.25.0 | Apache Software |
| opentelemetry-exporter-otlp-proto-common | 1.25.0 | Apache Software |
| opentelemetry-exporter-otlp-proto-http | 1.25.0 | Apache Software |
| opentelemetry-instrumentation-requests | 0.46b0 | Apache Software |
| opentelemetry-instrumentation | 0.46b0 | Apache Software |
| opentelemetry-proto | 1.25.0 | Apache Software |
| opentelemetry-sdk | 1.25.0 | Apache Software |
| opentelemetry-semantic-conventions | 0.46b0 | Apache Software |
| opentelemetry-util-http | 0.46b0 | Apache Software |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| passlib | 1.7.4 | BSD |
| peewee | 3.19.0 | MIT |
| pillow | 12.3.0 | MIT-CMU |
| pluggy | 1.6.0 | MIT |
| prometheus_client | 0.20.0 | Apache Software |
| propcache | 0.5.4 | Apache-2.0 |
| protobuf | 4.25.9 | 3-Clause BSD License |
| pyasn1 | 0.6.4 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic-settings | 2.5.2 | MIT |
| pydantic | 2.8.2 | MIT |
| pydantic | 2.9.2 | MIT |
| pydantic_core | 2.20.1 | MIT |
| pydantic_core | 2.23.4 | MIT |
| pygments | 2.21.0 | BSD-2-Clause |
| pyotp | 2.9.0 | MIT |
| pytest | 8.3.3 | MIT |
| python-dateutil | 2.9.0.post0 | Apache Software; BSD |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-jose | 3.3.0 | MIT |
| python-multipart | 0.0.9 | Apache Software |
| pytz | 2026.5 | MIT |
| pyyaml | 6.0.2 | MIT |
| pyyaml | 6.0.3 | MIT |
| redis | 5.0.8 | MIT |
| referencing | 0.37.0 | MIT |
| reportlab | 4.2.5 | BSD |
| requests | 2.32.3 | Apache Software |
| requests | 2.34.2 | Apache Software |
| rich | 15.0.0 | MIT |
| rpds-py | 0.30.0 | MIT |
| rsa | 4.9.1 | Apache Software |
| ruamel.yaml.clib | 0.2.15 | MIT |
| ruamel.yaml | 0.17.40 | MIT |
| s3transfer | 0.10.4 | Apache Software |
| semgrep | 1.86.0 | GNU Lesser General Public v2 (LGPLv2) |
| setuptools | 84.0.0 | MIT |
| six | 1.17.0 | MIT |
| sniffio | 1.3.1 | Apache Software; MIT |
| sqlalchemy | 2.0.35 | MIT |
| starlette | 0.38.6 | BSD |
| tomli | 2.0.2 | MIT |
| tomli | 2.4.1 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| tzlocal | 5.4.4 | MIT |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.30.6 | BSD |
| uvloop | 0.23.0 | Apache Software; MIT |
| watchfiles | 1.3.0 | MIT |
| wcmatch | 8.5.2 | MIT |
| websockets | 16.1.1 | BSD-3-Clause |
| wrapt | 1.17.3 | BSD |
| yarl | 1.25.1 | Apache-2.0 |
| zipp | 4.1.1 | MIT |

## Frontend (JavaScript) - paquetes que se incluyen en la app (42)

Las herramientas de desarrollo/compilacion (eslint, vite, vitest, typescript, etc.) no se distribuyen dentro de la aplicacion.

| Paquete | Version | Licencia |
|---|---|---|
| @remix-run/router | 1.23.4 | MIT |
| @tanstack/query-core | 5.103.2 | MIT |
| @tanstack/react-query | 5.103.2 | MIT |
| @types/prop-types | 15.7.15 | MIT |
| @types/react | 18.3.31 | MIT |
| agent-base | 6.0.2 | MIT |
| asynckit | 0.4.0 | MIT |
| axios | 1.20.0 | MIT |
| call-bind-apply-helpers | 1.0.2 | MIT |
| combined-stream | 1.0.8 | MIT |
| csstype | 3.2.3 | MIT |
| debug | 4.4.3 | MIT |
| delayed-stream | 1.0.0 | MIT |
| dunder-proto | 1.0.1 | MIT |
| es-define-property | 1.0.1 | MIT |
| es-errors | 1.3.0 | MIT |
| es-object-atoms | 1.1.2 | MIT |
| es-set-tostringtag | 2.1.0 | MIT |
| follow-redirects | 1.16.0 | MIT |
| form-data | 4.0.6 | MIT |
| function-bind | 1.1.2 | MIT |
| get-intrinsic | 1.3.0 | MIT |
| get-proto | 1.0.1 | MIT |
| gopd | 1.2.0 | MIT |
| has-symbols | 1.1.0 | MIT |
| has-tostringtag | 1.0.2 | MIT |
| hasown | 2.0.4 | MIT |
| https-proxy-agent | 5.0.1 | MIT |
| js-tokens | 4.0.0 | MIT |
| loose-envify | 1.4.0 | MIT |
| math-intrinsics | 1.1.0 | MIT |
| mime-db | 1.52.0 | MIT |
| mime-types | 2.1.35 | MIT |
| ms | 2.1.3 | MIT |
| proxy-from-env | 2.1.0 | MIT |
| react | 18.3.1 | MIT |
| react-dom | 18.3.1 | MIT |
| react-router | 6.30.6 | MIT |
| react-router-dom | 6.30.6 | MIT |
| scheduler | 0.23.2 | MIT |
| use-sync-external-store | 1.7.0 | MIT |
| zustand | 4.5.7 | MIT |
