# Gobernanza de IA en el codigo

App dentro de TERO (menu **Gobernanza de IA**, ruta `/ai-governance`, API `coderepo-service` bajo `/governance`).
Pensada para empresas grandes que quieren usar IA para escribir codigo (vibecoding) con control, evidencia y
transparencia.

## Que hace

1. **Procedencia (contador de modificaciones).** Al escanear un repositorio conectado, TERO lee el historial de
   git y registra cada commit: autor, fecha, si lo escribio una persona (`human`), una IA (`ai`) o ambas
   (`mixed`), herramienta, modelo, prompt resumido, lineas agregadas/quitadas, archivos y hallazgos.
2. **Compuerta de seguridad.** Cada cambio se evalua: secretos (gitleaks), 16 patrones inseguros en las lineas
   agregadas (eval/exec, `shell=True`, SQL armado con texto, TLS desactivado, hashes debiles...), revision
   humana exigida por la politica, y si la IA esta permitida en esa zona. Resultado: `passed`, `blocked`
   (politica en modo *Exigir*) u `observed_fail` ("hubiera bloqueado", modo *Observar*).
3. **Registro auditable.** Cadena de entradas por organizacion: cada entrada guarda el hash de la anterior y una
   firma HMAC-SHA256 con una clave que no esta en la base. Se puede verificar desde la pantalla, exportar
   (JSON verificable o CSV) y comparar contra un **ancla externa** (cantidad de entradas + hash final) guardada
   fuera de TERO para detectar que alguien borro las ultimas entradas.
4. **Politicas por equipo o zona.** IA `allowed` / `restricted` / `forbidden`, aprobaciones humanas (0 a 3),
   umbral de severidad que frena el cambio, repositorio y carpetas (`src/pagos/, infra/`), modo *Observar* o
   *Exigir*. Si varias aplican a un cambio, gana la mas estricta. Recomendado: empezar en *Observar* un mes.
5. **Tablero para direccion.** % de codigo con IA, cobertura de revision del codigo con IA, cambios marcados por
   la compuerta, hallazgos cada 1000 lineas (IA vs humano), tendencia semanal, herramientas y detalle por
   repositorio. El ahorro de horas es una estimacion que carga la persona (no se mide solo).

## Como se sabe que un cambio es de IA

Por las marcas del commit: lineas `Co-Authored-By:` de Claude, Copilot, Cursor, Aider y otras; `Assisted-by:`;
"Generated with ..."; autores bot; o trailers propios:

```
AI-Origin: mixed        # human | ai | mixed
AI-Tool: Cursor
AI-Model: gpt-5
AI-Prompt: resumen del pedido
```

Un commit sin marcas cuenta como humano **hasta que alguien lo declare** en la pantalla (queda en el registro
con el valor anterior y el nuevo). TERO no puede adivinar IA sin marcas: es un limite de cualquier herramienta.

## Roles

- Ver todo: cualquier usuario autenticado de la organizacion.
- Revisar, declarar origen, consultar la compuerta por API: `admin`, `soc_manager`, `analyst`.
- Crear/editar/borrar politicas: `admin`, `soc_manager`.
- Con una politica en modo *Exigir* aplicable, quien escribio el cambio no puede aprobarlo el mismo.

## Compuerta en el pipeline (GitHub Actions)

Pantalla **Compuerta** -> "Conectar la compuerta a tu pipeline": genera el workflow listo para copiar. Llama a
`POST /governance/gate/evaluate` con un token de TERO (secreto `TERO_TOKEN`, usuario con rol analyst o mayor) y
falla el job si `allowed` es `false`. El servidor de TERO debe ser accesible desde el runner (o usar un runner
propio). El repositorio tiene que estar conectado en TERO.

## API

| Metodo | Ruta | Para que |
|---|---|---|
| GET | `/governance/changes` | cambios (filtros: repo, origen, compuerta, texto; paginado) |
| GET | `/governance/changes/{id}` | detalle de un cambio |
| POST | `/governance/changes/{id}/review` | aprobar/rechazar, o declarar origen |
| POST | `/governance/gate/evaluate` | consulta de la compuerta desde CI |
| GET | `/governance/gate/runs` | historial de evaluaciones |
| GET/POST/PUT/DELETE | `/governance/policies` | politicas |
| GET | `/governance/metrics?days=&hours_per_ai_change=` | tablero |
| GET | `/governance/ledger`, `/ledger/verify`, `/ledger/anchor`, `/ledger/export?format=json\|csv` | registro auditable |

## Variables de entorno

- `AUDIT_LEDGER_KEY` (opcional): clave de firma del registro. Si falta se deriva de `JWT_SECRET_KEY`; con una
  clave propia, rotar el JWT no invalida las firmas viejas. Guardala fuera de la base y no la cambies si ya hay
  registro: la verificacion fallaria para lo anterior.
- `CODEREPO_GOV_MAX_COMMITS` (default 300): commits nuevos que se leen por escaneo de cada repositorio.

## Limites conocidos

- La deteccion de IA depende de las marcas del commit y de lo que declaren las personas.
- Los patrones inseguros son reglas simples sobre lineas agregadas (no un analisis de flujo de datos); para eso
  siguen estando gitleaks y trivy en el mismo escaneo. Las reglas que detectan secretos nunca guardan la linea.
- El historial se lee en tandas (tope por escaneo); en repositorios enormes se completa en escaneos sucesivos.
- La verificacion detecta alteraciones de entradas existentes siempre; el borrado de las ultimas entradas solo se
  detecta contra un ancla guardada por fuera.
