"""Multi-tenancy helpers compartidos por todos los microservicios.

El modelo es aislamiento por fila: cada tabla que guarda datos de un
cliente tiene una columna `organization_id`, poblada desde el claim
`org_id` del JWT (ver backend/shared/security.py::create_access_token,
emitido por auth-service). Cada microservicio confia en ese claim -- ya
viene validado (firma + expiracion) por get_current_claims -- y filtra
sus propias tablas por el, sin volver a golpear a auth-service en cada
request.

DEFAULT_ORGANIZATION_ID es un id fijo (no un UUID random) a proposito:
es el id que auth-service le da a la organizacion "default" que se crea
sola la primera vez que hace falta (ver auth-service/app/services.py::
get_default_organization). Al ser fijo y conocido de antemano, CADA
microservicio puede backfillear sus propias filas viejas (creadas antes
de que existiera multi-tenancy) a esa misma organizacion sin tener que
llamar a auth-service para preguntarle cual es -- evita una dependencia
de arranque entre servicios (que auth-service ya este arriba y con la
organizacion creada antes de que el resto pueda migrar sus tablas).

Uso tipico en un endpoint: cada request ya inyecta
`claims: dict = Depends(get_current_claims)` (o require_role(...), que
tambien devuelve el dict de claims) -- se llama org_id_from_claims(claims)
con eso, no hace falta una dependency nueva."""

DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"


def org_id_from_claims(claims: dict) -> str:
    """Devuelve el org_id del JWT actual, o DEFAULT_ORGANIZATION_ID si el
    claim no esta presente. Esto cubre dos casos legitimos, no solo
    tokens viejos: JWTs de servicio-a-servicio que un microservicio emite
    para si mismo (ej. el scheduler de reportes) y que todavia no llevan
    org_id explicito, y el caso de uso on-prem de un solo cliente donde
    total nunca va a existir mas de una organizacion."""
    return claims.get("org_id") or DEFAULT_ORGANIZATION_ID
