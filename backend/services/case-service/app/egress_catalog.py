"""Catalogo de destinos externos que TERO puede contactar, revisado a mano contra el codigo.

Sirve para clasificar lo que los servicios informan (egress_service.classify):
  * catalogado   -- esta en la lista de abajo: se sabe a quien, para que y que datos viajan.
  * configurado  -- lo define un usuario/administrador (un webhook, el SMTP, un IdP, un repositorio, una cuenta
                    de nube) en un servicio que por diseno tiene destinos configurables.
  * no catalogado -- un destino externo que no esta en la lista y que ningun usuario pudo haber configurado
                     en ese servicio: es lo que hay que mirar primero.

Si agregas una integracion nueva que sale a internet, sumala aca (y un test falla si falta el texto)."""
from __future__ import annotations

# host: nombre exacto, o "*.dominio" para el dominio y sus subdominios.
CATALOG: list[dict] = [
    {"id": "nvd", "host": "services.nvd.nist.gov", "services": ["vuln-service"], "category": "Inteligencia de vulnerabilidades",
     "purpose": "Consulta el puntaje CVSS oficial de cada CVE",
     "sends": "Solo el identificador del CVE (ej. CVE-2024-1234). Nada de tu infraestructura.",
     "optional": True, "offline": "Sin salida, los hallazgos quedan con el puntaje que traiga el escaner."},
    {"id": "epss", "host": "api.first.org", "services": ["vuln-service"], "category": "Inteligencia de vulnerabilidades",
     "purpose": "Consulta EPSS: probabilidad de que un CVE sea explotado",
     "sends": "Solo el identificador del CVE.", "optional": True,
     "offline": "Sin salida, la priorizacion no usa EPSS."},
    {"id": "kev", "host": "www.cisa.gov", "services": ["vuln-service"], "category": "Inteligencia de vulnerabilidades",
     "purpose": "Descarga el catalogo CISA KEV (vulnerabilidades explotadas activamente)",
     "sends": "Nada: es una descarga de un archivo publico.", "optional": True,
     "offline": "Sin salida, no se marcan las vulnerabilidades KEV (o se apunta CISA_KEV_URL a un espejo interno)."},
    {"id": "crtsh", "host": "crt.sh", "services": ["asm-service"], "category": "Superficie de ataque",
     "purpose": "Busca subdominios en los registros publicos de certificados",
     "sends": "El dominio que vos monitoreas (ya es publico en DNS y en los certificados).", "optional": True,
     "offline": "Sin salida, el descubrimiento de subdominios por certificados no funciona."},
    {"id": "abuseipdb", "host": "api.abuseipdb.com", "services": ["threatintel-service"], "category": "Inteligencia de amenazas",
     "purpose": "Consulta la reputacion de una IP publica",
     "sends": "La IP publica consultada (nunca IP privadas) y tu clave de API. Solo si definiste ABUSEIPDB_API_KEY.",
     "optional": True, "offline": "Sin salida, la reputacion se calcula con tus feeds internos y MISP propio."},
    {"id": "github", "host": "*.github.com", "services": ["coderepo-service", "scan-service"], "category": "Repositorios de codigo",
     "purpose": "Clona los repositorios que registraste para escanearlos",
     "sends": "El token de acceso del repositorio (si es privado). El codigo se baja, no se sube.", "optional": True,
     "offline": "Sin salida, solo se pueden escanear repositorios de un Git interno (GitLab/Gitea propio)."},
    {"id": "aws", "host": "*.amazonaws.com", "services": ["cloud-service"], "category": "Nube",
     "purpose": "Lee la configuracion de tu cuenta de AWS (solo lectura)",
     "sends": "Las credenciales de solo lectura que cargaste (firmadas por boto3, nunca en claro).", "optional": True,
     "offline": "Sin salida, no se sincroniza la nube."},
    {"id": "slack", "host": "hooks.slack.com", "services": ["notification-service", "soar-service"], "category": "Notificaciones",
     "purpose": "Avisa por Slack cuando hay una alerta",
     "sends": "El texto del aviso (titulo y severidad de la alerta).", "optional": True,
     "offline": "Sin salida, los avisos salen por mail interno u otro canal local."},
    {"id": "teams", "host": "*.webhook.office.com", "services": ["notification-service", "soar-service"], "category": "Notificaciones",
     "purpose": "Avisa por Microsoft Teams cuando hay una alerta",
     "sends": "El texto del aviso.", "optional": True, "offline": "Idem Slack."},
    {"id": "entra", "host": "login.microsoftonline.com", "services": ["auth-service"], "category": "Identidad",
     "purpose": "Inicio de sesion unico con Microsoft Entra ID (si lo configuraste)",
     "sends": "El codigo de autorizacion de la persona que inicia sesion.", "optional": True,
     "offline": "Sin salida, se usa usuario y contrasena (o un IdP interno)."},
    {"id": "google", "host": "*.googleapis.com", "services": ["auth-service"], "category": "Identidad",
     "purpose": "Valida el inicio de sesion con Google (si lo configuraste)",
     "sends": "El token de Google de la persona que inicia sesion.", "optional": True,
     "offline": "Sin salida, se usa usuario y contrasena."},
    {"id": "google-accounts", "host": "accounts.google.com", "services": ["auth-service"], "category": "Identidad",
     "purpose": "Inicio de sesion con Google (si lo configuraste)", "sends": "El codigo de autorizacion.",
     "optional": True, "offline": "Idem Google."},
    {"id": "atlassian", "host": "*.atlassian.net", "services": ["integration-service", "soar-service"], "category": "Tickets",
     "purpose": "Crea tickets en Jira (si lo configuraste)",
     "sends": "Titulo y descripcion de la alerta o del hallazgo, y tu token de Jira.", "optional": True,
     "offline": "Sin salida, los tickets se crean en un Jira o GLPI interno."},
]

# Servicios que, por diseno, hablan con destinos que define un usuario o un administrador.
USER_CONFIGURABLE: dict[str, str] = {
    "integration-service": "Integraciones (Jira, ITSM, webhooks) que cargo un administrador",
    "notification-service": "Servidor de correo (SMTP) y webhooks de aviso definidos por un administrador",
    "soar-service": "Acciones de playbooks hacia firewalls, tickets y webhooks definidos por un administrador",
    "auth-service": "Proveedor de identidad (SSO/OIDC), correo para restablecer contrasenas y servidor de licencias",
    "coderepo-service": "Repositorios Git registrados por un usuario",
    "scan-service": "Objetivos de escaneo y repositorios definidos por un usuario",
    "cloud-service": "Cuentas de nube conectadas por un administrador",
    "threatintel-service": "Instancia MISP y feeds definidos por un administrador",
    "asm-service": "Dominios monitoreados definidos por un usuario",
}

EXPECTED_SERVICES = [
    "asm-service", "asset-service", "auth-service", "case-service", "cloud-service", "coderepo-service",
    "integration-service", "notification-service", "purple-service", "report-service", "scan-service",
    "siem-service", "soar-service", "threatintel-service", "vuln-service",
]


def host_matches(pattern: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def classify(service: str, host: str) -> tuple[str, dict | None]:
    """('catalogado', entrada) | ('configurado', None) | ('no_catalogado', None)."""
    for entry in CATALOG:
        if host_matches(entry["host"], host) and (not entry["services"] or service in entry["services"]):
            return "catalogado", entry
    if service in USER_CONFIGURABLE:
        return "configurado", None
    return "no_catalogado", None
