"""Catalogo de cumplimiento: que se le pide a una organizacion argentina que trata datos personales y que
suele pedir un seguro de ciberseguridad, y de donde sale la evidencia de cada punto.

Dos tipos de control:
  * auto   -> TERO lo comprueba solo mirando datos reales (usuarios con MFA, escaneos recientes, etc.).
  * manual -> TERO no puede verlo (copias de respaldo, capacitacion, contratos). Una persona lo declara, con
              nota, fecha y vencimiento; queda en la cadena de custodia y NUNCA se mezcla con lo verificado.

Referencias normativas (verificadas; si cambia la norma, se cambia aca):
  * Ley 25.326 de Proteccion de los Datos Personales: art. 9 (seguridad de los datos), art. 10 (deber de
    confidencialidad), art. 12 (transferencia internacional), arts. 14 a 16 (derechos de acceso, rectificacion,
    actualizacion y supresion), art. 21 (inscripcion de las bases de datos).
  * Resolucion AAIP 47/2018: aprueba medidas de seguridad RECOMENDADAS (referenciales, no obligatorias) para el
    tratamiento de datos personales; derogo la Disposicion DNPDP 11/2006 y la 9/2008. Anexo I (medios
    informatizados): A Recoleccion, B Control de acceso, C Control de cambios, D Respaldo y recuperacion,
    E Gestion de vulnerabilidades, F Destruccion, G Incidentes de seguridad, H Entornos de desarrollo.
  * CIS Controls v8 (referencia tecnica internacional que muchos seguros usan como base).

Esto ayuda a preparar y ordenar evidencia; NO es asesoramiento legal ni una certificacion."""
from __future__ import annotations

L25326 = "Ley 25.326"
AAIP47 = "Res. AAIP 47/2018 Anexo I"
CIS = "CIS v8"

DISCLAIMER = (
    "Esta pantalla ordena evidencia para preparar una auditoria, una renovacion de seguro o una consulta legal. "
    "No es asesoramiento legal ni una certificacion. Las medidas de la Res. AAIP 47/2018 son recomendaciones; "
    "la obligacion legal de seguridad es la del art. 9 de la Ley 25.326."
)

AREAS = {
    "acceso": "Control de acceso",
    "activos": "Inventario de activos",
    "vulnerabilidades": "Gestion de vulnerabilidades",
    "registros": "Registros y deteccion",
    "incidentes": "Respuesta a incidentes",
    "datos": "Proteccion de datos personales",
    "respaldo": "Respaldo y recuperacion",
    "personas": "Personas y procesos",
    "tecnologia": "Proteccion tecnica",
}

# mode: auto | manual. "check" (solo auto) es el nombre de la comprobacion en compliance_evidence.CHECKS.
CONTROLS: list[dict] = [
    # --- automaticos ---
    {"id": "ACC-01", "area": "acceso", "mode": "auto", "check": "mfa_admins",
     "title": "Verificacion en dos pasos (MFA) en cuentas administradoras",
     "why": "Una contrasena robada de un administrador compromete todo. Es lo primero que piden los seguros.",
     "refs": [f"{AAIP47}-B", f"{CIS} 6"]},
    {"id": "ACC-02", "area": "acceso", "mode": "auto", "check": "mfa_all",
     "title": "Verificacion en dos pasos (MFA) en todas las cuentas",
     "why": "Reduce el riesgo de que una cuenta comun sea la puerta de entrada.",
     "refs": [f"{AAIP47}-B", f"{CIS} 6"]},
    {"id": "ACC-03", "area": "acceso", "mode": "auto", "check": "admin_share",
     "title": "Pocas cuentas administradoras (minimo privilegio)",
     "why": "Cuantas mas cuentas con poder total, mas superficie de ataque. Referencia: hasta 3 o hasta un tercio de las cuentas activas.",
     "refs": [f"{AAIP47}-B", f"{CIS} 5"]},
    {"id": "ACT-01", "area": "activos", "mode": "auto", "check": "assets_inventory",
     "title": "Inventario de equipos y servidores con responsable",
     "why": "No se puede proteger lo que no se sabe que existe, ni avisar a quien corresponde.",
     "refs": [L25326 + " art. 9", f"{CIS} 1"]},
    {"id": "VUL-01", "area": "vulnerabilidades", "mode": "auto", "check": "scans_recent",
     "title": "Escaneos de vulnerabilidades periodicos",
     "why": "Los seguros suelen pedir escaneos periodicos (por ejemplo mensuales); lo mejor es que esten programados.",
     "refs": [f"{AAIP47}-E", f"{CIS} 7"]},
    {"id": "VUL-02", "area": "vulnerabilidades", "mode": "auto", "check": "vulns_open_critical",
     "title": "Sin vulnerabilidades criticas ni explotadas activamente abiertas",
     "why": "Las criticas y las que figuran en el catalogo de explotadas (KEV) son las que se usan en ataques reales.",
     "refs": [f"{AAIP47}-E", f"{CIS} 7"]},
    {"id": "VUL-03", "area": "vulnerabilidades", "mode": "auto", "check": "closure_verified",
     "title": "Las correcciones se comprueban con un nuevo escaneo",
     "why": "Marcar algo como corregido no alcanza: hay que probar que dejo de estar.",
     "refs": [f"{AAIP47}-E", f"{CIS} 7"]},
    {"id": "LOG-01", "area": "registros", "mode": "auto", "check": "siem_recent",
     "title": "Registros de actividad centralizados y recibiendose",
     "why": "Sin registros recientes no se detecta ni se investiga un incidente.",
     "refs": [f"{AAIP47}-G", f"{CIS} 8"]},
    {"id": "LOG-02", "area": "registros", "mode": "auto", "check": "siem_rules",
     "title": "Reglas de deteccion activas",
     "why": "Los registros solos no avisan: las reglas convierten eventos en alertas.",
     "refs": [f"{AAIP47}-G", f"{CIS} 13"]},
    {"id": "LOG-03", "area": "registros", "mode": "auto", "check": "custody_chain",
     "title": "Registro inalterable de lo que se hizo (cadena de custodia)",
     "why": "Permite demostrar a un tercero que el registro no se modifico despues.",
     "refs": [L25326 + " art. 9", f"{CIS} 8"]},
    {"id": "INC-01", "area": "incidentes", "mode": "auto", "check": "soar_playbooks",
     "title": "Respuesta automatizada disponible",
     "why": "Responder en minutos y de forma consistente reduce el dano.",
     "refs": [f"{AAIP47}-G", f"{CIS} 17"]},
    {"id": "INC-02", "area": "incidentes", "mode": "auto", "check": "cases_handling",
     "title": "Los incidentes se gestionan como casos y no quedan abandonados",
     "why": "Un caso abierto hace semanas sin movimiento es un incidente sin dueno.",
     "refs": [f"{AAIP47}-G", f"{CIS} 17"]},
    {"id": "INC-03", "area": "incidentes", "mode": "auto", "check": "drills_recent",
     "title": "Simulacros de respuesta con tiempos medidos",
     "why": "Un plan que nunca se probo no sirve el dia del incidente: el simulacro mide cuanto tarda el equipo en reconocer y cerrar una alerta.",
     "refs": [f"{AAIP47}-G", f"{CIS} 17"]},
    {"id": "DAT-01", "area": "datos", "mode": "auto", "check": "sovereignty",
     "title": "Los datos no salen a internet sin que se sepa (transferencia internacional)",
     "why": "TERO registra a que destinos externos habla cada servicio y puede funcionar aislado.",
     "refs": [L25326 + " art. 9 y 12", f"{AAIP47}-B"]},
    # --- manuales ---
    {"id": "GOB-01", "area": "datos", "mode": "manual",
     "title": "Bases de datos con datos personales inscriptas ante la AAIP",
     "why": "La ley exige inscribir las bases de datos. TERO no puede ver el registro: lo declara una persona.",
     "refs": [L25326 + " art. 21"]},
    {"id": "GOB-02", "area": "personas", "mode": "manual",
     "title": "Politica de seguridad de la informacion y responsable designado",
     "why": "Alguien tiene que ser dueno de la seguridad y existir una politica escrita.",
     "refs": [L25326 + " art. 9", f"{CIS} 14"]},
    {"id": "GOB-03", "area": "personas", "mode": "manual",
     "title": "Deber de confidencialidad firmado por quienes tratan datos personales",
     "why": "La ley obliga a quienes intervienen en el tratamiento a guardar secreto.",
     "refs": [L25326 + " art. 10"]},
    {"id": "GOB-04", "area": "datos", "mode": "manual",
     "title": "Procedimiento para atender pedidos de acceso, rectificacion y supresion",
     "why": "Las personas tienen derecho a ver, corregir o borrar sus datos.",
     "refs": [L25326 + " arts. 14 a 16"]},
    {"id": "GOB-05", "area": "incidentes", "mode": "manual",
     "title": "Plan de respuesta a incidentes escrito y conocido por el equipo",
     "why": "En un incidente real no hay tiempo de decidir quien hace que.",
     "refs": [f"{AAIP47}-G", f"{CIS} 17"]},
    {"id": "RES-01", "area": "respaldo", "mode": "manual",
     "title": "Copias de respaldo con prueba de restauracion reciente",
     "why": "Una copia que nunca se restauro es una esperanza, no un respaldo.",
     "refs": [f"{AAIP47}-D", f"{CIS} 11"]},
    {"id": "RES-02", "area": "respaldo", "mode": "manual",
     "title": "Al menos una copia fuera de linea o inmutable",
     "why": "Es lo que salva a la organizacion de un ransomware que cifra tambien los respaldos conectados.",
     "refs": [f"{AAIP47}-D", f"{CIS} 11"]},
    {"id": "PER-01", "area": "personas", "mode": "manual",
     "title": "Capacitacion de seguridad al personal en el ultimo ano",
     "why": "El engano a una persona sigue siendo la entrada mas comun.",
     "refs": [f"{CIS} 14"]},
    {"id": "TEC-01", "area": "tecnologia", "mode": "manual",
     "title": "Proteccion contra malware (antivirus o EDR) en equipos y servidores",
     "why": "Los seguros preguntan si hay EDR y sobre que porcentaje de equipos.",
     "refs": [f"{CIS} 10"]},
    {"id": "TEC-02", "area": "tecnologia", "mode": "manual",
     "title": "Filtrado de correo contra phishing y adjuntos peligrosos",
     "why": "El correo es la via principal de phishing y ransomware.",
     "refs": [f"{CIS} 9"]},
    {"id": "TEC-03", "area": "tecnologia", "mode": "manual",
     "title": "Cifrado de discos de equipos portatiles y de las comunicaciones",
     "why": "Si roban una notebook o se intercepta una conexion, los datos siguen protegidos.",
     "refs": [L25326 + " art. 9", f"{CIS} 3"]},
    {"id": "TEC-04", "area": "tecnologia", "mode": "manual",
     "title": "Control de cambios en sistemas y entornos de desarrollo separados",
     "why": "Los cambios sin control y las pruebas con datos reales son fuente de incidentes.",
     "refs": [f"{AAIP47}-C y H", f"{CIS} 4"]},
    {"id": "TEC-05", "area": "tecnologia", "mode": "manual",
     "title": "Destruccion segura de equipos y soportes con datos",
     "why": "Un disco descartado sin borrar es una filtracion esperando a pasar.",
     "refs": [f"{AAIP47}-F"]},
    {"id": "PER-02", "area": "personas", "mode": "manual",
     "title": "Evaluacion de seguridad de proveedores que tocan datos o sistemas",
     "why": "Un proveedor mal protegido es una puerta indirecta a tu informacion.",
     "refs": [f"{CIS} 15"]},
]

CONTROL_BY_ID = {c["id"]: c for c in CONTROLS}

# Cuestionario tipo de ciberseguro. Cada insurer tiene el suyo: esto cubre lo que casi todos preguntan y se
# completa solo con la evidencia de arriba. "controls": que controles responden la pregunta.
INSURANCE_QUESTIONS: list[dict] = [
    {"id": "Q01", "text": "Se exige verificacion en dos pasos (MFA) a las cuentas administradoras?", "controls": ["ACC-01"]},
    {"id": "Q02", "text": "Se exige MFA al resto de los usuarios, incluido el acceso remoto?", "controls": ["ACC-02"]},
    {"id": "Q03", "text": "Se limita la cantidad de cuentas con privilegios de administrador?", "controls": ["ACC-03"]},
    {"id": "Q04", "text": "Existe un inventario actualizado de equipos y servidores?", "controls": ["ACT-01"]},
    {"id": "Q05", "text": "Se hacen escaneos de vulnerabilidades al menos una vez por mes?", "controls": ["VUL-01"]},
    {"id": "Q06", "text": "Se corrigen las vulnerabilidades criticas y explotadas activamente, y se verifica la correccion?", "controls": ["VUL-02", "VUL-03"]},
    {"id": "Q07", "text": "Se centralizan y monitorean los registros de actividad con alertas?", "controls": ["LOG-01", "LOG-02"]},
    {"id": "Q08", "text": "Los registros de auditoria estan protegidos contra modificaciones?", "controls": ["LOG-03"]},
    {"id": "Q09", "text": "Existe un plan de respuesta a incidentes y capacidad de respuesta automatizada?", "controls": ["GOB-05", "INC-01"]},
    {"id": "Q10", "text": "Los incidentes se registran y se gestionan hasta su cierre?", "controls": ["INC-02"]},
    {"id": "Q19", "text": "Se hacen simulacros de respuesta a incidentes con tiempos medidos al menos una vez al ano?", "controls": ["INC-03"]},
    {"id": "Q11", "text": "Hay copias de respaldo con restauracion probada y una copia fuera de linea o inmutable?", "controls": ["RES-01", "RES-02"]},
    {"id": "Q12", "text": "Hay antivirus o EDR en equipos y servidores?", "controls": ["TEC-01"]},
    {"id": "Q13", "text": "Se filtra el correo electronico contra phishing y adjuntos maliciosos?", "controls": ["TEC-02"]},
    {"id": "Q14", "text": "Se capacita al personal en seguridad al menos una vez por ano?", "controls": ["PER-01"]},
    {"id": "Q15", "text": "Se cifran los equipos portatiles y las comunicaciones?", "controls": ["TEC-03"]},
    {"id": "Q16", "text": "Se evalua la seguridad de los proveedores con acceso a datos o sistemas?", "controls": ["PER-02"]},
    {"id": "Q17", "text": "Las bases de datos con datos personales estan inscriptas y hay politica y responsable de seguridad?", "controls": ["GOB-01", "GOB-02"]},
    {"id": "Q18", "text": "Se controla a que destinos externos se envian datos desde los sistemas?", "controls": ["DAT-01"]},
]

QUESTION_BY_ID = {q["id"]: q for q in INSURANCE_QUESTIONS}
