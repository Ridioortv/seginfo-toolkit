/**
 * Contenido de la seccion de Ayuda: una guia interactiva, en espanol
 * simple y sin jerga tecnica, que explica que hace cada parte de
 * SentinelOps y como usarla con los botones y formularios reales de la
 * plataforma (nunca pide escribir codigo ni JSON a mano).
 *
 * Es contenido estatico -- no llama a ningun servicio -- por eso vive
 * como datos separados de Help.tsx en vez de mezclado con el componente.
 */

export interface HelpStep {
  title: string;
  body: string;
}

export interface HelpTopic {
  id: string;
  label: string;
  tagline: string;
  overview: string;
  steps: HelpStep[];
  tips?: string[];
  adminOnly?: boolean;
}

export const HELP_TOPICS: HelpTopic[] = [
  {
    id: "intro",
    label: "Como empezar",
    tagline: "Un recorrido rapido por toda la plataforma",
    overview:
      "SentinelOps te ayuda a vigilar tus equipos, encontrar fallos de seguridad y responder ante incidentes -- todo con botones y formularios. No hace falta saber programar ni escribir codigo para usar ninguna funcion. Esta guia explica, seccion por seccion, que hace cada parte y en que orden conviene usarlas.",
    steps: [
      { title: "1. Registra tus activos", body: "Empeza por la seccion Activos: ahi cargas los equipos, servidores o dispositivos que quieres vigilar." },
      { title: "2. Lanza un escaneo", body: "Desde Activos (boton \"Escanear (detectar fallos)\") o desde Escaneos, lanza un escaneo para buscar fallos de seguridad automaticamente." },
      { title: "3. Revisa las vulnerabilidades encontradas", body: "Todo lo que un escaneo encuentra aparece en Vulnerabilidades, con pasos concretos para solucionarlo." },
      { title: "4. Deja que SIEM y SOAR trabajen para ti", body: "SIEM junta y analiza toda la actividad de tus sistemas; SOAR puede responder automaticamente (por ejemplo, bloqueando una IP sospechosa)." },
      { title: "5. Segui los casos hasta resolverlos", body: "Cuando algo requiere atencion humana se crea un Caso -- ahi le das seguimiento hasta cerrarlo." },
    ],
    tips: [
      "Podes volver a esta guia en cualquier momento desde \"Ayuda\" en el menu de la izquierda.",
      "En ningun lugar de la plataforma vas a necesitar escribir codigo: todo se hace con botones, formularios y listas para elegir.",
    ],
  },
  {
    id: "assets",
    label: "Activos",
    tagline: "Que equipos estas vigilando",
    overview:
      "Un \"activo\" es cualquier equipo, servidor o dispositivo de tu red que quieras vigilar: una notebook, un servidor de archivos, una pagina web, etc. Registrar tus activos es el primer paso, porque le indica a SentinelOps que existe algo para revisar.",
    steps: [
      {
        title: "Agregar un activo nuevo",
        body: "En el formulario \"Agregar activo para monitorear\" completa el nombre del equipo (hostname) o su direccion IP -- alcanza con uno de los dos. Tambien podes indicar el sistema operativo, si es de Produccion, Staging, Desarrollo u Otro, que tan critico es (Baja, Media, Alta o Critica) y quien es el responsable. Despues apreta \"Agregar activo\".",
      },
      {
        title: "Lanzar un escaneo de deteccion de fallos",
        body: "En la tabla de abajo, cada activo tiene un boton \"Escanear (detectar fallos)\". Al apretarlo se lanza automaticamente un escaneo sobre ese equipo, sin configurar nada mas. El resultado aparece poco despues en la pagina Escaneos, y las fallas encontradas en Vulnerabilidades.",
      },
      {
        title: "Para que sirve la criticidad",
        body: "Es solo para ayudarte a priorizar: un activo \"Critica\" (por ejemplo, el servidor que atiende a tus clientes) conviene revisarlo mas seguido que uno \"Baja\" (por ejemplo, una notebook de prueba).",
      },
    ],
    tips: [
      "Si un activo tiene hostname e IP a la vez, el escaneo usa la IP.",
      "No hay limite de activos que puedas registrar.",
    ],
  },
  {
    id: "scans",
    label: "Escaneos",
    tagline: "Buscar fallos de seguridad automaticamente",
    overview:
      "Un escaneo revisa un equipo o una red buscando puertos abiertos, software desactualizado y otras debilidades. Esta seccion tiene varios paneles: escaneos inmediatos, escaneos programados (que se repiten solos), agentes de escaneo remoto (para revisar redes internas que SentinelOps no ve desde afuera) y el historial de todo lo ejecutado.",
    steps: [
      {
        title: "Nuevo escaneo (inmediato)",
        body: "Elegi el tipo de escaneo (nmap para puertos de red, trivy para contenedores e imagenes, nuclei para vulnerabilidades web, openvas para un analisis mas completo), el alcance de red (LAN, MAN, WAN o Personalizado) y el o los objetivos (IP, rango o nombre de host, uno por linea). Apreta \"Lanzar escaneo\".",
      },
      {
        title: "Escaneos programados",
        body: "Si queres que un escaneo se repita solo (por ejemplo, todas las noches), completa el formulario de \"Escaneos programados\" con nombre, tipo de escaneo, objetivo, frecuencia (diaria o semanal) y hora. SentinelOps lo ejecuta automaticamente en cada horario, sin que vuelvas a apretar nada. Se borra con \"Eliminar\" cuando ya no lo necesites.",
      },
      {
        title: "Agentes de escaneo remoto",
        body: "Si tenes una red interna que SentinelOps no puede alcanzar desde internet (por ejemplo, la red de tu oficina), instala un \"agente\" en un equipo de esa red: creá el agente aca con un nombre descriptivo (ej. PC-oficina-recepcion), copia la clave que se muestra una sola vez (\"Ya la copie\") y usala para instalarlo. Una vez instalado, el agente queda disponible para recibir trabajos de escaneo.",
      },
      {
        title: "Escaneos remotos (a traves de un agente)",
        body: "Con un agente ya instalado, elegilo de la lista y carga un objetivo (IP, rango o host visible desde ese agente) para que el escaneo se ejecute desde adentro de esa red.",
      },
      {
        title: "Escaneos realizados",
        body: "Aca ves el historial completo con el estado de cada escaneo (en progreso, completado, fallido). Los escaneos ya terminados tienen un boton \"Eliminar\"; los que estan en progreso no se pueden borrar hasta que terminen.",
      },
    ],
    tips: [
      "Los resultados de cualquier escaneo (inmediato, programado o remoto) llegan solos a Vulnerabilidades y a SIEM -- no hace falta cargarlos a mano.",
      "Si no sabes que tipo de escaneo elegir, nmap es un buen punto de partida.",
    ],
  },
  {
    id: "vulnerabilities",
    label: "Vulnerabilidades",
    tagline: "Los fallos encontrados y como solucionarlos",
    overview:
      "Cada fallo de seguridad que un escaneo detecta aparece aca, con su nivel de severidad (Critica, Alta, Media o Baja) y un plan de accion concreto para solucionarlo. No necesitas saber de seguridad informatica para entender que hacer.",
    steps: [
      {
        title: "Ver el plan de remediacion",
        body: "Hace click sobre una vulnerabilidad de la tabla para desplegar los pasos sugeridos: por ejemplo, actualizar un programa a una version especifica, cerrar un puerto abierto, o revisar el aviso oficial de una vulnerabilidad conocida (CVE). Si el fallo esta en la lista de vulnerabilidades activamente explotadas (CISA KEV), ese aviso aparece primero porque es prioridad maxima.",
      },
      {
        title: "Marcar el resultado de la revision",
        body: "Una vez que investigaste o solucionaste el fallo, usa los botones de accion para marcarlo como Confirmado (es un problema real), Falso positivo (no aplica), Riesgo aceptado (lo dejas asi a proposito) o Remediado (ya lo solucionaste).",
      },
    ],
    tips: [
      "El ultimo paso sugerido siempre es volver a escanear ese activo para confirmar que el fallo ya no aparece.",
      "Podes dejar una nota explicando por que tomaste una decision, por ejemplo por que aceptaste un riesgo.",
    ],
  },
  {
    id: "siem",
    label: "SIEM",
    tagline: "Todo lo que pasa en tus sistemas, en un solo lugar",
    overview:
      "SIEM junta la actividad de tus equipos (incluyendo los hallazgos de los escaneos) y la compara contra \"reglas de deteccion\" para avisarte cuando pasa algo que merece atencion, por ejemplo un fallo critico o intentos repetidos de acceso con una cuenta de administrador.",
    steps: [
      {
        title: "Cargar reglas recomendadas",
        body: "Si es la primera vez que usas SIEM, apreta \"Cargar reglas recomendadas\" para agregar automaticamente tres reglas ya armadas (fallo critico de escaneo, fallo alto de escaneo, login fallido repetido en cuenta administrativa). No necesitas escribir nada.",
      },
      {
        title: "Crear una regla propia",
        body: "Elegi un nombre, una severidad y las condiciones que tiene que cumplir un evento para disparar la alerta (por ejemplo: usuario es \"admin\" y resultado es \"fallo\"). Las condiciones se agregan y se sacan con botones -- no hay que escribir ningun codigo ni JSON a mano.",
      },
      {
        title: "Revisar las alertas",
        body: "Cada vez que una regla se cumple, aparece una alerta en la tabla de arriba. Usa \"Reconocer\" para marcar que ya la viste, y \"Cerrar\" cuando el tema quedo resuelto.",
      },
      {
        title: "Activar, desactivar o borrar reglas",
        body: "Podes prender o apagar una regla sin borrarla (por si la queres pausar un tiempo), o eliminarla del todo con \"Eliminar\".",
      },
    ],
    tips: [
      "Los hallazgos de cualquier escaneo llegan solos a SIEM.",
      "Las tarjetas de arriba (alertas totales, abiertas, criticas, reglas activas) te dan un resumen rapido del estado general.",
    ],
  },
  {
    id: "soar",
    label: "SOAR",
    tagline: "Respuestas automaticas ante un incidente",
    overview:
      "SOAR ejecuta \"playbooks\": una serie de pasos automaticos para responder a un problema, por ejemplo bloquear una IP sospechosa, aislar un equipo comprometido, o crear un caso o un ticket para que alguien lo revise.",
    steps: [
      {
        title: "Crear un playbook",
        body: "Dale un nombre y elegi las acciones una por una desde una lista (Bloquear IP, Aislar host, Crear caso, Crear ticket, Notificar), completando los datos que pida cada una (por ejemplo, que IP bloquear). Apreta \"+ Agregar paso\" para sumarla a la secuencia -- el playbook ejecuta los pasos en el orden en que los agregaste. Podes sacar un paso con \"Quitar\" antes de guardar.",
      },
      {
        title: "Ejecutar un playbook",
        body: "Con el boton \"Ejecutar ahora\" de la tabla de Playbooks, corres esa secuencia de acciones manualmente cuando la necesites.",
      },
      {
        title: "Activar, desactivar o borrar",
        body: "Los playbooks se pueden prender o apagar sin borrarlos, o eliminarse del todo si ya no se usan (los playbooks globales de la plataforma estan protegidos y no se pueden borrar).",
      },
      {
        title: "Revisar las ejecuciones",
        body: "La tabla de Ejecuciones muestra cada vez que un playbook corrio y si termino bien o con errores, para que confirmes que la respuesta automatica funciono.",
      },
    ],
    tips: [
      "Mientras no conectes tus sistemas reales en Integraciones, las acciones de contencion (bloquear IP, aislar host) quedan en modo simulado: no tocan nada de verdad, solo queda registrado que \"se hubiera hecho\".",
      "Un playbook puede dispararse solo si esta conectado a una regla de SIEM, o correrse a mano con \"Ejecutar ahora\".",
    ],
  },
  {
    id: "cases",
    label: "Casos",
    tagline: "Seguimiento de incidentes de principio a fin",
    overview:
      "Un caso agrupa todo lo relacionado a un incidente que necesita seguimiento humano: por ejemplo, una vulnerabilidad critica sin resolver o una alerta de SIEM importante. Los casos se actualizan solos a medida que SIEM y SOAR encuentran cosas nuevas.",
    steps: [
      {
        title: "Sincronizacion automatica",
        body: "SentinelOps revisa periodicamente los resultados de SOAR y crea o actualiza casos por si mismo. Si necesitas forzar esa revision en el momento, usa \"Sincronizar con SOAR ahora\" (visible solo para administradores y jefes de SOC).",
      },
      {
        title: "Avanzar un caso",
        body: "Cada caso tiene botones para moverlo por su ciclo de vida: \"Tomar caso\" (de Abierto a En progreso), \"Marcar resuelto\", \"Cerrar\", \"Reabrir\" o \"Devolver a abierto\", segun en que estado este.",
      },
      {
        title: "Asignar un responsable",
        body: "Escribi el nombre o email de la persona en el campo de asignacion y apreta el boton para dejar constancia de quien esta a cargo.",
      },
      {
        title: "Agregar notas",
        body: "Cada caso tiene una linea de tiempo. Escribi una nota (por ejemplo, que investigaste o que hiciste) y apreta \"Agregar nota\" para dejarla registrada con fecha y hora.",
      },
    ],
    tips: [
      "Las tarjetas de arriba muestran de un vistazo cuantos casos hay abiertos y cuantos tienen el plazo (SLA) vencido.",
      "Un caso con el SLA vencido es una senal de que conviene priorizarlo.",
    ],
  },
  {
    id: "purple-team",
    label: "Purple Team",
    tagline: "Poner a prueba tus defensas",
    overview:
      "Un ejercicio de Purple Team sirve para comprobar si tus defensas realmente detectan las tecnicas de ataque mas comunes (segun el catalogo MITRE ATT&CK). Declaras que tecnicas vas a simular y SentinelOps te dice cuales SI fueron detectadas y cuales quedaron como \"brechas\" (gaps) sin cobertura.",
    steps: [
      {
        title: "Declarar un ejercicio",
        body: "Dale un nombre y una descripcion, y marca en la lista (agrupada por tactica) las tecnicas de ataque que vas a poner a prueba. Apreta \"Crear ejercicio\" para guardarlo.",
      },
      {
        title: "Recalcular cobertura",
        body: "Despues de ejecutar el ejercicio en la practica, apreta \"Recalcular cobertura\" para que SentinelOps compare las tecnicas declaradas contra lo que realmente se detecto en SIEM.",
      },
      {
        title: "Ver los gaps",
        body: "Con \"Ver gaps\" desplegas el detalle de que tecnicas declaradas no se llegaron a detectar. Esas son las que conviene reforzar, por ejemplo agregando una regla nueva en SIEM.",
      },
    ],
    tips: ["El catalogo de tecnicas de referencia (arriba de todo) es solo informativo, para saber de que se trata cada tecnica antes de elegirla."],
  },
  {
    id: "reports",
    label: "Reportes",
    tagline: "Resumenes para compartir con tu equipo o tus clientes",
    overview:
      "Los reportes juntan la informacion de escaneos, vulnerabilidades, casos y demas en un documento descargable (CSV o PDF), ideal para compartir el estado de la seguridad con alguien que no usa la plataforma dia a dia.",
    steps: [
      {
        title: "Historial de reportes",
        body: "Cada reporte generado aparece en esta tabla con botones para descargarlo en \"CSV\" o \"PDF\", y un boton \"Eliminar\" para borrarlo cuando ya no lo necesites.",
      },
      {
        title: "Reportes programados",
        body: "Configura un reporte para que se genere y se envie solo, de forma periodica (por ejemplo, todos los lunes). Para que el envio por email funcione, necesitas tener al menos un canal de tipo \"email\" habilitado en Notificaciones -- si no hay ninguno, esta seccion te lo va a avisar.",
      },
    ],
    tips: [
      "Si un reporte programado no llega por email, lo primero para revisar es que haya un canal de notificaciones de tipo email activo y bien configurado en Notificaciones.",
      "Crear un reporte programado funciona igual que el resto de los formularios de la plataforma: se completa y se aprieta el boton, sin escribir codigo.",
    ],
  },
  {
    id: "notifications",
    label: "Notificaciones",
    tagline: "Como te avisa SentinelOps",
    overview:
      "Aca configuras por donde queres recibir avisos (por ejemplo email) y podes ver el historial de todo lo que se envio.",
    steps: [
      { title: "Agregar un canal", body: "Completa el formulario de abajo con el tipo de canal y sus datos (por ejemplo, la direccion de email) y guardalo." },
      { title: "Habilitar o deshabilitar", body: "Cada canal tiene un casillero para activarlo o desactivarlo sin borrarlo -- util si queres pausar los avisos por un tiempo." },
      { title: "Enviar una prueba", body: "Usa \"Enviar notificacion de prueba\" para confirmar que un canal esta bien configurado antes de depender de el." },
      { title: "Borrar un canal", body: "El boton \"Eliminar\" saca el canal de la lista para siempre." },
    ],
    tips: ["El Historial de envios muestra cuales notificaciones se entregaron bien y cuales fallaron, para corregir un canal mal configurado."],
  },
  {
    id: "integrations",
    label: "Integraciones",
    tagline: "Conectar SentinelOps con tus herramientas reales",
    overview:
      "Las integraciones conectan las acciones automaticas (por ejemplo, bloquear una IP en tu firewall real, o crear un ticket en Jira) con tus sistemas de verdad. Mientras no configures un conector, esas acciones quedan simuladas.",
    steps: [
      {
        title: "Crear un conector",
        body: "Elegi el tipo (por ejemplo firewall, EDR o sistema de tickets) y completa el formulario con los datos que pide: una direccion, una clave de acceso, etc. Todo con campos simples, sin escribir JSON a mano.",
      },
      {
        title: "Activar, desactivar o borrar",
        body: "Un conector deshabilitado no se usa, aunque siga guardado; \"Eliminar\" lo borra por completo.",
      },
      {
        title: "Tickets y contenciones",
        body: "Las tablas de abajo muestran los tickets que se crearon (por ejemplo desde un playbook de SOAR) y el historial de acciones de contencion ya ejecutadas contra tus sistemas reales.",
      },
    ],
    tips: [
      "Las claves de acceso que cargues quedan cifradas: nunca se muestran de nuevo en texto plano despues de guardarlas.",
      "Sin ningun conector configurado, SentinelOps sigue funcionando igual, pero las acciones de contencion quedan solo simuladas.",
    ],
  },
  {
    id: "org-billing",
    label: "Organizaciones y pagos",
    tagline: "Solo visible para administradores",
    adminOnly: true,
    overview:
      "Esta seccion es para quien administra la cuenta: los datos de tu organizacion, los usuarios que pueden entrar a la plataforma y el estado de la suscripcion.",
    steps: [
      { title: "Organizaciones", body: "Aca se gestionan los datos generales de tu organizacion y, si tenes mas de una, cada una se administra por separado." },
      { title: "Pagos y licencia", body: "Aca ves el estado de tu suscripcion (activa, por vencer o vencida) y el acceso para renovarla o cambiar el medio de pago." },
    ],
    tips: ["Esta seccion solo aparece en el menu para roles de administrador."],
  },
];
