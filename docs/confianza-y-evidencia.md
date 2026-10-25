# Confianza y evidencia

Pantalla **Confianza y evidencia** (menu lateral). Reune lo que TERO puede *demostrarle* a un auditor,
a un cliente o a un juez, de forma que ellos lo puedan verificar **sin tener que confiar en nosotros**.

Cada funcion explica abajo que prueba y que **no** prueba. Ninguna reemplaza una opinion legal o una
auditoria formal.

## 1. Cadena de custodia digital

**Para que sirve.** Poder demostrar que lo que paso en un caso (alertas, acciones de respuesta, cambios
de estado, escaneos, cierres de vulnerabilidades) quedo registrado en su momento y no se modifico ni se
borro despues.

**Como funciona.**

- Cada evento relevante se anota en una cadena por organizacion. Cada entrada guarda la huella
  (SHA-256) de la anterior: borrar o reordenar algo rompe todo lo que sigue.
- Cada entrada se firma con **Ed25519**. La clave publica se puede entregar a cualquiera; la privada
  nunca sale del servidor.
- Los eventos llegan solos desde `siem-service` (alertas), `soar-service` (playbooks), `vuln-service`
  (estados), `scan-service` (escaneos) y `case-service` (casos). Si `case-service` no responde, el
  servicio que emite reintenta desde una cola en memoria (hasta 500 eventos; se pierde si ese servicio se
  reinicia antes de lograr entregarlos).
- Solo `case-service` puede escribir eventos `case.*` y `evidence.*`.

**Como se usa.**

1. *Confianza y evidencia → Cadena de custodia → Verificar la cadena ahora*: recorre la cadena completa
   y avisa en que entrada se rompe, si se rompe.
2. *Paquete de evidencia de un caso* (o el boton **Descargar evidencia** en *Casos*): baja un `.zip` con
   la ficha del caso, todos sus eventos firmados, el listado completo de huellas de la cadena, un
   `LEEME.txt` y `verificar_evidencia.py`. De los eventos de otros casos solo hay huellas, no datos.
3. El auditor corre, en cualquier computadora con Python 3 y **sin acceso a TERO**:

   ```
   python verificar_evidencia.py evidencia-caso.zip
   python verificar_evidencia.py evidencia-caso.zip --huella 9f3a-01bc-...   # huella de la clave que le diste en mano
   ```

   El verificador usa solo la biblioteca estandar de Python e incluye su propia verificacion Ed25519.
   Hace 5 controles: cadena y firmas, eventos mostrados = eventos firmados, ficha del caso = la
   exportacion registrada, ancla firmada y coherente, y (opcional) huella de la clave.
4. *Ancla externa*: genera un registro firmado (cantidad + huella final) para guardar **fuera** de TERO
   (mail, ticket, carpeta aparte). Despues se puede verificar la cadena contra esa ancla.

**Configuracion recomendada.** Definir `CUSTODY_SIGNING_SEED` en `.env` (texto largo y secreto) antes
de empezar a usar la cadena. Si no esta definido, la clave se deriva de `JWT_SECRET_KEY` (funciona, pero
queda atada a ese secreto). Cambiar la semilla mas adelante invalida las firmas ya hechas.

**Limites (decirlos en voz alta).**

- Prueba **integridad y momento**: que el sistema registro eso y cuando. No prueba que los hechos sean
  verdaderos.
- Quien tenga la semilla de firma o administre el servidor podria rehacer una cadena completa. Por eso
  existen el ancla externa y la huella de la clave entregada por otro canal.
- Si `case-service` estuvo caido y se reinicio el servicio emisor, pueden faltar eventos de ese lapso
  (no se manipulan: simplemente no llegaron).
- La validez legal de un paquete depende de la jurisdiccion y del perito que lo presente.
