# Licencias de terceros

Los textos completos de cada licencia estan en la carpeta `licenses/`. Las librerias
de Python/JavaScript estan en `THIRD-PARTY-DEPENDENCIES.md`.

SentinelOps invoca los siguientes motores de escaneo como **binarios
externos** (via subprocess, nunca importados ni enlazados como libreria
dentro del codigo de SentinelOps). Cada uno conserva su propia licencia
open-source; ninguna de ellas impone condiciones que impidan vender
SentinelOps como producto comercial, siempre que se respeten los avisos
de copyright de abajo y, en el caso de Semgrep y YARA, que **nunca** se
distribuyan/usen las reglas de terceros mencionadas (ver el detalle en
cada seccion).

Este archivo documenta la atribucion legal de cada motor. No reemplaza
una revision legal propia si las condiciones de uso cambian (version
nueva del motor, relicenciamiento, etc.) -- conviene revisarlo cada vez
que se actualice una de estas dependencias.

---

## Trivy

- **Licencia:** Apache License 2.0 (texto en `licenses/APACHE-2.0.txt`; aviso NOTICE en `licenses/trivy-NOTICE.txt`)
- **Copyright:** Aqua Security Software Ltd. y contribuyentes del proyecto
  Trivy.
- **Repositorio:** https://github.com/aquasecurity/trivy
- **Texto completo de la licencia:** https://github.com/aquasecurity/trivy/blob/main/LICENSE
- Se invoca tal cual se distribuye oficialmente, sin modificaciones.

## Nuclei

- **Licencia:** MIT License
- **Copyright:** ProjectDiscovery, Inc. y contribuyentes del proyecto
  Nuclei.
- **Repositorio:** https://github.com/projectdiscovery/nuclei
- **Texto completo de la licencia:** https://github.com/projectdiscovery/nuclei/blob/dev/LICENSE.md
- Se invoca tal cual se distribuye oficialmente. SentinelOps solo usa las
  plantillas de deteccion estandar (categorias de severidad/deteccion),
  nunca las categorias `dos`/`fuzz`/`intrusive`.

## OWASP ZAP (Zed Attack Proxy)

- **Licencia:** Apache License 2.0
- **Copyright:** The ZAP Project contributors (proyecto bajo la Software
  Security Project de la OWASP Foundation).
- **Repositorio:** https://github.com/zaproxy/zaproxy
- **Texto completo de la licencia:** https://github.com/zaproxy/zaproxy/blob/main/LICENSE
- SentinelOps lo corre unicamente en modo **pasivo** (`-quickurl`/
  `-quickout` del Quick Start de linea de comandos de ZAP: spider +
  analisis pasivo). Nunca se usa `-quickattack` ni ningun modo de
  escaneo activo.

## Semgrep

- **Licencia del motor (CLI/engine):** GNU Lesser General Public License
  v2.1 (LGPL-2.1).
- **Copyright:** Semgrep, Inc.
- **Repositorio:** https://github.com/semgrep/semgrep
- **Texto completo de la licencia:** https://github.com/semgrep/semgrep/blob/develop/LICENSE
- El motor se invoca como **binario externo via subprocess** (nunca se
  importa ni se enlaza como libreria dentro del codigo de SentinelOps),
  que es precisamente la forma de uso que la LGPL-2.1 permite sin
  imponer condiciones de licenciamiento sobre el software que lo invoca.
- **Importante -- reglas:** SentinelOps usa UNICAMENTE reglas propias,
  escritas por el equipo de SentinelOps
  (`backend/services/scan-service/rules/semgrep/sentinelops-rules.yml`).
  **Nunca** se usa el registro publico de reglas de Semgrep (`--config
  auto`, `p/...`, `r/...`, el paquete `semgrep-rules`), porque ese
  registro se distribuye bajo la "Semgrep Rules License v1.0", una
  licencia separada de la del motor que prohibe explicitamente ofrecer
  esas reglas como parte de un servicio a terceros -- incompatible con
  venderlas embebidas en SentinelOps.

## Gitleaks

- **Licencia:** MIT License
- **Copyright:** Copyright (c) 2019 Zachary Rice.
- **Repositorio:** https://github.com/gitleaks/gitleaks

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## YARA

- **Licencia:** BSD 3-Clause License
- **Copyright:** Copyright (c) 2007-2016, The YARA Authors. All Rights Reserved.
- **Repositorio:** https://github.com/VirusTotal/yara
- **Texto completo:** `licenses/yara-BSD-3-Clause.txt` (copia del archivo COPYING oficial).

- **Importante -- reglas:** SentinelOps usa UNICAMENTE reglas propias,
  escritas por el equipo de SentinelOps
  (`backend/services/scan-service/rules/yara/sentinelops.yar`). No se
  incluye ningun pack de reglas YARA de terceros (muchos mezclan
  licencias incompatibles entre si o con uso comercial).

## Zeek

- **Licencia:** BSD 3-Clause License
- **Copyright:** Copyright (c) 1995-now, The Regents of the University of
  California through the Lawrence Berkeley National Laboratory and the
  International Computer Science Institute. All rights reserved.
- **Texto completo:** `licenses/zeek-BSD-3-Clause.txt`.
- **Repositorio:** https://github.com/zeek/zeek
- **Texto completo de la licencia:** https://github.com/zeek/zeek/blob/master/COPYING
- SentinelOps lo corre como job de **duracion fija** (ventana
  configurable de 1 a 60 minutos, default 5): captura y clasifica
  trafico de red durante esa ventana y reporta lo detectado, en vez de
  quedar corriendo como daemon permanente.

## Falco

- **Licencia:** Apache License 2.0
- **Copyright:** The Falco Authors (proyecto graduado de la Cloud Native
  Computing Foundation, CNCF).
- **Repositorio:** https://github.com/falcosecurity/falco
- **Texto completo de la licencia:** https://github.com/falcosecurity/falco/blob/master/COPYING
- SentinelOps lo corre como job de **duracion fija** (ventana
  configurable de 1 a 60 minutos, default 5, via su propio flag nativo
  `-M <segundos>`): observa eventos de runtime durante esa ventana y
  reporta lo detectado, en vez de quedar corriendo como daemon
  permanente.

---

## Resumen de compatibilidad comercial

| Motor | Licencia | Reglas/config de terceros usadas | Apto para vender |
|---|---|---|---|
| Trivy | Apache-2.0 | N/A | Si |
| Nuclei | MIT | Plantillas oficiales del proyecto | Si |
| OWASP ZAP | Apache-2.0 | N/A (modo pasivo) | Si |
| Semgrep | LGPL-2.1 (motor, via subprocess) | **Ninguna** -- solo reglas propias | Si |
| Gitleaks | MIT | N/A | Si |
| YARA | BSD-3-Clause | **Ninguna** -- solo reglas propias | Si |
| Zeek | BSD-3-Clause | N/A | Si |
| Falco | Apache-2.0 | N/A | Si |

Ninguno de estos 8 motores, usados de esta forma, impide vender
SentinelOps como producto comercial a terceros.
