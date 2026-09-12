# AI Web Auditor

Herramienta modular de auditoria web asistida por IA.

Esta version esta pensada como base segura para practicas y auditorias con
autorizacion. Solo ejecuta comprobaciones no intrusivas: validacion de URL y
scope, HTTP/HTTPS y redirecciones, cabeceras de seguridad, cookies, HTTP Basic
Auth, metodos anunciados por OPTIONS, TLS basico y crawling seguro limitado por
scope. Tambien incluye fingerprinting web no intrusivo a partir de cabeceras,
cookies, HTML inicial y ficheros publicos habituales, analisis IA opcional desde
CLI y GUI, informes Markdown/HTML/PDF, proyectos locales, historial separado por
proyecto, inventario web exportable, descubrimiento DNS seguro de subdominios,
chequeo TCP limitado de puertos, valoracion determinista de riesgo, plan de
remediacion, laboratorio vulnerable local, comparacion de auditorias y paquetes
de evidencias saneadas. Desde v0.20 tambien analiza JavaScript de forma pasiva
para descubrir endpoints citados en scripts, y genera un modelo de entry points
con endpoints, parametros, formularios y metodos observados para orientar la
revision manual posterior. Desde v0.21 incorpora un motor pasivo de reglas que
mapea las evidencias observadas contra controles OWASP WSTG y OWASP ASVS para
mejorar la trazabilidad de la auditoria. Desde v0.22 puede importar resultados
externos ya generados por herramientas como OWASP ZAP, Burp Suite, Nmap, CSV o
listas de URLs para centralizarlos en el mismo inventario, mapeo de reglas,
valoracion, evidencias e informes. Desde v0.23 permite ejecutar enumeraciones
con perfiles anonimos o autenticados y comparar la superficie visible entre
roles sin guardar secretos en los resultados. Desde v0.24 genera evidencias
visuales SVG desde el JSON de auditoria para resumir riesgo, fingerprinting y
cobertura de modulos sin ejecutar acciones adicionales contra el objetivo.

No implementa explotacion, fuerza bruta, fuzzing agresivo, crawling masivo,
escaneo de puertos amplio, fuerza bruta DNS agresiva ni pruebas intrusivas. La
importacion de archivos externos solo lee resultados existentes y no ejecuta
herramientas contra el objetivo.

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Tambien puedes instalar dependencias directamente:

```powershell
pip install -r requirements.txt
```

La v0.24 no necesita librerias externas en tiempo de ejecucion.

## Uso rapido

```powershell
ai-web-auditor scan https://example.com
```

Si Windows no reconoce `ai-web-auditor`, `py` o `python`, puedes usar el
lanzador incluido:

```powershell
.\ai-web-auditor.cmd --help
.\ai-web-auditor.cmd init-scope https://example.com --output audit.json
.\ai-web-auditor.cmd scan --config audit.json
.\ai-web-auditor.cmd analyze outputs/result.json --dry-run
.\ai-web-auditor.cmd inventory outputs/result.json --output outputs/inventory.csv
.\ai-web-auditor.cmd entrypoints outputs/result.json --output outputs/entry-points.csv
.\ai-web-auditor.cmd assess outputs/result.json --output outputs/assessment.json
.\ai-web-auditor.cmd rules outputs/result.json --output outputs/rules.json
.\ai-web-auditor.cmd evidence outputs/result.json --output outputs/evidence.zip
.\ai-web-auditor.cmd visuals outputs/result.json --output outputs/visual-evidence.json --svg-dir outputs/visuals
.\ai-web-auditor.cmd import examples/import-zap-example.json --target http://127.0.0.1:8080/members/ --output outputs/imported.json
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.md
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.html
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.pdf
.\ai-web-auditor.cmd history
.\ai-web-auditor.cmd compare baseline.json current.json
.\ai-web-auditor.cmd role-compare public.json member.json
.\ai-web-auditor.cmd project init "Cliente Demo" --target https://example.com
.\ai-web-auditor.cmd scan --project cliente-demo
.\ai-web-auditor.cmd lab
.\ai-web-auditor.cmd gui
```

Abrir la interfaz grafica local:

```powershell
ai-web-auditor gui
```

En Windows tambien puedes abrir la interfaz con doble clic en:

```powershell
.\start-ai-web-auditor.cmd
```

Por defecto se sirve en:

```text
http://127.0.0.1:8765/
```

Arrancar solo el laboratorio vulnerable local:

```powershell
ai-web-auditor lab
```

El objetivo de auditoria recomendado para la demo es:

```text
http://127.0.0.1:8080/members/
```

Crear una configuracion de auditoria con preguntas guiadas:

```powershell
ai-web-auditor init-scope https://example.com --output audit.json
```

Ejecutar usando la configuracion creada:

```powershell
ai-web-auditor scan --config audit.json
```

Ejecutar con un perfil autenticado temporal desde CLI:

```powershell
ai-web-auditor scan https://example.com --auth-profile analyst --auth-header "Authorization: Bearer <token>" --auth-cookie "sessionid=<valor>"
```

Guardar JSON:

```powershell
ai-web-auditor scan https://example.com --json-output outputs/example.json
```

Guardar JSON y paquete de evidencias en una sola ejecucion:

```powershell
ai-web-auditor scan https://example.com --json-output outputs/example.json --evidence-output outputs/evidence.zip
```

Generar un paquete de evidencias desde un JSON existente:

```powershell
ai-web-auditor evidence outputs/example.json --output outputs/evidence.zip
```

Generar evidencias visuales desde un JSON existente:

```powershell
ai-web-auditor visuals outputs/example.json --output outputs/visual-evidence.json --svg-dir outputs/visuals
```

Importar resultados externos ya generados:

```powershell
ai-web-auditor import examples/import-zap-example.json --target http://127.0.0.1:8080/members/ --output outputs/imported-zap.json
ai-web-auditor import examples/import-nmap-example.xml --target http://127.0.0.1:8080/members/ --output outputs/imported-nmap.json
ai-web-auditor import examples/import-findings-example.csv --target http://127.0.0.1:8080/members/ --output outputs/imported-csv.json
ai-web-auditor import examples/import-urls-example.txt --target http://127.0.0.1:8080/members/ --output outputs/imported-urls.json
```

Unir una importacion externa con una auditoria propia:

```powershell
ai-web-auditor import examples/import-zap-example.json --merge outputs/example.json --output outputs/example-with-zap.json
```

Exportar inventario de URLs a CSV:

```powershell
ai-web-auditor inventory outputs/example.json --output outputs/inventory.csv
```

Exportar puntos de entrada pasivos a CSV:

```powershell
ai-web-auditor entrypoints outputs/example.json --output outputs/entry-points.csv
```

Calcular valoracion de riesgo y plan de remediacion desde un JSON existente:

```powershell
ai-web-auditor assess outputs/example.json
ai-web-auditor assess outputs/example.json --output outputs/assessment.json
```

Calcular el mapeo pasivo OWASP WSTG/ASVS desde un JSON existente:

```powershell
ai-web-auditor rules outputs/example.json
ai-web-auditor rules outputs/example.json --output outputs/rules.json
```

Guardar una auditoria en el historial local:

```powershell
ai-web-auditor scan https://example.com --save-history --history-label "revision inicial"
ai-web-auditor history
```

Comparar dos auditorias:

```powershell
ai-web-auditor compare baseline.json current.json
ai-web-auditor compare id-auditoria-antigua id-auditoria-nueva
```

Analizar un resultado con IA:

```powershell
$env:OPENAI_API_KEY = "tu_api_key"
ai-web-auditor analyze outputs/example.json --markdown-output outputs/analysis.md
```

Probar el prompt sin llamar a la API:

```powershell
ai-web-auditor analyze outputs/example.json --dry-run --json
```

Generar un informe Markdown:

```powershell
ai-web-auditor report outputs/example.json --output outputs/report.md
```

Generar informes HTML o PDF:

```powershell
ai-web-auditor report outputs/example.json --format html --output outputs/report.html
ai-web-auditor report outputs/example.json --format pdf --output outputs/report.pdf
```

Anadir metadatos al informe:

```powershell
ai-web-auditor report outputs/example.json --output outputs/report.html --client "Cliente Demo" --auditor "David" --engagement "Practica 1" --scope-summary "https://example.com"
```

Generar un informe Markdown incorporando el analisis IA:

```powershell
ai-web-auditor analyze outputs/example.json --json-output outputs/analysis.json
ai-web-auditor report outputs/example.json --ai-analysis outputs/analysis.json --output outputs/report.md
```

Mostrar solo JSON en consola:

```powershell
ai-web-auditor scan https://example.com --json
```

Permitir objetivos privados o locales, util solo en laboratorio:

```powershell
ai-web-auditor scan http://127.0.0.1:8080 --allow-private
```

Usar un fichero de configuracion:

```powershell
ai-web-auditor scan https://example.com --config examples/audit.json
```

Tambien funciona como modulo:

```powershell
python -m ai_web_auditor scan https://example.com
```

Ejecutar tests:

```powershell
python -m unittest discover tests
```

## Configuracion

Ejemplo en `examples/audit.json`:

```json
{
  "target": {
    "url": "https://example.com/"
  },
  "scope": {
    "allowed_hosts": ["example.com"],
    "allow_subdomains": true,
    "allow_private_networks": false,
    "resolve_dns": true,
    "include_paths": ["/"],
    "exclude_paths": []
  },
  "http": {
    "timeout_seconds": 10,
    "max_redirects": 10,
    "user_agent": "AI-Web-Auditor/0.24",
    "verify_tls": true,
    "check_http_counterpart": true
  },
  "ai": {
    "provider": "openai",
    "model": "gpt-5.6",
    "api_key_env": "OPENAI_API_KEY",
    "endpoint": "https://api.openai.com/v1/responses",
    "timeout_seconds": 45.0,
    "max_input_chars": 60000,
    "store": false,
    "language": "es"
  },
  "fingerprinting": {
    "max_body_bytes": 262144,
    "detect_versions": true,
    "public_paths": [
      "/robots.txt",
      "/.well-known/security.txt",
      "/security.txt",
      "/sitemap.xml"
    ]
  },
  "crawler": {
    "max_depth": 1,
    "max_pages": 25,
    "delay_seconds": 0.0,
    "max_body_bytes": 262144,
    "include_query_strings": false,
    "use_robots_txt": true,
    "use_sitemap_xml": true,
    "use_well_known": true,
    "follow_sitemap_urls": true,
    "follow_robots_paths": false,
    "metadata_max_urls": 100
  },
  "javascript": {
    "max_pages": 10,
    "max_scripts": 25,
    "max_body_bytes": 262144,
    "include_inline": true,
    "fetch_external_scripts": true
  },
  "subdomains": {
    "candidates": ["www", "app", "api", "portal", "admin"],
    "max_candidates": 25,
    "timeout_seconds": 2.0
  },
  "ports": {
    "ports": [80, 443, 8080, 8443, 8000],
    "max_ports": 20,
    "timeout_seconds": 1.0
  },
  "auth": {
    "active_profile": "public",
    "profiles": [
      {
        "id": "public",
        "name": "Publico",
        "headers": {},
        "cookies": {},
        "notes": "Enumeracion anonima."
      }
    ]
  },
  "evidence": {
    "enabled": true,
    "capture_request_headers": true,
    "capture_response_headers": true,
    "capture_response_body_sample": true,
    "max_body_chars": 4000
  },
  "modules": {
    "scope": true,
    "http": true,
    "security_headers": true,
    "cookies": true,
    "basic_auth": true,
    "http_methods": true,
    "tls": true,
    "subdomains": false,
    "ports": false,
    "fingerprinting": true,
    "crawler": true,
    "javascript": true
  }
}
```

## Modulos incluidos

- `scope`: normaliza la URL, valida esquema `http`/`https`, evita credenciales
  embebidas y restringe el objetivo al scope permitido.
- `http`: revisa disponibilidad HTTP/HTTPS, cadena de redirecciones y si HTTP
  redirige a HTTPS.
- `security_headers`: comprueba cabeceras como HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy y Permissions-Policy.
- `cookies`: revisa flags `Secure`, `HttpOnly` y `SameSite` en cookies recibidas.
- `basic_auth`: detecta `WWW-Authenticate: Basic` y eleva el riesgo si aparece
  sobre HTTP sin TLS.
- `http_methods`: usa `OPTIONS` para leer metodos anunciados por el servidor.
- `tls`: obtiene informacion basica del certificado y de la version TLS
  negociada.
- `subdomains`: resuelve una lista corta de subdominios candidatos por DNS,
  respetando el scope. Esta desactivado por defecto y no escanea los hosts
  encontrados automaticamente.
- `ports`: realiza conexiones TCP basicas a una lista limitada de puertos del
  host objetivo. Esta desactivado por defecto y no solicita banners ni envia
  payloads.
- `fingerprinting`: identifica senales de servidor, CDN, framework, lenguaje,
  CMS y ficheros publicos como `robots.txt`, `security.txt` y `sitemap.xml`.
- `crawler`: recorre enlaces internos sin enviar formularios, sin salir del
  scope, con profundidad y numero de paginas limitados. Tambien
  lee `robots.txt`, `sitemap.xml`, endpoints `.well-known` y clasifica rutas
  interesantes como login, admin, API, recovery, callbacks o uploads.
- `javascript`: analiza HTML y ficheros JavaScript dentro del scope para
  descubrir endpoints, parametros y metodos inferidos desde llamadas como
  `fetch()` o `axios.post()`. No ejecuta los endpoints descubiertos ni envia
  cuerpos de peticion.

## Analisis IA

La IA no escanea objetivos ni ejecuta pruebas. Solo analiza un JSON ya generado:

```powershell
ai-web-auditor scan --config audit.json --json-output outputs/result.json
ai-web-auditor analyze outputs/result.json --markdown-output outputs/analysis.md
```

La API key se lee desde una variable de entorno:

```powershell
$env:OPENAI_API_KEY = "tu_api_key"
```

La configuracion permite cambiar proveedor, modelo, endpoint y limite de texto.
Antes de enviar datos a la API se aplica una redaccion basica de claves como
`Authorization`, `Cookie`, `token`, `password`, `secret` y parametros sensibles
en URLs.

Para revisar lo que se enviaria al proveedor sin hacer la llamada:

```powershell
ai-web-auditor analyze outputs/result.json --dry-run --json
```

Desde la interfaz grafica tambien puedes abrir la pestana `IA` despues de una
auditoria. Por defecto funciona en modo `Dry-run`, asi puedes revisar el prompt
sin consumir API. Si desactivas `Dry-run`, usara la API configurada mediante
`OPENAI_API_KEY`. Si la auditoria esta guardada en historial, el analisis se
puede guardar dentro del propio JSON como `ai_analysis`.

## Valoracion de riesgo

Cada escaneo nuevo incluye un bloque `assessment` dentro del JSON. Esta
valoracion no ejecuta nuevas peticiones: interpreta hallazgos, inventario,
subdominios y puertos ya observados.

Incluye:

- puntuacion de riesgo de 0 a 100;
- nivel `informational`, `low`, `medium`, `high` o `critical`;
- prioridades ordenadas por severidad, exposicion y tipo de hallazgo;
- acciones rapidas de bajo esfuerzo;
- plan de remediacion por fases;
- notas de cobertura y seguridad.

Tambien se puede recalcular sobre un JSON anterior:

```powershell
ai-web-auditor assess outputs/result.json --output outputs/assessment.json
```

La interfaz grafica muestra esta informacion en la pestana `Riesgo`.

## Motor pasivo de reglas OWASP

Cada escaneo nuevo incluye un bloque `rule_evaluation` dentro del JSON. Este
motor no contacta de nuevo con el objetivo: toma hallazgos, inventario, entry
points, JavaScript, DNS y puertos ya observados y los relaciona con reglas
pasivas.

Para cada regla se guarda:

- regla interna y severidad;
- hallazgos o senales que la han activado;
- controles OWASP WSTG y OWASP ASVS relacionados;
- razon de auditoria;
- siguiente revision manual recomendada;
- hallazgos que aun no tienen mapeo.

Recalcular el mapeo sobre una auditoria anterior:

```powershell
ai-web-auditor rules outputs/result.json --output outputs/rules.json
```

En la interfaz grafica se revisa desde la pestana `Reglas`. Sirve para preparar
la fase manual posterior: por ejemplo, saber que un Basic Auth sobre HTTP toca
revisiones de transporte seguro, o que endpoints detectados en JavaScript
alimentan el inventario de puntos de entrada. Una regla activada no significa
que exista una explotacion confirmada; significa que hay evidencia pasiva que
merece revision trazable.

## Reporting

La herramienta genera informes Markdown, HTML y PDF desde el JSON de escaneo.
Este paso no contacta con el objetivo ni ejecuta nuevas comprobaciones:

```powershell
ai-web-auditor report outputs/result.json --output outputs/report.md
ai-web-auditor report outputs/result.json --output outputs/report.html
ai-web-auditor report outputs/result.json --output outputs/report.pdf
```

Si ya existe un analisis IA guardado en JSON, se puede incorporar al informe:

```powershell
ai-web-auditor report outputs/result.json --ai-analysis outputs/analysis.json --output outputs/report.md
```

Si el resultado de auditoria ya contiene un bloque `ai_analysis`, el informe lo
usa automaticamente sin pasar `--ai-analysis`.

El informe incluye:

- metadatos de cliente, auditor, proyecto, scope y notas;
- objetivo y estado del escaneo;
- resumen ejecutivo;
- resumen por severidad;
- valoracion determinista de riesgo, prioridades y plan de remediacion;
- resumen por modulo;
- hallazgos y evidencias;
- fingerprinting, crawler, metadatos publicos y rutas clasificadas si estan presentes;
- analisis JavaScript con scripts revisados y endpoints citados por el cliente;
- inventario web con URLs, estados, tipos de contenido y formularios detectados;
- puntos de entrada con endpoints, parametros, formularios y metodos observados;
- descubrimiento de subdominios si se activa;
- chequeo TCP limitado de puertos si se activa;
- priorizacion IA si se aporta;
- limitaciones de la auditoria.

Hay ejemplos en `examples/report-example.md` y `examples/report-example.html`.

## Laboratorio local

La version actual incluye un laboratorio vulnerable solo para pruebas locales. Sirve una
web de demo en `127.0.0.1` con problemas controlados:

- HTTP sin TLS;
- Basic Auth sobre HTTP en `/members/`;
- cookies sin `HttpOnly`, `Secure` o `SameSite` adecuado;
- cabeceras de seguridad ausentes;
- metadatos de tecnologia expuestos;
- metodos HTTP de riesgo anunciados por `OPTIONS`;
- `robots.txt`, `sitemap.xml`, `security.txt` y OpenID metadata de ejemplo;
- rutas de login, API y recuperacion para probar la clasificacion del crawler;
- formulario HTML de login detectado de forma pasiva, sin envio de datos.
- ficheros JavaScript y bloques inline con endpoints de API de demo, parametros
  sensibles ficticios y referencias fuera de scope.

Arrancarlo desde consola:

```powershell
ai-web-auditor lab
```

Escanearlo desde otra terminal:

```powershell
ai-web-auditor scan http://127.0.0.1:8080/members/ --allow-private --save-history --history-label "lab-demo-inicial"
```

Desde la interfaz grafica puedes usar el panel `Laboratorio`:

1. Pulsa `Iniciar`.
2. Comprueba que el estado cambie a `Conectado`.
3. Pulsa `Usar demo`.
4. Ejecuta la auditoria.
5. Revisa hallazgos, JSON, IA en dry-run e informe.

El laboratorio esta pensado para la demo de la practica y no debe publicarse en
red. Por seguridad, solo permite arrancar en localhost o direcciones loopback.

## Evidencias

Cada auditoria registra evidencias HTTP saneadas dentro del bloque `requests`:

- identificador estable de peticion;
- metodo, URL saneada, codigo de estado y tiempo;
- cabeceras de request y response con valores sensibles redactados;
- muestra truncada del cuerpo de respuesta si es texto;
- hash SHA-256 de la muestra capturada por el cliente HTTP;
- motivo de no captura cuando el cuerpo esta vacio, desactivado o no es texto.

El paquete ZIP de evidencias contiene:

- `manifest.json`;
- `scan-result.json`;
- `http/requests.json`;
- un JSON individual por peticion en `http/`;
- `findings/findings.json`;
- `modules/modules.json`;
- `visuals/visual-evidence.json`;
- `visuals/audit-overview.svg`;
- `visuals/fingerprint-map.svg`;
- `visuals/coverage-matrix.svg`;
- `inventory/inventory.json`;
- `entry-points/entry-points.json`;
- `javascript/javascript.json`;
- `javascript/endpoints.json`;
- `assessment/assessment.json`;
- `rules/rule-evaluation.json`;
- `rules/matches.json`;
- `README.md` con notas de seguridad.

La herramienta redacta `Authorization`, `Cookie`, `Set-Cookie`, posibles tokens,
passwords, secrets y parametros de query sensibles. No guarda cuerpos de request
ni cuerpos completos de respuesta.

Generar evidencias:

```powershell
ai-web-auditor evidence outputs/result.json --output outputs/evidence.zip
```

Desde la interfaz grafica usa el boton `Evidencias ZIP` despues de ejecutar o
abrir una auditoria.

## Evidencia visual

La v0.24 anade un bloque `visual_evidence` al JSON y una pestana `Visual` en la
interfaz. Genera tres capturas SVG locales:

- `audit-overview.svg`: objetivo, severidad, riesgo y metricas principales;
- `fingerprint-map.svg`: tecnologias, ficheros publicos y superficie observada;
- `coverage-matrix.svg`: modulos agrupados por fase y estado.

Estas capturas no son screenshots de navegador. Se crean a partir de las
evidencias ya recogidas por la auditoria, por lo que no hacen crawling extra,
no renderizan paginas con navegador y no ejecutan endpoints descubiertos.

Exportar solo la evidencia visual:

```powershell
ai-web-auditor visuals outputs/result.json --output outputs/visual-evidence.json --svg-dir outputs/visuals
```

Tambien quedan incluidas en el ZIP de evidencias y en los informes HTML.

Hay ejemplos en `examples/visual-evidence-example.json` y `examples/visuals/`.

## Inventario web

Cada escaneo nuevo incluye un bloque `inventory` dentro del JSON. Este bloque
resume:

- URLs visitadas por el crawler;
- URLs descubiertas pero no visitadas;
- URLs excluidas por scope;
- URLs externas registradas sin solicitarlas;
- scripts JavaScript revisados y endpoints declarados en cliente;
- codigos HTTP y tipos de contenido disponibles;
- formularios HTML encontrados sin enviarlos;
- rutas interesantes como `/login`, `/admin`, `/members`, `/api` o `/private`.

Exportar solo el inventario:

```powershell
ai-web-auditor inventory outputs/result.json --format json
ai-web-auditor inventory outputs/result.json --output outputs/inventory.csv
```

En la interfaz grafica, la pestana `Inventario` permite filtrar por ruta,
estado HTTP, tipo de contenido, fuente o motivo de interes. El boton
`Inventario CSV` descarga la tabla para revisarla en Excel u otra herramienta.

Hay un ejemplo en `examples/inventory-example.csv`.

## Puntos de entrada

Cada escaneo nuevo incluye un bloque `entry_points` dentro del JSON. Este bloque
deriva una lista de revision a partir de evidencias pasivas:

- endpoints normalizados;
- parametros de query y campos de formularios;
- formularios HTML, metodo, action, campos password y posibles CSRF;
- metodos HTTP observados o anunciados;
- estado del endpoint: visitado, descubierto, metadatos, form action, excluido o fuera de scope;
- notas como `state_changing_method`, `sensitive_parameter_name`, `api_route` o `login_route`.

Exportar solo puntos de entrada:

```powershell
ai-web-auditor entrypoints outputs/result.json --format json
ai-web-auditor entrypoints outputs/result.json --output outputs/entry-points.csv
```

En la interfaz grafica, la pestana `Entradas` permite filtrar por URL, metodo,
parametro, tipo de ruta o nota. El boton `Entradas CSV` descarga la tabla para
priorizar revision manual. No se envian formularios ni se prueban valores.

## Analisis JavaScript

La v0.20 incorpora el modulo `javascript`. Su objetivo es ampliar la
enumeracion inicial detectando endpoints que no aparecen como enlaces HTML,
pero si estan citados en scripts del cliente.

Que hace:

- revisa paginas HTML ya vistas por el crawler y la URL inicial;
- extrae scripts externos con `<script src="...">`;
- descarga scripts externos solo si estan dentro del scope autorizado;
- analiza tambien bloques inline si `include_inline` esta activo;
- extrae URLs absolutas, rutas relativas, rutas `/api/...`, `/graphql`,
  login, auth, callbacks, uploads, health y patrones similares;
- infiere metodos cuando aparecen cerca de `fetch()`, `method: "POST"` o
  llamadas tipo `axios.post()`;
- registra parametros de query y marca nombres sensibles como `token`,
  `session`, `csrf`, `password`, `secret` o `key`;
- envia los endpoints encontrados a `inventory` y `entry_points`.

Que no hace:

- no ejecuta los endpoints descubiertos;
- no envia cuerpos de peticion;
- no analiza scripts de terceros fuera del scope;
- no desofusca codigo ni ejecuta JavaScript en navegador.

Configuracion:

```json
{
  "modules": {
    "javascript": true
  },
  "javascript": {
    "max_pages": 10,
    "max_scripts": 25,
    "max_body_bytes": 262144,
    "include_inline": true,
    "fetch_external_scripts": true
  }
}
```

En la interfaz grafica se revisa desde la pestana `JavaScript`. Ahi puedes
filtrar por endpoint, metodo, parametro, tipo de ruta u origen.

## Descubrimiento de subdominios

La version actual mantiene un modulo DNS seguro para descubrir subdominios candidatos. Esta
desactivado por defecto porque amplia la fase de reconocimiento y conviene
usarlo solo cuando el scope lo permita.

Para activarlo en `audit.json`:

```json
{
  "scope": {
    "allowed_hosts": ["example.com"],
    "allow_subdomains": true,
    "resolve_dns": true
  },
  "modules": {
    "subdomains": true
  },
  "subdomains": {
    "candidates": ["www", "app", "api", "portal", "admin"],
    "max_candidates": 25,
    "timeout_seconds": 2.0
  }
}
```

El modulo:

- solo resuelve hosts que entren en el scope configurado;
- registra candidatos fuera de scope sin resolverlos;
- no ejecuta HTTP, crawler, TLS ni otros modulos contra los subdominios
  encontrados;
- deja los resultados en el modulo `subdomains` del JSON y en los informes.

En la interfaz grafica se activa con el checkbox `Subdominios DNS` y se revisa
en la pestana `Subdominios`.

## Chequeo limitado de puertos

La version actual mantiene un modulo `ports` para comprobar conectividad TCP contra el host
objetivo. Esta desactivado por defecto porque, aunque es limitado, forma parte
de la fase de reconocimiento y debe usarse solo con autorizacion.

Para activarlo en `audit.json`:

```json
{
  "modules": {
    "ports": true
  },
  "ports": {
    "ports": [80, 443, 8080, 8443, 8000],
    "max_ports": 20,
    "timeout_seconds": 1.0
  }
}
```

El modulo:

- solo comprueba el host objetivo validado por scope;
- no escanea automaticamente subdominios descubiertos;
- no envia payloads ni solicita banners;
- registra `open`, `closed`, `filtered` o `error` por puerto;
- genera un hallazgo informativo si encuentra puertos abiertos.

En la interfaz grafica se activa con `Puertos TCP` y se revisa en la pestana
`Puertos`.

## Historial y comparacion

La herramienta permite guardar resultados en un historial local:

```powershell
ai-web-auditor scan --config audit.json --save-history --history-label "pre-fix"
ai-web-auditor history
```

El historial se guarda en `audits/`, que esta ignorado por Git para evitar
subir resultados de auditorias por accidente.

Cuando haces un analisis IA desde la GUI sobre una auditoria guardada, el
resultado puede quedar asociado a esa entrada del historial. Asi los informes
posteriores ya incluyen la priorizacion IA sin tener que adjuntar otro fichero.

Tambien puedes comparar dos ficheros JSON o dos IDs del historial:

```powershell
ai-web-auditor compare outputs/baseline.json outputs/current.json
ai-web-auditor compare 2026-08-16-010000-example.com-pre-fix 2026-08-16-020000-example.com-post-fix
```

La comparacion muestra:

- hallazgos nuevos;
- hallazgos resueltos;
- hallazgos persistentes;
- hallazgos cuya severidad ha cambiado.

Hay ejemplos de salida en `examples/comparison-example.json` y
`examples/role-comparison-example.json`.

## Perfiles autenticados

La v0.23 permite repetir la misma enumeracion con distintos perfiles. Esto es
util en auditorias reales porque la superficie publica, la de un usuario normal
y la de un administrador no suele ser igual.

Desde CLI puedes pasar credenciales temporales para una unica ejecucion:

```powershell
ai-web-auditor scan https://example.com --auth-profile member --auth-name "Usuario normal" --auth-header "Authorization: Bearer <token>" --auth-cookie "sessionid=<valor>" --save-history --history-label member
```

La herramienta envia esas cabeceras/cookies durante la ejecucion, pero en JSON,
evidencias e informes solo guarda los nombres usados, por ejemplo
`Authorization` o `sessionid`. Los valores se redactan.

Evita guardar tokens reales en archivos versionados. Para auditorias reales es
preferible pasar credenciales temporales con `--auth-header`/`--auth-cookie` o
configurarlas desde la UI justo antes de ejecutar.

Para comparar dos ejecuciones guardadas por perfil:

```powershell
ai-web-auditor role-compare public.json member.json
ai-web-auditor role-compare id-publico id-usuario --project cliente-demo
```

La comparacion por rol destaca:

- URLs visibles solo en el perfil actual;
- entry points nuevos;
- cambios de codigo HTTP entre perfiles;
- cambios de metodos observados;
- diferencia de puntuacion de riesgo.

## Proyectos

Los proyectos separan configuracion, historial e informes por cliente, dominio o
laboratorio:

```powershell
ai-web-auditor project init "Cliente Demo" --target https://example.com --client "Cliente Demo SL" --auditor "David"
ai-web-auditor project list
ai-web-auditor project show cliente-demo
```

Cada proyecto crea esta estructura local:

```text
projects/
  cliente-demo/
    project.json
    scope.json
    audits/
    reports/
    ai/
```

Ejecutar una auditoria dentro de un proyecto:

```powershell
ai-web-auditor scan --project cliente-demo
ai-web-auditor history --project cliente-demo
ai-web-auditor compare id-auditoria-antigua id-auditoria-nueva --project cliente-demo
```

Al usar `--project`, el comando `scan` carga `scope.json` del proyecto y guarda
la auditoria en `projects/<id>/audits/`. La carpeta `projects/` esta ignorada
por Git porque puede contener informacion sensible de clientes o laboratorios.

## Interfaz grafica local

La interfaz web local se sirve desde Python:

```powershell
ai-web-auditor gui
```

Tambien puedes evitar que abra el navegador automaticamente:

```powershell
ai-web-auditor gui --no-open
```

Desde la interfaz se puede:

- crear y seleccionar proyectos;
- iniciar, detener y usar el laboratorio local de demo;
- configurar objetivo, hosts, rutas y limites principales;
- seleccionar perfil publico, usuario demo, admin demo o perfil personalizado;
- activar o desactivar modulos;
- ver ayuda contextual dejando el raton sobre opciones, modulos y limites;
- ejecutar una auditoria no intrusiva;
- moverse por vistas agrupadas: auditoria, superficie, entregables e historial;
- revisar resumen, riesgo, hallazgos, modulos, inventario, entradas, subdominios, puertos y JSON;
- revisar reglas pasivas y trazabilidad OWASP desde la pestana `Reglas`;
- revisar endpoints detectados en JavaScript desde su pestana dedicada;
- ajustar el ancho de columnas en tablas como inventario, entradas, JavaScript, subdominios, puertos e historial;
- analizar la auditoria con IA en modo dry-run o con API;
- guardar el analisis IA en el historial local;
- guardar y abrir auditorias del historial local o del proyecto activo;
- comparar dos auditorias guardadas, incluyendo diferencias de superficie por perfil;
- generar informes Markdown, HTML y PDF;
- descargar JSON, Evidencias ZIP, Inventario CSV, Entradas CSV, AI JSON, Markdown, HTML y PDF;
- anadir metadatos de auditoria al informe.

## Scope de auditoria

La herramienta permite preparar una auditoria con preguntas:

```powershell
ai-web-auditor init-scope https://example.com --output audit.json
```

Ese archivo deja fijados los limites principales:

- hosts autorizados;
- si se permiten subdominios;
- rutas incluidas;
- rutas excluidas;
- si se permiten redes privadas o locales;
- limites del crawler y opciones de metadatos (`robots.txt`, `sitemap.xml`, `.well-known`);
- limites de analisis JavaScript: paginas, scripts, tamano maximo, inline y scripts externos;
- limite de candidatos para descubrimiento de subdominios;
- lista, limite y timeout para el chequeo TCP de puertos.

Despues se puede repetir la auditoria de forma consistente:

```powershell
ai-web-auditor scan --config audit.json --json-output outputs/result.json
```

## Importacion de herramientas externas

La version actual puede importar archivos ya exportados por otras herramientas y
convertirlos al modelo interno de AI Web Auditor. Formatos soportados:

- `zap-json`: reporte JSON tradicional de OWASP ZAP;
- `burp-xml`: reporte XML de Burp Suite;
- `nmap-xml`: salida XML de Nmap;
- `csv`: filas con columnas como `url`, `severity`, `finding`, `description` o `recommendation`;
- `url-list`: una URL por linea;
- `generic-json`: JSON sencillo con listas `findings`, `issues`, `alerts` o `items`.

La deteccion automatica suele bastar:

```powershell
ai-web-auditor import examples/import-zap-example.json --target http://127.0.0.1:8080/members/ --output outputs/imported.json
```

Hay un ejemplo de resultado normalizado en `examples/imported-result-example.json`.

Para enriquecer una auditoria ya realizada:

```powershell
ai-web-auditor import zap-report.json --merge outputs/result.json --output outputs/result-with-zap.json
```

En la interfaz grafica, abre la vista `Importar`, selecciona el formato o deja
`Auto`, elige el archivo y deja activado `Unir con auditoria actual` si ya tienes
un resultado abierto. La importacion recalcula inventario, puntos de entrada,
reglas pasivas y valoracion de riesgo.

Notas de seguridad:

- no ejecuta ZAP, Burp, Nmap ni ningun comando externo;
- no contacta el dominio objetivo durante la importacion;
- sanea valores sensibles en URLs y evidencias;
- marca los hallazgos importados como pendientes de validacion manual.

## Estructura para ampliar

La carpeta `src/ai_web_auditor/modules` contiene modulos independientes. Para
anadir uno nuevo:

1. Crear una clase con atributo `name`.
2. Implementar `run(context) -> ModuleResult`.
3. Registrarla en `engine.py`.
4. Anadir el interruptor correspondiente en `config.py`.

La secuencia de producto esta fijada en `ROADMAP.md`. Hasta completarla, no se
priorizaran funcionalidades fuera de estos bloques:

- v0.17: paquete de evidencias descargable por auditoria;
- v0.18: crawler avanzado con `robots.txt`, `sitemap.xml`, `.well-known` y clasificacion de rutas;
- v0.19: modelo de entry points: endpoints, parametros, formularios y metodos;
- v0.20: analisis de JavaScript y descubrimiento de endpoints;
- v0.21: motor pasivo de reglas con mapeo OWASP WSTG/ASVS;
- v0.22: importadores/adaptadores para herramientas externas;
- v0.23: perfiles autenticados y comparacion por roles;
- v0.24: screenshots, fingerprint visual y agrupacion de pantallas;
- v0.25: dashboard de auditoria real con cobertura, cambios, riesgos, pendientes y checklist;
- v0.26: estabilizacion de primera version completa, presets, UX y regresion;
- v0.27: preparacion de release funcional con empaquetado y guia operativa;
- v0.28: rediseno visual completo de la UI con tema oscuro negro/verde, navegacion lateral y menus por flujo;
- v0.29: documentacion Word completa de uso, botones, modulos, ejemplos, informes y flujo de entrega.

## Futuras pruebas controladas

Mas adelante se pueden anadir comprobaciones ofensivas controladas, pero deben
tratarse como modulos de verificacion, no como explotacion libre. La idea seria:

- requerir autorizacion y scope explicito antes de activar esos modulos;
- ejecutar solo pruebas no destructivas y con limite de ritmo;
- pedir confirmacion manual para cualquier comprobacion sensible;
- registrar evidencia y trazabilidad de cada intento;
- bloquear fuerza bruta, exfiltracion, persistencia y cambios destructivos.

Ejemplos razonables para una fase futura serian confirmar configuraciones
inseguras, validar exposicion de cabeceras, cookies o TLS, y comprobar de forma
limitada si una vulnerabilidad reportada sigue presente.

## Versionado

El proyecto usa Git. Flujo recomendado para cada version:

```powershell
git status
git add .
git commit -m "Describe el cambio"
git tag v0.24.0
git push
git push --tags
```

Antes de crear una nueva etiqueta conviene actualizar `pyproject.toml`,
`src/ai_web_auditor/__init__.py` y `CHANGELOG.md`.

## Ejemplo de salida JSON

```json
{
  "tool": "ai-web-auditor",
  "version": "0.24.0",
  "status": "completed",
  "target": {
    "original_url": "https://example.com",
    "normalized_url": "https://example.com/",
    "scheme": "https",
    "host": "example.com",
    "port": 443,
    "base_url": "https://example.com/",
    "ip_addresses": []
  },
  "auth_profile": {
    "id": "public",
    "name": "Publico",
    "authenticated": false,
    "request_header_names": [],
    "cookie_names": [],
    "sensitive_values_redacted": true
  },
  "findings": [],
  "inventory": {
    "summary": {
      "total_urls": 1,
      "fetched_urls": 1,
      "interesting_urls": 0,
      "forms": 0
    },
    "urls": [
      {
        "url": "https://example.com/",
        "status_code": 200,
        "content_type": "text/html",
        "fetched": true,
        "forms_found": 0,
        "interesting": false
      }
    ],
    "forms": []
  },
  "entry_points": {
    "summary": {
      "total_endpoints": 1,
      "review_candidates": 1,
      "forms": 0,
      "parameters": 0
    },
    "endpoints": [
      {
        "url": "https://example.com/",
        "state": "fetched",
        "methods": ["GET"],
        "parameters": [],
        "forms": []
      }
    ]
  },
  "assessment": {
    "summary": {
      "risk_score": 0,
      "risk_level": "informational",
      "finding_count": 0,
      "priority_count": 0,
      "quick_win_count": 0
    },
    "priorities": [],
    "quick_wins": [],
    "remediation_plan": []
  },
  "rule_evaluation": {
    "engine": "passive-rules",
    "summary": {
      "rules_total": 15,
      "rules_matched": 0,
      "framework_controls_matched": 0,
      "findings_unmapped": 0
    },
    "matches": [],
    "framework_index": []
  }
}
```

## Aviso de uso

Ejecuta esta herramienta solo contra sistemas propios, laboratorios o objetivos
para los que tengas autorizacion explicita. La herramienta esta disenada para
empezar por pruebas seguras, pero el contexto legal y operativo depende del
objetivo analizado.
