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
laboratorio vulnerable local y comparacion de auditorias.

No implementa explotacion, fuerza bruta, fuzzing agresivo, crawling masivo,
escaneo de puertos, fuerza bruta DNS agresiva ni pruebas intrusivas.

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

La v0.13 no necesita librerias externas en tiempo de ejecucion.

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
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.md
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.html
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.pdf
.\ai-web-auditor.cmd history
.\ai-web-auditor.cmd compare baseline.json current.json
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

Guardar JSON:

```powershell
ai-web-auditor scan https://example.com --json-output outputs/example.json
```

Exportar inventario de URLs a CSV:

```powershell
ai-web-auditor inventory outputs/example.json --output outputs/inventory.csv
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
    "user_agent": "AI-Web-Auditor/0.13",
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
    "include_query_strings": false
  },
  "subdomains": {
    "candidates": ["www", "app", "api", "portal", "admin"],
    "max_candidates": 25,
    "timeout_seconds": 2.0
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
    "fingerprinting": true,
    "crawler": true
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
- `fingerprinting`: identifica senales de servidor, CDN, framework, lenguaje,
  CMS y ficheros publicos como `robots.txt`, `security.txt` y `sitemap.xml`.
- `crawler`: recorre enlaces internos sin enviar formularios, sin salir del
  scope, con profundidad y numero de paginas limitados.

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
- resumen por modulo;
- hallazgos y evidencias;
- fingerprinting y crawler si estan presentes;
- inventario web con URLs, estados, tipos de contenido y formularios detectados;
- descubrimiento de subdominios si se activa;
- priorizacion IA si se aporta;
- limitaciones de la auditoria.

Hay ejemplos en `examples/report-example.md` y `examples/report-example.html`.

## Laboratorio local

La v0.13 incluye un laboratorio vulnerable solo para pruebas locales. Sirve una
web de demo en `127.0.0.1` con problemas controlados:

- HTTP sin TLS;
- Basic Auth sobre HTTP en `/members/`;
- cookies sin `HttpOnly`, `Secure` o `SameSite` adecuado;
- cabeceras de seguridad ausentes;
- metadatos de tecnologia expuestos;
- metodos HTTP de riesgo anunciados por `OPTIONS`;
- `robots.txt` y `sitemap.xml` de ejemplo.
- formulario HTML de login detectado de forma pasiva, sin envio de datos.

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

## Inventario web

Cada escaneo nuevo incluye un bloque `inventory` dentro del JSON. Este bloque
resume:

- URLs visitadas por el crawler;
- URLs descubiertas pero no visitadas;
- URLs excluidas por scope;
- URLs externas registradas sin solicitarlas;
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

## Descubrimiento de subdominios

La v0.13 anade un modulo DNS seguro para descubrir subdominios candidatos. Esta
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

Hay un ejemplo de salida en `examples/comparison-example.json`.

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
- activar o desactivar modulos;
- ejecutar una auditoria no intrusiva;
- revisar resumen, hallazgos, modulos, inventario, subdominios y JSON;
- analizar la auditoria con IA en modo dry-run o con API;
- guardar el analisis IA en el historial local;
- guardar y abrir auditorias del historial local o del proyecto activo;
- comparar dos auditorias guardadas;
- generar informes Markdown, HTML y PDF;
- descargar JSON, Inventario CSV, AI JSON, Markdown, HTML y PDF;
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
- limites del crawler;
- limite de candidatos para descubrimiento de subdominios.

Despues se puede repetir la auditoria de forma consistente:

```powershell
ai-web-auditor scan --config audit.json --json-output outputs/result.json
```

## Estructura para ampliar

La carpeta `src/ai_web_auditor/modules` contiene modulos independientes. Para
anadir uno nuevo:

1. Crear una clase con atributo `name`.
2. Implementar `run(context) -> ModuleResult`.
3. Registrarla en `engine.py`.
4. Anadir el interruptor correspondiente en `config.py`.

Los siguientes pasos naturales son:

- descubrimiento de subdominios;
- escaneo de puertos con limites claros;
- mejoras en la integracion con IA para comparar hallazgos entre auditorias;
- modulos de verificacion controlada para confirmar hallazgos sin explotacion destructiva;
- base de datos local opcional para proyectos grandes;
- empaquetado como aplicacion de escritorio cuando la GUI este mas estable.

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
git tag v0.13.0
git push
git push --tags
```

Antes de crear una nueva etiqueta conviene actualizar `pyproject.toml`,
`src/ai_web_auditor/__init__.py` y `CHANGELOG.md`.

## Ejemplo de salida JSON

```json
{
  "tool": "ai-web-auditor",
  "version": "0.13.0",
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
  }
}
```

## Aviso de uso

Ejecuta esta herramienta solo contra sistemas propios, laboratorios o objetivos
para los que tengas autorizacion explicita. La herramienta esta disenada para
empezar por pruebas seguras, pero el contexto legal y operativo depende del
objetivo analizado.
