# AI Web Auditor

Herramienta modular de auditoria web asistida por IA.

Esta version esta pensada como base segura para practicas y auditorias con
autorizacion. Solo ejecuta comprobaciones no intrusivas: validacion de URL y
scope, HTTP/HTTPS y redirecciones, cabeceras de seguridad, cookies, HTTP Basic
Auth, metodos anunciados por OPTIONS, TLS basico y crawling seguro limitado por
scope. Tambien incluye fingerprinting web no intrusivo a partir de cabeceras,
cookies, HTML inicial y ficheros publicos habituales, analisis IA opcional,
informes Markdown a partir del JSON de escaneo e interfaz web local.

No implementa explotacion, fuerza bruta, fuzzing agresivo, crawling masivo,
escaneo de puertos ni pruebas intrusivas.

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

La v0.6 no necesita librerias externas en tiempo de ejecucion.

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
.\ai-web-auditor.cmd report outputs/result.json --output outputs/report.md
.\ai-web-auditor.cmd gui
```

Abrir la interfaz grafica local:

```powershell
ai-web-auditor gui
```

Por defecto se sirve en:

```text
http://127.0.0.1:8765/
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
    "user_agent": "AI-Web-Auditor/0.6",
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
  "modules": {
    "scope": true,
    "http": true,
    "security_headers": true,
    "cookies": true,
    "basic_auth": true,
    "http_methods": true,
    "tls": true,
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

## Reporting

La herramienta genera informes Markdown desde el JSON de escaneo. Este paso no
contacta con el objetivo ni ejecuta nuevas comprobaciones:

```powershell
ai-web-auditor report outputs/result.json --output outputs/report.md
```

Si ya existe un analisis IA guardado en JSON, se puede incorporar al informe:

```powershell
ai-web-auditor report outputs/result.json --ai-analysis outputs/analysis.json --output outputs/report.md
```

El informe incluye:

- objetivo y estado del escaneo;
- resumen ejecutivo;
- resumen por severidad;
- resumen por modulo;
- hallazgos y evidencias;
- fingerprinting y crawler si estan presentes;
- priorizacion IA si se aporta;
- limitaciones de la auditoria.

## Interfaz grafica local

La v0.6 anade una interfaz web local servida desde Python:

```powershell
ai-web-auditor gui
```

Tambien puedes evitar que abra el navegador automaticamente:

```powershell
ai-web-auditor gui --no-open
```

Desde la interfaz se puede:

- configurar objetivo, hosts, rutas y limites principales;
- activar o desactivar modulos;
- ejecutar una auditoria no intrusiva;
- revisar hallazgos, modulos, resumen y JSON;
- generar informe Markdown;
- descargar JSON y Markdown;
- abrir la impresion del navegador para guardar el informe como PDF.

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
- limites del crawler.

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
- informes HTML/PDF nativos con plantillas;
- base de datos local para comparar auditorias.

## Versionado

El proyecto usa Git. Flujo recomendado para cada version:

```powershell
git status
git add .
git commit -m "Describe el cambio"
git tag v0.6.1
git push
git push --tags
```

Antes de crear una nueva etiqueta conviene actualizar `pyproject.toml`,
`src/ai_web_auditor/__init__.py` y `CHANGELOG.md`.

## Ejemplo de salida JSON

```json
{
  "tool": "ai-web-auditor",
  "version": "0.6.0",
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
  "findings": []
}
```

## Aviso de uso

Ejecuta esta herramienta solo contra sistemas propios, laboratorios o objetivos
para los que tengas autorizacion explicita. La herramienta esta disenada para
empezar por pruebas seguras, pero el contexto legal y operativo depende del
objetivo analizado.
