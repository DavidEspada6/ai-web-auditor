# AI Web Auditor

Herramienta modular de auditoria web asistida por IA.

Esta version esta pensada como base segura para practicas y auditorias con
autorizacion. Solo ejecuta comprobaciones no intrusivas: validacion de URL y
scope, HTTP/HTTPS y redirecciones, cabeceras de seguridad, cookies, HTTP Basic
Auth, metodos anunciados por OPTIONS, TLS basico y crawling seguro limitado por
scope. Tambien incluye fingerprinting web no intrusivo a partir de cabeceras,
cookies, HTML inicial y ficheros publicos habituales.

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

La v0.3 no necesita librerias externas en tiempo de ejecucion.

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
    "user_agent": "AI-Web-Auditor/0.3",
    "verify_tls": true,
    "check_http_counterpart": true
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

## Scope de auditoria

La v0.3 permite preparar una auditoria con preguntas:

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
- integracion con OpenAI para priorizacion y explicacion de hallazgos;
- generacion de informes en Markdown, HTML o PDF;
- base de datos local para comparar auditorias.

## Versionado

El proyecto usa Git. Flujo recomendado para cada version:

```powershell
git status
git add .
git commit -m "Describe el cambio"
git tag v0.3.1
git push
git push --tags
```

Antes de crear una nueva etiqueta conviene actualizar `pyproject.toml`,
`src/ai_web_auditor/__init__.py` y `CHANGELOG.md`.

## Ejemplo de salida JSON

```json
{
  "tool": "ai-web-auditor",
  "version": "0.3.0",
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
