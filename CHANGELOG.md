# Changelog

Todas las versiones relevantes del proyecto se documentaran aqui.

## [0.5.0] - 2026-08-16

### Anade

- Comando `report` para generar informes Markdown desde resultados JSON.
- Soporte opcional de `--ai-analysis` para incorporar el analisis IA al informe.
- Secciones de objetivo, resumen ejecutivo, severidades, modulos, hallazgos, tecnologias, crawler, notas IA y limitaciones.
- Escritura de informe con `--output` o salida directa por consola.
- Ejemplo `examples/report-example.md`.
- Tests del generador Markdown y del comando `report`.

### Seguridad

- El reporting no ejecuta peticiones de red ni acciones sobre objetivos.
- El informe refleja solo evidencias existentes en el JSON de escaneo y, si se aporta, el analisis IA ya generado.

## [0.4.0] - 2026-08-16

### Anade

- Comando `analyze` para analizar resultados JSON con IA.
- Proveedor `openai` usando la Responses API mediante HTTP estandar, sin dependencias externas.
- Configuracion `ai` para proveedor, modelo, endpoint, variable de API key, timeout, idioma y limite de entrada.
- Modo `--dry-run` para construir y revisar el prompt sin llamar a la API.
- Salida de analisis en consola, JSON y Markdown.
- Redaccion basica de claves, cookies, tokens, passwords, secrets y parametros sensibles en URLs antes de enviar el JSON a IA.
- Tests para redaccion, analisis con proveedor falso y CLI dry-run.

### Seguridad

- La IA no ejecuta acciones ni decide nuevos escaneos.
- El prompt obliga a no proponer explotacion, fuerza bruta, bypasses ni pruebas intrusivas.
- El parametro `store` se configura como `false` por defecto en la llamada a OpenAI.

## [0.3.0] - 2026-08-16

### Anade

- Modulo `fingerprinting` no intrusivo.
- Deteccion de tecnologias por cabeceras HTTP, cookies y HTML inicial.
- Deteccion basica de servidor, CDN, hosting, lenguaje, framework y CMS.
- Revision segura de `robots.txt`, `/.well-known/security.txt`, `/security.txt` y `sitemap.xml` si estan dentro del scope.
- Hallazgos informativos para cabeceras o metadata que revelan versiones o tecnologias.
- Tests locales para fingerprinting sin depender de Internet.

### Seguridad

- El fingerprinting solo realiza peticiones GET a rutas publicas configuradas.
- Las rutas publicas se omiten si quedan fuera del scope o estan excluidas.

## [0.2.0] - 2026-08-15

### Anade

- Comando `init-scope` para generar configuraciones de auditoria con preguntas guiadas.
- Soporte de `target.url` en configuracion para ejecutar `scan --config audit.json`.
- Reglas de scope por rutas incluidas y excluidas.
- Modulo `crawler` seguro con profundidad maxima, limite de paginas, retraso opcional y limite de cuerpo HTML.
- Descubrimiento de URLs internas y registro de enlaces externos sin visitarlos.
- Lanzador Windows `ai-web-auditor.cmd` para ejecutar la herramienta sin instalar el comando global.
- Tests de crawler local y redirecciones fuera de scope.

### Seguridad

- El crawler no envia formularios.
- El crawler no sigue enlaces fuera del scope.
- El host inicial se fija como scope por defecto si no se configuran hosts explicitos.

## [0.1.0] - 2026-08-15

### Anade

- Base modular en Python para auditoria web segura.
- CLI con salida en consola y JSON.
- Configuracion mediante JSON o TOML.
- Modelo de resultados con modulos, hallazgos, evidencias y peticiones.
- Validacion de URL y scope.
- Comprobaciones HTTP/HTTPS y redirecciones dentro de scope.
- Revision de cabeceras de seguridad.
- Revision basica de cookies.
- Deteccion de HTTP Basic Auth.
- Revision de metodos HTTP anunciados por OPTIONS.
- Revision TLS basica.
- Tests unitarios y de integracion local.

### Seguridad

- No incluye explotacion, fuerza bruta, fuzzing agresivo ni pruebas intrusivas.
- Las redirecciones fuera de scope se registran pero no se siguen.
