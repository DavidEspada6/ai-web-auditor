# Changelog

Todas las versiones relevantes del proyecto se documentaran aqui.

## [0.8.0] - 2026-08-16

### Anade

- Historial local de auditorias en `audits/`.
- Opcion `scan --save-history` y etiqueta opcional `--history-label`.
- Comando `history` para listar o mostrar auditorias guardadas.
- Comando `compare` para comparar dos JSON o dos IDs del historial.
- Deteccion de hallazgos nuevos, resueltos, persistentes y cambios de severidad.
- Panel de historial en la interfaz local.
- Panel de comparacion en la interfaz local.
- Tests de historial, carga de auditorias y comparacion.

### Seguridad

- `audits/` queda ignorado por Git para evitar subir resultados sensibles.
- La comparacion solo procesa JSON existentes y no hace peticiones al objetivo.
- No se anaden explotacion, fuerza bruta, fuzzing agresivo ni pruebas intrusivas.

## [0.7.0] - 2026-08-16

### Anade

- Generacion de informes HTML autocontenidos con estilo profesional.
- Generacion de informes PDF locales sin dependencias externas.
- Metadatos de informe: cliente, auditor, proyecto, resumen de scope y notas.
- Inferencia de formato por extension de `--output` en el comando `report`.
- Opcion `--format markdown|html|pdf` para seleccionar formato explicitamente.
- Descarga de informes Markdown, HTML y PDF desde la interfaz local.
- Vista previa HTML del informe dentro de la GUI.
- Tests para HTML, PDF y metadatos del reporting.

### Seguridad

- HTML y PDF se generan desde resultados ya existentes; no se hacen nuevas peticiones al objetivo.
- El PDF se genera localmente con libreria estandar.
- No se anaden explotacion, fuerza bruta, fuzzing agresivo ni pruebas intrusivas.

## [0.6.0] - 2026-08-16

### Anade

- Comando `gui` para lanzar una interfaz web local.
- Servidor local basado en libreria estandar de Python, sin dependencias externas.
- Formulario visual para objetivo, scope, rutas, limites y modulos.
- Ejecucion de auditorias no intrusivas desde navegador.
- Vista de resumen, severidades, hallazgos, modulos y JSON.
- Generacion de informe Markdown desde la interfaz.
- Descarga de resultados JSON e informe Markdown.
- Boton PDF basado en la impresion del navegador.
- Tests de configuracion generada desde la interfaz.

### Seguridad

- La interfaz se sirve por defecto en `127.0.0.1`.
- El backend de la GUI reutiliza el mismo motor seguro de escaneo.
- No se anaden explotacion, fuerza bruta, fuzzing agresivo ni pruebas intrusivas.

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
