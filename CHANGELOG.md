# Changelog

Todas las versiones relevantes del proyecto se documentaran aqui.

## [0.14.0] - 2026-08-16

### Anade

- Modulo `ports` para comprobacion TCP limitada de puertos del host objetivo.
- Configuracion `ports.ports`, `ports.max_ports` y `ports.timeout_seconds`.
- El modulo queda desactivado por defecto y debe activarse explicitamente, salvo en la demo local.
- Estados `open`, `closed`, `filtered` y `error` para cada puerto comprobado.
- Hallazgo informativo cuando se detectan puertos TCP abiertos.
- Panel `Puertos` en la interfaz grafica con resumen y tabla.
- Controles de lista de puertos, limite y timeout desde la interfaz.
- Seccion `TCP Port Check` en informes Markdown, HTML y PDF.
- Defaults del laboratorio para comprobar `127.0.0.1` de forma controlada.
- Tests del modulo de puertos, configuracion GUI y reporting.

### Seguridad

- Solo se realizan conexiones TCP basicas; no se envian payloads ni se solicitan banners.
- No se escanean subdominios automaticamente.
- El limite y timeout reducen el riesgo de escaneos amplios o lentos.

## [0.13.0] - 2026-08-16

### Anade

- Modulo `subdomains` para descubrimiento DNS seguro de subdominios candidatos.
- Configuracion `subdomains.candidates` y `subdomains.max_candidates`.
- El modulo queda desactivado por defecto y debe activarse explicitamente.
- Respeto estricto de `allowed_hosts`, `allow_subdomains` y `resolve_dns`.
- Hallazgo informativo cuando se resuelven subdominios dentro de scope.
- Artefactos con hosts resueltos, IPs, candidatos sin resolver y candidatos fuera de scope.
- Panel `Subdominios` en la interfaz grafica con resumen y tabla.
- Control de limite de candidatos desde la interfaz.
- Seccion `Subdomain Discovery` en informes Markdown, HTML y PDF.
- Tests del modulo DNS, configuracion GUI y reporting.

### Seguridad

- Los subdominios resueltos no se escanean automaticamente.
- Los candidatos fuera de scope se registran pero no se resuelven ni se auditan.
- No se anade crawling masivo, fuerza bruta DNS agresiva ni ataques intrusivos.

## [0.12.0] - 2026-08-16

### Anade

- Inventario web normalizado dentro del JSON de auditoria.
- Listado de URLs descubiertas, visitadas, excluidas y fuera de scope.
- Estado HTTP, tipo de contenido, profundidad, metodos observados, titulo y origen de cada URL.
- Deteccion pasiva de formularios HTML sin enviar datos.
- Marcado de rutas interesantes como `/login`, `/admin`, `/members`, `/api`, `/private` y ficheros sensibles habituales.
- Comando `inventory` para exportar el inventario a JSON o CSV.
- Pestana `Inventario` en la interfaz grafica con filtro por URL, estado, tipo, fuente o interes.
- Boton `Inventario CSV` en la interfaz.
- Seccion `Web Inventory` en informes Markdown, HTML y PDF.
- Formulario de login controlado en el laboratorio local para probar la deteccion.
- Tests del generador de inventario, CLI y laboratorio.

### Seguridad

- La deteccion de formularios es solo pasiva: no rellena, envia ni prueba credenciales.
- Las URLs fuera de scope o excluidas se registran como evidencia, pero no se visitan.
- No se anaden explotacion, fuerza bruta, fuzzing ni ataques intrusivos.

## [0.11.0] - 2026-08-16

### Anade

- Laboratorio vulnerable local para demos y pruebas sin auditar dominios reales.
- Comando `lab` para arrancar el laboratorio en `127.0.0.1`.
- Rutas de laboratorio con HTTP sin TLS, Basic Auth, cookies inseguras, cabeceras ausentes, metadatos expuestos, `robots.txt` y `sitemap.xml`.
- Endpoints GUI `/api/lab/status`, `/api/lab/start` y `/api/lab/stop`.
- Panel de laboratorio en la interfaz con estado `Conectado` / `Desconectado`.
- Botones para iniciar, detener y rellenar el formulario con la demo local.
- Defaults seguros para escanear `http://127.0.0.1:8080/members/` con scope local, DNS desactivado y TLS desactivado.
- Tests del laboratorio y de deteccion de hallazgos controlados.

### Seguridad

- El laboratorio solo permite bind en localhost o direcciones loopback.
- No se anaden ataques contra terceros ni explotacion destructiva.
- La demo genera evidencias controladas dentro de la maquina local.

## [0.10.0] - 2026-08-16

### Anade

- Gestion local de proyectos en `projects/`.
- Archivo `project.json` con cliente, auditor, trabajo, scope resumido y rutas del proyecto.
- Archivo `scope.json` por proyecto para mantener una configuracion de auditoria reutilizable.
- Carpetas separadas por proyecto para `audits/`, `reports/` y `ai/`.
- Comandos `project init`, `project list` y `project show`.
- Opcion `--project` en `scan`, `history`, `compare` y `report`.
- Selector y creacion rapida de proyectos desde la interfaz grafica.
- Historial filtrado por proyecto en la GUI.
- Metadatos de informe rellenados desde el proyecto cuando estan disponibles.
- Lanzador `start-ai-web-auditor.cmd` para abrir la interfaz con doble clic en Windows.
- Tests de creacion, listado, carga y CLI de proyectos.

### Seguridad

- `projects/` queda ignorado por Git para evitar subir informacion de clientes o auditorias.
- Los proyectos solo organizan configuracion, historial e informes; no anaden acciones intrusivas.
- El lanzador grafico reutiliza el mismo servidor local en `127.0.0.1` por defecto.

## [0.9.0] - 2026-08-16

### Anade

- Analisis IA directamente desde la interfaz grafica local.
- Endpoint local `/api/analyze` para analizar resultados ya generados sin ejecutar nuevos escaneos.
- Panel `IA` en la GUI con proveedor, modelo, idioma, limite de prompt, dry-run y guardado en historial.
- Descarga independiente del resultado `AI JSON`.
- Guardado opcional de `ai_analysis` dentro de auditorias del historial.
- Deteccion de auditorias con analisis IA en el panel de historial.
- Incorporacion automatica del analisis IA embebido en informes Markdown, HTML y PDF.
- Tests para analisis desde datos en memoria, guardado de analisis IA en historial y reporting con IA embebida.

### Seguridad

- El modo dry-run queda activado por defecto en la GUI.
- La API key se sigue leyendo solo desde variable de entorno y no se guarda en historial ni configuracion generada.
- Se mantiene la redaccion previa de tokens, cookies, passwords, secrets y parametros sensibles antes de enviar datos a IA.
- La IA no ejecuta pruebas, no cambia el scope y no realiza acciones contra el objetivo.

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
