# Changelog

Todas las versiones relevantes del proyecto se documentaran aqui.

## [0.26.0] - 2026-09-14

### Anade

- Preajustes `quick`, `standard` y `extended`, compartidos por CLI y GUI.
- Comando `presets` y opcion `--preset` en `scan` e `init-scope`.
- `scan --dry-run` y API `/api/config/preview` para validar sin DNS ni conexiones al objetivo.
- Selector de preajuste y resumen `Proxima ejecucion` con alcance, perfil, modulos y limites.
- Bloque `execution` en los resultados nuevos, conservado en JSON, historial y ZIP de evidencias.
- Guia operativa, configuracion reproducible para laboratorio y pruebas de regresion en navegador.

### Corrige

- Configuraciones con tipos incorrectos, numeros no finitos, limites negativos, puertos invalidos y perfiles inexistentes fallan antes de conectar.
- El servidor acepta `0,5` como timeout decimal y rechaza NaN, infinito y enteros fraccionarios.
- Se conserva el alcance y la autenticacion al aplicar un preajuste; DNS de subdominios y TCP quedan desactivados.
- Importar adapta sus controles al espacio disponible sin ensanchar la pagina.
- Ayudas contextuales y etiquetas del dashboard quedan dentro de sus contenedores.
- Cabecera movil compacta, sin cubrir el formulario al desplazarse.
- La comparacion anterior se limpia al ejecutar, cargar o importar otra auditoria.

### Verificacion

- 102 pruebas Python: configuracion, scope, HTTP/TLS, modulos, IA simulada, importadores, perfiles, historial, informes y evidencias.
- Recorrido automatizado de 18 vistas con laboratorio local, 3 preajustes, redimensionado de columnas, historial y descarga PDF.
- El rediseno visual completo y el manual Word siguen reservados para v0.28 y v0.29.

## [0.25.0] - 2026-09-12

### Anade

- Modulo `dashboard` para construir un panel operativo desde cualquier JSON de auditoria.
- Comando `dashboard` con salida de consola, JSON opcional, comparacion contra baseline y escritura a fichero.
- Bloque `dashboard` dentro del JSON principal de auditoria con cobertura, cambios, prioridades, pendientes y checklist.
- Pestana `Dashboard` en la interfaz grafica con estado de preparacion, riesgo, cobertura, cambios, pendientes y checklist agrupado.
- Inclusion de `dashboard/dashboard.json` dentro del paquete ZIP de evidencias.
- Seccion `Audit Dashboard` en informes Markdown, HTML y PDF.
- Ejemplo `examples/dashboard-example.json` para validar el formato sin tocar dominios reales.
- Tests de dashboard, CLI, informes, evidencias y UI.

### Cambia

- La salida de consola incluye un resumen operativo de dashboard al finalizar una auditoria.
- Los informes incorporan una vista de control previa a la valoracion detallada.
- El campo `Timeout puertos` de la UI acepta incrementos de `0.1`, por lo que el valor por defecto `0.5` ya es valido en navegadores configurados en espanol.

### Seguridad

- El dashboard se genera solo desde evidencias ya presentes; no realiza nuevas peticiones al objetivo.
- No se anaden explotacion, fuerza bruta, fuzzing, envio de formularios ni pruebas intrusivas.

## [0.24.0] - 2026-09-12

### Anade

- Bloque `visual_evidence` en el JSON de auditoria con fingerprint visual, grupos de UI y capturas SVG generadas localmente.
- Tres capturas SVG reproducibles: `audit-overview.svg`, `fingerprint-map.svg` y `coverage-matrix.svg`.
- Comando `visuals` para regenerar evidencias visuales desde cualquier JSON de auditoria y exportar los SVG a una carpeta.
- Pestana `Visual` en la interfaz grafica con resumen de riesgo, tecnologias, superficie y galeria de capturas.
- Inclusion de `visuals/visual-evidence.json` y los SVG dentro del paquete ZIP de evidencias.
- Seccion `Visual Evidence` en informes Markdown, HTML y PDF.
- Tests de generacion visual, exportacion CLI, paquete ZIP, informes y UI.

### Cambia

- La salida de consola indica cuantas capturas visuales SVG se generaron.
- Los informes HTML embeben visuales reconstruidos desde el JSON de auditoria para evitar confiar en SVGs importados desde fuentes externas.
- La navegacion agrupada incorpora la vista `Visual` dentro de la superficie de auditoria.

### Seguridad

- Las capturas visuales se generan solo desde evidencias pasivas ya recogidas.
- No se renderiza el objetivo en navegador, no se hace crawling extra, no se envian formularios y no se ejecutan endpoints descubiertos.
- La UI descarta SVGs con scripts, `foreignObject`, manejadores de eventos o URLs `javascript:` antes de pintarlos.

## [0.23.0] - 2026-09-02

### Anade

- Configuracion `auth` con perfiles anonimos o autenticados para ejecutar enumeraciones con cabeceras y cookies autorizadas.
- Soporte CLI para `--auth-profile`, `--auth-name`, `--auth-header` y `--auth-cookie` en el comando `scan`.
- Metadatos `auth_profile` en el JSON de auditoria, historial, consola e informes Markdown/HTML/PDF.
- Comando `role-compare` para comparar superficie visible entre dos perfiles o roles a partir de JSON/historial.
- Comparacion por perfil integrada en la vista `Comparar` de la UI.
- Controles de perfil en la UI: publico, usuario demo, admin demo y perfil personalizado.
- Laboratorio local ampliado con rutas visibles solo para perfil demo de usuario o administrador.
- Tests de perfiles autenticados, redaccion de secretos, laboratorio por rol, UI y comparacion por rol.

### Cambia

- El cliente HTTP aplica cabeceras/cookies de perfil desde un punto comun para que todos los modulos las hereden.
- El historial muestra el perfil usado en cada auditoria para evitar comparar ejecuciones equivocadas.
- Los informes incluyen una seccion `Audit Profile` con modo anonimo/autenticado y nombres de cabeceras/cookies usadas.

### Seguridad

- Los valores de `Authorization`, `Cookie` y cookies de sesion se redactan en evidencias, JSON e informes.
- Si un perfil solicitado no existe, no se usa otro perfil por defecto.
- No se anaden explotacion, fuerza bruta, fuzzing, envio de formularios ni validaciones intrusivas.
- Los perfiles autenticados estan pensados solo para sistemas propios, laboratorios u objetivos con autorizacion explicita.

## [0.22.0] - 2026-09-01

### Anade

- Modulo interno `importers` para normalizar resultados externos sin ejecutar herramientas contra el objetivo.
- Importacion de OWASP ZAP JSON, Burp Suite XML, Nmap XML, CSV, listas de URLs y JSON generico.
- Comando `import` para generar un JSON normalizado o enriquecer una auditoria existente con `--merge`.
- Vista `Importar` en la interfaz grafica con seleccion de formato, archivo local, objetivo opcional y merge con la auditoria abierta.
- Resumen de fuentes externas en JSON, consola, UI, informes Markdown/HTML/PDF y paquete ZIP de evidencias.
- Ejemplos en `examples/` para probar importaciones de ZAP, Nmap, CSV y listas de URLs sin tocar dominios reales.

### Cambia

- El inventario, los entry points, la valoracion de riesgo y el mapeo OWASP se recalculan tras importar resultados externos.
- Los hallazgos importados se deduplican y se mapean a IDs internos conocidos cuando coinciden con controles ya soportados.
- El paquete de evidencias incluye `external/external-sources.json` y `external/sources.json` cuando hay importaciones.

### Seguridad

- La importacion solo lee archivos existentes y no contacta el objetivo.
- No se anaden explotacion, fuzzing, fuerza bruta ni ejecucion automatica de ZAP, Burp, Nmap u otras herramientas.
- Las URLs y evidencias importadas se sanean para reducir exposicion de tokens, cookies o parametros sensibles.
- Los hallazgos externos quedan marcados como evidencia pendiente de validacion manual.

## [0.21.0] - 2026-08-30

### Anade

- Motor `passive-rules` para mapear evidencias ya observadas contra controles OWASP WSTG y OWASP ASVS.
- Catalogo inicial de reglas para transporte seguro, HSTS, TLS, cookies, cabeceras de navegador, metodos HTTP, fingerprinting, metadatos publicos, entry points, JavaScript, autenticacion, rutas administrativas, uploads, DNS/puertos y referencias fuera de scope.
- Bloque `rule_evaluation` dentro del JSON de auditoria con resumen, reglas activadas, controles relacionados, hallazgos sin mapeo y notas de seguridad.
- Comando `rules` para recalcular el mapeo OWASP desde cualquier JSON de auditoria.
- Pestana `Reglas` en la interfaz grafica con resumen, tabla redimensionable y trazabilidad OWASP.
- Archivos `rules/rule-evaluation.json` y `rules/matches.json` dentro del paquete ZIP de evidencias.
- Seccion `Passive Rule Mapping` en informes Markdown, HTML y PDF.

### Cambia

- La valoracion determinista de riesgo incluye contadores de reglas pasivas, controles OWASP y hallazgos sin mapeo.
- El resumen principal de la GUI muestra reglas activadas y controles OWASP relacionados.
- Los ejemplos generados incluyen salida de reglas para la demo local.

### Seguridad

- No se anaden explotacion, fuzzing, fuerza bruta ni pruebas intrusivas.
- El motor de reglas trabaja solo con evidencias ya recogidas por modulos pasivos.
- Una regla activada se presenta como guia de revision, no como prueba de explotabilidad.
- Las referencias fuera de scope se registran para clasificacion manual, pero no se escanean automaticamente.

## [0.20.0] - 2026-08-27

### Anade

- Modulo `javascript` para analisis pasivo de HTML, scripts externos en scope y bloques inline.
- Extraccion de referencias a endpoints desde strings JavaScript: URLs absolutas, rutas relativas, APIs, login, auth, callbacks, uploads, health y patrones similares.
- Inferencia basica de metodos desde contexto cercano como `fetch()`, `method: "POST"` y llamadas tipo `axios.post()`.
- Deteccion de parametros de query y nombres sensibles como `token`, `session`, `csrf`, `password`, `secret` o `key`, con valores saneados.
- Pestana `JavaScript` en la interfaz grafica con resumen, filtro y tabla redimensionable.
- Integracion de endpoints JS en `inventory`, `entry_points`, valoracion de riesgo, informes Markdown/HTML/PDF y ZIP de evidencias.
- Laboratorio local ampliado con `/static/app.js` y scripts inline para probar endpoints JS sin tocar dominios reales.
- Tests dedicados para el modulo JS y cobertura adicional en CLI, GUI, inventario, entry points, reporting, evidencias y laboratorio.

### Cambia

- El resumen principal y la vista `Riesgo` muestran cobertura de endpoints JavaScript.
- `init-scope` pregunta por limites de analisis JavaScript.
- El paquete de evidencias incluye `javascript/javascript.json` y `javascript/endpoints.json`.

### Seguridad

- No se anaden explotacion, fuzzing, fuerza bruta ni envio de formularios.
- El modulo JavaScript no ejecuta los endpoints descubiertos.
- Los scripts externos solo se descargan si estan dentro del scope autorizado.
- Las referencias fuera de scope o excluidas se registran como evidencia, pero no se solicitan.

## [0.19.0] - 2026-08-27

### Anade

- Modelo `entry_points` dentro del JSON de auditoria con endpoints, parametros, formularios y metodos observados.
- Comando `entrypoints` para exportar puntos de entrada a JSON o CSV.
- Resumen de puntos de entrada en consola y en la valoracion determinista de riesgo.
- Pestana `Entradas` en la interfaz grafica con filtro, resumen y tabla redimensionable.
- Boton `Entradas CSV` en la interfaz.
- Seccion `Entry Points` en informes Markdown y HTML.
- Inclusión de `entry-points/entry-points.json` en paquetes de evidencias.
- Tests dedicados para extractor, CLI, reporting, evidencias, GUI y crawler local.

### Cambia

- El resumen principal de la GUI muestra tambien endpoints y parametros detectados.
- La vista `Riesgo` incluye cobertura de entry points y parametros.
- Los informes diferencian inventario web general de puntos de entrada revisables.

### Seguridad

- No se anaden ataques, fuzzing, fuerza bruta ni envio de formularios.
- Los puntos de entrada se derivan solo de evidencias pasivas ya observadas.
- Los parametros con nombres sensibles se marcan para revision, pero no se exponen valores secretos.

## [0.18.0] - 2026-08-27

### Anade

- Crawler avanzado con lectura segura de `robots.txt`, `sitemap.xml` y endpoints `.well-known`.
- Descubrimiento de URLs desde metadatos publicos con origen trazable (`robots`, `sitemap`, `well_known`, etc.).
- Clasificador de rutas para identificar superficies relevantes como login, admin, API, recovery, callbacks, uploads, health, debug y ficheros sensibles.
- Artefactos `metadata_discovered_urls`, `url_sources`, `route_classifications` y `metadata` dentro del modulo `crawler`.
- Nuevas opciones de configuracion `crawler.use_robots_txt`, `use_sitemap_xml`, `use_well_known`, `follow_sitemap_urls`, `follow_robots_paths` y `metadata_max_urls`.
- Controles de crawler avanzado en la interfaz grafica local.
- Inventario enriquecido con `route_types` y `route_classifications`, tambien en CSV.
- Secciones de metadatos y rutas interesantes en informes Markdown y HTML.
- Laboratorio local ampliado con `security.txt`, OpenID metadata, rutas de login, recovery y API para demo controlada.
- Tests locales para validar crawler de metadatos sin tocar dominios reales.

### Cambia

- El resumen del crawler indica cuantas URLs vienen de metadatos publicos.
- El inventario muestra tipos de ruta junto a los motivos de interes.
- `init-scope` pregunta tambien por las opciones nuevas del crawler.

### Seguridad

- No se anaden pruebas ofensivas ni intrusivas.
- El crawler no envia formularios, no fuerza credenciales y no sigue rutas fuera de scope.
- Las rutas de `robots.txt` se registran por defecto pero no se visitan salvo configuracion explicita.
- Las URLs de sitemap solo se visitan si estan dentro del scope y respetan extensiones ignoradas.

## [0.17.0] - 2026-08-27

### Anade

- Captura segura de evidencias HTTP por peticion: metodo, URL saneada, estado, tiempos, cabeceras y muestra truncada del cuerpo.
- Configuracion `evidence` para activar captura, cabeceras y muestras de respuesta con limite de caracteres.
- Redaccion de cabeceras sensibles, cookies, tokens, secretos y parametros de query sensibles.
- Comando `evidence` para generar un ZIP saneado desde un JSON de auditoria.
- Opcion `scan --evidence-output` para generar el paquete de evidencias durante la auditoria.
- Boton `Evidencias ZIP` en la interfaz grafica.
- `ROADMAP.md` con la secuencia cerrada hasta `v0.25.0`.
- Tests dedicados para redaccion, ZIP de evidencias, CLI y descarga en GUI.

### Cambia

- El JSON de auditoria incluye registros HTTP enriquecidos con `id`, cabeceras saneadas y muestras de respuesta cuando aplica.
- El saneado se aplica tambien a URLs y evidencias textuales antes de serializar resultados.
- La roadmap pasa a estar versionada en el repositorio para mantener foco de producto.

### Seguridad

- No se anaden pruebas ofensivas ni intrusivas.
- No se guardan cuerpos de request.
- Los cuerpos de respuesta se guardan solo como muestras de texto truncadas.
- Valores de `Authorization`, `Cookie`, `Set-Cookie`, tokens, passwords, secrets y parametros sensibles se redactan.

## [0.16.0] - 2026-08-27

### Anade

- Ayuda contextual en la interfaz para opciones de scope, modulos y limites.
- Tooltips con retardo al pasar el raton sobre cada opcion configurable.
- Indicador visual discreto de ayuda en controles con informacion adicional.
- Navegacion lateral agrupada por `Auditar`, `Superficie`, `Entregables` y `Auditorias recientes`.
- Columnas redimensionables en tablas de modulos, inventario, subdominios, puertos e historial.
- Tests para comprobar que los modulos de la GUI mantienen textos de ayuda.

### Cambia

- La barra de pestanas se reorganiza para evitar desplazamiento horizontal de la pagina.
- Las tablas anchas se desplazan dentro de su propio contenedor en vez de romper el layout general.
- Los controles de navegacion usan dimensiones estables y uniformes.
- La zona principal deja de estirar filas automaticamente segun la altura del panel lateral.
- Las tarjetas de severidad conservan una altura fija para evitar saltos visuales entre pestanas.
- La roadmap mueve el paquete de evidencias a la siguiente version para priorizar usabilidad.

### Seguridad

- No se anaden nuevas peticiones ni pruebas contra objetivos.
- Los cambios son solo de interfaz, documentacion y versionado.

## [0.15.0] - 2026-08-16

### Anade

- Valoracion determinista de riesgo en el bloque `assessment` de cada JSON de auditoria.
- Puntuacion de 0 a 100, nivel de riesgo, prioridades, quick wins y plan de remediacion por fases.
- Comando `assess` para recalcular la valoracion desde un JSON ya existente.
- Resumen de riesgo en la salida por consola.
- Seccion `Risk Assessment` en informes Markdown, HTML y PDF.
- Pestana `Riesgo` en la interfaz grafica local.
- Enriquecimiento de auditorias antiguas al abrirlas desde historial, sin repetir escaneos.
- Tests dedicados para assessment, CLI, laboratorio y reporting.

### Seguridad

- No se anaden nuevas peticiones ni pruebas contra el objetivo.
- La valoracion se calcula solo con evidencias ya recogidas por modulos no intrusivos.
- La IA sigue siendo opcional y no sustituye la priorizacion determinista del JSON.

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
