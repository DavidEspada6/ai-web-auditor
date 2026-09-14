# Guia operativa v0.26.0

Esta guia cubre la preparacion, ejecucion y revision de una enumeracion web con
AI Web Auditor. El manual Word detallado sigue previsto para v0.29.0.

## 1. Elegir el preajuste

Los preajustes cambian los modulos y limites. No cambian el objetivo, hosts,
rutas, permisos de red privada, perfil de autenticacion, credenciales, proyecto,
historial ni configuracion IA. La lista de puertos se conserva, pero el modulo
TCP se desactiva, igual que el descubrimiento DNS de subdominios.

| Preajuste | Modulos | Crawler | JavaScript | Uso |
| --- | --- | --- | --- | --- |
| Rapida (`quick`) | Scope, HTTP, Headers, Cookies, Basic Auth, Metodos y TLS | Desactivado | Desactivado | Revisar un punto de entrada |
| Estandar (`standard`) | Rapida + Fingerprinting, Crawler y JavaScript | 25 paginas, profundidad 1, pausa 0.2 s | 10 paginas, 25 scripts | Primera enumeracion acotada |
| Ampliada (`extended`) | Los mismos que Estandar | 100 paginas, profundidad 3, pausa 0.5 s | 30 paginas, 100 scripts | Ampliar una enumeracion inicial |

Todos conservan la verificacion TLS y la opcion HTTP paralelo que ya hayas
configurado. HTTP usa timeout de 10 s y hasta 10 redirecciones. Los preajustes
estandar y ampliado habilitan la lectura de metadatos y el seguimiento de
sitemaps; no habilitan visitas a rutas por aparecer en robots.txt.

Los limites se aplican por modulo. Veinticinco paginas de crawler **no significan
25 peticiones totales**: tambien pueden intervenir redirecciones, metadatos,
fingerprinting y descargas de JavaScript. La pausa del crawler no regula el
ritmo de todos los demas modulos.

En la UI, selecciona un valor en **Preajuste de auditoria**, dentro de Modulos.
Se aplica al seleccionarlo. Al editar modulos o limites, el selector pasa a
**Personalizada**. Elegir Personalizada no deshace un preajuste ni carga otros
valores. Para restaurar un preajuste, vuelve a seleccionarlo.

## 2. Primera prueba, solo en el laboratorio

1. Abre la interfaz con `start-ai-web-auditor.cmd` o `python -m ai_web_auditor gui`.
2. En Laboratorio pulsa **Iniciar**. Espera a ver **Conectado**. La URL mostrada
   indica el puerto real; puede cambiar si 8080 esta ocupado.
3. Pulsa **Usar demo**. Comprueba que el Objetivo empieza por `http://127.0.0.1:`.
4. Selecciona **Estandar** en Preajuste de auditoria.
5. Verifica Hosts autorizados = `127.0.0.1`, Rutas incluidas = `/`,
   Subdominios desmarcado, Laboratorio local marcado y Perfil activo = Publico.
6. Conserva las exclusiones que rellena Usar demo. Deja Guardar historial marcado
   y escribe `demo-v026-publico` en Etiqueta historial.
7. Deja Subdominios DNS y Puertos TCP desactivados para esta primera prueba.
8. Al final del formulario revisa **Proxima ejecucion**: debe indicar configuracion
   valida, 10 modulos, crawler hasta 25 paginas y 25 scripts.
9. Pulsa **Ejecutar auditoria** y espera a que termine.

La vista previa comprueba tipos, limites, URL, hosts y rutas sin hacer DNS ni
conexiones al objetivo. No comprueba que este encendido. La resolucion DNS y la
disponibilidad se comprueban al ejecutar; una previsualizacion valida no garantiza
que la auditoria vaya a completarse.

En este laboratorio HTTP es esperable ver Basic Auth sobre HTTP, cabeceras
defensivas ausentes, cookies sin algunos atributos y TRACE anunciado en OPTIONS.
Son datos de demostracion. El modulo TLS puede aparecer omitido porque el objetivo
del laboratorio es HTTP. La herramienta no envia TRACE para verificarlo.

## 3. Revisar los resultados

| Vista | Que revisar |
| --- | --- |
| Resumen | Objetivo, perfil, peticiones, inventario y resultado general |
| Dashboard | Cobertura, pendientes y checklist. La cobertura es un indicador interno, no un porcentaje de todas las vulnerabilidades posibles |
| Riesgo | Prioridades y evidencias que justifican cada recomendacion |
| Reglas | Reglas evaluadas y mapeos a controles; un mapeo no acredita cumplimiento completo de WSTG/ASVS |
| Hallazgos | URL, severidad, descripcion y evidencia; valida el contexto antes de reportar |
| Modulos | Diferencia entre pasado, advertencia, omitido y error |
| Inventario | URLs visitadas frente a descubiertas; estado, tipo y formularios. Filtra y arrastra el separador de columnas |
| Entradas | Parametros, formularios y metodos observados; inventariar un formulario no implica enviarlo |
| JavaScript | Scripts y endpoints citados. Encontrar una ruta en un script no confirma que sea accesible |
| Subdominios / Puertos | Resultados solo si habilitaste los modulos correspondientes |
| Visual | Resumenes SVG generados desde las evidencias; no son capturas renderizadas del sitio objetivo |
| JSON | Fuente estructurada del resultado. `execution` registra el alcance, perfil sin valores secretos, modulos y limites de esa ejecucion |

`completed` indica que no se aislaron errores de modulos; no significa que el
objetivo carezca de vulnerabilidades. Con `completed_with_errors`, revisa Modulos
y las peticiones fallidas antes de confiar en la cobertura. Un error de
configuracion impide iniciar la auditoria. Los resultados anteriores pueden
seguir visibles, pero el estado superior indica el error de la nueva ejecucion.

Las auditorias anteriores a v0.26 siguen siendo legibles y no se les inventa un
bloque `execution`. Los ejemplos historicos de `examples/` conservan la version
con la que fueron generados.

## 4. Historial y perfiles

1. Abre **Historial**, actualiza y carga la ejecucion `demo-v026-publico`.
2. Vuelve al formulario, selecciona **Usuario demo** y cambia la etiqueta a
   `demo-v026-usuario`. Mantiene la misma URL y limites.
3. Ejecuta de nuevo. La cabecera de laboratorio `X-Lab-Role: member` hace que el
   servidor local muestre la vista de usuario.
4. En **Comparar**, elige la ejecucion publica como base y la de usuario como
   actual. Ejecuta la comparacion y revisa URLs nuevas y cambios 401/200.
5. Antes de interpretar un hallazgo como corregido, comprueba que las dos
   ejecuciones usan alcance, perfil y limites comparables. Una ruta que deja de
   aparecer puede deberse a menor cobertura o a un cambio de permisos.

Los perfiles demo solo tienen sentido en el laboratorio. Para una sesion real,
usa Personalizado y credenciales validas obtenidas para el trabajo. La herramienta
reutiliza esas cabeceras/cookies; no automatiza el inicio de sesion ni su renovacion.
Una sesion caducada puede parecer una perdida de superficie. Un perfil no definido
en la configuracion se rechaza antes de comenzar.

## 5. Importaciones, IA e informes

En **Importar**, selecciona un archivo de `examples/import-*`. Conserva
**Unir con auditoria actual** para anadirlo al inventario abierto, o desmarcalo para
revisarlo por separado. Importar lee archivos y no ejecuta ZAP, Burp o Nmap.
Las fuentes importadas pueden describir objetivos diferentes: revisa su procedencia.

En **IA**, usa primero la opcion de simulacion (`dry-run`). Genera la entrada de
analisis sin llamar al proveedor. La conexion real requiere la clave API y la
configuracion del proveedor ya documentadas en README. Esta regresion no valida
un proveedor remoto ni genera consumo de API.

En **Informe**, rellena titulo, cliente, auditor, trabajo y alcance. Genera los
informes y revisa el contenido antes de descargar Markdown, HTML o PDF. El JSON,
inventario CSV, entradas CSV y ZIP de evidencias se descargan desde la cabecera.
El ZIP conserva `execution` dentro de `scan-result.json`, ademas del dashboard,
reglas y evidencias. Las credenciales no forman parte del plan; revisa igualmente
los datos del objetivo antes de compartir un entregable.

Crear un proyecto permite separar historial e informes. Los cambios temporales
del formulario se aplican a la siguiente ejecucion; no actualizan automaticamente
el archivo de configuracion del proyecto. `execution` permite consultar despues
con que ajustes se obtuvo cada resultado.

## 6. Consola y precedencia

```powershell
python -m ai_web_auditor presets
python -m ai_web_auditor presets --json
python -m ai_web_auditor init-scope https://example.test --preset standard --output audit.json
python -m ai_web_auditor scan --config audit.json --dry-run
```

`example.test` es un ejemplo de formato para la vista previa sin red. Para ejecutar,
usa el laboratorio o la URL autorizada de tu trabajo.

En `scan`, primero se carga `--config` (o el proyecto); despues se aplica
`--preset`, si lo indicas; por ultimo, los argumentos de objetivo, red privada y
autenticacion. El preset no se guarda en el archivo cargado. Si configuraste TCP
en el archivo, pasar `--preset standard` vuelve a desactivar ese modulo. Para
ejecutar exactamente tu configuracion personalizada, omite `--preset`.

`init-scope --preset` usa el preajuste como valores iniciales del cuestionario;
las respuestas posteriores prevalecen y el resultado se escribe en JSON.
`scan --dry-run` siempre imprime JSON y no escribe auditorias, historial ni
paquetes, aunque se le hayan pasado opciones de salida de un scan real.

Prueba reproducible por consola, en dos terminales:

```powershell
# Terminal 1: deja el laboratorio en ejecucion.
python -m ai_web_auditor lab --no-open

# Terminal 2: comprueba el puerto anunciado por el laboratorio.
python -m ai_web_auditor scan --config examples/lab-standard.json --dry-run
python -m ai_web_auditor scan --config examples/lab-standard.json --json-output outputs/demo-v026.json --save-history
python -m ai_web_auditor report outputs/demo-v026.json --output outputs/demo-v026.pdf
python -m ai_web_auditor evidence outputs/demo-v026.json --output outputs/demo-v026-evidence.zip
```

Si el puerto difiere de 8080, pasa como argumento la URL mostrada por el
laboratorio: `scan http://127.0.0.1:PUERTO/members/ --config examples/lab-standard.json`.

## 7. Problemas habituales

- **Timeout de puertos 0,5**: es valido. La UI usa pasos de 0.1 y el servidor
  admite coma o punto decimal. Si aparece el aviso antiguo, reinicia la UI y
  recarga con Ctrl+F5 para descartar el JavaScript/CSS anterior.
- **Configuracion invalida**: revisa el campo indicado. Las configuraciones JSON
  necesitan numeros reales, enteros donde corresponde y booleanos `true/false`,
  no cadenas como `"false"`. NaN e infinito no son limites validos.
- **Host/ruta fuera de alcance**: corrige URL o scope para que coincidan con lo
  autorizado. Desmarcar Scope no elimina la validacion obligatoria del motor.
- **Laboratorio desconectado**: pulsa Iniciar y vuelve a usar la URL actual.
- **Nada en Puertos o Subdominios**: los preajustes los desactivan. En el
  laboratorio puedes activar TCP y dejar solo el puerto mostrado por el servidor.
- **Menos resultados en Rapida**: es esperado, porque no recorre paginas ni JS.
- **No se reconoce el comando**: usa `python -m ai_web_auditor` tras instalar el
  paquete o el lanzador del README. Necesitas un Python funcional, no solo el
  alias de Microsoft Store.

## 8. Verificacion de la version

```powershell
python -m unittest discover -s tests
python -m compileall -q src tests
```

La regresion incluye un laboratorio temporal en loopback, ejecuciones publica y
autenticada, historial, comparacion, HTML/Markdown/PDF y ZIP. No depende de dominios
externos. La prueba de navegador necesita Node y Playwright como herramientas de
desarrollo, no como dependencias de la aplicacion:

```powershell
npm install --no-save --package-lock=false --prefix work/browser-deps playwright
$env:PLAYWRIGHT_MODULE = (Resolve-Path work/browser-deps/node_modules/playwright).Path
# Ruta a tu Python funcional; opcional si python ya funciona en PATH.
$env:PYTHON = (Get-Command python).Source
# Usa Chrome instalado, o instala Chromium de Playwright y omite CHROME_PATH.
$env:CHROME_PATH = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
node tests/browser_smoke.cjs
```

El test abre una UI y un laboratorio en puertos libres, con historial temporal,
comprueba los preajustes, vista previa, 18 vistas, columnas, historial y PDF,
y guarda capturas en `outputs/ui-v0.26.0`. Cierra sus procesos al terminar.

La v0.26 estabiliza la enumeracion implementada. No certifica cobertura exhaustiva,
no verifica explotabilidad y no reemplaza las comprobaciones manuales de logica de
negocio. Las siguientes etapas siguen siendo v0.27 (release funcional), v0.28
(rediseno UI) y v0.29 (manual Word).
