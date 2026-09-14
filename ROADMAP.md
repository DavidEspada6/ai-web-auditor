# Roadmap

Este roadmap queda fijado como guia del proyecto. Hasta completar esta secuencia,
no se priorizaran funcionalidades fuera de estos bloques.

## Secuencia acordada

- `v0.17.0`: paquete de evidencias descargable por auditoria.
- `v0.18.0`: crawler avanzado con `robots.txt`, `sitemap.xml`, `.well-known` y clasificacion de rutas.
- `v0.19.0`: modelo de entry points: endpoints, parametros, formularios y metodos.
- `v0.20.0`: analisis de JavaScript y descubrimiento de endpoints.
- `v0.21.0`: motor pasivo de reglas con mapeo OWASP WSTG/ASVS.
- `v0.22.0`: importadores/adaptadores para herramientas externas. Completada.
- `v0.23.0`: perfiles autenticados y comparacion por roles. Completada en esta version.
- `v0.24.0`: screenshots, fingerprint visual y agrupacion de pantallas. Completada en esta version.
- `v0.25.0`: dashboard de auditoria real: cobertura, cambios, riesgos, pendientes y checklist. Completada en esta version.
- `v0.26.0`: estabilizacion de primera version completa: presets de auditoria, revision de UX, documentacion operativa y regresion completa. Completada.
- `v0.27.0`: preparacion de release funcional: empaquetado, instalador/lanzador pulido, ejemplos reproducibles y guia de uso en auditoria real.
- `v0.28.0`: rediseno visual completo de la UI: tema oscuro negro/verde, navegacion lateral profesional, menus por flujo de trabajo, estados visuales mas claros y menos saturacion de botones.
- `v0.29.0`: documentacion Word completa de uso: guia paso a paso, descripcion de cada menu/boton/modulo, que hace por detras, opciones disponibles, ejemplos de auditoria, informes y flujo de entrega.

## Criterio de producto

La herramienta debe ser util al comenzar una enumeracion web real porque centraliza
alcance, inventario, evidencias, priorizacion y trazabilidad. La IA puede ayudar
a analizar y redactar, pero la fuente de verdad debe seguir siendo el JSON
estructurado y las evidencias generadas por la aplicacion.
