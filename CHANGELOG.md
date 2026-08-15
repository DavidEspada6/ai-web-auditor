# Changelog

Todas las versiones relevantes del proyecto se documentaran aqui.

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
