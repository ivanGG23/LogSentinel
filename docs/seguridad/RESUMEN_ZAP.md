# Escaneo OWASP ZAP contra la API de LogSentinel (https://localhost:8444)

Herramienta: zap-api-scan.py (imagen ghcr.io/zaproxy/zaproxy:stable), modo OpenAPI.
Fecha: 2026-11-22. Escaneo sin autenticación.

| Escaneo | FAIL | WARN | PASS | Reportes |
|---|---|---|---|---|
| Antes | 0 | 2 | 118 | zap_api_antes.* |
| Intermedio | 0 | 1 | 119 | zap_api_despues.* |
| Final | 0 | 0 | 120 | zap_api_final.* |

## Hallazgos y correcciones (proxy nginx, proxy/default.conf)
1. Strict-Transport-Security ausente [10035]: se agregó `Strict-Transport-Security: max-age=86400`
   (en producción se recomienda un valor mayor; el navegador lo ignora con certificado autofirmado).
2. Cross-Origin-Resource-Policy ausente [90004]: se agregó `same-site`; ZAP lo marcó como menos seguro
   y se cambió a `same-origin` (no afecta al dashboard, que usa fetch con CORS).
3. Mejora adicional: `Cache-Control: no-store` en la API para que proxies no cacheen respuestas.

## Observaciones
- Durante el escaneo el rate limiting respondió 429 a las rutas probadas: evidencia de que funciona.
- Los endpoints /alerts y /events respondieron 401 sin credenciales, por lo que la lógica interna
  de los endpoints protegidos no fue ejercitada. Limitación: escaneo no autenticado.
- Alertas informativas restantes en intermedio (códigos 404/429/401, no-storable) no son vulnerabilidades.
