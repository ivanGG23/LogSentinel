# LogSentinel

SIEM ligero para el curso de Seguridad Informática. Recolecta, normaliza y correlaciona eventos de
SSH (`auth.log`), logins de una aplicación web y Nginx (`access.log`), y muestra las alertas en un
dashboard. **Detecta, no bloquea.**

## Arquitectura

```
 agentes (SSH / Nginx)  ──X-API-Key──┐
 simulador              ──X-API-Key──┤
                                     ▼
 navegador ──HTTPS 8443──► nginx (TLS) ──HTTPS 8444──► FastAPI ──► PostgreSQL
            (dashboard React)       proxy inverso      motor de reglas
```

- **API (FastAPI):** recibe eventos, los normaliza, aplica reglas y expone las alertas.
- **Motor de reglas:** ventanas deslizantes por tiempo del evento, deduplicación por regla e IP,
  etiquetas MITRE ATT&CK y una regla de correlación entre fuentes.
- **Dashboard (React + TypeScript):** alertas con filtros, gráfica por regla y actualización cada 5 s.
- **Proxy (nginx):** termina TLS 1.2/1.3 y agrega cabeceras de seguridad. La API no está expuesta
  directamente; solo el proxy puede alcanzarla.
- **Base de datos:** PostgreSQL 16.

## Reglas de detección (9)

| Regla | Qué detecta |
|---|---|
| `brute_force` | 5 intentos fallidos desde una IP en 120 s (T1110) |
| `password_spraying` | 4 usuarios distintos con login fallido desde una IP en 600 s (T1110.003) |
| `compromised_login` | Login exitoso tras 5 fallos desde la misma IP en 600 s (T1078) |
| `scan_404` | 10 errores 404 en 60 s (T1595.003) |
| `sensitive_paths` | 3 rutas sensibles distintas en 300 s, como `/.env` o `/admin` (T1595) |
| `sqli`, `xss`, `path_traversal` | Patrones de ataque en URLs (se decodifican 2 pasadas) |
| `coordinated_attack` | Misma IP con alertas en 2 o más fuentes en 30 min (crítica) |

## Inicio rápido

Requisitos: Docker (o Podman con compose), Node.js 20+, OpenSSL.

```bash
# 1. Variables de entorno
cp .env.example .env            # edita los valores; JWT_SECRET: openssl rand -hex 32

# 2. Certificado TLS autofirmado para localhost
mkdir -p proxy/certs && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout proxy/certs/localhost.key -out proxy/certs/localhost.crt -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 proxy/certs/localhost.key

# 3. Compilar el dashboard (el proxy sirve frontend/dist)
cd frontend && npm ci && npm run build && cd ..

# 4. Levantar todo
docker compose up --build -d
sleep 10 && curl --cacert proxy/certs/localhost.crt https://localhost:8444/health
```

Debe responder `{"status":"ok"}`.

## Crear usuario y fuentes

```bash
# Usuario del dashboard (pide contraseña de mínimo 12 caracteres)
docker compose exec api python -m app.create_user analista

# Fuente (agente) y su API key. La clave se muestra UNA vez; en la BD solo se guarda su hash.
docker compose exec api python -m app.create_source ssh-agent ssh      # tipos: ssh | web | nginx
```

Abre <https://localhost:8443> e inicia sesión. El navegador avisará del certificado autofirmado;
acéptalo también en <https://localhost:8444/docs> (la API y el dashboard son orígenes distintos).

## Demostración con el simulador

Genera 8 escenarios de ataque contra la API y comprueba que se dispare la alerta esperada:

```bash
source agents/.env.https && source agents/.env.sim && python3 simulator/simulate.py
```

Los archivos `agents/.env.*` están fuera de git (contienen API keys). Crea los tuyos:

- `agents/.env.https`: `export API_URL='https://localhost:8444'` y
  `export SSL_CERT_FILE="$(git rev-parse --show-toplevel)/proxy/certs/localhost.crt"`
- `agents/.env.sim`: `export SIM_SSH_KEY=...`, `export SIM_WEB_KEY=...` y `export SIM_NGINX_KEY=...` (una API key por fuente; crea una de cada tipo `ssh`, `web` y `nginx` con `create_source`)

Los agentes `agents/ssh_agent.py` y `agents/nginx_agent.py` leen un log y envían sus eventos a la API.

## API

| Método y ruta | Autenticación | Función |
|---|---|---|
| `GET /health` | Ninguna | Estado del servicio |
| `POST /events` | `X-API-Key` | Ingesta de un evento |
| `POST /auth/login` | Ninguna (con rate limiting) | Devuelve un JWT |
| `GET /alerts` | `Bearer` JWT | Lista alertas (filtros: `status`, `severity`, `rule`, `src_ip`, `limit`, `offset`) |
| `PATCH /alerts/{id}` | `Bearer` JWT | Cambia el estado de una alerta |

Documentación interactiva: <https://localhost:8444/docs>.

## Seguridad aplicada

- Contraseñas con Argon2; login de tiempo constante y sin enumeración de usuarios.
- JWT HS256 con algoritmos fijados, `exp` y `sub` obligatorios.
- API keys aleatorias (`secrets`), guardadas solo como hash SHA-256.
- Rate limiting en memoria: 5 fallos de login por usuario y 20 por IP en 15 min, y límites generales de API y de ingesta.
- Contenedor sin root (uid 10001), `cap_drop: ALL`, `no-new-privileges`, dependencias con versión fija.
- HTTPS (TLS 1.2/1.3), HSTS, CSP en el dashboard, `X-Content-Type-Options`, `X-Frame-Options`, CORP `same-origin`, `Cache-Control: no-store` en la API.
- CORS restringido a los orígenes del dashboard.

Evidencia en `docs/seguridad/`:

| Herramienta | Resultado |
|---|---|
| Bandit | 0 hallazgos |
| Trivy (dependencias Python) | 0 vulnerabilidades |
| Trivy (imagen) | Los HIGH restantes son paquetes de la base Debian sin parche disponible |
| OWASP ZAP (API) | 2 advertencias → 0; 120 pruebas superadas (`RESUMEN_ZAP.md`) |
| CodeQL | 2 alertas: 1 falso positivo (SHA-256 sobre API key aleatoria) y 1 de riesgo bajo (`print` de la clave al crearla) |

## Límites conocidos

- **Solo detecta:** no bloquea ni responde a los ataques.
- **Rate limiting en memoria:** se reinicia con la API y no se comparte entre varias instancias.
- **IP del cliente:** con Podman/NAT local, todos los clientes se ven como una IP interna `10.89.x.x`.
  El proxy y `--proxy-headers` están preparados para obtener la IP real en un despliegue real.
- **Certificado autofirmado:** solo para pruebas locales; en producción usar una CA y subir el `max-age` de HSTS.
- **ZAP sin autenticación:** los endpoints protegidos respondieron 401, así que su lógica interna no fue ejercitada.
- **Puerto 5433 de la base de datos** publicado solo en `127.0.0.1` para usar un cliente como DBeaver; quítalo en un despliegue.

## Estructura

```
backend/    API FastAPI, motor de reglas, rate limiting, Dockerfile
frontend/   Dashboard React + TypeScript (Vite)
agents/     Agentes que leen auth.log y access.log y los envían a la API
simulator/  8 escenarios de ataque con verificación automática
proxy/      Configuración de nginx (certificados y logs fuera de git)
docs/       Evidencia de seguridad (Bandit, Trivy, ZAP, CodeQL)
```
