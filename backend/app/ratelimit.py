"""Límite de peticiones en memoria (ventana deslizante)."""
import threading
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

MAX_KEYS = 10_000  # tope de claves en memoria antes de limpiar las vencidas


class SlidingWindow:
    """Permite `limit` eventos por clave dentro de los últimos `window_seconds`."""

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _purge(self, q: deque, now: float) -> None:
        while q and q[0] <= now - self.window:
            q.popleft()

    def _sweep(self, now: float) -> None:
        """Descarta claves vencidas para que la memoria no crezca sin límite."""
        vencidas = [k for k, q in self._hits.items() if not q or q[-1] <= now - self.window]
        for k in vencidas:
            del self._hits[k]

    def retry_after(self, key: str) -> int:
        """Segundos que faltan para poder reintentar (0 si la clave no está bloqueada)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                return 0
            self._purge(q, now)
            if len(q) < self.limit:
                return 0
            return int(q[0] + self.window - now) + 1

    def add(self, key: str) -> None:
        """Registra un evento (por ejemplo, un login fallido)."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > MAX_KEYS:
                self._sweep(now)
            q = self._hits[key]
            self._purge(q, now)
            q.append(now)

    def hit(self, key: str) -> int:
        """Registra una petición. Devuelve 0 si pasa, o los segundos de espera si se excedió."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > MAX_KEYS:
                self._sweep(now)
            q = self._hits[key]
            self._purge(q, now)
            if len(q) >= self.limit:
                return int(q[0] + self.window - now) + 1
            q.append(now)
            return 0

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


# Intentos de login FALLIDOS (ventana de 15 minutos)
login_user_limiter = SlidingWindow(limit=5, window_seconds=900)    # por usuario
login_ip_limiter = SlidingWindow(limit=20, window_seconds=900)     # por IP

# Peticiones en general, por IP (ventana de 1 minuto)
api_limiter = SlidingWindow(limit=120, window_seconds=60)
events_limiter = SlidingWindow(limit=1200, window_seconds=60)      # los agentes envían ráfagas


def client_ip(request: Request) -> str:
    # No se lee X-Forwarded-For: cualquiera puede falsificarlo.
    return request.client.host if request.client else "desconocido"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        limiter = events_limiter if request.url.path == "/events" else api_limiter
        wait = limiter.hit(client_ip(request))
        if wait:
            return JSONResponse(
                {"detail": "Demasiadas peticiones. Intenta más tarde."},
                status_code=429,
                headers={"Retry-After": str(wait)},
            )
        return await call_next(request)
