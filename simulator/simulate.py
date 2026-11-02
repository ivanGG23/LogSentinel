#!/usr/bin/env python3
"""Simulador de ataques de LogSentinel. Solo corre contra localhost.

Cada escenario usa una IP aleatoria propia, envía eventos a POST /events y luego
comprueba, con GET /alerts, que salieron las alertas esperadas y ninguna extra.
"""
import getpass
import json
import os
import random
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

API = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
if urlparse(API).hostname not in ("localhost", "127.0.0.1", "::1"):
    sys.exit("Por seguridad, el simulador solo corre contra localhost.")

KEYS = {t: os.environ.get(f"SIM_{t.upper()}_KEY") for t in ("ssh", "web", "nginx")}
faltan = [f"SIM_{t.upper()}_KEY" for t, k in KEYS.items() if not k]
if faltan:
    sys.exit("Faltan variables: " + ", ".join(faltan) + "  (haz: source agents/.env.sim)")


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except urllib.error.URLError as e:
        sys.exit(f"No se pudo conectar con la API: {e.reason}")


_usadas = set()


def nueva_ip(prefijo):
    """IP aleatoria de un rango de documentación (RFC 5737), distinta en cada escenario."""
    while True:
        ip = f"{prefijo}.{random.randint(100, 250)}"
        if ip not in _usadas:
            _usadas.add(ip)
            return ip


class Out:
    """Genera eventos con timestamps crecientes, terminando 'ahora'."""

    def __init__(self, ip):
        self.ip = ip
        self.t = datetime.now(timezone.utc) - timedelta(seconds=90)
        self.errores = 0

    def _send(self, source, ev):
        self.t += timedelta(seconds=1)
        ev["timestamp"] = self.t.isoformat()
        ev["src_ip"] = self.ip
        status, _ = call("POST", "/events", ev, {"X-API-Key": KEYS[source]})
        if status != 201:
            self.errores += 1

    def login(self, source, user, ok):
        self._send(source, {
            "event_type": "login", "username": user,
            "status": "success" if ok else "fail",
            "raw_log": f"[sim] login {'ok' if ok else 'fail'} {user}"})

    def http(self, path, code):
        self._send("nginx", {
            "event_type": "http_request", "path": path, "http_status": code,
            "raw_log": f"[sim] GET {path} {code}"})


SCENARIOS = []


def scenario(nombre, prefijo, esperadas, permitidas=()):
    def deco(fn):
        SCENARIOS.append((nombre, prefijo, set(esperadas), set(permitidas), fn))
        return fn
    return deco


@scenario("1. Tráfico normal (sin alertas)", "198.51.100", [])
def normal(o):
    o.login("web", "maria", False)   # un par de errores de contraseña
    o.login("web", "maria", False)
    o.login("web", "maria", True)
    for ruta, codigo in [("/", 200), ("/static/app.css", 200), ("/favicon.ico", 404),
                         ("/productos?id=5", 200), ("/buscar?q=zapatos", 200),
                         ("/admin", 200)]:
        o.http(ruta, codigo)


@scenario("2. Fuerza bruta (SSH)", "203.0.113", ["brute_force"])
def brute(o):
    for _ in range(6):
        o.login("ssh", "root", False)


@scenario("3. Password spraying (web)", "203.0.113", ["password_spraying"])
def spraying(o):
    for u in ("admin", "root", "test", "oracle"):
        o.login("web", u, False)


@scenario("4. Login comprometido (web)", "203.0.113", ["compromised_login"], ["brute_force"])
def comprometido(o):
    for _ in range(5):
        o.login("web", "admin", False)
    o.login("web", "admin", True)


@scenario("5. Escaneo de rutas (404)", "203.0.113", ["scan_404"])
def escaneo(o):
    for i in range(10):
        o.http(f"/nada{i}", 404)


@scenario("6. Rutas sensibles", "203.0.113", ["sensitive_paths"])
def sensibles(o):
    for ruta in ("/admin", "/.env", "/phpmyadmin"):
        o.http(ruta, 403)


@scenario("7. SQLi + XSS + path traversal", "203.0.113", ["sqli", "xss", "path_traversal"])
def inyecciones(o):
    o.http("/productos?id=1%27%20OR%201%3D1--", 200)
    o.http("/buscar?q=%3Cscript%3Ealert(1)%3C/script%3E", 403)
    o.http("/descargar?archivo=..%2F..%2F..%2Fetc%2Fpasswd", 200)


@scenario("8. Ataque coordinado (SSH + Nginx)", "203.0.113",
          ["brute_force", "sensitive_paths", "coordinated_attack"])
def coordinado(o):
    for _ in range(5):
        o.login("ssh", "root", False)
    for ruta in ("/admin", "/.env", "/phpmyadmin"):
        o.http(ruta, 403)


def main():
    user = os.environ.get("SIM_USER") or input("Usuario analista: ")
    pwd = os.environ.get("SIM_PASSWORD") or getpass.getpass("Contraseña: ")
    status, body = call("POST", "/auth/login", {"username": user, "password": pwd})
    if status != 200 or not body:
        sys.exit(f"Login fallido (HTTP {status}).")
    token = body.get("access_token") or body.get("token")
    auth = {"Authorization": f"Bearer {token}"}

    print(f"\nSimulando contra {API}\n")
    todos_ok = True
    for nombre, prefijo, esperadas, permitidas, fn in SCENARIOS:
        o = Out(nueva_ip(prefijo))
        fn(o)
        status, alertas = call("GET", f"/alerts?src_ip={o.ip}&limit=200", headers=auth)
        if status != 200:
            sys.exit(f"GET /alerts falló (HTTP {status}).")
        obtenidas = {a["rule"] for a in alertas}
        faltantes = esperadas - obtenidas
        extra = obtenidas - esperadas - permitidas
        ok = not faltantes and not extra and o.errores == 0
        todos_ok &= ok
        print(f"{'PASA ' if ok else 'FALLA'}  {nombre:<38} {o.ip:<16} "
              f"alertas: {', '.join(sorted(obtenidas)) or '-'}")
        if not ok:
            if faltantes:
                print(f"         faltan: {sorted(faltantes)}")
            if extra:
                print(f"         sobran: {sorted(extra)}")
            if o.errores:
                print(f"         eventos rechazados por la API: {o.errores}")

    print("\n" + ("Todos los escenarios pasaron." if todos_ok else "Hay escenarios con fallas."))
    sys.exit(0 if todos_ok else 1)


if __name__ == "__main__":
    main()
