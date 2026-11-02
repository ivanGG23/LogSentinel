"""Funciones compartidas por los agentes de LogSentinel."""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def send(event, api_url, api_key):
    if not api_url.startswith(("http://", "https://")):
        raise ValueError("API_URL debe empezar con http:// o https://")
    data = json.dumps(event).encode()
    req = urllib.request.Request(
        f"{api_url}/events", data=data, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - esquema validado arriba
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def follow(f):
    """Espera líneas nuevas (como tail -f)."""
    while True:
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(1)


def run(parse_line, description, key_env="API_KEY"):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("logfile", help="ruta del archivo de log")
    parser.add_argument("--follow", action="store_true",
                        help="seguir leyendo; solo envía las líneas que lleguen después")
    parser.add_argument("--from-start", action="store_true",
                        help="con --follow, procesar también lo que ya existe")
    args = parser.parse_args()

    api_url = os.environ.get("API_URL", "http://localhost:8000")
    api_key = os.environ.get(key_env)
    if not api_key:
        sys.exit(f"Falta la variable de entorno {key_env}")

    sent = failed = ignored = 0
    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as f:
            if args.follow and not args.from_start:
                f.seek(0, os.SEEK_END)
            for line in (follow(f) if args.follow else f):
                event = parse_line(line)
                if event is None:
                    ignored += 1
                    continue
                status = send(event, api_url, api_key)
                if status == 201:
                    sent += 1
                else:
                    failed += 1
                    print(f"Error {status} con la línea: {line.strip()[:80]}")
    except KeyboardInterrupt:
        print("\nAgente detenido.")
    print(f"Enviados: {sent} | Con error: {failed} | Ignorados: {ignored}")
