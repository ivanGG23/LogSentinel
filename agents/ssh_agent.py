"""Agente SSH de LogSentinel: lee auth.log y envía los logins a la API."""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Formato clásico: "Oct 28 10:15:02 ..."
SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s")
# Formato ISO: "2026-10-28T10:15:02.123456-06:00 ..."
ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s")

SSH_LOGIN = re.compile(
    r"sshd(?:-session)?\[\d+\]:\s+(?P<result>Failed|Accepted)\s+(?P<method>\S+)\s+"
    r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+")


def parse_timestamp(line):
    m = ISO_TS.match(line)
    if m:
        return datetime.fromisoformat(m["ts"])
    m = SYSLOG_TS.match(line)
    if m:
        now = datetime.now()
        h, mi, s = map(int, m["time"].split(":"))
        ts = datetime(now.year, MONTHS[m["mon"]], int(m["day"]), h, mi, s)
        if ts > now + timedelta(days=1):  # log de diciembre leído en enero
            ts = ts.replace(year=now.year - 1)
        return ts.astimezone()  # asume la zona horaria local
    return None


def parse_line(line):
    """Devuelve un evento normalizado o None si la línea no es un login."""
    line = line.rstrip("\n")
    m = SSH_LOGIN.search(line)
    if not m:
        return None
    try:
        ts = parse_timestamp(line)
    except (ValueError, KeyError):
        return None
    if ts is None:
        return None
    return {
        "timestamp": ts.isoformat(),
        "event_type": "login",
        "src_ip": m["ip"],
        "username": m["user"][:100],
        "status": "success" if m["result"] == "Accepted" else "fail",
        "raw_log": line[:4000],
    }


def send(event, api_url, api_key):
    data = json.dumps(event).encode()
    req = urllib.request.Request(
        f"{api_url}/events", data=data, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def follow(f):
    """Lee lo que ya existe y luego espera líneas nuevas (como tail -f)."""
    while True:
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Agente SSH de LogSentinel")
    parser.add_argument("logfile", help="ruta del auth.log")
    parser.add_argument("--follow", action="store_true",
                        help="seguir leyendo; solo envía las líneas que lleguen después")
    parser.add_argument("--from-start", action="store_true",
                        help="con --follow, procesar también lo que ya existe")
    args = parser.parse_args()

    api_url = os.environ.get("API_URL", "http://localhost:8000")
    api_key = os.environ.get("API_KEY")
    if not api_key:
        sys.exit("Falta la variable de entorno API_KEY")

    sent = failed = ignored = 0
    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as f:
            if args.follow and not args.from_start:
                f.seek(0, os.SEEK_END)  # saltar lo que ya existe
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


if __name__ == "__main__":
    main()
