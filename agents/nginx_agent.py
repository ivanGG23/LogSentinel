"""Agente Nginx de LogSentinel: lee access.log y envía las peticiones a la API."""
import re
from datetime import datetime, timedelta, timezone

from common import run

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Formato "combined" de Nginx:
# 203.0.113.5 - - [28/Oct/2026:10:15:03 -0600] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.5.0"
NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.+?)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) ')
TS = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")


def parse_ts(text):
    m = TS.match(text)
    if not m:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    if mon not in MONTHS:
        return None
    delta = timedelta(hours=int(oh), minutes=int(om))
    tz = timezone(-delta if sign == "-" else delta)
    try:
        return datetime(int(year), MONTHS[mon], int(day),
                        int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None


def parse_line(line):
    """Devuelve un evento normalizado o None si la línea no se reconoce."""
    line = line.rstrip("\n")
    m = NGINX.match(line)
    if not m:
        return None
    ts = parse_ts(m["ts"])
    if ts is None:
        return None
    return {
        "timestamp": ts.isoformat(),
        "event_type": "http_request",
        "src_ip": m["ip"],
        "path": m["path"][:2000],
        "http_status": int(m["status"]),
        "raw_log": line[:4000],
    }


if __name__ == "__main__":
    run(parse_line, "Agente Nginx de LogSentinel", key_env="NGINX_API_KEY")
