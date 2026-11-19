import re
from datetime import timedelta
from urllib.parse import unquote_plus

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Alert, Event, Rule

DEFAULT_RULES = [
    dict(name="brute_force",
         description="Muchos intentos de login fallidos desde una misma IP",
         threshold=5, window_seconds=120, severity="high", mitre="T1110"),
    dict(name="password_spraying",
         description="Una IP prueba muchos usuarios distintos",
         threshold=4, window_seconds=600, severity="high", mitre="T1110.003"),
    dict(name="compromised_login",
         description="Login exitoso después de varios fallos desde la misma IP",
         threshold=5, window_seconds=600, severity="critical", mitre="T1078"),
    dict(name="scan_404",
         description="Ráfaga de errores 404 desde una misma IP (escaneo de rutas)",
         threshold=10, window_seconds=60, severity="medium", mitre="T1595.003"),
    dict(name="sensitive_paths",
         description="Peticiones a varias rutas sensibles distintas (/.env, /admin, ...)",
         threshold=3, window_seconds=300, severity="high", mitre="T1595"),
    dict(name="sqli",
         description="Patrones de SQL injection en la URL",
         threshold=1, window_seconds=300, severity="high", mitre="T1190"),
    dict(name="xss",
         description="Patrones de XSS en la URL",
         threshold=1, window_seconds=300, severity="medium", mitre="T1190"),
    dict(name="path_traversal",
         description="Patrones de path traversal en la URL",
         threshold=1, window_seconds=300, severity="high", mitre="T1190"),
    dict(name="coordinated_attack",
         description="Una misma IP genera alertas en varias fuentes (SSH, web, Nginx)",
         threshold=2, window_seconds=1800, severity="critical", mitre="N/A"),
]

SENSITIVE_PATHS = (
    "/.env", "/.git", "/.aws", "/.htaccess", "/admin", "/phpmyadmin",
    "/wp-login.php", "/wp-admin", "/config.php", "/backup", "/server-status",
    "/actuator", "/id_rsa",
)

INJECTION_PATTERNS = {
    "sqli": [re.compile(p, re.I) for p in (
        r"\bunion\b[\s/*]+(all[\s/*]+)?select\b",
        r"['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"\bor\s+\d+\s*=\s*\d+",
        r"['\"]\s*(--|#|/\*)",
        r";\s*(drop|alter|truncate|insert|update|delete)\b",
        r"\b(pg_sleep|sleep|benchmark)\s*\(",
        r"\bwaitfor\s+delay\b",
        r"\binformation_schema\b",
    )],
    "xss": [re.compile(p, re.I) for p in (
        r"<\s*script\b",
        r"<\s*(iframe|svg|object|embed)\b",
        r"\bon(error|load|click|mouseover|focus)\s*=",
        r"javascript\s*:",
    )],
    "path_traversal": [re.compile(p, re.I) for p in (
        r"\.\.[/\\]",
        r"/etc/(passwd|shadow)\b",
        r"windows[/\\]system32",
    )],
}
INJECTION_LABELS = {"sqli": "SQL injection", "xss": "XSS", "path_traversal": "path traversal"}
_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


def seed_rules(db: Session) -> None:
    """Crea las reglas por defecto que todavía no existan."""
    existing = set(db.scalars(select(Rule.name)))
    new = [Rule(**r) for r in DEFAULT_RULES if r["name"] not in existing]
    if new:
        db.add_all(new)
        db.commit()


def _clean(text: str, limit: int = 120) -> str:
    """Recorta y reemplaza caracteres de control (ej. NUL) antes de guardar en la BD."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", text[:limit])


def _decode(value: str) -> str:
    """Decodifica la URL hasta 2 veces (cubre la doble codificación)."""
    for _ in range(2):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def _is_sensitive(path: str) -> bool:
    return _decode(path).split("?")[0].lower().startswith(SENSITIVE_PATHS)


def _injection_severity(rule: Rule, code: int | None) -> str:
    if code is None or code < 400:
        return rule.severity          # el servidor respondió normal: se mantiene
    if code >= 500:
        return "critical"             # error del servidor: puede ser vulnerable
    return _DOWNGRADE[rule.severity]  # rechazada (4xx): baja un nivel


def _create_alert(db: Session, rule: Rule, ip, ts, description, severity=None) -> None:
    """Crea la alerta salvo que ya exista una igual dentro de la misma ventana."""
    since = ts - timedelta(seconds=rule.window_seconds)
    exists = db.scalar(
        select(Alert.id)
        .where(Alert.rule == rule.name, Alert.src_ip == ip, Alert.event_time >= since)
        .limit(1)
    )
    if exists is None:
        db.add(Alert(rule=rule.name, severity=severity or rule.severity, src_ip=ip,
                     mitre=rule.mitre, description=description, event_time=ts))
        db.commit()


# ---------- Reglas de login (SSH y web) ----------

def _failed_logins(ip, ts, window_seconds):
    """Condiciones: logins fallidos de esa IP en la ventana que termina en ts."""
    return (
        Event.src_ip == ip,
        Event.event_type == "login",
        Event.status == "fail",
        Event.timestamp > ts - timedelta(seconds=window_seconds),
        Event.timestamp <= ts,
    )


def _evaluate_login(db: Session, event: Event, rules: dict) -> None:
    ip, ts = event.src_ip, event.timestamp

    if event.status == "fail":
        rule = rules.get("brute_force")
        if rule:
            n = db.scalar(select(func.count()).select_from(Event)
                          .where(*_failed_logins(ip, ts, rule.window_seconds)))
            if n >= rule.threshold:
                _create_alert(db, rule, ip, ts,
                              f"{n} intentos fallidos desde {ip} en {rule.window_seconds} s")

        rule = rules.get("password_spraying")
        if rule:
            n = db.scalar(select(func.count(func.distinct(Event.username)))
                          .where(*_failed_logins(ip, ts, rule.window_seconds)))
            if n >= rule.threshold:
                _create_alert(db, rule, ip, ts,
                              f"{ip} probó {n} usuarios distintos en {rule.window_seconds} s")

    elif event.status == "success":
        rule = rules.get("compromised_login")
        if rule:
            n = db.scalar(select(func.count()).select_from(Event)
                          .where(*_failed_logins(ip, ts, rule.window_seconds)))
            if n >= rule.threshold:
                _create_alert(db, rule, ip, ts,
                              f"Login exitoso de '{_clean(event.username or '', 100)}' "
                              f"desde {ip} tras {n} intentos fallidos")


# ---------- Reglas web (Nginx) ----------

def _evaluate_http(db: Session, event: Event, rules: dict) -> None:
    ip, ts = event.src_ip, event.timestamp
    path, code = event.path or "", event.http_status

    rule = rules.get("scan_404")
    if rule and code == 404:
        n = db.scalar(
            select(func.count()).select_from(Event).where(
                Event.src_ip == ip, Event.event_type == "http_request",
                Event.http_status == 404,
                Event.timestamp > ts - timedelta(seconds=rule.window_seconds),
                Event.timestamp <= ts))
        if n >= rule.threshold:
            _create_alert(db, rule, ip, ts,
                          f"{n} errores 404 desde {ip} en {rule.window_seconds} s "
                          f"(posible escaneo de rutas)")

    rule = rules.get("sensitive_paths")
    if rule and _is_sensitive(path):
        paths = db.scalars(
            select(Event.path).where(
                Event.src_ip == ip, Event.event_type == "http_request",
                Event.path.is_not(None),
                Event.timestamp > ts - timedelta(seconds=rule.window_seconds),
                Event.timestamp <= ts))
        hits = {_decode(p).split("?")[0].lower() for p in paths if _is_sensitive(p)}
        if len(hits) >= rule.threshold:
            sample = _clean(", ".join(sorted(hits)[:3]), 100)
            _create_alert(db, rule, ip, ts,
                          f"{ip} pidió {len(hits)} rutas sensibles distintas en "
                          f"{rule.window_seconds} s (ej.: {sample})")

    decoded = _decode(path)
    for name, patterns in INJECTION_PATTERNS.items():
        rule = rules.get(name)
        if rule and any(p.search(decoded) for p in patterns):
            _create_alert(db, rule, ip, ts,
                          f"Intento de {INJECTION_LABELS[name]} desde {ip} "
                          f"(HTTP {code}): {_clean(decoded)}",
                          severity=_injection_severity(rule, code))


# ---------- Correlación entre fuentes ----------

LOGIN_RULES = {"brute_force", "password_spraying", "compromised_login"}
WEB_RULES = {"scan_404", "sensitive_paths", "sqli", "xss", "path_traversal"}


def _sources_of(db: Session, ip, event_type: str, since, ts) -> set:
    return set(db.scalars(
        select(Event.source).where(
            Event.src_ip == ip, Event.event_type == event_type,
            Event.timestamp >= since, Event.timestamp <= ts).distinct()))


def _evaluate_correlation(db: Session, event: Event, rules: dict) -> None:
    rule = rules.get("coordinated_attack")
    if not rule:
        return
    ip, ts = event.src_ip, event.timestamp
    since = ts - timedelta(seconds=rule.window_seconds)

    fired = set(db.scalars(
        select(Alert.rule).where(
            Alert.src_ip == ip, Alert.event_time >= since,
            Alert.rule != rule.name).distinct()))

    sources = set()
    if fired & LOGIN_RULES:
        sources |= _sources_of(db, ip, "login", since, ts)
    if fired & WEB_RULES:
        sources |= _sources_of(db, ip, "http_request", since, ts)

    if len(sources) >= rule.threshold:
        _create_alert(db, rule, ip, ts,
                      f"{ip} generó alertas en {len(sources)} fuentes distintas "
                      f"({', '.join(sorted(sources))}) en {rule.window_seconds // 60} min: "
                      f"{', '.join(sorted(fired))}")


def evaluate_event(db: Session, event: Event) -> None:
    """Aplica las reglas activas a un evento recién guardado."""
    rules = {r.name: r for r in db.scalars(select(Rule).where(Rule.enabled.is_(True)))}
    if event.event_type == "login":
        _evaluate_login(db, event, rules)
    elif event.event_type == "http_request":
        _evaluate_http(db, event, rules)
    _evaluate_correlation(db, event, rules)
