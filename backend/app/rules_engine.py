from datetime import timedelta

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
]


def seed_rules(db: Session) -> None:
    """Crea las reglas por defecto si la tabla está vacía."""
    if db.scalar(select(func.count()).select_from(Rule)) == 0:
        db.add_all([Rule(**r) for r in DEFAULT_RULES])
        db.commit()


def _failed_logins(ip, ts, window_seconds):
    """Condiciones: logins fallidos de esa IP en la ventana que termina en ts."""
    return (
        Event.src_ip == ip,
        Event.event_type == "login",
        Event.status == "fail",
        Event.timestamp > ts - timedelta(seconds=window_seconds),
        Event.timestamp <= ts,
    )


def _create_alert(db: Session, rule: Rule, ip, ts, description) -> None:
    """Crea la alerta salvo que ya exista una igual dentro de la misma ventana."""
    since = ts - timedelta(seconds=rule.window_seconds)
    exists = db.scalar(
        select(Alert.id)
        .where(Alert.rule == rule.name, Alert.src_ip == ip, Alert.event_time >= since)
        .limit(1)
    )
    if exists is None:
        db.add(Alert(rule=rule.name, severity=rule.severity, src_ip=ip,
                     mitre=rule.mitre, description=description, event_time=ts))
        db.commit()


def evaluate_event(db: Session, event: Event) -> None:
    """Aplica las reglas activas a un evento recién guardado."""
    if event.event_type != "login":
        return
    rules = {r.name: r for r in db.scalars(select(Rule).where(Rule.enabled.is_(True)))}
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
                              f"Login exitoso de '{event.username}' desde {ip} "
                              f"tras {n} intentos fallidos")
