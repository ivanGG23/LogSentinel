import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  ApiError, listAlerts, updateAlert,
  type Alert, type AlertStatus, type Filters,
} from "./api/client";

const SEVERITIES = ["critical", "high", "medium", "low"];
const RULES = [
  "brute_force", "password_spraying", "compromised_login", "scan_404",
  "sensitive_paths", "sqli", "xss", "path_traversal", "coordinated_attack",
];
const STATUS_LABEL: Record<string, string> = {
  open: "Abierta", reviewed: "Revisada", false_positive: "Falso positivo",
};

function sevClass(sev: string): string {
  return SEVERITIES.includes(sev) ? `sev sev-${sev}` : "sev";
}

export default function Dashboard({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [filters, setFilters] = useState<Filters>({ status: "", severity: "", rule: "" });
  const [ip, setIp] = useState("");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [auto, setAuto] = useState(true);
  const [updated, setUpdated] = useState<Date | null>(null);

  const handleError = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) onLogout();
    else setError(err instanceof ApiError ? err.message : "Error inesperado");
  }, [onLogout]);

  const load = useCallback(async () => {
    try {
      setAlerts(await listAlerts(token, filters));
      setError("");
      setUpdated(new Date());
    } catch (err) {
      handleError(err);
    }
  }, [token, filters, handleError]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    if (!auto) return;
    const id = setInterval(() => void load(), 5000);
    return () => clearInterval(id);
  }, [auto, load]);

  async function changeStatus(id: number, status: AlertStatus) {
    try {
      await updateAlert(token, id, status);
      await load();
    } catch (err) {
      handleError(err);
    }
  }

  const shown = useMemo(
    () => alerts.filter((a) => !ip.trim() || a.src_ip.includes(ip.trim())),
    [alerts, ip],
  );

  const bySeverity = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of shown) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
    return counts;
  }, [shown]);

  const byRule = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of shown) counts[a.rule] = (counts[a.rule] ?? 0) + 1;
    return Object.entries(counts).map(([rule, total]) => ({ rule, total }));
  }, [shown]);

  return (
    <main className="dash">
      <header>
        <h1>LogSentinel</h1>
        <div className="actions">
          <label className="inline">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            Actualizar cada 5 s
          </label>
          <button onClick={() => void load()}>Actualizar</button>
          <button className="ghost" onClick={onLogout}>Salir</button>
        </div>
      </header>

      {error && <p className="error" role="alert">{error}</p>}

      <section className="cards">
        {SEVERITIES.map((s) => (
          <div key={s} className={`card ${sevClass(s)}`}>
            <span className="num">{bySeverity[s] ?? 0}</span>
            <span>{s}</span>
          </div>
        ))}
        <div className="card">
          <span className="num">{shown.length}</span>
          <span>alertas mostradas</span>
        </div>
      </section>

      <section className="chart">
        <h2>Alertas por regla</h2>
        {byRule.length === 0 ? (
          <p className="muted">Sin datos.</p>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={byRule}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="rule" stroke="#94a3b8" fontSize={12} />
              <YAxis allowDecimals={false} stroke="#94a3b8" />
              <Tooltip />
              <Bar dataKey="total" fill="#38bdf8" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </section>

      <section className="filters">
        <select value={filters.status}
                onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
          <option value="">Todos los estados</option>
          {Object.entries(STATUS_LABEL).map(([v, label]) => (
            <option key={v} value={v}>{label}</option>
          ))}
        </select>
        <select value={filters.severity}
                onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">Todas las severidades</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filters.rule}
                onChange={(e) => setFilters({ ...filters, rule: e.target.value })}>
          <option value="">Todas las reglas</option>
          {RULES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <input placeholder="Filtrar por IP" value={ip} onChange={(e) => setIp(e.target.value)} />
        {updated && <span className="muted">Actualizado {updated.toLocaleTimeString()}</span>}
      </section>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severidad</th><th>Regla</th><th>IP</th><th>MITRE</th>
              <th>Descripción</th><th>Hora del evento</th><th>Estado</th><th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a) => (
              <tr key={a.id}>
                <td><span className={sevClass(a.severity)}>{a.severity}</span></td>
                <td>{a.rule}</td>
                <td>{a.src_ip}</td>
                <td>{a.mitre ?? "-"}</td>
                {/* Texto del atacante: se muestra SIEMPRE como texto, nunca como HTML */}
                <td className="desc">{a.description}</td>
                <td>{new Date(a.event_time).toLocaleString()}</td>
                <td>{STATUS_LABEL[a.status] ?? a.status}</td>
                <td className="row-actions">
                  <button onClick={() => void changeStatus(a.id, "reviewed")}>Revisada</button>
                  <button onClick={() => void changeStatus(a.id, "false_positive")}>Falso +</button>
                  {a.status !== "open" && (
                    <button className="ghost" onClick={() => void changeStatus(a.id, "open")}>
                      Reabrir
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {shown.length === 0 && (
              <tr><td colSpan={8} className="muted">No hay alertas con esos filtros.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </main>
  );
}
