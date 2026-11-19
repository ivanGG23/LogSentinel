import { useState, type FormEvent } from "react";
import { ApiError, login } from "./api/client";

export default function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onLogin(await login(username, password));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Usuario o contraseña incorrectos");
      } else {
        setError(err instanceof ApiError ? err.message : "Error inesperado");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <h1>LogSentinel</h1>
      <p className="muted">Acceso de analistas</p>
      <form onSubmit={submit}>
        <label>
          Usuario
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 autoComplete="username" required />
        </label>
        <label>
          Contraseña
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 autoComplete="current-password" required />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? "Entrando..." : "Entrar"}</button>
      </form>
    </main>
  );
}
