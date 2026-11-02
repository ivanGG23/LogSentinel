import { useCallback, useState } from "react";
import Dashboard from "./Dashboard";
import Login from "./Login";

export default function App() {
  // El token vive solo en memoria: no se guarda en localStorage (protege contra robo por XSS).
  const [token, setToken] = useState<string | null>(null);
  const logout = useCallback(() => setToken(null), []);
  return token
    ? <Dashboard token={token} onLogout={logout} />
    : <Login onLogin={setToken} />;
}
