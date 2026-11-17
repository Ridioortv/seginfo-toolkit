import { useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import AuthShell from "../components/AuthShell";
import { resetPassword } from "../services/api";
import { passwordProblem, tokenFromSearch } from "../utils/password";

function detailOf(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string"
    ? detail
    : "No se pudo cambiar la contrasena. Revisa tu conexion e intenta de nuevo.";
}

// Pantalla a la que llega el link del mail ("/restablecer?token=..."): se elige la
// contrasena nueva. El token es de un solo uso y vence a los 30 minutos.
export default function ResetPassword() {
  const location = useLocation();
  const token = tokenFromSearch(location.search);
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const problem = passwordProblem(password, repeat);
    if (problem) {
      setError(problem);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(detailOf(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell>
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>Elegi tu contrasena nueva</h1>

        {!token ? (
          <>
            <p className="error-text">Este link no es valido. Pedi uno nuevo.</p>
            <p className="empty-hint">
              <Link to="/olvide-mi-contrasena">Pedir un link nuevo</Link>
            </p>
          </>
        ) : done ? (
          <>
            <p>Listo: tu contrasena se actualizo. Ya podes ingresar con la nueva.</p>
            <Link className="btn-primary" to="/login">
              Ir a ingresar
            </Link>
          </>
        ) : (
          <>
            <p>Escribi la contrasena nueva dos veces.</p>
            <div className="field">
              <label htmlFor="new-password">Contrasena nueva (minimo 12 caracteres)</label>
              <input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <div className="field">
              <label htmlFor="repeat-password">Repetir la contrasena nueva</label>
              <input
                id="repeat-password"
                type="password"
                autoComplete="new-password"
                value={repeat}
                onChange={(e) => setRepeat(e.target.value)}
                required
              />
            </div>
            <button className="btn-primary" type="submit" disabled={loading || !password || !repeat}>
              {loading ? "Guardando..." : "Cambiar contrasena"}
            </button>
            {error && <p className="error-text">{error}</p>}
            <p className="empty-hint" style={{ marginTop: 12 }}>
              <Link to="/olvide-mi-contrasena">Pedir un link nuevo</Link>
            </p>
          </>
        )}
      </form>
    </AuthShell>
  );
}
