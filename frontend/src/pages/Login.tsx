import { useState } from "react";
import { login } from "../services/api";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const tokens = await login(email, password, totpCode || undefined);
      localStorage.removeItem("sentinelops_access_token"); // placeholder until store wiring lands
      console.log("login ok", tokens.token_type);
    } catch {
      setError("Credenciales invalidas o MFA requerido.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>SentinelOps</h1>
        <p>Acceso a la plataforma de seguridad</p>

        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>

        <div className="field">
          <label htmlFor="password">Contrasena</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>

        <div className="field">
          <label htmlFor="totp">Codigo MFA (si esta activado)</label>
          <input id="totp" type="text" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="123456" />
        </div>

        <button className="btn-primary" type="submit" disabled={loading}>
          {loading ? "Ingresando..." : "Ingresar"}
        </button>

        {error && <p className="error-text">{error}</p>}
      </form>
    </div>
  );
}
