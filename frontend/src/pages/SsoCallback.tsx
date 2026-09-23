import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/auth";

// Adonde redirige auth-service despues de un login SSO (OIDC) exitoso --
// ver backend/services/auth-service/app/main.py::oidc_callback, que manda
// access_token/refresh_token en el FRAGMENTO de la URL (nunca en query
// params: el fragmento no se manda al servidor ni queda en logs de acceso,
// a diferencia de un query param). Esta pagina solo lee ese fragmento,
// guarda los tokens y redirige adentro de la app -- no hace ninguna
// llamada de red propia.
export default function SsoCallback() {
  const setTokens = useAuthStore((s) => s.setTokens);
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fragment = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
    const params = new URLSearchParams(fragment);
    const accessToken = params.get("access_token");
    const refreshToken = params.get("refresh_token");

    if (!accessToken || !refreshToken) {
      setError("El proveedor de SSO no devolvio una sesion valida. Volve a intentar el login desde tu organizacion.");
      return;
    }

    setTokens(accessToken, refreshToken);
    // Reemplaza la entrada del historial para que el fragmento con los
    // tokens no quede navegable con el boton "atras".
    navigate("/", { replace: true });
  }, [navigate, setTokens]);

  return (
    <div className="app-shell">
      <div className="login-card">
        <h1>SentinelOps</h1>
        {error ? (
          <>
            <p className="error-text">{error}</p>
            <button className="btn-primary" onClick={() => navigate("/login")}>
              Volver al login
            </button>
          </>
        ) : (
          <p>Completando el inicio de sesion con SSO...</p>
        )}
      </div>
    </div>
  );
}
