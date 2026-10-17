import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/auth";
import { consumeClientState } from "../utils/ssoState";

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
  // El valor de cs es de un solo uso: StrictMode (dev) corre este efecto dos veces.
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;
    const fragment = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
    const params = new URLSearchParams(fragment);
    const accessToken = params.get("access_token");
    const refreshToken = params.get("refresh_token");

    if (!accessToken || !refreshToken) {
      setError("El proveedor de SSO no devolvio una sesion valida. Volve a intentar el login desde tu organizacion.");
      return;
    }

    // Solo se instala la sesion si este navegador inicio el login SSO (ver utils/ssoState.ts):
    // un link con tokens ajenos en el fragmento no pasa este chequeo.
    if (!consumeClientState(params.get("cs"))) {
      window.history.replaceState(null, "", window.location.pathname);
      setError("El inicio de sesion SSO no se origino en este navegador, asi que se descarto. Volve a iniciarlo desde el login.");
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
        <h1>TERO Security</h1>
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
