import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  confirmRegistrationMfa, login, loginWithGoogle, mfaStatus, register, requestBlockedPaymentLink, type MfaEnrollOut,
} from "../services/api";
import MfaSetupCard from "../components/MfaSetupCard";
import { useAuthStore } from "../store/auth";
import { NO_PAYMENT_OFFER, parseLoginError, parsePaymentOffer } from "../utils/loginError";
import { PAYMENT_PROVIDERS, isHttpUrl, type PaymentProvider } from "../utils/payment";
import { generateClientState, storeClientState } from "../utils/ssoState";
import Icon, { BrandMark } from "../components/Icon";
import { LanguageSwitcher, useLangStore, type Lang } from "../i18n";

const GOOGLE_LOCALES: Record<Lang, string> = { es: "es", en: "en", zh: "zh_CN", ru: "ru" };

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;

// Mismo criterio que en services/api.ts (serviceUrl): la URL base de
// auth-service en runtime, no en build-time, para no duplicar la logica
// de fallback a localhost:8001.
const AUTH_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8001";

// La libreria de Google Identity Services se carga con un <script> en
// index.html y expone window.google en runtime; no tiene tipos propios
// instalados aca, asi que se accede de forma laxa (unknown) en vez de
// agregar una dependencia npm nueva solo para esto.
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: { client_id: string; callback: (resp: { credential: string }) => void }) => void;
          renderButton: (parent: HTMLElement, options: Record<string, unknown>) => void;
        };
      };
    };
  }
}

export default function Login() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [paymentUrls, setPaymentUrls] = useState<Partial<Record<PaymentProvider, string>>>({});
  // Oferta de pago del 402: pasarelas + pay_token. El link se pide al hacer clic.
  const [payOffer, setPayOffer] = useState(NO_PAYMENT_OFFER);
  const [payingWith, setPayingWith] = useState<PaymentProvider | null>(null);
  const [payError, setPayError] = useState<string | null>(null);
  const [openedPayUrl, setOpenedPayUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [orgSlug, setOrgSlug] = useState("");
  // Despues de crear la cuenta: QR del MFA para vincularla (ver MfaSetupCard).
  const [mfaSetup, setMfaSetup] = useState<{ enrollment: MfaEnrollOut; token: string } | null>(null);
  const setTokens = useAuthStore((s) => s.setTokens);
  const navigate = useNavigate();
  const googleButtonRef = useRef<HTMLDivElement>(null);
  const lang = useLangStore((s) => s.lang);

  // El login (email/password, Google o SSO) devuelve 402 cuando la
  // organizacion no tiene la suscripcion al dia (ver
  // _reject_if_org_inactive en auth-service/app/main.py). Ese 402 trae
  // el "detail" como objeto ({message, payment_url, payment_urls}), no como
  // string plano -- payment_urls trae un link por pasarela (PayPal y/o
  // Mercado Pago) armado por el servidor central de licencias si esta
  // configurado, o vacio si esta
  // instalacion todavia gestiona los pagos a mano (ahi solo se muestra
  // el mensaje, sin boton).
  function applyLoginError(err: unknown, fallback: string) {
    // Logica de interpretacion del error extraida a utils/loginError.ts
    // (funcion pura, testeada sin renderizar este componente) -- aca solo
    // queda volcar el resultado al estado del formulario.
    const { message, paymentUrls: urls } = parseLoginError(err, fallback);
    setError(message);
    setPaymentUrls(urls);
    setPayOffer(parsePaymentOffer(err));
    setPayError(null);
    setOpenedPayUrl(null);
  }

  function clearPayment() {
    setPaymentUrls({});
    setPayOffer(NO_PAYMENT_OFFER);
    setPayError(null);
    setOpenedPayUrl(null);
  }

  // Genera el link RECIEN ahora, solo de la pasarela elegida (no al fallar el
  // login): asi no quedan links viejos pagables que puedan cobrar dos veces.
  async function handlePay(provider: PaymentProvider) {
    if (!payOffer.payToken || payingWith) return;
    setPayingWith(provider);
    setPayError(null);
    try {
      const url = await requestBlockedPaymentLink(payOffer.payToken, provider);
      if (!isHttpUrl(url)) throw new Error("link invalido");
      setOpenedPayUrl(url);
      window.open(url, "_blank", "noopener,noreferrer");
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setPayError(typeof detail === "string" && detail ? detail : "No se pudo generar el link de pago. Intenta de nuevo en un momento.");
    } finally {
      setPayingWith(null);
    }
  }

  function handleSsoLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!orgSlug.trim()) return;
    // Redirect completo del navegador (no XHR/fetch): auth-service arma la
    // URL de autorizacion del proveedor OIDC de esta organizacion y
    // redirige para alla; el flujo entero pasa por fuera de esta SPA hasta
    // volver a /sso/callback con los tokens en el fragmento de la URL.
    const cs = generateClientState();
    if (!storeClientState(cs)) {
      setError("Tu navegador bloquea el almacenamiento de sesion; el login SSO no puede completarse de forma segura.");
      return;
    }
    window.location.href = `${AUTH_BASE_URL}/auth/oidc/${encodeURIComponent(orgSlug.trim())}/login?cs=${encodeURIComponent(cs)}`;
  }

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID || !googleButtonRef.current) return;

    async function handleGoogleCredential(response: { credential: string }) {
      setLoading(true);
      setError(null);
      clearPayment();
      try {
        const tokens = await loginWithGoogle(response.credential);
        setTokens(tokens.access_token, tokens.refresh_token);
        navigate("/");
      } catch (err) {
        applyLoginError(err, "No se pudo iniciar sesion con Google.");
      } finally {
        setLoading(false);
      }
    }

    // El script de Google puede tardar un instante en cargar; reintenta
    // un par de veces antes de rendirse en vez de asumir que ya esta listo.
    let attempts = 0;
    const tryInit = () => {
      if (window.google?.accounts?.id && googleButtonRef.current) {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCredential,
        });
        window.google.accounts.id.renderButton(googleButtonRef.current, {
          theme: "outline",
          size: "large",
          width: 280,
          text: "continue_with",
          locale: GOOGLE_LOCALES[lang],
        });
      } else if (attempts < 20) {
        attempts += 1;
        setTimeout(tryInit, 250);
      }
    };
    tryInit();
  }, [navigate, setTokens, lang]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    clearPayment();
    try {
      const tokens = await login(email, password, totpCode || undefined);
      setTokens(tokens.access_token, tokens.refresh_token);
      // Si la cuenta todavia no tiene MFA, se lleva directo a "Seguridad de la
      // cuenta" para que vea el QR y lo active (si falla la consulta, entra normal).
      let needsMfaSetup = false;
      try {
        needsMfaSetup = !(await mfaStatus());
      } catch {
        needsMfaSetup = false;
      }
      navigate(needsMfaSetup ? "/security" : "/", needsMfaSetup ? { state: { firstLogin: true } } : undefined);
    } catch (err) {
      applyLoginError(err, "Credenciales invalidas o MFA requerido.");
    } finally {
      setLoading(false);
    }
  }

  // Auto-registro (ver POST /auth/register): crea el usuario como
  // "analyst" en la organizacion "default" (el primer usuario que exista
  // en toda la base queda de admin solo). Justo despues, loguea con las
  // mismas credenciales -- asi quien se registra entra directo, sin tener
  // que volver a escribir el email/contrasena en el formulario de login.
  async function handleRegisterSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    clearPayment();
    // BUG (corregido aca): antes esto envolvia register() Y el login()
    // posterior en el mismo try/catch, asi que si la cuenta se creaba bien
    // pero el login automatico fallaba (ej. 402 porque la organizacion
    // "default" no tiene la suscripcion al dia), el usuario veia "No se
    // pudo crear la cuenta" -- un mensaje falso, la cuenta SI se creo -- y
    // nunca se le mostraba el link de pago (a diferencia del login manual,
    // que si usa parseLoginError/paymentUrl). Ahora cada paso tiene su
    // propio catch: uno para el registro en si, y otro (con la misma
    // logica de 402 que el login normal) para el login automatico que le
    // sigue.
    try {
      const created = await register(email, password, fullName);
      // El QR se muestra YA, en esta misma pantalla, sin depender de que el login funcione
      // (si la suscripcion esta vencida el login da 402 y el MFA igual queda vinculado).
      setMfaSetup({ enrollment: created.mfa_setup, token: created.mfa_setup_token });
    } catch (err) {
      const axiosErr = err as { response?: { data?: { detail?: unknown } } };
      const detail = axiosErr?.response?.data?.detail;
      setError(
        typeof detail === "string"
          ? detail
          : "No se pudo crear la cuenta. Revisa que el email no este ya registrado y que la contrasena tenga al menos 12 caracteres.",
      );
    } finally {
      setLoading(false);
    }
  }

  // Entra con las credenciales recien creadas. Si falla (ej. 402 por suscripcion vencida) vuelve
  // al formulario de login mostrando el motivo y el boton de pago; la cuenta y el MFA ya existen.
  async function enterAfterRegister(totp: string | undefined, next: () => void) {
    try {
      const tokens = await login(email, password, totp);
      setTokens(tokens.access_token, tokens.refresh_token);
      next();
    } catch (err) {
      setMfaSetup(null);
      setMode("login");
      setPassword("");
      setTotpCode("");
      applyLoginError(err, "La cuenta se creo, pero no se pudo iniciar sesion automaticamente. Ingresa con tu email y contrasena.");
    }
  }

  async function handleMfaConfirm(code: string) {
    if (!mfaSetup) return;
    await confirmRegistrationMfa(mfaSetup.token, code); // si el codigo es invalido lanza y la tarjeta lo muestra
    await enterAfterRegister(code, () => navigate("/"));
  }

  async function handleMfaSkip() {
    await enterAfterRegister(undefined, () => navigate("/security", { state: { firstLogin: true } }));
  }

  function toggleMode() {
    setMode((m) => (m === "login" ? "register" : "login"));
    setError(null);
    clearPayment();
  }

  return (
    <div className="app-shell">
      <LanguageSwitcher floating />
      <section className="login-hero" aria-hidden="true">
        <div className="sidebar-brand">
          <BrandMark />
          <span className="brand-name">
            TERO Security
            <small>Defensive platform</small>
          </span>
        </div>
        <div>
          <h2>
            Toda tu seguridad defensiva, <em>en un solo lugar</em>.
          </h2>
          <p>
            Inventario, escaneos, vulnerabilidades, SIEM, SOAR y casos en una plataforma que corre en tu propia
            infraestructura.
          </p>
        </div>
        <ul className="login-points">
          <li><Icon name="lock" /> Se instala en tu propia infraestructura</li>
          <li><Icon name="shield" /> Multi-organizacion, roles y MFA</li>
          <li><Icon name="activity" /> Deteccion, respuesta y reportes</li>
        </ul>
        <span className="login-copy">TERO Security</span>
      </section>
      <div className="login-side">
      {mfaSetup ? (
        <MfaSetupCard
          enrollment={mfaSetup.enrollment}
          onConfirm={handleMfaConfirm}
          onSkip={handleMfaSkip}
        />
      ) : (
      <form className="login-card" onSubmit={mode === "login" ? handleSubmit : handleRegisterSubmit}>
        <h1>{mode === "login" ? "Bienvenido" : "Crea tu cuenta"}</h1>
        <p>{mode === "login" ? "Ingresa a la plataforma de seguridad de TERO Security" : "Crear una cuenta nueva en TERO Security"}</p>

        {mode === "register" && (
          <div className="field">
            <label htmlFor="full-name">Nombre completo</label>
            <input id="full-name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
        )}

        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>

        <div className="field">
          <label htmlFor="password">{mode === "register" ? "Contrasena (minimo 12 caracteres)" : "Contrasena"}</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={mode === "register" ? 12 : undefined}
            required
          />
        </div>

        {mode === "login" && (
          <p className="empty-hint" style={{ margin: "-4px 0 12px", textAlign: "right" }}>
            <button
              type="button"
              className="btn-link"
              onClick={() => navigate("/olvide-mi-contrasena", { state: { email: email.trim() } })}
            >
              ¿Olvidaste tu contrasena?
            </button>
          </p>
        )}

        {mode === "login" && (
          <div className="field">
            <label htmlFor="totp">Codigo MFA de 6 digitos (si lo activaste)</label>
            <input id="totp" type="text" inputMode="numeric" autoComplete="one-time-code" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="123456" />
          </div>
        )}

        <button
          className="btn-primary"
          type="submit"
          disabled={loading || (mode === "register" && password.length > 0 && password.length < 12)}
        >
          {mode === "login" ? (loading ? "Ingresando..." : "Ingresar") : loading ? "Creando cuenta..." : "Crear cuenta"}
        </button>

        {error && <p className="error-text">{error}</p>}

        {payOffer.payToken && payOffer.providers.length > 0 && (
          <>
            {PAYMENT_PROVIDERS.filter((p) => payOffer.providers.includes(p.id)).map((p) => (
              <button
                key={p.id}
                type="button"
                className="btn-primary"
                disabled={payingWith !== null}
                onClick={() => handlePay(p.id)}
                style={{ marginTop: 8 }}
              >
                {payingWith === p.id
                  ? "Generando link..."
                  : payOffer.providers.length > 1
                    ? `Pagar con ${p.label}`
                    : "Pagar membresia"}
              </button>
            ))}
            {payError && <p className="error-text">{payError}</p>}
            {openedPayUrl && (
              <p className="empty-hint" style={{ marginTop: 8 }}>
                Si no se abrio la pagina de pago,{" "}
                <a href={openedPayUrl} target="_blank" rel="noopener noreferrer">
                  abrila desde aca
                </a>
                .
              </p>
            )}
            <p className="empty-hint" style={{ marginTop: 8 }}>
              Se abre la pagina de pago en una pestana nueva. Despues de pagar, esperá un minuto y volvé a
              intentar ingresar -- el acceso se reactiva solo, no hace falta avisarle a nadie.
            </p>
          </>
        )}

        {Object.keys(paymentUrls).length > 0 && (
          <>
            {PAYMENT_PROVIDERS.filter((p) => paymentUrls[p.id]).map((p) => (
              <a
                key={p.id}
                className="btn-primary"
                href={paymentUrls[p.id]}
                target="_blank"
                rel="noopener noreferrer"
                style={{ marginTop: 8 }}
              >
                {Object.keys(paymentUrls).length > 1 ? `Pagar con ${p.label}` : "Pagar membresia"}
              </a>
            ))}
            <p className="empty-hint" style={{ marginTop: 8 }}>
              Se abre la pagina de pago en una pestana nueva. Despues de pagar, esperá un minuto y volvé a
              intentar ingresar -- el acceso se reactiva solo, no hace falta avisarle a nadie.
            </p>
          </>
        )}

        <p className="empty-hint" style={{ marginTop: 12 }}>
          {mode === "login" ? "¿No tenes cuenta todavia? " : "¿Ya tenes cuenta? "}
          <button type="button" className="btn-link" onClick={toggleMode}>
            {mode === "login" ? "Creala con tu email" : "Iniciar sesion"}
          </button>
        </p>

        {mode === "login" && GOOGLE_CLIENT_ID && (
          <div className="google-signin-wrap">
            <div className="divider"><span>o</span></div>
            <div ref={googleButtonRef} />
          </div>
        )}

        {mode === "login" && (
          <>
            <div className="divider"><span>o</span></div>
            <div className="field">
              <label htmlFor="org-slug">SSO empresarial (tu organizacion)</label>
              <input
                id="org-slug"
                value={orgSlug}
                onChange={(e) => setOrgSlug(e.target.value)}
                placeholder="slug de tu organizacion, ej. acme-corp"
              />
            </div>
            <button className="btn-secondary" type="button" onClick={handleSsoLogin} disabled={!orgSlug.trim()}>
              Continuar con SSO
            </button>
          </>
        )}
      </form>
      )}
      </div>
    </div>
  );
}
