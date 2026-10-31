import type { ReactNode } from "react";
import Icon, { BrandMark } from "./Icon";
import { LanguageSwitcher } from "../i18n";

// Marco de las pantallas publicas de la cuenta (olvide / restablecer contrasena):
// el mismo panel de marca que el login y la tarjeta a la derecha.
export default function AuthShell({ children }: { children: ReactNode }) {
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
      <div className="login-side">{children}</div>
    </div>
  );
}
