import { useEffect, useRef, useState } from "react";
import Icon from "./Icon";
import { PAYMENT_PROVIDERS, type PaymentProvider } from "../utils/payment";

interface Props {
  open: boolean;
  // Pasarela cuyo link se esta generando ahora (deshabilita los botones).
  pendingProvider: PaymentProvider | null;
  error: string | null;
  onSelect: (provider: PaymentProvider, payerEmail?: string) => void;
  onClose: () => void;
}

// Ventana chica, centrada, para elegir con que pasarela pagar. Es un dialogo
// modal accesible: cierra con Escape o clic afuera, el foco entra al primer
// boton y vuelve al boton que la abrio, y el fondo no scrollea mientras esta
// abierta.
export default function PaymentMethodModal({ open, pendingProvider, error, onSelect, onClose }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [mpEmail, setMpEmail] = useState("");
  const busy = pendingProvider !== null;

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    dialogRef.current?.querySelector<HTMLElement>("button.pay-option")?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !dialogRef.current) return;
      // Mantiene el foco adentro del dialogo.
      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>("button:not(:disabled), input, summary, a[href]"),
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div ref={dialogRef} className="modal" role="dialog" aria-modal="true" aria-labelledby="pay-modal-title">
        <div className="modal-head">
          <h2 id="pay-modal-title">Elegi como pagar</h2>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Cerrar">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <p className="empty-hint" style={{ marginTop: 0 }}>
          Se abre la pagina de pago en una pestana nueva.
        </p>

        <div className="pay-options">
          {PAYMENT_PROVIDERS.map((p) => (
            <button
              key={p.id}
              type="button"
              className="pay-option"
              disabled={busy}
              onClick={() => onSelect(p.id, p.id === "mercadopago" ? mpEmail.trim() || undefined : undefined)}
            >
              <span className="pay-option-icon">
                <Icon name={p.id === "paypal" ? "surface" : "card"} />
              </span>
              <span className="pay-option-text">
                <strong>{pendingProvider === p.id ? "Generando link..." : p.label}</strong>
                <small>{p.hint}</small>
              </span>
            </button>
          ))}
        </div>

        <details className="pay-extra">
          <summary>¿Tu cuenta de Mercado Pago usa otro email?</summary>
          <label htmlFor="mp-email">Email de tu cuenta de Mercado Pago (opcional)</label>
          <input
            id="mp-email"
            type="email"
            autoComplete="email"
            maxLength={254}
            value={mpEmail}
            onChange={(e) => setMpEmail(e.target.value)}
            placeholder="tu-cuenta@mercadopago.com"
          />
        </details>

        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
