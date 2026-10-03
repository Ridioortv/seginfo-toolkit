import { useEffect, useState } from "react";

// Umbral tomado del mismo limite que usa el backend para recuperar un job
// "assigned" huerfano (ver el recovery de 10 min en
// scan-service/app/services.py, agent_can_claim_job): pasado ese tiempo
// otro agente bootstrap puede tomar el job como red de contencion, asi
// que avisamos ANTES de que eso pase en vez de que el usuario se entere
// por un mensaje de error que no tiene nada que ver con la causa real.
const SLOW_WARNING_MS = 8 * 60 * 1000;

function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  if (m <= 0) return `${s}s`;
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

// Barra de progreso indeterminada (no hay % real posible: ni el agente ni
// los scanners externos reportan avance parcial) para escaneos que
// todavia estan en curso (trivy/nuclei, locales o via agente). Sirve
// para distinguir "esta corriendo" de "se colgo" a simple vista, y el
// tiempo transcurrido (que tiquea solo, independiente del refetch de la
// tabla) confirma que la pagina sigue viva.
export function RunningIndicator({ since, label }: { since: string | null; label?: string }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  if (!since) {
    return (
      <div className="progress-wrap">
        <div className="progress-track">
          <div className="progress-bar" />
        </div>
        <span className="progress-label">en cola, esperando que lo tomen...</span>
      </div>
    );
  }

  const elapsedMs = now - new Date(since).getTime();
  const isSlow = elapsedMs > SLOW_WARNING_MS;

  return (
    <div className="progress-wrap">
      <div className={isSlow ? "progress-track progress-track-warn" : "progress-track"}>
        <div className="progress-bar" />
      </div>
      <span className="progress-label">
        {(label ?? "corriendo") + " hace " + formatElapsed(elapsedMs)}
        {isSlow ? " -- tarda mas de lo usual" : ""}
      </span>
    </div>
  );
}
