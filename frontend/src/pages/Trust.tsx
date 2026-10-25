import { useState } from "react";
import PageHeader from "../components/PageHeader";
import Custody from "./trust/Custody";
import Sovereignty from "./trust/Sovereignty";
import Closure from "./trust/Closure";
import Compliance from "./trust/Compliance";
import Drills from "./trust/Drills";
import { useAuthStore } from "../store/auth";

type Tab = "custody" | "sovereignty" | "closure" | "compliance" | "drills";

const TABS: { key: Tab; label: string; roles?: string[] }[] = [
  { key: "custody", label: "Cadena de custodia" },
  { key: "sovereignty", label: "Soberania", roles: ["admin", "soc_manager"] },
  { key: "closure", label: "Cierre verificado" },
  { key: "compliance", label: "Cumplimiento", roles: ["admin", "soc_manager", "analyst"] },
  { key: "drills", label: "Simulacros" },
];

// Confianza y evidencia: lo que TERO puede demostrarle a un tercero (auditor, cliente, juez) sin pedirle que confie.
export default function Trust() {
  const [tab, setTab] = useState<Tab>("custody");
  const role = useAuthStore((s) => s.claims?.role) ?? "";
  const tabs = TABS.filter((x) => !x.roles || x.roles.includes(role));
  return (
    <div>
      <PageHeader
        title="Confianza y evidencia"
        subtitle="Pruebas que TERO puede entregarle a un auditor, a un cliente o a un juez, y que se pueden verificar sin confiar en nosotros"
      />
      <div className="tabs" role="tablist">
        {tabs.map((x) => (
          <button key={x.key} role="tab" aria-selected={tab === x.key} className={`tab${tab === x.key ? " active" : ""}`} onClick={() => setTab(x.key)}>
            {x.label}
          </button>
        ))}
      </div>
      {tab === "custody" && <Custody />}
      {tab === "sovereignty" && <Sovereignty />}
      {tab === "closure" && <Closure />}
      {tab === "compliance" && <Compliance />}
      {tab === "drills" && <Drills />}
    </div>
  );
}
