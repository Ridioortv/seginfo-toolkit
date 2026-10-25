import { useState } from "react";
import PageHeader from "../components/PageHeader";
import Custody from "./trust/Custody";

type Tab = "custody";

const TABS: { key: Tab; label: string }[] = [
  { key: "custody", label: "Cadena de custodia" },
];

// Confianza y evidencia: lo que TERO puede demostrarle a un tercero (auditor, cliente, juez) sin pedirle que confie.
export default function Trust() {
  const [tab, setTab] = useState<Tab>("custody");
  return (
    <div>
      <PageHeader
        title="Confianza y evidencia"
        subtitle="Pruebas que TERO puede entregarle a un auditor, a un cliente o a un juez, y que se pueden verificar sin confiar en nosotros"
      />
      <div className="tabs" role="tablist">
        {TABS.map((x) => (
          <button key={x.key} role="tab" aria-selected={tab === x.key} className={`tab${tab === x.key ? " active" : ""}`} onClick={() => setTab(x.key)}>
            {x.label}
          </button>
        ))}
      </div>
      {tab === "custody" && <Custody />}
    </div>
  );
}
