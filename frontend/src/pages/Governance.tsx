import { useState } from "react";
import PageHeader from "../components/PageHeader";
import Overview from "./governance/Overview";
import Provenance from "./governance/Provenance";
import Gate from "./governance/Gate";
import Ledger from "./governance/Ledger";
import Policies from "./governance/Policies";

type Tab = "overview" | "provenance" | "gate" | "ledger" | "policies";

const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Resumen" },
  { key: "provenance", label: "Procedencia" },
  { key: "gate", label: "Compuerta" },
  { key: "ledger", label: "Registro auditable" },
  { key: "policies", label: "Politicas" },
];

// Gobernanza de codigo con IA: quien escribio cada cambio (persona o IA), si paso revision y la
// compuerta de seguridad, politicas por equipo y un registro firmado e inalterable.
export default function Governance() {
  const [tab, setTab] = useState<Tab>("overview");
  return (
    <div>
      <PageHeader
        title="Gobernanza de IA en el codigo"
        subtitle="Quien escribio cada cambio (persona o IA), si paso la revision y la compuerta de seguridad, y un registro firmado que nadie puede alterar sin que se note"
      />
      <div className="tabs" role="tablist">
        {TABS.map((x) => (
          <button key={x.key} role="tab" aria-selected={tab === x.key} className={`tab${tab === x.key ? " active" : ""}`} onClick={() => setTab(x.key)}>
            {x.label}
          </button>
        ))}
      </div>
      {tab === "overview" && <Overview goTo={setTab} />}
      {tab === "provenance" && <Provenance />}
      {tab === "gate" && <Gate />}
      {tab === "ledger" && <Ledger />}
      {tab === "policies" && <Policies />}
    </div>
  );
}
