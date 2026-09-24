import { useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import { useAuthStore } from "../store/auth";
import { HELP_TOPICS } from "./help/content";
import { filterHelpTopics, progressPercent } from "../utils/help";

const READ_STORAGE_KEY = "sentinelops_help_read_topics";

function loadReadIds(): Set<string> {
  try {
    const raw = localStorage.getItem(READ_STORAGE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? new Set(parsed) : new Set();
  } catch {
    return new Set();
  }
}

function saveReadIds(ids: Set<string>) {
  try {
    localStorage.setItem(READ_STORAGE_KEY, JSON.stringify(Array.from(ids)));
  } catch {
    // localStorage puede no estar disponible (modo privado, etc.) -- no es critico.
  }
}

export default function Help() {
  const claims = useAuthStore((s) => s.claims);
  const canSeeAdminTopics = claims?.role === "admin" || claims?.platform_admin === true;

  const visibleTopics = useMemo(
    () => HELP_TOPICS.filter((t) => !t.adminOnly || canSeeAdminTopics),
    [canSeeAdminTopics]
  );

  const [readIds, setReadIds] = useState<Set<string>>(() => loadReadIds());
  const [query, setQuery] = useState("");
  const [activeId, setActiveId] = useState<string>(visibleTopics[0]?.id ?? "");

  const filteredTopics = useMemo(() => filterHelpTopics(visibleTopics, query), [visibleTopics, query]);
  const activeTopic = visibleTopics.find((t) => t.id === activeId) ?? visibleTopics[0];

  const readCount = visibleTopics.filter((t) => readIds.has(t.id)).length;
  const percent = progressPercent(visibleTopics.length, readCount);

  function selectTopic(id: string) {
    setActiveId(id);
  }

  function toggleRead(id: string) {
    setReadIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      saveReadIds(next);
      return next;
    });
  }

  return (
    <div>
      <PageHeader
        title="Ayuda"
        subtitle="Una guia interactiva, en espanol simple, de que hace cada seccion de SentinelOps y como usarla -- sin necesidad de escribir codigo."
      />

      <div className="panel">
        <div className="help-progress-row">
          <span className="stat-hint">
            Progreso de la guia: {readCount}/{visibleTopics.length} secciones leidas
          </span>
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${percent}%` }} />
          </div>
          <span className="stat-hint">{percent}%</span>
        </div>
      </div>

      <div className="help-layout">
        <div className="panel help-topic-list">
          <input
            className="help-search"
            placeholder="Buscar en la guia (ej. 'escaneo', 'regla', 'canal')..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <nav className="help-nav">
            {filteredTopics.map((t) => (
              <button
                key={t.id}
                className={"help-topic-btn" + (activeTopic?.id === t.id ? " help-topic-btn-active" : "")}
                onClick={() => selectTopic(t.id)}
              >
                <span>{t.label}</span>
                {readIds.has(t.id) && <span className="badge badge-success">Leido</span>}
              </button>
            ))}
            {filteredTopics.length === 0 && <p className="empty-hint">Sin resultados para esa busqueda.</p>}
          </nav>
        </div>

        <div className="panel help-content">
          {activeTopic && (
            <>
              <h2>{activeTopic.label}</h2>
              <p className="help-tagline">{activeTopic.tagline}</p>
              <p>{activeTopic.overview}</p>

              <ol className="help-steps">
                {activeTopic.steps.map((step, idx) => (
                  <li key={idx}>
                    <strong>{step.title}</strong>
                    <p>{step.body}</p>
                  </li>
                ))}
              </ol>

              {activeTopic.tips && activeTopic.tips.length > 0 && (
                <div className="help-tips">
                  <h3>Tips</h3>
                  <ul>
                    {activeTopic.tips.map((tip, idx) => (
                      <li key={idx}>{tip}</li>
                    ))}
                  </ul>
                </div>
              )}

              <button className="btn-secondary" onClick={() => toggleRead(activeTopic.id)}>
                {readIds.has(activeTopic.id) ? "Marcar como no leida" : "Marcar esta seccion como leida"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
