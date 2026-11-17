import { useEffect, useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";
import AuthShell from "../components/AuthShell";
import { connectionErrorDetail } from "../utils/errors";
import { groupByDomain, unanswered, type PublicAssessment } from "../utils/vendors";
import { t } from "../i18n";

// Pagina PUBLICA (sin login): la abre el proveedor desde el link que recibio. No usa los clientes de api.ts a
// proposito: esos mandan el token de sesion y reaccionan a un 401 cerrando sesion; aca no hay sesion.
const caseBase = (import.meta.env as Record<string, string | undefined>).VITE_CASE_API_BASE_URL ?? "http://localhost:8007";

const OPTIONS: [string, string][] = [["yes", "Si"], ["partial", "Parcialmente"], ["no", "No"], ["na", "No aplica"]];

export default function VendorQuestionnaire() {
  const { token = "" } = useParams();
  const [data, setData] = useState<PublicAssessment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [comments, setComments] = useState<Record<string, string>>({});
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [sending, setSending] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let alive = true;
    axios.get<PublicAssessment>(`${caseBase}/public/vendor-assessments/${encodeURIComponent(token)}`)
      .then((r) => { if (alive) setData(r.data); })
      .catch((e) => { if (alive) setError(axios.isAxiosError(e) && e.response?.status === 404 ? t("Este link no existe o ya no es valido.") : connectionErrorDetail(e)); });
    return () => { alive = false; };
  }, [token]);

  const missing = data ? unanswered(data.questions, answers) : 0;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!data) return;
    setSending(true);
    setError(null);
    try {
      const body = Object.fromEntries(data.questions.map((q) => [q.id, { answer: answers[q.id], comment: comments[q.id] ?? "" }]));
      await axios.post(`${caseBase}/public/vendor-assessments/${encodeURIComponent(token)}`, {
        respondent_name: name.trim(), respondent_email: email.trim(), answers: body,
      });
      setDone(true);
    } catch (err) {
      setError(connectionErrorDetail(err));
    } finally {
      setSending(false);
    }
  }

  const closed = data && data.state !== "sent";
  return (
    <AuthShell>
      <div className="login-card" style={{ maxWidth: 820, width: "100%" }}>
        <h1>Cuestionario de seguridad</h1>
        {!data && !error && <p className="empty-hint">Cargando...</p>}
        {error && <p className="error-text"><span className="error-detail">{error}</span></p>}
        {done && <p className="empty-hint"><strong>Gracias.</strong> {t("Recibimos tus respuestas. Ya podes cerrar esta pagina.")}</p>}
        {data && closed && !done && (
          <p className="empty-hint">
            {data.state === "completed" && t("Este cuestionario ya fue respondido. Gracias.")}
            {data.state === "expired" && t("Este link vencio. Pedi uno nuevo a quien te lo envio.")}
            {data.state === "cancelled" && t("Este cuestionario fue cancelado. Pedi uno nuevo a quien te lo envio.")}
          </p>
        )}
        {data && !closed && !done && (
          <form onSubmit={submit}>
            <p>{t("{0} te pidio que respondas estas preguntas sobre como protegen la informacion. Lleva unos 15 minutos. Responde con lo que realmente hacen hoy: si algo no se cumple, marcalo asi.", data.vendor_name)}</p>
            <p className="empty-hint">{t("Tus respuestas se guardan junto a tu nombre y email. El link vale hasta el {0} y se usa una sola vez.", data.expires_at ? new Date(data.expires_at).toLocaleDateString() : "-")}</p>
            <div className="field"><label htmlFor="vq-name">Tu nombre y cargo</label><input id="vq-name" value={name} maxLength={255} onChange={(e) => setName(e.target.value)} required /></div>
            <div className="field"><label htmlFor="vq-email">Tu email</label><input id="vq-email" type="email" value={email} maxLength={255} onChange={(e) => setEmail(e.target.value)} required /></div>
            {groupByDomain(data.questions).map(([domain, qs]) => (
              <fieldset key={domain} style={{ border: "1px solid var(--border)", borderRadius: 8, margin: "14px 0", padding: 12 }}>
                <legend><strong>{t(domain)}</strong></legend>
                {qs.map((q) => (
                  <div key={q.id} style={{ marginBottom: 14 }}>
                    <div>{t(q.text)}</div>
                    <div role="radiogroup" aria-label={t(q.text)} style={{ display: "flex", gap: 14, flexWrap: "wrap", margin: "4px 0" }}>
                      {OPTIONS.map(([value, label]) => (
                        <label key={value} className="gov-row-check">
                          <input type="radio" name={q.id} value={value} checked={answers[q.id] === value} onChange={() => setAnswers({ ...answers, [q.id]: value })} /> {t(label)}
                        </label>
                      ))}
                    </div>
                    <input type="text" maxLength={500} placeholder={t("Comentario (opcional)")} value={comments[q.id] ?? ""} style={{ width: "100%" }}
                      onChange={(e) => setComments({ ...comments, [q.id]: e.target.value })} aria-label={t("Comentario (opcional)")} />
                  </div>
                ))}
              </fieldset>
            ))}
            <button className="btn-primary" type="submit" disabled={sending || missing > 0 || name.trim().length < 2 || !email.trim()}>
              {sending ? t("Enviando...") : missing > 0 ? t("Faltan {0} preguntas por responder", missing) : t("Enviar respuestas")}
            </button>
          </form>
        )}
      </div>
    </AuthShell>
  );
}
