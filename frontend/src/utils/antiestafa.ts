// Integracion con AntiEstafa AR (avisos de estafas que revisaron las personas). Ver docs/integracion-antiestafa.md.

export interface AntiEstafaStatus {
  organization_id: string;
  ingest_path: string;
  window_days: number;
  rules: { expected: number; active: number; missing: string[] };
  reports: number;
  by_outcome: Record<string, number>;
  by_channel: Record<string, number>;
  top_domains: { domain: string; count: number }[];
  campaigns: { key: string; reports: number; at: string | null }[];
  last_report_at: string | null;
  last_received: { at: string; test: boolean } | null;
  campaign_threshold: { reports: number; hours: number };
}

export const CHANNEL_LABEL: Record<string, string> = {
  mensaje: "Mensaje",
  captura: "Captura",
  audio: "Audio",
  link: "Link",
  qr: "QR",
  bot: "Bot de WhatsApp",
  otro: "Otro",
};

export const OUTCOME_LABEL: Record<string, string> = {
  estafa: "Estafa",
  sospechoso: "Sospechoso",
};

/** "dominio:x.example" -> "x.example"; "huella:abc" -> null (la huella no es un dato para mostrar como destino). */
export function campaignTarget(key: string): { kind: "dominio" | "mensaje"; value: string } {
  const [kind, ...rest] = key.split(":");
  const value = rest.join(":");
  return kind === "dominio" ? { kind: "dominio", value } : { kind: "mensaje", value };
}

/** Bloque de variables para el proyecto de Vercel de la empresa (las que pide AntiEstafa). */
export function vercelEnvBlock(publicUrl: string, token: string, organizationId: string, ingestPath: string): string {
  const base = publicUrl.trim().replace(/\/+$/, "") || "https://tero.tu-empresa.com.ar/api/siem";
  return [
    `TERO_SIEM_URL=${base}${ingestPath}`,
    `TERO_API_KEY=${token || "<token de ingesta>"}`,
    `TERO_ORGANIZACION=${organizationId}`,
    "TERO_INCLUIR_TEXTO=false",
  ].join("\n");
}

export function sumCounts(counts: Record<string, number>): number {
  return Object.values(counts).reduce((a, b) => a + b, 0);
}
