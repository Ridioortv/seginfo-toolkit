/** Estado del almacenamiento de logs del SIEM (GET /logs/storage-status del siem-service). */
export type LogStorageStatus = {
  writable: boolean;
  disk_full: boolean;
  disk_used_percent: number | null;
  message: string | null;
};

/** Mensaje que muestra el panel cuando OpenSearch dejo de aceptar logs por falta de disco. */
export const DISK_FULL_MESSAGE = "El disco de la PC está casi lleno: OpenSearch dejó de aceptar logs. Liberá espacio.";

/** Texto del aviso, o null si no hay nada que avisar (estado desconocido = no inventar alarmas). */
export function diskWarning(status: LogStorageStatus | null | undefined): string | null {
  if (!status || !status.disk_full) return null;
  const detalle = status.disk_used_percent != null ? ` (disco al ${Math.round(status.disk_used_percent)} %)` : "";
  return `${status.message ?? DISK_FULL_MESSAGE}${detalle}`;
}

/** True si un error de axios es el 503 "disk_full" del siem-service (ingesta rechazada por disco lleno). */
export function isDiskFullError(error: unknown): boolean {
  const resp = (error as { response?: { status?: number; data?: { code?: string } } } | null)?.response;
  return resp?.status === 503 && resp?.data?.code === "disk_full";
}
