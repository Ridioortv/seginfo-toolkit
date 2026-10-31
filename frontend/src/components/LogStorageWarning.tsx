import { useQuery } from "@tanstack/react-query";
import { siemApi } from "../services/api";
import { diskWarning, type LogStorageStatus } from "../utils/logStorage";

/**
 * Aviso de "disco casi lleno": cuando OpenSearch pasa del 95 % de uso del disco deja de aceptar
 * logs (el SIEM contesta 503). Se consulta cada minuto y solo se muestra si hay problema; si el
 * endpoint no responde no se dice nada (el banner de "servicio caido" ya cubre ese caso).
 */
export default function LogStorageWarning() {
  const storage = useQuery({
    queryKey: ["siem-storage-status"],
    queryFn: async () => (await siemApi.get<LogStorageStatus>("/logs/storage-status")).data,
    refetchInterval: 60_000,
    retry: false,
  });
  const texto = diskWarning(storage.data);
  if (!texto) return null;
  return (
    <div className="panel" role="alert" style={{ borderColor: "var(--warning)", background: "var(--warning-soft)" }}>
      <p style={{ margin: 0 }}>
        <b>Disco casi lleno.</b> {texto}
      </p>
    </div>
  );
}
