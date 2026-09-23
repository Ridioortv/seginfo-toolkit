import axios from "axios";

/**
 * Convierte cualquier error de una llamada a un microservicio en un
 * texto legible con el detalle real (status HTTP, mensaje del backend,
 * o el motivo de que no haya habido respuesta), en vez de un generico
 * "no se pudo conectar" que no permite distinguir un contenedor caido
 * de un 401/403/500. Pensado para mostrarse debajo del mensaje
 * amigable, asi el usuario puede copiar/pegar el detalle si necesita
 * soporte.
 */
export function connectionErrorDetail(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.response) {
      const detail =
        typeof error.response.data === "object" && error.response.data !== null && "detail" in error.response.data
          ? String((error.response.data as { detail?: unknown }).detail)
          : JSON.stringify(error.response.data);
      return `HTTP ${error.response.status}: ${detail}`.slice(0, 300);
    }
    if (error.code === "ERR_NETWORK" || error.message?.toLowerCase().includes("network")) {
      return `Sin respuesta (${error.message}) -- el contenedor de este servicio probablemente no esta corriendo o todavia se esta reiniciando.`;
    }
    if (error.code === "ECONNABORTED" || error.message?.toLowerCase().includes("timeout")) {
      return `Tiempo de espera agotado (${error.message}).`;
    }
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
