// Descarga de archivos generados por la API (zip, py, csv...): se piden con el token (axios, blob) y se guardan.
import type { AxiosResponse } from "axios";

export function saveBlob(resp: AxiosResponse<Blob>, fallbackName: string): string {
  const disposition = String(resp.headers["content-disposition"] ?? "");
  const name = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(resp.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return name;
}
