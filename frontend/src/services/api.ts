import axios, { AxiosInstance } from "axios";
import { useAuthStore } from "../store/auth";

function serviceUrl(envVar: string, port: number): string {
  const fromEnv = (import.meta.env as Record<string, string | undefined>)[envVar];
  return fromEnv ?? `http://localhost:${port}`;
}

function makeClient(baseURL: string): AxiosInstance {
  const client = axios.create({ baseURL });
  client.interceptors.request.use((config) => {
    const token = useAuthStore.getState().accessToken;
    if (token) {
      config.headers = config.headers ?? {};
      (config.headers as Record<string, string>).Authorization = `Bearer ${token}`;
    }
    return config;
  });
  return client;
}

// Cada microservicio corre en su propio puerto (ver docker-compose.yml);
// en produccion detras de un API gateway/reverse proxy estas URLs se
// reemplazan por variables de entorno VITE_*_SERVICE_URL en build time.
// Mismo esquema de nombres que ya definia .env.example en Fase 1
// (VITE_API_BASE_URL, VITE_ASSET_API_BASE_URL, etc.) -- se completan aca
// las variables para los servicios agregados en Fases 3-5.
export const authApi = makeClient(serviceUrl("VITE_API_BASE_URL", 8001));
export const assetApi = makeClient(serviceUrl("VITE_ASSET_API_BASE_URL", 8002));
export const scanApi = makeClient(serviceUrl("VITE_SCAN_API_BASE_URL", 8003));
export const vulnApi = makeClient(serviceUrl("VITE_VULN_API_BASE_URL", 8004));
export const siemApi = makeClient(serviceUrl("VITE_SIEM_API_BASE_URL", 8005));
export const soarApi = makeClient(serviceUrl("VITE_SOAR_API_BASE_URL", 8006));
export const caseApi = makeClient(serviceUrl("VITE_CASE_API_BASE_URL", 8007));
export const purpleApi = makeClient(serviceUrl("VITE_PURPLE_API_BASE_URL", 8008));
export const reportApi = makeClient(serviceUrl("VITE_REPORT_API_BASE_URL", 8009));
export const notificationApi = makeClient(serviceUrl("VITE_NOTIFICATION_API_BASE_URL", 8010));
export const integrationApi = makeClient(serviceUrl("VITE_INTEGRATION_API_BASE_URL", 8011));

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export async function loginWithGoogle(credential: string): Promise<TokenPair> {
  const { data } = await authApi.post<TokenPair>("/auth/google", { credential });
  return data;
}

export async function login(email: string, password: string, totpCode?: string): Promise<TokenPair> {
  const { data } = await authApi.post<TokenPair>("/auth/login", {
    email,
    password,
    totp_code: totpCode ?? null,
  });
  return data;
}
