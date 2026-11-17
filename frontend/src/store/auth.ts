import { create } from "zustand";

export interface Claims {
  sub: string;
  email?: string;
  role: string;
  exp: number;
  [key: string]: unknown;
}

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  claims: Claims | null;
  /** Sesion propia del partner mientras esta "dentro" de un cliente (null si no esta dentro de ninguno). */
  partnerSession: { accessToken: string; refreshToken: string } | null;
  setTokens: (access: string, refresh: string) => void;
  /** Entra a un cliente con el token corto que emite auth-service; guarda la sesion propia para poder volver. */
  enterClient: (clientAccessToken: string) => void;
  /** Vuelve a la consola del partner (o cierra sesion si no hay sesion guardada). */
  leaveClient: () => void;
  logout: () => void;
}

const STORAGE_KEY = "sentinelops_auth";
const PARTNER_KEY = "sentinelops_partner_session";

function decodeClaims(token: string): Claims | null {
  try {
    const payload = token.split(".")[1];
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(decodeURIComponent(escape(atob(normalized))));
    return json as Claims;
  } catch {
    return null;
  }
}

function loadInitial(): Pick<AuthState, "accessToken" | "refreshToken" | "claims"> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { accessToken: null, refreshToken: null, claims: null };
    const parsed = JSON.parse(raw) as { accessToken?: string; refreshToken?: string };
    const accessToken = parsed.accessToken ?? null;
    return {
      accessToken,
      refreshToken: parsed.refreshToken ?? null,
      claims: accessToken ? decodeClaims(accessToken) : null,
    };
  } catch {
    return { accessToken: null, refreshToken: null, claims: null };
  }
}

function loadPartnerSession(): AuthState["partnerSession"] {
  try {
    const raw = localStorage.getItem(PARTNER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { accessToken?: string; refreshToken?: string };
    return parsed.accessToken && parsed.refreshToken ? { accessToken: parsed.accessToken, refreshToken: parsed.refreshToken } : null;
  } catch {
    return null;
  }
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  ...loadInitial(),
  partnerSession: loadPartnerSession(),
  setTokens: (accessToken: string, refreshToken: string) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ accessToken, refreshToken }));
    set({ accessToken, refreshToken, claims: decodeClaims(accessToken) });
  },
  enterClient: (clientAccessToken: string) => {
    const { accessToken, refreshToken, partnerSession } = get();
    // si ya esta dentro de un cliente, se conserva la sesion original del partner (no la del cliente)
    const own = partnerSession ?? (accessToken && refreshToken ? { accessToken, refreshToken } : null);
    if (!own) return;
    localStorage.setItem(PARTNER_KEY, JSON.stringify(own));
    // el token de entrada no tiene refresh: cuando vence se vuelve solo a la consola
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ accessToken: clientAccessToken, refreshToken: "" }));
    set({ partnerSession: own, accessToken: clientAccessToken, refreshToken: "", claims: decodeClaims(clientAccessToken) });
  },
  leaveClient: () => {
    const own = get().partnerSession;
    localStorage.removeItem(PARTNER_KEY);
    if (!own) {
      get().logout();
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(own));
    set({ partnerSession: null, accessToken: own.accessToken, refreshToken: own.refreshToken, claims: decodeClaims(own.accessToken) });
  },
  logout: () => {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(PARTNER_KEY);
    set({ accessToken: null, refreshToken: null, claims: null, partnerSession: null });
  },
}));
