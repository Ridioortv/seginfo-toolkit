import { create } from "zustand";

export interface Claims {
  sub: string;
  role: string;
  exp: number;
  [key: string]: unknown;
}

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  claims: Claims | null;
  setTokens: (access: string, refresh: string) => void;
  logout: () => void;
}

const STORAGE_KEY = "sentinelops_auth";

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

export const useAuthStore = create<AuthState>((set) => ({
  ...loadInitial(),
  setTokens: (accessToken: string, refreshToken: string) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ accessToken, refreshToken }));
    set({ accessToken, refreshToken, claims: decodeClaims(accessToken) });
  },
  logout: () => {
    localStorage.removeItem(STORAGE_KEY);
    set({ accessToken: null, refreshToken: null, claims: null });
  },
}));
