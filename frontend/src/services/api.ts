import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8001";

export const api = axios.create({ baseURL });

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export async function login(email: string, password: string, totpCode?: string): Promise<TokenPair> {
  const { data } = await api.post<TokenPair>("/auth/login", {
    email,
    password,
    totp_code: totpCode ?? null,
  });
  return data;
}
