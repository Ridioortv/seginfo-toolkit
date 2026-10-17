// Proteccion contra login-CSRF en el flujo SSO (OIDC): antes de redirigir al proveedor la SPA
// guarda un valor aleatorio en sessionStorage y lo manda como `cs`; auth-service lo devuelve en
// el fragmento de /sso/callback. La SPA solo instala la sesion si el valor coincide, asi que un
// link armado por un atacante (/sso/callback#access_token=...) NO le inicia sesion a la victima
// en la cuenta del atacante (el atacante no conoce el valor guardado en el navegador de la victima).
const KEY = "sentinelops_sso_cs";

export interface StateStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function defaultStore(): StateStore | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function generateClientState(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function storeClientState(value: string, store: StateStore | null = defaultStore()): boolean {
  if (!store) return false;
  try {
    store.setItem(KEY, value);
    return true;
  } catch {
    return false;
  }
}

/** True solo si `received` coincide con el valor guardado. Es de un solo uso: siempre lo borra. */
export function consumeClientState(received: string | null, store: StateStore | null = defaultStore()): boolean {
  if (!store) return false;
  let expected: string | null = null;
  try {
    expected = store.getItem(KEY);
    store.removeItem(KEY);
  } catch {
    return false;
  }
  return !!expected && !!received && expected.length === received.length && expected === received;
}
