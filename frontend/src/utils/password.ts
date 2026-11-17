// Reglas de la contrasena nueva (las mismas que valida auth-service: 12 a 128 caracteres).
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

// Mensaje del servidor para "Olvide mi contrasena": es el mismo exista o no el email.
export const FORGOT_PASSWORD_MESSAGE =
  "Si el email corresponde a una cuenta, te enviamos un link para restablecer la contrasena. Revisa tambien la carpeta de spam.";

/** Primer problema de la contrasena nueva (texto en espanol, listo para mostrar) o null si esta bien. */
export function passwordProblem(password: string, repeat: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return "La contrasena tiene que tener al menos 12 caracteres.";
  if (password.length > MAX_PASSWORD_LENGTH) return "La contrasena puede tener hasta 128 caracteres.";
  if (password !== repeat) return "Las contrasenas no coinciden.";
  return null;
}

/** Token del link "/restablecer?token=..." (vacio si falta). */
export function tokenFromSearch(search: string): string {
  return new URLSearchParams(search).get("token")?.trim() ?? "";
}
