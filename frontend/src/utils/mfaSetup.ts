// Paso "vincular el MFA" al crear la cuenta (Login.tsx -> MfaSetupCard).

/** Codigo TOTP: 6 digitos (se ignoran los espacios que algunas apps muestran: "123 456"). */
export function normalizeTotp(code: string): string {
  return code.replace(/\s+/g, "");
}

/** Problema del codigo escrito (texto en espanol) o null si tiene pinta de valido. */
export function totpProblem(code: string): string | null {
  const c = normalizeTotp(code);
  if (!/^\d{6}$/.test(c)) return "El codigo tiene 6 digitos, los que muestra tu app de autenticacion.";
  return null;
}

/** La clave secreta en grupos de 4 para leerla/copiarla mejor ("ABCD EFGH ..."). */
export function groupSecret(secret: string): string {
  return secret.replace(/\s+/g, "").replace(/(.{4})/g, "$1 ").trim();
}
