import { describe, expect, it } from "vitest";
import { DISK_FULL_MESSAGE, diskWarning, isDiskFullError } from "./logStorage";

describe("diskWarning", () => {
  it("no avisa si no hay datos (no inventa alarmas)", () => {
    expect(diskWarning(undefined)).toBeNull();
    expect(diskWarning(null)).toBeNull();
  });

  it("no avisa si el disco esta bien", () => {
    expect(diskWarning({ writable: true, disk_full: false, disk_used_percent: 40, message: null })).toBeNull();
  });

  it("avisa con el mensaje del servidor y el porcentaje", () => {
    const texto = diskWarning({ writable: false, disk_full: true, disk_used_percent: 96.4, message: DISK_FULL_MESSAGE });
    expect(texto).toBe(`${DISK_FULL_MESSAGE} (disco al 96 %)`);
  });

  it("usa el mensaje por defecto si el servidor no lo manda", () => {
    expect(diskWarning({ writable: false, disk_full: true, disk_used_percent: null, message: null })).toBe(DISK_FULL_MESSAGE);
  });
});

describe("isDiskFullError", () => {
  it("reconoce el 503 disk_full", () => {
    expect(isDiskFullError({ response: { status: 503, data: { code: "disk_full", detail: DISK_FULL_MESSAGE } } })).toBe(true);
  });

  it("no confunde otros 503 ni otros errores", () => {
    expect(isDiskFullError({ response: { status: 503, data: { detail: "SIEM_INGEST_TOKEN no esta configurado" } } })).toBe(false);
    expect(isDiskFullError({ response: { status: 500, data: { code: "disk_full" } } })).toBe(false);
    expect(isDiskFullError(new Error("x"))).toBe(false);
    expect(isDiskFullError(null)).toBe(false);
  });
});
