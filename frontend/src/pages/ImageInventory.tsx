import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { scanApi } from "../services/api";
import type { ImageInventoryItem } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

const MODE_LABELS: Record<string, string> = {
  image: "Imagen",
  fs: "Filesystem",
  upload: "Archivo subido",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function matchesImageSearch(item: ImageInventoryItem, search: string): boolean {
  if (!search) return true;
  const needle = search.toLowerCase();
  if (item.target.toLowerCase().includes(needle)) return true;
  return item.packages.some((p) => p.name.toLowerCase().includes(needle));
}

export default function ImageInventory() {
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [packageFilter, setPackageFilter] = useState("");

  const images = useQuery({
    queryKey: ["scan-images"],
    queryFn: async () => (await scanApi.get<ImageInventoryItem[]>("/scan-images")).data,
  });

  const filtered = useMemo(() => {
    const rows = images.data ?? [];
    return rows.filter((i) => matchesImageSearch(i, search));
  }, [images.data, search]);

  const totals = useMemo(() => {
    const rows = images.data ?? [];
    return {
      images: rows.length,
      packages: rows.reduce((acc, i) => acc + i.package_count, 0),
      vulnerabilities: rows.reduce((acc, i) => acc + i.vulnerability_count, 0),
    };
  }, [images.data]);

  const expandedImage = filtered.find((i) => i.target === expandedTarget) ?? null;
  const expandedPackages = useMemo(() => {
    if (!expandedImage) return [];
    const needle = packageFilter.toLowerCase();
    if (!needle) return expandedImage.packages;
    return expandedImage.packages.filter(
      (p) => p.name.toLowerCase().includes(needle) || (p.version ?? "").toLowerCase().includes(needle)
    );
  }, [expandedImage, packageFilter]);

  return (
    <div>
      <PageHeader
        title="Imagenes y Paquetes"
        subtitle="Inventario de imagenes de contenedor y filesystems escaneados con trivy -- TODOS los paquetes detectados, no solo los que tienen una vulnerabilidad conocida"
      />

      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Imagenes escaneadas</span>
          <span className="stat-value">{totals.images}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Paquetes (total)</span>
          <span className="stat-value">{totals.packages}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Vulnerabilidades (total)</span>
          <span className="stat-value">{totals.vulnerabilities}</span>
        </div>
      </div>

      <div className="panel">
        <p className="empty-hint">
          Cada fila es la imagen o archivo escaneado mas reciente con trivy (subido en "Escaneos" -&gt; "Escanear
          imagen o paquete con Trivy", o un escaneo normal contra una imagen de registro). Reescanear la misma
          imagen actualiza su inventario en vez de duplicarlo.
        </p>

        <div className="inline-form">
          <input
            placeholder="Buscar por imagen o paquete..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ minWidth: 260 }}
          />
          {search && (
            <button className="btn-link" onClick={() => setSearch("")}>
              Limpiar
            </button>
          )}
        </div>

        {images.isLoading && <p className="empty-hint">Cargando...</p>}
        {images.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(images.error)}</span>
          </p>
        )}
        {images.data && images.data.length === 0 && (
          <p className="empty-hint">
            Todavia no hay ninguna imagen escaneada con trivy. Anda a "Escaneos" y subi una imagen (.tar de
            `docker save`) o un manifiesto de dependencias, o lanza un escaneo trivy normal contra una imagen de
            registro.
          </p>
        )}
        {images.data && images.data.length > 0 && (
          <>
            <p className="empty-hint" style={{ marginTop: 8 }}>
              Mostrando {filtered.length} de {images.data.length} imagen(es){search ? " (con filtro aplicado)" : ""}.
            </p>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Imagen / archivo</th>
                  <th>Modo</th>
                  <th>Paquetes</th>
                  <th>Vulnerabilidades</th>
                  <th>Ultimo escaneo</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => {
                  const isExpanded = expandedTarget === item.target;
                  return (
                    <Fragment key={item.target}>
                      <tr>
                        <td className="mono">{item.target}</td>
                        <td>{MODE_LABELS[item.mode] ?? item.mode}</td>
                        <td>{item.package_count}</td>
                        <td>
                          {item.vulnerability_count === 0 ? (
                            "-"
                          ) : (
                            <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
                              {SEVERITY_ORDER.filter((sev) => item.vulnerabilities_by_severity[sev]).map((sev) => (
                                <span key={sev} title={`${item.vulnerabilities_by_severity[sev]} ${sev}`}>
                                  <SeverityBadge value={sev} />{" "}
                                  <span className="mono">{item.vulnerabilities_by_severity[sev]}</span>
                                </span>
                              ))}
                            </span>
                          )}
                        </td>
                        <td>{item.scanned_at ? new Date(item.scanned_at).toLocaleString() : "-"}</td>
                        <td>
                          <button
                            className="btn-link"
                            onClick={() => {
                              setPackageFilter("");
                              setExpandedTarget(isExpanded ? null : item.target);
                            }}
                          >
                            {isExpanded ? "Ocultar paquetes" : "Ver paquetes"}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan={6}>
                            <div className="panel" style={{ margin: 0 }}>
                              <div className="inline-form">
                                <input
                                  placeholder="Filtrar paquetes por nombre o version..."
                                  value={packageFilter}
                                  onChange={(e) => setPackageFilter(e.target.value)}
                                  style={{ minWidth: 240 }}
                                />
                              </div>
                              <p className="empty-hint">
                                Mostrando {expandedPackages.length} de {item.package_count} paquete(s).
                              </p>
                              <table className="data-table">
                                <thead>
                                  <tr>
                                    <th>Paquete</th>
                                    <th>Version</th>
                                    <th>Tipo</th>
                                    <th>Arquitectura</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {expandedPackages.map((pkg, idx) => (
                                    <tr key={`${pkg.name}-${pkg.version}-${idx}`}>
                                      <td className="mono">{pkg.name}</td>
                                      <td className="mono">{pkg.version || "-"}</td>
                                      <td>{pkg.type || "-"}</td>
                                      <td>{pkg.arch || "-"}</td>
                                    </tr>
                                  ))}
                                  {expandedPackages.length === 0 && (
                                    <tr>
                                      <td colSpan={4} className="empty-hint">
                                        Ningun paquete coincide con el filtro.
                                      </td>
                                    </tr>
                                  )}
                                </tbody>
                              </table>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
