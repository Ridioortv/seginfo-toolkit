import { useEffect, useRef } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import { scanApi } from "../services/api";
import type { OpenvasStatusOut, OpenvasProgressOut } from "../types";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard" },
  { to: "/assets", label: "Activos" },
  { to: "/scans", label: "Escaneos" },
  { to: "/openvas-dashboard", label: "Dashboard OpenVAS" },
  { to: "/vulnerabilities", label: "Vulnerabilidades" },
  { to: "/siem", label: "SIEM" },
  { to: "/soar", label: "SOAR" },
  { to: "/cases", label: "Casos" },
  { to: "/purple-team", label: "Purple Team" },
  { to: "/reports", label: "Reportes" },
  { to: "/notifications", label: "Notificaciones" },
  { to: "/integrations", label: "Integraciones" },
];

export default function Layout() {
  const claims = useAuthStore((s) => s.claims);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();

  function handleLogout() {
    logout();
    navigate("/login");
  }

  // Abrir el dashboard de OpenVAS solo cuando termina de activarse --
  // ANTES esto vivia adentro de Scans.tsx, atado a que ese componente
  // siguiera montado y a un flag local (autoActivating) que se perdia si
  // el usuario recargaba la pagina o se iba a otra pantalla mientras
  // esperaba (la activacion real, del lado del orquestador, puede tardar
  // 20-40 min la primera vez -- nada raro que el usuario reincida o
  // recargue en el medio). Puesto aca en Layout (montado siempre que hay
  // sesion, en cualquier pantalla) el aviso funciona sin importar donde
  // este el usuario ni si recargo a mitad de camino.
  const canPollOpenvasProgress = claims?.role === "admin" || claims?.role === "soc_manager";

  const openvasStatus = useQuery({
    queryKey: ["openvas-status"],
    queryFn: async () => (await scanApi.get<OpenvasStatusOut>("/openvas/status")).data,
    refetchInterval: 15_000,
    retry: false,
  });

  // Consulta el progreso del ORQUESTADOR (no de este componente): su
  // estado vive del lado del servidor, asi que "resucita" solo la barra
  // de progreso/deteccion de listo aunque nadie haya seguido mirando esta
  // pestaña desde que se disparo la activacion.
  const openvasProgress = useQuery({
    queryKey: ["openvas-progress"],
    queryFn: async () => (await scanApi.get<OpenvasProgressOut>("/openvas/auto-activate/progress")).data,
    enabled: canPollOpenvasProgress && !openvasStatus.data?.ready,
    refetchInterval: 5000,
    retry: false,
  });

  useEffect(() => {
    if (openvasProgress.data?.ready) {
      queryClient.setQueryData(["openvas-status"], {
        configured: true,
        ready: true,
        detail: openvasProgress.data.detail,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openvasProgress.data]);

  // Detecta la TRANSICION de "no listo" a "listo" (nunca navega solo
  // porque en el primer chequeo ya estaba activo -- eso pasaria cada vez
  // que alguien entra a la app con OpenVAS ya andando de antes, y seria
  // muy molesto). seenFirst evita disparar en el snapshot inicial.
  const seenFirstStatus = useRef(false);
  const wasReady = useRef(false);
  useEffect(() => {
    if (!openvasStatus.isSuccess) return;
    const nowReady = openvasStatus.data.ready;
    if (!seenFirstStatus.current) {
      seenFirstStatus.current = true;
      wasReady.current = nowReady;
      return;
    }
    if (nowReady && !wasReady.current && location.pathname !== "/openvas-dashboard") {
      navigate("/openvas-dashboard");
    }
    wasReady.current = nowReady;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openvasStatus.data, openvasStatus.isSuccess]);

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">SentinelOps</div>
        <nav>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => "nav-link" + (isActive ? " nav-link-active" : "")}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="layout-main">
        <header className="topbar">
          <span className="topbar-user">{claims?.sub ?? "usuario"} &middot; {claims?.role ?? "sin rol"}</span>
          <button className="btn-secondary" onClick={handleLogout}>Salir</button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
