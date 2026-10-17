import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/auth";
import Icon, { BrandMark, type IconName } from "./Icon";
import { currentTheme, toggleTheme, type Theme } from "../utils/theme";

type NavItem = { to: string; label: string; icon: IconName };
type NavGroup = { label: string; items: NavItem[] };

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Resumen",
    items: [{ to: "/", label: "Dashboard", icon: "dashboard" }],
  },
  {
    label: "Inventario y exposicion",
    items: [
      { to: "/assets", label: "Activos", icon: "assets" },
      { to: "/scans", label: "Escaneos", icon: "scans" },
      { to: "/scan-images", label: "Imagenes y Paquetes", icon: "images" },
      { to: "/surface", label: "Superficie Externa", icon: "surface" },
      { to: "/cloud", label: "Integraciones Cloud", icon: "cloud" },
      { to: "/code-repos", label: "Código y Repositorios", icon: "code" },
    ],
  },
  {
    label: "Deteccion y respuesta",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilidades", icon: "bug" },
      { to: "/siem", label: "SIEM", icon: "activity" },
      { to: "/soar", label: "SOAR", icon: "zap" },
      { to: "/cases", label: "Casos", icon: "briefcase" },
      { to: "/purple-team", label: "Purple Team", icon: "target" },
    ],
  },
  {
    label: "Gestion",
    items: [
      { to: "/reports", label: "Reportes", icon: "file" },
      { to: "/notifications", label: "Notificaciones", icon: "bell" },
      { to: "/integrations", label: "Integraciones", icon: "plug" },
    ],
  },
  {
    label: "Cuenta",
    items: [
      { to: "/security", label: "Seguridad de la cuenta", icon: "shield" },
      { to: "/help", label: "Ayuda", icon: "help" },
    ],
  },
];

// Solo un admin de organizacion (administra su propia empresa: usuarios,
// SSO, facturacion) o un platform_admin (administra la plataforma entera:
// crea organizaciones nuevas, ve/administra la facturacion de cualquiera)
// necesita estas tres paginas -- ver Organizations.tsx, Billing.tsx y
// dependencies.py::require_platform_admin/require_org_admin_or_platform_admin.
const ADMIN_GROUP: NavGroup = {
  label: "Administracion",
  items: [
    { to: "/users", label: "Usuarios y roles", icon: "users" },
    { to: "/organizations", label: "Organizaciones", icon: "building" },
    { to: "/billing", label: "Pagos y licencia", icon: "card" },
  ],
};

function pageTitle(pathname: string, groups: NavGroup[]): string {
  const all = groups.flatMap((g) => g.items);
  const exact = all.find((i) => i.to === pathname);
  if (exact) return exact.label;
  const prefix = all.filter((i) => i.to !== "/" && pathname.startsWith(i.to + "/"));
  return prefix[0]?.label ?? "TERO Security";
}

function initials(name: string | undefined): string {
  const base = (name ?? "").split("@")[0].replace(/[^a-zA-Z0-9]+/g, " ").trim();
  if (!base) return "?";
  const parts = base.split(" ");
  return ((parts[0][0] ?? "") + (parts[1]?.[0] ?? parts[0][1] ?? "")).toUpperCase();
}

export default function Layout() {
  const claims = useAuthStore((s) => s.claims);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const location = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => currentTheme());

  const canManageOrganizations = claims?.role === "admin" || claims?.platform_admin === true;
  const groups = canManageOrganizations ? [...NAV_GROUPS, ADMIN_GROUP] : NAV_GROUPS;

  // El drawer movil se cierra solo al navegar y con Escape.
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navOpen]);

  function handleLogout() {
    logout();
    navigate("/login");
  }

  const username = claims?.sub ?? "usuario";

  return (
    <div className={"layout" + (navOpen ? " layout-nav-open" : "")}>
      <aside className="sidebar" id="main-nav" aria-label="Navegacion principal">
        <div className="sidebar-brand">
          <BrandMark />
          <span className="brand-name">
            TERO Security
            <small>Defensive platform</small>
          </span>
        </div>
        <nav>
          {groups.map((group) => (
            <div key={group.label} style={{ display: "contents" }}>
              <div className="nav-group-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) => "nav-link" + (isActive ? " nav-link-active" : "")}
                >
                  <Icon name={item.icon} />
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="status-dot" aria-hidden="true" />
          Sesion activa y cifrada
        </div>
      </aside>
      <div className="sidebar-backdrop" onClick={() => setNavOpen(false)} aria-hidden="true" />
      <div className="layout-main">
        <header className="topbar">
          <button
            type="button"
            className="icon-btn menu-btn"
            aria-label="Abrir menu"
            aria-controls="main-nav"
            aria-expanded={navOpen}
            onClick={() => setNavOpen((o) => !o)}
          >
            <Icon name="menu" />
          </button>
          <span className="topbar-title">{pageTitle(location.pathname, groups)}</span>
          <span className="topbar-spacer" />
          <button
            type="button"
            className="icon-btn"
            onClick={() => setTheme(toggleTheme())}
            aria-label={theme === "dark" ? "Cambiar a tema claro" : "Cambiar a tema oscuro"}
            title={theme === "dark" ? "Tema claro" : "Tema oscuro"}
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} />
          </button>
          <div className="topbar-user">
            <span className="avatar" aria-hidden="true">{initials(claims?.sub)}</span>
            <span className="topbar-user-text">
              <span className="topbar-user-name">{username}</span>
              <span className="topbar-user-role">{claims?.role ?? "sin rol"}</span>
            </span>
          </div>
          <button type="button" className="icon-btn" onClick={handleLogout} aria-label="Salir" title="Salir">
            <Icon name="logout" />
          </button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
