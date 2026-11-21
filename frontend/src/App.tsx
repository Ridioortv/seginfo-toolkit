import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import Dashboard from "./pages/Dashboard";
const Assets = lazy(() => import("./pages/Assets"));
const Scans = lazy(() => import("./pages/Scans"));
const ImageInventory = lazy(() => import("./pages/ImageInventory"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const Siem = lazy(() => import("./pages/Siem"));
const Surface = lazy(() => import("./pages/Surface"));
const Cloud = lazy(() => import("./pages/Cloud"));
const CodeRepos = lazy(() => import("./pages/CodeRepos"));
const Trust = lazy(() => import("./pages/Trust"));
const Executive = lazy(() => import("./pages/Executive"));
const Partner = lazy(() => import("./pages/Partner"));
const Governance = lazy(() => import("./pages/Governance"));
const Soar = lazy(() => import("./pages/Soar"));
const Cases = lazy(() => import("./pages/Cases"));
const PurpleTeam = lazy(() => import("./pages/PurpleTeam"));
const Reports = lazy(() => import("./pages/Reports"));
const Notifications = lazy(() => import("./pages/Notifications"));
const Integrations = lazy(() => import("./pages/Integrations"));
const Help = lazy(() => import("./pages/Help"));
const Organizations = lazy(() => import("./pages/Organizations"));
const Security = lazy(() => import("./pages/Security"));
const Billing = lazy(() => import("./pages/Billing"));
const Users = lazy(() => import("./pages/Users"));
const SsoCallback = lazy(() => import("./pages/SsoCallback"));
const VendorQuestionnaire = lazy(() => import("./pages/VendorQuestionnaire"));
import { useLangStore } from "./i18n";

export default function App() {
  // Al cambiar de idioma se vuelve a montar el arbol: asi fechas, mensajes y
  // todo lo calculado en JS se regeneran de cero en el idioma nuevo.
  const lang = useLangStore((s) => s.lang);
  return (
    <BrowserRouter key={lang}>
      {/* Cada pagina se descarga recien al abrirla (antes todo iba en un solo archivo de 1,4 MB). */}
      <Suspense fallback={<div className="loading" style={{ padding: 24 }}>Cargando...</div>}>
      <Routes>
        <Route path="/login" element={<Login />} />
        {/* Publicas: "Olvide mi contrasena" y el link del mail para elegir la nueva. */}
        <Route path="/olvide-mi-contrasena" element={<ForgotPassword />} />
        <Route path="/restablecer" element={<ResetPassword />} />
        {/* Fuera de ProtectedRoute a proposito: llega directo desde el
            proveedor de identidad externo (redirect de auth-service), sin
            tokens todavia -- los guarda ella misma antes de redirigir
            adentro de la app. Ver app/main.py::oidc_callback. */}
        <Route path="/sso/callback" element={<SsoCallback />} />
        {/* Publica: el proveedor responde el cuestionario de seguridad desde el link que recibio. */}
        <Route path="/proveedor/:token" element={<VendorQuestionnaire />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scan-images" element={<ImageInventory />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/siem" element={<Siem />} />
            <Route path="/surface" element={<Surface />} />
            <Route path="/cloud" element={<Cloud />} />
            <Route path="/code-repos" element={<CodeRepos />} />
            <Route path="/ai-governance" element={<Governance />} />
            <Route path="/executive" element={<Executive />} />
            <Route path="/partner" element={<Partner />} />
            <Route path="/trust" element={<Trust />} />
            <Route path="/soar" element={<Soar />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/purple-team" element={<PurpleTeam />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/security" element={<Security />} />
            <Route path="/help" element={<Help />} />
            <Route path="/organizations" element={<Organizations />} />
            <Route path="/billing" element={<Billing />} />
            <Route path="/users" element={<Users />} />
          </Route>
        </Route>
      </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
