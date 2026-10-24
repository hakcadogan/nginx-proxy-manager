import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, User } from "./api";
import HelpTip from "./components/HelpTip";
import LoginPage from "./pages/LoginPage";
import HostsPage from "./pages/HostsPage";
import ConfigPage from "./pages/ConfigPage";
import SSLPage from "./pages/SSLPage";
import LBPage from "./pages/LBPage";
import WAFPage from "./pages/WAFPage";
import IDSPage from "./pages/IDSPage";
import RatePage from "./pages/RatePage";
import DashboardPage from "./pages/DashboardPage";
import UsersPage from "./pages/UsersPage";

const titles: Record<string, string> = {
  "/": "dashboard",
  "/hosts": "hosts",
  "/lb": "lbPools",
  "/waf": "waf",
  "/ids": "ids",
  "/rate": "rateLimits",
  "/ssl": "ssl",
  "/config": "config",
  "/users": "users",
};

const pageHelp: Record<string, string> = {
  "/": "helpDashboard",
  "/hosts": "helpHosts",
  "/lb": "helpLB",
  "/waf": "helpWaf",
  "/ids": "helpIds",
  "/rate": "helpRate",
  "/ssl": "helpSsl",
  "/config": "helpConfig",
  "/users": "helpUsers",
};

export default function App() {
  const { t, i18n } = useTranslation();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [navOpen, setNavOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    api<{ user: User }>("/api/v1/auth/me")
      .then((d) => setUser(d.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  // Close drawer on route change
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  // Escape closes drawer; lock body scroll while open
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNavOpen(false);
    };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [navOpen]);

  async function logout() {
    await api("/api/v1/auth/logout", { method: "POST" });
    setUser(null);
    setNavOpen(false);
    navigate("/login");
  }

  function setLang(lng: string) {
    void i18n.changeLanguage(lng);
    localStorage.setItem("nsp_lang", lng);
  }

  if (loading) {
    return <div className="shell muted">{t("loading")}</div>;
  }

  const pageKey = titles[location.pathname] || "dashboard";
  const helpKey = pageHelp[location.pathname];

  return (
    <Routes>
      <Route
        path="/login"
        element={
          user ? (
            <Navigate to="/" replace />
          ) : (
            <LoginPage onAuthed={(u) => setUser(u)} />
          )
        }
      />
      <Route
        path="/*"
        element={
          !user ? (
            <Navigate to="/login" replace />
          ) : (
            <div className={`app-frame ${navOpen ? "nav-open" : ""}`}>
              <div
                className="nav-backdrop"
                hidden={!navOpen}
                onClick={() => setNavOpen(false)}
                aria-hidden="true"
              />
              <aside className="sidebar" id="app-sidebar">
                <div className="sidebar-brand">
                  <div className="brand">NSP</div>
                  <div className="brand-sub">{t("appName")}</div>
                  <button
                    type="button"
                    className="icon-btn ghost sidebar-close"
                    aria-label={t("closeMenu")}
                    onClick={() => setNavOpen(false)}
                  >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                      <path d="M18 6 6 18" />
                      <path d="m6 6 12 12" />
                    </svg>
                  </button>
                </div>
                <nav className="side-nav" aria-label="Main">
                  <NavLink to="/" end>
                    {t("dashboard")}
                  </NavLink>
                  <NavLink to="/hosts">{t("hosts")}</NavLink>
                  <NavLink to="/lb">{t("lbPools")}</NavLink>
                  <NavLink to="/waf">{t("waf")}</NavLink>
                  <NavLink to="/ids">{t("ids")}</NavLink>
                  <NavLink to="/rate">{t("rateLimits")}</NavLink>
                  <NavLink to="/ssl">{t("ssl")}</NavLink>
                  <NavLink to="/config">{t("config")}</NavLink>
                  {user.role === "admin" && <NavLink to="/users">{t("users")}</NavLink>}
                </nav>
                <div className="sidebar-foot">
                  <div className="user-chip">
                    <strong title={user.email}>{user.email}</strong>
                    <span className="muted">{user.role}</span>
                  </div>
                  <div className="row sidebar-foot-actions">
                    <label className="lang-label muted">
                      {t("language")}
                      <select
                        value={i18n.language.startsWith("tr") ? "tr" : "en"}
                        onChange={(e) => setLang(e.target.value)}
                        aria-label={t("language")}
                      >
                        <option value="tr">TR</option>
                        <option value="en">EN</option>
                      </select>
                    </label>
                    <button type="button" className="secondary" onClick={() => void logout()}>
                      {t("logout")}
                    </button>
                  </div>
                </div>
              </aside>
              <div className="main-col">
                <header className="topbar">
                  <div className="topbar-start">
                    <button
                      type="button"
                      className="icon-btn secondary menu-toggle"
                      aria-label={t("openMenu")}
                      aria-expanded={navOpen}
                      aria-controls="app-sidebar"
                      onClick={() => setNavOpen(true)}
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                        <path d="M4 6h16" />
                        <path d="M4 12h16" />
                        <path d="M4 18h16" />
                      </svg>
                    </button>
                    <div className="page-title heading-with-help">
                      {t(pageKey)}
                      {helpKey ? <HelpTip text={t(helpKey)} placement="below" /> : null}
                    </div>
                  </div>
                </header>
                <main className="content">
                  <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/hosts" element={<HostsPage />} />
                    <Route path="/lb" element={<LBPage />} />
                    <Route path="/waf" element={<WAFPage />} />
                    <Route path="/ids" element={<IDSPage />} />
                    <Route path="/rate" element={<RatePage />} />
                    <Route path="/ssl" element={<SSLPage />} />
                    <Route path="/config" element={<ConfigPage />} />
                    <Route path="/users" element={<UsersPage currentUser={user} />} />
                  </Routes>
                </main>
              </div>
            </div>
          )
        }
      />
    </Routes>
  );
}
