import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type Summary = {
  hosts_total: number;
  hosts_enabled: number;
  upstreams: number;
  members_up: number;
  members_down: number;
  certificates: number;
  certs_expiring_30d: number;
  config_status: string;
  config_version: number;
  users: number;
  generated_at: string;
};

export default function DashboardPage() {
  const { t } = useTranslation();
  const [s, setS] = useState<Summary | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api<Summary>("/api/v1/dashboard")
      .then(setS)
      .catch((e) => setErr(e instanceof Error ? e.message : "error"));
  }, []);

  if (err) return <div className="error">{err}</div>;
  if (!s) return <div className="muted">{t("loading")}</div>;

  const cards: { label: string; value: string | number; to?: string }[] = [
    { label: t("hosts"), value: `${s.hosts_enabled}/${s.hosts_total}`, to: "/hosts" },
    { label: t("lbPools"), value: s.upstreams, to: "/lb" },
    { label: t("members"), value: `${s.members_up}↑ ${s.members_down}↓`, to: "/lb" },
    { label: t("ssl"), value: `${s.certificates}`, to: "/ssl" },
    {
      label: t("expiry"),
      value: s.certs_expiring_30d,
      to: "/ssl",
    },
    { label: t("config"), value: `v${s.config_version}`, to: "/config" },
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="heading-with-help">
            {t("dashboard")}
            <HelpTip text={t("helpDashboard")} />
          </h1>
          <p className="muted">{s.generated_at}</p>
        </div>
        <Link to="/hosts">
          <button type="button">{t("createHost")}</button>
        </Link>
      </div>
      <div className="kpi-grid">
        {cards.map((c) =>
          c.to ? (
            <Link
              key={c.label}
              to={c.to}
              aria-label={c.label}
              style={{ textDecoration: "none", color: "inherit" }}
            >
              <div className="kpi" aria-hidden="true">
                <div className="label">{c.label}</div>
                <div className="value">{c.value}</div>
              </div>
            </Link>
          ) : (
            <div key={c.label} className="kpi">
              <div className="label">{c.label}</div>
              <div className="value">{c.value}</div>
            </div>
          ),
        )}
      </div>
      <section className="panel" style={{ marginTop: "1.1rem" }}>
        <h2>{t("status")}</h2>
        <p className="muted" style={{ margin: 0 }}>
          {t("config")}: <strong>{s.config_status}</strong> · {t("users")}: {s.users}
        </p>
      </section>
    </>
  );
}
