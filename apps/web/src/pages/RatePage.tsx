import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type Profile = {
  id: string;
  name: string;
  requests_per_second: number;
  burst: number;
  connections_per_ip: number;
  retry_after_seconds: number;
};

export default function RatePage() {
  const { t } = useTranslation();
  const [items, setItems] = useState<Profile[]>([]);
  const [ipActive, setIpActive] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const emptyForm = () => ({
    name: "",
    requests_per_second: 10,
    burst: 20,
    connections_per_ip: 20,
    retry_after_seconds: 1,
  });
  const [form, setForm] = useState(emptyForm);
  const [editing, setEditing] = useState<string | null>(null);

  async function load() {
    const data = await api<{ items: Profile[]; ip_rate_active?: boolean }>("/api/v1/rate-limits");
    setItems(data.items || []);
    setIpActive(!!data.ip_rate_active);
  }

  useEffect(() => {
    load().catch((e) => setError(String(e.message || e)));
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    try {
      if (editing) {
        await api(`/api/v1/rate-limits/${editing}`, {
          method: "PATCH",
          body: JSON.stringify(form),
        });
      } else {
        await api("/api/v1/rate-limits", { method: "POST", body: JSON.stringify(form) });
      }
      setForm(emptyForm());
      setEditing(null);
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function remove(p: Profile) {
    if (!window.confirm(t("confirmDeleteNamed", { name: p.name }))) return;
    setError("");
    setOk("");
    try {
      await api(`/api/v1/rate-limits/${p.id}`, { method: "DELETE" });
      if (editing === p.id) {
        setEditing(null);
        setForm(emptyForm());
      }
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  function startEdit(p: Profile) {
    setEditing(p.id);
    setForm({
      name: p.name,
      requests_per_second: p.requests_per_second,
      burst: p.burst,
      connections_per_ip: p.connections_per_ip,
      retry_after_seconds: p.retry_after_seconds || 1,
    });
  }

  return (
    <div className="grid two">
      <section className="panel">
        <h2 className="heading-with-help">
          {t("rateLimits")}
          <HelpTip text={t("helpRate")} />
        </h2>
        {!ipActive && <div className="callout warn">{t("rateNeedsTrustedProxies")}</div>}
        {error && <p className="error">{error}</p>}
        {ok && <p className="ok">{ok}</p>}
        <table className="table">
          <thead>
            <tr>
              <th>{t("name")}</th>
              <th>
                <span className="heading-with-help">
                  RPS
                  <HelpTip text={t("helpRps")} />
                </span>
              </th>
              <th>
                <span className="heading-with-help">
                  Burst
                  <HelpTip text={t("helpBurst")} />
                </span>
              </th>
              <th>
                <span className="heading-with-help">
                  {t("connPerIp")}
                  <HelpTip text={t("helpConnPerIp")} />
                </span>
              </th>
              <th>
                <span className="heading-with-help">
                  {t("retryAfter")}
                  <HelpTip text={t("helpRetryAfter")} />
                </span>
              </th>
              <th>{t("actions")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>{p.requests_per_second}</td>
                <td>{p.burst}</td>
                <td>{p.connections_per_ip}</td>
                <td>{p.retry_after_seconds ?? 1}s</td>
                <td className="row" style={{ gap: 6 }}>
                  <button type="button" className="secondary" onClick={() => startEdit(p)}>
                    {t("edit")}
                  </button>
                  <button type="button" className="danger" onClick={() => void remove(p)}>
                    {t("delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted" style={{ marginTop: "1rem" }}>
          {t("ratePageHint")}
        </p>
      </section>
      <section className="panel">
        <h2>{editing ? t("edit") : t("createRateProfile")}</h2>
        <form className="stack" onSubmit={(e) => void onSubmit(e)}>
          <div>
            <label>{t("name")}</label>
            <input
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div>
            <label className="heading-with-help">
              RPS
              <HelpTip text={t("helpRps")} />
            </label>
            <input
              type="number"
              min={0.1}
              step={0.1}
              value={form.requests_per_second}
              onChange={(e) => setForm({ ...form, requests_per_second: Number(e.target.value) })}
            />
          </div>
          <div>
            <label className="heading-with-help">
              Burst
              <HelpTip text={t("helpBurst")} />
            </label>
            <input
              type="number"
              min={0}
              value={form.burst}
              onChange={(e) => setForm({ ...form, burst: Number(e.target.value) })}
            />
          </div>
          <div>
            <label className="heading-with-help">
              {t("connPerIp")}
              <HelpTip text={t("helpConnPerIp")} />
            </label>
            <input
              type="number"
              min={1}
              value={form.connections_per_ip}
              onChange={(e) => setForm({ ...form, connections_per_ip: Number(e.target.value) })}
            />
          </div>
          <div>
            <label className="heading-with-help">
              {t("retryAfter")}
              <HelpTip text={t("helpRetryAfter")} />
            </label>
            <input
              type="number"
              min={1}
              max={3600}
              value={form.retry_after_seconds}
              onChange={(e) => setForm({ ...form, retry_after_seconds: Number(e.target.value) })}
            />
          </div>
          <div className="row">
            <button type="submit">{t("save")}</button>
            {editing && (
              <button
                type="button"
                className="secondary"
                onClick={() => {
                  setEditing(null);
                  setForm(emptyForm());
                }}
              >
                {t("cancelEdit")}
              </button>
            )}
          </div>
        </form>
      </section>
    </div>
  );
}
