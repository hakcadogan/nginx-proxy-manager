import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type Version = {
  id: string;
  version: number;
  checksum: string;
  status: string;
  message: string;
  created_at: string;
};

export default function ConfigPage() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [versions, setVersions] = useState<Version[]>([]);
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [trusted, setTrusted] = useState("");
  const [realIP, setRealIP] = useState("X-Forwarded-For");
  const [netMsg, setNetMsg] = useState("");
  const [logEnabled, setLogEnabled] = useState(true);
  const [logMaxMB, setLogMaxMB] = useState(100);
  const [logKeep, setLogKeep] = useState(7);
  const [logInterval, setLogInterval] = useState(60);
  const [logMsg, setLogMsg] = useState("");

  async function refresh() {
    const [s, v, net, logs] = await Promise.all([
      api<Record<string, unknown>>("/api/v1/config/status"),
      api<{ items: Version[] }>("/api/v1/config/versions"),
      api<{ trusted_proxies: string; real_ip_header: string }>("/api/v1/settings/network"),
      api<{ enabled: boolean; max_mb: number; keep: number; interval_min: number }>("/api/v1/settings/logs"),
    ]);
    setStatus(s);
    setVersions(v.items || []);
    setTrusted(net.trusted_proxies || "");
    setRealIP(net.real_ip_header || "X-Forwarded-For");
    setLogEnabled(!!logs.enabled);
    setLogMaxMB(logs.max_mb || 100);
    setLogKeep(logs.keep || 7);
    setLogInterval(logs.interval_min || 60);
  }

  useEffect(() => {
    refresh().catch((e) => setError(String(e.message || e)));
  }, []);

  async function validate() {
    setError("");
    setMsg("");
    try {
      const res = await api<{ ok: boolean; message: string; checksum: string }>(
        "/api/v1/config/validate",
        { method: "POST", body: "{}" },
      );
      setMsg(`${res.message} (${res.checksum.slice(0, 12)}…)`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    }
  }

  async function apply() {
    setError("");
    setMsg("");
    try {
      const res = await api<{ ok: boolean; version: number; message: string }>(
        "/api/v1/config/apply",
        { method: "POST", body: "{}" },
      );
      setMsg(`v${res.version}: ${res.message}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    }
  }

  async function rollback(id: string) {
    setError("");
    setMsg("");
    try {
      const res = await api<{ ok: boolean; version: number }>(
        "/api/v1/config/rollback",
        { method: "POST", body: JSON.stringify({ version_id: id }) },
      );
      setMsg(`rolled back → v${res.version}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    }
  }

  async function saveNetwork(e: FormEvent) {
    e.preventDefault();
    setNetMsg("");
    setError("");
    try {
      await api("/api/v1/settings/network", {
        method: "PUT",
        body: JSON.stringify({ trusted_proxies: trusted, real_ip_header: realIP }),
      });
      setNetMsg(t("savedOk"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveLogs(e: FormEvent) {
    e.preventDefault();
    setLogMsg("");
    setError("");
    try {
      await api("/api/v1/settings/logs", {
        method: "PUT",
        body: JSON.stringify({
          enabled: logEnabled,
          max_mb: logMaxMB,
          keep: logKeep,
          interval_min: logInterval,
        }),
      });
      setLogMsg(t("savedOk"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function rotateNow() {
    setLogMsg("");
    setError("");
    try {
      const res = await api<{ count: number; rotated: string[]; skipped?: string }>(
        "/api/v1/ops/log-rotate?force=1",
        { method: "POST", body: "{}" },
      );
      setLogMsg(
        res.skipped
          ? t("logRotateSkipped")
          : t("logRotateDone", { count: res.count ?? 0 }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  return (
    <div className="grid two">
      <section className="panel stack">
        <h2 className="heading-with-help">
          {t("config")}
          <HelpTip text={t("helpConfig")} />
        </h2>
        <pre className="muted" style={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(status, null, 2)}
        </pre>
        <div className="row">
          <button type="button" className="secondary" onClick={() => void validate()}>
            {t("validate")}
          </button>
          <button type="button" onClick={() => void apply()}>
            {t("apply")}
          </button>
        </div>
        {msg && <div className="ok">{msg}</div>}
        {error && <div className="error">{error}</div>}

        <h2 className="heading-with-help" style={{ marginTop: "1.5rem" }}>
          {t("networkSettings")}
          <HelpTip text={t("helpNetwork")} />
        </h2>
        <form className="stack" onSubmit={(e) => void saveNetwork(e)}>
          <div>
            <label htmlFor="trusted">{t("trustedProxies")}</label>
            <textarea
              id="trusted"
              rows={2}
              value={trusted}
              onChange={(e) => setTrusted(e.target.value)}
              placeholder="10.0.0.0/8, 192.168.0.1"
            />
            <p className="field-hint">{t("trustedProxiesHint")}</p>
          </div>
          <div>
            <label htmlFor="realip">{t("realIpHeader")}</label>
            <input id="realip" value={realIP} onChange={(e) => setRealIP(e.target.value)} />
          </div>
          <button type="submit">{t("saveNetwork")}</button>
          {netMsg && <div className="ok">{netMsg}</div>}
        </form>

        <h2 className="heading-with-help" style={{ marginTop: "1.5rem" }}>
          {t("logRotation")}
          <HelpTip text={t("helpLogRotation")} />
        </h2>
        <form className="stack" onSubmit={(e) => void saveLogs(e)}>
          <label className="check-row">
            <input type="checkbox" checked={logEnabled} onChange={(e) => setLogEnabled(e.target.checked)} />
            {t("logRotateEnabled")}
          </label>
          <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
            <div>
              <label htmlFor="logmax">{t("logRotateMaxMB")}</label>
              <input
                id="logmax"
                type="number"
                min={1}
                max={10240}
                value={logMaxMB}
                onChange={(e) => setLogMaxMB(Number(e.target.value))}
              />
            </div>
            <div>
              <label htmlFor="logkeep">{t("logRotateKeep")}</label>
              <input
                id="logkeep"
                type="number"
                min={1}
                max={30}
                value={logKeep}
                onChange={(e) => setLogKeep(Number(e.target.value))}
              />
            </div>
            <div>
              <label htmlFor="logint">{t("logRotateInterval")}</label>
              <input
                id="logint"
                type="number"
                min={5}
                max={10080}
                value={logInterval}
                onChange={(e) => setLogInterval(Number(e.target.value))}
              />
            </div>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <button type="submit">{t("save")}</button>
            <button type="button" className="secondary" onClick={() => void rotateNow()}>
              {t("logRotateNow")}
            </button>
          </div>
          {logMsg && <div className="ok">{logMsg}</div>}
        </form>
      </section>
      <section className="panel">
        <h2 className="heading-with-help">
          {t("versions")}
          <HelpTip text={t("helpVersions")} />
        </h2>
        <table className="table">
          <thead>
            <tr>
              <th>#</th>
              <th>{t("status")}</th>
              <th>checksum</th>
              <th>{t("actions")}</th>
            </tr>
          </thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.id}>
                <td>{v.version}</td>
                <td>{v.status}</td>
                <td>
                  <code>{v.checksum.slice(0, 10)}</code>
                </td>
                <td>
                  <button type="button" className="secondary" onClick={() => void rollback(v.id)}>
                    {t("rollback")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
