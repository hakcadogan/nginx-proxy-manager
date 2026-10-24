import { FormEvent, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type HeaderRule = { action: "add" | "remove"; name: string; value?: string };
type LocationForm = {
  path: string;
  upstream_scheme: string;
  upstream_host: string;
  upstream_port: number;
  allowed_methods: string;
  rate_limit_profile_id: string;
};

type Host = {
  id: string;
  primary_domain: string;
  upstream_scheme: string;
  upstream_host: string;
  upstream_port: number;
  upstream_id?: string | null;
  enabled: boolean;
  path_prefix: string;
  websocket_support: boolean;
  force_https: boolean;
  access_log_enabled?: boolean;
  access_log_format?: string;
  error_log_enabled?: boolean;
  waf_enabled?: boolean;
  security_headers_preset?: string;
  aliases: string[];
  custom_headers?: HeaderRule[];
  locations?: {
    path: string;
    upstream_scheme: string;
    upstream_host: string;
    upstream_port: number;
    allowed_methods?: string[];
    rate_limit_profile_id?: string;
  }[];
  certificate_id?: string | null;
  rate_limit_profile_id?: string | null;
  allowed_methods?: string[];
  listen_http?: boolean;
  listen_https?: boolean;
  http2?: boolean;
  client_max_body_size?: string;
  connect_timeout?: string;
  send_timeout?: string;
  read_timeout?: string;
  proxy_protocol?: string;
};

type Pool = { id: string; name: string };
type Cert = { id: string; name: string; kind?: string; domains?: string[] };
type RateProfile = { id: string; name: string; requests_per_second: number; burst: number };

/** NPM-style SSL label for host list (REQ-UI / host inventory). */
function sslLabel(
  h: Host,
  certById: Map<string, Cert>,
  t: (key: string) => string,
): { text: string; className: string } {
  if (!h.certificate_id) {
    return { text: t("sslHttpOnly"), className: "badge badge-off" };
  }
  const cert = certById.get(h.certificate_id);
  if (!cert) {
    return { text: t("sslHttpOnly"), className: "badge badge-off" };
  }
  switch (cert.kind) {
    case "acme":
      return { text: t("sslLetsEncrypt"), className: "badge badge-ok" };
    case "self_signed":
      return { text: t("sslSelfSigned"), className: "badge badge-warn" };
    case "private_ca":
      return { text: t("sslPrivateCa"), className: "badge badge-ok" };
    case "upload":
    default:
      return { text: t("sslCustom"), className: "badge badge-ok" };
  }
}

type TabId = "details" | "locations" | "ssl" | "advanced";

type FormState = {
  primary_domain: string;
  aliasesText: string;
  upstream_host: string;
  upstream_port: number;
  upstream_scheme: string;
  upstream_id: string;
  path_prefix: string;
  enabled: boolean;
  websocket_support: boolean;
  force_https: boolean;
  access_log_enabled: boolean;
  access_log_format: string;
  error_log_enabled: boolean;
  listen_http: boolean;
  listen_https: boolean;
  http2: boolean;
  client_max_body_size: string;
  connect_timeout: string;
  send_timeout: string;
  read_timeout: string;
  proxy_protocol: string;
  headers: HeaderRule[];
  locations: LocationForm[];
  certificate_id: string;
  security_headers_preset: string;
  rate_limit_profile_id: string;
  allowed_methods: string;
};

const emptyForm = (): FormState => ({
  primary_domain: "",
  aliasesText: "",
  upstream_host: "",
  upstream_port: 80,
  upstream_scheme: "http",
  upstream_id: "",
  path_prefix: "/",
  enabled: true,
  websocket_support: true,
  force_https: false,
  access_log_enabled: true,
  access_log_format: "main",
  error_log_enabled: true,
  listen_http: true,
  listen_https: true,
  http2: true,
  client_max_body_size: "10m",
  connect_timeout: "5s",
  send_timeout: "60s",
  read_timeout: "60s",
  proxy_protocol: "http",
  headers: [],
  locations: [],
  certificate_id: "",
  security_headers_preset: "none",
  rate_limit_profile_id: "",
  allowed_methods: "",
});

function parseAliases(text: string, primary: string): string[] {
  const primaryNorm = primary.trim().toLowerCase();
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of text.split(/[\n,]+/)) {
    const d = part.trim().toLowerCase();
    if (!d || d === primaryNorm || seen.has(d)) continue;
    seen.add(d);
    out.push(d);
  }
  return out;
}

function hostToForm(h: Host): FormState {
  return {
    primary_domain: h.primary_domain,
    aliasesText: (h.aliases || []).join("\n"),
    upstream_host: h.upstream_host || "",
    upstream_port: h.upstream_port || 80,
    upstream_scheme: h.upstream_scheme || "http",
    upstream_id: h.upstream_id || "",
    path_prefix: h.path_prefix || "/",
    enabled: h.enabled,
    websocket_support: h.websocket_support,
    force_https: h.force_https,
    access_log_enabled: h.access_log_enabled ?? true,
    access_log_format: h.access_log_format || "main",
    error_log_enabled: h.error_log_enabled ?? true,
    listen_http: h.listen_http ?? true,
    listen_https: h.listen_https ?? true,
    http2: h.http2 ?? true,
    client_max_body_size: h.client_max_body_size || "10m",
    connect_timeout: h.connect_timeout || "5s",
    send_timeout: h.send_timeout || "60s",
    read_timeout: h.read_timeout || "60s",
    proxy_protocol: h.proxy_protocol || "http",
    headers: (h.custom_headers || []).map((x) => ({
      action: x.action === "remove" ? "remove" : "add",
      name: x.name || "",
      value: x.value || "",
    })),
    locations: (h.locations || []).map((l) => ({
      path: l.path || "/",
      upstream_scheme: l.upstream_scheme || "http",
      upstream_host: l.upstream_host || "",
      upstream_port: l.upstream_port || 80,
      allowed_methods: (l.allowed_methods || []).join(","),
      rate_limit_profile_id: l.rate_limit_profile_id || "",
    })),
    certificate_id: h.certificate_id || "",
    security_headers_preset: h.security_headers_preset || "none",
    rate_limit_profile_id: h.rate_limit_profile_id || "",
    allowed_methods: (h.allowed_methods || []).join(","),
  };
}

function parseMethods(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((m) => m.trim().toUpperCase())
    .filter(Boolean);
}

export default function HostsPage() {
  const { t } = useTranslation();
  const [items, setItems] = useState<Host[]>([]);
  const [pools, setPools] = useState<Pool[]>([]);
  const [certs, setCerts] = useState<Cert[]>([]);
  const [rates, setRates] = useState<RateProfile[]>([]);
  const [listError, setListError] = useState("");
  const [ok, setOk] = useState("");
  const [q, setQ] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [baseline, setBaseline] = useState<Host | null>(null);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState("");
  const [probeMsg, setProbeMsg] = useState("");
  const [tab, setTab] = useState<TabId>("details");
  const [form, setForm] = useState<FormState>(emptyForm);

  async function load() {
    const [hosts, ups, c, rl] = await Promise.all([
      api<{ items: Host[] }>("/api/v1/hosts"),
      api<{ items: Pool[] }>("/api/v1/upstreams"),
      api<{ items: Cert[] }>("/api/v1/certificates"),
      api<{ items: RateProfile[] }>("/api/v1/rate-limits"),
    ]);
    setItems(hosts.items || []);
    setPools(ups.items || []);
    setCerts(c.items || []);
    setRates(rl.items || []);
  }

  useEffect(() => {
    load().catch((e) => setListError(String(e.message || e)));
  }, []);

  useEffect(() => {
    if (!modalOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) closeModal();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [modalOpen, busy]);

  const certById = useMemo(() => {
    const m = new Map<string, Cert>();
    for (const c of certs) m.set(c.id, c);
    return m;
  }, [certs]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return items;
    return items.filter(
      (h) =>
        h.id.toLowerCase().includes(s) ||
        h.primary_domain.toLowerCase().includes(s) ||
        h.aliases?.some((a) => a.toLowerCase().includes(s)) ||
        h.upstream_host.toLowerCase().includes(s) ||
        (h.upstream_id && pools.find((p) => p.id === h.upstream_id)?.name.toLowerCase().includes(s)) ||
        (h.certificate_id && h.certificate_id.toLowerCase().includes(s)),
    );
  }, [items, pools, q]);

  async function copyId(id: string) {
    try {
      await navigator.clipboard.writeText(id);
      setOk(t("idCopied"));
      setListError("");
      setFormError("");
    } catch {
      const msg = t("idCopyFailed");
      if (modalOpen) setFormError(msg);
      else setListError(msg);
    }
  }

  function closeModal() {
    setModalOpen(false);
    setEditingId(null);
    setBaseline(null);
    setForm(emptyForm());
    setFormError("");
    setProbeMsg("");
    setTab("details");
  }

  function openCreate() {
    setEditingId(null);
    setBaseline(null);
    setForm(emptyForm());
    setFormError("");
    setProbeMsg("");
    setOk("");
    setTab("details");
    setModalOpen(true);
  }

  async function openEdit(id: string) {
    setListError("");
    setOk("");
    setFormError("");
    setProbeMsg("");
    setTab("details");
    try {
      const h = await api<Host>(`/api/v1/hosts/${id}`);
      setEditingId(h.id);
      setBaseline(h);
      setForm(hostToForm(h));
      setModalOpen(true);
    } catch (err) {
      setListError(err instanceof Error ? err.message : "error");
    }
  }

  function buildBody(): Record<string, unknown> {
    const aliases = parseAliases(form.aliasesText, form.primary_domain);
    const custom_headers = form.headers
      .filter((h) => h.name.trim())
      .map((h) => ({
        action: h.action,
        name: h.name.trim(),
        value: h.action === "add" ? h.value || "" : "",
      }));
    const locations = form.locations
      .filter((l) => l.path.trim() && l.upstream_host.trim())
      .map((l) => ({
        path: l.path.trim().startsWith("/") ? l.path.trim() : `/${l.path.trim()}`,
        upstream_scheme: l.upstream_scheme || "http",
        upstream_host: l.upstream_host.trim(),
        upstream_port: l.upstream_port || 80,
        allowed_methods: parseMethods(l.allowed_methods || ""),
        rate_limit_profile_id: l.rate_limit_profile_id || "",
      }));
    const body: Record<string, unknown> = {
      primary_domain: form.primary_domain.trim().toLowerCase(),
      aliases,
      path_prefix: form.path_prefix || "/",
      enabled: form.enabled,
      websocket_support: form.websocket_support,
      force_https: form.force_https,
      access_log_enabled: form.access_log_enabled,
      access_log_format: form.access_log_format || "main",
      error_log_enabled: form.error_log_enabled,
      listen_http: form.listen_http,
      listen_https: form.listen_https,
      http2: form.http2,
      client_max_body_size: form.client_max_body_size || "10m",
      connect_timeout: form.connect_timeout || "5s",
      send_timeout: form.send_timeout || "60s",
      read_timeout: form.read_timeout || "60s",
      proxy_protocol: form.proxy_protocol || "http",
      custom_headers,
      locations,
      waf_enabled: baseline?.waf_enabled ?? true,
      security_headers_preset: form.security_headers_preset || "none",
      certificate_id: form.certificate_id || null,
      rate_limit_profile_id: form.rate_limit_profile_id || null,
      allowed_methods: parseMethods(form.allowed_methods),
    };
    if (form.upstream_id) {
      body.upstream_id = form.upstream_id;
      body.upstream_scheme = form.upstream_scheme || "http";
      body.upstream_host = form.upstream_host || "pool.local";
      body.upstream_port = form.upstream_port || 80;
    } else {
      body.upstream_id = null;
      body.upstream_scheme = form.upstream_scheme;
      body.upstream_host = form.upstream_host.trim();
      body.upstream_port = form.upstream_port;
    }
    return body;
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setOk("");
    setBusy(true);
    try {
      const body = buildBody();
      if (editingId) {
        await api(`/api/v1/hosts/${editingId}`, { method: "PATCH", body: JSON.stringify(body) });
        setOk(t("updatedOk"));
      } else {
        await api("/api/v1/hosts", { method: "POST", body: JSON.stringify(body) });
        setOk(t("savedOk"));
      }
      closeModal();
      await load();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string, domain: string) {
    if (!window.confirm(t("confirmDeleteNamed", { name: domain }))) return;
    setListError("");
    try {
      await api(`/api/v1/hosts/${id}`, { method: "DELETE" });
      if (editingId === id) closeModal();
      await load();
    } catch (err) {
      setListError(err instanceof Error ? err.message : "error");
    }
  }

  async function toggleEnabled(h: Host) {
    setListError("");
    try {
      await api(`/api/v1/hosts/${h.id}/${h.enabled ? "disable" : "enable"}`, { method: "POST", body: "{}" });
      await load();
    } catch (err) {
      setListError(err instanceof Error ? err.message : "error");
    }
  }

  async function probe() {
    if (!editingId) return;
    setProbeMsg("");
    setFormError("");
    try {
      const res = await api<{ ok: boolean; target: string; latency_ms: number; error?: string }>(
        `/api/v1/hosts/${editingId}/probe`,
        { method: "POST", body: "{}" },
      );
      setProbeMsg(
        res.ok
          ? `${t("probeOk")}: ${res.target} (${res.latency_ms}ms)`
          : `${t("probeFail")}: ${res.error || res.target}`,
      );
    } catch (err) {
      setProbeMsg(err instanceof Error ? err.message : t("probeFail"));
    }
  }

  const activeCount = items.filter((h) => h.enabled).length;
  const tabs: { id: TabId; label: string }[] = [
    { id: "details", label: t("tabDetails") },
    { id: "locations", label: t("tabLocations") },
    { id: "ssl", label: t("tabSsl") },
    { id: "advanced", label: t("tabAdvanced") },
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="heading-with-help">
            {t("hosts")}
            <HelpTip text={t("helpHosts")} />
          </h1>
          <p>
            {items.length} {t("hosts").toLowerCase()} · {activeCount} {t("enabled").toLowerCase()}
          </p>
        </div>
        <button type="button" onClick={openCreate}>
          {t("createHost")}
        </button>
      </div>

      {ok && !modalOpen && <div className="ok" style={{ marginBottom: "0.75rem" }}>{ok}</div>}
      {listError && <div className="error" style={{ marginBottom: "0.75rem" }}>{listError}</div>}

      <section className="panel">
        <div className="toolbar">
          <input
            className="search"
            type="search"
            placeholder={t("searchHosts")}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label={t("searchHosts")}
          />
        </div>
        {filtered.length === 0 ? (
          <div className="empty-state">{q ? t("noSearchResults") : t("noHosts")}</div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("domain")}</th>
                  <th>{t("upstream")}</th>
                  <th>{t("sslColumn")}</th>
                  <th>{t("status")}</th>
                  <th>{t("actions")}</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((h) => {
                  const ssl = sslLabel(h, certById, t);
                  return (
                  <tr key={h.id}>
                    <td>
                      <div className="domain-cell">
                        <strong>{h.primary_domain}</strong>
                        {h.aliases?.length > 0 && (
                          <span className="muted" style={{ fontSize: "0.78rem" }} title={h.aliases.join(", ")}>
                            +{h.aliases.length} {t("aliases").toLowerCase()}
                            {h.aliases.length <= 2 ? `: ${h.aliases.join(", ")}` : ""}
                          </span>
                        )}
                        <button
                          type="button"
                          className="id-chip"
                          title={`${t("hostId")}: ${h.id}`}
                          aria-label={`${t("copy")} ${t("hostId")}`}
                          onClick={() => void copyId(h.id)}
                        >
                          <span className="mono">{h.id.slice(0, 8)}</span>
                          <span className="muted">…</span>
                        </button>
                      </div>
                    </td>
                    <td>
                      <span className="upstream-chip">
                        {h.upstream_id
                          ? `pool:${pools.find((p) => p.id === h.upstream_id)?.name || h.upstream_id.slice(0, 8)}`
                          : `${h.upstream_scheme}://${h.upstream_host}:${h.upstream_port}`}
                      </span>
                    </td>
                    <td>
                      <span className={ssl.className} title={h.certificate_id || undefined}>
                        {ssl.text}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${h.enabled ? "badge-ok" : "badge-off"}`}>
                        {h.enabled ? t("enabled") : t("disabled")}
                      </span>
                    </td>
                    <td>
                      <div className="action-icons">
                        <button
                          type="button"
                          className="icon-btn secondary"
                          title={t("edit")}
                          aria-label={t("edit")}
                          onClick={() => void openEdit(h.id)}
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <path d="M12 20h9" />
                            <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          className={`icon-btn secondary ${h.enabled ? "is-on" : ""}`}
                          title={h.enabled ? t("disable") : t("enable")}
                          aria-label={h.enabled ? t("disable") : t("enable")}
                          onClick={() => void toggleEnabled(h)}
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <path d="M12 2v10" />
                            <path d="M18.4 6.6a8 8 0 1 1-12.8 0" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          className="icon-btn danger"
                          title={t("delete")}
                          aria-label={t("delete")}
                          onClick={() => void remove(h.id, h.primary_domain)}
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <path d="M3 6h18" />
                            <path d="M8 6V4h8v2" />
                            <path d="M19 6l-1 14H6L5 6" />
                            <path d="M10 11v6" />
                            <path d="M14 11v6" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {modalOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget && !busy) closeModal();
          }}
        >
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="host-modal-title">
            <div className="modal-header">
              <h2 id="host-modal-title">{editingId ? t("editHost") : t("createHost")}</h2>
              <button type="button" className="ghost modal-close" onClick={closeModal} aria-label={t("cancel")}>
                ×
              </button>
            </div>

            <div className="modal-tabs" role="tablist">
              {tabs.map((tb) => (
                <button
                  key={tb.id}
                  type="button"
                  role="tab"
                  aria-selected={tab === tb.id}
                  className={`modal-tab ${tab === tb.id ? "active" : ""}`}
                  onClick={() => setTab(tb.id)}
                >
                  {tb.label}
                </button>
              ))}
            </div>

            <form className="modal-body" onSubmit={(e) => void onSubmit(e)}>
              {tab === "details" && (
                <div className="stack modal-pane">
                  {editingId && (
                    <div>
                      <label htmlFor="host-id">{t("hostId")}</label>
                      <div className="id-field">
                        <code id="host-id" className="mono id-value">
                          {editingId}
                        </code>
                        <button type="button" className="ghost" onClick={() => void copyId(editingId)}>
                          {t("copy")}
                        </button>
                      </div>
                      <p className="field-hint">{t("hostIdHint")}</p>
                    </div>
                  )}
                  <div>
                    <label htmlFor="domain">{t("primaryDomain")}</label>
                    <input
                      id="domain"
                      required
                      value={form.primary_domain}
                      onChange={(e) => setForm({ ...form, primary_domain: e.target.value })}
                      placeholder="app.example.com"
                      autoComplete="off"
                    />
                  </div>
                  <div>
                    <label htmlFor="aliases">{t("aliases")}</label>
                    <textarea
                      id="aliases"
                      rows={3}
                      value={form.aliasesText}
                      onChange={(e) => setForm({ ...form, aliasesText: e.target.value })}
                      placeholder={"www.example.com\ncdn.example.com"}
                    />
                    <p className="field-hint">{t("aliasesHint")}</p>
                  </div>
                  <div>
                    <label htmlFor="pool">{t("lbPools")}</label>
                    <select
                      id="pool"
                      value={form.upstream_id}
                      onChange={(e) => setForm({ ...form, upstream_id: e.target.value })}
                    >
                      <option value="">— {t("directUpstream")} —</option>
                      {pools.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                    <p className="field-hint">{t("poolOrUpstreamHint")}</p>
                  </div>
                  {!form.upstream_id && (
                    <>
                      <div>
                        <label htmlFor="uphost">{t("forwardHost")}</label>
                        <input
                          id="uphost"
                          required
                          value={form.upstream_host}
                          onChange={(e) => setForm({ ...form, upstream_host: e.target.value })}
                          placeholder="backend.example.com"
                        />
                      </div>
                      <div className="row loc-grid">
                        <div>
                          <label htmlFor="scheme">{t("scheme")}</label>
                          <select
                            id="scheme"
                            value={form.upstream_scheme}
                            onChange={(e) => setForm({ ...form, upstream_scheme: e.target.value })}
                          >
                            <option value="http">http</option>
                            <option value="https">https</option>
                          </select>
                        </div>
                        <div>
                          <label htmlFor="port">{t("port")}</label>
                          <input
                            id="port"
                            type="number"
                            min={1}
                            max={65535}
                            value={form.upstream_port}
                            onChange={(e) => setForm({ ...form, upstream_port: Number(e.target.value) })}
                          />
                        </div>
                      </div>
                    </>
                  )}
                  <div>
                    <label htmlFor="path">{t("pathPrefix")}</label>
                    <input
                      id="path"
                      value={form.path_prefix}
                      onChange={(e) => setForm({ ...form, path_prefix: e.target.value })}
                      placeholder="/"
                    />
                  </div>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={form.enabled}
                      onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                    />
                    {t("enabled")}
                  </label>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={form.websocket_support}
                      disabled={form.proxy_protocol === "grpc"}
                      onChange={(e) => setForm({ ...form, websocket_support: e.target.checked })}
                    />
                    WebSocket
                  </label>
                </div>
              )}

              {tab === "locations" && (
                <div className="stack modal-pane">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() =>
                      setForm({
                        ...form,
                        locations: [
                          ...form.locations,
                          {
                            path: "/path",
                            upstream_scheme: "http",
                            upstream_host: "",
                            upstream_port: 80,
                            allowed_methods: "",
                            rate_limit_profile_id: "",
                          },
                        ],
                      })
                    }
                  >
                    {t("addLocation")}
                  </button>
                  {form.locations.length === 0 && (
                    <p className="field-hint">{t("locationsEmpty")}</p>
                  )}
                  {form.locations.map((loc, i) => (
                    <div key={i} className="location-card">
                      <div className="location-path-row">
                        <span className="location-prefix">location</span>
                        <input
                          required
                          value={loc.path}
                          onChange={(e) => {
                            const locations = [...form.locations];
                            locations[i] = { ...loc, path: e.target.value };
                            setForm({ ...form, locations });
                          }}
                          placeholder="/path"
                        />
                      </div>
                      <div className="row loc-grid">
                        <div>
                          <label>{t("scheme")}</label>
                          <select
                            value={loc.upstream_scheme}
                            onChange={(e) => {
                              const locations = [...form.locations];
                              locations[i] = { ...loc, upstream_scheme: e.target.value };
                              setForm({ ...form, locations });
                            }}
                          >
                            <option value="http">http</option>
                            <option value="https">https</option>
                          </select>
                        </div>
                        <div style={{ flex: 2 }}>
                          <label>{t("forwardHost")}</label>
                          <input
                            required
                            value={loc.upstream_host}
                            onChange={(e) => {
                              const locations = [...form.locations];
                              locations[i] = { ...loc, upstream_host: e.target.value };
                              setForm({ ...form, locations });
                            }}
                            placeholder="203.0.113.25"
                          />
                          <p className="field-hint">{t("locationHostHint")}</p>
                        </div>
                        <div>
                          <label>{t("port")}</label>
                          <input
                            type="number"
                            min={1}
                            max={65535}
                            value={loc.upstream_port}
                            onChange={(e) => {
                              const locations = [...form.locations];
                              locations[i] = { ...loc, upstream_port: Number(e.target.value) };
                              setForm({ ...form, locations });
                            }}
                          />
                        </div>
                      </div>
                      <div className="row loc-grid">
                        <div>
                          <label>{t("allowedMethods")}</label>
                          <input
                            value={loc.allowed_methods || ""}
                            onChange={(e) => {
                              const locations = [...form.locations];
                              locations[i] = { ...loc, allowed_methods: e.target.value };
                              setForm({ ...form, locations });
                            }}
                            placeholder="GET,POST"
                          />
                        </div>
                        <div>
                          <label>{t("rateProfile")}</label>
                          <select
                            value={loc.rate_limit_profile_id || ""}
                            onChange={(e) => {
                              const locations = [...form.locations];
                              locations[i] = { ...loc, rate_limit_profile_id: e.target.value };
                              setForm({ ...form, locations });
                            }}
                          >
                            <option value="">{t("none")}</option>
                            {rates.map((p) => (
                              <option key={p.id} value={p.id}>
                                {p.name} ({p.requests_per_second} r/s)
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="linkish"
                        onClick={() =>
                          setForm({ ...form, locations: form.locations.filter((_, j) => j !== i) })
                        }
                      >
                        {t("delete")}
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {tab === "ssl" && (
                <div className="stack modal-pane">
                  <div>
                    <label htmlFor="cert">{t("certificate")}</label>
                    <select
                      id="cert"
                      value={form.certificate_id}
                      onChange={(e) => setForm({ ...form, certificate_id: e.target.value })}
                    >
                      <option value="">— {t("none")} —</option>
                      {certs.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name || c.id.slice(0, 8)}
                          {c.domains?.length ? ` (${c.domains.join(", ")})` : ""}
                        </option>
                      ))}
                    </select>
                    <p className="field-hint">{t("certificateHint")}</p>
                  </div>
                  {form.certificate_id && (
                    <div>
                      <label htmlFor="cert-id">{t("certificateId")}</label>
                      <div className="id-field">
                        <code id="cert-id" className="mono id-value">
                          {form.certificate_id}
                        </code>
                        <button
                          type="button"
                          className="ghost"
                          onClick={() => void copyId(form.certificate_id)}
                        >
                          {t("copy")}
                        </button>
                      </div>
                      <p className="field-hint">{t("certificateIdHint")}</p>
                    </div>
                  )}
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={form.listen_https}
                      onChange={(e) => setForm({ ...form, listen_https: e.target.checked })}
                    />
                    {t("listenHttps")}
                  </label>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={form.force_https}
                      onChange={(e) => setForm({ ...form, force_https: e.target.checked })}
                    />
                    {t("forceHttps")}
                  </label>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={form.http2}
                      onChange={(e) => setForm({ ...form, http2: e.target.checked })}
                    />
                    HTTP/2
                  </label>
                  <div>
                    <label htmlFor="secHeaders">{t("securityHeaders")}</label>
                    <select
                      id="secHeaders"
                      value={form.security_headers_preset}
                      onChange={(e) => setForm({ ...form, security_headers_preset: e.target.value })}
                    >
                      <option value="none">{t("none")}</option>
                      <option value="basic">basic</option>
                      <option value="strict">strict</option>
                    </select>
                  </div>
                </div>
              )}

              {tab === "advanced" && (
                <div className="stack modal-pane">
                  <div className="callout warn">
                    <strong>{t("noRawSnippetTitle")}</strong>
                    <p>{t("noRawSnippetBody")}</p>
                  </div>
                  <div className="row" style={{ flexWrap: "wrap", gap: "1rem" }}>
                    <label className="check-row">
                      <input
                        type="checkbox"
                        checked={form.listen_http}
                        onChange={(e) => setForm({ ...form, listen_http: e.target.checked })}
                      />
                      {t("listenHttp")}
                    </label>
                    <label className="check-row">
                      <input
                        type="checkbox"
                        checked={form.access_log_enabled}
                        onChange={(e) => setForm({ ...form, access_log_enabled: e.target.checked })}
                      />
                      {t("accessLog")}
                    </label>
                    <label className="check-row">
                      <input
                        type="checkbox"
                        checked={form.error_log_enabled}
                        onChange={(e) => setForm({ ...form, error_log_enabled: e.target.checked })}
                      />
                      {t("errorLog")}
                    </label>
                  </div>
                  <p className="field-hint">{t("errorLogHint")}</p>
                  {form.access_log_enabled && (
                    <div>
                      <label htmlFor="logfmt">{t("accessLogFormat")}</label>
                      <select
                        id="logfmt"
                        value={form.access_log_format}
                        onChange={(e) => setForm({ ...form, access_log_format: e.target.value })}
                      >
                        <option value="main">main</option>
                        <option value="combined">combined</option>
                        <option value="detailed">detailed</option>
                        <option value="json">json</option>
                      </select>
                      <p className="field-hint">{t("accessLogFormatHint")}</p>
                    </div>
                  )}
                  <div className="row loc-grid">
                    <div>
                      <label htmlFor="proto">{t("proxyProtocol")}</label>
                      <select
                        id="proto"
                        value={form.proxy_protocol}
                        onChange={(e) => setForm({ ...form, proxy_protocol: e.target.value })}
                      >
                        <option value="http">HTTP</option>
                        <option value="grpc">gRPC</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="body">{t("bodySizeLimit")}</label>
                      <input
                        id="body"
                        value={form.client_max_body_size}
                        onChange={(e) => setForm({ ...form, client_max_body_size: e.target.value })}
                        placeholder="10m"
                      />
                    </div>
                  </div>
                  <div className="row loc-grid">
                    <div>
                      <label htmlFor="rate">{t("rateProfile")}</label>
                      <select
                        id="rate"
                        value={form.rate_limit_profile_id}
                        onChange={(e) => setForm({ ...form, rate_limit_profile_id: e.target.value })}
                      >
                        <option value="">{t("none")}</option>
                        {rates.map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.name} ({p.requests_per_second} r/s, burst {p.burst})
                          </option>
                        ))}
                      </select>
                      <p className="field-hint">{t("rateNeedsTrustedProxies")}</p>
                    </div>
                    <div>
                      <label htmlFor="methods">{t("allowedMethods")}</label>
                      <input
                        id="methods"
                        value={form.allowed_methods}
                        onChange={(e) => setForm({ ...form, allowed_methods: e.target.value })}
                        placeholder="GET,HEAD,POST"
                      />
                      <p className="field-hint">{t("allowedMethodsHint")}</p>
                    </div>
                  </div>
                  {!form.upstream_id ? (
                    <div className="row loc-grid">
                      <div>
                        <label htmlFor="cto">{t("connectTimeout")}</label>
                        <input
                          id="cto"
                          value={form.connect_timeout}
                          onChange={(e) => setForm({ ...form, connect_timeout: e.target.value })}
                        />
                      </div>
                      <div>
                        <label htmlFor="sto">{t("sendTimeout")}</label>
                        <input
                          id="sto"
                          value={form.send_timeout}
                          onChange={(e) => setForm({ ...form, send_timeout: e.target.value })}
                        />
                      </div>
                      <div>
                        <label htmlFor="rto">{t("readTimeout")}</label>
                        <input
                          id="rto"
                          value={form.read_timeout}
                          onChange={(e) => setForm({ ...form, read_timeout: e.target.value })}
                        />
                      </div>
                    </div>
                  ) : (
                    <p className="field-hint">{t("poolTimeoutHint")}</p>
                  )}
                  <div>
                    <label>{t("customHeaders")}</label>
                    {form.headers.map((hdr, i) => (
                      <div key={i} className="row" style={{ marginBottom: "0.4rem", alignItems: "flex-end" }}>
                        <select
                          value={hdr.action}
                          onChange={(e) => {
                            const headers = [...form.headers];
                            headers[i] = { ...hdr, action: e.target.value as "add" | "remove" };
                            setForm({ ...form, headers });
                          }}
                        >
                          <option value="add">{t("headerAdd")}</option>
                          <option value="remove">{t("headerRemove")}</option>
                        </select>
                        <input
                          placeholder="X-Custom"
                          value={hdr.name}
                          onChange={(e) => {
                            const headers = [...form.headers];
                            headers[i] = { ...hdr, name: e.target.value };
                            setForm({ ...form, headers });
                          }}
                        />
                        {hdr.action === "add" && (
                          <input
                            placeholder="value"
                            value={hdr.value || ""}
                            onChange={(e) => {
                              const headers = [...form.headers];
                              headers[i] = { ...hdr, value: e.target.value };
                              setForm({ ...form, headers });
                            }}
                          />
                        )}
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => setForm({ ...form, headers: form.headers.filter((_, j) => j !== i) })}
                        >
                          ×
                        </button>
                      </div>
                    ))}
                    <button
                      type="button"
                      className="secondary"
                      onClick={() =>
                        setForm({ ...form, headers: [...form.headers, { action: "add", name: "", value: "" }] })
                      }
                    >
                      {t("addHeader")}
                    </button>
                    <p className="field-hint">{t("headersHint")}</p>
                  </div>
                  {editingId && !form.upstream_id && (
                    <div className="row">
                      <button type="button" className="secondary" onClick={() => void probe()}>
                        {t("probe")}
                      </button>
                    </div>
                  )}
                  {probeMsg && <div className="ok">{probeMsg}</div>}
                </div>
              )}

              {ok && modalOpen && <div className="ok">{ok}</div>}
              {formError && <div className="error">{formError}</div>}

              <div className="modal-footer">
                <button type="button" className="secondary" disabled={busy} onClick={closeModal}>
                  {t("cancel")}
                </button>
                <button type="submit" disabled={busy}>
                  {t("save")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
