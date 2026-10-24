import { FormEvent, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

/** Member status poll interval (REQ-UI-006 / REQ-LB-012). 5s is responsive vs typical HC ≥10s. */
const MEMBERS_POLL_MS = 5000;

type Member = {
  id: string;
  host: string;
  port: number;
  weight: number;
  max_conns?: number;
  is_backup: boolean;
  is_down: boolean;
  is_drain: boolean;
  admin_disabled?: boolean;
  last_check_at?: string | null;
  last_check_ok?: boolean | null;
};

type Upstream = {
  id: string;
  name: string;
  algorithm: string;
  hash_key: string;
  scheme: string;
  sni: string;
  max_fails: number;
  fail_timeout: string;
  connect_timeout: string;
  send_timeout: string;
  read_timeout: string;
  health_check_enabled: boolean;
  health_check_path: string;
  health_check_interval_sec: number;
  next_upstream: string;
  next_upstream_tries: number;
  next_upstream_timeout: string;
  members?: Member[];
};

const ALGOS = [
  "round_robin",
  "weighted_round_robin",
  "least_conn",
  "ip_hash",
  "hash",
  "hash_consistent",
] as const;

const DEFAULT_NEXT = "error timeout http_502 http_503 http_504";

const emptyPoolForm = () => ({
  name: "",
  algorithm: "round_robin",
  hash_key: "$request_uri",
  scheme: "http",
  sni: "",
  connect_timeout: "5s",
  send_timeout: "60s",
  read_timeout: "60s",
  max_fails: 3,
  fail_timeout: "10s",
  health_check_enabled: false,
  health_check_path: "/",
  health_check_interval_sec: 10,
  next_upstream: DEFAULT_NEXT,
  next_upstream_tries: 0,
  next_upstream_timeout: "0",
});

function poolToForm(u: Upstream) {
  return {
    name: u.name,
    algorithm: u.algorithm,
    hash_key: u.hash_key || "$request_uri",
    scheme: u.scheme,
    sni: u.sni || "",
    connect_timeout: u.connect_timeout || "5s",
    send_timeout: u.send_timeout || "60s",
    read_timeout: u.read_timeout || "60s",
    max_fails: u.max_fails ?? 3,
    fail_timeout: u.fail_timeout || "10s",
    health_check_enabled: !!u.health_check_enabled,
    health_check_path: u.health_check_path || "/",
    health_check_interval_sec: u.health_check_interval_sec || 10,
    next_upstream: u.next_upstream || DEFAULT_NEXT,
    next_upstream_tries: u.next_upstream_tries ?? 0,
    next_upstream_timeout: u.next_upstream_timeout || "0",
  };
}

function memberStatus(m: Member, t: (k: string) => string): string {
  if (m.is_drain) return t("statusDrain");
  if (m.admin_disabled) return t("statusDisabled");
  if (m.is_down) return t("statusDown");
  if (m.last_check_ok === false) return t("statusHcFail");
  if (m.last_check_ok === true) return t("statusUp");
  // Health probe never ran (HC off / waiting) — member is still in rotation.
  return t("statusActive");
}

export default function LBPage() {
  const { t } = useTranslation();
  const [items, setItems] = useState<Upstream[]>([]);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [selected, setSelected] = useState<string>("");
  const [editingPool, setEditingPool] = useState(false);
  const [createForm, setCreateForm] = useState(emptyPoolForm());
  const [editForm, setEditForm] = useState(emptyPoolForm());
  const [member, setMember] = useState({
    host: "",
    port: 8080,
    weight: 1,
    max_conns: 0,
    is_backup: false,
  });
  const [weightEdit, setWeightEdit] = useState<Record<string, number>>({});
  const [editingMemberId, setEditingMemberId] = useState<string | null>(null);
  const [memberEdit, setMemberEdit] = useState({
    host: "",
    port: 8080,
    weight: 1,
    max_conns: 0,
    is_backup: false,
  });
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (opts?: { silent?: boolean }) => {
    try {
      const data = await api<{ items: Upstream[] }>("/api/v1/upstreams");
      setItems(data.items || []);
    } catch (e) {
      if (!opts?.silent) {
        setError(e instanceof Error ? e.message : String(e));
      }
      throw e;
    }
  }, []);

  useEffect(() => {
    load().catch(() => {
      /* error set in load */
    });
  }, [load]);

  // Auto-refresh member statuses while the tab is visible.
  useEffect(() => {
    const tick = () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      void load({ silent: true }).catch(() => {
        /* keep last good snapshot on background poll failure */
      });
    };
    const id = window.setInterval(tick, MEMBERS_POLL_MS);
    return () => window.clearInterval(id);
  }, [load]);

  async function refreshMembers() {
    setRefreshing(true);
    setError("");
    try {
      await load({ silent: true });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRefreshing(false);
    }
  }

  const current = items.find((u) => u.id === selected);

  useEffect(() => {
    if (current && editingPool) {
      setEditForm(poolToForm(current));
    }
  }, [current?.id, editingPool]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    try {
      const created = await api<Upstream>("/api/v1/upstreams", {
        method: "POST",
        body: JSON.stringify(createForm),
      });
      setOk(t("savedOk"));
      setCreateForm(emptyPoolForm());
      setSelected(created.id);
      setEditingPool(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function onUpdatePool(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setError("");
    setOk("");
    try {
      await api(`/api/v1/upstreams/${selected}`, {
        method: "PATCH",
        body: JSON.stringify(editForm),
      });
      setOk(t("updatedOk"));
      setEditingPool(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function addMember(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setError("");
    setOk("");
    try {
      await api(`/api/v1/upstreams/${selected}/members`, {
        method: "POST",
        body: JSON.stringify(member),
      });
      setMember((m) => ({ ...m, host: "" }));
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function patchMember(u: Upstream, m: Member, patch: Partial<Member>) {
    setError("");
    setOk("");
    try {
      await api(`/api/v1/upstreams/${u.id}/members/${m.id}`, {
        method: "PATCH",
        body: JSON.stringify({ ...m, ...patch }),
      });
      setOk(t("updatedOk"));
      setEditingMemberId(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveWeight(u: Upstream, m: Member) {
    const w = weightEdit[m.id] ?? m.weight;
    await patchMember(u, m, { weight: w });
  }

  function startEditMember(m: Member) {
    setEditingMemberId(m.id);
    setMemberEdit({
      host: m.host,
      port: m.port,
      weight: m.weight,
      max_conns: m.max_conns ?? 0,
      is_backup: m.is_backup,
    });
  }

  async function saveMemberEdit(u: Upstream, m: Member) {
    await patchMember(u, m, {
      host: memberEdit.host.trim(),
      port: memberEdit.port,
      weight: memberEdit.weight,
      max_conns: memberEdit.max_conns || 0,
      is_backup: memberEdit.is_backup,
    });
  }

  async function removeMember(u: Upstream, m: Member) {
    if (!window.confirm(t("confirmDeleteNamed", { name: `${m.host}:${m.port}` }))) return;
    setError("");
    try {
      await api(`/api/v1/upstreams/${u.id}/members/${m.id}`, { method: "DELETE" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function removeUpstream(u: Upstream) {
    if (!window.confirm(t("confirmDeleteNamed", { name: u.name }))) return;
    setError("");
    try {
      await api(`/api/v1/upstreams/${u.id}`, { method: "DELETE" });
      if (selected === u.id) {
        setSelected("");
        setEditingPool(false);
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  function startEdit(u: Upstream) {
    setSelected(u.id);
    setEditForm(poolToForm(u));
    setEditingPool(true);
  }

  type PoolFormState = ReturnType<typeof emptyPoolForm>;
  function renderPoolFields(
    form: PoolFormState,
    setForm: (f: PoolFormState) => void,
    opts?: { nameDisabled?: boolean },
  ) {
    const nonIdempotent = /\bnon_idempotent\b/i.test(form.next_upstream);
    const isHash = form.algorithm === "hash" || form.algorithm === "hash_consistent";
    const isIPHash = form.algorithm === "ip_hash";
    return (
      <>
        <div>
          <label>{t("name")}</label>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            required
            disabled={opts?.nameDisabled}
          />
        </div>
        <div>
          <label>{t("algorithm")}</label>
          <select value={form.algorithm} onChange={(e) => setForm({ ...form, algorithm: e.target.value })}>
            {ALGOS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          {isIPHash && <p className="field-hint">{t("ipHashHint")}</p>}
        </div>
        {isHash && (
          <div>
            <label>{t("hashKey")}</label>
            <input
              value={form.hash_key}
              onChange={(e) => setForm({ ...form, hash_key: e.target.value })}
              placeholder="$request_uri"
            />
          </div>
        )}
        <div className="row loc-grid">
          <div>
            <label>{t("scheme")}</label>
            <select value={form.scheme} onChange={(e) => setForm({ ...form, scheme: e.target.value })}>
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
          </div>
          <div>
            <label>SNI</label>
            <input value={form.sni} onChange={(e) => setForm({ ...form, sni: e.target.value })} placeholder="optional" />
          </div>
        </div>

        <h3 className="lb-section-title heading-with-help">
          {t("timeoutsSection")}
          <HelpTip text={t("poolTimeoutHint")} />
        </h3>
        <div className="row loc-grid">
          <div>
            <label>{t("connectTimeout")}</label>
            <input
              value={form.connect_timeout}
              onChange={(e) => setForm({ ...form, connect_timeout: e.target.value })}
            />
          </div>
          <div>
            <label>{t("sendTimeout")}</label>
            <input value={form.send_timeout} onChange={(e) => setForm({ ...form, send_timeout: e.target.value })} />
          </div>
          <div>
            <label>{t("readTimeout")}</label>
            <input value={form.read_timeout} onChange={(e) => setForm({ ...form, read_timeout: e.target.value })} />
          </div>
        </div>

        <h3 className="lb-section-title heading-with-help">
          {t("passiveHealthSection")}
          <HelpTip text={t("helpPassiveHealthSection")} />
        </h3>
        <div className="row loc-grid">
          <div>
            <label>{t("maxFails")}</label>
            <input
              type="number"
              min={0}
              value={form.max_fails}
              onChange={(e) => setForm({ ...form, max_fails: Number(e.target.value) })}
            />
          </div>
          <div>
            <label>{t("failTimeout")}</label>
            <input
              value={form.fail_timeout}
              onChange={(e) => setForm({ ...form, fail_timeout: e.target.value })}
            />
          </div>
        </div>

        <h3 className="lb-section-title heading-with-help">
          {t("activeHealthSection")}
          <HelpTip text={t("helpActiveHealthSection")} />
        </h3>
        <div className="callout warn">
          <strong>{t("activeHealthOssTitle")}</strong>
          <p>{t("activeHealthOssBody")}</p>
        </div>
        <label className="check-row">
          <input
            type="checkbox"
            checked={form.health_check_enabled}
            onChange={(e) => setForm({ ...form, health_check_enabled: e.target.checked })}
          />
          {t("activeHealth")}
        </label>
        <div className="row loc-grid">
          <div>
            <label>{t("healthPath")}</label>
            <input
              value={form.health_check_path}
              onChange={(e) => setForm({ ...form, health_check_path: e.target.value })}
            />
          </div>
          <div>
            <label>{t("healthInterval")}</label>
            <input
              type="number"
              min={5}
              value={form.health_check_interval_sec}
              onChange={(e) => setForm({ ...form, health_check_interval_sec: Number(e.target.value) })}
            />
          </div>
        </div>

        <h3 className="lb-section-title heading-with-help">
          {t("retrySection")}
          <HelpTip text={t("helpRetrySection")} />
        </h3>
        <div>
          <label>{t("nextUpstream")}</label>
          <input
            value={form.next_upstream}
            onChange={(e) => setForm({ ...form, next_upstream: e.target.value })}
            placeholder={DEFAULT_NEXT}
          />
        </div>
        {nonIdempotent && (
          <div className="callout warn">
            <strong>{t("retryNonIdempotentTitle")}</strong>
            <p>{t("retryNonIdempotentBody")}</p>
          </div>
        )}
        <div className="row loc-grid">
          <div>
            <label>{t("nextUpstreamTries")}</label>
            <input
              type="number"
              min={0}
              max={100}
              value={form.next_upstream_tries}
              onChange={(e) => setForm({ ...form, next_upstream_tries: Number(e.target.value) })}
            />
          </div>
          <div>
            <label>{t("nextUpstreamTimeout")}</label>
            <input
              value={form.next_upstream_timeout}
              onChange={(e) => setForm({ ...form, next_upstream_timeout: e.target.value })}
              placeholder="0"
            />
          </div>
        </div>
      </>
    );
  }

  return (
    <div className="grid two">
      <section className="panel">
        <h2 className="heading-with-help">
          {t("lbPools")}
          <HelpTip text={t("helpLB")} />
        </h2>
        <div className="callout" style={{ background: "var(--accent-soft)", border: "1px solid var(--border)", marginBottom: "0.75rem" }}>
          <strong>{t("lbOssCapabilitiesTitle")}</strong>
          <p style={{ margin: "0.35rem 0 0", color: "var(--muted)" }}>{t("lbOssCapabilitiesBody")}</p>
        </div>
        {error && <p className="error">{error}</p>}
        {ok && <p className="ok">{ok}</p>}
        {items.length === 0 ? (
          <p className="muted">{t("noPools")}</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t("name")}</th>
                <th>{t("algorithm")}</th>
                <th>{t("members")}</th>
                <th>{t("actions")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => {
                const up = (u.members || []).filter((m) => !m.is_down && !m.is_drain).length;
                const down = (u.members || []).length - up;
                return (
                  <tr key={u.id} className={selected === u.id ? "row-active" : undefined}>
                    <td>
                      <button type="button" className="linkish" onClick={() => { setSelected(u.id); setEditingPool(false); }}>
                        <code>{u.name}</code>
                      </button>
                    </td>
                    <td>
                      <code>{u.algorithm}</code>
                    </td>
                    <td>
                      {u.members?.length ?? 0}
                      <span className="muted" style={{ fontSize: "0.78rem", marginLeft: 6 }}>
                        ↑{up} ↓{down}
                      </span>
                    </td>
                    <td>
                      <div className="row" style={{ gap: "0.35rem", flexWrap: "wrap" }}>
                        <button type="button" className="secondary" onClick={() => startEdit(u)}>
                          {t("edit")}
                        </button>
                        <button type="button" className="danger" onClick={() => void removeUpstream(u)}>
                          {t("delete")}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {current && (
          <div className="stack" style={{ marginTop: 16 }}>
            <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
              <h3 style={{ margin: 0 }}>
                {t("members")}: <code>{current.name}</code>
              </h3>
              <div className="row" style={{ gap: 6, alignItems: "center" }}>
                <button
                  type="button"
                  className={`icon-btn secondary${refreshing ? " is-spinning" : ""}`}
                  title={t("refreshMembers")}
                  aria-label={t("refreshMembers")}
                  disabled={refreshing}
                  onClick={() => void refreshMembers()}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M21 12a9 9 0 1 1-2.64-6.36" />
                    <path d="M21 3v6h-6" />
                  </svg>
                </button>
                {!editingPool && (
                  <button type="button" className="secondary" onClick={() => startEdit(current)}>
                    {t("editPool")}
                  </button>
                )}
              </div>
            </div>
            <p className="field-hint">
              {t("metricsNote")} · algo=<code>{current.algorithm}</code> · passive max_fails=
              <code>{current.max_fails}</code>/<code>{current.fail_timeout}</code>
              {current.health_check_enabled ? ` · HC ${current.health_check_path}` : ""}
            </p>

            {editingPool && (
              <form className="stack location-card" onSubmit={(e) => void onUpdatePool(e)}>
                <h3 style={{ margin: 0 }}>{t("editPool")}</h3>
                {renderPoolFields(editForm, setEditForm, { nameDisabled: true })}
                <div className="row">
                  <button type="submit">{t("save")}</button>
                  <button type="button" className="secondary" onClick={() => setEditingPool(false)}>
                    {t("cancel")}
                  </button>
                </div>
              </form>
            )}

            {(current.members || []).length === 0 ? (
              <p className="muted">{t("noMembers")}</p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>{t("upstream")}</th>
                    <th>{t("weight")}</th>
                    <th>{t("maxConns")}</th>
                    <th>{t("status")}</th>
                    <th>{t("actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(current.members || []).map((m) =>
                    editingMemberId === m.id ? (
                      <tr key={m.id}>
                        <td colSpan={5}>
                          <form
                            className="stack"
                            style={{ gap: "0.65rem" }}
                            onSubmit={(e) => {
                              e.preventDefault();
                              void saveMemberEdit(current, m);
                            }}
                          >
                            <strong>{t("editMember")}</strong>
                            <div className="grid two">
                              <div>
                                <label>{t("memberHost")}</label>
                                <input
                                  value={memberEdit.host}
                                  onChange={(e) => setMemberEdit({ ...memberEdit, host: e.target.value })}
                                  required
                                />
                              </div>
                              <div>
                                <label>{t("port")}</label>
                                <input
                                  type="number"
                                  value={memberEdit.port}
                                  onChange={(e) =>
                                    setMemberEdit({ ...memberEdit, port: Number(e.target.value) })
                                  }
                                  required
                                />
                              </div>
                            </div>
                            <div className="grid two">
                              <div>
                                <label>{t("weight")}</label>
                                <input
                                  type="number"
                                  min={1}
                                  value={memberEdit.weight}
                                  onChange={(e) =>
                                    setMemberEdit({ ...memberEdit, weight: Number(e.target.value) })
                                  }
                                />
                              </div>
                              <div>
                                <label>{t("maxConns")}</label>
                                <input
                                  type="number"
                                  min={0}
                                  value={memberEdit.max_conns}
                                  onChange={(e) =>
                                    setMemberEdit({ ...memberEdit, max_conns: Number(e.target.value) })
                                  }
                                />
                                <p className="field-hint">{t("maxConnsHint")}</p>
                              </div>
                            </div>
                            <label className="check-row">
                              <input
                                type="checkbox"
                                checked={memberEdit.is_backup}
                                onChange={(e) =>
                                  setMemberEdit({ ...memberEdit, is_backup: e.target.checked })
                                }
                              />
                              {t("backup")} ({t("failover")})
                            </label>
                            <div className="row">
                              <button type="submit">{t("save")}</button>
                              <button
                                type="button"
                                className="secondary"
                                onClick={() => setEditingMemberId(null)}
                              >
                                {t("cancel")}
                              </button>
                            </div>
                          </form>
                        </td>
                      </tr>
                    ) : (
                      <tr key={m.id}>
                        <td>
                          <code>
                            {m.host}:{m.port}
                          </code>
                          {m.is_backup ? <span className="muted"> backup</span> : null}
                        </td>
                        <td>
                          <div className="row" style={{ gap: 4, alignItems: "center" }}>
                            <input
                              style={{ width: 64 }}
                              type="number"
                              min={1}
                              value={weightEdit[m.id] ?? m.weight}
                              onChange={(e) =>
                                setWeightEdit({ ...weightEdit, [m.id]: Number(e.target.value) })
                              }
                            />
                            <button
                              type="button"
                              className="icon-btn secondary"
                              title={t("save")}
                              aria-label={t("save")}
                              onClick={() => void saveWeight(current, m)}
                            >
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M20 6 9 17l-5-5" />
                              </svg>
                            </button>
                          </div>
                        </td>
                        <td>
                          <span className="muted">
                            {m.max_conns && m.max_conns > 0 ? m.max_conns : "∞"}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${m.is_down || m.is_drain ? "badge-off" : "badge-ok"}`}>
                            {memberStatus(m, t)}
                          </span>
                        </td>
                        <td>
                          <div className="action-icons">
                            <button
                              type="button"
                              className="icon-btn secondary"
                              title={t("edit")}
                              aria-label={t("edit")}
                              onClick={() => startEditMember(m)}
                            >
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M12 20h9" />
                                <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
                              </svg>
                            </button>
                            <button
                              type="button"
                              className={`icon-btn secondary ${m.is_down && !m.is_drain ? "" : "is-on"}`}
                              title={m.is_down && !m.is_drain ? t("enable") : t("disable")}
                              aria-label={m.is_down && !m.is_drain ? t("enable") : t("disable")}
                              onClick={() => {
                                const disabled = m.is_down && !m.is_drain;
                                void patchMember(
                                  current,
                                  m,
                                  disabled
                                    ? { is_down: false, is_drain: false }
                                    : { is_down: true, is_drain: false },
                                );
                              }}
                            >
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M12 2v10" />
                                <path d="M18.4 6.6a8 8 0 1 1-12.8 0" />
                              </svg>
                            </button>
                            <button
                              type="button"
                              className={`icon-btn secondary ${m.is_drain ? "is-on" : ""}`}
                              title={m.is_drain ? t("undrain") : t("drain")}
                              aria-label={m.is_drain ? t("undrain") : t("drain")}
                              onClick={() => {
                                if (m.is_drain) {
                                  void patchMember(current, m, { is_drain: false, is_down: false });
                                } else {
                                  void patchMember(current, m, { is_drain: true });
                                }
                              }}
                            >
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M12 2v6" />
                                <path d="M12 22a7 7 0 0 0 7-7c0-4-7-9-7-9s-7 5-7 9a7 7 0 0 0 7 7Z" />
                              </svg>
                            </button>
                            <button
                              type="button"
                              className="icon-btn danger"
                              title={t("delete")}
                              aria-label={t("delete")}
                              onClick={() => void removeMember(current, m)}
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
                    ),
                  )}
                </tbody>
              </table>
            )}

            <form className="stack" onSubmit={(e) => void addMember(e)}>
              <h3 className="heading-with-help" style={{ margin: 0 }}>
                {t("addMember")}
                <HelpTip text={t("helpAddMember")} />
              </h3>
              <div className="grid two">
                <div>
                  <label>{t("memberHost")}</label>
                  <input
                    value={member.host}
                    onChange={(e) => setMember({ ...member, host: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label>{t("port")}</label>
                  <input
                    type="number"
                    value={member.port}
                    onChange={(e) => setMember({ ...member, port: Number(e.target.value) })}
                  />
                </div>
              </div>
              <div className="grid two">
                <div>
                  <label>{t("weight")}</label>
                  <input
                    type="number"
                    min={1}
                    value={member.weight}
                    onChange={(e) => setMember({ ...member, weight: Number(e.target.value) })}
                  />
                </div>
                <div>
                  <label>{t("maxConns")}</label>
                  <input
                    type="number"
                    min={0}
                    value={member.max_conns}
                    onChange={(e) => setMember({ ...member, max_conns: Number(e.target.value) })}
                  />
                  <p className="field-hint">{t("maxConnsHint")}</p>
                </div>
              </div>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={member.is_backup}
                  onChange={(e) => setMember({ ...member, is_backup: e.target.checked })}
                />
                {t("backup")} ({t("failover")})
              </label>
              <button type="submit">{t("addMember")}</button>
            </form>
          </div>
        )}
      </section>

      <section className="panel">
        <h2 className="heading-with-help">
          {t("createPool")}
          <HelpTip text={t("helpCreatePool")} />
        </h2>
        <form className="stack" onSubmit={(e) => void onCreate(e)}>
          {renderPoolFields(createForm, setCreateForm)}
          <button type="submit">{t("save")}</button>
        </form>
      </section>
    </div>
  );
}
