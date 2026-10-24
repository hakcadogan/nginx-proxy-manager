import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type Policy = {
  id: string;
  kind: string;
  ip_cidr: string;
  reason: string;
  source: string;
  expires_at?: string | null;
};

type HistoryRow = {
  id: number;
  action: string;
  kind: string;
  ip_cidr: string;
  reason: string;
  source: string;
  country_code?: string;
  actor_email?: string;
  created_at: string;
};

type SecEvent = {
  id: number;
  source: string;
  rule_id: string;
  message: string;
  client_ip: string;
  created_at: string;
  payload_summary?: string;
};

type DetectionSettings = {
  http_probing_capacity: number;
  http_probing_leakspeed: string;
  http_probing_blackhole: string;
  http_crawl_capacity: number;
  http_crawl_leakspeed: string;
  http_crawl_blackhole: string;
  http_bf_capacity: number;
  http_bf_leakspeed: string;
  http_bf_blackhole: string;
  ban_duration: string;
};

type Tab = "policies" | "timeline" | "history" | "protected" | "detection";
type PolicyKind = "ban" | "allow" | "deny";

const PER_PAGE = 50;
const POLICY_KINDS: PolicyKind[] = ["ban", "allow", "deny"];

type KindBucket = { items: Policy[]; total: number; page: number };

const emptyBuckets = (): Record<PolicyKind, KindBucket> => ({
  ban: { items: [], total: 0, page: 1 },
  allow: { items: [], total: 0, page: 1 },
  deny: { items: [], total: 0, page: 1 },
});

const emptyDetection = (): DetectionSettings => ({
  http_probing_capacity: 10,
  http_probing_leakspeed: "10s",
  http_probing_blackhole: "5m",
  http_crawl_capacity: 40,
  http_crawl_leakspeed: "0.5s",
  http_crawl_blackhole: "1m",
  http_bf_capacity: 5,
  http_bf_leakspeed: "10s",
  http_bf_blackhole: "1m",
  ban_duration: "4h",
});

function matchesIP(hay: string, q: string): boolean {
  if (!q) return true;
  return hay.toLowerCase().includes(q.toLowerCase());
}

/** Extract IPs/CIDRs from CSV or plain text (first column; skip header). */
function parsePolicyCSV(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    // strip BOM
    if (i === 0 && line.charCodeAt(0) === 0xfeff) line = line.slice(1).trim();
    const first = line.split(/[,;\t]/)[0]?.trim().replace(/^"|"$/g, "") ?? "";
    if (!first) continue;
    const lower = first.toLowerCase();
    if (i === 0 && (lower === "ip" || lower === "cidr" || lower === "ip_cidr" || lower === "address")) {
      continue;
    }
    const key = lower;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(first);
  }
  return out;
}

export default function IDSPage() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("policies");
  const [buckets, setBuckets] = useState(emptyBuckets);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [events, setEvents] = useState<SecEvent[]>([]);
  const [lapiOK, setLapiOK] = useState(false);
  const [enforcement, setEnforcement] = useState<"active" | "passive">("active");
  const [enforcementBusy, setEnforcementBusy] = useState(false);
  const [realIPWarn, setRealIPWarn] = useState(false);
  const [protectedCIDRs, setProtectedCIDRs] = useState("127.0.0.1,::1");
  const [detection, setDetection] = useState<DetectionSettings>(emptyDetection);
  const [agentOK, setAgentOK] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [form, setForm] = useState({ ip: "", reason: "", kind: "ban" as PolicyKind, ttl_hours: 24 });
  const [ipQuery, setIpQuery] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busy, setBusy] = useState(false);

  const totalPolicies = buckets.ban.total + buckets.allow.total + buckets.deny.total;

  const fetchKind = useCallback(async (kind: PolicyKind, page: number, q: string) => {
    const params = new URLSearchParams({
      kind,
      page: String(page),
      per_page: String(PER_PAGE),
    });
    if (q.trim()) params.set("q", q.trim());
    return api<{
      items: Policy[];
      total: number;
      page: number;
      lapi_ok: boolean;
      enforcement?: string;
      real_ip_warning?: boolean;
      protected_cidrs?: string;
    }>(`/api/v1/ids/decisions?${params}`);
  }, []);

  const loadDecisions = useCallback(
    async (q = ipQuery, pages?: Partial<Record<PolicyKind, number>>) => {
      const pageMap: Record<PolicyKind, number> = {
        ban: pages?.ban ?? buckets.ban.page,
        allow: pages?.allow ?? buckets.allow.page,
        deny: pages?.deny ?? buckets.deny.page,
      };
      const results = await Promise.all(POLICY_KINDS.map((k) => fetchKind(k, pageMap[k], q)));
      const next = emptyBuckets();
      POLICY_KINDS.forEach((k, i) => {
        const data = results[i];
        next[k] = {
          items: data.items || [],
          total: data.total ?? (data.items || []).length,
          page: data.page || pageMap[k],
        };
      });
      setBuckets(next);
      const meta = results[0];
      setLapiOK(!!meta.lapi_ok);
      setRealIPWarn(!!meta.real_ip_warning);
      if (meta.enforcement === "passive" || meta.enforcement === "active") {
        setEnforcement(meta.enforcement);
      }
      if (meta.protected_cidrs) setProtectedCIDRs(meta.protected_cidrs);
      setSelected(new Set());
    },
    [buckets.ban.page, buckets.allow.page, buckets.deny.page, fetchKind, ipQuery],
  );

  async function setEnforcementMode(mode: "active" | "passive") {
    setError("");
    setOk("");
    setEnforcementBusy(true);
    try {
      const data = await api<{ enforcement: string }>("/api/v1/ids/enforcement", {
        method: "PUT",
        body: JSON.stringify({ enforcement: mode }),
      });
      setEnforcement(data.enforcement === "passive" ? "passive" : "active");
      setOk(mode === "passive" ? t("idsEnforcementPassiveOk") : t("idsEnforcementActiveOk"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setEnforcementBusy(false);
    }
  }

  async function loadHistory() {
    const data = await api<{ items: HistoryRow[] }>("/api/v1/ids/history?per_page=80");
    setHistory(data.items || []);
  }

  async function loadTimeline() {
    const data = await api<{ items: SecEvent[] }>("/api/v1/security-events?per_page=80");
    setEvents(data.items || []);
  }

  async function loadDetection() {
    const data = await api<{
      settings: DetectionSettings;
      agent_ok: boolean;
    }>("/api/v1/ids/detection");
    if (data.settings) setDetection({ ...emptyDetection(), ...data.settings });
    setAgentOK(!!data.agent_ok);
  }

  useEffect(() => {
    loadDecisions("", { ban: 1, allow: 1, deny: 1 }).catch((e) => setError(String(e.message || e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (tab === "history") loadHistory().catch((e) => setError(String(e.message || e)));
    if (tab === "timeline") loadTimeline().catch((e) => setError(String(e.message || e)));
    if (tab === "detection") loadDetection().catch((e) => setError(String(e.message || e)));
  }, [tab]);

  // Debounced server search for policies
  useEffect(() => {
    if (tab !== "policies") return;
    const tmr = window.setTimeout(() => {
      setIpQuery(searchInput);
      loadDecisions(searchInput, { ban: 1, allow: 1, deny: 1 }).catch((e) => setError(String(e.message || e)));
    }, 300);
    return () => window.clearTimeout(tmr);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput, tab]);

  const filteredHistory = useMemo(
    () =>
      history.filter(
        (h) =>
          matchesIP(h.ip_cidr, searchInput) ||
          matchesIP(h.reason || "", searchInput) ||
          matchesIP(h.action, searchInput),
      ),
    [history, searchInput],
  );

  const filteredEvents = useMemo(
    () =>
      events.filter(
        (ev) =>
          matchesIP(ev.client_ip, searchInput) ||
          matchesIP(ev.message || "", searchInput) ||
          matchesIP(ev.rule_id, searchInput),
      ),
    [events, searchInput],
  );

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    const path =
      form.kind === "allow" ? "/api/v1/ids/allowlist" : form.kind === "deny" ? "/api/v1/ids/denylist" : "/api/v1/ids/bans";
    try {
      await api(path, {
        method: "POST",
        body: JSON.stringify({
          ip: form.ip,
          reason: form.reason || form.kind,
          ttl_hours: form.kind === "ban" ? form.ttl_hours : 0,
        }),
      });
      setForm((f) => ({ ...f, ip: "", reason: "" }));
      setOk(t("savedOk"));
      await loadDecisions(ipQuery, { ...{ ban: buckets.ban.page, allow: buckets.allow.page, deny: buckets.deny.page }, [form.kind]: 1 });
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function onCSVImport(file: File | null) {
    if (!file) return;
    setError("");
    setOk("");
    setBusy(true);
    try {
      const text = await file.text();
      const ips = parsePolicyCSV(text);
      if (ips.length === 0) {
        setError(t("csvNoIps"));
        return;
      }
      if (ips.length > 500) {
        setError(t("csvTooMany", { count: ips.length }));
        return;
      }
      if (!window.confirm(t("confirmCsvImport", { count: ips.length, kind: form.kind }))) return;
      const res = await api<{ created: number; skipped: number; errors?: string[] }>(
        "/api/v1/ids/policies/bulk-create",
        {
          method: "POST",
          body: JSON.stringify({
            kind: form.kind,
            reason: form.reason || form.kind,
            ttl_hours: form.kind === "ban" ? form.ttl_hours : 0,
            ips,
          }),
        },
      );
      const errN = res.errors?.length ?? 0;
      setOk(t("csvImportOk", { created: res.created ?? 0, skipped: res.skipped ?? 0, errors: errN }));
      if (errN > 0 && res.errors) {
        setError(res.errors.slice(0, 5).join("; "));
      }
      await loadDecisions(ipQuery, { ban: 1, allow: 1, deny: 1 });
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  async function removeOne(p: Policy) {
    if (!window.confirm(t("confirmRemovePolicy", { ip: p.ip_cidr, kind: p.kind }))) return;
    setError("");
    setOk("");
    setBusy(true);
    try {
      const path =
        p.kind === "allow"
          ? `/api/v1/ids/allowlist/${p.id}`
          : p.kind === "deny"
            ? `/api/v1/ids/denylist/${p.id}`
            : `/api/v1/ids/bans/${p.id}`;
      await api(path, { method: "DELETE" });
      setOk(t("idsDeleteQueued"));
      const kind = p.kind as PolicyKind;
      setBuckets((prev) => ({
        ...prev,
        [kind]: {
          ...prev[kind],
          items: prev[kind].items.filter((x) => x.id !== p.id),
          total: Math.max(0, prev[kind].total - 1),
        },
      }));
      setSelected((prev) => {
        const next = new Set(prev);
        next.delete(p.id);
        return next;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  async function removeSelected() {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    if (!window.confirm(t("confirmBulkRemovePolicies", { count: ids.length }))) return;
    setError("");
    setOk("");
    setBusy(true);
    try {
      const res = await api<{ deleted: number }>("/api/v1/ids/policies/bulk-delete", {
        method: "POST",
        body: JSON.stringify({ ids }),
      });
      setOk(t("bulkRemovedOk", { count: res.deleted ?? ids.length }));
      await loadDecisions(ipQuery);
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleKindPage(kind: PolicyKind) {
    const items = buckets[kind].items;
    const allSelected = items.length > 0 && items.every((p) => selected.has(p.id));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        for (const p of items) next.delete(p.id);
      } else {
        for (const p of items) next.add(p.id);
      }
      return next;
    });
  }

  async function goKindPage(kind: PolicyKind, p: number) {
    const pageCount = Math.max(1, Math.ceil(buckets[kind].total / PER_PAGE));
    const next = Math.min(pageCount, Math.max(1, p));
    setBusy(true);
    try {
      await loadDecisions(ipQuery, {
        ban: buckets.ban.page,
        allow: buckets.allow.page,
        deny: buckets.deny.page,
        [kind]: next,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  async function saveProtected(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    try {
      await api("/api/v1/ids/protected", {
        method: "PUT",
        body: JSON.stringify({ protected_cidrs: protectedCIDRs }),
      });
      setOk(t("savedOk"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveDetection(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    setBusy(true);
    try {
      const data = await api<{ settings: DetectionSettings; applied?: boolean }>("/api/v1/ids/detection", {
        method: "PUT",
        body: JSON.stringify(detection),
      });
      if (data.settings) setDetection({ ...emptyDetection(), ...data.settings });
      setOk(t("idsDetectionSaved"));
      await loadDetection();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  function setDet<K extends keyof DetectionSettings>(key: K, value: DetectionSettings[K]) {
    setDetection((prev) => ({ ...prev, [key]: value }));
  }

  const showSearch = tab === "policies" || tab === "timeline" || tab === "history";

  return (
    <div className="stack">
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        {(["policies", "timeline", "history", "protected", "detection"] as Tab[]).map((id) => (
          <button
            key={id}
            type="button"
            className={tab === id ? undefined : "secondary"}
            onClick={() => setTab(id)}
          >
            {t(`idsTab_${id}`)}
          </button>
        ))}
      </div>

      <div className="row" style={{ gap: "0.75rem", flexWrap: "wrap", alignItems: "center" }}>
        <span className="muted">
          LAPI: {lapiOK ? "✓" : "—"} · {t("bouncerType")} · GeoIP: {t("geoipDeferred")}
          {tab === "policies"
            ? ` · ${totalPolicies} ${t("idsTotalPolicies")} (ban ${buckets.ban.total} · allow ${buckets.allow.total} · deny ${buckets.deny.total})`
            : ""}
        </span>
        <div className="row" style={{ gap: 6, alignItems: "center" }} title={t("idsEnforcementHint")}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>
            {t("idsEnforcement")}:
          </span>
          <button
            type="button"
            className={enforcement === "active" ? undefined : "secondary"}
            disabled={enforcementBusy || enforcement === "active"}
            onClick={() => void setEnforcementMode("active")}
          >
            {t("idsActive")}
          </button>
          <button
            type="button"
            className={enforcement === "passive" ? undefined : "secondary"}
            disabled={enforcementBusy || enforcement === "passive"}
            onClick={() => void setEnforcementMode("passive")}
          >
            {t("idsPassive")}
          </button>
          <span className={`badge ${enforcement === "active" ? "badge-ok" : "badge-warn"}`}>
            {enforcement === "active" ? t("idsActive") : t("idsPassive")}
          </span>
        </div>
      </div>
      {enforcement === "passive" && <div className="callout warn">{t("idsPassiveCallout")}</div>}
      {realIPWarn && <div className="callout warn">{t("realIpWarningIds")}</div>}
      {error && <p className="error">{error}</p>}
      {ok && <p className="ok">{ok}</p>}

      {showSearch && (
        <div className="toolbar">
          <input
            className="search"
            type="search"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder={t("searchIdsIp")}
            aria-label={t("searchIdsIp")}
          />
          {tab === "policies" && selected.size > 0 && (
            <button type="button" className="danger" disabled={busy} onClick={() => void removeSelected()}>
              {t("bulkRemove")} ({selected.size})
            </button>
          )}
        </div>
      )}

      {tab === "policies" && (
        <div className="stack">
          <section className="panel stack">
            <h2 className="heading-with-help">
              {t("addPolicy")}
              <HelpTip text={t("helpIdsPolicies")} />
            </h2>
            <form className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-end" }} onSubmit={(e) => void onCreate(e)}>
              <div>
                <label>{t("policyKind")}</label>
                <select
                  value={form.kind}
                  onChange={(e) => setForm({ ...form, kind: e.target.value as PolicyKind })}
                >
                  <option value="ban">ban</option>
                  <option value="allow">allow</option>
                  <option value="deny">deny</option>
                </select>
              </div>
              <div>
                <label>IP / CIDR</label>
                <input
                  required
                  value={form.ip}
                  onChange={(e) => setForm({ ...form, ip: e.target.value })}
                  placeholder="203.0.113.10"
                />
              </div>
              <div>
                <label>{t("reason")}</label>
                <input
                  value={form.reason}
                  onChange={(e) => setForm({ ...form, reason: e.target.value })}
                  placeholder={t("reasonSharedHint")}
                />
              </div>
              {form.kind === "ban" && (
                <div>
                  <label>TTL (h)</label>
                  <input
                    type="number"
                    min={0}
                    value={form.ttl_hours}
                    onChange={(e) => setForm({ ...form, ttl_hours: Number(e.target.value) })}
                  />
                </div>
              )}
              <button type="submit" disabled={busy}>
                {t("save")}
              </button>
            </form>
            <div className="stack" style={{ marginTop: 8 }}>
              <label htmlFor="ids-csv-import">{t("csvImportLabel")}</label>
              <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                {t("csvImportHint")}
              </p>
              <input
                id="ids-csv-import"
                type="file"
                accept=".csv,.txt,text/csv,text/plain"
                disabled={busy}
                onChange={(e) => {
                  const f = e.target.files?.[0] ?? null;
                  e.target.value = "";
                  void onCSVImport(f);
                }}
              />
            </div>
          </section>

          {POLICY_KINDS.map((kind) => {
            const bucket = buckets[kind];
            const pageCount = Math.max(1, Math.ceil(bucket.total / PER_PAGE));
            const allSelected = bucket.items.length > 0 && bucket.items.every((p) => selected.has(p.id));
            return (
              <section key={kind} className="panel stack">
                <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap", gap: 8 }}>
                  <h2 className="heading-with-help" style={{ margin: 0 }}>
                    {t(`idsPolicyTable_${kind}`)}
                    <HelpTip text={t(`idsPolicyTableHelp_${kind}`)} />
                  </h2>
                  <span className="muted">
                    {bucket.total} {t("idsTotalPolicies")}
                  </span>
                </div>
                <table className="table">
                  <thead>
                    <tr>
                      <th style={{ width: 36 }}>
                        <input
                          type="checkbox"
                          checked={allSelected}
                          onChange={() => toggleKindPage(kind)}
                          disabled={bucket.items.length === 0 || busy}
                          aria-label={t("selectAll")}
                        />
                      </th>
                      <th>IP</th>
                      <th>{t("reason")}</th>
                      <th>{t("policySource")}</th>
                      <th>{t("actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {bucket.items.map((p) => (
                      <tr key={p.id} className={selected.has(p.id) ? "row-active" : undefined}>
                        <td>
                          <input
                            type="checkbox"
                            checked={selected.has(p.id)}
                            onChange={() => toggleOne(p.id)}
                            disabled={busy}
                            aria-label={p.ip_cidr}
                          />
                        </td>
                        <td>
                          <code>{p.ip_cidr}</code>
                          {p.expires_at ? (
                            <div className="muted" style={{ fontSize: 12 }}>
                              TTL {new Date(p.expires_at).toLocaleString()}
                            </div>
                          ) : null}
                        </td>
                        <td>{p.reason || "—"}</td>
                        <td>{p.source}</td>
                        <td>
                          <button type="button" className="danger" disabled={busy} onClick={() => void removeOne(p)}>
                            {t("unban")}
                          </button>
                        </td>
                      </tr>
                    ))}
                    {bucket.items.length === 0 && (
                      <tr>
                        <td colSpan={5} className="muted">
                          {bucket.total === 0 ? t("noEvents") : t("noSearchResults")}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
                {bucket.total > PER_PAGE && (
                  <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy || bucket.page <= 1}
                      onClick={() => void goKindPage(kind, bucket.page - 1)}
                    >
                      ←
                    </button>
                    <span className="muted">
                      {bucket.page} / {pageCount}
                    </span>
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy || bucket.page >= pageCount}
                      onClick={() => void goKindPage(kind, bucket.page + 1)}
                    >
                      →
                    </button>
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}

      {tab === "timeline" && (
        <section className="panel">
          <h2>{t("idsTab_timeline")}</h2>
          <table className="table">
            <thead>
              <tr>
                <th>{t("time")}</th>
                <th>{t("policySource")}</th>
                <th>IP</th>
                <th>{t("eventType")}</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((ev) => (
                <tr key={ev.id}>
                  <td>{new Date(ev.created_at).toLocaleString()}</td>
                  <td>{ev.source}</td>
                  <td>
                    <code>{ev.client_ip}</code>
                  </td>
                  <td>
                    <code>{ev.rule_id}</code>
                    <div className="muted" style={{ fontSize: 12 }}>
                      {ev.message}
                    </div>
                  </td>
                </tr>
              ))}
              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    {events.length === 0 ? t("noEvents") : t("noSearchResults")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </section>
      )}

      {tab === "history" && (
        <section className="panel">
          <h2>{t("idsTab_history")}</h2>
          <table className="table">
            <thead>
              <tr>
                <th>{t("time")}</th>
                <th>{t("actions")}</th>
                <th>{t("policyKind")}</th>
                <th>IP</th>
                <th>{t("policySource")}</th>
                <th>Geo</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((h) => (
                <tr key={h.id}>
                  <td>{new Date(h.created_at).toLocaleString()}</td>
                  <td>{h.action}</td>
                  <td>{h.kind}</td>
                  <td>
                    <code>{h.ip_cidr}</code>
                    <div className="muted" style={{ fontSize: 12 }}>
                      {h.reason}
                      {h.actor_email ? ` · ${h.actor_email}` : ""}
                    </div>
                  </td>
                  <td>{h.source}</td>
                  <td>{h.country_code || "—"}</td>
                </tr>
              ))}
              {filteredHistory.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    {history.length === 0 ? t("noEvents") : t("noSearchResults")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </section>
      )}

      {tab === "protected" && (
        <section className="panel stack">
          <h2 className="heading-with-help">
            {t("idsTab_protected")}
            <HelpTip text={t("helpIdsProtected")} />
          </h2>
          <p className="muted">{t("protectedHint")}</p>
          <form className="stack" onSubmit={(e) => void saveProtected(e)}>
            <div>
              <label>{t("protectedCidrs")}</label>
              <input
                value={protectedCIDRs}
                onChange={(e) => setProtectedCIDRs(e.target.value)}
                placeholder="127.0.0.1,::1,10.0.0.0/8"
              />
            </div>
            <button type="submit">{t("save")}</button>
          </form>
        </section>
      )}

      {tab === "detection" && (
        <section className="panel stack">
          <h2 className="heading-with-help">
            {t("idsTab_detection")}
            <HelpTip text={t("helpIdsDetection")} />
          </h2>
          <p className="muted">{t("idsDetectionHint")}</p>
          <p className={agentOK ? "ok" : "error"} style={{ margin: 0 }}>
            {agentOK ? t("idsAgentOk") : t("idsAgentDown")}
          </p>
          <form className="stack" onSubmit={(e) => void saveDetection(e)}>
            <fieldset className="stack" style={{ border: "1px solid var(--border, #333)", padding: 12 }}>
              <legend>{t("idsDetProbing")}</legend>
              <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                {t("idsDetProbingHelp")}
              </p>
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <div>
                  <label>{t("idsDetCapacity")}</label>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={detection.http_probing_capacity}
                    onChange={(e) => setDet("http_probing_capacity", Number(e.target.value) || 0)}
                  />
                </div>
                <div>
                  <label>{t("idsDetLeakSpeed")}</label>
                  <input
                    value={detection.http_probing_leakspeed}
                    onChange={(e) => setDet("http_probing_leakspeed", e.target.value)}
                    placeholder="10s"
                  />
                </div>
                <div>
                  <label>{t("idsDetBlackhole")}</label>
                  <input
                    value={detection.http_probing_blackhole}
                    onChange={(e) => setDet("http_probing_blackhole", e.target.value)}
                    placeholder="5m"
                  />
                </div>
              </div>
            </fieldset>

            <fieldset className="stack" style={{ border: "1px solid var(--border, #333)", padding: 12 }}>
              <legend>{t("idsDetCrawl")}</legend>
              <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                {t("idsDetCrawlHelp")}
              </p>
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <div>
                  <label>{t("idsDetCapacity")}</label>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={detection.http_crawl_capacity}
                    onChange={(e) => setDet("http_crawl_capacity", Number(e.target.value) || 0)}
                  />
                </div>
                <div>
                  <label>{t("idsDetLeakSpeed")}</label>
                  <input
                    value={detection.http_crawl_leakspeed}
                    onChange={(e) => setDet("http_crawl_leakspeed", e.target.value)}
                    placeholder="0.5s"
                  />
                </div>
                <div>
                  <label>{t("idsDetBlackhole")}</label>
                  <input
                    value={detection.http_crawl_blackhole}
                    onChange={(e) => setDet("http_crawl_blackhole", e.target.value)}
                    placeholder="1m"
                  />
                </div>
              </div>
            </fieldset>

            <fieldset className="stack" style={{ border: "1px solid var(--border, #333)", padding: 12 }}>
              <legend>{t("idsDetBF")}</legend>
              <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                {t("idsDetBFHelp")}
              </p>
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <div>
                  <label>{t("idsDetCapacity")}</label>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={detection.http_bf_capacity}
                    onChange={(e) => setDet("http_bf_capacity", Number(e.target.value) || 0)}
                  />
                </div>
                <div>
                  <label>{t("idsDetLeakSpeed")}</label>
                  <input
                    value={detection.http_bf_leakspeed}
                    onChange={(e) => setDet("http_bf_leakspeed", e.target.value)}
                    placeholder="10s"
                  />
                </div>
                <div>
                  <label>{t("idsDetBlackhole")}</label>
                  <input
                    value={detection.http_bf_blackhole}
                    onChange={(e) => setDet("http_bf_blackhole", e.target.value)}
                    placeholder="1m"
                  />
                </div>
              </div>
            </fieldset>

            <div>
              <label>{t("idsDetBanDuration")}</label>
              <input
                value={detection.ban_duration}
                onChange={(e) => setDet("ban_duration", e.target.value)}
                placeholder="4h"
              />
              <p className="muted" style={{ margin: "4px 0 0", fontSize: 13 }}>
                {t("idsDetBanDurationHelp")}
              </p>
            </div>

            <button type="submit" disabled={busy}>
              {busy ? t("saving") : t("save")}
            </button>
          </form>
        </section>
      )}
    </div>
  );
}
