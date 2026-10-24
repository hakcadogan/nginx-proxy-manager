import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type Policy = {
  id: string;
  name: string;
  scope: string;
  host_id?: string | null;
  enabled: boolean;
  engine_mode: string;
  paranoia_level: number;
  inbound_anomaly_score_threshold?: number;
  outbound_anomaly_score_threshold?: number;
};

type Exception = {
  id: string;
  policy_id: string;
  host_id?: string | null;
  rule_id: string;
  path_prefix: string;
  argument?: string;
  reason: string;
};

type Event = {
  id: number;
  rule_id: string;
  message: string;
  uri: string;
  method: string;
  domain?: string;
  client_ip: string;
  payload_summary: string;
  created_at: string;
};

type Host = { id: string; primary_domain: string; waf_enabled?: boolean };

type Report = {
  by_attack_type: Record<string, number>;
  top_rules: {
    rule_id: string;
    count: number;
    attack_type: string;
    last_client_ip?: string;
    last_seen?: string;
  }[];
  crs_version?: string;
  note?: string;
};

type ModSecSettings = {
  audit_engine: string;
  debug_log_level: number;
  audit_log_parts: string;
  audit_log_relevant_status: string;
  audit_log_type: string;
  request_body_access: string;
  response_body_access: string;
  request_body_limit: number;
};

type CRSRule = {
  id: string;
  msg: string;
  file: string;
  paranoia: number;
  category: string;
  phase: number;
  enabled: boolean;
};

type Tab = "policy" | "rules" | "exceptions" | "advanced" | "events";

const defaultModSec = (): ModSecSettings => ({
  audit_engine: "RelevantOnly",
  debug_log_level: 0,
  audit_log_parts: "ABIJDEFHZ",
  audit_log_relevant_status: "^(?:5|4(?!04))",
  audit_log_type: "Serial",
  request_body_access: "On",
  response_body_access: "Off",
  request_body_limit: 13107200,
});

export default function WAFPage() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("policy");
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [crs, setCrs] = useState("");
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [exForm, setExForm] = useState({
    rule_id: "",
    path_prefix: "",
    argument: "",
    reason: "",
    host_id: "",
  });
  const [eventQ, setEventQ] = useState("");
  const [eventRule, setEventRule] = useState("");
  const [eventDomain, setEventDomain] = useState("");
  const [eventsRefreshing, setEventsRefreshing] = useState(false);
  const [inboundThr, setInboundThr] = useState(5);
  const [uaText, setUaText] = useState("");
  const [uaPresets, setUaPresets] = useState<string[]>([]);
  const [modsec, setModsec] = useState<ModSecSettings>(defaultModSec);
  const [customGlobal, setCustomGlobal] = useState("");
  const [customHostId, setCustomHostId] = useState("");
  const [customHostText, setCustomHostText] = useState("");
  const [customHosts, setCustomHosts] = useState<Record<string, string>>({});
  const [hostPol, setHostPol] = useState({
    host_id: "",
    engine_mode: "DetectionOnly",
    enabled: true,
    paranoia_level: 1,
  });

  const [rules, setRules] = useState<CRSRule[]>([]);
  const [rulesTotal, setRulesTotal] = useState(0);
  const [rulesDisabled, setRulesDisabled] = useState(0);
  const [rulesCatalog, setRulesCatalog] = useState(0);
  const [rulesCats, setRulesCats] = useState<Record<string, number>>({});
  const [ruleQ, setRuleQ] = useState("");
  const [ruleCat, setRuleCat] = useState("");
  const [ruleEnabled, setRuleEnabled] = useState("");
  const [rulePage, setRulePage] = useState(1);
  const [ruleBusy, setRuleBusy] = useState<string | null>(null);

  const global = policies.find((p) => p.scope === "global");

  async function load() {
    const [p, e, ev, h, rep, ua, ms, cr] = await Promise.all([
      api<{ items: Policy[]; crs_version?: string }>("/api/v1/waf/policies"),
      api<{ items: Exception[] }>("/api/v1/waf/exceptions"),
      api<{ items: Event[] }>("/api/v1/waf/events?per_page=40&source=waf"),
      api<{ items: Host[] }>("/api/v1/hosts"),
      api<Report>("/api/v1/waf/report"),
      api<{ patterns: string[]; presets?: string[] }>("/api/v1/waf/ua-allowlist"),
      api<{ settings: ModSecSettings }>("/api/v1/waf/modsec-settings"),
      api<{ global?: string; hosts?: Record<string, string> }>("/api/v1/waf/custom-rules"),
    ]);
    setPolicies(p.items || []);
    setCrs(p.crs_version || "");
    setExceptions(e.items || []);
    setEvents(ev.items || []);
    setHosts(h.items || []);
    setReport(rep);
    setUaText((ua.patterns || []).join("\n"));
    setUaPresets(ua.presets || []);
    if (ms.settings) setModsec({ ...defaultModSec(), ...ms.settings });
    setCustomGlobal(cr.global || "");
    setCustomHosts(cr.hosts || {});
    const g = (p.items || []).find((x) => x.scope === "global");
    if (g?.inbound_anomaly_score_threshold) {
      setInboundThr(g.inbound_anomaly_score_threshold);
    }
  }

  const loadRules = useCallback(async () => {
    const params = new URLSearchParams({ page: String(rulePage), per_page: "50" });
    if (ruleQ.trim()) params.set("q", ruleQ.trim());
    if (ruleCat) params.set("category", ruleCat);
    if (ruleEnabled) params.set("enabled", ruleEnabled);
    const data = await api<{
      items: CRSRule[];
      total: number;
      disabled_count: number;
      catalog_count: number;
      categories?: Record<string, number>;
      crs_version?: string;
    }>(`/api/v1/waf/crs-rules?${params}`);
    setRules(data.items || []);
    setRulesTotal(data.total || 0);
    setRulesDisabled(data.disabled_count || 0);
    setRulesCatalog(data.catalog_count || 0);
    setRulesCats(data.categories || {});
    if (data.crs_version) setCrs(data.crs_version);
  }, [rulePage, ruleQ, ruleCat, ruleEnabled]);

  useEffect(() => {
    load().catch((err) => setError(String(err.message || err)));
  }, []);

  useEffect(() => {
    if (tab !== "rules") return;
    loadRules().catch((err) => setError(String(err.message || err)));
  }, [tab, loadRules]);

  async function applyConfig() {
    await api("/api/v1/config/apply", { method: "POST", body: "{}" });
  }

  async function setMode(mode: string) {
    if (!global) return;
    if (mode === "On") {
      if (!window.confirm(t("blockingConfirm"))) return;
    }
    setError("");
    setOk("");
    try {
      await api(`/api/v1/waf/policies/${global.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          ...global,
          engine_mode: mode,
          enabled: mode !== "Off",
          inbound_anomaly_score_threshold: inboundThr,
        }),
      });
      await applyConfig();
      setOk(t("applied"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function setPL(level: number) {
    if (!global) return;
    try {
      await api(`/api/v1/waf/policies/${global.id}`, {
        method: "PATCH",
        body: JSON.stringify({ ...global, paranoia_level: level, inbound_anomaly_score_threshold: inboundThr }),
      });
      await applyConfig();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveAnomaly(e: FormEvent) {
    e.preventDefault();
    if (!global) return;
    setError("");
    try {
      await api(`/api/v1/waf/policies/${global.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          ...global,
          inbound_anomaly_score_threshold: inboundThr,
          outbound_anomaly_score_threshold: global.outbound_anomaly_score_threshold || 4,
        }),
      });
      await applyConfig();
      setOk(t("applied"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveHostPolicy(e: FormEvent) {
    e.preventDefault();
    if (!hostPol.host_id) return;
    if (hostPol.engine_mode === "On") {
      if (!window.confirm(t("blockingConfirm"))) return;
    }
    setError("");
    try {
      await api("/api/v1/waf/policies/host", {
        method: "POST",
        body: JSON.stringify(hostPol),
      });
      await applyConfig();
      setOk(t("applied"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  const exIsGlobal = useMemo(
    () => !exForm.host_id && !exForm.path_prefix.trim() && !exForm.argument.trim(),
    [exForm],
  );

  async function addException(e: FormEvent) {
    e.preventDefault();
    if (!global) return;
    if (exIsGlobal) {
      if (!window.confirm(t("globalExceptionConfirm"))) return;
    }
    setError("");
    try {
      await api("/api/v1/waf/exceptions", {
        method: "POST",
        body: JSON.stringify({
          policy_id: global.id,
          rule_id: exForm.rule_id,
          path_prefix: exForm.path_prefix,
          argument: exForm.argument,
          reason: exForm.reason,
          host_id: exForm.host_id || null,
        }),
      });
      setExForm({ rule_id: "", path_prefix: "", argument: "", reason: "", host_id: "" });
      await applyConfig();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function removeEx(x: Exception) {
    if (!window.confirm(t("confirmDeleteException", { rule: x.rule_id || x.id }))) return;
    setError("");
    try {
      await api(`/api/v1/waf/exceptions/${x.id}`, { method: "DELETE" });
      await applyConfig();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveUAAllowlist(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    const patterns = uaText
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    try {
      await api("/api/v1/waf/ua-allowlist", {
        method: "PUT",
        body: JSON.stringify({ patterns }),
      });
      await applyConfig();
      setOk(t("uaAllowlistSaved"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  function addUAPreset(phrase: string) {
    const lines = new Set(
      uaText
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean),
    );
    lines.add(phrase);
    setUaText(Array.from(lines).join("\n"));
  }

  async function saveModSec(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    try {
      await api("/api/v1/waf/modsec-settings", {
        method: "PUT",
        body: JSON.stringify({ settings: modsec }),
      });
      await applyConfig();
      setOk(t("modsecSettingsSaved"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function saveCustomRules(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    const hostsMap = { ...customHosts };
    if (customHostId) {
      const text = customHostText.trim();
      if (text) hostsMap[customHostId] = text;
      else delete hostsMap[customHostId];
    }
    try {
      await api("/api/v1/waf/custom-rules", {
        method: "PUT",
        body: JSON.stringify({ global: customGlobal, hosts: hostsMap }),
      });
      await applyConfig();
      setOk(t("customRulesSaved"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  function selectCustomHost(id: string) {
    setCustomHostId(id);
    setCustomHostText(id ? customHosts[id] || "" : "");
  }

  function applyGlobalPreset(kind: "env") {
    const preset =
      kind === "env"
        ? `SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "@rx (?i)(?:^|[/?])\\.env(?:$|[/?&#])" \\\n    "id:1100500,phase:1,deny,status:403,log,msg:'NSP block .env access'"`
        : "";
    if (!preset) return;
    setCustomGlobal((prev) => {
      const cur = prev.trim();
      if (!cur) return preset;
      if (cur.includes("id:1100500")) return cur;
      return `${cur}\n${preset}`;
    });
  }

  async function suggest(id: number) {
    const data = await api<{ suggestion: Exception }>(`/api/v1/waf/events/${id}/suggest-exception`);
    setExForm({
      rule_id: data.suggestion.rule_id,
      path_prefix: data.suggestion.path_prefix || "",
      argument: data.suggestion.argument || "",
      reason: data.suggestion.reason,
      host_id: data.suggestion.host_id || "",
    });
    setTab("exceptions");
  }

  async function searchEvents(e?: FormEvent) {
    e?.preventDefault();
    setError("");
    setEventsRefreshing(true);
    try {
      const params = new URLSearchParams({ per_page: "40", source: "waf" });
      if (eventQ.trim()) params.set("q", eventQ.trim());
      if (eventRule.trim()) params.set("rule_id", eventRule.trim());
      if (eventDomain.trim()) params.set("domain", eventDomain.trim());
      const ev = await api<{ items: Event[] }>(`/api/v1/waf/events?${params}`);
      setEvents(ev.items || []);
      const rep = await api<Report>("/api/v1/waf/report");
      setReport(rep);
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setEventsRefreshing(false);
    }
  }

  function formatEventTime(iso?: string) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  async function toggleRule(rule: CRSRule, enabled: boolean) {
    if (!enabled && !window.confirm(t("wafRuleDisableConfirm", { id: rule.id }))) return;
    setRuleBusy(rule.id);
    setError("");
    setOk("");
    try {
      await api(`/api/v1/waf/crs-rules/${rule.id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled }),
      });
      await applyConfig();
      setOk(enabled ? t("wafRuleEnabledOk") : t("wafRuleDisabledOk"));
      await loadRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setRuleBusy(null);
    }
  }

  const hostName = (id?: string | null) =>
    id ? hosts.find((h) => h.id === id)?.primary_domain || id.slice(0, 8) : "*";

  const rulePages = Math.max(1, Math.ceil(rulesTotal / 50));
  const catOptions = Object.keys(rulesCats).sort();

  return (
    <div className="stack">
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {(["policy", "rules", "exceptions", "advanced", "events"] as Tab[]).map((id) => (
          <button key={id} type="button" className={tab === id ? undefined : "secondary"} onClick={() => setTab(id)}>
            {t(`wafTab_${id}`)}
          </button>
        ))}
        <span className="muted" style={{ marginLeft: "auto", fontSize: "0.85rem" }}>
          CRS: <code>{crs || "—"}</code>
          {tab === "rules" ? ` · ${rulesCatalog} ${t("wafRulesInCatalog")} · ${rulesDisabled} ${t("wafRulesDisabled")}` : null}
        </span>
      </div>

      {error && <p className="error">{error}</p>}
      {ok && <p className="ok">{ok}</p>}

      {tab === "policy" && (
        <div className="grid two">
          <section className="panel stack">
            <h2 className="heading-with-help">
              {t("waf")}
              <HelpTip text={t("helpWaf")} />
            </h2>
            {String(modsec.request_body_access).toLowerCase() === "off" ? (
              <div className="callout warn" style={{ marginTop: 0 }}>
                <strong>{t("bodyInspectionHint")}: Off</strong>
                <p>{t("bodyInspectionOff")}</p>
              </div>
            ) : (
              <p className="muted" style={{ marginTop: 0 }}>
                {t("bodyInspectionOn")} ({modsec.request_body_access || "?"})
              </p>
            )}
            {global && (
              <>
                {global.engine_mode === "DetectionOnly" && (
                  <div className="callout warn">
                    <strong>{t("detectionOnlyTitle")}</strong>
                    <p>{t("detectionOnlyBody")}</p>
                  </div>
                )}
                {global.engine_mode === "On" && (
                  <div className="callout warn">
                    <strong>{t("blockingActiveTitle")}</strong>
                    <p>{t("blockingActiveBody")}</p>
                  </div>
                )}
                <div>
                  <label>{t("engineMode")}</label>
                  <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                    {["DetectionOnly", "On", "Off"].map((m) => (
                      <button
                        key={m}
                        type="button"
                        className={global.engine_mode === m ? undefined : "secondary"}
                        onClick={() => void setMode(m)}
                      >
                        {m === "On" ? t("blockingMode") : m === "DetectionOnly" ? t("detectionMode") : m}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label>{t("paranoia")}</label>
                  <select value={global.paranoia_level} onChange={(e) => void setPL(Number(e.target.value))}>
                    {[1, 2, 3, 4].map((n) => (
                      <option key={n} value={n}>
                        PL{n}
                      </option>
                    ))}
                  </select>
                </div>
                <form className="stack" onSubmit={(e) => void saveAnomaly(e)}>
                  <div>
                    <label>{t("anomalyThreshold")}</label>
                    <input
                      type="number"
                      min={1}
                      max={10000}
                      value={inboundThr}
                      onChange={(e) => setInboundThr(Number(e.target.value))}
                    />
                    <p className="field-hint">{t("anomalyHint")}</p>
                  </div>
                  <button type="submit" className="secondary">
                    {t("saveAnomaly")}
                  </button>
                </form>
              </>
            )}
          </section>

          <section className="panel stack">
            <h2 className="heading-with-help">
              {t("hostWafPolicy")}
              <HelpTip text={t("helpHostWaf")} />
            </h2>
            <form className="stack" onSubmit={(e) => void saveHostPolicy(e)}>
              <select
                value={hostPol.host_id}
                onChange={(e) => setHostPol({ ...hostPol, host_id: e.target.value })}
                required
              >
                <option value="">— {t("selectHost")} —</option>
                {hosts.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.primary_domain}
                  </option>
                ))}
              </select>
              <select
                value={hostPol.engine_mode}
                onChange={(e) => setHostPol({ ...hostPol, engine_mode: e.target.value })}
              >
                <option value="DetectionOnly">DetectionOnly</option>
                <option value="On">Blocking (On)</option>
                <option value="Off">Off</option>
              </select>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={hostPol.enabled}
                  onChange={(e) => setHostPol({ ...hostPol, enabled: e.target.checked })}
                />
                {t("enabled")}
              </label>
              <button type="submit">{t("saveHostPolicy")}</button>
            </form>
          </section>
        </div>
      )}

      {tab === "rules" && (
        <section className="panel stack">
          <h2 className="heading-with-help">
            {t("wafRulesTitle")}
            <HelpTip text={t("helpWafRules")} />
          </h2>
          <p className="muted" style={{ marginTop: 0 }}>
            {t("wafRulesHint")}
          </p>
          <form
            className="row"
            style={{ gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              setRulePage(1);
              void loadRules();
            }}
          >
            <div>
              <label>{t("search")}</label>
              <input
                value={ruleQ}
                onChange={(e) => setRuleQ(e.target.value)}
                placeholder="942100 / SQLi / XSS"
              />
            </div>
            <div>
              <label>{t("type")}</label>
              <select
                value={ruleCat}
                onChange={(e) => {
                  setRuleCat(e.target.value);
                  setRulePage(1);
                }}
              >
                <option value="">{t("all")}</option>
                {catOptions.map((c) => (
                  <option key={c} value={c}>
                    {c} ({rulesCats[c]})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label>{t("status")}</label>
              <select
                value={ruleEnabled}
                onChange={(e) => {
                  setRuleEnabled(e.target.value);
                  setRulePage(1);
                }}
              >
                <option value="">{t("all")}</option>
                <option value="active">{t("wafRuleActive")}</option>
                <option value="passive">{t("wafRulePassive")}</option>
              </select>
            </div>
            <button type="submit" className="secondary">
              {t("filter")}
            </button>
          </form>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>{t("description")}</th>
                  <th>{t("type")}</th>
                  <th>PL</th>
                  <th>{t("status")}</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <code>{r.id}</code>
                    </td>
                    <td>
                      <div>{r.msg}</div>
                      <div className="muted" style={{ fontSize: 12 }}>
                        {r.file}
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-ok">{r.category || "—"}</span>
                    </td>
                    <td>{r.paranoia || "—"}</td>
                    <td>
                      <div className="row" style={{ gap: 6, alignItems: "center" }}>
                        <button
                          type="button"
                          className={r.enabled ? undefined : "secondary"}
                          disabled={ruleBusy === r.id || r.enabled}
                          onClick={() => void toggleRule(r, true)}
                        >
                          {t("wafRuleActive")}
                        </button>
                        <button
                          type="button"
                          className={!r.enabled ? undefined : "secondary"}
                          disabled={ruleBusy === r.id || !r.enabled}
                          onClick={() => void toggleRule(r, false)}
                        >
                          {t("wafRulePassive")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr>
                    <td colSpan={5} className="muted">
                      {t("noSearchResults")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="row" style={{ gap: 8, alignItems: "center" }}>
            <button
              type="button"
              className="secondary"
              disabled={rulePage <= 1}
              onClick={() => setRulePage((p) => Math.max(1, p - 1))}
            >
              ←
            </button>
            <span className="muted">
              {rulePage} / {rulePages} · {rulesTotal}
            </span>
            <button
              type="button"
              className="secondary"
              disabled={rulePage >= rulePages}
              onClick={() => setRulePage((p) => p + 1)}
            >
              →
            </button>
          </div>
        </section>
      )}

      {tab === "exceptions" && (
        <section className="panel stack">
          <h2 className="heading-with-help">
            {t("exceptions")}
            <HelpTip text={t("helpExceptions")} />
          </h2>
          <p className="muted" style={{ marginTop: 0 }}>
            {t("wafExceptionsVsRulesHint")}
          </p>
          {exIsGlobal && (
            <div className="callout warn">
              <strong>{t("globalExceptionWarnTitle")}</strong>
              <p>{t("globalExceptionWarnBody")}</p>
            </div>
          )}
          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>{t("scope")}</th>
                <th>{t("actions")}</th>
              </tr>
            </thead>
            <tbody>
              {exceptions.map((x) => (
                <tr key={x.id}>
                  <td>
                    <code>{x.rule_id}</code>
                    {x.argument ? (
                      <div className="muted" style={{ fontSize: 12 }}>
                        arg={x.argument}
                      </div>
                    ) : null}
                    {x.reason ? (
                      <div className="muted" style={{ fontSize: 12 }}>
                        {x.reason}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    <code>
                      {hostName(x.host_id)}
                      {x.path_prefix || "/*"}
                    </code>
                  </td>
                  <td>
                    <button type="button" className="danger" onClick={() => void removeEx(x)}>
                      {t("delete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <form className="stack" onSubmit={(e) => void addException(e)} style={{ marginTop: 12 }}>
            <input
              placeholder="rule id (örn. 942100)"
              value={exForm.rule_id}
              onChange={(e) => setExForm({ ...exForm, rule_id: e.target.value })}
              required
            />
            <select value={exForm.host_id} onChange={(e) => setExForm({ ...exForm, host_id: e.target.value })}>
              <option value="">— {t("allHosts")} —</option>
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.primary_domain}
                </option>
              ))}
            </select>
            <input
              placeholder="/path"
              value={exForm.path_prefix}
              onChange={(e) => setExForm({ ...exForm, path_prefix: e.target.value })}
            />
            <input
              placeholder={t("argumentName")}
              value={exForm.argument}
              onChange={(e) => setExForm({ ...exForm, argument: e.target.value })}
            />
            <input
              placeholder={t("reason")}
              value={exForm.reason}
              onChange={(e) => setExForm({ ...exForm, reason: e.target.value })}
              required
            />
            <button type="submit">{t("addException")}</button>
          </form>
        </section>
      )}

      {tab === "advanced" && (
        <div className="grid two">
          <section className="panel stack">
            <h3 className="heading-with-help">
              {t("modsecGlobalTitle")}
              <HelpTip text={t("helpModsecGlobal")} />
            </h3>
            <form className="stack" onSubmit={(e) => void saveModSec(e)}>
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <div>
                  <label>SecAuditEngine</label>
                  <select
                    value={modsec.audit_engine}
                    onChange={(e) => setModsec({ ...modsec, audit_engine: e.target.value })}
                  >
                    <option value="RelevantOnly">RelevantOnly</option>
                    <option value="On">On</option>
                    <option value="Off">Off</option>
                  </select>
                </div>
                <div>
                  <label>SecDebugLogLevel</label>
                  <select
                    value={modsec.debug_log_level}
                    onChange={(e) => setModsec({ ...modsec, debug_log_level: Number(e.target.value) })}
                  >
                    {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label>SecAuditLogType</label>
                  <select
                    value={modsec.audit_log_type}
                    onChange={(e) => setModsec({ ...modsec, audit_log_type: e.target.value })}
                  >
                    <option value="Serial">Serial</option>
                    <option value="Concurrent">Concurrent</option>
                  </select>
                </div>
                <div>
                  <label>SecRequestBodyAccess</label>
                  <select
                    value={modsec.request_body_access}
                    onChange={(e) => setModsec({ ...modsec, request_body_access: e.target.value })}
                  >
                    <option value="On">On</option>
                    <option value="Off">Off</option>
                  </select>
                </div>
                <div>
                  <label>SecResponseBodyAccess</label>
                  <select
                    value={modsec.response_body_access}
                    onChange={(e) => setModsec({ ...modsec, response_body_access: e.target.value })}
                  >
                    <option value="Off">Off</option>
                    <option value="On">On</option>
                  </select>
                </div>
              </div>
              <div>
                <label>SecAuditLogParts</label>
                <input
                  value={modsec.audit_log_parts}
                  onChange={(e) => setModsec({ ...modsec, audit_log_parts: e.target.value.toUpperCase() })}
                />
              </div>
              <div>
                <label>SecAuditLogRelevantStatus</label>
                <input
                  value={modsec.audit_log_relevant_status}
                  onChange={(e) => setModsec({ ...modsec, audit_log_relevant_status: e.target.value })}
                />
              </div>
              <div>
                <label>SecRequestBodyLimit</label>
                <input
                  type="number"
                  min={1024}
                  max={104857600}
                  value={modsec.request_body_limit}
                  onChange={(e) => setModsec({ ...modsec, request_body_limit: Number(e.target.value) })}
                />
              </div>
              <button type="submit">{t("saveModsecSettings")}</button>
            </form>

            <h3 className="heading-with-help">
              {t("uaAllowlistTitle")}
              <HelpTip text={t("helpUaAllowlist")} />
            </h3>
            <form className="stack" onSubmit={(e) => void saveUAAllowlist(e)}>
              <textarea
                rows={5}
                value={uaText}
                onChange={(e) => setUaText(e.target.value)}
                placeholder={"Googlebot\nbingbot\nMyMonitor/1.0"}
                spellCheck={false}
              />
              {uaPresets.length > 0 && (
                <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                  {uaPresets.map((p) => (
                    <button key={p} type="button" className="secondary" onClick={() => addUAPreset(p)}>
                      + {p}
                    </button>
                  ))}
                </div>
              )}
              <button type="submit">{t("saveUAAllowlist")}</button>
            </form>
          </section>

          <section className="panel stack">
            <h3 className="heading-with-help">
              {t("customRulesTitle")}
              <HelpTip text={t("helpCustomRules")} />
            </h3>
            <form className="stack" onSubmit={(e) => void saveCustomRules(e)}>
              <div>
                <label className="heading-with-help">
                  {t("customRulesGlobal")}
                  <HelpTip text={t("helpCustomRulesGlobal")} />
                </label>
                <p className="field-hint">{t("customRulesGlobalHint")}</p>
                <textarea
                  rows={8}
                  value={customGlobal}
                  onChange={(e) => setCustomGlobal(e.target.value)}
                  placeholder={
                    'SecRule REQUEST_URI|ARGS "@rx (?i)(?:^|[/])\\.env(?:$|[/?&#])" \\\n    "id:1100500,phase:1,deny,status:403,log,msg:\'NSP block .env\'"'
                  }
                  spellCheck={false}
                  style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}
                />
                <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 6 }}>
                  <button type="button" className="secondary" onClick={() => applyGlobalPreset("env")}>
                    {t("customRulesPresetEnv")}
                  </button>
                </div>
              </div>
              <div>
                <label>{t("customRulesHost")}</label>
                <select value={customHostId} onChange={(e) => selectCustomHost(e.target.value)}>
                  <option value="">— {t("selectHost")} —</option>
                  {hosts.map((h) => (
                    <option key={h.id} value={h.id}>
                      {h.primary_domain}
                      {customHosts[h.id] ? " *" : ""}
                    </option>
                  ))}
                </select>
              </div>
              {customHostId && (
                <div>
                  <textarea
                    rows={6}
                    value={customHostText}
                    onChange={(e) => setCustomHostText(e.target.value)}
                    placeholder={'SecRule REQUEST_URI "@beginsWith /admin" "id:1100200,phase:1,deny,status:403"'}
                    spellCheck={false}
                    style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}
                  />
                </div>
              )}
              <button type="submit">{t("saveCustomRules")}</button>
            </form>
          </section>
        </div>
      )}

      {tab === "events" && (
        <section className="panel stack">
          <h2>{t("wafEvents")}</h2>
          <form className="stack" onSubmit={(e) => void searchEvents(e)}>
            <div className="row loc-grid">
              <input
                placeholder={t("searchEvents")}
                value={eventQ}
                onChange={(e) => setEventQ(e.target.value)}
              />
              <input
                placeholder="rule_id"
                value={eventRule}
                onChange={(e) => setEventRule(e.target.value)}
              />
              <input
                placeholder="domain"
                value={eventDomain}
                onChange={(e) => setEventDomain(e.target.value)}
              />
            </div>
            <button type="submit" className="secondary">
              {t("filter")}
            </button>
          </form>

          {report && (
            <div>
              <h3 className="heading-with-help">
                {t("attackReport")}
                <HelpTip text={t("helpAttackReport")} />
              </h3>
              <p className="field-hint">{report.note}</p>
              <div className="row" style={{ flexWrap: "wrap", gap: "0.5rem" }}>
                {Object.entries(report.by_attack_type || {}).map(([k, v]) => (
                  <span key={k} className="badge badge-ok">
                    {k}: {v}
                  </span>
                ))}
              </div>
              {(report.top_rules || []).length > 0 && (
                <table className="table" style={{ marginTop: 8 }}>
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>{t("type")}</th>
                      <th>#</th>
                      <th>{t("lastClientIp")}</th>
                      <th>{t("lastSeen")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.top_rules.slice(0, 10).map((r) => (
                      <tr key={r.rule_id}>
                        <td>
                          <code>{r.rule_id}</code>
                        </td>
                        <td>{r.attack_type}</td>
                        <td>{r.count}</td>
                        <td>
                          {r.last_client_ip ? (
                            <code>{r.last_client_ip}</code>
                          ) : (
                            <span className="muted">—</span>
                          )}
                        </td>
                        <td className="muted" style={{ whiteSpace: "nowrap" }}>
                          {formatEventTime(r.last_seen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>{t("domain")}</th>
                <th>URI</th>
                <th>{t("actions")}</th>
                <th style={{ width: 44, textAlign: "right" }}>
                  <button
                    type="button"
                    className={`icon-btn secondary${eventsRefreshing ? " is-spinning" : ""}`}
                    title={t("refreshEvents")}
                    aria-label={t("refreshEvents")}
                    disabled={eventsRefreshing}
                    onClick={() => void searchEvents()}
                  >
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M21 12a9 9 0 1 1-2.64-6.36" />
                      <path d="M21 3v6h-6" />
                    </svg>
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted">
                    {t("noEvents")}
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id}>
                    <td>
                      <code>{ev.rule_id}</code>
                      <div className="muted" style={{ fontSize: 12 }}>
                        {ev.message.slice(0, 80)}
                      </div>
                    </td>
                    <td>
                      {ev.domain ? <code>{ev.domain}</code> : <span className="muted">—</span>}
                    </td>
                    <td>
                      <code>
                        {ev.method} {ev.uri}
                      </code>
                    </td>
                    <td>
                      <button type="button" className="secondary" onClick={() => void suggest(ev.id)}>
                        {t("tune")}
                      </button>
                    </td>
                    <td />
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
