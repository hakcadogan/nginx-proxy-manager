import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import HelpTip from "../components/HelpTip";

type Cert = {
  id: string;
  name: string;
  domains: string[];
  kind: string;
  fingerprint_sha256: string;
  not_after?: string;
  days_remaining?: number;
  expiring_soon: boolean;
  acme_challenge?: string;
  auto_renew?: boolean;
  has_previous?: boolean;
  in_use?: boolean;
  expired?: boolean;
  status?: "in_use" | "unused" | "expired";
};

function certStatus(c: Cert): "in_use" | "unused" | "expired" {
  if (c.status === "in_use" || c.status === "unused" || c.status === "expired") return c.status;
  if (c.expired || (c.days_remaining != null && c.days_remaining < 0)) return "expired";
  if (c.in_use) return "in_use";
  return "unused";
}

function formatCertExpiry(iso?: string, locale?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(locale || undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function certKindLabel(kind: string, t: (k: string) => string): string {
  switch (kind) {
    case "acme":
      return t("sslKindAcme");
    case "upload":
      return t("sslKindUpload");
    case "self_signed":
      return t("sslKindSelfSigned");
    case "private_ca":
      return t("sslKindPrivateCa");
    default:
      return kind || "—";
  }
}

type Host = { id: string; primary_domain: string; aliases?: string[] };

type ACMEOp = {
  id: number;
  operation: string;
  challenge?: string;
  domains: string[];
  status: string;
  error_message?: string;
  created_at: string;
};

type PageTab = "inventory" | "ops";
type IssueTab = "letsencrypt" | "custom" | "selfsigned" | "privateca";

function parseDomains(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

async function readTextFile(file: File | null | undefined): Promise<string> {
  if (!file) return "";
  return file.text();
}

function FileOrPaste(props: {
  id: string;
  label: string;
  required?: boolean;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
}) {
  return (
    <div>
      <label htmlFor={props.id}>
        {props.label}
        {props.required ? " *" : ""}
      </label>
      <div className="row" style={{ gap: 8, marginBottom: 6 }}>
        <input
          id={`${props.id}-file`}
          type="file"
          accept=".pem,.crt,.cer,.key,.txt,application/x-pem-file,application/pkix-cert,text/plain"
          onChange={(e) => {
            const f = e.target.files?.[0];
            void readTextFile(f).then((t) => {
              if (t) props.onChange(t.trim());
            });
            e.target.value = "";
          }}
        />
      </div>
      <textarea
        id={props.id}
        rows={props.rows ?? 4}
        value={props.value}
        required={props.required}
        placeholder={props.placeholder || "-----BEGIN …-----"}
        onChange={(e) => props.onChange(e.target.value)}
        spellCheck={false}
      />
    </div>
  );
}

export default function SSLPage() {
  const { t } = useTranslation();
  const [pageTab, setPageTab] = useState<PageTab>("inventory");
  const [items, setItems] = useState<Cert[]>([]);
  const [unusedOnly, setUnusedOnly] = useState(false);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [ops, setOps] = useState<ACMEOp[]>([]);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [busy, setBusy] = useState(false);
  const [acmeEmail, setAcmeEmail] = useState("");
  const [dns01Available, setDns01Available] = useState(false);

  const [modalOpen, setModalOpen] = useState(false);
  const [issueTab, setIssueTab] = useState<IssueTab>("letsencrypt");

  const [name, setName] = useState("");
  const [domainsText, setDomainsText] = useState("");
  const [dnsChallenge, setDnsChallenge] = useState(false);
  const [staging, setStaging] = useState(true);
  const [tos, setTos] = useState(false);
  const [autoRenew, setAutoRenew] = useState(true);
  const [reachMsg, setReachMsg] = useState("");
  const [validDays, setValidDays] = useState(365);

  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [intermediatePem, setIntermediatePem] = useState("");
  const [caCert, setCaCert] = useState("");
  const [caKey, setCaKey] = useState("");

  const [bindCert, setBindCert] = useState("");
  const [bindHost, setBindHost] = useState("");

  async function load() {
    const q = unusedOnly ? "?unused=1" : "";
    const [c, h] = await Promise.all([
      api<{ items: Cert[]; acme_email?: string; dns01_available?: boolean }>(`/api/v1/certificates${q}`),
      api<{ items: Host[] }>("/api/v1/hosts"),
    ]);
    setItems(c.items || []);
    setHosts(h.items || []);
    if (c.acme_email) setAcmeEmail(c.acme_email);
    setDns01Available(!!c.dns01_available);
  }

  async function loadOps() {
    const data = await api<{ items: ACMEOp[] }>("/api/v1/certificates/ops");
    setOps(data.items || []);
  }

  useEffect(() => {
    load().catch((e) => setError(String(e.message || e)));
  }, [unusedOnly]);

  useEffect(() => {
    if (pageTab === "ops") loadOps().catch((e) => setError(String(e.message || e)));
  }, [pageTab]);

  useEffect(() => {
    if (!modalOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) closeModal();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [modalOpen, busy]);

  function resetIssueForm() {
    setName("");
    setDomainsText("");
    setDnsChallenge(false);
    setStaging(true);
    setTos(false);
    setAutoRenew(true);
    setReachMsg("");
    setValidDays(365);
    setCertPem("");
    setKeyPem("");
    setIntermediatePem("");
    setCaCert("");
    setCaKey("");
    setIssueTab("letsencrypt");
  }

  function openModal(tab: IssueTab = "letsencrypt") {
    resetIssueForm();
    setIssueTab(tab);
    setError("");
    setOk("");
    setModalOpen(true);
  }

  function closeModal() {
    if (busy) return;
    setModalOpen(false);
    resetIssueForm();
  }

  function fillDomainsFromHost(hostId: string) {
    const h = hosts.find((x) => x.id === hostId);
    if (!h) return;
    const list = [h.primary_domain, ...(h.aliases || [])];
    setDomainsText(list.join("\n"));
    if (!name) setName(h.primary_domain);
  }

  function testReachability() {
    const list = parseDomains(domainsText);
    setReachMsg("");
    if (list.length === 0) {
      setReachMsg(t("sslReachEmpty"));
      return;
    }
    const configured = new Set(
      hosts.flatMap((h) => [h.primary_domain.toLowerCase(), ...(h.aliases || []).map((a) => a.toLowerCase())]),
    );
    const missing = list.filter((d) => !d.startsWith("*.") && !configured.has(d));
    if (dnsChallenge) {
      setReachMsg(t("sslReachDnsSkip"));
      return;
    }
    if (missing.length === 0) {
      setReachMsg(t("sslReachOk"));
    } else {
      setReachMsg(t("sslReachMissing", { domains: missing.join(", ") }));
    }
  }

  async function onIssueSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    setBusy(true);
    try {
      if (issueTab === "letsencrypt") {
        const list = parseDomains(domainsText);
        if (list.length === 0) throw new Error(t("sslDomainsRequired"));
        if (!tos) throw new Error(t("sslTosRequired"));
        if (list.some((d) => d.startsWith("*.")) && !dnsChallenge) {
          throw new Error(t("wildcardNeedsDns"));
        }
        if (dnsChallenge && !dns01Available) {
          throw new Error(t("sslDns01Unavailable"));
        }
        await api("/api/v1/certificates/acme/issue", {
          method: "POST",
          body: JSON.stringify({
            name: name.trim() || list[0],
            domains: list,
            challenge: dnsChallenge ? "dns-01" : "http-01",
            auto_renew: autoRenew,
            staging,
          }),
        });
      } else if (issueTab === "custom") {
        if (!name.trim()) throw new Error(t("sslNameRequired"));
        if (!certPem.trim() || !keyPem.trim()) throw new Error(t("sslPemRequired"));
        const chain = intermediatePem.trim()
          ? `${certPem.trim()}\n${intermediatePem.trim()}`
          : certPem.trim();
        await api("/api/v1/certificates/upload", {
          method: "POST",
          body: JSON.stringify({
            name: name.trim(),
            certificate_pem: chain,
            private_key_pem: keyPem.trim(),
          }),
        });
      } else if (issueTab === "selfsigned") {
        const list = parseDomains(domainsText);
        if (list.length === 0) throw new Error(t("sslDomainsRequired"));
        await api("/api/v1/certificates/self-signed", {
          method: "POST",
          body: JSON.stringify({
            name: name.trim() || list[0],
            domains: list,
            valid_days: validDays,
          }),
        });
      } else {
        const list = parseDomains(domainsText);
        if (list.length === 0) throw new Error(t("sslDomainsRequired"));
        if (!caCert.trim() || !caKey.trim()) throw new Error(t("sslCaPemRequired"));
        await api("/api/v1/certificates/private-ca", {
          method: "POST",
          body: JSON.stringify({
            name: name.trim() || list[0],
            domains: list,
            valid_days: validDays,
            ca_certificate_pem: caCert.trim(),
            ca_private_key_pem: caKey.trim(),
          }),
        });
      }
      setOk(t("savedOk"));
      setModalOpen(false);
      resetIssueForm();
      await load();
      setPageTab("inventory");
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    } finally {
      setBusy(false);
    }
  }

  async function bind(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    try {
      await api(`/api/v1/certificates/${bindCert}/bind`, {
        method: "POST",
        body: JSON.stringify({ host_id: bindHost }),
      });
      setOk(t("savedOk"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function renew(id: string) {
    setError("");
    setOk("");
    try {
      await api(`/api/v1/certificates/${id}/renew`, { method: "POST", body: "{}" });
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function rollback(id: string) {
    setError("");
    setOk("");
    try {
      await api(`/api/v1/certificates/${id}/rollback`, { method: "POST", body: "{}" });
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function remove(c: Cert) {
    if (!window.confirm(t("confirmDeleteNamed", { name: c.name || c.id }))) return;
    setError("");
    try {
      await api(`/api/v1/certificates/${c.id}`, { method: "DELETE" });
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  const issueTabs: { id: IssueTab; label: string }[] = [
    { id: "letsencrypt", label: t("sslLetsEncrypt") },
    { id: "custom", label: t("sslCustom") },
    { id: "selfsigned", label: t("sslSelfSigned") },
    { id: "privateca", label: t("sslPrivateCa") },
  ];

  return (
    <div className="stack">
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        {(["inventory", "ops"] as PageTab[]).map((id) => (
          <button
            key={id}
            type="button"
            className={pageTab === id ? undefined : "secondary"}
            onClick={() => setPageTab(id)}
          >
            {t(`sslTab_${id}`)}
          </button>
        ))}
      </div>
      {error && !modalOpen && <div className="error">{error}</div>}
      {ok && !modalOpen && <div className="ok">{ok}</div>}

      {pageTab === "inventory" && (
        <section className="panel stack">
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
            <h2 className="heading-with-help" style={{ margin: 0 }}>
              {t("ssl")}
              <HelpTip text={t("helpSsl")} />
            </h2>
            <div className="row" style={{ gap: 10, alignItems: "center" }}>
              <label className="check-row">
                <input type="checkbox" checked={unusedOnly} onChange={(e) => setUnusedOnly(e.target.checked)} />
                {t("unusedCertsOnly")}
              </label>
              <button type="button" onClick={() => openModal("letsencrypt")}>
                {t("sslAddCertificate")}
              </button>
            </div>
          </div>
          <p className="muted">{t("sslTlsPolicyHint")}</p>
          <table className="table">
            <thead>
              <tr>
                <th>{t("name")}</th>
                <th>{t("domains")}</th>
                <th>{t("kind")}</th>
                <th>{t("expiry")}</th>
                <th>{t("status")}</th>
                <th>{t("actions")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => {
                const st = certStatus(c);
                const expiryClass =
                  st === "expired" ? "cert-expiry expired" : c.expiring_soon ? "cert-expiry soon" : "cert-expiry";
                return (
                  <tr key={c.id}>
                    <td>
                      {c.name}
                      {c.auto_renew ? <div className="muted" style={{ fontSize: 12 }}>auto-renew</div> : null}
                    </td>
                    <td>
                      <code>{(c.domains || []).join(", ")}</code>
                    </td>
                    <td>
                      {certKindLabel(c.kind, t)}
                      {c.kind === "acme" && c.acme_challenge ? (
                        <div className="muted" style={{ fontSize: 12 }}>{c.acme_challenge}</div>
                      ) : null}
                    </td>
                    <td className={expiryClass}>
                      <div>{formatCertExpiry(c.not_after)}</div>
                      {c.days_remaining != null && (
                        <div className="muted" style={{ fontSize: 12 }}>
                          {c.days_remaining < 0
                            ? t("sslExpiredAgo", { days: Math.abs(c.days_remaining) })
                            : t("sslDaysLeft", { days: c.days_remaining })}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`status-pill ${st === "in_use" ? "in-use" : st}`}>
                        <span className="dot" aria-hidden />
                        {st === "in_use"
                          ? t("sslStatusInUse")
                          : st === "expired"
                            ? t("sslStatusExpired")
                            : t("sslStatusUnused")}
                      </span>
                    </td>
                    <td className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                      {c.kind === "acme" && (
                        <button type="button" className="secondary" onClick={() => void renew(c.id)}>
                          {t("renew")}
                        </button>
                      )}
                      {c.has_previous && (
                        <button type="button" className="secondary" onClick={() => void rollback(c.id)}>
                          {t("rollbackCert")}
                        </button>
                      )}
                      <button type="button" className="danger" onClick={() => void remove(c)}>
                        {t("delete")}
                      </button>
                    </td>
                  </tr>
                );
              })}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    {t("noCerts")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          <form className="stack" onSubmit={(e) => void bind(e)} style={{ maxWidth: 480 }}>
            <h3 className="heading-with-help">
              {t("bindCert")}
              <HelpTip text={t("helpBindCert")} />
            </h3>
            <select value={bindCert} onChange={(e) => setBindCert(e.target.value)} required>
              <option value="">—</option>
              {items.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
            <select value={bindHost} onChange={(e) => setBindHost(e.target.value)} required>
              <option value="">—</option>
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.primary_domain}
                </option>
              ))}
            </select>
            <button type="submit">{t("bind")}</button>
          </form>
        </section>
      )}

      {pageTab === "ops" && (
        <section className="panel">
          <h2 className="heading-with-help">
            {t("sslTab_ops")}
            <HelpTip text={t("helpSslOps")} />
          </h2>
          <table className="table">
            <thead>
              <tr>
                <th>{t("time")}</th>
                <th>{t("actions")}</th>
                <th>{t("status")}</th>
                <th>{t("domains")}</th>
                <th>{t("reason")}</th>
              </tr>
            </thead>
            <tbody>
              {ops.map((o) => (
                <tr key={o.id}>
                  <td>{new Date(o.created_at).toLocaleString()}</td>
                  <td>
                    {o.operation}
                    {o.challenge ? `/${o.challenge}` : ""}
                  </td>
                  <td className={o.status === "failure" ? "error" : "ok"}>{o.status}</td>
                  <td>
                    <code>{(o.domains || []).join(", ")}</code>
                  </td>
                  <td className="muted">{o.error_message || "—"}</td>
                </tr>
              ))}
              {ops.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    {t("noEvents")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </section>
      )}

      {modalOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget && !busy) closeModal();
          }}
        >
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="ssl-modal-title">
            <div className="modal-header">
              <h2 id="ssl-modal-title">{t("sslAddCertificate")}</h2>
              <button type="button" className="ghost modal-close" onClick={closeModal} aria-label={t("cancel")} disabled={busy}>
                ×
              </button>
            </div>

            <div className="modal-tabs" role="tablist">
              {issueTabs.map((tb) => (
                <button
                  key={tb.id}
                  type="button"
                  role="tab"
                  aria-selected={issueTab === tb.id}
                  className={`modal-tab ${issueTab === tb.id ? "active" : ""}`}
                  onClick={() => !busy && setIssueTab(tb.id)}
                  disabled={busy}
                >
                  {tb.label}
                </button>
              ))}
            </div>

            <form className="modal-body" onSubmit={(e) => void onIssueSubmit(e)}>
              {issueTab === "letsencrypt" && (
                <div className="stack modal-pane">
                  <div className="callout warn">
                    <p style={{ margin: 0 }}>{t("sslDomainsMustPoint")}</p>
                  </div>
                  <div>
                    <label htmlFor="ssl-le-name">{t("name")}</label>
                    <input
                      id="ssl-le-name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t("sslNameOptional")}
                      disabled={busy}
                    />
                  </div>
                  <div>
                    <label htmlFor="ssl-le-domains">{t("domains")} *</label>
                    <textarea
                      id="ssl-le-domains"
                      rows={4}
                      required
                      value={domainsText}
                      onChange={(e) => setDomainsText(e.target.value)}
                      placeholder={"example.com\nwww.example.com"}
                      disabled={busy}
                      spellCheck={false}
                    />
                    <p className="field-hint">{t("sslDomainsHint")}</p>
                  </div>
                  {hosts.length > 0 && (
                    <div>
                      <label htmlFor="ssl-fill-host">{t("sslFillFromHost")}</label>
                      <select
                        id="ssl-fill-host"
                        defaultValue=""
                        onChange={(e) => {
                          if (e.target.value) fillDomainsFromHost(e.target.value);
                          e.target.value = "";
                        }}
                        disabled={busy}
                      >
                        <option value="">—</option>
                        {hosts.map((h) => (
                          <option key={h.id} value={h.id}>
                            {h.primary_domain}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                  <button type="button" className="secondary" onClick={testReachability} disabled={busy}>
                    {t("sslTestReachability")}
                  </button>
                  {reachMsg && <p className="field-hint">{reachMsg}</p>}
                  <p className="field-hint">{t("sslReachHint")}</p>
                  <div>
                    <label>{t("sslAcmeEmail")}</label>
                    <input value={acmeEmail || "—"} readOnly disabled />
                    <p className="field-hint">{t("sslAcmeEmailHint")}</p>
                  </div>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={dnsChallenge}
                      onChange={(e) => setDnsChallenge(e.target.checked)}
                      disabled={busy}
                    />
                    {t("sslUseDnsChallenge")}
                  </label>
                  {dnsChallenge && !dns01Available && (
                    <div className="callout warn">
                      <p style={{ margin: 0 }}>{t("sslDns01Unavailable")}</p>
                    </div>
                  )}
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={staging}
                      onChange={(e) => setStaging(e.target.checked)}
                      disabled={busy}
                    />
                    {t("sslUseStaging")}
                  </label>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={autoRenew}
                      onChange={(e) => setAutoRenew(e.target.checked)}
                      disabled={busy}
                    />
                    {t("sslAutoRenew")}
                  </label>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={tos}
                      onChange={(e) => setTos(e.target.checked)}
                      disabled={busy}
                      required
                    />
                    <span>
                      {t("sslTosAgree")}{" "}
                      <a href="https://letsencrypt.org/repository/" target="_blank" rel="noreferrer">
                        {t("sslTosLink")}
                      </a>
                      {" *"}
                    </span>
                  </label>
                </div>
              )}

              {issueTab === "custom" && (
                <div className="stack modal-pane">
                  <div className="callout warn">
                    <p style={{ margin: 0 }}>{t("sslPassphraseWarn")}</p>
                  </div>
                  <div>
                    <label htmlFor="ssl-custom-name">{t("name")} *</label>
                    <input
                      id="ssl-custom-name"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      disabled={busy}
                    />
                  </div>
                  <FileOrPaste
                    id="ssl-cert"
                    label={t("sslCertificatePem")}
                    required
                    value={certPem}
                    onChange={setCertPem}
                  />
                  <FileOrPaste
                    id="ssl-key"
                    label={t("sslPrivateKeyPem")}
                    required
                    value={keyPem}
                    onChange={setKeyPem}
                  />
                  <FileOrPaste
                    id="ssl-intermediate"
                    label={t("sslIntermediatePem")}
                    value={intermediatePem}
                    onChange={setIntermediatePem}
                    rows={3}
                  />
                  <p className="field-hint">{t("pemValidateHint")}</p>
                </div>
              )}

              {issueTab === "selfsigned" && (
                <div className="stack modal-pane">
                  <div className="callout warn">
                    <strong>{t("selfSignedWarnTitle")}</strong>
                    <p>{t("selfSignedWarnBody")}</p>
                  </div>
                  <div>
                    <label htmlFor="ssl-ss-name">{t("name")}</label>
                    <input id="ssl-ss-name" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
                  </div>
                  <div>
                    <label htmlFor="ssl-ss-domains">{t("domains")} *</label>
                    <textarea
                      id="ssl-ss-domains"
                      rows={3}
                      required
                      value={domainsText}
                      onChange={(e) => setDomainsText(e.target.value)}
                      placeholder={"lab.local\n*.lab.local"}
                      disabled={busy}
                      spellCheck={false}
                    />
                  </div>
                  <div>
                    <label htmlFor="ssl-ss-days">{t("validDays")}</label>
                    <select
                      id="ssl-ss-days"
                      value={validDays}
                      onChange={(e) => setValidDays(Number(e.target.value))}
                      disabled={busy}
                    >
                      <option value={30}>{t("validDays30")}</option>
                      <option value={90}>{t("validDays90")}</option>
                      <option value={365}>{t("validDays365")}</option>
                      <option value={825}>{t("validDays825")}</option>
                      <option value={3650}>{t("validDays3650")}</option>
                    </select>
                    <p className="field-hint">{t("validDaysHint")}</p>
                  </div>
                </div>
              )}

              {issueTab === "privateca" && (
                <div className="stack modal-pane">
                  <div>
                    <label htmlFor="ssl-pca-name">{t("name")}</label>
                    <input id="ssl-pca-name" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
                  </div>
                  <div>
                    <label htmlFor="ssl-pca-domains">{t("domains")} *</label>
                    <textarea
                      id="ssl-pca-domains"
                      rows={3}
                      required
                      value={domainsText}
                      onChange={(e) => setDomainsText(e.target.value)}
                      disabled={busy}
                      spellCheck={false}
                    />
                  </div>
                  <div>
                    <label htmlFor="ssl-pca-days">{t("validDays")}</label>
                    <select
                      id="ssl-pca-days"
                      value={validDays}
                      onChange={(e) => setValidDays(Number(e.target.value))}
                      disabled={busy}
                    >
                      <option value={30}>{t("validDays30")}</option>
                      <option value={90}>{t("validDays90")}</option>
                      <option value={365}>{t("validDays365")}</option>
                      <option value={825}>{t("validDays825")}</option>
                      <option value={3650}>{t("validDays3650")}</option>
                    </select>
                  </div>
                  <FileOrPaste id="ssl-ca-cert" label={t("sslCaCertPem")} required value={caCert} onChange={setCaCert} />
                  <FileOrPaste id="ssl-ca-key" label={t("sslCaKeyPem")} required value={caKey} onChange={setCaKey} />
                </div>
              )}

              {error && modalOpen && <div className="error" style={{ margin: "0 1.15rem" }}>{error}</div>}
              {ok && modalOpen && <div className="ok" style={{ margin: "0 1.15rem" }}>{ok}</div>}

              <div className="modal-footer">
                <button type="button" className="secondary" onClick={closeModal} disabled={busy}>
                  {t("cancel")}
                </button>
                <button type="submit" disabled={busy}>
                  {busy ? t("sslIssuing") : t("save")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
