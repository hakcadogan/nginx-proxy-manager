import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, User } from "../api";

export default function LoginPage({ onAuthed }: { onAuthed: (u: User) => void }) {
  const { t, i18n } = useTranslation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [totp, setTotp] = useState("");
  const [preAuth, setPreAuth] = useState("");
  const [bootstrapRequired, setBootstrapRequired] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ bootstrap_required: boolean }>("/api/v1/auth/bootstrap/status")
      .then((d) => setBootstrapRequired(d.bootstrap_required))
      .catch(() => setBootstrapRequired(false));
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (bootstrapRequired) {
        await api("/api/v1/auth/bootstrap", {
          method: "POST",
          body: JSON.stringify({ token, email, password }),
        });
      }
      if (preAuth) {
        const res = await api<{ user: User }>("/api/v1/auth/mfa/login", {
          method: "POST",
          body: JSON.stringify({ pre_auth_token: preAuth, totp }),
        });
        onAuthed(res.user);
        return;
      }
      const res = await api<{ user?: User; mfa_required?: boolean; pre_auth_token?: string }>(
        "/api/v1/auth/login",
        { method: "POST", body: JSON.stringify({ email, password, totp: totp || undefined }) },
      );
      if (res.mfa_required && res.pre_auth_token) {
        setPreAuth(res.pre_auth_token);
        return;
      }
      if (res.user) onAuthed(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("loginFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <form className="panel auth-card stack" onSubmit={(e) => void onSubmit(e)}>
        <div>
          <div className="muted" style={{ fontSize: "0.8rem", fontWeight: 600, letterSpacing: "0.06em" }}>
            NSP
          </div>
          <h1>{t("appName")}</h1>
          <p className="muted" style={{ margin: "0.35rem 0 0" }}>
            {bootstrapRequired ? t("bootstrap") : preAuth ? t("mfa") : t("login")}
          </p>
        </div>
        {bootstrapRequired && (
          <div>
            <label htmlFor="token">{t("bootstrapToken")}</label>
            <input id="token" value={token} onChange={(e) => setToken(e.target.value)} required />
          </div>
        )}
        {!preAuth && (
          <>
            <div>
              <label htmlFor="email">{t("email")}</label>
              <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="username" />
            </div>
            <div>
              <label htmlFor="password">{t("password")}</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={bootstrapRequired ? 12 : 1}
                autoComplete="current-password"
              />
            </div>
          </>
        )}
        {(preAuth || (!bootstrapRequired && totp !== undefined)) && (
          <div>
            <label htmlFor="totp">{t("mfa")}</label>
            <input
              id="totp"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder={preAuth ? "000000" : t("optional")}
            />
          </div>
        )}
        <div className="row" style={{ justifyContent: "space-between" }}>
          <button type="submit" disabled={busy}>
            {bootstrapRequired ? t("bootstrap") : t("login")}
          </button>
          <select
            value={i18n.language.startsWith("tr") ? "tr" : "en"}
            onChange={(e) => {
              void i18n.changeLanguage(e.target.value);
              localStorage.setItem("nsp_lang", e.target.value);
            }}
            style={{ width: "auto" }}
            aria-label={t("language")}
          >
            <option value="tr">TR</option>
            <option value="en">EN</option>
          </select>
        </div>
        {error && <div className="error">{error}</div>}
      </form>
    </div>
  );
}
