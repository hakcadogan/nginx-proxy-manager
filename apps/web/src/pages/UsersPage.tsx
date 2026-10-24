import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, User } from "../api";
import HelpTip from "../components/HelpTip";

type UserRow = User & { mfa_enabled?: boolean; locked_until?: string };

type Props = { currentUser: User };

export default function UsersPage({ currentUser }: Props) {
  const { t } = useTranslation();
  const [items, setItems] = useState<UserRow[]>([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [totp, setTotp] = useState("");

  const [editing, setEditing] = useState<UserRow | null>(null);
  const [editRole, setEditRole] = useState("viewer");
  const [editPassword, setEditPassword] = useState("");

  async function load() {
    const d = await api<{ items: UserRow[] }>("/api/v1/users");
    setItems(d.items || []);
  }

  useEffect(() => {
    load().catch((e) => setError(e instanceof Error ? e.message : "error"));
  }, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    setOk("");
    try {
      await api("/api/v1/users", {
        method: "POST",
        body: JSON.stringify({ email, password, role }),
      });
      setEmail("");
      setPassword("");
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  function startEdit(u: UserRow) {
    setEditing(u);
    setEditRole(u.role);
    setEditPassword("");
    setError("");
    setOk("");
  }

  async function onSaveEdit(e: FormEvent) {
    e.preventDefault();
    if (!editing) return;
    setError("");
    setOk("");
    const body: Record<string, unknown> = { role: editRole };
    if (editPassword.trim()) body.password = editPassword;
    try {
      await api(`/api/v1/users/${editing.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      setEditing(null);
      setEditPassword("");
      setOk(t("updatedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function remove(u: UserRow) {
    if (u.id === currentUser.id) {
      setError(t("cannotDeleteSelf"));
      return;
    }
    if (!window.confirm(t("confirmDeleteUser", { email: u.email }))) return;
    setError("");
    setOk("");
    try {
      await api(`/api/v1/users/${u.id}`, { method: "DELETE" });
      if (editing?.id === u.id) setEditing(null);
      setOk(t("savedOk"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "error");
    }
  }

  async function unlock(id: string) {
    setError("");
    await api(`/api/v1/users/${id}/unlock`, { method: "POST", body: "{}" });
    await load();
  }

  async function enrollMfa() {
    const d = await api<{ secret: string }>("/api/v1/auth/mfa/enroll", { method: "POST", body: "{}" });
    setMfaSecret(d.secret);
  }

  async function confirmMfa() {
    await api("/api/v1/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ totp }) });
    setMfaSecret("");
    setTotp("");
    await load();
  }

  return (
    <div className="stack">
      {error && <div className="error">{error}</div>}
      {ok && <div className="ok">{ok}</div>}

      <div className="grid two">
        <form className="panel stack" onSubmit={(e) => void onCreate(e)}>
          <h2>{t("createUser")}</h2>
          <label>
            {t("email")}
            <input value={email} onChange={(e) => setEmail(e.target.value)} required type="email" />
          </label>
          <label>
            {t("password")}
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
              type="password"
              autoComplete="new-password"
            />
          </label>
          <label>
            {t("role")}
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="admin">admin</option>
              <option value="operator">operator</option>
              <option value="viewer">viewer</option>
            </select>
          </label>
          <button type="submit">{t("save")}</button>
        </form>

        <div className="panel stack">
          <h2 className="heading-with-help">
            {t("mfa")}
            <HelpTip text={t("helpMfa")} />
          </h2>
          <p className="muted">{t("mfaSelfHint")}</p>
          <button type="button" className="secondary" onClick={() => void enrollMfa()}>
            {t("mfaEnroll")}
          </button>
          {mfaSecret && (
            <>
              <code>{mfaSecret}</code>
              <input value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="TOTP" />
              <button type="button" onClick={() => void confirmMfa()}>
                {t("mfaConfirm")}
              </button>
            </>
          )}
        </div>
      </div>

      {editing && (
        <form className="panel stack" onSubmit={(e) => void onSaveEdit(e)}>
          <h2>
            {t("editUser")}: <code>{editing.email}</code>
          </h2>
          <label>
            {t("role")}
            <select value={editRole} onChange={(e) => setEditRole(e.target.value)}>
              <option value="admin">admin</option>
              <option value="operator">operator</option>
              <option value="viewer">viewer</option>
            </select>
          </label>
          <label>
            {t("newPasswordOptional")}
            <input
              value={editPassword}
              onChange={(e) => setEditPassword(e.target.value)}
              minLength={12}
              type="password"
              autoComplete="new-password"
              placeholder={t("leaveBlankKeepPassword")}
            />
          </label>
          <div className="row">
            <button type="submit">{t("update")}</button>
            <button type="button" className="secondary" onClick={() => setEditing(null)}>
              {t("cancel")}
            </button>
          </div>
        </form>
      )}

      <section className="panel">
        <h2 className="heading-with-help">
          {t("users")}
          <HelpTip text={t("helpUsers")} />
        </h2>
        <table className="table">
          <thead>
            <tr>
              <th>{t("email")}</th>
              <th>{t("role")}</th>
              <th>MFA</th>
              <th>{t("actions")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((u) => (
              <tr key={u.id}>
                <td>
                  {u.email}
                  {u.id === currentUser.id ? (
                    <span className="muted" style={{ marginLeft: 8 }}>
                      ({t("you")})
                    </span>
                  ) : null}
                  {u.locked_until ? (
                    <div className="error" style={{ fontSize: 12 }}>
                      locked
                    </div>
                  ) : null}
                </td>
                <td>{u.role}</td>
                <td>{u.mfa_enabled ? "✓" : "—"}</td>
                <td>
                  <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                    <button type="button" className="secondary" onClick={() => startEdit(u)}>
                      {t("edit")}
                    </button>
                    {u.locked_until && (
                      <button type="button" className="secondary" onClick={() => void unlock(u.id)}>
                        {t("unlock")}
                      </button>
                    )}
                    <button
                      type="button"
                      className="danger"
                      disabled={u.id === currentUser.id}
                      onClick={() => void remove(u)}
                    >
                      {t("delete")}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
