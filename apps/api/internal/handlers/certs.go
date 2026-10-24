package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nginx-proxy-waf/api/internal/certs"
	"github.com/nginx-proxy-waf/api/internal/config"
	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/middleware"
	"github.com/nginx-proxy-waf/api/internal/models"
)

type CertHandler struct {
	Store     *db.Store
	Cfg       config.Config
	FS        *certs.Store
	ApplyHook func(ctx context.Context) error
}

type uploadReq struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	AutoRenew      bool   `json:"auto_renew"`
}

type selfSignedReq struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	ValidDays int      `json:"valid_days"`
}

type privateCAReq struct {
	Name          string   `json:"name"`
	Domains       []string `json:"domains"`
	ValidDays     int      `json:"valid_days"`
	CACertificate string   `json:"ca_certificate_pem"`
	CAPrivateKey  string   `json:"ca_private_key_pem"`
}

type acmeIssueReq struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Challenge string   `json:"challenge"`
	AutoRenew bool     `json:"auto_renew"`
	Staging   *bool    `json:"staging"`
}

type bindReq struct {
	HostID string `json:"host_id"`
}

func (h *CertHandler) actorEmail(r *http.Request) string {
	if sess, ok := middleware.SessionFrom(r.Context()); ok {
		return sess.Email
	}
	return ""
}

func (h *CertHandler) logACME(ctx context.Context, certID *uuid.UUID, op, chal string, domains []string, status, errMsg, actor string) {
	_ = h.Store.InsertACMEOperation(ctx, models.ACMEOperation{
		CertificateID: certID, Operation: op, Challenge: chal, Domains: domains,
		Status: status, ErrorMessage: errMsg, ActorEmail: actor,
	})
}

func (h *CertHandler) List(w http.ResponseWriter, r *http.Request) {
	unusedOnly := r.URL.Query().Get("unused") == "1" || r.URL.Query().Get("unused") == "true"
	var items []models.Certificate
	var err error
	if unusedOnly {
		items, err = h.Store.ListUnusedCertificates(r.Context())
	} else {
		items, err = h.Store.ListCertificates(r.Context())
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	inUse, _ := h.Store.CertificateIDsInUse(r.Context())
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":           publicCerts(items, h.FS, inUse),
		"unused_only":     unusedOnly,
		"acme_email":      h.Cfg.ACMEEmail,
		"dns01_available": h.Cfg.CloudflareAPIToken != "" || h.Cfg.ACMEUseMockDNS,
	})
}

func (h *CertHandler) ListOps(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ListACMEOperations(r.Context(), 80)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	if items == nil {
		items = []models.ACMEOperation{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *CertHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	c, err := h.Store.GetCertificate(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	WriteJSON(w, http.StatusOK, publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID)))
}

func (h *CertHandler) Upload(w http.ResponseWriter, r *http.Request) {
	var req uploadReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	bundle, err := certs.ParseAndValidatePEM([]byte(req.CertificatePEM), []byte(req.PrivateKeyPEM))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	c, err := h.persist(r.Context(), req.Name, "upload", nil, bundle, req.AutoRenew)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeAudit(h.Store, r, "cert.upload", "certificate", c.ID.String(), map[string]any{
		"domains": c.Domains, "fingerprint": c.FingerprintSHA256,
	})
	WriteJSON(w, http.StatusCreated, publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID)))
}

func (h *CertHandler) SelfSigned(w http.ResponseWriter, r *http.Request) {
	var req selfSignedReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	bundle, err := certs.GenerateSelfSigned(req.Domains, req.ValidDays)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	c, err := h.persist(r.Context(), req.Name, "self_signed", nil, bundle, false)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeAudit(h.Store, r, "cert.self_signed", "certificate", c.ID.String(), map[string]any{"domains": c.Domains})
	out := publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID))
	out["trust_warning"] = "self_signed_not_trusted"
	WriteJSON(w, http.StatusCreated, out)
}

func (h *CertHandler) PrivateCA(w http.ResponseWriter, r *http.Request) {
	var req privateCAReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	bundle, err := certs.SignWithPrivateCA(req.Domains, req.ValidDays, []byte(req.CACertificate), []byte(req.CAPrivateKey))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	c, err := h.persist(r.Context(), req.Name, "private_ca", nil, bundle, false)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeAudit(h.Store, r, "cert.private_ca", "certificate", c.ID.String(), map[string]any{"domains": c.Domains})
	WriteJSON(w, http.StatusCreated, publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID)))
}

func (h *CertHandler) ACMEIssue(w http.ResponseWriter, r *http.Request) {
	var req acmeIssueReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	chal := strings.ToLower(strings.TrimSpace(req.Challenge))
	if chal != "http-01" && chal != "dns-01" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "challenge must be http-01 or dns-01")
		return
	}
	if certs.IsWildcard(req.Domains) && chal != "dns-01" {
		WriteError(w, http.StatusBadRequest, "validation_failed", "wildcard requires dns-01")
		return
	}
	staging := true
	if req.Staging != nil {
		staging = *req.Staging
	}
	dirURL := certs.LetsEncryptStaging
	if !staging {
		dirURL = certs.LetsEncryptProd
	}
	acmeCfg := certs.ACMEConfig{
		Email: h.Cfg.ACMEEmail, DirectoryURL: dirURL,
		AccountDir: h.Cfg.ACMEAccountDir, HTTPWebRoot: h.Cfg.ACMEWebRoot,
	}
	if chal == "dns-01" {
		if h.Cfg.CloudflareAPIToken == "" && !h.Cfg.ACMEUseMockDNS {
			WriteError(w, http.StatusBadRequest, "validation_failed", "CLOUDFLARE_API_TOKEN required for dns-01")
			return
		}
		if h.Cfg.ACMEUseMockDNS {
			acmeCfg.DNS = certs.NewMockDNS()
		} else {
			acmeCfg.DNS = certs.NewCloudflareDNS(h.Cfg.CloudflareAPIToken)
		}
	}
	if chal == "http-01" && h.ApplyHook != nil {
		_ = os.MkdirAll(h.Cfg.ACMEWebRoot+"/.well-known/acme-challenge", 0o755)
		if err := h.ApplyHook(r.Context()); err != nil {
			h.logACME(r.Context(), nil, "issue", chal, req.Domains, "failure", "challenge publish: "+err.Error(), h.actorEmail(r))
			WriteError(w, http.StatusConflict, "reload_failed", "failed to publish challenge config: "+err.Error())
			return
		}
	}
	client, err := certs.NewACME(acmeCfg)
	if err != nil {
		h.logACME(r.Context(), nil, "issue", chal, req.Domains, "failure", err.Error(), h.actorEmail(r))
		WriteError(w, http.StatusInternalServerError, "internal", "acme init failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	bundle, err := client.Issue(ctx, req.Domains, chal)
	if err != nil {
		// Never include Cloudflare token / key material in stored message.
		h.logACME(r.Context(), nil, "issue", chal, req.Domains, "failure", sanitizeACMEErr(err), h.actorEmail(r))
		WriteError(w, http.StatusBadGateway, "acme_failed", sanitizeACMEErr(err))
		return
	}
	chalCopy := chal
	c, err := h.persist(r.Context(), req.Name, "acme", &chalCopy, bundle, req.AutoRenew)
	if err != nil {
		h.logACME(r.Context(), nil, "issue", chal, req.Domains, "failure", err.Error(), h.actorEmail(r))
		WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	cid := c.ID
	h.logACME(r.Context(), &cid, "issue", chal, c.Domains, "success", "", h.actorEmail(r))
	writeAudit(h.Store, r, "cert.acme_issue", "certificate", c.ID.String(), map[string]any{
		"domains": c.Domains, "challenge": chal, "staging": staging,
	})
	WriteJSON(w, http.StatusCreated, publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID)))
}

func (h *CertHandler) Renew(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	c, errMsg, err := h.RenewCertificate(r.Context(), id, h.actorEmail(r))
	if err != nil {
		code := http.StatusInternalServerError
		errCode := "internal"
		switch {
		case errors.Is(err, db.ErrNotFound):
			code, errCode = http.StatusNotFound, "not_found"
		case strings.Contains(err.Error(), "only acme"):
			code, errCode = http.StatusBadRequest, "validation_failed"
		case strings.Contains(err.Error(), "renew failed"):
			code, errCode = http.StatusBadGateway, "acme_failed"
		}
		WriteError(w, code, errCode, errMsg)
		return
	}
	writeAudit(h.Store, r, "cert.renew", "certificate", id.String(), map[string]any{"fingerprint": c.FingerprintSHA256})
	if h.ApplyHook != nil {
		_ = h.ApplyHook(r.Context())
	}
	WriteJSON(w, http.StatusOK, publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID)))
}

// RenewCertificate issues a fresh ACME cert, keeping previous on disk for rollback (REQ-SSL-008/016).
func (h *CertHandler) RenewCertificate(ctx context.Context, id uuid.UUID, actor string) (models.Certificate, string, error) {
	existing, err := h.Store.GetCertificate(ctx, id)
	if err != nil {
		return existing, "certificate not found", err
	}
	if existing.Kind != "acme" || existing.ACMEChallenge == nil {
		return existing, "only acme certificates can renew via this endpoint", fmt.Errorf("only acme")
	}
	chal := *existing.ACMEChallenge
	acmeCfg := certs.ACMEConfig{
		Email: h.Cfg.ACMEEmail, DirectoryURL: certs.LetsEncryptStaging,
		AccountDir: h.Cfg.ACMEAccountDir, HTTPWebRoot: h.Cfg.ACMEWebRoot,
	}
	if chal == "dns-01" {
		if h.Cfg.ACMEUseMockDNS {
			acmeCfg.DNS = certs.NewMockDNS()
		} else if h.Cfg.CloudflareAPIToken != "" {
			acmeCfg.DNS = certs.NewCloudflareDNS(h.Cfg.CloudflareAPIToken)
		}
	}
	client, err := certs.NewACME(acmeCfg)
	if err != nil {
		h.logACME(ctx, &id, "renew", chal, existing.Domains, "failure", err.Error(), actor)
		return existing, "acme init failed", err
	}
	issueCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	bundle, err := client.Issue(issueCtx, existing.Domains, chal)
	if err != nil {
		msg := "renew failed; previous certificate retained: " + sanitizeACMEErr(err)
		h.logACME(ctx, &id, "renew", chal, existing.Domains, "failure", sanitizeACMEErr(err), actor)
		return existing, msg, fmt.Errorf("renew failed: %w", err)
	}
	certPath, keyPath, err := h.FS.WriteBundle(id, bundle)
	if err != nil {
		h.logACME(ctx, &id, "renew", chal, existing.Domains, "failure", "write failed", actor)
		return existing, "write failed; previous retained", err
	}
	c, err := h.Store.UpdateCertificateBundle(ctx, id, bundle, certPath, keyPath)
	if err != nil {
		h.logACME(ctx, &id, "renew", chal, existing.Domains, "failure", "db update failed", actor)
		return existing, "db update failed", err
	}
	h.logACME(ctx, &id, "renew", chal, c.Domains, "success", "", actor)
	return c, "", nil
}

func (h *CertHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if _, err := h.Store.GetCertificate(r.Context(), id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	certPath, keyPath, err := h.FS.RestorePrevious(id)
	if err != nil {
		WriteError(w, http.StatusConflict, "no_revision", err.Error())
		return
	}
	bundle, err := h.FS.ReadBundle(id)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "read restored bundle failed")
		return
	}
	c, err := h.Store.UpdateCertificateBundle(r.Context(), id, bundle, certPath, keyPath)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "db update failed")
		return
	}
	h.logACME(r.Context(), &id, "rollback", "", c.Domains, "success", "", h.actorEmail(r))
	writeAudit(h.Store, r, "cert.rollback", "certificate", id.String(), map[string]any{"fingerprint": c.FingerprintSHA256})
	if h.ApplyHook != nil {
		_ = h.ApplyHook(r.Context())
	}
	WriteJSON(w, http.StatusOK, publicCert(c, h.FS, h.certInUseMap(r.Context(), c.ID)))
}

func (h *CertHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	if err := h.Store.DeleteCertificate(r.Context(), id); errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "certificate not found")
		return
	} else if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "delete failed")
		return
	}
	_ = h.FS.Remove(id)
	writeAudit(h.Store, r, "cert.delete", "certificate", id.String(), nil)
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *CertHandler) Bind(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid id")
		return
	}
	var req bindReq
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid json")
		return
	}
	hostID, err := uuid.Parse(req.HostID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "validation_failed", "invalid host_id")
		return
	}
	cert, err := h.Store.GetCertificate(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get failed")
		return
	}
	host, err := h.Store.GetHost(r.Context(), hostID)
	if errors.Is(err, db.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "get host failed")
		return
	}
	names := append([]string{host.PrimaryDomain}, host.Aliases...)
	for _, n := range names {
		if !certs.CoversHost(cert.Domains, n) {
			WriteError(w, http.StatusBadRequest, "san_mismatch",
				fmt.Sprintf("certificate SANs %v do not cover host %q", cert.Domains, n))
			return
		}
	}
	if err := h.Store.BindHostCertificate(r.Context(), hostID, id); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "bind failed")
		return
	}
	writeAudit(h.Store, r, "cert.bind", "certificate", id.String(), map[string]string{"host_id": hostID.String()})
	if h.ApplyHook != nil {
		if err := h.ApplyHook(r.Context()); err != nil {
			WriteError(w, http.StatusConflict, "reload_failed", "bound but apply failed: "+err.Error())
			return
		}
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "bound"})
}

func (h *CertHandler) persist(ctx context.Context, name, kind string, chal *string, bundle *certs.ParsedBundle, autoRenew bool) (models.Certificate, error) {
	if name == "" {
		name = bundle.Domains[0]
	}
	id := uuid.New()
	if err := h.FS.EnsureLayout(); err != nil {
		return models.Certificate{}, err
	}
	certPath, keyPath, err := h.FS.WriteBundle(id, bundle)
	if err != nil {
		return models.Certificate{}, err
	}
	nb, na := bundle.NotBefore, bundle.NotAfter
	c := models.Certificate{
		ID: id, Name: name, Domains: bundle.Domains, Kind: kind, ACMEChallenge: chal,
		FingerprintSHA256: bundle.Fingerprint, NotBefore: &nb, NotAfter: &na,
		Issuer: bundle.Issuer, CertPath: certPath, KeyPath: keyPath,
		AutoRenew: autoRenew, RenewAfterDays: 30,
	}
	created, err := h.Store.CreateCertificate(ctx, c)
	if err != nil {
		_ = h.FS.Remove(id)
		return models.Certificate{}, fmt.Errorf("db: %w", err)
	}
	return created, nil
}

func (h *CertHandler) certInUseMap(ctx context.Context, id uuid.UUID) map[uuid.UUID]bool {
	inUse, err := h.Store.CertificateIDsInUse(ctx)
	if err != nil || inUse == nil {
		return map[uuid.UUID]bool{}
	}
	// Keep map as-is; callers may pass single-id focus via CertificateIDsInUse.
	_ = id
	return inUse
}

func publicCert(c models.Certificate, fs *certs.Store, inUse map[uuid.UUID]bool) map[string]any {
	expired := c.DaysRemaining != nil && *c.DaysRemaining < 0
	used := inUse != nil && inUse[c.ID]
	status := "unused"
	if expired {
		status = "expired"
	} else if used {
		status = "in_use"
	}
	m := map[string]any{
		"id": c.ID, "name": c.Name, "domains": c.Domains, "kind": c.Kind,
		"acme_challenge": c.ACMEChallenge, "fingerprint_sha256": c.FingerprintSHA256,
		"not_before": c.NotBefore, "not_after": c.NotAfter, "issuer": c.Issuer,
		"auto_renew": c.AutoRenew, "renew_after_days": c.RenewAfterDays,
		"days_remaining": c.DaysRemaining, "expiring_soon": c.ExpiringSoon,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
		"has_previous": false,
		"in_use":       used,
		"expired":      expired,
		"status":       status, // in_use | unused | expired
	}
	if fs != nil {
		m["has_previous"] = fs.HasPrevious(c.ID)
	}
	return m
}

func publicCerts(items []models.Certificate, fs *certs.Store, inUse map[uuid.UUID]bool) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, c := range items {
		out = append(out, publicCert(c, fs, inUse))
	}
	return out
}

func sanitizeACMEErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// Strip anything that looks like a bearer token if it ever leaked into an error.
	if i := strings.Index(strings.ToLower(s), "bearer "); i >= 0 {
		return s[:i] + "bearer [redacted]"
	}
	return s
}

var _ = json.Marshal
