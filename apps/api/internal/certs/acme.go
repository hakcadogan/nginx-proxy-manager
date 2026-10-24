package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	LetsEncryptProd    = "https://acme-v02.api.letsencrypt.org/directory"
)

// ACMEConfig for account + challenge (REQ-SSL-010).
type ACMEConfig struct {
	Email        string
	DirectoryURL string
	AccountDir   string // persists account key
	HTTPWebRoot  string // for HTTP-01
	DNS          DNSProvider
	EABKID       string
	EABHMAC      []byte // optional
}

type ACMEClient struct {
	cfg    ACMEConfig
	client *acme.Client
}

func NewACME(cfg ACMEConfig) (*ACMEClient, error) {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = LetsEncryptStaging
	}
	if cfg.AccountDir == "" {
		return nil, fmt.Errorf("account dir required")
	}
	if err := os.MkdirAll(cfg.AccountDir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateAccountKey(filepath.Join(cfg.AccountDir, "account.key"))
	if err != nil {
		return nil, err
	}
	cli := &acme.Client{Key: key, DirectoryURL: cfg.DirectoryURL}
	a := &ACMEClient{cfg: cfg, client: cli}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := a.ensureAccount(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *ACMEClient) ensureAccount(ctx context.Context) (*acme.Account, error) {
	acc := &acme.Account{Contact: []string{"mailto:" + a.cfg.Email}}
	reg, err := a.client.Register(ctx, acc, acme.AcceptTOS)
	if err != nil {
		// Account may already exist for this key.
		reg, err = a.client.GetReg(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("acme register/get: %w", err)
		}
	}
	_ = a.cfg.EABKID
	_ = a.cfg.EABHMAC
	_ = os.WriteFile(filepath.Join(a.cfg.AccountDir, "account.json"), mustJSON(map[string]string{
		"email": a.cfg.Email, "uri": reg.URI, "directory": a.cfg.DirectoryURL,
	}), 0o600)
	return reg, nil
}

// Issue obtains a certificate (REQ-SSL-004/005/007/011).
// challenge: http-01 | dns-01. Wildcard requires dns-01.
func (a *ACMEClient) Issue(ctx context.Context, domains []string, challenge string) (*ParsedBundle, error) {
	domains = normalizeDomains(domains)
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains required")
	}
	if IsWildcard(domains) && challenge != "dns-01" {
		return nil, fmt.Errorf("wildcard certificates require dns-01 challenge")
	}
	if challenge == "http-01" && a.cfg.HTTPWebRoot == "" {
		return nil, fmt.Errorf("HTTP webroot required for http-01")
	}
	if challenge == "dns-01" && a.cfg.DNS == nil {
		return nil, fmt.Errorf("DNS provider required for dns-01")
	}

	order, err := a.client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, fmt.Errorf("authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := a.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		chal := pickChallenge(authz, challenge)
		if chal == nil {
			return nil, fmt.Errorf("challenge %s not offered for %s", challenge, authz.Identifier.Value)
		}
		if err := a.solve(ctx, authz.Identifier.Value, chal, challenge); err != nil {
			return nil, err
		}
	}

	order, err = a.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("wait order: %w", err)
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: domains,
	}, csrKey)
	if err != nil {
		return nil, err
	}
	der, _, err := a.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}
	var certPEM []byte
	for _, c := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keyPEM, err := encodeECKey(csrKey)
	if err != nil {
		return nil, err
	}
	return ParseAndValidatePEM(certPEM, keyPEM)
}

func (a *ACMEClient) solve(ctx context.Context, domain string, chal *acme.Challenge, kind string) error {
	keyAuth, err := a.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	switch kind {
	case "http-01":
		path := filepath.Join(a.cfg.HTTPWebRoot, ".well-known", "acme-challenge", chal.Token)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(keyAuth), 0o644); err != nil {
			return err
		}
		defer os.Remove(path)
	case "dns-01":
		txt, err := a.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		if err := a.cfg.DNS.Present(ctx, domain, chal.Token, txt); err != nil {
			return err
		}
		defer func() { _ = a.cfg.DNS.CleanUp(ctx, domain, chal.Token, txt) }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	default:
		return fmt.Errorf("unsupported challenge %s", kind)
	}
	if _, err := a.client.Accept(ctx, chal); err != nil {
		return err
	}
	_, err = a.client.WaitAuthorization(ctx, chal.URI)
	return err
}

func pickChallenge(authz *acme.Authorization, kind string) *acme.Challenge {
	for _, c := range authz.Challenges {
		if c.Type == kind {
			return c
		}
	}
	return nil
}

func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBytes, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// ShouldRenew reports whether cert should renew (REQ-SSL-008).
func ShouldRenew(notAfter time.Time, renewAfterDays int, now time.Time) bool {
	if renewAfterDays <= 0 {
		renewAfterDays = 30
	}
	return now.Add(time.Duration(renewAfterDays) * 24 * time.Hour).After(notAfter)
}

// Fix MockDNS Present to store digest passed as keyAuth when called from Issue (we pass txt digest).
func init() {
	_ = strings.TrimSpace
}
