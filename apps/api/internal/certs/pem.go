package certs

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	ErrInvalidPEM     = errors.New("invalid PEM")
	ErrKeyMismatch    = errors.New("certificate and private key do not match")
	ErrEmptyCert      = errors.New("certificate PEM is empty")
	ErrEmptyKey       = errors.New("private key PEM is empty")
)

type ParsedBundle struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	PrivateKey  any
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
	Domains     []string
	NotBefore   time.Time
	NotAfter    time.Time
	Issuer      string
}

// ParseAndValidatePEM validates cert+key PEMs (REQ-SSL-001). Never logs key material.
func ParseAndValidatePEM(certPEM, keyPEM []byte) (*ParsedBundle, error) {
	if len(certPEM) == 0 {
		return nil, ErrEmptyCert
	}
	if len(keyPEM) == 0 {
		return nil, ErrEmptyKey
	}
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !keysMatch(certs[0], key) {
		return nil, ErrKeyMismatch
	}
	if err := ValidateChain(certs); err != nil {
		return nil, err
	}
	fp := sha256.Sum256(certs[0].Raw)
	domains := certDomains(certs[0])
	return &ParsedBundle{
		Certificate: certs[0],
		Chain:       certs,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: hex.EncodeToString(fp[:]),
		Domains:     domains,
		NotBefore:   certs[0].NotBefore.UTC(),
		NotAfter:    certs[0].NotAfter.UTC(),
		Issuer:      certs[0].Issuer.String(),
	}, nil
}

func parseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPEM, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, ErrInvalidPEM
	}
	return out, nil
}

func parsePrivateKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrInvalidPEM
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, ErrInvalidPEM
}

func keysMatch(cert *x509.Certificate, key any) bool {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		return ok && pub.N.Cmp(k.N) == 0 && pub.E == k.E
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		return ok && pub.X.Cmp(k.X) == 0 && pub.Y.Cmp(k.Y) == 0
	default:
		return false
	}
}

func certDomains(c *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] || !isDNSNameLike(s) {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	// Prefer SANs; CN is often a human label (e.g. "Cloudflare Origin Certificate").
	for _, d := range c.DNSNames {
		add(d)
	}
	add(c.Subject.CommonName)
	return out
}

// isDNSNameLike filters certificate CN/SAN values that are not hostnames
// (Cloudflare Origin CN, organization strings, etc.).
func isDNSNameLike(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.ContainsAny(s, " \t") {
		return false
	}
	if s == "localhost" {
		return true
	}
	host := strings.TrimPrefix(s, "*.")
	if host == "" || strings.Contains(host, "*") {
		return false
	}
	// Require at least one dot (FQDN / multi-label) or a valid IPv4/IPv6 literal.
	if net.ParseIP(host) != nil {
		return true
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, p := range strings.Split(host, ".") {
		if p == "" || len(p) > 63 {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
		if p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
	}
	return true
}

// DaysUntilExpiry returns whole days until NotAfter (negative if expired).
func DaysUntilExpiry(notAfter time.Time, now time.Time) int {
	d := notAfter.Sub(now)
	return int(d.Hours() / 24)
}

// ValidateChain checks leaf←intermediate signatures (REQ-SSL-015).
// A single self-signed leaf is accepted; a multi-cert PEM must chain.
func ValidateChain(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return ErrInvalidPEM
	}
	if len(chain) == 1 {
		leaf := chain[0]
		if err := leaf.CheckSignatureFrom(leaf); err == nil {
			return nil // self-signed
		}
		// Leaf-only without self-sign (e.g. incomplete upload) — allow but require key match already done.
		return nil
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("certificate chain broken between cert[%d] and cert[%d]: %w", i, i+1, err)
		}
	}
	return nil
}

// CoversHost reports whether cert SANs cover host (incl. wildcard) — REQ-SSL-015.
func CoversHost(certDomains []string, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, d := range certDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == host {
			return true
		}
		if strings.HasPrefix(d, "*.") {
			suffix := d[1:] // .example.com
			if strings.HasSuffix(host, suffix) && !strings.Contains(strings.TrimSuffix(host, suffix), ".") {
				// single-label wildcard: *.example.com matches a.example.com not a.b.example.com
				left := strings.TrimSuffix(host, suffix)
				if left != "" && !strings.Contains(left, ".") {
					return true
				}
			}
		}
	}
	return false
}
