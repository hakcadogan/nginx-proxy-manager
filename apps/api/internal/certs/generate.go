package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// GenerateSelfSigned creates a self-signed cert+key (REQ-SSL-002).
func GenerateSelfSigned(domains []string, validDays int) (*ParsedBundle, error) {
	if validDays <= 0 {
		validDays = 365
	}
	if validDays > 8250 {
		return nil, fmt.Errorf("valid_days must be <= 8250")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template, err := leafTemplate(domains, validDays, true)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return bundleFromDER(der, key, domains)
}

// SignWithPrivateCA signs a leaf using CA cert+key PEMs (REQ-SSL-003).
func SignWithPrivateCA(domains []string, validDays int, caCertPEM, caKeyPEM []byte) (*ParsedBundle, error) {
	if validDays <= 0 {
		validDays = 90
	}
	if validDays > 8250 {
		return nil, fmt.Errorf("valid_days must be <= 8250")
	}
	caBundle, err := ParseAndValidatePEM(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if !caBundle.Certificate.IsCA {
		return nil, fmt.Errorf("ca certificate is not marked as CA")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template, err := leafTemplate(domains, validDays, false)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caBundle.Certificate, &key.PublicKey, caBundle.PrivateKey)
	if err != nil {
		return nil, err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Append CA cert for chain
	full := append(leafPEM, caBundle.CertPEM...)
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}
	return ParseAndValidatePEM(full, keyPEM)
}

// GeneratePrivateCA creates a basic CA cert for lab use (REQ-SSL-003 helper).
func GeneratePrivateCA(cn string, validDays int) (certPEM, keyPEM []byte, err error) {
	if validDays <= 0 {
		validDays = 3650
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"NSP Private CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err = encodeECKey(key)
	return certPEM, keyPEM, err
}

func leafTemplate(domains []string, validDays int, selfSigned bool) (*x509.Certificate, error) {
	domains = normalizeDomains(domains)
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain required")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, validDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
	}
	for _, d := range domains {
		if ip := net.ParseIP(d); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	if selfSigned {
		tmpl.BasicConstraintsValid = true
	}
	return tmpl, nil
}

func bundleFromDER(der []byte, key *ecdsa.PrivateKey, domains []string) (*ParsedBundle, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}
	return ParseAndValidatePEM(certPEM, keyPEM)
}

func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

func normalizeDomains(domains []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// IsWildcard reports whether any domain is a wildcard (REQ-SSL-007).
func IsWildcard(domains []string) bool {
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			return true
		}
	}
	return false
}
