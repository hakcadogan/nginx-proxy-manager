package certs

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSelfSignedRoundTrip(t *testing.T) {
	b, err := GenerateSelfSigned([]string{"app.example.com", "www.app.example.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if b.Fingerprint == "" {
		t.Fatal("missing fingerprint")
	}
	if !strings.Contains(string(b.CertPEM), "BEGIN CERTIFICATE") {
		t.Fatal("missing cert pem")
	}
	if strings.Contains(b.Fingerprint, string(b.KeyPEM)) {
		t.Fatal("fingerprint must not embed key")
	}
}

func TestRejectMismatchedKey(t *testing.T) {
	a, err := GenerateSelfSigned([]string{"a.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSelfSigned([]string{"b.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAndValidatePEM(a.CertPEM, b.KeyPEM)
	if err == nil {
		t.Fatal("expected key mismatch")
	}
}

func TestPrivateCASign(t *testing.T) {
	caCert, caKey, err := GeneratePrivateCA("NSP Test CA", 365)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := SignWithPrivateCA([]string{"svc.example.com"}, 30, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.Before(time.Now()) {
		t.Fatal("leaf expired")
	}
}

func TestWildcardRequiresDNS(t *testing.T) {
	if !IsWildcard([]string{"*.example.com"}) {
		t.Fatal("expected wildcard")
	}
}

func TestIsDNSNameLike(t *testing.T) {
	ok := []string{"example.com", "*.example.com", "www.example.com", "localhost", "127.0.0.1"}
	bad := []string{
		"cloudflare origin certificate",
		"CloudFlare Origin Certificate",
		"My Org CA",
		"",
		"*",
		"*.*.example.com",
		"no spaces allowed.com",
	}
	for _, s := range ok {
		if !isDNSNameLike(s) {
			t.Fatalf("expected ok: %q", s)
		}
	}
	for _, s := range bad {
		if isDNSNameLike(s) {
			t.Fatalf("expected reject: %q", s)
		}
	}
}

func TestCertDomainsSkipsLabelCN(t *testing.T) {
	// Simulate Cloudflare Origin-style leaf: human CN + real SANs.
	b, err := GenerateSelfSigned([]string{"*.craftpirlanta.com", "craftpirlanta.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	// Re-parse and ensure domains are hostname-like only.
	for _, d := range b.Domains {
		if !isDNSNameLike(d) {
			t.Fatalf("non-dns domain leaked: %q", d)
		}
		if strings.Contains(d, " ") {
			t.Fatalf("space in domain: %q", d)
		}
	}
}

func TestCoversHostWildcard(t *testing.T) {
	sans := []string{"*.example.com", "example.com"}
	if !CoversHost(sans, "example.com") {
		t.Fatal("apex")
	}
	if !CoversHost(sans, "a.example.com") {
		t.Fatal("wildcard leaf")
	}
	if CoversHost(sans, "a.b.example.com") {
		t.Fatal("multi-label must not match single wildcard")
	}
	if CoversHost(sans, "other.com") {
		t.Fatal("foreign domain")
	}
}

func TestValidateChainSelfSigned(t *testing.T) {
	b, err := GenerateSelfSigned([]string{"solo.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateChain(b.Chain); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicWriteBundle(t *testing.T) {
	dir := t.TempDir()
	st := &Store{Root: dir}
	b1, err := GenerateSelfSigned([]string{"v1.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	id := mustParseUUID("11111111-1111-1111-1111-111111111111")
	if _, _, err := st.WriteBundle(id, b1); err != nil {
		t.Fatal(err)
	}
	b2, err := GenerateSelfSigned([]string{"v2.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.WriteBundle(id, b2); err != nil {
		t.Fatal(err)
	}
	if !st.HasPrevious(id) {
		t.Fatal("expected previous revision")
	}
	if _, _, err := st.RestorePrevious(id); err != nil {
		t.Fatal(err)
	}
	got, err := st.ReadBundle(id)
	if err != nil {
		t.Fatal(err)
	}
	if !CoversHost(got.Domains, "v1.example.com") && !CoversHost(got.Domains, "v2.example.com") {
		// After restore of first backup of v1, then write v2 backed up v1;
		// RestorePrevious restores .prev which after second write is v1.
		t.Log(got.Domains)
	}
	if !CoversHost(got.Domains, "v1.example.com") {
		t.Fatalf("expected v1 after rollback, got %v", got.Domains)
	}
}

func mustParseUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

func TestShouldRenew(t *testing.T) {
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	soon := now.Add(10 * 24 * time.Hour)
	later := now.Add(60 * 24 * time.Hour)
	if !ShouldRenew(soon, 30, now) {
		t.Fatal("should renew soon expiry")
	}
	if ShouldRenew(later, 30, now) {
		t.Fatal("should not renew far expiry")
	}
}

func TestMockDNSPresent(t *testing.T) {
	m := NewMockDNS()
	if err := m.Present(nil, "example.com", "tok", "txtval"); err != nil {
		t.Fatal(err)
	}
	if m.Records["_acme-challenge.example.com"] != "txtval" {
		t.Fatalf("record=%v", m.Records)
	}
}
