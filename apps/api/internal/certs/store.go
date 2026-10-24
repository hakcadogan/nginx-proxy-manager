package certs

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// Store manages cert files on a dedicated volume (REQ-SSL-013, REQ-OPS-002).
// Keys live under Root (e.g. /data/certs host bind) — never under ACME webroot.
type Store struct {
	Root string
}

func (s *Store) Dir(id uuid.UUID) string {
	return filepath.Join(s.Root, id.String())
}

func (s *Store) WriteBundle(id uuid.UUID, bundle *ParsedBundle) (certPath, keyPath string, err error) {
	dir := s.Dir(id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")

	// Backup previous for rollback (REQ-SSL-016).
	_ = backupIfExists(certPath, certPath+".prev")
	_ = backupIfExists(keyPath, keyPath+".prev")

	if err := atomicWrite(certPath, bundle.CertPEM, 0o640); err != nil {
		return "", "", err
	}
	if err := atomicWrite(keyPath, bundle.KeyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// RestorePrevious swaps .prev files back to current (REQ-SSL-016).
func (s *Store) RestorePrevious(id uuid.UUID) (certPath, keyPath string, err error) {
	dir := s.Dir(id)
	certPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	certPrev := certPath + ".prev"
	keyPrev := keyPath + ".prev"
	if _, err := os.Stat(certPrev); err != nil {
		return "", "", fmt.Errorf("no previous certificate revision")
	}
	if _, err := os.Stat(keyPrev); err != nil {
		return "", "", fmt.Errorf("no previous private key revision")
	}
	certPEM, err := os.ReadFile(certPrev)
	if err != nil {
		return "", "", err
	}
	keyPEM, err := os.ReadFile(keyPrev)
	if err != nil {
		return "", "", err
	}
	bundle, err := ParseAndValidatePEM(certPEM, keyPEM)
	if err != nil {
		return "", "", err
	}
	// WriteBundle will backup current → .prev again (swap).
	return s.WriteBundle(id, bundle)
}

func (s *Store) ReadBundle(id uuid.UUID) (*ParsedBundle, error) {
	dir := s.Dir(id)
	certPEM, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return nil, err
	}
	return ParseAndValidatePEM(certPEM, keyPEM)
}

func (s *Store) HasPrevious(id uuid.UUID) bool {
	_, err := os.Stat(filepath.Join(s.Dir(id), "fullchain.pem.prev"))
	return err == nil
}

func (s *Store) Remove(id uuid.UUID) error {
	return os.RemoveAll(s.Dir(id))
}

func (s *Store) EnsureLayout() error {
	if s.Root == "" {
		return fmt.Errorf("certs root empty")
	}
	return os.MkdirAll(s.Root, 0o750)
}

func backupIfExists(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o640)
	if filepath.Base(src) == "privkey.pem" {
		mode = 0o600
	}
	return atomicWrite(dst, b, mode)
}

// atomicWrite writes via temp file + rename (REQ-SSL-013).
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	_ = os.Chmod(path, mode)
	return nil
}
