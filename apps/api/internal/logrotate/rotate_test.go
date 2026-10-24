package logrotate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotateTree(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nginx", "proxy_host")
	errSub := filepath.Join(dir, "nginx", "proxy_host_error")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(errSub, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(sub, "app.example.com.log")
	errLogPath := filepath.Join(errSub, "app.example.com.log")
	if err := os.WriteFile(logPath, make([]byte, 200), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errLogPath, make([]byte, 200), 0o644); err != nil {
		t.Fatal(err)
	}
	// undersized — no rotate
	rot, err := RotateTree(dir, 1000, 3)
	if err != nil || len(rot) != 0 {
		t.Fatalf("expected no rotate: %v %v", rot, err)
	}
	rot, err = RotateTree(dir, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(rot) != 2 {
		t.Fatalf("expected access+error rotated, got %v", rot)
	}
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatal("missing .1", err)
	}
	if _, err := os.Stat(errLogPath + ".1"); err != nil {
		t.Fatal("missing error .1", err)
	}
	if st, err := os.Stat(logPath); err != nil || st.Size() != 0 {
		t.Fatalf("active log should be recreated empty: %v %v", st, err)
	}
	// second rotate shifts
	if err := os.WriteFile(logPath, make([]byte, 200), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = RotateTree(dir, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath + ".2"); err != nil {
		t.Fatal("missing .2", err)
	}
}
