package honeytoken

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile(t *testing.T) {
	a := ContentHash("password=supersecret123")
	b := ContentHash("password=supersecret123")
	if a != b {
		t.Fatalf("ContentHash not stable: %q vs %q", a, b)
	}
	if a == ContentHash("other") {
		t.Fatal("ContentHash collision for different inputs")
	}
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(a))
	}
}

func TestFileTokenCheck_Intact(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.txt")
	content := "password=supersecret123"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mt := st.ModTime()
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	token := HoneyToken{
		Path: p,
		Hash: ContentHash(content),
	}
	res, err := checkDecoyFile(token)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Status != "intact" || res.Action != "" {
		t.Fatalf("expected intact, got %+v", res)
	}
}

func TestFileTokenCheck_Modified(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(p, []byte("original"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	token := HoneyToken{
		Path: p,
		Hash: ContentHash("original"),
	}
	if err := os.WriteFile(p, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}
	res, err := checkDecoyFile(token)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Status != "compromised" || res.Action != "modified" {
		t.Fatalf("expected modified compromise, got %+v", res)
	}
}
