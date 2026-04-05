//go:build !windows

package honeytoken

import (
	"fmt"
	"os"
	"path/filepath"
	"github.com/misherr2004/honeypot-agent/internal/store"
)

func (r *RegistryChecker) placeRegistry(opts PlaceOptions) error {
	if r.Store == nil {
		return fmt.Errorf("registry checker: store is nil")
	}
	name := sanitizeFilePart(opts.Name)
	if name == "" {
		return fmt.Errorf("registry token: name is required")
	}
	dir := filepath.Join(r.Home, ".honeypot", "registry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create registry marker dir: %w", err)
	}
	path := filepath.Join(dir, name+".reg")
	content := fakeRegFileContent(name, opts.Password)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write registry marker file: %w", err)
	}
	mtime, err := StatMtimeUnix(path)
	if err != nil {
		return fmt.Errorf("registry marker mtime: %w", err)
	}
	rec := store.Record{
		Name:     opts.Name,
		Type:     "registry",
		Path:     path,
		Hash:     ContentHash(content),
		Mtime:    mtime,
		Status:   "active",
		PlacedAt: FormatPlacedAt(),
	}
	if _, err := r.Store.Insert(rec); err != nil {
		return fmt.Errorf("persist registry token: %w", err)
	}
	return nil
}

func (r *RegistryChecker) checkRegistry(token HoneyToken) (CheckResult, error) {
	res, err := checkDecoyFile(token)
	if err != nil {
		return CheckResult{}, fmt.Errorf("registry file check: %w", err)
	}
	return res, nil
}

func fakeRegFileContent(name, password string) string {
	return fmt.Sprintf("Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\HoneypotAgent\\%s]\n\"Password\"=%q\n", name, password)
}
