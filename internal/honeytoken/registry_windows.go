//go:build windows

package honeytoken

import (
	"errors"
	"fmt"
	"strings"

	"github.com/misherr2004/honeypot-agent/internal/store"
	"golang.org/x/sys/windows/registry"
)

func (r *RegistryChecker) placeRegistry(opts PlaceOptions) error {
	if r.Store == nil {
		return fmt.Errorf("registry checker: store is nil")
	}
	name := sanitizeFilePart(opts.Name)
	if name == "" {
		return fmt.Errorf("registry token: name is required")
	}
	subKey := `Software\HoneypotAgent\Credentials\` + name
	k, _, err := registry.CreateKey(registry.CURRENT_USER, subKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create registry key: %w", err)
	}
	defer func() {
		_ = k.Close()
	}()
	if err := k.SetStringValue("Password", opts.Password); err != nil {
		return fmt.Errorf("set registry password: %w", err)
	}
	ki, err := k.Stat()
	if err != nil {
		return fmt.Errorf("stat registry key: %w", err)
	}
	storedPath := `HKCU\` + subKey
	rec := store.Record{
		Name:     opts.Name,
		Type:     "registry",
		Path:     storedPath,
		Hash:     ContentHash(opts.Password),
		Mtime:    ki.ModTime.Unix(),
		Status:   "active",
		PlacedAt: FormatPlacedAt(),
	}
	if _, err := r.Store.Insert(rec); err != nil {
		return fmt.Errorf("persist registry token: %w", err)
	}
	return nil
}

func (r *RegistryChecker) checkRegistry(token HoneyToken) (CheckResult, error) {
	sub, err := hkcuSubpath(token.Path)
	if err != nil {
		return CheckResult{}, fmt.Errorf("parse registry path: %w", err)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, sub, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return CheckResult{Action: "deleted", Status: "compromised"}, nil
		}
		return CheckResult{}, fmt.Errorf("open registry key: %w", err)
	}
	defer func() {
		_ = k.Close()
	}()
	pass, _, err := k.GetStringValue("Password")
	if err != nil {
		if err == registry.ErrNotExist {
			return CheckResult{Action: "modified", Status: "compromised"}, nil
		}
		return CheckResult{}, fmt.Errorf("read registry password: %w", err)
	}
	if ContentHash(pass) != token.Hash {
		return CheckResult{Action: "modified", Status: "compromised"}, nil
	}
	return CheckResult{Status: "intact"}, nil
}

func hkcuSubpath(storedPath string) (string, error) {
	storedPath = strings.TrimSpace(storedPath)
	pfx := `HKCU\`
	if !strings.HasPrefix(strings.ToUpper(storedPath), strings.ToUpper(pfx)) {
		return "", fmt.Errorf("unsupported registry path prefix: %s", storedPath)
	}
	return storedPath[len(pfx):], nil
}
