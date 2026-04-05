package honeytoken

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/misherr2004/honeypot-agent/internal/store"
)

// FileChecker places and monitors file-based honeytokens on disk.
type FileChecker struct {
	Store store.Store
}

// Place writes the decoy file and persists metadata in the store.
func (f *FileChecker) Place(opts PlaceOptions) error {
	if f.Store == nil {
		return fmt.Errorf("file checker: store is nil")
	}
	path, err := expandPath(opts.Path)
	if err != nil {
		return fmt.Errorf("expand path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent dirs: %w", err)
	}
	if err := os.WriteFile(path, []byte(opts.Content), 0o600); err != nil {
		return fmt.Errorf("write honey file: %w", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat honey file: %w", err)
	}
	mtime := st.ModTime().Unix()
	hash := ContentHash(opts.Content)
	name := filepath.Base(path)
	rec := store.Record{
		Name:     name,
		Type:     "file",
		Path:     path,
		Hash:     hash,
		Mtime:    mtime,
		Status:   "active",
		PlacedAt: FormatPlacedAt(),
	}
	if _, err := f.Store.Insert(rec); err != nil {
		return fmt.Errorf("persist file token: %w", err)
	}
	return nil
}

// Check compares the file on disk with the stored hash and timestamps.
func (f *FileChecker) Check(token HoneyToken) (CheckResult, error) {
	res, err := checkDecoyFile(token)
	if err != nil {
		return CheckResult{}, fmt.Errorf("file check: %w", err)
	}
	return res, nil
}

func expandPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.HasPrefix(p, "~"+string(os.PathSeparator)) || p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("user home: %w", err)
		}
		if p == "~" {
			return home, nil
		}
		return filepath.Join(home, p[2:]), nil
	}
	return filepath.Clean(p), nil
}

// StatMtimeUnix returns modification time as unix seconds for a path.
func StatMtimeUnix(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	return st.ModTime().Unix(), nil
}
