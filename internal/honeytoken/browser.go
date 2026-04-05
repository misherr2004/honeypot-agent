package honeytoken

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/misherr2004/honeypot-agent/internal/store"
)

const defaultBrowserPassword = "honeypot-fake-secret"

// BrowserChecker places a JSON file that mimics saved browser credentials.
type BrowserChecker struct {
	Store store.Store
	Home  string
}

// NewBrowserChecker returns a BrowserChecker rooted at the given home directory.
func NewBrowserChecker(s store.Store, home string) *BrowserChecker {
	return &BrowserChecker{Store: s, Home: home}
}

type browserCredentialJSON struct {
	URL      string `json:"url"`
	Login    string `json:"login"`
	Password string `json:"password"`
	Created  string `json:"created"`
}

// Place writes the decoy JSON credential file and persists metadata.
func (b *BrowserChecker) Place(opts PlaceOptions) error {
	if b.Store == nil {
		return fmt.Errorf("browser checker: store is nil")
	}
	url := strings.TrimSpace(opts.URL)
	login := strings.TrimSpace(opts.Login)
	if url == "" || login == "" {
		return fmt.Errorf("browser token: url and login are required")
	}
	pw := strings.TrimSpace(opts.Password)
	if pw == "" {
		pw = defaultBrowserPassword
	}
	created := time.Now().UTC().Format(time.RFC3339)
	payload := browserCredentialJSON{
		URL:      url,
		Login:    login,
		Password: pw,
		Created:  created,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal browser credential json: %w", err)
	}
	content := string(raw)
	dir := filepath.Join(b.Home, ".honeypot", "browser")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create browser decoy dir: %w", err)
	}
	fname := sanitizeBrowserFileName(url, login) + ".json"
	path := filepath.Join(dir, fname)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write browser decoy file: %w", err)
	}
	mtime, err := StatMtimeUnix(path)
	if err != nil {
		return fmt.Errorf("browser decoy mtime: %w", err)
	}
	name := fmt.Sprintf("%s_%s", url, login)
	rec := store.Record{
		Name:     name,
		Type:     "browser",
		Path:     path,
		Hash:     ContentHash(content),
		Mtime:    mtime,
		Status:   "active",
		PlacedAt: FormatPlacedAt(),
	}
	if _, err := b.Store.Insert(rec); err != nil {
		return fmt.Errorf("persist browser token: %w", err)
	}
	return nil
}

// Check verifies the browser decoy file using file-token heuristics.
func (b *BrowserChecker) Check(token HoneyToken) (CheckResult, error) {
	res, err := checkDecoyFile(token)
	if err != nil {
		return CheckResult{}, fmt.Errorf("browser file check: %w", err)
	}
	return res, nil
}

func sanitizeBrowserFileName(url, login string) string {
	base := url + "_" + login
	var b strings.Builder
	for _, r := range base {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	s := b.String()
	if s == "" {
		return "credential"
	}
	return s
}
