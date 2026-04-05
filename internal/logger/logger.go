// Package logger writes JSON-lines activation events for honeytoken alerts.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ActivationEntry is one JSON line written when a token is potentially compromised.
type ActivationEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

// ActivationLogger appends activation records as newline-delimited JSON.
type ActivationLogger struct {
	file *os.File
}

// NewActivationLogger opens the primary log path under /var/log/honeypot when writable,
// otherwise ~/.honeypot/activations.log under home.
func NewActivationLogger(home string) (*ActivationLogger, error) {
	path, err := resolveActivationLogPath(home)
	if err != nil {
		return nil, fmt.Errorf("resolve activation log path: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open activation log: %w", err)
	}
	return &ActivationLogger{file: f}, nil
}

// Log writes one JSON object terminated by a newline.
func (l *ActivationLogger) Log(entry ActivationEntry) error {
	if l == nil || l.file == nil {
		return fmt.Errorf("activation logger: not initialized")
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal activation entry: %w", err)
	}
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write activation log: %w", err)
	}
	return nil
}

// Close releases the log file handle.
func (l *ActivationLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close activation log: %w", err)
	}
	l.file = nil
	return nil
}

func resolveActivationLogPath(home string) (string, error) {
	primary := "/var/log/honeypot/activations.log"
	if runtime.GOOS != "windows" {
		if p, ok := tryLogPath(primary); ok {
			return p, nil
		}
	}
	fallback := filepath.Join(home, ".honeypot", "activations.log")
	if p, ok := tryLogPath(fallback); ok {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("could not create a writable activation log (tried %s)", fallback)
	}
	return "", fmt.Errorf("could not create a writable activation log (tried %s and %s)", primary, fallback)
}

func tryLogPath(path string) (string, bool) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", false
	}
	_ = f.Close()
	return path, true
}
