package commands

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/misherr2004/honeypot-agent/internal/logger"
	"github.com/misherr2004/honeypot-agent/internal/store"
)

// Main opens storage and logging, handles SIGINT/SIGTERM, and runs the CLI.
func Main(argv []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("user home dir: %w", err)
	}
	dbPath := filepath.Join(home, ".honeypot", "honeypot.db")
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	log, err := logger.NewActivationLogger(home)
	if err != nil {
		_ = st.Close()
		return fmt.Errorf("activation logger: %w", err)
	}
	app := NewApp(st, log, home)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = st.Close()
		_ = log.Close()
		os.Exit(0)
	}()
	runErr := Run(argv, app)
	_ = st.Close()
	_ = log.Close()
	return runErr
}
