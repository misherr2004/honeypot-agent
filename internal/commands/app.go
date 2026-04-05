package commands

import (
	"github.com/misherr2004/honeypot-agent/internal/logger"
	"github.com/misherr2004/honeypot-agent/internal/store"
)

// App bundles dependencies for CLI commands (no package-level mutable state).
type App struct {
	Store store.Store
	Log   *logger.ActivationLogger
	Home  string
}

// NewApp constructs an App with the given dependencies.
func NewApp(s store.Store, log *logger.ActivationLogger, home string) *App {
	return &App{Store: s, Log: log, Home: home}
}
