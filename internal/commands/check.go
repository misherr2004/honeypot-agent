package commands

import (
	"flag"
	"fmt"

	"github.com/misherr2004/honeypot-agent/internal/logger"
	"github.com/misherr2004/honeypot-agent/internal/store"
)

// RunCheck evaluates every stored honeytoken and updates the database.
func RunCheck(args []string, app *App) error {
	if app == nil || app.Store == nil {
		return fmt.Errorf("check: app or store is nil")
	}
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse check flags: %w", err)
	}
	rows, err := app.Store.List()
	if err != nil {
		return fmt.Errorf("list tokens for check: %w", err)
	}
	for _, row := range rows {
		ch, err := checkerFor(row.Type, app.Store, app.Home)
		if err != nil {
			return fmt.Errorf("checker for %s: %w", row.Type, err)
		}
		res, err := ch.Check(recordToToken(row))
		if err != nil {
			return fmt.Errorf("check token id=%d: %w", row.ID, err)
		}
		status := res.Status
		if status == "" {
			status = "intact"
		}
		checkedAt := store.NowRFC3339()
		if err := app.Store.UpdateAfterCheck(row.ID, status, checkedAt); err != nil {
			return fmt.Errorf("update token id=%d after check: %w", row.ID, err)
		}
		if res.Status == "compromised" && res.Action != "" && app.Log != nil {
			entry := logger.ActivationEntry{
				Timestamp: checkedAt,
				Type:      row.Type,
				Name:      row.Name,
				Action:    res.Action,
				Status:    res.Status,
			}
			if err := app.Log.Log(entry); err != nil {
				return fmt.Errorf("log activation for token id=%d: %w", row.ID, err)
			}
		}
	}
	return nil
}
