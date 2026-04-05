package commands

import (
	"flag"
	"fmt"
	"strings"
)

// RunList prints all honeytokens as a fixed-width table.
func RunList(args []string, app *App) error {
	if app == nil || app.Store == nil {
		return fmt.Errorf("list: app or store is nil")
	}
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse list flags: %w", err)
	}
	rows, err := app.Store.List()
	if err != nil {
		return fmt.Errorf("list tokens: %w", err)
	}
	home := ""
	if app != nil {
		home = app.Home
	}
	fmt.Printf("%-4s %-16s %-10s %-36s %-12s %-22s %-22s\n",
		"ID", "NAME", "TYPE", "PATH", "STATUS", "PLACED AT", "CHECKED AT")
	for _, r := range rows {
		pathDisp := displayPath(r.Path, home)
		checked := r.CheckedAt
		if checked == "" {
			checked = "-"
		}
		fmt.Printf("%-4d %-16s %-10s %-36s %-12s %-22s %-22s\n",
			r.ID,
			truncateRunes(r.Name, 16),
			r.Type,
			truncateRunes(pathDisp, 36),
			r.Status,
			r.PlacedAt,
			checked,
		)
	}
	return nil
}

func displayPath(p, home string) string {
	if home != "" && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
