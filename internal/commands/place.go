package commands

import (
	"flag"
	"fmt"

	"github.com/misherr2004/honeypot-agent/internal/honeytoken"
)

// RunPlace parses flags and places a honeytoken via the appropriate checker.
func RunPlace(args []string, app *App) error {
	if app == nil || app.Store == nil {
		return fmt.Errorf("place: app or store is nil")
	}
	fs := flag.NewFlagSet("place", flag.ContinueOnError)
	var (
		tokenType = fs.String("type", "", "Type of token: file | credential")
		path      = fs.String("path", "", "File path (for type=file)")
		content   = fs.String("content", "", "File content (for type=file)")
		target    = fs.String("target", "", "credential target: registry | browser")
		name      = fs.String("name", "", "Credential name / username (registry)")
		password  = fs.String("password", "", "Credential password")
		url       = fs.String("url", "", "URL (for browser credential)")
		login     = fs.String("login", "", "Login (for browser credential)")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: agent place [flags]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse place flags: %w", err)
	}
	opts := honeytoken.PlaceOptions{
		Type:     *tokenType,
		Path:     *path,
		Content:  *content,
		Target:   *target,
		Name:     *name,
		Password: *password,
		URL:      *url,
		Login:    *login,
	}
	switch opts.Type {
	case "file":
		ch := &honeytoken.FileChecker{Store: app.Store}
		if err := validateFilePlace(opts); err != nil {
			return fmt.Errorf("place file: %w", err)
		}
		if err := ch.Place(opts); err != nil {
			return fmt.Errorf("place file token: %w", err)
		}
	case "credential":
		switch opts.Target {
		case "registry":
			ch := honeytoken.NewRegistryChecker(app.Store, app.Home)
			if err := validateRegistryPlace(opts); err != nil {
				return fmt.Errorf("place registry: %w", err)
			}
			if err := ch.Place(opts); err != nil {
				return fmt.Errorf("place registry token: %w", err)
			}
		case "browser":
			ch := honeytoken.NewBrowserChecker(app.Store, app.Home)
			if err := validateBrowserPlace(opts); err != nil {
				return fmt.Errorf("place browser: %w", err)
			}
			if err := ch.Place(opts); err != nil {
				return fmt.Errorf("place browser token: %w", err)
			}
		default:
			return fmt.Errorf("credential requires --target=registry or --target=browser")
		}
	default:
		return fmt.Errorf("place requires --type=file or --type=credential")
	}
	return nil
}

func validateFilePlace(o honeytoken.PlaceOptions) error {
	if o.Path == "" {
		return fmt.Errorf("--path is required for file tokens")
	}
	return nil
}

func validateRegistryPlace(o honeytoken.PlaceOptions) error {
	if o.Name == "" {
		return fmt.Errorf("--name is required for registry credentials")
	}
	if o.Password == "" {
		return fmt.Errorf("--password is required for registry credentials")
	}
	return nil
}

func validateBrowserPlace(o honeytoken.PlaceOptions) error {
	if o.URL == "" || o.Login == "" {
		return fmt.Errorf("--url and --login are required for browser credentials")
	}
	return nil
}
