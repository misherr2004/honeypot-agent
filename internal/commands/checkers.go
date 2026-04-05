package commands

import (
	"fmt"

	"github.com/misherr2004/honeypot-agent/internal/honeytoken"
	"github.com/misherr2004/honeypot-agent/internal/store"
)

func checkerFor(typ string, s store.Store, home string) (honeytoken.HoneyChecker, error) {
	switch typ {
	case "file":
		return &honeytoken.FileChecker{Store: s}, nil
	case "registry":
		return honeytoken.NewRegistryChecker(s, home), nil
	case "browser":
		return honeytoken.NewBrowserChecker(s, home), nil
	default:
		return nil, fmt.Errorf("unknown stored token type %q", typ)
	}
}
