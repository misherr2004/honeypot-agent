package commands

import (
	"github.com/misherr2004/honeypot-agent/internal/honeytoken"
	"github.com/misherr2004/honeypot-agent/internal/store"
)

func recordToToken(r store.Record) honeytoken.HoneyToken {
	return honeytoken.HoneyToken{
		ID:        r.ID,
		Name:      r.Name,
		Type:      r.Type,
		Path:      r.Path,
		Hash:      r.Hash,
		Mtime:     r.Mtime,
		Status:    r.Status,
		PlacedAt:  r.PlacedAt,
		CheckedAt: r.CheckedAt,
	}
}
