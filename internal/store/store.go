// Package store defines persistence for honeytokens and a SQLite implementation.
package store

// Record is a single honeytoken row matching the SQLite schema.
type Record struct {
	ID        int64
	Name      string
	Type      string
	Path      string
	Hash      string
	Mtime     int64
	Status    string
	PlacedAt  string
	CheckedAt string // empty when never checked (stored as NULL in SQLite)
}

// Store abstracts honeytoken persistence for testing and swapping backends.
type Store interface {
	// Close releases underlying resources.
	Close() error
	// Insert persists a new row and returns its generated id.
	Insert(rec Record) (int64, error)
	// List returns all rows ordered by id.
	List() ([]Record, error)
	// UpdateAfterCheck sets status and checked_at after a monitoring pass.
	UpdateAfterCheck(id int64, status, checkedAt string) error
}
