// Package honeytoken defines honeytoken models, placement options, check results,
// and the HoneyChecker contract implemented per token kind.
package honeytoken

import "time"

// HoneyToken is a persisted honeytoken row used for monitoring.
type HoneyToken struct {
	// ID is the database primary key.
	ID int64
	// Name is a human-readable label (file basename, credential name, or url_login).
	Name string
	// Type is one of: file, registry, browser.
	Type string
	// Path is the filesystem path or a logical registry path (e.g. HKCU\... on Windows).
	Path string
	// Hash is the hex SHA-256 of decoy content at placement time.
	Hash string
	// Mtime is the Unix seconds of modification time recorded at placement.
	Mtime int64
	// Status is active (just placed), intact, or compromised after checks.
	Status string
	// PlacedAt is an RFC3339 UTC timestamp.
	PlacedAt string
	// CheckedAt is the last check time in RFC3339 UTC, if any.
	CheckedAt string
}

// PlaceOptions holds CLI flags for placing a honeytoken.
type PlaceOptions struct {
	Type     string // file | credential
	Path     string
	Content  string
	Target   string // registry | browser when Type=credential
	Name     string
	Password string
	URL      string
	Login    string
}

// CheckResult describes the outcome of a single check against a token.
type CheckResult struct {
	// Action is modified, deleted, accessed, or empty when nothing suspicious was found.
	Action string
	// Status is intact or compromised.
	Status string
}

// HoneyChecker places and checks one category of honeytoken.
type HoneyChecker interface {
	Place(opts PlaceOptions) error
	Check(token HoneyToken) (CheckResult, error)
}

// ContentHash returns the hex-encoded SHA-256 of content used at placement and check.
func ContentHash(content string) string {
	return hexSHA256(content)
}

// FormatPlacedAt returns the current time in RFC3339 UTC.
func FormatPlacedAt() string {
	return time.Now().UTC().Format(time.RFC3339)
}
