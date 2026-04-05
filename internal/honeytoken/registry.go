package honeytoken

import (
	"github.com/misherr2004/honeypot-agent/internal/store"
)

// RegistryChecker places a credential-shaped decoy in the registry (Windows) or as a marker file (!windows).
type RegistryChecker struct {
	Store store.Store
	Home  string
}

// NewRegistryChecker returns a RegistryChecker rooted at the given home directory (e.g. os.UserHomeDir).
func NewRegistryChecker(s store.Store, home string) *RegistryChecker {
	return &RegistryChecker{Store: s, Home: home}
}

// Place creates the registry decoy and persists metadata.
func (r *RegistryChecker) Place(opts PlaceOptions) error {
	return r.placeRegistry(opts)
}

// Check verifies the registry decoy using the same heuristics as file tokens where applicable.
func (r *RegistryChecker) Check(token HoneyToken) (CheckResult, error) {
	return r.checkRegistry(token)
}
