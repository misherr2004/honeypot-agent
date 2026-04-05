//go:build !darwin && !linux && !windows

package honeytoken

import "time"

func fileAccessAfterMod(path string, mod time.Time) (bool, error) {
	_ = path
	_ = mod
	return false, nil
}
