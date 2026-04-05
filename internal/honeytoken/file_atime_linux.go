//go:build linux

package honeytoken

import (
	"fmt"
	"syscall"
	"time"
)

func fileAccessAfterMod(path string, mod time.Time) (bool, error) {
	_ = mod
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false, fmt.Errorf("stat for atime/mtime: %w", err)
	}
	at := time.Unix(st.Atim.Sec, st.Atim.Nsec)
	mt := time.Unix(st.Mtim.Sec, st.Mtim.Nsec)
	return at.After(mt), nil
}
