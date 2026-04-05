//go:build windows

package honeytoken

import (
	"fmt"
	"syscall"
	"time"
)

func fileAccessAfterMod(path string, mod time.Time) (bool, error) {
	_ = mod
	namep, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("utf16 path: %w", err)
	}
	h, err := syscall.CreateFile(namep, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return false, fmt.Errorf("open file: %w", err)
	}
	defer syscall.CloseHandle(h)
	var ctime, atime, mtime syscall.Filetime
	if err := syscall.GetFileTime(h, &ctime, &atime, &mtime); err != nil {
		return false, fmt.Errorf("get file time: %w", err)
	}
	at := filetimeToTime(atime)
	mt := filetimeToTime(mtime)
	return at.After(mt), nil
}

func filetimeToTime(ft syscall.Filetime) time.Time {
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	nsec -= 116444736000000000
	if nsec < 0 {
		nsec = 0
	}
	return time.Unix(0, nsec*100)
}
