package honeytoken

import (
	"path/filepath"
	"strings"
)

func sanitizeFilePart(s string) string {
	s = filepath.Base(strings.TrimSpace(s))
	replacers := []string{"/", "\\", ":"}
	for _, ch := range replacers {
		s = strings.ReplaceAll(s, ch, "_")
	}
	return s
}
