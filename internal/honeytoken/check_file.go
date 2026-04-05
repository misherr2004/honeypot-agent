package honeytoken

import (
	"fmt"
	"os"
)

// checkDecoyFile applies file-token rules: missing, modified (hash), accessed (atime vs mtime), or intact.
func checkDecoyFile(token HoneyToken) (CheckResult, error) {
    path := token.Path
    st, err := os.Stat(path)
    if err != nil {
        if os.IsNotExist(err) {
            return CheckResult{Action: "deleted", Status: "compromised"}, nil
        }
        return CheckResult{}, fmt.Errorf("stat decoy file: %w", err)
    }

    accessed, err := fileAccessAfterMod(path, st.ModTime())
    if err != nil {
        return CheckResult{}, fmt.Errorf("compare access time: %w", err)
    }
    body, err := os.ReadFile(path)
    if err != nil {
        return CheckResult{}, fmt.Errorf("read decoy file: %w", err)
    }
    curHash := ContentHash(string(body))
    if curHash != token.Hash {
        return CheckResult{Action: "modified", Status: "compromised"}, nil
    }
    if accessed {
        return CheckResult{Action: "accessed", Status: "compromised"}, nil
    }
    return CheckResult{Status: "intact"}, nil
}