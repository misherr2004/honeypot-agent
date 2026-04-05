package commands

import (
	"fmt"
	"os"
)

// Run dispatches argv[1] to place, check, or list.
func Run(argv []string, app *App) error {
	if len(argv) < 2 {
		fmt.Fprintf(os.Stderr, "usage: agent <place|check|list> [flags]\n")
		return fmt.Errorf("missing command")
	}
	cmd := argv[1]
	args := argv[2:]
	switch cmd {
	case "place":
		return RunPlace(args, app)
	case "check":
		return RunCheck(args, app)
	case "list":
		return RunList(args, app)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}
