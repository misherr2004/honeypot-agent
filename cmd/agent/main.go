package main

import (
	"fmt"
	"os"

	"github.com/misherr2004/honeypot-agent/internal/commands"
)

func main() {
	if err := commands.Main(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
