// Command safeclaw runs Claude Code sessions in isolated Docker containers.
package main

import (
	"os"

	"github.com/josegonzalez/safeclaw/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
