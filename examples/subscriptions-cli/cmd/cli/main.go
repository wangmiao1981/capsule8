package main

import (
	"os"

	"github.com/capsule8/capsule8/examples/subscriptions-cli/pkg/cli"
)

func main() {
	rootCommand := cli.NewRootCommand(os.Stdout, os.Stderr)
	if err := rootCommand.Execute(); err != nil {
		os.Exit(-1)
	}
}
