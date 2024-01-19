package main

import (
	"os"

	"github.com/kondukto-io/kntrl/cmd/cli"
)

func main() {
	cli.Execute(os.Args[1:])
}
