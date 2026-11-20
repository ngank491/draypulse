// DrayPulse – lightweight MikroTik monitoring in a single binary.
package main

import (
	"fmt"
	"os"
	_ "time/tzdata" // timezone data embedded for Windows / scratch containers

	"draypulse/internal/app"
)

func main() {
	if err := app.Main(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "draypulse:", err)
		os.Exit(1)
	}
}
