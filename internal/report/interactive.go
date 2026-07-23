package report

import (
	"os"

	"github.com/mattn/go-isatty"
)

// Interactive reports whether stdout is an actual terminal a human is
// watching, as opposed to a pipe, file redirect, or non-interactive CI
// runner. Cosmetic-only output (the banner, live progress headers) must
// check this first — piped/scripted/--json consumers must always get the
// plain, stable format.
func Interactive() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}
