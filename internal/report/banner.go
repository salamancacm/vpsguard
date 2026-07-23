package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
)

// PrintBanner prints a small boxed wordmark. Callers must gate this behind
// Interactive() — it must never appear in piped, scripted, or --json output.
func PrintBanner(w io.Writer, version string) {
	title := "vpsguard " + version
	tagline := "audit · harden · monitor — Linux VPS security"

	width := len([]rune(title))
	if tw := len([]rune(tagline)); tw > width {
		width = tw
	}
	width += 4 // horizontal padding inside the box

	border := color.CyanString(strings.Repeat("═", width))
	titleStyle := color.New(color.FgCyan, color.Bold).SprintFunc()

	fmt.Fprintln(w, color.CyanString("╔")+border+color.CyanString("╗"))
	fmt.Fprintln(w, boxLine(width, title, titleStyle(title)))
	fmt.Fprintln(w, boxLine(width, tagline, color.HiBlackString(tagline)))
	fmt.Fprintln(w, color.CyanString("╚")+border+color.CyanString("╝"))
	fmt.Fprintln(w)
}

// boxLine centers plainText (used only to compute padding width, since
// ANSI color codes in styledText would otherwise throw off the rune count)
// inside a box of the given width, rendering styledText instead.
func boxLine(width int, plainText, styledText string) string {
	pad := width - len([]rune(plainText))
	left := pad / 2
	right := pad - left
	return color.CyanString("║") + strings.Repeat(" ", left) + styledText + strings.Repeat(" ", right) + color.CyanString("║")
}
