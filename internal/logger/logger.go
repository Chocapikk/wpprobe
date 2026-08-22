// Copyright (c) 2025 Valentin Lobstein (Chocapikk) <balgogan@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	ansiReset   = "\033[0m"
	ansiInfo    = "\033[38;5;39m"
	ansiWarning = "\033[38;5;220m"
	ansiError   = "\033[38;5;196m"
	ansiSuccess = "\033[32m"
	ansiGray    = "\033[38;5;245m"
	ansiBold    = "\033[1m"
	ansiCyan    = "\033[36m"
)

var DefaultLogger = NewLogger()

func colorize(color, text string) string {
	return color + text + ansiReset
}

type Logger struct {
	Logger  *log.Logger
	Verbose bool
}

func NewLogger() *Logger {
	return &Logger{
		Logger:  log.New(os.Stdout, "", 0),
		Verbose: true, // Default to verbose for CLI
	}
}

func NewLoggerWithVerbose(verbose bool) *Logger {
	return &Logger{
		Logger:  log.New(os.Stdout, "", 0),
		Verbose: verbose,
	}
}

func formatTime() string {
	return colorize(ansiGray, time.Now().Format("15:04:05"))
}

func (l *Logger) Info(msg string) {
	if !l.Verbose {
		return
	}
	l.Logger.Println(formatTime() + " [" + colorize(ansiInfo, "INFO") + "] " + msg)
}

func (l *Logger) Warning(msg string) {
	if !l.Verbose {
		return
	}
	l.Logger.Println(formatTime() + " [" + colorize(ansiWarning, "WARNING") + "] " + msg)
}

func (l *Logger) Error(msg string) {
	// Errors are always shown, even when not verbose
	l.Logger.Println(formatTime() + " [" + colorize(ansiError, "ERROR") + "] " + msg)
}

func (l *Logger) Success(msg string) {
	if !l.Verbose {
		return
	}
	l.Logger.Println(FormatSuccess(msg))
}

// FormatSuccess returns a formatted success message string without printing it.
func FormatSuccess(msg string) string {
	return formatTime() + " [" + colorize(ansiSuccess, "SUCCESS") + "] " + msg
}

// FormatInfo returns a formatted info message without printing it, allowing
// callers to route the line cleanly above an active progress bar.
func FormatInfo(msg string) string {
	return formatTime() + " [" + colorize(ansiInfo, "INFO") + "] " + msg
}

// FormatWarning returns a formatted warning message string without printing it,
// so callers can route it through an active progress bar (which otherwise eats a
// plain logger write) instead of the logger.
func FormatWarning(msg string) string {
	return formatTime() + " [" + colorize(ansiWarning, "WARNING") + "] " + msg
}

// BuildStatus is how a build compares to the published releases.
type BuildStatus int

const (
	// BuildLatest is a build at or ahead of the newest published release.
	BuildLatest BuildStatus = iota
	// BuildOutdated is a build behind the newest published release.
	BuildOutdated
	// BuildUnreleased is a build carrying no version to compare, so claiming it
	// is either current or outdated would be a guess.
	BuildUnreleased
	// BuildUnknown is a build whose version is comparable but whose release
	// lookup did not produce an answer, typically offline. Reporting it as
	// outdated would turn a failed check into a false claim.
	BuildUnknown
)

func (l *Logger) PrintBanner(version string, buildStatus BuildStatus) {
	var status string
	switch buildStatus {
	case BuildLatest:
		status = colorize(ansiSuccess+ansiBold, "latest")
	case BuildUnreleased:
		status = colorize(ansiWarning+ansiBold, "unreleased")
	case BuildUnknown:
		status = colorize(ansiGray+ansiBold, "unknown")
	default:
		status = colorize(ansiError+ansiBold, "outdated")
	}

	logo := `
 __    __  ___  ___           _
/ / /\ \ \/ _ \/ _ \_ __ ___ | |__   ___
\ \/  \/ / /_)/ /_)/ '__/ _ \| '_ \ / _ \
 \  /\  / ___/ ___/| | | (_) | |_) |  __/
  \/  \/\/   \/    |_|  \___/|_.__/ \___|`

	versionText := colorize(ansiCyan+ansiBold, version)
	statusText := "[" + status + "]"

	versionLine := versionText + " " + statusText
	// Right-pad to ~50 chars
	pad := 50 - len(version) - 3 // rough estimate
	if pad > 0 {
		versionLine = strings.Repeat(" ", pad) + versionLine
	}

	fmt.Println(logo + "\n" + versionLine + "\n")
	fmt.Println(colorize(ansiGray+ansiBold, "Stealthy WordPress Plugin Scanner - By @Chocapikk\n"))
}
