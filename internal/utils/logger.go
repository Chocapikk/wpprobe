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

package utils

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00AEEF"))
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5733"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#33CC33"))
	timeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
)

type Logger struct {
	logger *log.Logger
}

func NewLogger() *Logger {
	return &Logger{
		logger: log.New(os.Stdout, "", 0),
	}
}

func formatTime() string {
	return timeStyle.Render(time.Now().Format("15:04:05"))
}

func (l *Logger) Info(msg string) {
	l.logger.Println(formatTime() + " [" + infoStyle.Render("INFO") + "] " + msg)
}

func (l *Logger) Warning(msg string) {
	l.logger.Println(formatTime() + " [" + warningStyle.Render("WARNING") + "] " + msg)
}

func (l *Logger) Error(msg string) {
	l.logger.Println(formatTime() + " [" + errorStyle.Render("ERROR") + "] " + msg)
}

func (l *Logger) Success(msg string) {
	l.logger.Println(formatTime() + " [" + successStyle.Render("SUCCESS") + "] " + msg)
}

func (l *Logger) PrintBanner(version string, isLatest bool) {
	latestStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#33CC33"))
	outdatedStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5733"))
	versionStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00AEEF"))
	textStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#AAAAAA"))

	status := outdatedStyle.Render("outdated")
	if isLatest {
		status = latestStyle.Render("latest")
	}

	logo := `
 __    __  ___  ___           _          
/ / /\ \ \/ _ \/ _ \_ __ ___ | |__   ___ 
\ \/  \/ / /_)/ /_)/ '__/ _ \| '_ \ / _ \
 \  /\  / ___/ ___/| | | (_) | |_) |  __/
  \/  \/\/   \/    |_|  \___/|_.__/ \___|`

	versionText := versionStyle.Render(version)
	statusText := "[" + status + "]"

	logoLines := lipgloss.NewStyle().Render(logo)
	versionLine := lipgloss.Place(
		50,
		1,
		lipgloss.Right,
		lipgloss.Bottom,
		versionText+" "+statusText,
	)

	fmt.Println(logoLines + "\n" + versionLine + "\n")
	fmt.Println(textStyle.Render("Stealthy WordPress Plugin Scanner - By @Chocapikk\n"))

	if !isLatest {
		l.Warning("Your current WPProbe version is outdated. Latest version available.")
		l.Warning("Update with: wpprobe update")
	}
}
