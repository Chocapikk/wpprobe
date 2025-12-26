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

package scanner

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	bold           = lipgloss.NewStyle().Bold(true)
	urlStyle       = bold.Foreground(lipgloss.Color("#00FFFF"))
	titleStyle     = bold.Foreground(lipgloss.Color("#FFA500"))
	noVulnStyle    = bold.Foreground(lipgloss.Color("#00FF00"))
	noVersionStyle = bold.Foreground(lipgloss.Color("#808080"))
	criticalStyle  = bold.Foreground(lipgloss.Color("#FF0000"))
	highStyle      = bold.Foreground(lipgloss.Color("#FF4500"))
	mediumStyle    = bold.Foreground(lipgloss.Color("#FFA500"))
	lowStyle       = bold.Foreground(lipgloss.Color("#FFFF00"))

	separatorStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FFA500")).
			Padding(0, 2).
			Margin(1, 0)

	unauthStyle     = bold.Foreground(lipgloss.Color("#FF0000"))
	authStyle       = bold.Foreground(lipgloss.Color("#00FF00"))
	privilegedStyle = bold.Foreground(lipgloss.Color("#8A2BE2"))
	unknownStyle    = bold.Foreground(lipgloss.Color("#FFA500"))
)

// Exported styles for use in other packages.
var (
	TitleStyle     = titleStyle
	URLStyle       = urlStyle
	SeparatorStyle = separatorStyle
	CriticalStyle  = criticalStyle
	HighStyle      = highStyle
	MediumStyle    = mediumStyle
	LowStyle       = lowStyle
	UnknownStyle   = unknownStyle
	NoVulnStyle    = noVulnStyle
	NoVersionStyle = noVersionStyle

	UnauthStyle     = unauthStyle
	AuthStyle       = authStyle
	PrivilegedStyle = privilegedStyle
)

