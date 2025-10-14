package common

import "github.com/fatih/color"

type ColorType string

const (
	ColorRed    ColorType = "red"
	ColorGreen  ColorType = "green"
	ColorYellow ColorType = "yellow"
)

func Colors(colorType ColorType) *color.Color {
	switch colorType {
	case ColorRed:
		return color.New(color.FgRed)
	case ColorGreen:
		return color.New(color.FgGreen)
	case ColorYellow:
		return color.New(color.FgYellow)
	default:
		return color.New()
	}
}
