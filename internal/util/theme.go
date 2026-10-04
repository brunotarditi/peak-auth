package util

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var hexColorRegex = regexp.MustCompile(`^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// SanitizeHexColor valida y normaliza un color hexadecimal a formato "#rrggbb".
// Si el formato es inválido o contiene caracteres peligrosos, devuelve cadena vacía.
func SanitizeHexColor(hex string) string {
	hex = strings.TrimSpace(hex)
	if !hexColorRegex.MatchString(hex) {
		return ""
	}
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) == 3 {
		hex = string([]byte{hex[0], hex[0], hex[1], hex[1], hex[2], hex[2]})
	}
	return "#" + strings.ToLower(hex)
}

// RGB representa los componentes rojo, verde y azul en el rango [0, 255].
type RGB struct {
	R, G, B uint8
}

// HexToRGB convierte un código hex sanitizado en valores RGB.
func HexToRGB(hex string) (RGB, error) {
	clean := SanitizeHexColor(hex)
	if clean == "" {
		return RGB{}, fmt.Errorf("código hexadecimal inválido: %s", hex)
	}
	val, err := strconv.ParseUint(clean[1:], 16, 32)
	if err != nil {
		return RGB{}, err
	}
	return RGB{
		R: uint8((val >> 16) & 0xFF),
		G: uint8((val >> 8) & 0xFF),
		B: uint8(val & 0xFF),
	}, nil
}

// RGBToHex convierte una estructura RGB en formato "#rrggbb".
func (c RGB) Hex() string {
	return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B)
}

// Darken ajusta el brillo hacia negro en un porcentaje (0.0 a 1.0).
func (c RGB) Darken(factor float64) RGB {
	f := math.Max(0, math.Min(1, 1.0-factor))
	return RGB{
		R: uint8(float64(c.R) * f),
		G: uint8(float64(c.G) * f),
		B: uint8(float64(c.B) * f),
	}
}

// Lighten ajusta el brillo hacia blanco en un porcentaje (0.0 a 1.0).
func (c RGB) Lighten(factor float64) RGB {
	f := math.Max(0, math.Min(1, factor))
	return RGB{
		R: uint8(float64(c.R) + float64(255-c.R)*f),
		G: uint8(float64(c.G) + float64(255-c.G)*f),
		B: uint8(float64(c.B) + float64(255-c.B)*f),
	}
}

// Luminance calcula la luminancia relativa según fórmula WCAG 2.1.
func (c RGB) Luminance() float64 {
	convert := func(channel uint8) float64 {
		v := float64(channel) / 255.0
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*convert(c.R) + 0.7152*convert(c.G) + 0.0722*convert(c.B)
}

// ContrastTextColor determina si el texto sobre este color de fondo debe ser blanco o negro para legibilidad óptima.
func (c RGB) ContrastTextColor() string {
	// Luminance > 0.45 requiere texto oscuro para buen contraste
	if c.Luminance() > 0.45 {
		return "#0f172a"
	}
	return "#ffffff"
}

// ThemeColors contiene las tonalidades y contrastes calculados a partir de un color primario.
type ThemeColors struct {
	Brand50      string
	Brand400     string
	Brand500     string
	Brand600     string
	Brand700     string
	ContrastText string
}

// ResolveThemeColors calcula y valida la paleta de colores para un color hexadecimal primario.
// Si el color es inválido o vacío, devuelve nil para mantener los estilos predeterminados de forma segura.
func ResolveThemeColors(primaryColor string) *ThemeColors {
	clean := SanitizeHexColor(primaryColor)
	if clean == "" {
		return nil
	}

	rgb, err := HexToRGB(clean)
	if err != nil {
		return nil
	}

	return &ThemeColors{
		Brand50:      rgb.Lighten(0.92).Hex(),
		Brand400:     rgb.Lighten(0.18).Hex(),
		Brand500:     rgb.Hex(),
		Brand600:     rgb.Darken(0.12).Hex(),
		Brand700:     rgb.Darken(0.24).Hex(),
		ContrastText: rgb.ContrastTextColor(),
	}
}
