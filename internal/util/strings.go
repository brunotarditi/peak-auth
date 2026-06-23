package util

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Slugify convierte un string en un slug (ej: "Mi Aplicación" -> "mi-aplicacion")
func Slugify(s string) string {
	if s == "" {
		return ""
	}
	// 1. Normalizar para separar tildes de letras (e.g., 'í' -> 'i' + '´')
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	result, _, _ := transform.String(t, s)

	// A minúsculas
	result = strings.ToLower(result)

	// Reemplazar todo lo que no sea letra o número por guion
	var re = regexp.MustCompile(`[^a-z0-9]+`)
	result = re.ReplaceAllString(result, "-")

	// Quitar guiones consecutivos
	result = regexp.MustCompile(`-+`).ReplaceAllString(result, "-")

	// Quitar guiones del principio y final
	result = strings.Trim(result, "-")

	return result

}

// IsValidSlug valida que sea un slug razonable
func IsValidSlug(s string) bool {
	if len(s) < 2 || len(s) > 80 {
		return false
	}
	// Solo permite letras, números y guiones
	matched, _ := regexp.MatchString(`^[a-z0-9]+(?:-[a-z0-9]+)*$`, s)
	return matched
}
