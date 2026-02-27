package utils

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func Slugify(s string) string {
	// 1. Normalizar para separar tildes de letras (e.g., 'í' -> 'i' + '´')
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	result, _, _ := transform.String(t, s)

	// 2. A minúsculas y limpiar caracteres no deseados
	result = strings.ToLower(result)
	var re = regexp.MustCompile(`[^a-z0-9]+`)
	result = re.ReplaceAllString(result, "-")

	return strings.Trim(result, "-")
}
