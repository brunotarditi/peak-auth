package utils

import (
	"regexp"
	"strings"
)

func Slugify(s string) string {
	s = strings.ToLower(s)
	// Reemplaza todo lo que no sea letras o números por un guion
	var re = regexp.MustCompile(`[^a-z0-9]+`)
	s = re.ReplaceAllString(s, "-")
	// Quita guiones sobrantes al principio o al final
	return strings.Trim(s, "-")
}
