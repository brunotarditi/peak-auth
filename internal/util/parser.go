package util

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseJSONMap deserializa un string JSON a map[string]interface{}.
// Retorna nil si la cadena está vacía o si ocurre un error de deserialización.
func ParseJSONMap(str string) map[string]interface{} {
	if strings.TrimSpace(str) == "" {
		return nil
	}
	var res map[string]interface{}
	if err := json.Unmarshal([]byte(str), &res); err != nil {
		return nil
	}
	return res
}

// ParseUint convierte de manera flexible diferentes tipos (float64, int, int64, string) a uint.
// Retorna 0 si el valor es nil o si la conversión no es posible.
func ParseUint(val interface{}) uint {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case uint:
		return v
	case uint64:
		return uint(v)
	case float64:
		if v < 0 {
			return 0
		}
		return uint(v)
	case int:
		if v < 0 {
			return 0
		}
		return uint(v)
	case int64:
		if v < 0 {
			return 0
		}
		return uint(v)
	case string:
		u, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0
		}
		return uint(u)
	default:
		return 0
	}
}

// ParseAccessExpiration calcula la fecha de expiración basada en un preset ("24h", "7d", "30d", "90d")
// o en una fecha personalizada en formatos comunes (datetime-local, RFC3339, YYYY-MM-DD).
// Retorna nil si no se definió temporalidad (acceso permanente).
func ParseAccessExpiration(preset, customDateStr string) (*time.Time, error) {
	preset = strings.TrimSpace(strings.ToLower(preset))
	now := time.Now()

	switch preset {
	case "24h", "1d":
		t := now.Add(24 * time.Hour)
		return &t, nil
	case "7d", "1w":
		t := now.Add(7 * 24 * time.Hour)
		return &t, nil
	case "30d", "1m":
		t := now.Add(30 * 24 * time.Hour)
		return &t, nil
	case "90d", "3m":
		t := now.Add(90 * 24 * time.Hour)
		return &t, nil
	}

	customDateStr = strings.TrimSpace(customDateStr)
	if customDateStr == "" {
		return nil, nil
	}

	layouts := []string{
		"2006-01-02T15:04",
		"2006-01-02T15:04:05",
		time.RFC3339,
		"2006-01-02",
	}

	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, customDateStr, time.Local); err == nil {
			if layout == "2006-01-02" {
				t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			}
			return &t, nil
		}
	}

	return nil, fmt.Errorf("formato de fecha de expiración inválido: %s", customDateStr)
}

