package util

import (
	"encoding/json"
	"strconv"
	"strings"
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
