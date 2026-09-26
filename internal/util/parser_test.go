package util

import (
	"reflect"
	"testing"
)

func TestParseJSONMap(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]interface{}
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "whitespace only",
			input:    "   \n\t  ",
			expected: nil,
		},
		{
			name:     "invalid json",
			input:    "{invalid_json}",
			expected: nil,
		},
		{
			name:     "valid json object",
			input:    `{"user_id": 42, "role": "ADMIN"}`,
			expected: map[string]interface{}{"user_id": float64(42), "role": "ADMIN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseJSONMap(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseJSONMap(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseUint(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected uint
	}{
		{name: "nil input", input: nil, expected: 0},
		{name: "uint input", input: uint(12), expected: 12},
		{name: "uint64 input", input: uint64(99), expected: 99},
		{name: "float64 positive", input: float64(42), expected: 42},
		{name: "float64 negative", input: float64(-5), expected: 0},
		{name: "int positive", input: int(10), expected: 10},
		{name: "int negative", input: int(-1), expected: 0},
		{name: "int64 positive", input: int64(100), expected: 100},
		{name: "int64 negative", input: int64(-50), expected: 0},
		{name: "string valid", input: "123", expected: 123},
		{name: "string invalid", input: "not-a-number", expected: 0},
		{name: "unsupported type", input: []string{"a"}, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUint(tt.input)
			if got != tt.expected {
				t.Errorf("ParseUint(%v) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}
