package util

import (
	"strings"
	"testing"
)

func TestSanitizeHexColor(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"#2563eb", "#2563eb"},
		{"2563EB", "#2563eb"},
		{"#FFF", "#ffffff"},
		{"#fff", "#ffffff"},
		{"#000", "#000000"},
		{"#10B981", "#10b981"},
		{"", ""},
		{"invalid", ""},
		{"#12", ""},
		{"#12345", ""},
		{"#1234567", ""},
		{"#2563eb; color: red", ""},
		{"javascript:alert(1)", ""},
	}

	for _, tt := range tests {
		got := SanitizeHexColor(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeHexColor(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestHexToRGB_And_Variations(t *testing.T) {
	rgb, err := HexToRGB("#2563eb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rgb.R != 0x25 || rgb.G != 0x63 || rgb.B != 0xeb {
		t.Errorf("expected R:0x25 G:0x63 B:0xeb, got: %+v", rgb)
	}

	darker := rgb.Darken(0.15)
	if darker.R >= rgb.R && darker.G >= rgb.G && darker.B >= rgb.B {
		t.Errorf("Darken did not reduce color values: %s vs %s", darker.Hex(), rgb.Hex())
	}

	lighter := rgb.Lighten(0.20)
	if lighter.R <= rgb.R || lighter.G <= rgb.G || lighter.B <= rgb.B {
		t.Errorf("Lighten did not increase color values: %s vs %s", lighter.Hex(), rgb.Hex())
	}
}

func TestRGB_ContrastTextColor(t *testing.T) {
	whiteRGB, _ := HexToRGB("#ffffff")
	if whiteRGB.ContrastTextColor() != "#0f172a" {
		t.Errorf("expected dark text for white background, got: %s", whiteRGB.ContrastTextColor())
	}

	darkBlue, _ := HexToRGB("#1e3a8a")
	if darkBlue.ContrastTextColor() != "#ffffff" {
		t.Errorf("expected white text for dark blue background, got: %s", darkBlue.ContrastTextColor())
	}
}

func TestGenerateThemeCSS(t *testing.T) {
	t.Run("Empty input produces empty CSS", func(t *testing.T) {
		css := GenerateThemeCSS("")
		if css != "" {
			t.Errorf("expected empty string, got: %s", css)
		}
	})

	t.Run("Invalid hex produces empty CSS without injection", func(t *testing.T) {
		css := GenerateThemeCSS("#2563eb; } body { background: red; }")
		if css != "" {
			t.Errorf("expected empty string for malicious input, got: %s", css)
		}
	})

	t.Run("Valid hex produces CSS variables block", func(t *testing.T) {
		css := string(GenerateThemeCSS("#2563eb"))
		if !strings.Contains(css, ":root {") {
			t.Errorf("expected :root block in css: %s", css)
		}
		if !strings.Contains(css, "--brand-500: #2563eb;") {
			t.Errorf("expected --brand-500 in css: %s", css)
		}
		if !strings.Contains(css, "--brand-600:") {
			t.Errorf("expected --brand-600 in css: %s", css)
		}
		if !strings.Contains(css, "--brand-contrast-text:") {
			t.Errorf("expected --brand-contrast-text in css: %s", css)
		}
	})
}
