package util

import (
	"html/template"
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

func TestResolveThemeColors(t *testing.T) {
	t.Run("Empty input produces nil", func(t *testing.T) {
		colors := ResolveThemeColors("")
		if colors != nil {
			t.Errorf("expected nil for empty input, got: %+v", colors)
		}
	})

	t.Run("Invalid hex produces nil without injection", func(t *testing.T) {
		colors := ResolveThemeColors("#2563eb; } body { background: red; }")
		if colors != nil {
			t.Errorf("expected nil for malicious input, got: %+v", colors)
		}
	})

	t.Run("Valid hex produces resolved theme colors", func(t *testing.T) {
		colors := ResolveThemeColors("#2563eb")
		if colors == nil {
			t.Fatal("expected colors not to be nil")
		}
		if colors.Brand500 != "#2563eb" {
			t.Errorf("expected Brand500 #2563eb, got: %s", colors.Brand500)
		}
		if !strings.HasPrefix(colors.Brand600, "#") {
			t.Errorf("expected Brand600 to be hex, got: %s", colors.Brand600)
		}
		if colors.ContrastText == "" {
			t.Errorf("expected non-empty ContrastText")
		}
	})
}

func TestThemeColorsTemplateRendering(t *testing.T) {
	colors := ResolveThemeColors("#2563eb")
	if colors == nil {
		t.Fatal("expected colors not to be nil")
	}

	tmpl, err := template.New("test").Parse(`<style>:root { --brand-500: {{ .Brand500 }}; }</style>`)
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, colors); err != nil {
		t.Fatalf("failed to execute template: %v", err)
	}

	expected := `<style>:root { --brand-500: #2563eb; }</style>`
	if buf.String() != expected {
		t.Errorf("got %q, expected %q", buf.String(), expected)
	}
}
