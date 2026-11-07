package util

import (
	"testing"
)

func TestParseCorsPolicy_CloudflareFormat(t *testing.T) {
	cfJson := []byte(`[
  {
    "AllowedOrigins": [
      "https://mariela.pages.dev",
      "http://localhost:3000"
    ],
    "AllowedMethods": [
      "GET",
      "HEAD"
    ],
    "AllowedHeaders": [
      "*"
    ],
    "ExposeHeaders": [
      "ETag",
      "Content-Type"
    ],
    "MaxAgeSeconds": 86400
  }
]`)

	policy, err := ParseCorsPolicy(cfJson)
	if err != nil {
		t.Fatalf("unexpected error parsing cloudflare CORS json: %v", err)
	}
	if policy == nil {
		t.Fatalf("expected non-nil policy")
	}

	if len(policy.AllowedOrigins) != 2 {
		t.Errorf("expected 2 allowed origins, got %d", len(policy.AllowedOrigins))
	}
	if policy.AllowedOrigins[0] != "https://mariela.pages.dev" {
		t.Errorf("expected origin https://mariela.pages.dev, got %s", policy.AllowedOrigins[0])
	}
	if policy.MaxAge != 86400 {
		t.Errorf("expected MaxAge 86400, got %d", policy.MaxAge)
	}

	formatted := FormatCorsAsCloudflareJSON(policy)
	if formatted == "" || formatted == "[]" {
		t.Errorf("expected non-empty formatted cloudflare json, got %s", formatted)
	}
}

func TestParseCorsPolicy_StandardFormat(t *testing.T) {
	stdJson := []byte(`{
  "allowed_origins": ["http://localhost:4200"],
  "allowed_methods": ["GET", "POST", "OPTIONS"],
  "allowed_headers": ["Content-Type", "Authorization"],
  "max_age": 3600
}`)

	policy, err := ParseCorsPolicy(stdJson)
	if err != nil {
		t.Fatalf("unexpected error parsing standard CORS json: %v", err)
	}
	if policy == nil {
		t.Fatalf("expected non-nil policy")
	}
	if len(policy.AllowedOrigins) != 1 || policy.AllowedOrigins[0] != "http://localhost:4200" {
		t.Errorf("expected origin http://localhost:4200, got %v", policy.AllowedOrigins)
	}
	if policy.MaxAge != 3600 {
		t.Errorf("expected MaxAge 3600, got %d", policy.MaxAge)
	}
}
