package util

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyTurnstileToken(t *testing.T) {
	t.Run("disabled when keys are missing", func(t *testing.T) {
		t.Setenv("TURNSTILE_SITE_KEY", "")
		t.Setenv("TURNSTILE_SECRET_KEY", "")

		ok, err := VerifyTurnstileToken("", "127.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected true when Turnstile is disabled")
		}
	})

	t.Run("empty token fails when enabled", func(t *testing.T) {
		t.Setenv("TURNSTILE_SITE_KEY", "site-key")
		t.Setenv("TURNSTILE_SECRET_KEY", "secret-key")

		ok, err := VerifyTurnstileToken("   ", "127.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Fatal("expected false for empty token")
		}
	})

	t.Run("valid token succeeds", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form failed: %v", err)
			}
			if r.FormValue("secret") != "secret-key" || r.FormValue("response") != "valid-tok" || r.FormValue("remoteip") != "203.0.113.5" {
				t.Fatalf("unexpected form values: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		}))
		defer srv.Close()

		origURL := turnstileVerifyURL
		turnstileVerifyURL = srv.URL
		defer func() { turnstileVerifyURL = origURL }()

		t.Setenv("TURNSTILE_SITE_KEY", "site-key")
		t.Setenv("TURNSTILE_SECRET_KEY", "secret-key")

		ok, err := VerifyTurnstileToken("valid-tok", "203.0.113.5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected true for valid token")
		}
	})

	t.Run("rejected token returns false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
		}))
		defer srv.Close()

		origURL := turnstileVerifyURL
		turnstileVerifyURL = srv.URL
		defer func() { turnstileVerifyURL = origURL }()

		t.Setenv("TURNSTILE_SITE_KEY", "site-key")
		t.Setenv("TURNSTILE_SECRET_KEY", "secret-key")

		ok, err := VerifyTurnstileToken("bad-tok", "203.0.113.5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Fatal("expected false for rejected token")
		}
	})
}
