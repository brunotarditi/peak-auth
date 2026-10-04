package broker

import (
	"testing"
	"time"
)

func TestRelayState_SignAndValidate(t *testing.T) {
	secretKey := "super-secure-broker-secret-key-12345"

	stateParams := RelayState{
		ClientID:            "client-app-1",
		RedirectURI:         "https://client.com/callback",
		State:               "xyz-oauth-state",
		CodeChallenge:       "E9Melhoa2OwvFrGMTJguCH5rtx64LxPU67A5CdFeC44",
		CodeChallengeMethod: "S256",
		Provider:            "google",
	}

	rawState, err := GenerateRelayState(stateParams, secretKey)
	if err != nil {
		t.Fatalf("unexpected error generating relay state: %v", err)
	}

	validated, err := ValidateRelayState(rawState, secretKey, 10*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error validating relay state: %v", err)
	}

	if validated.ClientID != stateParams.ClientID {
		t.Errorf("expected ClientID %s, got %s", stateParams.ClientID, validated.ClientID)
	}
	if validated.RedirectURI != stateParams.RedirectURI {
		t.Errorf("expected RedirectURI %s, got %s", stateParams.RedirectURI, validated.RedirectURI)
	}
	if validated.State != stateParams.State {
		t.Errorf("expected State %s, got %s", stateParams.State, validated.State)
	}
	if validated.CodeChallenge != stateParams.CodeChallenge {
		t.Errorf("expected CodeChallenge %s, got %s", stateParams.CodeChallenge, validated.CodeChallenge)
	}
	if validated.Provider != "google" {
		t.Errorf("expected Provider google, got %s", validated.Provider)
	}
}

func TestRelayState_TamperedSignatureRejected(t *testing.T) {
	secretKey := "super-secure-broker-secret-key-12345"
	rawState, err := GenerateRelayState(RelayState{ClientID: "test"}, secretKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manipulate signature
	tampered := rawState + "extra"
	_, err = ValidateRelayState(tampered, secretKey, 10*time.Minute)
	if err == nil {
		t.Fatal("expected error validating tampered state, got nil")
	}

	// Validate with wrong key
	_, err = ValidateRelayState(rawState, "wrong-key", 10*time.Minute)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestRelayState_ExpiredRejected(t *testing.T) {
	secretKey := "super-secure-broker-secret-key-12345"
	pastState := RelayState{
		ClientID:  "test",
		Timestamp: time.Now().Add(-15 * time.Minute).Unix(),
	}

	rawState, err := GenerateRelayState(pastState, secretKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = ValidateRelayState(rawState, secretKey, 10*time.Minute)
	if err != ErrExpiredState {
		t.Fatalf("expected ErrExpiredState, got %v", err)
	}
}
