package service

import (
	"errors"
	"testing"
)

func TestErrorCodeOfFindsWrappedDomainError(t *testing.T) {
	err := domainError(ErrCodeAuthorization, "authorize", errors.New("denegado"))
	wrapped := errors.Join(errors.New("request failed"), err)

	if got := ErrorCodeOf(wrapped); got != ErrCodeAuthorization {
		t.Fatalf("expected authorization error code, got %q", got)
	}
}

func TestNoopEventPublisher(t *testing.T) {
	if err := NewNoopEventPublisher().Publish(nil, Event{Name: "test"}); err != nil {
		t.Fatalf("expected noop publisher to succeed, got %v", err)
	}
}
