package service

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	ErrCodeValidation     ErrorCode = "validation"
	ErrCodeAuthentication ErrorCode = "authentication"
	ErrCodeAuthorization  ErrorCode = "authorization"
	ErrCodeNotFound       ErrorCode = "not_found"
	ErrCodeConflict       ErrorCode = "conflict"
	ErrCodeConfiguration  ErrorCode = "configuration"
	ErrCodePersistence    ErrorCode = "persistence"
	ErrCodeInternal       ErrorCode = "internal"
)

type DomainError struct {
	Code ErrorCode
	Op   string
	Err  error
}

func (e *DomainError) Error() string {
	if e.Op == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *DomainError) Unwrap() error {
	return e.Err
}

func domainError(code ErrorCode, op string, err error) error {
	if err == nil {
		return nil
	}
	return &DomainError{Code: code, Op: op, Err: err}
}

func ErrorCodeOf(err error) ErrorCode {
	var domainErr *DomainError
	if errors.As(err, &domainErr) {
		return domainErr.Code
	}
	return ""
}
