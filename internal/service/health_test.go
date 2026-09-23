package service

import (
	"context"
	"errors"
	"testing"
)

type mockHealthRepo struct {
	pingErr error
}

func (m *mockHealthRepo) Ping(ctx context.Context) error {
	return m.pingErr
}

func TestHealthService_CheckHealth(t *testing.T) {
	svc := NewHealthService(&mockHealthRepo{}, nil)
	if !svc.CheckHealth() {
		t.Errorf("se esperaba CheckHealth == true")
	}
}

func TestHealthService_CheckReadiness(t *testing.T) {
	t.Run("DB ok pero TokenManager nil", func(t *testing.T) {
		svc := NewHealthService(&mockHealthRepo{pingErr: nil}, nil)
		dbOk, tmOk := svc.CheckReadiness(context.Background())
		if !dbOk {
			t.Errorf("se esperaba dbOk == true")
		}
		if tmOk {
			t.Errorf("se esperaba tmOk == false")
		}
	})

	t.Run("DB falla con error", func(t *testing.T) {
		svc := NewHealthService(&mockHealthRepo{pingErr: errors.New("connection refused")}, nil)
		dbOk, tmOk := svc.CheckReadiness(context.Background())
		if dbOk {
			t.Errorf("se esperaba dbOk == false")
		}
		if tmOk {
			t.Errorf("se esperaba tmOk == false")
		}
	})
}
