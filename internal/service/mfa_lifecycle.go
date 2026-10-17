package service

import (
	"fmt"
	"peak-auth/internal/store/repo"
)

type mfaLifecycleService struct {
	mfaRepo   repo.MfaRepository
	userRepo  repo.UserRepository
	txManager repo.TransactionManager
}

func newMfaLifecycleService(mfaRepo repo.MfaRepository, userRepo repo.UserRepository, txManager repo.TransactionManager) *mfaLifecycleService {
	return &mfaLifecycleService{mfaRepo: mfaRepo, userRepo: userRepo, txManager: txManager}
}

func (s *mfaLifecycleService) disable(userID uint) error {
	disable := func(mfaRepo repo.MfaRepository, userRepo repo.UserRepository) error {
		if err := mfaRepo.DeleteCredentialsByUser(userID); err != nil {
			return fmt.Errorf("error eliminando credenciales MFA: %w", err)
		}
		if err := mfaRepo.DeleteRecoveryCodesByUser(userID); err != nil {
			return fmt.Errorf("error eliminando códigos de recuperación: %w", err)
		}
		if err := userRepo.UpdateColumn("mfa_enabled", false, userID); err != nil {
			return fmt.Errorf("error desactivando MFA en el usuario: %w", err)
		}
		return nil
	}

	if s.txManager != nil {
		return s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
			return disable(tx.Mfa(), tx.Users())
		})
	}
	return disable(s.mfaRepo, s.userRepo)
}
