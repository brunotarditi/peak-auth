package repository

import "gorm.io/gorm"

type TxRepository interface {
	Users() UserRepository
	Apps() ApplicationRepository
	Roles() RoleRepository
	UAR() UserApplicationRoleRepository
	PasswordResets() PasswordResetRepository
	Rules() ApplicationRuleRepository
}

type TransactionManager interface {
	WithinTransaction(fn func(tx TxRepository) error) error
}

func NewTransactionManager(db *gorm.DB) TransactionManager {
	return &transactionManager{db: db}
}

// Esta es la implementación que agrupa todo
type unitOfWork struct {
	db *gorm.DB
}

func (u *unitOfWork) Users() UserRepository {
	return NewUserRepositoryRepository(u.db)
}

func (u *unitOfWork) Apps() ApplicationRepository {
	return NewApplicationRepository(u.db)
}

func (u *unitOfWork) Roles() RoleRepository {
	return NewRoleRepositoryRepository(u.db)
}

func (u *unitOfWork) UAR() UserApplicationRoleRepository {
	return NewUserApplicationRoleRepository(u.db)
}

func (u *unitOfWork) PasswordResets() PasswordResetRepository {
	return NewPasswordResetRepository(u.db)
}

func (u *unitOfWork) Rules() ApplicationRuleRepository {
	return NewApplicationRuleRepository(u.db)
}

type transactionManager struct {
	db *gorm.DB
}

func (tx *transactionManager) WithinTransaction(fn func(tx TxRepository) error) error {
	return tx.db.Transaction(func(tx *gorm.DB) error {
		return fn(&unitOfWork{db: tx})
	})
}
