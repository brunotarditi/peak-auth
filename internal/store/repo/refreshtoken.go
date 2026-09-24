package repo

import (
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
)

type RefreshTokenRepository interface {
	Create(token *model.RefreshToken) error
	FindByToken(token string) (model.RefreshToken, error)
	DeleteByToken(token string) error
	DeleteByTokenAtomic(token string) (int64, error)
	DeleteByUser(userID uint) error
	DeleteByUserAndApp(userID, appID uint) error
	DeleteByApp(appID uint) error
	FindActiveByUser(userID uint) ([]model.RefreshToken, error)
	DeleteByIDAndUser(id uint, userID uint) error
	DeleteOthersByUser(userID uint, currentTokenHash string) error
	DeleteOthersByID(userID uint, sessionID uint) error
	UpdateLastUsed(tokenHash string, ip string) error
	DeleteByUserAppAndDevice(userID, appID uint, ip, userAgent string) error
}

type refreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Create(token *model.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *refreshTokenRepository) FindByToken(token string) (model.RefreshToken, error) {
	var rt model.RefreshToken
	err := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&rt).Error
	return rt, err
}

func (r *refreshTokenRepository) DeleteByToken(token string) error {
	return r.db.Where("token = ?", token).Delete(&model.RefreshToken{}).Error
}

func (r *refreshTokenRepository) DeleteByTokenAtomic(token string) (int64, error) {
	result := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).Delete(&model.RefreshToken{})
	return result.RowsAffected, result.Error
}

func (r *refreshTokenRepository) DeleteByUser(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.RefreshToken{}).Error
}

func (r *refreshTokenRepository) DeleteByUserAndApp(userID, appID uint) error {
	return r.db.Where("user_id = ? AND application_id = ?", userID, appID).Delete(&model.RefreshToken{}).Error
}

func (r *refreshTokenRepository) DeleteByApp(appID uint) error {
	return r.db.Where("application_id = ?", appID).Delete(&model.RefreshToken{}).Error
}

func (r *refreshTokenRepository) FindActiveByUser(userID uint) ([]model.RefreshToken, error) {
	var tokens []model.RefreshToken
	err := r.db.Preload("Application").
		Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Order("last_used_at DESC, created_at DESC").
		Find(&tokens).Error
	return tokens, err
}

func (r *refreshTokenRepository) DeleteByIDAndUser(id uint, userID uint) error {
	result := r.db.Where("id = ? AND user_id = ?", id, userID).Delete(&model.RefreshToken{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *refreshTokenRepository) DeleteOthersByUser(userID uint, currentTokenHash string) error {
	return r.db.Where("user_id = ? AND token != ?", userID, currentTokenHash).Delete(&model.RefreshToken{}).Error
}

func (r *refreshTokenRepository) DeleteOthersByID(userID uint, sessionID uint) error {
	return r.db.Where("user_id = ? AND id != ?", userID, sessionID).Delete(&model.RefreshToken{}).Error
}

func (r *refreshTokenRepository) UpdateLastUsed(tokenHash string, ip string) error {
	updates := map[string]interface{}{
		"last_used_at": time.Now(),
	}
	if ip != "" {
		updates["ip_address"] = ip
	}
	return r.db.Model(&model.RefreshToken{}).Where("token = ?", tokenHash).Updates(updates).Error
}

func (r *refreshTokenRepository) DeleteByUserAppAndDevice(userID, appID uint, ip, userAgent string) error {
	if ip == "" && userAgent == "" {
		return nil
	}
	query := r.db.Where("user_id = ? AND application_id = ?", userID, appID)
	if userAgent != "" {
		// Mismo navegador/dispositivo: revocar sesión previa para evitar sesiones duplicadas en el mismo equipo
		query = query.Where("user_agent = ?", userAgent)
	} else if ip != "" {
		query = query.Where("ip_address = ?", ip)
	}
	return query.Delete(&model.RefreshToken{}).Error
}

