package repo

import (
	"fmt"
	"peak-auth/internal/store/model"
	"strings"
	"time"

	"gorm.io/gorm"
)

type AuditFilter struct {
	TableName string
	Action    string
	ChangedBy string
	StartDate *time.Time
	EndDate   *time.Time
	Page      int
	Limit     int
}

type AuditRepository interface {
	FindAppAuditLogs(appID uint, filter AuditFilter) ([]model.AuditLog, int64, error)
	FindByID(id int64) (*model.AuditLog, error)
	GetDistinctActionsByApp(appID uint) ([]string, error)
	GetDistinctTablesByApp(appID uint) ([]string, error)
}

type auditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) AuditRepository {
	return &auditRepository{db: db}
}

func (r *auditRepository) appScopeQuery(appID uint) *gorm.DB {
	appIDStr := fmt.Sprint(appID)
	// Vincula logs de:
	// 1. La propia tabla applications (cuando record_id es el id de la app)
	// 2. Tablas asociadas donde application_id en JSON coincida con la app
	return r.db.Where(
		"(table_name = 'applications' AND record_id = ?) OR "+
			"(table_name IN ('application_rules', 'roles', 'user_application_roles') AND "+
			"(new_data->>'application_id' = ? OR old_data->>'application_id' = ?))",
		appIDStr, appIDStr, appIDStr,
	)
}

func (r *auditRepository) FindAppAuditLogs(appID uint, filter AuditFilter) ([]model.AuditLog, int64, error) {
	query := r.appScopeQuery(appID)

	if filter.TableName != "" {
		query = query.Where("table_name = ?", filter.TableName)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", strings.ToUpper(filter.Action))
	}
	if filter.ChangedBy != "" {
		query = query.Where("changed_by ILIKE ?", "%"+filter.ChangedBy+"%")
	}
	if filter.StartDate != nil {
		query = query.Where("created_at >= ?", *filter.StartDate)
	}
	if filter.EndDate != nil {
		query = query.Where("created_at <= ?", *filter.EndDate)
	}

	var total int64
	if err := query.Model(&model.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	page := filter.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	var logs []model.AuditLog
	err := query.Order("created_at DESC, id DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error

	return logs, total, err
}

func (r *auditRepository) FindByID(id int64) (*model.AuditLog, error) {
	var log model.AuditLog
	if err := r.db.First(&log, id).Error; err != nil {
		return nil, err
	}
	return &log, nil
}

func (r *auditRepository) GetDistinctActionsByApp(appID uint) ([]string, error) {
	var actions []string
	err := r.appScopeQuery(appID).
		Model(&model.AuditLog{}).
		Distinct("action").
		Order("action ASC").
		Pluck("action", &actions).Error
	return actions, err
}

func (r *auditRepository) GetDistinctTablesByApp(appID uint) ([]string, error) {
	var tables []string
	err := r.appScopeQuery(appID).
		Model(&model.AuditLog{}).
		Distinct("table_name").
		Order("table_name ASC").
		Pluck("table_name", &tables).Error
	return tables, err
}
