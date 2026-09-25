package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strconv"
	"strings"
)

type AuditDetailResult struct {
	Log        *model.AuditLog
	TableLabel string
	Entities   map[string]string
}

type AuditService interface {
	GetAppAuditLogs(appID uint, filter repo.AuditFilter) (*response.AuditLogPageResponse, error)
	GetAuditLogDetail(id int64, appID uint) (*AuditDetailResult, error)
	GetAuditFilterOptions(appID uint) (tables []string, actions []string, err error)
}

type auditService struct {
	auditRepo repo.AuditRepository
	userRepo  repo.UserRepository
	roleRepo  repo.RoleRepository
	appRepo   repo.ApplicationRepository
}

func NewAuditService(
	auditRepo repo.AuditRepository,
	userRepo repo.UserRepository,
	roleRepo repo.RoleRepository,
	appRepo repo.ApplicationRepository,
) AuditService {
	return &auditService{
		auditRepo: auditRepo,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		appRepo:   appRepo,
	}
}

func formatTableLabel(tableName string) string {
	switch tableName {
	case "applications":
		return "Configuración de App"
	case "application_rules":
		return "Regla de Acceso"
	case "roles":
		return "Rol de Aplicación"
	case "user_application_roles":
		return "Usuario y Rol"
	case "users":
		return "Usuario"
	default:
		return tableName
	}
}

func parseJSONMap(str string) map[string]interface{} {
	if strings.TrimSpace(str) == "" {
		return nil
	}
	var res map[string]interface{}
	_ = json.Unmarshal([]byte(str), &res)
	return res
}

func parseUint(val interface{}) uint {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case float64:
		return uint(v)
	case int:
		return uint(v)
	case int64:
		return uint(v)
	case string:
		u, _ := strconv.ParseUint(v, 10, 64)
		return uint(u)
	default:
		return 0
	}
}

func (s *auditService) GetAppAuditLogs(appID uint, filter repo.AuditFilter) (*response.AuditLogPageResponse, error) {
	if filter.Limit <= 0 {
		filter.Limit = 15
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	logs, total, err := s.auditRepo.FindAppAuditLogs(appID, filter)
	if err != nil {
		return nil, fmt.Errorf("error al obtener logs de auditoría: %w", err)
	}

	totalPages := int(math.Ceil(float64(total) / float64(filter.Limit)))
	if totalPages == 0 {
		totalPages = 1
	}

	// Caches temporales para optimizar consultas de resolución en página
	userCache := make(map[uint]string)
	roleCache := make(map[uint]string)
	appCache := make(map[uint]string)

	getUserEmail := func(uID uint) string {
		if uID == 0 {
			return ""
		}
		if email, ok := userCache[uID]; ok {
			return email
		}
		if s.userRepo != nil {
			if u, err := s.userRepo.FindById(uID); err == nil && u.Email != "" {
				userCache[uID] = u.Email
				return u.Email
			}
		}
		res := fmt.Sprintf("Usuario #%d", uID)
		userCache[uID] = res
		return res
	}

	getRoleName := func(rID uint) string {
		if rID == 0 {
			return ""
		}
		if name, ok := roleCache[rID]; ok {
			return name
		}
		if s.roleRepo != nil {
			if r, err := s.roleRepo.FindByID(rID); err == nil && r.Name != "" {
				roleCache[rID] = r.Name
				return r.Name
			}
		}
		res := fmt.Sprintf("Rol #%d", rID)
		roleCache[rID] = res
		return res
	}

	getAppName := func(aID uint) string {
		if aID == 0 {
			return ""
		}
		if name, ok := appCache[aID]; ok {
			return name
		}
		if s.appRepo != nil {
			if a, err := s.appRepo.FindByID(aID); err == nil && a.Name != "" {
				appCache[aID] = a.Name
				return a.Name
			}
		}
		res := fmt.Sprintf("App #%d", aID)
		appCache[aID] = res
		return res
	}

	items := make([]response.AuditLogItem, 0, len(logs))
	for _, l := range logs {
		var dataMap map[string]interface{}
		if l.Action == "DELETE" {
			dataMap = parseJSONMap(l.OldData)
		} else {
			dataMap = parseJSONMap(l.NewData)
		}
		if dataMap == nil {
			dataMap = parseJSONMap(l.OldData)
		}

		var desc string
		switch l.TableName {
		case "user_application_roles":
			uID := parseUint(dataMap["user_id"])
			rID := parseUint(dataMap["role_id"])
			userEmail := getUserEmail(uID)
			roleName := getRoleName(rID)

			switch l.Action {
			case "INSERT":
				desc = fmt.Sprintf("Asignó rol %s a %s", roleName, userEmail)
			case "UPDATE":
				desc = fmt.Sprintf("Modificó rol de %s a %s", userEmail, roleName)
			case "DELETE":
				desc = fmt.Sprintf("Revocó rol %s de %s", roleName, userEmail)
			default:
				desc = fmt.Sprintf("%s en rol %s", userEmail, roleName)
			}

		case "application_rules":
			code, _ := dataMap["code"].(string)
			if code == "" {
				code, _ = dataMap["rule_type"].(string)
			}
			valStr := ""
			if v, ok := dataMap["value"]; ok && v != nil {
				valStr = fmt.Sprint(v)
			} else if v, ok := dataMap["rule_value"]; ok && v != nil {
				valStr = fmt.Sprint(v)
			}
			valStr = strings.Trim(valStr, "\"")
			if code != "" {
				if valStr != "" {
					desc = fmt.Sprintf("Regla %s = %s", code, valStr)
				} else {
					desc = fmt.Sprintf("Regla %s", code)
				}
			} else {
				desc = fmt.Sprintf("Regla #%s", l.RecordID)
			}

		case "applications":
			appName, _ := dataMap["name"].(string)
			appPublicID, _ := dataMap["app_id"].(string)
			if appPublicID == "" {
				appPublicID, _ = dataMap["client_id"].(string)
			}
			if appName != "" && appPublicID != "" {
				desc = fmt.Sprintf("%s (%s)", appName, appPublicID)
			} else if appName != "" {
				desc = appName
			} else {
				desc = fmt.Sprintf("App #%s", l.RecordID)
			}

		case "roles":
			roleName, _ := dataMap["name"].(string)
			if roleName != "" {
				desc = fmt.Sprintf("Rol: %s", roleName)
			} else {
				desc = fmt.Sprintf("Rol #%s", l.RecordID)
			}

		default:
			desc = fmt.Sprintf("Registro #%s", l.RecordID)
		}

		items = append(items, response.AuditLogItem{
			ID:          l.ID,
			TableName:   l.TableName,
			TableLabel:  formatTableLabel(l.TableName),
			RecordID:    l.RecordID,
			Action:      l.Action,
			ChangedBy:   l.ChangedBy,
			OldData:     l.OldData,
			NewData:     l.NewData,
			Description: desc,
			CreatedAt:   l.CreatedAt,
		})
	}

	// Suprimir advertencias de variables no usadas
	_ = getAppName

	hasPrev := filter.Page > 1
	hasNext := filter.Page < totalPages
	prevPage := filter.Page - 1
	if prevPage < 1 {
		prevPage = 1
	}
	nextPage := filter.Page + 1
	if nextPage > totalPages {
		nextPage = totalPages
	}

	return &response.AuditLogPageResponse{
		Items:       items,
		Total:       total,
		CurrentPage: filter.Page,
		TotalPages:  totalPages,
		HasPrev:     hasPrev,
		HasNext:     hasNext,
		PrevPage:    prevPage,
		NextPage:    nextPage,
	}, nil
}

func (s *auditService) GetAuditLogDetail(id int64, appID uint) (*AuditDetailResult, error) {
	log, err := s.auditRepo.FindByID(id)
	if err != nil {
		return nil, err
	}

	// Validación defensiva anti-IDOR: verificar que el log pertenezca efectivamente a appID
	appIDStr := fmt.Sprint(appID)
	belongs := false

	if log.TableName == "applications" && log.RecordID == appIDStr {
		belongs = true
	} else {
		// Verificar en JSON new_data o old_data
		var dataMap map[string]interface{}
		if log.NewData != "" && json.Unmarshal([]byte(log.NewData), &dataMap) == nil {
			if v, ok := dataMap["application_id"]; ok && fmt.Sprint(v) == appIDStr {
				belongs = true
			}
		}
		if !belongs && log.OldData != "" && json.Unmarshal([]byte(log.OldData), &dataMap) == nil {
			if v, ok := dataMap["application_id"]; ok && fmt.Sprint(v) == appIDStr {
				belongs = true
			}
		}
	}

	if !belongs {
		return nil, errors.New("registro de auditoría no encontrado o no pertenece a esta aplicación")
	}

	oldMap := parseJSONMap(log.OldData)
	newMap := parseJSONMap(log.NewData)

	entities := make(map[string]string)

	// Resolver nombre de la app
	if s.appRepo != nil {
		if app, err := s.appRepo.FindByID(appID); err == nil && app.Name != "" {
			entities[fmt.Sprintf("app_%d", appID)] = app.Name
		}
	}

	// Resolver usuarios y roles involucrados en los payloads
	for _, m := range []map[string]interface{}{oldMap, newMap} {
		if m == nil {
			continue
		}
		if uVal, ok := m["user_id"]; ok {
			uID := parseUint(uVal)
			if uID > 0 {
				key := fmt.Sprintf("user_%d", uID)
				if _, exists := entities[key]; !exists && s.userRepo != nil {
					if u, err := s.userRepo.FindById(uID); err == nil && u.Email != "" {
						entities[key] = u.Email
					}
				}
			}
		}
		if rVal, ok := m["role_id"]; ok {
			rID := parseUint(rVal)
			if rID > 0 {
				key := fmt.Sprintf("role_%d", rID)
				if _, exists := entities[key]; !exists && s.roleRepo != nil {
					if r, err := s.roleRepo.FindByID(rID); err == nil && r.Name != "" {
						entities[key] = r.Name
					}
				}
			}
		}
		if aVal, ok := m["application_id"]; ok {
			aID := parseUint(aVal)
			if aID > 0 {
				key := fmt.Sprintf("app_%d", aID)
				if _, exists := entities[key]; !exists && s.appRepo != nil {
					if a, err := s.appRepo.FindByID(aID); err == nil && a.Name != "" {
						entities[key] = a.Name
					}
				}
			}
		}
	}

	return &AuditDetailResult{
		Log:        log,
		TableLabel: formatTableLabel(log.TableName),
		Entities:   entities,
	}, nil
}

func (s *auditService) GetAuditFilterOptions(appID uint) ([]string, []string, error) {
	tables, err := s.auditRepo.GetDistinctTablesByApp(appID)
	if err != nil {
		return nil, nil, err
	}
	actions, err := s.auditRepo.GetDistinctActionsByApp(appID)
	if err != nil {
		return nil, nil, err
	}
	return tables, actions, nil
}
