package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"peak-auth/internal/service"
	"peak-auth/internal/store/repo"

	"github.com/gin-gonic/gin"
)

type AuditController struct {
	BaseController
	AuditService service.AuditService
	AppService   service.ApplicationService
}

func NewAuditController(auditService service.AuditService, appService service.ApplicationService) *AuditController {
	return &AuditController{
		AuditService: auditService,
		AppService:   appService,
	}
}

// GetAppAuditPage renderiza la vista de auditoría scoped para una aplicación específica.
func (ctrl *AuditController) GetAppAuditPage(c *gin.Context) {
	appIDParam := strings.TrimSpace(c.Param("id"))
	if appIDParam == "" {
		ctrl.renderError(c, http.StatusBadRequest, "Parámetro inválido", "El identificador de aplicación es requerido.")
		return
	}

	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		ctrl.renderError(c, http.StatusNotFound, "Aplicación no encontrada", "La aplicación solicitada no existe.")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	if limit < 1 || limit > 100 {
		limit = 15
	}

	filter := repo.AuditFilter{
		TableName: strings.TrimSpace(c.Query("table")),
		Action:    strings.TrimSpace(c.Query("action")),
		ChangedBy: strings.TrimSpace(c.Query("changed_by")),
		Page:      page,
		Limit:     limit,
	}

	auditPage, err := ctrl.AuditService.GetAppAuditLogs(app.ID, filter)
	if err != nil {
		ctrl.renderError(c, http.StatusInternalServerError, "Error de Auditoría", "No se pudieron obtener los logs de auditoría.")
		return
	}

	tables, actions, _ := ctrl.AuditService.GetAuditFilterOptions(app.ID)

	ctrl.renderAdmin(c, "app_audit.html", gin.H{
		"Title":            "Auditoría — " + app.Name,
		"App":              app,
		"Audit":            auditPage,
		"Filter":           filter,
		"AvailableTables":  tables,
		"AvailableActions": actions,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name, "URL": "/admin/apps/" + app.AppID},
			{"Label": "Auditoría"},
		},
	})
}

// GetAppAuditDetail devuelve los detalles estructurados (diff JSON) de un registro específico de auditoría.
func (ctrl *AuditController) GetAppAuditDetail(c *gin.Context) {
	appIDParam := strings.TrimSpace(c.Param("id"))
	logIDParam := strings.TrimSpace(c.Param("log_id"))

	logID, err := strconv.ParseInt(logIDParam, 10, 64)
	if err != nil || logID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de log inválido"})
		return
	}

	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Aplicación no encontrada"})
		return
	}

	detail, err := ctrl.AuditService.GetAuditLogDetail(logID, app.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var oldMap, newMap map[string]interface{}
	if detail.Log.OldData != "" {
		_ = json.Unmarshal([]byte(detail.Log.OldData), &oldMap)
	}
	if detail.Log.NewData != "" {
		_ = json.Unmarshal([]byte(detail.Log.NewData), &newMap)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          detail.Log.ID,
		"table_name":  detail.Log.TableName,
		"table_label": detail.TableLabel,
		"record_id":   detail.Log.RecordID,
		"action":      detail.Log.Action,
		"changed_by":  detail.Log.ChangedBy,
		"created_at":  detail.Log.CreatedAt,
		"old_data":    oldMap,
		"new_data":    newMap,
		"entities":    detail.Entities,
	})
}
