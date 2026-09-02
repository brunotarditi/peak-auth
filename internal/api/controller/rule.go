package controller

import (
	"encoding/json"
	"net/http"
	"peak-auth/internal/service"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

type RuleController struct {
	RuleService service.ApplicationRuleService
	AppService  service.ApplicationService
}

// PostAppRule (Crea nueva regla)
func (ctrl *RuleController) PostAppRule(c *gin.Context) {
	id := c.Param("id")
	code := c.Param("code")

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error leyendo el JSON"})
		return
	}

	err = ctrl.RuleService.CreateRule(app.ID, code, body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Regla creada exitosamente"})
}

// PutAppRule (Actualiza valor JSON de regla existente)
func (ctrl *RuleController) PutAppRule(c *gin.Context) {
	id := c.Param("id")
	code := c.Param("code")

	if id == util.AppIdPeakAuth && code != "SESSION_POLICY" && code != "MFA_POLICY" {
		c.JSON(http.StatusForbidden, gin.H{"error": "No está permitido modificar esta política para la aplicación principal (Peak Auth Raíz)"})
		return
	}

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error leyendo el JSON"})
		return
	}

	switch code {
	case "SESSION_POLICY":
		var params struct {
			TokenExpirationMinutes int `json:"token_expiration_minutes"`
			MaxFailedLogins        int `json:"max_failed_logins"`
		}
		if err := json.Unmarshal(body, &params); err == nil {
			if params.TokenExpirationMinutes < 1 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "La expiración de la sesión debe ser al menos de 1 minuto"})
				return
			}
			if params.MaxFailedLogins < 1 || params.MaxFailedLogins > 10 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "El máximo de logins fallidos debe estar entre 1 y 10"})
				return
			}
		}
	case "PWD_POLICY":
		var params struct {
			MinLength int `json:"min_length"`
		}
		if err := json.Unmarshal(body, &params); err == nil {
			if params.MinLength < 4 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "La contraseña debe tener al menos 4 caracteres"})
				return
			}
		}
	case "MFA_POLICY":
		var params struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(body, &params); err == nil {
			if params.Mode != "OPTIONAL" && params.Mode != "REQUIRED" && params.Mode != "DISABLED" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Modo de MFA inválido. Debe ser OPTIONAL, REQUIRED o DISABLED"})
				return
			}
		}
	}

	err = ctrl.RuleService.UpdateRuleValue(app.ID, code, body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Regla actualizada correctamente"})
}

// DeleteAppRule (Desactiva regla lógica)
func (ctrl *RuleController) DeleteAppRule(c *gin.Context) {
	id := c.Param("id")
	code := c.Param("code")

	if id == util.AppIdPeakAuth {
		c.JSON(http.StatusForbidden, gin.H{"error": "No se pueden eliminar las políticas de la aplicación principal (Peak Auth Raíz)"})
		return
	}

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	err = ctrl.RuleService.DeleteRule(app.ID, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Regla eliminada"})
}

// PostDefaultRules crea las reglas por defecto para una aplicación
func (ctrl *RuleController) PostDefaultRules(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)

	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}

	if err := ctrl.RuleService.CreateDefaultRules(app.ID); err != nil {
		c.String(http.StatusInternalServerError, "error creando reglas por defecto: %v", err)
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
}
