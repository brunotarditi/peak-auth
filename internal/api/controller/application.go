package controller

import (
	"encoding/json"
	"net/http"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

type ApplicationController struct {
	BaseController
	AppService  service.ApplicationService
	UserService service.UserService
	RuleService service.ApplicationRuleService
	RoleService service.RoleService
}

// renderAdmin renderiza la plantilla de administración

// GetFormApp renderiza el formulario de creación de aplicación
func (ctrl *ApplicationController) GetFormApp(c *gin.Context) {
	ctrl.renderAdmin(c, "app_new.html", gin.H{
		"FormAction": "/admin/apps",
		"IsEdit":     false,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": "Nueva Aplicación"},
		},
		"Title":          "Nueva Aplicación",
		"Action":         "Crear aplicación",
		"NameValue":      "",
		"NameReadonly":   false,
		"NameDisabled":   false,
		"NameClass":      "",
		"HelpText":       "El AppID se generará automáticamente",
		"IsActive":       true,
		"IsLocked":       false,
		"SubmitDisabled": true,
		"StatusApp":      "Activar inmediatamente",
	})
}

// GetEditApp renderiza el formulario de edición de aplicación
func (ctrl *ApplicationController) GetEditApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "App no encontrada")
		return
	}
	statusText := "Estado de la Aplicación (Inactiva)"
	if app.IsActive {
		statusText = "Estado de la Aplicación (Activa)"
	}

	ctrl.renderAdmin(c, "app_new.html", gin.H{
		"App":        app,
		"FormAction": "/admin/apps/" + app.AppID,
		"IsEdit":     true,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name, "URL": "/admin/apps/" + app.AppID},
			{"Label": "Editar"},
		},
		"Title":          "Editar " + app.Name,
		"Action":         "Guardar cambios",
		"NameValue":      app.Name,
		"NameReadonly":   true,
		"NameDisabled":   true,
		"NameClass":      "opacity-60 cursor-not-allowed",
		"HelpText":       "El nombre no puede modificarse después de la creación",
		"IsActive":       app.IsActive,
		"IsLocked":       app.AppID == util.AppIdPeakAuth,
		"SubmitDisabled": true,
		"StatusApp":      statusText,
	})
}

// PostFormApp crea una nueva aplicación
func (ctrl *ApplicationController) PostFormApp(c *gin.Context) {
	name := c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	if name == "" {
		c.String(http.StatusBadRequest, "name requerido")
		return
	}

	// Validar que no exista otra app con el mismo nombre
	if err := ctrl.AppService.ValidateAppNameUnique(name); err != nil {
		ctrl.renderAdmin(c, "app_new.html", gin.H{
			"Error":       err.Error(),
			"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva Aplicación"}},
			"Title":       "Nueva Aplicación",
		})
		return
	}

	app, plainSecret, err := ctrl.AppService.CreateApp(name, description, isActive)
	if err != nil {
		c.String(500, "Error creando app: %v", err)
		return
	}

	// Crear las reglas por defecto (Starter Pack) para la app recién nacida
	if err := ctrl.RuleService.CreateDefaultRules(app.ID); err != nil {
		// Log error pero continuamos porque la app ya fue creada exitosamente. El admin puede crear las reglas manualmente desde el dashboard.
		c.String(500, "App creada pero error generando políticas base: %v", err)
		return
	}

	audit.Event(c, "app.create", "app="+app.AppID)

	ctrl.renderAdmin(c, "app_created.html", gin.H{
		"App":         app,
		"PlainSecret": plainSecret,
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva Aplicación"}, {"Label": "Creada"}},
		"Title":       "Aplicación Creada",
	})
}

// UpdateFormApp actualiza una aplicación (descripción y estado activo/inactivo).
// La ELIMINACIÓN es una operación separada y explícita (ver PostDeleteApp).
func (ctrl *ApplicationController) UpdateFormApp(c *gin.Context) {
	id := c.Param("id")
	_ = c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	// La app raíz no puede desactivarse.
	if !isActive && id == util.AppIdPeakAuth {
		ctrl.renderAdmin(c, "error.html", gin.H{
			"error":       "La aplicación principal (Peak Auth Raíz) no puede ser desactivada. Es el núcleo del sistema SSO.",
			"Title":       "Operación Bloqueada",
			"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Error"}},
		})
		return
	}

	if err := ctrl.AppService.UpdateApp(id, description, isActive); err != nil {
		c.String(http.StatusInternalServerError, "Error actualizando app: %v", err)
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
}

// PostDeleteApp maneja la eliminación real (lógica) de una aplicación
func (ctrl *ApplicationController) PostDeleteApp(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		c.String(http.StatusBadRequest, "La aplicación principal (Peak Auth Raíz) no puede ser eliminada")
		return
	}

	// Solo ROOT puede eliminar (garantizado por RootOnlyMiddleware; defensa en profundidad)
	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	if !isRoot {
		c.String(http.StatusForbidden, "Se requiere rol ROOT para eliminar aplicaciones de manera permanente de la vista")
		return
	}

	if err := ctrl.AppService.DeleteApp(id); err != nil {
		c.String(http.StatusInternalServerError, "Error eliminando app: %v", err)
		return
	}

	audit.Event(c, "app.delete", "app="+id)

	// Redirigir al dashboard principal porque la app ya no existe a la vista
	c.Redirect(http.StatusSeeOther, "/admin")
}

// GetAppDetails muestra los detalles de una aplicación
func (ctrl *ApplicationController) GetAppDetails(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	rules, _ := ctrl.RuleService.FindRulesByAppID(app.ID)
	users, _ := ctrl.UserService.FindUserByAppID(id)
	roles, _ := ctrl.RoleService.FindVisibleForApp(app.ID)

	var regPolicy *util.RegistrationPolicy
	var pwdPolicy *util.PasswordPolicy
	var sessionPolicy *util.SessionPolicy
	var authzPolicy *util.AuthzPolicy
	var mfaPolicy *util.MfaPolicy

	for _, r := range rules {
		switch r.Code {
		case "REGISTRATION_POLICY":
			regPolicy, _ = util.ParseRegistrationPolicy(r.Value)
		case "PWD_POLICY":
			var p util.PasswordPolicy
			if err := json.Unmarshal(r.Value, &p); err == nil {
				pwdPolicy = &p
			}
		case "SESSION_POLICY":
			sessionPolicy, _ = util.ParseSessionPolicy(r.Value)
		case "AUTHZ_POLICY":
			authzPolicy, _ = util.ParseAuthzPolicy(r.Value)
		case "MFA_POLICY":
			mfaPolicy, _ = util.ParseMfaPolicy(r.Value)
		}
	}

	if mfaPolicy == nil {
		mfaPolicy = &util.MfaPolicy{Mode: "OPTIONAL"}
	}

	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	ctrl.renderAdmin(c, "app_show.html", gin.H{
		"App":           app,
		"Rules":         rules,
		"RegPolicy":     regPolicy,
		"PwdPolicy":     pwdPolicy,
		"SessionPolicy": sessionPolicy,
		"AuthzPolicy":   authzPolicy,
		"MfaPolicy":     mfaPolicy,
		"UserCount":     len(users),
		"Roles":         roles,
		"IsRoot":        isRoot,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name},
		},
		"Title": app.Name,
	})
}

// PostRegenerateSecret regenera el secreto de una aplicación
func (ctrl *ApplicationController) PostRegenerateSecret(c *gin.Context) {
	id := c.Param("id")
	plainSecret, err := ctrl.AppService.RegenerateSecret(id)
	if err != nil {
		c.String(http.StatusInternalServerError, "error regenerando secreto: %v", err)
		return
	}

	audit.Event(c, "app.secret.regenerate", "app="+id)

	app, _ := ctrl.AppService.GetAppDetails(id)

	ctrl.renderAdmin(c, "app_created.html", gin.H{
		"App":         app,
		"PlainSecret": plainSecret,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name, "URL": "/admin/apps/" + id},
			{"Label": "Nuevo Secreto"},
		},
		"Title": "Nuevo Secreto - " + app.Name,
	})
}

// GetAppRules redirige a los detalles de la aplicación
func (ctrl *ApplicationController) GetAppRules(c *gin.Context) {
	id := c.Param("id")
	c.Redirect(http.StatusMovedPermanently, "/admin/apps/"+id)
}
