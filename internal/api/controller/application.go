package controller

import (
	"encoding/json"
	"net/http"
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
		"IsActive":       true,
		"IsLocked":       false,
		"SubmitDisabled": true,
		"StatusApp":      "Estado de la Aplicación (Activa)",
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
		c.String(500, "Error creando aplicación")
		return
	}

	// Crear las reglas por defecto (Starter Pack) para la app recién nacida
	if err := ctrl.RuleService.CreateDefaultRules(app.ID); err != nil {
		// Log error pero continuamos porque la app ya fue creada exitosamente. El admin puede crear las reglas manualmente desde el dashboard.
		c.String(500, "App creada pero error generando políticas base")
		return
	}

	ctrl.renderAdmin(c, "app_created.html", gin.H{
		"App":         app,
		"PlainSecret": plainSecret,
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva Aplicación"}, {"Label": "Creada"}},
		"Title":       "Aplicación Creada",
	})
}

// UpdateFormApp actualiza una aplicación
func (ctrl *ApplicationController) UpdateFormApp(c *gin.Context) {
	id := c.Param("id")
	_ = c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	if !isActive {
		if id == util.AppIdPeakAuth {
			ctrl.renderAdmin(c, "error.html", gin.H{
				"error":       "La aplicación principal (Peak Auth Raíz) no puede ser desactivada ni eliminada. Es el núcleo del sistema SSO.",
				"Title":       "Operación Bloqueada",
				"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Error"}},
			})
			return
		}

		// Verificar rol ROOT para la eliminación
		roles, _ := c.Get("user_roles")
		isRoot := false
		if rList, ok := roles.([]string); ok {
			for _, rol := range rList {
				if rol == "ROOT" {
					isRoot = true
					break
				}
			}
		}

		if !isRoot {
			c.String(http.StatusForbidden, "Se requiere rol ROOT para desactivar/eliminar aplicaciones")
			return
		}

		if err := ctrl.AppService.DeleteApp(id); err != nil {
			c.String(http.StatusInternalServerError, "Error eliminando aplicación")
			return
		}
		c.Redirect(http.StatusSeeOther, "/admin")
		return
	}

	err := ctrl.AppService.UpdateApp(id, description, true)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error actualizando aplicación")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin")
}

// PostDeleteApp maneja la eliminación real (lógica) de una aplicación
func (ctrl *ApplicationController) PostDeleteApp(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		c.String(http.StatusBadRequest, "La aplicación principal (Peak Auth Raíz) no puede ser eliminada")
		return
	}

	// Solo ROOT puede eliminar
	roles, _ := c.Get("user_roles")
	isRoot := false
	if rList, ok := roles.([]string); ok {
		for _, r := range rList {
			if r == "ROOT" {
				isRoot = true
				break
			}
		}
	}

	if !isRoot {
		c.String(http.StatusForbidden, "Se requiere rol ROOT para eliminar aplicaciones de manera permanente de la vista")
		return
	}

	if err := ctrl.AppService.DeleteApp(id); err != nil {
		c.String(http.StatusInternalServerError, "Error eliminando aplicación")
		return
	}

	// Redirigir al dashboard principal porque la app ya no existe a la vista
	c.Redirect(http.StatusSeeOther, "/admin")
}

// GetAppDetails muestra los detalles de una aplicación
func (ctrl *ApplicationController) GetAppDetails(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "Aplicación no encontrada")
		return
	}
	rules, _ := ctrl.RuleService.FindRulesByAppID(app.ID)
	users, _ := ctrl.UserService.FindUserByAppID(id)
	roles, _ := ctrl.RoleService.FindAll()

	var regPolicy *util.RegistrationPolicy
	var pwdPolicy *util.PasswordPolicy
	var sessionPolicy *util.SessionPolicy
	var authzPolicy *util.AuthzPolicy

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
		}
	}

	ctrl.renderAdmin(c, "app_show.html", gin.H{
		"App":           app,
		"Rules":         rules,
		"RegPolicy":     regPolicy,
		"PwdPolicy":     pwdPolicy,
		"SessionPolicy": sessionPolicy,
		"AuthzPolicy":   authzPolicy,
		"UserCount":     len(users),
		"Roles":         roles,
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
		c.String(http.StatusInternalServerError, "Error regenerando secreto")
		return
	}

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
