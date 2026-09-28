package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type ApplicationController struct {
	BaseController
	AppService  service.ApplicationService
	UserService service.UserService
	RuleService service.ApplicationRuleService
	RoleService service.RoleService
}

// GetFormApp renderiza el formulario de creación de aplicación
func (ctrl *ApplicationController) GetFormApp(c *gin.Context) {
	ctrl.renderAdmin(c, "app_new.html", gin.H{
		"FormAction": "/admin/apps",
		"IsEdit":     false,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": "Nueva aplicación"},
		},
		"Title":          "Nueva aplicación",
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
		ctrl.renderError(c, http.StatusNotFound, "No Encontrada", "La aplicación solicitada no existe.")
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
	name := strings.TrimSpace(c.PostForm("name"))
	description := strings.TrimSpace(c.PostForm("description"))
	redirectURL := strings.TrimSpace(c.PostForm("redirect_url"))
	isActive := c.PostForm("is_active") == "on"

	renderNewForm := func(status int, nameErr, redirectErr string) {
		data := gin.H{
			"FormAction":       "/admin/apps",
			"IsEdit":           false,
			"Breadcrumbs":      []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva aplicación"}},
			"Title":            "Nueva aplicación",
			"Action":           "Crear aplicación",
			"NameValue":        name,
			"DescriptionValue": description,
			"RedirectURLValue": redirectURL,
			"NameReadonly":     false,
			"NameDisabled":     false,
			"NameClass":        "",
			"HelpText":         "El AppID se generará automáticamente",
			"IsActive":         isActive,
			"IsLocked":         false,
			"SubmitDisabled":   false,
			"StatusApp":        "Activar inmediatamente",
			"Error":            nameErr,
			"RedirectError":    redirectErr,
		}
		if email, exists := c.Get("user_email"); exists {
			data["UserEmail"] = email
		}
		if token, exists := c.Get("csrf_token"); exists {
			data["CSRFToken"] = token
		}
		c.HTML(status, "app_new.html", data)
	}

	if name == "" {
		renderNewForm(http.StatusBadRequest, "El nombre de la aplicación es requerido.", "")
		return
	}

	// Validar que no exista otra app con el mismo nombre
	if err := ctrl.AppService.ValidateAppNameUnique(name); err != nil {
		renderNewForm(http.StatusBadRequest, err.Error(), "")
		return
	}

	// Validar redirectURL antes de llamar a CreateApp
	if redirectURL == "" {
		renderNewForm(http.StatusBadRequest, "", "La URL de redirección es obligatoria.")
		return
	}
	if err := service.ValidateRedirectURISecurity(redirectURL); err != nil {
		renderNewForm(http.StatusBadRequest, "", err.Error())
		return
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint)

	app, plainSecret, err := ctrl.AppService.CreateApp(name, description, redirectURL, isActive, userID)
	if err != nil {
		ctrl.internalErrorHTML(c, "PostFormApp.CreateApp", err, "No se pudo crear la aplicación. Intente nuevamente.")
		return
	}

	// Crear las reglas por defecto (Starter Pack) para la app recién nacida
	if err := ctrl.RuleService.CreateDefaultRules(app.ID); err != nil {
		// Log error pero continuamos porque la app ya fue creada exitosamente. El admin puede crear las reglas manualmente desde el dashboard.
		ctrl.internalErrorHTML(c, "PostFormApp.CreateDefaultRules", err, "La aplicación fue creada pero hubo un error generando las políticas base. Puede configurarlas manualmente.")
		return
	}

	audit.Event(c, "app.create", "app="+app.AppID)

	ctrl.renderAdmin(c, "app_created.html", gin.H{
		"App":         app,
		"PlainSecret": plainSecret,
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva aplicación"}, {"Label": "Creada"}},
		"Title":       "Aplicación creada",
	})
}

// UpdateFormApp actualiza una aplicación (descripción y estado activo/inactivo).
func (ctrl *ApplicationController) UpdateFormApp(c *gin.Context) {
	id := c.Param("id")
	_ = c.PostForm("name")
	description := strings.TrimSpace(c.PostForm("description"))
	redirectURL := strings.TrimSpace(c.PostForm("redirect_url"))
	isActive := c.PostForm("is_active") == "on"

	// La app raíz no puede desactivarse.
	if !isActive && id == util.AppIdPeakAuth {
		ctrl.renderAdmin(c, "error.html", gin.H{
			"error":       "La aplicación principal (Peak Auth Raíz) no puede ser desactivada. Es el núcleo del sistema SSO.",
			"Title":       "Operación bloqueada",
			"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Error"}},
		})
		return
	}

	if id != util.AppIdPeakAuth {
		if redirectURL == "" {
			ctrl.renderError(c, http.StatusBadRequest, "Datos Inválidos", "La URL de redirección es obligatoria.")
			return
		}

		if err := service.ValidateRedirectURISecurity(redirectURL); err != nil {
			ctrl.renderError(c, http.StatusBadRequest, "URL de Redirección Inválida", err.Error())
			return
		}
	} else {
		redirectURL = ""
	}

	if err := ctrl.AppService.UpdateApp(id, description, redirectURL, isActive); err != nil {
		ctrl.internalErrorHTML(c, "UpdateFormApp", err, "No se pudo actualizar la aplicación.")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
}

// PostDeleteApp maneja la eliminación real (lógica) de una aplicación
func (ctrl *ApplicationController) PostDeleteApp(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		ctrl.renderError(c, http.StatusBadRequest, "Operación Bloqueada", "La aplicación principal (Peak Auth Raíz) no puede ser eliminada.")
		return
	}

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		ctrl.renderError(c, http.StatusNotFound, "No Encontrada", "La aplicación solicitada no existe.")
		return
	}

	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint)
	isOwner := app.OwnerID != nil && *app.OwnerID == userID

	if !isRoot && !isOwner {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "Solo el propietario (OWNER) o un administrador ROOT pueden eliminar esta aplicación.")
		return
	}

	if err := ctrl.AppService.DeleteApp(id); err != nil {
		ctrl.internalErrorHTML(c, "PostDeleteApp", err, "No se pudo eliminar la aplicación.")
		return
	}

	audit.Event(c, "app.delete", "app="+id)

	c.Redirect(http.StatusSeeOther, "/admin")
}

// GetAppDetails muestra los detalles de una aplicación
func (ctrl *ApplicationController) GetAppDetails(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		ctrl.renderError(c, http.StatusNotFound, "No Encontrada", "La aplicación solicitada no existe o fue eliminada.")
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
		case util.REGISTRATION_POLICY:
			regPolicy, _ = util.ParseRegistrationPolicy(r.Value)
		case util.PWD_POLICY:
			var p util.PasswordPolicy
			if err := json.Unmarshal(r.Value, &p); err == nil {
				pwdPolicy = &p
			}
		case util.SESSION_POLICY:
			sessionPolicy, _ = util.ParseSessionPolicy(r.Value)
		case util.AUTHZ_POLICY:
			authzPolicy, _ = util.ParseAuthzPolicy(r.Value)
		case util.MFA_POLICY:
			mfaPolicy, _ = util.ParseMfaPolicy(r.Value)
		}
	}

	if mfaPolicy == nil {
		mfaPolicy = &util.MfaPolicy{Mode: "OPTIONAL"}
	}

	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint)
	isOwner := app.OwnerID != nil && *app.OwnerID == userID

	ctrl.renderAdmin(c, "app_show.html", gin.H{
		"App":           app,
		"Rules":         rules,
		"RegPolicy":     regPolicy,
		"PwdPolicy":     pwdPolicy,
		"SessionPolicy": sessionPolicy,
		"AuthzPolicy":   authzPolicy,
		"MfaPolicy":     mfaPolicy,
		"UserCount":     len(users),
		"Users":         users,
		"Roles":         roles,
		"IsRoot":        isRoot,
		"IsOwner":       isOwner,
		"CanManage":     isRoot || isOwner,
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

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		ctrl.internalErrorHTML(c, "PostRegenerateSecret", err, "No se pudo obtener la aplicación.")
		return
	}

	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint)
	isOwner := app.OwnerID != nil && *app.OwnerID == userID

	if !isRoot && !isOwner {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "Solo el propietario (OWNER) o un administrador ROOT pueden regenerar el secreto de la aplicación.")
		return
	}

	plainSecret, err := ctrl.AppService.RegenerateSecret(id)
	if err != nil {
		ctrl.internalErrorHTML(c, "PostRegenerateSecret", err, "No se pudo regenerar el secreto de la aplicación.")
		return
	}

	audit.Event(c, "app.secret.regenerate", "app="+id)

	app, _ = ctrl.AppService.GetAppDetails(id)

	ctrl.renderAdmin(c, "app_created.html", gin.H{
		"App":         app,
		"PlainSecret": plainSecret,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name, "URL": "/admin/apps/" + id},
			{"Label": "Nuevo secreto"},
		},
		"Title": "Nuevo secreto - " + app.Name,
	})
}

// PostTransferOwnership transfiere la propiedad de la aplicación a otro usuario.
func (ctrl *ApplicationController) PostTransferOwnership(c *gin.Context) {
	id := c.Param("id")

	var targetUserID uint
	rawID := strings.TrimSpace(c.PostForm("new_owner_id"))
	if rawID != "" {
		parsed, err := strconv.ParseUint(rawID, 10, 32)
		if err != nil {
			ctrl.renderError(c, http.StatusBadRequest, "Datos Inválidos", "ID de nuevo propietario inválido.")
			return
		}
		targetUserID = uint(parsed)
	} else {
		targetEmail := strings.TrimSpace(c.PostForm("new_owner_email"))
		if targetEmail == "" {
			ctrl.renderError(c, http.StatusBadRequest, "Datos Inválidos", "Debe especificar el nuevo propietario.")
			return
		}
		user, err := ctrl.UserService.FindVerifiedUser(targetEmail)
		if err != nil {
			ctrl.renderError(c, http.StatusNotFound, "Usuario No Encontrado", "El usuario indicado no existe o no está verificado.")
			return
		}
		targetUserID = user.ID
	}

	userIDVal, _ := c.Get("user_id")
	currentUserID, _ := userIDVal.(uint)

	if err := ctrl.AppService.TransferOwnership(id, currentUserID, targetUserID); err != nil {
		ctrl.renderError(c, http.StatusBadRequest, "Error al Transferir", err.Error())
		return
	}

	audit.Event(c, "app.ownership.transfer", fmt.Sprintf("app=%s new_owner_id=%d", id, targetUserID))

	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
}

// GetAppRules redirige a los detalles de la aplicación
func (ctrl *ApplicationController) GetAppRules(c *gin.Context) {
	id := c.Param("id")
	c.Redirect(http.StatusMovedPermanently, "/admin/apps/"+id)
}
