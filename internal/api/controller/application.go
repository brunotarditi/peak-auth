package controller

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/storage"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type ApplicationController struct {
	BaseController
	AppService     service.ApplicationService
	UserService    service.UserService
	RuleService    service.ApplicationRuleService
	RoleService    service.RoleService
	StorageService storage.StorageService
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

// GetAppBranding renderiza la pantalla de personalización de marca y temas de una aplicación.
func (ctrl *ApplicationController) GetAppBranding(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "La aplicación raíz Peak Auth es el proveedor de identidad del sistema y no admite personalización de temas.")
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
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "Solo el propietario (OWNER) o un administrador ROOT pueden personalizar la apariencia de la aplicación.")
		return
	}

	theme, _ := ctrl.AppService.GetAppTheme(id)

	primaryColor := "#2563eb"
	logoURL := ""
	faviconURL := ""
	customTitle := ""
	customSubtitle := ""
	termsURL := ""
	privacyURL := ""

	if theme != nil {
		if theme.PrimaryColor != "" {
			primaryColor = theme.PrimaryColor
		}
		logoURL = theme.LogoURL
		faviconURL = theme.FaviconURL
		customTitle = theme.CustomTitle
		customSubtitle = theme.CustomSubtitle
		termsURL = theme.TermsURL
		privacyURL = theme.PrivacyURL
	}

	themeCSS := util.GenerateThemeCSS(primaryColor)

	ctrl.renderAdmin(c, "app_branding.html", gin.H{
		"App":            app,
		"Theme":          theme,
		"PrimaryColor":   primaryColor,
		"LogoURL":        logoURL,
		"FaviconURL":     faviconURL,
		"CustomTitle":    customTitle,
		"CustomSubtitle": customSubtitle,
		"TermsURL":       termsURL,
		"PrivacyURL":     privacyURL,
		"ThemeCSS":       template.CSS(themeCSS),
		"Saved":          c.Query("saved") == "true",
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name, "URL": "/admin/apps/" + id},
			{"Label": "Personalización y Branding"},
		},
		"Title": "Personalización - " + app.Name,
	})
}

// PostAppBranding guarda las preferencias de marca y temas de una aplicación.
func (ctrl *ApplicationController) PostAppBranding(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "La aplicación raíz Peak Auth no admite personalización de temas.")
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
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "Solo el propietario (OWNER) o un administrador ROOT pueden personalizar la apariencia de la aplicación.")
		return
	}

	primaryColor := util.SanitizeHexColor(c.PostForm("primary_color"))
	if primaryColor == "" {
		primaryColor = "#2563eb"
	}

	customTitle := strings.TrimSpace(c.PostForm("custom_title"))
	customSubtitle := strings.TrimSpace(c.PostForm("custom_subtitle"))
	termsURL := strings.TrimSpace(c.PostForm("terms_url"))
	privacyURL := strings.TrimSpace(c.PostForm("privacy_url"))
	logoURL := strings.TrimSpace(c.PostForm("logo_url"))
	faviconURL := strings.TrimSpace(c.PostForm("favicon_url"))

	// Manejo opcional de subida directa de archivos en el formulario
	if file, header, err := c.Request.FormFile("logo_file"); err == nil && ctrl.StorageService != nil {
		if uploadedURL, err := ctrl.StorageService.Upload(c.Request.Context(), file, header.Filename, storage.FolderLogos); err == nil {
			logoURL = uploadedURL
		}
	}

	if file, header, err := c.Request.FormFile("favicon_file"); err == nil && ctrl.StorageService != nil {
		if uploadedURL, err := ctrl.StorageService.Upload(c.Request.Context(), file, header.Filename, storage.FolderFavicon); err == nil {
			faviconURL = uploadedURL
		}
	}

	theme := model.ApplicationTheme{
		PrimaryColor:   primaryColor,
		CustomTitle:    customTitle,
		CustomSubtitle: customSubtitle,
		TermsURL:       termsURL,
		PrivacyURL:     privacyURL,
		LogoURL:        logoURL,
		FaviconURL:     faviconURL,
	}

	if err := ctrl.AppService.UpdateAppTheme(id, &theme); err != nil {
		ctrl.internalErrorHTML(c, "PostAppBranding", err, "No se pudo guardar la configuración de diseño.")
		return
	}

	audit.Event(c, "app.branding.update", fmt.Sprintf("app=%s color=%s", id, primaryColor))

	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id+"/branding?saved=true")
}

// PostAppThemeReset restablece el tema a los valores por defecto del sistema.
func (ctrl *ApplicationController) PostAppThemeReset(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "La aplicación raíz Peak Auth no admite personalización de temas.")
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
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "Solo el propietario (OWNER) o un administrador ROOT pueden restablecer el tema.")
		return
	}

	if err := ctrl.AppService.ResetAppTheme(id); err != nil {
		ctrl.internalErrorHTML(c, "PostAppThemeReset", err, "No se pudo restablecer el tema.")
		return
	}

	audit.Event(c, "app.branding.reset", "app="+id)

	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id+"/branding")
}

// PostAppUploadLogo procesa la subida de un logo mediante AJAX.
func (ctrl *ApplicationController) PostAppUploadLogo(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		c.JSON(http.StatusForbidden, gin.H{"error": "La aplicación raíz Peak Auth no admite personalización de temas"})
		return
	}

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Aplicación no encontrada"})
		return
	}

	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint)
	isOwner := app.OwnerID != nil && *app.OwnerID == userID

	if !isRoot && !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "No autorizado"})
		return
	}

	file, header, err := c.Request.FormFile("logo")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Debe seleccionar un archivo de imagen"})
		return
	}

	if ctrl.StorageService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Servicio de almacenamiento no disponible"})
		return
	}

	url, err := ctrl.StorageService.Upload(c.Request.Context(), file, header.Filename, storage.FolderLogos)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"url":     url,
		"message": "Logo subido exitosamente",
	})
}

// PostAppUploadFavicon procesa la subida de un favicon mediante AJAX.
func (ctrl *ApplicationController) PostAppUploadFavicon(c *gin.Context) {
	id := c.Param("id")

	if id == util.AppIdPeakAuth {
		c.JSON(http.StatusForbidden, gin.H{"error": "La aplicación raíz Peak Auth no admite personalización de temas"})
		return
	}

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Aplicación no encontrada"})
		return
	}

	isRootVal, _ := c.Get("is_root")
	isRoot, _ := isRootVal.(bool)

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(uint)
	isOwner := app.OwnerID != nil && *app.OwnerID == userID

	if !isRoot && !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "No autorizado"})
		return
	}

	file, header, err := c.Request.FormFile("favicon")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Debe seleccionar un archivo de icono"})
		return
	}

	if ctrl.StorageService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Servicio de almacenamiento no disponible"})
		return
	}

	url, err := ctrl.StorageService.Upload(c.Request.Context(), file, header.Filename, storage.FolderFavicon)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"url":     url,
		"message": "Favicon subido exitosamente",
	})
}

