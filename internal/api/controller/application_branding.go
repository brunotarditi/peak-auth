package controller

import (
	"fmt"
	"net/http"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/storage"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"strings"

	"github.com/gin-gonic/gin"
)

type ApplicationBrandingController struct {
	BaseController
	AppService     service.ApplicationService
	RuleService    service.ApplicationRuleService
	StorageService storage.StorageService
}

type applicationBrandingRequest struct {
	PrimaryColor   string
	CustomTitle    string
	CustomSubtitle string
	TermsURL       string
	PrivacyURL     string
	LogoURL        string
	FaviconURL     string
}

func newApplicationBrandingRequest(c *gin.Context) applicationBrandingRequest {
	primaryColor := util.SanitizeHexColor(c.PostForm("primary_color"))
	if primaryColor == "" {
		primaryColor = "#2563eb"
	}

	return applicationBrandingRequest{
		PrimaryColor:   primaryColor,
		CustomTitle:    strings.TrimSpace(c.PostForm("custom_title")),
		CustomSubtitle: strings.TrimSpace(c.PostForm("custom_subtitle")),
		TermsURL:       strings.TrimSpace(c.PostForm("terms_url")),
		PrivacyURL:     strings.TrimSpace(c.PostForm("privacy_url")),
		LogoURL:        strings.TrimSpace(c.PostForm("logo_url")),
		FaviconURL:     strings.TrimSpace(c.PostForm("favicon_url")),
	}
}

func NewApplicationBrandingController(
	appService service.ApplicationService,
	ruleService service.ApplicationRuleService,
	storageService storage.StorageService,
) *ApplicationBrandingController {
	return &ApplicationBrandingController{
		AppService:     appService,
		RuleService:    ruleService,
		StorageService: storageService,
	}
}

func (ctrl *ApplicationBrandingController) GetAppBranding(c *gin.Context) {
	id := c.Param("id")
	app, ok := ctrl.loadEditableApp(c, id)
	if !ok {
		return
	}

	theme, err := ctrl.AppService.GetAppTheme(id)
	if err != nil {
		ctrl.internalErrorHTML(c, "GetAppBranding.GetAppTheme", err, "No se pudo cargar la configuración de diseño.")
		return
	}

	view := gin.H{
		"App":          app,
		"Theme":        theme,
		"PrimaryColor": "#2563eb",
		"Saved":        c.Query("saved") == "true",
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name, "URL": "/admin/apps/" + id},
			{"Label": "Personalización y Branding"},
		},
		"Title": "Personalización - " + app.Name,
	}

	if theme != nil {
		if theme.PrimaryColor != "" {
			view["PrimaryColor"] = theme.PrimaryColor
		}
		view["LogoURL"] = theme.LogoURL
		view["FaviconURL"] = theme.FaviconURL
		view["CustomTitle"] = theme.CustomTitle
		view["CustomSubtitle"] = theme.CustomSubtitle
		view["TermsURL"] = theme.TermsURL
		view["PrivacyURL"] = theme.PrivacyURL
	}

	view["ThemeColors"] = util.ResolveThemeColors(view["PrimaryColor"].(string))
	view["AllowRegistration"] = ctrl.registrationIsPublic(app.ID)
	ctrl.renderAdmin(c, "app_branding.html", view)
}

func (ctrl *ApplicationBrandingController) PostAppBranding(c *gin.Context) {
	id := c.Param("id")
	if _, ok := ctrl.loadEditableApp(c, id); !ok {
		return
	}

	currentTheme, _ := ctrl.AppService.GetAppTheme(id)

	request := newApplicationBrandingRequest(c)
	logoURL := request.LogoURL
	if uploadedURL, provided, err := uploadApplicationAsset(c, ctrl.StorageService, "logo_file", storage.FolderLogos); provided {
		if err != nil {
			ctrl.internalErrorHTML(c, "PostAppBranding.LogoUpload", err, "No se pudo subir el logo.")
			return
		}
		logoURL = uploadedURL
	}

	faviconURL := request.FaviconURL
	if uploadedURL, provided, err := uploadApplicationAsset(c, ctrl.StorageService, "favicon_file", storage.FolderFavicon); provided {
		if err != nil {
			ctrl.internalErrorHTML(c, "PostAppBranding.FaviconUpload", err, "No se pudo subir el favicon.")
			return
		}
		faviconURL = uploadedURL
	}

	if currentTheme != nil && ctrl.StorageService != nil {
		if currentTheme.LogoURL != "" && currentTheme.LogoURL != logoURL {
			_ = ctrl.StorageService.Delete(c.Request.Context(), currentTheme.LogoURL)
		}
		if currentTheme.FaviconURL != "" && currentTheme.FaviconURL != faviconURL {
			_ = ctrl.StorageService.Delete(c.Request.Context(), currentTheme.FaviconURL)
		}
	}

	theme := model.ApplicationTheme{
		PrimaryColor:   request.PrimaryColor,
		CustomTitle:    request.CustomTitle,
		CustomSubtitle: request.CustomSubtitle,
		TermsURL:       request.TermsURL,
		PrivacyURL:     request.PrivacyURL,
		LogoURL:        logoURL,
		FaviconURL:     faviconURL,
	}

	if err := ctrl.AppService.UpdateAppTheme(id, &theme); err != nil {
		ctrl.internalErrorHTML(c, "PostAppBranding", err, "No se pudo guardar la configuración de diseño.")
		return
	}

	audit.Event(c, "app.branding.update", fmt.Sprintf("app=%s color=%s", id, request.PrimaryColor))
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id+"/branding?saved=true")
}

func (ctrl *ApplicationBrandingController) PostAppThemeReset(c *gin.Context) {
	id := c.Param("id")
	if _, ok := ctrl.loadEditableApp(c, id); !ok {
		return
	}

	if currentTheme, err := ctrl.AppService.GetAppTheme(id); err == nil && currentTheme != nil && ctrl.StorageService != nil {
		if currentTheme.LogoURL != "" {
			_ = ctrl.StorageService.Delete(c.Request.Context(), currentTheme.LogoURL)
		}
		if currentTheme.FaviconURL != "" {
			_ = ctrl.StorageService.Delete(c.Request.Context(), currentTheme.FaviconURL)
		}
	}

	if err := ctrl.AppService.ResetAppTheme(id); err != nil {
		ctrl.internalErrorHTML(c, "PostAppThemeReset", err, "No se pudo restablecer el tema.")
		return
	}

	audit.Event(c, "app.branding.reset", "app="+id)
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id+"/branding")
}

func (ctrl *ApplicationBrandingController) PostAppUploadLogo(c *gin.Context) {
	ctrl.upload(c, "logo", storage.FolderLogos, "Debe seleccionar un archivo de imagen", "Logo subido exitosamente")
}

func (ctrl *ApplicationBrandingController) PostAppUploadFavicon(c *gin.Context) {
	ctrl.upload(c, "favicon", storage.FolderFavicon, "Debe seleccionar un archivo de icono", "Favicon subido exitosamente")
}

func (ctrl *ApplicationBrandingController) loadEditableApp(c *gin.Context, id string) (model.Application, bool) {
	if id == util.AppIdPeakAuth {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "La aplicación raíz Peak Auth no admite personalización de temas.")
		return model.Application{}, false
	}

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		ctrl.renderError(c, http.StatusNotFound, "No Encontrada", "La aplicación solicitada no existe.")
		return model.Application{}, false
	}

	access, ok := getApplicationAccess(c, app)
	if !ok {
		ctrl.renderError(c, http.StatusUnauthorized, "No autenticado", "La sesión de usuario no es válida.")
		return model.Application{}, false
	}
	if !access.IsRoot && !access.IsOwner {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "Solo el propietario (OWNER) o un administrador ROOT pueden personalizar la apariencia de la aplicación.")
		return model.Application{}, false
	}
	return app, true
}

func (ctrl *ApplicationBrandingController) registrationIsPublic(appID uint) bool {
	if ctrl.RuleService == nil {
		return false
	}
	rules, err := ctrl.RuleService.FindRulesByAppID(appID)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if rule.Code != util.REGISTRATION_POLICY {
			continue
		}
		policy, err := util.ParseRegistrationPolicy(rule.Value)
		if err == nil && policy != nil && policy.Mode == "public" {
			return true
		}
	}
	return false
}

func (ctrl *ApplicationBrandingController) upload(c *gin.Context, field, folder, missingMessage, successMessage string) {
	id := c.Param("id")
	if _, ok := ctrl.loadEditableApp(c, id); !ok {
		return
	}

	currentTheme, _ := ctrl.AppService.GetAppTheme(id)

	url, provided, err := uploadApplicationAsset(c, ctrl.StorageService, field, folder)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !provided {
		c.JSON(http.StatusBadRequest, gin.H{"error": missingMessage})
		return
	}

	if currentTheme != nil && ctrl.StorageService != nil {
		if field == "logo" && currentTheme.LogoURL != "" && currentTheme.LogoURL != url {
			_ = ctrl.StorageService.Delete(c.Request.Context(), currentTheme.LogoURL)
		} else if field == "favicon" && currentTheme.FaviconURL != "" && currentTheme.FaviconURL != url {
			_ = ctrl.StorageService.Delete(c.Request.Context(), currentTheme.FaviconURL)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"url":     url,
		"message": successMessage,
	})
}
