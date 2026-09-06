package controller

import (
	"fmt"
	"log"
	"net/http"
	"peak-auth/internal/util"
	"strconv"

	"github.com/gin-gonic/gin"
)

func parseUserIDFromSubject(sub string) (uint, error) {
	val, err := strconv.ParseUint(sub, 10, 64)
	if err != nil || val == 0 {
		return 0, fmt.Errorf("identificador de usuario inválido en token")
	}
	return uint(val), nil
}

type BaseController struct{}

// setAdminCookie establece la cookie de sesión administrativa con flags seguras centralizadas.
func (ctrl *BaseController) setAdminCookie(c *gin.Context, token string, maxAgeSeconds int) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("admin_token", token, maxAgeSeconds, "/", "", isSecure, true)
}

// clearAdminCookie borra la cookie de sesión administrativa.
func (ctrl *BaseController) clearAdminCookie(c *gin.Context) {
	ctrl.setAdminCookie(c, "", -1)
}

// setMfaCookie establece una cookie temporal HttpOnly para el token pendiente de MFA (5 minutos)
func (ctrl *BaseController) setMfaCookie(c *gin.Context, mfaToken string) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("mfa_pending_token", mfaToken, 300, "/", "", isSecure, true)
}

// clearMfaCookie borra la cookie temporal de MFA
func (ctrl *BaseController) clearMfaCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("mfa_pending_token", "", -1, "/", "", isSecure, true)
}

// extractMfaToken obtiene el token MFA pendiente desde la cookie HttpOnly, el formulario, el query param o cabecera
func (ctrl *BaseController) extractMfaToken(c *gin.Context) string {
	if cookie, err := c.Cookie("mfa_pending_token"); err == nil && cookie != "" {
		return cookie
	}
	if form := c.PostForm("mfa_token"); form != "" {
		return form
	}
	if query := c.Query("mfa_token"); query != "" {
		return query
	}
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// internalErrorJSON loguea el error real (para diagnóstico) y devuelve al cliente
// un mensaje genérico, evitando filtrar detalles internos (GORM, infraestructura).
func internalErrorJSON(c *gin.Context, context string, err error) {
	log.Printf("[error] %s: %v", context, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "ocurrió un error procesando la solicitud"})
}

func (ctrl *BaseController) renderAdmin(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}
	if token, exists := c.Get("csrf_token"); exists {
		data["CSRFToken"] = token
	}

	if data["Title"] == nil {
		data["Title"] = "Panel"
	}

	c.HTML(http.StatusOK, templateName, data)
}

// renderError renderiza la plantilla error.html con el layout admin completo
// (inyecta UserEmail, CSRFToken, Title) y el código de estado HTTP indicado.
func (ctrl *BaseController) renderError(c *gin.Context, status int, title, message string) {
	data := gin.H{
		"Title":   title,
		"Message": message,
	}
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}
	if token, exists := c.Get("csrf_token"); exists {
		data["CSRFToken"] = token
	}
	c.HTML(status, "error.html", data)
}

// internalErrorHTML loguea el error real y muestra una página de error genérica,
// evitando filtrar detalles internos (queries GORM, stack traces, etc.).
func (ctrl *BaseController) internalErrorHTML(c *gin.Context, context string, err error, userMessage string) {
	log.Printf("[error] %s: %v", context, err)
	ctrl.renderError(c, http.StatusInternalServerError, "Error", userMessage)
}
