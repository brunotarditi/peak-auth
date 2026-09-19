package controller

import (
	"fmt"
	"log"
	"net/http"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func parseUserIDFromSubject(sub string) (uint, error) {
	val, err := strconv.ParseUint(sub, 10, strconv.IntSize)
	if err != nil || val == 0 {
		return 0, fmt.Errorf("identificador de usuario inválido en token")
	}
	return uint(val), nil
}

// sanitizeForLogging removes control characters (including newlines and carriage returns)
// from user input to prevent log injection attacks.
func sanitizeForLogging(input string) string {
	return strings.Map(func(r rune) rune {
		// Remove control characters (0x00-0x1F) and DEL (0x7F)
		if r < 0x20 || r == 0x7F {
			return -1 // Drop character
		}
		return r
	}, input)
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

// setMfaTransactionCookie establece una cookie con el transaction ID opaco (no el JWT)
func (ctrl *BaseController) setMfaTransactionCookie(c *gin.Context, transactionID string) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("mfa_txn_id", transactionID, 300, "/", "", isSecure, true)
}

// clearMfaTransactionCookie borra la cookie de transaction ID
func (ctrl *BaseController) clearMfaTransactionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("mfa_txn_id", "", -1, "/", "", isSecure, true)
}

// getMfaSessionIdentifier returns a stable session identifier for binding MFA transactions to the browser
func (ctrl *BaseController) getMfaSessionIdentifier(c *gin.Context) string {
	// Use a combination of factors to create a stable session identifier
	// This binds the MFA transaction to the specific browser session
	return c.ClientIP() + "|" + c.GetHeader("User-Agent")
}

// extractMfaToken obtiene el token MFA pendiente desde la cookie HttpOnly, el formulario o la cabecera Authorization (evitando URLs/query params por seguridad)
func (ctrl *BaseController) extractMfaToken(c *gin.Context) string {
	if cookie, err := c.Cookie("mfa_pending_token"); err == nil && cookie != "" {
		return cookie
	}
	if form := c.PostForm("mfa_token"); form != "" {
		return form
	}
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

// extractMfaTransactionID obtiene el transaction ID desde la cookie
func (ctrl *BaseController) extractMfaTransactionID(c *gin.Context) string {
	if cookie, err := c.Cookie("mfa_txn_id"); err == nil && cookie != "" {
		return cookie
	}
	return ""
}

// getMfaTransactionFromCookie retrieves and validates the MFA transaction from the cookie
func (ctrl *BaseController) getMfaTransactionFromCookie(c *gin.Context) (*service.MfaTransaction, error) {
	transactionID := ctrl.extractMfaTransactionID(c)
	if transactionID == "" {
		return nil, fmt.Errorf("no se encontró transaction ID de MFA")
	}

	sessionID := ctrl.getMfaSessionIdentifier(c)
	txn, err := service.GetMfaTransaction(transactionID, sessionID)
	if err != nil {
		return nil, err
	}

	return txn, nil
}

// setNoCacheHeaders sets Cache-Control headers to prevent caching of sensitive MFA pages
func (ctrl *BaseController) setNoCacheHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
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
