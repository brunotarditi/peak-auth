package controller

import (
	"fmt"
	"net/http"
	"peak-auth/internal/service"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

type UserController struct {
	BaseController
	UserService service.UserService
	AppService  service.ApplicationService
	RuleService service.ApplicationRuleService
	RoleService service.RoleService
}

// GetResetPassword muestra el formulario de cambio de contraseña
func (c *UserController) GetResetPassword(ctx *gin.Context) {
	token := ctx.Query("token")
	if token == "" {
		ctx.String(400, "Token requerido")
		return
	}

	// Renderizamos el template de reset-password
	ctx.HTML(200, "reset_password.html", gin.H{
		"token": token,
	})
}

// PostResetPassword procesa el cambio de contraseña
func (c *UserController) PostResetPassword(ctx *gin.Context) {
	token := ctx.PostForm("token")
	password := ctx.PostForm("password")
	confirm := ctx.PostForm("confirm_password")

	if token == "" || password == "" {
		ctx.String(http.StatusBadRequest, "El token y la contraseña son requeridos")
		return
	}

	if password != confirm {
		ctx.String(http.StatusBadRequest, "Las contraseñas no coinciden")
		return
	}

	if err := c.UserService.ResetPassword(token, password); err != nil {
		ctx.String(http.StatusBadRequest, err.Error())
		return
	}

	ctx.String(http.StatusOK, "Contraseña actualizada. Ya puedes iniciar sesión en tu aplicación.")
}

// Refresh maneja la renovación de tokens vía refresh token
func (c *UserController) Refresh(ctx *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": "Refresh token es requerido"})
		return
	}

	resp, err := c.UserService.Refresh(req.RefreshToken)
	if err != nil {
		ctx.JSON(401, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(200, resp)
}

// RevokeUserAccess revoca el acceso de un usuario a una aplicación
func (ctrl *UserController) RevokeUserAccess(c *gin.Context) {
	appIDParam := c.Param("id")
	userIDParam := c.Param("user_id")

	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	var userID uint
	if _, err := fmt.Sscanf(userIDParam, "%d", &userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de usuario inválido"})
		return
	}

	if err := ctrl.AppService.RevokeUserFromApp(userID, app.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Acceso revocado"})
}

// GetAppUsers muestra los usuarios de una aplicación
func (ctrl *UserController) GetAppUsers(c *gin.Context) {
	appIDParam := c.Param("id")

	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		c.String(http.StatusNotFound, "Aplicación no encontrada")
		return
	}

	pageStr := c.DefaultQuery("page", "1")
	var page int
	if _, err := fmt.Sscanf(pageStr, "%d", &page); err != nil || page < 1 {
		page = 1
	}
	limit := 10

	users, total, err := ctrl.UserService.FindUserByAppIDPaginated(appIDParam, page, limit)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error al cargar los usuarios")
		return
	}

	roles, err := ctrl.RoleService.FindAll()
	if err != nil {
		c.String(http.StatusInternalServerError, "Error al cargar los roles")
		return
	}

	rules, _ := ctrl.RuleService.FindRulesByAppID(app.ID)
	maxFailedLogins := 5
	for _, r := range rules {
		if r.Code == "SESSION_POLICY" {
			if sess, err := util.ParseSessionPolicy(r.Value); err == nil && sess.MaxFailedLogins > 0 {
				maxFailedLogins = sess.MaxFailedLogins
			}
		}
	}

	totalPages := int((total + int64(limit) - 1) / int64(limit))
	if totalPages < 1 {
		totalPages = 1
	}

	pagesSlice := make([]int, totalPages)
	for i := 0; i < totalPages; i++ {
		pagesSlice[i] = i + 1
	}

	nextPg := page + 1
	if nextPg > totalPages {
		nextPg = totalPages
	}
	prevPg := page - 1
	if prevPg < 1 {
		prevPg = 1
	}

	ctrl.renderAdmin(c, "users.html", gin.H{
		"App":             app,
		"Users":           users,
		"TotalCount":      total,
		"CurrentPg":       page,
		"TotalPages":      totalPages,
		"NextPg":          nextPg,
		"PrevPg":          prevPg,
		"Pages":           pagesSlice,
		"Roles":           roles,
		"MaxFailedLogins": maxFailedLogins,
		"Breadcrumbs": []gin.H{
			{"Label": app.Name, "URL": "/admin/apps/" + app.AppID},
			{"Label": "Usuarios"},
		},
		"Title": "Usuarios - " + app.Name,
	})
}

// PostUnlockUser resetea el contador de intentos fallidos de los usuarios bloqueados
func (ctrl *UserController) PostUnlockUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	var userID uint
	fmt.Sscanf(userIDStr, "%d", &userID)

	if err := ctrl.UserService.UnlockUser(userID); err != nil {
		c.JSON(500, gin.H{"error": "No se pudo desbloquear al usuario"})
		return
	}

	c.JSON(200, gin.H{"message": "Usuario desbloqueado correctamente"})
}
