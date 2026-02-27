package controller

import (
	"net/http"
	"peak-auth/service"

	"github.com/gin-gonic/gin"
)

type AdminController struct {
	UserService service.UserService
	AppService  service.ApplicationService
	RuleService service.ApplicationRuleService
	RoleService service.RoleService
}

func (ctrl *AdminController) Dashboard(c *gin.Context) {
	stats, err := ctrl.AppService.GetDashboardStats()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
		return
	}
	c.HTML(200, "dashboard.html", gin.H{
		"Applications": stats,
		"UserEmail":    "root@local",
	})
}

func (ctrl *AdminController) GetFormApp(c *gin.Context) {
	c.HTML(http.StatusOK, "apps_new.html", nil)
}

func (ctrl *AdminController) PostFormApp(c *gin.Context) {
	name := c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	if name == "" {
		c.String(http.StatusBadRequest, "name requerido")
		return
	}

	app, plainSecret, err := ctrl.AppService.CreateApp(name, description, isActive)
	if err != nil {
		c.String(500, "Error creando app: %v", err)
		return
	}
	c.HTML(http.StatusOK, "app_created.html", gin.H{"App": app, "PlainSecret": plainSecret})
}

func (ctrl *AdminController) GetLoginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func (ctrl *AdminController) PostLoginForm(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	token, err := ctrl.UserService.AdminLogin(email, password)
	if err != nil {
		c.String(http.StatusUnauthorized, err.Error())
		return
	}

	c.SetCookie("admin_token", token, 12*3600, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin")

}

func (ctrl *AdminController) PostLogout(c *gin.Context) {
	c.SetCookie("admin_token", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

func (ctrl *AdminController) GetApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	c.HTML(http.StatusOK, "app_show.html", gin.H{"App": app})
}

func (ctrl *AdminController) GetAppUsers(c *gin.Context) {
	appIDParam := c.Param("id")

	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		c.String(http.StatusNotFound, "Aplicación no encontrada")
		return
	}

	users, err := ctrl.UserService.FindUserByAppID(appIDParam)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error al cargar los usuarios")
		return
	}

	roles, err := ctrl.RoleService.FindAll()
	if err != nil {
		c.String(http.StatusInternalServerError, "Error al cargar los roles")
		return
	}

	c.HTML(http.StatusOK, "app_users.html", gin.H{
		"App":   app,
		"Users": users,
		"Roles": roles,
	})
}

func (ctrl *AdminController) PostUsersInApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	email := c.PostForm("email")
	role := c.PostForm("role")
	if email == "" || role == "" {
		c.String(http.StatusBadRequest, "email y role requeridos")
		return
	}
	if err := ctrl.AppService.RegisterUserInApp(email, app.AppID, role); err != nil {
		c.String(http.StatusInternalServerError, "error registrando usuario en app: %v", err)
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+c.Param("id")+"/users")
}

func (ctrl *AdminController) GetAppRules(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)

	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	rules, err := ctrl.RuleService.FindRulesByAppID(app.ID)
	if err != nil {
		c.String(http.StatusInternalServerError, "error obteniendo reglas: %v", err)
		return
	}

	c.HTML(http.StatusOK, "app_rules.html", gin.H{"App": app, "Rules": rules})

}

func (ctrl *AdminController) PostDefaultRules(c *gin.Context) {
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
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+c.Param("id")+"/rules")

}

func (ctrl *AdminController) PostRole(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre de rol requerido"})
		return
	}

	// Usar el servicio para crear el rol
	err := ctrl.RoleService.CreateRole(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol creado con éxito"})
}
