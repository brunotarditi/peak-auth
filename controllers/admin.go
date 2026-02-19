package controllers

import (
	"net/http"
	"peak-auth/services"

	"github.com/gin-gonic/gin"
)

type AdminController struct {
	UserService services.UserService
	AppService  services.ApplicationService
	RuleService services.ApplicationRuleService
}

// Obtener dashboard con info
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

// Obtener form para nueva app
func (ctrl *AdminController) GetFormApp(c *gin.Context) {
	c.HTML(http.StatusOK, "apps_new.html", nil)
}

// Crear nueva app
func (ctrl *AdminController) PostFormApp(c *gin.Context) {
	name := c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	if name == "" {
		c.String(http.StatusBadRequest, "name requerido")
		return
	}

	_, err := ctrl.AppService.CreateApp(name, description, isActive)
	if err != nil {
		c.String(500, "Error creando app: %v", err)
		return
	}
	c.Redirect(303, "/admin")
}

// GET Login admin (formulario)
func (ctrl *AdminController) GetLoginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/login.html", nil)
}

// POST login admin: reuse the form (email/password)
func (ctrl *AdminController) PostLoginForm(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	// El servicio se encarga de: buscar user, verificar hash, chequear rol ROOT
	token, err := ctrl.UserService.AdminLogin(email, password)
	if err != nil {
		c.String(http.StatusUnauthorized, err.Error())
		return
	}

	// El controlador solo se encarga de la parte web (Cookies y Redirects)
	c.SetCookie("admin_token", token, 12*3600, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin")

}

// Logout POST
func (ctrl *AdminController) PostLogout(c *gin.Context) {
	// borrar cookie
	c.SetCookie("admin_token", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// Mostrar app
func (ctrl *AdminController) GetApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	c.HTML(http.StatusOK, "app_show.html", gin.H{"App": app})
}

// Usuarios de la app: mostrar los usuarios de cada app
func (ctrl *AdminController) GetAppUsers(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	users, err := ctrl.UserService.FindUserByAppID(id)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to load users")
		return
	}
	c.HTML(http.StatusOK, "admin/app_users.html", gin.H{"App": app, "Users": users})
}

// Usuarios de la app: formulario para registrar usuario en app
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

// Reglas de la app
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

// Crear reglas por defecto
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
