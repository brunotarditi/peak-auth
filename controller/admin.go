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

func (ctrl *AdminController) renderAdmin(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	// Obtener el email del contexto (puesto por el middleware)
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}

	if data["Title"] == nil {
		data["Title"] = "Panel"
	}

	c.HTML(http.StatusOK, templateName, data)
}

func (ctrl *AdminController) Dashboard(c *gin.Context) {
	stats, err := ctrl.AppService.GetDashboardStats()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
		return
	}
	ctrl.renderAdmin(c, "dashboard.html", gin.H{
		"Applications": stats,
		"Breadcrumbs":  nil,
		"Title":        "Dashboard",
	})
}

func (ctrl *AdminController) GetFormApp(c *gin.Context) {
	ctrl.renderAdmin(c, "apps_new.html", gin.H{
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva Aplicación"}},
		"Title":       "Nueva Aplicación",
	})
}

func (ctrl *AdminController) GetEditApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "App no encontrada")
		return
	}
	ctrl.renderAdmin(c, "apps_new.html", gin.H{
		"App":         app,
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": app.Name, "URL": "/admin/apps/" + app.AppID}, {"Label": "Editar"}},
		"Title":       "Editar " + app.Name,
	})
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
	ctrl.renderAdmin(c, "app_created.html", gin.H{
		"App":         app,
		"PlainSecret": plainSecret,
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva Aplicación"}, {"Label": "Creada"}},
		"Title":       "Aplicación Creada",
	})
}

func (ctrl *AdminController) PostUpdateApp(c *gin.Context) {
	id := c.Param("id")
	name := c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	if name == "" {
		c.String(http.StatusBadRequest, "name requerido")
		return
	}

	err := ctrl.AppService.UpdateApp(id, name, description, isActive)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error actualizando app: %v", err)
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
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
	rules, _ := ctrl.RuleService.FindRulesByAppID(app.ID)
	users, _ := ctrl.UserService.FindUserByAppID(id)

	ctrl.renderAdmin(c, "app_show.html", gin.H{
		"App":       app,
		"Rules":     rules,
		"UserCount": len(users),
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name},
		},
		"Title": app.Name,
	})
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

	ctrl.renderAdmin(c, "app_users.html", gin.H{
		"App":   app,
		"Users": users,
		"Roles": roles,
		"Breadcrumbs": []gin.H{
			{"Label": app.Name, "URL": "/admin/apps/" + app.AppID},
			{"Label": "Usuarios"},
		},
		"Title": "Usuarios - " + app.Name,
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
	c.Redirect(http.StatusMovedPermanently, "/admin/apps/"+id)
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
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
}

func (ctrl *AdminController) PostRegenerateSecret(c *gin.Context) {
	id := c.Param("id")
	plainSecret, err := ctrl.AppService.RegenerateSecret(id)
	if err != nil {
		c.String(http.StatusInternalServerError, "error regenerando secreto: %v", err)
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
