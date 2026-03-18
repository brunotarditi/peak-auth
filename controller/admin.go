package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"peak-auth/response"
	"peak-auth/service"
	"peak-auth/utils"

	"github.com/gin-gonic/gin"
)

// AdminController struct
type AdminController struct {
	UserService service.UserService
	AppService  service.ApplicationService
	RuleService service.ApplicationRuleService
	RoleService service.RoleService
}

// Dashboard renderiza el dashboard
func (ctrl *AdminController) Dashboard(c *gin.Context) {
	isRoot, _ := c.Get("is_root")
	rootStatus, _ := isRoot.(bool)
	valUser, _ := c.Get("user_id")
	userID, _ := valUser.(uint)

	var stats []response.AppStatsResponse
	var err error

	if rootStatus {
		// ROOT ve todo
		stats, err = ctrl.AppService.GetDashboardStats()
	} else {
		// Admin local solo ve sus apps
		stats, err = ctrl.AppService.GetDashboardStatsForUser(userID)
	}

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

// GetFormApp renderiza el formulario de creación de aplicación
func (ctrl *AdminController) GetFormApp(c *gin.Context) {
	ctrl.renderAdmin(c, "app_new.html", gin.H{
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": "Nueva Aplicación"}},
		"Title":       "Nueva Aplicación",
	})
}

// GetEditApp renderiza el formulario de edición de aplicación
func (ctrl *AdminController) GetEditApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "App no encontrada")
		return
	}
	ctrl.renderAdmin(c, "app_new.html", gin.H{
		"App":         app,
		"Breadcrumbs": []gin.H{{"Label": "Apps", "URL": "/admin"}, {"Label": app.Name, "URL": "/admin/apps/" + app.AppID}, {"Label": "Editar"}},
		"Title":       "Editar " + app.Name,
	})
}

// PostFormApp crea una nueva aplicación
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

	// Crear las reglas por defecto (Starter Pack) para la app recién nacida
	if err := ctrl.RuleService.CreateDefaultRules(app.ID); err != nil {
		// Log error pero continuamos
		c.String(500, "App creada pero error generando políticas base: %v", err)
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
func (ctrl *AdminController) UpdateFormApp(c *gin.Context) {
	id := c.Param("id")
	name := c.PostForm("name")
	description := c.PostForm("description")
	isActive := c.PostForm("is_active") == "on"

	if name == "" {
		c.String(http.StatusBadRequest, "Nombre requerido")
		return
	}

	// Si desactivan el check de la raíz, no lo permitimos
	if !isActive && id == "peak-auth-raiz" {
		c.String(http.StatusBadRequest, "La aplicación principal (Peak Auth Raíz) no puede ser desactivada")
		return
	}

	err := ctrl.AppService.UpdateApp(id, name, description, isActive)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error actualizando app: %v", err)
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin/apps/"+id)
}

// PostDeleteApp maneja la eliminación real (lógica) de una aplicación desde la zona de peligro
func (ctrl *AdminController) PostDeleteApp(c *gin.Context) {
	id := c.Param("id")

	// No permitimos borrar la App Maestra
	if id == "peak-auth-raiz" {
		c.String(http.StatusBadRequest, "La aplicación principal (Peak Auth Raíz) no puede ser eliminada")
		return
	}

	// Solo ROOT puede eliminar (capa extra de seguridad por si acaso a pesar del middleware)
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
		c.String(http.StatusInternalServerError, "Error eliminando app: %v", err)
		return
	}
	
	// Redirigir al dashboard principal porque la app ya no existe a la vista
	c.Redirect(http.StatusSeeOther, "/admin")
}


// GetLoginForm renderiza el formulario de login
func (ctrl *AdminController) GetLoginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

// PostLoginForm procesa el login
func (ctrl *AdminController) PostLoginForm(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	token, err := ctrl.UserService.AdminLogin(email, password)
	if err != nil {
		c.String(http.StatusUnauthorized, err.Error())
		return
	}

	// Configuración de cookie segura
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := os.Getenv("ENV") == "production"

	c.SetCookie("admin_token", token, 12*3600, "/", "", isSecure, true)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// PostLogout cierra la sesión
func (ctrl *AdminController) PostLogout(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("admin_token", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// GetAppDetails muestra los detalles de una aplicación
func (ctrl *AdminController) GetAppDetails(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.String(http.StatusNotFound, "app no encontrada: %v", err)
		return
	}
	rules, _ := ctrl.RuleService.FindRulesByAppID(app.ID)
	users, _ := ctrl.UserService.FindUserByAppID(id)
	roles, _ := ctrl.RoleService.FindAll()

	// Pre-procesar reglas para la vista
	var regPolicy *utils.RegistrationPolicy
	var pwdPolicy *utils.PasswordPolicy
	var sessionPolicy *utils.SessionPolicy
	var authzPolicy *utils.AuthzPolicy

	for _, r := range rules {
		switch r.Code {
		case "REGISTRATION_POLICY":
			regPolicy, _ = utils.ParseRegistrationPolicy(r.Value)
		case "PWD_POLICY":
			var p utils.PasswordPolicy
			if err := json.Unmarshal(r.Value, &p); err == nil {
				pwdPolicy = &p
			}
		case "SESSION_POLICY":
			sessionPolicy, _ = utils.ParseSessionPolicy(r.Value)
		case "AUTHZ_POLICY":
			authzPolicy, _ = utils.ParseAuthzPolicy(r.Value)
		}
	}

	ctrl.renderAdmin(c, "app_show.html", gin.H{
		"App":            app,
		"Rules":          rules,
		"RegPolicy":      regPolicy,
		"PwdPolicy":      pwdPolicy,
		"SessionPolicy":  sessionPolicy,
		"AuthzPolicy":    authzPolicy,
		"UserCount":      len(users),
		"Roles":          roles,
		"Breadcrumbs": []gin.H{
			{"Label": "Apps", "URL": "/admin"},
			{"Label": app.Name},
		},
		"Title": app.Name,
	})
}


// GetAppUsers muestra los usuarios de una aplicación
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

// PostUsersInApp registra un usuario en una aplicación
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

// GetAppRules redirige a los detalles de la aplicación
func (ctrl *AdminController) GetAppRules(c *gin.Context) {
	id := c.Param("id")
	c.Redirect(http.StatusMovedPermanently, "/admin/apps/"+id)
}

// PostDefaultRules crea las reglas por defecto para una aplicación
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

// PostRegenerateSecret regenera el secreto de una aplicación
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

// PostRole crea un nuevo rol
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

// --- GESTIÓN DE REGLAS VÍA API AJAX ---

// PostAppRule (Crea nueva regla)
func (ctrl *AdminController) PostAppRule(c *gin.Context) {
	id := c.Param("id")
	code := c.Param("code")

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error leyendo el JSON"})
		return
	}

	err = ctrl.RuleService.CreateRule(app.ID, code, body)
	if err != nil {
		// Asumiendo que si el error es de gorm duplicado, devolvemos un 409
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Regla creada exitosamente"})
}

// PutAppRule (Actualiza valor JSON de regla existente)
func (ctrl *AdminController) PutAppRule(c *gin.Context) {
	id := c.Param("id")
	code := c.Param("code")

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error leyendo el JSON"})
		return
	}

	err = ctrl.RuleService.UpdateRuleValue(app.ID, code, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Regla actualizada correctamente"})
}

// DeleteAppRule (Desactiva regla lógica)
func (ctrl *AdminController) DeleteAppRule(c *gin.Context) {
	id := c.Param("id")
	code := c.Param("code")

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	err = ctrl.RuleService.DeleteRule(app.ID, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Regla eliminada"})
}


// renderAdmin renderiza la plantilla de administración
func (ctrl *AdminController) renderAdmin(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}

	if data["Title"] == nil {
		data["Title"] = "Panel"
	}

	c.HTML(http.StatusOK, templateName, data)
}
