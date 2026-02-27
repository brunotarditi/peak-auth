package main

import (
	"peak-auth/app"
	"peak-auth/controller"
	"peak-auth/middleware"

	"github.com/gin-gonic/gin"
)

// SetupRoutes registra las rutas del servidor en el router Gin proporcionado.
func SetupRoutes(r *gin.Engine, app *app.App) {

	userCtrl := &controller.UserController{
		UserService: app.UserService,
	}

	setupCtrl := &controller.SetupController{
		SetupService: app.SetupService,
		TokenManager: app.TokenManager,
	}

	adminCtrl := &controller.AdminController{
		AppService:  app.AppService,
		UserService: app.UserService,
		RuleService: app.RuleService,
		RoleService: app.RoleService,
	}

	// --- SETUP ---
	r.GET("/setup", setupCtrl.ShowSetup)
	r.POST("/setup", setupCtrl.ProcessSetup)

	// --- API V1 ---
	api := r.Group("/api/v1")
	{
		api.POST("/login", userCtrl.Login)
		api.POST("/register", userCtrl.Register)
	}

	// --- RUTAS PÚBLICAS DE ADMINISTRACIÓN ---
	adminPublic := r.Group("/admin")
	{
		adminPublic.GET("/login", adminCtrl.GetLoginForm)
		adminPublic.POST("/login", adminCtrl.PostLoginForm)

		// El setup también es "público" porque se autoprotege con su propio token efímero
		adminPublic.GET("/setup", setupCtrl.ShowSetup)
		adminPublic.POST("/setup", setupCtrl.ProcessSetup)
	}

	// --- RUTAS PROTEGIDAS DE ADMINISTRACIÓN ---
	adminPrivate := r.Group("/admin")
	adminPrivate.Use(middleware.AuthMiddleware(app.TokenManager))
	{
		adminPrivate.GET("/", adminCtrl.Dashboard)
		adminPrivate.POST("/logout", adminCtrl.PostLogout)

		// Gestión de Apps
		adminPrivate.GET("/apps/new", adminCtrl.GetFormApp)
		adminPrivate.POST("/apps", middleware.RoleMiddleware(app.UarRepo, "ROOT", "ADMIN"), adminCtrl.PostFormApp)

		// Gestión de Roles
		adminPrivate.POST("/roles", adminCtrl.PostRole)

		// Gestión de Usuarios por App
		apps := adminPrivate.Group("/apps/:id")
		{
			apps.GET("/users", adminCtrl.GetAppUsers)
			apps.POST("/users", middleware.RoleMiddleware(app.UarRepo, "ROOT", "ADMIN"), adminCtrl.PostUsersInApp)
			apps.GET("/rules", adminCtrl.GetAppRules)
			apps.POST("/rules", middleware.RoleMiddleware(app.UarRepo, "ROOT", "ADMIN"), adminCtrl.PostDefaultRules)
		}
	}

}
