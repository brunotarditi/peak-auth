package main

import (
	"peak-auth/app"
	"peak-auth/controller"
	"peak-auth/middleware"

	"github.com/gin-gonic/gin"
)

// SetupRoutes registra las rutas del servidor en el router Gin proporcionado.
func SetRoutes(r *gin.Engine, app *app.App) {

	r.Static("/static", "./static")

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

	// --- SETUP & USER ACTIONS (Raíz) ---
	r.GET("/setup", setupCtrl.ShowSetup)
	r.POST("/setup", setupCtrl.ProcessSetup)
	r.GET("/verify", userCtrl.GetVerifyEmail)
	r.GET("/reset-password", userCtrl.GetResetPassword)
	r.POST("/reset-password", userCtrl.PostResetPassword)

	// --- API V1 (Para integraciones externas) ---
	api := r.Group("/api/v1")
	{
		api.POST("/login", userCtrl.Login)
		api.POST("/register", userCtrl.Register)
		api.POST("/refresh", userCtrl.Refresh)
	}

	// --- RUTAS PÚBLICAS DE ADMINISTRACIÓN ---
	adminPublic := r.Group("/admin")
	{
		adminPublic.GET("/login", adminCtrl.GetLoginForm)
		adminPublic.POST("/login", adminCtrl.PostLoginForm)

		// El setup también es accesible desde /admin/setup
		adminPublic.GET("/setup", setupCtrl.ShowSetup)
		adminPublic.POST("/setup", setupCtrl.ProcessSetup)
	}

	// --- RUTAS PROTEGIDAS DE ADMINISTRACIÓN ---
	adminPrivate := r.Group("/admin")
	adminPrivate.Use(middleware.SecurityHeaderMiddleware())
	adminPrivate.Use(middleware.AuthMiddleware(app.TokenManager))
	{
		adminPrivate.GET("/", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.Dashboard)
		adminPrivate.POST("/logout", adminCtrl.PostLogout)

		// Gestión de Apps
		adminPrivate.GET("/apps/new", adminCtrl.GetFormApp)
		adminPrivate.POST("/apps", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostFormApp)
		adminPrivate.GET("/apps/:id", adminCtrl.GetAppDetails)
		adminPrivate.GET("/apps/:id/edit", adminCtrl.GetEditApp)
		adminPrivate.POST("/apps/:id", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.UpdateFormApp)
		adminPrivate.POST("/apps/:id/delete", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT"), adminCtrl.PostDeleteApp)

		// Gestión de Roles
		adminPrivate.POST("/roles", adminCtrl.PostRole)
		adminPrivate.DELETE("/roles", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.DeleteRole)

		// Gestión de Usuarios por App
		apps := adminPrivate.Group("/apps/:id")
		{
			apps.GET("/users", adminCtrl.GetAppUsers)
			apps.POST("/users", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostUsersInApp)
			apps.DELETE("/users/:user_id", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.RevokeUserAccess)
			apps.POST("/users/:user_id/unlock", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostUnlockUser)
			apps.POST("/users/:user_id/resend-verification", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostResendVerification)
			apps.POST("/users/:user_id/send-reset", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostSendResetPassword)
			apps.GET("/rules", adminCtrl.GetAppRules)
			apps.POST("/rules", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostDefaultRules)
			apps.POST("/rules/:code", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostAppRule)
			apps.PUT("/rules/:code", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PutAppRule)
			apps.DELETE("/rules/:code", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.DeleteAppRule)
			apps.POST("/secret", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), adminCtrl.PostRegenerateSecret)
		}
	}

}
