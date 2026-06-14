package main

import (
	"peak-auth/internal/api/controller"
	"peak-auth/internal/api/middleware"
	"peak-auth/internal/app"

	"github.com/gin-gonic/gin"
)

// SetupRoutes registra las rutas del servidor en el router Gin proporcionado.
func SetRoutes(r *gin.Engine, app *app.App) {

	r.Static("/static", "./web/static")

	//Inicializamos los controladores con las dependencias necesarias
	userCtrl := &controller.UserController{
		AppService:  app.AppService,
		UserService: app.UserService,
		RuleService: app.RuleService,
		RoleService: app.RoleService,
	}

	setupCtrl := &controller.SetupController{
		SetupService: app.SetupService,
		TokenManager: app.TokenManager,
	}

	dashboardCtrl := &controller.DashboardController{
		AppService:  app.AppService,
		UserService: app.UserService,
	}

	appCtrl := &controller.ApplicationController{
		AppService:  app.AppService,
		UserService: app.UserService,
		RuleService: app.RuleService,
		RoleService: app.RoleService,
	}

	loginCtrl := &controller.LoginController{
		UserService: app.UserService,
	}

	registerCtrl := &controller.RegisterController{
		UserService: app.UserService,
		AppService:  app.AppService,
	}

	roleCtrl := &controller.RoleController{
		RoleService: app.RoleService,
	}

	ruleCtrl := &controller.RuleController{
		RuleService: app.RuleService,
		AppService:  app.AppService,
	}

	// --- SETUP & USER ACTIONS (App inicial) ---
	r.GET("/setup", setupCtrl.ShowSetup)
	r.POST("/setup", setupCtrl.ProcessSetup)
	r.GET("/verify", registerCtrl.GetVerifyEmail)
	r.GET("/reset-password", userCtrl.GetResetPassword)
	r.POST("/reset-password", userCtrl.PostResetPassword)

	// --- API V1 (Para integraciones externas) ---
	api := r.Group("/api/v1")
	{
		api.POST("/login", loginCtrl.Login)
		api.POST("/register", registerCtrl.Register)
		api.POST("/refresh", userCtrl.Refresh)
	}

	// --- RUTAS PÚBLICAS DE ADMINISTRACIÓN ---
	adminPublic := r.Group("/admin")
	{
		adminPublic.GET("/login", loginCtrl.GetLoginForm)
		adminPublic.POST("/login", loginCtrl.PostLoginForm)

		// El setup también es accesible desde /admin/setup
		adminPublic.GET("/setup", setupCtrl.ShowSetup)
		adminPublic.POST("/setup", setupCtrl.ProcessSetup)
	}

	// --- RUTAS PROTEGIDAS DE ADMINISTRACIÓN ---
	adminPrivate := r.Group("/admin")
	adminPrivate.Use(middleware.SecurityHeaderMiddleware())
	adminPrivate.Use(middleware.AuthMiddleware(app.TokenManager))
	{
		adminPrivate.GET("/", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), dashboardCtrl.Dashboard)
		adminPrivate.POST("/logout", loginCtrl.PostLogout)

		// Gestión de Apps
		adminPrivate.GET("/apps/new", appCtrl.GetFormApp)
		adminPrivate.POST("/apps", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), appCtrl.PostFormApp)
		adminPrivate.GET("/apps/:id", appCtrl.GetAppDetails)
		adminPrivate.GET("/apps/:id/edit", appCtrl.GetEditApp)
		adminPrivate.POST("/apps/:id", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), appCtrl.UpdateFormApp)
		adminPrivate.POST("/apps/:id/delete", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT"), appCtrl.PostDeleteApp)

		// Gestión de Roles
		adminPrivate.POST("/roles", roleCtrl.PostRole)
		adminPrivate.DELETE("/roles", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), roleCtrl.DeleteRole)

		// Gestión de Usuarios por App
		apps := adminPrivate.Group("/apps/:id")
		{
			apps.GET("/users", userCtrl.GetAppUsers)
			apps.POST("/users", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), registerCtrl.PostUsersInApp)
			apps.DELETE("/users/:user_id", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), userCtrl.RevokeUserAccess)
			apps.POST("/users/:user_id/unlock", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), userCtrl.PostUnlockUser)
			apps.POST("/users/:user_id/resend-verification", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), dashboardCtrl.PostResendVerification)
			apps.POST("/users/:user_id/send-reset", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), dashboardCtrl.PostSendResetPassword)
			apps.GET("/rules", appCtrl.GetAppRules)
			apps.POST("/rules", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), ruleCtrl.PostDefaultRules)
			apps.POST("/rules/:code", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), ruleCtrl.PostAppRule)
			apps.PUT("/rules/:code", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), ruleCtrl.PutAppRule)
			apps.DELETE("/rules/:code", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), ruleCtrl.DeleteAppRule)
			apps.POST("/secret", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ROOT", "ADMIN"), appCtrl.PostRegenerateSecret)
		}
	}

}
