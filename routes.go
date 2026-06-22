package main

import (
	"time"

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
		AppService:  app.AppService,
	}

	ruleCtrl := &controller.RuleController{
		RuleService: app.RuleService,
		AppService:  app.AppService,
	}

	docsCtrl := &controller.DocsController{}

	// --- SETUP & USER ACTIONS (App inicial) ---
	// Limitadores por IP para mitigar fuerza bruta en endpoints sensibles.
	// (También protege cuentas privilegiadas como ROOT, que no se bloquean por diseño.)
	loginLimiter := middleware.RateLimitMiddleware(10, time.Minute)
	resetLimiter := middleware.RateLimitMiddleware(5, time.Minute)

	// Estas rutas también usan protección CSRF (double-submit cookie).
	r.GET("/setup", middleware.AdminCSRFMiddleware(), setupCtrl.ShowSetup)
	r.POST("/setup", middleware.AdminCSRFMiddleware(), setupCtrl.ProcessSetup)
	r.GET("/verify", registerCtrl.GetVerifyEmail)
	r.GET("/reset-password", middleware.AdminCSRFMiddleware(), userCtrl.GetResetPassword)
	r.POST("/reset-password", resetLimiter, middleware.AdminCSRFMiddleware(), userCtrl.PostResetPassword)

	// --- API V1 (Para integraciones externas) ---
	api := r.Group("/api/v1")
	api.Use(middleware.CORSMiddleware())
	{
		api.POST("/login", loginLimiter, loginCtrl.Login)
		api.POST("/register", loginLimiter, middleware.AppAuthMiddleware(app.AppRepo), registerCtrl.Register)
		api.POST("/refresh", loginLimiter, userCtrl.Refresh)
	}

	// --- RUTAS PÚBLICAS DE ADMINISTRACIÓN ---
	adminPublic := r.Group("/admin")
	adminPublic.Use(middleware.AdminCSRFMiddleware())
	{
		adminPublic.GET("/login", loginCtrl.GetLoginForm)
		adminPublic.POST("/login", loginLimiter, loginCtrl.PostLoginForm)

		// El setup también es accesible desde /admin/setup
		adminPublic.GET("/setup", setupCtrl.ShowSetup)
		adminPublic.POST("/setup", setupCtrl.ProcessSetup)
	}

	// --- RUTAS PROTEGIDAS DE ADMINISTRACIÓN ---
	adminPrivate := r.Group("/admin")
	adminPrivate.Use(middleware.SecurityHeaderMiddleware())
	adminPrivate.Use(middleware.AdminCSRFMiddleware())
	adminPrivate.Use(middleware.AuthMiddleware(app.TokenManager))
	{
		adminPrivate.GET("/", dashboardCtrl.Dashboard)
		adminPrivate.POST("/logout", loginCtrl.PostLogout)

		// Gestión de Apps (crear/listar = solo plataforma)
		adminPrivate.GET("/apps/new", middleware.PlatformAdminMiddleware(app.UarRepo, app.AppRepo), appCtrl.GetFormApp)
		adminPrivate.POST("/apps", middleware.PlatformAdminMiddleware(app.UarRepo, app.AppRepo), appCtrl.PostFormApp)

		// Documentación
		adminPrivate.GET("/docs", docsCtrl.ShowDocs)
		adminPrivate.GET("/docs/api", docsCtrl.ShowAPI)

		// Detalle/edición de una app: requiere ser admin de ESA app (o plataforma)
		adminPrivate.GET("/apps/:id", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ADMIN"), appCtrl.GetAppDetails)
		adminPrivate.GET("/apps/:id/edit", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ADMIN"), appCtrl.GetEditApp)
		adminPrivate.POST("/apps/:id", middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ADMIN"), appCtrl.UpdateFormApp)
		adminPrivate.POST("/apps/:id/delete", middleware.RootOnlyMiddleware(app.UarRepo, app.AppRepo), appCtrl.PostDeleteApp)

		// Gestión de Roles GLOBALES del sistema (solo plataforma)
		adminPrivate.POST("/roles", middleware.PlatformAdminMiddleware(app.UarRepo, app.AppRepo), roleCtrl.PostRole)
		adminPrivate.DELETE("/roles", middleware.PlatformAdminMiddleware(app.UarRepo, app.AppRepo), roleCtrl.DeleteRole)

		// Gestión de Usuarios y configuración por App (requiere admin de ESA app)
		apps := adminPrivate.Group("/apps/:id")
		apps.Use(middleware.RoleMiddleware(app.UarRepo, app.AppRepo, "ADMIN"))
		{
			apps.GET("/users", userCtrl.GetAppUsers)
			apps.POST("/users", registerCtrl.PostUsersInApp)
			apps.DELETE("/users/:user_id", userCtrl.RevokeUserAccess)
			apps.POST("/users/:user_id/unlock", userCtrl.PostUnlockUser)
			apps.POST("/users/:user_id/resend-verification", dashboardCtrl.PostResendVerification)
			apps.POST("/users/:user_id/send-reset", dashboardCtrl.PostSendResetPassword)
			apps.GET("/rules", appCtrl.GetAppRules)
			apps.POST("/rules", ruleCtrl.PostDefaultRules)
			apps.POST("/rules/:code", ruleCtrl.PostAppRule)
			apps.PUT("/rules/:code", ruleCtrl.PutAppRule)
			apps.DELETE("/rules/:code", ruleCtrl.DeleteAppRule)
			apps.POST("/secret", appCtrl.PostRegenerateSecret)

			// Roles propios de la app (solo si la app tiene el sistema de roles activo)
			apps.POST("/roles", roleCtrl.PostAppRole)
			apps.DELETE("/roles/:code", roleCtrl.DeleteAppRole)
		}
	}

}
