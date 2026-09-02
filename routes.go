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
		MfaService:  app.MfaService,
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
		UserService:  app.UserService,
		MfaService:   app.MfaService,
		TokenManager: app.TokenManager,
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

	oauthCtrl := &controller.OAuthController{
		OAuthService: app.OAuthService,
		UserService:  app.UserService,
		TokenManager: app.TokenManager,
	}

	// Limitadores por IP para mitigar fuerza bruta en endpoints sensibles.
	loginLimiter := middleware.RateLimitMiddleware(10, time.Minute)
	resetLimiter := middleware.RateLimitMiddleware(5, time.Minute)

	// --- OAUTH2 ENDPOINTS ---
	oauth := r.Group("/oauth")
	{
		oauth.GET("/authorize", oauthCtrl.AuthorizeEndpoint)
		oauth.POST("/token", oauthCtrl.TokenEndpoint) // S2S, might need basic auth or just form body

		// Flujo público de login para Web
		oauth.GET("/login", oauthCtrl.GetPublicLogin)
		oauth.POST("/login", loginLimiter, oauthCtrl.PostPublicLogin)
		oauth.GET("/login/mfa", oauthCtrl.GetPublicLoginMfa)
		oauth.GET("/login/mfa/setup", oauthCtrl.GetPublicLoginMfaSetup)
	}

	docsCtrl := &controller.DocsController{}

	// --- SETUP & USER ACTIONS (App inicial) ---
	// Estas rutas también usan protección CSRF (double-submit cookie).

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
		api.POST("/login/mfa/totp", loginLimiter, loginCtrl.VerifyMfaTotp)
		api.POST("/login/mfa/recovery", loginLimiter, loginCtrl.VerifyMfaRecovery)
		api.POST("/login/mfa/totp/setup", loginLimiter, loginCtrl.SetupTOTPLogin)
		api.POST("/login/mfa/totp/verify", loginLimiter, loginCtrl.VerifyTOTPLogin)
		api.GET("/login/mfa/webauthn/register/begin", loginLimiter, loginCtrl.BeginWebAuthnRegistrationLogin)
		api.POST("/login/mfa/webauthn/register/finish", loginLimiter, loginCtrl.FinishWebAuthnRegistrationLogin)
		api.POST("/register", loginLimiter, middleware.AppAuthMiddleware(app.AppRepo), registerCtrl.Register)
		api.POST("/refresh", loginLimiter, userCtrl.Refresh)
	}

	// --- API V1 Protegida (MFA configuration) ---
	apiPrivate := r.Group("/api/v1")
	apiPrivate.Use(middleware.CORSMiddleware())
	apiPrivate.Use(middleware.AuthMiddleware(app.TokenManager))
	{
		apiPrivate.POST("/mfa/totp/setup", userCtrl.SetupTOTP)
		apiPrivate.POST("/mfa/totp/verify", userCtrl.VerifyTOTP)
		apiPrivate.POST("/mfa/webauthn/setup", userCtrl.BeginWebAuthnRegistration)
		apiPrivate.POST("/mfa/webauthn/verify", userCtrl.FinishWebAuthnRegistration)
		apiPrivate.POST("/mfa/totp/disable", userCtrl.DisableMFA)
		apiPrivate.GET("/mfa/status", userCtrl.GetMfaStatus)
	}

	// --- RUTAS PÚBLICAS DE ADMINISTRACIÓN ---
	adminPublic := r.Group("/admin")
	adminPublic.Use(middleware.AdminCSRFMiddleware())
	{
		adminPublic.GET("/login", loginCtrl.GetLoginForm)
		adminPublic.POST("/login", loginLimiter, loginCtrl.PostLoginForm)

		// Rutas para MFA en la administración
		adminPublic.GET("/login/mfa", loginCtrl.GetAdminMfaForm)
		adminPublic.POST("/login/mfa", loginLimiter, middleware.AdminCSRFMiddleware(), loginCtrl.PostAdminMfa)
		adminPublic.GET("/login/mfa/setup", loginCtrl.GetAdminMfaSetupForm)
		adminPublic.GET("/login/mfa/webauthn/begin", loginLimiter, loginCtrl.BeginWebAuthnLogin)
		adminPublic.POST("/login/mfa/webauthn/finish", loginLimiter, middleware.AdminCSRFMiddleware(), loginCtrl.FinishWebAuthnLoginAdmin)

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
		adminPrivate.GET("/", middleware.PlatformScopeMiddleware(app.UarRepo, app.AppRepo), dashboardCtrl.Dashboard)
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
