package main

import (
	"net/http"
	"time"

	"peak-auth/internal/api/controller"
	"peak-auth/internal/api/middleware"
	"peak-auth/internal/app"

	"github.com/gin-gonic/gin"
)

// SetupRoutes registra las rutas del servidor en el router Gin proporcionado.
func SetRoutes(r *gin.Engine, app *app.App) {

	r.Static("/static", "./web/static")

	// Redirección amigable desde la raíz del servidor hacia el panel
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/admin")
	})

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
		MfaService:   app.MfaService,
		TokenManager: app.TokenManager,
		RuleService:  app.RuleService,
		AppService:   app.AppService,
	}

	docsCtrl := &controller.DocsController{}

	discoveryCtrl := &controller.DiscoveryController{
		TokenManager: app.TokenManager,
	}

	introspectCtrl := &controller.IntrospectController{
		TokenManager: app.TokenManager,
		UserRepo:     app.UserRepo,
		UarRepo:      app.UarRepo,
	}

	healthCtrl := &controller.HealthController{
		HealthService: app.HealthService,
	}

	// Limitadores por IP para mitigar fuerza bruta en endpoints sensibles.
	loginLimiter := middleware.RateLimitMiddleware(10, time.Minute)
	resetLimiter := middleware.RateLimitMiddleware(5, time.Minute)
	tokenLimiter := middleware.RateLimitMiddleware(20, time.Minute)
	mfaSetupLimiter := middleware.RateLimitMiddleware(10, time.Minute)
	setupLimiter := middleware.RateLimitMiddleware(5, time.Minute)
	verifyLimiter := middleware.RateLimitMiddleware(10, time.Minute)
	ruleMutationLimiter := middleware.RateLimitMiddleware(20, time.Minute)
	healthLimiter := middleware.RateLimitMiddleware(60, time.Minute) // 1 req/seg por IP para monitores y balanceadores

	// ============================================================================
	// HEALTH & READINESS PROBES (Público, para Docker, Kubernetes y balanceadores)
	// ============================================================================
	r.GET("/health", healthLimiter, healthCtrl.Health)
	r.GET("/ready", healthLimiter, healthCtrl.Ready)

	// ============================================================================
	// OIDC & JWKS DISCOVERY (Público, CORS abierto para SDKs y librerías cliente)
	// ============================================================================
	r.GET("/.well-known/jwks.json", discoveryCtrl.JWKS)
	r.OPTIONS("/.well-known/jwks.json", discoveryCtrl.JWKS)
	r.GET("/.well-known/openid-configuration", discoveryCtrl.OpenIDConfiguration)
	r.OPTIONS("/.well-known/openid-configuration", discoveryCtrl.OpenIDConfiguration)

	// ============================================================================
	// OAUTH 2.0 & SSO FLOW (/oauth)
	// Flujo de autorización estándar con PKCE y vistas públicas de login SSO
	// ============================================================================
	oauth := r.Group("/oauth")
	oauth.Use(middleware.RequireHTTPSMiddleware())
	{
		oauth.GET("/authorize", oauthCtrl.AuthorizeEndpoint)
		oauth.POST("/token", tokenLimiter, oauthCtrl.TokenEndpoint) // Token Exchange (S2S o SPA)
		oauth.OPTIONS("/token", oauthCtrl.TokenEndpoint)            // Preflight CORS para clientes SPA
		oauth.GET("/logout", oauthCtrl.LogoutEndpoint)              // Federated Logout (GET)
		oauth.POST("/logout", oauthCtrl.LogoutEndpoint)             // Federated Logout (POST)

		// Consent page for user authorization approval
		oauthConsent := oauth.Group("/consent")
		oauthConsent.Use(middleware.CSRFMiddleware())
		{
			oauthConsent.GET("", oauthCtrl.GetConsentPage)
			oauthConsent.POST("/approve", oauthCtrl.PostConsentApprove)
			oauthConsent.POST("/deny", oauthCtrl.PostConsentDeny)
		}

		// Flujo público de login para Web (SSO) protegido con CSRF
		oauthWeb := oauth.Group("/login")
		oauthWeb.Use(middleware.CSRFMiddleware())
		{
			oauthWeb.GET("", oauthCtrl.GetPublicLogin)
			oauthWeb.POST("", loginLimiter, oauthCtrl.PostPublicLogin)
			oauthWeb.GET("/mfa", oauthCtrl.GetPublicLoginMfa)
			oauthWeb.POST("/mfa/totp", loginLimiter, oauthCtrl.PostPublicLoginMfaTotp)
			oauthWeb.POST("/mfa/recovery", loginLimiter, oauthCtrl.PostPublicLoginMfaRecovery)
			oauthWeb.POST("/mfa/webauthn/finish", loginLimiter, oauthCtrl.PostPublicLoginMfaWebAuthnFinish)
			oauthWeb.GET("/mfa/setup", oauthCtrl.GetPublicLoginMfaSetup)
			oauthWeb.POST("/mfa/setup/verify", loginLimiter, oauthCtrl.PostPublicLoginMfaSetupVerify)
			oauthWeb.POST("/mfa/setup/webauthn/finish", loginLimiter, oauthCtrl.PostPublicLoginMfaSetupWebAuthnFinish)
		}
	}

	// ============================================================================
	// SETUP & RECOVERY (Acciones de cuenta y bootstrap inicial)
	// ============================================================================
	r.POST("/setup/auth", setupLimiter, middleware.RequireHTTPSMiddleware(), middleware.AdminCSRFMiddleware(), setupCtrl.AuthenticateSetup)
	r.GET("/setup", middleware.RequireHTTPSMiddleware(), middleware.AdminCSRFMiddleware(), setupCtrl.ShowSetup)
	r.POST("/setup", setupLimiter, middleware.RequireHTTPSMiddleware(), middleware.AdminCSRFMiddleware(), setupCtrl.ProcessSetup)
	r.GET("/verify", verifyLimiter, middleware.RequireHTTPSMiddleware(), middleware.CSRFMiddleware(), registerCtrl.GetVerifyEmail)
	r.POST("/verify", verifyLimiter, middleware.RequireHTTPSMiddleware(), middleware.CSRFMiddleware(), registerCtrl.PostVerifyEmail)
	r.GET("/reset-password", middleware.RequireHTTPSMiddleware(), middleware.AdminCSRFMiddleware(), userCtrl.GetResetPassword)
	r.POST("/reset-password", resetLimiter, middleware.RequireHTTPSMiddleware(), middleware.AdminCSRFMiddleware(), userCtrl.PostResetPassword)

	// ============================================================================
	// API V1 Pública para integraciones externas
	// ============================================================================
	api := r.Group("/api/v1")
	api.Use(middleware.RequireHTTPSMiddleware())
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
		// Token introspection endpoint for online validation (requires app authentication)
		api.POST("/introspect", middleware.AppAuthMiddleware(app.AppRepo), introspectCtrl.Introspect)
	}

	// ============================================================================
	// API V1 Protegida (MFA configuration)
	// ============================================================================
	apiPrivate := r.Group("/api/v1")
	apiPrivate.Use(middleware.RequestBodyLimitMiddleware(1024 * 1024))
	apiPrivate.Use(middleware.CORSMiddleware())
	apiPrivate.Use(middleware.AuthMiddleware(app.TokenManager, app.UserRepo))
	{
		apiPrivate.POST("/mfa/totp/setup", userCtrl.SetupTOTP)
		apiPrivate.POST("/mfa/totp/verify", mfaSetupLimiter, userCtrl.VerifyTOTP)
		apiPrivate.POST("/mfa/webauthn/setup", mfaSetupLimiter, userCtrl.BeginWebAuthnRegistration)
		apiPrivate.POST("/mfa/webauthn/verify", mfaSetupLimiter, userCtrl.FinishWebAuthnRegistration)
		apiPrivate.GET("/mfa/webauthn/credentials", userCtrl.ListWebAuthnKeys)
		apiPrivate.DELETE("/mfa/webauthn/credentials/:id", mfaSetupLimiter, userCtrl.DeleteWebAuthnKey)
		apiPrivate.POST("/mfa/totp/disable", mfaSetupLimiter, userCtrl.DisableMFA)
		apiPrivate.GET("/mfa/status", userCtrl.GetMfaStatus)
	}

	// ============================================================================
	// --- RUTAS PÚBLICAS DE ADMINISTRACIÓN ---
	// ============================================================================
	adminPublic := r.Group("/admin")
	adminPublic.Use(middleware.RequireHTTPSMiddleware())
	adminPublic.Use(middleware.AdminCSRFMiddleware())
	adminPublic.Use(middleware.AdminGuestMiddleware(app.TokenManager))
	{
		adminPublic.GET("/login", loginCtrl.GetLoginForm)
		adminPublic.POST("/login", loginLimiter, loginCtrl.PostLoginForm)

		// Rutas para MFA en la administración
		adminPublic.GET("/login/mfa", loginCtrl.GetAdminMfaForm)
		adminPublic.POST("/login/mfa", loginLimiter, middleware.AdminCSRFMiddleware(), loginCtrl.PostAdminMfa)
		adminPublic.GET("/login/mfa/setup", loginCtrl.GetAdminMfaSetupForm)
		adminPublic.POST("/mfa/setup", loginLimiter, loginCtrl.PostAdminMfaSetup)
		adminPublic.POST("/mfa/verify", loginLimiter, loginCtrl.PostAdminMfaVerifySetup)
		adminPublic.GET("/login/mfa/webauthn/begin", loginLimiter, loginCtrl.BeginWebAuthnLogin)
		adminPublic.POST("/login/mfa/webauthn/finish", loginLimiter, middleware.AdminCSRFMiddleware(), loginCtrl.FinishWebAuthnLoginAdmin)

		// El setup también es accesible desde /admin/setup
		adminPublic.POST("/setup/auth", setupLimiter, middleware.AdminCSRFMiddleware(), setupCtrl.AuthenticateSetup)
		adminPublic.GET("/setup", setupCtrl.ShowSetup)
		adminPublic.POST("/setup", setupLimiter, middleware.AdminCSRFMiddleware(), setupCtrl.ProcessSetup)
	}

	// ============================================================================
	// --- RUTAS PRIVADAS DE ADMINISTRACIÓN ---
	// ============================================================================
	adminPrivate := r.Group("/admin")
	adminPrivate.Use(middleware.SecurityHeaderMiddleware())
	adminPrivate.Use(middleware.AdminCSRFMiddleware())
	adminPrivate.Use(middleware.AuthMiddleware(app.TokenManager, app.UserRepo))
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
			apps.POST("/users", middleware.RequestBodyLimitMiddleware(1024*1024), registerCtrl.PostUsersInApp)
			apps.DELETE("/users/:user_id", userCtrl.RevokeUserAccess)
			apps.POST("/users/:user_id/unlock", userCtrl.PostUnlockUser)
			apps.POST("/users/:user_id/resend-verification", dashboardCtrl.PostResendVerification)
			apps.POST("/users/:user_id/send-reset", resetLimiter, dashboardCtrl.PostSendResetPassword)
			apps.GET("/rules", appCtrl.GetAppRules)
			apps.POST("/rules", ruleCtrl.PostDefaultRules)
			apps.POST("/rules/:code", ruleMutationLimiter, middleware.RequestBodyLimitMiddleware(64*1024), ruleCtrl.PostAppRule)
			apps.PUT("/rules/:code", ruleMutationLimiter, middleware.RequestBodyLimitMiddleware(64*1024), ruleCtrl.PutAppRule)
			apps.DELETE("/rules/:code", ruleCtrl.DeleteAppRule)
			apps.POST("/secret", appCtrl.PostRegenerateSecret)

			// Roles propios de la app (solo si la app tiene el sistema de roles activo)
			apps.POST("/roles", middleware.RequestBodyLimitMiddleware(256*1024), roleCtrl.PostAppRole)
			apps.DELETE("/roles/:code", roleCtrl.DeleteAppRole)
		}
	}

}
