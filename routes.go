package main

import (
	"peak-auth/app"
	"peak-auth/controllers"
	"peak-auth/middlewares"

	"github.com/gin-gonic/gin"
)

// SetupRoutes registra las rutas del servidor en el router Gin proporcionado.
func SetupRoutes(r *gin.Engine, app *app.App) {

	userCtrl := &controllers.UserController{
		UserService: app.UserService,
	}

	setupCtrl := &controllers.SetupController{
		SetupService: app.SetupService,
	}

	adminCtrl := &controllers.AdminController{
		AppService:  app.AppService,
		UserService: app.UserService,
		RuleService: app.RuleService,
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

	// --- ADMIN DASHBOARD ---
	admin := r.Group("/admin")
	admin.Use(middlewares.AuthMiddleware(app.TokenManager))
	{
		admin.GET("/", adminCtrl.Dashboard)
		admin.GET("/login", adminCtrl.GetLoginForm)
		admin.POST("/login", adminCtrl.PostLoginForm)
		admin.POST("/logout", adminCtrl.PostLogout)
		admin.GET("/apps/new", adminCtrl.GetFormApp)
		admin.POST("/apps", middlewares.RoleMiddleware(app.UarRepo, "ROOT", "ADMIN"), adminCtrl.PostFormApp)
		admin.GET("/apps/:id/users", adminCtrl.GetAppUsers)
		admin.POST("/apps/:id/users", middlewares.RoleMiddleware(app.UarRepo, "ROOT", "ADMIN"), adminCtrl.PostUsersInApp)
		admin.GET("/apps/:id/rules", adminCtrl.GetAppRules)
		admin.POST("/apps/:id/rules", middlewares.RoleMiddleware(app.UarRepo, "ROOT", "ADMIN"), adminCtrl.PostDefaultRules)
	}

}
