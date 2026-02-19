package app

import (
	"os"
	"peak-auth/auth"
	"peak-auth/repositories"
	"peak-auth/services"

	"gorm.io/gorm"
)

type App struct {
	DB           *gorm.DB
	UserService  services.UserService
	AppService   services.ApplicationService
	SetupService services.SetupService
	RuleService  services.ApplicationRuleService
	UarRepo      repositories.UserApplicationRoleRepository
	TokenManager *auth.JWTManager
}

func NewApp(db *gorm.DB, jwtManager *auth.JWTManager) *App {
	// Setup service para primer bootstrap (token y servicio se inicializarán después)
	setupToken := os.Getenv("SETUP_TOKEN")
	// 1. Inicializar Repositorios
	userRepo := repositories.NewUserRepositoryRepository(db)
	roleRepo := repositories.NewRoleRepositoryRepository(db)
	uarRepo := repositories.NewUserApplicationRoleRepository(db)
	appRepo := repositories.NewApplicationRepository(db)
	ruleRepo := repositories.NewApplicationRuleRepository(db)
	emailRepo := repositories.NewEmailVerificationRepositoryRepository(db)
	passRepo := repositories.NewPasswordResetRepository(db)
	setupRepo := repositories.NewSetupRepository(db)

	// 2. Inicializar Servicios inyectando los repos
	ruleService := services.NewApplicationRuleService(ruleRepo, uarRepo, roleRepo)

	appService := services.NewApplicationService(appRepo, userRepo, roleRepo, uarRepo)
	userService := services.NewUserService(userRepo, roleRepo, uarRepo, appRepo, ruleService, jwtManager, emailRepo, passRepo)
	setupService := services.NewSetupService(userRepo, appRepo, roleRepo, uarRepo, setupRepo, setupToken)

	return &App{
		DB:           db,
		UserService:  userService,
		AppService:   appService,
		SetupService: setupService,
		RuleService:  ruleService,
	}
}
