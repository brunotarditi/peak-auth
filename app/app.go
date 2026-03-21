package app

import (
	"os"
	"peak-auth/auth"
	"peak-auth/repository"
	"peak-auth/service"

	"gorm.io/gorm"
)

type App struct {
	DB           *gorm.DB
	UserService  service.UserService
	AppService   service.ApplicationService
	SetupService service.SetupService
	RuleService  service.ApplicationRuleService
	UarRepo      repository.UserApplicationRoleRepository
	AppRepo      repository.ApplicationRepository
	TokenManager *auth.JWTManager
	RoleService  service.RoleService
	EmailService *service.EmailService
}

func NewApp(db *gorm.DB, jwtManager *auth.JWTManager) *App {
	// Setup service para primer bootstrap (token y servicio se inicializarán después)
	setupToken := os.Getenv("SETUP_TOKEN")
	// 1. Inicializar Repositorios
	userRepo := repository.NewUserRepositoryRepository(db)
	roleRepo := repository.NewRoleRepositoryRepository(db)
	uarRepo := repository.NewUserApplicationRoleRepository(db)
	appRepo := repository.NewApplicationRepository(db)
	ruleRepo := repository.NewApplicationRuleRepository(db)
	emailRepo := repository.NewEmailVerificationRepositoryRepository(db)
	passRepo := repository.NewPasswordResetRepository(db)
	setupRepo := repository.NewSetupRepository(db)
	refreshRepo := repository.NewRefreshTokenRepository(db)
	txManager := repository.NewTransactionManager(db)

	// 2. Inicializar Servicios inyectando los repos
	ruleService := service.NewApplicationRuleService(ruleRepo, uarRepo, roleRepo)

	emailService := service.NewEmailService()
	appService := service.NewApplicationService(appRepo, userRepo, roleRepo, uarRepo, txManager, emailService, passRepo)
	userService := service.NewUserService(userRepo, roleRepo, uarRepo, appRepo, ruleService, jwtManager, emailRepo, passRepo, emailService, refreshRepo)
	setupService := service.NewSetupService(setupRepo, setupToken, txManager)
	roleService := service.NewRoleService(roleRepo)

	return &App{
		DB:           db,
		UserService:  userService,
		AppService:   appService,
		SetupService: setupService,
		RuleService:  ruleService,
		TokenManager: jwtManager,
		UarRepo:      uarRepo,
		AppRepo:      appRepo,
		RoleService:  roleService,
		EmailService: emailService,
	}
}
