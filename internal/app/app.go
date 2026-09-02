package app

import (
	"log"
	"os"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"time"

	"gorm.io/gorm"
)

type App struct {
	DB           *gorm.DB
	UserService  service.UserService
	AppService   service.ApplicationService
	SetupService service.SetupService
	RuleService  service.ApplicationRuleService
	UarRepo      repo.UserApplicationRoleRepository
	AppRepo      repo.ApplicationRepository
	TokenManager *auth.JWTManager
	RoleService  service.RoleService
	EmailService *service.EmailService
	MfaService   service.MfaService
	OAuthService service.OAuthService
}

func NewApp(db *gorm.DB, jwtManager *auth.JWTManager) *App {
	// Validar que la clave de encriptación MFA esté configurada antes de arrancar
	if _, err := util.GetMfaEncryptionKey(); err != nil {
		log.Fatalf("Error crítico al inicializar la aplicación: %v", err)
	}

	// Setup service para primer bootstrap (token y servicio se inicializarán después)
	setupToken := os.Getenv("SETUP_TOKEN")
	// 1. Inicializar Repositorios
	userRepo := repo.NewUserRepositoryRepository(db)
	roleRepo := repo.NewRoleRepositoryRepository(db)
	uarRepo := repo.NewUserApplicationRoleRepository(db)
	appRepo := repo.NewApplicationRepository(db)
	ruleRepo := repo.NewApplicationRuleRepository(db)
	emailRepo := repo.NewEmailVerificationRepositoryRepository(db)
	passRepo := repo.NewPasswordResetRepository(db)
	setupRepo := repo.NewSetupRepository(db)
	refreshRepo := repo.NewRefreshTokenRepository(db)
	mfaRepo := repo.NewMfaRepository(db)
	oauthRepo := repo.NewOAuthRepository(db)
	txManager := repo.NewTransactionManager(db)

	// 2. Inicializar Servicios inyectando los repos
	ruleService := service.NewApplicationRuleService(ruleRepo, uarRepo, roleRepo, appRepo)

	emailService := service.NewEmailService()
	appService := service.NewApplicationService(appRepo, userRepo, roleRepo, uarRepo, txManager, emailService, passRepo)
	mfaService := service.NewMfaService(mfaRepo, userRepo)
	userService := service.NewUserService(userRepo, roleRepo, uarRepo, appRepo, ruleService, jwtManager, emailRepo, passRepo, emailService, refreshRepo, txManager)
	setupService := service.NewSetupService(setupRepo, setupToken, txManager)
	roleService := service.NewRoleService(roleRepo, ruleRepo)
	oauthService := service.NewOAuthService(oauthRepo, appRepo)

	// 3. Iniciar Tareas en Segundo Plano
	oauthService.StartCleanupTask(10 * time.Minute)

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
		MfaService:   mfaService,
		OAuthService: oauthService,
	}
}
