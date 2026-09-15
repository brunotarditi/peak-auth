package service

import (
	"crypto/subtle"
	"errors"
	"log"
	"time"

	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
)

type SetupService interface {
	CreateRootUser(email, password, token string) (model.User, error)
	ValidateSetupToken(token string) error
	IsFirstRun() (bool, error)
	InitializeSystem(port string)
	CompleteSetup(rootUser model.User)
	RequiresToken() bool
}

type setupService struct {
	setupRepo      repo.SetupRepository
	txManager      repo.TransactionManager
	setupToken     string
	ephemeralToken string
	tokenExpiry    time.Time
	setupCompleted bool
}

func NewSetupService(setupRepo repo.SetupRepository, setupToken string, txManager repo.TransactionManager) SetupService {
	return &setupService{setupRepo: setupRepo, setupToken: setupToken, txManager: txManager}
}

func (s *setupService) CreateRootUser(email, password, token string) (model.User, error) {
	var user model.User

	// Prevent setup after it's been completed
	if s.setupCompleted {
		return model.User{}, errors.New("el sistema ya ha sido configurado")
	}

	if err := s.ValidateSetupToken(token); err != nil {
		return model.User{}, errors.New("token de setup inválido")
	}

	// Validación de complejidad de password
	if !util.ValidatePasswordStrength(password) {
		return model.User{}, errors.New("la contraseña es demasiado débil: debe tener al menos 8 caracteres, mayúsculas, números y símbolos")
	}

	hashedPassword, err := util.HashPassword(password)
	if err != nil {
		return model.User{}, err
	}
	err = s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
		// 2. Ejecutamos mediante el repositorio
		rootApp := model.Application{Name: "Peak Auth", AppID: util.AppIdPeakAuth, IsActive: true}
		rootRole := model.Role{Name: "ROOT", IsDefault: true}
		user = model.User{Email: email, Password: hashedPassword, IsVerified: true}
		profile := model.Profile{FirstName: "System", LastName: "Root"}

		if err := tx.Apps().Create(&rootApp); err != nil {
			return err
		}

		// Crear las políticas para la app Raíz
		if err := tx.Rules().CreateDefaultRules(rootApp.ID); err != nil {
			return err
		}

		// Roles por defecto del sistema
		adminRole := model.Role{Name: "ADMIN", IsDefault: true}
		userRole := model.Role{Name: "USER", IsDefault: true}

		if err = tx.Roles().Create(&rootRole); err != nil {
			return err
		}
		if err = tx.Roles().Create(&adminRole); err != nil {
			return err
		}
		if err = tx.Roles().Create(&userRole); err != nil {
			return err
		}
		if err := tx.Users().CreateWithProfile(&user, &profile); err != nil {
			return err
		}

		// 3. Asignación final
		return tx.UAR().AssignRole(user.ID, rootApp.ID, rootRole.ID)
	})

	if err == nil {
		// Mark setup as completed - this makes the token permanently invalid
		s.setupCompleted = true
		s.CompleteSetup(user)
	}

	return user, err
}

func (s *setupService) IsFirstRun() (bool, error) {
	return s.setupRepo.IsFirstRun()
}

func (s *setupService) InitializeSystem(port string) {
	// 1. Usamos el repositorio para chequear si es la primera vez
	first, err := s.setupRepo.IsFirstRun()
	if err != nil || !first {
		return
	}

	baseURL := util.BaseURL()

	log.Printf("================================================================")
	log.Printf("⚠️  PEAK-AUTH: MODO INSTALACIÓN ACTIVADO (Primer arranque)")
	log.Printf("Acceda a %s/setup para inicializar la cuenta maestra ROOT.", baseURL)
	if s.setupToken != "" {
		log.Printf("Autenticación requerida con SETUP_TOKEN configurado en entorno.")
	}
	log.Printf("================================================================")
}

func (s *setupService) ValidateSetupToken(token string) error {
	// Prevent reuse after setup is completed
	if s.setupCompleted {
		return errors.New("el sistema ya ha sido configurado")
	}

	// Si se configuró un SETUP_TOKEN en .env, se exige coincidencia estricta
	if s.setupToken != "" {
		if token == "" || subtle.ConstantTimeCompare([]byte(s.setupToken), []byte(token)) != 1 {
			return errors.New("token de instalación inválido")
		}
		return nil
	}

	// Si no se configuró SETUP_TOKEN, se permite en primer arranque
	first, _ := s.setupRepo.IsFirstRun()
	if first {
		return nil
	}
	return errors.New("el sistema ya ha sido configurado")
}

func (s *setupService) RequiresToken() bool {
	return s.setupToken != ""
}

func (s *setupService) CompleteSetup(rootUser model.User) {
	s.ephemeralToken = ""
	s.tokenExpiry = time.Time{}
	log.Println("✅ Setup finalizado. Cuenta ROOT creada con éxito.")
}
