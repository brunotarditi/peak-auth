package service

import (
	"errors"
	"log"
	"os"
	"peak-auth/model"
	"peak-auth/repository"
	"peak-auth/utils"
	"time"
)

type SetupService interface {
	CreateRootUser(email, password, token string) (model.User, error)
	ValidateSetupToken(token string) error
	IsFirstRun() (bool, error)
	InitializeSystem(port string)
	CompleteSetup(rootUser model.User)
}

type setupService struct {
	setupRepo      repository.SetupRepository
	txManager      repository.TransactionManager
	setupToken     string
	ephemeralToken string
	tokenExpiry    time.Time
}

func NewSetupService(setupRepo repository.SetupRepository, setupToken string, txManager repository.TransactionManager) SetupService {
	return &setupService{setupRepo: setupRepo, setupToken: setupToken, txManager: txManager}
}

func (s *setupService) CreateRootUser(email, password, token string) (model.User, error) {
	var user model.User
	if err := s.ValidateSetupToken(token); err != nil {
		return model.User{}, errors.New("token de setup inválido")
	}
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return model.User{}, err
	}
	err = s.txManager.WithinTransaction(func(tx repository.TxRepository) error {
		// Creamos los modelos...
		rootApp := model.Application{Name: "Peak Auth Raíz", AppID: "peak-auth-raiz", IsActive: true}
		rootRole := model.Role{Name: "ROOT"}
		user := model.User{Email: email, Password: hashedPassword, IsVerified: true}
		profile := model.Profile{FirstName: "System", LastName: "Root"}

		// 2. Ejecutamos mediante el repositorio
		if err := tx.Apps().Create(&rootApp); err != nil {
			return err
		}
		if err := tx.Roles().Create(&rootRole); err != nil {
			return err
		}
		user = model.User{Email: email, Password: hashedPassword, IsVerified: true}
		if err := tx.Users().CreateWithProfile(&user, &profile); err != nil {
			return err
		}

		// 3. Asignación final
		if err := tx.UAR().AssignRole(user.ID, rootApp.ID, rootRole.ID); err != nil {
			return err
		}

		// 4. Si llegamos acá, limpiamos el token en memoria
		s.CompleteSetup(user)
		return err

	})
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

	// 2. Generamos el token en memoria
	token, _, _ := utils.GenerateToken(32)
	s.ephemeralToken = token
	s.tokenExpiry = time.Now().Add(2 * time.Hour) // Expira en 2 horas

	host := os.Getenv("HOST")
	if host == "" {
		host = "localhost"
	}

	log.Printf("================================================================")
	log.Printf("⚠️  PEAK-AUTH: MODO INSTALACIÓN ACTIVADO")
	log.Printf("Token efímero (solo memoria): %s", s.ephemeralToken)
	log.Printf("URL de Setup: http://%s:%s/setup?token=%s", host, port, s.ephemeralToken)
	log.Printf("================================================================")
}

func (s *setupService) ValidateSetupToken(token string) error {
	if s.ephemeralToken == "" || s.ephemeralToken != token {
		return errors.New("token de instalación inválido")
	}

	if time.Now().After(s.tokenExpiry) {
		// Si expiró, el admin debe reiniciar el server para generar uno nuevo
		return errors.New("el token ha expirado, reinicie el servidor")
	}

	return nil
}

func (s *setupService) CompleteSetup(rootUser model.User) {
	s.ephemeralToken = ""
	s.tokenExpiry = time.Time{}
	log.Println("✅ Setup finalizado. Token efímero destruido.")
}
