package service

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/png"
	"net/http"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
)

func hashRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	normalized = strings.TrimSpace(normalized)
	if len(normalized) == 8 {
		normalized = normalized[:4] + "-" + normalized[4:]
	}
	h := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(h[:])
}

func verifyRecoveryCodeHash(inputCode, storedHash string) bool {
	if strings.TrimSpace(inputCode) == "" || strings.TrimSpace(storedHash) == "" {
		return false
	}

	normalized := strings.ToUpper(strings.ReplaceAll(inputCode, "-", ""))
	normalized = strings.TrimSpace(normalized)
	if len(normalized) == 8 {
		normalized = normalized[:4] + "-" + normalized[4:]
	}

	if strings.HasPrefix(storedHash, "sha256:") {
		h := sha256.Sum256([]byte(normalized))
		expectedHash := "sha256:" + hex.EncodeToString(h[:])
		return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(storedHash)) == 1
	}

	// Fallback para códigos legados hasheados previamente con bcrypt
	return util.CheckPasswordHash(normalized, storedHash)
}

// MfaService gestiona la configuración y validación de MFA.
type MfaService interface {
	// TOTP
	SetupTOTP(userID uint, userEmail string) (*response.TOTPSetupResponse, error)
	VerifyAndActivateTOTP(userID uint, code string) ([]string, error)
	ValidateTOTPCode(userID uint, code string) error

	// Códigos de recuperación
	ValidateRecoveryCode(userID uint, code string) error
	RegenerateRecoveryCodes(userID uint) ([]string, error)

	// WebAuthn
	BeginWebAuthnRegistration(userID uint, userEmail string) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishWebAuthnRegistration(userID uint, session *webauthn.SessionData, r *http.Request) error
	BeginWebAuthnLogin(userID uint) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishWebAuthnLogin(userID uint, session *webauthn.SessionData, r *http.Request) error

	// Gestión general
	DisableMFA(userID uint) error
	IsMfaEnabled(userID uint) bool
	GetMfaStatus(userID uint) (*response.MfaStatusResponse, error)
}

type mfaService struct {
	mfaRepo  repo.MfaRepository
	userRepo repo.UserRepository
}

func NewMfaService(mfaRepo repo.MfaRepository, userRepo repo.UserRepository) MfaService {
	return &mfaService{mfaRepo: mfaRepo, userRepo: userRepo}
}

// SetupTOTP genera un nuevo secreto TOTP para el usuario.
// La credencial se guarda como INACTIVA hasta que el usuario la verifique.
func (s *mfaService) SetupTOTP(userID uint, userEmail string) (*response.TOTPSetupResponse, error) {
	// Verificar que no tenga ya un TOTP activo
	existing, err := s.mfaRepo.FindActiveCredentialByUserAndType(userID, "TOTP")
	if err == nil && existing != nil {
		return nil, fmt.Errorf("ya tiene un autenticador TOTP configurado. Desactívelo primero para configurar uno nuevo")
	}

	// Eliminar credenciales TOTP inactivas previas (intentos de setup no completados)
	s.cleanupInactiveTOTP(userID)

	// Generar clave TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "PeakAuth",
		AccountName: userEmail,
		Period:      30,
		Digits:      6,
	})
	if err != nil {
		return nil, fmt.Errorf("error generando clave TOTP: %w", err)
	}

	// Cifrar el secreto antes de guardar
	encryptedSecret, err := util.EncryptAESGCM(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("error cifrando secreto TOTP: %w", err)
	}

	// Guardar credencial como inactiva
	cred := &model.UserMfaCredential{
		UserID:   userID,
		Type:     "TOTP",
		Name:     "Authenticator",
		Secret:   encryptedSecret,
		IsActive: false,
	}
	if err := s.mfaRepo.CreateCredential(cred); err != nil {
		return nil, fmt.Errorf("error guardando credencial TOTP: %w", err)
	}

	// Generar QR code en base64
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, fmt.Errorf("error generando imagen QR: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("error codificando imagen QR: %w", err)
	}

	qrBase64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	return &response.TOTPSetupResponse{
		Secret:  key.Secret(),
		QRCode:  qrBase64,
		OTPAuth: key.URL(),
	}, nil
}

// VerifyAndActivateTOTP valida el primer código TOTP y activa la credencial.
// Genera y retorna los códigos de recuperación.
func (s *mfaService) VerifyAndActivateTOTP(userID uint, code string) ([]string, error) {
	// Buscar credencial TOTP inactiva (pendiente de verificación)
	var cred model.UserMfaCredential
	err := s.findPendingTOTP(userID, &cred)
	if err != nil {
		return nil, fmt.Errorf("no se encontró una configuración TOTP pendiente de verificación")
	}

	// Descifrar secreto
	secret, err := util.DecryptAESGCM(cred.Secret)
	if err != nil {
		return nil, fmt.Errorf("error interno al procesar la credencial")
	}

	// Validar código
	if !totp.Validate(code, secret) {
		return nil, fmt.Errorf("código TOTP inválido. Verifique que la hora de su dispositivo esté sincronizada")
	}

	// Activar credencial
	if err := s.mfaRepo.ActivateCredential(cred.ID); err != nil {
		return nil, fmt.Errorf("error activando credencial TOTP: %w", err)
	}

	// Activar MFA en el usuario
	s.userRepo.UpdateColumn("mfa_enabled", true, userID)

	// Generar códigos de recuperación
	recoveryCodes, err := s.generateAndSaveRecoveryCodes(userID)
	if err != nil {
		return nil, fmt.Errorf("error generando códigos de recuperación: %w", err)
	}

	return recoveryCodes, nil
}

// ValidateTOTPCode valida un código TOTP contra la credencial activa del usuario.
func (s *mfaService) ValidateTOTPCode(userID uint, code string) error {
	cred, err := s.mfaRepo.FindActiveCredentialByUserAndType(userID, "TOTP")
	if err != nil {
		return fmt.Errorf("no se encontró un autenticador TOTP activo")
	}

	secret, err := util.DecryptAESGCM(cred.Secret)
	if err != nil {
		return fmt.Errorf("error interno al procesar la credencial")
	}

	if !totp.Validate(code, secret) {
		return fmt.Errorf("código TOTP inválido")
	}

	return nil
}

// ValidateRecoveryCode valida y consume un código de recuperación.
func (s *mfaService) ValidateRecoveryCode(userID uint, code string) error {
	codes, err := s.mfaRepo.FindUnusedRecoveryCodesByUser(userID)
	if err != nil || len(codes) == 0 {
		return fmt.Errorf("no hay códigos de recuperación disponibles")
	}

	for _, rc := range codes {
		if verifyRecoveryCodeHash(code, rc.CodeHash) {
			return s.mfaRepo.MarkRecoveryCodeUsed(rc.ID)
		}
	}

	return fmt.Errorf("código de recuperación inválido")
}

// RegenerateRecoveryCodes elimina los códigos existentes y genera nuevos.
func (s *mfaService) RegenerateRecoveryCodes(userID uint) ([]string, error) {
	if !s.IsMfaEnabled(userID) {
		return nil, fmt.Errorf("MFA no está habilitado")
	}
	return s.generateAndSaveRecoveryCodes(userID)
}

// DisableMFA desactiva MFA completamente: elimina credenciales y códigos de recuperación.
func (s *mfaService) DisableMFA(userID uint) error {
	if err := s.mfaRepo.DeleteCredentialsByUser(userID); err != nil {
		return fmt.Errorf("error eliminando credenciales MFA: %w", err)
	}
	if err := s.mfaRepo.DeleteRecoveryCodesByUser(userID); err != nil {
		return fmt.Errorf("error eliminando códigos de recuperación: %w", err)
	}
	s.userRepo.UpdateColumn("mfa_enabled", false, userID)
	return nil
}

// IsMfaEnabled verifica si el usuario tiene MFA activado.
func (s *mfaService) IsMfaEnabled(userID uint) bool {
	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return false
	}
	return user.MfaEnabled
}

// GetMfaStatus retorna el estado detallado del MFA del usuario.
func (s *mfaService) GetMfaStatus(userID uint) (*response.MfaStatusResponse, error) {
	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return nil, fmt.Errorf("usuario no encontrado")
	}

	status := &response.MfaStatusResponse{
		Enabled: user.MfaEnabled,
	}

	totpCred, err := s.mfaRepo.FindActiveCredentialByUserAndType(userID, "TOTP")
	if err == nil && totpCred != nil {
		status.TOTPConfigured = true
		status.TOTPName = totpCred.Name
	}

	unusedCodes, err := s.mfaRepo.FindUnusedRecoveryCodesByUser(userID)
	if err == nil {
		status.RecoveryCodesLeft = len(unusedCodes)
	}

	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			status.WebAuthnConfigured = true
			break
		}
	}

	return status, nil
}

// --- Helpers privados ---

func (s *mfaService) generateAndSaveRecoveryCodes(userID uint) ([]string, error) {
	// Eliminar códigos anteriores
	s.mfaRepo.DeleteRecoveryCodesByUser(userID)

	// Generar 10 códigos nuevos
	plainCodes, err := util.GenerateRecoveryCodes(10)
	if err != nil {
		return nil, err
	}

	// Hashear y guardar
	var dbCodes []model.UserRecoveryCode
	for _, code := range plainCodes {
		hash := hashRecoveryCode(code)
		dbCodes = append(dbCodes, model.UserRecoveryCode{
			UserID:   userID,
			CodeHash: hash,
		})
	}

	if err := s.mfaRepo.CreateRecoveryCodes(dbCodes); err != nil {
		return nil, fmt.Errorf("error guardando códigos de recuperación: %w", err)
	}

	return plainCodes, nil
}

func (s *mfaService) cleanupInactiveTOTP(userID uint) {
	creds, err := s.mfaRepo.FindAllCredentialsByUser(userID)
	if err != nil {
		return
	}
	for _, c := range creds {
		if c.Type == "TOTP" && !c.IsActive {
			s.mfaRepo.DeleteCredential(c.ID)
		}
	}
}

func (s *mfaService) findPendingTOTP(userID uint, out *model.UserMfaCredential) error {
	cred, err := s.mfaRepo.FindPendingCredentialByUserAndType(userID, "TOTP")
	if err != nil {
		return err
	}
	*out = *cred
	return nil
}
