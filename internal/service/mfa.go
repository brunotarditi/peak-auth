package service

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"log"
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
	FinishWebAuthnRegistration(userID uint, session *webauthn.SessionData, r *http.Request, keyName ...string) error
	BeginWebAuthnLogin(userID uint) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishWebAuthnLogin(userID uint, session *webauthn.SessionData, r *http.Request) error
	ListWebAuthnCredentials(userID uint) ([]response.WebAuthnKeyItem, error)
	DeleteWebAuthnCredential(userID uint, credID uint) error

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
		return nil, fmt.Errorf("error activando credencial TOTP")
	}

	// Activar MFA en el usuario
	s.userRepo.UpdateColumn("mfa_enabled", true, userID)

	// Generar códigos de recuperación
	recoveryCodes, err := s.generateAndSaveRecoveryCodes(userID)
	if err != nil {
		return nil, fmt.Errorf("error generando códigos de recuperación")
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
			if err := s.mfaRepo.MarkRecoveryCodeUsed(rc.ID); err != nil {
				return fmt.Errorf("error al actualizar código de recuperación")
			}
			return nil
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

// BeginWebAuthnRegistration inicia el proceso de registro de una nueva llave
func (s *mfaService) BeginWebAuthnRegistration(userID uint, userEmail string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	wa, err := getWebAuthn()
	if err != nil {
		return nil, nil, fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("usuario no encontrado")
	}

	// Obtener credenciales existentes para excluirlas (así no registra la misma llave dos veces)
	var waCreds []webauthn.Credential
	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			var cred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &cred); err == nil {
				waCreds = append(waCreds, cred)
			}
		}
	}

	wUser := &webAuthnUserWrapper{
		user:        &user,
		credentials: waCreds,
	}

	options, sessionData, err := wa.BeginRegistration(
		wUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error iniciando registro WebAuthn: %w", err)
	}

	return options, sessionData, nil
}

// FinishWebAuthnRegistration finaliza el registro, guarda la credencial y activa MFA
func (s *mfaService) FinishWebAuthnRegistration(userID uint, session *webauthn.SessionData, r *http.Request, keyName ...string) error {
	if session == nil {
		// Client validation error - session expired or invalid
		return ErrWebAuthnValidation
	}

	wa, err := getWebAuthn()
	if err != nil {
		// Log the detailed error server-side for diagnostics
		log.Printf("[error] FinishWebAuthnRegistration: WebAuthn initialization failed: %v", err)
		return ErrWebAuthnInternal
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		// Log the detailed error server-side for diagnostics
		log.Printf("[error] FinishWebAuthnRegistration: user lookup failed for userID=%d: %v", userID, err)
		return ErrWebAuthnInternal
	}

	wUser := &webAuthnUserWrapper{
		user: &user,
	}

	credential, err := wa.FinishRegistration(wUser, *session, r)
	if err != nil {
		// Client validation error - malformed ceremony, invalid signature, etc.
		return ErrWebAuthnValidation
	}

	// Verificar si la credencial ya existe para este usuario y límite de 5
	existingCreds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	webauthnCount := 0
	for _, c := range existingCreds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			webauthnCount++
			var existingCred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &existingCred); err == nil {
				if bytes.Equal(existingCred.ID, credential.ID) {
					// Client validation error - duplicate credential
					return ErrWebAuthnValidation
				}
			}
		}
	}

	if webauthnCount >= 5 {
		return errors.New("límite máximo alcanzado (máximo 5 llaves de seguridad por cuenta)")
	}

	finalName := "Llave de Seguridad Passkey"
	if len(keyName) > 0 && strings.TrimSpace(keyName[0]) != "" {
		finalName = strings.TrimSpace(keyName[0])
		if len(finalName) > 100 {
			finalName = finalName[:100]
		}
	} else if webauthnCount > 0 {
		finalName = fmt.Sprintf("Llave de Seguridad #%d", webauthnCount+1)
	}

	// Encode credential ID as base64 for storage and uniqueness checking
	credentialIDBase64 := base64.StdEncoding.EncodeToString(credential.ID)

	// Serializar credencial a JSON
	credJSON, err := json.Marshal(credential)
	if err != nil {
		// Log the detailed error server-side for diagnostics
		log.Printf("[error] FinishWebAuthnRegistration: credential marshaling failed for userID=%d: %v", userID, err)
		return ErrWebAuthnInternal
	}

	// Guardar en base de datos con el credential ID para unicidad
	newCred := &model.UserMfaCredential{
		UserID:       userID,
		Type:         "WEBAUTHN",
		Name:         finalName,
		Secret:       string(credJSON),
		CredentialID: &credentialIDBase64,
		IsActive:     true,
	}

	if err := s.mfaRepo.CreateCredential(newCred); err != nil {
		// Check if this is a duplicate key error (credential already registered)
		// GORM/SQLite/PostgreSQL/MySQL all include "UNIQUE constraint" or "duplicate" in the error message
		errMsg := err.Error()
		if bytes.Contains([]byte(errMsg), []byte("UNIQUE")) ||
			bytes.Contains([]byte(errMsg), []byte("duplicate")) ||
			bytes.Contains([]byte(errMsg), []byte("Duplicate")) {
			// This is an idempotent replay - credential already exists (client validation error)
			return ErrWebAuthnValidation
		}
		// Log the detailed error server-side for diagnostics
		log.Printf("[error] FinishWebAuthnRegistration: credential persistence failed for userID=%d: %v", userID, err)
		return ErrWebAuthnInternal
	}

	// Activar MFA en el usuario
	s.userRepo.UpdateColumn("mfa_enabled", true, userID)

	// Generar códigos de recuperación de respaldo si no tiene
	codes, _ := s.mfaRepo.FindUnusedRecoveryCodesByUser(userID)
	if len(codes) == 0 {
		_, _ = s.generateAndSaveRecoveryCodes(userID)
	}

	return nil
}

// BeginWebAuthnLogin inicia el challenge para iniciar sesión
func (s *mfaService) BeginWebAuthnLogin(userID uint) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	wa, err := getWebAuthn()
	if err != nil {
		return nil, nil, fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("usuario no encontrado")
	}

	var waCreds []webauthn.Credential
	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			var cred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &cred); err == nil {
				waCreds = append(waCreds, cred)
			}
		}
	}

	if len(waCreds) == 0 {
		return nil, nil, fmt.Errorf("no hay llaves de seguridad configuradas para este usuario")
	}

	wUser := &webAuthnUserWrapper{
		user:        &user,
		credentials: waCreds,
	}

	options, sessionData, err := wa.BeginLogin(wUser)
	if err != nil {
		return nil, nil, fmt.Errorf("error iniciando login WebAuthn: %w", err)
	}

	return options, sessionData, nil
}

// FinishWebAuthnLogin verifica el challenge firmado
func (s *mfaService) FinishWebAuthnLogin(userID uint, session *webauthn.SessionData, r *http.Request) error {
	wa, err := getWebAuthn()
	if err != nil {
		return fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return fmt.Errorf("usuario no encontrado")
	}

	var waCreds []webauthn.Credential
	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			var cred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &cred); err == nil {
				waCreds = append(waCreds, cred)
			}
		}
	}

	wUser := &webAuthnUserWrapper{
		user:        &user,
		credentials: waCreds,
	}

	if session == nil {
		return fmt.Errorf("sesión WebAuthn inválida o expirada")
	}

	updatedCredential, err := wa.FinishLogin(wUser, *session, r)
	if err != nil {
		return fmt.Errorf("validación WebAuthn fallida: %w", err)
	}

	// Persistir el contador actualizado del autenticador en la BD para detección de clonación (RFC WebAuthn).
	// Este paso es OBLIGATORIO: si falla, rechazamos el login para garantizar que el contador
	// siempre refleje el estado más reciente del autenticador.
	var matchedCred *model.UserMfaCredential
	var oldSecret string

	for i := range creds {
		if creds[i].Type == "WEBAUTHN" && creds[i].IsActive {
			var storedCred webauthn.Credential
			if err := json.Unmarshal([]byte(creds[i].Secret), &storedCred); err == nil {
				if bytes.Equal(storedCred.ID, updatedCredential.ID) {
					matchedCred = &creds[i]
					oldSecret = creds[i].Secret
					break
				}
			}
		}
	}

	if matchedCred == nil {
		return fmt.Errorf("no se encontró la credencial correspondiente en la base de datos")
	}

	updatedJSON, err := json.Marshal(updatedCredential)
	if err != nil {
		return fmt.Errorf("error serializando credencial actualizada: %w", err)
	}

	// Actualización atómica: solo actualiza si el secret no ha cambiado desde que lo leímos.
	// Esto previene que autenticaciones paralelas sobrescriban un contador más nuevo con estado obsoleto.
	err = s.mfaRepo.UpdateCredentialSecretAtomic(matchedCred.ID, oldSecret, string(updatedJSON))
	if err != nil {
		return fmt.Errorf("error persistiendo contador de autenticador actualizado: %w", err)
	}

	return nil
}

// ListWebAuthnCredentials lista todas las llaves físicas y passkeys activas del usuario.
func (s *mfaService) ListWebAuthnCredentials(userID uint) ([]response.WebAuthnKeyItem, error) {
	creds, err := s.mfaRepo.FindActiveWebAuthnCredentialsByUser(userID)
	if err != nil {
		return nil, fmt.Errorf("error al obtener llaves de seguridad: %w", err)
	}

	items := make([]response.WebAuthnKeyItem, len(creds))
	for i, c := range creds {
		items[i] = response.WebAuthnKeyItem{
			ID:        c.ID,
			Name:      c.Name,
			CreatedAt: c.CreatedAt,
		}
	}
	return items, nil
}

// DeleteWebAuthnCredential elimina una llave de seguridad puntual del usuario.
// Si era la última credencial activa y no tiene TOTP, desactiva MFA en el usuario.
func (s *mfaService) DeleteWebAuthnCredential(userID uint, credID uint) error {
	if err := s.mfaRepo.DeleteCredentialByIDAndUser(credID, userID); err != nil {
		return fmt.Errorf("error eliminando llave de seguridad: %w", err)
	}

	remaining, err := s.mfaRepo.CountActiveCredentials(userID)
	if err == nil && remaining == 0 {
		_ = s.userRepo.UpdateColumn("mfa_enabled", false, userID)
		_ = s.mfaRepo.DeleteRecoveryCodesByUser(userID)
	}

	return nil
}

// DisableMFA desactiva MFA completamente: elimina credenciales y códigos de recuperación.
func (s *mfaService) DisableMFA(userID uint) error {
	if !s.IsMfaEnabled(userID) {
		return fmt.Errorf("MFA no está habilitado")
	}
	if err := s.mfaRepo.DeleteCredentialsByUser(userID); err != nil {
		return fmt.Errorf("error eliminando credenciales MFA")
	}
	if err := s.mfaRepo.DeleteRecoveryCodesByUser(userID); err != nil {
		return fmt.Errorf("error eliminando códigos de recuperación")
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
	var webAuthnKeys []response.WebAuthnKeyItem
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			status.WebAuthnConfigured = true
			webAuthnKeys = append(webAuthnKeys, response.WebAuthnKeyItem{
				ID:        c.ID,
				Name:      c.Name,
				CreatedAt: c.CreatedAt,
			})
		}
	}
	status.WebAuthnKeys = webAuthnKeys

	return status, nil
}

// --- Helpers privados ---
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
		return nil, fmt.Errorf("error guardando códigos de recuperación")
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
