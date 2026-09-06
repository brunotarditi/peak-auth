package response

type AppStatsResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	AppID       string `json:"app_id"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
	UserCount   int64  `json:"user_count"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	MfaRequired      bool   `json:"mfa_required,omitempty"`
	MfaSetupRequired bool   `json:"mfa_setup_required,omitempty"`
	MfaToken         string `json:"mfa_token,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
}

type UserAppRow struct {
	ID           uint
	Email        string
	FirstName    string
	LastName     string
	RoleName     string
	IsVerified   bool
	IsActive     bool
	MfaEnabled   bool
	FailedLogins uint
}

// TOTPSetupResponse contiene los datos necesarios para configurar TOTP en el authenticator.
type TOTPSetupResponse struct {
	Secret  string `json:"secret"`  // Solo se muestra durante el setup
	QRCode  string `json:"qr_code"` // Imagen QR en base64 (data URI)
	OTPAuth string `json:"otpauth"` // URI otpauth:// para copiar manualmente
}

// MfaStatusResponse indica el estado actual del MFA de un usuario.
type MfaStatusResponse struct {
	Enabled            bool   `json:"enabled"`
	TOTPConfigured     bool   `json:"totp_configured"`
	WebAuthnConfigured bool   `json:"webauthn_configured"`
	TOTPName           string `json:"totp_name,omitempty"`
	RecoveryCodesLeft  int    `json:"recovery_codes_left"`
}
