package util

const AppIdPeakAuth = "peak-auth"

// BcryptMaxPasswordBytes es el límite real de bcrypt: ignora todo byte más allá del 72.
const BcryptMaxPasswordBytes = 72

// Límites de duración para tokens de sesión (SESSION_POLICY)
const (
	MinTokenExpirationMinutes     = 5
	MaxTokenExpirationMinutes     = 10080 // 7 días
	DefaultTokenExpirationMinutes = 15
)

// Policies
const REGISTRATION_POLICY = "REGISTRATION_POLICY"
const PWD_POLICY = "PWD_POLICY"
const SESSION_POLICY = "SESSION_POLICY"
const AUTHZ_POLICY = "AUTHZ_POLICY"
const MFA_POLICY = "MFA_POLICY"
