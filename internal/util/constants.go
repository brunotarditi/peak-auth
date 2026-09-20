package util

const AppIdPeakAuth = "peak-auth"

// BcryptMaxPasswordBytes es el límite real de bcrypt: ignora todo byte más allá
// del 72. Validar explícitamente evita truncados silenciosos.
const BcryptMaxPasswordBytes = 72

// Límites de duración para tokens de sesión (SESSION_POLICY)
const (
	MinTokenExpirationMinutes     = 5
	MaxTokenExpirationMinutes     = 10080 // 7 días (10080 minutos)
	DefaultTokenExpirationMinutes = 15
)
