package broker

import "context"

// BrokerProfile representa el perfil verificado y normalizado recibido de un IdP externo
type BrokerProfile struct {
	Provider       string // "google", "github"
	ProviderUserID string // ID único estable provisto por el IdP (sub o id numérico en string)
	Email          string // Email verificado del usuario
	FirstName      string
	LastName       string
	AvatarURL      string
}

// IdentityProvider define la interfaz común para proveedores de identidad federados
type IdentityProvider interface {
	// GetAuthURL genera la URL de redirección hacia el proveedor con el state firmado
	GetAuthURL(state string) string
	// Exchange intercambia el código de autorización por el perfil del usuario
	Exchange(ctx context.Context, code string) (*BrokerProfile, error)
	// ProviderName devuelve el nombre identificador del proveedor ("google", "github")
	ProviderName() string
}
