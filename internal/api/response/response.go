package response

type AppStatsResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	AppID       string `json:"app_id"`
	Description string `json:"description"`
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
