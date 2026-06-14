package response

type AppStatsResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	AppID       string `json:"app_id"`
	Description string `json:"description"`
	UserCount   int64  `json:"user_count"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserAppRow struct {
	ID           uint
	Email        string
	FirstName    string
	LastName     string
	RoleName     string
	IsVerified   bool
	IsActive     bool
	FailedLogins uint
}
