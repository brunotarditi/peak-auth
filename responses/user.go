package responses

import "time"

type UserResponse struct {
	ID        uint      `json:"id"`
	Username  string    `json:"user_name"`
	CreatedAt time.Time `json:"created_at"`
	IsActive  bool      `json:"is_active"`
	LastLogin time.Time `json:"last_login"`
	Roles     []string  `json:"roles"`
}
