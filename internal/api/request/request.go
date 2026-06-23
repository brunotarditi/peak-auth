package request

import (
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username  string `json:"username" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	AppID     string `json:"app_id" binding:"required"`
	Password  string `json:"password" binding:"required,min=6,max=72"`
	FirstName string `json:"first_name" binding:"required,max=50"`
	LastName  string `json:"last_name" binding:"required,max=50"`
}

func (r RegisterRequest) ToUser() (model.User, error) {
	hashedPassword, err := util.HashPassword(r.Password)
	if err != nil {
		return model.User{}, err
	}

	return model.User{
		Email:    r.Email,
		Password: hashedPassword,
	}, nil
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type Role struct {
	RoleName string `json:"role"`
}

type UserRequest struct {
	IsActive bool `json:"is_active"`
}

// func (r UserRequest) ToModel() (model.User, error) {
// 	return model.User{
// 		IsActive: r.IsActive,
// 	}, nil
// }

// func (r UserRequest) UpdateModel(existing model.User) (model.User, error) {
// 	existing.IsActive = r.IsActive
// 	return existing, nil
// }
