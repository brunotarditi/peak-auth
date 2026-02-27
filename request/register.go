package request

import (
	"peak-auth/model"
	"peak-auth/utils"
)

type RegisterRequest struct {
	Username  string `json:"username" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	AppID     string `json:"app_id" binding:"required"`
	Password  string `json:"password" binding:"required,min=6"`
	FirstName string `json:"first_name" binding:"required,max=50"`
	LastName  string `json:"last_name" binding:"required,max=50"`
}

func (r RegisterRequest) ToUser() (model.User, error) {
	hashedPassword, err := utils.HashPassword(r.Password)
	if err != nil {
		return model.User{}, err
	}

	return model.User{
		Email:    r.Email,
		Password: hashedPassword,
	}, nil
}
