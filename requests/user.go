package requests

import (
	"peak-auth/models"
)

type UserRequest struct {
	IsActive bool `json:"is_active"`
}

func (r UserRequest) ToModel() (models.User, error) {
	return models.User{
		IsActive: r.IsActive,
	}, nil
}

func (r UserRequest) UpdateModel(existing models.User) (models.User, error) {
	existing.IsActive = r.IsActive
	return existing, nil
}
