package request

import (
	"peak-auth/model"
)

type UserRequest struct {
	IsActive bool `json:"is_active"`
}

func (r UserRequest) ToModel() (model.User, error) {
	return model.User{
		IsActive: r.IsActive,
	}, nil
}

func (r UserRequest) UpdateModel(existing model.User) (model.User, error) {
	existing.IsActive = r.IsActive
	return existing, nil
}
