package service

import (
	"fmt"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
)

type applicationThemeService struct {
	appRepo   repo.ApplicationRepository
	themeRepo repo.ApplicationThemeRepository
}

func newApplicationThemeService(appRepo repo.ApplicationRepository, themeRepo repo.ApplicationThemeRepository) *applicationThemeService {
	return &applicationThemeService{appRepo: appRepo, themeRepo: themeRepo}
}

func (s *applicationThemeService) get(publicAppID string) (*model.ApplicationTheme, error) {
	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return nil, err
	}
	if s.themeRepo == nil {
		return nil, nil
	}
	return s.themeRepo.FindByAppID(app.ID)
}

func (s *applicationThemeService) update(publicAppID string, theme *model.ApplicationTheme) error {
	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return err
	}
	if theme == nil {
		return fmt.Errorf("tema inválido")
	}
	theme.ApplicationID = app.ID
	if theme.PrimaryColor != "" {
		theme.PrimaryColor = util.SanitizeHexColor(theme.PrimaryColor)
	}
	if s.themeRepo == nil {
		return fmt.Errorf("repositorio de temas no disponible")
	}
	return s.themeRepo.Upsert(theme)
}

func (s *applicationThemeService) reset(publicAppID string) error {
	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return err
	}
	if s.themeRepo == nil {
		return nil
	}
	return s.themeRepo.DeleteByAppID(app.ID)
}
