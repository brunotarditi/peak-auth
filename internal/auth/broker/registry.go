package broker

import "fmt"

type Registry struct {
	providers map[string]IdentityProvider
}

func NewRegistry(cfg BrokerConfig) *Registry {
	r := &Registry{
		providers: make(map[string]IdentityProvider),
	}

	if cfg.IsGoogleConfigured() {
		r.providers["google"] = NewGoogleProvider(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL)
	}

	if cfg.IsGitHubConfigured() {
		r.providers["github"] = NewGitHubProvider(cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubRedirectURL)
	}

	return r
}

func (r *Registry) Register(p IdentityProvider) {
	r.providers[p.ProviderName()] = p
}

func (r *Registry) Get(provider string) (IdentityProvider, error) {
	p, ok := r.providers[provider]
	if !ok {
		return nil, fmt.Errorf("proveedor de identidad '%s' no está configurado o no es soportado", provider)
	}
	return p, nil
}

func (r *Registry) IsConfigured(provider string) bool {
	_, ok := r.providers[provider]
	return ok
}

func (r *Registry) ListAvailable() []string {
	list := make([]string, 0, len(r.providers))
	for name := range r.providers {
		list = append(list, name)
	}
	return list
}
