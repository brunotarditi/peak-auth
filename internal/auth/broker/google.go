package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GoogleProvider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string, client ...*http.Client) *GoogleProvider {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if len(client) > 0 && client[0] != nil {
		httpClient = client[0]
	}
	return &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   httpClient,
	}
}

func (p *GoogleProvider) ProviderName() string {
	return "google"
}

func (p *GoogleProvider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", p.clientID)
	params.Set("redirect_uri", p.redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	params.Set("access_type", "online")
	params.Set("prompt", "select_account")

	return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?%s", params.Encode())
}

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type googleUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string) (*BrokerProfile, error) {
	if code == "" {
		return nil, errors.New("código de autorización de Google vacío")
	}

	// 1. Intercambio de código por tokens
	tokenURL := "https://oauth2.googleapis.com/token"
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("redirect_uri", p.redirectURL)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creando solicitud de token Google: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error de conexión con Google token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, fmt.Errorf("error leyendo respuesta de Google token: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp googleTokenResponse
		_ = json.Unmarshal(body, &errResp)
		if errResp.ErrorDesc != "" {
			return nil, fmt.Errorf("error de Google token: %s (%s)", errResp.Error, errResp.ErrorDesc)
		}
		return nil, fmt.Errorf("Google token endpoint retornó status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp googleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("error parseando JSON de Google token: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, errors.New("Google no retornó access_token")
	}

	// 2. Consulta de información de usuario (OIDC UserInfo)
	userInfoURL := "https://openidconnect.googleapis.com/v1/userinfo"
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando solicitud userinfo Google: %w", err)
	}
	userReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenResp.AccessToken))
	userReq.Header.Set("Accept", "application/json")

	userResp, err := p.httpClient.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("error de conexión con Google userinfo: %w", err)
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(io.LimitReader(userResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("error leyendo userinfo de Google: %w", err)
	}

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google userinfo retornó status %d: %s", userResp.StatusCode, string(userBody))
	}

	var userInfo googleUserInfoResponse
	if err := json.Unmarshal(userBody, &userInfo); err != nil {
		return nil, fmt.Errorf("error parseando JSON userinfo de Google: %w", err)
	}

	if userInfo.Sub == "" {
		return nil, errors.New("Google no proveyó identificador 'sub'")
	}
	if userInfo.Email == "" {
		return nil, errors.New("Google no proveyó correo electrónico")
	}
	if !userInfo.EmailVerified {
		return nil, errors.New("la cuenta de Google no tiene el email verificado")
	}

	firstName := userInfo.GivenName
	lastName := userInfo.FamilyName
	if firstName == "" && userInfo.Name != "" {
		parts := strings.SplitN(userInfo.Name, " ", 2)
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = parts[1]
		}
	}

	return &BrokerProfile{
		Provider:       "google",
		ProviderUserID: userInfo.Sub,
		Email:          strings.ToLower(strings.TrimSpace(userInfo.Email)),
		FirstName:      firstName,
		LastName:       lastName,
		AvatarURL:      userInfo.Picture,
	}, nil
}
