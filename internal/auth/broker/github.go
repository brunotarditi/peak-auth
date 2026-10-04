package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type GitHubProvider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client
}

func NewGitHubProvider(clientID, clientSecret, redirectURL string, client ...*http.Client) *GitHubProvider {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if len(client) > 0 && client[0] != nil {
		httpClient = client[0]
	}
	return &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   httpClient,
	}
}

func (p *GitHubProvider) ProviderName() string {
	return "github"
}

func (p *GitHubProvider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", p.clientID)
	params.Set("redirect_uri", p.redirectURL)
	params.Set("scope", "read:user user:email")
	params.Set("state", state)

	return fmt.Sprintf("https://github.com/login/oauth/authorize?%s", params.Encode())
}

type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type githubUserResponse struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Email     string `json:"email"`
}

type githubEmailItem struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *GitHubProvider) Exchange(ctx context.Context, code string) (*BrokerProfile, error) {
	if code == "" {
		return nil, errors.New("código de autorización de GitHub vacío")
	}

	// 1. Intercambio de código por token
	tokenURL := "https://github.com/login/oauth/access_token"
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("redirect_uri", p.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creando solicitud de token GitHub: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error de conexión con GitHub token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("error leyendo respuesta de GitHub token: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub token endpoint retornó status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp githubTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("error parseando JSON de GitHub token: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("error de GitHub token: %s (%s)", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("GitHub no retornó access_token")
	}

	// 2. Consulta de información de usuario principal
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("error creando solicitud /user de GitHub: %w", err)
	}
	userReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenResp.AccessToken))
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userReq.Header.Set("User-Agent", "PeakAuth-Broker")

	userResp, err := p.httpClient.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("error de conexión con GitHub /user: %w", err)
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(io.LimitReader(userResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("error leyendo /user de GitHub: %w", err)
	}

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub /user retornó status %d: %s", userResp.StatusCode, string(userBody))
	}

	var ghUser githubUserResponse
	if err := json.Unmarshal(userBody, &ghUser); err != nil {
		return nil, fmt.Errorf("error parseando JSON /user de GitHub: %w", err)
	}

	if ghUser.ID == 0 {
		return nil, errors.New("GitHub no proveyó ID de usuario")
	}

	// 3. Consulta de emails (para resolver email primario y verificado aunque el perfil sea privado)
	verifiedEmail := ghUser.Email

	emailsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err == nil {
		emailsReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenResp.AccessToken))
		emailsReq.Header.Set("Accept", "application/vnd.github+json")
		emailsReq.Header.Set("User-Agent", "PeakAuth-Broker")

		emailsResp, err := p.httpClient.Do(emailsReq)
		if err == nil {
			defer emailsResp.Body.Close()
			if emailsResp.StatusCode == http.StatusOK {
				emailsBody, _ := io.ReadAll(io.LimitReader(emailsResp.Body, 1<<20))
				var emailList []githubEmailItem
				if err := json.Unmarshal(emailsBody, &emailList); err == nil {
					for _, item := range emailList {
						if item.Primary && item.Verified {
							verifiedEmail = item.Email
							break
						}
					}
					// Si ninguno era primario y verificado, buscar cualquiera verificado
					if verifiedEmail == "" {
						for _, item := range emailList {
							if item.Verified {
								verifiedEmail = item.Email
								break
							}
						}
					}
				}
			}
		}
	}

	if verifiedEmail == "" {
		return nil, errors.New("no se encontró ningún correo verificado asociado a la cuenta de GitHub")
	}

	firstName := ghUser.Name
	lastName := ""
	if firstName == "" {
		firstName = ghUser.Login
	} else {
		parts := strings.SplitN(ghUser.Name, " ", 2)
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = parts[1]
		}
	}

	return &BrokerProfile{
		Provider:       "github",
		ProviderUserID: strconv.FormatInt(ghUser.ID, 10),
		Email:          strings.ToLower(strings.TrimSpace(verifiedEmail)),
		FirstName:      firstName,
		LastName:       lastName,
		AvatarURL:      ghUser.AvatarURL,
	}, nil
}
