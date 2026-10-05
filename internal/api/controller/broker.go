package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"peak-auth/internal/audit"
	"peak-auth/internal/auth"
	"peak-auth/internal/auth/broker"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"time"

	"github.com/gin-gonic/gin"
)

type BrokerController struct {
	BrokerService service.BrokerService
	TokenManager  *auth.JWTManager
	AppService    service.ApplicationService
	RuleService   service.ApplicationRuleService
}

func NewBrokerController(
	brokerService service.BrokerService,
	tokenManager *auth.JWTManager,
	appService service.ApplicationService,
	ruleService service.ApplicationRuleService,
) *BrokerController {
	return &BrokerController{
		BrokerService: brokerService,
		TokenManager:  tokenManager,
		AppService:    appService,
		RuleService:   ruleService,
	}
}

// AuthEndpoint inicia el flujo de autorización externa redirigiendo al proveedor
// GET /oauth/broker/:provider/auth
func (c *BrokerController) AuthEndpoint(ctx *gin.Context) {
	provider := ctx.Param("provider")
	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	state := ctx.Query("state")
	codeChallenge := ctx.Query("code_challenge")
	codeChallengeMethod := ctx.Query("code_challenge_method")

	if clientID == "" || redirectURI == "" {
		ctx.String(http.StatusBadRequest, "client_id y redirect_uri son requeridos")
		return
	}

	nonce, nerr := broker.GenerateNonce()
	if nerr != nil {
		ctx.String(http.StatusInternalServerError, "error generando estado de seguridad")
		return
	}

	relay := broker.RelayState{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
	}

	authURL, err := c.BrokerService.GetAuthURL(provider, relay)
	if err != nil {
		loginURL := url.URL{Path: "/oauth/login"}
		q := loginURL.Query()
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("state", state)
		q.Set("error", err.Error())
		if codeChallenge != "" {
			q.Set("code_challenge", codeChallenge)
			q.Set("code_challenge_method", codeChallengeMethod)
		}
		loginURL.RawQuery = q.Encode()
		ctx.Redirect(http.StatusSeeOther, loginURL.String())
		return
	}

	// Vincular el nonce al navegador del usuario vía cookie HttpOnly SameSite=Lax para mitigar Login CSRF
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie(
		"broker_nonce",
		nonce,
		600, // 10 minutos (misma duración máxima que el RelayState)
		"/oauth/broker",
		"",
		util.IsProduction(),
		true, // HttpOnly
	)

	ctx.Redirect(http.StatusFound, authURL)
}

// CallbackEndpoint procesa el retorno desde el proveedor de identidad externo
// GET /oauth/broker/:provider/callback
func (c *BrokerController) CallbackEndpoint(ctx *gin.Context) {
	provider := ctx.Param("provider")
	code := ctx.Query("code")
	rawState := ctx.Query("state")
	providerError := ctx.Query("error")
	providerErrorDesc := ctx.Query("error_description")

	// Si el usuario canceló en la pantalla del proveedor
	if providerError != "" {
		errMsg := fmt.Sprintf("Autenticación con %s cancelada o denegada", provider)
		if providerErrorDesc != "" {
			errMsg = fmt.Sprintf("%s: %s", errMsg, providerErrorDesc)
		}
		c.redirectToLoginWithError(ctx, rawState, errMsg)
		return
	}

	if code == "" || rawState == "" {
		c.redirectToLoginWithError(ctx, rawState, "Respuesta incompleta del proveedor de identidad")
		return
	}

	// Validar y destruir de inmediato la cookie de nonce para vincular la petición al navegador y prevenir Replay
	cookieNonce, _ := ctx.Cookie("broker_nonce")
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("broker_nonce", "", -1, "/oauth/broker", "", util.IsProduction(), true)

	if cookieNonce == "" {
		c.redirectToLoginWithError(ctx, rawState, "Sesión de autenticación social inválida o expirada (Login CSRF prevenido)")
		return
	}

	res, err := c.BrokerService.ProcessCallback(ctx.Request.Context(), provider, code, rawState, cookieNonce)
	if err != nil {
		c.redirectToLoginWithError(ctx, rawState, err.Error())
		return
	}

	audit.Event(ctx, "user.broker_login", fmt.Sprintf("provider=%s user_id=%d email=%s", provider, res.User.ID, res.User.Email))

	// Caso MFA: Redirigir al desafío de segundo factor
	if res.MfaRequired {
		c.setMfaCookie(ctx, res.MfaToken)
		ctx.Redirect(http.StatusSeeOther, res.RedirectURL)
		return
	}

	// Caso Éxito: Establecer cookie de sesión SSO HttpOnly
	if err := c.setSSOSessionCookie(ctx, res.User.ID, res.User.Email, false, res.User.AuthzVersion); err != nil {
		c.redirectToLoginWithError(ctx, rawState, "Error al inicializar sesión SSO")
		return
	}

	// Redirigir a /oauth/authorize para completar el flujo PKCE y emitir authorization_code
	ctx.Redirect(http.StatusSeeOther, res.RedirectURL)
}

func (c *BrokerController) redirectToLoginWithError(ctx *gin.Context, rawState, errMsg string) {
	loginURL := url.URL{Path: "/oauth/login"}
	q := loginURL.Query()
	q.Set("error", errMsg)

	// Recuperar parámetros de app desde el state para no perder el contexto PKCE
	if rawState != "" {
		if relay, err := broker.ExtractRelayState(rawState); err == nil && relay != nil {
			if relay.ClientID != "" {
				q.Set("client_id", relay.ClientID)
			}
			if relay.RedirectURI != "" {
				q.Set("redirect_uri", relay.RedirectURI)
			}
			if relay.State != "" {
				q.Set("state", relay.State)
			}
			if relay.CodeChallenge != "" {
				q.Set("code_challenge", relay.CodeChallenge)
				q.Set("code_challenge_method", relay.CodeChallengeMethod)
			}
		}
	}

	loginURL.RawQuery = q.Encode()
	ctx.Redirect(http.StatusSeeOther, loginURL.String())
}

func (c *BrokerController) setSSOSessionCookie(ctx *gin.Context, userID uint, username string, mfaVerified bool, authzVersion uint) error {
	duration := time.Duration(util.DefaultTokenExpirationMinutes) * time.Minute
	if c.AppService != nil && c.RuleService != nil {
		app, err := c.AppService.GetAppDetails(util.AppIdPeakAuth)
		if err == nil {
			rules, rerr := c.RuleService.FindRulesByAppID(app.ID)
			if rerr == nil {
				for _, r := range rules {
					if r.Code == "SESSION_POLICY" {
						sess, perr := util.ValidateSessionPolicy(r.Value)
						if perr == nil {
							duration = time.Duration(sess.TokenExpirationMinutes) * time.Minute
							break
						}
					}
				}
			}
		}
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, duration, mfaVerified, authzVersion)
	if err != nil {
		return fmt.Errorf("no se pudo generar la sesión SSO: %w", err)
	}

	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, int(duration.Seconds()), "/", "", util.IsProduction(), true)
	return nil
}

func (c *BrokerController) setMfaCookie(ctx *gin.Context, mfaToken string) {
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie(
		"mfa_pending",
		mfaToken,
		300,
		"/oauth/login/mfa",
		"",
		util.IsProduction(),
		true,
	)
}
