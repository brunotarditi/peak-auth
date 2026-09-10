package middleware

import (
	"fmt"
	"net/http"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(manager *auth.JWTManager, userRepo ...repo.UserRepository) gin.HandlerFunc {
	var uRepo repo.UserRepository
	if len(userRepo) > 0 {
		uRepo = userRepo[0]
	}

	return func(c *gin.Context) {
		token := extractToken(c)

		if token == "" {
			handleUnauthorized(c)
			return
		}

		jsonToken, err := manager.VerifyTokenForApp(token, util.AppIdPeakAuth)
		if err != nil {
			handleAuthError(c, err)
			return
		}

		if !jsonToken.MfaVerified || jsonToken.TokenType != "access" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "se requiere completar la verificación MFA",
			})
			return
		}

		userID, err := strconv.ParseUint(jsonToken.Subject, 10, 32)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token con formato inválido"})
			return
		}

		if uRepo != nil {
			user, err := uRepo.FindById(uint(userID))
			if err != nil || !user.IsActive {
				handleUnauthorized(c)
				return
			}
			// Si la contraseña fue restablecida con posterioridad a la emisión del token, invalidarlo
			if user.PasswordChangedAt != nil && jsonToken.IssuedAt != nil {
				if jsonToken.IssuedAt.Time.Before(*user.PasswordChangedAt) {
					handleAuthError(c, fmt.Errorf("token invalidado por cambio de contraseña"))
					return
				}
			}
		}

		c.Set("user_id", uint(userID))
		c.Set("user_email", jsonToken.Username)
		c.Set("user_roles", jsonToken.Roles)
		c.Set("is_authenticated", true)

		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	if cookie, err := c.Cookie("admin_token"); err == nil {
		return cookie
	}
	return ""
}

func handleUnauthorized(c *gin.Context) {
	if strings.HasPrefix(c.Request.URL.Path, "/admin") {
		c.Redirect(http.StatusSeeOther, "/admin/login")
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token no provisto"})
	}
	c.Abort()
}

func handleAuthError(c *gin.Context, _ error) {
	if strings.HasPrefix(c.Request.URL.Path, "/admin") {
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("admin_token", "", -1, "/", "", util.IsProduction(), true)
		c.Redirect(http.StatusSeeOther, "/admin/login")
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token inválido o expirado"})
	}
	c.Abort()
}
