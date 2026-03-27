package middleware

import (
	"fmt"
	"net/http"
	"peak-auth/auth"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(manager *auth.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ""
		authHeader := c.GetHeader("Authorization")

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			if cookie, err := c.Cookie("admin_token"); err == nil {
				token = cookie
			}
		}

		if token == "" {
			if strings.HasPrefix(c.Request.URL.Path, "/admin") {
				c.Redirect(http.StatusSeeOther, "/admin/login")
				c.Abort()
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token no provisto"})
			}
			return
		}

		jsonToken, err := manager.VerifyToken(token)
		if err != nil {
			if strings.HasPrefix(c.Request.URL.Path, "/admin") {
				c.SetCookie("admin_token", "", -1, "/", "", false, true)
				c.Redirect(http.StatusSeeOther, "/admin/login")
				c.Abort()
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token inválido"})
			}
			return
		}

		var userID uint
		fmt.Sscanf(jsonToken.Subject, "%d", &userID)
		c.Set("user_id", userID)
		c.Set("user_email", jsonToken.Username)
		c.Set("user_roles", jsonToken.Roles)
		c.Next()
	}
}
