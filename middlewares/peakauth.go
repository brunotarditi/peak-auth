package middlewares

import (
	"fmt"
	"net/http"
	"peak-auth/auth"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(manager *auth.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token no provisto"})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		jsonToken, err := manager.VerifyToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token inválido"})
			return
		}

		var userID uint
		_, err = fmt.Sscanf(jsonToken.Subject, "%d", &userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "ID de usuario inválido"})
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}
