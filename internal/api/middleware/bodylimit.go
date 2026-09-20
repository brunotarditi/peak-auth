package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequestBodyLimitMiddleware limits the size of request bodies to prevent
// resource exhaustion attacks via oversized payloads.
func RequestBodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
