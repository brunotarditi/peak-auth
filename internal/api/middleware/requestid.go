package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// RequestIDHeader es la cabecera estándar HTTP para rastreo de solicitudes.
	RequestIDHeader = "X-Request-ID"
	// RequestIDKey es la clave utilizada en el contexto de Gin para almacenar el ID.
	RequestIDKey = "request_id"
)

// RequestIDMiddleware extrae o genera un identificador único por solicitud (Correlation ID).
// Si el cliente o el proxy/load-balancer envía un X-Request-ID seguro, se reutiliza.
// Si no viene o no es válido, genera un ID aleatorio criptográficamente seguro de 32 caracteres hex.
// El ID se propaga en la cabecera HTTP de respuesta y en el contexto de Gin.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := strings.TrimSpace(c.GetHeader(RequestIDHeader))

		// Validar que el ID entrante sea seguro y no exceda un largo razonable
		if reqID == "" || len(reqID) > 128 || strings.ContainsAny(reqID, "\r\n") {
			var b [16]byte
			_, _ = rand.Read(b[:])
			reqID = hex.EncodeToString(b[:])
		}

		c.Set(RequestIDKey, reqID)
		c.Header(RequestIDHeader, reqID)
		c.Next()
	}
}

// GetRequestID recupera el correlation ID del contexto de Gin, o una cadena vacía si no existe.
func GetRequestID(c *gin.Context) string {
	if val, ok := c.Get(RequestIDKey); ok {
		if id, ok := val.(string); ok {
			return id
		}
	}
	return ""
}
