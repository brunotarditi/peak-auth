package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimiter implementa un limitador por IP basado en ventana fija en memoria.
// Es suficiente para mitigar fuerza bruta en una sola instancia. Para despliegues
// multi-instancia conviene migrar a un store compartido (Redis).
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
}

type visitor struct {
	count     int
	windowEnd time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}
	go rl.cleanupLoop()
	return rl
}

const maxVisitors = 50000

// allow registra un golpe para la clave y devuelve si está dentro del límite,
// junto con los segundos a esperar (Retry-After) si fue bloqueado.
func (rl *rateLimiter) allow(key string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[key]
	if !ok || now.After(v.windowEnd) {
		// Control de memoria: si la tabla está al tope por spoofing de IPs
		if len(rl.visitors) >= maxVisitors {
			for k, item := range rl.visitors {
				if now.After(item.windowEnd) {
					delete(rl.visitors, k)
				}
			}
			// Si aún sigue al tope, desalojar una entrada para admitir la nueva
			if len(rl.visitors) >= maxVisitors {
				for k := range rl.visitors {
					delete(rl.visitors, k)
					break
				}
			}
		}

		rl.visitors[key] = &visitor{count: 1, windowEnd: now.Add(rl.window)}
		return true, 0
	}

	if v.count >= rl.limit {
		retry := int(time.Until(v.windowEnd).Seconds())
		if retry < 1 {
			retry = 1
		}
		return false, retry
	}

	v.count++
	return true, 0
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, v := range rl.visitors {
			if now.After(v.windowEnd) {
				delete(rl.visitors, k)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware limita la cantidad de peticiones por IP en la ventana dada.
// Pensado para endpoints sensibles (login, refresh, reset) y para frenar fuerza
// bruta incluso contra cuentas privilegiadas (que no se bloquean por diseño).
func RateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	rl := newRateLimiter(limit, window)
	return func(c *gin.Context) {
		ip := clientIP(c)
		allowed, retryAfter := rl.allow(ip)
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "demasiadas solicitudes, intente nuevamente más tarde",
			})
			return
		}
		c.Next()
	}
}

// clientIP obtiene la IP del cliente de forma segura (usa el motor de Gin, que
// respeta los proxies de confianza configurados).
func clientIP(c *gin.Context) string {
	if ip := c.ClientIP(); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return host
}
