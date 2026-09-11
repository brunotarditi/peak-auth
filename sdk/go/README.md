# Peak Auth Go SDK

SDK oficial y liviano de **Peak Auth** para Go. Permite validar tokens JWT asimétricos (RSA-256) de forma offline utilizando el endpoint JWKS automático con cache en memoria, e incluye middlewares listos para usar en **Gin** y **`net/http`**.

---

## 📦 Instalación

```bash
go get github.com/brunotarditi/peak-auth/sdk/go
```

---

## ⚡ Inicio Rápido

### 1. Inicializar el cliente

```go
package main

import (
	"log"

	peakauth "github.com/brunotarditi/peak-auth/sdk/go"
)

func main() {
	client, err := peakauth.New(peakauth.Config{
		IssuerURL: "https://auth.tuempresa.com", // o http://localhost:8080
		ClientID:  "tu_client_id",
		ClientSecret: "tu_client_secret", // Opcional si usas PKCE
		RedirectURI:  "https://tu-app.com/callback",
	})
	if err != nil {
		log.Fatalf("Error inicializando Peak Auth: %v", err)
	}
}
```

---

## 🛡️ Uso con Gin Framework

```go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	peakauth "github.com/brunotarditi/peak-auth/sdk/go"
)

func main() {
	client, _ := peakauth.New(peakauth.Config{
		IssuerURL: "https://auth.tuempresa.com",
		ClientID:  "mi-aplicacion",
	})

	r := gin.Default()

	// Ruta pública
	r.GET("/api/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Ruta protegida (cualquier usuario con token válido)
	r.GET("/api/profile", client.GinMiddleware(), func(c *gin.Context) {
		claims, _ := peakauth.ClaimsFromGin(c)
		c.JSON(http.StatusOK, gin.H{
			"user":   claims.Username,
			"roles":  claims.Roles,
			"app_id": claims.AppID,
		})
	})

	// Ruta que requiere rol ADMIN
	r.GET("/api/admin", client.GinMiddleware("ADMIN"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Acceso de administrador concedido"})
	})

	r.Run(":3000")
}
```

---

## 🌐 Uso con `net/http` Estándar

```go
package main

import (
	"fmt"
	"net/http"

	peakauth "github.com/brunotarditi/peak-auth/sdk/go"
)

func main() {
	client, _ := peakauth.New(peakauth.Config{
		IssuerURL: "https://auth.tuempresa.com",
		ClientID:  "mi-aplicacion",
	})

	mux := http.NewServeMux()

	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := peakauth.ClaimsFromContext(r.Context())
		fmt.Fprintf(w, "Bienvenido, %s! Roles: %v", claims.Username, claims.Roles)
	})

	// Proteger con el middleware estándar
	mux.Handle("/api/admin", client.HTTPMiddleware("ADMIN")(adminHandler))

	http.ListenAndServe(":3000", mux)
}
```

---

## 🔐 Flujo OAuth 2.0 con PKCE

```go
// 1. Generar PKCE
pkce, err := peakauth.GeneratePKCE()
if err != nil {
    // manejar error
}

// 2. Construir la URL de login
loginURL, err := client.GetAuthorizationURL("state-csrf", pkce.CodeChallenge)
// Redirigir al usuario a loginURL...

// 3. En el callback de tu app, canjear código por tokens:
tokens, err := client.ExchangeCode(ctx, code, pkce.CodeVerifier)
if err != nil {
    // manejar error
}
// tokens.AccessToken contiene el JWT
```

---

## 📄 Licencia

MIT © Bruno Tarditi
