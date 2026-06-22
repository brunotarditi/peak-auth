package main

import (
	"log"
	"os"
	"strings"

	"peak-auth/internal/api/middleware"
	"peak-auth/internal/app"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/db"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	// 1) Cargar variables de entorno desde el archivo .env (solo fuera de producción)
	if !util.IsProduction() {
		if err := godotenv.Load(); err != nil {
			log.Println("No se pudo cargar el archivo .env")
		}
	}

	// Modo de Gin: release en producción para no exponer logs de debug.
	if util.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	// 2) Definir puerto
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Println("PORT no definido; usando 8080 por defecto")
	}

	// 3) Conectar a la base de datos
	dbInstance := db.ConnectDB()
	defer db.DisconnectDB()
	db.AutoMigrate()

	jwtManager, err := auth.NewJWTManager()
	if err != nil {
		log.Fatal("Error inicializando JWT:", err)
	}

	// 4) Creamos la instancia de la aplicación con sus servicios
	appInstance := app.NewApp(dbInstance, jwtManager)

	// 5) Gin router con recuperación de panics, logging y cabeceras de seguridad.
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.BaseSecurityHeaders())

	// Configurar proxies de confianza para que ClientIP() (usado por el
	// rate-limiter) no pueda ser falsificado vía X-Forwarded-For. Por defecto
	// no se confía en ningún proxy; se habilitan vía TRUSTED_PROXIES (CSV).
	if tp := os.Getenv("TRUSTED_PROXIES"); tp != "" {
		proxies := strings.Split(tp, ",")
		for i := range proxies {
			proxies[i] = strings.TrimSpace(proxies[i])
		}
		if err := router.SetTrustedProxies(proxies); err != nil {
			log.Printf("advertencia: TRUSTED_PROXIES inválido: %v", err)
		}
	} else {
		_ = router.SetTrustedProxies(nil)
	}

	// 6) Cargar plantillas HTML de forma recursiva e ISOLADA (delegado a util)
	util.SetTemplateRenderer(router)

	// 7) Enrutar
	SetRoutes(router, appInstance)

	appInstance.SetupService.InitializeSystem(port)

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("error starting server: %v", err)
	}

}
