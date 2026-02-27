package main

import (
	"log"
	"os"

	"peak-auth/app"
	"peak-auth/auth"
	"peak-auth/db"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	// 1) Cargar variables de entorno desde el archivo .env
	if os.Getenv("ENV") != "production" {
		if err := godotenv.Load(); err != nil {
			log.Println("No se pudo cargar .env, probablemente estés en producción")
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		log.Println("No exite el puerto")
	}

	// 2) Conectar a la base de datos
	dbInstance := db.ConnectDB()
	defer db.DisconnectDB()
	db.AutoMigrate()

	jwtManager, err := auth.NewJWTManager()
	if err != nil {
		log.Fatal("Error inicializando JWT:", err)
	}

	// 3) Creamos la instancia de la aplicación con sus servicios
	appInstance := app.NewApp(dbInstance, jwtManager)

	// 4) Inicializar sistema
	//setupInitializer(setupToken, port, systemRepo)

	// 5) Gin router (templates se cargan ahora; rutas se registran tras crear setupSvc)
	router := gin.New()
	// Cargar plantillas HTML
	router.LoadHTMLGlob("templates/**/*.html")

	SetupRoutes(router, appInstance)

	appInstance.SetupService.InitializeSystem(port)

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("error starting server: %v", err)
	}

}
