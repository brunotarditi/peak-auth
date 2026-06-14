package main

import (
	"log"
	"os"

	"peak-auth/internal/app"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/db"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	// 1) Cargar variables de entorno desde el archivo .env
	if os.Getenv("ENV") != "production" {
		if err := godotenv.Load(); err != nil {
			log.Println("No se pudo cargar el archivo .env")
		}
	}

	// 2) Definir puerto
	port := os.Getenv("PORT")
	if port == "" {
		log.Println("No exite el puerto")
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

	// 5) Gin router
	router := gin.New()

	// 6) Cargar plantillas HTML de forma recursiva e ISOLADA (delegado a util)
	util.SetTemplateRenderer(router)

	// 7) Enrutar
	SetRoutes(router, appInstance)

	appInstance.SetupService.InitializeSystem(port)

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("error starting server: %v", err)
	}

}
