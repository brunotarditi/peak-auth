package main

import (
	"errors"
	"html/template"
	"log"
	"os"
	"time"

	"peak-auth/app"
	"peak-auth/auth"
	"peak-auth/db"
	"peak-auth/utils"

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

	// 5) Gin router
	router := gin.New()

	// Registrar funciones globales para templates
	funcMap := template.FuncMap{
		"now": func() time.Time {
			return time.Now()
		},
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, errors.New("invalid dict call")
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, errors.New("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
	}

	// Cargar plantillas HTML de forma recursiva e ISOLADA por cada página
	renderer, err := utils.NewRenderer("templates", funcMap)
	if err != nil {
		log.Fatalf("error initializing template renderer: %v", err)
	}
	router.HTMLRender = renderer

	SetupRoutes(router, appInstance)

	appInstance.SetupService.InitializeSystem(port)

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("error starting server: %v", err)
	}

}
