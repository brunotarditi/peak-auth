package main

import (
	"log"
	"os"

	"peak-auth/app"
	"peak-auth/auth"
	"peak-auth/db"
	"peak-auth/repositories"
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

	if err := router.Run(":9009"); err != nil {
		log.Fatalf("error starting server: %v", err)
	}

}

// TODO: revisar tema ENV y token, hacer debug
func setupInitializer(setupToken string, port string, systemRepo repositories.SetupRepository) {
	// Si es el primer inicio (no hay usuarios), generar o imprimir la URL de setup con token
	if first, err := systemRepo.IsFirstRun(); err != nil {
		log.Printf("error verificando primer inicio: %v", err)
	} else if first {
		if setupToken == "" {
			// Generar token usando utilitario central
			tok, _, gerr := utils.GenerateToken(16)
			if gerr != nil {
				log.Printf("no se pudo generar SETUP_TOKEN: %v", gerr)
			} else {
				setupToken = tok
				// Intentar persistir en .env si no estamos en producción
				if os.Getenv("ENV") != "production" {
					f, err := os.OpenFile(".env", os.O_APPEND|os.O_WRONLY, 0600)
					if err == nil {
						if _, err := f.WriteString("\nSETUP_TOKEN=" + setupToken + "\n"); err != nil {
							log.Printf("no se pudo escribir SETUP_TOKEN en .env: %v", err)
						} else {
							log.Println("SETUP_TOKEN añadido a .env")
						}
						f.Close()
					} else {
						log.Printf("no se pudo abrir .env para añadir SETUP_TOKEN: %v", err)
					}
				} else {
					log.Println("SETUP_TOKEN generado; exportalo en producción antes de iniciar")
				}
			}
		}

		host := os.Getenv("HOST")
		if host == "" {
			host = "localhost"
		}
		log.Printf("URL de setup (primer inicio): http://%s:%s/admin/setup?token=%s", host, port, setupToken)
	}
}
