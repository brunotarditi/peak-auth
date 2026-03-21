package utils

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin/render"
)

// MultitemplateRenderer gestiona plantillas aisladas para evitar colisiones de bloques
type MultitemplateRenderer struct {
	templates map[string]*template.Template
}

// Instance cumple con la interfaz render.HTMLRender de Gin
func (r MultitemplateRenderer) Instance(name string, data any) render.Render {
	return render.HTML{
		Template: r.templates[name],
		Name:     name,
		Data:     data,
	}
}

// NewRenderer construye el cargador de plantillas avanzado
func NewRenderer(root string, funcs template.FuncMap) (render.HTMLRender, error) {
	renderer := MultitemplateRenderer{
		templates: make(map[string]*template.Template),
	}

	// 1. Encontrar Layouts, Partials y Componentes compartidos
	var baseStyles []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".html") {
			// Normalizar la ruta para que sea independiente del sistema
			cleanPath := filepath.ToSlash(path)

			// Consideramos layouts, partials y cualquier cosa en carpetas específicas como base común
			isComponent := strings.Contains(cleanPath, "/layouts/") ||
				strings.Contains(cleanPath, "/partials/") ||
				strings.Contains(cleanPath, "/components/") 

			if isComponent {
				baseStyles = append(baseStyles, path)
			}
		}
		return nil
	})

	// 2. Cargar cada página de manera aislada
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".html") {
			return nil
		}

		cleanPath := filepath.ToSlash(path)

		// Ignorar layouts, partials y componentes como entry-points directos
		isComponent := strings.Contains(cleanPath, "/layouts/") ||
			strings.Contains(cleanPath, "/partials/") ||
			strings.Contains(cleanPath, "/components/")

		if isComponent {
			return nil
		}

		// Crear un nuevo set de plantillas con las funciones globales
		t := template.New(info.Name()).Funcs(funcs)

		// Parsear el archivo de la página y los estilos base
		files := append(baseStyles, path)
		if _, err := t.ParseFiles(files...); err != nil {
			return err
		}

		renderer.templates[info.Name()] = t
		return nil
	})

	return renderer, err
}
