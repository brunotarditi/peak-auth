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

// isGlobalComponent determina si un archivo HTML es una pieza compartida (Layout, Partial o Component)
func isGlobalComponent(path string) bool {
	cleanPath := filepath.ToSlash(path)
	return strings.Contains(cleanPath, "/layouts/") ||
		strings.Contains(cleanPath, "/partials/") ||
		strings.Contains(cleanPath, "/components/")
}

// NewRenderer construye el cargador de plantillas avanzado.
// Su objetivo es crear un pool de plantillas aisladas por archivo, incluyendo 
// siempre los layouts y componentes comunes para evitar colisiones de bloques entre páginas.
func NewRenderer(root string, funcs template.FuncMap) (render.HTMLRender, error) {
	renderer := MultitemplateRenderer{
		templates: make(map[string]*template.Template),
	}

	// 1. Recolectar todos los archivos HTML y clasificarlos
	var baseStyles []string
	var pageFiles []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".html") {
			return err
		}

		if isGlobalComponent(path) {
			baseStyles = append(baseStyles, path)
		} else {
			pageFiles = append(pageFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	// 2. Procesar cada página de manera independiente
	// Para cada página (ej: login.html), creamos un set de plantillas que incluya:
	// La página misma + Todos los componentes base (piezas comunes).
	for _, pagePath := range pageFiles {
		fileName := filepath.Base(pagePath)
		
		// Creamos la instancia de la plantilla aislada
		t := template.New(fileName).Funcs(funcs)

		// Combinamos la página específica con todos los estilos/layouts base
		allFiles := append([]string{pagePath}, baseStyles...)
		
		if _, err := t.ParseFiles(allFiles...); err != nil {
			return nil, err
		}

		// Registramos la plantilla por el nombre del archivo
		renderer.templates[fileName] = t
	}

	return renderer, nil
}
