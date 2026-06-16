package util

import (
	"bytes"
	"errors"
	"html/template"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func RenderVerificationEmail(path string, data any) (string, error) {
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GetTemplateFuncMap retorna el mapa global de funciones para templates
func GetTemplateFuncMap() template.FuncMap {
	return template.FuncMap{
		"sub": func(a interface{}, b interface{}) int {
			var valA int
			var valB int
			switch v := a.(type) {
			case int:
				valA = v
			case int64:
				valA = int(v)
			case uint:
				valA = int(v)
			}
			switch v := b.(type) {
			case int:
				valB = v
			case int64:
				valB = int(v)
			case uint:
				valB = int(v)
			}
			return valA - valB
		},
		"safe_slice": func(s string, start, end int) string {
			if len(s) == 0 {
				return ""
			}
			if start < 0 {
				start = 0
			}
			if end > len(s) {
				end = len(s)
			}
			if start > end {
				return ""
			}
			return s[start:end]
		},
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
		"asset": func(path string) string {
			return Asset(path)
		},
		"js": func(name string) string {
			return JS(name)
		},
		"year": func() int {
			return time.Now().Year()
		},
		"version": func() string {
			return "1.0.0"
		},
		"env": func() string {
			e := os.Getenv("ENV")
			if e == "" {
				return "development"
			}
			return e
		},
	}
}

// SetupRenderer inicializa el renderer de Gin con las funciones globales y las plantillas
func SetTemplateRenderer(router *gin.Engine) {
	renderer, err := NewRenderer("web/templates", GetTemplateFuncMap())
	if err != nil {
		log.Fatalf("error initializing template renderer: %v", err)
	}
	router.HTMLRender = renderer
}
