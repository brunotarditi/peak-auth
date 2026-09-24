package util

import "strings"

// DetectionStrategy define la interfaz del patrón Strategy para clasificar clientes y dispositivos.
type DetectionStrategy interface {
	Match(ua string) (string, bool)
}

// apiClientStrategy identifica clientes HTTP backend, SDKs y herramientas de desarrollo mediante reglas tabulares.
type apiClientStrategy struct {
	rules []struct {
		keywords []string
		name     string
	}
}

func newApiClientStrategy() *apiClientStrategy {
	return &apiClientStrategy{
		rules: []struct {
			keywords []string
			name     string
		}{
			{keywords: []string{"go-http-client"}, name: "API / Go Client"},
			{keywords: []string{"axios", "node-fetch", "undici"}, name: "API / Node.js"},
			{keywords: []string{"python-requests", "urllib", "aiohttp"}, name: "API / Python"},
			{keywords: []string{"okhttp", "apache-httpclient", "java/"}, name: "API / Java"},
			{keywords: []string{"guzzlehttp"}, name: "API / PHP"},
			{keywords: []string{"curl", "postman", "insomnia", "httpie", "wget"}, name: "API Client"},
		},
	}
}

func (s *apiClientStrategy) Match(ua string) (string, bool) {
	for _, rule := range s.rules {
		for _, kw := range rule.keywords {
			if strings.Contains(ua, kw) {
				return rule.name, true
			}
		}
	}
	return "", false
}

// webBrowserStrategy identifica el navegador y el sistema operativo mediante reglas desacopladas.
type webBrowserStrategy struct {
	osRules []struct {
		keywords []string
		name     string
		isTablet bool
		isMobile bool
	}
	browserRules []struct {
		keyword string
		name    string
		exclude string
	}
}

func newWebBrowserStrategy() *webBrowserStrategy {
	return &webBrowserStrategy{
		osRules: []struct {
			keywords []string
			name     string
			isTablet bool
			isMobile bool
		}{
			{keywords: []string{"ipad"}, name: "iPadOS", isTablet: true},
			{keywords: []string{"tablet"}, name: "Android Tablet", isTablet: true},
			{keywords: []string{"iphone"}, name: "iOS", isMobile: true},
			{keywords: []string{"android"}, name: "Android", isMobile: true},
			{keywords: []string{"windows"}, name: "Windows"},
			{keywords: []string{"macintosh", "mac os"}, name: "macOS"},
			{keywords: []string{"cros"}, name: "ChromeOS"},
			{keywords: []string{"linux", "x11"}, name: "Linux"},
		},
		browserRules: []struct {
			keyword string
			name    string
			exclude string
		}{
			{keyword: "edg/", name: "Edge"},
			{keyword: "opr/", name: "Opera"},
			{keyword: "opera", name: "Opera"},
			{keyword: "chrome/", name: "Chrome"},
			{keyword: "crios/", name: "Chrome"},
			{keyword: "firefox/", name: "Firefox"},
			{keyword: "fxios/", name: "Firefox"},
			{keyword: "safari/", name: "Safari", exclude: "chrome"},
		},
	}
}

func (s *webBrowserStrategy) Match(ua string) (string, bool) {
	var osName string
	var isTablet, isMobile bool

	// Caso especial: Android Tablet (android sin palabra clave mobile)
	if strings.Contains(ua, "android") && !strings.Contains(ua, "mobile") {
		osName = "Android Tablet"
		isTablet = true
	} else {
		for _, rule := range s.osRules {
			matched := false
			for _, kw := range rule.keywords {
				if strings.Contains(ua, kw) {
					osName = rule.name
					isTablet = rule.isTablet
					isMobile = rule.isMobile
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}

	var browserName string
	for _, rule := range s.browserRules {
		if strings.Contains(ua, rule.keyword) {
			if rule.exclude == "" || !strings.Contains(ua, rule.exclude) {
				browserName = rule.name
				break
			}
		}
	}

	if browserName != "" && osName != "" {
		return browserName + " en " + osName, true
	}
	if osName != "" {
		if isTablet {
			return "Tablet (" + osName + ")", true
		}
		if isMobile {
			return "Móvil (" + osName + ")", true
		}
		return "Desktop (" + osName + ")", true
	}
	if browserName != "" {
		return browserName, true
	}

	if isTablet {
		return "Tablet", true
	}
	if isMobile {
		return "Móvil", true
	}

	return "", false
}

// detectionPipeline contiene las estrategias registradas en orden de prioridad.
var detectionPipeline = []DetectionStrategy{
	newApiClientStrategy(),
	newWebBrowserStrategy(),
}

// DetectDeviceType clasifica el User-Agent aplicando el patrón Strategy en orden de prioridad.
func DetectDeviceType(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return "API Client"
	}

	for _, strategy := range detectionPipeline {
		if result, ok := strategy.Match(ua); ok {
			return result
		}
	}

	return "Desktop"
}
