package util

import "testing"

func TestDetectDeviceType(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Empty User-Agent",
			userAgent: "",
			want:      "API Client",
		},
		{
			name:      "Go HTTP Client",
			userAgent: "Go-http-client/1.1",
			want:      "API / Go Client",
		},
		{
			name:      "Node.js Axios",
			userAgent: "axios/1.6.0",
			want:      "API / Node.js",
		},
		{
			name:      "Python requests",
			userAgent: "python-requests/2.31.0",
			want:      "API / Python",
		},
		{
			name:      "Postman",
			userAgent: "PostmanRuntime/7.32.3",
			want:      "API Client",
		},
		{
			name:      "Chrome on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
			want:      "Chrome en Windows",
		},
		{
			name:      "Edge on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
			want:      "Edge en Windows",
		},
		{
			name:      "Firefox on Linux",
			userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
			want:      "Firefox en Linux",
		},
		{
			name:      "Safari on iPhone",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			want:      "Safari en iOS",
		},
		{
			name:      "iPad Safari",
			userAgent: "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			want:      "Safari en iPadOS",
		},
		{
			name:      "Android Chrome",
			userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36",
			want:      "Chrome en Android",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectDeviceType(tc.userAgent)
			if got != tc.want {
				t.Errorf("DetectDeviceType(%q) = %q, want %q", tc.userAgent, got, tc.want)
			}
		})
	}
}
