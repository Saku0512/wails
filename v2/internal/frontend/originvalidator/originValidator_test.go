package originvalidator

import (
	"net/url"
	"testing"
)

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

func TestWildcardPatternDoesNotCrossDomainBoundaries(t *testing.T) {
	tests := []struct {
		name           string
		allowedOrigins string
		origin         string
		expected       bool
	}{
		// Legitimate subdomain wildcard — should still work
		{
			name:           "subdomain wildcard matches subdomain",
			allowedOrigins: "https://*.myapp.com",
			origin:         "https://api.myapp.com",
			expected:       true,
		},
		{
			name:           "subdomain wildcard matches different subdomain",
			allowedOrigins: "https://*.myapp.com",
			origin:         "https://www.myapp.com",
			expected:       true,
		},
		{
			name:           "subdomain wildcard rejects different domain",
			allowedOrigins: "https://*.myapp.com",
			origin:         "https://evil.com",
			expected:       false,
		},
		{
			name:           "subdomain wildcard rejects suffix domain bypass",
			allowedOrigins: "https://*.myapp.com",
			origin:         "https://api.myapp.com.evil.com",
			expected:       false,
		},
		// Trailing wildcard — the vulnerability vector
		{
			name:           "trailing wildcard rejects different TLD (bypass attempt)",
			allowedOrigins: "https://myapp.com*",
			origin:         "https://myapp.community",
			expected:       false,
		},
		{
			name:           "trailing wildcard rejects attacker subdomain (bypass attempt)",
			allowedOrigins: "https://myapp.com*",
			origin:         "https://myapp.com.attacker.com",
			expected:       false,
		},
		{
			name:           "trailing wildcard rejects arbitrary suffix",
			allowedOrigins: "https://myapp.com*",
			origin:         "https://myapp.comXXXXX",
			expected:       false,
		},
		{
			name:           "leading wildcard rejects partial label suffix bypass",
			allowedOrigins: "https://*myapp.com",
			origin:         "https://evilmyapp.com",
			expected:       false,
		},
		{
			name:           "port wildcard matches port component",
			allowedOrigins: "https://localhost:*",
			origin:         "https://localhost:8080",
			expected:       true,
		},
		{
			name:           "port wildcard rejects suffix domain bypass",
			allowedOrigins: "https://myapp.com:*",
			origin:         "https://myapp.com.evil.com:443",
			expected:       false,
		},
		{
			name:           "partial port wildcard rejects suffix port bypass",
			allowedOrigins: "https://myapp.com:*443",
			origin:         "https://myapp.com:8443",
			expected:       false,
		},
		{
			name:           "partial label wildcard rejects middle wildcard bypass",
			allowedOrigins: "https://myapp.*com",
			origin:         "https://myapp.evilcom",
			expected:       false,
		},
		{
			name:           "partial label wildcard with port rejects suffix domain bypass",
			allowedOrigins: "https://myapp.com*:*",
			origin:         "https://myapp.com.evil.com:443",
			expected:       false,
		},
		{
			name:           "host and port wildcards match separate components",
			allowedOrigins: "https://*.myapp.com:*",
			origin:         "https://api.myapp.com:443",
			expected:       true,
		},
		// Exact match still works
		{
			name:           "exact match",
			allowedOrigins: "https://myapp.com",
			origin:         "https://myapp.com",
			expected:       true,
		},
		{
			name:           "exact match rejects different origin",
			allowedOrigins: "https://myapp.com",
			origin:         "https://evil.com",
			expected:       false,
		},
		// Wildcard does not cross into path or port
		{
			name:           "wildcard does not match across port separator",
			allowedOrigins: "https://localhost*",
			origin:         "https://localhost:8080",
			expected:       false,
		},
		{
			name:           "wildcard does not match across path separator",
			allowedOrigins: "https://myapp*",
			origin:         "https://myapp/evil",
			expected:       false,
		},
		// Empty origin
		{
			name:           "empty origin is rejected",
			allowedOrigins: "https://*.myapp.com",
			origin:         "",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startURL := mustParseURL("https://wails.localhost")
			v := NewOriginValidator(startURL, tt.allowedOrigins)
			got := v.IsOriginAllowed(tt.origin)
			if got != tt.expected {
				t.Errorf("IsOriginAllowed(%q) with pattern %q = %v, want %v",
					tt.origin, tt.allowedOrigins, got, tt.expected)
			}
		})
	}
}

func TestGetOriginFromURLRejectsUserinfoBypass(t *testing.T) {
	startURL := mustParseURL("https://wails.localhost")
	v := NewOriginValidator(startURL, "https://*.myapp.com")

	origin, err := v.GetOriginFromURL("https://api.myapp.com@evil.com")
	if err != nil {
		t.Fatalf("GetOriginFromURL returned error: %v", err)
	}
	if origin != "https://evil.com" {
		t.Fatalf("GetOriginFromURL returned %q, want %q", origin, "https://evil.com")
	}
	if v.IsOriginAllowed(origin) {
		t.Fatalf("IsOriginAllowed(%q) = true, want false", origin)
	}
}
