package model

import "testing"

// TestAuthCallbackPath rejects URL components, traversal, ambiguous encodings and noncanonical paths.
func TestAuthCallbackPath(t *testing.T) {
	for _, callbackPath := range []string{DefaultAuthCallbackPath, "/", "/signin/complete", "/v2/auth_done"} {
		if err := ValidateAuthCallbackPath(callbackPath); err != nil {
			t.Errorf("valid path %q: %v", callbackPath, err)
		}
	}
	for _, callbackPath := range []string{
		"", "callback", "https://example.com/callback", "//evil.example/callback",
		"/auth/../callback", "/auth/./callback", "/auth//callback", "/auth/callback/",
		"/auth?next=x", "/auth#done", "/%2e%2e/auth", "/%252f/auth",
		"/auth\\callback", "/auth\ncallback",
	} {
		if err := ValidateAuthCallbackPath(callbackPath); err == nil {
			t.Errorf("accepted invalid path %q", callbackPath)
		}
	}
}

// TestAuthPaths requires canonical distinct initiation and callback routes.
func TestAuthPaths(t *testing.T) {
	for _, signInPath := range []string{"/account/start", DefaultAuthSignInPath} {
		if err := ValidateAuthPaths(signInPath, DefaultAuthCallbackPath); err != nil {
			t.Fatal(err)
		}
	}
	for _, signInPath := range []string{"", "//example.com", "/a/../b", "/%2f", "/signin?next=/", DefaultAuthCallbackPath} {
		if err := ValidateAuthPaths(signInPath, DefaultAuthCallbackPath); err == nil {
			t.Errorf("accepted invalid Sign In path %q", signInPath)
		}
	}
}
