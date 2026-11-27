package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCredentialRequestsRefuseRedirects checks that the CLI never follows a
// redirect, which would resend a credential to its target, and leaves the
// caller's own client unchanged.
func TestCredentialRequestsRefuseRedirects(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { reached = true }))
	defer target.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	callerClient := &http.Client{}
	args := &Args{HTTPClient: callerClient}
	err := postJSON(context.Background(), args.httpClient(), redirecting.URL, struct{}{}, &struct{}{})
	if err == nil {
		t.Fatal("a redirected credential request succeeded")
	}
	if reached {
		t.Fatal("the credential request followed the redirect")
	}
	if callerClient.CheckRedirect != nil {
		t.Fatal("the caller's client was changed")
	}
}
