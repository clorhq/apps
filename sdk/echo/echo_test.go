package echo

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/sdk"
	echo "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// TestEchoAuthentication verifies anonymous context propagation and API authentication failures.
func TestEchoAuthentication(t *testing.T) {
	client, err := sdk.NewClient(
		t.Context(),
		&sdk.NewClientArgs{
			EnvironmentOnly: true,
			Authentication:  true,
			APIKey:          strings.Repeat("a", 32),
			Configuration: &sdk.Configuration{
				Version:          model.ProtocolVersion,
				AppID:            "example-app",
				InstanceID:       "example-instance",
				ServiceOrigin:    "https://api.example.com",
				PrimaryHostname:  "app.example.com",
				AuthCallbackPath: model.DefaultAuthCallbackPath,
				AuthSignInPath:   model.DefaultAuthSignInPath,
				WebsiteOrigin:    "https://example.com",
				CookieKey:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
		},
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()
	app := echo.New()
	app.GET("/optional", func(c echo.Context) error {
		_, ok := UserFromContext(c)
		require.False(t, ok)
		return c.NoContent(http.StatusNoContent)
	}, OptionalAuthentication(client))
	app.GET(
		"/required",
		func(c echo.Context) error {
			t.Error("unauthenticated handler ran")
			return nil
		},
		RequiredAuthentication(client),
	)
	for route, code := range map[string]int{"/optional": http.StatusNoContent, "/required": http.StatusUnauthorized} {
		recorder := httptest.NewRecorder()
		app.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://app.example.com"+route, nil))
		require.Equal(t, code, recorder.Code)
	}
	app.GET("/browser", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) }, RequireSignIn(client, "/signin"))
	recorder := httptest.NewRecorder()
	app.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://app.example.com/browser", nil))
	require.Equal(t, http.StatusFound, recorder.Code)
	require.Equal(t, "/signin", recorder.Header().Get("Location"))
}
