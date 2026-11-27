// Package echo adapts the optional Apps SDK to Echo v4 without owning the application server.
package echo

import (
	"net/http"

	"github.com/clorhq/apps/sdk"
	echo "github.com/labstack/echo/v4"
)

// UserFromContext returns the identity set by SDK middleware on an Echo request.
func UserFromContext(c echo.Context) (sdk.User, bool) {
	return sdk.UserFromContext(c.Request().Context())
}

// Handler adapts a framework-neutral Sign In, callback or logout handler.
func Handler(handler http.Handler) echo.HandlerFunc { return echo.WrapHandler(handler) }

// OptionalAuthentication attaches an optional user and checks cookie-authenticated unsafe requests for CSRF.
func OptionalAuthentication(client *sdk.Client) echo.MiddlewareFunc {
	return adaptMiddleware(client.OptionalAuthentication)
}

// RequiredAuthentication requires a local user and returns 401 when absent.
func RequiredAuthentication(client *sdk.Client) echo.MiddlewareFunc {
	return adaptMiddleware(client.RequiredAuthentication)
}

// RequireSignIn redirects unauthenticated browser GETs through the SDK's validated local Sign In route.
func RequireSignIn(client *sdk.Client, signInPath string) echo.MiddlewareFunc {
	return adaptMiddleware(func(next http.Handler) http.Handler { return client.RequireSignIn(signInPath, next) })
}

// adaptMiddleware preserves Echo's error handling while transferring the SDK request context.
func adaptMiddleware(middleware func(http.Handler) http.Handler) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var handlerErr error
			middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				c.SetRequest(req)
				handlerErr = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return handlerErr
		}
	}
}
