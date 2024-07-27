package fiberoidc

import (
	"fmt"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

func execVirtualHandler(
	uri string,
	authHeader string,
	headers map[string]string,
	handler fiber.Handler,
) {
	app := fiber.New()
	app.Get(uri, handler)
	h := app.Handler()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.Header.SetMethod(fiber.MethodGet)
	fctx.Request.SetRequestURI("/")
	if authHeader != "" {
		fctx.Request.Header.Set(fiber.HeaderAuthorization, authHeader)
	}
	for name, value := range headers {
		fctx.Request.Header.SetCookie(name, value)
	}
	h(fctx)
}

func TestVirtualHandler(t *testing.T) {
	hasExecuted := false
	execVirtualHandler("/", "", nil, func(c *fiber.Ctx) error { hasExecuted = true; return nil })
	if !hasExecuted {
		t.Fail()
	}
}

func TestGetAuth(t *testing.T) {
	authHeaderValue := uuid.NewString()
	authCookieName := "cookie-id"
	authCookieValue := uuid.NewString()
	if authHeaderValue == authCookieValue {
		t.FailNow() // not gonna happen
	}

	obj := FiberOidcStruct{
		Config: &Config{},
	}

	execVirtualHandler(
		"/",
		"",
		nil,
		func(c *fiber.Ctx) error {
			token := obj.getAuthToken(c)
			if token != "" {
				t.Fatalf("Unexpected Auth Token: %v", token)
			}
			return nil
		},
	)

	execVirtualHandler(
		"/",
		"not a bearer token",
		map[string]string{
			authCookieName: authCookieValue,
		},
		func(c *fiber.Ctx) error {
			token := obj.getAuthToken(c)
			if token != "" {
				t.Fatalf("Unexpected Auth Token: %v", token)
			}
			return nil
		},
	)
	execVirtualHandler(
		"/",
		fmt.Sprintf("bearer %v", authHeaderValue),
		map[string]string{
			authCookieName: authCookieValue,
		},
		func(c *fiber.Ctx) error {
			token := obj.getAuthToken(c)
			if token != authHeaderValue {
				t.Fatalf("Unexpected Auth Token: %v", token)
			}
			return nil
		},
	)

	// now with auth cookie name set
	obj.Config = &Config{
		AuthCookieName: authCookieName,
	}

	execVirtualHandler(
		"/",
		fmt.Sprintf("bearer %v", authHeaderValue),
		map[string]string{
			authCookieName: authCookieValue,
		},
		func(c *fiber.Ctx) error {

			token := obj.getAuthToken(c)
			if token != authHeaderValue {
				t.Fatalf("Unexpected Auth Token: %v", token)
			}
			return nil
		},
	)

	// falls back to cookie (when present)
	execVirtualHandler(
		"/",
		"",
		map[string]string{
			authCookieName: authCookieValue,
		},
		func(c *fiber.Ctx) error {

			token := obj.getAuthToken(c)
			if token != authCookieValue {
				t.Fatalf("Unexpected Auth Token: %v", token)
			}
			return nil
		},
	)

	// ANY non empty auth header takes precedence
	execVirtualHandler(
		"/",
		"invalid",
		map[string]string{
			authCookieName: authCookieValue,
		},
		func(c *fiber.Ctx) error {

			token := obj.getAuthToken(c)
			if token != "" {
				t.Fatalf("Unexpected Auth Token: %v", token)
			}
			return nil
		},
	)
}
