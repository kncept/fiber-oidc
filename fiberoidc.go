package fiberoidc

import (
	"context"
	"errors"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"golang.org/x/oauth2"
)

// internal context key for the oidc
type oidcTokenKey struct{}

// direct access to fields, if you need to tweak or override something
// which should, of course, be entirely unnessesary
type FiberOidcStruct struct {
	Config          *Config
	oauth2Config    *oauth2.Config
	goOidcProvider  *gooidc.Provider
	IdTokenVerifier *gooidc.IDTokenVerifier
}

type FiberOidc interface {
	// Allows protection of the entire app in one handler
	// This style matches the way that many web applications (eg: spring boot)
	// tend to handle security
	ProtectedApp(routeProtector RouteProtectorFunc) fiber.Handler

	// Allows protection of a single route
	// Will redirect if required
	ProtectedRoute() fiber.Handler

	// Does not protect the route, but will still bind any valid
	// auth token to the request
	UnprotectedRoute() fiber.Handler

	// Handles the OIDC callback
	CallbackHandler() fiber.Handler
	// easy access to the callback path
	CallbackPath() string
}

func New(ctx context.Context, config *Config) (FiberOidc, error) {
	// ensure config is defaulted correctly
	config.WithDefaults()

	err := config.Validate()
	if err != nil {
		return nil, err
	}

	oidcProvider, err := gooidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}

	// cache id token verifier
	idTokenVerifier := oidcProvider.Verifier(&gooidc.Config{
		ClientID: config.ClientId,
	})
	return &FiberOidcStruct{
		Config:          config,
		IdTokenVerifier: idTokenVerifier,
	}, nil
}

func (obj *FiberOidcStruct) GoOidcProvider(ctx context.Context) (*gooidc.Provider, error) {
	if obj.goOidcProvider == nil {
		config := obj.Config
		oidcProvider, err := gooidc.NewProvider(ctx, config.Issuer)
		if err != nil {
			return nil, err
		}
		obj.goOidcProvider = oidcProvider
	}
	return obj.goOidcProvider, nil
}

func (obj *FiberOidcStruct) Oauth2Config(ctx context.Context) (*oauth2.Config, error) {
	if obj.oauth2Config == nil {
		goOidcProvider, err := obj.GoOidcProvider(ctx)
		if err != nil {
			return nil, err
		}
		config := obj.Config
		obj.oauth2Config = &oauth2.Config{
			ClientID:     config.ClientId,
			ClientSecret: config.ClientSecret,
			Endpoint:     goOidcProvider.Endpoint(),
			RedirectURL:  config.RedirectUri,
			Scopes:       config.Scopes,
		}
	}
	return obj.oauth2Config, nil
}

func (obj *FiberOidcStruct) ProtectedRoute() fiber.Handler {
	return obj.handleProtectedRoute
}

func (obj *FiberOidcStruct) UnprotectedRoute() fiber.Handler {
	return obj.handleUnprotectedRoute
}

func (obj *FiberOidcStruct) CallbackHandler() fiber.Handler {
	return obj.handleOAuth2Callback
}

func (obj *FiberOidcStruct) CallbackPath() string {
	return obj.Config.CallbackPath
}

// New creates a new middleware handler
func (obj *FiberOidcStruct) ProtectedApp(routeProtector RouteProtectorFunc) fiber.Handler {
	// Return new handler
	return func(c *fiber.Ctx) error {

		// only execute middleware on protected routes
		// by default, all routes are protected
		if routeProtector != nil {
			protected, err := routeProtector(c)
			if err != nil {
				return err
			}
			if !protected {
				return obj.handleUnprotectedRoute(c)
			}
		}

		// Set token back to client on this call
		// essentially handleOAuth2Callback from https://github.com/coreos/go-oidc
		if c.Path() == obj.Config.CallbackPath {
			return obj.handleOAuth2Callback(c)
		}

		// This is just a regular protected route, handle appropriately
		return obj.handleProtectedRoute(c)
	}
}

func (obj *FiberOidcStruct) getAuthToken(c *fiber.Ctx) string {
	// Get authorization header
	auth := c.Get(fiber.HeaderAuthorization)
	if len(auth) > 7 && utils.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}

	// if its empty, fallback to 'authcookiename' (if not blank)
	if auth == "" && obj.Config.AuthCookieName != "" {
		return c.Cookies(obj.Config.AuthCookieName)
	}
	return ""
}

func (obj *FiberOidcStruct) handleOAuth2Callback(c *fiber.Ctx) error {
	ctx := c.Context()
	// decode response

	// state verification (and/or restoration)
	state := c.Query("state")

	// callback to the oidc server to exchange the code
	code := c.Query("code")

	oauth2Config, err := obj.Oauth2Config(ctx)
	if err != nil {
		return err
	}
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return err
	}

	// Extract the ID Token from OAuth2 token.
	rawToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return errors.New("auth code not exchangable for token")
	}

	// Parse and verify ID Token payload.
	idToken, err := obj.IdTokenVerifier.Verify(c.Context(), rawToken)
	if err != nil {
		return err
	}
	// if successful, bind to context
	c.Locals(oidcTokenKey{}, idToken)

	// also set it into a cookie if configured to do so
	if obj.Config.AuthCookieName != "" {
		c.Cookie(&fiber.Cookie{
			Name:  obj.Config.AuthCookieName,
			Value: rawToken,
		})
	}
	// complete, use *FromContext to access user details
	return obj.Config.LoginSuccessHandler(state, c)
}

func (obj *FiberOidcStruct) doAuthRequiredRedirect(c *fiber.Ctx) error {
	state, err := obj.Config.LoginStateEncoder(c)
	if err != nil {
		return err
	}

	oauth2Config, err := obj.Oauth2Config(c.Context())
	if err != nil {
		return err
	}

	// V3 Redirect (for later)
	// return c.Redirect().To(cfg.OidcConfig.AuthCodeURL(""))
	return c.Redirect(oauth2Config.AuthCodeURL(state), 302)
}

func (obj *FiberOidcStruct) handleProtectedRoute(c *fiber.Ctx) error {
	rawToken := obj.getAuthToken(c)
	if rawToken == "" {
		return obj.doAuthRequiredRedirect(c)
	}

	// Parse the JWT
	// token, err := jwt.Parse([]byte(tokenSring))
	idToken, err := obj.IdTokenVerifier.Verify(c.Context(), rawToken)
	if err != nil {
		// handle expired by re-asking for auth
		if _, ok := err.(*gooidc.TokenExpiredError); ok {
			return obj.doAuthRequiredRedirect(c)
		}
		return obj.Config.Unauthorized(c)
	}
	if idToken == nil {
		return obj.Config.Unauthorized(c)
	}
	// if successful, bind to context
	c.Locals(oidcTokenKey{}, idToken)
	return c.Next()
}

func (obj *FiberOidcStruct) handleUnprotectedRoute(c *fiber.Ctx) error {
	rawToken := obj.getAuthToken(c)
	if rawToken != "" {
		// Parse the JWT
		// token, err := jwt.Parse([]byte(tokenSring))
		idToken, err := obj.IdTokenVerifier.Verify(c.Context(), rawToken)
		if err == nil && idToken != nil {
			// if successful, bind to context
			c.Locals(oidcTokenKey{}, idToken)
		}

	}
	return c.Next()
}

// IdTokenFromContext returns the jwt token found in the context
// returns a nil pointer if nothing exists
func IdTokenFromContext(c *fiber.Ctx) *gooidc.IDToken {
	token, ok := c.Locals(oidcTokenKey{}).(*gooidc.IDToken)
	if !ok {
		return nil
	}
	return token
}
