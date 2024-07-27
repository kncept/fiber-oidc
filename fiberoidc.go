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
	OidcConfig      *oauth2.Config
	OidcProvider    *gooidc.Provider
	IdTokenVerifier *gooidc.IDTokenVerifier
}

type FiberOidc interface {
	AppProtector(routeProtector RouteProtectorFunc) fiber.Handler
	RouteProtector() fiber.Handler
	CallbackHandler() fiber.Handler
}

func New(ctx context.Context, config Config) (FiberOidc, error) {
	// ensure config is defaulted correctly
	cfg := configDefault(config)

	oidcProvider, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oauth2.Config{
		ClientID:     cfg.ClientId,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
	}

	// cache id token verifier
	idTokenVerifier := oidcProvider.Verifier(&gooidc.Config{
		ClientID: cfg.ClientId,
	})
	return &FiberOidcStruct{
		Config:          &cfg,
		OidcConfig:      oidcConfig,
		IdTokenVerifier: idTokenVerifier,
		OidcProvider:    oidcProvider,
	}, nil
}

func (obj *FiberOidcStruct) RouteProtector() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return obj.handleOAuth2Callback(c)
	}
}

func (obj *FiberOidcStruct) CallbackHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return obj.handleProtectedRoute(c)
	}
}

// New creates a new middleware handler
func (obj *FiberOidcStruct) AppProtector(routeProtector RouteProtectorFunc) fiber.Handler {

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
				return c.Next()
			}
		}

		// Set token back to client on this call
		// essentially handleOAuth2Callback from https://github.com/coreos/go-oidc
		if obj.Config.CallbackPath != nil && c.Path() == *obj.Config.CallbackPath {
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
	// decode response

	// state verification (and/or restoration)
	state := c.Query("state")

	// callback to the oidc server to exchange the code
	code := c.Query("code")
	oauth2Token, err := obj.OidcConfig.Exchange(c.Context(), code)
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
	return obj.Config.SuccessHandler(state, c)
}

func (obj *FiberOidcStruct) doAuthRequiredRedirect(c *fiber.Ctx) error {
	state, err := obj.Config.StateEncoder(c)
	if err != nil {
		return err
	}
	// V3 Redirect (for later)
	// return c.Redirect().To(cfg.OidcConfig.AuthCodeURL(""))
	return c.Redirect(obj.OidcConfig.AuthCodeURL(state), 302)
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

// IdTokenFromContext returns the jwt token found in the context
// returns a nil pointer if nothing exists
func IdTokenFromContext(c *fiber.Ctx) *gooidc.IDToken {
	token, ok := c.Locals(oidcTokenKey{}).(*gooidc.IDToken)
	if !ok {
		return nil
	}
	return token
}
