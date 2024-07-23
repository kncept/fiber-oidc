package fiberoidc

import (
	"errors"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

type oidcTokenKey struct{}

// New creates a new middleware handler
func New(config Config) fiber.Handler {

	// ensure config is defaulted correctly
	cfg := configDefault(config)

	// cache id token verifier
	idTokenVerifier := cfg.OidcProvider.Verifier(&gooidc.Config{
		ClientID: cfg.OidcConfig.ClientID,
	})

	// Return new handler
	return func(c *fiber.Ctx) error {

		// only execute middleware on protected routes
		// by default, all routes are protected
		protected, err := cfg.Protected(c)
		if err != nil {
			return err
		}
		if !protected {
			return c.Next()
		}

		// Set token back to client on this call
		// essentially handleOAuth2Callback from https://github.com/coreos/go-oidc
		if c.Path() == *cfg.CallbackPath {
			return handleOAuth2Callback(cfg, c, idTokenVerifier)
		}

		// This is just a regular protected route, handle appropriately
		return handleProtectedRoute(cfg, c, idTokenVerifier)
	}
}

func getAuthToken(cfg Config, c *fiber.Ctx) string {
	// Get authorization header
	auth := c.Get(fiber.HeaderAuthorization)
	if len(auth) > 7 && utils.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}

	// if its empty, fallback to 'authcookiename' (if not blank)
	if auth == "" && cfg.AuthCookieName != "" {
		return c.Cookies(cfg.AuthCookieName)
	}
	return ""
}

func handleOAuth2Callback(cfg Config, c *fiber.Ctx, idTokenVerifier *gooidc.IDTokenVerifier) error {
	// decode response

	// state verification (and/or restoration)
	state := c.Query("state")

	// callback to the oidc server to exchange the code
	code := c.Query("code")
	oauth2Token, err := cfg.OidcConfig.Exchange(c.Context(), code)
	if err != nil {
		return err
	}

	// Extract the ID Token from OAuth2 token.
	rawToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return errors.New("auth code not exchangable for token")
	}

	// Parse and verify ID Token payload.
	idToken, err := idTokenVerifier.Verify(c.Context(), rawToken)
	if err != nil {
		return err
	}
	// if successful, bind to context
	c.Locals(oidcTokenKey{}, idToken)

	// also set it into a cookie if configured to do so
	if cfg.AuthCookieName != "" {
		c.Cookie(&fiber.Cookie{
			Name:  cfg.AuthCookieName,
			Value: rawToken,
		})
	}
	// complete, use *FromContext to access user details
	return cfg.SuccessHandler(state, c)
}

func doAuthRequiredRedirect(cfg Config, c *fiber.Ctx) error {
	state, err := cfg.StateEncoder(c)
	if err != nil {
		return err
	}
	// V3 Redirect (for later)
	// return c.Redirect().To(cfg.OidcConfig.AuthCodeURL(""))
	return c.Redirect(cfg.OidcConfig.AuthCodeURL(state), 302)
}

func handleProtectedRoute(cfg Config, c *fiber.Ctx, idTokenVerifier *gooidc.IDTokenVerifier) error {
	rawToken := getAuthToken(cfg, c)
	if rawToken == "" {
		return doAuthRequiredRedirect(cfg, c)
	}

	// Parse the JWT
	// token, err := jwt.Parse([]byte(tokenSring))
	idToken, err := idTokenVerifier.Verify(c.Context(), rawToken)
	if err != nil {
		// handle expired by re-asking for auth
		if _, ok := err.(*gooidc.TokenExpiredError); ok {
			return doAuthRequiredRedirect(cfg, c)
		}
		return cfg.Unauthorized(c)
	}
	if idToken == nil {
		return cfg.Unauthorized(c)
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
