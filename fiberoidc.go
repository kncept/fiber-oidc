package fiberoidc

import (
	"errors"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

type oidcTokenKey struct{}
type oidcClaimsKey struct{}

type OidcClaims struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`

	Name string `json:"name,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`

	PoneNumber          string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
}

// New creates a new middleware handler
func New(config Config) fiber.Handler {
	// Set default config
	cfg := configDefault(config)

	verifierConfig := &gooidc.Config{
		ClientID: cfg.OidcConfig.ClientID,
	}
	idTokenVerifier := cfg.OidcProvider.Verifier(verifierConfig)

	// Return new handler
	return func(c *fiber.Ctx) error {

		// Don't execute middleware if Next returns true
		// So in order to NOT require auth on a route (like an index, or static files), return true here
		if cfg.Next != nil && cfg.Next(*c) {
			return c.Next()
		}

		// Set token back to client on this call
		// essentially handleOAuth2Callback from https://github.com/coreos/go-oidc
		if c.Path() == *cfg.CallbackPath {
			//decode response

			// state verification (and/or restoration)
			// c.Params("state")

			// callback to the oidc server to exchange the code
			code := c.Get("code")
			oauth2Token, err := cfg.OidcConfig.Exchange(c.Context(), code)
			if err != nil {
				return err
			}

			// Extract the ID Token from OAuth2 token.
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				return errors.New("auth code not exchangable for token")
			}

			// Parse and verify ID Token payload.
			idToken, err := idTokenVerifier.Verify(c.Context(), rawIDToken)
			if err != nil {
				return err
			}

			claims := &OidcClaims{}
			err = idToken.Claims(&claims)
			if err != nil {
				return err
			}

			// do we need to verify this?
			c.Locals(oidcTokenKey{}, idToken)
			c.Locals(oidcClaimsKey{}, claims)

			// also set it into a cookie if configured to do so
			if cfg.AuthCookieName != "" {
				c.Cookie(&fiber.Cookie{
					Name:  cfg.AuthCookieName,
					Value: rawIDToken,
				})
			}

			// complete, use *FromContext to access user details
			return nil
		}

		// Get authorization header
		auth := c.Get(fiber.HeaderAuthorization)

		// if its empty, fallback to 'authcookiename' (if not blank)
		if auth == "" && cfg.AuthCookieName != "" {
			auth = c.Cookies(cfg.AuthCookieName)
			if auth == "" {
				// V3 Redirect (for later)
				// c.Redirect().To(cfg.OidcConfig.AuthCodeURL(""))
				c.Redirect(cfg.OidcConfig.AuthCodeURL(""), 302)
			}
		} else {
			if len(auth) <= 7 || !utils.EqualFold(auth[:7], "bearer ") {
				// no bearer token - assume this requires a redirect
				c.Redirect(cfg.OidcConfig.AuthCodeURL(""), 302)
			}
			// Trim to just the token
			auth = auth[7:]
		}

		// Parse the JWT
		// token, err := jwt.Parse([]byte(tokenSring))
		token, err := idTokenVerifier.Verify(c.Context(), auth)
		if err != nil {
			return cfg.Unauthorized(c)
		}
		if token == nil {
			return cfg.Unauthorized(c)
		}

		// Set the JWT into the context
		if cfg.Authorizer(*token) {
			c.Locals(oidcTokenKey{}, token)
			return c.Next()
		}

		// Authentication failed
		return cfg.Unauthorized(c)
	}
}

// IdTokenFromContext returns the jwt token found in the context
// returns a nil pointer if nothing exists
func IdTokenFromContext(c fiber.Ctx) *gooidc.IDToken {
	token, ok := c.Locals(oidcTokenKey{}).(*gooidc.IDToken)
	if !ok {
		return nil
	}
	return token
}

// ClaimsFromContext returns the Oidc Claims fount in the context
// returns a nil pointer if nothing exists
func ClaimsFromContext(c fiber.Ctx) *OidcClaims {
	claims, ok := c.Locals(oidcClaimsKey{}).(*OidcClaims)
	if !ok {
		return nil
	}
	return claims
}
